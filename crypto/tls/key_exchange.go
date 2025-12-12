//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/markkurossi/gotls/crypto/hkdf"
	"golang.org/x/crypto/chacha20poly1305"
)

func (conn *Conn) keydbgf(format string, a ...interface{}) {
	if true && conn.config.Debug {
		fmt.Printf(format, a...)
	}
}

// HKDF-Expand-Label as per TLS 1.3 spec: 7.1. Key Schedule, page 91
func hkdfExpandLabel(secret []byte, label string, context []byte,
	length int) []byte {

	var hkdfLabel []byte
	if false {
		hkdfLabel = make([]byte, 0, 2+1+len("tls13 ")+len(label)+1+len(context))
		hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
		hkdfLabel = append(hkdfLabel, byte(len("tls13 ")+len(label)))
		hkdfLabel = append(hkdfLabel, []byte("tls13 ")...)
		hkdfLabel = append(hkdfLabel, []byte(label)...)
		hkdfLabel = append(hkdfLabel, byte(len(context)))
		hkdfLabel = append(hkdfLabel, context...)
	} else {
		// struct {
		//     uint16 length = Length;
		//     opaque label<7..255> = "tls13 " + Label;
		//     opaque context<0..255> = Context;
		// } HkdfLabel;

		tls13 := []byte("tls13 ")
		hkdfLabel = make([]byte, 0, 2+1+len(tls13)+len(label)+1+len(context))
		hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
		hkdfLabel = append(hkdfLabel, byte(len(tls13)+len(label)))
		hkdfLabel = append(hkdfLabel, tls13...)
		hkdfLabel = append(hkdfLabel, []byte(label)...)
		hkdfLabel = append(hkdfLabel, byte(len(context)))
		hkdfLabel = append(hkdfLabel, context...)
	}

	hash := sha256.New
	expander := hkdf.Expand(hash, secret, hkdfLabel)
	out := make([]byte, length)
	io.ReadFull(expander, out)
	return out
}

// Derive secret using HKDF-Expand-Label
func deriveSecret(secret []byte, label string, hash []byte) []byte {
	return hkdfExpandLabel(secret, label, hash, sha256.Size)
}

func (conn *Conn) deriveHandshakeKeys(server bool) error {
	// XXX should take the has function from the selected cipher suite.
	cs := conn.cipherSuites[0]

	// TLS 1.3 Key Schedule: RFC-8446: 7.1. Key Schedule, page 91-
	conn.keydbgf(" - Handshake:\n")
	conn.keydbgf("   shared   : %x\n", conn.sharedSecret)

	transcript := conn.transcript.Sum(nil)
	conn.keydbgf("   transcrpt: %x\n", transcript)

	zeroHash := make([]byte, sha256.Size)
	earlySecret := hkdf.Extract(sha256.New, zeroHash, zeroHash)
	conn.keydbgf("   early    : %x\n", earlySecret)

	emptyHash := sha256.Sum256([]byte{})
	derivedSecret := deriveSecret(earlySecret, "derived", emptyHash[:])
	conn.keydbgf("   derived  : %x\n", derivedSecret)

	conn.handshakeSecret = hkdf.Extract(sha256.New, conn.sharedSecret,
		derivedSecret)
	conn.keydbgf("   handshake: %x\n", conn.handshakeSecret)

	// Derive handshake traffic secrets.
	conn.clientHSTr = deriveSecret(conn.handshakeSecret, "c hs traffic",
		transcript)
	conn.serverHSTr = deriveSecret(conn.handshakeSecret, "s hs traffic",
		transcript)
	conn.keydbgf("   c-hs-tr  : %x\n", conn.clientHSTr)
	conn.keydbgf("   s-hs-tr  : %x\n", conn.serverHSTr)

	// Derive keys and IVs from traffic secrets.

	clientHSKey := hkdfExpandLabel(conn.clientHSTr, "key", nil, cs.KeySize())
	clientHSIV := hkdfExpandLabel(conn.clientHSTr, "iv", nil, cs.IVSize())

	conn.keydbgf("   c-hs-key : %x\n", clientHSKey)
	conn.keydbgf("   c-hs-iv  : %x\n", clientHSIV)

	serverHSKey := hkdfExpandLabel(conn.serverHSTr, "key", nil, cs.KeySize())
	serverHSIV := hkdfExpandLabel(conn.serverHSTr, "iv", nil, cs.IVSize())

	conn.keydbgf("   s-hs-key : %x\n", serverHSKey)
	conn.keydbgf("   s-hs-iv  : %x\n", serverHSIV)

	// Instantiate handshake keys.

	serverCipher, err := NewCipher(conn, serverHSKey, serverHSIV)
	if err != nil {
		return err
	}
	clientCipher, err := NewCipher(conn, clientHSKey, clientHSIV)
	if err != nil {
		return err
	}

	if server {
		conn.writeCipher = serverCipher
		conn.readCipher = clientCipher
	} else {
		conn.writeCipher = clientCipher
		conn.readCipher = serverCipher
	}

	return nil
}

func (conn *Conn) deriveKeys(server bool, transcript []byte) error {
	// XXX should take the has function from the selected cipher suite.
	cs := conn.cipherSuites[0]

	zeroHash := make([]byte, sha256.Size)
	emptyHash := sha256.Sum256([]byte{})

	// TLS 1.3 Key Schedule: RFC-8446: 7.1. Key Schedule, page 91-
	conn.keydbgf(" - Traffic  :\n")
	conn.keydbgf("   handshake: %x\n", conn.handshakeSecret)
	conn.keydbgf("   transcrpt: %x\n", transcript)

	derivedSecret := deriveSecret(conn.handshakeSecret, "derived", emptyHash[:])
	conn.keydbgf("   derived  : %x\n", derivedSecret)

	masterSecret := hkdf.Extract(sha256.New, zeroHash, derivedSecret)
	conn.keydbgf("   master   : %x\n", masterSecret)

	// Derive application traffic secrets.
	clientAppTr := deriveSecret(masterSecret, "c ap traffic", transcript)
	serverAppTr := deriveSecret(masterSecret, "s ap traffic", transcript)

	// Derive keys and IVs from traffic secrets.

	clientAppKey := hkdfExpandLabel(clientAppTr, "key", nil, cs.KeySize())
	clientAppIV := hkdfExpandLabel(clientAppTr, "iv", nil, cs.IVSize())

	conn.keydbgf("   c-app-key: %x\n", clientAppKey)
	conn.keydbgf("   c-app-iv : %x\n", clientAppIV)

	serverAppKey := hkdfExpandLabel(serverAppTr, "key", nil, cs.KeySize())
	serverAppIV := hkdfExpandLabel(serverAppTr, "iv", nil, cs.IVSize())

	conn.keydbgf("   s-app-key: %x\n", serverAppKey)
	conn.keydbgf("   s-app-iv : %x\n", serverAppIV)

	// Instantiate application keys.

	serverCipher, err := NewCipher(conn, serverAppKey, serverAppIV)
	if err != nil {
		return err
	}
	clientCipher, err := NewCipher(conn, clientAppKey, clientAppIV)
	if err != nil {
		return err
	}

	if server {
		conn.writeCipher = serverCipher
		conn.readCipher = clientCipher
	} else {
		conn.writeCipher = clientCipher
		conn.readCipher = serverCipher
	}

	return nil
}

var (
	serverSignatureCtx = []byte("TLS 1.3, server CertificateVerify")
	clientSignatureCtx = []byte("TLS 1.3, client CertificateVerify")
)

func (conn *Conn) certificateVerify(hash crypto.Hash) []byte {
	data := make([]byte, 0, 64+len(serverSignatureCtx)+1+conn.transcript.Size())

	for i := 0; i < 64; i++ {
		data = append(data, 32)
	}
	data = append(data, serverSignatureCtx...)
	data = append(data, 0)
	data = conn.transcript.Sum(data)

	h := hash.New()
	h.Write(data)

	return h.Sum(nil)
}

// Finished computes the finished verification code for client/server
// depending on the server argument.
func (conn *Conn) finished(server bool) []byte {
	var baseKey []byte
	if server {
		baseKey = conn.serverHSTr
	} else {
		baseKey = conn.clientHSTr
	}
	finishedKey := hkdfExpandLabel(baseKey, "finished", nil, sha256.Size)
	hash := hmac.New(sha256.New, finishedKey)
	digest := conn.transcript.Sum(nil)
	conn.keydbgf("FinishedDigest:\n%s", hex.Dump(digest))
	hash.Write(digest)
	return hash.Sum(nil)
}

// Cipher implements an AEAD cipher instance.
type Cipher struct {
	cipher cipher.AEAD
	iv     []byte
	seq    uint64
	ivSeq  []byte
}

// NewCipher creates a new Cipher for the key and iv.
func NewCipher(conn *Conn, key, iv []byte) (*Cipher, error) {
	conn.keydbgf("NewCipher: cs=%v, key=%x\n", conn.cipherSuites[0], key)

	var aead cipher.AEAD
	var err error

	switch conn.cipherSuites[0] {
	case CipherTLSAes128GcmSha256, CipherTLSAes256GcmSha384:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

	case CipherTLSChacha20Poly1305Sha256:
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
	}

	return &Cipher{
		cipher: aead,
		iv:     iv,
		ivSeq:  make([]byte, len(iv)),
	}, nil
}

// Encrypt encrypts the data. The ct argument specifies the content
// type of the data.
func (cipher *Cipher) Encrypt(ct ContentType, data []byte) []byte {
	// Construct TLSInnerPlaintext:
	//
	// struct {
	//     opaque content[TLSPlaintext.length];
	//     ContentType type;
	//     uint8 zeros[length_of_padding];
	// } TLSInnerPlaintext;
	//
	// struct {
	//     ContentType opaque_type = application_data; /* 23 */
	//     ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
	//     uint16 length;
	//     opaque encrypted_record[TLSCiphertext.length];
	// } TLSCiphertext;

	plaintext := make([]byte, len(data)+1)
	copy(plaintext, data)
	plaintext[len(data)] = byte(ct)

	cipherLen := len(plaintext) + cipher.cipher.Overhead()

	// Additional data is the TLS record header.
	var hdr [5]byte
	hdr[0] = byte(CTApplicationData)
	bo.PutUint16(hdr[1:3], uint16(VersionTLS12))
	bo.PutUint16(hdr[3:5], uint16(cipherLen))

	// IV.
	iv := cipher.IV()

	return cipher.cipher.Seal(nil, iv, plaintext, hdr[:])
}

// Decrypt decrypts the data and returns its content type and
// decrypted content.
func (cipher *Cipher) Decrypt(data []byte) (ContentType, []byte, error) {
	// Additional data is the TLS record header.
	var hdr [5]byte
	hdr[0] = byte(CTApplicationData)
	bo.PutUint16(hdr[1:3], uint16(VersionTLS12))
	bo.PutUint16(hdr[3:5], uint16(len(data)))

	iv := cipher.IV()

	plain, err := cipher.cipher.Open(nil, iv, data, hdr[:])
	if err != nil {
		return CTInvalid, nil, err
	}

	// Remove padding and resolve the original content type.
	var end int
	for end = len(plain) - 1; end > 0; end-- {
		if plain[end] != 0 {
			break
		}
	}
	if end == 0 {
		return CTInvalid, nil, AlertUnexpectedMessage
	}

	return ContentType(plain[end]), plain[:end], nil
}

// IV creates the IV for the next encrypt/decrypt operation.
func (cipher *Cipher) IV() []byte {
	copy(cipher.ivSeq[0:], cipher.iv)

	var seq [8]byte
	bo.PutUint64(seq[0:], cipher.seq)
	cipher.seq++

	for i := 0; i < len(seq); i++ {
		cipher.ivSeq[len(cipher.ivSeq)-len(seq)+i] ^= seq[i]
	}

	return cipher.ivSeq
}
