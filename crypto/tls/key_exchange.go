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
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/markkurossi/gotls/crypto/hkdf"
)

var (
	errUnexpectedMessage = errors.New("unexpected_message")
)

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

func (conn *Connection) deriveServerHandshakeKeys() error {
	// TLS 1.3 Key Schedule: RFC-8446: 7.1. Key Schedule, page 91-
	fmt.Printf(" - Handshake:\n")

	zeroHash := make([]byte, sha256.Size)
	earlySecret := hkdf.Extract(sha256.New, zeroHash, zeroHash)
	fmt.Printf("   early    : %x\n", earlySecret)

	emptyHash := sha256.Sum256([]byte{})
	derivedSecret := deriveSecret(earlySecret, "derived", emptyHash[:])
	fmt.Printf("   derived  : %x\n", derivedSecret)

	conn.handshakeSecret = hkdf.Extract(sha256.New, conn.sharedSecret,
		derivedSecret)
	fmt.Printf("   handshake: %x\n", conn.handshakeSecret)

	// Derive handshake traffic secrets.
	transcript := conn.transcript.Sum(nil)
	conn.clientHSTr = deriveSecret(conn.handshakeSecret, "c hs traffic",
		transcript)
	conn.serverHSTr = deriveSecret(conn.handshakeSecret, "s hs traffic",
		transcript)
	fmt.Printf("   c-hs-tr  : %x\n", conn.clientHSTr)
	fmt.Printf("   s-hs-tr  : %x\n", conn.serverHSTr)

	// Derive keys and IVs from traffic secrets.

	clientHSKey := hkdfExpandLabel(conn.clientHSTr, "key", nil, 16)
	clientHSIV := hkdfExpandLabel(conn.clientHSTr, "iv", nil, 12)

	fmt.Printf("   c-hs-key : %x\n", clientHSKey)
	fmt.Printf("   c-hs-iv  : %x\n", clientHSIV)

	serverHSKey := hkdfExpandLabel(conn.serverHSTr, "key", nil, 16)
	serverHSIV := hkdfExpandLabel(conn.serverHSTr, "iv", nil, 12)

	fmt.Printf("   s-hs-key : %x\n", serverHSKey)
	fmt.Printf("   s-hs-iv  : %x\n", serverHSIV)

	// Instantiate handshake keys.

	var err error

	conn.writeCipher, err = NewCipher(serverHSKey, serverHSIV)
	if err != nil {
		return err
	}
	conn.readCipher, err = NewCipher(clientHSKey, clientHSIV)
	if err != nil {
		return err
	}

	return nil
}

func (conn *Connection) deriveKeys() error {
	zeroHash := make([]byte, sha256.Size)
	emptyHash := sha256.Sum256([]byte{})

	// TLS 1.3 Key Schedule: RFC-8446: 7.1. Key Schedule, page 91-
	fmt.Printf(" - Traffic  :\n")

	derivedSecret := deriveSecret(conn.handshakeSecret, "derived", emptyHash[:])
	fmt.Printf("   derived  : %x\n", derivedSecret)

	masterSecret := hkdf.Extract(sha256.New, zeroHash, derivedSecret)
	fmt.Printf("   master   : %x\n", masterSecret)

	// Derive application traffic secrets.
	transcript := conn.transcript.Sum(nil)
	clientAppTr := deriveSecret(masterSecret, "c ap traffic", transcript)
	serverAppTr := deriveSecret(masterSecret, "s ap traffic", transcript)

	// Derive keys and IVs from traffic secrets.

	clientAppKey := hkdfExpandLabel(clientAppTr, "key", nil, 16)
	clientAppIV := hkdfExpandLabel(clientAppTr, "iv", nil, 12)

	fmt.Printf("   c-app-key: %x\n", clientAppKey)
	fmt.Printf("   c-app-iv : %x\n", clientAppIV)

	serverAppKey := hkdfExpandLabel(serverAppTr, "key", nil, 16)
	serverAppIV := hkdfExpandLabel(serverAppTr, "iv", nil, 12)

	fmt.Printf("   s-app-key: %x\n", serverAppKey)
	fmt.Printf("   s-app-iv : %x\n", serverAppIV)

	// Instantiate application keys.

	var err error

	conn.writeCipher, err = NewCipher(serverAppKey, serverAppIV)
	if err != nil {
		return err
	}
	conn.readCipher, err = NewCipher(clientAppKey, clientAppIV)
	if err != nil {
		return err
	}

	return nil
}

var (
	serverSignatureCtx = []byte("TLS 1.3, server CertificateVerify")
	clientSignatureCtx = []byte("TLS 1.3, client CertificateVerify")
)

func (conn *Connection) serverCertificateVerify() ([]byte, error) {
	data := make([]byte, 0, 64+len(serverSignatureCtx)+1+conn.transcript.Size())

	for i := 0; i < 64; i++ {
		data = append(data, 32)
	}
	data = append(data, serverSignatureCtx...)
	data = append(data, 0)
	data = conn.transcript.Sum(data)

	sum := sha256.Sum256(data)

	return conn.serverKey.Sign(rand.Reader, sum[:], crypto.SHA256)
}

func (conn *Connection) finished(server bool) []byte {
	var baseKey []byte
	if server {
		baseKey = conn.serverHSTr
	} else {
		baseKey = conn.clientHSTr
	}
	finishedKey := hkdfExpandLabel(baseKey, "finished", nil, sha256.Size)
	hash := hmac.New(sha256.New, finishedKey)
	hash.Write(conn.transcript.Sum(nil))
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
func NewCipher(key, iv []byte) (*Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		cipher: cipher,
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
		return CTInvalid, nil, errUnexpectedMessage
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
