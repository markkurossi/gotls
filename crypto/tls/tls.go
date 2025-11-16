//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"time"
)

var (
	bo = binary.BigEndian

	supportedVersions = map[ProtocolVersion]bool{
		VersionTLS13: true,
	}
	supportedCipherSuites = map[CipherSuite]bool{
		CipherTLSAes128GcmSha256: true,
	}
	supportedGroups = map[NamedGroup]bool{
		GroupSecp256r1: true,
		GroupX25519:    false,
	}
	supportedSignatureSchemes = map[SignatureScheme]bool{
		SigSchemeEcdsaSecp256r1Sha256: true,
	}

	_ io.ReadWriteCloser = &Conn{}
	_ net.Conn           = &Conn{}
)

// Config defines TLS client and server configuration options.
type Config struct {
	Debug       bool
	PrivateKey  *ecdsa.PrivateKey
	Certificate *x509.Certificate
	ServerName  string
}

// Conn implements a TLS connection.
type Conn struct {
	conn   net.Conn
	config *Config
	rbuf   []byte

	serverKey  *ecdsa.PrivateKey
	serverCert *x509.Certificate

	// Handshake.
	handshakeState   HandshakeState
	transcript       hash.Hash
	clientHello      *ClientHello
	serverNames      []string
	versions         []ProtocolVersion
	cipherSuites     []CipherSuite
	groups           []NamedGroup
	signatureSchemes []SignatureScheme
	peerKeyShare     *KeyShareEntry
	peerCert         *x509.Certificate
	sharedSecret     []byte
	handshakeSecret  []byte
	clientHSTr       []byte
	serverHSTr       []byte

	writeCipher *Cipher
	readCipher  *Cipher
	readEOF     bool
	appData     []byte
}

// HandshakeState defines the connection's handshake state.
type HandshakeState uint8

// Handshake states.
const (
	HSClientHello HandshakeState = iota
	HSServerHello
	HSServerDone
	HSDone
)

func (hs HandshakeState) String() string {
	name, ok := handshakeStates[hs]
	if ok {
		return name
	}
	return fmt.Sprintf("{HandshakeState %d}", int(hs))
}

var handshakeStates = map[HandshakeState]string{
	HSClientHello: "client_hello",
	HSServerHello: "server_hello",
	HSServerDone:  "server_done",
	HSDone:        "done",
}

// NewConnection creates a new TLS connection for the argument conn.
func NewConnection(conn net.Conn, config *Config) *Conn {
	return &Conn{
		conn:   conn,
		config: config,
		rbuf:   make([]byte, 65536),
	}
}

// Debugf prints debug output for the connection.
func (conn *Conn) Debugf(format string, a ...interface{}) {
	if conn.config.Debug {
		fmt.Printf(format, a...)
	}
}

func (conn *Conn) readHandshakeMsg() (ContentType, []byte, error) {
	for {
		ct, data, err := conn.ReadRecord()
		if err != nil {
			return CTInvalid, nil, err
		}
		switch ct {
		case CTChangeCipherSpec:
			err = conn.recvChangeCipherSpec(data)
			if err != nil {
				return CTInvalid, nil, err
			}
		case CTAlert:
			err = conn.recvAlert(data)
			if err != nil {
				return CTInvalid, nil, err
			}
		case CTHandshake:
			return ct, data, nil
		default:
			return CTInvalid, nil,
				conn.alertf(AlertUnexpectedMessage, "received %v", ct)
		}
	}
}

func (conn *Conn) writeHandshakeMsg(ht HandshakeType, data []byte) error {
	// Set TypeLen
	typeLen := uint32(ht)<<24 | uint32(len(data)-4)
	bo.PutUint32(data[0:4], typeLen)

	conn.transcript.Write(data)

	return conn.WriteRecord(CTHandshake, data)
}

// ClientHandshake runs the client handshake protocol.
func (conn *Conn) ClientHandshake() error {
	ecdhCurve := ecdh.P256()
	ecdhPriv, err := ecdhCurve.GenerateKey(rand.Reader)
	if err != nil {
		return conn.internalErrorf("failed to generate DH key: %v", err)
	}

	// ClientHello

	var legacySessionID [32]byte
	_, err = rand.Read(legacySessionID[:])
	if err != nil {
		return conn.internalErrorf("failed to create legacy_session_id: %v",
			err)
	}

	keyShare := &KeyShareEntry{
		Group:       GroupSecp256r1,
		KeyExchange: ecdhPriv.PublicKey().Bytes(),
	}

	conn.clientHello = &ClientHello{
		LegacyVersion:   VersionTLS12,
		LegacySessionID: legacySessionID[:],
		CipherSuites: []CipherSuite{
			CipherTLSAes128GcmSha256,
		},
		LegacyCompressionMethods: []byte{0},
		Extensions: []Extension{
			NewExtension(ETSupportedGroups, GroupSecp256r1),
			NewExtension(ETSignatureAlgorithms,
				SigSchemeEcdsaSecp256r1Sha256,
				SigSchemeEcdsaSecp384r1Sha384,
				SigSchemeEcdsaSecp521r1Sha512,
				SigSchemeRsaPkcs1Sha256,
				SigSchemeRsaPkcs1Sha384,
				SigSchemeRsaPkcs1Sha512,
				SigSchemeRsaPssPssSha256,
				SigSchemeRsaPssPssSha384,
				SigSchemeRsaPssPssSha512,
				SigSchemeRsaPssRsaeSha256,
				SigSchemeRsaPssRsaeSha384,
				SigSchemeRsaPssRsaeSha512),
			NewExtension(ETSupportedVersions, VersionTLS13),
			NewExtension(ETKeyShare, keyShare),
		},
	}
	if len(conn.config.ServerName) > 0 {
		conn.clientHello.Extensions = append(conn.clientHello.Extensions,
			NewExtension(ETServerName, &ServerName{
				Hostname: []byte(conn.config.ServerName),
			}))
	}

	_, err = rand.Read(conn.clientHello.Random[:])
	if err != nil {
		return conn.internalErrorf("failed to create random: %v", err)
	}

	// Init transcript.
	conn.transcript = conn.clientHello.CipherSuites[0].Hash()

	data, err := Marshal(conn.clientHello)
	if err != nil {
		return err
	}
	conn.Debugf(" > ClientHello: %v bytes\n", len(data))

	err = conn.writeHandshakeMsg(HTClientHello, data)
	if err != nil {
		return conn.internalErrorf("write failed: %v", err)
	}
	conn.handshakeState = HSServerHello

	// Process server messages until server's handshake is done.
	for conn.handshakeState != HSServerDone {
		_, data, err = conn.readHandshakeMsg()
		if err != nil {
			return err
		}
		err = conn.recvServerHandshake(data, ecdhCurve, ecdhPriv)
		if err != nil {
			return err
		}
	}
	conn.handshakeState = HSServerDone

	transcript := conn.transcript.Sum(nil)

	// Finished.
	verifyData := conn.finished(false)
	var vd32 [32]byte
	copy(vd32[0:], verifyData)
	finished := &Finished{
		VerifyData: vd32,
	}
	data, err = Marshal(finished)
	if err != nil {
		return conn.internalErrorf("marshal failed: %v", err)
	}
	conn.Debugf(" > Finished: %v bytes\n", len(data))
	err = conn.writeHandshakeMsg(HTFinished, data)
	if err != nil {
		return conn.internalErrorf("write failed: %v", err)
	}
	conn.handshakeState = HSDone

	err = conn.deriveKeys(false, transcript)
	if err != nil {
		return conn.internalErrorf("key derivation failed: %v", err)
	}

	return nil
}

// ServerHandshake runs the server handshake protocol.
func (conn *Conn) ServerHandshake(key *ecdsa.PrivateKey,
	cert *x509.Certificate) error {

	//  Client                                               Server
	//
	//  ClientHello
	//  + key_share             -------->
	//                                            HelloRetryRequest
	//                          <--------               + key_share
	//  ClientHello
	//  + key_share             -------->
	//                                                  ServerHello
	//                                                  + key_share
	//                                        {EncryptedExtensions}
	//                                        {CertificateRequest*}
	//                                               {Certificate*}
	//                                         {CertificateVerify*}
	//                                                   {Finished}
	//                          <--------       [Application Data*]
	//  {Certificate*}
	//  {CertificateVerify*}
	//  {Finished}              -------->
	//  [Application Data]      <------->        [Application Data]
	//
	//       Figure 2: Message Flow for a Full Handshake with
	//                     Mismatched Parameters

	conn.serverKey = key
	conn.serverCert = cert

	_, data, err := conn.readHandshakeMsg()
	if err != nil {
		return err
	}
	err = conn.recvClientHandshake(data)
	if err != nil {
		return err
	}

	// Init transcript.
	conn.transcript = conn.cipherSuites[0].Hash()
	conn.transcript.Write(data)

	if conn.peerKeyShare == nil {
		// No matching group, send HelloRetryRequest.

		// ClientHello1 is replaced with a special synthetic handshake
		// message.

		var hdr [4]byte
		hdr[0] = byte(HTMessageHash)
		hdr[3] = byte(conn.transcript.Size())

		digest := conn.transcript.Sum(nil)

		conn.transcript.Reset()
		conn.transcript.Write(hdr[:])
		conn.transcript.Write(digest)

		// Create HelloRetryRequest message.
		req := &ServerHello{
			LegacyVersion:   VersionTLS12,
			Random:          HelloRetryRequestRandom,
			LegacySessionID: conn.clientHello.LegacySessionID,
			CipherSuite:     conn.cipherSuites[0],
			Extensions: []Extension{
				Extension{
					Type: ETSupportedVersions,
					Data: VersionTLS13.Bytes(),
				},
				Extension{
					Type: ETKeyShare,
					Data: GroupSecp256r1.Bytes(),
				},
			},
		}
		data, err = Marshal(req)
		if err != nil {
			return conn.internalErrorf("marshal failed: %v", err)
		}
		conn.Debugf(" > HelloRetryRequest: %v bytes\n", len(data))

		err = conn.writeHandshakeMsg(HTServerHello, data)
		if err != nil {
			return conn.internalErrorf("write failed: %v", err)
		}

		// Read ClientHello.
		_, data, err := conn.readHandshakeMsg()
		if err != nil {
			return err
		}
		err = conn.recvClientHandshake(data)
		if err != nil {
			return err
		}
		conn.transcript.Write(data)

		if conn.peerKeyShare == nil {
			return conn.alert(AlertHandshakeFailure)
		}
	}
	conn.handshakeState = HSServerHello

	// ServerHello

	ecdhCurve := ecdh.P256()
	ecdhPriv, err := ecdhCurve.GenerateKey(rand.Reader)
	if err != nil {
		return conn.internalErrorf("error creating private key: %v", err)
	}

	// Decode client's public key.
	ecdhClientPub, err := ecdhCurve.NewPublicKey(conn.peerKeyShare.KeyExchange)
	if err != nil {
		return conn.decodeErrorf("invalid client public key: %v", err)
	}
	conn.sharedSecret, err = ecdhPriv.ECDH(ecdhClientPub)
	if err != nil {
		return conn.decodeErrorf("ECDH failed: %v", err)
	}

	keyShare := &KeyShareEntry{
		Group:       GroupSecp256r1,
		KeyExchange: ecdhPriv.PublicKey().Bytes(),
	}
	req := &ServerHello{
		LegacyVersion:   VersionTLS12,
		LegacySessionID: conn.clientHello.LegacySessionID,
		CipherSuite:     conn.cipherSuites[0],
		Extensions: []Extension{
			Extension{
				Type: ETSupportedVersions,
				Data: VersionTLS13.Bytes(),
			},
			Extension{
				Type: ETKeyShare,
				Data: keyShare.Bytes(),
			},
		},
	}
	_, err = rand.Read(req.Random[:])
	if err != nil {
		return conn.internalErrorf("failed to create random: %v", err)
	}
	data, err = Marshal(req)
	if err != nil {
		return conn.internalErrorf("marshal failed: %v", err)
	}
	conn.Debugf(" > ServerHello: %v bytes\n", len(data))

	err = conn.writeHandshakeMsg(HTServerHello, data)
	if err != nil {
		return conn.internalErrorf("write failed: %v", err)
	}

	err = conn.deriveHandshakeKeys(true)
	if err != nil {
		return err
	}

	// EncryptedExtensions.
	msg := &EncryptedExtensions{
		Extensions: []Extension{},
	}
	data, err = Marshal(msg)
	if err != nil {
		return conn.internalErrorf("marshal failed: %v", err)
	}
	conn.Debugf(" > EncryptedExtensions: %v bytes\n", len(data))
	err = conn.writeHandshakeMsg(HTEncryptedExtensions, data)
	if err != nil {
		return conn.internalErrorf("write failed: %v", err)
	}

	// Certificate.
	msgCertificate := &Certificate{
		CertificateList: []CertificateEntry{
			CertificateEntry{
				Data: conn.serverCert.Raw,
			},
		},
	}
	data, err = Marshal(msgCertificate)
	if err != nil {
		return conn.internalErrorf("marshal failed: %v", err)
	}
	conn.Debugf(" > Certificate: %v bytes\n", len(data))
	err = conn.writeHandshakeMsg(HTCertificate, data)
	if err != nil {
		return conn.internalErrorf("write failed: %v", err)
	}

	// CertificateVerify.
	hashFunc := crypto.SHA256
	digest := conn.certificateVerify(hashFunc)
	signature, err := conn.serverKey.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		return conn.internalErrorf("signature failed: %v", err)
	}
	msgCertVerify := &CertificateVerify{
		Algorithm: conn.signatureSchemes[0],
		Signature: signature,
	}
	data, err = Marshal(msgCertVerify)
	if err != nil {
		return conn.internalErrorf("marshal failed: %v", err)
	}
	conn.Debugf(" > CertificateVerify: %v bytes\n", len(data))
	err = conn.writeHandshakeMsg(HTCertificateVerify, data)
	if err != nil {
		return conn.internalErrorf("write failed: %v", err)
	}

	// Finished.
	verifyData := conn.finished(true)
	var vd32 [32]byte
	copy(vd32[0:], verifyData)
	finished := &Finished{
		VerifyData: vd32,
	}
	data, err = Marshal(finished)
	if err != nil {
		return conn.internalErrorf("marshal failed: %v", err)
	}
	conn.Debugf(" > Finished: %v bytes\n", len(data))
	err = conn.writeHandshakeMsg(HTFinished, data)
	if err != nil {
		return conn.internalErrorf("write failed: %v", err)
	}
	conn.handshakeState = HSServerDone

	// Server handshake done. We could now derive the server
	// application keys but since we won't send any data before the
	// client handshake is finished below, we can derive the
	// application keys once the handshake is complete. Please, note
	// that the client Finished is encrypted with the handshake keys.

	transcript := conn.transcript.Sum(nil)

	// Server handshake done. Read client messages until Finished to
	// complete the handshake.
	for conn.handshakeState != HSDone {
		_, data, err := conn.readHandshakeMsg()
		if err != nil {
			return fmt.Errorf("%w: %v", AlertHandshakeFailure, err)
		}
		err = conn.recvClientHandshake(data)
		if err != nil {
			return err
		}
	}

	err = conn.deriveKeys(true, transcript)
	if err != nil {
		return conn.internalErrorf("key derivation failed: %v", err)
	}

	return nil
}

func (conn *Conn) Read(p []byte) (n int, err error) {
	if conn.readCipher == nil {
		return 0, errors.New("handshake not completed")
	}

	for len(conn.appData) == 0 {
		if conn.readEOF {
			return 0, io.EOF
		}
		ct, data, err := conn.ReadRecord()
		if err != nil {
			return 0, err
		}
		switch ct {
		case CTAlert:
			err = conn.recvAlert(data)
			if err != nil {
				return 0, err
			}

		case CTApplicationData:
			conn.appData = data

		case CTHandshake:
			err = conn.recvServerHandshake(data, nil, nil)
			if err != nil {
				return 0, err
			}

		default:
			return 0, conn.alertf(AlertUnexpectedMessage, "received %v", ct)
		}
	}

	n = copy(p, conn.appData)
	conn.appData = conn.appData[n:]

	return n, nil
}

func (conn *Conn) Write(p []byte) (int, error) {
	if conn.writeCipher == nil {
		return 0, errors.New("handshake not completed")
	}

	err := conn.WriteRecord(CTApplicationData, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements io.Closer.Close.
func (conn *Conn) Close() error {
	conn.alert(AlertCloseNotify)
	return conn.conn.Close()
}

// LocalAddr implements net.Conn.LocalAddr.
func (conn *Conn) LocalAddr() net.Addr {
	return conn.conn.LocalAddr()
}

// RemoteAddr implements net.Conn.RemoteAddr.
func (conn *Conn) RemoteAddr() net.Addr {
	return conn.conn.RemoteAddr()
}

// SetDeadline implements net.Conn.SetDeadline.
func (conn *Conn) SetDeadline(t time.Time) error {
	return conn.conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn.SetReadDeadline.
func (conn *Conn) SetReadDeadline(t time.Time) error {
	return conn.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline.
func (conn *Conn) SetWriteDeadline(t time.Time) error {
	return conn.conn.SetWriteDeadline(t)
}

func (conn *Conn) recvClientHandshake(data []byte) error {
	if len(data) < 4 {
		return conn.decodeErrorf("truncated handshake")
	}
	typeLen := bo.Uint32(data)
	ht := HandshakeType(typeLen >> 24)
	length := typeLen & 0xffffff
	if int(length+4) != len(data) {
		return conn.decodeErrorf(
			"handshake length mismatch: got %v, expected %v",
			length+4, len(data))
	}
	switch conn.handshakeState {
	case HSClientHello:
		if ht == HTClientHello {
			return conn.recvClientHello(data)
		}
	case HSServerDone:
		switch ht {
		case HTCertificate:
			conn.transcript.Write(data)
			return conn.internalErrorf("client %v not implemented yet", ht)

		case HTCertificateVerify:
			conn.transcript.Write(data)
			return conn.internalErrorf("client %v not implemented yet", ht)

		case HTFinished:
			return conn.recvFinished(true, data)
		}
	}
	return conn.illegalParameterf("%s: invalid handshake message: %v",
		conn.handshakeState, ht)
}

func (conn *Conn) recvClientHello(data []byte) error {
	conn.clientHello = new(ClientHello)
	err := Unmarshal(data, conn.clientHello)
	if err != nil {
		return conn.decodeErrorf("failed to decode client_hello: %v", err)
	}

	// Clear all negotiation parameters from the initial ClientHello.
	conn.versions = nil
	conn.cipherSuites = nil
	conn.groups = nil
	conn.signatureSchemes = nil

	conn.Debugf(" < client_hello:\n")
	conn.Debugf(" - random: %x\n", conn.clientHello.Random)

	conn.Debugf(" - cipher_suites: {")
	var col int
	for _, suite := range conn.clientHello.CipherSuites {
		if supportedCipherSuites[suite] {
			conn.cipherSuites = append(conn.cipherSuites, suite)
		}

		name, ok := tls13CipherSuites[suite]
		if col%12 == 0 || ok {
			conn.Debugf("\n     ")
			col = 0
		} else {
			conn.Debugf(" ")
		}
		if ok {
			conn.Debugf("%v", name)
		} else {
			conn.Debugf("%04x", int(suite))
		}
		col++
	}
	if col > 0 {
		conn.Debugf("\n")
	}
	conn.Debugf("   }\n")

	conn.Debugf(" - legacy_compression_methods: {")
	col = 0
	for _, method := range conn.clientHello.LegacyCompressionMethods {
		if col%12 == 0 {
			conn.Debugf("\n     ")
			col = 0
		} else {
			conn.Debugf(" ")
		}
		conn.Debugf("%02x", method)
		col++
	}
	if col > 0 {
		conn.Debugf("\n")
	}
	conn.Debugf("   }\n")

	conn.Debugf(" - extensions: {")
	col = 0
	for _, ext := range conn.clientHello.Extensions {
		switch ext.Type {
		case ETServerName:
			if len(ext.Data) < 2 {
				return conn.decodeErrorf("%v: invalid data", ext.Type)
			}
			ll := int(bo.Uint16(ext.Data))
			if 2+ll != len(ext.Data) {
				return conn.decodeErrorf("%v: invalid data", ext.Type)
			}
			for i := 2; i < len(ext.Data); {
				var name ServerName
				n, err := UnmarshalFrom(ext.Data[i:], &name)
				if err != nil {
					return conn.decodeErrorf("%v: invalid data: %v",
						ext.Type, err)
				}
				conn.serverNames = append(conn.serverNames,
					string(name.Hostname))
				i += n
			}

		case ETSupportedGroups:
			arr, err := ext.Uint16List(2)
			if err != nil {
				return conn.decodeErrorf("invalid extension: %v", err)
			}
			for _, el := range arr {
				v := NamedGroup(el)
				if supportedGroups[v] {
					conn.groups = append(conn.groups, v)
				}
			}

		case ETSignatureAlgorithms:
			arr, err := ext.Uint16List(2)
			if err != nil {
				return conn.decodeErrorf("invalid extension: %v", err)
			}
			for _, el := range arr {
				v := SignatureScheme(el)
				if supportedSignatureSchemes[v] {
					conn.signatureSchemes = append(conn.signatureSchemes, v)
				}
			}

		case ETSupportedVersions:
			arr, err := ext.Uint16List(1)
			if err != nil {
				return conn.decodeErrorf("invalid extension: %v", err)
			}
			for _, el := range arr {
				v := ProtocolVersion(el)
				if supportedVersions[v] {
					conn.versions = append(conn.versions, v)
				}
			}

		case ETKeyShare:
			if len(ext.Data) < 2 {
				return conn.decodeErrorf("%v: invalid data", ext.Type)
			}
			ll := int(bo.Uint16(ext.Data))
			if 2+ll != len(ext.Data) {
				return conn.decodeErrorf("%v: invalid data", ext.Type)
			}
			for i := 2; i < len(ext.Data); {
				var entry KeyShareEntry
				n, err := UnmarshalFrom(ext.Data[i:], &entry)
				if err != nil {
					return conn.decodeErrorf("%v: invalid data: %v",
						ext.Type, err)
				}
				if supportedGroups[entry.Group] && conn.peerKeyShare == nil {
					conn.peerKeyShare = entry.Clone()
				}
				i += n
			}
		}

		_, ok := tls13Extensions[ext.Type]
		if col%12 == 0 || ok {
			conn.Debugf("\n     ")
			col = 0
		} else {
			conn.Debugf(" ")
		}
		col++

		if ok {
			conn.Debugf("%v", ext)
			col = 12
		} else {
			conn.Debugf("%v", ext)
		}
	}
	if col > 0 {
		conn.Debugf("\n")
	}
	conn.Debugf("   }\n")

	conn.Debugf(" - versions        : %v\n", conn.versions)
	conn.Debugf(" - cipherSuites    : %v\n", conn.cipherSuites)
	conn.Debugf(" - groups          : %v\n", conn.groups)
	conn.Debugf(" - signatureSchemes: %v\n", conn.signatureSchemes)
	conn.Debugf(" - peerKeyShare    : %v\n", conn.peerKeyShare)

	if len(conn.versions) == 0 {
		return conn.alert(AlertProtocolVersion)
	}
	if len(conn.cipherSuites) == 0 || len(conn.groups) == 0 ||
		len(conn.signatureSchemes) == 0 {
		return conn.alert(AlertHandshakeFailure)
	}
	if len(conn.clientHello.LegacyCompressionMethods) != 1 ||
		conn.clientHello.LegacyCompressionMethods[0] != 0 {
		return conn.illegalParameterf("invalid legacy_compression_methods: %v",
			conn.clientHello.LegacyCompressionMethods)
	}

	return nil
}

func (conn *Conn) recvFinished(server bool, data []byte) error {
	var finished Finished

	err := Unmarshal(data, &finished)
	if err != nil {
		return err
	}
	conn.Debugf(" < finished:\n")
	conn.Debugf(" - verify_data: %x\n", finished.VerifyData)

	// When computing our expected peer verification code, reverse our
	// role flag server.
	verifyData := conn.finished(!server)
	conn.Debugf(" - computed   : %x\n", verifyData)

	if bytes.Compare(finished.VerifyData[:], verifyData) != 0 {
		return conn.alert(AlertDecryptError)
	}

	if server {
		conn.handshakeState = HSDone
	} else {
		conn.handshakeState = HSServerDone
	}

	conn.transcript.Write(data)

	return nil
}

func (conn *Conn) recvServerHandshake(data []byte, ecdhCurve ecdh.Curve,
	ecdhPriv *ecdh.PrivateKey) error {

	if len(data) < 4 {
		return conn.decodeErrorf("truncated handshake")
	}
	typeLen := bo.Uint32(data)
	ht := HandshakeType(typeLen >> 24)
	length := typeLen & 0xffffff
	if int(length+4) != len(data) {
		return conn.decodeErrorf(
			"handshake length mismatch: got %v, expected %v",
			length+4, len(data))
	}
	switch conn.handshakeState {
	case HSServerHello:
		switch ht {
		case HTServerHello:
			return conn.recvServerHello(data, ecdhCurve, ecdhPriv)

		case HTEncryptedExtensions:
			return conn.recvEncryptedExtensions(data)

		case HTCertificate:
			return conn.recvCertificate(data)

		case HTCertificateVerify:
			return conn.recvCertificateVerify(data)

		case HTFinished:
			return conn.recvFinished(false, data)
		}

	case HSDone:
		switch ht {
		case HTNewSessionTicket:
			return conn.recvNewSessionTicket(data)
		}
	}
	return conn.illegalParameterf("%s: invalid handshake message: %v",
		conn.handshakeState, ht)
}

func (conn *Conn) recvServerHello(data []byte, ecdhCurve ecdh.Curve,
	ecdhPriv *ecdh.PrivateKey) error {

	conn.Debugf(" < server_hello:\n")

	serverHello := new(ServerHello)

	err := Unmarshal(data, serverHello)
	if err != nil {
		return conn.decodeErrorf("failed to decode server_hello: %v", err)
	}

	if bytes.Compare(serverHello.Random[:], HelloRetryRequestRandom[:]) == 0 {
		// No further algorithms to select.
		conn.Debugf(" - random: HelloRetryRequestRandom\n")
		return conn.alert(AlertHandshakeFailure)
	}
	// If negotiating TLS 1.2, TLS 1.3 servers MUST set the last 8 bytes of
	// their Random value to the bytes:
	//
	//   44 4F 57 4E 47 52 44 01
	//
	// If negotiating TLS 1.1 or below, TLS 1.3 servers MUST, and TLS 1.2
	// servers SHOULD, set the last 8 bytes of their ServerHello.Random
	// value to the bytes:
	//
	//   44 4F 57 4E 47 52 44 00
	//
	// TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below
	// MUST check that the last 8 bytes are not equal to either of these
	// values.  TLS 1.2 clients SHOULD also check that the last 8 bytes are
	// not equal to the second value if the ServerHello indicates TLS 1.1 or
	// below.  If a match is found, the client MUST abort the handshake with
	// an "illegal_parameter" alert.  This mechanism provides limited
	// protection against downgrade attacks over and above what is provided
	// by the Finished exchange: because the ServerKeyExchange, a message
	// present in TLS 1.2 and below, includes a signature over both random
	// values, it is not possible for an active attacker to modify the
	// random values without detection as long as ephemeral ciphers are
	// used.  It does not provide downgrade protection when static RSA
	// is used.
	conn.Debugf(" - random: %x\n", serverHello.Random)

	if bytes.Compare(serverHello.LegacySessionID,
		conn.clientHello.LegacySessionID) != 0 {
		return conn.illegalParameterf("legacy_session_id_echo mismatch")
	}
	conn.Debugf(" - cipher_suite: %v\n", serverHello.CipherSuite)
	if serverHello.LegacyCompressionMethod != 0 {
		return conn.illegalParameterf("invalid legacy_compression_method: %v",
			serverHello.LegacyCompressionMethod)
	}
	err = conn.processServerExtensions(serverHello.Extensions)
	if err != nil {
		return err
	}
	if conn.peerKeyShare == nil {
		return conn.missingExceptionf("key_share")
	}
	if len(conn.versions) == 0 {
		return conn.missingExceptionf("supported_versions")
	}
	if conn.versions[0] != VersionTLS13 {
		return conn.alert(AlertProtocolVersion)
	}

	ecdhServerPub, err := ecdhCurve.NewPublicKey(conn.peerKeyShare.KeyExchange)
	if err != nil {
		return conn.decodeErrorf("invalid client public key: %v", err)
	}
	conn.sharedSecret, err = ecdhPriv.ECDH(ecdhServerPub)
	if err != nil {
		return conn.decodeErrorf("ECDH failed: %v", err)
	}

	conn.transcript.Write(data)
	err = conn.deriveHandshakeKeys(false)
	if err != nil {
		return err
	}

	return nil
}

func (conn *Conn) recvEncryptedExtensions(data []byte) error {
	conn.Debugf(" < encrypted_extensions\n")

	encryptedExtensions := new(EncryptedExtensions)
	err := Unmarshal(data, encryptedExtensions)
	if err != nil {
		return conn.decodeErrorf("failed to decode encrypted_extensions: %v",
			err)
	}
	err = conn.processServerExtensions(encryptedExtensions.Extensions)
	if err != nil {
		return err
	}
	// XXX check which encrypted extensions are allowed

	conn.transcript.Write(data)

	return nil
}

func (conn *Conn) recvCertificate(data []byte) error {
	conn.Debugf(" < certificate\n")

	certificate := new(Certificate)
	err := Unmarshal(data, certificate)
	if err != nil {
		return conn.decodeErrorf("failed to decode certificate: %v", err)
	}
	if len(certificate.CertificateList) == 0 {
		return conn.alert(AlertCertificateRequired)
	}
	eeCert := certificate.CertificateList[0]
	conn.peerCert, err = x509.ParseCertificate(eeCert.Data)
	if err != nil {
		return conn.alert(AlertBadCertificate)
	}

	conn.Debugf(" - PublicKeyAlgorithm: %v\n", conn.peerCert.PublicKeyAlgorithm)

	conn.transcript.Write(data)

	return nil
}

func (conn *Conn) recvCertificateVerify(data []byte) error {
	conn.Debugf(" < certificate_verify\n")

	verify := new(CertificateVerify)
	err := Unmarshal(data, verify)
	if err != nil {
		return conn.decodeErrorf("failed to decode certificate_verify: %v", err)
	}

	conn.Debugf(" - SignatureScheme: %v\n", verify.Algorithm)

	var hashFunc crypto.Hash
	switch verify.Algorithm {
	case SigSchemeRsaPkcs1Sha256, SigSchemeEcdsaSecp256r1Sha256,
		SigSchemeRsaPssRsaeSha256, SigSchemeRsaPssPssSha256:
		hashFunc = crypto.SHA256

	case SigSchemeRsaPkcs1Sha384, SigSchemeEcdsaSecp384r1Sha384,
		SigSchemeRsaPssRsaeSha384, SigSchemeRsaPssPssSha384:
		hashFunc = crypto.SHA384

	case SigSchemeRsaPkcs1Sha512, SigSchemeEcdsaSecp521r1Sha512,
		SigSchemeRsaPssRsaeSha512, SigSchemeRsaPssPssSha512:
		hashFunc = crypto.SHA512

	default:
		conn.alert(AlertUnsupportedCertificate)
	}

	var verifyPubkeyAlg x509.PublicKeyAlgorithm
	switch verify.Algorithm {
	case SigSchemeEcdsaSecp256r1Sha256, SigSchemeEcdsaSecp384r1Sha384,
		SigSchemeEcdsaSecp521r1Sha512:
		verifyPubkeyAlg = x509.ECDSA

	case SigSchemeRsaPkcs1Sha1, SigSchemeRsaPkcs1Sha256,
		SigSchemeRsaPkcs1Sha384, SigSchemeRsaPkcs1Sha512,
		SigSchemeRsaPssPssSha256, SigSchemeRsaPssPssSha384,
		SigSchemeRsaPssPssSha512, SigSchemeRsaPssRsaeSha256,
		SigSchemeRsaPssRsaeSha384, SigSchemeRsaPssRsaeSha512:
		verifyPubkeyAlg = x509.RSA

	default:
		conn.alert(AlertUnsupportedCertificate)
	}
	_ = verifyPubkeyAlg

	digest := conn.certificateVerify(hashFunc)

	var pubkeyAlg x509.PublicKeyAlgorithm
	var verifyResult bool

	switch pub := conn.peerCert.PublicKey.(type) {
	case *rsa.PublicKey:
		pubkeyAlg = x509.RSA
		switch verify.Algorithm {
		case SigSchemeRsaPkcs1Sha1, SigSchemeRsaPkcs1Sha256,
			SigSchemeRsaPkcs1Sha384, SigSchemeRsaPkcs1Sha512:
			err = rsa.VerifyPKCS1v15(pub, hashFunc, digest, verify.Signature)
			if err != nil {
				conn.Debugf(" - VerifyPKCSv15 failed: %v\n", err)
			} else {
				verifyResult = true
			}

		case SigSchemeRsaPssPssSha256, SigSchemeRsaPssPssSha384,
			SigSchemeRsaPssPssSha512, SigSchemeRsaPssRsaeSha256,
			SigSchemeRsaPssRsaeSha384, SigSchemeRsaPssRsaeSha512:
			err = rsa.VerifyPSS(pub, hashFunc, digest, verify.Signature, nil)
			if err != nil {
				conn.Debugf(" - VerifyPSS failed: %v\n", err)
			} else {
				verifyResult = true
			}

		default:
			return conn.alert(AlertUnsupportedCertificate)
		}

	case *dsa.PublicKey:
		conn.Debugf(" - DSA public key\n")
		pubkeyAlg = x509.DSA
		return conn.alert(AlertUnsupportedCertificate)

	case *ecdsa.PublicKey:
		pubkeyAlg = x509.ECDSA
		verifyResult = ecdsa.VerifyASN1(pub, digest, verify.Signature)

	case ed25519.PublicKey:
		conn.Debugf(" - Ed25519 public key\n")
		pubkeyAlg = x509.Ed25519
		return conn.alert(AlertUnsupportedCertificate)

	default:
		return conn.alert(AlertUnsupportedCertificate)
	}
	if !verifyResult {
		conn.Debugf(" - certificate verification failed\n")
		return conn.alert(AlertDecryptError)
	}

	if verifyPubkeyAlg != pubkeyAlg {
		conn.Debugf(" - verifyPubkeyAlg=%v does not match pubkeyAlg=%v",
			verifyPubkeyAlg, pubkeyAlg)
		return conn.alert(AlertBadCertificate)
	}

	// XXX conn.serverCert.Verify()

	conn.transcript.Write(data)

	return nil
}

func (conn *Conn) recvNewSessionTicket(data []byte) error {
	conn.Debugf(" < new_session_ticket\n")

	ticket := new(NewSessionTicket)
	err := Unmarshal(data, ticket)
	if err != nil {
		return conn.decodeErrorf("failed to decode new_session_ticket: %v", err)
	}
	conn.Debugf(" - ticket_lifetime: %d\n", ticket.TicketLifetime)
	conn.Debugf(" - ticket_age_add : %d\n", ticket.TicketAgeAdd)
	conn.Debugf(" - ticket_nonce   : %x\n", ticket.TicketNonce)
	conn.Debugf(" - ticket         : %x\n", ticket.Ticket)

	err = conn.processServerExtensions(ticket.Extensions)
	if err != nil {
		return err
	}

	// XXX handle NewSessionTicket

	return nil
}

func (conn *Conn) processServerExtensions(extensions []Extension) error {
	conn.Debugf(" - extensions: {")
	col := 0
	for _, ext := range extensions {
		switch ext.Type {
		case ETSupportedVersions:
			if len(ext.Data) != 2 {
				return conn.illegalParameterf("invalid supported_versions: %v",
					ext)
			}
			conn.versions = append(conn.versions,
				ProtocolVersion(bo.Uint16(ext.Data)))

		case ETKeyShare:
			keyShare := new(KeyShareEntry)
			err := Unmarshal(ext.Data, keyShare)
			if err != nil {
				return conn.illegalParameterf("invalid key_share: %v", err)
			}
			conn.peerKeyShare = keyShare
		}
		_, ok := tls13Extensions[ext.Type]
		if col%12 == 0 || ok {
			conn.Debugf("\n     ")
			col = 0
		} else {
			conn.Debugf(" ")
		}
		col++

		if ok {
			conn.Debugf("%v", ext)
			col = 12
		} else {
			conn.Debugf("%v", ext)
		}
	}
	if col > 0 {
		conn.Debugf("\n")
	}
	conn.Debugf("   }\n")

	return nil
}

func (conn *Conn) recvChangeCipherSpec(data []byte) error {
	if len(data) != 1 || data[0] != 1 {
		return conn.decodeErrorf("invalid change_cipher_spec")
	}
	conn.Debugf(" < change_cipher_spec\n")

	return nil
}

func (conn *Conn) recvAlert(data []byte) error {
	if len(data) != 2 {
		return conn.decodeErrorf("invalid alert")
	}
	desc := AlertDescription(data[1])
	conn.Debugf(" < alert: %v: %v\n", desc.Level(), desc)

	if desc == AlertCloseNotify {
		conn.readEOF = true
	} else if desc.Level() == AlertLevelFatal {
		conn.conn.Close()
	}

	return nil
}
