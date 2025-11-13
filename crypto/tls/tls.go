//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
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

	_ io.ReadWriteCloser = &Connection{}
)

// Connection implements a TLS connection.
type Connection struct {
	conn net.Conn
	rbuf []byte

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
	sharedSecret     []byte
	handshakeSecret  []byte
	clientHSTr       []byte
	serverHSTr       []byte

	writeCipher *Cipher
	readCipher  *Cipher
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
func NewConnection(conn net.Conn) *Connection {
	return &Connection{
		conn: conn,
		rbuf: make([]byte, 65536),
	}
}

// Debugf prints debug output for the connection.
func (conn *Connection) Debugf(format string, a ...interface{}) {
	fmt.Printf(format, a...)
}

func (conn *Connection) readHandshakeMsg() (ContentType, []byte, error) {
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
			return CTInvalid, nil, conn.alert(AlertUnexpectedMessage)
		}
	}
}

func (conn *Connection) writeHandshakeMsg(ht HandshakeType, data []byte) error {
	// Set TypeLen
	typeLen := uint32(ht)<<24 | uint32(len(data)-4)
	bo.PutUint32(data[0:4], typeLen)

	conn.transcript.Write(data)

	return conn.WriteRecord(CTHandshake, data)
}

// ClientHandshake runs the client handshake protocol.
func (conn *Connection) ClientHandshake() error {
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
			NewExtension(ETSignatureAlgorithms, SigSchemeEcdsaSecp256r1Sha256,
				// XXX this is needed for www.google.com, check also SNI
				SigSchemeRsaPssRsaeSha256,
				// XXX is needed for some Amazon hosted services.
				SigSchemeRsaPkcs1Sha256),
			NewExtension(ETSupportedVersions, VersionTLS13),
			NewExtension(ETKeyShare, keyShare),
		},
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
	fmt.Printf(" > ClientHello: %v bytes\n", len(data))

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

	// XXX Finished

	return nil
}

// ServerHandshake runs the server handshake protocol.
func (conn *Connection) ServerHandshake(key *ecdsa.PrivateKey,
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
		fmt.Printf(" > HelloRetryRequest: %v bytes\n", len(data))

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
	fmt.Printf(" > ServerHello: %v bytes\n", len(data))

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
	fmt.Printf(" > EncryptedExtensions: %v bytes\n", len(data))
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
	fmt.Printf(" > Certificate: %v bytes\n", len(data))
	err = conn.writeHandshakeMsg(HTCertificate, data)
	if err != nil {
		return conn.internalErrorf("write failed: %v", err)
	}

	// CertificateVerify.
	signature, err := conn.serverCertificateVerify()
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
	fmt.Printf(" > CertificateVerify: %v bytes\n", len(data))
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
	fmt.Printf(" > Finished: %v bytes\n", len(data))
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

	// Server handshake done. Read client messages until Finished to
	// complete the handshake.
	for conn.handshakeState != HSDone {
		_, data, err := conn.readHandshakeMsg()
		err = conn.recvClientHandshake(data)
		if err != nil {
			return err
		}
	}

	err = conn.deriveKeys()
	if err != nil {
		return conn.internalErrorf("key derivation failed: %v", err)
	}

	return nil
}

func (conn *Connection) Read(p []byte) (n int, err error) {
	if conn.readCipher == nil {
		return 0, errors.New("handshake not completed")
	}

	for len(conn.appData) == 0 {
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

		default:
			return 0, conn.alert(AlertUnexpectedMessage)
		}
	}

	n = copy(p, conn.appData)
	conn.appData = conn.appData[n:]

	return n, nil
}

func (conn *Connection) Write(p []byte) (int, error) {
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
func (conn *Connection) Close() error {
	conn.alert(AlertCloseNotify)
	return conn.conn.Close()
}

func (conn *Connection) recvClientHandshake(data []byte) error {
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
			return conn.recvClientFinished(data)
		}
	}
	return conn.illegalParameterf("%s: invalid handshake message: %v",
		conn.handshakeState, ht)
}

func (conn *Connection) recvClientHello(data []byte) error {
	conn.clientHello = new(ClientHello)
	consumed, err := UnmarshalFrom(data, conn.clientHello)
	if err != nil {
		return conn.decodeErrorf("failed to decode client_hello: %v", err)
	}
	if consumed != len(data) {
		return conn.decodeErrorf("trailing data after client_hello: len=%v",
			len(data)-consumed)
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
		fmt.Println()
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
		fmt.Println()
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

	fmt.Printf(" - versions        : %v\n", conn.versions)
	fmt.Printf(" - cipherSuites    : %v\n", conn.cipherSuites)
	fmt.Printf(" - groups          : %v\n", conn.groups)
	fmt.Printf(" - signatureSchemes: %v\n", conn.signatureSchemes)
	fmt.Printf(" - peerKeyShare    : %v\n", conn.peerKeyShare)

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

func (conn *Connection) recvClientFinished(data []byte) error {
	var finished Finished

	consumed, err := UnmarshalFrom(data, &finished)
	if err != nil {
		return err
	}
	if consumed != len(data) {
		return conn.decodeErrorf("trailing data after client finished: len=%d",
			len(data)-consumed)
	}
	conn.Debugf(" < finished:\n")
	conn.Debugf(" - verify_data: %x\n", finished.VerifyData)

	verifyData := conn.finished(false)
	conn.Debugf(" - computed   : %x\n", verifyData)

	if bytes.Compare(finished.VerifyData[:], verifyData) != 0 {
		return conn.alert(AlertDecryptError)
	}

	conn.handshakeState = HSDone

	return nil
}

func (conn *Connection) recvServerHandshake(data []byte,
	ecdhCurve ecdh.Curve, ecdhPriv *ecdh.PrivateKey) error {

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
		case HTFinished:
			return conn.recvServerFinished(data)
		}
	}
	return conn.illegalParameterf("%s: invalid handshake message: %v",
		conn.handshakeState, ht)
}

func (conn *Connection) recvServerHello(data []byte,
	ecdhCurve ecdh.Curve, ecdhPriv *ecdh.PrivateKey) error {

	serverHello := new(ServerHello)

	consumed, err := UnmarshalFrom(data, serverHello)
	if err != nil {
		return conn.decodeErrorf("failed to decode server_hello: %v", err)
	}
	if consumed != len(data) {
		return conn.decodeErrorf("trailing data after server_hello: len=%v",
			len(data)-consumed)
	}

	conn.Debugf(" < server_hello:\n")
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
	conn.Debugf(" - extensions: {")
	col := 0
	for _, ext := range serverHello.Extensions {
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
			consumed, err := UnmarshalFrom(ext.Data, keyShare)
			if err != nil || consumed != len(ext.Data) {
				return conn.illegalParameterf("invalid key_share: %v (%v/%v)",
					err, consumed, len(ext.Data))
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

	if conn.peerKeyShare == nil {
		return conn.alert(AlertMissingExtension)
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

func (conn *Connection) recvServerFinished(data []byte) error {
	// XXX is this the same as recvClientFinished?
	return fmt.Errorf("recvServerFinished not implemented yet")
}

func (conn *Connection) recvChangeCipherSpec(data []byte) error {
	if len(data) != 1 || data[0] != 1 {
		return conn.decodeErrorf("invalid change_cipher_spec")
	}
	return nil
}

func (conn *Connection) recvAlert(data []byte) error {
	if len(data) != 2 {
		return conn.decodeErrorf("invalid alert")
	}
	desc := AlertDescription(data[1])
	fmt.Printf("alert: %v: %v\n", desc.Level(), desc)
	// XXX should terminate the connection etc.
	return nil
}
