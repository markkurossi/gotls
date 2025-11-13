//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// ContentType specifies record layer record types.
type ContentType uint8

// Record layer record types.
const (
	CTInvalid          ContentType = 0
	CTChangeCipherSpec ContentType = 20
	CTAlert            ContentType = 21
	CTHandshake        ContentType = 22
	CTApplicationData  ContentType = 23
)

func (ct ContentType) String() string {
	name, ok := contentTypes[ct]
	if ok {
		return name
	}
	return fmt.Sprintf("{ContentType %d}", ct)
}

var contentTypes = map[ContentType]string{
	CTInvalid:          "invalid",
	CTChangeCipherSpec: "change_cipher_spec",
	CTAlert:            "alert",
	CTHandshake:        "handshake",
	CTApplicationData:  "application_data",
}

// ProtocolVersion defines TLS protocol version.
type ProtocolVersion uint16

// Version numbers.
const (
	VersionSSL30 ProtocolVersion = 0x0300
	VersionTLS10 ProtocolVersion = 0x0301
	VersionTLS11 ProtocolVersion = 0x0302
	VersionTLS12 ProtocolVersion = 0x0303
	VersionTLS13 ProtocolVersion = 0x0304
)

func (v ProtocolVersion) String() string {
	name, ok := protocolVersions[v]
	if ok {
		return name
	}
	return fmt.Sprintf("%04x", uint(v))
}

// Bytes returns the protocol encoding of the group.
func (v ProtocolVersion) Bytes() []byte {
	buf := make([]byte, 2)
	bo.PutUint16(buf, uint16(v))
	return buf
}

var protocolVersions = map[ProtocolVersion]string{
	0x0300: "SSL 3.0",
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3",
}

// HandshakeType defines handshake message types.
type HandshakeType uint8

// Handshake message types.
const (
	HTClientHello HandshakeType = iota + 1
	HTServerHello
	_
	HTNewSessionTicket
	HTEndOfEarlyData
	_
	_
	HTEncryptedExtensions
	_
	_
	HTCertificate
	_
	HTCertificateRequest
	_
	HTCertificateVerify
	_
	_
	_
	_
	HTFinished
	_
	_
	_
	HTKeyUpdate

	HTMessageHash HandshakeType = 254
)

func (ht HandshakeType) String() string {
	name, ok := handshakeTypes[ht]
	if ok {
		return name
	}
	return fmt.Sprintf("{HandshakeType %d}", ht)
}

var handshakeTypes = map[HandshakeType]string{
	HTClientHello:         "client_hello",
	HTServerHello:         "server_hello",
	HTNewSessionTicket:    "new_session_ticket",
	HTEndOfEarlyData:      "end_of_early_data",
	HTEncryptedExtensions: "encrypted_extensions",
	HTCertificate:         "certificate",
	HTCertificateRequest:  "certificate_request",
	HTCertificateVerify:   "certificate_verify",
	HTFinished:            "finished",
	HTKeyUpdate:           "key_update",
	HTMessageHash:         "message_hash",
}

// ClientHello implements the client_hello message.
type ClientHello struct {
	HandshakeTypeLen         uint32
	LegacyVersion            ProtocolVersion
	Random                   [32]byte
	LegacySessionID          []byte        `tls:"u8"`
	CipherSuites             []CipherSuite `tls:"u16"`
	LegacyCompressionMethods []byte        `tls:"u8"`
	Extensions               []Extension   `tls:"u16"`
}

// ServerHello implements the server_hello message.
type ServerHello struct {
	HandshakeTypeLen        uint32
	LegacyVersion           ProtocolVersion
	Random                  [32]byte
	LegacySessionID         []byte `tls:"u8"`
	CipherSuite             CipherSuite
	LegacyCompressionMethod byte
	Extensions              []Extension `tls:"u16"`
}

// HelloRetryRequestRandom defines the well-known value of the
// HelloRetryRequest's Random field.
var HelloRetryRequestRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// EncryptedExtensions implements the encrypted_extensions handshake
// message.
type EncryptedExtensions struct {
	HandshakeTypeLen uint32
	Extensions       []Extension `tls:"u16"`
}

// Certificate implements the certificate handshake message.
type Certificate struct {
	HandshakeTypeLen          uint32
	CertificateRequestContext []byte             `tls:"u8"`
	CertificateList           []CertificateEntry `tls:"u24"`
}

// CertificateEntry defines a certificate entry in the Certificate
// message.
type CertificateEntry struct {
	Data       []byte      `tls:"u24"`
	Extensions []Extension `tls:"u16"`
}

// CertificateVerify implements the certificate_verify handshake
// message.
type CertificateVerify struct {
	HandshakeTypeLen uint32
	Algorithm        SignatureScheme
	Signature        []byte `tls:"u16"`
}

// Finished implements the finished handshake message.
type Finished struct {
	HandshakeTypeLen uint32
	VerifyData       [32]byte
}

// CipherSuite defines cipher suites.
type CipherSuite uint16

// TLS 1.3 mandatory cipher suites.
const (
	CipherTLSAes128GcmSha256        CipherSuite = 0x1301
	CipherTLSAes256GcmSha384        CipherSuite = 0x1302
	CipherTLSChacha20Poly1305Sha256 CipherSuite = 0x1303
)

func (cs CipherSuite) String() string {
	name, ok := tls13CipherSuites[cs]
	if ok {
		return name
	}
	return fmt.Sprintf("{CipherSuite 0x%02x,0x%02x}", int(cs>>8), int(cs&0xff))
}

var tls13CipherSuites = map[CipherSuite]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

// Hash returns the cipher suite's hash function.
func (cs CipherSuite) Hash() hash.Hash {
	switch cs {
	case CipherTLSAes128GcmSha256, CipherTLSChacha20Poly1305Sha256:
		return sha256.New()

	case CipherTLSAes256GcmSha384:
		return sha512.New384()

	default:
		fmt.Printf("CipherSuite.Hash: default SHA-256 for %v", cs)
		return sha256.New()
	}
}

// NamedGroup defines named key exchange groups.
type NamedGroup uint16

// Named groups.
const (
	GroupSecp256r1      NamedGroup = 0x0017
	GroupSecp384r1      NamedGroup = 0x0018
	GroupSecp521r1      NamedGroup = 0x0019
	GroupX25519         NamedGroup = 0x001D
	GroupX448           NamedGroup = 0x001E
	GroupFfdhe2048      NamedGroup = 0x0100
	GroupFfdhe3072      NamedGroup = 0x0101
	GroupFfdhe4096      NamedGroup = 0x0102
	GroupFfdhe6144      NamedGroup = 0x0103
	GroupFfdhe8192      NamedGroup = 0x0104
	GroupX25519MLKEM768 NamedGroup = 0x11EC
)

func (group NamedGroup) String() string {
	name, ok := tls13NamedGroups[group]
	if ok {
		return name
	}
	return fmt.Sprintf("%04x", int(group))
}

// Bytes returns the protocol encoding of the group.
func (group NamedGroup) Bytes() []byte {
	buf := make([]byte, 2)
	bo.PutUint16(buf, uint16(group))
	return buf
}

var tls13NamedGroups = map[NamedGroup]string{
	GroupSecp256r1:      "secp256r1",
	GroupSecp384r1:      "secp384r1",
	GroupSecp521r1:      "secp521r1",
	GroupX25519:         "x25519",
	GroupX25519MLKEM768: "X25519MLKEM768",
}

// SignatureScheme defines the signature algorithms for the
// signature_algorithms and signature_algorithms_cert extensions.
type SignatureScheme uint16

// Signature algorithms.
const (
	SigSchemeRsaPkcs1Sha256       SignatureScheme = 0x0401
	SigSchemeRsaPkcs1Sha384       SignatureScheme = 0x0501
	SigSchemeRsaPkcs1Sha512       SignatureScheme = 0x0601
	SigSchemeEcdsaSecp256r1Sha256 SignatureScheme = 0x0403
	SigSchemeEcdsaSecp384r1Sha384 SignatureScheme = 0x0503
	SigSchemeEcdsaSecp521r1Sha512 SignatureScheme = 0x0603
	SigSchemeRsaPssRsaeSha256     SignatureScheme = 0x0804
	SigSchemeRsaPssRsaeSha384     SignatureScheme = 0x0805
	SigSchemeRsaPssRsaeSha512     SignatureScheme = 0x0806
	SigSchemeEd25519              SignatureScheme = 0x0807
	SigSchemeEd448                SignatureScheme = 0x0808
	SigSchemeRsaPssPssSha256      SignatureScheme = 0x0809
	SigSchemeRsaPssPssSha384      SignatureScheme = 0x080a
	SigSchemeRsaPssPssSha512      SignatureScheme = 0x080b
	SigSchemeRsaPkcs1Sha1         SignatureScheme = 0x0201
	SigSchemeEcdsaSha1            SignatureScheme = 0x0203
)

func (scheme SignatureScheme) String() string {
	name, ok := tls13SignatureSchemes[scheme]
	if ok {
		return name
	}

	return fmt.Sprintf("%04x", int(scheme))
}

var tls13SignatureSchemes = map[SignatureScheme]string{
	SigSchemeRsaPkcs1Sha256:       "rsa_pkcs1_sha256",
	SigSchemeRsaPssRsaeSha256:     "rsa_pss_rsae_sha256",
	SigSchemeEcdsaSecp256r1Sha256: "ecdsa_secp256r1_sha256",
}

// KeyShareEntry defines a key_share extension entry.
type KeyShareEntry struct {
	Group       NamedGroup
	KeyExchange []byte `tls:"u16"`
}

func (key KeyShareEntry) String() string {
	return fmt.Sprintf("%v=%x", key.Group, key.KeyExchange)
}

// Clone creates an independent copy of the KeyShareEntry.
func (key KeyShareEntry) Clone() *KeyShareEntry {
	result := &KeyShareEntry{
		Group:       key.Group,
		KeyExchange: make([]byte, len(key.KeyExchange)),
	}
	copy(result.KeyExchange, key.KeyExchange)

	return result
}

// Bytes returns the key share entry's protocol encoding.
func (key KeyShareEntry) Bytes() []byte {
	data, err := Marshal(key)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal KeyShareEntry: %v", err))
	}
	return data
}

// ServerName defines a server_name extension.
type ServerName struct {
	NameType uint8
	Hostname []byte `tls:"u16"`
}

// Extension defines protocol extensions.
type Extension struct {
	Type ExtensionType
	Data []byte `tls:"u16"`
}

// NewExtension creates a new protocol extension.
func NewExtension(t ExtensionType, values ...interface{}) Extension {
	var buf [4]byte
	var result bytes.Buffer

	var ll int
	switch t {
	case ETSupportedGroups, ETSignatureAlgorithms, ETKeyShare:
		ll = 2
	case ETSupportedVersions:
		ll = 1
	default:
		panic(fmt.Sprintf("NewExtension: unknown ExtensionType: %v", t))
	}

	for i := 0; i < ll; i++ {
		result.WriteByte(0)
	}
	for _, val := range values {
		switch v := val.(type) {
		case NamedGroup:
			bo.PutUint16(buf[0:2], uint16(v))
			result.Write(buf[0:2])

		case SignatureScheme:
			bo.PutUint16(buf[0:2], uint16(v))
			result.Write(buf[0:2])

		case ProtocolVersion:
			bo.PutUint16(buf[0:2], uint16(v))
			result.Write(buf[0:2])

		case *KeyShareEntry:
			data, err := Marshal(v)
			if err != nil {
				panic(fmt.Sprintf("failed to marshal KeyShareEntry: %v", err))
			}
			result.Write(data)

		default:
			panic(fmt.Sprintf("unsupported extension value %T", v))
		}
	}

	// Set extension length field.
	l := result.Len() - ll
	data := result.Bytes()
	switch ll {
	case 1:
		data[0] = byte(l)
	case 2:
		bo.PutUint16(data[0:2], uint16(l))
	default:
		panic("invalid length")
	}

	return Extension{
		Type: t,
		Data: data,
	}
}

// Uint16List returns the extension value as a list of uint16
// values. The argument lsize specifies the list value length in
// bytes.
func (ext Extension) Uint16List(lsize int) ([]uint16, error) {
	if len(ext.Data) < lsize {
		return nil, fmt.Errorf("%s: truncated data", ext.Type)
	}
	var ll int
	var data []byte

	switch lsize {
	case 1:
		ll = int(ext.Data[0])
		data = ext.Data[1:]
	case 2:
		ll = int(bo.Uint16(ext.Data))
		data = ext.Data[2:]
	default:
		panic("invalid lsize")
	}
	if ll != len(data) {
		return nil, fmt.Errorf("%s: invalid data", ext.Type)
	}
	var result []uint16
	for i := 0; i < ll; i += 2 {
		result = append(result, bo.Uint16(data[i:]))
	}
	return result, nil
}

func (ext Extension) String() string {
	switch ext.Type {
	case ETServerName:
		if len(ext.Data) < 2 {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		result := fmt.Sprintf("%v:", ext.Type)

		ll := int(bo.Uint16(ext.Data))
		if 2+ll != len(ext.Data) {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		for i := 2; i < len(ext.Data); {
			var name ServerName
			n, err := UnmarshalFrom(ext.Data[i:], &name)
			if err != nil {
				return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
			}
			result += fmt.Sprintf(" %s", string(name.Hostname))
			i += n
		}
		return result

	case ETSupportedGroups:
		arr, err := ext.Uint16List(2)
		if err != nil {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		result := fmt.Sprintf("%v:", ext.Type)
		for _, v := range arr {
			result += fmt.Sprintf(" %v", NamedGroup(v))
		}
		return result

	case ETSignatureAlgorithms:
		arr, err := ext.Uint16List(2)
		if err != nil {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		result := fmt.Sprintf("%v:", ext.Type)
		for _, v := range arr {
			result += fmt.Sprintf(" %v", SignatureScheme(v))
		}
		return result

	case ETSupportedVersions:
		if len(ext.Data) < 2 {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		if len(ext.Data) == 2 {
			// ServerHello.
			return ProtocolVersion(bo.Uint16(ext.Data)).String()
		}
		arr, err := ext.Uint16List(1)
		if err != nil {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		result := fmt.Sprintf("%v:", ext.Type)
		for _, v := range arr {
			result += fmt.Sprintf(" %v", ProtocolVersion(v))
		}
		return result

	case ETKeyShare:
		if len(ext.Data) < 2 {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		if len(ext.Data) == 2 {
			// HelloRetryRequest.
			return NamedGroup(bo.Uint16(ext.Data)).String()
		}

		result := fmt.Sprintf("%v:", ext.Type)

		ll := int(bo.Uint16(ext.Data))
		if 2+ll != len(ext.Data) {
			// ServerHello key_share.
			var entry KeyShareEntry
			n, err := UnmarshalFrom(ext.Data, &entry)
			if err != nil || n != len(ext.Data) {
				return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
			}
			return fmt.Sprintf("%v[%d]", entry.Group, len(entry.KeyExchange))
		}

		for i := 2; i < len(ext.Data); {
			var entry KeyShareEntry
			n, err := UnmarshalFrom(ext.Data[i:], &entry)
			if err != nil {
				return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
			}
			result += fmt.Sprintf(" %v[%d]",
				entry.Group, len(entry.KeyExchange))
			i += n
		}
		return result

	default:
		return fmt.Sprintf("%04x", int(ext.Type))
	}
}

// ExtensionType defines the protocol extensions.
type ExtensionType uint16

// ExtensionTypes.
const (
	ETServerName                          ExtensionType = 0     // RFC 6066
	ETMaxFragmentLength                   ExtensionType = 1     // RFC 6066
	ETStatusRequest                       ExtensionType = 5     // RFC 6066
	ETSupportedGroups                     ExtensionType = 10    // RFC 8422 7919
	ETECPointFormats                      ExtensionType = 11    // RFC 8422
	ETSignatureAlgorithms                 ExtensionType = 13    // RFC 8446
	ETUseSRTP                             ExtensionType = 14    // RFC 5764
	ETHeartbeat                           ExtensionType = 15    // RFC 6520
	ETApplicationLayerProtocolNegotiation ExtensionType = 16    // RFC 7301
	ETSignedCertificateTimestamp          ExtensionType = 18    // RFC 6962
	ETClientCertificateType               ExtensionType = 19    // RFC 7250
	ETServerCertificateType               ExtensionType = 20    // RFC 7250
	ETPadding                             ExtensionType = 21    // RFC 7685
	ETExtendedMasterSecret                ExtensionType = 23    // RFC 7627
	ETCompressCertificate                 ExtensionType = 27    // RFC 8879
	ETSessionTicket                       ExtensionType = 35    // RFC 8446
	ETPreSharedKey                        ExtensionType = 41    // RFC 8446
	ETEarlyData                           ExtensionType = 42    // RFC 8446
	ETSupportedVersions                   ExtensionType = 43    // RFC 8446
	ETCookie                              ExtensionType = 44    // RFC 8446
	ETPSKKeyExchangeModes                 ExtensionType = 45    // RFC 8446
	ETCertificateAuthorities              ExtensionType = 47    // RFC 8446
	ETOIDFilters                          ExtensionType = 48    // RFC 8446
	ETPostHandshakeAuth                   ExtensionType = 49    // RFC 8446
	ETSignatureAlgorithmsCert             ExtensionType = 50    // RFC 8446
	ETKeyShare                            ExtensionType = 51    // RFC 8446
	ETRenegotiationInfo                   ExtensionType = 65281 // RFC 5746
)

func (et ExtensionType) String() string {
	name, ok := tls13Extensions[et]
	if ok {
		return name
	}
	name, ok = extensionTypeNames[et]
	if ok {
		return name
	}
	return fmt.Sprintf("{ExtensionType %d}", et)
}

var tls13Extensions = map[ExtensionType]string{
	ETServerName:          "server_name",
	ETSupportedVersions:   "supported_versions",
	ETSignatureAlgorithms: "signature_algorithms",
	ETSupportedGroups:     "supported_groups",
	ETKeyShare:            "key_share",
	ETPreSharedKey:        "pre_shared_key",
	ETPSKKeyExchangeModes: "psk_key_exchange_modes",
}

var extensionTypeNames = map[ExtensionType]string{
	ETServerName:                          "server_name",
	ETMaxFragmentLength:                   "max_fragment_length",
	ETStatusRequest:                       "status_request",
	ETECPointFormats:                      "ec_point_formats",
	ETUseSRTP:                             "use_srtp",
	ETHeartbeat:                           "heartbeat",
	ETApplicationLayerProtocolNegotiation: "applicationlayer_protocol_negotiation",
	ETSignedCertificateTimestamp:          "signed_certificate_timestamp",
	ETClientCertificateType:               "client_certificate_type",
	ETServerCertificateType:               "server_certificate_type",
	ETPadding:                             "padding",
	ETExtendedMasterSecret:                "extended_master_secret",
	ETCompressCertificate:                 "compress_certificate",
	ETSessionTicket:                       "session_ticket",
	ETEarlyData:                           "early_data",
	ETCookie:                              "cookie",
	ETCertificateAuthorities:              "certificate_authorities",
	ETOIDFilters:                          "oid_filters",
	ETPostHandshakeAuth:                   "post_handshake_auth",
	ETSignatureAlgorithmsCert:             "signature_algorithms_cert",
	ETRenegotiationInfo:                   "renegotiation_info",
}

// Alert defines alert messages.
type Alert struct {
	Level       AlertLevel
	Description AlertDescription
}

// AlertLevel defines alert severity
type AlertLevel uint8

func (level AlertLevel) String() string {
	switch level {
	case AlertLevelWarning:
		return "warning"
	case AlertLevelFatal:
		return "fatal"
	default:
		return fmt.Sprintf("{AlertLevel %d}", int(level))
	}
}

// Alert Levels.
const (
	AlertLevelWarning AlertLevel = 1
	AlertLevelFatal   AlertLevel = 2
)

// AlertDescription describes the alert.
type AlertDescription uint8

// Level returns the alert description's severity.
func (desc AlertDescription) Level() AlertLevel {
	if desc == 0 || desc == 90 {
		return AlertLevelWarning
	}
	return AlertLevelFatal
}

func (desc AlertDescription) String() string {
	name, ok := alertDescriptions[desc]
	if ok {
		return name
	}
	return fmt.Sprintf("{AlertDescription %d}", int(desc))
}

// Alert descriptions.
const (
	AlertCloseNotify                  AlertDescription = 0
	AlertUnexpectedMessage            AlertDescription = 10
	AlertBadRecordMAC                 AlertDescription = 20
	AlertRecordOverflow               AlertDescription = 22
	AlertHandshakeFailure             AlertDescription = 40
	AlertBadCertificate               AlertDescription = 42
	AlertUnsupportedCertificate       AlertDescription = 43
	AlertCertificateRevoked           AlertDescription = 44
	AlertCertificateExpired           AlertDescription = 45
	AlertCertificateUnknown           AlertDescription = 46
	AlertIllegalParameter             AlertDescription = 47
	AlertUnknownCA                    AlertDescription = 48
	AlertAccessDenied                 AlertDescription = 49
	AlertDecodeError                  AlertDescription = 50
	AlertDecryptError                 AlertDescription = 51
	AlertProtocolVersion              AlertDescription = 70
	AlertInsufficientSecurity         AlertDescription = 71
	AlertInternalError                AlertDescription = 80
	AlertInappropriateFallback        AlertDescription = 86
	AlertUserCanceled                 AlertDescription = 90
	AlertMissingExtension             AlertDescription = 109
	AlertUnsupportedExtension         AlertDescription = 110
	AlertUnrecognizedName             AlertDescription = 112
	AlertBadCertificateStatusResponse AlertDescription = 113
	AlertUnknownPSKIdentity           AlertDescription = 115
	AlertCertificateRequired          AlertDescription = 116
	AlertNoApplicationProtocol        AlertDescription = 120
)

var alertDescriptions = map[AlertDescription]string{
	AlertCloseNotify:                  "close_notify",
	AlertUnexpectedMessage:            "unexpected_message",
	AlertBadRecordMAC:                 "bad_record_mac",
	AlertRecordOverflow:               "record_overflow",
	AlertHandshakeFailure:             "handshake_failure",
	AlertBadCertificate:               "bad_certificate",
	AlertUnsupportedCertificate:       "unsupported_certificate",
	AlertCertificateRevoked:           "certificate_revoked",
	AlertCertificateExpired:           "certificate_expired",
	AlertCertificateUnknown:           "certificate_unknown",
	AlertIllegalParameter:             "illegal_parameter",
	AlertUnknownCA:                    "unknown_ca",
	AlertAccessDenied:                 "access_denied",
	AlertDecodeError:                  "decode_error",
	AlertDecryptError:                 "decrypt_error",
	AlertProtocolVersion:              "protocol_version",
	AlertInsufficientSecurity:         "insufficient_security",
	AlertInternalError:                "internal_error",
	AlertInappropriateFallback:        "inappropriate_fallback",
	AlertUserCanceled:                 "user_canceled",
	AlertMissingExtension:             "missing_extension",
	AlertUnsupportedExtension:         "unsupported_extension",
	AlertUnrecognizedName:             "unrecognized_name",
	AlertBadCertificateStatusResponse: "bad_certificate_status_response",
	AlertUnknownPSKIdentity:           "unknown_psk_identity",
	AlertCertificateRequired:          "certificate_required",
	AlertNoApplicationProtocol:        "no_application_protocol",
}
