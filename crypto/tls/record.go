//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

// ReadRecord reads a record layer record.
func (conn *Connection) ReadRecord() (ContentType, []byte, error) {
	// Read record header.
	for i := 0; i < 5; {
		n, err := conn.conn.Read(conn.rbuf[i:5])
		if err != nil {
			return CTInvalid, nil, err
		}
		i += n
	}
	ct := ContentType(conn.rbuf[0])
	legacyVersion := ProtocolVersion(bo.Uint16(conn.rbuf[1:3]))
	length := int(bo.Uint16(conn.rbuf[3:5]))

	conn.Debugf("<< %s %s[%d]\n", legacyVersion, ct, length)

	for i := 0; i < length; {
		n, err := conn.conn.Read(conn.rbuf[i:length])
		if err != nil {
			return CTInvalid, nil, err
		}
		i += n
	}

	data := conn.rbuf[:length]
	var err error

	if ct == CTApplicationData {
		if conn.readCipher == nil {
			return CTInvalid, nil, conn.alert(AlertUnexpectedMessage)
		}
		ct, data, err = conn.readCipher.Decrypt(data)
		if err != nil {
			return CTInvalid, nil, conn.alert(AlertBadRecordMAC)
		}
	}

	return ct, data, nil
}

// WriteRecord writes a record layer record.
func (conn *Connection) WriteRecord(ct ContentType, data []byte) error {
	if conn.writeCipher != nil {
		data = conn.writeCipher.Encrypt(ct, data)
		ct = CTApplicationData
	}

	var hdr [5]byte

	hdr[0] = byte(ct)
	bo.PutUint16(hdr[1:3], uint16(VersionTLS12))
	bo.PutUint16(hdr[3:5], uint16(len(data)))

	conn.Debugf(">> WriteRecord: %v[%d]\n", ct, len(data))

	_, err := conn.conn.Write(hdr[:])
	if err != nil {
		return err
	}
	_, err = conn.conn.Write(data)
	return err
}
