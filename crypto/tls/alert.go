//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"fmt"
)

func (conn *Conn) alert(desc AlertDescription) error {
	var buf [2]byte

	buf[0] = byte(desc.Level())
	buf[1] = byte(desc)

	conn.Debugf(" > Alert: level=%v, desc=%v\n", desc.Level(), desc)

	err := conn.WriteRecord(CTAlert, buf[:])
	if err != nil {
		return fmt.Errorf("write %w failed: %w", desc, err)
	}
	if desc.Level() == AlertLevelWarning {
		return nil
	}

	err = conn.conn.Close()
	if err != nil {
		return fmt.Errorf("close after %w failed: %w", desc, err)
	}

	return desc
}

func (conn *Conn) alertf(desc AlertDescription, format string,
	a ...interface{}) error {

	err := conn.alert(desc)
	if err == nil {
		err = desc
	}

	msg := fmt.Errorf(format, a...)

	return fmt.Errorf("%s: %w", msg, err)
}

func (conn *Conn) decodeErrorf(msg string, a ...interface{}) error {
	return conn.alertf(AlertDecodeError, msg, a...)
}

func (conn *Conn) illegalParameterf(msg string, a ...interface{}) error {
	return conn.alertf(AlertIllegalParameter, msg, a...)
}

func (conn *Conn) missingExceptionf(msg string, a ...interface{}) error {
	return conn.alertf(AlertMissingExtension, msg, a...)
}

func (conn *Conn) internalErrorf(msg string, a ...interface{}) error {
	return conn.alertf(AlertInternalError, msg, a...)
}
