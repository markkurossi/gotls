//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"errors"
	"fmt"
)

func (conn *Connection) alert(desc AlertDescription) error {
	var buf [2]byte

	buf[0] = byte(desc.Level())
	buf[1] = byte(desc)

	fmt.Printf(" > Alert: level=%v, desc=%v\n", desc.Level(), desc)

	return conn.WriteRecord(CTAlert, buf[:])
}

func (conn *Connection) decodeErrorf(msg string, a ...interface{}) error {
	orig := fmt.Errorf(msg, a...)
	err := conn.alert(AlertDecodeError)
	if err != nil {
		return errors.Join(err, orig)
	}
	return orig
}

func (conn *Connection) illegalParameterf(msg string, a ...interface{}) error {
	orig := fmt.Errorf(msg, a...)
	err := conn.alert(AlertIllegalParameter)
	if err != nil {
		return errors.Join(err, orig)
	}
	return orig
}

func (conn *Connection) internalErrorf(msg string, a ...interface{}) error {
	orig := fmt.Errorf(msg, a...)
	err := conn.alert(AlertInternalError)
	if err != nil {
		return errors.Join(err, orig)
	}
	return orig
}
