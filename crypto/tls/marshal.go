//
// Copyright (c) 2018-2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// MarshalTo encodes the value v to the buffer buf.
func MarshalTo(buf []byte, v interface{}) (int, error) {
	out := bytes.NewBuffer(buf)
	err := marshalValue(out, reflect.ValueOf(v), 0)
	if err != nil {
		return 0, err
	}
	return out.Len(), nil
}

// Marshal encodes the value v.
func Marshal(v interface{}) ([]byte, error) {
	out := new(bytes.Buffer)

	err := marshalValue(out, reflect.ValueOf(v), 0)
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func marshalValue(out *bytes.Buffer, value reflect.Value, length int) error {
	var buf [8]byte

	if !value.IsValid() {
		return nil
	}

	switch value.Type().Kind() {

	case reflect.Uint8:
		buf[0] = uint8(value.Uint())
		_, err := out.Write(buf[:1])
		return err

	case reflect.Int:
		binary.BigEndian.PutUint32(buf[:4], uint32(value.Int()))
		_, err := out.Write(buf[:4])
		return err

	case reflect.Uint16:
		binary.BigEndian.PutUint16(buf[:2], uint16(value.Uint()))
		_, err := out.Write(buf[:2])
		return err

	case reflect.Uint32:
		binary.BigEndian.PutUint32(buf[:4], uint32(value.Uint()))
		_, err := out.Write(buf[:4])
		return err

	case reflect.Uint64:
		binary.BigEndian.PutUint64(buf[:8], value.Uint())
		_, err := out.Write(buf[:8])
		return err

	case reflect.Int64:
		binary.BigEndian.PutUint64(buf[:8], uint64(value.Int()))
		_, err := out.Write(buf[:8])
		return err

	case reflect.Slice:
		if length < 1 || length > 4 {
			return fmt.Errorf("invalid length %v", length)
		}
		lofs := out.Len()
		for i := 0; i < length; i++ {
			if err := out.WriteByte(0); err != nil {
				return err
			}
		}
		if value.CanAddr() && value.Type().Elem().Kind() == reflect.Uint8 {
			_, err := out.Write(value.Bytes())
			if err != nil {
				return err
			}
		} else {
			for i := 0; i < value.Len(); i++ {
				if err := marshalValue(out, value.Index(i), 0); err != nil {
					return err
				}
			}
		}
		count := uint(out.Len() - lofs - length)
		data := out.Bytes()
		switch length {
		case 1:
			data[lofs] = byte(count)
		case 2:
			binary.BigEndian.PutUint16(data[lofs:], uint16(count))
		case 3:
			data[lofs+0] = byte(count >> 16)
			data[lofs+1] = byte(count >> 8)
			data[lofs+2] = byte(count)
		case 4:
			binary.BigEndian.PutUint32(data[lofs:], uint32(count))
		}
		return nil

	case reflect.Array:
		if value.CanAddr() && value.Type().Elem().Kind() == reflect.Uint8 {
			_, err := out.Write(value.Bytes())
			return err
		}
		for i := 0; i < value.Len(); i++ {
			if err := marshalValue(out, value.Index(i), 0); err != nil {
				return err
			}
		}
		return nil

	case reflect.String:
		data := []byte(value.String())
		binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
		_, err := out.Write(buf[:4])
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err

	case reflect.Ptr:
		return marshalValue(out, reflect.Indirect(value), 0)

	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			tags := getTags(value, i)
			if tags.ignore {
				continue
			}
			err := marshalValue(out, value.Field(i), tags.length)
			if err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("unsupported type: %s", value.Type().Kind().String())
	}

	return nil
}

// UnmarshalFrom decodes the value v from the buffer buf.
func UnmarshalFrom(buf []byte, v interface{}) (int, error) {
	in := bytes.NewReader(buf)
	err := Unmarshal(in, v)
	if err != nil {
		return len(buf) - in.Len(), err
	}
	return len(buf) - in.Len(), nil
}

// Unmarshal decodes the value v from the reader in.
func Unmarshal(in *bytes.Reader, v interface{}) error {
	return unmarshalValue(in, reflect.ValueOf(v), 0)
}

func unmarshalValue(in *bytes.Reader, value reflect.Value, length int) (
	err error) {

	var buf [8]byte

	if !value.IsValid() {
		return nil
	}

	switch value.Type().Kind() {
	case reflect.Uint8:
		_, err = io.ReadFull(in, buf[:1])
		if err != nil {
			return
		}
		value.SetUint(uint64(buf[0]))

	case reflect.Int:
		_, err = io.ReadFull(in, buf[:4])
		if err != nil {
			return
		}
		value.SetInt(int64(binary.BigEndian.Uint32(buf[:4])))

	case reflect.Uint16:
		_, err = io.ReadFull(in, buf[:2])
		if err != nil {
			return
		}
		value.SetUint(uint64(binary.BigEndian.Uint16(buf[:2])))

	case reflect.Uint32:
		_, err = io.ReadFull(in, buf[:4])
		if err != nil {
			return
		}
		value.SetUint(uint64(binary.BigEndian.Uint32(buf[:4])))

	case reflect.Uint64:
		_, err = io.ReadFull(in, buf[:8])
		if err != nil {
			return
		}
		value.SetUint(binary.BigEndian.Uint64(buf[:8]))

	case reflect.Int64:
		_, err = io.ReadFull(in, buf[:8])
		if err != nil {
			return
		}
		value.SetInt(int64(binary.BigEndian.Uint64(buf[:8])))

	case reflect.Slice:
		if length < 1 || length > 4 {
			return fmt.Errorf("invalid length %v", length)
		}
		_, err = io.ReadFull(in, buf[:length])
		if err != nil {
			return
		}
		var count int
		switch length {
		case 1:
			count = int(buf[0])
		case 2:
			count = int(binary.BigEndian.Uint16(buf[:2]))
		case 3:
			c := uint(buf[0])
			c <<= 8
			c |= uint(buf[1])
			c <<= 8
			c |= uint(buf[2])
			count = int(c)
		case 4:
			count = int(binary.BigEndian.Uint32(buf[:4]))

		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			data := make([]byte, count)
			_, err := io.ReadFull(in, data)
			if err != nil {
				return err
			}
			value.SetBytes(data)
		} else {
			avail := in.Len()
			slice := reflect.MakeSlice(value.Type(), 0, count)
			for i := 0; avail-in.Len() < count; i++ {
				el := reflect.New(value.Type().Elem())
				if err := unmarshalValue(in, el, 0); err != nil {
					return err
				}
				slice = reflect.Append(slice, reflect.Indirect(el))
			}
			if avail-in.Len() != count {
				return fmt.Errorf("array size not multiple of items")
			}
			value.Set(slice)
		}

	case reflect.Array:
		count := value.Len()
		array := reflect.Indirect(reflect.New(value.Type()))
		for i := 0; i < count; i++ {
			el := reflect.New(value.Type().Elem())
			if err := unmarshalValue(in, el, 0); err != nil {
				return err
			}
			array.Index(i).Set(reflect.Indirect(el))
		}
		value.Set(array)

	case reflect.String:
		_, err := io.ReadFull(in, buf[:4])
		if err != nil {
			return err
		}
		count := binary.BigEndian.Uint32(buf[:4])
		data := make([]byte, count)
		_, err = io.ReadFull(in, data)
		if err != nil {
			return err
		}
		value.SetString(string(data))

	case reflect.Ptr:
		pointed := reflect.Indirect(value)
		if !pointed.IsValid() {
			pointed = reflect.New(value.Type().Elem())
			value.Set(pointed)
		}
		return unmarshalValue(in, pointed, 0)

	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			tags := getTags(value, i)
			if tags.ignore {
				continue
			}
			err = unmarshalValue(in, value.Field(i), tags.length)
			if err != nil {
				return
			}
		}

	default:
		return fmt.Errorf("unsupported type: %s", value.Type().Kind().String())
	}

	return
}

func getTags(value reflect.Value, i int) tags {
	t := tags{}
	structField := value.Type().Field(i)

	tags := structField.Tag.Get("tls")
	for _, tag := range strings.Split(tags, ",") {
		switch tag {
		case "-":
			t.ignore = true
		case "u8":
			t.length = 1
		case "u16":
			t.length = 2
		case "u24":
			t.length = 3
		case "u32":
			t.length = 4
		}
	}

	return t
}

type tags struct {
	ignore bool
	length int
}
