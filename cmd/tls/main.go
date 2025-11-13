//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/markkurossi/gotls/crypto/tls"
)

func main() {
	flag.Parse()

	if len(flag.Args()) != 1 {
		log.Fatalf("not target specified")
	}

	c, err := net.Dial("tcp", flag.Args()[0])
	if err != nil {
		log.Fatal(err)
	}
	conn := tls.NewConnection(c)

	err = conn.ClientHandshake()
	if err != nil {
		log.Fatal(err)
	}

	_, err = conn.Write([]byte("Hello, world!"))
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("read: %s\n", string(buf[:n]))
	err = conn.Close()
	if err != nil {
		log.Fatal(err)
	}
}
