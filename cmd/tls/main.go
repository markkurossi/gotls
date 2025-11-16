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
	"strings"

	"github.com/markkurossi/gotls/crypto/tls"
)

func main() {
	fDebug := flag.Bool("d", false, "debug output")
	flag.Parse()

	if len(flag.Args()) != 1 {
		log.Fatalf("not target specified")
	}

	target := flag.Args()[0]

	c, err := net.Dial("tcp", target)
	if err != nil {
		log.Fatal(err)
	}
	config := &tls.Config{
		Debug: *fDebug,
	}
	idx := strings.IndexByte(target, ':')
	if idx > 0 {
		config.ServerName = target[:idx]
	}

	conn := tls.NewConnection(c, config)

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
