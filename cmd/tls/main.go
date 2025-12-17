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
	"time"

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

	tsStart := time.Now()

	err = conn.ClientHandshake()
	if err != nil {
		log.Fatal(err)
	}

	tsHandshake := time.Now()

	_, err = conn.Write([]byte("Hello, world!\n"))
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

	tsEnd := time.Now()

	fmt.Printf("handshake: %v\n", tsHandshake.Sub(tsStart))
	fmt.Printf("req/resp : %v\n", tsEnd.Sub(tsHandshake))
	fmt.Printf("roundtrip: %v\n", tsEnd.Sub(tsStart))
}
