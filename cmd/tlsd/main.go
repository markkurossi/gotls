//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/markkurossi/gotls/crypto/tls"
)

var (
	keyPath  = "server-key.pem"
	certPath = "server-cert.pem"
)

var (
	indexHTML = []byte(`HTTP/1.1 200 OK

<html>
<body>
<h1>Hello, world!</h1>
</body>
</html>
`)
)

func main() {
	fDebug := flag.Bool("d", false, "debug output")
	httpd := flag.Bool("httpd", false, "Simple HTTPD")
	flag.Parse()

	priv, cert, err := loadKeyAndCert(keyPath, certPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Fatalf("failed to load key and cert: %v", err)
		}
		err = createKeyAndCert(keyPath, certPath)
		if err != nil {
			log.Fatalf("failed to create key and cert: %v", err)
		}
		priv, cert, err = loadKeyAndCert(keyPath, certPath)
		if err != nil {
			log.Fatalf("failed to load key and cert: %v", err)
		}
	}
	listener, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}

	for {
		c, err := listener.Accept()
		if err != nil {
			log.Printf("accept failed: %v\n", err)
			continue
		}
		conn := tls.NewConnection(c, &tls.Config{
			Debug: *fDebug,
		})
		go func(c *tls.Connection) {
			err := c.ServerHandshake(priv, cert)
			if err != nil {
				log.Printf("TLS handshake failed: %v", err)
				return
			}
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if err != nil {
					log.Printf("read: %v\n", err)
					return
				}
				fmt.Printf("read: %s\n", buf[:n])
				if *httpd {
					_, err = c.Write(indexHTML)
				} else {
					_, err = c.Write(buf[:n])
				}
				if err != nil {
					log.Printf("write: %v\n", err)
					return
				}
			}

		}(conn)
	}
}

func createKeyAndCert(keyPath, certPath string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// Generate a random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	// Certificate template
	template := x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		SerialNumber:       serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Ephemelier"},
			Country:      []string{"FI"},
			CommonName:   "ephemelier.com",
		},
		DNSNames:              []string{"www.ephemelier.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	err = pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err != nil {
		return err
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err != nil {
		return err
	}

	return nil
}

func loadKeyAndCert(keyPath, certPath string) (
	*ecdsa.PrivateKey, *x509.Certificate, error) {

	// Load certificate file.
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Load private key file.
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode private key PEM")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	privateKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not ECDSA, got %T",
			parsedKey)
	}

	// Verify that the private key matches the certificate's public key.
	certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("certificate public key is not ECDSA")
	}
	if !certPubKey.Equal(&privateKey.PublicKey) {
		return nil, nil,
			fmt.Errorf("private key does not match certificate public key")
	}

	return privateKey, cert, nil
}
