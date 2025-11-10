//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestHandshakeType(t *testing.T) {
	if HTNewSessionTicket != 4 {
		t.Errorf("HTNewSessionTicket=%v, expected 4\n", HTNewSessionTicket)
	}
	if HTFinished != 20 {
		t.Errorf("HTFinished=%v, expected 20\n", HTFinished)
	}
}

func TestExtensions(t *testing.T) {
	ext := NewExtension(ETSupportedGroups, GroupSecp256r1, GroupSecp384r1,
		GroupSecp521r1, GroupX25519)
	fmt.Printf("ext: %v\n", ext)

	ext = NewExtension(ETSignatureAlgorithms, SigSchemeEcdsaSecp256r1Sha256)
	fmt.Printf("ext: %v\n", ext)

	ext = NewExtension(ETSupportedVersions, VersionTLS13)
	fmt.Printf("ext: %v (%x)\n", ext, ext.Data)
}

func TestKeyShareExtension(t *testing.T) {
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyShare := &KeyShareEntry{
		Group:       GroupSecp256r1,
		KeyExchange: privateKey.PublicKey().Bytes(),
	}

	ext := NewExtension(ETKeyShare, keyShare)
	fmt.Printf("ext: %v\n", ext)
}
