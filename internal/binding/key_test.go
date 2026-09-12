// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/ori-platform/ori-cli/internal/binding"
)

func TestParsePrivateKeyReadsBothSpellings(t *testing.T) {
	c := loadCorpus(t)
	seed, err := hex.DecodeString(c.CommissioningSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	want := ed25519.NewKeyFromSeed(seed)

	fromHex, err := binding.ParsePrivateKey([]byte("  " + c.CommissioningSeedHex + "\n"))
	if err != nil || !fromHex.Equal(want) {
		t.Fatalf("hex seed: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(want)
	if err != nil {
		t.Fatal(err)
	}
	fromPEM, err := binding.ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil || !fromPEM.Equal(want) {
		t.Fatalf("PEM: %v", err)
	}
	pub, err := hex.DecodeString(c.CommissioningPublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	if binding.SigningKeyName(want.Public().(ed25519.PublicKey)) != "ed25519:"+base64.StdEncoding.EncodeToString(pub) {
		t.Fatal("the key name is not the form the corpus names it in")
	}
}

func TestParsePrivateKeyRefusesWithoutEchoing(t *testing.T) {
	c := loadCorpus(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"hex of the wrong length", []byte(c.CommissioningSeedHex[:62])},
		{"not hex", []byte(strings.Repeat("zz", 32))},
		{"raw seed bytes", []byte(strings.Repeat("\x33", 32))},
		{"pem without pkcs8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")})},
		{"pkcs8 of another algorithm", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: other})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := binding.ParsePrivateKey(tc.data)
			if err == nil {
				t.Fatal("parsed")
			}
			if len(tc.data) >= 16 && strings.Contains(err.Error(), string(tc.data[:16])) {
				t.Fatalf("the error echoes the input: %v", err)
			}
		})
	}
}
