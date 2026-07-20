// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGenerateCreatesKeypairFiles(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	pubHex, err := ks.Generate(false)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(pubHex) != 64 {
		t.Fatalf("public key hex length = %d, want 64", len(pubHex))
	}
	if _, err := hex.DecodeString(pubHex); err != nil {
		t.Fatalf("public key is not valid hex: %v", err)
	}

	privPath := filepath.Join(dir, PrivateKeyFile)
	pubPath := filepath.Join(dir, PublicKeyFile)

	privData, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	if !strings.Contains(string(privData), "BEGIN PRIVATE KEY") {
		t.Fatalf("private key does not contain PEM header: %s", privData)
	}

	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	if strings.TrimSpace(string(pubData)) != pubHex {
		t.Fatalf("public key file = %q, want %q", pubData, pubHex)
	}

	if runtime.GOOS != "windows" {
		privInfo, err := os.Stat(privPath)
		if err != nil {
			t.Fatalf("stat private key: %v", err)
		}
		if privInfo.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode = %o, want 0o600", privInfo.Mode().Perm())
		}

		pubInfo, err := os.Stat(pubPath)
		if err != nil {
			t.Fatalf("stat public key: %v", err)
		}
		if pubInfo.Mode().Perm() != 0o644 {
			t.Fatalf("public key mode = %o, want 0o644", pubInfo.Mode().Perm())
		}
	}
}

func TestGenerateRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	if _, err := ks.Generate(false); err != nil {
		t.Fatalf("first Generate failed: %v", err)
	}

	_, err := ks.Generate(false)
	if err == nil {
		t.Fatal("expected second Generate to fail without force")
	}
	if !strings.Contains(err.Error(), "use --force") {
		t.Fatalf("expected --force hint in error, got: %v", err)
	}
}

func TestGenerateForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	first, err := ks.Generate(false)
	if err != nil {
		t.Fatalf("first Generate failed: %v", err)
	}

	second, err := ks.Generate(true)
	if err != nil {
		t.Fatalf("force Generate failed: %v", err)
	}

	if first == second {
		t.Fatal("expected new keypair after force overwrite")
	}
}

func TestGenerateKeypairDoesNotWriteFiles(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		_ = os.Chdir(origDir)
	}()

	pubHex, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	if len(pubHex) != 64 {
		t.Fatalf("public key hex length = %d, want 64", len(pubHex))
	}
	if priv == nil {
		t.Fatal("expected private key")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files written, got %d", len(entries))
	}
}

func TestGenerateCreatesKeyDirectory(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested", "ori")
	ks := KeyStore{Dir: nested}

	if _, err := ks.Generate(false); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if _, err := os.Stat(nested); err != nil {
		t.Fatalf("key directory was not created: %v", err)
	}
}

func TestGenerateEmptyDirectoryFails(t *testing.T) {
	ks := KeyStore{}
	_, err := ks.Generate(false)
	if err == nil {
		t.Fatal("expected Generate to fail with empty directory")
	}
}

func TestPublicKeyReadsStoredKey(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	pubHex, err := ks.Generate(false)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	read, err := ks.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	if strings.TrimSpace(read) != pubHex {
		t.Fatalf("PublicKey = %q, want %q", read, pubHex)
	}
}
