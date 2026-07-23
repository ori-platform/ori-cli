// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnsureKeypairCreatesKeypairFiles(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	pubHex, generated, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}
	if !generated {
		t.Fatal("expected generated=true for new keypair")
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

func TestEnsureKeypairReusesExistingValidPair(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	first, generated, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("first EnsureKeypair failed: %v", err)
	}
	if !generated {
		t.Fatal("expected generated=true on first call")
	}

	second, generated2, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("second EnsureKeypair failed: %v", err)
	}
	if generated2 {
		t.Fatal("expected generated=false when reusing existing pair")
	}
	if first != second {
		t.Fatal("expected same public key on reuse")
	}
}

func TestEnsureKeypairForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	first, _, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("first EnsureKeypair failed: %v", err)
	}

	second, generated, err := ks.EnsureKeypair(true)
	if err != nil {
		t.Fatalf("force EnsureKeypair failed: %v", err)
	}
	if !generated {
		t.Fatal("expected generated=true for force overwrite")
	}
	if first == second {
		t.Fatal("expected new keypair after force overwrite")
	}
}

func TestEnsureKeypairDetectsMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	_, _, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}

	pubPath := filepath.Join(dir, PublicKeyFile)
	if err := os.WriteFile(pubPath, []byte("deadbeef\n"), 0o644); err != nil {
		t.Fatalf("corrupt public key: %v", err)
	}

	_, _, err = ks.EnsureKeypair(false)
	if err == nil {
		t.Fatal("expected error for mismatched pair")
	}
	if !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("expected inconsistent pair error, got: %v", err)
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

func TestEnsureKeypairCreatesKeyDirectory(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested", "ori")
	ks := KeyStore{Dir: nested}

	if _, _, err := ks.EnsureKeypair(false); err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}

	if _, err := os.Stat(nested); err != nil {
		t.Fatalf("key directory was not created: %v", err)
	}
}

func TestEnsureKeypairEmptyDirectoryFails(t *testing.T) {
	ks := KeyStore{}
	_, _, err := ks.EnsureKeypair(false)
	if err == nil {
		t.Fatal("expected EnsureKeypair to fail with empty directory")
	}
}

func TestLoadPrivateKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	pubHex, _, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}

	priv, err := ks.LoadPrivateKey()
	if err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}
	if hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != pubHex {
		t.Fatal("loaded private key does not match stored public key")
	}
}

func TestEnsureKeypairRecoversPartialPrivateCommit(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	oldPub, _, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("first EnsureKeypair failed: %v", err)
	}

	privPath := filepath.Join(dir, PrivateKeyFile)
	pubPath := filepath.Join(dir, PublicKeyFile)
	privBak := filepath.Join(dir, privateKeyBackupFile)
	pubBak := filepath.Join(dir, publicKeyBackupFile)

	// Simulate an interrupted force overwrite: backup exists, final private was
	// committed, final public is missing.
	if err := os.Rename(privPath, privBak); err != nil {
		t.Fatalf("backup private: %v", err)
	}
	if err := os.Rename(pubPath, pubBak); err != nil {
		t.Fatalf("backup public: %v", err)
	}
	if err := os.WriteFile(privPath, []byte("new-private-stub"), 0o600); err != nil {
		t.Fatalf("write partial private: %v", err)
	}

	recovered, generated, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("recovery EnsureKeypair failed: %v", err)
	}
	if generated {
		t.Fatal("expected recovery to reuse existing pair, not generate")
	}
	if recovered != oldPub {
		t.Fatalf("recovered public key = %q, want %q", recovered, oldPub)
	}
	if _, err := ks.loadValidPair(); err != nil {
		t.Fatalf("recovered pair is not loadable: %v", err)
	}
}

func TestEnsureKeypairRecoversFromBackupsWhenFinalFilesMissing(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	oldPub, _, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("first EnsureKeypair failed: %v", err)
	}

	privPath := filepath.Join(dir, PrivateKeyFile)
	pubPath := filepath.Join(dir, PublicKeyFile)
	privBak := filepath.Join(dir, privateKeyBackupFile)
	pubBak := filepath.Join(dir, publicKeyBackupFile)

	// Simulate an interrupted write after backups were taken but before any
	// final file was renamed into place.
	if err := os.Rename(privPath, privBak); err != nil {
		t.Fatalf("backup private: %v", err)
	}
	if err := os.Rename(pubPath, pubBak); err != nil {
		t.Fatalf("backup public: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".device.key.tmp.123"), []byte("temp"), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}

	recovered, generated, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("recovery EnsureKeypair failed: %v", err)
	}
	if generated {
		t.Fatal("expected recovery to reuse existing pair, not generate")
	}
	if recovered != oldPub {
		t.Fatalf("recovered public key = %q, want %q", recovered, oldPub)
	}
}

func TestEnsureKeypairForceRemovesBackupsOnSuccess(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	if _, _, err := ks.EnsureKeypair(false); err != nil {
		t.Fatalf("first EnsureKeypair failed: %v", err)
	}

	if _, _, err := ks.EnsureKeypair(true); err != nil {
		t.Fatalf("force EnsureKeypair failed: %v", err)
	}

	if fileExists(filepath.Join(dir, privateKeyBackupFile)) {
		t.Fatal("private backup should be removed after successful force overwrite")
	}
	if fileExists(filepath.Join(dir, publicKeyBackupFile)) {
		t.Fatal("public backup should be removed after successful force overwrite")
	}
}

func TestEnsureKeypairRecoversPartialInitialCreation(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	// Simulate an interrupted initial write: final private was committed but
	// final public was not, and no backup exists.
	privPath := filepath.Join(dir, PrivateKeyFile)
	if err := os.WriteFile(privPath, []byte("partial-private-stub"), 0o600); err != nil {
		t.Fatalf("write partial private: %v", err)
	}

	pubHex, generated, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("recovery EnsureKeypair failed: %v", err)
	}
	if !generated {
		t.Fatal("expected recovery to generate a fresh pair after partial initial creation")
	}
	if len(pubHex) != 64 {
		t.Fatalf("public key hex length = %d, want 64", len(pubHex))
	}
	if _, err := ks.loadValidPair(); err != nil {
		t.Fatalf("recovered pair is not loadable: %v", err)
	}
}
