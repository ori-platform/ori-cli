// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
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

func TestEnsureKeypairRejectsOverPermissiveExistingPrivateKey(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}
	if _, _, err := ks.EnsureKeypair(false); err != nil {
		t.Fatalf("first EnsureKeypair failed: %v", err)
	}

	privPath := filepath.Join(dir, PrivateKeyFile)
	if err := os.Chmod(privPath, 0o644); err != nil {
		t.Fatalf("make private key over-permissive: %v", err)
	}

	if _, _, err := ks.EnsureKeypair(false); err == nil {
		t.Fatal("expected over-permissive private key to fail closed")
	} else if !strings.Contains(err.Error(), "require 0600") {
		t.Fatalf("expected restrictive-permissions error, got %v", err)
	}
	info, err := os.Lstat(privPath)
	if err != nil {
		t.Fatalf("private key should remain for operator recovery: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("private key mode changed unexpectedly: got %04o", info.Mode().Perm())
	}
}

func TestEnsureKeypairRejectsSymlinkedPrivateKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires privileges on some Windows environments")
	}
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}
	if _, _, err := ks.EnsureKeypair(false); err != nil {
		t.Fatalf("first EnsureKeypair failed: %v", err)
	}

	privPath := filepath.Join(dir, PrivateKeyFile)
	targetPath := filepath.Join(dir, "external-device.key")
	if err := os.Rename(privPath, targetPath); err != nil {
		t.Fatalf("move private key target: %v", err)
	}
	if err := os.Symlink(targetPath, privPath); err != nil {
		t.Fatalf("create private key symlink: %v", err)
	}

	if _, _, err := ks.EnsureKeypair(false); err == nil {
		t.Fatal("expected symlinked private key to fail closed")
	} else if !strings.Contains(err.Error(), "regular non-symlink") {
		t.Fatalf("expected non-symlink error, got %v", err)
	}
	info, err := os.Lstat(privPath)
	if err != nil {
		t.Fatalf("lstat private key symlink: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("private key symlink should not be silently replaced")
	}
}

func TestEnsureKeypairRefusesConcurrentWriter(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprintf("force=%t", force), func(t *testing.T) {
			dir := t.TempDir()
			ks := KeyStore{Dir: dir}
			lock, err := ks.acquireLock()
			if err != nil {
				t.Fatalf("acquire first key store lock: %v", err)
			}

			if _, _, err := ks.EnsureKeypair(force); !errors.Is(err, errKeyStoreLocked) {
				t.Fatalf("concurrent EnsureKeypair error = %v, want key-store lock refusal", err)
			}
			assertPathMissing(t, filepath.Join(dir, PrivateKeyFile))
			assertPathMissing(t, filepath.Join(dir, PublicKeyFile))

			if err := lock.release(); err != nil {
				t.Fatalf("release first key store lock: %v", err)
			}
			if _, _, err := ks.EnsureKeypair(force); err != nil {
				t.Fatalf("EnsureKeypair after lock release failed: %v", err)
			}
		})
	}
}

func TestEnsureKeypairRejectsSymlinkedLockFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires privileges on some Windows environments")
	}
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}
	targetPath := filepath.Join(dir, "lock-target")
	if err := os.WriteFile(targetPath, []byte("do not chmod"), 0o644); err != nil {
		t.Fatalf("write lock target: %v", err)
	}
	if err := os.Symlink(targetPath, filepath.Join(dir, privateKeyLockFile)); err != nil {
		t.Fatalf("create lock symlink: %v", err)
	}

	if _, _, err := ks.EnsureKeypair(false); err == nil {
		t.Fatal("expected symlinked lock file to fail closed")
	} else if !strings.Contains(err.Error(), "regular non-symlink") {
		t.Fatalf("expected non-symlink lock error, got %v", err)
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("stat lock target: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("symlink target mode changed: got %04o, want 0644", info.Mode().Perm())
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

func TestEnsureKeypairForceCreatesWhenNoPairExists(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	pubHex, generated, err := ks.EnsureKeypair(true)
	if err != nil {
		t.Fatalf("force EnsureKeypair on empty store failed: %v", err)
	}
	if !generated {
		t.Fatal("expected generated=true for force on an empty store")
	}
	if len(pubHex) != 64 {
		t.Fatalf("public key hex length = %d, want 64", len(pubHex))
	}
	if _, err := ks.loadValidPair(); err != nil {
		t.Fatalf("generated pair is not loadable: %v", err)
	}
}

func TestEnsureKeypairRepairsPublicProjection(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	original, _, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}

	pubPath := filepath.Join(dir, PublicKeyFile)
	if err := os.WriteFile(pubPath, []byte("deadbeef\n"), 0o644); err != nil {
		t.Fatalf("corrupt public key: %v", err)
	}

	repaired, generated, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("repair mismatched public projection: %v", err)
	}
	if generated {
		t.Fatal("public projection repair must not rotate the private identity")
	}
	if repaired != original {
		t.Fatalf("repaired public key = %q, want original %q", repaired, original)
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

func TestEnsureKeypairRecoversCrashAfterPrivateBackup(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	oldPub, _, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("first EnsureKeypair failed: %v", err)
	}

	privPath := filepath.Join(dir, PrivateKeyFile)
	privBak := filepath.Join(dir, privateKeyBackupFile)

	// Simulate a crash immediately after the force path moves the authoritative
	// private key to its backup. The old public projection remains in place.
	if err := os.Rename(privPath, privBak); err != nil {
		t.Fatalf("backup private: %v", err)
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

func TestEnsureKeypairRecoversCrashAfterNewPrivateCommit(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	oldPub, _, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("first EnsureKeypair failed: %v", err)
	}

	privPath := filepath.Join(dir, PrivateKeyFile)
	privBak := filepath.Join(dir, privateKeyBackupFile)

	_, replacementPrivate, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate replacement keypair: %v", err)
	}
	replacementTemp, err := ks.writeTempPrivateKey(replacementPrivate)
	if err != nil {
		t.Fatalf("write replacement private temp: %v", err)
	}

	// Simulate a crash after the new private key reaches its final path but
	// before its public projection is committed.
	if err := os.Rename(privPath, privBak); err != nil {
		t.Fatalf("backup private: %v", err)
	}
	if err := os.Rename(replacementTemp, privPath); err != nil {
		t.Fatalf("commit replacement private: %v", err)
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

func TestEnsureKeypairFinalizesCommittedReplacement(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	if _, _, err := ks.EnsureKeypair(false); err != nil {
		t.Fatalf("first EnsureKeypair failed: %v", err)
	}

	privPath := filepath.Join(dir, PrivateKeyFile)
	pubPath := filepath.Join(dir, PublicKeyFile)
	privBak := filepath.Join(dir, privateKeyBackupFile)
	replacementPub, replacementPrivate, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate replacement keypair: %v", err)
	}
	replacementPrivTemp, err := ks.writeTempPrivateKey(replacementPrivate)
	if err != nil {
		t.Fatalf("write replacement private temp: %v", err)
	}
	replacementPubTemp, err := ks.writeTempPublicKey(replacementPub)
	if err != nil {
		t.Fatalf("write replacement public temp: %v", err)
	}

	// Simulate a crash after both final files are committed but before the old
	// private-key backup is removed.
	if err := os.Rename(privPath, privBak); err != nil {
		t.Fatalf("backup private: %v", err)
	}
	if err := os.Rename(replacementPrivTemp, privPath); err != nil {
		t.Fatalf("commit replacement private: %v", err)
	}
	if err := os.Rename(replacementPubTemp, pubPath); err != nil {
		t.Fatalf("commit replacement public: %v", err)
	}

	recovered, generated, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("recovery EnsureKeypair failed: %v", err)
	}
	if generated {
		t.Fatal("expected committed replacement to be reused, not generated")
	}
	if recovered != replacementPub {
		t.Fatalf("recovered public key = %q, want replacement %q", recovered, replacementPub)
	}
	assertPathMissing(t, privBak)
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

	assertPathMissing(t, filepath.Join(dir, privateKeyBackupFile))
}

func TestEnsureKeypairRepairsMissingPublicFromValidPrivate(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}

	original, _, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("first EnsureKeypair failed: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, PublicKeyFile)); err != nil {
		t.Fatalf("remove public projection: %v", err)
	}

	repaired, generated, err := ks.EnsureKeypair(false)
	if err != nil {
		t.Fatalf("recovery EnsureKeypair failed: %v", err)
	}
	if generated {
		t.Fatal("missing public projection must not rotate the private identity")
	}
	if repaired != original {
		t.Fatalf("repaired public key = %q, want original %q", repaired, original)
	}
	if _, err := ks.loadValidPair(); err != nil {
		t.Fatalf("recovered pair is not loadable: %v", err)
	}
}

func TestEnsureKeypairRejectsCorruptPrivateWithoutDeletingIt(t *testing.T) {
	dir := t.TempDir()
	ks := KeyStore{Dir: dir}
	privPath := filepath.Join(dir, PrivateKeyFile)
	corrupt := []byte("partial-private-stub")
	if err := os.WriteFile(privPath, corrupt, 0o600); err != nil {
		t.Fatalf("write corrupt private key: %v", err)
	}

	if _, _, err := ks.EnsureKeypair(false); err == nil {
		t.Fatal("expected corrupt authoritative private key to fail closed")
	}
	got, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("corrupt private key should remain for operator recovery: %v", err)
	}
	if string(got) != string(corrupt) {
		t.Fatalf("corrupt private key changed: got %q, want %q", got, corrupt)
	}
	assertPathMissing(t, filepath.Join(dir, PublicKeyFile))
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	exists, err := pathExists(path)
	if err != nil {
		t.Fatalf("inspect %s: %v", path, err)
	}
	if exists {
		t.Fatalf("expected %s to be absent", path)
	}
}
