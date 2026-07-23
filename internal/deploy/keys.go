// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// DefaultKeyDir is the directory under the user's home dir that holds
	// device key material. It mirrors the convention used by offline-token.pub.
	DefaultKeyDir = ".ori"

	// PrivateKeyFile is the on-disk filename for the device identity private key.
	PrivateKeyFile = "device.key"

	// PublicKeyFile is the on-disk filename for the device identity public key.
	PublicKeyFile = "device.pub"

	// privateKeyBackupFile and publicKeyBackupFile are used to snapshot an
	// existing pair during overwrite so a failed write can be rolled back without
	// rotating the identity key.
	privateKeyBackupFile = "device.key.bak"
	publicKeyBackupFile  = "device.pub.bak"
)

// KeyStore handles on-device generation and persistence of the device identity
// Ed25519 keypair. Private key material never leaves the directory it is stored
// in; callers are responsible for not transmitting it.
type KeyStore struct {
	// Dir is the directory where device.key and device.pub are written.
	// If empty, the store cannot be used.
	Dir string
}

// DefaultKeyStore returns a KeyStore rooted at ~/.ori.
func DefaultKeyStore() KeyStore {
	home, err := os.UserHomeDir()
	if err != nil {
		return KeyStore{}
	}
	return KeyStore{Dir: filepath.Join(home, DefaultKeyDir)}
}

// EnsureKeypair returns a usable device identity public key. If the keypair
// already exists and is a consistent pair, it is returned without rotation.
// If the keypair is missing, a new one is generated and stored. If force is
// true, any existing keypair is overwritten with a new one. The returned bool
// reports whether a new keypair was generated.
func (ks KeyStore) EnsureKeypair(force bool) (pubHex string, generated bool, err error) {
	if ks.Dir == "" {
		return "", false, errors.New("key directory is not configured")
	}

	// Recover from any previous interrupted write so the store is always in a
	// deterministically resumable state: either the old valid pair or no pair.
	if err := ks.recover(); err != nil {
		return "", false, fmt.Errorf("recover keypair state: %w", err)
	}

	privPath := filepath.Join(ks.Dir, PrivateKeyFile)
	pubPath := filepath.Join(ks.Dir, PublicKeyFile)

	privExists := fileExists(privPath)
	pubExists := fileExists(pubPath)

	if !force {
		if privExists && pubExists {
			if pubHex, err := ks.loadValidPair(); err == nil {
				return pubHex, false, nil
			}
			return "", false, fmt.Errorf("existing keypair is inconsistent; use --force to regenerate")
		}
		if privExists {
			return "", false, fmt.Errorf("private key already exists at %s; use --force to overwrite", privPath)
		}
		if pubExists {
			return "", false, fmt.Errorf("public key already exists at %s; use --force to overwrite", pubPath)
		}
	}

	if err := os.MkdirAll(ks.Dir, 0o700); err != nil {
		return "", false, fmt.Errorf("create key directory: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", false, fmt.Errorf("generate ed25519 keypair: %w", err)
	}

	pubHex = hex.EncodeToString(priv.Public().(ed25519.PublicKey))

	if err := ks.writePair(priv, pubHex, force); err != nil {
		return "", false, err
	}

	return pubHex, true, nil
}

// GenerateKeypair returns a freshly generated Ed25519 keypair without writing
// anything to disk. It is used by --dry-run flows.
func GenerateKeypair() (pubHex string, priv ed25519.PrivateKey, err error) {
	_, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	pubHex = hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	return pubHex, priv, nil
}

// PublicKey reads the persisted public key file and returns the hex string.
func (ks KeyStore) PublicKey() (string, error) {
	if ks.Dir == "" {
		return "", errors.New("key directory is not configured")
	}
	data, err := os.ReadFile(filepath.Join(ks.Dir, PublicKeyFile))
	if err != nil {
		return "", fmt.Errorf("read public key: %w", err)
	}
	return string(data), nil
}

// loadValidPair loads the private key, derives the public key, and compares it
// to the public key file. It returns the public key hex when the pair is
// consistent.
func (ks KeyStore) loadValidPair() (string, error) {
	priv, err := ks.LoadPrivateKey()
	if err != nil {
		return "", err
	}
	pubHexFile, err := ks.PublicKey()
	if err != nil {
		return "", err
	}
	pubHexFile = trimHex(pubHexFile)
	expectedHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	if pubHexFile != expectedHex {
		return "", fmt.Errorf("public key file does not match private key; use --force to regenerate")
	}
	return expectedHex, nil
}

// LoadPrivateKey reads and parses the persisted private key.
func (ks KeyStore) LoadPrivateKey() (ed25519.PrivateKey, error) {
	if ks.Dir == "" {
		return nil, errors.New("key directory is not configured")
	}
	data, err := os.ReadFile(filepath.Join(ks.Dir, PrivateKeyFile))
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key is not PEM encoded")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519, got %T", key)
	}
	return priv, nil
}

func (ks KeyStore) writePair(priv ed25519.PrivateKey, pubHex string, force bool) error {
	privPath := filepath.Join(ks.Dir, PrivateKeyFile)
	pubPath := filepath.Join(ks.Dir, PublicKeyFile)
	privBak := filepath.Join(ks.Dir, privateKeyBackupFile)
	pubBak := filepath.Join(ks.Dir, publicKeyBackupFile)

	// Snapshot any existing pair so we can roll back to it if the write fails.
	if force {
		if err := ks.backupExisting(privPath, privBak); err != nil {
			return fmt.Errorf("backup existing private key: %w", err)
		}
		if err := ks.backupExisting(pubPath, pubBak); err != nil {
			_ = ks.restoreBackup(privBak, privPath)
			return fmt.Errorf("backup existing public key: %w", err)
		}
	}

	privTmp, err := ks.writeTempPrivateKey(priv)
	if err != nil {
		ks.rollback(force)
		return err
	}
	pubTmp, err := ks.writeTempPublicKey(pubHex)
	if err != nil {
		_ = os.Remove(privTmp)
		ks.rollback(force)
		return err
	}

	if err := os.Rename(privTmp, privPath); err != nil {
		_ = os.Remove(privTmp)
		_ = os.Remove(pubTmp)
		ks.rollback(force)
		return fmt.Errorf("commit private key: %w", err)
	}
	if err := os.Rename(pubTmp, pubPath); err != nil {
		_ = os.Remove(pubTmp)
		ks.rollback(force)
		return fmt.Errorf("commit public key: %w", err)
	}

	// Success: remove the now-obsolete backup pair.
	if force {
		_ = os.Remove(privBak)
		_ = os.Remove(pubBak)
	}
	return nil
}

func (ks KeyStore) writeTempPrivateKey(priv ed25519.PrivateKey) (string, error) {
	marshalled, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: marshalled}

	tmp, err := os.CreateTemp(ks.Dir, ".device.key.tmp.")
	if err != nil {
		return "", fmt.Errorf("create temp private key file: %w", err)
	}
	tmpPath := tmp.Name()

	if err := pem.Encode(tmp, block); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("encode private key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close temp private key file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("set private key permissions: %w", err)
	}
	return tmpPath, nil
}

func (ks KeyStore) writeTempPublicKey(pubHex string) (string, error) {
	tmp, err := os.CreateTemp(ks.Dir, ".device.pub.tmp.")
	if err != nil {
		return "", fmt.Errorf("create temp public key file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.WriteString(pubHex + "\n"); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("write public key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close temp public key file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("set public key permissions: %w", err)
	}
	return tmpPath, nil
}

func trimHex(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// recover cleans up stale temp files and restores a consistent keypair state
// from backups if a previous write was interrupted. After recovery the store
// is in one of two states: both final files exist, or neither does.
func (ks KeyStore) recover() error {
	privPath := filepath.Join(ks.Dir, PrivateKeyFile)
	pubPath := filepath.Join(ks.Dir, PublicKeyFile)
	privBak := filepath.Join(ks.Dir, privateKeyBackupFile)
	pubBak := filepath.Join(ks.Dir, publicKeyBackupFile)

	_ = removeGlob(filepath.Join(ks.Dir, ".device.key.tmp.*"))
	_ = removeGlob(filepath.Join(ks.Dir, ".device.pub.tmp.*"))

	privExists := fileExists(privPath)
	pubExists := fileExists(pubPath)
	privBakExists := fileExists(privBak)
	pubBakExists := fileExists(pubBak)

	// Consistent final pair: remove any leftover backups and continue.
	if privExists && pubExists {
		_ = os.Remove(privBak)
		_ = os.Remove(pubBak)
		return nil
	}

	// Inconsistent final state. Restore the backup pair if we have one.
	if privBakExists && pubBakExists {
		if privExists {
			_ = os.Remove(privPath)
		}
		if pubExists {
			_ = os.Remove(pubPath)
		}
		if err := os.Rename(privBak, privPath); err != nil {
			return err
		}
		if err := os.Rename(pubBak, pubPath); err != nil {
			return err
		}
		return nil
	}

	// No usable backup; remove any partial final files and leftover backups.
	if privExists {
		_ = os.Remove(privPath)
	}
	if pubExists {
		_ = os.Remove(pubPath)
	}
	_ = os.Remove(privBak)
	_ = os.Remove(pubBak)
	return nil
}

// backupExisting moves src to dst if src exists, removing any stale dst first.
func (ks KeyStore) backupExisting(src, dst string) error {
	if !fileExists(src) {
		_ = os.Remove(dst)
		return nil
	}
	if fileExists(dst) {
		_ = os.Remove(dst)
	}
	return os.Rename(src, dst)
}

// restoreBackup moves backup back to final if the backup exists.
func (ks KeyStore) restoreBackup(backupPath, finalPath string) error {
	if !fileExists(backupPath) {
		return nil
	}
	if fileExists(finalPath) {
		_ = os.Remove(finalPath)
	}
	return os.Rename(backupPath, finalPath)
}

// rollback restores the backup pair when a force overwrite fails partway.
func (ks KeyStore) rollback(force bool) {
	if !force {
		return
	}
	privPath := filepath.Join(ks.Dir, PrivateKeyFile)
	pubPath := filepath.Join(ks.Dir, PublicKeyFile)
	privBak := filepath.Join(ks.Dir, privateKeyBackupFile)
	pubBak := filepath.Join(ks.Dir, publicKeyBackupFile)

	// If only one final file was committed, it is the new partial key and must
	// be removed so the old pair can be restored together.
	if fileExists(privPath) && !fileExists(pubPath) {
		_ = os.Remove(privPath)
	}
	if fileExists(pubPath) && !fileExists(privPath) {
		_ = os.Remove(pubPath)
	}

	_ = ks.restoreBackup(privBak, privPath)
	_ = ks.restoreBackup(pubBak, pubPath)
}

func removeGlob(pattern string) error {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	for _, m := range matches {
		_ = os.Remove(m)
	}
	return nil
}
