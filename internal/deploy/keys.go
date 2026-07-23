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

	if err := ks.writePair(priv, pubHex); err != nil {
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

func (ks KeyStore) writePair(priv ed25519.PrivateKey, pubHex string) error {
	privPath := filepath.Join(ks.Dir, PrivateKeyFile)
	pubPath := filepath.Join(ks.Dir, PublicKeyFile)

	privTmp, err := ks.writeTempPrivateKey(priv)
	if err != nil {
		return err
	}
	pubTmp, err := ks.writeTempPublicKey(pubHex)
	if err != nil {
		_ = os.Remove(privTmp)
		return err
	}

	if err := os.Rename(privTmp, privPath); err != nil {
		_ = os.Remove(privTmp)
		_ = os.Remove(pubTmp)
		return fmt.Errorf("commit private key: %w", err)
	}
	if err := os.Rename(pubTmp, pubPath); err != nil {
		_ = os.Remove(pubPath)
		return fmt.Errorf("commit public key: %w", err)
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
