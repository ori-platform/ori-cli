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

// Generate creates a new Ed25519 keypair and writes the private and public keys
// to the configured directory. It returns the public key as a 64-character
// lowercase hex string. If either key file already exists and force is false,
// it returns an error without modifying the filesystem.
func (ks KeyStore) Generate(force bool) (string, error) {
	if ks.Dir == "" {
		return "", errors.New("key directory is not configured")
	}

	privPath := filepath.Join(ks.Dir, PrivateKeyFile)
	pubPath := filepath.Join(ks.Dir, PublicKeyFile)

	if !force {
		if _, err := os.Stat(privPath); err == nil {
			return "", fmt.Errorf("private key already exists at %s; use --force to overwrite", privPath)
		}
		if _, err := os.Stat(pubPath); err == nil {
			return "", fmt.Errorf("public key already exists at %s; use --force to overwrite", pubPath)
		}
	}

	if err := os.MkdirAll(ks.Dir, 0o700); err != nil {
		return "", fmt.Errorf("create key directory: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ed25519 keypair: %w", err)
	}

	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))

	if err := ks.writePrivateKey(priv); err != nil {
		return "", err
	}
	if err := ks.writePublicKey(pubHex); err != nil {
		return "", err
	}

	return pubHex, nil
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

func (ks KeyStore) writePrivateKey(priv ed25519.PrivateKey) error {
	path := filepath.Join(ks.Dir, PrivateKeyFile)

	marshalled, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: marshalled}

	tmp, err := os.CreateTemp(ks.Dir, ".device.key.tmp.")
	if err != nil {
		return fmt.Errorf("create temp private key file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := pem.Encode(tmp, block); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode private key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp private key file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("set private key permissions: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit private key: %w", err)
	}
	cleanup = false
	return nil
}

func (ks KeyStore) writePublicKey(pubHex string) error {
	path := filepath.Join(ks.Dir, PublicKeyFile)

	tmp, err := os.CreateTemp(ks.Dir, ".device.pub.tmp.")
	if err != nil {
		return fmt.Errorf("create temp public key file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.WriteString(pubHex + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write public key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp public key file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return fmt.Errorf("set public key permissions: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit public key: %w", err)
	}
	cleanup = false
	return nil
}
