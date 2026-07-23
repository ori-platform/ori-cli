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
	"io"
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

	// privateKeyBackupFile retains the previous authoritative private key until
	// both files for a forced replacement are durably committed.
	privateKeyBackupFile = "device.key.bak"

	privateKeyLockFile = ".device.key.lock"
)

var errKeyStoreLocked = errors.New("key store is locked by another deploy process")

// KeyStore handles on-device generation and persistence of the device identity
// Ed25519 keypair. Private key material never leaves the directory it is stored
// in; callers are responsible for not transmitting it.
type KeyStore struct {
	// Dir is the directory where device.key and device.pub are written.
	// If empty, the store cannot be used.
	Dir string
}

type keyStoreLock struct {
	file *os.File
}

func (ks KeyStore) acquireLock() (*keyStoreLock, error) {
	lockPath := filepath.Join(ks.Dir, privateKeyLockFile)
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open key store lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect open key store lock: %w", err)
	}
	pathInfo, err := os.Lstat(lockPath)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect key store lock path: %w", err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, pathInfo) {
		_ = file.Close()
		return nil, errors.New("key store lock must be a regular non-symlink file")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("set key store lock permissions: %w", err)
	}
	if err := lockFileNonBlocking(file); err != nil {
		_ = file.Close()
		if errors.Is(err, errKeyStoreLocked) {
			return nil, errKeyStoreLocked
		}
		return nil, fmt.Errorf("acquire key store lock: %w", err)
	}
	return &keyStoreLock{file: file}, nil
}

func (lock *keyStoreLock) release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := unlockFile(lock.file)
	closeErr := lock.file.Close()
	return errors.Join(unlockErr, closeErr)
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
	if err := os.MkdirAll(ks.Dir, 0o700); err != nil {
		return "", false, fmt.Errorf("create key directory: %w", err)
	}
	lock, err := ks.acquireLock()
	if err != nil {
		return "", false, err
	}
	defer func() {
		if releaseErr := lock.release(); releaseErr != nil && err == nil {
			pubHex = ""
			generated = false
			err = fmt.Errorf("release key store lock: %w", releaseErr)
		}
	}()

	// Recover from any previous interrupted write so the store is always in a
	// deterministically resumable state: either the old valid pair or no pair.
	if err := ks.recover(); err != nil {
		return "", false, fmt.Errorf("recover keypair state: %w", err)
	}

	privPath := filepath.Join(ks.Dir, PrivateKeyFile)
	pubPath := filepath.Join(ks.Dir, PublicKeyFile)

	privExists, err := pathExists(privPath)
	if err != nil {
		return "", false, fmt.Errorf("inspect private key: %w", err)
	}
	pubExists, err := pathExists(pubPath)
	if err != nil {
		return "", false, fmt.Errorf("inspect public key: %w", err)
	}

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
	expectedHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	if pubHexFile != expectedHex+"\n" {
		return "", fmt.Errorf("public key file does not match private key; use --force to regenerate")
	}
	return expectedHex, nil
}

// LoadPrivateKey reads and parses the persisted private key.
func (ks KeyStore) LoadPrivateKey() (ed25519.PrivateKey, error) {
	if ks.Dir == "" {
		return nil, errors.New("key directory is not configured")
	}
	return loadPrivateKeyFile(filepath.Join(ks.Dir, PrivateKeyFile))
}

func loadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open private key: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect open private key: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect private key path: %w", err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, pathInfo) {
		return nil, errors.New("private key must be a regular non-symlink file")
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("private key permissions are %04o, require 0600", info.Mode().Perm())
	}
	data, err := io.ReadAll(file)
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
	privExists, err := pathExists(privPath)
	if err != nil {
		return fmt.Errorf("inspect private key before write: %w", err)
	}
	replacingExisting := force && privExists

	privTmp, err := ks.writeTempPrivateKey(priv)
	if err != nil {
		return err
	}
	pubTmp, err := ks.writeTempPublicKey(pubHex)
	if err != nil {
		_ = os.Remove(privTmp)
		return err
	}

	if replacingExisting {
		if err := os.Remove(privBak); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = os.Remove(privTmp)
			_ = os.Remove(pubTmp)
			return fmt.Errorf("remove stale private key backup: %w", err)
		}
		if err := os.Rename(privPath, privBak); err != nil {
			_ = os.Remove(privTmp)
			_ = os.Remove(pubTmp)
			return fmt.Errorf("backup existing private key: %w", err)
		}
		if err := syncDirectory(ks.Dir); err != nil {
			rollbackErr := ks.rollbackForcedReplacement()
			_ = os.Remove(privTmp)
			_ = os.Remove(pubTmp)
			return operationAndRollbackError(fmt.Errorf("sync private key backup: %w", err), rollbackErr)
		}
	}

	if err := os.Rename(privTmp, privPath); err != nil {
		_ = os.Remove(privTmp)
		_ = os.Remove(pubTmp)
		if replacingExisting {
			return operationAndRollbackError(
				fmt.Errorf("commit private key: %w", err),
				ks.rollbackForcedReplacement(),
			)
		}
		return fmt.Errorf("commit private key: %w", err)
	}
	if err := syncDirectory(ks.Dir); err != nil {
		_ = os.Remove(pubTmp)
		if replacingExisting {
			return operationAndRollbackError(
				fmt.Errorf("sync private key commit: %w", err),
				ks.rollbackForcedReplacement(),
			)
		} else {
			_ = os.Remove(privPath)
			_ = syncDirectory(ks.Dir)
		}
		return fmt.Errorf("sync private key commit: %w", err)
	}
	if err := os.Rename(pubTmp, pubPath); err != nil {
		_ = os.Remove(pubTmp)
		if replacingExisting {
			return operationAndRollbackError(
				fmt.Errorf("commit public key: %w", err),
				ks.rollbackForcedReplacement(),
			)
		} else {
			_ = os.Remove(privPath)
			_ = syncDirectory(ks.Dir)
		}
		return fmt.Errorf("commit public key: %w", err)
	}
	if err := syncDirectory(ks.Dir); err != nil {
		if replacingExisting {
			return operationAndRollbackError(
				fmt.Errorf("sync public key commit: %w", err),
				ks.rollbackForcedReplacement(),
			)
		} else {
			_ = os.Remove(privPath)
			_ = os.Remove(pubPath)
			_ = syncDirectory(ks.Dir)
		}
		return fmt.Errorf("sync public key commit: %w", err)
	}

	if replacingExisting {
		if err := os.Remove(privBak); err != nil {
			return fmt.Errorf("remove private key backup: %w", err)
		}
		if err := syncDirectory(ks.Dir); err != nil {
			return fmt.Errorf("sync private key backup removal: %w", err)
		}
	}
	return nil
}

func operationAndRollbackError(operationErr, rollbackErr error) error {
	if rollbackErr == nil {
		return operationErr
	}
	return errors.Join(operationErr, fmt.Errorf("rollback forced key replacement: %w", rollbackErr))
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
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("set private key permissions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("sync temp private key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close temp private key file: %w", err)
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
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("set public key permissions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("sync temp public key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close temp public key file: %w", err)
	}
	return tmpPath, nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// recover resolves every durable state in the replacement protocol. The
// private key is authoritative; the public file is a derived projection.
func (ks KeyStore) recover() error {
	privPath := filepath.Join(ks.Dir, PrivateKeyFile)
	pubPath := filepath.Join(ks.Dir, PublicKeyFile)
	privBak := filepath.Join(ks.Dir, privateKeyBackupFile)

	if err := removeGlob(filepath.Join(ks.Dir, ".device.key.tmp.*")); err != nil {
		return fmt.Errorf("remove stale private key temp files: %w", err)
	}
	if err := removeGlob(filepath.Join(ks.Dir, ".device.pub.tmp.*")); err != nil {
		return fmt.Errorf("remove stale public key temp files: %w", err)
	}

	privExists, err := pathExists(privPath)
	if err != nil {
		return fmt.Errorf("inspect private key recovery state: %w", err)
	}
	pubExists, err := pathExists(pubPath)
	if err != nil {
		return fmt.Errorf("inspect public key recovery state: %w", err)
	}
	privBakExists, err := pathExists(privBak)
	if err != nil {
		return fmt.Errorf("inspect private key backup recovery state: %w", err)
	}

	if privBakExists {
		// A matching final pair means the new identity reached its commit point;
		// only backup cleanup was interrupted.
		if privExists && pubExists {
			matches, err := keyPairMatches(privPath, pubPath)
			if err == nil && matches {
				if err := os.Remove(privBak); err != nil {
					return fmt.Errorf("remove committed private key backup: %w", err)
				}
				return syncDirectory(ks.Dir)
			}
		}

		// Any other state is pre-commit. Restore the previous private identity
		// and regenerate its public projection.
		if err := os.Remove(privPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove interrupted private key replacement: %w", err)
		}
		if err := os.Rename(privBak, privPath); err != nil {
			return fmt.Errorf("restore private key backup: %w", err)
		}
		if err := ks.rewritePublicFromPrivate(privPath, pubPath); err != nil {
			return fmt.Errorf("restore public key projection: %w", err)
		}
		return syncDirectory(ks.Dir)
	}

	if privExists {
		if err := ks.rewritePublicFromPrivate(privPath, pubPath); err != nil {
			return fmt.Errorf("repair public key projection: %w", err)
		}
		return nil
	}

	// A public-only file is an incomplete initial creation and carries no
	// authority. Remove it so a fresh pair can be generated.
	if pubExists {
		if err := os.Remove(pubPath); err != nil {
			return fmt.Errorf("remove orphaned public key: %w", err)
		}
		return syncDirectory(ks.Dir)
	}
	return nil
}

func (ks KeyStore) rewritePublicFromPrivate(privPath, pubPath string) error {
	priv, err := loadPrivateKeyFile(privPath)
	if err != nil {
		return err
	}
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	pubExists, err := pathExists(pubPath)
	if err != nil {
		return err
	}
	if pubExists {
		data, err := os.ReadFile(pubPath)
		if err == nil && string(data) == pubHex+"\n" {
			return nil
		}
	}
	pubTmp, err := ks.writeTempPublicKey(pubHex)
	if err != nil {
		return err
	}
	if err := os.Rename(pubTmp, pubPath); err != nil {
		_ = os.Remove(pubTmp)
		return err
	}
	return syncDirectory(ks.Dir)
}

func keyPairMatches(privPath, pubPath string) (bool, error) {
	priv, err := loadPrivateKeyFile(privPath)
	if err != nil {
		return false, err
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return false, err
	}
	expected := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	return string(pubData) == expected+"\n", nil
}

func (ks KeyStore) rollbackForcedReplacement() error {
	privPath := filepath.Join(ks.Dir, PrivateKeyFile)
	pubPath := filepath.Join(ks.Dir, PublicKeyFile)
	privBak := filepath.Join(ks.Dir, privateKeyBackupFile)

	privBakExists, err := pathExists(privBak)
	if err != nil {
		return err
	}
	if !privBakExists {
		return nil
	}
	if err := os.Remove(privPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(privBak, privPath); err != nil {
		return err
	}
	if err := ks.rewritePublicFromPrivate(privPath, pubPath); err != nil {
		return err
	}
	return syncDirectory(ks.Dir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func removeGlob(pattern string) error {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	for _, m := range matches {
		if err := os.Remove(m); err != nil {
			return err
		}
	}
	return nil
}
