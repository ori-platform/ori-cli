// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestUseOfflineVerifiesPythonMintedToken ensures the CLI validator agrees with
// the runtime's offline token signer. Skips if python3 or cryptography is
// unavailable.
func TestUseOfflineVerifiesPythonMintedToken(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	if err := probePythonCryptography(python); err != nil {
		t.Skipf("cryptography Ed25519 unavailable: %v", err)
	}

	script := filepath.Join(t.TempDir(), "mint.py")
	if err := os.WriteFile(script, []byte(pythonMintScript), 0o600); err != nil {
		t.Fatalf("write mint script: %v", err)
	}

	cmd := exec.Command(python, script)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run mint script: %v", err)
	}
	var minted struct {
		Token        string `json:"token"`
		PublicKeyB64 string `json:"public_key_b64"`
	}
	if err := json.Unmarshal(out, &minted); err != nil {
		t.Fatalf("parse mint output: %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "device.pub")
	if err := os.WriteFile(keyPath, []byte(minted.PublicKeyB64), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	result, err := UseOffline(minted.Token, UseOptions{
		TokenKeyPath:    keyPath,
		ExpectedDeviceID: "dev-int-01",
		ClockSkew:        300 * time.Second,
	})
	if err != nil {
		t.Fatalf("verify python-minted token: %v", err)
	}
	if !result.OK {
		t.Fatal("expected ok result")
	}
}

func probePythonCryptography(python string) error {
	cmd := exec.Command(python, "-c", "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey")
	return cmd.Run()
}

const pythonMintScript = `import base64
import json
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()
public_key_b64 = base64.b64encode(
    public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
).decode("ascii")

now_s = int(time.time())
payload = {
    "token_id": "tok-int-01",
    "device_id": "dev-int-01",
    "action_scope": "open_safety_circuit",
    "issued_at": now_s - 5,
    "expires_at": now_s + 120,
    "nonce": "n1",
}

canonical_obj = {k: v for k, v in payload.items() if k != "signature"}
canonical_json = json.dumps(
    canonical_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")

signature = private_key.sign(canonical_json)
payload["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

print(json.dumps({"token": token, "public_key_b64": public_key_b64}))
`
