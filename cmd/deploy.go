// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ori-platform/ori-cli/internal/cloud"
	"github.com/ori-platform/ori-cli/internal/deploy"
	"github.com/ori-platform/ori-cli/internal/output"
	"github.com/ori-platform/ori-cli/internal/rpc"
	"github.com/spf13/cobra"
)

func newDeployCommand(state *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Provision a device deployment",
		Long: `Generate the device identity Ed25519 keypair on-device, read the
runtime health snapshot to obtain the device ID and evidence layer verification
anchor, and optionally register the public identity key with ori-cloud.

The private key is written with restrictive permissions and never leaves the
device. It is never included in any cloud registration payload, log message, or
stdout/stderr output.

Use --dry-run to preview the public key without writing files, reading the
runtime health socket, or making network calls. Cloud registration requires both
--cloud-url and --device-api-key and an explicit --yes flag (or noninteractive
mode).`,
	}

	cmd.Flags().String("key-dir", "", "directory for device key material (default ~/.ori)")
	cmd.Flags().Bool("force", false, "overwrite existing device keys")
	cmd.Flags().Bool("dry-run", false, "generate keys without writing files or calling cloud")
	cmd.Flags().String("socket", rpc.DefaultHealthSocket, "runtime health Unix socket path")
	cmd.Flags().String("cloud-url", "", "ori-cloud base URL (also ORI_CLOUD_URL)")
	cmd.Flags().String("device-api-key", "", "device API key for cloud keypair registration (also ORI_DEVICE_API_KEY)")
	cmd.Flags().Bool("yes", false, "confirm cloud keypair registration without interactive prompt")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		keyDir, err := cmd.Flags().GetString("key-dir")
		if err != nil {
			return fmt.Errorf("failed to read --key-dir: %w", err)
		}
		force, err := cmd.Flags().GetBool("force")
		if err != nil {
			return fmt.Errorf("failed to read --force: %w", err)
		}
		dryRun, err := cmd.Flags().GetBool("dry-run")
		if err != nil {
			return fmt.Errorf("failed to read --dry-run: %w", err)
		}
		socketPath, err := cmd.Flags().GetString("socket")
		if err != nil {
			return fmt.Errorf("failed to read --socket: %w", err)
		}
		cloudURL, err := cmd.Flags().GetString("cloud-url")
		if err != nil {
			return fmt.Errorf("failed to read --cloud-url: %w", err)
		}
		if cloudURL == "" {
			cloudURL = os.Getenv("ORI_CLOUD_URL")
		}
		deviceAPIKey, err := cmd.Flags().GetString("device-api-key")
		if err != nil {
			return fmt.Errorf("failed to read --device-api-key: %w", err)
		}
		if deviceAPIKey == "" {
			deviceAPIKey = os.Getenv("ORI_DEVICE_API_KEY")
		}
		yes, err := cmd.Flags().GetBool("yes")
		if err != nil {
			return fmt.Errorf("failed to read --yes: %w", err)
		}

		if dryRun {
			pubHex, _, err := deploy.GenerateKeypair()
			if err != nil {
				return err
			}
			if state.json {
				return output.JSON(state.stdout, map[string]any{
					"ok":                  true,
					"dry_run":             true,
					"identity_pubkey_hex": pubHex,
					"message":             "dry-run: no files written, no health socket read, and no cloud calls made",
				})
			}
			fmt.Fprintln(state.stdout, "Dry-run: no files written, no health socket read, and no cloud calls made.")
			fmt.Fprintf(state.stdout, "Identity public key: %s\n", pubHex)
			return nil
		}

		var ks deploy.KeyStore
		if keyDir != "" {
			ks = deploy.KeyStore{Dir: keyDir}
		} else {
			ks = deploy.DefaultKeyStore()
		}

		// Validate runtime health and required identity information BEFORE
		// persisting any key material. This prevents leaving orphaned keys when
		// health or the evidence anchor is unavailable.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		health, err := state.getHealth(ctx, socketPath)
		if err != nil {
			return fmt.Errorf("runtime health unavailable: %w", err)
		}
		if health.DeviceID == "" {
			return fmt.Errorf("runtime health did not report a device_id")
		}
		if health.Evidence.Enabled {
			if !health.Evidence.Available {
				return fmt.Errorf("evidence layer is enabled but the evidence state is not available")
			}
			if !isLowerHex64(health.Evidence.PublicKeyHex) {
				return fmt.Errorf("evidence layer verification anchor must be exactly 64 lowercase hexadecimal characters")
			}
		}

		// Ensure a usable keypair exists. If a valid pair is already present and
		// force is not set, reuse it so retries are idempotent.
		pubHex, generated, err := ks.EnsureKeypair(force)
		if err != nil {
			return err
		}

		// Cloud registration is opt-in and requires explicit consent.
		cloudRegistered := false
		if cloudURL != "" || deviceAPIKey != "" {
			if cloudURL == "" {
				return fmt.Errorf("--device-api-key requires --cloud-url or ORI_CLOUD_URL")
			}
			if deviceAPIKey == "" {
				return fmt.Errorf("--cloud-url requires --device-api-key or ORI_DEVICE_API_KEY")
			}
			if !yes {
				return fmt.Errorf("cloud keypair registration requires explicit --yes flag")
			}
			req := cloud.RegisterKeypairRequest{
				IdentityPubKeyHex: pubHex,
			}
			if err := state.registerKeypair(ctx, cloudURL, deviceAPIKey, health.DeviceID, req); err != nil {
				return fmt.Errorf("cloud keypair registration failed: %w", err)
			}
			cloudRegistered = true
		}

		message := "device identity keypair ready; configure --cloud-url and --device-api-key with --yes to register with ori-cloud"
		if cloudRegistered {
			message = "device identity keypair generated and registered with ori-cloud"
		}
		if !generated && !cloudRegistered {
			message = "device identity keypair already present; configure --cloud-url and --device-api-key with --yes to register with ori-cloud"
		}

		if state.json {
			return output.JSON(state.stdout, map[string]any{
				"ok":                  true,
				"dry_run":             false,
				"device_id":           health.DeviceID,
				"identity_pubkey_hex": pubHex,
				"evidence_pubkey_hex": health.Evidence.PublicKeyHex,
				"key_dir":             ks.Dir,
				"cloud_registered":    cloudRegistered,
				"message":             message,
			})
		}

		if generated {
			fmt.Fprintln(state.stdout, "Device identity keypair generated.")
		} else {
			fmt.Fprintln(state.stdout, "Device identity keypair already present; using existing keys.")
		}
		fmt.Fprintf(state.stdout, "Device ID: %s\n", health.DeviceID)
		fmt.Fprintf(state.stdout, "Identity public key: %s\n", pubHex)
		if health.Evidence.PublicKeyHex != "" {
			fmt.Fprintf(state.stdout, "Evidence public key:  %s\n", health.Evidence.PublicKeyHex)
		} else {
			fmt.Fprintln(state.stdout, "Evidence public key:  not available (evidence signing disabled)")
		}
		fmt.Fprintf(state.stdout, "Private key: %s\n", filepath.Join(ks.Dir, deploy.PrivateKeyFile))
		fmt.Fprintf(state.stdout, "Public key:  %s\n", filepath.Join(ks.Dir, deploy.PublicKeyFile))
		if cloudRegistered {
			fmt.Fprintln(state.stdout, "Cloud registration: successful.")
		} else {
			fmt.Fprintln(state.stdout, "Cloud registration: not configured; provide --cloud-url, --device-api-key, and --yes to register.")
		}
		return nil
	}

	return cmd
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
