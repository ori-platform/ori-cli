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
runtime health snapshot to obtain the device ID and Verity evidence anchor, and
optionally register the public keys with ori-cloud.

The private key is written with restrictive permissions and never leaves the
device. It is never included in any cloud registration payload, log message, or
stdout/stderr output.

Use --dry-run to preview the public key without writing files, reading the
runtime health socket, or making network calls.`,
	}

	cmd.Flags().String("key-dir", "", "directory for device key material (default ~/.ori)")
	cmd.Flags().Bool("force", false, "overwrite existing device keys")
	cmd.Flags().Bool("dry-run", false, "generate keys without writing files or calling cloud")
	cmd.Flags().String("socket", rpc.DefaultHealthSocket, "runtime health Unix socket path")
	cmd.Flags().String("cloud-url", "", "ori-cloud base URL (also ORI_CLOUD_URL)")

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

		pubHex, err := ks.Generate(force)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		health, err := state.getHealth(ctx, socketPath)
		if err != nil {
			return fmt.Errorf("runtime health unavailable: %w", err)
		}

		evidencePub := health.Evidence.PublicKeyHex
		if health.Evidence.Enabled && evidencePub == "" {
			return fmt.Errorf("evidence signing is enabled but the evidence anchor public key is not available")
		}

		cloudRegistered := false
		if cloudURL != "" {
			req := cloud.RegisterDeviceRequest{
				DeviceID:          health.DeviceID,
				IdentityPubKeyHex: pubHex,
				EvidencePubKeyHex: evidencePub,
				RegisteredAtMs:    cloud.Now(),
			}
			_, err := state.registerDevice(ctx, cloudURL, req)
			if err != nil {
				return fmt.Errorf("cloud registration failed: %w", err)
			}
			cloudRegistered = true
		}

		message := "device identity keypair generated; register the public keys with ori-cloud to complete deployment"
		if cloudRegistered {
			message = "device identity keypair generated and registered with ori-cloud"
		}

		if state.json {
			return output.JSON(state.stdout, map[string]any{
				"ok":                  true,
				"dry_run":             false,
				"device_id":           health.DeviceID,
				"identity_pubkey_hex": pubHex,
				"evidence_pubkey_hex": evidencePub,
				"key_dir":             ks.Dir,
				"cloud_registered":    cloudRegistered,
				"message":             message,
			})
		}

		fmt.Fprintln(state.stdout, "Device identity keypair generated.")
		if health.DeviceID != "" {
			fmt.Fprintf(state.stdout, "Device ID: %s\n", health.DeviceID)
		}
		fmt.Fprintf(state.stdout, "Identity public key: %s\n", pubHex)
		if evidencePub != "" {
			fmt.Fprintf(state.stdout, "Evidence public key:  %s\n", evidencePub)
		} else {
			fmt.Fprintln(state.stdout, "Evidence public key:  not available (evidence signing disabled)")
		}
		fmt.Fprintf(state.stdout, "Private key: %s\n", filepath.Join(ks.Dir, deploy.PrivateKeyFile))
		fmt.Fprintf(state.stdout, "Public key:  %s\n", filepath.Join(ks.Dir, deploy.PublicKeyFile))
		if cloudRegistered {
			fmt.Fprintln(state.stdout, "Cloud registration: successful.")
		} else {
			fmt.Fprintln(state.stdout, "Cloud registration: not configured; register the public keys with ori-cloud to complete deployment.")
		}
		return nil
	}

	return cmd
}
