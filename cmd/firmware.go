// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ori-platform/ori-cli/internal/output"
	"github.com/ori-platform/ori-cli/internal/rpc"
	"github.com/spf13/cobra"
)

const firmwareMQTTTimeout = 15 * time.Second

type reportedCommandError struct{}

func (reportedCommandError) Error() string { return "command failure already reported" }

func newFirmwareCommand(state *rootState) *cobra.Command {
	firmware := &cobra.Command{
		Use:   "firmware",
		Short: "Manage firmware devices through runtime authority",
	}
	mqtt := &cobra.Command{
		Use:   "mqtt",
		Short: "Manage firmware MQTT transport identity",
		Long: `Manage a firmware device's MQTT transport identity through the
authenticated runtime service.

MQTT identity is transport defence in depth. It does not grant Layer 1
evidence trust or Tier B/C/D action authority. The CLI never owns issuer or
device private keys.`,
	}

	mqtt.AddCommand(
		newFirmwareMQTTCreateCSRCommand(state),
		newFirmwareMQTTPrepareInstallCommand(state),
		newFirmwareMQTTVerifyCommand(state, "verify-install-result", "verify_install_result"),
		newFirmwareMQTTRevokeCommand(state),
		newFirmwareMQTTVerifyCommand(state, "verify-revoke-result", "verify_revoke_result"),
		newFirmwareMQTTStatusCommand(state),
		newFirmwareMQTTVerifyCommand(state, "verify-status-response", "verify_status_response"),
	)
	firmware.AddCommand(mqtt)
	return firmware
}

func newFirmwareMQTTCreateCSRCommand(state *rootState) *cobra.Command {
	request := rpc.NewFirmwareMQTTRequest("create_csr")
	cmd := &cobra.Command{
		Use:   "create-csr",
		Short: "Create a signed on-device CSR request",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request.DeviceID, _ = cmd.Flags().GetString("device-id")
			request.Reason, _ = cmd.Flags().GetString("reason")
			return runFirmwareMQTT(state, cmd, request)
		},
	}
	addFirmwareMQTTCommonFlags(cmd)
	cmd.Flags().String("device-id", "", "firmware device ID")
	cmd.Flags().String("reason", "", "audited reason for CSR creation")
	_ = cmd.MarkFlagRequired("device-id")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}

func newFirmwareMQTTPrepareInstallCommand(state *rootState) *cobra.Command {
	request := rpc.NewFirmwareMQTTRequest("prepare_install")
	cmd := &cobra.Command{
		Use:   "prepare-install",
		Short: "Verify a CSR response and prepare certificate installation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request.CorrelationID, _ = cmd.Flags().GetString("correlation-id")
			request.ResponseB64, _ = cmd.Flags().GetString("response-b64")
			request.Reason, _ = cmd.Flags().GetString("reason")
			return runFirmwareMQTT(state, cmd, request)
		},
	}
	addFirmwareMQTTCommonFlags(cmd)
	addFirmwareMQTTResponseFlags(cmd)
	cmd.Flags().String("reason", "", "audited reason for certificate installation")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}

func newFirmwareMQTTRevokeCommand(state *rootState) *cobra.Command {
	request := rpc.NewFirmwareMQTTRequest("revoke")
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Create a signed MQTT transport revocation request",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request.DeviceID, _ = cmd.Flags().GetString("device-id")
			request.Reason, _ = cmd.Flags().GetString("reason")
			return runFirmwareMQTT(state, cmd, request)
		},
	}
	addFirmwareMQTTCommonFlags(cmd)
	cmd.Flags().String("device-id", "", "firmware device ID")
	cmd.Flags().String("reason", "", "audited reason for revocation")
	_ = cmd.MarkFlagRequired("device-id")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}

func newFirmwareMQTTStatusCommand(state *rootState) *cobra.Command {
	request := rpc.NewFirmwareMQTTRequest("status")
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Create a signed public MQTT identity status request",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request.DeviceID, _ = cmd.Flags().GetString("device-id")
			request.RequestID, _ = cmd.Flags().GetString("request-id")
			return runFirmwareMQTT(state, cmd, request)
		},
	}
	addFirmwareMQTTCommonFlags(cmd)
	cmd.Flags().String("device-id", "", "firmware device ID")
	cmd.Flags().String("request-id", "", "fleet correlation identifier")
	_ = cmd.MarkFlagRequired("device-id")
	_ = cmd.MarkFlagRequired("request-id")
	return cmd
}

func newFirmwareMQTTVerifyCommand(
	state *rootState,
	use string,
	operation string,
) *cobra.Command {
	request := rpc.NewFirmwareMQTTRequest(operation)
	cmd := &cobra.Command{
		Use:   use,
		Short: "Verify a device-signed MQTT provisioning response",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request.CorrelationID, _ = cmd.Flags().GetString("correlation-id")
			request.ResponseB64, _ = cmd.Flags().GetString("response-b64")
			return runFirmwareMQTT(state, cmd, request)
		},
	}
	addFirmwareMQTTCommonFlags(cmd)
	addFirmwareMQTTResponseFlags(cmd)
	return cmd
}

func addFirmwareMQTTCommonFlags(cmd *cobra.Command) {
	cmd.Flags().String("socket", rpc.DefaultFirmwareMQTTSocket, "runtime firmware MQTT operator socket")
}

func addFirmwareMQTTResponseFlags(cmd *cobra.Command) {
	cmd.Flags().String("correlation-id", "", "runtime-issued correlation ID")
	cmd.Flags().String("response-b64", "", "canonical base64 device response")
	_ = cmd.MarkFlagRequired("correlation-id")
	_ = cmd.MarkFlagRequired("response-b64")
}

func runFirmwareMQTT(
	state *rootState,
	cmd *cobra.Command,
	request rpc.FirmwareMQTTRequest,
) error {
	socketPath, err := cmd.Flags().GetString("socket")
	if err != nil {
		return fmt.Errorf("read --socket: %w", err)
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), firmwareMQTTTimeout)
	defer cancel()
	response, err := state.firmwareMQTT(ctx, socketPath, request)
	if err != nil {
		return fmt.Errorf("runtime firmware MQTT service unavailable: %w", err)
	}
	if err := validateFirmwareMQTTResult(response); err != nil {
		return err
	}
	if !response.OK {
		return renderFirmwareMQTTFailure(state, response)
	}
	if state.json {
		if err := output.JSON(state.stdout, response); err != nil {
			return err
		}
	} else if err := renderFirmwareMQTTText(state.stdout, response.Result); err != nil {
		return err
	}
	if request.Operation == "verify_install_result" ||
		request.Operation == "verify_revoke_result" {
		var result struct {
			Verdict    string `json:"verdict"`
			Successful bool   `json:"successful"`
		}
		if err := json.Unmarshal(response.Result, &result); err != nil {
			return fmt.Errorf("decode verified mutation result: %w", err)
		}
		if result.Verdict != "accepted" || !result.Successful {
			return reportedCommandError{}
		}
	}
	return nil
}

func validateFirmwareMQTTResult(response rpc.FirmwareMQTTResponse) error {
	if !response.OK {
		if response.Error == nil || response.Error.Code == "" || response.Error.Detail == "" {
			return errors.New("runtime firmware MQTT failure has no complete typed error")
		}
		if containsPrivateMaterial(response.Error.Detail) {
			return errors.New("runtime firmware MQTT failure contains forbidden private material")
		}
		return nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("decode firmware MQTT result: %w", err)
	}
	if _, ok := value.(map[string]any); !ok {
		return errors.New("firmware MQTT result must be an object")
	}
	if containsPrivateMaterial(value) {
		return errors.New("runtime firmware MQTT result contains forbidden private material")
	}
	return nil
}

func containsPrivateMaterial(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "private") ||
				strings.Contains(lower, "seed") ||
				strings.Contains(lower, "ca_key") {
				return true
			}
			if containsPrivateMaterial(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsPrivateMaterial(child) {
				return true
			}
		}
	case string:
		return strings.Contains(strings.ToUpper(typed), "PRIVATE KEY")
	}
	return false
}

func renderFirmwareMQTTFailure(
	state *rootState,
	response rpc.FirmwareMQTTResponse,
) error {
	if state.json {
		if err := output.JSON(state.stdout, response); err != nil {
			return err
		}
		return reportedCommandError{}
	}
	return fmt.Errorf(
		"runtime firmware MQTT request failed: %s: %s",
		response.Error.Code,
		response.Error.Detail,
	)
}

func renderFirmwareMQTTText(w io.Writer, raw json.RawMessage) error {
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("decode firmware MQTT result: %w", err)
	}
	operation, _ := result["operation"].(string)
	if operation == "" {
		return errors.New("runtime firmware MQTT result has no operation")
	}
	if successful, ok := result["successful"].(bool); ok {
		verdict, _ := result["verdict"].(string)
		if successful {
			fmt.Fprintf(w, "Verified %s response: accepted\n", operation)
		} else {
			fmt.Fprintf(w, "Verified %s response: refused (%s)\n", operation, verdict)
		}
	} else {
		fmt.Fprintf(w, "Created %s request.\n", operation)
	}
	keys := make([]string, 0, len(result))
	for key := range result {
		if key != "operation" && key != "response" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		rendered, err := formatFirmwareMQTTValue(result[key])
		if err != nil {
			return fmt.Errorf("render firmware MQTT result field %q: %w", key, err)
		}
		fmt.Fprintf(w, "%s: %s\n", key, rendered)
	}
	return nil
}

func formatFirmwareMQTTValue(value any) (string, error) {
	switch value.(type) {
	case map[string]any, []any:
		encoded, err := json.Marshal(value)
		if err != nil {
			return "", err
		}
		return string(encoded), nil
	default:
		return fmt.Sprint(value), nil
	}
}
