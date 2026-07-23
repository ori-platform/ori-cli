// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
)

const (
	FirmwareMQTTContract        = "ori.runtime.firmware-mqtt-operator"
	FirmwareMQTTSchemaVersion   = 1
	DefaultFirmwareMQTTSocket   = "/run/ori/firmware-mqtt-provisioning.sock"
	firmwareMQTTRequestMaxBytes = 32 * 1024
	firmwareMQTTReplyMaxBytes   = 64 * 1024
)

type FirmwareMQTTRequest struct {
	Contract      string `json:"contract"`
	SchemaVersion int    `json:"schema_version"`
	Operation     string `json:"operation"`
	DeviceID      string `json:"device_id,omitempty"`
	Reason        string `json:"reason,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	ResponseB64   string `json:"response_b64,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
}

type FirmwareMQTTError struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type FirmwareMQTTResponse struct {
	Contract      string             `json:"contract"`
	SchemaVersion int                `json:"schema_version"`
	OK            bool               `json:"ok"`
	Result        json.RawMessage    `json:"result,omitempty"`
	Error         *FirmwareMQTTError `json:"error,omitempty"`
}

func NewFirmwareMQTTRequest(operation string) FirmwareMQTTRequest {
	return FirmwareMQTTRequest{
		Contract:      FirmwareMQTTContract,
		SchemaVersion: FirmwareMQTTSchemaVersion,
		Operation:     operation,
	}
}

func CallFirmwareMQTT(
	ctx context.Context,
	socketPath string,
	request FirmwareMQTTRequest,
) (FirmwareMQTTResponse, error) {
	if socketPath == "" {
		socketPath = DefaultFirmwareMQTTSocket
	}
	if err := validateFirmwareMQTTSocketPath(socketPath); err != nil {
		return FirmwareMQTTResponse{}, err
	}
	if request.Contract != FirmwareMQTTContract {
		return FirmwareMQTTResponse{}, fmt.Errorf("firmware MQTT request contract must be %q", FirmwareMQTTContract)
	}
	if request.SchemaVersion != FirmwareMQTTSchemaVersion {
		return FirmwareMQTTResponse{}, fmt.Errorf(
			"firmware MQTT request schema_version must be %d",
			FirmwareMQTTSchemaVersion,
		)
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return FirmwareMQTTResponse{}, fmt.Errorf("encode firmware MQTT request: %w", err)
	}
	if len(payload)+1 > firmwareMQTTRequestMaxBytes {
		return FirmwareMQTTResponse{}, fmt.Errorf("firmware MQTT request exceeds %d-byte limit", firmwareMQTTRequestMaxBytes)
	}
	payload = append(payload, '\n')

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return FirmwareMQTTResponse{}, fmt.Errorf("connect to firmware MQTT operator socket: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return FirmwareMQTTResponse{}, fmt.Errorf("set firmware MQTT operator deadline: %w", err)
		}
	}
	if err := writeAll(conn, payload); err != nil {
		return FirmwareMQTTResponse{}, fmt.Errorf("write firmware MQTT operator request: %w", err)
	}

	reply, err := readFirmwareMQTTReply(conn)
	if err != nil {
		return FirmwareMQTTResponse{}, err
	}
	return ParseFirmwareMQTTResponse(reply)
}

func ParseFirmwareMQTTResponse(payload []byte) (FirmwareMQTTResponse, error) {
	if err := rejectDuplicateJSONFields(payload); err != nil {
		return FirmwareMQTTResponse{}, fmt.Errorf("decode firmware MQTT operator response: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var response FirmwareMQTTResponse
	if err := decoder.Decode(&response); err != nil {
		return FirmwareMQTTResponse{}, fmt.Errorf("decode firmware MQTT operator response: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return FirmwareMQTTResponse{}, fmt.Errorf("decode firmware MQTT operator response: %w", err)
	}
	if response.Contract != FirmwareMQTTContract {
		return FirmwareMQTTResponse{}, fmt.Errorf(
			"firmware MQTT operator contract mismatch: got %q, want %q",
			response.Contract,
			FirmwareMQTTContract,
		)
	}
	if response.SchemaVersion != FirmwareMQTTSchemaVersion {
		return FirmwareMQTTResponse{}, fmt.Errorf(
			"firmware MQTT operator schema_version mismatch: got %d, want %d",
			response.SchemaVersion,
			FirmwareMQTTSchemaVersion,
		)
	}
	if response.OK {
		if response.Error != nil {
			return FirmwareMQTTResponse{}, errors.New("firmware MQTT operator success response contains an error")
		}
		if len(response.Result) == 0 || bytes.Equal(response.Result, []byte("null")) {
			return FirmwareMQTTResponse{}, errors.New("firmware MQTT operator success response has no result")
		}
		return response, nil
	}
	if response.Error == nil || response.Error.Code == "" || response.Error.Detail == "" {
		return FirmwareMQTTResponse{}, errors.New("firmware MQTT operator failure response has no complete error")
	}
	if len(response.Result) != 0 && !bytes.Equal(response.Result, []byte("null")) {
		return FirmwareMQTTResponse{}, errors.New("firmware MQTT operator failure response contains a result")
	}
	return response, nil
}

func validateFirmwareMQTTSocketPath(socketPath string) error {
	if !filepath.IsAbs(socketPath) {
		return errors.New("firmware MQTT operator socket path must be absolute")
	}
	if strings.ContainsRune(socketPath, '\x00') {
		return errors.New("firmware MQTT operator socket path contains NUL")
	}
	return nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[written:]
	}
	return nil
}

func readFirmwareMQTTReply(reader io.Reader) ([]byte, error) {
	reply, err := io.ReadAll(io.LimitReader(reader, firmwareMQTTReplyMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read firmware MQTT operator response: %w", err)
	}
	if len(reply) > firmwareMQTTReplyMaxBytes {
		return nil, fmt.Errorf("firmware MQTT operator response exceeds %d-byte limit", firmwareMQTTReplyMaxBytes)
	}
	if len(reply) == 0 || reply[len(reply)-1] != '\n' {
		return nil, errors.New("firmware MQTT operator closed without a newline-terminated response")
	}
	if bytes.Count(reply, []byte{'\n'}) != 1 {
		return nil, errors.New("firmware MQTT operator returned more than one response")
	}
	return reply[:len(reply)-1], nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func rejectDuplicateJSONFields(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate field %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}
