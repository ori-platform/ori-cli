// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ori-platform/ori-cli/internal/bridge"
	"github.com/ori-platform/ori-cli/internal/doctor"
	"github.com/ori-platform/ori-cli/internal/output"
	"github.com/ori-platform/ori-cli/internal/rpc"
	"github.com/spf13/cobra"
)

func newDoctorCommand(state *rootState) *cobra.Command {
	socketPath := rpc.DefaultHealthSocket
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose local Ori runtime health and posture",
		Long: `Diagnose local Ori runtime health: sensor freshness, alert-channel
runtime availability, tier execution readiness, evidence posture, and
broad runtime posture.

Health is read through the runtime bridge (health snapshot), falling back
to the direct health socket. Doctor reports readiness signals only; it
never grants or denies action-tier authority, never infers deployment
type, and never exposes remote-command sender identities. A degraded
report still exits zero; only transport or contract failures exit
non-zero.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), doctorOverallTimeout)
			defer cancel()
			status, err := fetchDoctorHealth(state, ctx, socketPath)
			if err != nil {
				return err
			}
			summary := doctor.BuildSummary(status, state.nowMs())
			if state.json {
				return output.JSON(state.stdout, summary)
			}
			renderDoctorText(state.stdout, summary)
			return nil
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", rpc.DefaultHealthSocket, "runtime health Unix socket path")
	cmd.AddCommand(newRuntimeHealthCommand(state))
	return cmd
}

// Doctor transport budgets. Each attempt gets its own bounded context
// derived from the overall command deadline so a bridge that hangs until
// its own timeout still leaves live time for the direct-socket fallback.
// Tests may shrink these.
var (
	doctorOverallTimeout = 10 * time.Second
	doctorBridgeTimeout  = 5 * time.Second
	doctorSocketTimeout  = 3 * time.Second
)

// fetchDoctorHealth reads runtime health through the runtime bridge first,
// falling back to the direct health socket when the bridge is unavailable or
// its payload fails contract parsing. Each transport runs under its own
// timeout within the parent command context.
func fetchDoctorHealth(state *rootState, ctx context.Context, socketPath string) (rpc.RuntimeHealthStatus, error) {
	var bridgeErr error
	bridgeCtx, bridgeCancel := context.WithTimeout(ctx, doctorBridgeTimeout)
	raw, err := bridge.HealthSnapshot(bridgeCtx, state.bridge, socketPath)
	bridgeCancel()
	if err != nil {
		bridgeErr = err
	} else if status, parseErr := rpc.ParseHealth(raw); parseErr != nil {
		bridgeErr = parseErr
	} else {
		return status, nil
	}

	socketCtx, socketCancel := context.WithTimeout(ctx, doctorSocketTimeout)
	status, socketErr := state.getHealth(socketCtx, socketPath)
	socketCancel()
	if socketErr == nil {
		return status, nil
	}
	return rpc.RuntimeHealthStatus{}, fmt.Errorf("runtime health unavailable: bridge: %v; socket: %w", bridgeErr, socketErr)
}

func renderDoctorText(w io.Writer, summary doctor.Summary) {
	overall := "OK"
	if summary.Degraded {
		overall = "DEGRADED"
	}
	fmt.Fprintf(w, "ori doctor: %s\n", overall)
	if summary.DeviceID != "" {
		fmt.Fprintf(w, "Device: %s\n", summary.DeviceID)
	}

	renderDoctorSensors(w, summary.SensorFreshness)
	renderDoctorAlerts(w, summary.AlertChannels)
	renderDoctorTiers(w, summary.Tiers)
	renderDoctorEvidence(w, summary.Evidence)
	renderDoctorPosture(w, summary.Posture)
}

func renderDoctorSensors(w io.Writer, sensors doctor.SensorFreshnessSummary) {
	fmt.Fprintln(w, "\nSensors:")
	if len(sensors.Sensors) == 0 {
		fmt.Fprintln(w, "  none reported")
		return
	}
	for _, sensor := range sensors.Sensors {
		fmt.Fprintf(w, "  %s: %s\n", sensor.SensorID, sensorFreshnessText(sensor))
	}
}

func sensorFreshnessText(sensor doctor.SensorFreshness) string {
	parts := []string{}
	if sensor.DeltaMs == nil {
		parts = append(parts, "no timestamp")
	} else if *sensor.DeltaMs < 0 {
		parts = append(parts, "timestamp in future")
	} else {
		parts = append(parts, "last seen "+formatDoctorDuration(*sensor.DeltaMs)+" ago")
	}
	if sensor.RuntimeStale {
		parts = append(parts, "runtime stale")
	}
	if len(sensor.DegradedReasons) > 0 {
		parts = append(parts, "degraded ("+strings.Join(sensor.DegradedReasons, ", ")+")")
	}
	return strings.Join(parts, "; ")
}

func renderDoctorAlerts(w io.Writer, alerts doctor.AlertChannelSummary) {
	fmt.Fprintln(w, "\nAlert channels (runtime availability):")
	fmt.Fprintf(w, "  sms: %s\n", availableText(alerts.SMSRuntimeAvailable))
	fmt.Fprintf(w, "  whatsapp: %s\n", availableText(alerts.WhatsAppRuntimeAvailable))
	fmt.Fprintf(w, "  internet: %s\n", availableText(alerts.InternetAvailable))
	fmt.Fprintf(w, "  outbox backlog: %d", alerts.OutboxBacklogCount)
	if alerts.OutboxOldestAgeMs != nil {
		fmt.Fprintf(w, " (oldest %s)", formatDoctorDuration(*alerts.OutboxOldestAgeMs))
	}
	fmt.Fprintln(w)
}

func renderDoctorTiers(w io.Writer, tiers doctor.TierCapabilitySummary) {
	fmt.Fprintln(w, "\nTiers (authority / execution readiness):")
	renderDoctorTier(w, "A", tiers.TierA)
	renderDoctorTier(w, "B", tiers.TierB)
	renderDoctorTier(w, "C", tiers.TierC)
	renderDoctorTier(w, "D", tiers.TierD)
}

func renderDoctorTier(w io.Writer, name string, tier doctor.TierExecutionState) {
	fmt.Fprintf(w, "  Tier %s %s: %s\n", name, tier.AuthorityModel, tierReadinessText(tier))
}

func tierReadinessText(tier doctor.TierExecutionState) string {
	var readiness string
	switch {
	case tier.ExecutionReady == nil:
		readiness = "readiness unknown"
	case *tier.ExecutionReady:
		readiness = "ready"
	default:
		readiness = "not ready"
	}
	if len(tier.DegradedReasons) > 0 {
		readiness += " (" + strings.Join(tier.DegradedReasons, ", ") + ")"
	}
	return readiness
}

func renderDoctorEvidence(w io.Writer, evidence doctor.EvidenceSummary) {
	fmt.Fprintln(w, "\nEvidence:")
	fmt.Fprintf(w, "  enabled: %t, available: %t\n", evidence.Enabled, evidence.Available)
	if evidence.ProtocolVersion != "" {
		fmt.Fprintf(w, "  protocol: %s\n", evidence.ProtocolVersion)
	}
	if evidence.ActionEventType != "" {
		fmt.Fprintf(w, "  action event: %s\n", evidence.ActionEventType)
	}
	fmt.Fprintf(w, "  chain head: %s\n", nullableStringText(evidence.ChainHeadHash))
	fmt.Fprintf(w, "  pending exports: %s\n", nullableIntText(evidence.PendingExportCount))
	fmt.Fprintf(w, "  attestation gaps: %d\n", evidence.AttestationGapCount)
	if len(evidence.DegradedReasons) > 0 {
		fmt.Fprintf(w, "  degraded (%s)\n", strings.Join(evidence.DegradedReasons, ", "))
	}
}

func renderDoctorPosture(w io.Writer, posture doctor.RuntimePostureSummary) {
	fmt.Fprintln(w, "\nPosture:")
	fmt.Fprintf(w, "  gateway broker: %s\n", degradedText(posture.GatewayBrokerDegraded))
	fmt.Fprintf(w, "  state store encryption: %s\n", degradedText(posture.StateStoreEncryptionDegraded))
	fmt.Fprintf(w, "  alert outbox: %s\n", degradedText(posture.AlertOutboxDegraded))
	fmt.Fprintf(w, "  evidence: %s\n", degradedText(posture.EvidenceDegraded))
	lockout := posture.RemoteCommandLockout
	fmt.Fprintf(w, "  remote command lockout: %s", degradedText(lockout.Degraded))
	fmt.Fprintf(w, " (senders: %d, elevated: %d, critical: %d, locked out: %d, stale: %d, enforcement: %t)\n",
		lockout.TotalSenderCount, lockout.ElevatedCount, lockout.CriticalCount,
		lockout.LockedOutCount, lockout.StaleCount, lockout.EnforcementEnabled)
}

func availableText(available bool) string {
	if available {
		return "runtime available"
	}
	return "runtime unavailable"
}

func degradedText(degraded bool) string {
	if degraded {
		return "degraded"
	}
	return "ok"
}

func nullableStringText(value *string) string {
	if value == nil || *value == "" {
		return "none"
	}
	return *value
}

func nullableIntText(value *int64) string {
	if value == nil {
		return "none"
	}
	return strconv.FormatInt(*value, 10)
}

// formatDoctorDuration renders a millisecond duration in the coarsest unit
// that stays readable for operators.
func formatDoctorDuration(ms int64) string {
	switch {
	case ms < 1000:
		return fmt.Sprintf("%d ms", ms)
	case ms < 60_000:
		return fmt.Sprintf("%d s", ms/1000)
	case ms < 3_600_000:
		return fmt.Sprintf("%d min", ms/60_000)
	default:
		return fmt.Sprintf("%d h", ms/3_600_000)
	}
}

func newRuntimeHealthCommand(state *rootState) *cobra.Command {
	socketPath := rpc.DefaultHealthSocket
	cmd := &cobra.Command{
		Use:   "runtime-health",
		Short: "Read runtime health from the local Unix socket",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			status, err := state.getHealth(ctx, socketPath)
			if err != nil {
				return fmt.Errorf("runtime health unavailable: %w", err)
			}
			if state.json {
				return output.JSON(state.stdout, status)
			}
			fmt.Fprintf(state.stdout, "Runtime health: %s\n", status.StatusOrUnknown())
			if status.DeviceID != "" {
				fmt.Fprintf(state.stdout, "Device: %s\n", status.DeviceID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", rpc.DefaultHealthSocket, "runtime health Unix socket path")
	return cmd
}
