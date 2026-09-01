// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/ori-platform/ori-cli/internal/binding"
	"github.com/ori-platform/ori-cli/internal/capture"
	"github.com/spf13/cobra"
)

// exportTimeout bounds the read-only export. There is deliberately no
// equivalent for `prove`: see runBindingProve.
const exportTimeout = 10 * time.Second

func newBindingCommand(state *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "binding",
		Short: "Commission the safety binding through the runtime bridge",
	}

	proveCmd := &cobra.Command{
		Use:   "prove",
		Short: "Ask the runtime to command one outcome so it can be observed",
		Long: `Ask the runtime to command one commissioned outcome, once, so the
control leg can be observed.

The runtime performs this, not the CLI. A tool that built the actuator and drove
the pin itself would prove what the tool did rather than what the binding
asserts, so this command parses arguments and invokes the runtime.

Consent is taken by the runtime on the device's controlling terminal, which it
opens itself. It cannot be supplied here, and neither can the observation: an
answer given before the command describes an effect that has not happened yet.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := cmd.Flags().GetString("path")
			if err != nil {
				return fmt.Errorf("failed to read --path: %w", err)
			}
			outcome, err := cmd.Flags().GetString("outcome")
			if err != nil {
				return fmt.Errorf("failed to read --outcome: %w", err)
			}
			zone, err := cmd.Flags().GetString("zone")
			if err != nil {
				return fmt.Errorf("failed to read --zone: %w", err)
			}
			return runBindingProve(state, path, outcome, zone)
		},
	}
	proveCmd.Flags().String("path", "ori.yaml", "path to the runtime configuration")
	proveCmd.Flags().String("outcome", "", "the protected-circuit outcome to command")
	proveCmd.Flags().String("zone", "", "the zone to prove, when the binding declares more than one")
	_ = proveCmd.MarkFlagRequired("outcome")

	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Read what the runtime recorded, and assemble a control leg from it",
		Long: `Read the observations the runtime recorded against the provisional
binding.

With --zone, the recorded observations are assembled into a control leg, or the
command explains why they cannot be. A leg needs both outcomes observed, and a
row whose attestation is not "matched" is never assembled into one.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := cmd.Flags().GetString("path")
			if err != nil {
				return fmt.Errorf("failed to read --path: %w", err)
			}
			zone, err := cmd.Flags().GetString("zone")
			if err != nil {
				return fmt.Errorf("failed to read --zone: %w", err)
			}
			return runBindingExport(state, path, zone)
		},
	}
	exportCmd.Flags().String("path", "ori.yaml", "path to the runtime configuration")
	exportCmd.Flags().String("zone", "", "assemble a control leg for this zone")

	captureCmd := &cobra.Command{
		Use:   "capture",
		Short: "Build a binding draft from the runtime's declared hardware",
		Long: `Ask for one zone's commissioned facts and write an unsigned draft.

The candidate set comes from the runtime's declared inventory, so a binding
cannot name hardware the device does not have. Nothing is inferred: the three
commissioned outcomes are asked separately, a contact type is not among the
questions, and polarity is answered rather than defaulted.

The draft is unsigned and incomplete by design. Signing is a separate step with
its own key custody.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := cmd.Flags().GetString("path")
			if err != nil {
				return fmt.Errorf("failed to read --path: %w", err)
			}
			zone, err := cmd.Flags().GetString("zone")
			if err != nil {
				return fmt.Errorf("failed to read --zone: %w", err)
			}
			out, err := cmd.Flags().GetString("out")
			if err != nil {
				return fmt.Errorf("failed to read --out: %w", err)
			}
			force, err := cmd.Flags().GetBool("force")
			if err != nil {
				return fmt.Errorf("failed to read --force: %w", err)
			}
			return runBindingCapture(state, cmd.InOrStdin(), path, zone, out, force)
		},
	}
	captureCmd.Flags().String("path", "ori.yaml", "path to the runtime configuration")
	captureCmd.Flags().String("zone", "", "the zone this binding covers")
	captureCmd.Flags().String("out", "", "write the draft here instead of stdout")
	captureCmd.Flags().Bool("force", false, "overwrite an existing draft")
	_ = captureCmd.MarkFlagRequired("zone")

	deliverCmd := &cobra.Command{
		Use:   "deliver",
		Short: "Deliver a signed binding to the runtime through the bridge",
		Long: `Hand a signed binding envelope to the runtime, which verifies it
against this device through every stage of the contract and installs it only if
it passes.

The verdict is the runtime's. This command reports it and never decides it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := cmd.Flags().GetString("path")
			if err != nil {
				return fmt.Errorf("failed to read --path: %w", err)
			}
			file, err := cmd.Flags().GetString("binding")
			if err != nil {
				return fmt.Errorf("failed to read --binding: %w", err)
			}
			force, err := cmd.Flags().GetBool("force")
			if err != nil {
				return fmt.Errorf("failed to read --force: %w", err)
			}
			return runBindingDeliver(state, path, file, force)
		},
	}
	deliverCmd.Flags().String("path", "ori.yaml", "path to the runtime configuration")
	deliverCmd.Flags().String("binding", "", "the signed binding envelope to deliver")
	deliverCmd.Flags().Bool("force", false, "replace a differing staged document")
	_ = deliverCmd.MarkFlagRequired("binding")

	candidatesCmd := &cobra.Command{
		Use:   "candidates",
		Short: "Show the runtime's declared inventory as the set a binding may name",
		Long: `Show the hardware the device declares: the sensor ids and the
actuators, by identity.

This is the candidate set. A binding may name nothing outside it, so an
installer can see before capturing what this device will accept.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := cmd.Flags().GetString("path")
			if err != nil {
				return fmt.Errorf("failed to read --path: %w", err)
			}
			return runBindingCandidates(state, path)
		},
	}
	candidatesCmd.Flags().String("path", "ori.yaml", "path to the runtime configuration")

	cmd.AddCommand(candidatesCmd, proveCmd, exportCmd, captureCmd, deliverCmd)
	return cmd
}

// runBindingCapture reads the inventory, runs the ceremony, and writes a draft.
//
// The draft is never signed here and is incomplete on purpose: the fields an
// authority stage checks belong to the signing step, so nothing this command
// writes can be mistaken for a document a runtime would accept.
func runBindingCapture(
	state *rootState, in io.Reader, path, zone, out string, force bool,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), exportTimeout)
	defer cancel()

	payload, err := invokeBridgeEchoing(state, ctx, []string{
		"commissioning", "inventory", "--path", path,
	}, false)
	if err != nil {
		return err
	}
	raw, marshalErr := json.Marshal(payload["result"])
	if marshalErr != nil {
		return fmt.Errorf("failed to re-encode the inventory: %w", marshalErr)
	}
	var inv capture.Inventory
	if decodeErr := json.Unmarshal(raw, &inv); decodeErr != nil {
		return fmt.Errorf("the runtime inventory is not readable: %w", decodeErr)
	}

	// Checked before a single question, so an operator does not answer nine of
	// them at a panel to be told the path was in the way.
	if out != "" {
		if err := checkDraftPath(out, force); err != nil {
			return err
		}
	}

	asker := capture.NewTerminalAsker(in, state.stderr)
	draft, captureErr := capture.Capture(asker, inv, zone)
	if captureErr != nil {
		return refusedError{captureErr}
	}

	encoded, encodeErr := capture.DraftJSON(draft)
	if encodeErr != nil {
		return fmt.Errorf("failed to encode the draft: %w", encodeErr)
	}
	if out == "" {
		_, writeErr := state.stdout.Write(append(encoded, '\n'))
		return writeErr
	}
	if writeErr := writeDraft(out, append(encoded, '\n'), force); writeErr != nil {
		return writeErr
	}
	fmt.Fprintf(state.stderr, "wrote an unsigned draft to %s\n", out)
	return nil
}

// runBindingDeliver hands a signed envelope to the runtime and reports its verdict.
func runBindingDeliver(state *rootState, path, file string, force bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), exportTimeout)
	defer cancel()

	args := []string{"commissioning", "deliver", "--path", path, "--binding", file}
	if force {
		args = append(args, "--force")
	}
	payload, err := invokeCommissioningBridge(state, ctx, args)
	if err != nil {
		return err
	}
	if state.json {
		return nil
	}
	result, _ := payload["result"].(map[string]any)
	stateName, _ := result["state"].(string)
	message, _ := result["message"].(string)
	fmt.Fprintf(state.stdout, "%s: %s\n", stateName, message)
	return nil
}

// runBindingProve invokes the runtime's proof operation and renders its verdict.
//
// **No deadline is imposed here, deliberately.** The runtime bounds its own
// hold and observation window; consent before them is unbounded, because an
// operator standing at a panel decides in their own time. A context deadline
// would cancel the subprocess with SIGKILL, which the runtime cannot catch, and
// the coil would be left commanded with the pin unreleased and the audit row
// never completed. The runtime turns an interrupt into a cancellation that does
// release the pin, so Ctrl-C is the correct way to abandon this — not a timer
// in the tool.
func runBindingProve(state *rootState, path, outcome, zone string) error {
	args := []string{"commissioning", "prove-command", "--path", path, "--outcome", outcome}
	if zone != "" {
		args = append(args, "--zone", zone)
	}
	payload, err := invokeCommissioningBridge(state, context.Background(), args)
	if err != nil {
		return err
	}
	result, _ := payload["result"].(map[string]any)
	attestation, _ := result["operator_attestation"].(string)
	held, _ := result["held_ms"].(float64)
	// The runtime turns every non-matched verdict into a refusal, so reaching
	// here with anything else means a payload this build does not understand.
	// Reporting it as a proof would assume a meaning it was never given.
	if attestation != binding.AttestationMatched {
		return refusedError{fmt.Errorf(
			"the runtime reported the attestation %q, which this build does not "+
				"recognise as a proof", attestation)}
	}
	if state.json {
		return nil
	}
	fmt.Fprintf(state.stdout,
		"commanded %s: the operator attested %q after %.1fs\n",
		outcome, attestation, held/1000)
	fmt.Fprintf(state.stdout,
		"the runtime did not verify the coil; only that attestation speaks to "+
			"what happened\n")
	return nil
}

func runBindingExport(state *rootState, path, zone string) error {
	ctx, cancel := context.WithTimeout(context.Background(), exportTimeout)
	defer cancel()

	payload, err := invokeBridgeEchoing(state, ctx, []string{
		"commissioning", "proof-export", "--path", path,
	}, zone == "")
	if err != nil {
		return err
	}
	if zone == "" {
		return nil
	}

	raw, marshalErr := json.Marshal(payload["result"])
	if marshalErr != nil {
		return fmt.Errorf("failed to re-encode the proof export: %w", marshalErr)
	}
	export, decodeErr := binding.DecodeProofExport(raw)
	if decodeErr != nil {
		return decodeErr
	}
	leg, legErr := binding.ControlPathFor(export, zone)
	if legErr != nil {
		return refusedError{legErr}
	}
	if state.json {
		encoded, encodeErr := binding.ControlPathJSON(*leg)
		if encodeErr != nil {
			return encodeErr
		}
		_, writeErr := state.stdout.Write(append(encoded, '\n'))
		return writeErr
	}
	fmt.Fprintf(state.stdout,
		"control leg for zone %q: %s, %d observations, performed at %d\n",
		zone, leg.Method, len(leg.Observations), leg.PerformedAtMs)
	return nil
}

// invokeCommissioningBridge runs a bridge command and unwraps its envelope. The
// bridge emits exactly one JSON object; a structured refusal is rendered and
// returned as an error so a refused proof exits non-zero rather than looking
// like a quiet success.
func invokeCommissioningBridge(
	state *rootState, ctx context.Context, args []string,
) (map[string]any, error) {
	return invokeBridgeEchoing(state, ctx, args, true)
}

// invokeBridgeEchoing runs a bridge command. `echo` writes the runtime's own
// envelope to stdout in JSON mode; a command that emits an object of its own
// passes false, because the contract is one JSON object per command and two
// cannot be parsed by anything expecting one.
func invokeBridgeEchoing(
	state *rootState, ctx context.Context, args []string, echo bool,
) (map[string]any, error) {
	result, err := state.bridge.Run(ctx, args...)
	if len(result.Stderr) > 0 {
		_, _ = state.stderr.Write(result.Stderr)
	}
	var payload map[string]any
	if jsonErr := json.Unmarshal(result.Stdout, &payload); jsonErr != nil || payload == nil {
		// No readable envelope, so the exit status is all there is to report.
		if err != nil {
			return nil, fmt.Errorf("runtime bridge command %v failed: %w", args, err)
		}
		if payload == nil {
			return nil, fmt.Errorf("runtime bridge returned a non-object JSON value")
		}
		return nil, fmt.Errorf("runtime bridge returned invalid JSON: %w", jsonErr)
	}
	if state.json && echo {
		if _, writeErr := state.stdout.Write(result.Stdout); writeErr != nil {
			return nil, writeErr
		}
	}
	if ok, _ := payload["ok"].(bool); !ok {
		// A refusal the runtime described. It exits non-zero to say so, and
		// that status is the refusal rather than a failure to report.
		return payload, refusedError{
			fmt.Errorf("%s: %s", args[1], refusalDetail(payload)),
		}
	}
	// `ok: true` and a non-zero exit is the runtime claiming success and then
	// dying -- killed, out of memory, a crash on flush. The claim is not
	// honoured: a proof reported this way would be assembled into a leg.
	if err != nil {
		return nil, fmt.Errorf(
			"runtime bridge command %v reported success and then failed: %w",
			args, err)
	}
	return payload, nil
}

// refusedError marks an expected operator outcome — a refused document, a
// refused proof — as distinct from a tool that failed. The contract gives it
// its own exit status for that reason.
type refusedError struct{ err error }

func (r refusedError) Error() string { return r.err.Error() }
func (r refusedError) Unwrap() error { return r.err }

// refusalDetail names the stage as well as the reason.
//
// A refusal only proves a check ran if every earlier stage passed, so a reason
// without its stage is a sentence rather than a verdict.
func refusalDetail(payload map[string]any) string {
	detail := errorDetail(payload)
	errObj, _ := payload["error"].(map[string]any)
	if errObj == nil {
		return detail
	}
	if stage, _ := errObj["stage"].(string); stage != "" {
		return fmt.Sprintf("%s (at stage %s)", detail, stage)
	}
	return detail
}

// checkDraftPath refuses a destination before the ceremony begins.
//
// `os.Lstat`, not `os.Stat`: a planted symlink would otherwise send the draft
// wherever it points, written as the installer's own uid.
func checkDraftPath(out string, force bool) error {
	info, err := os.Lstat(out)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"%s is a symbolic link; a draft is written to the path given, not "+
				"wherever a link points", out)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", out)
	}
	if !force {
		return fmt.Errorf(
			"%s already exists; pass --force to replace it, having checked it is "+
				"not a draft someone else is still working from", out)
	}
	return nil
}

// writeDraft creates the file without following a link, and without inheriting
// an existing file's mode.
func writeDraft(out string, body []byte, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC | syscall.O_NOFOLLOW
	}
	file, err := os.OpenFile(out, flags, 0o600)
	if err != nil {
		return err
	}
	if _, writeErr := file.Write(body); writeErr != nil {
		_ = file.Close()
		return writeErr
	}
	if force {
		// A replaced draft must not keep a mode someone else chose for it.
		if chmodErr := file.Chmod(0o600); chmodErr != nil {
			_ = file.Close()
			return chmodErr
		}
	}
	return file.Close()
}

// runBindingCandidates shows what a binding on this device may name.
func runBindingCandidates(state *rootState, path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), exportTimeout)
	defer cancel()

	payload, err := invokeBridgeEchoing(state, ctx, []string{
		"commissioning", "inventory", "--path", path,
	}, true)
	if err != nil {
		return err
	}
	if state.json {
		return nil
	}
	raw, marshalErr := json.Marshal(payload["result"])
	if marshalErr != nil {
		return fmt.Errorf("failed to re-encode the inventory: %w", marshalErr)
	}
	var inv capture.Inventory
	if decodeErr := json.Unmarshal(raw, &inv); decodeErr != nil {
		return fmt.Errorf("the runtime inventory is not readable: %w", decodeErr)
	}
	fmt.Fprintf(state.stdout, "device %s, posture %s, binding %d in force\n",
		inv.DeviceID, inv.DeploymentPosture, inv.AcceptedBindingSeq)
	if len(inv.SensorIDs) == 0 {
		fmt.Fprintf(state.stdout, "  sensors:   none declared\n")
	}
	for _, id := range inv.SensorIDs {
		fmt.Fprintf(state.stdout, "  sensor:    %s\n", id)
	}
	if len(inv.Actuators) == 0 {
		fmt.Fprintf(state.stdout,
			"  actuators: none declared — a site with nothing to actuate has no "+
				"binding to make\n")
	}
	for _, act := range inv.Actuators {
		fmt.Fprintf(state.stdout, "  actuator:  %s\n", capture.DescribeActuator(act))
	}
	return nil
}
