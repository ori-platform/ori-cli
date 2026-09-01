// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ori-platform/ori-cli/internal/bridge"
)

// deadlineBridge records whether the caller imposed a deadline on the runtime.
type deadlineBridge struct {
	args        [][]string
	hadDeadline []bool
	out         []byte
	err         error
}

func (d *deadlineBridge) Run(ctx context.Context, args ...string) (bridge.Result, error) {
	_, has := ctx.Deadline()
	d.hadDeadline = append(d.hadDeadline, has)
	d.args = append(d.args, append([]string(nil), args...))
	return bridge.Result{Stdout: d.out}, d.err
}

const provedOK = `{"schema_version":1,"ok":true,"command":"commissioning prove-command",
"result":{"zone_id":"main","outcome":"open_protected_circuit","operator_attestation":"matched",
"held_ms":8400,"command_issued":true,"effect_verified":false}}`

// The runtime bounds its own hold and observation window, and the consent
// before them is unbounded because an operator at a panel decides in their own
// time. A deadline here would cancel the subprocess with SIGKILL, which the
// runtime cannot catch, leaving the coil commanded, the pin unreleased and the
// audit row never completed.
func TestProveImposesNoDeadlineOnTheRuntime(t *testing.T) {
	stub := &deadlineBridge{out: []byte(provedOK)}
	code, _, stderr := runWithOptions(
		[]string{"binding", "prove", "--path", "ori.yaml", "--outcome", "open_protected_circuit"},
		Options{Bridge: stub},
	)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(stub.hadDeadline) != 1 {
		t.Fatalf("bridge invoked %d times", len(stub.hadDeadline))
	}
	if stub.hadDeadline[0] {
		t.Fatal("prove imposed a deadline; a timer here kills the runtime mid-dwell")
	}
}

// The read-only export is a different case: it returns promptly and nothing is
// energised while it runs.
func TestExportIsBounded(t *testing.T) {
	stub := &deadlineBridge{out: []byte(`{"ok":true,"result":{"observations":[]}}`)}
	if code, _, stderr := runWithOptions(
		[]string{"binding", "export", "--path", "ori.yaml"},
		Options{Bridge: stub},
	); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !stub.hadDeadline[0] {
		t.Fatal("the read-only export should be bounded")
	}
}

// CLI-9: the tool invokes the operation and does not perform it.
func TestProvePassesOnlyWhatItParsed(t *testing.T) {
	stub := &deadlineBridge{out: []byte(provedOK)}
	runWithOptions(
		[]string{"binding", "prove", "--path", "ori.yaml",
			"--outcome", "open_protected_circuit", "--zone", "main"},
		Options{Bridge: stub},
	)
	got := strings.Join(stub.args[0], " ")
	want := "commissioning prove-command --path ori.yaml --outcome open_protected_circuit --zone main"
	if got != want {
		t.Fatalf("bridge args\n got: %s\nwant: %s", got, want)
	}
	// Neither consent nor any part of the observation may travel from here.
	for _, forbidden := range []string{
		"--yes", "--consent", "--nonce", "--observed-circuit", "--load-before",
		"--load-after", "--sensor-before", "--sensor-after", "--instrument",
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("the CLI supplied %s", forbidden)
		}
	}
}

// A refused proof must not look like a quiet success.
func TestRefusedProofExitsNonZero(t *testing.T) {
	stub := &deadlineBridge{out: []byte(
		`{"ok":false,"command":"commissioning prove-command",` +
			`"error":{"code":"attestation_inconclusive","detail":"no proof follows"}}`)}
	code, _, stderr := runWithOptions(
		[]string{"binding", "prove", "--path", "ori.yaml", "--outcome", "open_protected_circuit"},
		Options{Bridge: stub},
	)
	// A refusal is the system working; an installer needs it distinguishable
	// from a broken tool, so it does not share an exit status with one.
	if code != 2 {
		t.Fatalf("a refused proof exited %d, want 2: %s", code, stderr)
	}
	if !strings.Contains(stderr, "attestation_inconclusive") {
		t.Fatalf("the refusal reason was not shown: %s", stderr)
	}
}

func TestExportAssemblesALegForAZone(t *testing.T) {
	stub := &deadlineBridge{out: []byte(`{"ok":true,"result":{"observations":[
{"zone_id":"main","outcome":"open_protected_circuit","operator_attestation":"matched","command_issued":true,"release_requested":true,"effect_verified":false,"coil_state_commanded":"energised","level_driven":"high",
 "commanded_at_ms":100,"observed":{"commanded":"open_protected_circuit","coil_state":"energised",
 "gpio_level":"high","load_present_before":true,"load_present_after":false,
 "terminal_state_observed":"open"}},
{"zone_id":"main","outcome":"close_protected_circuit","operator_attestation":"matched","command_issued":true,"release_requested":true,"effect_verified":false,"coil_state_commanded":"de_energised","level_driven":"low",
 "commanded_at_ms":200,"observed":{"commanded":"close_protected_circuit","coil_state":"de_energised",
 "gpio_level":"low","load_present_before":false,"load_present_after":true,
 "terminal_state_observed":"closed"}}]}}`)}
	code, stdout, stderr := runWithOptions(
		[]string{"binding", "export", "--path", "ori.yaml", "--zone", "main"},
		Options{Bridge: stub},
	)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "commanded_and_observed") || !strings.Contains(stdout, "2 observations") {
		t.Fatalf("the leg was not reported: %s", stdout)
	}
}

func TestExportRefusesAnIncompleteLeg(t *testing.T) {
	stub := &deadlineBridge{out: []byte(`{"ok":true,"result":{"observations":[
{"zone_id":"main","outcome":"open_protected_circuit","operator_attestation":"matched","command_issued":true,"release_requested":true,"effect_verified":false,"coil_state_commanded":"energised","level_driven":"high",
 "commanded_at_ms":100,"observed":{"commanded":"open_protected_circuit","coil_state":"energised",
 "gpio_level":"high","load_present_before":true,"load_present_after":false,
 "terminal_state_observed":"open"}}]}}`)}
	code, _, stderr := runWithOptions(
		[]string{"binding", "export", "--path", "ori.yaml", "--zone", "main"},
		Options{Bridge: stub},
	)
	if code == 0 {
		t.Fatal("an incomplete leg was reported as usable")
	}
	if !strings.Contains(stderr, "close_protected_circuit") {
		t.Fatalf("the refusal does not name what is missing: %s", stderr)
	}
}

func stateWith(bridge BridgeRunner, stdout, stderr *bytes.Buffer) *rootState {
	return &rootState{stdout: stdout, stderr: stderr, bridge: bridge}
}

const inventoryOK = `{"ok":true,"result":{"device_id":"bench-01",
"sensor_ids":["load-current-main"],
"actuators":[{"kind":"local_gpio","identity":{"gpio_pin":26}}],
"deployment_posture":"development","accepted_binding_seq":3}}`

// sensor, actuator, polarity, open, close, terminal, capacity, range, method
const exportBothMatched = `{"ok":true,"result":{"observations":[
{"zone_id":"main","outcome":"open_protected_circuit","operator_attestation":"matched","command_issued":true,"release_requested":true,"effect_verified":false,"coil_state_commanded":"energised","level_driven":"high",
 "commanded_at_ms":100,"observed":{"commanded":"open_protected_circuit","coil_state":"energised",
 "gpio_level":"high","load_present_before":true,"load_present_after":false,
 "terminal_state_observed":"open"}},
{"zone_id":"main","outcome":"close_protected_circuit","operator_attestation":"matched","command_issued":true,"release_requested":true,"effect_verified":false,"coil_state_commanded":"de_energised","level_driven":"low",
 "commanded_at_ms":200,"observed":{"commanded":"close_protected_circuit","coil_state":"de_energised",
 "gpio_level":"low","load_present_before":false,"load_present_after":true,
 "terminal_state_observed":"closed"}}]}}`

// The ceremony's questions, in order: sensor, actuator, polarity, the three
// mapping outcomes, provenance, capacity, the eight sensor fields, the
// inventory generation, the proof method and its timestamp, then both
// outcomes' load determinations.
const captureAnswers = "1\n1\nhigh\nenergised\nde_energised\nclosed\n" +
	"nameplate\n10\ncurrent\nampere\npositive_is_load_draw\n0\n100\n" +
	"0.05\nbench-2026-09-01\n1\npre_energisation\n1800000000000\n" +
	// each outcome: coil observed, terminal observed, load before, load after
	"energised\nopen\nyes\nno\n" +
	"de_energised\nclosed\nno\nyes\n"

func TestCaptureBuildsADraftFromTheInventory(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stub := &deadlineBridge{out: []byte(inventoryOK)}
	err := runBindingCapture(
		stateWith(stub, &stdout, &stderr),
		strings.NewReader(captureAnswers), "ori.yaml", "main", "", false,
	)
	if err != nil {
		t.Fatalf("capture: %v (prompts: %s)", err, stderr.String())
	}
	var draft map[string]any
	if jsonErr := json.Unmarshal(stdout.Bytes(), &draft); jsonErr != nil {
		t.Fatalf("the draft is not JSON: %v", jsonErr)
	}
	if draft["device_id"] != "bench-01" {
		t.Fatalf("the draft did not take the device from the inventory: %v", draft)
	}
	if strings.Join(stub.args[0], " ") != "commissioning inventory --path ori.yaml" {
		t.Fatalf("unexpected bridge call: %v", stub.args[0])
	}
}

// Nothing this command writes may be mistaken for a document a runtime accepts.
func TestCaptureWritesNoSignature(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runBindingCapture(
		stateWith(&deadlineBridge{out: []byte(inventoryOK)}, &stdout, &stderr),
		strings.NewReader(captureAnswers), "ori.yaml", "main", "", false,
	); err != nil {
		t.Fatalf("capture: %v", err)
	}
	lowered := strings.ToLower(stdout.String())
	for _, forbidden := range []string{"signature", "signing_key", "signingkey"} {
		if strings.Contains(lowered, forbidden) {
			t.Fatalf("the draft carries %q", forbidden)
		}
	}
}

func TestCaptureRefusesToClobberADraft(t *testing.T) {
	dir := t.TempDir()
	existing := dir + "/draft.json"
	if err := os.WriteFile(existing, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := runBindingCapture(
		stateWith(&deadlineBridge{out: []byte(inventoryOK)}, &stdout, &stderr),
		strings.NewReader(captureAnswers), "ori.yaml", "main", existing, false,
	)
	if err == nil {
		t.Fatal("an existing draft was overwritten without --force")
	}
	body, readErr := os.ReadFile(existing)
	if readErr != nil || string(body) != "{}" {
		t.Fatalf("the existing draft was modified: %q", string(body))
	}
}

// The prompts go to stderr so the draft on stdout stays machine-readable.
func TestCapturePromptsDoNotContaminateTheDraft(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runBindingCapture(
		stateWith(&deadlineBridge{out: []byte(inventoryOK)}, &stdout, &stderr),
		strings.NewReader(captureAnswers), "ori.yaml", "main", "", false,
	); err != nil {
		t.Fatalf("capture: %v", err)
	}
	if !strings.Contains(stderr.String(), "protected circuit") {
		t.Fatal("the ceremony asked nothing on stderr")
	}
	if strings.Contains(stdout.String(), "protected circuit?") {
		t.Fatal("a prompt was written into the draft")
	}
}

func TestDeliverReportsTheRuntimesVerdict(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stub := &deadlineBridge{out: []byte(`{"ok":true,"result":{"state":"provisional",
"message":"binding verified and staged, and provisional"}}`)}
	if err := runBindingDeliver(
		stateWith(stub, &stdout, &stderr), "ori.yaml", "signed.json", false,
	); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if !strings.Contains(stdout.String(), "provisional") {
		t.Fatalf("the verdict was not reported: %s", stdout.String())
	}
	if strings.Join(stub.args[0], " ") !=
		"commissioning deliver --path ori.yaml --binding signed.json" {
		t.Fatalf("unexpected bridge call: %v", stub.args[0])
	}
}

func TestDeliverSurfacesARefusalWithItsStage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stub := &deadlineBridge{out: []byte(`{"ok":false,"command":"commissioning deliver",
"error":{"code":"proof_contradiction","detail":"the document was refused",
"stage":"mapping_self_consistency"}}`)}
	err := runBindingDeliver(stateWith(stub, &stdout, &stderr), "ori.yaml", "signed.json", false)
	if err == nil {
		t.Fatal("a refused delivery reported success")
	}
	if !strings.Contains(err.Error(), "proof_contradiction") {
		t.Fatalf("the refusal reason was lost: %v", err)
	}
	// Asserted against a detail that does not mention the stage, so the test
	// cannot pass on the runtime's prose happening to include it.
	if !strings.Contains(err.Error(), "mapping_self_consistency") {
		t.Fatalf("the stage was lost, leaving a sentence not a verdict: %v", err)
	}
}

// A runtime that emits its envelope and then dies must not be reported as a
// completed, attested proof.
func TestABridgeThatDiesAfterItsEnvelopeIsNotASuccess(t *testing.T) {
	stub := &deadlineBridge{out: []byte(provedOK), err: errKilled}
	code, _, stderr := runWithOptions(
		[]string{"binding", "prove", "--path", "ori.yaml", "--outcome", "open_protected_circuit"},
		Options{Bridge: stub},
	)
	if code == 0 {
		t.Fatalf("a killed bridge reported a proof: %s", stderr)
	}
}

var errKilled = errStrCmd("signal: killed")

type errStrCmd string

func (e errStrCmd) Error() string { return string(e) }

// The contract is one JSON object per command; two cannot be parsed by
// anything expecting one.
func TestJSONModeEmitsExactlyOneObject(t *testing.T) {
	cases := []struct {
		name string
		args []string
		out  string
	}{
		{"prove", []string{"binding", "prove", "--path", "p", "--outcome", "open_protected_circuit"}, provedOK},
		{"export", []string{"binding", "export", "--path", "p"}, `{"ok":true,"result":{"observations":[]}}`},
		{"export-zone", []string{"binding", "export", "--path", "p", "--zone", "main"}, exportBothMatched},
		{"deliver", []string{"binding", "deliver", "--path", "p", "--binding", "b.json"},
			`{"ok":true,"result":{"state":"provisional","message":"staged"}}`},
	}
	for _, tc := range cases {
		stub := &deadlineBridge{out: []byte(tc.out)}
		code, stdout, stderr := runWithOptions(append([]string{"--json"}, tc.args...), Options{Bridge: stub})
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", tc.name, code, stderr)
		}
		decoder := json.NewDecoder(strings.NewReader(stdout))
		var objects int
		for {
			var v any
			if err := decoder.Decode(&v); err != nil {
				break
			}
			objects++
		}
		if objects != 1 {
			t.Fatalf("%s emitted %d JSON objects:\n%s", tc.name, objects, stdout)
		}
	}
}

// The leg is what an installer puts in the draft they are about to sign. Go
// field names, and present-but-empty optionals, make it unusable for that.
func TestTheExportedLegUsesTheContractsFieldNames(t *testing.T) {
	stub := &deadlineBridge{out: []byte(exportBothMatched)}
	code, stdout, stderr := runWithOptions(
		[]string{"--json", "binding", "export", "--path", "p", "--zone", "main"},
		Options{Bridge: stub},
	)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var leg map[string]any
	if err := json.Unmarshal([]byte(stdout), &leg); err != nil {
		t.Fatalf("not one JSON object: %v\n%s", err, stdout)
	}
	for _, want := range []string{"method", "performed_at_ms", "observations"} {
		if _, ok := leg[want]; !ok {
			t.Fatalf("the leg has no %q: %v", want, leg)
		}
	}
	// `reason` on a commanded_and_observed leg is refused by the contract.
	for _, absent := range []string{"reason", "Method", "PerformedAtMs", "Observations"} {
		if _, present := leg[absent]; present {
			t.Fatalf("the leg carries %q", absent)
		}
	}
	obs := leg["observations"].([]any)[0].(map[string]any)
	for _, want := range []string{
		"commanded", "coil_state", "gpio_level", "load_present_before",
		"load_present_after", "terminal_state_observed",
	} {
		if _, ok := obs[want]; !ok {
			t.Fatalf("an observation has no %q: %v", want, obs)
		}
	}
	for _, absent := range []string{"sensor_before", "sensor_after", "instrument"} {
		if _, present := obs[absent]; present {
			t.Fatalf("an unmeasured %q was emitted", absent)
		}
	}
}

// A planted link would otherwise send the draft wherever it points, written as
// the installer's own uid, and keep the mode someone else chose for it.
func TestCaptureRefusesToWriteThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "draft.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	for _, force := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		err := runBindingCapture(
			stateWith(&deadlineBridge{out: []byte(inventoryOK)}, &stdout, &stderr),
			strings.NewReader(captureAnswers), "ori.yaml", "main", link, force,
		)
		if err == nil {
			t.Fatalf("force=%v: the draft was written through a link", force)
		}
		body, readErr := os.ReadFile(victim)
		if readErr != nil || string(body) != "ORIGINAL" {
			t.Fatalf("force=%v: the link target was modified: %q", force, string(body))
		}
	}
}

// The path is checked before a single question, so an operator does not answer
// nine of them at a panel to be told the path was in the way.
func TestCaptureChecksTheDestinationBeforeAsking(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "draft.json")
	if err := os.WriteFile(existing, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := runBindingCapture(
		stateWith(&deadlineBridge{out: []byte(inventoryOK)}, &stdout, &stderr),
		strings.NewReader(captureAnswers), "ori.yaml", "main", existing, false,
	)
	if err == nil {
		t.Fatal("an existing draft was overwritten")
	}
	if strings.Contains(stderr.String(), "protected circuit") {
		t.Fatal("the ceremony asked its questions before checking the path")
	}
}

func TestAReplacedDraftIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "draft.json")
	if err := os.WriteFile(target, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := runBindingCapture(
		stateWith(&deadlineBridge{out: []byte(inventoryOK)}, &stdout, &stderr),
		strings.NewReader(captureAnswers), "ori.yaml", "main", target, true,
	); err != nil {
		t.Fatalf("capture: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the replaced draft kept mode %v", info.Mode().Perm())
	}
}

// A degenerate payload is not a proof. The runtime refuses every non-matched
// verdict, so anything else reaching here is a payload this build does not
// understand.
func TestProveRefusesAnAttestationItCannotRead(t *testing.T) {
	for _, body := range []string{
		`{"ok":true,"result":{}}`,
		`{"ok":true,"result":{"operator_attestation":"provisionally_matched"}}`,
		`{"ok":true,"result":{"operator_attestation":null}}`,
	} {
		code, _, stderr := runWithOptions(
			[]string{"binding", "prove", "--path", "p", "--outcome", "open_protected_circuit"},
			Options{Bridge: &deadlineBridge{out: []byte(body)}},
		)
		if code == 0 {
			t.Fatalf("a degenerate payload reported a proof: %s", body)
		}
		if !strings.Contains(stderr, "does not") {
			t.Fatalf("the refusal does not say why: %s", stderr)
		}
	}
}

// A binding may name nothing outside the candidate set, so an installer can
// see before capturing what this device will accept.
func TestCandidatesShowsTheDeclaredInventory(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stub := &deadlineBridge{out: []byte(inventoryOK)}
	if err := runBindingCandidates(stateWith(stub, &stdout, &stderr), "ori.yaml"); err != nil {
		t.Fatalf("candidates: %v", err)
	}
	shown := stdout.String()
	for _, want := range []string{"bench-01", "load-current-main", "gpio_pin=26"} {
		if !strings.Contains(shown, want) {
			t.Fatalf("the candidate set omits %q:\n%s", want, shown)
		}
	}
	if strings.Join(stub.args[0], " ") != "commissioning inventory --path ori.yaml" {
		t.Fatalf("unexpected bridge call: %v", stub.args[0])
	}
}

// A site with nothing to actuate has no binding to make, and the candidate set
// should say so rather than showing an empty list.
func TestCandidatesSaysWhenThereIsNothingToBind(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stub := &deadlineBridge{out: []byte(
		`{"ok":true,"result":{"device_id":"d","sensor_ids":[],"actuators":[]}}`)}
	if err := runBindingCandidates(stateWith(stub, &stdout, &stderr), "ori.yaml"); err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if !strings.Contains(stdout.String(), "nothing to actuate") {
		t.Fatalf("an empty inventory was shown as an empty list:\n%s", stdout.String())
	}
}

// The runtime exits non-zero to say it refused. That status is the refusal, not
// a failure to report over it — observed on the bench, where a correct
// `attestation_inconclusive` surfaced as "bridge failed: exit status 2".
func TestAStructuredRefusalSurvivesANonZeroExit(t *testing.T) {
	stub := &deadlineBridge{
		out: []byte(`{"ok":false,"command":"commissioning prove-command",` +
			`"error":{"code":"attestation_inconclusive","detail":"no proof follows"}}`),
		err: errKilled,
	}
	code, _, stderr := runWithOptions(
		[]string{"binding", "prove", "--path", "p", "--outcome", "open_protected_circuit"},
		Options{Bridge: stub},
	)
	if code != 2 {
		t.Fatalf("a structured refusal exited %d, want 2: %s", code, stderr)
	}
	if !strings.Contains(stderr, "attestation_inconclusive") {
		t.Fatalf("the refusal reason was replaced by the exit status: %s", stderr)
	}
}
