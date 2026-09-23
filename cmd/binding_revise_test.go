// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ori-platform/ori-cli/internal/binding"
	"github.com/ori-platform/ori-cli/internal/bridge"
	"github.com/ori-platform/ori-cli/internal/capture"
)

const (
	priorProofAt   = int64(1700000000000)
	priorControlAt = int64(1700000100000)
	reviseNow      = int64(1800000000000)
)

var revisionKey = ed25519.NewKeyFromSeed([]byte("ori-cli-revision-test-seed-32byt"))

func intPtr(v int) *int    { return &v }
func boolPtr(v bool) *bool { return &v }

// provenZone is a zone with both legs proven, as a binding in force has.
func provenZone(zoneID, sensorID string, pin int, activeHigh bool) binding.Zone {
	openCoil, closeCoil := binding.CoilEnergised, binding.CoilDeEnergised
	levelFor := func(coil string) string {
		if (coil == binding.CoilEnergised) == activeHigh {
			return binding.GPIOLevelHigh
		}
		return binding.GPIOLevelLow
	}
	observations := func(withLevel bool) []binding.Observation {
		open := binding.Observation{
			Commanded: binding.OutcomeOpen, CoilState: openCoil,
			TerminalStateObserved: binding.CircuitOpen, LoadPresentBefore: true,
		}
		closeObs := binding.Observation{
			Commanded: binding.OutcomeClose, CoilState: closeCoil,
			TerminalStateObserved: binding.CircuitClosed, LoadPresentAfter: true,
		}
		if withLevel {
			open.GPIOLevel, closeObs.GPIOLevel = levelFor(openCoil), levelFor(closeCoil)
		}
		return []binding.Observation{open, closeObs}
	}
	return binding.Zone{
		ZoneID: zoneID,
		RatedCapacity: binding.RatedCapacity{
			Parameter: "rated_capacity_amps", Value: 10, Provenance: binding.ProvenanceNameplate,
		},
		Sensor: binding.Sensor{
			SensorID: sensorID, Quantity: "current", Unit: "ampere", RangeMin: 0,
			RangeMax: 100, Direction: "positive_is_load_draw", NoiseFloor: 0.05,
			CalibrationRef: "cal-" + zoneID,
		},
		Actuator: binding.Actuator{
			Kind:     binding.KindLocalGPIO,
			Identity: binding.Identity{GPIOPin: intPtr(pin), ActiveHigh: boolPtr(activeHigh)},
			Mapping: binding.Mapping{
				OpenProtectedCircuit: openCoil, CloseProtectedCircuit: closeCoil,
				DeEnergisedTerminalState: binding.CircuitClosed,
			},
		},
		Proof: binding.Proof{
			Method: binding.MethodPreEnergy, PerformedAtMs: priorProofAt,
			Observations: observations(false),
			ControlPath: &binding.ControlPath{
				Method: binding.ControlCommanded, PerformedAtMs: priorControlAt,
				Observations: observations(true),
			},
		},
	}
}

// device holds a signed binding in force, and answers the two bridge commands
// a revision reads as the runtime would.
type device struct {
	envelope []byte
	accepted *binding.Accepted
	inv      map[string]any
	// export overrides the binding-export answer when set.
	export string
	calls  [][]string
}

func signedBinding(t *testing.T, seq int64, supersedes *string, zones ...binding.Zone) []byte {
	t.Helper()
	return signedBindingAt(t, seq, supersedes, 1, zones...)
}

func signedBindingAt(t *testing.T, seq int64, supersedes *string, generation int64, zones ...binding.Zone) []byte {
	t.Helper()
	doc := binding.Binding{
		V: 1, BindingSeq: seq, DeviceID: "bench-01", IssuedAtMs: priorControlAt + 1,
		SignerID: "commissioner", SigningKey: binding.SigningKeyName(revisionKey.Public().(ed25519.PublicKey)),
		InventoryGeneration: generation, Supersedes: supersedes, Actor: "installer", Reason: "commissioned",
		Zones: zones,
	}
	envelope, _, err := doc.SignedEnvelope(revisionKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return envelope
}

func bindingInForce(t *testing.T, zones ...binding.Zone) *device {
	t.Helper()
	return bindingInForceAt(t, 1, zones...)
}

func bindingInForceAt(t *testing.T, generation int64, zones ...binding.Zone) *device {
	t.Helper()
	envelope := signedBindingAt(t, 3, nil, generation, zones...)
	accepted, err := binding.VerifyOffline(envelope)
	if err != nil {
		t.Fatalf("the binding in force does not verify: %v", err)
	}
	if !accepted.InForceEligible() {
		t.Fatal("the fixture is not a binding that could be in force")
	}
	sensors := []any{}
	actuators := []any{}
	for _, z := range zones {
		sensors = append(sensors, z.Sensor.SensorID)
		actuators = append(actuators, map[string]any{
			"kind": "local_gpio", "identity": map[string]any{"gpio_pin": *z.Actuator.Identity.GPIOPin},
		})
	}
	return &device{
		envelope: envelope,
		accepted: accepted,
		inv: map[string]any{
			"device_id": "bench-01", "sensor_ids": sensors, "actuators": actuators,
			"deployment_posture": "development", "accepted_binding_seq": 3,
			"accepted_binding_hash": accepted.CanonicalHash,
		},
	}
}

func singleZone(t *testing.T) *device {
	return bindingInForce(t, provenZone("main", "load-current-main", 26, true))
}

func twoZones(t *testing.T) *device {
	return bindingInForce(t,
		provenZone("main", "load-current-main", 26, true),
		provenZone("aux", "load-current-aux", 19, true))
}

// declaring replaces the actuators the device declares, by pin.
func (d *device) declaring(pins ...int) *device {
	actuators := []any{}
	for _, pin := range pins {
		actuators = append(actuators, map[string]any{
			"kind": "local_gpio", "identity": map[string]any{"gpio_pin": pin},
		})
	}
	d.inv["actuators"] = actuators
	return d
}

func (d *device) Run(_ context.Context, args ...string) (bridge.Result, error) {
	d.calls = append(d.calls, append([]string(nil), args...))
	switch args[1] {
	case "inventory":
		body, _ := json.Marshal(map[string]any{"ok": true, "result": d.inv})
		return bridge.Result{Stdout: body}, nil
	case "binding-export":
		if d.export != "" {
			return bridge.Result{Stdout: []byte(d.export)}, nil
		}
		body, _ := json.Marshal(map[string]any{"ok": true, "result": map[string]any{
			"binding_seq": 3, "binding_hash": d.accepted.CanonicalHash,
			"envelope_json": string(d.envelope),
		}})
		return bridge.Result{Stdout: body}, nil
	}
	return bridge.Result{}, fmt.Errorf("unexpected bridge call %v", args)
}

func (d *device) exported() bool {
	for _, call := range d.calls {
		if call[1] == "binding-export" {
			return true
		}
	}
	return false
}

// Answers for a revision, in the order the ceremony asks. Each fact is
// answered unchanged unless overridden.
type answers struct {
	why, actuator, replaced, sensor, calibration, polarity, mapping, capacity, generation []string
	proof                                                                                 []string
}

func carry() answers {
	return answers{
		why: []string{"breaker upgraded"}, actuator: []string{"unchanged"},
		replaced: []string{"none"}, sensor: []string{"unchanged"},
		calibration: []string{"unchanged"}, polarity: []string{"unchanged"},
		mapping: []string{"unchanged"}, capacity: []string{"unchanged"},
		generation: []string{"unchanged"},
	}
}

// movedTo21 answers a zone moved to gpio_pin 21, which no zone drives.
func movedTo21() answers {
	a := carry()
	a.actuator = []string{"changed", "local_gpio (gpio_pin=21)"}
	a.proof = freshProof(priorProofAt + 1)
	return a
}

// freshProof answers a pre_energisation leg for the mapping in the fixture.
func freshProof(at int64) []string {
	return []string{
		binding.MethodPreEnergy, fmt.Sprint(at),
		"energised", "open", "yes", "no",
		"de_energised", "closed", "no", "yes",
	}
}

func (a answers) stdin() string {
	var all []string
	for _, part := range [][]string{
		a.why, a.actuator, a.replaced, a.sensor, a.calibration, a.polarity, a.mapping,
		a.capacity, a.generation, a.proof,
	} {
		all = append(all, part...)
	}
	return strings.Join(all, "\n") + "\n"
}

type runOpts struct {
	json bool
	zone string
	// file, when set, is presented with --revise instead of the runtime's export.
	file []byte
}

type revisionRun struct {
	code           int
	stdout, stderr string
	out            string
}

// revise drives `ori binding capture` through the command tree.
func revise(t *testing.T, d *device, stdin string, opts runOpts) revisionRun {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "draft.json")
	zone := opts.zone
	if zone == "" {
		zone = "main"
	}
	args := []string{"binding", "capture", "--path", "ori.yaml", "--zone", zone, "--out", out}
	if opts.file != nil {
		prior := filepath.Join(dir, "in-force.json")
		if err := os.WriteFile(prior, opts.file, 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--revise", prior)
	}
	if opts.json {
		args = append([]string{"--json"}, args...)
	}
	code, stdout, stderr := runWithOptions(args, Options{
		Bridge: d,
		Stdin:  strings.NewReader(stdin),
		NowMs:  func() int64 { return reviseNow },
	})
	return revisionRun{code: code, stdout: stdout, stderr: stderr, out: out}
}

func (r revisionRun) draft(t *testing.T) binding.Binding {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("the revision exited %d:\n%s%s", r.code, r.stdout, r.stderr)
	}
	raw, err := os.ReadFile(r.out)
	if err != nil {
		t.Fatalf("no draft was written: %v", err)
	}
	doc, _, err := binding.DecodeDocument(raw)
	if err != nil {
		t.Fatalf("the draft does not decode: %v", err)
	}
	return doc
}

// refused holds a refusal to its invariants: the exit status, the reason, and
// no draft on disk. In JSON mode, exactly one error object and nothing on stdout.
func (r revisionRun) refused(t *testing.T, name string, status int, because string, jsonMode bool) {
	t.Helper()
	if r.code != status {
		t.Fatalf("%s: exit %d, want %d:\n%s%s", name, r.code, status, r.stdout, r.stderr)
	}
	if !jsonMode && !strings.Contains(r.stderr, because) {
		t.Fatalf("%s: the refusal does not say %q:\n%s", name, because, r.stderr)
	}
	if _, err := os.Stat(r.out); !os.IsNotExist(err) {
		t.Fatalf("%s: a refused capture wrote a draft", name)
	}
	if !jsonMode {
		return
	}
	if strings.TrimSpace(r.stdout) != "" {
		t.Fatalf("%s: a refusal wrote to stdout:\n%s", name, r.stdout)
	}
	// Prompts share stderr with the refusal; the refusal is the last thing on it.
	idx := strings.LastIndex(r.stderr, "{\n  \"ok\"")
	if idx < 0 {
		t.Fatalf("%s: no JSON refusal on stderr:\n%s", name, r.stderr)
	}
	decoder := json.NewDecoder(strings.NewReader(r.stderr[idx:]))
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		t.Fatalf("%s: the refusal is not a JSON object: %v", name, err)
	}
	if ok, _ := payload["ok"].(bool); ok {
		t.Fatalf("%s: a refusal reported ok", name)
	}
	if msg, _ := payload["error"].(string); !strings.Contains(msg, because) {
		t.Fatalf("%s: the JSON refusal does not say %q: %q", name, because, msg)
	}
	var extra any
	if decoder.Decode(&extra) == nil {
		t.Fatalf("%s: more than one JSON object after the refusal", name)
	}
}

func bothModes(t *testing.T, each func(t *testing.T, jsonMode bool)) {
	for _, jsonMode := range []bool{false, true} {
		each(t, jsonMode)
	}
}

// deliverable signs the draft as sign would and runs it through every stage a
// runtime holding the binding in force would, with the zone state it retained
// and the hardware the device declares.
func deliverable(
	t *testing.T, d *device, draft binding.Binding, multiplier *float64,
) (*binding.Accepted, error) {
	t.Helper()
	draft.IssuedAtMs, draft.SignerID, draft.Actor = reviseNow, "commissioner", "installer"
	draft.SigningKey = binding.SigningKeyName(revisionKey.Public().(ed25519.PublicKey))
	envelope, _, err := draft.SignedEnvelope(revisionKey)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(d.inv)
	var inv capture.Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	refs, err := capture.DeclaredRefs(inv)
	if err != nil {
		t.Fatal(err)
	}
	hash := d.accepted.CanonicalHash
	return binding.VerifyEnvelope(envelope, binding.Context{
		DeviceID:                   "bench-01",
		CommissioningAnchorCurrent: revisionKey.Public().(ed25519.PublicKey),
		AcceptedBindingSeq:         3,
		AcceptedBindingHash:        &hash,
		DeclaredSensorIDs:          inv.SensorIDs,
		DeclaredActuators:          refs,
		DeploymentPosture:          "development",
		ProfileMultiplier:          multiplier,
		AcceptedZoneState:          binding.RetainedState(d.accepted),
	})
}

type revisionJSON struct {
	OK     bool `json:"ok"`
	Result struct {
		Path     string           `json:"path"`
		Revision capture.Revision `json:"revision"`
	} `json:"result"`
}

func (r revisionRun) revision(t *testing.T) capture.Revision {
	t.Helper()
	var payload revisionJSON
	if err := json.Unmarshal([]byte(r.stdout), &payload); err != nil || !payload.OK {
		t.Fatalf("the JSON output is not one ok object: %v\n%s", err, r.stdout)
	}
	if payload.Result.Path != r.out {
		t.Fatalf("the JSON output names %q, not the draft written", payload.Result.Path)
	}
	return payload.Result.Revision
}

func TestRevisionNamesTheBindingInForce(t *testing.T) {
	a := carry()
	a.capacity = []string{"changed", "installer_measured", "16"}
	for _, route := range []string{"export", "file"} {
		d := singleZone(t)
		opts := runOpts{}
		if route == "file" {
			opts.file = d.envelope
		}
		draft := revise(t, d, a.stdin(), opts).draft(t)
		if draft.BindingSeq != 4 {
			t.Fatalf("%s: binding_seq %d, want one past the 3 in force", route, draft.BindingSeq)
		}
		if draft.Supersedes == nil || *draft.Supersedes != d.accepted.CanonicalHash {
			t.Fatalf("%s: supersedes %v, want %s", route, draft.Supersedes, d.accepted.CanonicalHash)
		}
		if (route == "export") != d.exported() {
			t.Fatalf("%s: the binding in force was read from the wrong place: %v", route, d.calls)
		}
		accepted, err := deliverable(t, d, draft, nil)
		if err != nil {
			t.Fatalf("%s: a runtime holding the binding in force refuses the revision: %v", route, err)
		}
		if !accepted.InForceEligible() {
			t.Fatalf("%s: a capacity-only revision lost the proof it carries", route)
		}
	}
}

// The prior value of everything changed is carried into the reason, after the
// installer's own why.
func TestRevisionCarriesPriorValuesIntoTheReason(t *testing.T) {
	a := movedTo21()
	a.why = []string{"contactor moved to the new panel"}
	a.replaced = []string{"sensor"}
	a.capacity = []string{"changed", "nameplate", "16"}
	a.generation = []string{"changed", "2"}
	draft := revise(t, singleZone(t).declaring(21), a.stdin(), runOpts{}).draft(t)
	for _, want := range []string{
		"contactor moved to the new panel. ",
		"actuator was local_gpio (gpio_pin=26), now local_gpio (gpio_pin=21)",
		"replaced_like_for_like was as commissioned, now sensor replaced",
		"rated_capacity was 10A (nameplate), now 16A (nameplate)",
		"inventory_generation was 1, now 2",
	} {
		if !strings.Contains(draft.Reason, want) {
			t.Fatalf("the reason does not carry %q:\n%s", want, draft.Reason)
		}
	}
}

// The signer's reason is the one capture composed. sign keeps it and refuses a
// --reason that would replace it, rather than discarding either.
func TestSignKeepsTheCarriedReason(t *testing.T) {
	a := carry()
	a.capacity = []string{"changed", "nameplate", "16"}
	run := revise(t, singleZone(t), a.stdin(), runOpts{})
	draft := run.draft(t)
	dir := filepath.Dir(run.out)
	key := writeTemp(t, dir, "key", []byte(fmt.Sprintf("%x", revisionKey.Seed())), 0o600)

	signed := filepath.Join(dir, "signed.json")
	code, _, stderr := runWithOptions([]string{"binding", "sign", "--in", run.out, "--key", key,
		"--signer-id", "s", "--actor", "a", "--out", signed}, Options{})
	if code != 0 {
		t.Fatalf("sign refused the revision draft: %s", stderr)
	}
	accepted, err := binding.VerifyOffline(mustRead(t, signed))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Binding struct {
			Reason string `json:"reason"`
		} `json:"binding"`
	}
	_ = json.Unmarshal(accepted.CanonicalBytes, &env.Binding)
	if env.Binding.Reason != draft.Reason {
		t.Fatalf("the signed reason %q is not the one capture carried %q", env.Binding.Reason, draft.Reason)
	}

	other := filepath.Join(dir, "other.json")
	code, _, stderr = runWithOptions([]string{"binding", "sign", "--in", run.out, "--key", key,
		"--signer-id", "s", "--actor", "a", "--reason", "something else", "--out", other}, Options{})
	if code != 2 || !strings.Contains(stderr, "signing does not rewrite a document") {
		t.Fatalf("a --reason replacing the carried one was not refused: exit %d %s", code, stderr)
	}
	mustNotExist(t, other)
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Only the binding the runtime reports in force is a prior, whichever route
// presents it; anything else is refused before a question is asked.
func TestRevisionRefusesAnythingButTheBindingInForce(t *testing.T) {
	ok := func(d *device, result map[string]any) string {
		body, _ := json.Marshal(map[string]any{"ok": true, "result": result})
		return string(body)
	}
	provisional := func(d *device) []byte {
		hash := d.accepted.CanonicalHash
		return signedBinding(t, 4, &hash, provenZone("main", "load-current-main", 26, false))
	}
	cases := []struct {
		name    string
		setup   func(d *device) runOpts
		because string
	}{
		{"export refuses", func(d *device) runOpts {
			d.export = `{"ok":false,"command":"commissioning binding-export",` +
				`"error":{"code":"no_binding_in_force","detail":"this device holds no binding in force"}}`
			return runOpts{}
		}, "no_binding_in_force"},
		{"export names another hash", func(d *device) runOpts {
			d.export = ok(d, map[string]any{"binding_seq": 3, "binding_hash": "sha256:" + strings.Repeat("0", 64),
				"envelope_json": string(d.envelope)})
			return runOpts{}
		}, "the runtime exported binding"},
		{"export names another sequence", func(d *device) runOpts {
			d.export = ok(d, map[string]any{"binding_seq": 2, "binding_hash": d.accepted.CanonicalHash,
				"envelope_json": string(d.envelope)})
			return runOpts{}
		}, "the runtime exported binding"},
		{"export carries no envelope", func(d *device) runOpts {
			d.export = ok(d, map[string]any{"binding_seq": 3, "binding_hash": d.accepted.CanonicalHash})
			return runOpts{}
		}, "carries no envelope"},
		{"export envelope as an object", func(d *device) runOpts {
			d.export = ok(d, map[string]any{"binding_seq": 3, "binding_hash": d.accepted.CanonicalHash,
				"envelope_json": json.RawMessage(d.envelope)})
			return runOpts{}
		}, "not readable"},
		{"export envelope truncated", func(d *device) runOpts {
			d.export = ok(d, map[string]any{"binding_seq": 3, "binding_hash": d.accepted.CanonicalHash,
				"envelope_json": string(d.envelope[:len(d.envelope)/2])})
			return runOpts{}
		}, "does not verify"},
		{"export of the provisional document", func(d *device) runOpts {
			d.export = ok(d, map[string]any{"binding_seq": 3, "binding_hash": d.accepted.CanonicalHash,
				"envelope_json": string(provisional(d))})
			return runOpts{}
		}, "the binding in force on device"},
		{"file of the provisional document", func(d *device) runOpts {
			return runOpts{file: provisional(d)}
		}, "the binding in force on device"},
		{"file of another document", func(d *device) runOpts {
			return runOpts{file: signedBinding(t, 3, nil, provenZone("main", "load-current-main", 26, false))}
		}, "the binding in force on device"},
		{"file with an unknown field", func(d *device) runOpts {
			return runOpts{file: []byte(strings.Replace(string(d.envelope), `{"binding":{`, `{"binding":{"extra":1,`, 1))}
		}, "does not verify"},
		{"file with no binding in force", func(d *device) runOpts {
			d.inv["accepted_binding_seq"], d.inv["accepted_binding_hash"] = 0, nil
			return runOpts{file: d.envelope}
		}, "no binding in force"},
	}
	for _, tc := range cases {
		bothModes(t, func(t *testing.T, jsonMode bool) {
			d := singleZone(t)
			opts := tc.setup(d)
			opts.json = jsonMode
			run := revise(t, d, carry().stdin(), opts)
			run.refused(t, tc.name, 2, tc.because, jsonMode)
			if strings.Contains(run.stderr, "Actuator:") {
				t.Fatalf("%s: a question was asked before the refusal", tc.name)
			}
		})
	}
}

// The inventory's account of the binding in force and the document must agree
// on its sequence and device, not only its hash.
func TestRevisionRefusesAnInventoryThatMisdescribesThePrior(t *testing.T) {
	for name, tweak := range map[string]func(d *device){
		"another sequence": func(d *device) { d.inv["accepted_binding_seq"] = 7 },
		"another device":   func(d *device) { d.inv["device_id"] = "bench-02" },
	} {
		bothModes(t, func(t *testing.T, jsonMode bool) {
			d := singleZone(t)
			tweak(d)
			run := revise(t, d, carry().stdin(), runOpts{file: d.envelope, json: jsonMode})
			run.refused(t, name, 2, "the inventory does not describe it", jsonMode)
		})
	}
}

// A sequence without a hash, or the reverse, is not a device state, and a
// producer that chose one would chain onto a document the device never held.
func TestCaptureRefusesAChainThatContradictsItself(t *testing.T) {
	for name, tweak := range map[string]func(d *device){
		"sequence without hash": func(d *device) { d.inv["accepted_binding_hash"] = nil },
		"hash without sequence": func(d *device) { d.inv["accepted_binding_seq"] = 0 },
		"hash not canonical":    func(d *device) { d.inv["accepted_binding_hash"] = "sha256:XYZ" },
	} {
		bothModes(t, func(t *testing.T, jsonMode bool) {
			d := singleZone(t)
			tweak(d)
			run := revise(t, d, captureAnswers, runOpts{json: jsonMode})
			run.refused(t, name, 1, "the runtime inventory reports", jsonMode)
		})
	}
}

// With a binding in force there is no capture without a prior: capture reads
// it from the runtime, and a device that cannot export it gets nothing.
func TestCaptureOnABindingInForceIsARevision(t *testing.T) {
	bothModes(t, func(t *testing.T, jsonMode bool) {
		d := singleZone(t)
		d.export = `{"ok":false,"error":{"code":"retained_binding_mismatch","detail":"nothing is exported"}}`
		run := revise(t, d, captureAnswers, runOpts{json: jsonMode})
		run.refused(t, "export unavailable", 2, "retained_binding_mismatch", jsonMode)
		if !d.exported() {
			t.Fatal("capture on a device with a binding in force did not read it")
		}
	})
}

func TestRevisionCarriesWhatDidNotChange(t *testing.T) {
	d := twoZones(t)
	a := carry()
	a.capacity = []string{"changed", "design_document", "12.5"}
	run := revise(t, d, a.stdin(), runOpts{})
	draft := run.draft(t)

	for _, question := range []string{
		"Full-scale range", "Below what change", "To OPEN the protected circuit",
		"How was the circuit leg established", "Commanding",
	} {
		if strings.Contains(run.stderr, question) {
			t.Fatalf("a carried fact was asked again (%q):\n%s", question, run.stderr)
		}
	}
	priorDoc := decodeEnvelope(t, d.envelope)
	if len(draft.Zones) != 2 {
		t.Fatalf("the revision has %d zones, want both in force", len(draft.Zones))
	}
	for i, z := range draft.Zones {
		want := priorDoc.Zones[i]
		if z.ZoneID == "main" {
			if z.RatedCapacity.Value != 12.5 || z.RatedCapacity.Provenance != "design_document" {
				t.Fatalf("the changed capacity was not recorded: %+v", z.RatedCapacity)
			}
			want.RatedCapacity = z.RatedCapacity
		}
		// Carried means the same canonical bytes, proof legs and all.
		if zoneBytes(t, z) != zoneBytes(t, want) {
			t.Fatalf("zone %q was not carried as it is in force:\n got %s\nwant %s",
				z.ZoneID, zoneBytes(t, z), zoneBytes(t, want))
		}
	}
	if draft.InventoryGeneration != priorDoc.InventoryGeneration {
		t.Fatal("the inventory generation was not carried")
	}
	accepted, err := deliverable(t, d, draft, nil)
	if err != nil {
		t.Fatalf("a runtime holding the binding in force refuses the revision: %v", err)
	}
	if !accepted.InForceEligible() {
		t.Fatal("a revision that carried both legs is not in force")
	}
}

// Fresh legs on a line the binding in force still drives can never be proven,
// so the change is refused by name the moment it is declared: no proof is
// asked for, and no one is told to go and prove it.
func TestRevisionRefusesFreshLegsOnADrivenLine(t *testing.T) {
	cases := []struct {
		name   string
		device func(*testing.T) *device
		answer func(*answers)
		fact   string
		owner  string
		pin    int
	}{
		{"polarity flipped", singleZone, func(a *answers) { a.polarity = []string{"changed", "low"} },
			"active_high", "main", 26},
		{"recalibrated", singleZone, func(a *answers) { a.calibration = []string{"changed", "cal-2"} },
			"calibration_ref", "main", 26},
		{"mapping rewired", singleZone, func(a *answers) {
			a.mapping = []string{"changed", "de_energised", "energised", "open"}
		}, "commissioned_mapping", "main", 26},
		{"sensor re-described", singleZone, func(a *answers) {
			a.sensor = []string{"changed", "load-current-main", "current", "ampere",
				"positive_is_load_draw", "0", "50", "0.05", "cal-main"}
			a.calibration = nil
		}, "sensor", "main", 26},
		{"relay replaced like for like", singleZone, func(a *answers) {
			a.replaced = []string{"relay or contactor"}
		}, "replaced_like_for_like", "main", 26},
		{"clamp replaced like for like", singleZone, func(a *answers) {
			a.replaced = []string{"sensor"}
		}, "replaced_like_for_like", "main", 26},
		{"moved onto another zone's line", twoZones, func(a *answers) {
			a.actuator = []string{"changed", "local_gpio (gpio_pin=19)"}
		}, "actuator", "aux", 19},
	}
	for _, tc := range cases {
		bothModes(t, func(t *testing.T, jsonMode bool) {
			a := carry()
			tc.answer(&a)
			a.proof = freshProof(priorProofAt + 1)
			run := revise(t, tc.device(t), a.stdin(), runOpts{json: jsonMode})
			run.refused(t, tc.name, 2, fmt.Sprintf(
				"%s changed, so zone \"main\" needs fresh legs, and gpio_pin=%d is still driven by zone %q",
				tc.fact, tc.pin, tc.owner), jsonMode)
			for _, never := range []string{"How was the circuit leg established", "prove both outcomes"} {
				if strings.Contains(run.stderr, never) {
					t.Fatalf("%s: %q reached the installer for a line that cannot be proven:\n%s",
						tc.name, never, run.stderr)
				}
			}
			// Refused as declared: nothing after the declaring answer is asked.
			if tc.fact == "replaced_like_for_like" && strings.Contains(run.stderr, "Sensor:") {
				t.Fatalf("%s: the ceremony went on past the change that decided it", tc.name)
			}
		})
	}
}

// A changed zone moved to a line no zone drives is captured with fresh legs,
// named before they are asked for, and the control leg in force is not carried.
func TestRevisionRequiresFreshProof(t *testing.T) {
	cases := []struct {
		name   string
		answer func(*answers)
		facts  []string
	}{
		{"moved", func(*answers) {}, []string{"actuator"}},
		{"moved and flipped", func(a *answers) { a.polarity = []string{"changed", "low"} },
			[]string{"actuator", "active_high"}},
		{"moved and recalibrated", func(a *answers) { a.calibration = []string{"changed", "cal-2"} },
			[]string{"actuator", "calibration_ref"}},
		{"moved with its relay replaced", func(a *answers) { a.replaced = []string{"relay or contactor"} },
			[]string{"actuator", "replaced_like_for_like"}},
		{"moved and rewired", func(a *answers) {
			a.mapping = []string{"changed", "de_energised", "energised", "open"}
			a.proof = []string{binding.MethodPreEnergy, fmt.Sprint(priorProofAt + 1),
				"de_energised", "open", "yes", "no", "energised", "closed", "no", "yes"}
		}, []string{"actuator", "commissioned_mapping"}},
	}
	for _, tc := range cases {
		bothModes(t, func(t *testing.T, jsonMode bool) {
			d := singleZone(t).declaring(21)
			a := movedTo21()
			tc.answer(&a)
			run := revise(t, d, a.stdin(), runOpts{json: jsonMode})
			draft := run.draft(t)

			stated := strings.Index(run.stderr, fmt.Sprintf("needs a fresh circuit leg performed after %d", priorProofAt))
			asked := strings.LastIndex(run.stderr, "How was the circuit leg established")
			if stated < 0 || asked < 0 || stated > asked {
				t.Fatalf("%s: the fresh proof was not named before it was asked for:\n%s", tc.name, run.stderr)
			}
			zone := draft.Zones[0]
			if zone.Proof.ControlPath != nil {
				t.Fatalf("%s: the control leg in force was carried onto a changed zone", tc.name)
			}
			if _, err := deliverable(t, d, draft, nil); err != nil {
				t.Fatalf("%s: the runtime refuses the revision: %v", tc.name, err)
			}
			stale := draft
			stale.Zones = append([]binding.Zone(nil), draft.Zones...)
			stale.Zones[0].Proof.PerformedAtMs = priorProofAt
			if _, err := deliverable(t, d, stale, nil); err == nil ||
				!strings.Contains(err.Error(), binding.ReasonStaleProof) {
				t.Fatalf("%s: the circuit leg in force was not stale: %v", tc.name, err)
			}
			if jsonMode {
				rev := run.revision(t)
				if !rev.FreshProof || strings.Join(rev.Because, ",") != strings.Join(tc.facts, ",") ||
					rev.ControlLeg != "prove_after_delivery" || rev.ProofState != capture.StateProvisional ||
					rev.CircuitLegAfterMs != priorProofAt {
					t.Fatalf("%s: the JSON revision does not say what is required: %s", tc.name, run.stdout)
				}
			}
		})
	}
}

// A leg time no later than the proof in force is refused as it is entered,
// before the observations are asked; so is one dated past this machine's clock.
func TestRevisionRefusesALegTimeAsItIsEntered(t *testing.T) {
	cases := map[int64]string{
		priorProofAt:                  "is not after the proof in force",
		priorProofAt - 1:              "is not after the proof in force",
		reviseNow + 5*60*1000 + 1:     "later than this machine's clock",
		reviseNow + 1000*365*86400000: "later than this machine's clock",
	}
	for at, because := range cases {
		bothModes(t, func(t *testing.T, jsonMode bool) {
			a := movedTo21()
			a.proof = freshProof(at)
			run := revise(t, singleZone(t).declaring(21), a.stdin(), runOpts{json: jsonMode})
			run.refused(t, fmt.Sprint(at), 2, because, jsonMode)
			if strings.Contains(run.stderr, "Commanding") {
				t.Fatalf("%d: the observations were asked after a leg time that could not stand", at)
			}
		})
	}
	a := movedTo21()
	a.proof = freshProof(reviseNow + 5*60*1000)
	revise(t, singleZone(t).declaring(21), a.stdin(), runOpts{}).draft(t)
}

// The first-capture ceremony refuses a future-dated proof as well: it is the
// time every later revision has to follow.
func TestCaptureRefusesAFutureProof(t *testing.T) {
	future := strings.Replace(captureAnswers, "pre_energisation\n1800000000000\n",
		"pre_energisation\n25080000000000\n", 1)
	d := &device{inv: map[string]any{
		"device_id": "bench-01", "sensor_ids": []any{"load-current-main"},
		"actuators":          []any{map[string]any{"kind": "local_gpio", "identity": map[string]any{"gpio_pin": 26}}},
		"deployment_posture": "development", "accepted_binding_seq": 0, "accepted_binding_hash": nil,
	}}
	run := revise(t, d, future, runOpts{})
	run.refused(t, "future first proof", 2, "later than this machine's clock", false)
}

// Proven, provisional and undemonstrated are three things; the trip-point bound
// is deferred to delivery in every one of them, and never reported as checked.
func TestRevisionReportsThreeProofStates(t *testing.T) {
	carried := carry()
	carried.capacity = []string{"changed", "nameplate", "11"}
	unproven := movedTo21()
	unproven.proof = []string{binding.MethodUnproven, "the load could not be isolated"}
	for want, a := range map[string]answers{
		capture.StateProven: carried, capture.StateProvisional: movedTo21(),
		capture.StateUndemonstrated: unproven,
	} {
		device := func() *device {
			if want == capture.StateProven {
				return singleZone(t)
			}
			return singleZone(t).declaring(21)
		}
		got := revise(t, device(), a.stdin(), runOpts{json: true}).revision(t)
		if got.ProofState != want || got.TripPointBound != "deferred_to_delivery" {
			t.Fatalf("reported %q / %q, want %q / deferred_to_delivery", got.ProofState, got.TripPointBound, want)
		}
		text := revise(t, device(), a.stdin(), runOpts{})
		if !strings.Contains(text.stderr, fmt.Sprintf("proof once delivered: %s\n", want)) ||
			!strings.Contains(text.stderr, "not checked here, decided at delivery") {
			t.Fatalf("the text report does not say %q with the bound deferred:\n%s", want, text.stderr)
		}
	}
}

// A capacity above full scale over the release's multiplier passes every check
// capture can make and fails the trip-point bound at delivery; the report says
// that bound was not checked rather than calling the zone ready.
func TestRevisionDefersTheTripPointBound(t *testing.T) {
	a := carry()
	a.capacity = []string{"changed", "nameplate", "60"}
	bothModes(t, func(t *testing.T, jsonMode bool) {
		d := singleZone(t)
		run := revise(t, d, a.stdin(), runOpts{json: jsonMode})
		draft := run.draft(t)
		if jsonMode {
			if rev := run.revision(t); rev.TripPointBound != "deferred_to_delivery" {
				t.Fatalf("the trip-point bound is reported %q", rev.TripPointBound)
			}
		} else if !strings.Contains(run.stderr, "trip-point bound") ||
			!strings.Contains(run.stderr, "not checked here, decided at delivery") {
			t.Fatalf("the text report does not defer the trip-point bound:\n%s", run.stderr)
		}
		two := 2.0
		if _, err := deliverable(t, d, draft, &two); err == nil ||
			!strings.Contains(err.Error(), binding.ReasonOutOfBounds) {
			t.Fatalf("a 60A capacity on a 100A sensor passed a x2 trip-point bound: %v", err)
		}
	})
}

// Every other way a revision can go wrong at the panel is refused with nothing
// written, in text and in JSON.
func TestRevisionRefusals(t *testing.T) {
	cases := []struct {
		name    string
		device  func(*testing.T) *device
		answers func() answers
		zone    string
		because string
	}{
		{"a sensor moved onto another zone's", func(t *testing.T) *device { return twoZones(t).declaring(19, 21) },
			func() answers {
				a := movedTo21()
				a.sensor = []string{"changed", "load-current-aux"}
				a.calibration = nil
				return a
			}, "main", "is bound to zone \"aux\""},
		{"a capacity the sensor cannot observe", singleZone, func() answers {
			a := carry()
			a.capacity = []string{"changed", "nameplate", "150"}
			return a
		}, "main", "full scale"},
		{"polarity answered changed to the value in force", func(t *testing.T) *device {
			return singleZone(t).declaring(21)
		}, func() answers {
			a := movedTo21()
			a.polarity = []string{"changed", "high"}
			return a
		}, "main", "answered changed and then given the value in force"},
		{"a zone not in force", singleZone, carry, "elsewhere", "has no zone"},
		{"no reason given", singleZone, func() answers {
			a := carry()
			a.why = []string{""}
			return a
		}, "main", "records why it was made"},
		{"input ending mid-ceremony", singleZone, func() answers {
			return answers{why: []string{"w"}, actuator: []string{"unchanged"}}
		}, "main", "the ceremony ended"},
		{"no input at all", singleZone, func() answers { return answers{} }, "main", "the ceremony ended"},
		{"a mapping that contradicts itself", func(t *testing.T) *device { return singleZone(t).declaring(21) },
			func() answers {
				a := movedTo21()
				a.mapping = []string{"changed", "de_energised", "energised", "closed"}
				return a
			}, "main", "one of those two observations"},
		// Every earlier check passes; only the gate that runs the verifier's
		// own stages over the draft sees the pin the move left unbound.
		{"a move that leaves a declared pin unbound", func(t *testing.T) *device {
			return singleZone(t).declaring(19, 21, 26)
		}, movedTo21, "main", "the runtime would refuse this revision (inventory: unbound_actuator)"},
		{"a claimed leg against a proof in force dated just ahead", func(t *testing.T) *device {
			return bindingInForce(t, zoneProvenAt(reviseNow+60*1000)).declaring(21)
		}, func() answers {
			a := movedTo21()
			a.proof = freshProof(reviseNow + 30*1000)
			return a
		}, "main", "the proof in force is dated 1800000060000, after this machine's clock"},
		{"fresh legs against a proof in force dated far ahead", func(t *testing.T) *device {
			return bindingInForce(t, zoneProvenAt(reviseNow+10*86400000)).declaring(21)
		}, movedTo21, "main", "the proof in force is dated 1800864000000, after this machine's clock"},
		// The boundary: a proof in force dated exactly at the clock plus the
		// skew leaves no instant a fresh leg could be dated.
		{"fresh legs against a proof in force dated at the skew (far ahead boundary)", func(t *testing.T) *device {
			return bindingInForce(t, zoneProvenAt(reviseNow+5*60*1000)).declaring(21)
		}, movedTo21, "main", "the proof in force is dated 1800000300000, after this machine's clock"},
		{"a lower inventory generation", func(t *testing.T) *device {
			return bindingInForceAt(t, 5, provenZone("main", "load-current-main", 26, true))
		}, func() answers {
			a := carry()
			a.generation = []string{"changed", "4"}
			return a
		}, "main", "inventory generation 4 is below the 5"},
	}
	for _, tc := range cases {
		bothModes(t, func(t *testing.T, jsonMode bool) {
			stdin := tc.answers().stdin()
			if tc.name == "no input at all" {
				stdin = ""
			}
			run := revise(t, tc.device(t), stdin, runOpts{json: jsonMode, zone: tc.zone})
			run.refused(t, tc.name, 2, tc.because, jsonMode)
			if strings.Contains(tc.name, "far ahead") &&
				strings.Contains(run.stderr, "When was that proof performed") {
				t.Fatalf("%s: a proof was asked for that no time could satisfy", tc.name)
			}
		})
	}
}

// zoneProvenAt is the fixture zone with both legs dated from at.
func zoneProvenAt(at int64) binding.Zone {
	z := provenZone("main", "load-current-main", 26, true)
	z.Proof.PerformedAtMs = at
	leg := *z.Proof.ControlPath
	leg.PerformedAtMs = at + 1
	z.Proof.ControlPath = &leg
	return z
}

// An undemonstrated leg claims no proof, so it is not held to the time of the
// proof in force, even one dated ahead of this machine's clock: the zone is
// captured, and delivered, as undemonstrated.
func TestAnUnclaimedLegIsNotHeldToTheRetainedTime(t *testing.T) {
	for _, priorAt := range []int64{reviseNow + 60*1000, reviseNow + 5*60*1000, reviseNow + 10*86400000} {
		bothModes(t, func(t *testing.T, jsonMode bool) {
			d := bindingInForce(t, zoneProvenAt(priorAt)).declaring(21)
			a := movedTo21()
			a.proof = []string{binding.MethodUnproven, "the load could not be isolated"}
			run := revise(t, d, a.stdin(), runOpts{json: jsonMode})
			draft := run.draft(t)
			// A circuit leg not redone is recorded undemonstrated; a control
			// leg not redone is left absent, never written undemonstrated.
			if draft.Zones[0].Proof.Method != binding.MethodUnproven {
				t.Fatalf("%d: the leg was not recorded undemonstrated", priorAt)
			}
			if draft.Zones[0].Proof.ControlPath != nil {
				t.Fatalf("%d: a control leg that was not redone was written", priorAt)
			}
			if jsonMode {
				if rev := run.revision(t); rev.ProofState != capture.StateUndemonstrated {
					t.Fatalf("%d: reported %q", priorAt, rev.ProofState)
				}
			}
			accepted, err := deliverable(t, d, draft, nil)
			if err != nil || accepted.InForceEligible() {
				t.Fatalf("%d: an unclaimed leg was refused, or reached in force: %v", priorAt, err)
			}
		})
	}
}

func decodeEnvelope(t *testing.T, envelope []byte) binding.Binding {
	t.Helper()
	var env struct {
		Binding json.RawMessage `json:"binding"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatal(err)
	}
	doc, _, err := binding.DecodeDocument(env.Binding)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// zoneBytes is a zone's canonical form, compared as the signature would see it.
func zoneBytes(t *testing.T, z binding.Zone) string {
	t.Helper()
	doc := binding.Binding{
		V: 1, BindingSeq: 1, DeviceID: "d", SignerID: "s", Actor: "a", Reason: "r",
		SigningKey:          binding.SigningKeyName(revisionKey.Public().(ed25519.PublicKey)),
		InventoryGeneration: 1, Zones: []binding.Zone{z},
	}
	pre, err := doc.Preimage()
	if err != nil {
		t.Fatal(err)
	}
	return string(pre)
}

// The revision rule follows the hardware, not the name: every retained zone a
// revised zone shares a name, a pin or a sensor with holds it to fresh legs.
func TestTheRevisionRuleFollowsTheHardwareNotTheName(t *testing.T) {
	d := twoZones(t)
	prior := decodeEnvelope(t, d.envelope)
	revision := func(edit func(zones []binding.Zone)) binding.Binding {
		zones := make([]binding.Zone, len(prior.Zones))
		copy(zones, prior.Zones)
		edit(zones)
		hash := d.accepted.CanonicalHash
		return binding.Binding{V: 1, BindingSeq: 4, DeviceID: "bench-01",
			InventoryGeneration: 1, Supersedes: &hash, Reason: "r", Zones: zones}
	}
	circuitOnly := func(z *binding.Zone) { z.Proof.ControlPath = nil }
	cases := []struct {
		name  string
		edit  func([]binding.Zone)
		stale bool
	}{
		{"renamed, nothing else", func(z []binding.Zone) { z[0].ZoneID = "main-renamed" }, false},
		{"renamed and flipped", func(z []binding.Zone) {
			z[0].ZoneID = "main-renamed"
			z[0].Actuator.Identity.ActiveHigh = boolPtr(false)
			circuitOnly(&z[0])
		}, true},
		{"renamed and sensor re-described", func(z []binding.Zone) {
			z[0].ZoneID = "main-renamed"
			z[0].Sensor.RangeMax = 50
		}, true},
		// Each of these shares exactly one thing with a retained zone.
		{"renamed onto main's pin with another sensor, flipped", func(z []binding.Zone) {
			z[0].ZoneID = "x"
			z[0].Sensor.SensorID = "load-current-spare"
			z[0].Actuator.Identity.ActiveHigh = boolPtr(false)
			circuitOnly(&z[0])
		}, true},
		{"renamed onto main's sensor on another pin, re-described", func(z []binding.Zone) {
			z[0].ZoneID = "y"
			z[0].Actuator.Identity.GPIOPin = intPtr(21)
			z[0].Sensor.RangeMax = 50
		}, true},
		{"moved to a new pin and a new sensor, keeping only its name", func(z []binding.Zone) {
			z[0].Actuator.Identity.GPIOPin = intPtr(21)
			z[0].Sensor.SensorID = "load-current-spare"
		}, true},
		{"mapping rewired, nothing else", func(z []binding.Zone) {
			z[0].Actuator.Mapping = binding.Mapping{
				OpenProtectedCircuit: binding.CoilDeEnergised, CloseProtectedCircuit: binding.CoilEnergised,
				DeEnergisedTerminalState: binding.CircuitOpen,
			}
			// The circuit leg observes the new mapping but keeps the time of
			// the proof in force, so only its age is wrong.
			z[0].Proof.Observations = append([]binding.Observation(nil), z[0].Proof.Observations...)
			for i := range z[0].Proof.Observations {
				o := &z[0].Proof.Observations[i]
				o.CoilState = map[string]string{
					binding.OutcomeOpen: binding.CoilDeEnergised, binding.OutcomeClose: binding.CoilEnergised,
				}[o.Commanded]
			}
			circuitOnly(&z[0])
		}, true},
		{"two zones exchanging sensors", func(z []binding.Zone) {
			z[0].Sensor, z[1].Sensor = z[1].Sensor, z[0].Sensor
		}, true},
		{"main onto aux's pin while aux moves away", func(z []binding.Zone) {
			z[0].Actuator.Identity.GPIOPin = intPtr(19)
			z[1].Actuator.Identity.GPIOPin = intPtr(21)
			circuitOnly(&z[0])
			circuitOnly(&z[1])
		}, true},
	}
	for _, tc := range cases {
		draft := revision(tc.edit)
		// The device declares exactly what the revision binds, so nothing but
		// the revision rule stands between it and acceptance.
		var pins []int
		var sensors []any
		for _, z := range draft.Zones {
			pins = append(pins, *z.Actuator.Identity.GPIOPin)
			sensors = append(sensors, z.Sensor.SensorID)
		}
		d.inv["sensor_ids"] = sensors
		accepted, err := deliverable(t, d.declaring(pins...), draft, nil)
		if tc.stale {
			if err == nil || !strings.Contains(err.Error(), binding.ReasonStaleProof) {
				t.Fatalf("%s: verdict %v, want stale_proof", tc.name, err)
			}
			continue
		}
		if err != nil || !accepted.InForceEligible() {
			t.Fatalf("%s: a rename that changed nothing was refused or lost its proof: %v", tc.name, err)
		}
	}
}
