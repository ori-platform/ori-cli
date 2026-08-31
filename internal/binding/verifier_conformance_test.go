// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	canonicaljson "github.com/ori-platform/ori-canonicaljson"
	"github.com/ori-platform/ori-cli/internal/binding"
)

// This is the verifier's conformance proof, and the contract's ratification
// condition: an implementation in a second language, sharing no code with the
// corpus generator, that accepts every accept case and refuses every reject
// case at exactly its declared stage having passed every earlier one. Right
// reason at the wrong stage is not evidence that the named check exists.

type rejectCase struct {
	Name            string          `json:"name"`
	Binding         json.RawMessage `json:"binding"`
	VerifierContext json.RawMessage `json:"verifier_context"`
	CanonicalHex    string          `json:"canonical_hex"`
	CanonicalSHA256 string          `json:"canonical_sha256"`
	SignatureB64    string          `json:"signature_b64"`
	MessageHex      string          `json:"message_hex"`
	Reason          string          `json:"reason"`
	Stage           string          `json:"stage"`
	SignatureValid  *bool           `json:"signature_valid"`
}

type envelopeCase struct {
	Name            string          `json:"name"`
	Envelope        json.RawMessage `json:"envelope"`
	VerifierContext json.RawMessage `json:"verifier_context"`
	Reason          string          `json:"reason"`
	Stage           string          `json:"stage"`
}

type profileCase struct {
	Name            string          `json:"name"`
	FirmwareProfile json.RawMessage `json:"firmware_profile"`
	VerifierContext json.RawMessage `json:"verifier_context"`
	CanonicalHex    string          `json:"canonical_hex"`
	SignatureB64    string          `json:"signature_b64"`
	Reason          string          `json:"reason"`
	Stage           string          `json:"stage"`
	SignatureValid  *bool           `json:"signature_valid"`
}

type fullCorpus struct {
	AcceptanceOrder     []string       `json:"acceptance_order"`
	ProfileOrder        []string       `json:"firmware_profile_acceptance_order"`
	Cases               []rejectCase   `json:"cases"`
	RejectCases         []rejectCase   `json:"reject_cases"`
	EnvelopeRejectCases []envelopeCase `json:"envelope_reject_cases"`
	ProfileCases        []profileCase  `json:"firmware_profile_cases"`
	ProfileRejectCases  []profileCase  `json:"firmware_profile_reject_cases"`
}

func loadFullCorpus(t testing.TB) fullCorpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusDir, corpusFile))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c fullCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(c.Cases) == 0 || len(c.RejectCases) == 0 || len(c.EnvelopeRejectCases) == 0 ||
		len(c.ProfileCases) == 0 || len(c.ProfileRejectCases) == 0 {
		t.Fatal("corpus is missing a case group")
	}
	return c
}

// wireContext mirrors the corpus's verifier_context. Identity objects are
// decoded with UseNumber so their pins keep the spelling the corpus wrote.
type wireContext struct {
	DeviceID          string   `json:"device_id"`
	CurrentHex        string   `json:"commissioning_anchor_current_hex"`
	PreviousHex       string   `json:"commissioning_anchor_previous_hex"`
	ProvisioningHex   string   `json:"provisioning_anchor_hex"`
	AcceptedSeq       int64    `json:"accepted_binding_seq"`
	AcceptedHash      *string  `json:"accepted_binding_hash"`
	Posture           string   `json:"deployment_posture"`
	ProfileMultiplier *float64 `json:"profile_multiplier"`
	DeclaredInventory struct {
		SensorIDs []string `json:"sensor_ids"`
		Actuators []struct {
			Kind     string         `json:"kind"`
			Identity map[string]any `json:"identity"`
		} `json:"actuators"`
	} `json:"declared_inventory"`
	AcceptedZoneState map[string]struct {
		Identity       map[string]any    `json:"identity"`
		Mapping        map[string]string `json:"mapping"`
		CalibrationRef string            `json:"calibration_ref"`
		ProofAtMs      int64             `json:"proof_at_ms"`
		// Absent when the retained document carried no control leg.
		ControlProofAtMs *int64 `json:"control_proof_at_ms"`
	} `json:"accepted_zone_state"`
	FirmwareDeviceID string            `json:"firmware_device_id"`
	Channel          string            `json:"channel"`
	ExpectedMapping  map[string]string `json:"expected_mapping"`
}

func decodeContext(t testing.TB, raw json.RawMessage) wireContext {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var w wireContext
	if err := dec.Decode(&w); err != nil {
		t.Fatalf("decode verifier_context: %v", err)
	}
	return w
}

func anchorBytes(t testing.TB, hexText string) []byte {
	t.Helper()
	if hexText == "" {
		return nil
	}
	raw, err := hex.DecodeString(hexText)
	if err != nil {
		t.Fatalf("anchor hex: %v", err)
	}
	return raw
}

func mappingOf(m map[string]string) binding.Mapping {
	return binding.Mapping{
		OpenProtectedCircuit:     m["open_protected_circuit"],
		CloseProtectedCircuit:    m["close_protected_circuit"],
		DeEnergisedTerminalState: m["de_energised_terminal_state"],
	}
}

func bindingContext(t testing.TB, raw json.RawMessage) binding.Context {
	t.Helper()
	w := decodeContext(t, raw)
	ctx := binding.Context{
		DeviceID:                    w.DeviceID,
		CommissioningAnchorCurrent:  anchorBytes(t, w.CurrentHex),
		CommissioningAnchorPrevious: anchorBytes(t, w.PreviousHex),
		ProvisioningAnchor:          anchorBytes(t, w.ProvisioningHex),
		AcceptedBindingSeq:          w.AcceptedSeq,
		AcceptedBindingHash:         w.AcceptedHash,
		DeclaredSensorIDs:           w.DeclaredInventory.SensorIDs,
		DeploymentPosture:           w.Posture,
		ProfileMultiplier:           w.ProfileMultiplier,
		AcceptedZoneState:           map[string]binding.ZoneState{},
	}
	for _, a := range w.DeclaredInventory.Actuators {
		ref := binding.ActuatorRef{Kind: a.Kind}
		switch a.Kind {
		case binding.KindLocalGPIO:
			pin, ok := a.Identity["gpio_pin"].(json.Number)
			if !ok {
				t.Fatalf("declared gpio_pin is not a number: %v", a.Identity["gpio_pin"])
			}
			n, err := pin.Int64()
			if err != nil {
				t.Fatalf("declared gpio_pin: %v", err)
			}
			ref.GPIOPin = n
		case binding.KindFirmware:
			ref.FirmwareDeviceID, _ = a.Identity["firmware_device_id"].(string)
			ref.Channel, _ = a.Identity["channel"].(string)
		default:
			t.Fatalf("declared actuator of unknown kind %q", a.Kind)
		}
		ctx.DeclaredActuators = append(ctx.DeclaredActuators, ref)
	}
	for zoneID, was := range w.AcceptedZoneState {
		ctx.AcceptedZoneState[zoneID] = binding.ZoneState{
			Identity:         was.Identity,
			Mapping:          mappingOf(was.Mapping),
			CalibrationRef:   was.CalibrationRef,
			ProofAtMs:        was.ProofAtMs,
			ControlProofAtMs: was.ControlProofAtMs,
		}
	}
	return ctx
}

func profileContext(t testing.TB, raw json.RawMessage) binding.ProfileContext {
	t.Helper()
	w := decodeContext(t, raw)
	return binding.ProfileContext{
		FirmwareDeviceID:            w.FirmwareDeviceID,
		Channel:                     w.Channel,
		CommissioningAnchorCurrent:  anchorBytes(t, w.CurrentHex),
		CommissioningAnchorPrevious: anchorBytes(t, w.PreviousHex),
		ProvisioningAnchor:          anchorBytes(t, w.ProvisioningHex),
		AcceptedBindingSeq:          w.AcceptedSeq,
		AcceptedBindingHash:         w.AcceptedHash,
		ExpectedMapping:             mappingOf(w.ExpectedMapping),
	}
}

// envelopeBytes wraps a case's document, exactly as the file spelled it, in
// the wire envelope. Number spellings survive because the document is carried
// as raw bytes rather than decoded and re-encoded.
func envelopeBytes(inner string, doc json.RawMessage, sigB64 string) []byte {
	return []byte(`{"` + inner + `":` + string(doc) + `,"signature":"ed25519:` + sigB64 + `"}`)
}

func refusalOf(t *testing.T, err error) *binding.Refusal {
	t.Helper()
	var r *binding.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("expected a *Refusal, got %T: %v", err, err)
	}
	return r
}

func indexOf(order []string, stage string) int {
	for i, s := range order {
		if s == stage {
			return i
		}
	}
	return -1
}

func TestVerifierAcceptsEveryPublishedBinding(t *testing.T) {
	c := loadFullCorpus(t)
	for _, vc := range c.Cases {
		t.Run(vc.Name, func(t *testing.T) {
			env := envelopeBytes("binding", vc.Binding, vc.SignatureB64)
			accepted, err := binding.VerifyEnvelope(env, bindingContext(t, vc.VerifierContext))
			if err != nil {
				t.Fatalf("accept case refused: %v", err)
			}
			if hex.EncodeToString(accepted.CanonicalBytes) != vc.CanonicalHex {
				t.Fatal("retained canonical bytes differ from the contract")
			}
			if accepted.CanonicalHash != vc.CanonicalSHA256 {
				t.Fatalf("retained hash %s; contract %s", accepted.CanonicalHash, vc.CanonicalSHA256)
			}
			message, err := canonicaljson.MarshalWire(env)
			if err != nil || hex.EncodeToString(message) != vc.MessageHex {
				t.Fatalf("envelope bytes do not reproduce message_hex (%v)", err)
			}
			if accepted.Signature != "ed25519:"+vc.SignatureB64 {
				t.Fatal("retained signature differs from the one presented")
			}
			if len(accepted.Zones) == 0 || accepted.InventoryGeneration < 1 {
				t.Fatal("accepted binding retained no zones or no inventory generation")
			}
		})
	}
}

func TestVerifierRefusesEveryRejectCaseAtItsDeclaredStage(t *testing.T) {
	c := loadFullCorpus(t)
	for _, rc := range c.RejectCases {
		t.Run(rc.Name, func(t *testing.T) {
			env := envelopeBytes("binding", rc.Binding, rc.SignatureB64)
			_, err := binding.VerifyEnvelope(env, bindingContext(t, rc.VerifierContext))
			if err == nil {
				t.Fatalf("reject case was ACCEPTED; corpus declares %s (%s)", rc.Stage, rc.Reason)
			}
			r := refusalOf(t, err)
			if r.Stage != rc.Stage || r.Reason != rc.Reason {
				t.Fatalf("refused at %s (%s); corpus declares %s (%s)", r.Stage, r.Reason, rc.Stage, rc.Reason)
			}
		})
	}
}

// TestRejectCasesDeclareSignatureValidity: `signature_valid` must agree with
// where the refusal happened, so a case refused before the signature is never
// mistaken for one that proved a post-signature rule.
func TestRejectCasesDeclareSignatureValidity(t *testing.T) {
	c := loadFullCorpus(t)
	if indexOf(c.AcceptanceOrder, binding.StageSignature) < 0 {
		t.Fatal("acceptance_order does not name the signature stage")
	}
	for _, rc := range c.RejectCases {
		if rc.SignatureValid == nil {
			t.Fatalf("%s: no signature_valid", rc.Name)
		}
		decidedAfter := indexOf(c.AcceptanceOrder, rc.Stage) > indexOf(c.AcceptanceOrder, binding.StageSignature)
		if *rc.SignatureValid && rc.Stage == binding.StageSignature {
			t.Fatalf("%s: signature_valid but refused at signature", rc.Name)
		}
		if !*rc.SignatureValid && decidedAfter {
			t.Fatalf("%s: signature invalid but refused after signature", rc.Name)
		}
	}
}

func TestEnvelopeRejectCases(t *testing.T) {
	c := loadFullCorpus(t)
	for _, ec := range c.EnvelopeRejectCases {
		t.Run(ec.Name, func(t *testing.T) {
			var shape map[string]json.RawMessage
			if err := json.Unmarshal(ec.Envelope, &shape); err != nil {
				t.Fatalf("envelope is not an object: %v", err)
			}
			var err error
			if _, isBinding := shape["binding"]; isBinding {
				_, err = binding.VerifyEnvelope(ec.Envelope, bindingContext(t, ec.VerifierContext))
			} else {
				err = binding.VerifyProfileEnvelope(ec.Envelope, profileContext(t, ec.VerifierContext))
			}
			if err == nil {
				t.Fatal("envelope reject case was ACCEPTED")
			}
			r := refusalOf(t, err)
			if r.Stage != ec.Stage || r.Reason != ec.Reason {
				t.Fatalf("refused at %s (%s); corpus declares %s (%s)", r.Stage, r.Reason, ec.Stage, ec.Reason)
			}
		})
	}
}

func TestFirmwareProfileCases(t *testing.T) {
	c := loadFullCorpus(t)
	for _, pc := range c.ProfileCases {
		t.Run(pc.Name, func(t *testing.T) {
			env := envelopeBytes("firmware_profile", pc.FirmwareProfile, pc.SignatureB64)
			if err := binding.VerifyProfileEnvelope(env, profileContext(t, pc.VerifierContext)); err != nil {
				t.Fatalf("accept profile refused: %v", err)
			}
			canonical, err := canonicaljson.MarshalWire(pc.FirmwareProfile)
			if err != nil || hex.EncodeToString(canonical) != pc.CanonicalHex {
				t.Fatalf("profile canonical bytes do not reproduce (%v)", err)
			}
		})
	}
	for _, pc := range c.ProfileRejectCases {
		t.Run(pc.Name, func(t *testing.T) {
			env := envelopeBytes("firmware_profile", pc.FirmwareProfile, pc.SignatureB64)
			err := binding.VerifyProfileEnvelope(env, profileContext(t, pc.VerifierContext))
			if err == nil {
				t.Fatalf("reject profile was ACCEPTED; corpus declares %s (%s)", pc.Stage, pc.Reason)
			}
			r := refusalOf(t, err)
			if r.Stage != pc.Stage || r.Reason != pc.Reason {
				t.Fatalf("refused at %s (%s); corpus declares %s (%s)", r.Stage, r.Reason, pc.Stage, pc.Reason)
			}
			if pc.SignatureValid == nil {
				t.Fatal("reject profile has no signature_valid")
			}
			decidedAfter := indexOf(c.ProfileOrder, r.Stage) > indexOf(c.ProfileOrder, binding.StageSignature)
			if *pc.SignatureValid && r.Stage == binding.StageSignature {
				t.Fatal("signature_valid but refused at signature")
			}
			if !*pc.SignatureValid && decidedAfter {
				t.Fatal("signature invalid but refused after signature")
			}
		})
	}
}

// TestEveryDeclaredStageIsExercised: a stage no vector reaches is a rule
// nothing holds this verifier to.
func TestEveryDeclaredStageIsExercised(t *testing.T) {
	c := loadFullCorpus(t)
	if strings.Join(c.AcceptanceOrder, ",") != strings.Join(binding.AcceptanceOrder, ",") {
		t.Fatalf("verifier order %v differs from the corpus %v", binding.AcceptanceOrder, c.AcceptanceOrder)
	}
	if strings.Join(c.ProfileOrder, ",") != strings.Join(binding.ProfileAcceptanceOrder, ",") {
		t.Fatalf("profile order %v differs from the corpus %v", binding.ProfileAcceptanceOrder, c.ProfileOrder)
	}
	reached := map[string]bool{}
	for _, rc := range c.RejectCases {
		env := envelopeBytes("binding", rc.Binding, rc.SignatureB64)
		_, err := binding.VerifyEnvelope(env, bindingContext(t, rc.VerifierContext))
		if err != nil {
			reached[refusalOf(t, err).Stage] = true
		}
	}
	for _, stage := range c.AcceptanceOrder {
		if !reached[stage] {
			t.Errorf("no binding vector stops at %s", stage)
		}
	}
	reached = map[string]bool{}
	for _, pc := range c.ProfileRejectCases {
		env := envelopeBytes("firmware_profile", pc.FirmwareProfile, pc.SignatureB64)
		if err := binding.VerifyProfileEnvelope(env, profileContext(t, pc.VerifierContext)); err != nil {
			reached[refusalOf(t, err).Stage] = true
		}
	}
	for _, stage := range c.ProfileOrder {
		if !reached[stage] {
			t.Errorf("no profile vector stops at %s", stage)
		}
	}
}

// ── hostile input ───────────────────────────────────────────────────────
//
// The corpus stores decoded objects, so it cannot carry what only raw bytes
// can express: unpaired surrogate escapes, invalid UTF-8, trailing bytes, a
// number spelled two ways. And it asserts only what it lists. These cover the
// neighbouring shapes, and above all the obligation that a verifier returns a
// verdict rather than crashing: a verifier that panics has not refused.

type mutation func(b map[string]any)

func mutated(t *testing.T, base json.RawMessage, m mutation) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(base))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode base: %v", err)
	}
	m(doc)
	return doc
}

func encodeEnvelope(t *testing.T, doc map[string]any, sigB64 string) []byte {
	t.Helper()
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode mutated document: %v", err)
	}
	return envelopeBytes("binding", body, sigB64)
}

func zone(b map[string]any, i int) map[string]any {
	return b["zones"].([]any)[i].(map[string]any)
}

func obs(b map[string]any, z, i int) map[string]any {
	return zone(b, z)["proof"].(map[string]any)["observations"].([]any)[i].(map[string]any)
}

func hostileMutations() map[string]mutation {
	return map[string]mutation{
		// Unknown keys at every level.
		"unknown_binding_key":  func(b map[string]any) { b["contact_type"] = "NC" },
		"unknown_zone_key":     func(b map[string]any) { zone(b, 0)["notes"] = "see folder" },
		"unknown_capacity_key": func(b map[string]any) { zone(b, 0)["rated_capacity"].(map[string]any)["derived_from"] = "photo" },
		"unknown_identity_key": func(b map[string]any) {
			zone(b, 0)["actuator"].(map[string]any)["identity"].(map[string]any)["board"] = "x"
		},
		"unknown_mapping_key": func(b map[string]any) {
			zone(b, 0)["actuator"].(map[string]any)["commissioned_mapping"].(map[string]any)["contact_type"] = "NC"
		},
		"unknown_proof_key": func(b map[string]any) { zone(b, 0)["proof"].(map[string]any)["witness"] = "x" },
		// Field types: a key set is not a grammar.
		"v_as_string":                   func(b map[string]any) { b["v"] = "1" },
		"v_as_float":                    func(b map[string]any) { b["v"] = json.Number("1.0") },
		"v_as_boolean":                  func(b map[string]any) { b["v"] = true },
		"binding_seq_as_string":         func(b map[string]any) { b["binding_seq"] = "one" },
		"binding_seq_as_float":          func(b map[string]any) { b["binding_seq"] = json.Number("1.0") },
		"binding_seq_below_one":         func(b map[string]any) { b["binding_seq"] = json.Number("0") },
		"inventory_generation_as_bool":  func(b map[string]any) { b["inventory_generation"] = true },
		"inventory_generation_as_float": func(b map[string]any) { b["inventory_generation"] = json.Number("7.0") },
		"issued_at_ms_as_string":        func(b map[string]any) { b["issued_at_ms"] = "1800000000000" },
		"performed_at_ms_as_float": func(b map[string]any) {
			zone(b, 0)["proof"].(map[string]any)["performed_at_ms"] = json.Number("1800000000000.0")
		},
		"gpio_pin_as_boolean": func(b map[string]any) {
			zone(b, 0)["actuator"].(map[string]any)["identity"].(map[string]any)["gpio_pin"] = true
		},
		"gpio_pin_as_float": func(b map[string]any) {
			zone(b, 0)["actuator"].(map[string]any)["identity"].(map[string]any)["gpio_pin"] = json.Number("26.0")
		},
		"active_high_as_string": func(b map[string]any) {
			zone(b, 0)["actuator"].(map[string]any)["identity"].(map[string]any)["active_high"] = "false"
		},
		"capacity_value_as_boolean": func(b map[string]any) { zone(b, 0)["rated_capacity"].(map[string]any)["value"] = true },
		"noise_floor_as_boolean":    func(b map[string]any) { zone(b, 0)["sensor"].(map[string]any)["noise_floor"] = true },
		"noise_floor_of_zero":       func(b map[string]any) { zone(b, 0)["sensor"].(map[string]any)["noise_floor"] = json.Number("0.0") },
		"inverted_sensor_range": func(b map[string]any) {
			s := zone(b, 0)["sensor"].(map[string]any)
			s["range_min"] = json.Number("100.0")
			s["range_max"] = json.Number("0.0")
		},
		"load_present_as_string":         func(b map[string]any) { obs(b, 0, 0)["load_present_after"] = "no" },
		"load_present_as_integer":        func(b map[string]any) { obs(b, 0, 0)["load_present_after"] = json.Number("0") },
		"number_in_exponent_notation":    func(b map[string]any) { zone(b, 0)["sensor"].(map[string]any)["range_max"] = json.Number("1e2") },
		"number_below_agreement_zone":    func(b map[string]any) { zone(b, 0)["sensor"].(map[string]any)["noise_floor"] = json.Number("0.00001") },
		"integer_above_agreement_zone":   func(b map[string]any) { b["issued_at_ms"] = json.Number("9007199254740992") },
		"zone_id_empty":                  func(b map[string]any) { zone(b, 0)["zone_id"] = "" },
		"actor_whitespace_only":          func(b map[string]any) { b["actor"] = "\t " },
		"signer_id_empty":                func(b map[string]any) { b["signer_id"] = "" },
		"instrument_empty":               func(b map[string]any) { obs(b, 0, 0)["instrument"] = "" },
		"calibration_ref_empty":          func(b map[string]any) { zone(b, 0)["sensor"].(map[string]any)["calibration_ref"] = "" },
		"provenance_outside_vocabulary":  func(b map[string]any) { zone(b, 0)["rated_capacity"].(map[string]any)["provenance"] = "assumed" },
		"gpio_level_outside_vocabulary":  func(b map[string]any) { obs(b, 0, 0)["gpio_level"] = "floating" },
		"gpio_level_on_firmware_channel": func(b map[string]any) { obs(b, 1, 0)["gpio_level"] = "high" },
		"one_sided_sensor_reading":       func(b map[string]any) { delete(obs(b, 0, 0), "sensor_after") },
		"undemonstrated_with_observations": func(b map[string]any) {
			p := zone(b, 0)["proof"].(map[string]any)
			p["method"] = "undemonstrated"
			p["reason"] = "x"
		},
		"undemonstrated_without_reason": func(b map[string]any) {
			p := zone(b, 0)["proof"].(map[string]any)
			p["method"] = "undemonstrated"
			p["observations"] = []any{}
		},
		"empty_observation_list": func(b map[string]any) { zone(b, 0)["proof"].(map[string]any)["observations"] = []any{} },
		"zones_absent":           func(b map[string]any) { b["zones"] = []any{} },
		"supersedes_as_number":   func(b map[string]any) { b["supersedes"] = json.Number("7") },
		"supersedes_not_digest":  func(b map[string]any) { b["supersedes"] = "sha256:short" },
		// Encodings.
		"signing_key_without_prefix": func(b map[string]any) { b["signing_key"] = strings.TrimPrefix(b["signing_key"].(string), "ed25519:") },
		"signing_key_with_newline":   func(b map[string]any) { b["signing_key"] = b["signing_key"].(string) + "\n" },
		"signing_key_not_base64":     func(b map[string]any) { b["signing_key"] = "ed25519:!!!!not base64!!!!" },
		"signing_key_as_number":      func(b map[string]any) { b["signing_key"] = json.Number("42") },
		"signing_key_as_array":       func(b map[string]any) { b["signing_key"] = []any{} },
		"signing_key_wrong_length": func(b map[string]any) {
			b["signing_key"] = "ed25519:" + base64.StdEncoding.EncodeToString(make([]byte, 31))
		},
		"signing_key_url_safe_alphabet": func(b map[string]any) {
			b["signing_key"] = "ed25519:" + strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimPrefix(b["signing_key"].(string), "ed25519:"))
		},
		// Values chosen to break decoders and lookups rather than checks.
		"zones_not_a_list":    func(b map[string]any) { b["zones"] = "not a list" },
		"zone_not_an_object":  func(b map[string]any) { b["zones"] = []any{"not an object"} },
		"sensor_null":         func(b map[string]any) { zone(b, 0)["sensor"] = nil },
		"actuator_array":      func(b map[string]any) { zone(b, 0)["actuator"] = []any{} },
		"proof_number":        func(b map[string]any) { zone(b, 0)["proof"] = json.Number("7") },
		"capacity_string":     func(b map[string]any) { zone(b, 0)["rated_capacity"] = "10A" },
		"identity_string":     func(b map[string]any) { zone(b, 0)["actuator"].(map[string]any)["identity"] = "gpio26" },
		"mapping_array":       func(b map[string]any) { zone(b, 0)["actuator"].(map[string]any)["commissioned_mapping"] = []any{} },
		"observations_string": func(b map[string]any) { zone(b, 0)["proof"].(map[string]any)["observations"] = "x" },
		"observation_null":    func(b map[string]any) { zone(b, 0)["proof"].(map[string]any)["observations"] = []any{nil} },
		"kind_array":          func(b map[string]any) { zone(b, 0)["actuator"].(map[string]any)["kind"] = []any{} },
		"method_object":       func(b map[string]any) { zone(b, 0)["proof"].(map[string]any)["method"] = map[string]any{} },
		"provenance_array":    func(b map[string]any) { zone(b, 0)["rated_capacity"].(map[string]any)["provenance"] = []any{} },
		"mapping_value_object": func(b map[string]any) {
			zone(b, 0)["actuator"].(map[string]any)["commissioned_mapping"].(map[string]any)["open_protected_circuit"] = map[string]any{}
		},
		"terminal_state_array": func(b map[string]any) {
			zone(b, 0)["actuator"].(map[string]any)["commissioned_mapping"].(map[string]any)["de_energised_terminal_state"] = []any{}
		},
		"commanded_object":         func(b map[string]any) { obs(b, 0, 0)["commanded"] = map[string]any{} },
		"coil_state_array":         func(b map[string]any) { obs(b, 0, 0)["coil_state"] = []any{} },
		"terminal_observed_object": func(b map[string]any) { obs(b, 0, 0)["terminal_state_observed"] = map[string]any{} },
		"gpio_level_array":         func(b map[string]any) { obs(b, 0, 0)["gpio_level"] = []any{} },
	}
}

// verdict runs the verifier and reports a panic as a failure rather than
// letting it abort the test binary, so every hostile shape is reported.
func verdict(t *testing.T, name string, env []byte, ctx binding.Context) (r *binding.Refusal) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s: verifier panicked instead of returning a verdict: %v", name, recovered)
		}
	}()
	_, err := binding.VerifyEnvelope(env, ctx)
	if err == nil {
		t.Fatalf("%s: hostile input was ACCEPTED", name)
	}
	return refusalOf(t, err)
}

func TestHostileShapesAreMalformedNotCrashes(t *testing.T) {
	c := loadFullCorpus(t)
	base := c.Cases[0]
	ctx := bindingContext(t, base.VerifierContext)
	// The base case must be sound before mutating it means anything.
	if _, err := binding.VerifyEnvelope(envelopeBytes("binding", base.Binding, base.SignatureB64), ctx); err != nil {
		t.Fatalf("base case refused: %v", err)
	}
	for name, m := range hostileMutations() {
		env := encodeEnvelope(t, mutated(t, base.Binding, m), base.SignatureB64)
		r := verdict(t, name, env, ctx)
		if r.Stage != binding.StageParses || r.Reason != binding.ReasonMalformed {
			t.Errorf("%s: refused at %s (%s); want parses (malformed)", name, r.Stage, r.Reason)
		}
	}
}

// TestRawBytesTheCorpusCannotCarry: what only bytes can express.
func TestRawBytesTheCorpusCannotCarry(t *testing.T) {
	c := loadFullCorpus(t)
	base := c.Cases[0]
	ctx := bindingContext(t, base.VerifierContext)
	good := envelopeBytes("binding", base.Binding, base.SignatureB64)
	replace := func(old, new string) []byte {
		if !bytes.Contains(good, []byte(old)) {
			t.Fatalf("base envelope does not contain %q", old)
		}
		return bytes.Replace(good, []byte(old), []byte(new), 1)
	}
	inputs := map[string][]byte{
		"unpaired_high_surrogate_in_value": replace(`"initial commissioning"`, `"\ud800"`),
		"unpaired_low_surrogate_in_value":  replace(`"initial commissioning"`, `"a\udfffb"`),
		"unpaired_surrogate_in_key":        replace(`"reason"`, `"\udc00"`),
		"invalid_utf8_byte":                replace(`"initial commissioning"`, "\"\xff\""),
		"trailing_bytes":                   append(append([]byte{}, good...), []byte(` {"more": true}`)...),
		"trailing_garbage":                 append(append([]byte{}, good...), []byte(`x`)...),
		"empty":                            {},
		"not_json":                         []byte("not json"),
		"top_level_array":                  []byte("[]"),
		"top_level_string":                 []byte(`"binding"`),
		"top_level_null":                   []byte("null"),
		"envelope_signature_array":         replace(`"signature":"ed25519:`+base.SignatureB64+`"`, `"signature":[]`),
		"envelope_signature_object":        replace(`"signature":"ed25519:`+base.SignatureB64+`"`, `"signature":{}`),
		"envelope_signature_number":        replace(`"signature":"ed25519:`+base.SignatureB64+`"`, `"signature":64`),
		"envelope_signature_surrogate":     replace(`"signature":"ed25519:`+base.SignatureB64+`"`, `"signature":"ed25519:\ud800"`),
		"envelope_extra_field":             replace(`,"signature"`, `,"extra":"unauthenticated","signature"`),
		"envelope_binding_null":            []byte(`{"binding":null,"signature":"ed25519:` + base.SignatureB64 + `"}`),
		"envelope_binding_array":           []byte(`{"binding":[],"signature":"ed25519:` + base.SignatureB64 + `"}`),
		"envelope_binding_string":          []byte(`{"binding":"x","signature":"ed25519:` + base.SignatureB64 + `"}`),
		"envelope_without_signature":       []byte(`{"binding":` + string(base.Binding) + `}`),
		"envelope_without_binding":         []byte(`{"signature":"ed25519:` + base.SignatureB64 + `"}`),
		// A duplicate key is refused during parsing even when both values are
		// equal: the canonical form is undefined, and a last-wins decoder
		// would otherwise verify a signature over one value while a first-wins
		// parser on a device reads the other.
		"duplicate_key_same_value":      replace(`"v": 1`, `"v": 1, "v": 1`),
		"duplicate_key_different_value": replace(`"binding_seq": 1`, `"binding_seq": 5, "binding_seq": 1`),
		"duplicate_key_nested":          replace(`"gpio_pin": 26`, `"gpio_pin": 27, "gpio_pin": 26`),
		"duplicate_key_in_envelope":     replace(`,"signature"`, `,"signature":"x","signature"`),
	}
	for name, raw := range inputs {
		r := verdict(t, name, raw, ctx)
		if r.Stage != binding.StageParses || r.Reason != binding.ReasonMalformed {
			t.Errorf("%s: refused at %s (%s); want parses (malformed)", name, r.Stage, r.Reason)
		}
	}
}

// otherSpellings returns every alternative base64 text that decodes to the
// same bytes: base64 leaves the low bits of the final character unused, and a
// merely validating decoder ignores them. Derived from the corpus key rather
// than written down, so it cannot go stale.
func otherSpellings(t *testing.T, b64 string) []string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base spelling does not decode: %v", err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var variants []string
	for i, ch := range b64 {
		if ch == '=' {
			continue
		}
		for _, candidate := range alphabet {
			if candidate == ch {
				continue
			}
			variant := b64[:i] + string(candidate) + b64[i+1:]
			// The lenient decoder is the one that accepts unused-bit variants;
			// that leniency is the problem the canonical rule exists for.
			if decoded, err := base64.StdEncoding.DecodeString(variant); err == nil && bytes.Equal(decoded, raw) {
				variants = append(variants, variant)
			}
		}
	}
	return variants
}

func TestNonCanonicalSpellingsAreMalformed(t *testing.T) {
	c := loadFullCorpus(t)
	base := c.Cases[0]
	ctx := bindingContext(t, base.VerifierContext)

	doc := mutated(t, base.Binding, func(map[string]any) {})
	key := strings.TrimPrefix(doc["signing_key"].(string), "ed25519:")
	keyVariants := otherSpellings(t, key)
	if len(keyVariants) == 0 {
		t.Fatal("no alternative spelling decodes to the same key; the canonical rule no longer has the problem it was written for")
	}
	for _, variant := range keyVariants {
		env := encodeEnvelope(t, mutated(t, base.Binding, func(b map[string]any) { b["signing_key"] = "ed25519:" + variant }), base.SignatureB64)
		r := verdict(t, "key "+variant, env, ctx)
		if r.Stage != binding.StageParses || r.Reason != binding.ReasonMalformed {
			t.Errorf("key spelling %s: refused at %s (%s)", variant, r.Stage, r.Reason)
		}
	}

	sigVariants := otherSpellings(t, base.SignatureB64)
	if len(sigVariants) == 0 {
		t.Fatal("no alternative spelling of the signature to test")
	}
	for _, variant := range sigVariants {
		env := envelopeBytes("binding", base.Binding, variant)
		r := verdict(t, "signature "+variant, env, ctx)
		if r.Stage != binding.StageParses || r.Reason != binding.ReasonMalformed {
			t.Errorf("signature spelling %s: refused at %s (%s)", variant, r.Stage, r.Reason)
		}
	}
}

// TestNoTrialVerification: the verifier tries exactly the key the document
// names. A document naming the provisioning key over bytes nobody signed is
// refused as bad_signature, never wrong_authority, so the verdict cannot be
// manufactured by anyone who knows a public key.
func TestNoTrialVerification(t *testing.T) {
	c := loadFullCorpus(t)
	base := c.Cases[0]
	ctx := bindingContext(t, base.VerifierContext)
	named := "ed25519:" + base64.StdEncoding.EncodeToString(ctx.ProvisioningAnchor)
	env := encodeEnvelope(t, mutated(t, base.Binding, func(b map[string]any) { b["signing_key"] = named }), base.SignatureB64)
	r := verdict(t, "provisioning key over unsigned bytes", env, ctx)
	if r.Stage != binding.StageSignature || r.Reason != binding.ReasonBadSignature {
		t.Fatalf("refused at %s (%s); want signature (bad_signature)", r.Stage, r.Reason)
	}
}

// TestAbsentCurrentAnchorIsUnknownSigner: with no current anchor no key can be
// selected, whatever the document names.
func TestAbsentCurrentAnchorIsUnknownSigner(t *testing.T) {
	c := loadFullCorpus(t)
	base := c.Cases[0]
	ctx := bindingContext(t, base.VerifierContext)
	ctx.CommissioningAnchorCurrent = nil
	ctx.CommissioningAnchorPrevious = nil
	r := verdict(t, "no anchors", envelopeBytes("binding", base.Binding, base.SignatureB64), ctx)
	if r.Stage != binding.StageKeySelection || r.Reason != binding.ReasonUnknownSigner {
		t.Fatalf("refused at %s (%s); want key_selection (unknown_signer)", r.Stage, r.Reason)
	}
}

// TestRetainedStateBuiltFromGoValuesMatchesTheWire: a consumer that rebuilds
// ZoneState from its own store uses Go integers and booleans, not json.Number.
// The revision rule must still see an unchanged identity as unchanged.
func TestRetainedStateBuiltFromGoValuesMatchesTheWire(t *testing.T) {
	c := loadFullCorpus(t)
	var revision *rejectCase
	for i := range c.Cases {
		if c.Cases[i].Name == "revision_with_fresh_proof_accepted" {
			revision = &c.Cases[i]
		}
	}
	if revision == nil {
		t.Fatal("corpus no longer carries revision_with_fresh_proof_accepted")
	}
	ctx := bindingContext(t, revision.VerifierContext)
	// The retained state as a Go consumer would hold it: the prior identity
	// with a Go int and bool, and a proof time equal to the revision's, so
	// that any spurious "changed" verdict surfaces as stale_proof.
	ctx.AcceptedZoneState = map[string]binding.ZoneState{
		"borehole-pump": {
			Identity:       map[string]any{"firmware_device_id": "ori-fw-7c9f2b3a", "channel": "relay0"},
			Mapping:        binding.Mapping{OpenProtectedCircuit: "energised", CloseProtectedCircuit: "de_energised", DeEnergisedTerminalState: "closed"},
			CalibrationRef: "sct013-100-2026-08-19-b",
			ProofAtMs:      1800000000000,
		},
		"main-distribution": {
			Identity:       map[string]any{"gpio_pin": 26, "active_high": false},
			Mapping:        binding.Mapping{OpenProtectedCircuit: "de_energised", CloseProtectedCircuit: "energised", DeEnergisedTerminalState: "open"},
			CalibrationRef: "sct013-100-2026-08-19-a",
			ProofAtMs:      1800000000000,
		},
	}
	env := envelopeBytes("binding", revision.Binding, revision.SignatureB64)
	if _, err := binding.VerifyEnvelope(env, ctx); err != nil {
		t.Fatalf("revision with fresh proof refused against Go-built retained state: %v", err)
	}
	// And the same state with a pin that differs must trip the revision rule.
	changed := ctx.AcceptedZoneState["main-distribution"]
	changed.Identity = map[string]any{"gpio_pin": 27, "active_high": false}
	changed.ProofAtMs = 1800000600000
	ctx.AcceptedZoneState["main-distribution"] = changed
	_, err := binding.VerifyEnvelope(env, ctx)
	r := refusalOf(t, err)
	if r.Stage != binding.StageProofConsistency || r.Reason != binding.ReasonStaleProof {
		t.Fatalf("refused at %s (%s); want proof_consistency (stale_proof)", r.Stage, r.Reason)
	}
}

func ExampleVerifyEnvelope() {
	_, err := binding.VerifyEnvelope([]byte(`{"binding":{},"signature":"x"}`), binding.Context{})
	fmt.Println(err)
	// Output: parses: malformed
}

// TestLoadClassifierDecidesNotTheReading isolates the rule the corpus cannot:
// its idle-load and transposed vectors are also refusable by the noise-floor
// delta, so a verifier that reads the sensor and ignores the instrument still
// passes them. Here the readings are absent or agree, and only the instrument's
// classification contradicts the command.
func TestLoadClassifierDecidesNotTheReading(t *testing.T) {
	c := loadFullCorpus(t)
	base := c.Cases[0]
	ctx := bindingContext(t, base.VerifierContext)
	cases := map[string]mutation{
		"open_with_no_load_before_and_no_readings": func(b map[string]any) {
			o := obs(b, 0, 0)
			o["load_present_before"] = false
			delete(o, "sensor_before")
			delete(o, "sensor_after")
		},
		"open_with_load_still_present_and_no_readings": func(b map[string]any) {
			o := obs(b, 0, 0)
			o["load_present_after"] = true
			delete(o, "sensor_before")
			delete(o, "sensor_after")
		},
		"close_with_load_already_present_and_no_readings": func(b map[string]any) {
			o := obs(b, 0, 1)
			o["load_present_before"] = true
			delete(o, "sensor_before")
			delete(o, "sensor_after")
		},
		"open_with_readings_that_fall_but_instrument_saw_no_load": func(b map[string]any) {
			o := obs(b, 0, 0)
			o["load_present_before"] = false
			o["load_present_after"] = false
		},
	}
	for name, m := range cases {
		env := encodeEnvelope(t, mutated(t, base.Binding, m), base.SignatureB64)
		// The mutation changes the signed bytes, so re-sign as the corpus key.
		env = resignedAsCorpus(t, c, env)
		r := verdict(t, name, env, ctx)
		if r.Stage != binding.StageProofConsistency || r.Reason != binding.ReasonProofContradiction {
			t.Errorf("%s: refused at %s (%s); want proof_consistency (proof_contradiction)", name, r.Stage, r.Reason)
		}
	}
}

// resignedAsCorpus re-signs a mutated envelope with the corpus commissioning
// key, so a document-rule test is decided by the rule and not by the
// signature the mutation broke.
func resignedAsCorpus(t *testing.T, c fullCorpus, env []byte) []byte {
	t.Helper()
	var shape struct {
		Binding json.RawMessage `json:"binding"`
	}
	if err := json.Unmarshal(env, &shape); err != nil {
		t.Fatalf("mutated envelope: %v", err)
	}
	preimage, err := canonicaljson.MarshalWire(shape.Binding)
	if err != nil {
		t.Fatalf("canonicalise mutated binding: %v", err)
	}
	key := corpusKey(t, loadCorpus(t))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, preimage))
	return envelopeBytes("binding", shape.Binding, sig)
}

// ── raw reject cases ────────────────────────────────────────────────────
//
// Wire bytes rather than decoded objects, for the rules decoding destroys: a
// number's spelling, a repeated key, and an unpaired surrogate. Each is the
// pristine signed envelope with one byte-level alteration, so the signature
// still covers the document a re-canonicalising verifier would reconstruct —
// which is why such a verifier accepts every one of them.
//
// That a raw case is genuinely raw — that decoding it really does lose
// something an ordinary case could have carried — is a property of the corpus,
// checked where the corpus lives and again in the runtime. It is deliberately
// not re-asserted here: canonicaljson.MarshalWire preserves the number
// spelling it receives, by design, so the obvious Go spelling of that check
// would compare a document against itself and pass for the wrong reason.

type rawCase struct {
	Name            string          `json:"name"`
	EnvelopeHex     string          `json:"envelope_hex"`
	VerifierContext json.RawMessage `json:"verifier_context"`
	Reason          string          `json:"reason"`
	Stage           string          `json:"stage"`
}

func loadRawCases(t testing.TB) []rawCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusDir, corpusFile))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c struct {
		RawRejectCases []rawCase `json:"raw_reject_cases"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(c.RawRejectCases) == 0 {
		t.Fatal("corpus carries no raw reject cases")
	}
	return c.RawRejectCases
}

func TestRawRejectCasesAreRefusedFromBytes(t *testing.T) {
	for _, rc := range loadRawCases(t) {
		t.Run(rc.Name, func(t *testing.T) {
			env, err := hex.DecodeString(rc.EnvelopeHex)
			if err != nil {
				t.Fatalf("envelope_hex: %v", err)
			}
			r := verdict(t, rc.Name, env, bindingContext(t, rc.VerifierContext))
			if r.Stage != rc.Stage || r.Reason != rc.Reason {
				t.Fatalf("refused at %s (%s); corpus declares %s (%s)",
					r.Stage, r.Reason, rc.Stage, rc.Reason)
			}
		})
	}
}
