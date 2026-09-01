// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ori-platform/ori-cli/internal/binding"
)

// scripted answers each prompt in order, and records what it was offered.
type scripted struct {
	answers []string
	offered [][]string
	prompts []string
	at      int
}

func (s *scripted) next(prompt string) (string, error) {
	s.prompts = append(s.prompts, prompt)
	if s.at >= len(s.answers) {
		return "", errExhausted
	}
	answer := s.answers[s.at]
	s.at++
	return answer, nil
}

func (s *scripted) Choose(prompt string, options []string) (string, error) {
	s.offered = append(s.offered, append([]string(nil), options...))
	answer, err := s.next(prompt)
	if err != nil {
		return "", err
	}
	for _, option := range options {
		if option == answer {
			return answer, nil
		}
	}
	return "", errNotOffered
}

func (s *scripted) Ask(prompt string) (string, error) { return s.next(prompt) }

var (
	errExhausted  = errStr("the ceremony asked more questions than the script answers")
	errNotOffered = errStr("an answer outside the offered set was accepted")
)

type errStr string

func (e errStr) Error() string { return string(e) }

func inventory() Inventory {
	return Inventory{
		DeviceID:           "bench-01",
		SensorIDs:          []string{"load-current-main"},
		Actuators:          []InventoryActuator{{Kind: "local_gpio", Identity: map[string]any{"gpio_pin": float64(26)}}},
		AcceptedBindingSeq: 3,
	}
}

// The ceremony's questions, in order. Named rather than indexed, so a test
// that changes one answer says which.
const (
	qSensor = iota
	qActuator
	qPolarity
	qOpen
	qClose
	qTerminal
	qProvenance
	qCapacity
	qQuantity
	qUnit
	qDirection
	qRangeMin
	qRangeMax
	qNoiseFloor
	qCalibration
	qGeneration
	qMethod
	qPerformedAt
	qOpenCoil
	qOpenTerminal
	qOpenLoadBefore
	qOpenLoadAfter
	qCloseCoil
	qCloseTerminal
	qCloseLoadBefore
	qCloseLoadAfter
)

func goodAnswers() []string {
	return []string{
		qSensor:          "load-current-main",
		qActuator:        "local_gpio (gpio_pin=26)",
		qPolarity:        "high",
		qOpen:            "energised",
		qClose:           "de_energised",
		qTerminal:        "closed",
		qProvenance:      "nameplate",
		qCapacity:        "10",
		qQuantity:        "current",
		qUnit:            "ampere",
		qDirection:       "positive_is_load_draw",
		qRangeMin:        "0",
		qRangeMax:        "100",
		qNoiseFloor:      "0.05",
		qCalibration:     "bench-2026-09-01",
		qGeneration:      "1",
		qMethod:          binding.MethodPreEnergy,
		qPerformedAt:     "1800000000000",
		qOpenCoil:        "energised",
		qOpenTerminal:    "open",
		qOpenLoadBefore:  "yes",
		qOpenLoadAfter:   "no",
		qCloseCoil:       "de_energised",
		qCloseTerminal:   "closed",
		qCloseLoadBefore: "no",
		qCloseLoadAfter:  "yes",
	}
}

func answersWith(overrides map[int]string) []string {
	answers := goodAnswers()
	for at, value := range overrides {
		answers[at] = value
	}
	return answers
}

func TestCandidatesComeFromTheInventory(t *testing.T) {
	s := &scripted{answers: goodAnswers()}
	if _, err := Capture(s, inventory(), "main"); err != nil {
		t.Fatalf("capture: %v", err)
	}
	if got := s.offered[0]; len(got) != 1 || got[0] != "load-current-main" {
		t.Fatalf("sensor candidates were not the inventory's: %v", got)
	}
	if got := s.offered[1]; len(got) != 1 || !strings.Contains(got[0], "gpio_pin=26") {
		t.Fatalf("actuator candidates were not the inventory's: %v", got)
	}
}

func TestPolarityIsAskedAndRecorded(t *testing.T) {
	for _, tc := range []struct {
		answer string
		want   bool
	}{{"high", true}, {"low", false}} {
		answers := answersWith(map[int]string{qPolarity: tc.answer})
		draft, err := Capture(&scripted{answers: answers}, inventory(), "main")
		if err != nil {
			t.Fatalf("capture: %v", err)
		}
		got := draft.Zones[0].Actuator.Identity.ActiveHigh
		if got == nil {
			t.Fatal("polarity was left unset after being asked")
		}
		if *got != tc.want {
			t.Fatalf("active_high = %v for %q", *got, tc.answer)
		}
	}
}

// A contact type is not among the questions, and neither outcome is derived
// from the other.
func TestTheMappingIsAskedNotInferred(t *testing.T) {
	s := &scripted{answers: goodAnswers()}
	if _, err := Capture(s, inventory(), "main"); err != nil {
		t.Fatalf("capture: %v", err)
	}
	joined := strings.ToLower(strings.Join(s.prompts, " "))
	for _, forbidden := range []string{
		"normally open", "normally closed", "normally-open", "normally-closed",
		" no ", " nc ",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("the ceremony asked about contact type: %q", forbidden)
		}
	}
	var mappingQuestions int
	for _, p := range s.prompts {
		if strings.Contains(p, "OPEN the protected circuit") ||
			strings.Contains(p, "CLOSE the protected circuit") ||
			strings.Contains(p, "DE-ENERGISED") {
			mappingQuestions++
		}
	}
	if mappingQuestions != 3 {
		t.Fatalf("the three outcomes were not asked separately: %d questions", mappingQuestions)
	}
}

func TestOneCoilStateCannotProduceBothOutcomes(t *testing.T) {
	answers := answersWith(map[int]string{qClose: "energised"}) // same as open
	_, err := Capture(&scripted{answers: answers}, inventory(), "main")
	if err == nil {
		t.Fatal("a self-contradicting mapping was accepted")
	}
	if !strings.Contains(err.Error(), "cannot produce both") {
		t.Fatalf("the refusal does not say what is wrong: %v", err)
	}
}

func TestPreEnergisationNeedsNoActuation(t *testing.T) {
	draft, err := Capture(&scripted{answers: goodAnswers()}, inventory(), "main")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if draft.Zones[0].Proof.Method != binding.MethodPreEnergy {
		t.Fatalf("method = %q", draft.Zones[0].Proof.Method)
	}
	if draft.Zones[0].Proof.ControlPath != nil {
		t.Fatal("the ceremony authored a control leg; that leg is the runtime's")
	}
}

// The control leg is proven by the runtime commanding the coil. A leg this
// tool authored would record what the tool asserted.
func TestTheCeremonyNeverOffersCommandedAndObserved(t *testing.T) {
	s := &scripted{answers: goodAnswers()}
	if _, err := Capture(s, inventory(), "main"); err != nil {
		t.Fatalf("capture: %v", err)
	}
	for _, options := range s.offered {
		for _, option := range options {
			if option == binding.ControlCommanded || option == binding.MethodActuate {
				t.Fatalf("the ceremony offered to author %q", option)
			}
		}
	}
}

func TestUndemonstratedRequiresItsReason(t *testing.T) {
	answers := answersWith(map[int]string{qMethod: binding.MethodUnproven, qPerformedAt: "   "})
	_, err := Capture(&scripted{answers: answers}, inventory(), "main")
	if err == nil {
		t.Fatal("an undemonstrated proof was recorded with no reason")
	}

	answers = answersWith(map[int]string{qMethod: binding.MethodUnproven, qPerformedAt: "no load wired at commissioning"})
	draft, err := Capture(&scripted{answers: answers}, inventory(), "main")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if draft.Zones[0].Proof.Reason == "" {
		t.Fatal("the reason was not recorded")
	}
}

func TestADeviceWithNoActuatorHasNoBinding(t *testing.T) {
	inv := inventory()
	inv.Actuators = nil
	if _, err := Capture(&scripted{answers: goodAnswers()}, inv, "main"); err == nil {
		t.Fatal("a Tier A-only site produced a binding")
	}
}

func TestTheDraftSupersedesTheAcceptedSequence(t *testing.T) {
	draft, err := Capture(&scripted{answers: goodAnswers()}, inventory(), "main")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if draft.BindingSeq != 4 {
		t.Fatalf("binding_seq = %d, want one past the accepted 3", draft.BindingSeq)
	}
}

func TestCapacityAboveTheSensorRangeIsRefused(t *testing.T) {
	answers := answersWith(map[int]string{qCapacity: "150", qRangeMax: "100"})
	_, err := Capture(&scripted{answers: answers}, inventory(), "main")
	if err == nil {
		t.Fatal("a capacity above the sensor's full scale was accepted")
	}
	if !strings.Contains(err.Error(), "cannot observe") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

func TestNonPositiveQuantitiesAreRefused(t *testing.T) {
	for _, at := range []int{qCapacity, qRangeMax} {
		answers := answersWith(map[int]string{at: "0"})
		if _, err := Capture(&scripted{answers: answers}, inventory(), "main"); err == nil {
			t.Fatalf("a zero quantity at position %d was accepted", at)
		}
	}
}

// An answer nobody quite gave is the failure this ceremony exists to prevent.
func TestTerminalAskerAcceptsOnlyWhatItOffered(t *testing.T) {
	var out strings.Builder
	asker := NewTerminalAsker(strings.NewReader("maybe\n7\nlow\n"), &out)
	got, err := asker.Choose("polarity?", []string{"high", "low"})
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	if got != "low" {
		t.Fatalf("got %q", got)
	}
	shown := out.String()
	if !strings.Contains(shown, `"maybe" is not one of the choices`) {
		t.Fatalf("an unrecognised answer was not re-asked: %s", shown)
	}
	if !strings.Contains(shown, "7 is not one of the 2 choices") {
		t.Fatalf("an out-of-range number was not re-asked: %s", shown)
	}
}

func TestTerminalAskerTakesTheNumberedChoice(t *testing.T) {
	var out strings.Builder
	asker := NewTerminalAsker(strings.NewReader("1\n"), &out)
	got, err := asker.Choose("which?", []string{"energised", "de_energised"})
	if err != nil || got != "energised" {
		t.Fatalf("got %q, err %v", got, err)
	}
}

func TestTerminalAskerEndingEarlyIsAnError(t *testing.T) {
	var out strings.Builder
	asker := NewTerminalAsker(strings.NewReader(""), &out)
	if _, err := asker.Choose("which?", []string{"a", "b"}); err == nil {
		t.Fatal("an unanswered question returned a value")
	}
}

// A draft is a set of captured facts, not an incomplete document pretending to
// be a complete one.
func TestTheDraftCarriesWhatCaptureOwnsAndNothingSigningOwns(t *testing.T) {
	inv := inventory()
	inv.AcceptedBindingHash = "sha256:prior"
	draft, err := Capture(&scripted{answers: goodAnswers()}, inv, "main")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	encoded, encodeErr := DraftJSON(draft)
	if encodeErr != nil {
		t.Fatalf("encode: %v", encodeErr)
	}
	var body map[string]any
	if unmarshalErr := json.Unmarshal(encoded, &body); unmarshalErr != nil {
		t.Fatalf("draft is not JSON: %v", unmarshalErr)
	}

	// Capture's own, including the two it reads from the runtime's payload.
	for _, want := range []string{
		"v", "binding_seq", "device_id", "inventory_generation", "supersedes",
		"zones",
	} {
		if _, ok := body[want]; !ok {
			t.Fatalf("the draft has no %q", want)
		}
	}
	if body["supersedes"] != "sha256:prior" {
		t.Fatalf("supersedes = %v, want the hash the runtime returned", body["supersedes"])
	}

	// Signing's, and present-but-empty would read as a document that has them.
	for _, absent := range []string{
		"signing_key", "signature", "issued_at_ms", "signer_id", "actor",
	} {
		if _, present := body[absent]; present {
			t.Fatalf("the draft carries %q, which signing owns", absent)
		}
	}

	zone := body["zones"].([]any)[0].(map[string]any)
	sensor := zone["sensor"].(map[string]any)
	for _, want := range []string{
		"sensor_id", "quantity", "unit", "range_min", "range_max", "direction",
		"noise_floor", "calibration_ref",
	} {
		if _, ok := sensor[want]; !ok {
			t.Fatalf("the sensor block has no %q", want)
		}
	}
	proof := zone["proof"].(map[string]any)
	if _, ok := proof["performed_at_ms"]; !ok {
		t.Fatal("a proof records when it was performed")
	}
	observations, ok := proof["observations"].([]any)
	if !ok || len(observations) != 2 {
		t.Fatalf("a proof admits a non-empty observations list; got %v", proof["observations"])
	}
	first := observations[0].(map[string]any)
	for _, want := range []string{
		"commanded", "coil_state", "terminal_state_observed",
		"load_present_before", "load_present_after",
	} {
		if _, ok := first[want]; !ok {
			t.Fatalf("an observation has no %q", want)
		}
	}

	actuator := zone["actuator"].(map[string]any)
	identity := actuator["identity"].(map[string]any)
	if _, ok := identity["active_high"]; !ok {
		t.Fatal("the polarity that was asked for is not in the draft")
	}
	mapping := actuator["commissioned_mapping"].(map[string]any)
	for _, key := range []string{
		"open_protected_circuit", "close_protected_circuit",
		"de_energised_terminal_state",
	} {
		if mapping[key] == "" || mapping[key] == nil {
			t.Fatalf("the mapping is missing %q", key)
		}
	}
}

// A first binding supersedes nothing, and absence is what says so.
func TestAFirstBindingSupersedesNothing(t *testing.T) {
	draft, err := Capture(&scripted{answers: goodAnswers()}, inventory(), "main")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	encoded, _ := DraftJSON(draft)
	var body map[string]any
	_ = json.Unmarshal(encoded, &body)
	if _, present := body["supersedes"]; present {
		t.Fatal("a first binding named something to supersede")
	}
}

// An unproven zone carrying observations claims a proof it also says it lacks.
func TestAnUndemonstratedProofCarriesNoObservations(t *testing.T) {
	draft, err := Capture(&scripted{answers: answersWith(map[int]string{
		qMethod:      binding.MethodUnproven,
		qPerformedAt: "no load was wired at commissioning",
	})}, inventory(), "main")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	encoded, _ := DraftJSON(draft)
	var body map[string]any
	_ = json.Unmarshal(encoded, &body)
	proof := body["zones"].([]any)[0].(map[string]any)["proof"].(map[string]any)
	if _, present := proof["observations"]; present {
		t.Fatal("an undemonstrated proof carries observations")
	}
	if _, present := proof["performed_at_ms"]; present {
		t.Fatal("an undemonstrated proof carries a performed_at_ms")
	}
	if proof["reason"] == nil || proof["reason"] == "" {
		t.Fatal("the reason was not recorded")
	}
}

// A noise floor of zero would let any reading count as a change.
func TestANoiseFloorMustBePositive(t *testing.T) {
	for _, value := range []string{"0", "-1"} {
		_, err := Capture(&scripted{answers: answersWith(map[int]string{
			qNoiseFloor: value,
		})}, inventory(), "main")
		if err == nil {
			t.Fatalf("a noise floor of %s was accepted", value)
		}
	}
}

// A clamp mounted backwards reports a hazard as a fall in magnitude.
func TestDirectionIsAskedAndHasNoDefault(t *testing.T) {
	s := &scripted{answers: answersWith(map[int]string{
		qDirection: "negative_is_load_draw",
	})}
	draft, err := Capture(s, inventory(), "main")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if draft.Zones[0].Sensor.Direction != "negative_is_load_draw" {
		t.Fatalf("direction = %q", draft.Zones[0].Sensor.Direction)
	}
}

// A capacity is a safety parameter and an audit needs to know what kind of
// claim it was, so it is asked rather than stamped.
func TestProvenanceIsAsked(t *testing.T) {
	draft, err := Capture(&scripted{answers: answersWith(map[int]string{
		qProvenance: "installer_measured",
	})}, inventory(), "main")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if draft.Zones[0].RatedCapacity.Provenance != "installer_measured" {
		t.Fatalf("provenance = %q", draft.Zones[0].RatedCapacity.Provenance)
	}
}

// An observation whose load never changed state demonstrates nothing.
func TestAnObservationWithNoLoadChangeIsRefused(t *testing.T) {
	for _, override := range []map[int]string{
		{qOpenLoadBefore: "no"},   // idle before an open
		{qOpenLoadAfter: "yes"},   // still drawing after it
		{qCloseLoadBefore: "yes"}, // already drawing before a close
		{qCloseLoadAfter: "no"},   // still idle after it
	} {
		if _, err := Capture(
			&scripted{answers: answersWith(override)}, inventory(), "main",
		); err == nil {
			t.Fatalf("a vacuous observation was accepted: %v", override)
		}
	}
}

func TestACalibrationReferenceIsRequired(t *testing.T) {
	if _, err := Capture(&scripted{answers: answersWith(map[int]string{
		qCalibration: "   ",
	})}, inventory(), "main"); err == nil {
		t.Fatal("a sensor with no calibration reference was accepted")
	}
}

func TestATerminalStateThatContradictsTheMappingIsRefused(t *testing.T) {
	// de-energising closes the circuit, so the de-energised state is "closed".
	answers := answersWith(map[int]string{qTerminal: "open"})
	_, err := Capture(&scripted{answers: answers}, inventory(), "main")
	if err == nil {
		t.Fatal("a zone that reads as failing safe while it fails closed was accepted")
	}
	if !strings.Contains(err.Error(), "something else") {
		t.Fatalf("the refusal does not say what disagrees: %v", err)
	}
}

func TestTheContradictionIsCheckedInBothDirections(t *testing.T) {
	// The reversed mapping, with observations that match it: de-energising
	// opens, so the coil observed for each outcome flips too.
	reversed := map[int]string{
		qOpen: "de_energised", qClose: "energised",
		qOpenCoil: "de_energised", qCloseCoil: "energised",
		qTerminal: "closed", // de-energising now opens, so this contradicts
	}
	answers := answersWith(reversed)
	if _, err := Capture(&scripted{answers: answers}, inventory(), "main"); err == nil {
		t.Fatal("the reversed mapping was not checked")
	}
	reversed[qTerminal] = "open"
	answers = answersWith(reversed)
	if _, err := Capture(&scripted{answers: answers}, inventory(), "main"); err != nil {
		t.Fatalf("a consistent reversed mapping was refused: %v", err)
	}
}

// NaN compares false against everything, so it survived both range checks and
// failed at the encoder instead of at the question.
func TestAQuantityACircuitCannotHaveIsRefused(t *testing.T) {
	// 0x1p3 is 8: inside the sensor range and above zero, so only the check
	// that refuses hexadecimal can catch it.
	for _, value := range []string{"NaN", "nan", "Inf", "+Inf", "-Inf", "0x1p3"} {
		if _, err := Capture(&scripted{answers: answersWith(map[int]string{
			qCapacity: value,
		})}, inventory(), "main"); err == nil {
			t.Fatalf("%q was accepted as a rated capacity", value)
		}
	}
}

func TestAZoneNeedsANameThatSurvivesRecording(t *testing.T) {
	for _, zone := range []string{"", "   ", "zone-\xff"} {
		if _, err := Capture(
			&scripted{answers: goodAnswers()}, inventory(), zone,
		); err == nil {
			t.Fatalf("zone %q was accepted", zone)
		}
	}
	draft, err := Capture(&scripted{answers: goodAnswers()}, inventory(), "  main  ")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if draft.Zones[0].ZoneID != "main" {
		t.Fatalf("zone_id = %q, want it trimmed", draft.Zones[0].ZoneID)
	}
}

// A proof that cannot disagree with the claim it tests proves nothing.
//
// Deriving `coil_state` from the mapping and `terminal_state_observed` from the
// outcome's name produced observations that agreed with the mapping by
// construction — so a mapping describing the wrong wiring was confirmed by its
// own proof.
func TestTheProofCanContradictTheMappingItTests(t *testing.T) {
	// The mapping says opening needs the coil energised. The installer observed
	// it de-energised: the mapping describes wiring this is not.
	_, err := Capture(&scripted{answers: answersWith(map[int]string{
		qOpenCoil: "de_energised",
	})}, inventory(), "main")
	if err == nil {
		t.Fatal("an observation contradicting the mapping was accepted")
	}
	if !strings.Contains(err.Error(), "wiring this is not") {
		t.Fatalf("the refusal does not say what disagrees: %v", err)
	}

	// And the circuit must actually do what the command names.
	_, err = Capture(&scripted{answers: answersWith(map[int]string{
		qOpenTerminal: "closed",
	})}, inventory(), "main")
	if err == nil {
		t.Fatal("a command that did not do what it names was accepted")
	}
	if !strings.Contains(err.Error(), "did not do what it names") {
		t.Fatalf("the refusal does not say what happened: %v", err)
	}
}

// Both facts are asked for each outcome, not inferred from one another.
func TestBothObservedFactsAreAsked(t *testing.T) {
	s := &scripted{answers: goodAnswers()}
	if _, err := Capture(s, inventory(), "main"); err != nil {
		t.Fatalf("capture: %v", err)
	}
	var coilQuestions, terminalQuestions int
	for _, p := range s.prompts {
		if strings.Contains(p, "was the coil observed") {
			coilQuestions++
		}
		if strings.Contains(p, "was the protected circuit observed") {
			terminalQuestions++
		}
	}
	if coilQuestions != 2 || terminalQuestions != 2 {
		t.Fatalf("coil asked %d times, terminal %d; both outcomes need both",
			coilQuestions, terminalQuestions)
	}
}
