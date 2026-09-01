// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"strings"
	"testing"
)

func observed(outcome, coil, level, terminal string, before, after bool) *ExportedObserved {
	return &ExportedObserved{
		Commanded:             outcome,
		CoilState:             coil,
		GPIOLevel:             level,
		LoadPresentBefore:     before,
		LoadPresentAfter:      after,
		TerminalStateObserved: terminal,
	}
}

func row(outcome, attestation string, at int64, obs *ExportedObserved) ProofObservation {
	row := ProofObservation{
		ZoneID:              "main",
		Outcome:             outcome,
		CommandIssued:       true,
		ReleaseRequested:    true,
		CommandedAtMs:       at,
		OperatorAttestation: attestation,
		Observed:            obs,
	}
	if obs != nil {
		row.CoilStateCommanded = obs.CoilState
		row.LevelDriven = obs.GPIOLevel
	}
	return row
}

func bothMatched() ProofExport {
	return ProofExport{Observations: []ProofObservation{
		row(OutcomeOpen, AttestationMatched, 100,
			observed(OutcomeOpen, "energised", "high", "open", true, false)),
		row(OutcomeClose, AttestationMatched, 200,
			observed(OutcomeClose, "de_energised", "low", "closed", false, true)),
	}}
}

func TestControlPathNeedsBothOutcomes(t *testing.T) {
	export := ProofExport{Observations: bothMatched().Observations[:1]}
	if _, err := ControlPathFor(export, "main"); err == nil {
		t.Fatal("a leg was assembled from one outcome")
	} else if !strings.Contains(err.Error(), OutcomeClose) {
		t.Fatalf("the refusal does not name the missing outcome: %v", err)
	}
}

func TestControlPathCarriesEveryObservedFact(t *testing.T) {
	leg, err := ControlPathFor(bothMatched(), "main")
	if err != nil {
		t.Fatalf("both outcomes matched but no leg: %v", err)
	}
	if leg.Method != ControlCommanded {
		t.Fatalf("method = %q", leg.Method)
	}
	if leg.PerformedAtMs != 200 {
		t.Fatalf("PerformedAtMs = %d, want the latest command", leg.PerformedAtMs)
	}
	if len(leg.Observations) != 2 {
		t.Fatalf("observations = %d", len(leg.Observations))
	}
	for _, obs := range leg.Observations {
		if obs.GPIOLevel == "" || obs.CoilState == "" || obs.TerminalStateObserved == "" {
			t.Fatalf("an observation lost a fact the contract requires: %+v", obs)
		}
	}
}

// A mismatch is a finding about the binding, not a row to skip past: the
// polarity it asserts has been contradicted.
func TestMismatchRefusesTheWholeLeg(t *testing.T) {
	export := bothMatched()
	export.Observations = append(export.Observations,
		row(OutcomeOpen, AttestationMismatched, 300,
			observed(OutcomeOpen, "energised", "high", "closed", true, true)))
	_, err := ControlPathFor(export, "main")
	if err == nil {
		t.Fatal("a contradicted polarity was assembled into a leg")
	}
	if !strings.Contains(err.Error(), "contradicted") {
		t.Fatalf("the refusal does not say what was found: %v", err)
	}
}

// Neither demonstrates anything, and neither contradicts the binding, so a
// later attempt on the same outcome can still complete the leg.
func TestInconclusiveAndTimeoutAreSkippedNotFatal(t *testing.T) {
	export := ProofExport{Observations: []ProofObservation{
		row(OutcomeOpen, AttestationTimeout, 10, nil),
		row(OutcomeOpen, AttestationInconclusive, 20,
			observed(OutcomeOpen, "energised", "high", "open", false, false)),
		row(OutcomeOpen, AttestationMatched, 100,
			observed(OutcomeOpen, "energised", "high", "open", true, false)),
		row(OutcomeClose, AttestationMatched, 200,
			observed(OutcomeClose, "de_energised", "low", "closed", false, true)),
	}}
	leg, err := ControlPathFor(export, "main")
	if err != nil {
		t.Fatalf("a superseded attempt blocked the leg: %v", err)
	}
	for _, obs := range leg.Observations {
		if obs.Commanded == OutcomeOpen && obs.LoadPresentBefore != true {
			t.Fatal("an unusable row was assembled instead of the matched one")
		}
	}
}

// The vocabulary is closed and may gain members. Reading an unknown verdict as
// a proof assumes a meaning it was never given.
func TestUnknownAttestationIsRefused(t *testing.T) {
	export := bothMatched()
	export.Observations[0].OperatorAttestation = "provisionally_matched"
	if _, err := ControlPathFor(export, "main"); err == nil {
		t.Fatal("an unrecognised attestation was treated as a proof")
	}
}

func TestMatchedWithoutAnObservationIsRefused(t *testing.T) {
	export := bothMatched()
	export.Observations[0].Observed = nil
	if _, err := ControlPathFor(export, "main"); err == nil {
		t.Fatal("a matched row with no observation produced a leg")
	}
}

func TestRowsForAnotherZoneAreIgnored(t *testing.T) {
	export := bothMatched()
	for i := range export.Observations {
		export.Observations[i].ZoneID = "other"
	}
	if _, err := ControlPathFor(export, "main"); err == nil {
		t.Fatal("another zone's proof was assembled into this one's leg")
	}
}

func TestDecodeProofExportRejectsRubbish(t *testing.T) {
	if _, err := DecodeProofExport([]byte("{")); err == nil {
		t.Fatal("truncated JSON decoded")
	}
}

// The obligation is both outcomes, not two map keys.
func TestAnObservationFiledUnderTheWrongOutcomeIsRefused(t *testing.T) {
	export := bothMatched()
	export.Observations[0].Observed.Commanded = OutcomeClose
	if _, err := ControlPathFor(export, "main"); err == nil {
		t.Fatal("a leg was assembled with one direction recorded twice")
	}
}

// The level driven is the evidence this leg records.
func TestAnObservationWithoutAGPIOLevelIsRefused(t *testing.T) {
	export := bothMatched()
	export.Observations[1].Observed.GPIOLevel = ""
	if _, err := ControlPathFor(export, "main"); err == nil {
		t.Fatal("a leg recorded the command and not the control path")
	}
}

// The revision freshness rule turns on this timestamp.
func TestALegWithoutAUsableTimestampIsRefused(t *testing.T) {
	export := bothMatched()
	for i := range export.Observations {
		export.Observations[i].CommandedAtMs = 0
	}
	if _, err := ControlPathFor(export, "main"); err == nil {
		t.Fatal("a leg was assembled that cannot say when it was performed")
	}
}

// A row carrying no verdict is indistinguishable from one whose field was
// dropped, so neither is assumed. Refusing names it; skipping would treat an
// unreadable record as a non-event.
func TestARowWithNoAttestationIsRefusedNotSkipped(t *testing.T) {
	export := bothMatched()
	export.Observations = append([]ProofObservation{
		{ZoneID: "main", Outcome: OutcomeOpen, CommandIssued: true,
			OperatorAttestation: "", CommandedAtMs: 10},
	}, export.Observations...)
	_, err := ControlPathFor(export, "main")
	if err == nil {
		t.Fatal("a row with no attestation was silently skipped")
	}
	if !strings.Contains(err.Error(), "carries no attestation") {
		t.Fatalf("the refusal does not name what is missing: %v", err)
	}
}

// The claim is that the runtime commanded the binding's own pin and recorded
// the result. A row that does not say so is not a record of it, whatever the
// operator attested about the circuit.
func TestARowThatIsNotARecordOfACommandIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*ProofObservation){
		"no command issued": func(r *ProofObservation) { r.CommandIssued = false },
		"no release":        func(r *ProofObservation) { r.ReleaseRequested = false },
		"effect verified":   func(r *ProofObservation) { r.EffectVerified = true },
		"coil disagrees":    func(r *ProofObservation) { r.CoilStateCommanded = "de_energised" },
		"level disagrees":   func(r *ProofObservation) { r.LevelDriven = "low" },
		// Both sides deleted. Only the presence requirement catches this: an
		// equality check on two absent values agrees with itself, and the row
		// would then say nothing about what the runtime commanded.
		"no commanded coil": func(r *ProofObservation) {
			r.CoilStateCommanded = ""
			r.Observed.CoilState = ""
		},
		"no driven level": func(r *ProofObservation) {
			r.LevelDriven = ""
			r.Observed.GPIOLevel = ""
		},
	} {
		export := bothMatched()
		mutate(&export.Observations[0])
		if _, err := ControlPathFor(export, "main"); err == nil {
			t.Fatalf("%s: a leg was assembled from it", name)
		}
	}
}
