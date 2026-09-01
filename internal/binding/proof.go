// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"encoding/json"
	"fmt"
	"sort"
)

// The verdicts `commissioning prove-command` can record, as
// `cli-commands/v1.md` names them. Only Matched is a success; the others are
// each a distinct finding and none of them is a proof.
const (
	AttestationMatched      = "matched"
	AttestationMismatched   = "mismatched"
	AttestationInconclusive = "inconclusive"
	AttestationTimeout      = "timeout"
)

// ProofExport is what `commissioning proof-export` returns: every recorded,
// consented attempt against one provisional binding.
//
// It is a log rather than a leg. Refusals decided before consent leave no audit
// row, so this is not a record of everything attempted, and a row here carries
// no implication that it belongs in a document.
type ProofExport struct {
	BindingHash  string             `json:"binding_hash"`
	BindingSeq   int64              `json:"binding_seq"`
	Observations []ProofObservation `json:"observations"`
}

// ProofObservation is one recorded command and what the operator attested of it.
type ProofObservation struct {
	ZoneID              string            `json:"zone_id"`
	Outcome             string            `json:"outcome"`
	CoilStateCommanded  string            `json:"coil_state_commanded"`
	LevelDriven         string            `json:"level_driven"`
	GPIOPin             int               `json:"gpio_pin"`
	ActiveHigh          bool              `json:"active_high"`
	CommandedAtMs       int64             `json:"commanded_at_ms"`
	HeldMs              int64             `json:"held_ms"`
	CommandIssued       bool              `json:"command_issued"`
	EffectVerified      bool              `json:"effect_verified"`
	OperatorAttestation string            `json:"operator_attestation"`
	ReleaseRequested    bool              `json:"release_requested"`
	Observed            *ExportedObserved `json:"observed"`
	Note                string            `json:"note"`
}

// ExportedObserved is the contract-shaped observation the runtime recorded.
// The three measurement fields are absent from anything this surface produces:
// `prove-command` offers no measurement path.
type ExportedObserved struct {
	Commanded             string   `json:"commanded"`
	CoilState             string   `json:"coil_state"`
	GPIOLevel             string   `json:"gpio_level"`
	LoadPresentBefore     bool     `json:"load_present_before"`
	LoadPresentAfter      bool     `json:"load_present_after"`
	TerminalStateObserved string   `json:"terminal_state_observed"`
	SensorBefore          *float64 `json:"sensor_before"`
	SensorAfter           *float64 `json:"sensor_after"`
	Instrument            string   `json:"instrument"`
}

// DecodeProofExport reads the bridge's `result` payload.
func DecodeProofExport(payload []byte) (ProofExport, error) {
	var export ProofExport
	if err := json.Unmarshal(payload, &export); err != nil {
		return ProofExport{}, fmt.Errorf("proof export is not readable: %w", err)
	}
	return export, nil
}

// ControlPathFor assembles the control leg for one zone from what the runtime
// recorded, or explains why it cannot.
//
// The obligation is the contract's, not this function's convenience: a leg
// needs both outcomes, each of them observed, and a row whose attestation is
// not `matched` must not be assembled into one. Building a leg from anything
// else produces a document the verifier refuses at `proof_consistency`, so the
// system fails closed either way — the point of refusing here is to say so
// while the installer is still at the panel rather than after a signature.
func ControlPathFor(export ProofExport, zoneID string) (*ControlPath, error) {
	usable := map[string]ProofObservation{}
	var latest int64

	for _, row := range export.Observations {
		if row.ZoneID != zoneID {
			continue
		}
		switch row.OperatorAttestation {
		case AttestationMatched:
		case AttestationMismatched:
			return nil, fmt.Errorf(
				"zone %q: the operator observed %s doing the opposite of what it "+
					"asserts; the binding's polarity is contradicted and no leg "+
					"follows from it", zoneID, row.Outcome)
		case AttestationInconclusive, AttestationTimeout:
			// Not a contradiction, and not a proof. Skipped rather than
			// refused: a later attempt on the same outcome can still succeed.
			continue
		case "":
			// Fail closed. A row carrying no verdict is indistinguishable here
			// from one whose field was dropped or never written, and nothing in
			// the payload separates a pre-migration record from a malformed
			// one. Refusing names the row so an operator can decide; skipping
			// would silently treat an unreadable record as a non-event.
			return nil, fmt.Errorf(
				"zone %q: a recorded command for %s carries no attestation. A row "+
					"written before that field existed reads the same as one "+
					"whose field was lost, so neither is assumed",
				zoneID, row.Outcome)
		default:
			// The set is closed and may gain members. An attestation this
			// build does not recognise is a refusal, never a success.
			return nil, fmt.Errorf(
				"zone %q: attestation %q is not one this build recognises; "+
					"treating it as a proof would assume a meaning it was never "+
					"given", zoneID, row.OperatorAttestation)
		}
		// The claim this leg makes is that the runtime commanded the binding's
		// own pin and recorded the result. A row that does not say the command
		// was issued, or that the line was released, is not a record of that,
		// whatever the operator attested about the circuit.
		if !row.CommandIssued {
			return nil, fmt.Errorf(
				"zone %q: %s is attested matched but the runtime does not record "+
					"the command as issued", zoneID, row.Outcome)
		}
		if !row.ReleaseRequested {
			return nil, fmt.Errorf(
				"zone %q: %s records no release of the line, so it is not a "+
					"record of a bounded command", zoneID, row.Outcome)
		}
		// The runtime commands the coil and does not observe it. A row claiming
		// otherwise did not come from this operation.
		if row.EffectVerified {
			return nil, fmt.Errorf(
				"zone %q: %s claims the effect was verified, which the runtime "+
					"never records", zoneID, row.Outcome)
		}
		if row.Observed == nil {
			return nil, fmt.Errorf(
				"zone %q: %s is recorded matched but carries no observation",
				zoneID, row.Outcome)
		}
		// The obligation is both outcomes, not two map keys. An observation
		// whose commanded direction disagrees with the row it is filed under
		// would assemble a leg with one direction recorded twice.
		if row.Observed.Commanded != row.Outcome {
			return nil, fmt.Errorf(
				"zone %q: a row for %s carries an observation of %s; one of the "+
					"two is filed against the wrong outcome",
				zoneID, row.Outcome, row.Observed.Commanded)
		}
		// Required on a local_gpio control-path observation: the level actually
		// driven is the evidence this leg records, and a leg without it has
		// recorded the command and not the control path.
		if row.Observed.GPIOLevel == "" {
			return nil, fmt.Errorf(
				"zone %q: the observation of %s records no gpio_level, so it "+
					"records the command and not the control path",
				zoneID, row.Outcome)
		}
		// What the runtime commanded and what the observation records must be
		// the same act. Both facts are required, not merely compared when
		// present: an absent one would skip its own check, and the leg's whole
		// claim is that the runtime's recorded command — not only the
		// operator's answer about the circuit — is what became the proof.
		if row.CoilStateCommanded == "" {
			return nil, fmt.Errorf(
				"zone %q: %s records no commanded coil state, so nothing says "+
					"the runtime commanded what the observation describes",
				zoneID, row.Outcome)
		}
		if row.LevelDriven == "" {
			return nil, fmt.Errorf(
				"zone %q: %s records no driven level, so nothing says the runtime "+
					"drove the pin the observation describes", zoneID, row.Outcome)
		}
		if row.Observed.CoilState != row.CoilStateCommanded {
			return nil, fmt.Errorf(
				"zone %q: %s was commanded with the coil %s but the observation "+
					"records %s", zoneID, row.Outcome,
				row.CoilStateCommanded, row.Observed.CoilState)
		}
		if row.Observed.GPIOLevel != row.LevelDriven {
			return nil, fmt.Errorf(
				"zone %q: %s drove the pin %s but the observation records %s",
				zoneID, row.Outcome, row.LevelDriven, row.Observed.GPIOLevel)
		}
		// A later attempt supersedes an earlier one for the same outcome.
		if prior, seen := usable[row.Outcome]; !seen || row.CommandedAtMs >= prior.CommandedAtMs {
			usable[row.Outcome] = row
		}
		if row.CommandedAtMs > latest {
			latest = row.CommandedAtMs
		}
	}

	if missing := missingOutcomes(usable); len(missing) > 0 {
		return nil, fmt.Errorf(
			"zone %q: a control leg needs both outcomes observed; %s %s no "+
				"matched observation",
			zoneID, joinOutcomes(missing), plural(len(missing)))
	}

	// The freshness rule a revision is judged by turns on this timestamp, so a
	// leg that cannot say when it was performed is not one.
	if latest <= 0 {
		return nil, fmt.Errorf(
			"zone %q: no recorded command carries a usable timestamp, so the leg "+
				"cannot say when it was performed", zoneID)
	}

	leg := &ControlPath{Method: ControlCommanded, PerformedAtMs: latest}
	for _, outcome := range sortedOutcomes(usable) {
		row := usable[outcome]
		leg.Observations = append(leg.Observations, Observation{
			Commanded:             row.Observed.Commanded,
			CoilState:             row.Observed.CoilState,
			GPIOLevel:             row.Observed.GPIOLevel,
			TerminalStateObserved: row.Observed.TerminalStateObserved,
			LoadPresentBefore:     row.Observed.LoadPresentBefore,
			LoadPresentAfter:      row.Observed.LoadPresentAfter,
			SensorBefore:          row.Observed.SensorBefore,
			SensorAfter:           row.Observed.SensorAfter,
			Instrument:            row.Observed.Instrument,
		})
	}
	return leg, nil
}

func missingOutcomes(usable map[string]ProofObservation) []string {
	var missing []string
	for _, outcome := range []string{OutcomeOpen, OutcomeClose} {
		if _, ok := usable[outcome]; !ok {
			missing = append(missing, outcome)
		}
	}
	return missing
}

func sortedOutcomes(usable map[string]ProofObservation) []string {
	outcomes := make([]string, 0, len(usable))
	for outcome := range usable {
		outcomes = append(outcomes, outcome)
	}
	sort.Strings(outcomes)
	return outcomes
}

func joinOutcomes(outcomes []string) string {
	if len(outcomes) == 1 {
		return outcomes[0]
	}
	return outcomes[0] + " and " + outcomes[1]
}

func plural(n int) string {
	if n == 1 {
		return "has"
	}
	return "have"
}

// ControlPathJSON renders a control leg in the contract's own field names.
//
// The struct is not marshalled directly: it carries no JSON tags, because it is
// serialised through the canonical encoder rather than by `encoding/json`.
// Marshalling it emits Go field names, and its zero values put `reason: ""` and
// `sensor_before: null` into a leg — under the contract's closed grammar that is
// malformed twice over, and `reason` on a commanded_and_observed leg is refused
// outright. The absent fields are absent, not empty.
func ControlPathJSON(leg ControlPath) ([]byte, error) {
	observations := make([]map[string]any, 0, len(leg.Observations))
	for _, o := range leg.Observations {
		entry := map[string]any{
			"commanded":               o.Commanded,
			"coil_state":              o.CoilState,
			"load_present_before":     o.LoadPresentBefore,
			"load_present_after":      o.LoadPresentAfter,
			"terminal_state_observed": o.TerminalStateObserved,
		}
		if o.GPIOLevel != "" {
			entry["gpio_level"] = o.GPIOLevel
		}
		if o.SensorBefore != nil {
			entry["sensor_before"] = *o.SensorBefore
		}
		if o.SensorAfter != nil {
			entry["sensor_after"] = *o.SensorAfter
		}
		if o.Instrument != "" {
			entry["instrument"] = o.Instrument
		}
		observations = append(observations, entry)
	}
	body := map[string]any{
		"method":          leg.Method,
		"performed_at_ms": leg.PerformedAtMs,
		"observations":    observations,
	}
	if leg.Reason != "" {
		body["reason"] = leg.Reason
	}
	return json.MarshalIndent(body, "", "  ")
}
