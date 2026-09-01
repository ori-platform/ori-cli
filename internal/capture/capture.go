// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

// Package capture builds a commissioned binding draft from what a site
// actually presents.
//
// Two rules shape everything here. The candidate set comes from the runtime's
// declared inventory rather than operator free text, so a binding cannot name
// hardware the device does not have. And nothing is inferred: the three
// commissioned outcomes are asked separately, a contact type is not among the
// questions, and no answer is defaulted from another. A mapping derived from a
// convention is the failure this ceremony exists to prevent.
package capture

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ori-platform/ori-cli/internal/binding"
)

// Asker is how the ceremony reaches the installer. Tests supply their own.
type Asker interface {
	// Choose returns one of options. It must not accept anything else.
	Choose(prompt string, options []string) (string, error)
	Ask(prompt string) (string, error)
}

// Inventory is the runtime's declared hardware, as `commissioning inventory`
// returns it.
//
// AcceptedBindingHash is read because a revision must name what it supersedes,
// and the runtime returns it in the same payload. Dropping it produced drafts
// that no consumer would accept, using a value already in hand.
type Inventory struct {
	DeviceID            string              `json:"device_id"`
	SensorIDs           []string            `json:"sensor_ids"`
	Actuators           []InventoryActuator `json:"actuators"`
	DeploymentPosture   string              `json:"deployment_posture"`
	AcceptedBindingSeq  int64               `json:"accepted_binding_seq"`
	AcceptedBindingHash string              `json:"accepted_binding_hash"`
}

// InventoryActuator is one actuator the device declares, by identity.
type InventoryActuator struct {
	Kind     string         `json:"kind"`
	Identity map[string]any `json:"identity"`
}

const (
	coilEnergised   = "energised"
	coilDeEnergised = "de_energised"
	circuitOpen     = "open"
	circuitClosed   = "closed"
)

// Capture asks for one zone's facts and returns a draft.
//
// The draft is checked as a consumer would check it before it is returned, so
// an implausible rated capacity or a self-contradicting mapping fails here —
// where the installer can still see the wiring — rather than at a device.
func Capture(a Asker, inv Inventory, zoneID string) (binding.Binding, error) {
	if strings.TrimSpace(zoneID) == "" {
		return binding.Binding{}, fmt.Errorf(
			"a zone needs a name: it is what an inventory comparison and every " +
				"later revision identify it by")
	}
	// Go substitutes U+FFFD for invalid UTF-8 where a producer elsewhere would
	// raise, so a signed binding would name a zone the installer never typed
	// and inventory disambiguation would fail for a reason nothing explains.
	if !utf8.ValidString(zoneID) {
		return binding.Binding{}, fmt.Errorf(
			"the zone name is not valid UTF-8; it would be recorded with its " +
				"invalid bytes replaced, naming a zone nobody typed")
	}
	if len(inv.SensorIDs) == 0 {
		return binding.Binding{}, fmt.Errorf(
			"device %q declares no sensors, so there is nothing to bind",
			inv.DeviceID)
	}
	if len(inv.Actuators) == 0 {
		return binding.Binding{}, fmt.Errorf(
			"device %q declares no actuator; a site with nothing to actuate has "+
				"no binding to make", inv.DeviceID)
	}

	sensorID, err := a.Choose("Which sensor observes the protected circuit?", sorted(inv.SensorIDs))
	if err != nil {
		return binding.Binding{}, err
	}

	actuator, err := chooseActuator(a, inv.Actuators)
	if err != nil {
		return binding.Binding{}, err
	}

	// Asked, never derived. The stage's polarity is a commissioned fact: a
	// board that energises on a low is as ordinary as one that energises on a
	// high, and no default is safe for both.
	activeHighAnswer, err := a.Choose(
		"Does the driver stage energise the coil when the output is high or low?",
		[]string{"high", "low"})
	if err != nil {
		return binding.Binding{}, err
	}
	activeHigh := activeHighAnswer == "high"

	mapping, err := captureMapping(a)
	if err != nil {
		return binding.Binding{}, err
	}

	// Asked, not assumed. A capacity is a safety parameter and an audit needs to
	// know what kind of claim it was.
	provenance, err := a.Choose(
		"Where does the rated capacity come from?",
		[]string{"nameplate", "installer_measured", "design_document"})
	if err != nil {
		return binding.Binding{}, err
	}
	capacity, err := askFloat(a, "Rated capacity of the protected circuit, in amperes:")
	if err != nil {
		return binding.Binding{}, err
	}

	sensor, err := captureSensor(a, sensorID)
	if err != nil {
		return binding.Binding{}, err
	}
	rangeMax := sensor.RangeMax

	// Refused here, where the installer can still see the wiring, rather than
	// at a device. A capacity above the sensor's full scale describes a circuit
	// this sensor cannot observe, and the trip point is that capacity times a
	// release-owned constant.
	if capacity > rangeMax {
		return binding.Binding{}, fmt.Errorf(
			"a rated capacity of %gA is above the sensor's full scale of %gA, so "+
				"this sensor cannot observe the circuit it would be bound to",
			capacity, rangeMax)
	}
	if capacity <= 0 || rangeMax <= 0 {
		return binding.Binding{}, fmt.Errorf(
			"rated capacity and sensor range are both positive quantities; got "+
				"%gA and %gA", capacity, rangeMax)
	}

	// The generation is an operator input: it belongs to the provisioning-signed
	// inventory authority, and a runtime holds only the value a binding claims.
	generation, err := askInt(a, "Inventory generation this binding is made against:")
	if err != nil {
		return binding.Binding{}, err
	}

	proof, err := captureProof(a, mapping)
	if err != nil {
		return binding.Binding{}, err
	}

	draft := binding.Binding{
		V:                   1,
		BindingSeq:          inv.AcceptedBindingSeq + 1,
		DeviceID:            inv.DeviceID,
		InventoryGeneration: generation,
		// A revision names what it replaces; a first binding supersedes nothing.
		// The pointer keeps those apart, and the runtime returned the hash in
		// the same payload the candidates came from.
		Supersedes: supersedes(inv),
		Zones: []binding.Zone{{
			ZoneID: strings.TrimSpace(zoneID),
			RatedCapacity: binding.RatedCapacity{
				Parameter:  "rated_capacity_amps",
				Value:      capacity,
				Provenance: provenance,
			},
			Sensor: sensor,
			Actuator: binding.Actuator{
				Kind:     actuator.Kind,
				Identity: identityFrom(actuator, activeHigh),
				Mapping:  mapping,
			},
			Proof: proof,
		}},
	}
	return draft, nil
}

// captureMapping asks the three commissioned outcomes separately.
//
// A contact type is not among the questions, and no answer is derived from
// another: normally-open and normally-closed describe a contact, not what the
// downstream wiring does to the load, so a mapping inferred from one is an
// assumption wearing the authority of a measurement.
// captureSensor asks for the eight fields the contract requires of a sensor.
//
// None is defaulted. `direction` has no default because a clamp mounted
// backwards reports a hazard as a fall in magnitude, and a profile evaluating
// an upper bound would never fire; `noise_floor` bounds what a proof is allowed
// to call a change, so a zero would let any reading count.
func captureSensor(a Asker, sensorID string) (binding.Sensor, error) {
	quantity, err := a.Choose("What does that sensor measure?", []string{"current"})
	if err != nil {
		return binding.Sensor{}, err
	}
	unit, err := a.Choose("In what unit?", []string{"ampere"})
	if err != nil {
		return binding.Sensor{}, err
	}
	direction, err := a.Choose(
		"Which way does the sensor read a load drawing current?",
		[]string{"positive_is_load_draw", "negative_is_load_draw"})
	if err != nil {
		return binding.Sensor{}, err
	}
	rangeMin, err := askFloat(a, "Lowest value that sensor can report:")
	if err != nil {
		return binding.Sensor{}, err
	}
	rangeMax, err := askFloat(a, "Full-scale range of that sensor:")
	if err != nil {
		return binding.Sensor{}, err
	}
	if rangeMax <= rangeMin {
		return binding.Sensor{}, fmt.Errorf(
			"a full scale of %g is not above the lowest reportable value %g",
			rangeMax, rangeMin)
	}
	noiseFloor, err := askFloat(a,
		"Below what change is a reading indistinguishable from noise?")
	if err != nil {
		return binding.Sensor{}, err
	}
	if noiseFloor <= 0 {
		return binding.Sensor{}, fmt.Errorf(
			"a noise floor of %g would let any reading count as a change; it is "+
				"a positive quantity in the sensor's own unit", noiseFloor)
	}
	calibration, err := a.Ask("Calibration reference for that sensor:")
	if err != nil {
		return binding.Sensor{}, err
	}
	if strings.TrimSpace(calibration) == "" {
		return binding.Sensor{}, fmt.Errorf(
			"a calibration reference is required; it is what an audit follows " +
				"back to the instrument")
	}
	return binding.Sensor{
		SensorID:       sensorID,
		Quantity:       quantity,
		Unit:           unit,
		RangeMin:       rangeMin,
		RangeMax:       rangeMax,
		Direction:      direction,
		NoiseFloor:     noiseFloor,
		CalibrationRef: strings.TrimSpace(calibration),
	}, nil
}

func captureMapping(a Asker) (binding.Mapping, error) {
	open, err := a.Choose(
		"To OPEN the protected circuit, must the coil be energised or de-energised?",
		[]string{coilEnergised, coilDeEnergised})
	if err != nil {
		return binding.Mapping{}, err
	}
	closed, err := a.Choose(
		"To CLOSE the protected circuit, must the coil be energised or de-energised?",
		[]string{coilEnergised, coilDeEnergised})
	if err != nil {
		return binding.Mapping{}, err
	}
	if open == closed {
		return binding.Mapping{}, fmt.Errorf(
			"both outcomes were answered %q; one coil state cannot produce both, "+
				"so one of the two answers describes the wiring wrongly", open)
	}
	terminal, err := a.Choose(
		"With the coil DE-ENERGISED — controller off or crashed — is the "+
			"protected circuit open or closed? Observe it; do not reason from "+
			"the contact type.",
		[]string{circuitOpen, circuitClosed})
	if err != nil {
		return binding.Mapping{}, err
	}
	// The de-energised state is separately established, and disagreement means
	// the proof did not establish what the document records. Getting this wrong
	// gives a zone that reads as failing safe while it fails closed, recorded
	// at the one moment a human is standing where they can see the wiring.
	deEnergisedOutcome := circuitClosed
	if open == coilDeEnergised {
		deEnergisedOutcome = circuitOpen
	}
	if terminal != deEnergisedOutcome {
		return binding.Mapping{}, fmt.Errorf(
			"with the coil de-energised this zone was answered %q, but %q was "+
				"answered as the outcome de-energising produces, so it goes %q; "+
				"one of those two observations is of something else",
			terminal, deEnergisedOutcome, deEnergisedOutcome)
	}

	return binding.Mapping{
		OpenProtectedCircuit:     open,
		CloseProtectedCircuit:    closed,
		DeEnergisedTerminalState: terminal,
	}, nil
}

// captureProof records how the mapping was established, or that it was not.
//
// `commanded_and_observed` is absent by design: the control leg is proven by
// the runtime commanding the coil, and its observations are read back from the
// runtime rather than typed here. A leg this tool authored would record what
// the tool asserted.
func captureProof(a Asker, mapping binding.Mapping) (binding.Proof, error) {
	method, err := a.Choose(
		"How was the circuit leg established?",
		[]string{binding.MethodPreEnergy, binding.MethodUnproven})
	if err != nil {
		return binding.Proof{}, err
	}
	if method == binding.MethodUnproven {
		reason, askErr := a.Ask("Why could no proof be performed?")
		if askErr != nil {
			return binding.Proof{}, askErr
		}
		if strings.TrimSpace(reason) == "" {
			return binding.Proof{}, fmt.Errorf(
				"an undemonstrated proof records why none was possible; an empty " +
					"reason would leave the document claiming less than it knows")
		}
		// Its observations must be empty: a zone carrying them is claiming a
		// proof it also says it does not have.
		return binding.Proof{Method: method, Reason: strings.TrimSpace(reason)}, nil
	}

	performedAt, err := askInt(a,
		"When was that proof performed? Unix milliseconds:")
	if err != nil {
		return binding.Proof{}, err
	}
	if performedAt <= 0 {
		return binding.Proof{}, fmt.Errorf(
			"a proof records when it was performed; %d is not a time", performedAt)
	}

	// A proof admits a non-empty observations list, and both outcomes must be
	// observed: one-sided proof establishes one direction, and the direction it
	// leaves undemonstrated is the one a cutoff exists for.
	observations := make([]binding.Observation, 0, 2)
	for _, outcome := range []string{binding.OutcomeOpen, binding.OutcomeClose} {
		obs, obsErr := captureObservation(a, outcome, mapping)
		if obsErr != nil {
			return binding.Proof{}, obsErr
		}
		observations = append(observations, obs)
	}
	return binding.Proof{
		Method:        method,
		PerformedAtMs: performedAt,
		Observations:  observations,
	}, nil
}

// captureObservation records one commanded outcome and what was measured.
//
// Every fact here is observed, not derived. Deriving `coil_state` from the
// mapping and `terminal_state_observed` from the outcome's name produces an
// observation that agrees with the mapping by construction — which is exactly
// the wrong answer, because catching a mapping that does not match the wiring
// is what this proof is for. A proof that cannot disagree with the claim it
// tests proves nothing.
//
// The load determination is asked rather than read off a threshold: the
// instrument decides whether the load was drawing, not a comparison applied to
// a current value.
func captureObservation(
	a Asker, outcome string, mapping binding.Mapping,
) (binding.Observation, error) {
	coil, err := a.Choose(
		fmt.Sprintf("Commanding %s — was the coil observed energised or "+
			"de-energised?", outcome),
		[]string{coilEnergised, coilDeEnergised})
	if err != nil {
		return binding.Observation{}, err
	}
	terminal, err := a.Choose(
		fmt.Sprintf("Commanding %s — was the protected circuit observed open or "+
			"closed?", outcome),
		[]string{circuitOpen, circuitClosed})
	if err != nil {
		return binding.Observation{}, err
	}
	before, err := a.Choose(
		fmt.Sprintf("Commanding %s — was the load drawing BEFORE the command?",
			outcome), []string{"yes", "no"})
	if err != nil {
		return binding.Observation{}, err
	}
	after, err := a.Choose(
		fmt.Sprintf("Commanding %s — was the load drawing AFTER it?", outcome),
		[]string{"yes", "no"})
	if err != nil {
		return binding.Observation{}, err
	}

	// The observation and the declared mapping must agree, and disagreement
	// means the mapping describes wiring this is not.
	declaredCoil := mapping.CloseProtectedCircuit
	if outcome == binding.OutcomeOpen {
		declaredCoil = mapping.OpenProtectedCircuit
	}
	if coil != declaredCoil {
		return binding.Observation{}, fmt.Errorf(
			"the mapping says %s needs the coil %s, but it was observed %s; the "+
				"mapping describes wiring this is not",
			outcome, declaredCoil, coil)
	}
	expectedTerminal := circuitClosed
	if outcome == binding.OutcomeOpen {
		expectedTerminal = circuitOpen
	}
	if terminal != expectedTerminal {
		return binding.Observation{}, fmt.Errorf(
			"commanding %s left the circuit observed %s; the command did not do "+
				"what it names", outcome, terminal)
	}

	// The pair the consistency stage requires. An observation whose load never
	// changed state demonstrates nothing about this outcome.
	wantBefore, wantAfter := true, false
	if outcome == binding.OutcomeClose {
		wantBefore, wantAfter = false, true
	}
	if (before == "yes") != wantBefore || (after == "yes") != wantAfter {
		return binding.Observation{}, fmt.Errorf(
			"commanding %s, the load was answered %s then %s; a proof of this "+
				"outcome needs it to change state, and one that does not "+
				"demonstrates nothing", outcome, before, after)
	}

	return binding.Observation{
		Commanded:             outcome,
		CoilState:             coil,
		TerminalStateObserved: terminal,
		LoadPresentBefore:     before == "yes",
		LoadPresentAfter:      after == "yes",
	}, nil
}

func askInt(a Asker, prompt string) (int64, error) {
	raw, err := a.Ask(prompt)
	if err != nil {
		return 0, err
	}
	value, parseErr := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if parseErr != nil {
		return 0, fmt.Errorf("%q is not a whole number", strings.TrimSpace(raw))
	}
	return value, nil
}

func chooseActuator(a Asker, actuators []InventoryActuator) (InventoryActuator, error) {
	labels := make([]string, 0, len(actuators))
	byLabel := map[string]InventoryActuator{}
	for _, act := range actuators {
		label := DescribeActuator(act)
		labels = append(labels, label)
		byLabel[label] = act
	}
	sort.Strings(labels)
	chosen, err := a.Choose("Which actuator controls that circuit?", labels)
	if err != nil {
		return InventoryActuator{}, err
	}
	act, ok := byLabel[chosen]
	if !ok {
		return InventoryActuator{}, fmt.Errorf(
			"%q is not an actuator this device declares", chosen)
	}
	return act, nil
}

// DescribeActuator renders an actuator by identity, as the candidate set shows
// it and as the ceremony offers it, so the two cannot drift apart.
func DescribeActuator(act InventoryActuator) string {
	keys := make([]string, 0, len(act.Identity))
	for k := range act.Identity {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, act.Identity[k]))
	}
	return fmt.Sprintf("%s (%s)", act.Kind, strings.Join(parts, " "))
}

// identityFrom sets both pointers explicitly. They are pointers so that an
// unanswered polarity is distinguishable from a false one; this ceremony asked,
// so it records an answer rather than leaving the absence that means unknown.
func identityFrom(act InventoryActuator, activeHigh bool) binding.Identity {
	id := binding.Identity{ActiveHigh: &activeHigh}
	if pin, ok := act.Identity["gpio_pin"]; ok {
		var value int
		switch v := pin.(type) {
		case float64:
			value = int(v)
		case int:
			value = v
		default:
			return id
		}
		id.GPIOPin = &value
	}
	return id
}

func askFloat(a Asker, prompt string) (float64, error) {
	raw, err := a.Ask(prompt)
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(raw)
	value, parseErr := strconv.ParseFloat(text, 64)
	if parseErr != nil {
		return 0, fmt.Errorf("%q is not a number", text)
	}
	// NaN compares false against everything, so it survives a range check and
	// an above-zero check alike; an infinity passes both and describes no
	// circuit. Refused here, where the question was asked.
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, fmt.Errorf("%q is not a quantity a circuit can have", text)
	}
	// ParseFloat accepts hexadecimal floats, so `0x1p10` would silently become
	// 1024 — a commissioning answer nobody typed.
	if strings.ContainsAny(text, "xXpP") {
		return 0, fmt.Errorf(
			"%q is not a decimal number; commissioning quantities are written "+
				"as the installer reads them", text)
	}
	return value, nil
}

func sorted(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

// supersedes is the hash of the binding in force, or nil on a first binding.
func supersedes(inv Inventory) *string {
	if inv.AcceptedBindingHash == "" {
		return nil
	}
	hash := inv.AcceptedBindingHash
	return &hash
}
