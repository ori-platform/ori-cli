// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ori-platform/ori-cli/internal/binding"
)

// Proof states a revised zone can be left in. They are three different things
// and never reported as one another.
const (
	StateProven         = "proven"
	StateProvisional    = "provisional"
	StateUndemonstrated = "undemonstrated"
)

const (
	answerUnchanged = "unchanged"
	answerChanged   = "changed"
)

// Prior is the binding in force a revision is captured against: the document
// itself, and what a consumer retained from it.
type Prior struct {
	Document binding.Binding
	Accepted *binding.Accepted
}

// Change is one fact a revision altered, with the value it replaced.
type Change struct {
	Fact string `json:"fact"`
	Was  string `json:"was"`
	Now  string `json:"now"`
}

// Revision is what a revision changed, what it carried, and the proof it needs.
type Revision struct {
	Supersedes        string   `json:"supersedes"`
	SupersedesSeq     int64    `json:"supersedes_binding_seq"`
	BindingSeq        int64    `json:"binding_seq"`
	ZoneID            string   `json:"zone_id"`
	Changed           []Change `json:"changed"`
	Carried           []string `json:"carried"`
	CarriedZones      []string `json:"carried_zones"`
	FreshProof        bool     `json:"fresh_proof_required"`
	Because           []string `json:"fresh_proof_because"`
	CircuitLegAfterMs int64    `json:"circuit_leg_after_ms"`
	ControlLegAfterMs *int64   `json:"control_leg_after_ms"`
	CircuitLeg        string   `json:"circuit_leg"`
	ControlLeg        string   `json:"control_leg"`
	ProofState        string   `json:"proof_state"`
	TripPointBound    string   `json:"trip_point_bound"`
	Reason            string   `json:"reason"`
}

// LoadPrior binds a signed envelope to the binding the runtime reports in
// force. The runtime reports only the hash, so the document is what an
// installer presents, and it is trusted for nothing until its canonical hash
// is the one the runtime returned.
func LoadPrior(inv Inventory, envelope []byte) (Prior, error) {
	if inv.AcceptedBindingHash == "" {
		return Prior{}, fmt.Errorf(
			"device %q reports no binding in force, so there is nothing to revise; "+
				"capture a first binding without --revise", inv.DeviceID)
	}
	accepted, err := binding.VerifyOffline(envelope)
	if err != nil {
		return Prior{}, fmt.Errorf(
			"the document given as the binding in force does not verify (%v), so "+
				"nothing in it can be carried", err)
	}
	if accepted.CanonicalHash != inv.AcceptedBindingHash {
		return Prior{}, fmt.Errorf(
			"the document given hashes to %s, and the binding in force on device %q "+
				"is %s; a revision is captured against the binding in force and no other",
			accepted.CanonicalHash, inv.DeviceID, inv.AcceptedBindingHash)
	}
	if accepted.BindingSeq != inv.AcceptedBindingSeq || accepted.DeviceID != inv.DeviceID {
		return Prior{}, fmt.Errorf(
			"the runtime reports binding %d on device %q with that hash, and the "+
				"document is binding %d for %q; the inventory does not describe it",
			inv.AcceptedBindingSeq, inv.DeviceID, accepted.BindingSeq, accepted.DeviceID)
	}
	var env struct {
		Binding json.RawMessage `json:"binding"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		return Prior{}, fmt.Errorf("the binding in force is not readable: %w", err)
	}
	doc, _, err := binding.DecodeDocument(env.Binding)
	if err != nil {
		return Prior{}, fmt.Errorf("the binding in force is not readable: %w", err)
	}
	return Prior{Document: doc, Accepted: accepted}, nil
}

// Exported is what `commissioning binding-export` answers. The envelope is a
// string so that no JSON layer between the runtime and here re-encodes the
// bytes whose hash is compared.
type Exported struct {
	BindingSeq   int64   `json:"binding_seq"`
	BindingHash  string  `json:"binding_hash"`
	EnvelopeJSON *string `json:"envelope_json"`
}

// LoadExported takes the prior from the runtime's export, which must name the
// binding the inventory reports in force before its envelope is read at all.
func LoadExported(inv Inventory, result []byte) (Prior, error) {
	var exported Exported
	if err := json.Unmarshal(result, &exported); err != nil {
		return Prior{}, fmt.Errorf("the runtime's binding export is not readable: %w", err)
	}
	if exported.BindingSeq != inv.AcceptedBindingSeq || exported.BindingHash != inv.AcceptedBindingHash {
		return Prior{}, fmt.Errorf(
			"the runtime exported binding %d (%s) and reports binding %d (%s) in "+
				"force; a revision is captured against the binding in force and no other",
			exported.BindingSeq, exported.BindingHash, inv.AcceptedBindingSeq,
			inv.AcceptedBindingHash)
	}
	if exported.EnvelopeJSON == nil || *exported.EnvelopeJSON == "" {
		return Prior{}, fmt.Errorf("the runtime's binding export carries no envelope")
	}
	return LoadPrior(inv, []byte(*exported.EnvelopeJSON))
}

// Revise captures a change to one zone of the binding in force.
//
// Each fact is shown as the binding in force records it and asked only whether
// it changed; what did not is carried rather than re-typed, and the prior value
// of what did is carried into the reason. The proof is carried only when
// nothing but the rated capacity or the inventory generation changed. Any other
// change, or a like-for-like replacement, needs fresh legs, and those can be
// proven only on a line no zone of the binding in force drives: the proof
// operation refuses such a line. The line is therefore asked first, and a
// change needing fresh legs on a driven line is refused as it is declared.
func Revise(
	a Asker, inv Inventory, prior Prior, zoneID string, nowMs int64,
) (binding.Binding, Revision, error) {
	at := -1
	names := make([]string, 0, len(prior.Document.Zones))
	driven := map[int]string{}
	sensorOf := map[string]string{}
	for i, z := range prior.Document.Zones {
		names = append(names, z.ZoneID)
		if z.ZoneID == zoneID {
			at = i
		}
		if z.Actuator.Kind == binding.KindLocalGPIO && z.Actuator.Identity.GPIOPin != nil {
			driven[*z.Actuator.Identity.GPIOPin] = z.ZoneID
		}
		sensorOf[z.Sensor.SensorID] = z.ZoneID
	}
	fail := func(err error) (binding.Binding, Revision, error) {
		return binding.Binding{}, Revision{}, err
	}
	if at < 0 {
		return fail(fmt.Errorf(
			"the binding in force has no zone %q (it has %s); a revision changes a "+
				"zone that is in force", zoneID, strings.Join(quoted(names), ", ")))
	}
	was := prior.Document.Zones[at]
	if was.Actuator.Kind != binding.KindLocalGPIO || was.Actuator.Identity.GPIOPin == nil ||
		was.Actuator.Identity.ActiveHigh == nil {
		return fail(fmt.Errorf(
			"zone %q is bound to a %s actuator, and this ceremony revises local_gpio "+
				"zones only", zoneID, was.Actuator.Kind))
	}
	state := binding.RetainedState(prior.Accepted)[zoneID]

	rev := Revision{
		Supersedes:        inv.AcceptedBindingHash,
		SupersedesSeq:     inv.AcceptedBindingSeq,
		BindingSeq:        inv.AcceptedBindingSeq + 1,
		ZoneID:            zoneID,
		Changed:           []Change{},
		Carried:           []string{},
		CarriedZones:      []string{},
		Because:           []string{},
		CircuitLegAfterMs: state.ProofAtMs,
		ControlLegAfterMs: state.ControlProofAtMs,
		TripPointBound:    "deferred_to_delivery",
	}
	a.Say(fmt.Sprintf(
		"Revising zone %q of binding %d, the binding in force (%s).\n"+
			"Each fact is shown as that binding records it; answer %q to carry it.\n"+
			"Only a change to the rated capacity or the inventory generation carries "+
			"the proof. Any other change to this zone, or hardware replaced like for "+
			"like, needs fresh legs, and fresh legs can be proven only on a line no "+
			"zone of the binding in force drives: the runtime's proof operation "+
			"refuses a line the binding in force still drives, so such a change on "+
			"one is refused as soon as it is declared.",
		zoneID, inv.AcceptedBindingSeq, inv.AcceptedBindingHash, answerUnchanged))

	why, err := a.Ask("Why is this change being made? It opens the recorded reason.")
	if err != nil {
		return fail(err)
	}
	why = strings.TrimSpace(why)
	if why == "" || !utf8.ValidString(why) {
		return fail(fmt.Errorf(
			"a revision records why it was made; the answer was empty or not valid UTF-8"))
	}

	now := was
	pin := *was.Actuator.Identity.GPIOPin
	activeHigh := *was.Actuator.Identity.ActiveHigh
	changed := func(fact, before, after string, needsProof bool) error {
		rev.Changed = append(rev.Changed, Change{Fact: fact, Was: before, Now: after})
		if !needsProof {
			return nil
		}
		rev.Because = append(rev.Because, fact)
		if owner, ok := driven[pin]; ok {
			return fmt.Errorf(
				"%s changed, so zone %q needs fresh legs, and gpio_pin=%d is still "+
					"driven by zone %q of the binding in force. The runtime's proof "+
					"operation refuses a line the binding in force drives, so this "+
					"revision could never be proven; nothing was written. Taking a "+
					"zone out of operation to prove it afresh is not yet specified",
				fact, zoneID, pin, owner)
		}
		return nil
	}

	// The line first: whether fresh legs could ever be proven depends on it.
	wasActuator := DescribeActuator(InventoryActuator{
		Kind: was.Actuator.Kind, Identity: map[string]any{"gpio_pin": pin},
	})
	actuatorAnswer, err := askChanged(a, fmt.Sprintf(
		"Actuator: %s. Is the protected circuit now controlled by a different "+
			"actuator or control input?", wasActuator),
		declaresPin(inv.Actuators, pin), "the device no longer declares that actuator")
	if err != nil {
		return fail(err)
	}
	if actuatorAnswer == answerChanged {
		act, chooseErr := chooseActuator(a, inv.Actuators)
		if chooseErr != nil {
			return fail(chooseErr)
		}
		identity := identityFrom(act, activeHigh)
		if act.Kind != binding.KindLocalGPIO || identity.GPIOPin == nil {
			return fail(fmt.Errorf(
				"%s is not a local_gpio actuator, and this ceremony revises local_gpio "+
					"zones only", DescribeActuator(act)))
		}
		if *identity.GPIOPin == pin {
			return fail(unchangedRefusal("the actuator"))
		}
		pin = *identity.GPIOPin
		if changeErr := changed("actuator", wasActuator, DescribeActuator(act), true); changeErr != nil {
			return fail(changeErr)
		}
	} else {
		rev.Carried = append(rev.Carried, "actuator")
	}

	// Nothing in the document shows a like-for-like replacement, so it is asked.
	replaced, err := a.Choose(
		"Was any hardware bound to this zone replaced like for like, with the "+
			"same part on the same pin or input?",
		[]string{"none", "relay or contactor", "sensor", "both"})
	if err != nil {
		return fail(err)
	}
	if replaced != "none" {
		if changeErr := changed("replaced_like_for_like", "as commissioned",
			replaced+" replaced", true); changeErr != nil {
			return fail(changeErr)
		}
	}

	sensorAnswer, err := askChanged(a, fmt.Sprintf(
		"Sensor: %s. Was it moved to another sensor, or has any of that other than "+
			"its calibration changed?", describeSensor(was.Sensor)),
		contains(inv.SensorIDs, was.Sensor.SensorID), "the device no longer declares that sensor")
	if err != nil {
		return fail(err)
	}
	if sensorAnswer == answerChanged {
		sensorID, chooseErr := a.Choose("Which sensor observes the protected circuit?", sorted(inv.SensorIDs))
		if chooseErr != nil {
			return fail(chooseErr)
		}
		if owner, ok := sensorOf[sensorID]; ok && owner != zoneID {
			return fail(fmt.Errorf(
				"%s is bound to zone %q of the binding in force; two zones cannot "+
					"name one sensor", sensorID, owner))
		}
		if changeErr := changed("sensor", describeSensor(was.Sensor), "", true); changeErr != nil {
			return fail(changeErr)
		}
		sensor, sensorErr := captureSensor(a, sensorID)
		if sensorErr != nil {
			return fail(sensorErr)
		}
		if sensor == was.Sensor {
			return fail(unchangedRefusal("the sensor"))
		}
		now.Sensor = sensor
		rev.Changed[len(rev.Changed)-1].Now = describeSensor(sensor)
	} else {
		calAnswer, calErr := askChanged(a, fmt.Sprintf(
			"Calibration reference: %q. Was the sensor recalibrated?",
			was.Sensor.CalibrationRef), true, "")
		if calErr != nil {
			return fail(calErr)
		}
		if calAnswer == answerChanged {
			if changeErr := changed("calibration_ref", was.Sensor.CalibrationRef, "", true); changeErr != nil {
				return fail(changeErr)
			}
			ref, askErr := a.Ask("Calibration reference for that sensor:")
			if askErr != nil {
				return fail(askErr)
			}
			ref = strings.TrimSpace(ref)
			if ref == "" {
				return fail(fmt.Errorf(
					"a calibration reference is required; it is what an audit follows " +
						"back to the instrument"))
			}
			if ref == was.Sensor.CalibrationRef {
				return fail(unchangedRefusal("the calibration reference"))
			}
			now.Sensor.CalibrationRef = ref
			rev.Changed[len(rev.Changed)-1].Now = ref
		} else {
			rev.Carried = append(rev.Carried, "sensor")
		}
	}

	// Polarity is shown and asked, never carried silently onto new wiring.
	polarityAnswer, err := askChanged(a, fmt.Sprintf(
		"Polarity: the driver stage energises the coil when the output is %s.",
		levelName(activeHigh)), true, "")
	if err != nil {
		return fail(err)
	}
	if polarityAnswer == answerChanged {
		if changeErr := changed("active_high", strconv.FormatBool(activeHigh), "", true); changeErr != nil {
			return fail(changeErr)
		}
		level, chooseErr := a.Choose(
			"Does the driver stage energise the coil when the output is high or low?",
			[]string{"high", "low"})
		if chooseErr != nil {
			return fail(chooseErr)
		}
		if (level == "high") == activeHigh {
			return fail(unchangedRefusal("the polarity"))
		}
		activeHigh = level == "high"
		rev.Changed[len(rev.Changed)-1].Now = strconv.FormatBool(activeHigh)
	} else {
		rev.Carried = append(rev.Carried, "active_high")
	}
	now.Actuator.Identity = binding.Identity{GPIOPin: &pin, ActiveHigh: &activeHigh}

	mappingAnswer, err := askChanged(a, fmt.Sprintf(
		"Commissioned mapping: %s.", describeMapping(was.Actuator.Mapping)), true, "")
	if err != nil {
		return fail(err)
	}
	if mappingAnswer == answerChanged {
		if changeErr := changed("commissioned_mapping", describeMapping(was.Actuator.Mapping), "", true); changeErr != nil {
			return fail(changeErr)
		}
		mapping, mapErr := captureMapping(a)
		if mapErr != nil {
			return fail(mapErr)
		}
		if mapping == was.Actuator.Mapping {
			return fail(unchangedRefusal("the mapping"))
		}
		now.Actuator.Mapping = mapping
		rev.Changed[len(rev.Changed)-1].Now = describeMapping(mapping)
	} else {
		rev.Carried = append(rev.Carried, "commissioned_mapping")
	}

	capacityAnswer, err := askChanged(a, fmt.Sprintf(
		"Rated capacity: %gA, from the %s.", was.RatedCapacity.Value,
		was.RatedCapacity.Provenance), true, "")
	if err != nil {
		return fail(err)
	}
	if capacityAnswer == answerChanged {
		provenance, chooseErr := a.Choose(
			"Where does the rated capacity come from?",
			[]string{"nameplate", "installer_measured", "design_document"})
		if chooseErr != nil {
			return fail(chooseErr)
		}
		value, askErr := askFloat(a, "Rated capacity of the protected circuit, in amperes:")
		if askErr != nil {
			return fail(askErr)
		}
		capacity := binding.RatedCapacity{
			Parameter: was.RatedCapacity.Parameter, Value: value, Provenance: provenance,
		}
		if capacity == was.RatedCapacity {
			return fail(unchangedRefusal("the rated capacity"))
		}
		now.RatedCapacity = capacity
		_ = changed("rated_capacity",
			fmt.Sprintf("%gA (%s)", was.RatedCapacity.Value, was.RatedCapacity.Provenance),
			fmt.Sprintf("%gA (%s)", value, provenance), false)
	} else {
		rev.Carried = append(rev.Carried, "rated_capacity")
	}
	// Re-bounds-checked whether or not it changed: the sensor it is bounded by
	// may have. The trip point is not: its multiplier is the release's, and only
	// delivery applies it.
	if now.RatedCapacity.Value <= 0 || now.RatedCapacity.Value > now.Sensor.RangeMax {
		return fail(fmt.Errorf(
			"a rated capacity of %gA is outside what a sensor with a full scale of "+
				"%gA can observe", now.RatedCapacity.Value, now.Sensor.RangeMax))
	}

	generation := prior.Document.InventoryGeneration
	generationAnswer, err := askChanged(a, fmt.Sprintf(
		"Inventory generation this binding is made against: %d.", generation), true, "")
	if err != nil {
		return fail(err)
	}
	if generationAnswer == answerChanged {
		value, askErr := askInt(a, "Inventory generation this binding is made against:")
		if askErr != nil {
			return fail(askErr)
		}
		if value < 1 {
			return fail(fmt.Errorf(
				"an inventory generation is at least 1; %d names no inventory", value))
		}
		if value == generation {
			return fail(unchangedRefusal("the inventory generation"))
		}
		// Generations are monotonic per device, so one below the binding in
		// force names an inventory the device has already left.
		if value < generation {
			return fail(fmt.Errorf(
				"inventory generation %d is below the %d the binding in force was "+
					"made against; generations only increase", value, generation))
		}
		_ = changed("inventory_generation", strconv.FormatInt(generation, 10),
			strconv.FormatInt(value, 10), false)
		generation = value
	} else {
		rev.Carried = append(rev.Carried, "inventory_generation")
	}

	rev.FreshProof = len(rev.Because) > 0
	if rev.FreshProof {
		// Reached only on a line no zone of the binding in force drives.
		a.Say(fmt.Sprintf(
			"This revision changes %s, so zone %q cannot inherit the proof in force.\n"+
				"It needs a fresh circuit leg performed after %d. The control leg in "+
				"force%s is not carried: once this binding is delivered and the runtime "+
				"restarts, prove both outcomes on gpio_pin=%d and export a fresh control "+
				"leg. Until then the zone is provisional.",
			strings.Join(rev.Because, ", "), zoneID, state.ProofAtMs,
			controlLegClause(state.ControlProofAtMs), pin))
		if inv.DeploymentPosture != "development" {
			a.Say(fmt.Sprintf(
				"This device verifies under %s posture, which refuses an "+
					"undemonstrated circuit leg.", inv.DeploymentPosture))
		}
		proof, proofErr := captureProof(a, now.Actuator.Mapping, nowMs, state.ProofAtMs)
		if proofErr != nil {
			return fail(proofErr)
		}
		now.Proof = proof
		rev.CircuitLeg = "fresh"
		if proof.Method == binding.MethodUnproven {
			rev.CircuitLeg = StateUndemonstrated
		}
		rev.ControlLeg = "prove_after_delivery"
	} else {
		a.Say(fmt.Sprintf(
			"Nothing this revision changes invalidates the proof, so zone %q carries "+
				"both legs of the binding in force.", zoneID))
		rev.Carried = append(rev.Carried, "proof")
		rev.CircuitLeg = "carried"
		rev.ControlLeg = "carried"
	}
	rev.ProofState = ProofState(now.Proof)
	rev.Reason = composeReason(why, rev)

	zones := make([]binding.Zone, len(prior.Document.Zones))
	copy(zones, prior.Document.Zones)
	zones[at] = now
	for _, z := range zones {
		if z.ZoneID != zoneID {
			rev.CarriedZones = append(rev.CarriedZones, z.ZoneID)
		}
	}
	hash := inv.AcceptedBindingHash
	draft := binding.Binding{
		V:                   1,
		BindingSeq:          inv.AcceptedBindingSeq + 1,
		DeviceID:            inv.DeviceID,
		InventoryGeneration: generation,
		Supersedes:          &hash,
		Reason:              rev.Reason,
		Zones:               zones,
	}
	return draft, rev, nil
}

// composeReason is the installer's why, then the prior value of everything the
// revision changed, so the document says what it replaced as well as why.
func composeReason(why string, rev Revision) string {
	parts := make([]string, 0, len(rev.Changed))
	for _, c := range rev.Changed {
		parts = append(parts, fmt.Sprintf("%s was %s, now %s", c.Fact, c.Was, c.Now))
	}
	changes := "nothing changed"
	if len(parts) > 0 {
		changes = strings.Join(parts, "; ")
	}
	return fmt.Sprintf("%s. Revises binding %d (%s), zone %q: %s.",
		strings.TrimSuffix(why, "."), rev.SupersedesSeq, rev.Supersedes, rev.ZoneID, changes)
}

// ProofState names what a zone's proof establishes: both legs, the circuit leg
// alone, or nothing.
func ProofState(p binding.Proof) string {
	if p.Method == binding.MethodUnproven {
		return StateUndemonstrated
	}
	if p.ControlPath != nil && p.ControlPath.Method == binding.ControlCommanded {
		return StateProven
	}
	return StateProvisional
}

// DeclaredRefs is the inventory in the verifier's terms.
func DeclaredRefs(inv Inventory) ([]binding.ActuatorRef, error) {
	refs := make([]binding.ActuatorRef, 0, len(inv.Actuators))
	for _, act := range inv.Actuators {
		ref := binding.ActuatorRef{Kind: act.Kind}
		switch act.Kind {
		case binding.KindLocalGPIO:
			pin, ok := act.Identity["gpio_pin"].(float64)
			if !ok || pin != float64(int64(pin)) {
				return nil, fmt.Errorf("the inventory names %s, whose pin is not a whole number",
					DescribeActuator(act))
			}
			ref.GPIOPin = int64(pin)
		case binding.KindFirmware:
			device, ok1 := act.Identity["firmware_device_id"].(string)
			channel, ok2 := act.Identity["channel"].(string)
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("the inventory names %s, which is not a firmware channel identity",
					DescribeActuator(act))
			}
			ref.FirmwareDeviceID, ref.Channel = device, channel
		default:
			return nil, fmt.Errorf("the inventory names an actuator of kind %q, which this build does not know",
				act.Kind)
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// askChanged offers "changed" alone when the value in force can no longer be
// carried, and says why.
func askChanged(a Asker, prompt string, carriable bool, why string) (string, error) {
	if !carriable {
		a.Say(fmt.Sprintf("%s cannot be carried: %s.", strings.TrimSuffix(prompt, "."), why))
		return a.Choose(prompt, []string{answerChanged})
	}
	return a.Choose(prompt, []string{answerUnchanged, answerChanged})
}

func unchangedRefusal(what string) error {
	return fmt.Errorf(
		"%s was answered changed and then given the value in force; one of those "+
			"two answers describes the site wrongly", what)
}

func controlLegClause(at *int64) string {
	if at == nil {
		return ""
	}
	return fmt.Sprintf(" (performed at %d)", *at)
}

func describeSensor(s binding.Sensor) string {
	return fmt.Sprintf("%s, %s in %s, %s, range %g to %g, noise floor %g, calibration %q",
		s.SensorID, s.Quantity, s.Unit, s.Direction, s.RangeMin, s.RangeMax,
		s.NoiseFloor, s.CalibrationRef)
}

func describeMapping(m binding.Mapping) string {
	return fmt.Sprintf("open needs the coil %s, close needs it %s, de-energised the circuit is %s",
		m.OpenProtectedCircuit, m.CloseProtectedCircuit, m.DeEnergisedTerminalState)
}

func levelName(activeHigh bool) string {
	if activeHigh {
		return "high"
	}
	return "low"
}

func declaresPin(actuators []InventoryActuator, pin int) bool {
	for _, act := range actuators {
		if act.Kind != binding.KindLocalGPIO {
			continue
		}
		if value, ok := act.Identity["gpio_pin"].(float64); ok && value == float64(pin) {
			return true
		}
	}
	return false
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func quoted(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strconv.Quote(v))
	}
	sort.Strings(out)
	return out
}
