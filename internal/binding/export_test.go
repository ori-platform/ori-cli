// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"sort"
	"strings"
)

// RevisionRule is one reading of the revision rule, switch by switch, so a
// test can hold the corpus to readings other than the verifier's own. The
// switches and their values mirror the runtime's mutation-adequacy harness.
type RevisionRule struct {
	MatchName     bool
	MatchActuator bool
	MatchSensor   bool
	SensorMatch   string // sensor_id | whole | id_and:<sensor field>
	GPIOMatch     string // pin | whole
	FirmwareMatch string // identity | board | channel

	ChangeIdentity  bool
	IdentityCompare string // whole | ignore_board | ignore_channel
	ChangeMapping   bool
	// whole | sensor_id | id_and_calibration | ignore:<field>, where range
	// names range_min and range_max together
	ChangeSensor   string
	RenameIsChange bool

	// all | first | last | latest_proof | sensor_first | name_if_no_actuator |
	// break_on_unchanged | stop_after_pass
	Visit string

	CircuitUnclaimedExempt        bool
	CircuitSkipIfControlFresh     bool
	CircuitOnlySingleMatch        bool
	CircuitStrict                 bool
	ControlRequiresClaim          bool
	ControlOn                     string // any_change | identity | identity_or_mapping
	ControlSkipIfCircuitUnclaimed bool
	ControlMissing                string // fresh | stale | circuit_time
	ControlStrict                 bool

	OneToOne                          bool
	ControlOnlySingleMatch            bool
	CircuitSkipIfControlUnclaimed     bool
	ControlAbsentStale                bool
	SingleRetainedTime                bool
	FreshAgainstEveryMatchOnceChanged bool
	ProofChangeIsChange               bool
	ClaimedMethods                    string // any_but_undemonstrated | actuate_and_observe
	CircuitRetainedTime               string // own | earlier
	// Exempt holds leg:field pairs; a leg so named is exempt from freshness
	// when that field is the only one the revision changed against a match.
	Exempt map[string]bool
	// ExemptSets holds a leg and a field set; the leg is exempt when the
	// revision changed exactly those fields against a match.
	ExemptSets []ExemptSet
	// ExemptAtLeast maps a leg to a count; the leg is exempt when the revision
	// changed at least that many fields against a match.
	ExemptAtLeast map[string]int
	// ExemptKindChange exempts the circuit leg on a change of actuator kind in
	// the named direction: "firmware" (GPIO to firmware) or "GPIO" (firmware
	// to GPIO).
	ExemptKindChange                   map[string]bool
	ExemptControlBehindPreEnergisation bool
	// ExemptPostures holds leg:posture pairs; the leg is exempt in that posture.
	ExemptPostures      map[string]bool
	ControlRetainedTime string // own | later
}

// ExemptSet names a leg and the exact field set that exempts it.
type ExemptSet struct {
	Leg    string
	Fields []string
}

// ReferenceRule is the contract's reading.
var ReferenceRule = RevisionRule{
	MatchName: true, MatchActuator: true, MatchSensor: true,
	SensorMatch: "sensor_id", GPIOMatch: "pin", FirmwareMatch: "identity",
	ChangeIdentity: true, IdentityCompare: "whole", ChangeMapping: true,
	ChangeSensor: "whole", Visit: "all",
	CircuitUnclaimedExempt: true, ControlRequiresClaim: true,
	ControlOn: "any_change", ControlMissing: "fresh",
	ClaimedMethods: "any_but_undemonstrated", CircuitRetainedTime: "own",
	ControlRetainedTime: "own",
}

// VerifyWithRule runs every stage, with the revision rule read as rule.
func VerifyWithRule(raw []byte, ctx Context, rule RevisionRule) (*Accepted, error) {
	return verifyEnvelope(raw, ctx, func(b *parsedBinding, prior map[string]ZoneState) *Refusal {
		if r := stObservations(b); r != nil {
			return r
		}
		return rule.check(b, prior, ctx.DeploymentPosture)
	})
}

type heldZone struct {
	zoneID string
	was    ZoneState
	ways   map[string]bool
}

func (rule RevisionRule) check(b *parsedBinding, prior map[string]ZoneState, posture string) *Refusal {
	ids := make([]string, 0, len(prior))
	for id := range prior {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, c := prior[ids[i]], prior[ids[j]]
		if a.Seq != c.Seq {
			return a.Seq < c.Seq
		}
		return ids[i] < ids[j]
	})
	consumed := map[string]bool{}
	for _, z := range b.zones {
		var held []heldZone
		for _, id := range ids {
			if rule.OneToOne && consumed[id] {
				continue
			}
			if ways := rule.ways(id, prior[id], z); len(ways) > 0 {
				held = append(held, heldZone{id, prior[id], ways})
			}
		}
		if rule.OneToOne {
			for _, h := range held {
				consumed[h.zoneID] = true
			}
		}
		if rule.FreshAgainstEveryMatchOnceChanged {
			anyChanged := false
			for _, h := range held {
				if len(rule.changes(h.zoneID, h.was, z)) > 0 {
					anyChanged = true
				}
			}
			if anyChanged {
				for _, h := range held {
					if rule.stale(z, h.was, map[string]bool{"identity": true}, len(held) == 1, posture) {
						return refuse(StageProofConsistency, ReasonStaleProof)
					}
				}
				continue
			}
		}
		held = rule.visit(held)
		for _, h := range held {
			changed := rule.changes(h.zoneID, h.was, z)
			if len(changed) == 0 {
				if rule.Visit == "break_on_unchanged" {
					break
				}
				continue
			}
			if rule.stale(z, h.was, changed, len(held) == 1, posture) {
				return refuse(StageProofConsistency, ReasonStaleProof)
			}
			if rule.Visit == "stop_after_pass" {
				break
			}
		}
	}
	return nil
}

func (rule RevisionRule) visit(held []heldZone) []heldZone {
	switch rule.Visit {
	case "first":
		if len(held) > 1 {
			return held[:1]
		}
	case "last":
		if len(held) > 1 {
			return held[len(held)-1:]
		}
	case "latest_proof":
		if len(held) > 0 {
			best := held[0]
			for _, h := range held[1:] {
				if h.was.ProofAtMs > best.was.ProofAtMs {
					best = h
				}
			}
			return []heldZone{best}
		}
	case "sensor_first":
		for _, h := range held {
			if h.ways["sensor"] {
				return []heldZone{h}
			}
		}
		if len(held) > 1 {
			return held[:1]
		}
	case "name_if_no_actuator":
		anyActuator := false
		for _, h := range held {
			if h.ways["actuator"] {
				anyActuator = true
			}
		}
		if anyActuator {
			var kept []heldZone
			for _, h := range held {
				if !(len(h.ways) == 1 && h.ways["name"]) {
					kept = append(kept, h)
				}
			}
			return kept
		}
	}
	return held
}

func (rule RevisionRule) ways(zoneID string, was ZoneState, z parsedZone) map[string]bool {
	ways := map[string]bool{}
	if rule.MatchName && zoneID == z.zoneID {
		ways["name"] = true
	}
	if rule.MatchActuator && rule.sameActuator(was.Identity, z.identity) {
		ways["actuator"] = true
	}
	if rule.MatchSensor && rule.sameSensor(was.Sensor, z.sensor) {
		ways["sensor"] = true
	}
	return ways
}

func (rule RevisionRule) sameActuator(retained, identity map[string]any) bool {
	pinA, okA := retained["gpio_pin"]
	pinB, okB := identity["gpio_pin"]
	if okA && okB {
		if rule.GPIOMatch == "whole" {
			return sameIdentity(retained, identity)
		}
		return sameIdentity(map[string]any{"gpio_pin": pinA}, map[string]any{"gpio_pin": pinB})
	}
	switch rule.FirmwareMatch {
	case "board":
		return sameIdentity(only(retained, "firmware_device_id"), only(identity, "firmware_device_id"))
	case "channel":
		return sameIdentity(only(retained, "channel"), only(identity, "channel"))
	}
	return sameIdentity(retained, identity)
}

func (rule RevisionRule) sameSensor(was, now Sensor) bool {
	switch rule.SensorMatch {
	case "whole":
		return was == now
	}
	if field, ok := strings.CutPrefix(rule.SensorMatch, "id_and:"); ok {
		return was.SensorID == now.SensorID && sensorField(was, field) == sensorField(now, field)
	}
	return was.SensorID == now.SensorID
}

func (rule RevisionRule) changes(zoneID string, was ZoneState, z parsedZone) map[string]bool {
	changed := map[string]bool{}
	if rule.ChangeIdentity {
		a, c := was.Identity, z.identity
		switch rule.IdentityCompare {
		case "ignore_board":
			a, c = without(a, "firmware_device_id"), without(c, "firmware_device_id")
		case "ignore_channel":
			a, c = without(a, "channel"), without(c, "channel")
		}
		if !sameIdentity(a, c) {
			changed["identity"] = true
		}
	}
	if rule.ChangeMapping && was.Mapping != z.mapping {
		changed["mapping"] = true
	}
	var differs bool
	switch rule.ChangeSensor {
	case "ignore:calibration_ref", "ignore:range", "ignore:range_min", "ignore:unit",
		"ignore:direction", "ignore:quantity":
		differs = blank(was.Sensor, rule.ChangeSensor) != blank(z.sensor, rule.ChangeSensor)
	case "sensor_id":
		differs = was.Sensor.SensorID != z.sensor.SensorID
	case "id_and_calibration":
		differs = was.Sensor.SensorID != z.sensor.SensorID ||
			was.Sensor.CalibrationRef != z.sensor.CalibrationRef
	default:
		differs = was.Sensor != z.sensor
	}
	if differs {
		changed["sensor"] = true
	}
	if rule.ProofChangeIsChange {
		legDiffers := z.controlMethod != "" &&
			(was.ControlProofAtMs == nil || z.controlPerformedAtMs != *was.ControlProofAtMs)
		if z.performedAtMs != was.ProofAtMs || legDiffers {
			changed["proof"] = true
		}
	}
	if rule.RenameIsChange && zoneID != z.zoneID {
		changed["name"] = true
	}
	return changed
}

func (rule RevisionRule) stale(z parsedZone, was ZoneState, changed map[string]bool, single bool, posture string) bool {
	unclaimed := z.method == MethodUnproven
	if rule.ClaimedMethods == "actuate_and_observe" {
		unclaimed = z.method != MethodActuate
	}
	hasLeg := z.controlMethod != ""
	controlFresh := z.controlMethod == ControlCommanded && was.ControlProofAtMs != nil &&
		z.controlPerformedAtMs > *was.ControlProofAtMs
	checkCircuit := !(rule.CircuitUnclaimedExempt && unclaimed)
	if rule.CircuitSkipIfControlUnclaimed && z.controlMethod == ControlUnproven {
		checkCircuit = false
	}
	circuitRetained := was.ProofAtMs
	if rule.exempt("circuit", z, was, posture) {
		checkCircuit = false
	}
	if rule.CircuitRetainedTime == "earlier" && was.ControlProofAtMs != nil {
		circuitRetained = min(was.ProofAtMs, *was.ControlProofAtMs)
	}
	if rule.SingleRetainedTime && was.ControlProofAtMs != nil {
		circuitRetained = max(was.ProofAtMs, *was.ControlProofAtMs)
	}
	if rule.CircuitSkipIfControlFresh && controlFresh {
		checkCircuit = false
	}
	if rule.CircuitOnlySingleMatch && !single {
		checkCircuit = false
	}
	if checkCircuit {
		if rule.CircuitStrict && z.performedAtMs < circuitRetained ||
			!rule.CircuitStrict && z.performedAtMs <= circuitRetained {
			return true
		}
	}
	if !hasLeg {
		return rule.ControlAbsentStale && !unclaimed && was.ControlProofAtMs != nil
	}
	if rule.ControlOnlySingleMatch && !single {
		return false
	}
	if rule.exempt("control", z, was, posture) {
		return false
	}
	if rule.ControlRequiresClaim && z.controlMethod != ControlCommanded {
		return false
	}
	if rule.ControlSkipIfCircuitUnclaimed && unclaimed {
		return false
	}
	if rule.ControlOn == "identity" && !changed["identity"] {
		return false
	}
	if rule.ControlOn == "identity_or_mapping" && !changed["identity"] && !changed["mapping"] {
		return false
	}
	var retained int64
	switch {
	case was.ControlProofAtMs != nil:
		retained = *was.ControlProofAtMs
		if rule.SingleRetainedTime || rule.ControlRetainedTime == "later" {
			retained = max(was.ProofAtMs, retained)
		}
	case rule.ControlMissing == "stale":
		return true
	case rule.ControlMissing == "circuit_time":
		retained = was.ProofAtMs
	default:
		return false
	}
	if rule.ControlStrict {
		return z.controlPerformedAtMs < retained
	}
	return z.controlPerformedAtMs <= retained
}

func only(m map[string]any, key string) map[string]any {
	out := map[string]any{}
	if v, ok := m[key]; ok {
		out[key] = v
	}
	return out
}

func without(m map[string]any, key string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k != key {
			out[k] = v
		}
	}
	return out
}

// blank clears the sensor fields an ignore: reading leaves out of the change test.
func blank(s Sensor, reading string) Sensor {
	switch reading {
	case "ignore:calibration_ref":
		s.CalibrationRef = ""
	case "ignore:range":
		s.RangeMin, s.RangeMax = 0, 0
	case "ignore:range_min":
		s.RangeMin = 0
	case "ignore:unit":
		s.Unit = ""
	case "ignore:direction":
		s.Direction = ""
	case "ignore:quantity":
		s.Quantity = ""
	}
	return s
}

func (rule RevisionRule) exempt(leg string, z parsedZone, was ZoneState, posture string) bool {
	fields := fieldChanges(z, was)
	if len(fields) == 1 {
		for field := range fields {
			if rule.Exempt[leg+":"+field] {
				return true
			}
		}
	}
	for _, set := range rule.ExemptSets {
		if set.Leg != leg || len(set.Fields) != len(fields) {
			continue
		}
		exact := true
		for _, field := range set.Fields {
			if !fields[field] {
				exact = false
			}
		}
		if exact {
			return true
		}
	}
	if k, ok := rule.ExemptAtLeast[leg]; ok && len(fields) >= k {
		return true
	}
	if rule.ExemptPostures[leg+":"+posture] {
		return true
	}
	if leg == "circuit" {
		_, wasGPIO := was.Identity["gpio_pin"]
		_, nowGPIO := z.identity["gpio_pin"]
		if wasGPIO && !nowGPIO && rule.ExemptKindChange["firmware"] {
			return true
		}
		if nowGPIO && !wasGPIO && rule.ExemptKindChange["GPIO"] {
			return true
		}
	}
	return leg == "control" && rule.ExemptControlBehindPreEnergisation && z.method == MethodPreEnergy
}

// fieldChanges names the individual fields a revision changed against one
// retained zone.
func fieldChanges(z parsedZone, was ZoneState) map[string]bool {
	fields := map[string]bool{}
	keys := map[string]bool{}
	for k := range was.Identity {
		keys[k] = true
	}
	for k := range z.identity {
		keys[k] = true
	}
	for k := range keys {
		a, inA := was.Identity[k]
		b, inB := z.identity[k]
		if inA != inB || !sameIdentity(map[string]any{k: a}, map[string]any{k: b}) {
			fields[k] = true
		}
	}
	if was.Mapping != z.mapping {
		fields["mapping"] = true
	}
	a, b := was.Sensor, z.sensor
	for name, differs := range map[string]bool{
		"sensor_id": a.SensorID != b.SensorID, "quantity": a.Quantity != b.Quantity,
		"unit": a.Unit != b.Unit, "range_min": a.RangeMin != b.RangeMin,
		"range_max": a.RangeMax != b.RangeMax, "direction": a.Direction != b.Direction,
		"noise_floor": a.NoiseFloor != b.NoiseFloor, "calibration_ref": a.CalibrationRef != b.CalibrationRef,
	} {
		if differs {
			fields[name] = true
		}
	}
	return fields
}

// sensorField is one sensor field by its contract name, for id_and: readings.
func sensorField(s Sensor, name string) any {
	switch name {
	case "quantity":
		return s.Quantity
	case "unit":
		return s.Unit
	case "range_min":
		return s.RangeMin
	case "range_max":
		return s.RangeMax
	case "direction":
		return s.Direction
	case "noise_floor":
		return s.NoiseFloor
	case "calibration_ref":
		return s.CalibrationRef
	}
	panic("unknown sensor field " + name)
}
