// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"fmt"
	"math/rand"
	"testing"
)

// TestTheReferenceIsTheProductionRuleBeyondTheCorpus compares the harness's
// reference reading with the production revision rule on seeded random
// revisions. Agreement on the corpus alone would let the reference drift from
// the verifier wherever the corpus is silent, and the misreadings would then be
// measured against the wrong rule. Only the revision rule is compared: the
// observation checks are not part of either side here.
func TestTheReferenceIsTheProductionRuleBeyondTheCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(20260923))
	pins := []int{19, 21, 26}
	sensors := []string{"s-a", "s-b", "s-c"}
	pick := func(choices ...string) string { return choices[rng.Intn(len(choices))] }
	at := func(choices ...int64) int64 { return choices[rng.Intn(len(choices))] }
	// GPIO and firmware identities, every proof method, and several sensor
	// fields, so the reference cannot drift from the verifier where the corpus
	// is silent.
	identity := func(index int) map[string]any {
		if rng.Float64() < 0.25 {
			return map[string]any{"firmware_device_id": pick("fw-1", "fw-2"), "channel": pick("r0", "r1")}
		}
		return map[string]any{"gpio_pin": pins[index], "active_high": rng.Intn(2) == 0}
	}
	sensor := func(id string) Sensor {
		return Sensor{
			SensorID:       id,
			NoiseFloor:     []float64{0.05, 0.07}[rng.Intn(2)],
			RangeMin:       []float64{0, 1}[rng.Intn(2)],
			Unit:           pick("ampere", "amp"),
			CalibrationRef: pick("c1", "c2"),
		}
	}
	mapping := func() Mapping { return Mapping{OpenProtectedCircuit: pick(CoilEnergised, CoilDeEnergised)} }
	for i := 0; i < 20000; i++ {
		prior := map[string]ZoneState{}
		for index := 0; index < 1+rng.Intn(3); index++ {
			state := ZoneState{
				Identity:  identity(index),
				Mapping:   mapping(),
				Sensor:    sensor(sensors[index]),
				ProofAtMs: at(0, 300, 600),
				Seq:       index,
			}
			if control := rng.Intn(4); control > 0 {
				v := []int64{0, 300, 600}[control-1]
				state.ControlProofAtMs = &v
			}
			prior[fmt.Sprintf("z%d", index)] = state
		}
		b := &parsedBinding{}
		for index := 0; index < 1+rng.Intn(2); index++ {
			z := parsedZone{
				zoneID:        pick("z0", "z1", "z2", fmt.Sprintf("new%d", index)),
				identity:      identity(rng.Intn(3)),
				mapping:       mapping(),
				sensor:        sensor(sensors[rng.Intn(3)]),
				method:        pick(MethodActuate, MethodPreEnergy, MethodUnproven),
				performedAtMs: at(0, 300, 600, 900),
			}
			if rng.Float64() < 0.7 {
				z.controlMethod = pick(ControlCommanded, ControlUnproven)
				z.controlPerformedAtMs = at(0, 300, 600, 900)
			}
			b.zones = append(b.zones, z)
		}
		// Posture varies so a reference that read it would diverge: the rule
		// ignores posture.
		posture := pick("production", "staging", "development")
		production, reference := stRevisionRule(b, prior), ReferenceRule.check(b, prior, posture)
		if (production == nil) != (reference == nil) {
			t.Fatalf("case %d (%s): production %v, reference %v\nzones %+v\nretained %+v",
				i, posture, production, reference, b.zones, prior)
		}
	}
}
