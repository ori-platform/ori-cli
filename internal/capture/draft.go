// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"encoding/json"

	"github.com/ori-platform/ori-cli/internal/binding"
)

// DraftJSON renders a captured zone in the contract's own field names.
//
// The struct is not marshalled directly. Its Go field names are not the wire
// names, and its zero values would put empty authority fields into the
// document — a `signing_key` of `""` reads as a document with a key rather than
// one that has not been signed. What signing owns is absent here instead:
// `issued_at_ms`, `signer_id`, `actor` and the signature. What capture owns is
// present: the generation it was told, and the hash of the binding it
// supersedes, which the runtime returned alongside the candidates.
//
// A draft is a set of captured facts, not an incomplete document pretending to
// be a complete one.
func DraftJSON(b binding.Binding) ([]byte, error) {
	zones := make([]map[string]any, 0, len(b.Zones))
	for _, z := range b.Zones {
		identity := map[string]any{}
		if z.Actuator.Identity.GPIOPin != nil {
			identity["gpio_pin"] = *z.Actuator.Identity.GPIOPin
		}
		if z.Actuator.Identity.ActiveHigh != nil {
			identity["active_high"] = *z.Actuator.Identity.ActiveHigh
		}
		proof := map[string]any{"method": z.Proof.Method}
		if z.Proof.Reason != "" {
			proof["reason"] = z.Proof.Reason
		}
		if z.Proof.Method != binding.MethodUnproven {
			// Closed per method: an undemonstrated proof carries neither, and
			// carrying them would claim a proof it says it does not have.
			proof["performed_at_ms"] = z.Proof.PerformedAtMs
			observations := make([]map[string]any, 0, len(z.Proof.Observations))
			for _, o := range z.Proof.Observations {
				observations = append(observations, map[string]any{
					"commanded":               o.Commanded,
					"coil_state":              o.CoilState,
					"terminal_state_observed": o.TerminalStateObserved,
					"load_present_before":     o.LoadPresentBefore,
					"load_present_after":      o.LoadPresentAfter,
				})
			}
			proof["observations"] = observations
		}
		zones = append(zones, map[string]any{
			"zone_id": z.ZoneID,
			"rated_capacity": map[string]any{
				"parameter":  z.RatedCapacity.Parameter,
				"value":      z.RatedCapacity.Value,
				"provenance": z.RatedCapacity.Provenance,
			},
			"sensor": map[string]any{
				"sensor_id":       z.Sensor.SensorID,
				"quantity":        z.Sensor.Quantity,
				"unit":            z.Sensor.Unit,
				"range_min":       z.Sensor.RangeMin,
				"range_max":       z.Sensor.RangeMax,
				"direction":       z.Sensor.Direction,
				"noise_floor":     z.Sensor.NoiseFloor,
				"calibration_ref": z.Sensor.CalibrationRef,
			},
			"actuator": map[string]any{
				"kind":     z.Actuator.Kind,
				"identity": identity,
				"commissioned_mapping": map[string]any{
					"open_protected_circuit":      z.Actuator.Mapping.OpenProtectedCircuit,
					"close_protected_circuit":     z.Actuator.Mapping.CloseProtectedCircuit,
					"de_energised_terminal_state": z.Actuator.Mapping.DeEnergisedTerminalState,
				},
			},
			"proof": proof,
		})
	}
	body := map[string]any{
		"v":                    b.V,
		"binding_seq":          b.BindingSeq,
		"device_id":            b.DeviceID,
		"inventory_generation": b.InventoryGeneration,
		"zones":                zones,
	}
	// Absent on a first binding, and absence is what says so.
	if b.Supersedes != nil {
		body["supersedes"] = *b.Supersedes
	}
	return json.MarshalIndent(body, "", "  ")
}
