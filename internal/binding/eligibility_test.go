// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ori-platform/ori-cli/internal/binding"
)

// InForceEligible decides whether a coil may be commanded, and it is reachable
// with values the grammar cannot produce: AcceptedZone is exported, and a
// caller reconstructing one from a stored row can present an empty or
// unrecognised method. The corpus cannot exercise that, because every document
// in it carries valid vocabulary — so each clause is asserted directly, and
// each is an allow-list rather than a test for one known-bad value.
func TestZoneEligibilityIsAnAllowList(t *testing.T) {
	proven := binding.AcceptedZone{
		Kind:               binding.KindLocalGPIO,
		ProofMethod:        binding.MethodActuate,
		ControlProofMethod: binding.ControlCommanded,
	}
	if !proven.InForceEligible() {
		t.Fatal("a zone with both legs proven is not eligible")
	}
	preEnergised := proven
	preEnergised.ProofMethod = binding.MethodPreEnergy
	if !preEnergised.InForceEligible() {
		t.Fatal("pre_energisation is a proven circuit leg")
	}

	for _, tc := range []struct {
		name string
		zone binding.AcceptedZone
	}{
		{"circuit method empty", withCircuit(proven, "")},
		{"circuit method truncated", withCircuit(proven, "actuate")},
		{"circuit method miscased", withCircuit(proven, "ACTUATE_AND_OBSERVE")},
		{"circuit method undemonstrated", withCircuit(proven, binding.MethodUnproven)},
		{"circuit method is a control method", withCircuit(proven, binding.ControlCommanded)},
		{"control method empty", withControl(proven, "")},
		{"control method undemonstrated", withControl(proven, binding.ControlUnproven)},
		{"control method miscased", withControl(proven, "COMMANDED_AND_OBSERVED")},
		{"control method is a circuit method", withControl(proven, binding.MethodActuate)},
		{"kind empty", withKind(proven, "")},
		{"kind firmware", withKind(proven, binding.KindFirmware)},
		{"kind unrecognised", withKind(proven, "local-gpio")},
	} {
		if tc.zone.InForceEligible() {
			t.Errorf("%s: eligible, so a coil could be commanded on it", tc.name)
		}
	}
}

// One zone short leaves the whole document provisional, and a document with no
// zones authorises nothing.
func TestDocumentEligibilityNeedsEveryZone(t *testing.T) {
	proven := binding.AcceptedZone{
		Kind:               binding.KindLocalGPIO,
		ProofMethod:        binding.MethodActuate,
		ControlProofMethod: binding.ControlCommanded,
	}
	if (binding.Accepted{Zones: []binding.AcceptedZone{proven}}).InForceEligible() != true {
		t.Fatal("a single proven zone should be in force")
	}
	short := binding.Accepted{Zones: []binding.AcceptedZone{
		proven, withControl(proven, binding.ControlUnproven),
	}}
	if short.InForceEligible() {
		t.Error("one zone short must leave the whole document provisional")
	}
	if (binding.Accepted{}).InForceEligible() {
		t.Error("a document with no zones must not be in force")
	}
}

func withCircuit(z binding.AcceptedZone, m string) binding.AcceptedZone {
	z.ProofMethod = m
	return z
}

func withControl(z binding.AcceptedZone, m string) binding.AcceptedZone {
	z.ControlProofMethod = m
	return z
}

func withKind(z binding.AcceptedZone, k string) binding.AcceptedZone {
	z.Kind = k
	return z
}

// Both outcomes must be commanded and observed, and each leg must satisfy that
// on its own. The corpus carries no one-sided proof, so a tally shared between
// the legs — letting one complete the other's — would otherwise go unnoticed.
func TestEachLegNeedsBothOutcomesOnItsOwn(t *testing.T) {
	c := loadFullCorpus(t)
	var proven rejectCase
	for _, vc := range c.Cases {
		if vc.Name == "local_gpio_control_path_proven_is_in_force" {
			proven = vc
		}
	}
	if proven.Name == "" {
		t.Fatal("the single-zone both-legs-proven case is gone from the corpus")
	}

	for _, leg := range []string{"proof", "control_path"} {
		t.Run("one_sided_"+leg, func(t *testing.T) {
			// UseNumber, because a plain decode turns every integer into a
			// float64 and re-encoding then breaks the contract's number
			// spelling rule — the document would be refused at `parses`
			// before the rule under test is ever reached.
			dec := json.NewDecoder(bytes.NewReader(proven.Binding))
			dec.UseNumber()
			var doc map[string]any
			if err := dec.Decode(&doc); err != nil {
				t.Fatalf("decode: %v", err)
			}
			zone := doc["zones"].([]any)[0].(map[string]any)
			target := zone["proof"].(map[string]any)
			if leg == "control_path" {
				target = target["control_path"].(map[string]any)
			}
			target["observations"] = target["observations"].([]any)[:1]

			body, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			env := resignedAsCorpus(t, c, envelopeBytes("binding", body, ""))
			_, verr := binding.VerifyEnvelope(env, bindingContext(t, proven.VerifierContext))
			r := refusalOf(t, verr)
			if r.Stage != binding.StageProofConsistency ||
				r.Reason != binding.ReasonProofContradiction {
				t.Fatalf("refused at %s (%s); want proof_consistency (proof_contradiction)",
					r.Stage, r.Reason)
			}
		})
	}
}
