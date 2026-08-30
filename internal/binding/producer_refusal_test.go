// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ori-platform/ori-cli/internal/binding"
)

// A signature proves authorship, not correctness. These tests hold the
// producer to refusing, before it signs, every document the contract says a
// consumer must refuse on the document's own evidence.

func corpusKey(t *testing.T, c corpusFileShape) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(c.CommissioningSeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("corpus commissioning seed is unusable: %v", err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// documentOnly picks the reject cases whose verdict depends on nothing but
// the document: no anchors, no accepted binding, no inventory, no posture.
// Those are exactly the refusals a producer can and must make itself.
func documentOnly(c fullCorpus) []rejectCase {
	var out []rejectCase
	for _, rc := range c.RejectCases {
		switch rc.Stage {
		case binding.StageMappingSelfConsistency, binding.StageDisambiguation:
			out = append(out, rc)
		case binding.StageProofConsistency:
			// stale_proof compares against the retained prior document.
			if rc.Reason == binding.ReasonProofContradiction {
				out = append(out, rc)
			}
		case binding.StageBounds:
			// The trip-point bound needs the release-owned multiplier, which
			// the producer does not author.
			if rc.Name != "trip_point_above_sensor_full_scale" {
				out = append(out, rc)
			}
		}
	}
	return out
}

// TestSignRefusesWhatAConsumerWouldRefuse lifts each document-only reject
// vector into typed values and requires Sign to refuse it with the stage and
// reason the corpus declares. The transposed binding, the idle-load proof, the
// reversed driver stage and the capacity above full scale are all here.
func TestSignRefusesWhatAConsumerWouldRefuse(t *testing.T) {
	c := loadCorpus(t)
	key := corpusKey(t, c)
	cases := documentOnly(loadFullCorpus(t))
	if len(cases) < 8 {
		t.Fatalf("expected the corpus to carry document-only reject cases, found %d", len(cases))
	}
	for _, rc := range cases {
		t.Run(rc.Name, func(t *testing.T) {
			_, err := typedFrom(t, rc.Binding).Sign(key)
			var refusal *binding.Refusal
			if !errors.As(err, &refusal) {
				t.Fatalf("Sign returned %v; want a refusal at %s (%s)", err, rc.Stage, rc.Reason)
			}
			if refusal.Stage != rc.Stage || refusal.Reason != rc.Reason {
				t.Fatalf("refused at %s (%s); corpus declares %s (%s)",
					refusal.Stage, refusal.Reason, rc.Stage, rc.Reason)
			}
		})
	}
}

// TestTransposedBindingRefused names the case the issue names: the clamp on
// one circuit and the contactor on another. The proof's readings do not move
// when the contactor opens, and the producer must not sign it.
func TestTransposedBindingRefused(t *testing.T) {
	c := loadCorpus(t)
	key := corpusKey(t, c)
	full := loadFullCorpus(t)
	var transposed *rejectCase
	for i := range full.RejectCases {
		if full.RejectCases[i].Name == "transposed_binding" {
			transposed = &full.RejectCases[i]
		}
	}
	if transposed == nil {
		t.Fatal("corpus no longer carries transposed_binding")
	}
	_, err := typedFrom(t, transposed.Binding).Sign(key)
	var refusal *binding.Refusal
	if !errors.As(err, &refusal) || refusal.Reason != binding.ReasonProofContradiction {
		t.Fatalf("a transposed binding was signed (err=%v)", err)
	}
}

// TestCapacityOutOfRangeRefused: a capacity the sensor cannot observe is
// refused where a human can still see the wiring.
func TestCapacityOutOfRangeRefused(t *testing.T) {
	c := loadCorpus(t)
	key := corpusKey(t, c)
	doc := typedFrom(t, c.Cases[0].Binding)
	doc.Zones[0].RatedCapacity.Value = doc.Zones[0].Sensor.RangeMax + 1
	_, err := doc.Sign(key)
	var refusal *binding.Refusal
	if !errors.As(err, &refusal) || refusal.Stage != binding.StageBounds {
		t.Fatalf("capacity above full scale was signed (err=%v)", err)
	}
	doc.Zones[0].RatedCapacity.Value = 0
	_, err = doc.Sign(key)
	if !errors.As(err, &refusal) || refusal.Stage != binding.StageBounds {
		t.Fatalf("zero capacity was signed (err=%v)", err)
	}
}

// TestPolarityExplicit: a local GPIO actuator with no active_high is not a
// document. Nothing infers the driver stage's polarity.
func TestPolarityExplicit(t *testing.T) {
	c := loadCorpus(t)
	key := corpusKey(t, c)
	doc := typedFrom(t, c.Cases[0].Binding)
	if doc.Zones[0].Actuator.Kind != binding.KindLocalGPIO {
		t.Fatal("first zone of the first case is no longer local_gpio")
	}
	doc.Zones[0].Actuator.Identity.ActiveHigh = nil
	if _, err := doc.Sign(key); err == nil {
		t.Fatal("a local_gpio zone with no active_high was signed")
	}
}

// TestUndemonstratedRecordedHonestly: an unproven zone carries a reason and no
// observations; a zone claiming a proof method carries observations. Neither
// half may be dropped to make the other pass.
func TestUndemonstratedRecordedHonestly(t *testing.T) {
	c := loadCorpus(t)
	key := corpusKey(t, c)

	claimed := typedFrom(t, c.Cases[0].Binding)
	claimed.Zones[0].Proof.Method = binding.MethodUnproven
	claimed.Zones[0].Proof.Reason = "no load available"
	if _, err := claimed.Sign(key); err == nil {
		t.Fatal("an undemonstrated zone carrying observations was signed")
	}

	silent := typedFrom(t, c.Cases[0].Binding)
	silent.Zones[0].Proof.Method = binding.MethodUnproven
	silent.Zones[0].Proof.Observations = nil
	if _, err := silent.Sign(key); err == nil {
		t.Fatal("an undemonstrated zone with no reason was signed")
	}

	unproven := typedFrom(t, c.Cases[0].Binding)
	unproven.Zones[0].Proof.Observations = nil
	_, err := unproven.Sign(key)
	var refusal *binding.Refusal
	if !errors.As(err, &refusal) || refusal.Reason != binding.ReasonMalformed {
		t.Fatalf("a proof method with no observations was signed (err=%v)", err)
	}
}

// TestInventoryGenerationRequired: a binding to no inventory is a binding to
// absence, and the floor is one.
func TestInventoryGenerationRequired(t *testing.T) {
	c := loadCorpus(t)
	key := corpusKey(t, c)
	doc := typedFrom(t, c.Cases[0].Binding)
	doc.InventoryGeneration = 0
	if _, err := doc.Sign(key); err == nil {
		t.Fatal("inventory_generation 0 was signed")
	}
}
