// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding

import "crypto/ed25519"

// RetainedState is the per-zone record the revision rule reads, taken from the
// accepted binding in force exactly as a consumer retains it.
func RetainedState(a *Accepted) map[string]ZoneState {
	out := make(map[string]ZoneState, len(a.Zones))
	for i, z := range a.Zones {
		out[z.ZoneID] = ZoneState{
			Seq:              i,
			Identity:         z.Identity,
			Mapping:          z.Mapping,
			Sensor:           z.Sensor,
			ProofAtMs:        z.ProofPerformedAtMs,
			ControlProofAtMs: z.ControlProofPerformedAtMs,
		}
	}
	return out
}

// CheckRevision runs, over an unsigned revision draft, every stage a consumer
// decides from the document, the zone state it retained, and its declared
// inventory and posture: everything except the signature and its authority.
//
// A draft carries none of the fields signing owns, and no stage run here reads
// them, so stand-ins are supplied only to make the bytes parse. The revision
// rule is the verifier's own, so what is refused here is what a runtime would
// refuse as stale_proof.
func (b Binding) CheckRevision(prior map[string]ZoneState, ctx Context) error {
	standIn := b
	standIn.IssuedAtMs = 1
	standIn.SignerID, standIn.Actor, standIn.Reason = "draft", "draft", "draft"
	standIn.SigningKey = SigningKeyName(make(ed25519.PublicKey, ed25519.PublicKeySize))
	preimage, err := standIn.Preimage()
	if err != nil {
		return err
	}
	value, r := decodeWire(preimage)
	if r != nil {
		return r
	}
	body, ok := value.(map[string]any)
	if !ok {
		return malformed()
	}
	parsed, r := stParses(body)
	if r != nil {
		return r
	}
	for _, stage := range []func() *Refusal{
		func() *Refusal { return stMappingSelfConsistency(parsed) },
		func() *Refusal { return stProofConsistency(parsed, prior) },
		func() *Refusal { return stBounds(parsed, ctx.ProfileMultiplier) },
		func() *Refusal { return stDisambiguation(parsed) },
		func() *Refusal { return stInventory(parsed, ctx) },
		func() *Refusal { return stActivationPosture(parsed, ctx.DeploymentPosture) },
	} {
		if r := stage(); r != nil {
			return r
		}
	}
	return nil
}

// IsDigest reports whether s is a canonical hash as the contract spells one.
func IsDigest(s string) bool { return digestPattern.MatchString(s) }
