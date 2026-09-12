// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ori-platform/ori-cli/internal/binding"
)

func TestDecodeDocumentReportsWhatSigningOwns(t *testing.T) {
	c := loadCorpus(t)
	full, supplied, err := binding.DecodeDocument(c.Cases[0].Binding)
	if err != nil {
		t.Fatal(err)
	}
	if supplied != (binding.Supplied{IssuedAtMs: true, SignerID: true, SigningKey: true, Actor: true, Reason: true}) {
		t.Fatalf("a published binding reported %+v", supplied)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(c.Cases[0].Binding, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"issued_at_ms", "signer_id", "signing_key", "actor", "reason"} {
		delete(fields, name)
	}
	draftRaw, _ := json.Marshal(fields)
	draft, supplied, err := binding.DecodeDocument(draftRaw)
	if err != nil {
		t.Fatal(err)
	}
	if supplied != (binding.Supplied{}) {
		t.Fatalf("a draft reported %+v", supplied)
	}
	if draft.IssuedAtMs != 0 || draft.SignerID != "" || draft.SigningKey != "" || draft.Actor != "" || draft.Reason != "" {
		t.Fatal("absent fields were given values")
	}
	if draft.DeviceID != full.DeviceID || len(draft.Zones) != len(full.Zones) {
		t.Fatal("the draft lost what it did carry")
	}
}

func TestDecodeDocumentRefusesWhatTheVerifierRefuses(t *testing.T) {
	c := loadCorpus(t)
	published := c.Cases[0].Binding
	cases := []struct {
		name string
		raw  []byte
		says string
	}{
		{"null owned field", bytes.Replace(published, []byte(`"actor":`), []byte(`"actor":null,"x_actor":`), 1), "actor is null"},
		{"duplicate key", bytes.Replace(published, []byte(`{`), []byte(`{"v":1,`), 1), "repeats a key"},
		{"unknown field", bytes.Replace(published, []byte(`{`), []byte(`{"extra":1,`), 1), "extra"},
		{"trailing bytes", append(append([]byte{}, published...), '1'), "after its closing brace"},
		{"array", []byte(`[1]`), "not readable"},
		{"null", []byte(`null`), "not a JSON object"},
		{"invalid utf-8", []byte("{\"device_id\":\"\xff\"}"), "not valid JSON text"},
		{"float binding_seq", bytes.Replace(published, []byte(`"binding_seq": 1`), []byte(`"binding_seq": 1.0`), 1), "binding_seq"},
		{"string gpio_pin", bytes.Replace(published, []byte(`"gpio_pin": 26`), []byte(`"gpio_pin": "26"`), 1), "gpio_pin"},
		{"absent noise_floor", bytes.Replace(published, []byte(`"noise_floor"`), []byte(`"noise_floor_x"`), 1), "zones[0].sensor.noise_floor is absent"},
		{"absent mapping member", bytes.Replace(published, []byte(`"de_energised_terminal_state"`), []byte(`"de_energised_terminal_state_x"`), 1), "commissioned_mapping.de_energised_terminal_state is absent"},
		{"absent load_present_after", bytes.Replace(published, []byte(`"load_present_after"`), []byte(`"load_present_after_x"`), 1), "observations[0].load_present_after is absent"},
		{"absent gpio identity member", bytes.Replace(published, []byte(`"active_high"`), []byte(`"active_high_x"`), 1), "identity.active_high is absent"},
		{"absent zones", bytes.Replace(published, []byte(`"zones":`), []byte(`"zoned":`), 1), "zones"},
		{"null range_min", bytes.Replace(published, []byte(`"range_min": 0.0`), []byte(`"range_min": null`), 1), "sensor.range_min is null"},
		{"null observations", bytes.Replace(published, []byte(`"observations": [`), []byte(`"observations": null, "observations_x": [`), 1), "proof.observations is null"},
		{"null zones", bytes.Replace(published, []byte(`"zones": [`), []byte(`"zones": null, "zoned": [`), 1), "zones is not an array"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if bytes.Equal(tc.raw, published) {
				t.Fatal("the mutation did not land in the input")
			}
			_, _, err := binding.DecodeDocument(tc.raw)
			if err == nil {
				t.Fatal("decoded")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("error %q does not say %q", err, tc.says)
			}
		})
	}
}

func TestDecodeControlPathRoundTripsWhatExportWrites(t *testing.T) {
	c := loadCorpus(t)
	doc, _, err := binding.DecodeDocument(c.Cases[1].Binding)
	if err != nil {
		t.Fatal(err)
	}
	leg := doc.Zones[0].Proof.ControlPath
	if leg == nil {
		t.Fatal("the case carries no control leg")
	}
	encoded, err := binding.ControlPathJSON(*leg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := binding.DecodeControlPath(encoded)
	if err != nil {
		t.Fatal(err)
	}
	doc.Zones[0].Proof.ControlPath = &decoded
	got, err := doc.Preimage()
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(c.Cases[1].CanonicalHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("a leg through export's encoding and back changed the signed bytes")
	}
	if _, err := binding.DecodeControlPath([]byte(`{"method":"undemonstrated","reason":"x","unknown":true}`)); err == nil {
		t.Fatal("an unknown leg field decoded")
	}
}

func TestVerifyOfflineDrawsTheDeliveryBoundary(t *testing.T) {
	c := loadCorpus(t)
	for _, vc := range c.Cases {
		envelope := envelopeBytes("binding", vc.Binding, vc.SignatureB64)
		if _, err := binding.VerifyOffline(envelope); err != nil {
			t.Fatalf("%s: refused offline: %v", vc.Name, err)
		}
	}
	offline := map[string]bool{}
	for _, s := range binding.OfflineStages {
		offline[s] = true
	}
	var seenOffline, seenDelivery int
	for _, rc := range loadFullCorpus(t).RejectCases {
		if rc.SignatureValid == nil || (!*rc.SignatureValid && rc.Stage != binding.StageSignature) {
			continue
		}
		envelope := envelopeBytes("binding", rc.Binding, rc.SignatureB64)
		_, err := binding.VerifyOffline(envelope)
		if offline[rc.Stage] {
			// Two refusals inside an offline stage need what only the runtime
			// holds: the trip point is capacity times the profile multiplier,
			// and a stale proof is stale against the zone state it retained.
			// Both are delivery's; a capacity outside the sensor's own range
			// and a proof contradicting its own mapping are not.
			needsRuntimeState := rc.Reason == binding.ReasonStaleProof ||
				rc.Name == "trip_point_above_sensor_full_scale"
			if err == nil && needsRuntimeState {
				seenDelivery++
				continue
			}
			seenOffline++
			if err == nil || err.Error() != rc.Stage+": "+rc.Reason {
				t.Fatalf("%s: offline verdict %v, corpus says %s: %s", rc.Name, err, rc.Stage, rc.Reason)
			}
			continue
		}
		seenDelivery++
		if err != nil {
			t.Fatalf("%s: a %s refusal is the runtime's to make, but offline refused: %v", rc.Name, rc.Stage, err)
		}
	}
	if seenOffline == 0 || seenDelivery == 0 {
		t.Fatalf("the corpus exercised %d offline and %d delivery refusals", seenOffline, seenDelivery)
	}
}
