// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ori-platform/ori-cli/internal/binding"
)

// This is the producer's conformance proof, and it is deliberately not a test
// of the canonical JSON library.
//
// The library proves it can re-serialise a decoded document. That says nothing
// about whether *this* producer builds the right document: decoding into typed
// Go values discards how each number was spelled, so re-emitting requires the
// schema to decide, per field, whether a value is an integer or not. Get one
// wrong and the document still parses, still carries the right values, and its
// signature verifies nowhere.
//
// So every case here is rebuilt from typed values through the production path
// and required to match the published bytes.

const (
	corpusDir  = "testdata/vectors/commissioned_safety_binding"
	corpusFile = "binding-vectors-v1.json"
)

type wireCase struct {
	Name            string          `json:"name"`
	Binding         json.RawMessage `json:"binding"`
	CanonicalHex    string          `json:"canonical_hex"`
	CanonicalSHA256 string          `json:"canonical_sha256"`
	SignatureB64    string          `json:"signature_b64"`
	MessageHex      string          `json:"message_hex"`
}

type corpusFileShape struct {
	CommissioningSeedHex      string     `json:"commissioning_test_seed_hex"`
	CommissioningPublicKeyHex string     `json:"commissioning_public_key_hex"`
	Cases                     []wireCase `json:"cases"`
}

func loadCorpus(t *testing.T) corpusFileShape {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusDir, corpusFile))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c corpusFileShape
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(c.Cases) == 0 {
		t.Fatal("corpus carries no accept cases")
	}
	return c
}

// wire mirrors the published JSON so a case can be lifted into the typed
// document. It exists only in the test: the producer's own input is typed Go
// values, and this is how a published document becomes some.
type wire struct {
	V                   int     `json:"v"`
	BindingSeq          int64   `json:"binding_seq"`
	DeviceID            string  `json:"device_id"`
	IssuedAtMs          int64   `json:"issued_at_ms"`
	SignerID            string  `json:"signer_id"`
	SigningKey          string  `json:"signing_key"`
	InventoryGeneration int64   `json:"inventory_generation"`
	Supersedes          *string `json:"supersedes"`
	Actor               string  `json:"actor"`
	Reason              string  `json:"reason"`
	Zones               []struct {
		ZoneID        string `json:"zone_id"`
		RatedCapacity struct {
			Parameter  string  `json:"parameter"`
			Value      float64 `json:"value"`
			Provenance string  `json:"provenance"`
		} `json:"rated_capacity"`
		Sensor struct {
			SensorID       string  `json:"sensor_id"`
			Quantity       string  `json:"quantity"`
			Unit           string  `json:"unit"`
			RangeMin       float64 `json:"range_min"`
			RangeMax       float64 `json:"range_max"`
			Direction      string  `json:"direction"`
			NoiseFloor     float64 `json:"noise_floor"`
			CalibrationRef string  `json:"calibration_ref"`
		} `json:"sensor"`
		Actuator struct {
			Kind     string `json:"kind"`
			Identity struct {
				GPIOPin          *int   `json:"gpio_pin"`
				ActiveHigh       *bool  `json:"active_high"`
				FirmwareDeviceID string `json:"firmware_device_id"`
				Channel          string `json:"channel"`
			} `json:"identity"`
			Mapping struct {
				Open     string `json:"open_protected_circuit"`
				Close    string `json:"close_protected_circuit"`
				Terminal string `json:"de_energised_terminal_state"`
			} `json:"commissioned_mapping"`
		} `json:"actuator"`
		Proof struct {
			Method        string `json:"method"`
			PerformedAtMs int64  `json:"performed_at_ms"`
			Reason        string `json:"reason"`
			Observations  []struct {
				Commanded    string   `json:"commanded"`
				CoilState    string   `json:"coil_state"`
				Terminal     string   `json:"terminal_state_observed"`
				LoadBefore   bool     `json:"load_present_before"`
				LoadAfter    bool     `json:"load_present_after"`
				GPIOLevel    string   `json:"gpio_level"`
				SensorBefore *float64 `json:"sensor_before"`
				SensorAfter  *float64 `json:"sensor_after"`
				Instrument   string   `json:"instrument"`
			} `json:"observations"`
		} `json:"proof"`
	} `json:"zones"`
}

func typedFrom(t *testing.T, raw json.RawMessage) binding.Binding {
	t.Helper()
	var w wire
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatalf("lift case into typed values: %v", err)
	}
	doc := binding.Binding{
		V: w.V, BindingSeq: w.BindingSeq, DeviceID: w.DeviceID,
		IssuedAtMs: w.IssuedAtMs, SignerID: w.SignerID, SigningKey: w.SigningKey,
		InventoryGeneration: w.InventoryGeneration,
		Supersedes:          w.Supersedes, Actor: w.Actor, Reason: w.Reason,
	}
	for _, z := range w.Zones {
		zone := binding.Zone{
			ZoneID: z.ZoneID,
			RatedCapacity: binding.RatedCapacity{
				Parameter: z.RatedCapacity.Parameter, Value: z.RatedCapacity.Value,
				Provenance: z.RatedCapacity.Provenance,
			},
			Sensor: binding.Sensor{
				SensorID: z.Sensor.SensorID, Quantity: z.Sensor.Quantity,
				Unit: z.Sensor.Unit, RangeMin: z.Sensor.RangeMin,
				RangeMax: z.Sensor.RangeMax, Direction: z.Sensor.Direction,
				NoiseFloor: z.Sensor.NoiseFloor, CalibrationRef: z.Sensor.CalibrationRef,
			},
			Actuator: binding.Actuator{
				Kind: z.Actuator.Kind,
				Identity: binding.Identity{
					GPIOPin: z.Actuator.Identity.GPIOPin, ActiveHigh: z.Actuator.Identity.ActiveHigh,
					FirmwareDeviceID: z.Actuator.Identity.FirmwareDeviceID,
					Channel:          z.Actuator.Identity.Channel,
				},
				Mapping: binding.Mapping{
					OpenProtectedCircuit:     z.Actuator.Mapping.Open,
					CloseProtectedCircuit:    z.Actuator.Mapping.Close,
					DeEnergisedTerminalState: z.Actuator.Mapping.Terminal,
				},
			},
			Proof: binding.Proof{
				Method: z.Proof.Method, PerformedAtMs: z.Proof.PerformedAtMs,
				Reason: z.Proof.Reason,
			},
		}
		for _, o := range z.Proof.Observations {
			zone.Proof.Observations = append(zone.Proof.Observations, binding.Observation{
				Commanded: o.Commanded, CoilState: o.CoilState,
				TerminalStateObserved: o.Terminal,
				LoadPresentBefore:     o.LoadBefore, LoadPresentAfter: o.LoadAfter,
				GPIOLevel: o.GPIOLevel, SensorBefore: o.SensorBefore,
				SensorAfter: o.SensorAfter, Instrument: o.Instrument,
			})
		}
		doc.Zones = append(doc.Zones, zone)
	}
	return doc
}

// TestProducerRebuildsEveryPublishedBinding is the conformance claim. Each
// document is reduced to typed Go values -- losing every spelling decision --
// and rebuilt through the production path, which must restore the published
// bytes exactly.
func TestProducerRebuildsEveryPublishedBinding(t *testing.T) {
	c := loadCorpus(t)
	for _, vc := range c.Cases {
		t.Run(vc.Name, func(t *testing.T) {
			got, err := typedFrom(t, vc.Binding).Preimage()
			if err != nil {
				t.Fatalf("build preimage: %v", err)
			}
			if hex.EncodeToString(got) != vc.CanonicalHex {
				want, _ := hex.DecodeString(vc.CanonicalHex)
				t.Fatalf("producer bytes differ from the contract\n got: %s\nwant: %s", got, want)
			}
			sum := sha256.Sum256(got)
			if "sha256:"+hex.EncodeToString(sum[:]) != vc.CanonicalSHA256 {
				t.Fatalf("digest differs: %x", sum)
			}
		})
	}
}

// TestProducerSignaturesMatchThePublishedOnes closes the loop. Ed25519 is
// deterministic, so signing the rebuilt preimage with the corpus key must
// yield the published signature byte-for-byte -- not merely a signature that
// happens to verify.
func TestProducerSignaturesMatchThePublishedOnes(t *testing.T) {
	c := loadCorpus(t)
	seed, err := hex.DecodeString(c.CommissioningSeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("corpus commissioning seed is unusable: %v", err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	for _, vc := range c.Cases {
		t.Run(vc.Name, func(t *testing.T) {
			env, err := typedFrom(t, vc.Binding).Sign(key)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			gotSig, _ := env["signature"].(string)
			wantSig := "ed25519:" + vc.SignatureB64
			if gotSig != wantSig {
				t.Fatalf("signature differs\n got: %s\nwant: %s", gotSig, wantSig)
			}
		})
	}
}

// TestSignRefusesAKeyTheDocumentDoesNotName stops the producer signing a
// binding that names someone else's key. Left to a consumer, this surfaces as
// a bad_signature on a device rather than as an error where it was made.
func TestSignRefusesAKeyTheDocumentDoesNotName(t *testing.T) {
	c := loadCorpus(t)
	doc := typedFrom(t, c.Cases[0].Binding)
	_, other, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := doc.Sign(other); err == nil {
		t.Fatal("Sign accepted a key the document does not name")
	}
}

// TestVendoredCorpusMatchesItsManifest is the local-edit check.
func TestVendoredCorpusMatchesItsManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(corpusDir, "MANIFEST.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m struct {
		SourceRepository string            `json:"source_repository"`
		SourceCommit     string            `json:"source_commit"`
		Files            map[string]string `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if m.SourceRepository == "" || m.SourceCommit == "" || len(m.Files) == 0 {
		t.Fatal("manifest carries no provenance")
	}
	for name, want := range m.Files {
		body, err := os.ReadFile(filepath.Join(corpusDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatalf("%s was edited locally; re-vendor from %s@%s",
				name, m.SourceRepository, m.SourceCommit)
		}
	}
}
