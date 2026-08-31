// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

// Package binding produces commissioned safety bindings as defined by
// ori-specs/commissioned-safety-binding/v1.
//
// A binding records the physical arrangement a safety profile evaluates
// against: which sensor observes which circuit, which actuator controls it,
// what the load does when the coil de-energises, and the proof that each of
// those was measured rather than assumed. The runtime refuses to actuate a
// channel it has no binding for, so producing one correctly is the difference
// between a commissioned cutoff and none.
//
// # Why the document is typed here
//
// The canonical form admits integers and non-integers with different
// spellings: binding_seq 2 is "2", and a rated capacity of 2 A is "2.0". JSON
// does not distinguish them and a generic numeric admission cannot infer which
// was meant — only the schema knows. That knowledge lives in this package, in
// canonicalValue below, where each field is converted through d011.Int or
// d011.Float explicitly.
//
// Getting it wrong produces a document that parses, carries the right values,
// and whose signature does not verify anywhere. The corpus test in this
// package exists to catch exactly that: it builds every published binding from
// typed Go values and requires the bytes to match.
package binding

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	canonicaljson "github.com/ori-platform/ori-canonicaljson"
	"github.com/ori-platform/ori-canonicaljson/d011"
)

// Closed vocabularies from the contract. Values outside them are refused at
// construction rather than at the runtime that would have to actuate on them.
const (
	CoilEnergised       = "energised"
	CoilDeEnergised     = "de_energised"
	CircuitOpen         = "open"
	CircuitClosed       = "closed"
	KindLocalGPIO       = "local_gpio"
	KindFirmware        = "firmware_channel"
	OutcomeOpen         = "open_protected_circuit"
	OutcomeClose        = "close_protected_circuit"
	MethodActuate       = "actuate_and_observe"
	MethodPreEnergy     = "pre_energisation"
	MethodUnproven      = "undemonstrated"
	GPIOLevelHigh       = "high"
	GPIOLevelLow        = "low"
	ProvenanceNameplate = "nameplate"
	ProvenanceMeasured  = "installer_measured"
	ProvenanceDesign    = "design_document"
)

// Binding is one device's commissioned arrangement.
type Binding struct {
	V          int
	BindingSeq int64
	DeviceID   string
	IssuedAtMs int64
	SignerID   string
	SigningKey string
	// InventoryGeneration names the device/site inventory generation this
	// binding was commissioned against; at least 1.
	InventoryGeneration int64
	// Supersedes is the canonical hash of the binding this replaces, or nil
	// for the first. A pointer rather than "" because null and absent are
	// different documents and the contract distinguishes them.
	Supersedes *string
	Actor      string
	Reason     string
	Zones      []Zone
}

// Zone binds one sensor to one actuator, with the proof that the pairing holds.
type Zone struct {
	ZoneID        string
	RatedCapacity RatedCapacity
	Sensor        Sensor
	Actuator      Actuator
	Proof         Proof
}

// RatedCapacity is a safety parameter, not inventory: a trip point is this
// value times a release-owned multiplier.
type RatedCapacity struct {
	Parameter  string
	Value      float64
	Provenance string
}

// Sensor describes what observes the circuit, including the noise floor a
// proof's readings must exceed to count as a measurement.
type Sensor struct {
	SensorID       string
	Quantity       string
	Unit           string
	RangeMin       float64
	RangeMax       float64
	Direction      string
	NoiseFloor     float64
	CalibrationRef string
}

// Actuator carries an identity and the commissioned outcome mapping. The three
// mapping fields are independently established; none is derived from another.
type Actuator struct {
	Kind     string
	Identity Identity
	Mapping  Mapping
}

// Identity is closed per kind. A GPIO identity on a firmware channel names an
// actuator that does not exist.
type Identity struct {
	// local_gpio
	GPIOPin    *int
	ActiveHigh *bool
	// firmware_channel
	FirmwareDeviceID string
	Channel          string
}

// Mapping records which coil state produces which circuit outcome, and what
// the load does when the coil has no power.
type Mapping struct {
	OpenProtectedCircuit     string
	CloseProtectedCircuit    string
	DeEnergisedTerminalState string
}

// Proof is how the mapping was established.
type Proof struct {
	Method        string
	PerformedAtMs int64
	// Reason is required for, and only for, an undemonstrated proof.
	Reason       string
	Observations []Observation
	// ControlPath is the control leg, and nil means unproven. The circuit leg
	// above establishes what the coil does to the circuit; this establishes
	// that the control input the binding names is what moves that coil.
	ControlPath *ControlPath
}

// ControlPath is the second proof leg. `commanded_and_observed` is admissible
// only for a local_gpio actuator, and `gpio_level` is required on each of its
// observations: the level actually driven is the evidence this leg records.
type ControlPath struct {
	Method        string
	PerformedAtMs int64
	// Reason is required for, and only for, an undemonstrated leg.
	Reason       string
	Observations []Observation
}

// Observation is one commanded outcome and what was measured.
//
// LoadPresentBefore and LoadPresentAfter are the classifier: the commissioning
// instrument decides whether the load was drawing, not a threshold read into a
// current value. The sensor readings are recorded evidence.
type Observation struct {
	Commanded             string
	CoilState             string
	TerminalStateObserved string
	LoadPresentBefore     bool
	LoadPresentAfter      bool
	// Optional.
	GPIOLevel    string
	SensorBefore *float64
	SensorAfter  *float64
	Instrument   string
}

// canonicalValue converts the document to the shape the canonical encoder
// takes. Every number passes through d011 with its schema type applied: an
// integer field through Int, a non-integer field through Float. This function
// is the only place that decision is made.
func (b Binding) canonicalValue() (map[string]any, error) {
	seq, err := d011.Int(b.BindingSeq)
	if err != nil {
		return nil, fmt.Errorf("binding_seq: %w", err)
	}
	issued, err := d011.Int(b.IssuedAtMs)
	if err != nil {
		return nil, fmt.Errorf("issued_at_ms: %w", err)
	}
	v, err := d011.Int(int64(b.V))
	if err != nil {
		return nil, fmt.Errorf("v: %w", err)
	}
	if b.InventoryGeneration < 1 {
		return nil, fmt.Errorf("inventory_generation: a binding is commissioned against an inventory, so there has to be one for it to name")
	}
	generation, err := d011.Int(b.InventoryGeneration)
	if err != nil {
		return nil, fmt.Errorf("inventory_generation: %w", err)
	}
	zones := make([]any, 0, len(b.Zones))
	for i, z := range b.Zones {
		zv, err := z.canonicalValue()
		if err != nil {
			return nil, fmt.Errorf("zones[%d]: %w", i, err)
		}
		zones = append(zones, zv)
	}
	var supersedes any // nil marshals as null, which is what the contract wants
	if b.Supersedes != nil {
		supersedes = *b.Supersedes
	}
	return map[string]any{
		"v":                    v,
		"binding_seq":          seq,
		"device_id":            b.DeviceID,
		"issued_at_ms":         issued,
		"signer_id":            b.SignerID,
		"signing_key":          b.SigningKey,
		"inventory_generation": generation,
		"supersedes":           supersedes,
		"actor":                b.Actor,
		"reason":               b.Reason,
		"zones":                zones,
	}, nil
}

func (z Zone) canonicalValue() (map[string]any, error) {
	capValue, err := d011.Float(z.RatedCapacity.Value)
	if err != nil {
		return nil, fmt.Errorf("rated_capacity.value: %w", err)
	}
	rangeMin, err := d011.Float(z.Sensor.RangeMin)
	if err != nil {
		return nil, fmt.Errorf("sensor.range_min: %w", err)
	}
	rangeMax, err := d011.Float(z.Sensor.RangeMax)
	if err != nil {
		return nil, fmt.Errorf("sensor.range_max: %w", err)
	}
	noiseFloor, err := d011.Float(z.Sensor.NoiseFloor)
	if err != nil {
		return nil, fmt.Errorf("sensor.noise_floor: %w", err)
	}
	identity, err := z.Actuator.Identity.canonicalValue(z.Actuator.Kind)
	if err != nil {
		return nil, fmt.Errorf("actuator.identity: %w", err)
	}
	proof, err := z.Proof.canonicalValue()
	if err != nil {
		return nil, fmt.Errorf("proof: %w", err)
	}
	return map[string]any{
		"zone_id": z.ZoneID,
		"rated_capacity": map[string]any{
			"parameter":  z.RatedCapacity.Parameter,
			"value":      capValue,
			"provenance": z.RatedCapacity.Provenance,
		},
		"sensor": map[string]any{
			"sensor_id":       z.Sensor.SensorID,
			"quantity":        z.Sensor.Quantity,
			"unit":            z.Sensor.Unit,
			"range_min":       rangeMin,
			"range_max":       rangeMax,
			"direction":       z.Sensor.Direction,
			"noise_floor":     noiseFloor,
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
	}, nil
}

func (i Identity) canonicalValue(kind string) (map[string]any, error) {
	switch kind {
	case KindLocalGPIO:
		if i.GPIOPin == nil || i.ActiveHigh == nil {
			return nil, fmt.Errorf("local_gpio identity needs gpio_pin and active_high")
		}
		pin, err := d011.Int(int64(*i.GPIOPin))
		if err != nil {
			return nil, fmt.Errorf("gpio_pin: %w", err)
		}
		return map[string]any{"gpio_pin": pin, "active_high": *i.ActiveHigh}, nil
	case KindFirmware:
		if i.FirmwareDeviceID == "" || i.Channel == "" {
			return nil, fmt.Errorf("firmware_channel identity needs firmware_device_id and channel")
		}
		return map[string]any{
			"firmware_device_id": i.FirmwareDeviceID,
			"channel":            i.Channel,
		}, nil
	default:
		return nil, fmt.Errorf("unknown actuator kind %q", kind)
	}
}

func (c ControlPath) canonicalValue() (map[string]any, error) {
	at, err := d011.Int(c.PerformedAtMs)
	if err != nil {
		return nil, fmt.Errorf("performed_at_ms: %w", err)
	}
	obs := make([]any, 0, len(c.Observations))
	for i, o := range c.Observations {
		ov, err := o.canonicalValue()
		if err != nil {
			return nil, fmt.Errorf("observations[%d]: %w", i, err)
		}
		obs = append(obs, ov)
	}
	out := map[string]any{
		"method":          c.Method,
		"performed_at_ms": at,
		"observations":    obs,
	}
	switch c.Method {
	case ControlUnproven:
		if c.Reason == "" {
			return nil, fmt.Errorf("an undemonstrated control leg must carry a reason")
		}
		if len(c.Observations) != 0 {
			return nil, fmt.Errorf("an undemonstrated control leg must carry no observations")
		}
		out["reason"] = c.Reason
	case ControlCommanded:
		if c.Reason != "" {
			return nil, fmt.Errorf("only an undemonstrated control leg carries a reason")
		}
		if len(c.Observations) == 0 {
			return nil, fmt.Errorf("a commanded control leg must carry observations")
		}
	default:
		return nil, fmt.Errorf("control_path method %q is not a control method", c.Method)
	}
	return out, nil
}

func (p Proof) canonicalValue() (map[string]any, error) {
	at, err := d011.Int(p.PerformedAtMs)
	if err != nil {
		return nil, fmt.Errorf("performed_at_ms: %w", err)
	}
	obs := make([]any, 0, len(p.Observations))
	for i, o := range p.Observations {
		ov, err := o.canonicalValue()
		if err != nil {
			return nil, fmt.Errorf("observations[%d]: %w", i, err)
		}
		obs = append(obs, ov)
	}
	out := map[string]any{
		"method":          p.Method,
		"performed_at_ms": at,
		"observations":    obs,
	}
	if p.ControlPath != nil {
		leg, err := p.ControlPath.canonicalValue()
		if err != nil {
			return nil, fmt.Errorf("control_path: %w", err)
		}
		out["control_path"] = leg
	}
	if p.Method == MethodUnproven {
		if p.Reason == "" {
			return nil, fmt.Errorf("an undemonstrated proof must carry a reason")
		}
		if len(p.Observations) != 0 {
			return nil, fmt.Errorf("an undemonstrated proof must carry no observations")
		}
		out["reason"] = p.Reason
	} else if p.Reason != "" {
		return nil, fmt.Errorf("only an undemonstrated proof carries a reason")
	}
	return out, nil
}

func (o Observation) canonicalValue() (map[string]any, error) {
	out := map[string]any{
		"commanded":               o.Commanded,
		"coil_state":              o.CoilState,
		"terminal_state_observed": o.TerminalStateObserved,
		"load_present_before":     o.LoadPresentBefore,
		"load_present_after":      o.LoadPresentAfter,
	}
	if o.GPIOLevel != "" {
		out["gpio_level"] = o.GPIOLevel
	}
	if o.Instrument != "" {
		out["instrument"] = o.Instrument
	}
	// Readings are paired: one without the other cannot show a change, and
	// admitting it would let a proof skip the noise-floor rule by omission.
	if (o.SensorBefore == nil) != (o.SensorAfter == nil) {
		return nil, fmt.Errorf("sensor_before and sensor_after are recorded together or not at all")
	}
	if o.SensorBefore != nil {
		before, err := d011.Float(*o.SensorBefore)
		if err != nil {
			return nil, fmt.Errorf("sensor_before: %w", err)
		}
		after, err := d011.Float(*o.SensorAfter)
		if err != nil {
			return nil, fmt.Errorf("sensor_after: %w", err)
		}
		out["sensor_before"] = before
		out["sensor_after"] = after
	}
	return out, nil
}

// Preimage returns the canonical bytes a signature covers.
func (b Binding) Preimage() ([]byte, error) {
	v, err := b.canonicalValue()
	if err != nil {
		return nil, err
	}
	return canonicaljson.Marshal(v)
}

// Check runs the contract's document-only stages over the bytes this producer
// would sign: the closed grammar, the mapping's self-consistency, the proof
// against the mapping it claims to establish, the capacity bounds, and
// disambiguation. A refusal is a *Refusal naming the stage and reason a
// consumer would report.
//
// A signature proves authorship, not correctness. A transposed proof, a
// capacity above the sensor's full scale, or a mapping that contradicts itself
// is refused here, where a human can still see the wiring, rather than by a
// runtime that would report it as a verdict on a device.
func (b Binding) Check() error {
	preimage, err := b.Preimage()
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
	if _, r := checkDocument(body, nil); r != nil {
		return r
	}
	return nil
}

// Sign returns the wire envelope for this binding.
//
// The key is checked against the SigningKey the document names. A binding whose
// named key is not the one that signed it is refused here rather than by every
// consumer that later fails to verify it, and the mismatch is exactly the case
// the contract's authority stage exists to catch. The document is then checked
// as a consumer would check it, so nothing is signed that would be refused.
func (b Binding) Sign(key ed25519.PrivateKey) (map[string]any, error) {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signing key is not ed25519")
	}
	named := "ed25519:" + base64.StdEncoding.EncodeToString(pub)
	if b.SigningKey != named {
		return nil, fmt.Errorf(
			"binding names signing_key %q but was signed by %q", b.SigningKey, named)
	}
	if err := b.Check(); err != nil {
		return nil, err
	}
	preimage, err := b.Preimage()
	if err != nil {
		return nil, err
	}
	value, err := b.canonicalValue()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"binding":   value,
		"signature": "ed25519:" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, preimage)),
	}, nil
}
