// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	canonicaljson "github.com/ori-platform/ori-canonicaljson"
)

// Supplied records which of the fields signing owns a decoded document already
// carried. A draft carries none of them; a document being re-signed carries all
// of them; the signer fills what is absent and never rewrites what is present.
type Supplied struct {
	IssuedAtMs bool
	SignerID   bool
	SigningKey bool
	Actor      bool
	Reason     bool
}

// wireBinding mirrors the published JSON so a document can be lifted into the
// typed producer input. The five fields signing owns are pointers so a draft
// that omits them decodes, and their absence is reported rather than read as
// an empty string or a zero timestamp.
type wireBinding struct {
	V                   int        `json:"v"`
	BindingSeq          int64      `json:"binding_seq"`
	DeviceID            string     `json:"device_id"`
	IssuedAtMs          *int64     `json:"issued_at_ms"`
	SignerID            *string    `json:"signer_id"`
	SigningKey          *string    `json:"signing_key"`
	InventoryGeneration int64      `json:"inventory_generation"`
	Supersedes          *string    `json:"supersedes"`
	Actor               *string    `json:"actor"`
	Reason              *string    `json:"reason"`
	Zones               []wireZone `json:"zones"`
}

type wireZone struct {
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
		Method        string            `json:"method"`
		PerformedAtMs int64             `json:"performed_at_ms"`
		Reason        string            `json:"reason"`
		Observations  []wireObservation `json:"observations"`
		ControlPath   *wireControlPath  `json:"control_path"`
	} `json:"proof"`
}

type wireControlPath struct {
	Method        string            `json:"method"`
	PerformedAtMs int64             `json:"performed_at_ms"`
	Reason        string            `json:"reason"`
	Observations  []wireObservation `json:"observations"`
}

type wireObservation struct {
	Commanded    string   `json:"commanded"`
	CoilState    string   `json:"coil_state"`
	Terminal     string   `json:"terminal_state_observed"`
	LoadBefore   bool     `json:"load_present_before"`
	LoadAfter    bool     `json:"load_present_after"`
	GPIOLevel    string   `json:"gpio_level"`
	SensorBefore *float64 `json:"sensor_before"`
	SensorAfter  *float64 `json:"sensor_after"`
	Instrument   string   `json:"instrument"`
}

// ownedFields are the top-level keys signing owns, in the contract's order.
var ownedFields = []string{"issued_at_ms", "signer_id", "signing_key", "actor", "reason"}

// DecodeDocument lifts a binding document — a draft, an assembled document, or
// a signed one's inner object — into the typed producer input, reporting
// which of the fields signing owns it supplied.
//
// The decode is strict where the verifier is strict: invalid UTF-8, duplicated
// keys, trailing bytes, a non-object, an unknown field anywhere, or a number
// spelled in a way its field's type does not admit are all refused. An owned
// field written as null is refused rather than read as absent, because a
// signer that filled it would be rewriting what the document said.
func DecodeDocument(raw []byte) (Binding, Supplied, error) {
	fields, err := strictObject(raw)
	if err != nil {
		return Binding{}, Supplied{}, err
	}
	var supplied Supplied
	for _, name := range ownedFields {
		value, present := fields[name]
		if !present {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return Binding{}, Supplied{}, fmt.Errorf(
				"%s is null; omit the field for signing to fill it, or give it a value", name)
		}
		switch name {
		case "issued_at_ms":
			supplied.IssuedAtMs = true
		case "signer_id":
			supplied.SignerID = true
		case "signing_key":
			supplied.SigningKey = true
		case "actor":
			supplied.Actor = true
		case "reason":
			supplied.Reason = true
		}
	}
	if err := checkMembers(fields); err != nil {
		return Binding{}, Supplied{}, err
	}
	var w wireBinding
	if err := strictDecode(raw, &w); err != nil {
		return Binding{}, Supplied{}, err
	}
	doc := Binding{
		V: w.V, BindingSeq: w.BindingSeq, DeviceID: w.DeviceID,
		InventoryGeneration: w.InventoryGeneration,
		Supersedes:          w.Supersedes,
	}
	if w.IssuedAtMs != nil {
		doc.IssuedAtMs = *w.IssuedAtMs
	}
	if w.SignerID != nil {
		doc.SignerID = *w.SignerID
	}
	if w.SigningKey != nil {
		doc.SigningKey = *w.SigningKey
	}
	if w.Actor != nil {
		doc.Actor = *w.Actor
	}
	if w.Reason != nil {
		doc.Reason = *w.Reason
	}
	for _, z := range w.Zones {
		zone := Zone{
			ZoneID: z.ZoneID,
			RatedCapacity: RatedCapacity{
				Parameter: z.RatedCapacity.Parameter, Value: z.RatedCapacity.Value,
				Provenance: z.RatedCapacity.Provenance,
			},
			Sensor: Sensor{
				SensorID: z.Sensor.SensorID, Quantity: z.Sensor.Quantity,
				Unit: z.Sensor.Unit, RangeMin: z.Sensor.RangeMin,
				RangeMax: z.Sensor.RangeMax, Direction: z.Sensor.Direction,
				NoiseFloor: z.Sensor.NoiseFloor, CalibrationRef: z.Sensor.CalibrationRef,
			},
			Actuator: Actuator{
				Kind: z.Actuator.Kind,
				Identity: Identity{
					GPIOPin: z.Actuator.Identity.GPIOPin, ActiveHigh: z.Actuator.Identity.ActiveHigh,
					FirmwareDeviceID: z.Actuator.Identity.FirmwareDeviceID,
					Channel:          z.Actuator.Identity.Channel,
				},
				Mapping: Mapping{
					OpenProtectedCircuit:     z.Actuator.Mapping.Open,
					CloseProtectedCircuit:    z.Actuator.Mapping.Close,
					DeEnergisedTerminalState: z.Actuator.Mapping.Terminal,
				},
			},
			Proof: Proof{
				Method: z.Proof.Method, PerformedAtMs: z.Proof.PerformedAtMs,
				Reason:       z.Proof.Reason,
				Observations: liftObservations(z.Proof.Observations),
			},
		}
		if leg := z.Proof.ControlPath; leg != nil {
			lifted := liftControlPath(*leg)
			zone.Proof.ControlPath = &lifted
		}
		doc.Zones = append(doc.Zones, zone)
	}
	return doc, supplied, nil
}

// DecodeControlPath lifts an exported control leg, as `export --zone` writes
// it, into the typed value a zone's proof carries.
func DecodeControlPath(raw []byte) (ControlPath, error) {
	fields, err := strictObject(raw)
	if err != nil {
		return ControlPath{}, err
	}
	if err := checkLegMembers("control leg", fields); err != nil {
		return ControlPath{}, err
	}
	var w wireControlPath
	if err := strictDecode(raw, &w); err != nil {
		return ControlPath{}, err
	}
	return liftControlPath(w), nil
}

func liftControlPath(w wireControlPath) ControlPath {
	return ControlPath{
		Method: w.Method, PerformedAtMs: w.PerformedAtMs, Reason: w.Reason,
		Observations: liftObservations(w.Observations),
	}
}

func liftObservations(ws []wireObservation) []Observation {
	var out []Observation
	for _, o := range ws {
		out = append(out, Observation{
			Commanded: o.Commanded, CoilState: o.CoilState,
			TerminalStateObserved: o.Terminal,
			LoadPresentBefore:     o.LoadBefore, LoadPresentAfter: o.LoadAfter,
			GPIOLevel: o.GPIOLevel, SensorBefore: o.SensorBefore,
			SensorAfter: o.SensorAfter, Instrument: o.Instrument,
		})
	}
	return out
}

// checkMembers requires every member the contract's closed grammar names to
// be present in the input, before types are applied. A typed decode cannot
// tell an absent member from a zero one, and canonical encoding would then
// write a range_min of 0.0, a load_present_before of false or a
// performed_at_ms of 0 the document never contained. The only absences
// admitted are the five fields signing owns and supersedes, whose absence on
// a first binding is what says there is nothing it replaces.
//
// The key sets are the verifier's own, so what is required here is what it
// requires; only the per-kind and per-method selection is repeated.
func checkMembers(top map[string]json.RawMessage) error {
	for _, name := range bindingKeys {
		if name == "supersedes" || contains(ownedFields, name) {
			continue
		}
		if _, ok := top[name]; !ok {
			return fmt.Errorf("%s is absent", name)
		}
	}
	var zones []json.RawMessage
	if err := json.Unmarshal(top["zones"], &zones); err != nil || isNull(top["zones"]) {
		return errors.New("zones is not an array")
	}
	for i, raw := range zones {
		if err := checkZoneMembers(fmt.Sprintf("zones[%d]", i), raw); err != nil {
			return err
		}
	}
	return nil
}

func checkZoneMembers(where string, raw json.RawMessage) error {
	zone, err := membersOf(where, raw, zoneKeys)
	if err != nil {
		return err
	}
	if _, err := membersOf(where+".rated_capacity", zone["rated_capacity"], capacityKeys); err != nil {
		return err
	}
	if _, err := membersOf(where+".sensor", zone["sensor"], sensorKeys); err != nil {
		return err
	}
	actuator, err := membersOf(where+".actuator", zone["actuator"], actuatorKeys)
	if err != nil {
		return err
	}
	if _, err := membersOf(where+".actuator.commissioned_mapping", actuator["commissioned_mapping"], mappingKeys); err != nil {
		return err
	}
	switch stringOf(actuator["kind"]) {
	case KindLocalGPIO:
		if _, err := membersOf(where+".actuator.identity", actuator["identity"], gpioKeys); err != nil {
			return err
		}
	case KindFirmware:
		if _, err := membersOf(where+".actuator.identity", actuator["identity"], firmwareKeys); err != nil {
			return err
		}
	}
	proof, err := membersOf(where+".proof", zone["proof"], []string{"method"})
	if err != nil {
		return err
	}
	keys := provenProofKeys
	if stringOf(proof["method"]) == MethodUnproven {
		keys = unprovenKeys
	}
	if _, err := membersOf(where+".proof", zone["proof"], keys); err != nil {
		return err
	}
	if err := checkObservationMembers(where+".proof", proof["observations"]); err != nil {
		return err
	}
	if leg, ok := proof["control_path"]; ok {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(leg, &fields); err != nil || fields == nil {
			return fmt.Errorf("%s.proof.control_path is not an object", where)
		}
		return checkLegMembers(where+".proof.control_path", fields)
	}
	return nil
}

func checkLegMembers(where string, leg map[string]json.RawMessage) error {
	keys := controlProven
	if stringOf(leg["method"]) == ControlUnproven {
		keys = controlUnproven
	}
	for _, name := range keys {
		if _, ok := leg[name]; !ok {
			return fmt.Errorf("%s.%s is absent", where, name)
		}
	}
	return checkObservationMembers(where, leg["observations"])
}

func checkObservationMembers(where string, raw json.RawMessage) error {
	var observations []json.RawMessage
	if err := json.Unmarshal(raw, &observations); err != nil || isNull(raw) {
		return fmt.Errorf("%s.observations is not an array", where)
	}
	for i, o := range observations {
		if _, err := membersOf(fmt.Sprintf("%s.observations[%d]", where, i), o, obsRequired); err != nil {
			return err
		}
	}
	return nil
}

// membersOf decodes one object and requires each named member to be present
// and not null: a null decodes into the same zero value an absent member
// does, and would be written as a fact just the same.
func membersOf(where string, raw json.RawMessage, keys []string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("%s is not an object", where)
	}
	for _, name := range keys {
		value, ok := fields[name]
		if !ok {
			return nil, fmt.Errorf("%s.%s is absent", where, name)
		}
		if isNull(value) {
			return nil, fmt.Errorf("%s.%s is null", where, name)
		}
	}
	return fields, nil
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func stringOf(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// strictObject refuses what the two runtimes would not agree on, then returns
// the top-level members so presence can be read before types are applied.
func strictObject(raw []byte) (map[string]json.RawMessage, error) {
	if err := canonicaljson.ValidateWireUnicode(raw); err != nil {
		return nil, fmt.Errorf("the document is not valid JSON text: %w", err)
	}
	if hasDuplicateKeys(raw) {
		return nil, errors.New("the document repeats a key, so its canonical form is undefined")
	}
	var fields map[string]json.RawMessage
	if err := strictDecode(raw, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, errors.New("the document is not a JSON object")
	}
	return fields, nil
}

// strictDecode decodes one JSON value into target, refusing unknown fields and
// anything after the value.
func strictDecode(raw []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("the document is not readable: %w", err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("the document carries bytes after its closing brace")
	}
	return nil
}
