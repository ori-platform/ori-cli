// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding

// The verifier half of commissioned-safety-binding/v1.
//
// It reads wire bytes, never typed values, and it shares nothing with the
// corpus generator: the contract's ratification condition is a verifier in
// another language that reaches every declared verdict over the published
// corpus, and this is that verifier. Every refusal names the stage it was
// decided at, because a refusal only proves a check ran if every earlier
// stage passed. Nothing here derives a coil state, a terminal state, or a
// polarity from anything but the signed document.
//
// A verifier that panics on malformed input has not refused it, so nothing in
// this file indexes a map or asserts a type without having checked it first.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"

	canonicaljson "github.com/ori-platform/ori-canonicaljson"
	"github.com/ori-platform/ori-canonicaljson/d011"
)

// Stage names, in the contract's acceptance order.
const (
	StageParses                 = "parses"
	StageDeviceID               = "device_id"
	StageKeySelection           = "key_selection"
	StageSignature              = "signature"
	StageAuthority              = "authority"
	StageFreshness              = "freshness"
	StageMappingSelfConsistency = "mapping_self_consistency"
	StageProofConsistency       = "proof_consistency"
	StageBounds                 = "bounds"
	StageDisambiguation         = "disambiguation"
	StageInventory              = "inventory"
	StageActivationPosture      = "activation_posture"

	// Profile-only stages.
	StageDeviceBinding = "device_binding"
	StageBindingMatch  = "binding_match"
	StageMappingMatch  = "mapping_match"
)

// Refusal reasons.
const (
	ReasonMalformed              = "malformed"
	ReasonWrongDevice            = "wrong_device"
	ReasonAnchorCollision        = "anchor_collision"
	ReasonUnknownSigner          = "unknown_signer"
	ReasonBadSignature           = "bad_signature"
	ReasonWrongAuthority         = "wrong_authority"
	ReasonSupersededSigner       = "superseded_signer"
	ReasonStale                  = "stale"
	ReasonMappingContradiction   = "mapping_contradiction"
	ReasonProofContradiction     = "proof_contradiction"
	ReasonStaleProof             = "stale_proof"
	ReasonOutOfBounds            = "out_of_bounds"
	ReasonAmbiguousBinding       = "ambiguous_binding"
	ReasonUnknownHardware        = "unknown_hardware"
	ReasonUnboundActuator        = "unbound_actuator"
	ReasonUndemonstratedBinding  = "undemonstrated_binding"
	ReasonProfileBindingMismatch = "profile_binding_mismatch"
	ReasonProfileChannelMismatch = "profile_channel_mismatch"
	ReasonProfileMappingMismatch = "profile_mapping_mismatch"
)

// AcceptanceOrder is the contract's binding verification order.
var AcceptanceOrder = []string{
	StageParses, StageDeviceID, StageKeySelection, StageSignature, StageAuthority,
	StageFreshness, StageMappingSelfConsistency, StageProofConsistency, StageBounds,
	StageDisambiguation, StageInventory, StageActivationPosture,
}

// ProfileAcceptanceOrder is the contract's firmware-profile verification order.
var ProfileAcceptanceOrder = []string{
	StageParses, StageDeviceBinding, StageKeySelection, StageSignature,
	StageAuthority, StageBindingMatch, StageMappingMatch,
}

// Refusal is a verdict: the stage it was decided at and the contract's reason.
type Refusal struct {
	Stage  string
	Reason string
}

func (r *Refusal) Error() string { return r.Stage + ": " + r.Reason }

func refuse(stage, reason string) *Refusal { return &Refusal{Stage: stage, Reason: reason} }

func malformed() *Refusal { return refuse(StageParses, ReasonMalformed) }

// ActuatorRef names declared actuating hardware by identity. Polarity is a
// commissioned fact, not an inventory one, so a local GPIO actuator is
// identified by its pin alone.
type ActuatorRef struct {
	Kind             string
	GPIOPin          int64
	FirmwareDeviceID string
	Channel          string
}

func (a ActuatorRef) key() string {
	if a.Kind == KindLocalGPIO {
		return KindLocalGPIO + ":" + strconv.FormatInt(a.GPIOPin, 10)
	}
	return a.Kind + ":" + strconv.Quote(a.FirmwareDeviceID) + ":" + strconv.Quote(a.Channel)
}

// ZoneState is what a consumer retained from the binding in force, per zone,
// for the revision rule: a changed actuator cannot inherit the proof of the
// one it replaced.
type ZoneState struct {
	// Identity is the full identity object, active_high included, as the
	// accepted document carried it.
	Identity       map[string]any
	Mapping        Mapping
	CalibrationRef string
	ProofAtMs      int64
}

// Context is everything a binding verdict depends on that is not in the
// document. A nil anchor is an absent anchor.
type Context struct {
	DeviceID                    string
	CommissioningAnchorCurrent  []byte
	CommissioningAnchorPrevious []byte
	ProvisioningAnchor          []byte
	AcceptedBindingSeq          int64
	AcceptedBindingHash         *string
	DeclaredSensorIDs           []string
	DeclaredActuators           []ActuatorRef
	// DeploymentPosture is "development", "staging" or "production". Only
	// development admits an undemonstrated zone; anything else, the empty
	// string included, is treated as hardened.
	DeploymentPosture string
	// ProfileMultiplier, when set, is the release-owned multiplier the
	// trip-point bound applies to each zone's rated capacity.
	ProfileMultiplier *float64
	AcceptedZoneState map[string]ZoneState
}

// ProfileContext is everything a firmware-profile verdict depends on.
type ProfileContext struct {
	FirmwareDeviceID            string
	Channel                     string
	CommissioningAnchorCurrent  []byte
	CommissioningAnchorPrevious []byte
	ProvisioningAnchor          []byte
	AcceptedBindingSeq          int64
	AcceptedBindingHash         *string
	ExpectedMapping             Mapping
}

// AcceptedZone is what is retained per zone from an accepted binding.
type AcceptedZone struct {
	ZoneID             string
	SensorID           string
	Kind               string
	Identity           map[string]any
	Mapping            Mapping
	CalibrationRef     string
	ProofMethod        string
	ProofPerformedAtMs int64
	RatedCapacity      float64
}

// Accepted is a binding that passed every stage, with what a consumer retains.
type Accepted struct {
	BindingSeq          int64
	CanonicalHash       string
	InventoryGeneration int64
	DeviceID            string
	SignerID            string
	IssuedAtMs          int64
	Supersedes          *string
	Zones               []AcceptedZone
	CanonicalBytes      []byte
	Signature           string
}

// ── grammar ─────────────────────────────────────────────────────────────

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var (
	bindingKeys     = []string{"v", "binding_seq", "device_id", "issued_at_ms", "signer_id", "signing_key", "inventory_generation", "supersedes", "actor", "reason", "zones"}
	zoneKeys        = []string{"zone_id", "rated_capacity", "sensor", "actuator", "proof"}
	capacityKeys    = []string{"parameter", "value", "provenance"}
	sensorKeys      = []string{"sensor_id", "quantity", "unit", "range_min", "range_max", "direction", "noise_floor", "calibration_ref"}
	actuatorKeys    = []string{"kind", "identity", "commissioned_mapping"}
	mappingKeys     = []string{"open_protected_circuit", "close_protected_circuit", "de_energised_terminal_state"}
	gpioKeys        = []string{"gpio_pin", "active_high"}
	firmwareKeys    = []string{"firmware_device_id", "channel"}
	provenProofKeys = []string{"method", "performed_at_ms", "observations"}
	unprovenKeys    = []string{"method", "performed_at_ms", "reason", "observations"}
	obsRequired     = []string{"commanded", "coil_state", "load_present_before", "load_present_after", "terminal_state_observed"}
	obsOptional     = []string{"gpio_level", "sensor_before", "sensor_after", "instrument"}
	profileKeys     = []string{"v", "binding_hash", "binding_seq", "device_id", "firmware_device_id", "channel", "commissioned_mapping", "signing_key"}

	coilStates    = []string{CoilEnergised, CoilDeEnergised}
	circuitStates = []string{CircuitOpen, CircuitClosed}
	kinds         = []string{KindLocalGPIO, KindFirmware}
	methods       = []string{MethodActuate, MethodPreEnergy, MethodUnproven}
	provenances   = []string{ProvenanceNameplate, ProvenanceMeasured, ProvenanceDesign}
	gpioLevels    = []string{GPIOLevelHigh, GPIOLevelLow}
	outcomes      = []string{OutcomeOpen, OutcomeClose}
)

// decodeWire turns bytes into the six decoder types, refusing what the two
// runtimes would not agree on: invalid UTF-8, unpaired surrogates, trailing
// bytes. Numbers keep the spelling they arrived with.
func decodeWire(raw []byte) (any, *Refusal) {
	if err := canonicaljson.ValidateWireUnicode(raw); err != nil {
		return nil, malformed()
	}
	if hasDuplicateKeys(raw) {
		return nil, malformed()
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, malformed()
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, malformed()
	}
	return value, nil
}

// hasDuplicateKeys walks the token stream, because a decoder that keeps the
// last occurrence would verify bytes a first-wins parser reads differently:
// the same file would carry one capacity to this verifier and another to a
// device. The canonical form of such an object is undefined, so it is refused
// during parsing. Structural errors are left for Decode to report.
func hasDuplicateKeys(raw []byte) bool {
	type frame struct {
		object    bool
		keys      map[string]bool
		expectKey bool
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if top != nil && top.object {
					top.expectKey = true
				}
				stack = append(stack, &frame{object: delim == '{', keys: map[string]bool{}, expectKey: delim == '{'})
			default:
				if len(stack) == 0 {
					return false
				}
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top == nil || !top.object {
			continue
		}
		if !top.expectKey {
			top.expectKey = true
			continue
		}
		key, ok := tok.(string)
		if !ok {
			return false
		}
		if top.keys[key] {
			return true
		}
		top.keys[key] = true
		top.expectKey = false
	}
}

// closed admits an object carrying exactly the given keys.
func closed(v any, keys []string) (map[string]any, bool) {
	obj, ok := v.(map[string]any)
	if !ok || len(obj) != len(keys) {
		return nil, false
	}
	for _, k := range keys {
		if _, present := obj[k]; !present {
			return nil, false
		}
	}
	return obj, true
}

func text(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", false
	}
	return s, true
}

func flag(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

// number admits a `number` field: inside the D-011 agreement zone, spelled
// canonically, and spelled with a fractional part. A boolean is not a number.
//
// The fractional part is the field-type half of the spelling rule. Admit alone
// accepts `10` as a canonical integer, and every field reaching here is typed
// `number` by the contract, so `10` is a second signing input for a value the
// schema says is written `10.0`. JSON cannot tell the two apart; only the
// schema knows which was meant.
func number(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok || d011.Admit(n) != nil || !strings.Contains(n.String(), ".") {
		return 0, false
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// whole admits an integer, and integer is meant literally: "7.0" is not 7.
func whole(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || d011.Admit(n) != nil || strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	i, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil {
		return 0, false
	}
	return i, true
}

// vocab checks the type before membership, so a shape chosen to break a
// lookup is refused rather than crashed on.
func vocab(v any, allowed []string) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	for _, a := range allowed {
		if s == a {
			return s, true
		}
	}
	return "", false
}

// canonicalB64 admits exactly one spelling: decode, re-encode, require the
// same text. Strict decoding alone leaves the pad bits unchecked.
func canonicalB64(s string, size int) ([]byte, bool) {
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) != size || base64.StdEncoding.EncodeToString(raw) != s {
		return nil, false
	}
	return raw, true
}

func prefixed(v any, prefix string, size int) ([]byte, bool) {
	s, ok := v.(string)
	if !ok || !strings.HasPrefix(s, prefix) {
		return nil, false
	}
	return canonicalB64(strings.TrimPrefix(s, prefix), size)
}

func rawKey(v any) ([]byte, bool)       { return prefixed(v, "ed25519:", ed25519.PublicKeySize) }
func rawSignature(v any) ([]byte, bool) { return prefixed(v, "ed25519:", ed25519.SignatureSize) }

func digest(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || !digestPattern.MatchString(s) {
		return "", false
	}
	return s, true
}

// parseEnvelope closes the wrapper as well as what it wraps. A field beside
// the signature is outside the signed bytes and unauthenticated by
// construction.
func parseEnvelope(raw []byte, inner string) (map[string]any, []byte, string, *Refusal) {
	value, r := decodeWire(raw)
	if r != nil {
		return nil, nil, "", r
	}
	env, ok := closed(value, []string{inner, "signature"})
	if !ok {
		return nil, nil, "", malformed()
	}
	body, ok := env[inner].(map[string]any)
	if !ok {
		return nil, nil, "", malformed()
	}
	sig, ok := rawSignature(env["signature"])
	if !ok {
		return nil, nil, "", malformed()
	}
	return body, sig, env["signature"].(string), nil
}

// ── the parsed document ─────────────────────────────────────────────────

type parsedObservation struct {
	commanded    string
	coilState    string
	terminal     string
	loadBefore   bool
	loadAfter    bool
	gpioLevel    string // "" when absent
	hasReadings  bool
	sensorBefore float64
	sensorAfter  float64
}

type parsedZone struct {
	zoneID         string
	capacity       float64
	sensorID       string
	rangeMin       float64
	rangeMax       float64
	noiseFloor     float64
	calibrationRef string
	kind           string
	identity       map[string]any
	ref            ActuatorRef
	activeHigh     bool
	mapping        Mapping
	method         string
	performedAtMs  int64
	observations   []parsedObservation
}

type parsedBinding struct {
	raw                 map[string]any
	seq                 int64
	deviceID            string
	issuedAtMs          int64
	signerID            string
	signingKey          []byte
	inventoryGeneration int64
	supersedes          *string
	zones               []parsedZone
	canonical           []byte
}

func parseMapping(v any) (Mapping, bool) {
	obj, ok := closed(v, mappingKeys)
	if !ok {
		return Mapping{}, false
	}
	open, ok1 := vocab(obj["open_protected_circuit"], coilStates)
	cls, ok2 := vocab(obj["close_protected_circuit"], coilStates)
	term, ok3 := vocab(obj["de_energised_terminal_state"], circuitStates)
	if !ok1 || !ok2 || !ok3 {
		return Mapping{}, false
	}
	return Mapping{OpenProtectedCircuit: open, CloseProtectedCircuit: cls, DeEnergisedTerminalState: term}, true
}

func parseZone(v any) (parsedZone, bool) {
	var z parsedZone
	obj, ok := closed(v, zoneKeys)
	if !ok {
		return z, false
	}
	if z.zoneID, ok = text(obj["zone_id"]); !ok {
		return z, false
	}

	capacity, ok := closed(obj["rated_capacity"], capacityKeys)
	if !ok {
		return z, false
	}
	if _, ok = text(capacity["parameter"]); !ok {
		return z, false
	}
	if z.capacity, ok = number(capacity["value"]); !ok {
		return z, false
	}
	if _, ok = vocab(capacity["provenance"], provenances); !ok {
		return z, false
	}

	sensor, ok := closed(obj["sensor"], sensorKeys)
	if !ok {
		return z, false
	}
	for _, name := range []string{"sensor_id", "quantity", "unit", "direction", "calibration_ref"} {
		if _, ok = text(sensor[name]); !ok {
			return z, false
		}
	}
	z.sensorID = sensor["sensor_id"].(string)
	z.calibrationRef = sensor["calibration_ref"].(string)
	if z.rangeMin, ok = number(sensor["range_min"]); !ok {
		return z, false
	}
	if z.rangeMax, ok = number(sensor["range_max"]); !ok {
		return z, false
	}
	if z.noiseFloor, ok = number(sensor["noise_floor"]); !ok {
		return z, false
	}
	if !(z.rangeMin < z.rangeMax) || z.noiseFloor <= 0 {
		return z, false
	}

	actuator, ok := closed(obj["actuator"], actuatorKeys)
	if !ok {
		return z, false
	}
	if z.kind, ok = vocab(actuator["kind"], kinds); !ok {
		return z, false
	}
	z.ref.Kind = z.kind
	switch z.kind {
	case KindLocalGPIO:
		identity, ok := closed(actuator["identity"], gpioKeys)
		if !ok {
			return z, false
		}
		if z.ref.GPIOPin, ok = whole(identity["gpio_pin"]); !ok {
			return z, false
		}
		if z.activeHigh, ok = flag(identity["active_high"]); !ok {
			return z, false
		}
		z.identity = identity
	case KindFirmware:
		identity, ok := closed(actuator["identity"], firmwareKeys)
		if !ok {
			return z, false
		}
		if z.ref.FirmwareDeviceID, ok = text(identity["firmware_device_id"]); !ok {
			return z, false
		}
		if z.ref.Channel, ok = text(identity["channel"]); !ok {
			return z, false
		}
		z.identity = identity
	}
	if z.mapping, ok = parseMapping(actuator["commissioned_mapping"]); !ok {
		return z, false
	}

	proofObj, ok := obj["proof"].(map[string]any)
	if !ok {
		return z, false
	}
	if z.method, ok = vocab(proofObj["method"], methods); !ok {
		return z, false
	}
	keys := provenProofKeys
	if z.method == MethodUnproven {
		keys = unprovenKeys
	}
	proof, ok := closed(proofObj, keys)
	if !ok {
		return z, false
	}
	if z.performedAtMs, ok = whole(proof["performed_at_ms"]); !ok {
		return z, false
	}
	observations, ok := proof["observations"].([]any)
	if !ok {
		return z, false
	}
	if z.method == MethodUnproven {
		if _, ok = text(proof["reason"]); !ok {
			return z, false
		}
		return z, len(observations) == 0
	}
	if len(observations) == 0 {
		return z, false
	}
	for _, item := range observations {
		o, ok := parseObservation(item, z.kind)
		if !ok {
			return z, false
		}
		z.observations = append(z.observations, o)
	}
	return z, true
}

func parseObservation(v any, kind string) (parsedObservation, bool) {
	var o parsedObservation
	obj, ok := v.(map[string]any)
	if !ok {
		return o, false
	}
	for _, k := range obsRequired {
		if _, present := obj[k]; !present {
			return o, false
		}
	}
	for k := range obj {
		if !contains(obsRequired, k) && !contains(obsOptional, k) {
			return o, false
		}
	}
	if o.commanded, ok = vocab(obj["commanded"], outcomes); !ok {
		return o, false
	}
	if o.coilState, ok = vocab(obj["coil_state"], coilStates); !ok {
		return o, false
	}
	if o.terminal, ok = vocab(obj["terminal_state_observed"], circuitStates); !ok {
		return o, false
	}
	if o.loadBefore, ok = flag(obj["load_present_before"]); !ok {
		return o, false
	}
	if o.loadAfter, ok = flag(obj["load_present_after"]); !ok {
		return o, false
	}
	if level, present := obj["gpio_level"]; present {
		// A pin level is meaningless for a channel with no pin.
		if kind != KindLocalGPIO {
			return o, false
		}
		if o.gpioLevel, ok = vocab(level, gpioLevels); !ok {
			return o, false
		}
	}
	if instrument, present := obj["instrument"]; present {
		if _, ok = text(instrument); !ok {
			return o, false
		}
	}
	before, hasBefore := obj["sensor_before"]
	after, hasAfter := obj["sensor_after"]
	// Readings are paired: one without the other cannot show a change.
	if hasBefore != hasAfter {
		return o, false
	}
	if hasBefore {
		if o.sensorBefore, ok = number(before); !ok {
			return o, false
		}
		if o.sensorAfter, ok = number(after); !ok {
			return o, false
		}
		o.hasReadings = true
	}
	return o, true
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// stParses is the closed grammar. Every refusal here is `malformed`.
func stParses(body map[string]any) (*parsedBinding, *Refusal) {
	b := &parsedBinding{raw: body}
	obj, ok := closed(body, bindingKeys)
	if !ok {
		return nil, malformed()
	}
	if v, ok := whole(obj["v"]); !ok || v != 1 {
		return nil, malformed()
	}
	for _, name := range []string{"device_id", "signer_id", "actor", "reason"} {
		if _, ok = text(obj[name]); !ok {
			return nil, malformed()
		}
	}
	b.deviceID = obj["device_id"].(string)
	b.signerID = obj["signer_id"].(string)
	if b.signingKey, ok = rawKey(obj["signing_key"]); !ok {
		return nil, malformed()
	}
	if b.seq, ok = whole(obj["binding_seq"]); !ok || b.seq < 1 {
		return nil, malformed()
	}
	if b.issuedAtMs, ok = whole(obj["issued_at_ms"]); !ok {
		return nil, malformed()
	}
	if b.inventoryGeneration, ok = whole(obj["inventory_generation"]); !ok || b.inventoryGeneration < 1 {
		return nil, malformed()
	}
	if obj["supersedes"] != nil {
		s, ok := digest(obj["supersedes"])
		if !ok {
			return nil, malformed()
		}
		b.supersedes = &s
	}
	zones, ok := obj["zones"].([]any)
	if !ok || len(zones) == 0 {
		return nil, malformed()
	}
	for _, item := range zones {
		z, ok := parseZone(item)
		if !ok {
			return nil, malformed()
		}
		b.zones = append(b.zones, z)
	}
	canonical, err := canonicaljson.Marshal(body)
	if err != nil {
		return nil, malformed()
	}
	b.canonical = canonical
	return b, nil
}

// ── key selection and authority ─────────────────────────────────────────

type anchors struct {
	current      []byte
	previous     []byte
	provisioning []byte
}

func (a anchors) collision() bool {
	if a.provisioning == nil {
		return false
	}
	return bytes.Equal(a.provisioning, a.current) || bytes.Equal(a.provisioning, a.previous)
}

// selectKey chooses exactly one candidate by comparing key material, and
// issues no verdict about authority. No signature is attempted against a key
// the document did not name.
func (a anchors) selectKey(named []byte) *Refusal {
	if a.collision() {
		return refuse(StageKeySelection, ReasonAnchorCollision)
	}
	for _, candidate := range [][]byte{a.current, a.previous, a.provisioning} {
		if candidate != nil && bytes.Equal(candidate, named) {
			return nil
		}
	}
	return refuse(StageKeySelection, ReasonUnknownSigner)
}

// authority is decided only over a verified signature, so it cannot be
// manufactured by naming a public key over arbitrary bytes.
func (a anchors) authority(named []byte) *Refusal {
	if a.provisioning != nil && bytes.Equal(named, a.provisioning) {
		return refuse(StageAuthority, ReasonWrongAuthority)
	}
	if a.previous != nil && bytes.Equal(named, a.previous) {
		return refuse(StageAuthority, ReasonSupersededSigner)
	}
	if !bytes.Equal(named, a.current) {
		return refuse(StageAuthority, ReasonUnknownSigner)
	}
	return nil
}

func verifySignature(pub, message, sig []byte) *Refusal {
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(pub), message, sig) {
		return refuse(StageSignature, ReasonBadSignature)
	}
	return nil
}

// ── document stages ─────────────────────────────────────────────────────

func stMappingSelfConsistency(b *parsedBinding) *Refusal {
	for _, z := range b.zones {
		m := z.mapping
		if m.OpenProtectedCircuit == m.CloseProtectedCircuit {
			return refuse(StageMappingSelfConsistency, ReasonMappingContradiction)
		}
		opensByRelease := m.OpenProtectedCircuit == CoilDeEnergised
		if opensByRelease != (m.DeEnergisedTerminalState == CircuitOpen) {
			return refuse(StageMappingSelfConsistency, ReasonMappingContradiction)
		}
	}
	return nil
}

func (m Mapping) coilFor(outcome string) string {
	if outcome == OutcomeOpen {
		return m.OpenProtectedCircuit
	}
	return m.CloseProtectedCircuit
}

func stProofConsistency(b *parsedBinding, prior map[string]ZoneState) *Refusal {
	contradiction := refuse(StageProofConsistency, ReasonProofContradiction)
	for _, z := range b.zones {
		if z.method == MethodUnproven {
			continue
		}
		seen := map[string]bool{}
		for _, o := range z.observations {
			seen[o.commanded] = true
			if o.coilState != z.mapping.coilFor(o.commanded) {
				return contradiction
			}
			opening := o.commanded == OutcomeOpen
			if opening && o.terminal != CircuitOpen || !opening && o.terminal != CircuitClosed {
				return contradiction
			}
			// The instrument classifies load presence; the reading is evidence.
			if o.loadBefore != opening || o.loadAfter == opening {
				return contradiction
			}
			if o.hasReadings {
				delta := o.sensorAfter - o.sensorBefore
				if math.Abs(delta) <= z.noiseFloor || (delta > 0) != o.loadAfter {
					return contradiction
				}
			}
			if o.gpioLevel != "" {
				energised := o.coilState == CoilEnergised
				expected := GPIOLevelLow
				if energised == z.activeHigh {
					expected = GPIOLevelHigh
				}
				if o.gpioLevel != expected {
					return contradiction
				}
			}
		}
		if !seen[OutcomeOpen] || !seen[OutcomeClose] {
			return contradiction
		}
	}
	// A revision changing actuator identity, mapping or calibration needs a
	// proof performed after the accepted document.
	for _, z := range b.zones {
		was, retained := prior[z.zoneID]
		if !retained {
			continue
		}
		changed := !sameIdentity(was.Identity, z.identity) ||
			was.Mapping != z.mapping ||
			was.CalibrationRef != z.calibrationRef
		if changed && z.performedAtMs <= was.ProofAtMs {
			return refuse(StageProofConsistency, ReasonStaleProof)
		}
	}
	return nil
}

// sameIdentity compares identity objects by canonical bytes, after admitting
// Go integers and booleans a caller may have built the retained state from.
func sameIdentity(a, b map[string]any) bool {
	ca, errA := canonicaljson.Marshal(normaliseIdentity(a))
	cb, errB := canonicaljson.Marshal(normaliseIdentity(b))
	if errA != nil || errB != nil {
		return false
	}
	return bytes.Equal(ca, cb)
}

func normaliseIdentity(identity map[string]any) map[string]any {
	out := make(map[string]any, len(identity))
	for k, v := range identity {
		switch t := v.(type) {
		case int:
			out[k] = json.Number(strconv.Itoa(t))
		case int64:
			out[k] = json.Number(strconv.FormatInt(t, 10))
		case float64:
			if t == math.Trunc(t) && math.Abs(t) <= d011.MaxSafeInteger {
				out[k] = json.Number(strconv.FormatInt(int64(t), 10))
			} else {
				out[k] = v
			}
		default:
			out[k] = v
		}
	}
	return out
}

func stBounds(b *parsedBinding, multiplier *float64) *Refusal {
	for _, z := range b.zones {
		if z.capacity <= 0 || z.capacity > z.rangeMax || z.capacity < z.rangeMin {
			return refuse(StageBounds, ReasonOutOfBounds)
		}
		if multiplier != nil && z.capacity*(*multiplier) > z.rangeMax {
			return refuse(StageBounds, ReasonOutOfBounds)
		}
	}
	return nil
}

func stDisambiguation(b *parsedBinding) *Refusal {
	sensors := map[string]bool{}
	actuators := map[string]bool{}
	for _, z := range b.zones {
		if sensors[z.sensorID] || actuators[z.ref.key()] {
			return refuse(StageDisambiguation, ReasonAmbiguousBinding)
		}
		sensors[z.sensorID] = true
		actuators[z.ref.key()] = true
	}
	return nil
}

func stInventory(b *parsedBinding, ctx Context) *Refusal {
	declaredSensors := map[string]bool{}
	for _, id := range ctx.DeclaredSensorIDs {
		declaredSensors[id] = true
	}
	declaredActuators := map[string]bool{}
	for _, a := range ctx.DeclaredActuators {
		declaredActuators[a.key()] = true
	}
	bound := map[string]bool{}
	for _, z := range b.zones {
		if !declaredSensors[z.sensorID] || !declaredActuators[z.ref.key()] {
			return refuse(StageInventory, ReasonUnknownHardware)
		}
		bound[z.ref.key()] = true
	}
	for key := range declaredActuators {
		if !bound[key] {
			return refuse(StageInventory, ReasonUnboundActuator)
		}
	}
	return nil
}

func stActivationPosture(b *parsedBinding, posture string) *Refusal {
	if posture == "development" {
		return nil
	}
	for _, z := range b.zones {
		if z.method == MethodUnproven {
			return refuse(StageActivationPosture, ReasonUndemonstratedBinding)
		}
	}
	return nil
}

// checkDocument runs the stages that depend on nothing outside the document:
// the grammar, the mapping's self-consistency, the proof against the mapping,
// the capacity bounds, and disambiguation. The producer runs these before
// signing so that what a consumer would refuse is refused where it was made.
func checkDocument(body map[string]any, multiplier *float64) (*parsedBinding, *Refusal) {
	b, r := stParses(body)
	if r != nil {
		return nil, r
	}
	if r := stMappingSelfConsistency(b); r != nil {
		return nil, r
	}
	if r := stProofConsistency(b, nil); r != nil {
		return nil, r
	}
	if r := stBounds(b, multiplier); r != nil {
		return nil, r
	}
	if r := stDisambiguation(b); r != nil {
		return nil, r
	}
	return b, nil
}

func (b *parsedBinding) accepted(signature string) *Accepted {
	sum := sha256.Sum256(b.canonical)
	out := &Accepted{
		BindingSeq:          b.seq,
		CanonicalHash:       "sha256:" + hex.EncodeToString(sum[:]),
		InventoryGeneration: b.inventoryGeneration,
		DeviceID:            b.deviceID,
		SignerID:            b.signerID,
		IssuedAtMs:          b.issuedAtMs,
		Supersedes:          b.supersedes,
		CanonicalBytes:      b.canonical,
		Signature:           signature,
	}
	for _, z := range b.zones {
		out.Zones = append(out.Zones, AcceptedZone{
			ZoneID:             z.zoneID,
			SensorID:           z.sensorID,
			Kind:               z.kind,
			Identity:           z.identity,
			Mapping:            z.mapping,
			CalibrationRef:     z.calibrationRef,
			ProofMethod:        z.method,
			ProofPerformedAtMs: z.performedAtMs,
			RatedCapacity:      z.capacity,
		})
	}
	return out
}

// VerifyEnvelope verifies a binding envelope's wire bytes through the
// contract's twelve stages in order. A non-nil error is always a *Refusal.
func VerifyEnvelope(raw []byte, ctx Context) (*Accepted, error) {
	body, sig, sigText, r := parseEnvelope(raw, "binding")
	if r != nil {
		return nil, r
	}
	b, r := stParses(body)
	if r != nil {
		return nil, r
	}
	if b.deviceID != ctx.DeviceID {
		return nil, refuse(StageDeviceID, ReasonWrongDevice)
	}
	keys := anchors{
		current:      ctx.CommissioningAnchorCurrent,
		previous:     ctx.CommissioningAnchorPrevious,
		provisioning: ctx.ProvisioningAnchor,
	}
	if r := keys.selectKey(b.signingKey); r != nil {
		return nil, r
	}
	if r := verifySignature(b.signingKey, b.canonical, sig); r != nil {
		return nil, r
	}
	if r := keys.authority(b.signingKey); r != nil {
		return nil, r
	}
	if b.seq <= ctx.AcceptedBindingSeq || !sameDigest(b.supersedes, ctx.AcceptedBindingHash) {
		return nil, refuse(StageFreshness, ReasonStale)
	}
	if r := stMappingSelfConsistency(b); r != nil {
		return nil, r
	}
	if r := stProofConsistency(b, ctx.AcceptedZoneState); r != nil {
		return nil, r
	}
	if r := stBounds(b, ctx.ProfileMultiplier); r != nil {
		return nil, r
	}
	if r := stDisambiguation(b); r != nil {
		return nil, r
	}
	if r := stInventory(b, ctx); r != nil {
		return nil, r
	}
	if r := stActivationPosture(b, ctx.DeploymentPosture); r != nil {
		return nil, r
	}
	return b.accepted(sigText), nil
}

func sameDigest(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// ── firmware profile ────────────────────────────────────────────────────

// VerifyProfileEnvelope verifies a firmware-profile envelope through the
// contract's seven profile stages. A non-nil error is always a *Refusal.
func VerifyProfileEnvelope(raw []byte, ctx ProfileContext) error {
	body, sig, _, r := parseEnvelope(raw, "firmware_profile")
	if r != nil {
		return r
	}
	obj, ok := closed(body, profileKeys)
	if !ok {
		return malformed()
	}
	if v, ok := whole(obj["v"]); !ok || v != 1 {
		return malformed()
	}
	for _, name := range []string{"device_id", "firmware_device_id", "channel"} {
		if _, ok = text(obj[name]); !ok {
			return malformed()
		}
	}
	seq, ok := whole(obj["binding_seq"])
	if !ok || seq < 1 {
		return malformed()
	}
	hash, ok := digest(obj["binding_hash"])
	if !ok {
		return malformed()
	}
	named, ok := rawKey(obj["signing_key"])
	if !ok {
		return malformed()
	}
	mapping, ok := parseMapping(obj["commissioned_mapping"])
	if !ok {
		return malformed()
	}
	canonical, err := canonicaljson.Marshal(body)
	if err != nil {
		return malformed()
	}

	if obj["firmware_device_id"].(string) != ctx.FirmwareDeviceID {
		return refuse(StageDeviceBinding, ReasonWrongDevice)
	}
	if obj["channel"].(string) != ctx.Channel {
		return refuse(StageDeviceBinding, ReasonProfileChannelMismatch)
	}
	keys := anchors{
		current:      ctx.CommissioningAnchorCurrent,
		previous:     ctx.CommissioningAnchorPrevious,
		provisioning: ctx.ProvisioningAnchor,
	}
	if r := keys.selectKey(named); r != nil {
		return r
	}
	if r := verifySignature(named, canonical, sig); r != nil {
		return r
	}
	if r := keys.authority(named); r != nil {
		return r
	}
	if ctx.AcceptedBindingHash == nil || hash != *ctx.AcceptedBindingHash || seq != ctx.AcceptedBindingSeq {
		return refuse(StageBindingMatch, ReasonProfileBindingMismatch)
	}
	if mapping != ctx.ExpectedMapping {
		return refuse(StageMappingMatch, ReasonProfileMappingMismatch)
	}
	return nil
}
