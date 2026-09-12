// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ori-platform/ori-cli/internal/binding"
)

const signCorpusPath = "../internal/binding/testdata/vectors/commissioned_safety_binding/binding-vectors-v1.json"

type signCorpusCase struct {
	Name            string          `json:"name"`
	Binding         json.RawMessage `json:"binding"`
	CanonicalHex    string          `json:"canonical_hex"`
	CanonicalSHA256 string          `json:"canonical_sha256"`
	SignatureB64    string          `json:"signature_b64"`
	Stage           string          `json:"stage"`
	Reason          string          `json:"reason"`
	SignatureValid  bool            `json:"signature_valid"`
	VerifierContext struct {
		DeviceID          string  `json:"device_id"`
		DeploymentPosture string  `json:"deployment_posture"`
		ProfileMultiplier float64 `json:"profile_multiplier"`
		DeclaredInventory struct {
			SensorIDs []string `json:"sensor_ids"`
			Actuators []struct {
				Kind     string `json:"kind"`
				Identity struct {
					GPIOPin          int64  `json:"gpio_pin"`
					FirmwareDeviceID string `json:"firmware_device_id"`
					Channel          string `json:"channel"`
				} `json:"identity"`
			} `json:"actuators"`
		} `json:"declared_inventory"`
	} `json:"verifier_context"`
}

type signCorpus struct {
	SeedHex     string           `json:"commissioning_test_seed_hex"`
	Cases       []signCorpusCase `json:"cases"`
	RejectCases []signCorpusCase `json:"reject_cases"`
}

func loadSignCorpus(t *testing.T) signCorpus {
	t.Helper()
	raw, err := os.ReadFile(signCorpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c signCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

func (c signCorpus) acceptCase(t *testing.T, name string) signCorpusCase {
	t.Helper()
	for _, vc := range c.Cases {
		if vc.Name == name {
			return vc
		}
	}
	t.Fatalf("no accept case %q", name)
	return signCorpusCase{}
}

func (c signCorpus) rejectCase(t *testing.T, name string) signCorpusCase {
	t.Helper()
	for _, vc := range c.RejectCases {
		if vc.Name == name {
			return vc
		}
	}
	t.Fatalf("no reject case %q", name)
	return signCorpusCase{}
}

// publishedEnvelope is the bytes sign must write for a corpus case.
func (vc signCorpusCase) publishedEnvelope(t *testing.T) []byte {
	t.Helper()
	canonical, err := hex.DecodeString(vc.CanonicalHex)
	if err != nil {
		t.Fatalf("canonical_hex: %v", err)
	}
	return []byte(`{"binding":` + string(canonical) + `,"signature":"ed25519:` + vc.SignatureB64 + `"}` + "\n")
}

func writeTemp(t *testing.T, dir, name string, body []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", name, err)
	}
	return path
}

// strippedOfOwnedFields turns a published binding into the draft capture would
// have written for it: the fields signing owns removed.
func strippedOfOwnedFields(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("parse binding: %v", err)
	}
	for _, name := range []string{"issued_at_ms", "signer_id", "signing_key", "actor", "reason"} {
		delete(fields, name)
	}
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("re-encode draft: %v", err)
	}
	return out
}

func ownedField(t *testing.T, raw json.RawMessage, name string) string {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("parse binding: %v", err)
	}
	value, ok := fields[name].(string)
	if !ok {
		t.Fatalf("%s is not a string", name)
	}
	return value
}

func issuedAt(t *testing.T, raw json.RawMessage) int64 {
	t.Helper()
	var fields struct {
		IssuedAtMs int64 `json:"issued_at_ms"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("parse binding: %v", err)
	}
	return fields.IssuedAtMs
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("%s exists after a refusal (err=%v)", path, err)
	}
}

func TestSignReproducesCorpusSignature(t *testing.T) {
	c := loadSignCorpus(t)
	for _, vc := range c.Cases {
		t.Run(vc.Name, func(t *testing.T) {
			dir := t.TempDir()
			in := writeTemp(t, dir, "binding.json", vc.Binding, 0o600)
			key := writeTemp(t, dir, "key", []byte(c.SeedHex+"\n"), 0o600)
			out := filepath.Join(dir, "signed.json")

			code, stdout, stderr := runWithOptions([]string{
				"--json", "binding", "sign", "--in", in, "--key", key, "--out", out,
			}, Options{})
			if code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			written, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("read envelope: %v", err)
			}
			if !bytes.Equal(written, vc.publishedEnvelope(t)) {
				t.Fatalf("the envelope is not the published bytes:\n got %s\nwant %s",
					written, vc.publishedEnvelope(t))
			}
			var report struct {
				OK     bool `json:"ok"`
				Result struct {
					Signature       string   `json:"signature"`
					CanonicalSHA256 string   `json:"canonical_sha256"`
					Path            string   `json:"path"`
					Offline         []string `json:"verified_offline"`
					Delivery        []string `json:"decided_at_delivery"`
					Deferred        []string `json:"deferred_to_delivery"`
				} `json:"result"`
			}
			if err := json.Unmarshal([]byte(stdout), &report); err != nil {
				t.Fatalf("report is not one JSON object: %v\n%s", err, stdout)
			}
			if !report.OK || report.Result.Signature != "ed25519:"+vc.SignatureB64 ||
				report.Result.CanonicalSHA256 != vc.CanonicalSHA256 || report.Result.Path != out {
				t.Fatalf("report does not describe the published signature: %s", stdout)
			}
			if strings.Join(report.Result.Offline, ",") != strings.Join(binding.OfflineStages, ",") ||
				strings.Join(report.Result.Delivery, ",") != strings.Join(binding.DeliveryStages, ",") ||
				strings.Join(report.Result.Deferred, ";") != strings.Join(binding.DeferredChecks, ";") {
				t.Fatalf("the JSON verdict does not draw the delivery boundary: %s", stdout)
			}
			info, err := os.Stat(out)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("envelope mode %v, err %v", info.Mode(), err)
			}
		})
	}
}

func TestSignRefusesForeignKey(t *testing.T) {
	c := loadSignCorpus(t)
	vc := c.Cases[0]
	dir := t.TempDir()
	in := writeTemp(t, dir, "binding.json", vc.Binding, 0o600)
	foreignSeed := strings.Repeat("44", ed25519.SeedSize)
	key := writeTemp(t, dir, "key", []byte(foreignSeed), 0o600)
	out := filepath.Join(dir, "signed.json")

	code, stdout, stderr := runWithOptions([]string{
		"binding", "sign", "--in", in, "--key", key, "--out", out,
	}, Options{})
	if code != 2 {
		t.Fatalf("a foreign key exited %d, not 2: %s%s", code, stdout, stderr)
	}
	named := ownedField(t, vc.Binding, "signing_key")
	foreign := binding.SigningKeyName(ed25519.NewKeyFromSeed(mustHex(t, foreignSeed)).Public().(ed25519.PublicKey))
	if !strings.Contains(stderr, named) || !strings.Contains(stderr, foreign) {
		t.Fatalf("the mismatch is not named with both keys: %s", stderr)
	}
	if strings.Contains(stdout+stderr, foreignSeed) {
		t.Fatal("the private key material was echoed")
	}
	mustNotExist(t, out)

	// A draft names no key, so whichever key signs it is the key it records.
	draft := writeTemp(t, dir, "draft.json", strippedOfOwnedFields(t, vc.Binding), 0o600)
	code, stdout, stderr = runWithOptions([]string{
		"--json", "binding", "sign", "--in", draft, "--key", key,
		"--signer-id", "s", "--actor", "a", "--reason", "r",
	}, Options{})
	if code != 0 {
		t.Fatalf("a draft signed by another key exited %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, foreign) {
		t.Fatalf("the draft did not record the key that signed it: %s", stdout)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignRefusesIncompleteDocument(t *testing.T) {
	c := loadSignCorpus(t)
	full := c.Cases[0].Binding
	draft := strippedOfOwnedFields(t, full)
	withNull := bytes.Replace(draft, []byte(`{`), []byte(`{"actor":null,`), 1)
	withUnknown := bytes.Replace(draft, []byte(`{`), []byte(`{"derived_from":"x",`), 1)
	withDuplicate := bytes.Replace(draft, []byte(`{`), []byte(`{"v":1,`), 1)
	transposed := c.rejectCase(t, "transposed_binding")
	unproven := strippedOfOwnedFields(t, c.acceptCase(t, "undemonstrated_zone_accepted_in_development").Binding)
	// Renamed rather than deleted, so the member is absent whatever the
	// surrounding spelling; the unknown name is refused only after presence.
	withoutRangeMin := bytes.Replace(draft, []byte(`"range_min"`), []byte(`"range_min_x"`), 1)
	withoutLoadBefore := bytes.Replace(draft, []byte(`"load_present_before"`), []byte(`"load_present_before_x"`), 1)
	withoutPerformedAt := bytes.Replace(unproven, []byte(`"performed_at_ms"`), []byte(`"performed_at_ms_x"`), 1)
	withoutObservations := bytes.Replace(unproven, []byte(`"observations"`), []byte(`"observations_x"`), 1)
	withoutReason := bytes.Replace(unproven, []byte(`"reason":"borehole`), []byte(`"reason_x":"borehole`), 1)
	for name, mutated := range map[string][]byte{
		"range_min": withoutRangeMin, "load_present_before": withoutLoadBefore,
		"performed_at_ms": withoutPerformedAt, "observations": withoutObservations,
		"reason": withoutReason,
	} {
		if bytes.Equal(mutated, draft) || bytes.Equal(mutated, unproven) {
			t.Fatalf("the %s removal did not land", name)
		}
	}
	filled := []string{"--signer-id", "s", "--actor", "a", "--reason", "r"}
	cases := []struct {
		name  string
		body  []byte
		flags []string
		names string
	}{
		{"draft without the fields signing owns", draft, nil, "carries no signer_id"},
		{"draft missing only a reason", draft, []string{"--signer-id", "s", "--actor", "a"}, "carries no reason"},
		{"owned field written as null", withNull, []string{"--signer-id", "s", "--actor", "a", "--reason", "r"}, "actor is null"},
		{"unknown field", withUnknown, nil, "derived_from"},
		{"duplicated key", withDuplicate, nil, "repeats a key"},
		{"empty file", nil, nil, "not readable"},
		{"truncated", []byte(`{"v":1,`), nil, "not readable"},
		{"array", []byte(`[]`), nil, "not readable"},
		{"null", []byte(`null`), nil, "not a JSON object"},
		{"object with nothing in it", []byte(`{}`), []string{"--signer-id", "s", "--actor", "a", "--reason", "r"}, "v is absent"},
		{"trailing bytes", append(append([]byte{}, draft...), []byte(` {}`)...), nil, "after its closing brace"},
		{"invalid utf-8", append([]byte(`{"device_id":"`), append([]byte{0xff}, []byte(`"}`)...)...), nil, "not valid JSON text"},
		{"contradicted proof", transposed.Binding, nil, transposed.Stage + ": " + transposed.Reason},
		// Absent members that a typed decode would read as zero values and
		// canonical encoding would then write as facts.
		{"sensor without a range_min", withoutRangeMin, filled, "sensor.range_min is absent"},
		{"observation without load_present_before", withoutLoadBefore, filled, "observations[0].load_present_before is absent"},
		{"undemonstrated proof without performed_at_ms", withoutPerformedAt, filled, "proof.performed_at_ms is absent"},
		{"undemonstrated proof without its empty observations", withoutObservations, filled, "proof.observations is absent"},
		{"undemonstrated proof without a reason", withoutReason, filled, "proof.reason is absent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in := writeTemp(t, dir, "in.json", tc.body, 0o600)
			key := writeTemp(t, dir, "key", []byte(c.SeedHex), 0o600)
			out := filepath.Join(dir, "signed.json")
			args := append([]string{"binding", "sign", "--in", in, "--key", key, "--out", out}, tc.flags...)
			code, stdout, stderr := runWithOptions(args, Options{})
			if code != 2 {
				t.Fatalf("exit %d, not 2: %s%s", code, stdout, stderr)
			}
			if !strings.Contains(stderr, tc.names) {
				t.Fatalf("refusal does not name %q: %s", tc.names, stderr)
			}
			mustNotExist(t, out)
		})
	}
}

func TestSignedEnvelopeVerifies(t *testing.T) {
	c := loadSignCorpus(t)
	vc := c.acceptCase(t, "pre_energisation_proof_accepted")
	dir := t.TempDir()
	draft := writeTemp(t, dir, "draft.json", strippedOfOwnedFields(t, vc.Binding), 0o600)
	key := writeTemp(t, dir, "key", []byte(c.SeedHex), 0o600)
	out := filepath.Join(dir, "signed.json")

	code, stdout, stderr := runWithOptions([]string{
		"binding", "sign", "--in", draft, "--key", key, "--out", out,
		"--signer-id", ownedField(t, vc.Binding, "signer_id"),
		"--actor", ownedField(t, vc.Binding, "actor"),
		"--reason", ownedField(t, vc.Binding, "reason"),
	}, Options{NowMs: func() int64 { return issuedAt(t, vc.Binding) }})
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, stdout, stderr)
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, vc.publishedEnvelope(t)) {
		t.Fatalf("filling a draft did not rebuild the published envelope:\n%s", written)
	}
	for _, stage := range binding.OfflineStages {
		if !strings.Contains(stdout, stage) {
			t.Fatalf("the report does not say %s was verified: %s", stage, stdout)
		}
	}
	for _, stage := range binding.DeliveryStages {
		if !strings.Contains(stdout, stage) {
			t.Fatalf("the report does not say %s is decided at delivery: %s", stage, stdout)
		}
	}
	for _, check := range binding.DeferredChecks {
		if !strings.Contains(stdout, check) {
			t.Fatalf("the report does not name the deferred check %q: %s", check, stdout)
		}
	}

	// The runtime's own verdict on the file, through every stage.
	pub := ed25519.NewKeyFromSeed(mustHex(t, c.SeedHex)).Public().(ed25519.PublicKey)
	ctx := binding.Context{
		DeviceID:                   vc.VerifierContext.DeviceID,
		CommissioningAnchorCurrent: pub,
		DeclaredSensorIDs:          vc.VerifierContext.DeclaredInventory.SensorIDs,
		DeploymentPosture:          vc.VerifierContext.DeploymentPosture,
		ProfileMultiplier:          &vc.VerifierContext.ProfileMultiplier,
	}
	for _, a := range vc.VerifierContext.DeclaredInventory.Actuators {
		ctx.DeclaredActuators = append(ctx.DeclaredActuators, binding.ActuatorRef{
			Kind: a.Kind, GPIOPin: a.Identity.GPIOPin,
			FirmwareDeviceID: a.Identity.FirmwareDeviceID, Channel: a.Identity.Channel,
		})
	}
	accepted, verifyErr := binding.VerifyEnvelope(written, ctx)
	if verifyErr != nil {
		t.Fatalf("the runtime verifier refused what sign wrote: %v", verifyErr)
	}
	if accepted.CanonicalHash != vc.CanonicalSHA256 {
		t.Fatalf("accepted hash %s, published %s", accepted.CanonicalHash, vc.CanonicalSHA256)
	}
}

func TestKeyNeverFromFlagOrEnvironment(t *testing.T) {
	c := loadSignCorpus(t)
	dir := t.TempDir()
	in := writeTemp(t, dir, "binding.json", c.Cases[0].Binding, 0o600)
	out := filepath.Join(dir, "signed.json")
	t.Setenv("ORI_SIGNING_KEY", c.SeedHex)
	t.Setenv("ORI_COMMISSIONING_KEY", c.SeedHex)
	t.Setenv("ORI_KEY", c.SeedHex)

	key := writeTemp(t, dir, "key", []byte(c.SeedHex), 0o600)
	cases := []struct {
		name string
		args []string
	}{
		{"seed as the --key value", []string{"--key", c.SeedHex}},
		{"pem as the --key value", []string{"--key", "-----BEGIN PRIVATE KEY-----\n" + c.SeedHex}},
		{"path that does not exist, named after the seed", []string{"--key", filepath.Join(dir, c.SeedHex[:40])}},
		{"environment only", nil},
		{"both --key and --key-fd", []string{"--key", key, "--key-fd", "3"}},
		{"stdin named twice", []string{"--key-fd", "0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"binding", "sign", "--in", in, "--out", out}, tc.args...)
			if tc.name == "stdin named twice" {
				args = append([]string{"binding", "sign", "--in", "-", "--out", out}, tc.args...)
			}
			code, stdout, stderr := runWithOptions(args, Options{})
			if code == 0 {
				t.Fatalf("signed without a key file: %s", stdout)
			}
			if strings.Contains(stdout+stderr, c.SeedHex[:40]) {
				t.Fatalf("the key material was echoed: %s%s", stdout, stderr)
			}
			mustNotExist(t, out)
		})
	}

	// The flag set itself: every flag the command has is listed, so a later
	// addition that takes key material as a value has to be added here on
	// purpose, against the rule.
	var names []string
	for _, line := range strings.Split(newBindingSignCommand(&rootState{}).Flags().FlagUsages(), "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			names = append(names, strings.Fields(line[i:])[0])
		}
	}
	want := "--actor --control-path --force --in --key --key-fd --out --reason --signer-id"
	if strings.Join(names, " ") != want {
		t.Fatalf("the flag set changed; confirm no new flag carries key material:\n%v", names)
	}
}

func TestSignReadsTheKeyFromADescriptor(t *testing.T) {
	c := loadSignCorpus(t)
	vc := c.Cases[0]
	dir := t.TempDir()
	in := writeTemp(t, dir, "binding.json", vc.Binding, 0o600)
	out := filepath.Join(dir, "signed.json")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(c.SeedHex + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	defer r.Close()

	code, stdout, stderr := runWithOptions([]string{
		"binding", "sign", "--in", in, "--key-fd", fmtInt(int(r.Fd())), "--out", out,
	}, Options{})
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, stdout, stderr)
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, vc.publishedEnvelope(t)) {
		t.Fatalf("a key from a descriptor did not reproduce the published envelope")
	}
}

func fmtInt(n int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + itoa(n)) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestSignRefusesAKeyOthersCanRead(t *testing.T) {
	c := loadSignCorpus(t)
	dir := t.TempDir()
	in := writeTemp(t, dir, "binding.json", c.Cases[0].Binding, 0o600)
	out := filepath.Join(dir, "signed.json")
	shared := writeTemp(t, dir, "shared", []byte(c.SeedHex), 0o644)
	private := writeTemp(t, dir, "private", []byte(c.SeedHex), 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	garbage := writeTemp(t, dir, "garbage", []byte("not a key at all"), 0o600)
	pemOther := writeTemp(t, dir, "pem", []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600)

	cases := []struct {
		name, key, names string
	}{
		{"group and world readable", shared, "0600"},
		{"symbolic link", link, "symbolic link"},
		{"directory", dir, "not a regular file"},
		{"absent", filepath.Join(dir, "missing"), "failed to open the key: no such file"},
		{"unparseable", garbage, "neither a PKCS#8"},
		{"pem holding nothing", pemOther, "PKCS#8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runWithOptions([]string{
				"binding", "sign", "--in", in, "--key", tc.key, "--out", out,
			}, Options{})
			if code != 1 {
				t.Fatalf("exit %d, not 1: %s%s", code, stdout, stderr)
			}
			if !strings.Contains(stderr, tc.names) {
				t.Fatalf("error does not say %q: %s", tc.names, stderr)
			}
			if strings.Contains(stdout+stderr, c.SeedHex) {
				t.Fatal("the key material was echoed")
			}
			mustNotExist(t, out)
		})
	}
}

// legSplit takes the control leg off one zone of a published binding and
// returns the document without it plus the leg as export writes it.
func legSplit(t *testing.T, raw json.RawMessage, zoneID string) ([]byte, []byte) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var leg any
	for _, z := range doc["zones"].([]any) {
		zone := z.(map[string]any)
		if zone["zone_id"] != zoneID {
			continue
		}
		proof := zone["proof"].(map[string]any)
		leg = proof["control_path"]
		delete(proof, "control_path")
	}
	if leg == nil {
		t.Fatalf("zone %q carries no control leg to split off", zoneID)
	}
	without, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	legJSON, err := json.Marshal(leg)
	if err != nil {
		t.Fatal(err)
	}
	return without, legJSON
}

func TestSignAttachesAnExportedControlLeg(t *testing.T) {
	c := loadSignCorpus(t)
	vc := c.acceptCase(t, "local_gpio_control_path_proven_is_in_force")
	const zone = "main-distribution"
	dir := t.TempDir()
	without, leg := legSplit(t, vc.Binding, zone)
	in := writeTemp(t, dir, "assembled.json", without, 0o600)
	legPath := writeTemp(t, dir, "leg.json", leg, 0o600)
	key := writeTemp(t, dir, "key", []byte(c.SeedHex), 0o600)
	out := filepath.Join(dir, "signed.json")

	code, stdout, stderr := runWithOptions([]string{
		"binding", "sign", "--in", in, "--key", key, "--out", out,
		"--control-path", zone + "=" + legPath,
	}, Options{})
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, stdout, stderr)
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, vc.publishedEnvelope(t)) {
		t.Fatalf("attaching the exported leg did not rebuild the published envelope:\n%s", written)
	}

	full := writeTemp(t, dir, "full.json", vc.Binding, 0o600)
	refusals := []struct {
		name  string
		in    string
		spec  string
		names string
	}{
		{"zone already carrying a leg", full, zone + "=" + legPath, "already carries a control leg"},
		{"zone the document lacks", in, "borehole=" + legPath, "no zone \"borehole\""},
		{"spec without a file", in, zone, "not zone=file"},
		{"leg with an unknown field", in, zone + "=" + writeTemp(t, dir, "bad.json",
			[]byte(`{"method":"commanded_and_observed","performed_at_ms":1,"observations":[],"extra":1}`), 0o600), "extra"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			refusedOut := filepath.Join(t.TempDir(), "signed.json")
			code, stdout, stderr := runWithOptions([]string{
				"binding", "sign", "--in", tc.in, "--key", key, "--out", refusedOut,
				"--control-path", tc.spec,
			}, Options{})
			if code == 0 {
				t.Fatalf("signed: %s", stdout)
			}
			if !strings.Contains(stderr, tc.names) {
				t.Fatalf("refusal does not say %q: %s", tc.names, stderr)
			}
			mustNotExist(t, refusedOut)
		})
	}
}

func TestSignRefusesAFlagThatDisagreesWithTheDocument(t *testing.T) {
	c := loadSignCorpus(t)
	vc := c.Cases[0]
	dir := t.TempDir()
	in := writeTemp(t, dir, "binding.json", vc.Binding, 0o600)
	key := writeTemp(t, dir, "key", []byte(c.SeedHex), 0o600)
	out := filepath.Join(dir, "signed.json")

	code, _, stderr := runWithOptions([]string{
		"binding", "sign", "--in", in, "--key", key, "--out", out, "--actor", "someone else",
	}, Options{})
	if code != 2 || !strings.Contains(stderr, "does not rewrite") {
		t.Fatalf("a disagreeing --actor was applied: exit %d, %s", code, stderr)
	}
	mustNotExist(t, out)

	code, _, stderr = runWithOptions([]string{
		"binding", "sign", "--in", in, "--key", key, "--out", out, "--actor", "",
	}, Options{})
	if code != 2 || !strings.Contains(stderr, "--actor is empty") {
		t.Fatalf("an empty --actor was accepted: exit %d, %s", code, stderr)
	}
	mustNotExist(t, out)

	code, _, stderr = runWithOptions([]string{
		"binding", "sign", "--in", in, "--key", key, "--out", out,
		"--actor", ownedField(t, vc.Binding, "actor"),
	}, Options{})
	if code != 0 {
		t.Fatalf("an agreeing --actor was refused: %s", stderr)
	}
}

func TestSignWritesTheEnvelopeToStdoutWhenNoPathIsGiven(t *testing.T) {
	c := loadSignCorpus(t)
	vc := c.Cases[0]
	dir := t.TempDir()
	in := writeTemp(t, dir, "binding.json", vc.Binding, 0o600)
	key := writeTemp(t, dir, "key", []byte(c.SeedHex), 0o600)

	code, stdout, stderr := runWithOptions([]string{"binding", "sign", "--in", in, "--key", key}, Options{})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if stdout != string(vc.publishedEnvelope(t)) {
		t.Fatalf("stdout is not exactly the envelope:\n%s", stdout)
	}
	if !strings.Contains(stderr, "verified offline") {
		t.Fatalf("the report did not go to stderr: %s", stderr)
	}

	code, stdout, stderr = runWithOptions([]string{"--json", "binding", "sign", "--in", in, "--key", key}, Options{})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	decoder := json.NewDecoder(strings.NewReader(stdout))
	var report struct {
		Result struct {
			Envelope json.RawMessage `json:"envelope"`
		} `json:"result"`
	}
	if err := decoder.Decode(&report); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		t.Fatalf("more than one JSON object was emitted:\n%s", stdout)
	}
	if _, err := binding.VerifyOffline(report.Result.Envelope); err != nil {
		t.Fatalf("the embedded envelope does not verify: %v", err)
	}
}

func TestSignRefusesToOverwriteWithoutForce(t *testing.T) {
	c := loadSignCorpus(t)
	vc := c.Cases[0]
	dir := t.TempDir()
	in := writeTemp(t, dir, "binding.json", vc.Binding, 0o600)
	key := writeTemp(t, dir, "key", []byte(c.SeedHex), 0o600)
	out := writeTemp(t, dir, "signed.json", []byte("someone's envelope"), 0o644)

	code, _, stderr := runWithOptions([]string{"binding", "sign", "--in", in, "--key", key, "--out", out}, Options{})
	if code == 0 || !strings.Contains(stderr, "--force") {
		t.Fatalf("an existing envelope was replaced: exit %d, %s", code, stderr)
	}
	kept, _ := os.ReadFile(out)
	if string(kept) != "someone's envelope" {
		t.Fatal("the existing file was touched")
	}

	code, _, stderr = runWithOptions([]string{
		"binding", "sign", "--in", in, "--key", key, "--out", out, "--force",
	}, Options{})
	if code != 0 {
		t.Fatalf("--force did not replace: %s", stderr)
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("a replaced envelope kept mode %v", info.Mode())
	}
}

// The draft capture writes for a zone nobody could prove is the contract's
// shape, so signing it invents nothing.
func TestSignAcceptsTheDraftCaptureWritesForAnUndemonstratedZone(t *testing.T) {
	c := loadSignCorpus(t)
	dir := t.TempDir()
	key := writeTemp(t, dir, "key", []byte(c.SeedHex), 0o600)
	out := filepath.Join(dir, "signed.json")
	var stdout, stderr bytes.Buffer
	stub := &deadlineBridge{out: []byte(inventoryOK)}
	answers := "1\n1\nhigh\nenergised\nde_energised\nclosed\n" +
		"nameplate\n10\ncurrent\nampere\npositive_is_load_draw\n0\n100\n" +
		"0.05\nbench-2026-09-01\n1\nundemonstrated\nno load was wired at commissioning\n"
	draft := filepath.Join(dir, "draft.json")
	if err := runBindingCapture(
		stateWith(stub, &stdout, &stderr), strings.NewReader(answers), "ori.yaml", "main", draft, false,
	); err != nil {
		t.Fatalf("capture: %v\n%s", err, stderr.String())
	}
	code, signOut, signErr := runWithOptions([]string{
		"binding", "sign", "--in", draft, "--key", key, "--out", out,
		"--signer-id", "s", "--actor", "a", "--reason", "r",
	}, Options{})
	if code != 0 {
		t.Fatalf("the draft capture wrote was refused: exit %d\n%s%s", code, signOut, signErr)
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), `"method":"undemonstrated"`) ||
		!strings.Contains(string(written), `"performed_at_ms":1800000000000`) {
		t.Fatalf("the signed envelope does not carry the draft's undemonstrated proof as recorded: %s", written)
	}
}
