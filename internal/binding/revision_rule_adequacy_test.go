// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ori-platform/ori-cli/internal/binding"
)

// The corpus must refuse every wrong reading of the revision rule, not only
// agree with this verifier: a consumer that read the rule one of these ways
// would otherwise pass every case. The readings are ori-specs'
// revision-misreadings-v1.json, vendored beside the corpus under the same pin,
// so the contract's checker, the runtime's harness and this test hold the
// corpus to one table. It guards those misreadings and no others.
const misreadingsFile = "revision-misreadings-v1.json"

type misreadingTable struct {
	Reference     map[string]json.RawMessage            `json:"reference"`
	ChangeEvents  map[string][]string                   `json:"change_events"`
	Misreadings   map[string]map[string]json.RawMessage `json:"misreadings"`
	referenceRule binding.RevisionRule
}

func loadMisreadingTable(t *testing.T) misreadingTable {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusDir, misreadingsFile))
	if err != nil {
		t.Fatalf("read misreading table: %v", err)
	}
	var table misreadingTable
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatalf("decode misreading table: %v", err)
	}
	for name := range revisionSwitches(&binding.RevisionRule{}) {
		if _, ok := table.Reference[name]; !ok {
			t.Fatalf("the table's reference omits the switch %q", name)
		}
	}
	if err := applySwitches(&table.referenceRule, table.Reference); err != nil {
		t.Fatalf("the table's reference: %v", err)
	}
	return table
}

// revisionSwitches maps each switch name in the table to a setter on rule.
func revisionSwitches(rule *binding.RevisionRule) map[string]func(json.RawMessage) error {
	strict := func(raw json.RawMessage, into any) error {
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		return dec.Decode(into)
	}
	flag := func(field *bool) func(json.RawMessage) error {
		return func(raw json.RawMessage) error { return strict(raw, field) }
	}
	text := func(field *string) func(json.RawMessage) error {
		return func(raw json.RawMessage) error { return strict(raw, field) }
	}
	// A pair list decodes into leg:value keys; empty leaves the switch unset.
	pairs := func(field *map[string]bool) func(json.RawMessage) error {
		return func(raw json.RawMessage) error {
			var list [][2]string
			if err := strict(raw, &list); err != nil {
				return err
			}
			*field = nil
			for _, pair := range list {
				if *field == nil {
					*field = map[string]bool{}
				}
				(*field)[pair[0]+":"+pair[1]] = true
			}
			return nil
		}
	}
	return map[string]func(json.RawMessage) error{
		"match_name":                             flag(&rule.MatchName),
		"match_actuator":                         flag(&rule.MatchActuator),
		"match_sensor":                           flag(&rule.MatchSensor),
		"sensor_match":                           text(&rule.SensorMatch),
		"gpio_match":                             text(&rule.GPIOMatch),
		"firmware_match":                         text(&rule.FirmwareMatch),
		"change_identity":                        flag(&rule.ChangeIdentity),
		"identity_compare":                       text(&rule.IdentityCompare),
		"change_mapping":                         flag(&rule.ChangeMapping),
		"change_sensor":                          text(&rule.ChangeSensor),
		"rename_is_change":                       flag(&rule.RenameIsChange),
		"visit":                                  text(&rule.Visit),
		"circuit_unclaimed_exempt":               flag(&rule.CircuitUnclaimedExempt),
		"circuit_skip_if_control_fresh":          flag(&rule.CircuitSkipIfControlFresh),
		"circuit_only_single_match":              flag(&rule.CircuitOnlySingleMatch),
		"circuit_strict":                         flag(&rule.CircuitStrict),
		"control_requires_claim":                 flag(&rule.ControlRequiresClaim),
		"control_on":                             text(&rule.ControlOn),
		"control_skip_if_circuit_unclaimed":      flag(&rule.ControlSkipIfCircuitUnclaimed),
		"control_missing":                        text(&rule.ControlMissing),
		"control_strict":                         flag(&rule.ControlStrict),
		"one_to_one":                             flag(&rule.OneToOne),
		"control_only_single_match":              flag(&rule.ControlOnlySingleMatch),
		"circuit_skip_if_control_unclaimed":      flag(&rule.CircuitSkipIfControlUnclaimed),
		"control_absent_stale":                   flag(&rule.ControlAbsentStale),
		"single_retained_time":                   flag(&rule.SingleRetainedTime),
		"fresh_against_every_match_once_changed": flag(&rule.FreshAgainstEveryMatchOnceChanged),
		"proof_change_is_change":                 flag(&rule.ProofChangeIsChange),
		"claimed_methods":                        text(&rule.ClaimedMethods),
		"circuit_retained_time":                  text(&rule.CircuitRetainedTime),
		"control_retained_time":                  text(&rule.ControlRetainedTime),
		"exempt_control_behind_pre_energisation": flag(&rule.ExemptControlBehindPreEnergisation),
		"exempt":                                 pairs(&rule.Exempt),
		"exempt_postures":                        pairs(&rule.ExemptPostures),
		"exempt_sets": func(raw json.RawMessage) error {
			var list [][2]json.RawMessage
			if err := strict(raw, &list); err != nil {
				return err
			}
			rule.ExemptSets = nil
			for _, entry := range list {
				var set binding.ExemptSet
				if err := strict(entry[0], &set.Leg); err != nil {
					return err
				}
				if err := strict(entry[1], &set.Fields); err != nil {
					return err
				}
				rule.ExemptSets = append(rule.ExemptSets, set)
			}
			return nil
		},
		"exempt_at_least": func(raw json.RawMessage) error {
			var list [][2]json.RawMessage
			if err := strict(raw, &list); err != nil {
				return err
			}
			rule.ExemptAtLeast = nil
			for _, entry := range list {
				var leg string
				var k int
				if err := strict(entry[0], &leg); err != nil {
					return err
				}
				if err := strict(entry[1], &k); err != nil {
					return err
				}
				if rule.ExemptAtLeast == nil {
					rule.ExemptAtLeast = map[string]int{}
				}
				rule.ExemptAtLeast[leg] = k
			}
			return nil
		},
		"exempt_kind_change": func(raw json.RawMessage) error {
			var kinds []string
			if err := strict(raw, &kinds); err != nil {
				return err
			}
			rule.ExemptKindChange = nil
			for _, kind := range kinds {
				if rule.ExemptKindChange == nil {
					rule.ExemptKindChange = map[string]bool{}
				}
				rule.ExemptKindChange[kind] = true
			}
			return nil
		},
	}
}

// applySwitches sets each named switch on rule, refusing a name it does not know.
func applySwitches(rule *binding.RevisionRule, switches map[string]json.RawMessage) error {
	setters := revisionSwitches(rule)
	names := make([]string, 0, len(switches))
	for name := range switches {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		set, ok := setters[name]
		if !ok {
			return fmt.Errorf("unknown switch %q", name)
		}
		if err := set(switches[name]); err != nil {
			return fmt.Errorf("switch %q: %w", name, err)
		}
	}
	return nil
}

// casesGotWrong lists the corpus cases a reading of the rule decides wrongly.
func casesGotWrong(t *testing.T, c fullCorpus, rule binding.RevisionRule) []string {
	t.Helper()
	var wrong []string
	for _, vc := range c.Cases {
		env := envelopeBytes("binding", vc.Binding, vc.SignatureB64)
		if _, err := binding.VerifyWithRule(env, bindingContext(t, vc.VerifierContext), rule); err != nil {
			wrong = append(wrong, vc.Name)
		}
	}
	for _, rc := range c.RejectCases {
		env := envelopeBytes("binding", rc.Binding, rc.SignatureB64)
		_, err := binding.VerifyWithRule(env, bindingContext(t, rc.VerifierContext), rule)
		var r *binding.Refusal
		if !errors.As(err, &r) || r.Stage != rc.Stage || r.Reason != rc.Reason {
			wrong = append(wrong, rc.Name)
		}
	}
	return wrong
}

// The table's reference reading must be the verifier's, or a surviving
// misreading proves nothing about the corpus. It must also be the reference
// the seeded comparison with the production rule uses.
func TestTheReferenceRuleAgreesWithTheWholeCorpus(t *testing.T) {
	table := loadMisreadingTable(t)
	if !reflect.DeepEqual(table.referenceRule, binding.ReferenceRule) {
		t.Fatalf("the table's reference %+v is not ReferenceRule %+v", table.referenceRule, binding.ReferenceRule)
	}
	if wrong := casesGotWrong(t, loadFullCorpus(t), table.referenceRule); len(wrong) > 0 {
		t.Fatalf("the reference reading gets %d cases wrong: %v", len(wrong), wrong)
	}
}

// Every override must name a switch this test can set, or a misreading would
// run as the reference and pass for the wrong reason.
func TestTheMisreadingTableIsNonEmptyAndKnown(t *testing.T) {
	table := loadMisreadingTable(t)
	if len(table.Misreadings) == 0 {
		t.Fatal("the misreading table is empty: it would guard nothing")
	}
	for name, overrides := range table.Misreadings {
		if len(overrides) == 0 {
			t.Errorf("the misreading %q overrides no switch", name)
		}
		rule := table.referenceRule
		if err := applySwitches(&rule, overrides); err != nil {
			t.Errorf("the misreading %q: %v", name, err)
		}
	}
}

func TestAnUnknownSwitchIsRefused(t *testing.T) {
	rule := binding.ReferenceRule
	err := applySwitches(&rule, map[string]json.RawMessage{"no_such_switch": json.RawMessage("true")})
	if err == nil {
		t.Fatal("an unknown switch was accepted")
	}
}

func TestTheCorpusRefusesEveryMisreadingOfTheRule(t *testing.T) {
	c := loadFullCorpus(t)
	table := loadMisreadingTable(t)
	if len(table.Misreadings) == 0 {
		t.Fatal("the misreading table is empty: it would guard nothing")
	}
	events := make([]string, 0, len(table.ChangeEvents))
	for name := range table.ChangeEvents {
		events = append(events, name)
	}
	sort.Strings(events)
	names := make([]string, 0, len(table.Misreadings))
	for name := range table.Misreadings {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			rule := table.referenceRule
			if err := applySwitches(&rule, table.Misreadings[name]); err != nil {
				t.Fatalf("the misreading %q: %v", name, err)
			}
			if len(casesGotWrong(t, c, rule)) == 0 {
				t.Fatalf("no vector refuses the misreading %q: a consumer that read the "+
					"revision rule this way would pass every case. Add a vector it gets "+
					"wrong. This guard covers only the misreadings in %s; exemptions keyed "+
					"on a set of fields grow exponentially, so only the change_events sets "+
					"(%s) are enumerated.", name, misreadingsFile, strings.Join(events, ", "))
			}
		})
	}
}
