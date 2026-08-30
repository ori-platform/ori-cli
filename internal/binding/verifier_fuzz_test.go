// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding_test

import (
	"errors"
	"testing"

	"github.com/ori-platform/ori-cli/internal/binding"
)

// FuzzVerifyEnvelope holds the verifier to two properties over arbitrary
// bytes: it never panics, and it never accepts a document that is not one of
// the published signed ones. Ed25519 binds a signature to exact canonical
// bytes, so any accepted input must canonicalise to a document the corpus
// key actually signed; anything else accepted is a forgery of the grammar.
func FuzzVerifyEnvelope(f *testing.F) {
	c := loadFullCorpus(f)
	base := c.Cases[0]
	ctx := bindingContext(f, base.VerifierContext)
	signed := map[string]bool{}
	for _, vc := range c.Cases {
		signed[vc.CanonicalSHA256] = true
		f.Add(envelopeBytes("binding", vc.Binding, vc.SignatureB64))
	}
	for _, rc := range c.RejectCases {
		f.Add(envelopeBytes("binding", rc.Binding, rc.SignatureB64))
	}
	for _, ec := range c.EnvelopeRejectCases {
		f.Add([]byte(ec.Envelope))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		accepted, err := binding.VerifyEnvelope(raw, ctx)
		if err != nil {
			var r *binding.Refusal
			if !errors.As(err, &r) {
				t.Fatalf("error is not a *Refusal: %T", err)
			}
			return
		}
		if !signed[accepted.CanonicalHash] {
			t.Fatalf("accepted a document the corpus key never signed: %s", accepted.CanonicalHash)
		}
	})
}
