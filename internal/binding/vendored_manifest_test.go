// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestVendoredVectorsAreThePublishedArtifactsAtThePinnedRevision holds the
// vendored directory to its manifest. This is a local-edit check only: upstream
// drift is the refresh script's job, because only it can see ori-specs.
func TestVendoredVectorsAreThePublishedArtifactsAtThePinnedRevision(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(corpusDir, "MANIFEST.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest struct {
		SourceRepository string            `json:"source_repository"`
		SourceCommit     string            `json:"source_commit"`
		Files            map[string]string `json:"files"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.SourceRepository != "ori-platform/ori-specs" {
		t.Errorf("the manifest names %q as its source, not ori-platform/ori-specs", manifest.SourceRepository)
	}
	if manifest.SourceCommit == "" {
		t.Error("the manifest pins no source_commit")
	}
	paths, err := filepath.Glob(filepath.Join(corpusDir, "*.json"))
	if err != nil {
		t.Fatalf("list vendored files: %v", err)
	}
	var present []string
	for _, path := range paths {
		if name := filepath.Base(path); name != "MANIFEST.json" {
			present = append(present, name)
			if _, ok := manifest.Files[name]; !ok {
				t.Errorf("%s is vendored but not in the manifest; re-vendor with "+
					"scripts/refresh-binding-vectors.sh rather than adding it here", name)
			}
		}
	}
	if len(present) == 0 {
		t.Fatal("no vendored files: the manifest would hold nothing")
	}
	names := make([]string, 0, len(manifest.Files))
	for name := range manifest.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(corpusDir, name))
		if err != nil {
			t.Errorf("%s is in the manifest but cannot be read (%v); re-vendor with "+
				"scripts/refresh-binding-vectors.sh", name, err)
			continue
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != manifest.Files[name] {
			t.Errorf("the vendored %s has been edited locally (sha256 %s, manifest %s); "+
				"re-vendor with scripts/refresh-binding-vectors.sh rather than editing it here",
				name, got, manifest.Files[name])
		}
	}
}
