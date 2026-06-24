// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"sort"
	"testing"
)

// declaredTagConstants is every attest:* tag key constant declared in tags.go.
// The conformance test below locks this set to the canonical schema, so adding,
// removing, or renaming a constant without updating attest-tags-schema.json (and,
// in the same release, qualify's byte-identical copy) fails CI. This is the guard
// against the silent qualify↔attest drift described in qualify#32.
var declaredTagConstants = []string{
	TagCUITraining,
	TagCUITrainingExpiry,
	TagHIPAATraining,
	TagHIPAATrainingExpiry,
	TagAwarenessTraining,
	TagAwarenessTrainingExpiry,
	TagFERPATraining,
	TagFERPATrainingExpiry,
	TagITARTraining,
	TagITARTrainingExpiry,
	TagDataClassTraining,
	TagDataClassTrainingExpiry,
	TagResearchSecurityTraining,
	TagResearchSecurityExpiry,
	TagCOCCheckCurrent,
	TagCOCCheckExpiry,
	TagCountry,
	TagNIHApproval,
	TagNIHApprovalExpiry,
	TagNIHDUAIDs,
	TagLabID,
	TagAdminLevel,
	TagCUIExpiryLegacy,
}

// TestSchemaVersionMatchesCanonical guards that the Go SchemaVersion constant and
// the embedded canonical schema agree. The same assertion in qualify (against its
// byte-identical copy) is what makes SchemaVersion a meaningful cross-repo signal.
func TestSchemaVersionMatchesCanonical(t *testing.T) {
	s, err := LoadTagSchema()
	if err != nil {
		t.Fatalf("LoadTagSchema: %v", err)
	}
	if s.Version != SchemaVersion {
		t.Errorf("canonical schema version = %d, SchemaVersion const = %d — bump them together", s.Version, SchemaVersion)
	}
	if s.Namespace != "attest:" {
		t.Errorf("schema namespace = %q, want %q", s.Namespace, "attest:")
	}
}

// attestReadWriters are the schema writers whose tags attest itself reads via the
// principal resolver (training/identity from qualify, NIH approval from attest, the
// legacy key). attest declares a Go constant for each of THESE. The producer rows
// (vet/nitro/tpm) are read by ground's SCPs, not attest's resolver — they are
// governed by their own writers' conformance tests, per ADR 0003 ("each writer
// locks its own rows"). This is the writer-scoping that lets the schema be the
// complete namespace registry without forcing attest to declare tags it never reads.
var attestReadWriters = map[string]bool{"qualify": true, "attest": true, "legacy": true}

// TestDeclaredConstantsMatchSchema is the conformance test: the set of attest:* key
// constants attest declares must be exactly the set of *attest-read* keys in the
// canonical registry (writers in attestReadWriters) — no missing keys (attest can't
// read a tag it has no constant for) and no extra keys (a constant with no schema
// entry is undocumented drift). Producer-only rows are intentionally excluded.
func TestDeclaredConstantsMatchSchema(t *testing.T) {
	s, err := LoadTagSchema()
	if err != nil {
		t.Fatalf("LoadTagSchema: %v", err)
	}

	schemaKeys := make(map[string]bool)
	for _, e := range s.Tags {
		if !attestReadWriters[e.Writer] {
			continue // producer-only row (vet/nitro/tpm) — governed by that writer's repo
		}
		if e.Pattern {
			continue // a key family (no attest-read patterns today, but be explicit)
		}
		if schemaKeys[e.Key] {
			t.Errorf("duplicate key in schema: %q", e.Key)
		}
		schemaKeys[e.Key] = true
	}

	declared := make(map[string]bool, len(declaredTagConstants))
	for _, k := range declaredTagConstants {
		declared[k] = true
	}

	for k := range schemaKeys {
		if !declared[k] {
			t.Errorf("attest-read schema key %q has no attest constant — add it to tags.go and declaredTagConstants", k)
		}
	}
	for k := range declared {
		if !schemaKeys[k] {
			t.Errorf("attest constant %q is not an attest-read key in the canonical schema — fix attest-tags-schema.json (every repo) and bump SchemaVersion", k)
		}
	}

	if len(declaredTagConstants) != len(schemaKeys) {
		t.Errorf("count mismatch: %d declared constants vs %d attest-read schema keys\n declared: %v",
			len(declaredTagConstants), len(schemaKeys), dedupSorted(declaredTagConstants))
	}
}

// TestRegistryCoversProducerTags asserts the registry includes the producer-written
// tags (the whole point of v3 — the namespace is complete here even though attest
// doesn't declare constants for them). A guard against a producer tag silently
// leaving the registry.
func TestRegistryCoversProducerTags(t *testing.T) {
	s, err := LoadTagSchema()
	if err != nil {
		t.Fatalf("LoadTagSchema: %v", err)
	}
	want := map[string]string{
		"attest:vetted":           "vet",
		"attest:pcr<N>":           "vet",
		"attest:enclave-attested": "nitro",
		"attest:boot-attested":    "tpm",
	}
	got := map[string]string{}
	for _, e := range s.Tags {
		if _, ok := want[e.Key]; ok {
			got[e.Key] = e.Writer
		}
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("registry missing/mismatched producer tag %q (want writer %q, got %q)", k, w, got[k])
		}
	}
	// The conflated tag must be gone.
	for _, e := range s.Tags {
		if e.Key == "attest:nitro-attested" {
			t.Error("attest:nitro-attested must be retired (split into enclave-attested/boot-attested per ADR 0003)")
		}
	}
}

// TestSchemaEntriesWellFormed checks each entry has a known writer and type, and
// that any referenced expiry/module key is itself a schema key (no dangling refs).
func TestSchemaEntriesWellFormed(t *testing.T) {
	s, err := LoadTagSchema()
	if err != nil {
		t.Fatalf("LoadTagSchema: %v", err)
	}
	keys := make(map[string]bool, len(s.Tags))
	for _, e := range s.Tags {
		keys[e.Key] = true
	}
	writers := map[string]bool{
		"qualify": true, "attest": true, "vet": true, "nitro": true, "tpm": true, "legacy": true,
	}
	types := map[string]bool{"bool": true, "timestamp": true, "string": true, "set": true}
	for _, e := range s.Tags {
		if !writers[e.Writer] {
			t.Errorf("%s: unknown writer %q", e.Key, e.Writer)
		}
		if !types[e.Type] {
			t.Errorf("%s: unknown type %q", e.Key, e.Type)
		}
		if e.Expiry != "" && !keys[e.Expiry] {
			t.Errorf("%s: expiry %q is not a schema key", e.Key, e.Expiry)
		}
	}
}

func dedupSorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
