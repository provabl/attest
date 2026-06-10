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
	TagNIHDUAID,
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

// TestDeclaredConstantsMatchSchema is the conformance test: the set of attest:* key
// constants attest declares must be exactly the set of keys in the canonical schema
// — no missing keys (attest can't read a tag it has no constant for) and no extra
// keys (a constant with no schema entry is undocumented drift).
func TestDeclaredConstantsMatchSchema(t *testing.T) {
	s, err := LoadTagSchema()
	if err != nil {
		t.Fatalf("LoadTagSchema: %v", err)
	}

	schemaKeys := make(map[string]bool, len(s.Tags))
	for _, e := range s.Tags {
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
			t.Errorf("schema key %q has no attest constant — add it to tags.go and declaredTagConstants", k)
		}
	}
	for k := range declared {
		if !schemaKeys[k] {
			t.Errorf("attest constant %q is not in the canonical schema — add it to attest-tags-schema.json (both repos) and bump SchemaVersion", k)
		}
	}

	if len(declaredTagConstants) != len(s.Tags) {
		got, want := dedupSorted(declaredTagConstants), schemaKeySlice(s)
		t.Errorf("count mismatch: %d declared constants vs %d schema keys\n declared: %v\n schema:   %v", len(declaredTagConstants), len(s.Tags), got, want)
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
	writers := map[string]bool{"qualify": true, "attest": true, "legacy": true}
	types := map[string]bool{"bool": true, "timestamp": true, "string": true}
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

func schemaKeySlice(s *TagSchema) []string {
	out := make([]string, 0, len(s.Tags))
	for _, e := range s.Tags {
		out = append(out, e.Key)
	}
	sort.Strings(out)
	return out
}
