// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package workload_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/provabl/attest/internal/workload"
)

func writeGateResult(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "gate-result.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func TestLoad_PresentFile(t *testing.T) {
	dir := t.TempDir()
	// Mirrors vet's gate-result.json — note the extra fields attest ignores.
	writeGateResult(t, dir, `{
		"artifact": "ghcr.io/test/app:v1.0",
		"artifact_hash": "sha256:abc123",
		"slsa_level": 2,
		"sbom_present": true,
		"cve_critical": false,
		"cve_high": true,
		"signed": true,
		"policy_met": true,
		"evaluated_at": "2026-06-08T00:00:00Z"
	}`)

	attrs, err := workload.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if attrs == nil {
		t.Fatal("expected attributes, got nil")
	}
	if attrs.SLSALevel != 2 {
		t.Errorf("SLSALevel = %d, want 2", attrs.SLSALevel)
	}
	if !attrs.SBOMPresent || !attrs.Signed || !attrs.CVEHigh {
		t.Errorf("bool fields wrong: %+v", attrs)
	}
	if attrs.CVECritical {
		t.Error("CVECritical should be false")
	}
	if attrs.ArtifactHash != "sha256:abc123" {
		t.Errorf("ArtifactHash = %q, want sha256:abc123", attrs.ArtifactHash)
	}
}

func TestLoad_AbsentFile(t *testing.T) {
	// Empty temp dir — no gate-result.json. Absent is not an error.
	attrs, err := workload.Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	if attrs != nil {
		t.Errorf("expected nil for absent file, got %+v", attrs)
	}
}

func TestLoad_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeGateResult(t, dir, `{not valid json`)

	if _, err := workload.Load(dir); err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}
