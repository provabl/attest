// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package platform_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/provabl/attest/internal/platform"
)

func writeAttestation(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "attestation.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func TestLoad_PresentFile(t *testing.T) {
	dir := t.TempDir()
	writeAttestation(t, dir, `{
		"nitro_attested": true,
		"module_id": "i-0abc.enclave",
		"nonce_verified": true,
		"signature_valid": true,
		"pcr0": "aa",
		"pcr1": "bb",
		"pcr2": "cc",
		"pcr8": "dd"
	}`)

	attrs, err := platform.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if attrs == nil {
		t.Fatal("expected attributes, got nil")
	}
	if !attrs.NitroAttested || !attrs.NonceVerified || !attrs.SignatureValid {
		t.Errorf("bool fields wrong: %+v", attrs)
	}
	if attrs.ModuleID != "i-0abc.enclave" {
		t.Errorf("ModuleID = %q", attrs.ModuleID)
	}
	if attrs.PCR0 != "aa" || attrs.PCR8 != "dd" {
		t.Errorf("PCR fields wrong: %+v", attrs)
	}
}

func TestLoad_AbsentFile(t *testing.T) {
	attrs, err := platform.Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	if attrs != nil {
		t.Errorf("expected nil for absent file, got %+v", attrs)
	}
}

func TestLoad_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeAttestation(t, dir, `{not valid json`)
	if _, err := platform.Load(dir); err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}
