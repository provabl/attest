// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"context"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
)

// The dataset-scoped NIH Approved-User gate (nih-gds 1.1; provabl ADR 0002,
// attest#100). A base permit plus the forbid-unless that binds the dataset's
// required DUA to the principal's approved-DUA set — being approved for one study
// must NOT grant access to another. This exercises the real cedar-go engine end to
// end, including the []string → Cedar Set lowering in toValue and the
// .contains(resource.dua_id) membership test.
const datasetScopedNIHPolicy = `permit(principal, action, resource);
forbid (principal, action, resource)
when {
  resource has nih_controlled_access &&
  resource.nih_controlled_access == true &&
  !(principal has nih_approval_current &&
    principal.nih_approval_current == true &&
    principal has nih_approval_dua_ids &&
    resource has dua_id &&
    principal.nih_approval_dua_ids.contains(resource.dua_id))
};`

func nihPolicySet(t *testing.T) *cedar.PolicySet {
	t.Helper()
	ps, err := cedar.NewPolicySetFromBytes("nih.cedar", []byte(datasetScopedNIHPolicy))
	if err != nil {
		t.Fatalf("parse dataset-scoped NIH policy: %v", err)
	}
	return ps
}

func evalDataset(t *testing.T, attrs map[string]any) string {
	t.Helper()
	ev := NewEvaluator(nil)
	req := &AuthzRequest{
		PrincipalARN: "arn:aws:iam::123456789012:role/researcher",
		Action:       "s3:GetObject",
		ResourceARN:  "arn:aws:s3:::dbgap-dataset",
		Attributes:   attrs,
	}
	d, err := ev.EvaluateWithPolicies(context.Background(), nihPolicySet(t), req)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return d.Effect
}

// Approved for the dataset's required DUA → permitted.
func TestDatasetScope_HoldsRequiredDUA(t *testing.T) {
	got := evalDataset(t, map[string]any{
		"principal.nih_approval_current": true,
		"principal.nih_approval_dua_ids": []string{"phs000178", "phs000200"},
		"resource.nih_controlled_access": true,
		"resource.dua_id":                "phs000178",
	})
	if got != "ALLOW" {
		t.Errorf("holder of phs000178 accessing phs000178 dataset: got %s, want ALLOW", got)
	}
}

// Approved for a DIFFERENT study than the dataset requires → denied. This is the
// whole point of the change: blanket NIH approval no longer crosses datasets.
func TestDatasetScope_WrongDUA(t *testing.T) {
	got := evalDataset(t, map[string]any{
		"principal.nih_approval_current": true,
		"principal.nih_approval_dua_ids": []string{"phs000178"},
		"resource.nih_controlled_access": true,
		"resource.dua_id":                "phs000200",
	})
	if got != "DENY" {
		t.Errorf("holder of only phs000178 accessing phs000200 dataset: got %s, want DENY", got)
	}
}

// Not an approved user at all → denied.
func TestDatasetScope_NotApproved(t *testing.T) {
	got := evalDataset(t, map[string]any{
		"principal.nih_approval_current": false,
		"resource.nih_controlled_access": true,
		"resource.dua_id":                "phs000178",
	})
	if got != "DENY" {
		t.Errorf("unapproved principal: got %s, want DENY", got)
	}
}

// An approved user with an empty DUA set → denied (no dataset matches an empty
// set). Guards the inconsistent state approval.Revoke refuses to write.
func TestDatasetScope_EmptyDUASet(t *testing.T) {
	got := evalDataset(t, map[string]any{
		"principal.nih_approval_current": true,
		"principal.nih_approval_dua_ids": []string{},
		"resource.nih_controlled_access": true,
		"resource.dua_id":                "phs000178",
	})
	if got != "DENY" {
		t.Errorf("approved user with empty DUA set: got %s, want DENY", got)
	}
}

// A resource that is not NIH controlled-access is unaffected by the gate.
func TestDatasetScope_NonControlledResource(t *testing.T) {
	got := evalDataset(t, map[string]any{
		"principal.nih_approval_current": false,
		"resource.nih_controlled_access": false,
	})
	if got != "ALLOW" {
		t.Errorf("non-controlled resource: got %s, want ALLOW", got)
	}
}
