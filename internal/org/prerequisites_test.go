// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type mockSTS struct {
	arn string
	err error
}

func (m mockSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &sts.GetCallerIdentityOutput{Arn: aws.String(m.arn)}, nil
}

type mockIAMSim struct {
	// deniedActions are returned as explicitDeny; all others as allowed.
	deniedActions map[string]bool
	err           error
}

func (m mockIAMSim) SimulatePrincipalPolicy(_ context.Context, in *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	var results []iamtypes.EvaluationResult
	for _, a := range in.ActionNames {
		dec := iamtypes.PolicyEvaluationDecisionTypeAllowed
		if m.deniedActions[a] {
			dec = iamtypes.PolicyEvaluationDecisionTypeExplicitDeny
		}
		results = append(results, iamtypes.EvaluationResult{
			EvalActionName: aws.String(a),
			EvalDecision:   dec,
		})
	}
	return &iam.SimulatePrincipalPolicyOutput{EvaluationResults: results}, nil
}

const testCallerARN = "arn:aws:iam::942542972736:role/attest-runner"

func allOK(t *testing.T, results []PrereqResult) bool {
	t.Helper()
	for _, r := range results {
		if !r.Status {
			return false
		}
	}
	return true
}

func TestCheckCallerPermissions_AllAllowed(t *testing.T) {
	results := checkCallerPermissions(context.Background(),
		mockSTS{arn: testCallerARN}, mockIAMSim{})
	if len(results) != len(attestRequiredActions) {
		t.Fatalf("expected %d results (one per action), got %d", len(attestRequiredActions), len(results))
	}
	if !allOK(t, results) {
		t.Error("expected all actions allowed → all ok")
	}
}

// The core case: a denied action must surface as a non-ok result with remediation,
// so preflight flips to NOT READY (fail-closed on missing permission).
func TestCheckCallerPermissions_DeniedActionIsError(t *testing.T) {
	results := checkCallerPermissions(context.Background(),
		mockSTS{arn: testCallerARN},
		mockIAMSim{deniedActions: map[string]bool{"iam:ListRoleTags": true}})

	var found bool
	for _, r := range results {
		if r.Name == "IAM: iam:ListRoleTags" {
			found = true
			if r.Status {
				t.Error("denied action must be a non-ok result")
			}
			if r.Severity != "error" {
				t.Errorf("denied action severity = %q, want error", r.Severity)
			}
			if r.Remediation == "" {
				t.Error("denied action must carry a remediation")
			}
		}
	}
	if !found {
		t.Fatal("no result for the denied action iam:ListRoleTags")
	}
	if allOK(t, results) {
		t.Error("a denied action must make the overall set not-all-ok")
	}
}

func TestCheckCallerPermissions_CallerIdentityErrorFailsClosed(t *testing.T) {
	results := checkCallerPermissions(context.Background(),
		mockSTS{err: errors.New("ExpiredToken")}, mockIAMSim{})
	if len(results) != 1 || results[0].Status {
		t.Fatalf("expected a single error result on GetCallerIdentity failure, got %+v", results)
	}
}

// A simulator API failure must NOT be read as "permitted" — it's fail-closed.
func TestCheckCallerPermissions_SimulatorErrorFailsClosed(t *testing.T) {
	results := checkCallerPermissions(context.Background(),
		mockSTS{arn: testCallerARN}, mockIAMSim{err: errors.New("AccessDenied")})
	if len(results) != 1 || results[0].Status {
		t.Fatalf("expected a single fail-closed error result on simulator failure, got %+v", results)
	}
	if results[0].Remediation == "" {
		t.Error("fail-closed result should explain how to enable the self-check")
	}
}
