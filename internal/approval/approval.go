// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package approval activates an NIH DUA / IRB approval on a researcher's IAM
// role: it writes the attest:nih-* tags the principal resolver reads and the
// cedar-nih-approved-user policy gates on. This is the "activate" half of the
// approval lifecycle (attest#99); the durable, human-affirmed record is a
// schema.Attestation managed separately (internal/attestation).
//
// The load-bearing detail is the DUA set. A researcher accrues DUAs for multiple
// studies, and compute-to-data (attest#100) binds each controlled dataset to a
// specific DUA via principal.nih_approval_dua_ids.contains(resource.dua_id). So
// granting a DUA MERGES into the existing attest:nih-dua-ids set rather than
// overwriting it, and revoking removes exactly one member. The set is carried in
// one IAM tag value, SetDelim-joined (see schema.SetDelim — '+', because a comma
// is not a valid IAM tag-value character).
package approval

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/provabl/attest/pkg/schema"
)

// RoleTagger reads and writes a role's tags. Implemented by the AWS IAM client in
// production (cmd/attest), faked in tests. The three methods map to
// iam:ListRoleTags / iam:TagRole / iam:UntagRole.
type RoleTagger interface {
	ListRoleTags(ctx context.Context, roleName string) (map[string]string, error)
	TagRole(ctx context.Context, roleName string, tags map[string]string) error
	UntagRole(ctx context.Context, roleName string, keys []string) error
}

// Grant activates (or extends) NIH Approved-User status on roleName for one DUA:
// it sets attest:nih-approval=true and attest:nih-approval-expiry, and MERGES
// duaID into the attest:nih-dua-ids set. It returns the resulting DUA set.
//
// Idempotent: granting a DUA already present is a no-op for the set. The expiry
// is always (re)written — extending one DUA refreshes the principal's approval
// horizon, which is the intended semantics (access is also bounded per-dataset by
// the dataset's own DUA, enforced in Cedar).
func Grant(ctx context.Context, t RoleTagger, roleName, duaID string, expires time.Time) ([]string, error) {
	if roleName == "" {
		return nil, fmt.Errorf("role name is required")
	}
	if err := validateDUAID(duaID); err != nil {
		return nil, err
	}
	if expires.IsZero() {
		return nil, fmt.Errorf("an expiry date is required (DUAs are time-bounded)")
	}

	current, err := t.ListRoleTags(ctx, roleName)
	if err != nil {
		return nil, fmt.Errorf("read current tags for %s: %w", roleName, err)
	}

	set := parseSet(current[schema.TagNIHDUAIDs])
	set = addToSet(set, duaID)

	tags := map[string]string{
		schema.TagNIHApproval:       "true",
		schema.TagNIHApprovalExpiry: expires.UTC().Format(time.RFC3339),
		schema.TagNIHDUAIDs:         joinSet(set),
	}
	if err := t.TagRole(ctx, roleName, tags); err != nil {
		return nil, fmt.Errorf("write approval tags to %s: %w", roleName, err)
	}
	return set, nil
}

// Revoke removes duaID from the role's attest:nih-dua-ids set. When the last DUA
// is removed it also clears attest:nih-approval (the principal is no longer an
// approved user of any study) by deleting the approval tags outright. It returns
// the remaining DUA set.
func Revoke(ctx context.Context, t RoleTagger, roleName, duaID string) ([]string, error) {
	if roleName == "" {
		return nil, fmt.Errorf("role name is required")
	}
	if err := validateDUAID(duaID); err != nil {
		return nil, err
	}

	current, err := t.ListRoleTags(ctx, roleName)
	if err != nil {
		return nil, fmt.Errorf("read current tags for %s: %w", roleName, err)
	}

	set := removeFromSet(parseSet(current[schema.TagNIHDUAIDs]), duaID)

	if len(set) == 0 {
		// No DUAs left → not an approved user. Remove the approval tags entirely
		// rather than leaving attest:nih-approval=true with an empty DUA set
		// (which would pass the blanket gate but fail every dataset-scoped check —
		// an inconsistent state we refuse to write).
		keys := []string{schema.TagNIHApproval, schema.TagNIHApprovalExpiry, schema.TagNIHDUAIDs}
		if err := t.UntagRole(ctx, roleName, keys); err != nil {
			return nil, fmt.Errorf("clear approval tags on %s: %w", roleName, err)
		}
		return nil, nil
	}

	if err := t.TagRole(ctx, roleName, map[string]string{schema.TagNIHDUAIDs: joinSet(set)}); err != nil {
		return nil, fmt.Errorf("update DUA set on %s: %w", roleName, err)
	}
	return set, nil
}

// validateDUAID rejects an empty id and one containing the set delimiter (which
// would split into phantom members on read).
func validateDUAID(duaID string) error {
	if strings.TrimSpace(duaID) == "" {
		return fmt.Errorf("a DUA / study id is required")
	}
	if strings.Contains(duaID, schema.SetDelim) {
		return fmt.Errorf("DUA id %q must not contain the set delimiter %q", duaID, schema.SetDelim)
	}
	return nil
}

// parseSet splits a SetDelim-joined value into trimmed, non-empty members.
func parseSet(v string) []string {
	var out []string
	for _, m := range strings.Split(v, schema.SetDelim) {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// joinSet renders members back into the single tag value, sorted for a stable,
// diff-friendly result.
func joinSet(members []string) string {
	sort.Strings(members)
	return strings.Join(members, schema.SetDelim)
}

func addToSet(set []string, member string) []string {
	for _, m := range set {
		if m == member {
			return set
		}
	}
	return append(set, member)
}

func removeFromSet(set []string, member string) []string {
	out := set[:0:0]
	for _, m := range set {
		if m != member {
			out = append(out, m)
		}
	}
	return out
}
