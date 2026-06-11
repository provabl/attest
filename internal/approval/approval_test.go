// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/provabl/attest/pkg/schema"
)

// fakeTagger is an in-memory RoleTagger keyed by role name.
type fakeTagger struct {
	tags    map[string]map[string]string
	listErr error
	tagErr  error
}

func newFakeTagger(initial map[string]string) *fakeTagger {
	t := &fakeTagger{tags: map[string]map[string]string{"researcher": {}}}
	for k, v := range initial {
		t.tags["researcher"][k] = v
	}
	return t
}

func (f *fakeTagger) ListRoleTags(_ context.Context, role string) (map[string]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := map[string]string{}
	for k, v := range f.tags[role] {
		out[k] = v
	}
	return out, nil
}

func (f *fakeTagger) TagRole(_ context.Context, role string, tags map[string]string) error {
	if f.tagErr != nil {
		return f.tagErr
	}
	if f.tags[role] == nil {
		f.tags[role] = map[string]string{}
	}
	for k, v := range tags {
		f.tags[role][k] = v
	}
	return nil
}

func (f *fakeTagger) UntagRole(_ context.Context, role string, keys []string) error {
	for _, k := range keys {
		delete(f.tags[role], k)
	}
	return nil
}

var expiry = time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC)

func TestGrant_FirstDUA(t *testing.T) {
	f := newFakeTagger(nil)
	set, err := Grant(context.Background(), f, "researcher", "phs000178", expiry)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if !reflect.DeepEqual(set, []string{"phs000178"}) {
		t.Errorf("set = %v, want [phs000178]", set)
	}
	got := f.tags["researcher"]
	if got[schema.TagNIHApproval] != "true" {
		t.Errorf("%s = %q, want true", schema.TagNIHApproval, got[schema.TagNIHApproval])
	}
	if got[schema.TagNIHDUAIDs] != "phs000178" {
		t.Errorf("%s = %q, want phs000178", schema.TagNIHDUAIDs, got[schema.TagNIHDUAIDs])
	}
	if got[schema.TagNIHApprovalExpiry] != "2027-05-01T00:00:00Z" {
		t.Errorf("expiry = %q, want 2027-05-01T00:00:00Z", got[schema.TagNIHApprovalExpiry])
	}
}

func TestGrant_MergesIntoExistingSet(t *testing.T) {
	f := newFakeTagger(map[string]string{
		schema.TagNIHApproval: "true",
		schema.TagNIHDUAIDs:   "phs000178",
	})
	set, err := Grant(context.Background(), f, "researcher", "phs000200", expiry)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	want := []string{"phs000178", "phs000200"} // sorted
	if !reflect.DeepEqual(set, want) {
		t.Errorf("set = %v, want %v", set, want)
	}
	if got := f.tags["researcher"][schema.TagNIHDUAIDs]; got != "phs000178+phs000200" {
		t.Errorf("tag value = %q, want phs000178+phs000200", got)
	}
}

func TestGrant_Idempotent(t *testing.T) {
	f := newFakeTagger(map[string]string{schema.TagNIHDUAIDs: "phs000178"})
	set, err := Grant(context.Background(), f, "researcher", "phs000178", expiry)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if !reflect.DeepEqual(set, []string{"phs000178"}) {
		t.Errorf("set = %v, want [phs000178] (no duplicate)", set)
	}
}

func TestGrant_Validation(t *testing.T) {
	f := newFakeTagger(nil)
	if _, err := Grant(context.Background(), f, "", "phs000178", expiry); err == nil {
		t.Error("empty role: want error")
	}
	if _, err := Grant(context.Background(), f, "researcher", "", expiry); err == nil {
		t.Error("empty DUA: want error")
	}
	if _, err := Grant(context.Background(), f, "researcher", "phs+bad", expiry); err == nil {
		t.Error("DUA containing delimiter: want error")
	}
	if _, err := Grant(context.Background(), f, "researcher", "phs000178", time.Time{}); err == nil {
		t.Error("zero expiry: want error")
	}
}

func TestGrant_ListError(t *testing.T) {
	f := newFakeTagger(nil)
	f.listErr = errors.New("AccessDenied")
	if _, err := Grant(context.Background(), f, "researcher", "phs000178", expiry); err == nil {
		t.Error("list error: want propagated error")
	}
}

func TestRevoke_RemovesOneOfMany(t *testing.T) {
	f := newFakeTagger(map[string]string{
		schema.TagNIHApproval: "true",
		schema.TagNIHDUAIDs:   "phs000178+phs000200",
	})
	set, err := Revoke(context.Background(), f, "researcher", "phs000178")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !reflect.DeepEqual(set, []string{"phs000200"}) {
		t.Errorf("set = %v, want [phs000200]", set)
	}
	got := f.tags["researcher"]
	if got[schema.TagNIHApproval] != "true" {
		t.Error("approval should remain true while a DUA is left")
	}
	if got[schema.TagNIHDUAIDs] != "phs000200" {
		t.Errorf("tag value = %q, want phs000200", got[schema.TagNIHDUAIDs])
	}
}

func TestRevoke_LastDUAClearsApproval(t *testing.T) {
	f := newFakeTagger(map[string]string{
		schema.TagNIHApproval:       "true",
		schema.TagNIHApprovalExpiry: "2027-05-01T00:00:00Z",
		schema.TagNIHDUAIDs:         "phs000178",
	})
	set, err := Revoke(context.Background(), f, "researcher", "phs000178")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if set != nil {
		t.Errorf("set = %v, want nil (no DUAs left)", set)
	}
	got := f.tags["researcher"]
	for _, k := range []string{schema.TagNIHApproval, schema.TagNIHApprovalExpiry, schema.TagNIHDUAIDs} {
		if _, present := got[k]; present {
			t.Errorf("tag %q should have been removed, got %q", k, got[k])
		}
	}
}

func TestRevoke_NotPresentIsNoError(t *testing.T) {
	f := newFakeTagger(map[string]string{
		schema.TagNIHApproval: "true",
		schema.TagNIHDUAIDs:   "phs000178",
	})
	// Revoking a DUA the role doesn't hold leaves the existing set intact.
	set, err := Revoke(context.Background(), f, "researcher", "phs999999")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !reflect.DeepEqual(set, []string{"phs000178"}) {
		t.Errorf("set = %v, want [phs000178] unchanged", set)
	}
}
