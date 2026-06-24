// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// SchemaVersion is the version of the attest:* IAM tag contract shared between
// qualify (writer) and attest (reader). It MUST equal the "version" field of the
// canonical attest-tags-schema.json embedded below, and the same constant in
// qualify's internal/training/tags.go. Bump it (in both repos, same release)
// whenever a tag key is added, removed, or renamed.
// See: https://github.com/provabl/qualify/issues/32
//
// v2 (2026-06): attest:nih-dua-id (string) → attest:nih-dua-ids (set). A
// researcher holds DUAs for multiple studies, and compute-to-data binds each
// dataset to a specific DUA. See docs/adr/0002-compute-to-data-access.md.
//
// v3 (2026-06): the schema becomes the registry of the COMPLETE attest:*
// namespace, not just the qualify↔attest subset. Adds vet's attest:vetted +
// attest:pcr<N> (pattern), and splits the conflated attest:nitro-attested into
// per-property attest:enclave-attested (nitro) and attest:boot-attested (tpm).
// Each writer repo locks its own rows. See docs/adr/0003-attest-tag-namespace-no-conflation.md.
const SchemaVersion = 3

// canonicalTagsSchemaJSON is the byte-identical canonical schema, also present in
// qualify at internal/training/attest-tags-schema.json. The conformance test in
// tags_schema_test.go locks the constants in this file to it, so a drift between
// the Go constants and the schema (or between the two repos' copies, via the shared
// version) fails CI rather than silently breaking Cedar evaluation.
//
//go:embed attest-tags-schema.json
var canonicalTagsSchemaJSON []byte

// TagSchemaEntry is one row of the canonical registry.
type TagSchemaEntry struct {
	Key     string `json:"key"`
	Writer  string `json:"writer"` // "qualify" | "attest" | "vet" | "nitro" | "tpm" | "legacy"
	Type    string `json:"type"`   // "bool" | "timestamp" | "string" | "set"
	Module  string `json:"module,omitempty"`
	Expiry  string `json:"expiry,omitempty"`
	Pattern bool   `json:"pattern,omitempty"` // true if Key is a family (e.g. attest:pcr<N>), not a literal key
}

// SetDelim joins members of a "set"-typed tag value into the single IAM tag
// value string. A comma is not a valid IAM tag-value character; '+' is. DUA /
// phs study ids contain '.' and '-' but never '+', so '+' is an unambiguous
// separator. See docs/adr/0002-compute-to-data-access.md.
const SetDelim = "+"

// TagSchema is the parsed canonical schema.
type TagSchema struct {
	Version   int              `json:"version"`
	Namespace string           `json:"namespace"`
	Tags      []TagSchemaEntry `json:"tags"`
}

// LoadTagSchema parses the embedded canonical attest:* tag schema.
func LoadTagSchema() (*TagSchema, error) {
	var s TagSchema
	if err := json.Unmarshal(canonicalTagsSchemaJSON, &s); err != nil {
		return nil, fmt.Errorf("parse canonical attest-tags-schema.json: %w", err)
	}
	return &s, nil
}

// attest:* IAM role tag key constants — authoritative schema for the attest side.
//
// qualify (github.com/provabl/qualify) writes these tags to researchers' IAM roles
// on training completion. attest reads them via the principal resolver to populate
// Cedar evaluation attributes.
//
// IMPORTANT: Both qualify (internal/training/tags.go) and attest (this file) must
// agree on these key strings AND on SchemaVersion. The canonical contract is
// attest-tags-schema.json (embedded above, byte-identical in both repos); the
// conformance test locks these constants to it. If any key changes, update the
// schema JSON in BOTH repos and bump SchemaVersion in the same release.
// See: https://github.com/provabl/qualify/issues/32
const (
	// Training completion tags — written by qualify on module pass.
	TagCUITraining              = "attest:cui-training"
	TagCUITrainingExpiry        = "attest:cui-training-expiry"
	TagHIPAATraining            = "attest:hipaa-training"
	TagHIPAATrainingExpiry      = "attest:hipaa-training-expiry"
	TagAwarenessTraining        = "attest:awareness-training"
	TagAwarenessTrainingExpiry  = "attest:awareness-training-expiry"
	TagFERPATraining            = "attest:ferpa-training"
	TagFERPATrainingExpiry      = "attest:ferpa-training-expiry"
	TagITARTraining             = "attest:itar-training"
	TagITARTrainingExpiry       = "attest:itar-training-expiry"
	TagDataClassTraining        = "attest:data-class-training"
	TagDataClassTrainingExpiry  = "attest:data-class-training-expiry"
	TagResearchSecurityTraining = "attest:research-security-training"
	TagResearchSecurityExpiry   = "attest:research-security-training-expiry"
	TagCOCCheckCurrent          = "attest:coc-check-current"
	TagCOCCheckExpiry           = "attest:coc-check-expiry"

	// Countries-of-concern check tags — written by qualify lab record-check.
	TagCountry = "attest:country" // ISO 3166-1 alpha-2 institutional affiliation

	// NIH DUA / Approved User tags — written by NIH DUA management workflow.
	TagNIHApproval       = "attest:nih-approval"
	TagNIHApprovalExpiry = "attest:nih-approval-expiry"
	// TagNIHDUAIDs is a set (SetDelim-joined) of the DUA / study ids this
	// principal is approved under — one per controlled-access dataset. The
	// dataset-scoped Cedar policy checks membership against resource.dua_id.
	TagNIHDUAIDs = "attest:nih-dua-ids"

	// Identity and lab tags — written by qualify lab setup.
	TagLabID      = "attest:lab-id"
	TagAdminLevel = "attest:admin-level" // "none" | "env" | "sre"

	// Legacy tag key written by older qualify versions — supported for backward compat.
	TagCUIExpiryLegacy = "attest:cui-expiry"
)
