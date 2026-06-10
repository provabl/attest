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
const SchemaVersion = 1

// canonicalTagsSchemaJSON is the byte-identical canonical schema, also present in
// qualify at internal/training/attest-tags-schema.json. The conformance test in
// tags_schema_test.go locks the constants in this file to it, so a drift between
// the Go constants and the schema (or between the two repos' copies, via the shared
// version) fails CI rather than silently breaking Cedar evaluation.
//
//go:embed attest-tags-schema.json
var canonicalTagsSchemaJSON []byte

// TagSchemaEntry is one row of the canonical schema.
type TagSchemaEntry struct {
	Key    string `json:"key"`
	Writer string `json:"writer"` // "qualify" | "attest" | "legacy"
	Type   string `json:"type"`   // "bool" | "timestamp" | "string"
	Module string `json:"module,omitempty"`
	Expiry string `json:"expiry,omitempty"`
}

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
	TagNIHDUAID          = "attest:nih-dua-id"

	// Identity and lab tags — written by qualify lab setup.
	TagLabID      = "attest:lab-id"
	TagAdminLevel = "attest:admin-level" // "none" | "env" | "sre"

	// Legacy tag key written by older qualify versions — supported for backward compat.
	TagCUIExpiryLegacy = "attest:cui-expiry"
)
