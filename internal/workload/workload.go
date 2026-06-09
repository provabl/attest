// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package workload reads vet's gate-result.json into schema.WorkloadAttributes
// for Cedar context.workload.* evaluation.
//
// attest is the policy decision point: it consumes the lowered supply-chain
// attributes vet produces. It does NOT run vet's evidence kernel — appraisal
// happens in vet at the source, and the durable artifact is the JSON file this
// package reads. Coupling to vet's JSON shape (not its Go types) is deliberate:
// it lets vet and attest version independently. The single point that maps
// gate-result.json field names to attest's struct is Load, below — keep it the
// only place, so a vet field rename is a one-line fix here.
package workload

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/provabl/attest/pkg/schema"
)

// DefaultVetDir is the conventional .vet directory vet writes into.
const DefaultVetDir = ".vet"

// gateResultFile is the file vet's `gate` command writes within the .vet dir.
const gateResultFile = "gate-result.json"

// Load reads gate-result.json from dir (dir/gate-result.json). If dir is empty it
// defaults to ".vet". It returns (nil, nil) when the file is absent: workload
// context is then simply unset, and policies that require context.workload.*
// default to deny under the forbid-unless pattern — exactly as a missing
// principal attribute does. An error is returned only when the file exists but
// cannot be read or parsed.
func Load(dir string) (*schema.WorkloadAttributes, error) {
	if dir == "" {
		dir = DefaultVetDir
	}

	// Confine the read to dir: the filename is a fixed constant, so the joined
	// path must resolve to a direct child of dir. This rejects a dir like
	// "../../etc" escaping anywhere unexpected before we touch the filesystem.
	base, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving workload dir %q: %w", dir, err)
	}
	path := filepath.Join(base, gateResultFile)
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving workload path: %w", err)
	}
	if !strings.HasPrefix(abs+string(filepath.Separator), base+string(filepath.Separator)) {
		return nil, fmt.Errorf("workload path %q escapes %q", abs, base)
	}

	data, err := os.ReadFile(abs) // #nosec G304 — confined to base above
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	// The SINGLE mapping from vet's gate-result.json to attest's workload schema.
	// schema.WorkloadAttributes' json tags match vet's GateResult field tags, so
	// extra fields (artifact, policy_met, evaluated_at) are ignored on decode.
	var attrs schema.WorkloadAttributes
	if err := json.Unmarshal(data, &attrs); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &attrs, nil
}
