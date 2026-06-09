// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package platform reads a nitro attestation result into schema.PlatformAttributes
// for Cedar context.platform.* evaluation.
//
// attest is the policy decision point: it consumes the lowered runtime-attestation
// attributes the evidence kernel's nitro provider produces. It does NOT run the
// evidence kernel — appraisal happens at the source (an enclave / a nitro tool),
// and the durable artifact is the JSON file this package reads. Coupling to the
// JSON shape (not a shared Go type) lets the producer and attest version
// independently. The single point that maps the JSON field names to attest's
// struct is Load, below — keep it the only place so a field rename is a one-line
// fix here.
package platform

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/provabl/attest/pkg/schema"
)

// DefaultNitroDir is the conventional .nitro directory the attestation result is
// written into.
const DefaultNitroDir = ".nitro"

// attestationFile is the file the nitro tool / enclave runtime writes within the
// .nitro dir.
const attestationFile = "attestation.json"

// Load reads attestation.json from dir (dir/attestation.json). If dir is empty it
// defaults to ".nitro". It returns (nil, nil) when the file is absent: platform
// context is then simply unset, and policies that require context.platform.*
// default to deny under the forbid-unless pattern — exactly as a missing
// principal attribute does. An error is returned only when the file exists but
// cannot be read or parsed.
func Load(dir string) (*schema.PlatformAttributes, error) {
	if dir == "" {
		dir = DefaultNitroDir
	}

	// Confine the read to dir: the filename is a fixed constant, so the joined
	// path must resolve to a direct child of dir. This rejects a dir like
	// "../../etc" escaping anywhere unexpected before we touch the filesystem.
	base, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving nitro dir %q: %w", dir, err)
	}
	path := filepath.Join(base, attestationFile)
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving nitro path: %w", err)
	}
	if !strings.HasPrefix(abs+string(filepath.Separator), base+string(filepath.Separator)) {
		return nil, fmt.Errorf("nitro path %q escapes %q", abs, base)
	}

	data, err := os.ReadFile(abs) // #nosec G304 — confined to base above
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	// The SINGLE mapping from the nitro attestation JSON to attest's platform
	// schema. schema.PlatformAttributes' json tags match the nitro provider's
	// lowered platform.* claim keys.
	var attrs schema.PlatformAttributes
	if err := json.Unmarshal(data, &attrs); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &attrs, nil
}
