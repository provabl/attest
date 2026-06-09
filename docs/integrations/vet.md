# vet ↔ attest Integration Contract

**vet** (github.com/provabl/vet) is the software supply-chain verification tool in the
Provabl suite. After `vet gate`, it writes `.vet/gate-result.json` with the appraised
supply-chain posture of an artifact. attest reads that file and makes the result
available to Cedar policies as `context.workload.*` attributes.

This document is the formal contract between the two systems. Both sides must adhere to
it. The coupling point is the **JSON shape** of `gate-result.json` — not a shared Go
type — so vet and attest version independently.

---

## The Interface: gate-result.json → Cedar context

vet writes a JSON file. attest reads it. attest does **not** run vet's evidence kernel;
appraisal happens in vet at the source, and the durable artifact is the lowered JSON.

**Direction**: vet gate → `.vet/gate-result.json` → attest `internal/workload` reader →
Cedar `context.workload.*`

attest reads the file via `internal/workload.Load(dir)` (default dir `.vet`). When the
file is absent, the workload context is simply unset — policies that require
`context.workload.*` then default to deny under the forbid-unless pattern, exactly as a
missing principal attribute does.

---

## Attribute Schema

`gate-result.json` fields map to `context.workload.*` Cedar attributes. Keys are
**snake_case**, consistent with attest's principal attributes (`principal.cui_training_current`).

| JSON field | Type | Cedar attribute | Notes |
|---|---|---|---|
| `slsa_level` | int | `context.workload.slsa_level` | SLSA provenance level; `0` = not verified |
| `sbom_present` | bool | `context.workload.sbom_present` | SBOM attached and attested |
| `cve_critical` | bool | `context.workload.cve_critical` | critical CVEs present |
| `cve_high` | bool | `context.workload.cve_high` | high CVEs present |
| `signed` | bool | `context.workload.signed` | cosign/Sigstore signature verified |
| `artifact_hash` | string | `context.workload.artifact_hash` | subject digest |

The `artifact`, `policy_met`, and `evaluated_at` fields of `gate-result.json` are not
surfaced as Cedar attributes.

**Single mapping point:** the JSON-field → attribute mapping lives only in
`internal/workload/workload.go` (`Load`) and `pkg/schema.WorkloadAttributes`'s json tags.
A vet field rename is a one-line fix there.

### Example policy

```cedar
permit(principal, action, resource in ResourceGroup::"cui-data")
when {
  principal.cui_training_current == true &&   // from qualify (IAM tags)
  context.workload.slsa_level >= 2 &&         // from vet (gate-result.json)
  context.workload.cve_critical == false
};
```

---

## Why attest does not re-appraise (relates to #102)

Each tool in the suite runs the evidence kernel **in-process** with an **ephemeral**
attestation-manager key and persists only the *lowered* result (qualify → `attest:*` IAM
tags; vet → `gate-result.json`). The evidence bundle is never persisted and the signing
key never leaves the process, so there is no cross-process bundle for attest to verify.

attest is the **policy decision point**. It consumes the lowered attributes that are the
product of appraisal at the source. Re-appraising them in attest would re-judge
already-judged data under a fresh key — ceremony with no new trust property. This is the
"appraisal produces the verdict; Cedar acts on it; they never merge" boundary from
ADR 0001. Consequently attest's resolver/evaluator consume attributes; they do not run
the kernel.
