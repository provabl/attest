# nitro ↔ attest Integration Contract

**nitro** is the runtime/enclave attestation provider in the evidence kernel
(`github.com/provabl/evidence`, `providers/nitro`). It verifies an AWS Nitro Enclave
attestation document — native nonce binding, PCR policy, COSE_Sign1 signature to the AWS
Nitro PKI root — and lowers the verdict to `platform.*` attributes. A nitro tool / enclave
runtime writes the lowered result to `.nitro/attestation.json`; attest reads that file and
makes it available to Cedar policies as `context.platform.*` attributes.

This document is the formal contract between the two. The coupling point is the **JSON
shape** of `attestation.json` — not a shared Go type — so the producer and attest version
independently.

> **Status:** attest ships the *consumer* half (the reader + the `context.platform.*`
> wiring). The producer that writes `.nitro/attestation.json` — a nitro CLI or the enclave
> runtime running the evidence kernel's nitro provider and lowering its verdict — does not
> exist yet (tracked in provabl/evidence#5). Until then the file is simply absent, and
> policies requiring `context.platform.*` default to deny. attest is correct today; the
> end-to-end loop closes when the producer lands.

---

## The Interface: attestation.json → Cedar context

A nitro tool writes a JSON file. attest reads it. attest does **not** run the evidence
kernel; appraisal happens at the source (the enclave), and the durable artifact is the
lowered JSON.

**Direction**: nitro provider → `.nitro/attestation.json` → attest `internal/platform`
reader → Cedar `context.platform.*`

attest reads the file via `internal/platform.Load(dir)` (default dir `.nitro`). When the
file is absent, the platform context is simply unset — policies that require
`context.platform.*` then default to deny under the forbid-unless pattern, exactly as a
missing principal attribute does.

---

## Attribute Schema

`attestation.json` fields map to `context.platform.*` Cedar attributes. Keys are
**snake_case**, consistent with `context.workload.*` and `principal.*`.

| JSON field | Type | Cedar attribute | Notes |
|---|---|---|---|
| `nitro_attested` | bool | `context.platform.nitro_attested` | overall verdict (nonce bound, signature valid, PCRs matched) |
| `module_id` | string | `context.platform.module_id` | enclave module id |
| `nonce_verified` | bool | `context.platform.nonce_verified` | the document carried the issued challenge (native binding) |
| `signature_valid` | bool | `context.platform.signature_valid` | COSE_Sign1 chains to the AWS Nitro PKI root |
| `pcr0` | string | `context.platform.pcr0` | enclave image (SHA384 hex) |
| `pcr1` | string | `context.platform.pcr1` | kernel / bootstrap |
| `pcr2` | string | `context.platform.pcr2` | application |
| `pcr8` | string | `context.platform.pcr8` | signing certificate |

**Single mapping point:** the JSON-field → attribute mapping lives only in
`internal/platform/platform.go` (`Load`) and `pkg/schema.PlatformAttributes`'s json tags.
A producer field rename is a one-line fix there.

### Example policy

```cedar
permit(principal, action, resource in ResourceGroup::"cui-data")
when {
  principal.cui_training_current == true &&     // from qualify (IAM tags)
  context.workload.slsa_level >= 2 &&           // from vet (gate-result.json)
  context.platform.nitro_attested == true &&    // from nitro (attestation.json)
  context.platform.pcr0 == "<expected-enclave-image>"
};
```

This is the full picture the evidence kernel enables: the *person* is trained (qualify),
the *software* is provenance-verified (vet), and the *runtime* is a known-good enclave
(nitro) — all appraised at the source and consumed here as Cedar attributes.

---

## Why attest does not re-appraise (relates to #102)

Each producer in the suite runs the evidence kernel **in-process** with an **ephemeral**
attestation-manager key and persists only the *lowered* result (qualify → `attest:*` IAM
tags; vet → `gate-result.json`; nitro → `attestation.json`). The evidence bundle is never
persisted and the signing key never leaves the process, so there is no cross-process bundle
for attest to verify.

attest is the **policy decision point**. It consumes the lowered attributes that are the
product of appraisal at the source. Re-appraising them would re-judge already-judged data
under a fresh key — ceremony with no new trust property. This is the "appraisal produces
the verdict; Cedar acts on it; they never merge" boundary from ADR 0001.

---

## ground's IAM-layer counterpart

attest evaluates `context.platform.*` in Cedar (application-layer). ground deploys an
SCP (`policies/nitro_attestation_scp.json`, provabl/ground#12) that denies sensitive-data
actions unless the principal carries `aws:PrincipalTag/attest:nitro-attested == "true"` —
the IAM-layer counterpart. The same attestation result drives both: Cedar context here, a
principal tag there. (Who writes that principal tag is the same open producer step noted
above.)
