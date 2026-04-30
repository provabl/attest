# Open-Core Model

attest is open-source software (Apache 2.0). The compliance compiler — framework YAML, SCP/Cedar/Config generation, crosswalk mapping, and audit document generation — is free, self-hostable, and will always remain open source.

The commercial tier, **attest Cloud**, extends the open-source base with operational features for institutions running SREs in production. Commercial code lives in a separate private repository (`provabl/attest-cloud`) that imports attest as a dependency.

This boundary is also documented in [CLAUDE.md](CLAUDE.md) for AI-assisted development context.

---

## What is open source

| Component | Description |
|---|---|
| Framework definitions | YAML compliance framework files (`frameworks/*/framework.yaml`) |
| Framework schema | `pkg/schema/` — SRE, Framework, Control, Crosswalk, Posture types |
| SCP compiler | `internal/compiler/scp/` — generates SCPs from framework controls |
| Cedar compiler | `internal/compiler/cedar/` — generates Cedar policies |
| Config compiler | Generates AWS Config rules |
| IaC output | Terraform HCL and CDK TypeScript generators |
| CLI gap analysis | `attest scan` posture reporting |
| Audit document generation | `attest generate ssp`, `attest generate closeout` |
| OSCAL export | SSP, AR, POA&M in machine-readable OSCAL format |
| Policy testing | `attest test` — unit tests and simulation for generated policies |
| Crosswalk manifest generator | Maps controls across frameworks |
| attest:* IAM tag schema | `pkg/schema/tags.go` — versioned tag contract with qualify |
| Waiver management | Time-bounded, approved exceptions to controls |
| Regulatory intelligence | Source monitoring and change detection |
| ground integration | GroundMeta contract, prerequisite checks |

**Community-maintained compliance frameworks** — NIST 800-171, CMMC L1/L2, HIPAA, FERPA, NIH GDS, ITAR, GDPR, FedRAMP Moderate, NIST 800-223 — are open source. They are the foundation.

---

## What is commercial (attest Cloud)

| Feature | Why commercial |
|---|---|
| **Cedar PDP (continuous enforcement)** | Real-time policy evaluation for every AWS API call. Requires infrastructure to run; sold as a managed service |
| **Compliance dashboard** | Live posture view, trend analysis, control heat maps, multi-SRE management |
| **AI compliance navigator** | Bedrock + Claude capabilities: `attest navigate`, regulatory triage, automated remediation suggestions |
| **GRC integrations** | OSCAL continuous sync to GRC platforms (ServiceNow, Archer, OneTrust) |
| **Multi-SRE management** | Manage compliance across multiple organizations/institutions |
| **Operational monitoring + alerting** | Drift detection, control degradation alerts, PagerDuty/Slack integration |
| **Managed regulatory watch** | Curated regulatory change feed with impact analysis — not just raw monitoring |
| **Bouncing auth for dashboard** | Institutional SSO-gated dashboard access |
| **Framework customization service** | Expert-assisted custom framework authoring for institution-specific requirements |
| **SLA + support** | Priority issue response, dedicated Slack, advisory hours |

---

## The boundary in practice

```
attest (OSS)                          attest Cloud (commercial)
────────────────────────────────       ──────────────────────────────────
Compliance framework definitions       Cedar PDP (continuous enforcement)
SCP / Cedar / Config compilers         Live compliance dashboard
IaC output (Terraform, CDK)            AI compliance navigator
attest scan (posture snapshot)         GRC integrations (OSCAL continuous)
SSP + OSCAL document generation        Multi-SRE management
Policy testing + simulation            Operational monitoring + alerting
Waiver management                      Managed regulatory watch
Regulatory source monitoring           Bouncing auth for dashboard
qualify tag schema contract            Framework customization service
```

`attest scan` gives you a compliance snapshot. attest Cloud gives you continuous enforcement and operational visibility.

---

## Community frameworks

Framework YAML files in `frameworks/*/framework.yaml` are community-maintained. If your institution uses a compliance framework that isn't yet supported, PRs are welcome. See the framework schema in `pkg/schema/types.go` and existing frameworks as examples.

For commercial licensing, contact [hello@provabl.dev](mailto:hello@provabl.dev).
