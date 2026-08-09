# EU AI Act review

Review date: 2026-08-09. Regulation: EU 2024/1689. This is an engineering control review,
not legal advice or a declaration of conformity.

## Scope and classification

Archon's authoritative audit findings, severity, governance checks, action eligibility,
approval validation, and rollback are deterministic software. A model can only narrate an
already-computed report. The supported hosted and customer Compose paths inject no LLM
credential, so they use a deterministic fixture narrator and truthfully report that no model
API call occurred.

If an operator enables a live model provider, Archon is an AI-system component for the
narrative only. On its stated purpose it does not make decisions about people, control a
safety component, or fall into an Annex III high-risk use case. A customer that changes the
purpose, data, or downstream decision must repeat the classification. Articles 10, 13, 14,
and 15 are therefore treated as high-risk-grade voluntary controls, not falsely claimed as
mandatory certification. Article 50 transparency duties are assessed directly because its
general application began on 2 August 2026.

Roles require deployment-specific confirmation. The repository author is the software
provider; the party running Archon is normally the deployer; the external model vendor, when
enabled, is a separate provider or subprocessor under its own terms.

## Control matrix

| Article | Trigger and applicability | Implemented control and evidence | Owner | Status and residual gap |
| --- | --- | --- | --- | --- |
| 10 — data and data governance | Mandatory for high-risk training/validation/test data. Archon trains no model and is not high-risk by stated purpose | one exact DataHub scope; bounded metadata; synthetic public demo; deterministic fixtures; no public write; `src/datahub/harvest-policy.ts`, `src/application/runtime-readiness.ts` | deployer data owner | **Conditional/partial.** Optional external narration receives classification counts and up to eight finding summaries. Before enabling it, establish lawful basis, minimization, retention, DPA/transfer terms, and a representative quality review. Automated PII redaction is not implemented |
| 13 — transparency and instructions | Mandatory for high-risk providers; adopted here as product transparency | active architecture, limitations, exact query, source badge, audit trace, public projection, release SHA, runtime/model provenance, quickstart and failure behavior; `docs/ACTIVE_ARCHITECTURE.md`, `web/src/App.tsx`, `src/reporting/public-audit-report.ts` | product owner | **Implemented for supported path.** Keep customer-specific intended purpose, accuracy limits, supported DataHub version, oversight roles, retention, and incident contact in deployment instructions |
| 14 — human oversight | Mandatory for high-risk systems; directly relevant to governed action | findings are recommendations; only G6 is actionable; the workflow revalidates exact environment protection and binds the configured GitHub reviewer ID/login, environment ID, approved state and content-bound comment; the deterministic decision remains digest-bound and expiring; stale-state/replay rejection, read-after-write and a separately approved rollback remain mandatory; `src/remediation/`, `scripts/capture-github-environment-approval.sh`, protected GitHub environments | data steward / deployer | **Implemented; release-evidence gated.** An environment label cannot self-assert a `DataSteward`; the verified human becomes the approval principal. The public API cannot write. Every release claim is conditioned on one successful exact-SHA write/read-back/rollback run |
| 15 — accuracy, robustness and cybersecurity | Mandatory for high-risk systems; adopted as engineering baseline | exact scope, strict parsing, uncertainty preservation, bounded paging/history/concurrency/deadlines, provider-error redaction, combined coverage gate, Gitleaks, CodeQL, SCA/SBOM, prompt-injection and authorization tests, non-root image, private GMS, production browser journeys and strict OWASP ZAP DAST | engineering and security owner | **Strong for the supported judging path.** CI and hosted observations cover the exact bounded product slice. A customer must add deployment-specific alerting, live performance objectives, backup/restore and incident operations |
| 50 — transparency for certain AI systems and generated content | Applicable when people interact with AI or when synthetic content marking/disclosure duties attach | UI distinguishes `No model call` from `Live model call`; live output carries provider, requested/returned model, response ID, token usage and latency; JSON/Markdown/SARIF retain machine-readable provenance; deterministic output cannot masquerade as model output; `src/llm/provenance.ts`, `web/src/App.tsx`, `web/src/evidence-pack.ts` | provider and deployer | **Implemented disclosure; partial marking assurance.** Provenance is adjacent machine-readable metadata, but interoperability with future Article 50 codes/standards has not been independently validated. Public-interest publication or deepfake use is outside intended purpose |

## Deterministic versus model output

| Output | Authority | May affect a write? | Disclosure |
| --- | --- | --- | --- |
| classification, contradiction, lineage and G1–G6 findings | deterministic rules over bounded DataHub evidence | only a deterministic G6 finding can enter planning | audit trace and evidence-linked finding |
| blast radius and severity ordering | deterministic graph/rules | no direct write authority | report fields and trace |
| executive narrative with no provider configured | deterministic fixture narrator | no | `source=deterministic-fixture`, visible “No model call” |
| executive narrative with a provider configured | external model over an already-computed bounded summary | no | `source=live-provider`, visible “Live model call”, machine-readable provenance |
| G6 plan, approval, execution and rollback | deterministic policy plus authenticated human decisions | yes, only after exact approval | approval/receipt/rollback digests |

The narrative is never parsed back into a finding, policy decision, action target, or tool
argument. This one-way boundary is the primary protection against hallucination becoming an
external side effect.

## Required deployment record

Before a customer enables a live model, the deployer must record:

1. intended purpose, prohibited downstream uses, role allocation, and risk classification;
2. DataHub fields sent to the narrator, lawful basis, minimization, retention, residency,
   processor terms, and any DPIA decision;
3. model/provider/version, evaluation set, accuracy and harmful-output thresholds;
4. named human overseers, approval and rollback coverage, incident and appeal/escalation path;
5. logging retention, access control, security testing, monitoring, and change-management
   evidence; and
6. the exact UI/export disclosure used for Article 50.

## Release decision

- **Supported deterministic hosted/Compose path:** acceptable for a synthetic demo or a
  customer trial after CI and infrastructure gates close; it makes no live-model claim.
- **Live-provider narration:** blocked from a production claim until the deployer completes
  the data-governance record and validates Article 50 marking against applicable standards.
- **Governed write:** a live-evidence claim is permitted only for an exact release SHA whose
  protected run contains both human approvals, mutation/read-back, rollback, and restoration
  receipt. Repository code or an environment label alone never satisfies this gate.
