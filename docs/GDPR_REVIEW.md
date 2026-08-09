# GDPR readiness review

Review date: 2026-08-09. This is an engineering control review, not legal advice or a
claim that every customer deployment is automatically compliant.

## Scope and roles

The public submission uses one synthetic DataHub dataset and processes no end-user account
data. A customer DataHub may contain personal data in metadata, such as owner identities,
schema names, descriptions, tags, and lineage. The customer remains controller for that
catalog; the operator of Archon is a processor only when a separate deployment contract says
so. Archon does not read table rows or become the system of record for business data.

## Implemented controls

| GDPR principle | Product control | Evidence |
| --- | --- | --- |
| Purpose limitation and minimisation (Art. 5) | one configured dataset; bounded aspects; allowlisted public projection; no arbitrary search or row data | `src/datahub/harvest-policy.ts`, `src/reporting/public-audit-report.ts` |
| Accuracy (Art. 5(1)(d)) | current MCP reads are reconciled with provenance-bearing retained history; missing evidence becomes unknown/manual | `src/datahub/version-history.ts`, `src/audit/consistency.ts` |
| Storage limitation (Art. 5(1)(e)) | CI intermediates use `RUNNER_TEMP`; retained evidence is sanitized and content-addressed; no workstation artifacts are required | `.github/workflows/ci.yml`, `.github/workflows/live-governed-proof.yml` |
| Integrity and confidentiality (Arts. 5(1)(f), 32) | public runtime has no write credential; short-lived OIDC; distinct write/rollback identities; secret/SAST/SCA/container/IaC/DAST gates | `docs/ACTIVE_ARCHITECTURE.md`, `.github/workflows/hosted-demo.yml` |
| Transparency and human control | source badge distinguishes fixture/live; deterministic/model provenance is explicit; every mutation needs a digest-bound human approval | `web/src/App.tsx`, `src/remediation/` |
| Data protection by design/default (Art. 25) | fail-closed scope, safe projections, no public mutation route, no autonomous remediation, least-privilege adapters | `src/http/server.ts`, `services/datahub-hosted-api/` |

The default audit path is deterministic and sends no catalog metadata to an external model.
Optional narration or Analytics Agent providers must remain disabled until the deployer has
documented a lawful basis, data-processing terms, residency/transfer controls, retention,
and the exact minimized fields sent to that provider.

## Customer deployment checklist

Before processing a non-synthetic catalog, the controller must record:

1. purpose and Art. 6 lawful basis;
2. data inventory, recipients, retention schedule, and deletion procedure;
3. processor/subprocessor DPAs and Chapter V transfer mechanism where applicable;
4. data-subject request and correction workflow for metadata identities;
5. access review, incident contact, and Arts. 33–34 breach procedure; and
6. whether scale, monitoring, sensitive categories, or employee profiling requires a DPIA
   under Art. 35.

## Release decision

The synthetic public demo is acceptable for submission: it is read-only, credentialless,
data-minimized, visibly labelled, and does not expose personal data. A customer production
deployment is **conditional** on the checklist above; Archon must never be marketed as
granting legal compliance by installation alone.
