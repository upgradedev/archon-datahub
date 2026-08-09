# Active product architecture

This document defines the product that Archon operates and proves today. It is the
architecture authority for implementation and customer onboarding. `infra/aws/` is a
non-deployed reference experiment and is not part of the active product path.

## Product boundary

Archon has one narrow job: audit one explicitly configured DataHub dataset, explain
evidence-linked integrity findings, and permit one G6 classification repair after an exact
human approval. It does not host DataHub, manage arbitrary catalog entities, or provide a
general mutation API.

```text
Anonymous browser
  -> Firebase Hosting
  -> Cloud Run read API (no write credential)
  -> private DataHub Core 1.6 endpoint

Human-approved canary
  -> isolated remediation command (separate write credential)
  -> exact G6 tag mutation
  -> read-after-write verification
  -> rollback and rollback verification
  -> immutable, sanitized receipt
```

## Clean dependency rule

Dependencies point inward:

1. `src/types.ts`, `src/datahub/models.ts`, and `src/remediation/contracts.ts` define domain
   values and invariants without cloud SDKs or HTTP.
2. `src/audit/`, `src/governance/`, `src/remediation/`, and `src/pipeline/` implement use
   cases against narrow ports.
3. `src/datahub/*-live.ts`, `src/http/`, `src/worker/`, and deployment workflows are adapters.
4. `web/` consumes only the public HTTP projection. It never selects a mutation tool or
   supplies mutation arguments.

Cloud, transport, authentication, and persistence types must not enter the domain or use-case
layers. New infrastructure is rejected unless it is required by an acceptance gate below.

## Runtime truth contract

- `/healthz` proves only that the process can serve HTTP.
- `/readyz` returns `200 ready/live` only after a bounded DataHub query resolves the one
  configured public dataset. Environment-variable presence is not readiness evidence.
- Provider, endpoint, token, and raw error details never cross the public boundary.
- The public service is read-only and has no mutation credential or mutation route.
- The write proof runs separately under a dedicated least-privilege identity. Immediately
  before OIDC it revalidates the protected environment and binds one exact GitHub reviewer
  event to the plan; rollback repeats this with a distinct approval. Success requires
  read-after-write and exact restoration verification.

## Acceptance gates for a 9/10 technical and customer bar

1. Anonymous hosted audit executes against DataHub Core 1.6 and returns an evidence-linked
   contradiction, lineage gap, and G6 finding.
2. Readiness fails closed when DataHub is unreachable or the configured query resolves zero
   or more than one dataset.
3. The approved canary adds only the configured G6 tag to one configured column, verifies it,
   removes it, verifies restoration, and emits a sanitized receipt.
4. A single customer command validates prerequisites and starts the supported local stack;
   a second command runs the smoke proof.
5. CI includes live-adapter contract coverage and a disposable DataHub 1.6 integration proof.
6. The active path has no dependency on AWS, Cognito, DynamoDB, S3, Step Functions, or the
   historical submission-receipt workflows.
7. AWS Well-Architected review covers all six pillars against the active GCP deployment,
   with evidence and open risks rather than aspirational claims.
8. EU AI Act review maps Articles 10, 13, 14, 15, and 50 to implemented controls, evidence,
   owner, and residual gap. Deterministic output is explicitly distinguished from model output.

## YAGNI decisions

- Freeze the AWS reference architecture. Do not extend, deploy, or keep it in required CI.
- Do not add a public write API, multi-tenant control plane, runtime selector, paid sandbox,
  generic policy engine, or additional remediation action for this submission.
- Do not expand receipt formats. Keep one audit report and one write/rollback proof.
- Prefer deletion or quarantine of dead submission machinery after the active path is green;
  do not perform a big-bang rewrite while the live proof is unavailable.

## External deployment prerequisite

Repository Actions policy currently blocks the hosted workflow before job creation. The
minimal owner-approved change is to allow only these action families while retaining mandatory
full-SHA pinning:

- `google-github-actions/auth@*`
- `google-github-actions/setup-gcloud@*`

No broader `verified_allowed` or `github_owned_allowed` relaxation is required.

## Architecture and compliance reviews

- [Clean architecture quality review](ARCHITECTURE_QUALITY_REVIEW.md) records the SOLID,
  KISS, YAGNI and residual repository-coupling assessment.
- [Active workload Well-Architected review](WELL_ARCHITECTED_REVIEW.md) covers all six
  pillars plus the AWS Agentic AI Lens concerns against the active GCP path.
- [EU AI Act review](EU_AI_ACT_REVIEW.md) maps Articles 10, 13, 14, 15, and 50 to implemented
  evidence, accountable owner, applicability, and residual gap.
- [SOTA judge and customer scorecard](SOTA_SCORECARD.md) separates observable score from the
  gated 9/10 target across the official criteria and named judge personas.
