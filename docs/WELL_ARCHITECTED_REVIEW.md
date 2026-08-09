# Active workload Well-Architected review

Review date: 2026-08-06. Scope: the active Firebase Hosting → Cloud Run read API →
private DataHub Core path, the customer Compose path, and the separately approved G6
write/rollback proof. The non-deployed AWS CDK experiment is out of scope.

This is an engineering review against the six AWS Well-Architected pillars, applied
cloud-neutrally to the active GCP workload. It is not an AWS certification or a claim that
an unexecuted control is effective. Repository evidence is distinguished from observed
deployment evidence throughout.

## Executive decision

The product boundary is clean and intentionally small: one exact dataset audit, one
read-only public API, and one separately authorized G6 repair. The dependency direction,
failure behavior, and human-authority boundary are strong. The workload is not yet
production-ready because its active deployment and recovery controls have not been
observed end to end.

| Pillar | Current state | Strongest evidence | Material open risk |
| --- | --- | --- | --- |
| Operational excellence | Partial | SHA-bound deploy, runbook, truthful readiness, request IDs | no active GCP monitor, alert, or exercised rollback runbook |
| Security | Strong design; owner-gated runtime | private GMS, exact query, no public write route, WIF, non-root image, dedicated runtime identity | public API has no edge rate limiter; runtime IAM and hosted secret binding remain unexecuted |
| Reliability | Partial | provider-aware `/readyz`, bounded deadlines, read-after-write and rollback verification | single-zone DataHub VM, no proven reseed/restore, no progressive Cloud Run promotion |
| Performance efficiency | Partial | bounded one-entity preview, operation deadlines, readiness cache, autoscaling ceiling | only offline load evidence; no live p95/p99 or saturation measurement |
| Cost optimization | Good for a demo | Firebase, bounded Cloud Run, explicit VM cost and teardown | one warm Cloud Run instance plus always-on GCE; no budget alert or measured utilization |
| Sustainability | Partial | one region, direct private path, bounded scale, no live multi-cloud chain | always-on VM and warm CPU chosen for judge availability without utilization evidence |

No pillar is marked complete until the required CI and live observations exist.

## 1. Operational excellence

Implemented in code:

- `.github/workflows/hosted-demo.yml` builds one release-SHA image, deploys it, proves
  `/readyz`, executes an audit, deploys the SPA, and proves the hosted origin.
- `docs/HOSTED_DEMO_DEPLOY.md` is the single active deployment runbook.
- `src/http/server.ts` emits bounded request IDs and never serializes provider errors.
- `compose.yaml` and `src/onboarding/doctor.ts` give customers a two-command, fail-closed
  start and smoke path.

Open controls:

- **WA-OE-1 (P0):** run the required CI on the exact candidate; local tests are prohibited
  and Docker is unavailable in the authoring environment.
- **WA-OE-2 (P0):** observe one hosted deployment and retain the SHA-bound readiness/audit
  output. The Cloud Run service does not yet exist.
- **WA-OE-3 (P1):** add a GCP-specific availability probe and alert only after the live
  backend exists. The historical `availability.yml` observes the frozen AWS experiment and
  is not evidence for this workload.
- **WA-OE-4 (P1):** document and exercise promotion/rollback for a bad Cloud Run revision.
  The current workflow tests after deployment but does not keep the prior revision serving
  until candidate verification completes.

## 2. Security

Implemented in code:

- DataHub has no public ingress. Cloud Run uses Direct VPC egress to a private IP.
- The public process has no mutation route and receives no write credential.
- `ARCHON_DEMO_QUERY` is an exact allowlist; wildcards, padded equivalents, alternate
  queries, and a zero/multiple match readiness result fail closed.
- GitHub uses OIDC/WIF rather than a service-account key. All actions are full-SHA pinned.
- The workflows require distinct deploy, runtime, and governed-proof identities. Every proof
  job fails before OIDC if `GCP_PROOF_SERVICE_ACCOUNT` is empty or aliases deploy/runtime.
- The write and rollback jobs revalidate the exact reviewer/master-only environment policy,
  then bind exactly one content-bound GitHub approval event and configured reviewer before
  requesting a cloud credential. Environment names alone are not treated as human identity.
- The runtime image is digest-pinned, runs as UID 65532, and carries the sealed DataHub MCP
  environment. The Compose path drops all capabilities, is read-only, uses
  `no-new-privileges`, and binds only to loopback.
- Gitleaks, CodeQL, SCA, boundary tests, public-output projection, size limits, security
  headers, and opaque provider failures reduce common application and supply-chain risks.

Open controls:

- **WA-SEC-1 (P0, owner):** create the dedicated runtime and proof service accounts. Bind the
  runtime only to the optional read-token secret; bind proof only to the configured VM's
  describe/IAP-tunnel path; set both repository variables and prove they differ from deploy.
  The WIF provider must accept only `master` tokens from `hosted-demo.yml` or
  `live-governed-proof.yml`, never repository-wide PR workflow tokens.
- **WA-SEC-2 (P0, owner):** retain the explicit synthetic-demo exception only while the GMS
  contains no customer data and remains private. Customer deployments require HTTPS,
  DataHub authentication, and a least-privilege read token.
- **WA-SEC-3 (P1):** add edge abuse controls or an authenticated ingress for customer use.
  Query scoping, four-request concurrency, three-instance maximum, and deadlines bound
  impact but are not a substitute for rate limiting.
- **WA-SEC-4 (P1):** produce SBOM, vulnerability scan, and provenance for the MCP-capable
  hosted image. Its Docker build is tested, but `provenance: false` is not a production
  supply-chain posture.
- **WA-SEC-5 (P1):** narrow `.c8rc.json`; the live adapters remain excluded from coverage.

## 3. Reliability

Implemented in code:

- `/healthz` means process liveness; `/readyz` means the configured query reached exactly
  one live DataHub dataset. Provider failure returns 503 without provider details.
- Audit search, entity hydration, schema, lineage, aspect history, concurrency, and total
  execution have explicit bounds and deadlines.
- Cloud Run has a three-instance ceiling and four-request concurrency. The workflow proves
  both the service URL and Firebase rewrite.
- G6 mutation requires exact pre-state, read-after-write verification, a content-addressed
  receipt, a second approval for rollback, and exact restoration verification.

Open controls:

- **WA-REL-1 (P0):** execute the write and rollback workflow once through both protected
  environments; code and synthetic tests are not live recovery evidence.
- **WA-REL-2 (P1):** create a reproducible seed/restore procedure for the flagship DataHub
  dataset. The current single GCE VM is a single-zone, manually curated demo dependency.
- **WA-REL-3 (P1):** use no-traffic candidate deployment and explicit promotion, or document
  an equivalent automated Cloud Run rollback.
- **WA-REL-4 (P1):** define a modest demo SLO and alert on readiness plus audit completion.

## 4. Performance efficiency

Implemented in code:

- The public profile permits one entity and two retained versions, uses bounded parallelism,
  and rejects incomplete or over-broad results instead of degrading silently.
- The readiness probe coalesces concurrent checks and caches successful or failed results
  for ten seconds.
- Direct VPC egress avoids an internet proxy between Cloud Run and DataHub.
- `load/audit.js` has a zero-error and p95 threshold, but it measures deterministic
  in-process execution rather than live DataHub.

Open controls:

- **WA-PERF-1 (P1):** capture live p50/p95/p99 for readiness and audit at concurrency 1 and
  4; record DataHub saturation and timeout rate.
- **WA-PERF-2 (P1):** tune CPU, memory, minimum instances, and concurrency from those
  measurements rather than from assumptions.

## 5. Cost optimization

Implemented in code:

- The active route avoids the unused AWS estate and Kubernetes. Firebase is static, Cloud
  Run is capped, and the DataHub VM cost is explicitly documented at roughly $3.40/day.
- The public query and execution ceilings bound per-request work and denial-of-wallet
  exposure. A teardown command is documented.

Open controls:

- **WA-COST-1 (P1, owner):** set a project budget alert and Artifact Registry retention.
- **WA-COST-3 (P1):** stop the GCE instance immediately after the required judging window.

Closed controls:

- **WA-COST-2:** the hosted API scales to zero, throttles CPU while idle, and is capped at
  one instance. The private DataHub VM remains the only meaningful judging-window cost.
- **WA-SEC-5:** every hosted release runs an image-digest-pinned OWASP ZAP passive DAST
  scan against the final Firebase origin and fails on medium/high alerts. JSON, HTML, and
  Markdown reports are retained as CI evidence.

## 6. Sustainability

Implemented in code:

- Application, registry, Cloud Run, and DataHub are colocated in `europe-west1`; private
  traffic stays regional.
- The active workload avoids the non-deployed multi-cloud reference chain and bounds maximum
  compute. Immutable static assets receive long cache lifetimes.

Open controls:

- **WA-SUS-2 (P1):** stop the always-on demo VM after judging and publish a customer sizing
  baseline instead of copying the demo shape.

## AWS Agentic AI Lens alignment

The relevant agentic-AI concerns are satisfied by reducing autonomy, not by adding another
agent framework.

| Concern | Implemented control | Residual gap |
| --- | --- | --- |
| Task and autonomy boundary | audit one query; deterministic findings; public path is read-only | none for the supported path |
| Tool authority | one G6 action catalog; exact target; separate writer; no browser-selected tool arguments | live protected-environment proof pending |
| Human oversight | authenticated DataSteward approval; expiry; replay defense; separate rollback approval | operational reviewer availability is owner-managed |
| Model risk | only narration can call a model; findings and action eligibility are deterministic; strict model provenance | optional live-provider prompts need customer data-governance review |
| Memory and data | no conversational memory; bounded DataHub metadata; public projection strips sensitive detail | no automated redaction before optional external narration |
| Observability and evidence | trace, request ID, release SHA, model provenance, write and rollback receipts | no active GCP alert/SLO yet |
| Failure containment | exact scope, deadlines, fail-closed parsing, stale-state rejection, verified rollback | single demo DataHub host and deploy promotion gap |

## Release gates

Before claiming **hackathon 9/10 readiness**, close WA-OE-1, WA-OE-2, WA-SEC-1, and
WA-REL-1. Before claiming **customer production readiness**, also close every P1 item or
publish a deployment-specific risk acceptance signed by the workload owner.
