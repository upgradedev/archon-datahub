# Active workload Well-Architected and Agentic AI Lens review

Review date: 2026-08-09. Scope: Firebase Hosting → a bounded Cloud Run read API →
private DataHub Core 1.6, the customer Compose quickstart, and the separately protected G6
write/rollback proof. The repository's undeployed AWS reference architecture is not counted as
runtime evidence.

This is an engineering review against all six AWS Well-Architected pillars, applied
cloud-neutrally to the active GCP workload, plus the relevant Agentic AI Lens concerns. It is
not an AWS certification. `implemented` means repository evidence exists; `observed` means a
hosted or protected pipeline exercised the control.

## Executive decision

The active slice is intentionally small: audit one exact dataset, reconcile retained DataHub
evidence, compute deterministic findings and prepare one reversible G6 action. Public access is
read-only. Mutation exists only in protected CI with a distinct identity and two content-bound
human approvals.

| Pillar | State | Strongest evidence | Residual risk |
| --- | --- | --- | --- |
| Operational excellence | Strong demo posture | SHA-bound CI/deploy, readiness, runbooks, request IDs, retained artifacts | no customer-specific on-call/SLO |
| Security | Strong | private GMS, no public mutation route, WIF/OIDC, distinct identities, SAST/SCA/SBOM/DAST | anonymous edge has bounded scope but no dedicated rate limiter |
| Reliability | Strong for judging | fail-closed readiness, deadlines, exact read-back, automatic recovery path | one single-zone demo VM |
| Performance efficiency | Good | one-entity scope, bounded history/concurrency, Cloud Run max-one, offline SLO gate | no broad catalog-scale benchmark claim |
| Cost optimization | Strong | static Firebase, scale-to-zero Cloud Run, no EKS, temporary low-cost GCE host | VM cost persists during judging |
| Sustainability | Good | one region, private regional path, bounded compute, teardown plan | availability requires the demo VM to remain on |

## 1. Operational excellence

Implemented and observed:

- Required GitHub checks build and test one immutable candidate; no local build is accepted as
  release evidence.
- `hosted-demo.yml` deploys the exact image and SPA candidates, proves `/readyz`, executes the
  live audit, runs production browser journeys and seals DAST artifacts.
- `live-governed-proof.yml` separates read/plan, write and rollback into three bounded jobs and
  retains content-addressed receipts.
- `docs/HOSTED_DEMO_DEPLOY.md`, `docs/QUICKSTART.md` and `docs/JUDGE_TESTING.md` are the
  operator, customer and judge paths.
- Request IDs, release SHA and source/model provenance make failures attributable.

Residual deployment-owner controls:

- **WA-OE-1 (P1):** define a customer-specific SLO, paging owner and escalation path before
  production use. The judging monitor is not a substitute for customer operations.
- **WA-OE-2 (P1):** rehearse customer-specific rollback and DataHub recovery; the public demo
  uses synthetic data and a replaceable host.

## 2. Security

Implemented and observed:

- DataHub GMS has no public ingress. Cloud Run reaches it through regional private networking.
- The anonymous process receives no write credential and exposes only health, readiness and one
  exact allowlisted audit. Zero/multiple matches, padded or alternate queries and provider
  failures fail closed.
- GitHub obtains short-lived GCP credentials through workload identity federation. Deploy,
  runtime, proof and video identities are distinct and constrained to exact repository/ref/
  workflow conditions.
- The write path exposes only typed `add_tags`/`remove_tags` operations for one entity/column/
  tag. The transport is one-shot and each action is bound to the approved plan digest.
- Write and rollback jobs revalidate the environment configuration, exact reviewer identity,
  exact approval comment, master SHA and run attempt before requesting cloud credentials.
- Gitleaks, CodeQL, dependency review, npm/Python SCA, OpenVEX, CycloneDX SBOM, pinned actions,
  non-root container checks, Trivy, CloudFormation Guard, SARIF and OWASP ZAP run in CI.
- The final hosted origin uses strict CSP without `unsafe-inline`, anti-framing, MIME,
  referrer, permissions and cross-origin isolation headers; DAST rejects every medium/high alert.

Residual controls:

- **WA-SEC-1 (P1):** add authenticated ingress and/or dedicated rate limiting for a customer
  deployment. The demo is bounded to one query, four in-process requests and one Cloud Run
  instance, but this is not a general abuse-control layer.
- **WA-SEC-2 (P1):** customer deployments must use HTTPS, a least-privilege DataHub token,
  secrets management and deployment-specific retention/redaction policy. The anonymous demo is
  synthetic and uses a private loopback exception only inside the protected proof tunnel.

## 3. Reliability

Implemented and observed:

- `/healthz` proves process liveness; `/readyz` proves the allowlisted query reaches exactly one
  live DataHub dataset. Opaque 503 responses do not leak provider details.
- Search, hydration, schema, lineage, retained history, concurrency and total execution have
  explicit limits and deadlines. Unknown evidence never becomes a pass.
- Cloud Run scales to zero, caps at one instance, and the hosted workflow proves both direct
  service and Firebase-rewrite paths.
- The governed action checks the exact pre-state, verifies write read-back, creates a rollback
  proposal, requires a separate recovery approval and verifies byte-equivalent logical state.
- If the forward job cannot publish its receipt, recovery can restore from prepared evidence
  after confirming the current state is exactly either the pre-state or approved post-state.

Residual controls:

- **WA-REL-1 (P1):** the single-zone synthetic DataHub host is a judging dependency. A customer
  deployment must use its own DataHub availability, backups and restore objectives.
- **WA-REL-2 (P1):** progressive Cloud Run traffic promotion is unnecessary at max-one demo
  scale but recommended for a customer production rollout.

## 4. Performance efficiency

- The public profile resolves one entity, hydrates only required aspects and two retained
  versions, and bounds lineage hops, result size and concurrency.
- Readiness requests are coalesced and cached for ten seconds; provider calls have deadlines.
- Direct VPC egress avoids a public proxy and all active components are colocated in
  `europe-west1`.
- The offline load gate requires zero errors and a p95 threshold. No unsupported enterprise-
  scale or multi-million-entity throughput claim is made.

**WA-PERF-1 (P1):** customers should establish live p50/p95/p99 and tune CPU, concurrency and
catalog query policy against their own graph. This is intentionally not a submission blocker.

## 5. Cost optimization

- The active design deliberately avoids EKS/Kubernetes. Firebase serves immutable static assets;
  Cloud Run uses CPU throttling, minimum zero and maximum one instance.
- The private DataHub Core VM is the only material judging-window cost, previously measured at
  roughly USD 3.40/day. It is synthetic, replaceable and scheduled for teardown after judging.
- The exact query and bounded execution prevent unbounded per-request graph work.
- CI artifacts have explicit retention; no release artifact is built or retained on the owner's
  low-disk workstation.

**WA-COST-1 (P1, owner):** retain a modest cloud budget alert and repository/package retention,
then stop the VM immediately after the required judging window.

## 6. Sustainability

- Static delivery, scale-to-zero compute, regional private traffic and maximum-one runtime bound
  idle and peak consumption.
- Immutable caching avoids repeated SPA transfer and build work.
- The demo VM trades temporary idle energy for judge availability; automated teardown is the
  compensating control. Customer sizing should follow measured utilization, not copy the demo.

## Agentic AI Lens alignment

Archon improves agent safety by limiting autonomy rather than adding an unconstrained planner.

| Concern | Implemented control | Residual gap |
| --- | --- | --- |
| business objective | one narrow job: find DataHub integrity risk and prepare one governed repair | no general autonomous administration claim |
| context quality | DataHub is authoritative context; ACK preserves provenance and unknowns; five pinned Skills shape analysis | customer source quality remains the customer's responsibility |
| tool authority | public read-only; one typed G6 action; exact target and plan digest; one-shot privileged transport | customer role mapping is deployment-specific |
| human oversight | authenticated DataSteward write approval and separate rollback approval | reviewer availability is an operator concern |
| model risk | findings, severity, action and rollback are deterministic; optional model can narrate only | external narration needs customer DPA/redaction review |
| memory/data | no conversational memory; bounded metadata; public projection removes private operational detail | no generic PII detector before optional external narration |
| observability | request ID, release SHA, source/model provenance, audit/write/rollback receipts | customer alerting remains deployment-specific |
| failure containment | fail-closed parsing, deadlines, exact scope, stale-state rejection and verified recovery | single demo DataHub host |

## Release decision

Hackathon release readiness requires one exact SHA to pass CI, hosted live audit, strict DAST,
browser journeys, governed write/read-back/rollback and submission-video generation. Customer
production readiness is a separate decision and additionally requires closing the deployment-
specific P1 items above. This separation prevents the demo's strong evidence from becoming an
unsupported blanket production claim.
