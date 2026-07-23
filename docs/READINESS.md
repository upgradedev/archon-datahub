# Submission Readiness — Archon DataHub

Current source review: **2026-07-23**. Submission deadline: **2026-08-10,
17:00 EDT**.

This document is deliberately evidence-based. It does not assign a score, percentage,
test count, green-CI state, live-DataHub state, or deployment state until a corresponding
remote run or public endpoint exists.

## Status vocabulary

- **Implemented / source-complete:** the implementation and its tests or configuration are
  present in this branch. This does not mean CI has accepted the commit.
- **CI-unverified:** the relevant workflow exists, but this branch still needs a remote run
  and retained run URL/artifacts.
- **User-gated:** completion requires credentials, a cloud account, an external service,
  an approval, or evidence that cannot be manufactured offline.
- **Deferred-to-end:** intentionally postponed until the product and live proof are stable.

## Project submitted to the challenge

The intended category is **Agents That Do Real Work**.

Archon is a provenance-aware reliability control loop for the DataHub Context Graph. It
reads catalog metadata and version history, detects governance regressions and conflicting
claims, calculates downstream blast radius, prepares an evidence-bound remediation plan,
and permits one narrowly scoped G6 classification-tag correction only after authenticated,
digest-bound human approval. It then reads the state back, verifies postconditions, and
issues a tamper-evident receipt and rollback proposal.

The boundary is intentional:

- DataHub remains the catalog and context graph.
- `src/datahub/mcp-client.ts` and `src/datahub/mcp-client-live.ts` are the read capability.
- `src/datahub/mutation-client.ts` and `src/datahub/mutation-client-live.ts` are a separate,
  private, tag-only write capability with separate credentials.
- `src/mcp/server.ts` remains a public **read-only** Archon MCP surface.
- `src/remediation/` contains planning, approval binding, execution, verification,
  receipts, idempotency contracts, and rollback proposals.
- `src/datahub/version-history.ts` and `src/datahub/blast-radius.ts` provide provenance-aware
  conflict recovery and lineage impact.
- `src/audit-worker.ts`, `infra/aws/lambda/approval/handoff.js`, and
  `src/remediation-worker.ts` isolate read/LLM, approval-token, and write capabilities.
  Separate queues, roles, DLQs, bounded execution leases, append-only Object-Lock evidence,
  and verified/rejected receipts back the callback route.
- `infra/aws/lambda/control/` and `web/src/api.ts` implement the public durable
  start/status journey with an opaque 256-bit polling capability, immutable-evidence
  verification, continued polling through approval, and a strict terminal projection
  backed by independently verified execution evidence and receipt-chain summaries.
- Approval deadline and storage retention are separate: the deadline remains immutable,
  while a decided DynamoDB record is retained for 90 days for terminal-proof verification.

No live mutation, real DataHub result, AWS resource, or public URL is claimed here.

## Judge-facing matrix

The five official Stage Two criteria are equally weighted.

| Official criterion | Present in source | Current status | Proof still required |
|---|---|---|---|
| **1. Use of DataHub** | Official MCP read adapter; direct GMS aspect-version read; stable-source provenance handling; lineage blast radius; separate official `add_tags`/`remove_tags` write adapter; G6 governed writeback loop. | **Implemented / source-complete; CI-unverified; live path user-gated.** | Run against a real DataHub with retained aspect versions and stable pipeline identities; plant both a cross-source contradiction and a G6 gap; retain sanitized evidence of MCP reads, version recovery, blast radius, approval-bound canary tag write, read-after-write verification, and separately approved rollback. |
| **2. Technical Execution** | Deterministic audit/remediation code; one-bundle live harvest with fail-closed search/entity/history completeness; fixed one-URN synchronous and 25-URN durable budgets with controlled concurrency/deadlines; isolated hosted audit/remediation workers; secretless approval handoff with separate immutable deadline/90-day decided retention; least-privilege async start/status Lambda that verifies execution evidence and receipt chains; HTTP boundary in `src/http/server.ts`; production `Dockerfile`; React/Tailwind application with Cognito code + PKCE, continued lifecycle polling, and sanitized terminal proof in `web/`; deployment-generated no-store auth runtime config; CI, CodeQL, live-proof, protected governed-canary/rollback, supply-chain, and immutable AWS promotion workflows; locked AWS CDK reference architecture in `infra/aws/`; project-owned Guard policy and Trivy IaC scan. | **Implemented / source-complete; CI/CD execution unverified.** | Obtain branch CI, CodeQL, container, web, worker, infra, security, load, SBOM, scan, and attestation evidence. Configure protected environments, narrow one-dataset `DATAHUB_DEMO_QUERY` values, separate hosted DataHub read/write MCP endpoints, distinct tokens, and AWS OIDC. Keep `WorkerDesiredCount=0` until the exact image is green, then activate and prove both isolated worker services and retain browser start → immutable report → approval → terminal receipt/evidence digests and verified/rejected summaries. |
| **3. Originality** | “Audit the catalog itself” positioning; temporal/provenance contradictions rather than generic catalog chat; lineage-aware blast radius; evidence dossier, human approval, exact-action catalog, verified writeback, and hash-chained receipt. | **Implemented / source-complete; evaluation proof missing.** | Demonstrate the same planted defects against DataHub’s out-of-box behavior and Archon; document what Analytics Agent/MCP already provide versus Archon’s added control loop; retain a reproducible before/after result without claiming statistical quality that has not been measured. |
| **4. Real-World Usefulness** | Governance checks, current-view drift, version-history conflict detection, blast radius, JSON/Markdown/SARIF exporters, safe remediation contracts, dashboard source, and production-oriented AWS topology. | **Implemented / source-complete; operational value user-gated.** | Complete one realistic catalog incident end-to-end on live infrastructure; show a practitioner-readable report and verified remediation receipt; prove authentication, least-privilege read/write separation, failure behavior, audit retention, and rollback. |
| **5. Submission Quality** | Public-facing README and design/research documents; UI source; reproducible commands and disclosure material (`LICENSE`, `NOTICE.md`). | **Partially source-complete; final artifacts deferred-to-end.** | Public working-project URL, final screenshots, concise English setup/testing instructions, sample outputs, sub-three-minute public demo video, required Devpost text, and consistency review across every claim. |
| **OSS bonus** | A local DataHub Skill candidate exists under `contrib/datahub-audit/`. | **Candidate only; no bonus claimed.** | Confirm it is meaningfully distinct from existing upstream work, open an upstream issue/PR with tests and documentation, and link the public contribution. A local folder alone does not earn the bonus. |

## Required deliverables

| Official requirement | State | Exact remaining action |
|---|---|---|
| Working application using open-source DataHub plus MCP Server, Agent Context Kit, DataHub Skills, or Analytics Agent | Implementation is present; **CI and live behavior are unverified**. | Complete CI and the live DataHub proof. Ensure behavior shown in the submission exactly matches the deployed build. |
| Easy-access project URL for judges | **User-gated; absent.** | Deploy the exact CI-approved artifacts and provide a free, stable URL. If authentication is required, include judge credentials and testing instructions. |
| Public source repository with all source, assets, instructions, and visible Apache 2.0 license | Repository and license material exist; current branch changes are **CI-unverified**. | Merge/publish the accepted commit, verify the repository About panel detects Apache 2.0, and verify a clean judge can follow setup instructions. |
| Text description | **Deferred-to-end; required.** | Write the final English Devpost description only after the live claims and URLs are fixed. A separate blog post is not listed as a required deliverable. |
| Demonstration video | **Deferred-to-end; required.** | Publish a video shorter than three minutes on YouTube, Vimeo, or Youku; show the functioning deployed project; use only authorized marks/music; provide the public URL. |
| Sample outputs | **Recommended; not yet packaged as judge-ready examples.** | Add sanitized representative audit JSON, Markdown, SARIF, evidence dossier, and execution receipt outputs so judging does not depend on running the system. |
| Testing access through the judging period | **User-gated.** | Keep the application free and available through **2026-08-31, 17:00 Eastern Time**, monitor it, and retain a rollback path and non-expiring judge access. |
| English submission materials | **Deferred-to-end.** | Deliver the description, video narration/subtitles, and testing instructions in English or include an English translation. |
| New-project and third-party disclosure compliance | Disclosure files exist; final narrative review remains. | Ensure `NOTICE.md`, repository history, final text, and video consistently disclose reused patterns and authorized third-party services. |
| Completed Devpost entry | **Deferred-to-end.** | Enter every required field and submit before the deadline; verify every URL in an unauthenticated browser. |

## Remaining proof gates

### 1. Remote CI evidence

- Push the final branch and retain the exact commit and run URLs.
- Require the ordinary CI, CodeQL, and supply-chain workflows to finish for that commit.
- Retain the automatic v3 supply-chain attestation; before promotion, use the daily rescan
  or dispatch the supply-chain workflow with the exact successful CI run ID and 40-character
  SHA so the original three artifacts have vulnerability intelligence no older than 24 hours.
- Retain only CI-generated coverage/readiness, container, deterministic web archive, CDK
  assembly/templates, Guard results, Trivy/CodeQL SARIF, SBOM, CVE scan, and attestation
  evidence.
- Treat every security result as a pipeline result; workstation and manual scanner output
  must not substitute for a CI/CD gate.

### 2. Real DataHub evidence

- Provide protected read and write credentials with no token fallback between them.
- Provide both the hosted MCP read endpoint and direct read-only GMS endpoint; hosted
  audits fail closed rather than treating MCP-only current state as complete history.
- Seed version history where repeated runs of one pipeline remain one source and two stable
  pipelines create the intended contradiction.
- Prove the instance actually retains the aspect versions Archon needs.
- Run `.github/workflows/live-datahub-proof.yml` and retain the sanitized result.
- Configure the three protected canary environments in
  [`docs/GOVERNED_CANARY.md`](GOVERNED_CANARY.md), then run the manual-only
  `.github/workflows/governed-canary.yml`. It fails closed unless the exact staging
  release, disposable TEST/DEV fixture, dedicated tenant endpoints, pre-approval sealed
  plan/recovery digests, Cognito PKCE approval, terminal receipt, separately approved
  inverse, and read-after-rollback are all bound.
  Never expose write tools on the public Archon MCP/API surface.

### 3. AWS deployment evidence

- Configure an AWS account, GitHub OIDC trust, protected environments, budgets, and
  deployment secrets.
- Configure `ARCHON_CLOUDFRONT_DOMAIN_NAME`, a matching validated
  `ARCHON_CLOUDFRONT_CERTIFICATE_ARN` from `us-east-1`, and the owning public
  `ARCHON_CLOUDFRONT_HOSTED_ZONE_ID` in both protected GitHub environments.
- Configure a trimmed, non-wildcard `DATAHUB_DEMO_QUERY` in staging and production that
  resolves to exactly one safe demo dataset; retain its digest-bound smoke evidence.
- Allow deployment only from a successful default-branch CI run and matching full SHA.
- Promote the verified inner container, SPA, and Lambda archive digests; do not rebuild
  application artifacts during deployment.
- Verify CloudFront/S3, Cognito code + PKCE, the exact no-store
  `/runtime-config.json`, scoped API Gateway authorization, Fargate,
  queues/state machine, 90-day decided-approval retention, evidence retention, terminal
  receipt/evidence projection, alarms, public audit, negative authorization/schema cases,
  and rollback.
- Retain the public application URL and sanitized deployment receipt. Keep the service
  available for the full judging period.

### 4. Judge evidence and final submission

- Package sanitized sample outputs and screenshots.
- Record the final live demo only after the deployed commit and DataHub proof are fixed.
- Write the English Devpost text and testing instructions, then perform a claim-by-claim
  consistency check against the README, video, live application, and retained evidence.
- Submit on Devpost last.

## CI/CD truth

CI definitions now cover application build/test, web build/test and deterministic packaging,
CDK typecheck/assertions/coverage/synth, nested Lambda packaging, dependency audits,
project-owned CloudFormation Guard policy tests, Trivy IaC SARIF, container checks, CodeQL,
load/SLO, exact-artifact daily/manual SBOM/CVE rescans, and freshness-bound v3 attestations.
**None is declared green for this branch until the corresponding remote run completes.**

The CD definition now covers a successful-default-branch source gate, artifact-envelope and
inner-digest verification, short-lived AWS OIDC credentials, account allow-listing,
semantic v3 attestation verification with a 24-hour database-retrieval limit,
staging deployment, secret rotation, ECR scan, exact no-store auth
runtime-config publication, control-Lambda dependency/SCA gates, fail-closed hosted
start/status smoke contracts, protected OWASP
ZAP DAST, production approval, same-digest promotion, rollback selection, and
retained deployment evidence. It is **not operationally proven yet**: the repository currently has no configured
GitHub environments, branch protection, AWS role/bootstrapped account, deployment secrets,
hosted URL, or successful promotion receipt. Therefore Archon has a comparable CD design,
but not yet the same proven end-to-end posture as the referenced Nebius, Qwen, or OpenAI
Buildweek projects.

## Multiple submissions

Multiple Devpost submissions are allowed, but every submission must be **unique and
substantially different** from the others, as determined by the sponsor and Devpost. A
reskin, provider swap, or alternate deployment of Archon is not a safe second submission.
Any second entry needs a different problem, user journey, core agent behavior, and demo.
