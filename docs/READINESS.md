# Submission Readiness — Archon DataHub

Current source review: **2026-07-25**. Submission deadline: **2026-08-10,
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
| **1. Use of DataHub** | Official MCP read adapter; direct GMS aspect-version read; stable-source provenance handling; lineage blast radius; separate official `add_tags`/`remove_tags` write adapter; G6 governed writeback loop; frozen seven-case current-view-vs-retained-history benchmark. | **Implemented / source-complete; CI-unverified; live path user-gated.** | Obtain the exact benchmark artifact, then run against a real DataHub with retained aspect versions and stable pipeline identities; plant both a cross-source contradiction and a G6 gap; retain sanitized evidence of MCP reads, version recovery, blast radius, approval-bound canary tag write, read-after-write verification, and separately approved rollback. |
| **2. Technical Execution** | Deterministic audit/remediation code; strict fixture-vs-live model-runtime provenance with no prompt/credential/raw-response fields; one-bundle live harvest with fail-closed search/entity/history completeness; fixed one-URN synchronous and 25-URN durable budgets with controlled concurrency/deadlines; isolated hosted audit/remediation workers; secretless approval handoff with separate immutable deadline/90-day decided retention; least-privilege async start/status Lambda that verifies execution evidence and receipt chains; HTTP boundary in `src/http/server.ts`; production `Dockerfile`; React/Tailwind application with Cognito code + PKCE, lifecycle polling, terminal proof, WebCrypto evidence export, and passive judge tour; global plus decision-critical web coverage ratchets; exact-pinned Playwright/Axe CI journey over built Vite preview on desktop, Pixel 7, and 320×568 with fail-closed auth, zero-authority, keyboard, overflow, screenshot, and accessibility evidence; reproducible judge pack; deployment-generated no-store auth runtime config; self-contained `us-east-1` certificate/CloudFront-WAF edge stack; regional API WAF; default-deny prefix-list-scoped workload networking with no Fargate public IP; versioned S3 access logging; encrypted two-second status cache; active X-Ray; CI, CodeQL, availability, live-proof, protected governed-canary/rollback, supply-chain, and immutable AWS promotion workflows; locked AWS CDK reference architecture in `infra/aws/`; project-owned Guard policy and Trivy IaC scan. | **Implemented / source-complete; CI/CD execution unverified.** | Obtain branch CI, CodeQL, benchmark, judge-pack, browser, coverage, container, web, worker, infra, security, load, SBOM, scan, and attestation evidence. Configure protected environments, narrow one-dataset `DATAHUB_DEMO_QUERY` values, separate hosted DataHub read/write MCP endpoints, distinct tokens, the three external endpoint prefix lists, and AWS OIDC. Keep `WorkerDesiredCount=0` until the exact image is green, then activate and prove both isolated worker services and retain browser start → immutable report → approval → terminal receipt/evidence digests and verified/rejected summaries. |
| **3. Originality** | “Audit the catalog itself” positioning; temporal/provenance contradictions rather than generic catalog chat; lineage-aware blast radius; evidence dossier, human approval, exact-action catalog, verified writeback, hash-chained receipt; frozen positive and false-positive-control cases. | **Implemented / source-complete; benchmark CI-unverified.** | Retain the exact benchmark artifact and live proof. Do not describe the current-view boundary as a competitor-product benchmark or claim hosted statistical superiority. |
| **4. Real-World Usefulness** | Governance checks, current-view drift, version-history conflict detection, blast radius, JSON/Markdown/SARIF exporters, browser and CI judge packs, safe remediation contracts, dashboard, scheduled public-path availability proof, and production-oriented AWS topology. | **Implemented / source-complete; operational value user-gated.** | Complete one realistic catalog incident end-to-end on live infrastructure; show a practitioner-readable report and verified remediation receipt; prove authentication, least-privilege read/write separation, failure behavior, audit retention, rollback, and sustained availability. |
| **5. Submission Quality** | Public-facing README and design/research documents; guided UI; deterministic sample-output generator/verifier; reproducible commands and disclosure material (`LICENSE`, `NOTICE.md`). | **Source-complete except final/live media; CI-unverified.** | Retain the verified judge pack, then add the public working-project URL, final screenshots, concise English testing instructions, sub-three-minute public demo video, required Devpost text, and claim consistency review. |
| **OSS bonus** | A distinct `get_aspect_history` candidate for the official DataHub MCP server is staged against exact upstream commit `9a6946d…`, with a read-only/bounded implementation, registration patch, 13 focused upstream tests, dated overlap inspection, and a CI job that applies it to that revision and runs upstream lint/type/focused tests. The older `datahub-audit` Skill remains supplemental because it overlaps parallel audit-skill work. | **Source-complete; CI-unverified; no bonus claimed yet.** | Obtain green remote candidate CI, recheck upstream overlap immediately before submission, open a focused public upstream PR with maintainer-ready context, and link it. A local folder or CI result alone does not earn the bonus. |

## Required deliverables

| Official requirement | State | Exact remaining action |
|---|---|---|
| Working application using open-source DataHub plus MCP Server, Agent Context Kit, DataHub Skills, or Analytics Agent | Implementation is present; **CI and live behavior are unverified**. | Complete CI and the live DataHub proof. Ensure behavior shown in the submission exactly matches the deployed build. |
| Easy-access project URL for judges | **User-gated; absent.** | Deploy the exact CI-approved artifacts and provide a free, stable URL. If authentication is required, include judge credentials and testing instructions. |
| Public source repository with all source, assets, instructions, and visible Apache 2.0 license | Repository and license material exist; current branch changes are **CI-unverified**. | Merge/publish the accepted commit, verify the repository About panel detects Apache 2.0, and verify a clean judge can follow setup instructions. |
| Text description | **Deferred-to-end; required.** | Write the final English Devpost description only after the live claims and URLs are fixed. A separate blog post is not listed as a required deliverable. |
| Demonstration video | **Deferred-to-end; required.** | Publish a video shorter than three minutes on YouTube, Vimeo, or Youku; show the functioning deployed project; use only authorized marks/music; provide the public URL. |
| Sample outputs | Deterministic JSON, Markdown, SARIF, dossier, plan, approval, verified receipt, and rollback pack is **source-complete; CI-unverified**. | Retain the exact remote `judge-evidence-<sha>` artifact and link or project its sanitized files for judges; never label the synthetic pack as live proof. |
| Testing access through the judging period | **User-gated.** | Keep the application free and available through **2026-08-31, 17:00 Eastern Time**, monitor it, and retain a rollback path and non-expiring judge access. |
| English submission materials | **Deferred-to-end.** | Deliver the description, video narration/subtitles, and testing instructions in English or include an English translation. |
| New-project and third-party disclosure compliance | Disclosure files exist; final narrative review remains. | Ensure `NOTICE.md`, repository history, final text, and video consistently disclose reused patterns and authorized third-party services. |
| Completed Devpost entry | **Deferred-to-end.** | Enter every required field and submit before the deadline; verify every URL in an unauthenticated browser. |

## Remaining proof gates

### 1. Remote CI evidence

- Push the final branch and retain the exact commit and run URLs.
- Require the ordinary CI, CodeQL, and supply-chain workflows to finish for that commit.
- Retain the automatic v4 supply-chain attestation; the daily path resolves the exact live
  `Archon-production` deployment through the protected `production-observer` environment
  and dedicated `AWS_RUNTIME_READ_ROLE_ARN`. It verifies the exact deployment artifact,
  embedded CI artifact digests, ECS/Lambda/versioned-S3 live bytes, scans the same three
  inner subjects, repeats the AWS byte observation, and revalidates the sealed current
  observer whole-snapshot receipt immediately before signing. It then reads the latest
  CodeQL and workflow-security runs for the exact deployed historical source SHA twice and
  requires both snapshots to equal the sealed source-gate receipt; the deployed SHA need
  not still be current `master`. Before promotion, alternatively dispatch the workflow with
  the exact successful CI run ID and 40-character SHA so the original three artifacts have
  vulnerability intelligence no older than 24 hours.
- Configure and run the signed production-posture gate documented in
  [`docs/PRODUCTION_POSTURE.md`](PRODUCTION_POSTURE.md); all three stacks must have
  termination protection, be `IN_SYNC`, retain the exact confirmed alarm subscription,
  and remain unchanged across the bounded check.
- Retain only CI-generated coverage/readiness, container, deterministic web archive, CDK
  assembly/templates, Guard results, benchmark, replay-verified judge pack,
  Trivy/CodeQL SARIF, SBOM, CVE scan, availability, and attestation evidence.
- Treat every security result as a pipeline result. Security verification and release
  evidence are produced exclusively by CI/CD; workstation builds, local synths, manual
  scanners, and copied reports must not substitute for or supplement a CI/CD gate.

### 2. Real DataHub evidence

- Provide protected read and write credentials with no token fallback between them.
- Provide both the hosted MCP read endpoint and direct read-only GMS endpoint; hosted
  audits fail closed rather than treating MCP-only current state as complete history.
- Seed version history where repeated runs of one pipeline remain one source and two stable
  pipelines create the intended contradiction.
- Prove the instance actually retains the aspect versions Archon needs.
- Run `.github/workflows/live-datahub-proof.yml` and retain the sanitized result.
- Configure the three protected canary environments in
  [`docs/GOVERNED_CANARY.md`](GOVERNED_CANARY.md). The immutable deployment pipeline
  dispatches `.github/workflows/governed-canary.yml` after staging and blocks production
  until its exact signed rollback proof is verified. It fails closed unless the exact
  staging release, disposable TEST/DEV fixture, dedicated tenant endpoints,
  pre-approval sealed plan/recovery digests, Cognito PKCE approval, terminal receipt,
  separately approved inverse, and read-after-rollback are all bound.
  Never expose write tools on the public Archon MCP/API surface.

### 3. AWS deployment evidence

- Configure an AWS account, GitHub OIDC trust, protected environments, budgets, and
  deployment secrets.
- Configure `production-observer` with the exact production application origin and bounded
  demo query. It carries no AWS role or provider token and must run the scheduled
  credentialless availability workflow without an approval wait.
- Ensure each environment's OIDC deployment role can perform the live, read-only
  evidence calls used by the fail-closed gates, including `ec2:DescribeVpcs`,
  `ec2:DescribeSecurityGroups`, `ec2:DescribeSecurityGroupRules`,
  `elasticloadbalancing:DescribeLoadBalancers`, the required WAFv2 getters, and
  `logs:DescribeLogGroups`, `kms:DescribeKey`, and
  `kms:GetKeyRotationStatus`. A successful CloudFormation deployment without
  these independently observed contracts is not promotable.
- CDK-bootstrap that account in both the selected workload region and `us-east-1`; the
  edge-first deployment cannot create its global certificate/WAF resources otherwise.
- Configure `ARCHON_CLOUDFRONT_DOMAIN_NAME` and its owning public
  `ARCHON_CLOUDFRONT_HOSTED_ZONE_ID` in both protected GitHub environments. Do not
  configure a certificate ARN: `Archon-<stage>-Edge` creates and DNS-validates the ACM
  certificate in `us-east-1`, creates the CloudFront-scope WAF/logging resources, and
  hands their validated outputs to the regional platform deployment.
- Configure the account-owned customer-managed
  `ARCHON_DATAHUB_READ_EGRESS_PREFIX_LIST_ID`,
  `ARCHON_DATAHUB_WRITE_EGRESS_PREFIX_LIST_ID`, and
  `ARCHON_LLM_EGRESS_PREFIX_LIST_ID` values in both protected environments. Each must
  be a complete, non-empty IPv4 list with entries no broader than `/8` and the exact
  `ArchonEgressScope` tag expected by the deployment gate; their `MaxEntries` weights,
  together with the AWS service lists, must remain within the pipeline's conservative
  60-rule outbound security-group quota.
- Do not configure S3/DynamoDB prefix-list variables. The pipeline must resolve the exact
  AWS-owned regional `com.amazonaws.<region>.s3` and
  `com.amazonaws.<region>.dynamodb` IDs and pass them to the platform stack separately
  from the three external endpoint allowlists.
- Configure a trimmed, non-wildcard `DATAHUB_DEMO_QUERY` in staging and production that
  resolves to exactly one safe demo dataset; retain its digest-bound smoke evidence.
- Allow deployment only from a successful default-branch CI run and matching full SHA.
- Revalidate the current default-branch control-plane SHA and latest exact CI, CodeQL, and
  workflow-security receipts after approval, before AWS OIDC, before mutation, and after
  the live production byte observation immediately before promotion evidence is sealed;
  retain the canonical receipt in deployment evidence.
- Promote the verified inner container, SPA, and Lambda archive digests; do not rebuild
  application artifacts during deployment.
- Verify CloudFront/S3, Cognito code + PKCE, the exact no-store
  `/runtime-config.json`, scoped API Gateway authorization, Fargate,
  queues/state machine, 90-day decided-approval retention, evidence retention, terminal
  receipt/evidence projection, both WAF associations, sampled-data protection, filtered
  logging configurations and encrypted retained log groups, least-privilege
  security-group egress, disabled public-IP assignment, versioning/server-access logging,
  the CloudFront origin key/usage-plan binding and backend credential non-propagation,
  direct-origin rejection, the encrypted two-second status cache, active X-Ray, alarms,
  public audit, negative authorization/schema cases, and rollback.
- Retain the public application URL and sanitized deployment receipt, including its
  digest-bound edge-security, regional-WAF, and network-egress contracts plus edge and
  regional CDK outputs. Keep the service available for the full judging period.

### 4. Judge evidence and final submission

- Retain the replay-verified, checksum-sealed synthetic judge pack for the exact accepted
  SHA; its artifact digest must appear in the default-branch release attestation.
- Use the browser's on-demand WebCrypto projection for the live demo, and keep tenant
  metadata within the judge access boundary.
- Capture screenshots only from the final deployed release.
- Record the final live demo only after the deployed commit and DataHub proof are fixed.
- Write the English Devpost text and testing instructions, then perform a claim-by-claim
  consistency check against the README, video, live application, and retained evidence.
- Submit on Devpost last.

## CI/CD truth

CI definitions now cover application build/test, web build/test, global and
decision-critical coverage, exact-pinned Chromium desktop/mobile Vite-preview journeys,
keyboard/overflow/Axe gates, CI-only browser evidence, and deterministic packaging,
the frozen DataHub benchmark, replay-verified judge evidence, CDK
typecheck/assertions/coverage/synth, nested Lambda packaging, dependency audits,
project-owned CloudFormation Guard policy tests, Trivy IaC SARIF, container checks, CodeQL,
load/SLO, exact-artifact daily/manual SBOM/CVE rescans, and freshness-bound v4 attestations.
**None is declared green for this branch until the corresponding remote run completes.**

The CD definition now covers a successful-default-branch source gate, artifact-envelope and
inner-digest verification, short-lived AWS OIDC credentials, account allow-listing,
semantic v4 attestation verification with a 24-hour database-retrieval limit,
edge-first certificate/WAF deployment and validated platform handoff, AWS-owned regional
S3/DynamoDB prefix-list resolution, validation of the three account-owned external egress
lists, staging deployment, versioned secret refresh, ECR scan, exact no-store auth
runtime-config publication, control-Lambda dependency/SCA gates, fail-closed hosted
start/status smoke contracts, protected OWASP
ZAP DAST, production approval, same-digest promotion, rollback selection, and
retained deployment evidence plus a scheduled public availability proof. It is **not
operationally proven yet**: the repository currently has no configured GitHub environments,
trusted second collaborator for protected approvals, branch protection, AWS
role/bootstrapped account, deployment secrets, hosted URL, or successful promotion
receipt. Therefore Archon has a comparable CD design,
but not yet the same proven end-to-end posture as the referenced Nebius, Qwen, or OpenAI
Buildweek projects.

## Multiple submissions

Multiple Devpost submissions are allowed, but every submission must be **unique and
substantially different** from the others, as determined by the sponsor and Devpost. A
reskin, provider swap, or alternate deployment of Archon is not a safe second submission.
Any second entry needs a different problem, user journey, core agent behavior, and demo.
