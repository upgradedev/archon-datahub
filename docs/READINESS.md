# Submission Readiness — Archon DataHub

Current source review: **2026-07-29**. Submission deadline: **2026-08-10,
17:00 EDT**.

This document is deliberately evidence-based. It does not assign a predicted judge score,
green-CI state, live-DataHub state, or deployment state without the corresponding remote
run or public endpoint. The machine report's percentage is only equal-weight evidence
coverage, as defined below.

Remote source validation for revision
`13bb4aaddc5ab97c76ea246cc46156b238d5d8b1` is successful: [CI run
30336582832](https://github.com/upgradedev/archon-datahub/actions/runs/30336582832),
[CodeQL run
30336583192](https://github.com/upgradedev/archon-datahub/actions/runs/30336583192), and
[Workflow Security run
30336583604](https://github.com/upgradedev/archon-datahub/actions/runs/30336583604).
This validates the source and static contracts plus the retained CI artifacts; it does not
claim a live AWS deployment, live DataHub result, GitHub-posture receipt, reviewer gate,
public URL, upstream merge, feedback submission, video, or Devpost entry.

## Status vocabulary

- **Implemented / source-complete:** the implementation and its tests or configuration are
  present in this branch. This does not mean CI has accepted the commit.
- **Source CI-validated:** the reviewed implementation revision passed its remote source
  gates. This does not mean a manual, protected, credentialed, or deployment workflow ran.
- **CI-unverified:** the relevant workflow exists, but this branch still needs a remote run
  and retained run URL/artifacts.
- **User-gated:** completion requires credentials, a cloud account, an external service,
  an approval, or evidence that cannot be manufactured offline.
- **Deferred-to-end:** intentionally postponed until the product and live proof are stable.

## Machine-readable readiness semantics

`npm run readiness` reports two deliberately different views:

1. **Official judging-evidence projection.** It uses the five official criteria exactly as
   named below, each at **20%**. The percentage is evidence coverage, not a predicted judge
   score. Check weights only prioritize evidence within one criterion; they cannot make one
   official criterion count more than another.
2. **Offline capability evidence.** It groups machine-checkable repository evidence into
   separate `engineering` and `security` axes. Its 95% gate is a CI regression gate only.
   A pass means the offline evidence remains healthy; it does **not** mean the entry is
   ready to submit. Engineering projections use stable `ENG-<official-id>` identifiers,
   while native security checks use `SEC-<number>`, keeping both capability namespaces
   disjoint from the unchanged official IDs.

Final readiness is fail-closed. The 95% offline threshold is never reused as a submission
threshold. The readiness projection is deliberately **unsigned**: it always emits
`submission.ready = false`, `submission.readyToSubmit = false`, and
`submission.submitted = false`. When every eligibility and capability check has passed,
it may emit only `submission.evidenceCompleteForSealing = true` with status
`evidence-complete-awaiting-seal`; otherwise its status is `blocked`. That flag is a
request to the protected sealing boundary, not a trusted ready-to-submit decision. A
consumer may establish trusted readiness only by verifying the exact
`https://archon.datahub.dev/attestations/submission-readiness-seal/v1` predicate signed by
`.github/workflows/submission-readiness.yml` for the canonical sealed subjects. The
post-submit `SQ11` confirmation remains a separate fact and cannot create a circular
pre-submit prerequisite or make the unsigned projection claim submission. The enforced
order is: aggregate without `SQ11`, protected readiness seal, real Devpost submission,
post-submit `SQ11` attestation, then a new reporting aggregate that may include `SQ11`.

All five official criterion IDs, both capability axes, and every registered external-proof
check must remain present with its exact criterion and readiness role. Check IDs must be
globally unambiguous and every evidence weight must be positive; a missing, duplicate,
mis-mapped, or invalidly weighted check is itself an internal blocker. The report exposes
internal failures separately from eligibility blockers, recommended evidence, and
post-submit confirmation. Eligibility remains blocked while any of these proofs is absent:

- a stable public working-project URL;
- functioning fresh-judge access, including credentials and testing instructions if auth
  is required;
- a public complete source repository whose hosting UI detects the Apache-2.0 license;
- every final written submission field and testing instruction in English (or with a
  complete English translation);
- a public demonstration video shorter than three minutes, with English
  narration/subtitles or a complete English translation;
- an active availability monitor, alert/recovery path, credential-rotation path, and free
  judge access configured for the full judging period;
- a final cross-review of `NOTICE.md`, repository history, Devpost text, and video for
  consistent reused-work and third-party disclosures; and
- retained live DataHub/deployed-application proof for the behavior and usefulness claimed.

The retained sanitized sample-output pack is still recommended by Devpost and contributes
to the judging-evidence projection, but `SQ9` is explicitly nonblocking. `SQ11` records the
completed, logged-out-verified Devpost entry only after submission. `SQ10` requires an
active monitor and recovery mechanism before submission and then remains an ongoing
operational obligation; it does not falsely claim that future uptime has already occurred.

The `bonus` axis is independent of official eligibility. `BONUS-OSS` requires public
upstream contribution/acceptance evidence, and `BONUS-FEEDBACK` requires confirmation of
the rules-defined, one-per-entrant optional Feedback Submission. `bonus.allBonusesReady`
never changes
`submission.evidenceCompleteForSealing` or any readiness trust decision.

### Strict external-evidence transition

Ordinary `npm run readiness` and regular CI deliberately have no file, environment, or
workstation-JSON override for external proof. With no manifest, every external proof stays
`user-gated`. The programmatic `computeReadiness({ externalEvidence })` path is reserved
for a protected verifier that has independently checked GitHub API metadata, the exact
artifact bytes/checksums, and its attestation before constructing `expectedBinding`.

The accepted manifest schema is
`archon.submission-readiness-evidence/v1`. It binds, exactly:

- repository `upgradedev/archon-datahub` and a lowercase 40-hex release SHA;
- hard-whitelisted source workflow
  `.github/workflows/submission-evidence.yml`, run ID, immutable artifact-producer
  attempt, and successful attestation attempt, with producer attempt not later than
  attestation attempt;
- artifact name `submission-evidence-<releaseSha>-<producerRunAttempt>`, numeric
  artifact ID, and lowercase SHA-256 digest;
- predicate type
  `https://archon.datahub.dev/attestations/submission-readiness/v1` and predicate digest;
- protected environment `submission-readiness`; and
- verifier workflow `.github/workflows/submission-readiness.yml` on
  `refs/heads/master`, with its exact run ID/attempt, environment ID, configured solo-owner
  reviewer ID, and approval-receipt digest.

Every proof also carries its exact registered ID/criterion, literal `verified` state,
sanitized evidence summary, and a named SHA-256-bound receipt. Unknown keys, unknown or
duplicate IDs, malformed values, mapping changes, binding differences, non-user-gated
targets, and repository/release/run/artifact/predicate/approval mismatches reject the
whole manifest: no partial proof is applied, and the report adds
`EVIDENCE:manifest` as an internal blocker. A valid manifest may be partial; only its
verified proofs transition and all others stay visibly gated. The verifier—not this
projection—owns artifact/attestation acquisition and trust establishment.

The deterministic aggregate **producer** is
`.github/workflows/submission-evidence.yml`. Its dispatch surface accepts only the exact
current release SHA and hard-registered upstream run IDs—never a claims document, JSON
blob, URL, workflow path, artifact path, or local file. For each registry row it verifies
the exact same-repository workflow path, release, branch, run/attempt, artifact
ID/name/digest/ownership, bounded canonical ZIP inventory, local checksums, signer
workflow, source digest/ref, custom predicate, and one exact matching attestation for
**every** registered proof envelope and proof-specific support subject. Each standard
support subject embeds one sanitized canonical capture whose bytes, size, record count,
role, fact subset, repository, and release are recomputed. The aggregate retains the exact
full upstream subject-inventory bytes, every inventoried regular file, predicate,
deterministic verification projections, and full subject/verification set digests. It
derives one distinct canonical receipt per proof, reruns the
proof-specific semantic validator and inventories the complete aggregate. That
network-facing producer has only `actions: read`, `attestations: read`, and
`contents: read`; it cannot request an OIDC token or write an attestation. A dependent
secretless job first pins the retained artifact's ID, name, digest, size, owning run, and
head SHA through the GitHub API, downloads only that ID, rechecks the complete inventory,
rebuilds the canonical claims/predicate/semantic projection byte-for-byte with the
immutable producer attempt, and only then attests `claims.json` and `SHA256SUMS`.
`id-token: write` and `attestations: write` exist only in that dependent job. A retry of
only the attester therefore signs the original producer-attempt subjects instead of
silently rebuilding claims for the retry attempt. The protected consumer separately
binds the immutable producer attempt used by `predicate.json` and the latest successful
workflow/attestation attempt, so an attester-only retry remains both verifiable and
unambiguous.

The validator does not accept `{}`, a generic `verified: true`, or arbitrary evidence
text. It enforces exact proof-to-source mappings and receipt schemas, public HTTPS URL
binding, a complete fresh-judge journey, exact Apache-2.0 repository detection, English
written-material contracts, a public English-accessible provider video of 1–179 seconds
with an exact video ID and rights review for all third-party material, official-period
New Projects Only repository history and cross-medium disclosure digests, non-live `SQ9`
classification, exact accepted
`acryldata/mcp-server-datahub` contribution provenance, and fresh availability, posture,
paging, recovery, credential-rotation, and judging-window facts. Cross-proof URL,
instructions, and claims digests must agree. `SQ4` requires four ordered, attested,
sanitized judge-user operation receipts plus a separate exact fresh-journey artifact and
terminal receipt. The lifecycle aggregate, every operation, and the journey must all bind
`stage: production` and the SHA-256 of the canonical application origin; a successful
workflow status or a valid receipt from staging or another origin is insufficient. The
protected consumer reruns this same validation—including freshness—during both collection
and independent review and reruns `gh attestation verify` for every retained upstream
envelope/support against the exact registered signer workflow, release, ref, predicate,
queried subject, and source-mode-aware **full attested subject inventory**. Retained
producer verification JSON is explanatory evidence, never the protected trust oracle.

The protected **review/sealer** path is
`.github/workflows/submission-readiness.yml`:

1. `collect` accepts only exact identifiers/digests—not JSON or a workstation path—and
   fetches one successful same-repository, current-master source run and artifact through
   the GitHub API. The producer identity is not selectable: both the TypeScript contract
   and CI verifier require `.github/workflows/submission-evidence.yml`. Collection verifies
   the raw artifact ZIP digest, safe/unique archive paths, complete inner `SHA256SUMS`,
   every named proof receipt, canonical claims/predicate contracts, proof-specific
   semantic/cross-proof/freshness rules, fresh upstream attestations over every registered
   envelope/support subject, and GitHub attestations over both aggregate claims and
   inventory.
2. `review` is bound to the `submission-readiness` environment. It requires one exact
   approval comment from the configured sole `upgradedev` owner, with self-review enabled
   and the approval remaining attributable. It validates the collected artifact metadata
   before downloading its bytes, then refetches and reruns the complete source verifier
   after approval. It constructs the canonical manifest and separate expected binding,
   invokes the unsigned programmatic readiness projection, and fails unless
   `evidenceCompleteForSealing == true`, status is
   `evidence-complete-awaiting-seal`, all of `ready`, `readyToSubmit`, and `submitted`
   remain false, and no internal or eligibility blocker exists.
3. `seal` resolves and bounds the exact reviewed artifact through the GitHub API before
   download, revalidates its inventory and approval receipt, and attests the exact
   canonical manifest/readiness/source/approval subject set with predicate
   `submission-readiness-seal/v1`, and retains a 90-day sealed artifact. Only successful
   verification of that seal—not the unsigned projection—establishes trusted readiness.
   The reviewed artifact exports its immutable producer attempt; a seal-only retry uses
   that attempt for approval/binding validation while requiring it not to exceed the
   current retry attempt.

The source artifact contract is intentionally fail-closed:
`claims.json`, `predicate.json`, `SHA256SUMS`, and every referenced receipt must be
regular, checksum-bound files; the custom predicate must be signed by the exact source
workflow/release. Claims must include `D4`, `U3`, `SQ3`–`SQ8`, and `SQ10`. `SQ9`,
and the two bonus receipts remain optional in this bundle. `SQ11` is forbidden: the
protected source verifier rejects both a claims entry and any retained `SQ11` receipt so
the pre-submit seal cannot depend on post-submit evidence. If an upstream receipt does not
yet exist, the workflow fails; it never creates a passing claim for it. The
environment must be configured with `upgradedev` as its sole individual User reviewer,
prevent-self-review disabled so the solo owner can approve, and a master-only custom
branch policy before this path can run.

For producers, `claimsDigest` is the SHA-256 of the exact `claims.json` bytes.
`receiptSetDigest` is the SHA-256 of the newline-terminated output of
`jq -cS '[.proofs[], .bonuses[]] | map({id, receipt}) | sort_by(.id)' claims.json`.
`SHA256SUMS` inventories every other regular file exactly once and never inventories
itself. `predicate.json` uses schema
`archon.submission-readiness-predicate/v1`, contains only
`schemaVersion`, `repository`, `releaseSha`, `source`, `artifactName`,
`claimsDigest`, and `receiptSetDigest`, and must be the exact custom predicate attached to
attestations for both `claims.json` and `SHA256SUMS`.

The aggregate producer now exists and is executable, but it is intentionally not
pass-capable without real upstream evidence. The existing attested
`.github/workflows/live-datahub-proof.yml` v4 artifact can produce `D4` and `U3`.
Availability evidence now also has an isolated, checksum-bound
`production-availability/v1` attestation, but it is only one input to later operational
proof and cannot alone satisfy `SQ3` or `SQ10`.

The protected `.github/workflows/submission-project-access.yml` and its dedicated
`.github/workflows/submission-judge-journey.yml` support producer now exist for `SQ3`–`SQ5`
and fail closed until the hosted production application and judge identity are configured.
The required `.github/workflows/submission-operations.yml` standard-v1 producer now exists
for `SQ10`. It accepts only exact scalar run IDs, independently verifies the registered
live/project-access sources plus the checksum-bound availability, posture, paging, and
governed-canary artifacts, reconstructs all facts again in a separate retry-safe attester,
and signs the exact nine-subject inventory. In particular, availability time remains the
attested upstream observation rather than the later public probe, alarm inventory is the
exact ten operational alarms within the fourteen-alarm stack topology, and governed-canary
verification stays bound to the raw verification digest already sealed by deployment
evidence. It is source-complete but cannot pass until fresh successful remote upstream
runs exist for the exact release.

The protected `.github/workflows/submission-content-review.yml` standard-v1 producer now
exists for `SQ6`–`SQ8`. It independently reconstructs the exact final Devpost fields,
credentialless public-video observation, complete repository history, disclosures, and
cross-medium claims; binds the protected environment approval to the candidate and its
transitive source digests; and signs the exact sixteen-subject inventory. It is
source-complete but intentionally cannot pass before the canonical final content JSON,
public under-three-minute video, fresh project-access evidence, and the trusted protected
solo-owner approval exist.

The optional `.github/workflows/submission-judge-pack.yml` standard-v1 producer now exists
for `SQ9`. It resolves only the latest successful current-release `master` CI push and its
exact-attempt judge/container artifacts, verifies the signed CI release predicate, labels
the evidence as a sanitized synthetic offline fixture rather than live proof, independently
reconstructs the facts, and signs the exact four-subject inventory.

The post-submit
`.github/workflows/submission-devpost-confirmation.yml` standard-v1 producer now exists
for `SQ11` and is documented in
[`SUBMISSION_DEVPOST_CONFIRMATION.md`](SUBMISSION_DEVPOST_CONFIRMATION.md). Its unprivileged
prepare job revalidates the exact pre-submit seal and reviewed final content; its
`submission-devpost-confirmation` protected job requires the configured sole owner to
verify the private submission confirmation and salted commitment out of band;
and its attester repeats the full source, approval, rules, and public-URL checks before
signing and verifying all six subjects offline and through persisted lookup. Its source
contract is CI-validated, but its protected workflow has not run and remains externally
blocked until the real entry is submitted,
the exact public Devpost URL and authoritative private submission time/commitment exist,
all judging URLs are live, the protected environment is configured, and the attributable
solo-owner approval occurs.

The optional `.github/workflows/submission-bonus-oss.yml` standard-v1 producer now exists.
It credentiallessly binds the exact public Apache-2.0 upstream repository and independently
merged four-path pull request to the immutable CI validation receipt, reconstructs the
complete candidate head tree from both receipt bytes and staged source, verifies merged path
modes/bytes plus the signed CI release predicate, and signs the exact registered four-subject
inventory. Its contract is documented in
[`SUBMISSION_BONUS_OSS.md`](SUBMISSION_BONUS_OSS.md). Its source and exact upstream
candidate validation are CI-validated, but it is intentionally blocked: no upstream PR has
been opened or changed, no matching merged PR
exists, and the contribution manifest/README truthfully remain in the staged phase.

The optional
`.github/workflows/submission-bonus-feedback.yml` standard-v1 producer now exists. It
retains only public rules metadata, privacy-preserving commitments, and independently
reviewed GitHub approval provenance; signs the exact registered three-subject inventory;
and is documented in
[`SUBMISSION_BONUS_FEEDBACK.md`](SUBMISSION_BONUS_FEEDBACK.md). Its source contract is
CI-validated, but it deliberately cannot pass before the real feedback, authoritative
confirmation timestamp/reference, canonical confirmation file, protected environment,
and exact solo-owner private approval exist.
Consequently the aggregate workflow fails closed when any required run is missing or comes
from another workflow; it does not reinterpret CI fixtures, availability, posture, paging,
or local OSS artifacts as sufficient proof. Video/final copy remain deferred-to-end, and
live paging, hosted judge access, license detection, disclosure approval, public upstream
acceptance, and feedback confirmation must come from the real dedicated pipelines rather
than manual JSON or synthetic passes.

These blockers cannot be cleared by fixture output, source inspection, or a green offline
CI gate. **Current ready-to-submit status: BLOCKED / NOT READY.**

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
| **1. Use of DataHub** | Official MCP read adapter; direct GMS aspect-version read; stable-source provenance handling; lineage blast radius; separate official `add_tags`/`remove_tags` write adapter; G6 governed writeback loop; frozen seven-case current-view-vs-retained-history benchmark. | **Implemented / source-complete; benchmark CI-validated; live path user-gated.** | Use the retained exact benchmark artifact, then run against a real DataHub with retained aspect versions and stable pipeline identities; plant both a cross-source contradiction and a G6 gap; retain sanitized evidence of MCP reads, version recovery, blast radius, approval-bound canary tag write, read-after-write verification, and separately approved rollback. |
| **2. Technical Execution** | Deterministic audit/remediation code; strict fixture-vs-live model-runtime provenance with no prompt/credential/raw-response fields; one-bundle live harvest with fail-closed search/entity/history completeness; fixed one-URN synchronous and 25-URN durable budgets with controlled concurrency/deadlines; isolated hosted audit/remediation workers; secretless approval handoff with separate immutable deadline/90-day decided retention; least-privilege async start/status Lambda that verifies execution evidence and receipt chains; HTTP boundary in `src/http/server.ts`; production `Dockerfile`; React/Tailwind application with Cognito code + PKCE, lifecycle polling, terminal proof, WebCrypto evidence export, and passive judge tour; global plus decision-critical web coverage ratchets; exact-pinned Playwright/Axe CI journey over built Vite preview on desktop, Pixel 7, and 320×568 with fail-closed auth, zero-authority, keyboard, overflow, screenshot, and accessibility evidence; reproducible judge pack; deployment-generated no-store auth runtime config; self-contained `us-east-1` CloudFront-WAF/log edge stack and regional provider-hostname/default-certificate distribution; regional API WAF; default-deny workload networking with dedicated DataHub PrivateLink and no Fargate public IP; stage-scoped retained Bedrock Mantle projects, PrivateLink, and short-term task-role tokens; versioned S3 access logging; encrypted two-second status cache; active X-Ray; CI, CodeQL, availability, live-proof, protected governed-canary/rollback, supply-chain, and immutable AWS promotion workflows; locked AWS CDK reference architecture in `infra/aws/`; project-owned Guard policy and Trivy IaC scan. | **Implemented / source-complete; source CI, CodeQL, and workflow-security validated; live CD execution user-gated.** | Link the retained source evidence for judges. The 12 solo-owner reviewer gates and five reviewerless automation/read-only environments are configured. Run the protected AWS foundation workflow, then configure tenant-scoped hosted DataHub read/write GMS and MCP URLs, distinct tokens/provider RBAC, and `ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME`. Keep `WorkerDesiredCount=0` until the exact image is green, then activate and prove both isolated worker services and retain browser start → immutable report → approval → terminal receipt/evidence digests and verified/rejected summaries. |
| **3. Originality** | “Audit the catalog itself” positioning; temporal/provenance contradictions rather than generic catalog chat; lineage-aware blast radius; evidence dossier, human approval, exact-action catalog, verified writeback, hash-chained receipt; frozen positive and false-positive-control cases. | **Implemented / source-complete; benchmark CI-validated.** | Link the retained benchmark artifact and obtain live proof. Do not describe the current-view boundary as a competitor-product benchmark or claim hosted statistical superiority. |
| **4. Real-World Usefulness** | Governance checks, current-view drift, version-history conflict detection, blast radius, JSON/Markdown/SARIF exporters, browser and CI judge packs, safe remediation contracts, dashboard, scheduled public-path availability proof, and production-oriented AWS topology. | **Implemented / source-complete; operational value user-gated.** | Complete one realistic catalog incident end-to-end on live infrastructure; show a practitioner-readable report and verified remediation receipt; prove authentication, least-privilege read/write separation, failure behavior, audit retention, rollback, and sustained availability. |
| **5. Submission Quality** | Public-facing README and design/research documents; guided UI; deterministic sample-output generator/verifier; reproducible commands and disclosure material (`LICENSE`, `NOTICE.md`). | **Source CI-validated except final/live media; final deliverables user-gated.** | Link the retained verified judge pack, then add the public working-project URL, final screenshots, concise English testing instructions, sub-three-minute public demo video, required Devpost text, and claim consistency review. |
| **OSS bonus** | A distinct `get_aspect_history` candidate for the official DataHub MCP server is staged against exact upstream commit `9a6946d…`, with a read-only/bounded implementation, registration patch, 13 focused upstream tests, dated overlap inspection, CI validation receipt, and a source-complete [merged-upstream evidence producer](SUBMISSION_BONUS_OSS.md). The older `datahub-audit` Skill remains supplemental because it overlaps parallel audit-skill work. | **Source and candidate CI-validated; externally blocked; no PR opened and no bonus claimed.** | Use the retained remote candidate validation receipt, recheck overlap, open one public PR limited to the exact four paths, and obtain an independent upstream maintainer merge within the submission period. Then update only the manifest status and contribution README status paragraph to their exact merged phase in a normal CI-reviewed release and dispatch the evidence workflow. A local folder, CI result, or merely open PR does not earn the bonus. |
| **Most Valuable Feedback prize** | The [official rules](https://datahub.devpost.com/rules) define an optional, one-per-entrant Feedback Submission and award its prize to individuals rather than Projects; the public challenge overview instructs entrants to complete the feedback section during submission. The [privacy-preserving evidence producer](SUBMISSION_BONUS_FEEDBACK.md) is source-complete. | **Source contract CI-validated; user-gated; completion unverified.** | While registered for the hackathon, opt in and submit at most one complete, actionable feedback response before **2026-08-10, 17:00 EDT**. Retain only the documented salted commitments and protected solo-owner review; do not treat the feedback as a Project feature or substitute for the OSS contribution. |

## Required deliverables

| Official requirement | State | Exact remaining action |
|---|---|---|
| Working application using open-source DataHub plus MCP Server, Agent Context Kit, DataHub Skills, or Analytics Agent | Implementation is **source CI-validated; live behavior remains unverified and submission-blocking.** | Retain live DataHub plus deployed-application proof. Ensure behavior shown in the submission exactly matches the deployed build. |
| Easy-access public project URL for judges | **User-gated; absent; submission-blocking.** | Deploy the exact CI-approved artifacts and verify a free, stable URL from an unauthenticated browser. |
| Functioning judge access | **User-gated; unproven; submission-blocking.** | Exercise the complete journey as a fresh judge. If authentication is required, provide the pipeline-managed `CONFIRMED` credential, concise testing instructions, and a tested rotation path for the full judging period. |
| Public source repository with all source, assets, instructions, and visible Apache 2.0 license | Local repository and license material exist; **public completeness and license detection are unverified and submission-blocking.** | Merge/publish the accepted commit, verify logged-out access to the complete repository, verify the repository About panel detects Apache 2.0, and verify a clean judge can follow setup instructions. |
| Text description | **Deferred-to-end; required.** | Write the final English Devpost description only after the live claims and URLs are fixed. A separate blog post is not listed as a required deliverable. |
| Demonstration video | **Deferred-to-end; required; submission-blocking.** | Publish a public video shorter than three minutes on YouTube, Vimeo, or Youku; show the functioning deployed project; provide English narration/subtitles or a complete English translation; use only authorized marks/music; provide the public URL. |
| Sample outputs (recommended, not an official required deliverable) | Deterministic JSON, Markdown, SARIF, dossier, plan, approval, verified receipt, and rollback pack is **source CI-validated and retained; nonblocking in `SQ9`**. | Link or project the sanitized files from the exact remote `judge-evidence-<sha>-<run-attempt>` artifact for judges; never label the synthetic pack as live proof. |
| Testing access through the judging period | **User-gated operational requirement.** | Before submission, activate free judge access, scheduled monitoring/alerting, rollback, recovery, and protected credential rotation. Keep those controls active through **2026-08-31, 17:00 Eastern Time**; the readiness projection records active controls, not fictional proof of future uptime. |
| English submission materials | **Deferred-to-end; submission-blocking.** | Deliver the description, video narration/subtitles, and testing instructions in English or include a complete English translation. |
| New-project and third-party disclosure compliance | Disclosure files exist; **final cross-medium review is submission-blocking.** | Ensure `NOTICE.md`, repository history, final text, and video consistently disclose reused patterns and authorized third-party services. |
| Completed Devpost entry | `SQ11` producer is **source CI-validated; unexecuted, deferred-to-end, and externally blocked.** | Seal an aggregate that excludes `SQ11`; submit every required field before the deadline; dispatch `submission-devpost-confirmation.yml` with the exact seal identity, public project URL, authoritative private UTC timestamp, and salted commitment; obtain the attributable protected solo-owner approval; require persisted verification of all six subjects; only then build a new reporting aggregate that may include `SQ11`. The unsigned projection itself never sets `readyToSubmit`. |

A separate blog post is not listed as a required deliverable. The optional Most Valuable
Feedback action is a rules-defined Feedback Submission and the public overview places its
feedback section during submission; it must be completed during the Feedback Period to be
eligible for that prize. This wording does not claim a separate public page or authenticated
UI layout.

## Remaining proof gates

### 1. Remote CI evidence

- The reviewed implementation revision has successful ordinary CI, CodeQL, and
  workflow-security runs linked above. Retain matching runs for every later source revision
  before promotion.
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
- The successful CI run retained coverage/readiness, container/security, deterministic web
  archive and browser evidence, CDK assembly/templates, Lambda packages, Guard results,
  DataHub benchmark, replay-verified judge pack, OSS validation receipt, MCP security/SBOM,
  and scan evidence. Availability, deployment, and live attestations remain separate,
  unexecuted proof gates.
- Treat every security result as a pipeline result. Security verification and release
  evidence are produced exclusively by CI/CD; workstation builds, local synths, manual
  scanners, and copied reports must not substitute for or supplement a CI/CD gate.
- The GitHub-posture workflow and source contracts are CI-validated; run
  `.github/workflows/github-repository-posture.yml` on `master` and retain its first live
  normalized secretless receipt. The automatic `GITHUB_TOKEN` tier checks only the
  repository/merge lifecycle values, public `master` protection signal, Apache-2.0
  detection, private vulnerability reporting, exact 17-environment inventory,
  `can_admins_bypass=false`, and each environment's exact `master`-only deployment policy.
  It must report detailed branch-protection rules, the Actions allowlist/SHA-pinning
  controls, and all environment secret-name inventories as unverified. No elevated
  credential is currently configured; a future tier would require the reviewed
  least-privilege set `Actions:read`, `Administration:read`, `Environments:read`, and
  `Metadata:read`. Never export or copy a workstation `gh` token into GitHub Actions.

### 2. Real DataHub evidence

- Provide protected read and write credentials with no token fallback between them.
- Provide both the hosted MCP read endpoint and direct read-only GMS endpoint; hosted
  audits fail closed rather than treating MCP-only current state as complete history.
- Seed version history where repeated runs of one pipeline remain one source and two stable
  pipelines create the intended contradiction.
- Configure `datahub-demo` and explicit solo-owner-protected `datahub-demo-seed`, then run the
  plan-before-mutation seed/reset protocol in
  [`docs/DEMO_DATA_STATE.md`](DEMO_DATA_STATE.md). Its exact official-pack commit/file
  digests, query/URN, two retained source identities, G6 email gap, dangling upstream, and
  two-URN hard-delete allowlist must all appear in the retained pipeline receipt.
- Renew the current reviewed OpenVEX disposition before its 14-day CI horizon fails at
  `2026-08-08T11:30:00Z`; the committed statement expires during judging at
  `2026-08-22T11:30:00Z`. Re-evaluate the exact runtime first and retain the 30-day maximum
  validity and pipeline-only review described in
  [`docs/LIVE_DATAHUB_PROOF.md`](LIVE_DATAHUB_PROOF.md).
- Prove the instance actually retains the aspect versions Archon needs.
- Run `.github/workflows/live-datahub-proof.yml` and retain the sanitized result.
- Configure the reviewerless read-only preparation environment and the three protected
  canary environments in
  [`docs/GOVERNED_CANARY.md`](GOVERNED_CANARY.md). The immutable deployment pipeline
  dispatches `.github/workflows/governed-canary.yml` after staging and blocks production
  until its exact signed rollback proof is verified. It fails closed unless the exact
  staging release, disposable TEST/DEV fixture, dedicated tenant endpoints,
  pre-approval sealed plan/recovery digests, Cognito PKCE approval, terminal receipt,
  separately approved inverse, and read-after-rollback are all bound.
  Never expose write tools on the public Archon MCP/API surface.

### 3. AWS deployment evidence

- Use the protected `.github/workflows/aws-foundation.yml` pipeline to reconcile the
  exact modern CDK bootstrap in `eu-west-1` and `us-east-1` and create the dedicated,
  environment-bound deployment role. The GitHub OIDC provider, protected environment,
  and foundation role already exist; no local bootstrap is accepted as evidence.
- Deploy the application in two pipeline phases. First dispatch
  `.github/workflows/deploy.yml` with `deployment_mode=staging-bootstrap`, an exact
  successful default-branch CI run/SHA, and the protected demo-state receipt. This runs the
  immutable source and control-plane gates, deploys and verifies staging, stops before the
  governed canary/production, and emits only
  `staging-bootstrap-manifest.json`, `attestation-predicate.json`, and `SHA256SUMS`.
  Verify the workflow attestation, then configure the six emitted non-secret values
  `CANARY_APPLICATION_URL`, `CANARY_EVIDENCE_BUCKET`,
  `CANARY_COGNITO_CLIENT_ID`, `CANARY_COGNITO_HOSTED_UI_ORIGIN`,
  `CANARY_CHROME_VERSION`, and `CANARY_CHROME_BINARY_SHA256`, together with the
  separately protected canary credentials and explicit solo-owner reviewer rules. Finally dispatch
  `deployment_mode=promote` for the selected immutable release; it repeats staging
  verification, requires the signed governed write/rollback canary, and only then permits
  protected production promotion. The bootstrap artifact is a bound configuration handoff,
  never a credential carrier. Its static/source contract is CI-validated; the actual
  `staging-bootstrap` and `promote` dispatches remain externally blocked and unexecuted.
- Configure the dedicated `judge-access-staging` and `judge-access-production`
  environments, narrow Cognito lifecycle roles, and protected password delivery described
  in [`docs/JUDGE_ACCESS.md`](JUDGE_ACCESS.md). Provision, rotate, reactivate, and deactivate judge
  identities only through the manual pipeline, require a permanent-password
  `CONFIRMED` read-back with no first-login challenge, and retain no credential artifact.
- Configure `production-observer` with the exact production application origin and bounded
  demo query. It carries no AWS role or provider token and must run the scheduled
  credentialless availability workflow without an approval wait.
- Ensure each environment's OIDC deployment role can perform the live, read-only
  evidence calls used by the fail-closed gates, including `ec2:DescribeVpcs`,
  `ec2:DescribeSecurityGroups`, `ec2:DescribeSecurityGroupRules`,
  `ec2:DescribeVpcEndpoints`, `cloudformation:GetResource`,
  `iam:SimulatePrincipalPolicy`,
  `elasticloadbalancing:DescribeLoadBalancers`, `wafv2:GetWebACL`,
  `wafv2:GetLoggingConfiguration`, `wafv2:GetWebACLForResource`, the dependent
  `cognito-idp:GetWebACLForResource` scoped to the exact `ArchonUserPoolArn`,
  `logs:DescribeLogGroups`, `kms:DescribeKey`, and `kms:GetKeyRotationStatus`.
  A successful CloudFormation deployment without the independently observed API-stage
  and exact Cognito user-pool associations is not promotable.
- Verify the foundation attestation proves the exact pinned `CDKToolkit` version in both
  the selected workload region and `us-east-1`; the edge-first deployment cannot create
  its global CloudFront-WAF/logging resources otherwise.
- Do not configure a custom CloudFront hostname, Route 53 hosted-zone value, or ACM
  certificate input. The regional stack uses the distribution's generated
  `*.cloudfront.net` hostname and default certificate, enforces HTTPS, and derives the
  Cognito callback/logout URLs from that hostname. `Archon-<stage>-Edge` creates only the
  CloudFront-scope WAF and retained KMS-encrypted logs in `us-east-1`; the pipeline passes
  its validated Web ACL ARN to the regional platform deployment.
- Configure the provider-issued
  `ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME` in both protected environments. The deployment
  must discover it in the authenticated account/region, require an external owner and
  verified provider private DNS, select two provider-supported account AZs, and pass that
  exact service/AZ tuple to CloudFormation before any mutation.
- Do not configure S3/DynamoDB prefix-list variables. The pipeline must resolve the exact
  AWS-owned regional `com.amazonaws.<region>.s3` and
  `com.amazonaws.<region>.dynamodb` IDs and pass them to the platform stack separately
  from the DataHub PrivateLink boundary. Do not configure an LLM secret or
  egress prefix list: each stack creates a retained stage-scoped Bedrock Mantle project
  and dedicated PrivateLink endpoint, and API/audit tasks mint short-term tokens from
  their bounded ECS task roles.
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
  receipt/evidence projection, the exact `ArchonUserPoolId`/`ArchonUserPoolArn` binding,
  both live WAF associations to one regional ACL, sampled-data protection, filtered
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
- Keep `submission-devpost-confirmation` bound to the sole `upgradedev` User reviewer,
  self-review enabled, administrator bypass disabled, and an exact `master` branch policy;
  the protected approval remains attributable without claiming separation of duties.
- Seal the pre-submit aggregate without `SQ11`, then submit on Devpost last. Keep the
  authenticated confirmation, salt, credentials, cookies, screenshots, and entrant PII
  outside GitHub.
- After submission, dispatch the `SQ11` workflow with the exact readiness run/artifact
  identity, public Devpost project URL, authoritative private UTC timestamp, and salted
  confirmation commitment. A public page or HTTP `200` alone cannot prove the private
  timestamp, required fields, or application functionality.
- Treat the real submitted entry, live public application/repository/video URLs, protected
  reviewer, and private confirmation inputs as external blockers. Only after all six
  subjects pass offline-bundle and persisted attestation verification may a later
  reporting aggregate include `SQ11`; never reseal pre-submit readiness with that result.

## CI/CD truth

CI definitions now cover application build/test, web build/test, global and
decision-critical coverage, exact-pinned Chromium desktop/mobile Vite-preview journeys,
keyboard/overflow/Axe gates, CI-only browser evidence, and deterministic packaging,
the frozen DataHub benchmark, replay-verified judge evidence, CDK
typecheck/assertions/coverage/synth, nested Lambda packaging, dependency audits,
project-owned CloudFormation Guard policy tests, Trivy IaC SARIF, container checks, CodeQL,
load/SLO, exact-artifact daily/manual SBOM/CVE rescans, and freshness-bound v4 attestations.
For the reviewed implementation revision, ordinary CI, CodeQL, and workflow-security are
green and the retained CI artifacts cover the source-level evidence listed above. This does
not mark scheduled, manual, protected, credentialed, or deployment workflows as executed.

The CD definition now covers a successful-default-branch source gate, artifact-envelope and
inner-digest verification, short-lived AWS OIDC credentials, account allow-listing,
semantic v4 attestation verification with a 24-hour database-retrieval limit,
edge-first CloudFront-WAF deployment and validated platform handoff, AWS-owned regional
S3/DynamoDB prefix-list resolution, fail-closed DataHub PrivateLink service/private-DNS/AZ
preflight and live endpoint evidence, staging deployment, versioned secret refresh, ECR scan, exact no-store auth
runtime-config publication, control-Lambda dependency/SCA gates, fail-closed hosted
start/status smoke contracts, protected OWASP
ZAP DAST, production approval, same-digest promotion, rollback selection, and
retained deployment evidence plus a scheduled public availability proof. The repository
control plane now has all 17 exact `master`-only environments, administrator bypass
disabled, strict app-bound `master` protection, a SHA-pinned explicit Actions allowlist,
private vulnerability reporting, and exact sole-owner approval on all 12 protected
mutation/approval environments. It is **not operationally proven yet** because the
protected AWS foundation/bootstrap pipeline, DataHub credential/endpoint configuration,
hosted URL, and production promotion receipt are still pending. Therefore Archon has a comparable CD design,
but not yet the same proven end-to-end posture as the referenced Nebius, Qwen, or OpenAI
Buildweek projects.

## Multiple submissions

Multiple Devpost submissions are allowed, but every submission must be **unique and
substantially different** from the others, as determined by the sponsor and Devpost. A
reskin, provider swap, or alternate deployment of Archon is not a safe second submission.
Any second entry needs a different problem, user journey, core agent behavior, and demo.
