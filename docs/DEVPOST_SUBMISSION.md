# Devpost submission source

This is the canonical English copy for submitted Devpost project `1125619`. Its public video,
thumbnail, five-image gallery, links and saved fields were rechecked after publication. The
release-bound video is https://youtu.be/6iHvBr4Qr1s.

## Project name

Archon for DataHub

## Elevator pitch

An evidence-first agent that audits your DataHub catalog against itself: it finds where two
sources disagree, traces what breaks downstream, and hands a steward one exact governed fix.

## Category

Agents That Do Real Work

## Judge proof strip

**Track: Agents That Do Real Work**

> **Proof strip:** 1 live OSS DataHub Core · 4 evidence-linked findings · 1 governed fix · verified
> read-back and rollback · upstream PR #183**

**The wedge:** Others trust the catalog; Archon proves it can be trusted before allowing one
reversible action.

**Judge shortcuts:** [live app](https://archon-datahub.web.app) ·
[exact 2:41 demo](https://youtu.be/6iHvBr4Qr1s) ·
[judge testing](https://github.com/upgradedev/archon-datahub/blob/master/docs/JUDGE_TESTING.md) ·
[sample outputs](https://github.com/upgradedev/archon-datahub/tree/master/examples) ·
[exact release](https://github.com/upgradedev/archon-datahub/releases/tag/datahub-hackathon-2026-final) ·
[upstream PR #183](https://github.com/acryldata/mcp-server-datahub/pull/183).

**Real DataHub write-back:** the public UI is deliberately read-only. Protected CI binds
separate human approvals to the exact G6 `add_tags` plan, read-back, rollback and verified
restoration. [Governed-proof run 31325511840](https://github.com/upgradedev/archon-datahub/actions/runs/31325511840)
demonstrates the mutation without exposing a public write credential.

## Inspiration

A data catalog is where an organisation agrees on what its data means. The problem is that it
can quietly stop agreeing with itself: two ingestion sources declare different owners, lineage
references an asset that no longer exists, or a sensitive field has no classification. Every
individual record can look valid while the catalog as a whole tells conflicting stories.

Most assistants make metadata easier to retrieve. We asked a harder question: is the context
internally consistent, what is actually exposed when it is not, and can one safe correction be
made without giving an agent open-ended authority?

## What it does

Archon runs a bounded evidence, reason and propose loop over DataHub.

- **Cross-source contradictions:** it reconciles current metadata with retained aspect history
  and ingestion-registry provenance, so it can recover a disagreement even when DataHub's
  `pipelineName` field remains sticky across runs.
- **Lineage gaps and blast radius:** it checks declared upstreams against the resolved graph and
  expands a missing asset into a bounded, cycle-safe downstream impact path.
- **Governance controls G1–G6:** deterministic checks cover ownership, domain, documentation,
  typing and classification. Unknown evidence stays unknown; an unrelated tag cannot satisfy G6.
- **Portable evidence:** JSON, Markdown and SARIF exports carry provenance and content digests,
  so a platform team can review a catalog finding in an existing code-scanning workflow.
- **One governed action:** only an unclassified sensitive field can become a typed `add_tags`
  plan. The anonymous app cannot write. Protected CI binds a human approval to the exact plan,
  verifies read-after-write, requires a separate rollback approval and verifies restoration.

The public demo's catalog evidence is not a mock. One click executes a read-only audit against a
private DataHub Core 1.6 catalog and returns four live findings: G6, a retained-history owner
contradiction, G2 and a dangling lineage edge. Narrative generation is deterministic and explicitly
reports that no provider model call occurred. A visibly labelled deterministic preview keeps the
story available if the live dependency is temporarily unavailable.

## How we built it

The core is TypeScript with deterministic domain rules and narrow ports. React, Tailwind and
Vite provide the steward interface. Firebase serves the immutable SPA; a scale-to-zero,
maximum-one Cloud Run adapter exposes only health, readiness and one allowlisted read audit to a
private DataHub Core host. No Kubernetes or EKS is required.

All four DataHub agent components have separate responsibilities:

| Component | Material use |
| --- | --- |
| DataHub MCP Server | bounded live search/entity/schema/lineage/quality reads and the protected exact tag mutation; retained history uses bounded direct GMS until upstream PR #183 lands |
| Agent Context Kit | provenance-bearing context envelope with explicit unknown preservation |
| DataHub Skills | pinned search → lineage → quality → audit → enrich workflow with receipts |
| Analytics Agent | grounded SQL/chart trace, context-quality output and proposal-only context improvement |

Security and quality evidence is pipeline-only: unit, integration, functional, authorization,
prompt-injection, component and Playwright user-journey tests; measured combined coverage ≥85%;
Gitleaks, CodeQL, dependency review, npm/Python SCA, OpenVEX, CycloneDX SBOM, container and IaC
scans; and strict OWASP ZAP DAST against the final Firebase origin. The final application
release, hosted proof, governed receipts and public 2:41 demo are bound to exact application SHA
`7cf2ab063312c2bf06fd2d65c798e802f7070a37`. CI verifies the public video's 161.48-second
duration, 1920×1080 dimensions, eight-scene structure and content hash.

## Challenges we ran into

Our first live integration failed even though the fixture suite was green. Search incorrectly
assumed DataHub's `count` was the number of returned results, entity reads missed an official
response shape, and the headline contradiction could not fire because retained versions carried
the first ingestion source's sticky `pipelineName`.

Running against DataHub Core revealed the better source of truth: the ingestion registry maps
each aspect run ID to its actual ingestion source. Archon now prefers that provenance and fails
closed when identity cannot be resolved. Contract tests are pinned to observed live response
shapes rather than convenient assumptions.

The governed proof also exposed two transport-lifecycle defects: successful read and write stdio
MCP children could outlive a bounded CI action. Both adapters now release authority explicitly;
the mutation transport is deliberately one-shot.

## Accomplishments we are proud of

- A no-login judge can run a real DataHub audit and inspect evidence-linked findings.
- Public reads and privileged writes have different code paths, identities and authority.
- The G6 correction is content-bound, human-approved, read-back verified and separately
  reversible rather than an autonomous catalog-admin tool.
- We contributed the missing bounded read-only `get_aspect_history` capability upstream in
  [acryldata/mcp-server-datahub#183](https://github.com/acryldata/mcp-server-datahub/pull/183).
  The PR is openly represented as under review, not as accepted.
- The active hosted design costs only the temporary DataHub demo host plus bounded serverless
  use, rather than an always-on Kubernetes estate.

## What we learned

A passing suite is not evidence that an integration works when tests encode an assumption about
someone else's API. Provenance is also a product feature, not an implementation detail: the
catalog's operational registry was more trustworthy than the field that appeared designed to
name a source. Finally, human approval is meaningful only when it is bound to exact content,
identity, state and an independently verified recovery path.

## What is next

Customer-specific SLOs, authenticated edge controls and backup/restore rehearsals come before a
production claim. After that, the same narrow engine can schedule posture reports and add new
remediation actions one at a time, each with its own policy, evidence and rollback contract.

## Built with

DataHub, DataHub MCP Server, Agent Context Kit, DataHub Skills, Analytics Agent, TypeScript,
Node.js, React, Tailwind CSS, Vite, Python, SARIF, Firebase Hosting, Google Cloud Run, Google
Cloud, GitHub Actions, Playwright, OWASP ZAP, CodeQL, CycloneDX, OpenVEX and Docker.

## Links

- Application: https://archon-datahub.web.app
- Exact public video: https://youtu.be/6iHvBr4Qr1s
- Public repository: https://github.com/upgradedev/archon-datahub
- Judge testing: https://github.com/upgradedev/archon-datahub/blob/master/docs/JUDGE_TESTING.md
- Sample outputs: https://github.com/upgradedev/archon-datahub/tree/master/examples
- Exact release: https://github.com/upgradedev/archon-datahub/releases/tag/datahub-hackathon-2026-final
- Upstream contribution: https://github.com/acryldata/mcp-server-datahub/pull/183

## Testing instructions

No account, credential, installation or payment is required.

1. Open https://archon-datahub.web.app.
2. Select **Run live audit**. Wait for the source badge to say **Live DataHub**.
3. Inspect the four findings: G6, retained-history ownership contradiction, G2 and lineage gap.
4. Scroll to **DataHub Agent Stack**. The UI states exactly which MCP evidence is live publicly
   and which ACK, Skills, Analytics Agent and governed-action evidence is protected in CI.
5. Under **Judge evidence pack**, select **Prepare & verify pack**. All nine WebCrypto integrity
   and privacy checks must report PASS for the JSON, Markdown and SARIF projections.
6. Select **Return to fixture preview**. At the human-authority boundary select
   **Reject proposal**. Rejection performs no mutation and still produces a
   content-addressed decision receipt.

The full write is intentionally not anonymous. The repository's protected governed-proof run
shows exact approval → `add_tags` → read-back → separate rollback approval → restoration on the
synthetic target. Detailed evidence boundaries and failure behaviour are in
`docs/JUDGE_TESTING.md`.

## Prior-work and third-party disclosure

The project was created during the submission period. Reused first-party material is listed
file-by-file in `NOTICE.md`; it consists of an OpenAI-compatible narration seam and a prior
self-audit engine adapted to DataHub metadata. The supported demo uses deterministic narration
and makes no external model call. DataHub and other dependencies are used under their published
open-source licences; the repository includes Apache-2.0 at the top level. No third-party music
or stock footage is used in the video; application capture, captions and narration are generated
for this submission.

## Published gallery

The Devpost gallery contains the public video plus five captioned images: the Archon cover,
live OSS DataHub findings, bounded blast radius, the governed write/read-back/rollback workflow,
and upstream PR #183. The cover is also the project thumbnail.

## Final form checklist

- Public application and repository links open in a logged-out browser.
- The repository About section visibly detects Apache-2.0.
- Public YouTube/Vimeo/Youku video is under three minutes and shows the functioning product.
- Custom 3:2 thumbnail and five captioned gallery images are publicly visible (six carousel slides including the video).
- Description, testing instructions, built-with list, category and prior-work disclosure match
  this file.
- Additional-info feedback answers remain saved.
- Final submission confirmation is captured before 2026-08-10 21:00 UTC.
