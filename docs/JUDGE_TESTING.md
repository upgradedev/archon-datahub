# Judge testing guide

Archon is a hosted, judge-facing DataHub governance application. The public
application URL and the judge credential are provided separately in the Devpost
testing instructions. No installation, cloud account, paid subscription, or
DataHub credential is required from a judge.

## Recommended quick path

1. Open the supplied HTTPS application URL in a new private browser window.
   Confirm that the Archon landing page and the preconfigured demo scope load
   without a browser warning.
2. Select **Sign in** and authenticate through the hosted Amazon Cognito page
   with the supplied judge credential. Return to the same Archon origin after
   authentication.
3. Keep the prefilled, single-dataset demo scope and select **Run audit**.
   Archon starts a durable audit against the deployed DataHub demo tenant. It
   does not ask the judge for a DataHub URL, token, or query.
4. Wait for the audit to reach its review state. Inspect the metadata-health
   summary, provenance conflict, sensitive-field governance finding, dangling
   lineage finding, blast-radius projection, and evidence digests.
5. Select **Reject proposal**. This is the recommended hackathon path: it proves
   the human decision boundary and closes the durable workflow without invoking
   a DataHub mutation.
6. Wait for **Rejection sealed without mutation**. Confirm that the terminal
   panel shows a rejected outcome and a content-addressed receipt digest.
7. Select **Sign out**. Reopen the application in another new private window and
   confirm that steward decision controls require authentication again.

## Optional governed-write journey

Use this path only when the final testing instructions mark the staging DataHub Cloud
canary as ready and its separately governed inverse is armed. It is an optional bounded
proof; the recommended rejection path above remains the fastest review.

1. Keep the exact synthetic demo target:
   - dataset:
     `urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)`;
   - field: `customer_email`; and
   - proposed tag: `urn:li:tag:PII`.
   Do not substitute another entity, field, tag, or tenant.
2. Sign in with the supplied judge credential, retain the explicit **DataHub Cloud
   (managed)** profile, keep the prefilled question, and start the DataHub Agent Stack
   journey.
3. Wait for the MCP reads, Agent Context Kit provenance envelope, five DataHub Skills,
   and Analytics Agent result. Select **Generate proposal** and verify that the UI still
   says **Proposal only** and displays content-addressed before/after digests.
4. Select **Approve exact plan** after inspecting the exact PII plan. That authenticated
   click is the explicit human approval boundary; it authorizes only the displayed
   content-addressed plan.
5. Wait for **SUCCEEDED · COMPLETE** and
   **Official DataHub MCP add_tags + post-write ACK and Analytics rerun verified.**
   Confirm both **ACK context · changed** and **Analytics result · changed**. These are
   the read-after-write and context-delta proofs for the exact synthetic field.
6. Sign out after the session teardown is shown. Do not attempt manual cleanup. After
   the browser job, the workflow automatically enters the rollback job even if the
   browser journey failed or was cancelled after preparation. The separate
   `governed-canary-rollback` environment requires a fresh human approval, removes
   only the canonical PII tag when present, reads the baseline again, and seals an
   attested `restored` or `already-baseline` receipt.

Archon does not mutate autonomously: the write cannot start without explicit steward
approval of the exact plan, and the inverse uses distinct, separately approved
authority. If this optional path is not explicitly armed, select **Reject proposal**.

## What the journey demonstrates

- live reads from the deployed DataHub metadata graph;
- retained aspect history and deterministic contradiction recovery;
- schema, classification, lineage, provenance, and governance analysis;
- bounded blast-radius reasoning for the exact affected entity;
- durable server-side state with a human-gated decision;
- a rejection receipt proving that no mutation was requested; and
- browser-session isolation after Cognito logout.

## Safety and access

Use only the prefilled demo scope. The recommended rejection journey is
read-only and does not modify DataHub. Do not paste the judge credential into
the query field, screenshots, issue reports, or public chat. The credential is
shared only for judging, is free to use, and is maintained through the judging
window.

If the application or sign-in path is unavailable, use the contact information
in the Devpost entry and include the UTC time of the attempt. Do not include the
credential, authentication tokens, or complete browser network logs.

## Optional repository review

The public repository link in the Devpost entry is pinned to the submitted
release. Reviewers can inspect the architecture, tests, infrastructure as code,
CI/CD security gates, deployment receipts, and the clearly labelled synthetic
judge-evidence pack. Synthetic evidence is a reproducible regression aid; it is
not presented as proof of a live deployment or live DataHub access.
