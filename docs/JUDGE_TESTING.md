# Judge testing guide

The live demo is **https://archon-datahub.web.app**.

No account, no credential, no installation and no cost. There is no sign-in
step. Open the URL in a normal browser window and every step in the
recommended path below works.

To be precise about what you are testing: the AWS stack in the README,
including the Amazon Cognito login that an earlier version of this guide
described, is a reference architecture. It was never deployed, so there is no
hosted login and no judge credential. What is running is a Firebase-hosted
single-page app in deterministic showcase mode. The live DataHub path is real
and has been run against DataHub Core v1.6.0, but it is not hosted. You run it
yourself against your own instance, per "Connect a real DataHub" in the README.

## Recommended quick path

1. Open https://archon-datahub.web.app. The demo loads straight into a
   completed integrity pass. Nothing needs to be started and nothing needs
   to be configured.
2. Read the posture header: integrity score, catalogued assets, open
   findings, downstream exposure and lineage mapped.
3. Open each of the five findings. Two are high severity:
   - an unclassified sensitive field on
     `snowflake,prod.customer_360,PROD`, caught by governance control G6; and
   - a cross-source ownership contradiction on
     `snowflake,prod.orders,PROD`, recovered from retained aspect history.

   The other three are a lineage gap on `kafka,payment_events,PROD`, a
   missing-ownership finding (G1) on `s3,raw/support_tickets,PROD`, and a
   missing-domain finding (G2) on `postgres,ops.shipment_status,PROD`. Each
   finding names its rule, its subject and its downstream impact.
4. Scroll to **Judge evidence pack** and select **Prepare & verify pack**.
   Archon builds `report.json`, `report.md` and `report.sarif` in the browser,
   then runs **nine** named self-consistency checks over them with WebCrypto:
   `MANIFEST_SCHEMA_VALID`, `MANIFEST_DIGEST_VALID`, `FILE_SET_EXACT`,
   `FILE_DIGESTS_VALID`, `PUBLIC_PROJECTION_VALID`,
   `TERMINAL_PROJECTION_VALID`, `SUMMARY_CONSISTENT`,
   `SOURCE_FIELDS_CONSISTENT` and `PRIVACY_SCAN_VALID`. All nine report PASS.
5. Scroll to the human authority boundary.
   Select **Reject proposal**. This is the recommended path. It shows that a
   proposed remediation closes with no mutation and still seals a
   content-addressed receipt.
6. Optional: **Start judge tour** walks the same route with narration.

This pack is a deterministic synthetic projection. It is a reproducible
regression aid. It is not offered as proof of a live deployment or of live
DataHub access.

## Why two controls are disabled here

**Run Agent Stack** and **Launch pinned session** stay disabled on the public
URL, by design. They start a credentialed run against a real DataHub tenant
with a real write credential, so they need an authenticated steward session
that the public demo deliberately does not have. That path is not dead code:
it has been run against DataHub Core v1.6.0. To run it yourself, follow
"Connect a real DataHub" in the README.

## Optional governed-write journey

**This path is not available on https://archon-datahub.web.app.** There is no
hosted canary and no judge credential. It runs only against your own DataHub
instance, with your own write credential, from your own checkout. Treat what
follows as the contract the code enforces, not as something you can click on
the public URL.

1. Keep the exact synthetic demo target:
   - dataset:
     `urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)`;
   - field: `customer_email`; and
   - proposed tag: `urn:li:tag:PII`.
   Do not substitute another entity, field, tag, or tenant.
2. Configure your own DataHub per the README, keep the prefilled question, and
   start the DataHub Agent Stack journey as an authenticated steward.
3. Wait for the MCP reads, Agent Context Kit provenance envelope, five DataHub
   Skills, and Analytics Agent result. Select **Generate proposal** and verify
   that the UI still says **Proposal only** and displays content-addressed
   before/after digests.
4. Select **Approve exact plan** after inspecting the exact PII plan. That
   authenticated click is the explicit human approval boundary. It authorizes
   only the displayed content-addressed plan.
5. Wait for **SUCCEEDED · COMPLETE** and
   **Official DataHub MCP add_tags + post-write ACK and Analytics rerun verified.**
   Confirm both **ACK context · changed** and **Analytics result · changed**.
   These are the read-after-write and context-delta proofs for the exact
   synthetic field.
6. Do not attempt manual cleanup. After the browser job, the
   workflow automatically enters the rollback job even if the browser journey
   failed or was cancelled after preparation. The separate
   `governed-canary-recovery` environment requires a fresh human approval,
   removes only the canonical PII tag when present, reads the baseline again,
   and seals an attested `restored` or `already-baseline` receipt.

Archon does not mutate autonomously: the write cannot start without explicit
steward approval of the exact plan, and the inverse uses
distinct, separately approved authority. On the public URL the only available
decision is **Reject proposal**.

## What the recommended path demonstrates

- deterministic reproduction of a completed integrity pass;
- retained aspect history and deterministic contradiction recovery;
- schema, classification, lineage, provenance, and governance analysis;
- bounded blast-radius reasoning for the exact affected entity;
- a human-gated decision boundary;
- a rejection receipt proving that no mutation was requested; and
- browser-side verification of the evidence pack with WebCrypto.

## Safety and access

The recommended journey is read-only. It does not modify DataHub, because it
does not talk to a DataHub at all. It replays a sealed synthetic fixture in
your browser. Nothing you do on the public URL can mutate a catalog.

The public URL is free, needs no credential and is maintained through the
judging window. If it is unavailable, use the contact information in the
Devpost entry and include the UTC time of the attempt.

## Optional repository review

The public repository link in the Devpost entry is pinned to the submitted
release. Reviewers can inspect the architecture, tests, infrastructure as
code, CI/CD security gates, and the clearly labelled synthetic judge-evidence
pack. The upstream contribution to the official DataHub MCP server is in
[`contrib/mcp-get-aspect-history/`](../contrib/mcp-get-aspect-history/).
