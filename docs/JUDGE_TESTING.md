# Judge testing guide

The live demo is **https://archon-datahub.web.app**.

No account, no credential, no installation and no cost. There is no sign-in
step. Open the URL in a normal browser window and every step in the
recommended path below works.

To be precise about what you are testing: Firebase serves the exact CI-built SPA
and proxies allowlisted read routes to a Cloud Run service with no write
credential. That service reaches one private DataHub Core v1.6 catalog. The AWS
stack and Cognito flow in the repository are non-deployed reference architecture;
there is no judge credential and the anonymous route cannot mutate DataHub.

## Recommended quick path

1. Open https://archon-datahub.web.app. The explicitly labelled deterministic
   preview appears immediately, so the product remains understandable even if a
   live dependency is temporarily unavailable.
2. Select **Run the live read-only audit** and wait for the source badge to say
   **Live DataHub**. No login or configuration is required.
3. Read the live posture header and open the four live findings. The pinned
   DataHub Core dataset demonstrates G6 sensitive-field classification, a
   cross-source ownership contradiction recovered from retained aspect history,
   a lineage gap, and a missing-domain G2 finding.
4. Scroll to **DataHub Agent Stack**. The panel states the evidence boundary:
   DataHub MCP is the public live proof; Agent Context Kit, the five DataHub
   Skills, Analytics Agent, and the governed write/rollback path are implemented
   and exercised by protected CI, not falsely exposed as anonymous mutations.
5. Scroll to **Judge evidence pack** and select **Prepare & verify pack**.
   Archon builds `report.json`, `report.md` and `report.sarif` in the browser,
   then runs **nine** named self-consistency checks over them with WebCrypto:
   `MANIFEST_SCHEMA_VALID`, `MANIFEST_DIGEST_VALID`, `FILE_SET_EXACT`,
   `FILE_DIGESTS_VALID`, `PUBLIC_PROJECTION_VALID`,
   `TERMINAL_PROJECTION_VALID`, `SUMMARY_CONSISTENT`,
   `SOURCE_FIELDS_CONSISTENT` and `PRIVACY_SCAN_VALID`. All nine report PASS.
6. Select **Return to fixture preview**, then scroll to the human authority
   boundary and select **Reject proposal**. This is the recommended path. It
   shows that a proposed remediation closes with no mutation and still seals a
   content-addressed receipt.
7. Optional: **Start judge tour** walks the same route with narration.

This pack is a deterministic synthetic projection. It is a reproducible
regression aid. It is not offered as proof of a live deployment or of live
DataHub access.

## Why two controls are disabled here

**Run Agent Stack** and **Launch pinned session** stay disabled on the public
URL, by design. The public live audit already exercises the real read-only
DataHub path. The full loop also needs Agent Context Kit, Analytics Agent, and a
separate write credential, so it is verified in protected CI and available for
customer-owned deployment rather than exposed to anonymous judges.

## Protected governed-write evidence

**This path is deliberately not a public button.** The exact release's
`live-governed-proof.yml` run is the auditable demonstration. It uses a distinct
short-lived workload identity and two GitHub protected environments.

1. The read/plan job queries only
   `urn:li:dataset:(urn:li:dataPlatform:snowflake,omega_ledger_audit_target,PROD)`
   and prepares a low-risk G6 plan for `customer_email` → `urn:li:tag:PII`.
2. The plan is `ACTIONABLE` only if the live pre-state, policy, evidence dossier,
   action catalog and plan digests all verify. No mutation occurs in this job.
3. `governed-canary` binds exactly one reviewer event and exact approval comment
   to the run ID, attempt, `write` operation and plan digest before OIDC is issued.
4. The official DataHub MCP `add_tags` tool changes only that field. A direct, bounded read-back
   must match the approved post-state before the write receipt
   and rollback proposal can be sealed.
5. `governed-canary-recovery` requires a fresh reviewer event bound to the same
   plan and the `rollback` operation. It removes only the canonical PII tag and
   verifies the exact pre-state digest.
6. If the forward job cannot publish its receipt after changing state, recovery uses the prepared evidence
   and proceeds only when current state equals exactly
   the approved pre-state or post-state. The final receipt says `restored` or
   `already-baseline`; every other state fails closed.

Archon does not mutate autonomously: the write cannot start without explicit
steward approval of the exact plan, and the inverse uses distinct, separately approved authority.
In fixture preview on the public URL, the only available decision is
**Reject proposal**. The live result remains strictly read-only and offers an
explicit **Return to fixture preview** control.

## What the recommended path demonstrates

- deterministic reproduction of a completed integrity pass;
- retained aspect history and deterministic contradiction recovery;
- schema, classification, lineage, provenance, and governance analysis;
- bounded blast-radius reasoning for the exact affected entity;
- a human-gated decision boundary;
- a rejection receipt proving that no mutation was requested; and
- browser-side verification of the evidence pack with WebCrypto.

## Safety and access

The recommended public journey is read-only. Its live control talks to DataHub,
but the Cloud Run identity has no write credential and exposes no mutation
route. Fixture-preview actions remain browser-only. Nothing available on the
anonymous URL can mutate the catalog.

The public URL is free, needs no credential and is maintained through the
judging window. If it is unavailable, use the contact information in the
Devpost entry and include the UTC time of the attempt.

## Optional repository review

The public repository link in the Devpost entry opens the maintained default
branch. The exact submitted application snapshot remains available in the
[datahub-hackathon-2026-submission release](https://github.com/upgradedev/archon-datahub/releases/tag/datahub-hackathon-2026-submission).
Reviewers can inspect the architecture, tests, infrastructure as code, CI/CD
security gates, and the clearly labelled synthetic judge-evidence pack. The
upstream contribution to the official DataHub MCP server is in
[`contrib/mcp-get-aspect-history/`](../contrib/mcp-get-aspect-history/).
