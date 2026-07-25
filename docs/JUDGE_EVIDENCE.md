# Judge evidence pack

Archon's judge evidence pack is a deterministic, synthetic projection of the real audit
and governed-remediation code paths. It lets a reviewer inspect representative JSON,
Markdown, SARIF, approval bindings, a verified execution receipt, and a rollback proposal
without trusting hand-authored sample output.

It is intentionally **not** live proof. The pack does not claim that a DataHub tenant was
queried, that AWS was deployed, or that a real catalog was mutated. Live DataHub,
deployment, browser, and governed-canary evidence remain separate CI/CD artifacts.

## What generates the pack

`scripts/generate-judge-evidence.ts` directly invokes:

1. `AuditPipeline` with `FakeDataHubMcpClient` and an explicitly injected
   `FakeLlmClient`;
2. the production G6 planner and trusted-policy constructors;
3. the production approval-request and approval-decision constructors;
4. `executeApprovedRemediation` against an exact, in-memory tag port;
5. execution-receipt verification and `createRollbackProposal`;
6. the production JSON, Markdown, and SARIF audit exporters.

The filesystem generator is CI-only. It accepts only an output directory and an exact
lowercase 40-character source revision, requires the canonical
`upgradedev/archon-datahub` repository and `CI` workflow identity, requires that revision
to equal `GITHUB_SHA`, and keeps output below `RUNNER_TEMP`. A dedicated preload denies
Node HTTP(S), sockets, DNS, UDP, WebSocket/fetch, and child-process escape hatches before
the TypeScript loader or generator starts. The in-memory builder remains available to the
test suite but cannot write a pack through the CLI.

The generator cannot accept a DataHub URL, credential, query, alternate fixture, mutation
target, or arbitrary tool name. Every clock value, synthetic identity, nonce, target, and
mutation response is fixed. The release SHA is the only content input that varies.

## Bundle contract

The generator creates one new directory and refuses to overwrite an existing path:

```text
judge-evidence/
  README.md
  audit/
    report.json
    report.md
    report.sarif
  control/
    evidence-dossier.json
    remediation-plan.json
    approval-request.json
    approval-decision.json
    execution-receipt.json
    rollback-proposal.json
  manifest.json
  SHA256SUMS
```

The committed fixture profile is deliberately exact:

- 3 catalog entities;
- 2 cross-source contradictions;
- 1 lineage gap;
- 4 governance violations;
- one policy-derived G6 classification-tag action;
- one authenticated synthetic steward approval;
- one verified transition with all five postconditions passing;
- one eligible rollback anchor and a separately approvable rollback proposal.

`manifest.json` uses `archon.judge-evidence-pack/v1`. It labels the evidence
`SYNTHETIC_OFFLINE_FIXTURE`, binds the tested release SHA and committed fixture digest,
records the semantic digest chain, and records byte size and SHA-256 for every payload
file. `SHA256SUMS` independently covers every file except itself.

## Verification

`scripts/verify-judge-evidence.ts` fails closed unless:

- the directory contains exactly the documented regular files and no symbolic links;
- per-file and aggregate size limits hold;
- `SHA256SUMS`, manifest byte digests, and the manifest canonical digest verify;
- the dossier, plan, approval request, approval decision, receipt, and rollback bindings
  form one exact chain;
- the receipt is `VERIFIED`, all five checks pass, and rollback is `ELIGIBLE`;
- recreating the rollback proposal from the receipt yields identical canonical content;
- the report retains its exact 2/1/4 finding profile and SARIF has one result per finding;
- no task-token field or common credential-shaped value is present;
- every DataHub URN, URL, and email identity belongs to the fixed public-fixture allowlist;
- forbidden keys are compared case- and separator-insensitively, and common AWS, GitHub,
  Slack, Google, OpenAI-compatible, bearer, JWT, and private-key shapes are rejected;
- replaying the production functions for the same release SHA reproduces every byte.

Both the generator and verifier CLI require the same canonical repository/workflow
binding and the network/child-process deny preload. The manifest makes only the narrower
claims that are established by its fixed fake DataHub client and in-memory mutation port;
it does not rely on a self-declared network-call counter.

The in-memory E2E contract is in `tests/e2e/judge-evidence.e2e.test.ts`. It performs no
filesystem writes.

## CI/CD integration

The `Reproducible judge evidence` CI job generates the pack only in ephemeral runner
directories:

```bash
npm run evidence:judge:generate -- \
  --release-sha "${GITHUB_SHA}" \
  --output "${RUNNER_TEMP}/judge-evidence-a"

npm run evidence:judge:generate -- \
  --release-sha "${GITHUB_SHA}" \
  --output "${RUNNER_TEMP}/judge-evidence-b"

diff --recursive --no-dereference \
  "${RUNNER_TEMP}/judge-evidence-a" \
  "${RUNNER_TEMP}/judge-evidence-b"

npm run evidence:judge:verify -- \
  --release-sha "${GITHUB_SHA}" \
  --input "${RUNNER_TEMP}/judge-evidence-a"

(cd "${RUNNER_TEMP}/judge-evidence-a" && \
  sha256sum --check --strict SHA256SUMS)
```

Only the verified first directory is uploaded as
`judge-evidence-${{ github.sha }}`, with a 90-day retention period and
`if-no-files-found: error`; the replay directory remains ephemeral. The job depends on the
ordinary build-and-test gate, and the upload-artifact digest is a required field in the
default-branch release-attestation predicate. The in-memory E2E contract is also part of
the explicit E2E, aggregate-test, and coverage command lists.

This integration is source-complete. It becomes retained CI evidence only after the exact
branch commit succeeds remotely; source presence alone is not called green evidence.

## Privacy and security boundary

The public pack contains only committed synthetic DataHub URNs, the reserved
`steward@example.test` identity, `https://oidc.example.test`, canonical digests, and
sanitized mutation acknowledgements. It contains no task tokens, provider credentials,
live endpoints, real account identifiers, raw provider responses, or real user data.

The generator must never be generalized to consume a live audit result. Audit JSON and
SARIF finding details can contain tenant metadata, and a pending live approval request can
contain operational identifiers that are unsuitable for a public artifact. Real evidence
must continue through the dedicated sanitized live-proof and governed-canary pipelines.
