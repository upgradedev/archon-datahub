# NOTICE — Pre-existing code disclosure

Archon-DataHub is a **new project**, created during the Build with DataHub hackathon
window, and is licensed under **Apache-2.0**. Ownership of all code in this repository
is solely ours.

In the spirit of the hackathon rules, this file discloses **exactly** which parts reuse
our own pre-existing code as libraries, and which parts are new. The reused code was
written by us for earlier Archon projects; it is ported here as a library and **re-aimed
from its original domain onto DataHub metadata governance**. No third-party or
proprietary/organizational (non-Archon) code is included. This is a clean-room build.

## Source projects (all our own prior work)

| Alias | Path |
|---|---|
| **MemoryAgent** | `repos/qwen-memoryagent` |
| **Autopilot** | `repos/qwen-autopilot` |
| **Nebius** | `repos/nebius` (conceptual ancestor of the above — see note) |

The Microsoft Agents League, Google Vibecoding, OpenAI Buildweek, Kerdon, CockroachDB,
and Backblaze projects were reviewed for **architecture patterns only**: exact-argument
approval, deterministic state handoff, RED→GREEN verification, immutable delivery,
content-addressed evidence, and build-once/promote-the-same-artifact deployment. No source
file was copied from those projects.

## Ported files (reused as libraries, then re-aimed to DataHub)

| File in this repo | Ported from | What changed |
|---|---|---|
| `src/audit/consistency.ts` | MemoryAgent `src/memory/consistency.ts` | The self-audit **contradiction + resolution engine** (the differentiator). Algorithm unchanged; re-aimed from cross-session memory contradictions onto **cross-source metadata contradictions + lineage gaps**. |
| `src/governance/validator.ts` | MemoryAgent `src/pipeline/validator.ts` | The deterministic **per-rule validation gate**. Pattern unchanged (one ValidationResult per rule per record, fixed thresholds, no LLM); re-aimed onto **G1–G6 data-governance policy rules** over catalog entities. |
| `src/llm/client.ts` | Autopilot `src/qwen/client.ts` | The **OpenAI-compatible LLM seam** (chat + function-calling interfaces, env-driven creds, offline auto-fallback). Generalized from Qwen-specific to **provider-agnostic** (`LLM_*` env vars). |
| `src/llm/fake.ts` | Autopilot `src/ap/fake-chat.ts` | The **deterministic offline Fake LLM** at the same seam. Re-aimed from the AP decision policy onto the **audit tool-selection + narrator** policies. |
| `src/ap/loop.ts` | Autopilot `src/ap/loop.ts` | The **bounded multi-step ReAct loop** (observe → decide → act, human gate, trace, no-progress + max-steps fallbacks). Re-aimed onto **read-only audit tools**; the human gate is now "findings are pending recommendations — nothing mutates DataHub". |
| `src/mcp/server.ts` | Autopilot `src/mcp/server.ts` | The **MCP server** wrapping the agent as MCP tools over stdio + an injectable, in-memory-testable build. Re-aimed onto the **read-only audit tool surface**. |
| `src/agents/narrator.ts` | MemoryAgent `src/agents/narrator.ts` | The **LLM narrator** pattern (grounded executive summary, injectable client). Re-aimed to narrate audit findings. |
| Config: `tsconfig.json`, `.c8rc.json`, `.github/workflows/ci.yml`, `package.json` scripts | MemoryAgent / Autopilot conventions | Same TypeScript + `node --test` + `c8 ≥80%` + gitleaks-first CI conventions. |

## New files (written for this project)

- `src/datahub/mcp-client.ts` — **NEW.** The DataHub MCP **client** that CONSUMES the
  official `acryldata/mcp-server-datahub`. There was **no MCP client** in the source
  projects (they only had an MCP *server*), so this is original code: the `DataHubClient`
  interface, the `FakeDataHubMcpClient`, and the current-view merge.
- `src/datahub/mcp-client-live.ts` — **NEW.** The thin live adapter over the real DataHub
  MCP server (stdio + Streamable HTTP).
- `src/datahub/version-history.ts` — **NEW.** The aspect **version-history recovery**: pinned
  OpenAPI v3 versioned-aspect types + pure mappers that turn an aspect's per-run history into
  the neutral fact stream, and the distinct-source-gated audit that recovers cross-source
  contradictions a live catalog's current view hid. Also the cross-scan drift detector.
- `src/datahub/version-history-reader.ts` — **NEW.** The fail-closed direct-GMS reader that
  combines current `v0` with retained history, bounds pagination, and distinguishes a natural
  404 history end from authentication, server, transport, or malformed-response failure.
- `src/datahub/blast-radius.ts` — **NEW.** Deterministic, bounded, cycle-safe downstream impact
  analysis over DataHub lineage.
- `src/datahub/mutation-client.ts`, `src/datahub/mutation-client-live.ts` — **NEW.** A
  separately credentialed, non-generic write capability limited to the official
  `add_tags` / `remove_tags` tools for one entity, column, and tag. It is not exposed by the
  public MCP server or HTTP audit plane.
- `src/datahub/models.ts`, `src/datahub/fixtures.ts`, `src/audit/harvest.ts`,
  `src/types.ts` — **NEW.** The DataHub domain model, deterministic fixtures (incl. the
  version-history fixtures), and the harvest seam that turns catalog metadata into the
  neutral fact stream.
- `src/pipeline/pipeline.ts` — **NEW.** The four-agent orchestration (classifier →
  lineage-analyzer → governance-auditor → narrator), including version-history merge,
  dedupe, and bounded blast-radius enrichment.
- `src/agents/classifier.ts`, `lineage-analyzer.ts`, `governance-auditor.ts` — **NEW.**
  Thin agents that wrap the ported engines in the Finding vocabulary.
- `src/remediation/*.ts`, `policies/archon-remediation.v1.json` — **NEW.** The G6-only
  governed control loop: structured evidence dossier, trusted policy and action-catalog
  digests, immutable approval binding, atomic one-use execution claim, fresh pre-state,
  postcondition verification, hash-chained receipt, and fresh-approval rollback proposal.
- `src/audit-worker.ts`, `src/remediation-worker.ts`, `src/worker/contracts.ts`,
  `src/worker/configuration.ts`, `src/worker/service.ts`, and
  `src/worker/aws-adapters.ts` — **NEW.** The isolated callback consumers, strict queue
  contracts, bounded execution leases, retry/quarantine behavior, immutable evidence
  adapters, and stale-write reconciliation path.
- `src/datahub/tag-projection-reader-live.ts` — **NEW.** The narrow, digest-producing
  direct-GMS projection reader used for approval preconditions and post-write verification.
- `src/reporting/exporters.ts` — **NEW.** JSON, safe Markdown, and SARIF 2.1.0 evidence
  exporters with stable finding fingerprints.
- `src/http/server.ts`, `Dockerfile`, `tsconfig.build.json` — **NEW.** The hardened,
  read-only production audit API and non-root container boundary.
- `web/` — **NEW.** The responsive React/Tailwind evidence-review application. Its browser
  approval contract submits disposition and comment only; actor identity, tool, arguments,
  and policy are rehydrated at the trusted server boundary.
- `infra/` — **NEW.** AWS CDK reference architecture plus the secretless approval-handoff
  and capability-scoped start/status Lambdas for private S3 + CloudFront OAC,
  Cognito/WAF/API control plane, isolated audit and write workloads, durable approval state,
  KMS-protected evidence, queues/DLQ, and observability.
- `scripts/readiness.ts` — **NEW.** The machine-checkable readiness gate (weighted,
  evidence-based, CI-enforced) + its cassette (`tests/cassettes/`) and e2e.
- `scripts/governed-canary.ts`, `.github/workflows/governed-canary.yml`,
  `.github/workflows/governed-canary-recovery.yml`, and `docs/GOVERNED_CANARY.md` —
  **NEW.** The pipeline-native isolated write proof: immutable
  release/plan binding, Cognito Hosted UI PKCE, pre-mutation recovery evidence, a separately
  approved exact inverse, and direct read-after-rollback verification.
- `tests/security/*.test.ts` — **NEW.** The application-security pen-test suite (AuthZ /
  tool-boundary, prompt-injection, governance/contradiction-engine injection, sensitive-
  data-exposure), driving the real pipeline / loop / MCP surface offline.
- `load/audit.js` — **NEW.** The offline, in-process k6-equivalent load harness (SLO-gated:
  error-rate + p95) over the audit/recall hot path against the Fake backend.
- `tests/e2e/journeys.e2e.test.ts` — **NEW.** The extensive end-to-end journey suite
  exercising scan → audit → recovery → dual-face MCP → quantified report offline.
- `tests/e2e/remediation.e2e.test.ts` — **NEW.** The full finding → dossier → approval →
  mutation → verification → receipt path plus the manual-only contradiction path.

The self-audit contradiction engine (`src/audit/consistency.ts`) gained one **new option**,
`requireDistinctSources`, used by the version-history path so a single-run edit is treated as
benign drift rather than a contradiction. The core algorithm is otherwise unchanged.

## Note on `repos/nebius`

`repos/nebius` is the earlier Archon platform from which the MemoryAgent and Autopilot
engines conceptually descend. **No code was ported directly from `repos/nebius`** into
this repository; the direct ports are from the two Qwen repos above. It is listed here
for full lineage transparency.

## Third-party dependencies

Standard OSS libraries only, via `package.json`: `@modelcontextprotocol/sdk` (MCP),
`openai` (OpenAI-compatible client), `tsx`, `typescript`, `c8`. The official DataHub MCP
server (`acryldata/mcp-server-datahub@0.6.0`) is consumed as a pinned external process over
MCP — it is **not** vendored into this repo. The web and infrastructure packages disclose
their locked OSS dependencies in their own `package-lock.json` files.
