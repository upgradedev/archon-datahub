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
  MCP server (stdio + Streamable HTTP), plus the direct-GMS OpenAPI v3 version-history read
  that feeds the contradiction-recovery path.
- `src/datahub/version-history.ts` — **NEW.** The aspect **version-history recovery**: pinned
  OpenAPI v3 versioned-aspect types + pure mappers that turn an aspect's per-run history into
  the neutral fact stream, and the distinct-source-gated audit that recovers cross-source
  contradictions a live catalog's current view hid. Also the cross-scan drift detector.
- `src/datahub/models.ts`, `src/datahub/fixtures.ts`, `src/audit/harvest.ts`,
  `src/types.ts` — **NEW.** The DataHub domain model, deterministic fixtures (incl. the
  version-history fixtures), and the harvest seam that turns catalog metadata into the
  neutral fact stream.
- `src/pipeline/pipeline.ts` — **NEW.** The four-agent orchestration (classifier →
  lineage-analyzer → governance-auditor → narrator), incl. the version-history merge + dedupe.
- `src/agents/classifier.ts`, `lineage-analyzer.ts`, `governance-auditor.ts` — **NEW.**
  Thin agents that wrap the ported engines in the Finding vocabulary.
- `scripts/readiness.ts` — **NEW.** The machine-checkable readiness gate (weighted,
  evidence-based, CI-enforced) + its cassette (`tests/cassettes/`) and e2e.
- `tests/security/*.test.ts` — **NEW.** The application-security pen-test suite (AuthZ /
  tool-boundary, prompt-injection, governance/contradiction-engine injection, sensitive-
  data-exposure), driving the real pipeline / loop / MCP surface offline.
- `load/audit.js` — **NEW.** The offline, in-process k6-equivalent load harness (SLO-gated:
  error-rate + p95) over the audit/recall hot path against the Fake backend.
- `tests/e2e/journeys.e2e.test.ts` — **NEW.** The extensive end-to-end journey suite
  (9 journeys) exercising scan → audit → recovery → dual-face MCP → quantified report offline.

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
server (`acryldata/mcp-server-datahub`) is consumed as an external process over MCP — it
is **not** vendored into this repo.
