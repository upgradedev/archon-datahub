# Archon-DataHub — Design

_Build with DataHub: The Agent Hackathon · Track 3 (Production ML Agents / lineage)._

## 1. Thesis

A data catalog accumulates metadata about the same asset from **many independent
sources** — a source system's own schema, a dbt manifest, an ingestion connector, a
manual steward edit. Nothing forces those to agree, and DataHub (like every catalog)
resolves a read by returning the current value, staying **silent about the conflict**.
Meanwhile lineage is declared, not verified, so a pipeline can claim an upstream the
catalog never ingested; and governance policy (owners, domains, classifications) drifts
as assets are added faster than they are governed.

Archon is a **read-only, deterministic agent** that interrogates the catalog for exactly
these internal failures and hands a steward prioritized, explained, human-gated
recommendations. It **consumes** the official DataHub MCP server for metadata and
**re-exposes** its audit as MCP tools — an agent that both uses DataHub and extends it.

The core move is a **self-audit consistency engine**: a pure function over a neutral fact
stream that detects contradictions (two sources, one attribute, different values) and
absences (a referenced entity nothing catalogues). It is the same engine in tests and
against a live instance, so "self-auditing" is a measured property, not a slogan.

## 2. Multi-agent pipeline

Harvested metadata (via the `DataHubClient` seam over the DataHub MCP server) flows
through four agents. A bounded **ReAct loop** (`src/ap/loop.ts`) can drive the same
read-only tools agentically, with a human gate and a step-budget fallback.

| # | Agent | Kind | Responsibility | Key module |
|---|---|---|---|---|
| 1 | **ClassifierAgent** | deterministic | Partition the catalog: per-domain / per-platform counts, which entities carry lineage, which carry sensitive fields. Fast, explainable, no model call. | `src/agents/classifier.ts` |
| 2 | **LineageAnalyzerAgent** ★ | deterministic | Run the **self-audit** over the fact stream → cross-source contradictions + dangling-lineage-edge (gap) findings. | `src/agents/lineage-analyzer.ts` → `src/audit/consistency.ts` |
| 3 | **GovernanceAuditorAgent** | deterministic | Run the **G1–G6** policy gate over the snapshot → governance-violation findings. | `src/agents/governance-auditor.ts` → `src/governance/validator.ts` |
| 4 | **NarratorAgent** | LLM | Write a grounded, steward-facing executive summary over the findings the deterministic agents produced. Never invents numbers. Injectable client; Fake offline. | `src/agents/narrator.ts` → `src/llm/*` |

★ the differentiator. Everything findings-related is deterministic; the LLM only
narrates. That is deliberate: governance findings must be reproducible and auditable, so
the *judgement* is deterministic and the *language* is the only LLM-generated part.

### Governance rules (G1–G6)

| Rule | Check | Aspect |
|---|---|---|
| G1 | every dataset has ≥1 owner | `ownership` |
| G2 | every dataset is assigned a domain | `domains` |
| G3 | every dataset has a non-empty description | `datasetProperties` |
| G4 | a deprecated dataset has no active downstream | `deprecation` + lineage |
| G5 | every schema field has a resolved type | `schemaMetadata` |
| G6 | every sensitive field carries a classification | `schemaMetadata` + tags/terms |

## 3. Reused feature → agent → judging criteria

The six hackathon criteria, and how each reused/new capability serves them.

| Capability (origin) | Agent it powers | Serves which criteria |
|---|---|---|
| **Self-audit consistency engine** (ported: MemoryAgent) | LineageAnalyzer | **Originality** (a self-auditing catalog agent, not a retriever), **Real-World** (silent metadata conflicts are a real, unaddressed catalog failure), **Technical Execution** (pure, deterministic, 95%+ covered) |
| **Governance validator G1–G6** (ported: MemoryAgent) | GovernanceAuditor | **Use-of-DataHub** (maps 1:1 to DataHub aspects), **Real-World** (ungoverned-asset sprawl), **Technical Execution** |
| **DataHub MCP client** (new) | the whole harvest seam | **Use-of-DataHub** (consumes the *official* MCP server + its documented tools), **Technical Execution** (clean interface, offline Fake + live adapter) |
| **MCP server** (ported: Autopilot) | re-exposes audit as tools | **Use-of-DataHub** (both consumes and extends the MCP ecosystem), **Originality** |
| **ReAct loop + human gate + trace** (ported: Autopilot) | agentic driver | **Technical Execution** (bounded, terminating, fallbacks), **Real-World** (human-in-the-loop governance) |
| **LLM narrator** (ported: MemoryAgent) | Narrator | **Submission Quality** (boardroom-ready summary), provider-agnostic |
| **gitleaks-first CI + c8 ≥80% gate** (ported: conventions) | — | **Technical Execution**, **Submission Quality** |
| **Read-only guarantee** (new framing) | pipeline + loop + server | **Real-World** (safe to point at production metadata), **Originality** |
| **Bonus: OSS contribution** (planned) | — | **Bonus-OSS-contrib** (see roadmap) |

## 4. Read-only + human-gate design

- The DataHub MCP server's mutation tools are OFF by default; Archon never sets
  `TOOLS_IS_MUTATION_ENABLED` and never calls them.
- Every finding is a **recommendation** with a rationale and a confidence, not an action.
- The ReAct loop's only terminal success is `emit_findings`, which returns a `pending`
  report; the loop can never write back. Guards (max-steps, no-progress) fall back to
  `flag_for_review` — still pending, still nothing mutated.

## 5. Where DataHub runs

DataHub OSS quickstart is ~14 containers — it belongs on a **cloud VM**, never the dev
desktop (this repo is cloud-first). CI + tests + both demo scripts run entirely against
the deterministic **Fake DataHub MCP** (fixtures), so nothing about proving the agent
requires the heavy stack. When a real instance is available, the thin live adapter
(`src/datahub/mcp-client-live.ts`) is pinned against captured MCP responses and the same
pipeline runs unchanged.

## 6. Phased plan to Aug 10

- **Phase 1 — foundation (DONE).** Repo + Apache-2.0 + CI (gitleaks → typecheck → test →
  coverage ≥80%). DataHub MCP client seam + Fake + fixtures + harvester. Self-audit +
  governance engines re-aimed. Four-agent pipeline + ReAct loop + our MCP server. First
  connected slice green offline (40 tests). Docs (README / NOTICE / this).
- **Phase 2 — live proof.** Stand DataHub up on a cloud VM; run the live adapter against
  it; pin the MCP response shapes; capture a real audit run (screenshots + a recorded
  finding). Enable the real LLM narrator behind a key.
- **Phase 3 — depth.** Column-level lineage gaps (`get_lineage_paths_between`); multi-hop
  schema-break blast-radius; a findings history store (pgvector) so audits diff across
  runs; a small web view of the findings + trace.
- **Phase 4 — submission + OSS bonus.** Demo video + write-up. **OSS contribution**: a
  DataHub *Skill* (the skills registry) that packages "self-audit a catalog for
  contradictions + lineage gaps" as an installable agent workflow, and/or an upstream
  fix/example to `acryldata/mcp-server-datahub`.

## 7. Module map

```
src/
  types.ts                     domain vocabulary (AuditFact, Finding)
  datahub/
    models.ts                  DataHub entity/aspect/lineage view + sensitive-field heuristic
    fixtures.ts                deterministic catalog (baked-in contradiction/gap/violation)
    mcp-client.ts              DataHubClient seam + FakeDataHubMcpClient + factory   [NEW]
    mcp-client-live.ts         thin live adapter over acryldata/mcp-server-datahub   [NEW, provisional]
  audit/
    harvest.ts                 metadata → neutral AuditFact stream (provenance-aware) [NEW]
    consistency.ts             self-audit contradiction + resolution engine  ★  [ported]
  governance/
    validator.ts               G1–G6 deterministic policy gate                  [ported]
  llm/
    client.ts                  provider-agnostic OpenAI-compatible LLM seam     [ported]
    fake.ts                    deterministic offline Fake LLM                   [ported]
  agents/
    classifier.ts              [NEW]  lineage-analyzer.ts [NEW]
    governance-auditor.ts      [NEW]  narrator.ts         [ported pattern]
  pipeline/pipeline.ts         four-agent orchestration                         [NEW]
  ap/loop.ts                   bounded, human-gated ReAct audit loop            [ported]
  mcp/server.ts                MCP server exposing the read-only audit tools    [ported]
scripts/first-slice.ts · scripts/demo-audit.ts
tests/unit/{consistency,governance,datahub-mcp,pipeline}.test.ts
```

Full disclosure of ported vs. new: [`../NOTICE.md`](../NOTICE.md).
