# Archon-DataHub — a self-auditing metadata-governance & lineage agent

**Build with DataHub: The Agent Hackathon · Track 3 (Production ML Agents / lineage)**

Archon is a **read-only, deterministic** agent that connects to a
[DataHub](https://datahub.com) catalog over the **official DataHub MCP server**
(`acryldata/mcp-server-datahub`), harvests its metadata (entities, aspects, schema,
lineage, governance), and **audits the catalog against itself**. It surfaces three
classes of problem and, for each, a human-gated recommendation — it **never mutates
DataHub**:

- **Cross-source contradictions** — two ingestion sources (a Snowflake connector, a dbt
  manifest, a manual edit) disagree about the same entity: different owners for one
  dataset, different types for one column. A plain catalog lookup silently returns
  whichever ranked higher; Archon flags the conflict and recommends which side to trust.
- **Lineage gaps** — a dataset declares an upstream that the catalog never ingested: a
  dangling lineage edge that hides schema-break risk to everything downstream.
- **Governance violations** — ungoverned or unclassified assets (no owner, no domain, no
  description, an untyped field, an unclassified sensitive field), via deterministic
  policy rules **G1–G6**.

> **The differentiator:** a self-auditing contradiction/inconsistency engine. Most catalog
> agents *retrieve* metadata; Archon *interrogates* it for internal disagreement, and does
> so with a **pure, deterministic engine** that runs identically in tests and against a
> live instance — the "self-auditing" claim is measured on the same code that ships.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Archon-DataHub agent (read-only)                                          │
│                                                                            │
│   MCP server (our tools)            Multi-agent audit pipeline             │
│   audit_catalog · run_audit_loop    1. ClassifierAgent      (deterministic)│
│   search_datasets · get_entity      2. LineageAnalyzerAgent (self-audit ★) │
│         ▲                            3. GovernanceAuditor    (G1–G6)        │
│         │ MCP (stdio)               4. NarratorAgent         (LLM summary)  │
│   any MCP client                          │                                │
│   (IDE / orchestrator / agent)       ReAct loop (bounded, human-gated) ─────┤
│                                           │                                │
│   DataHubClient seam  ◄── harvest ── mcp-client.ts ──► Fake | Live         │
└───────────────────────────────────────────┬──────────────────────────────┘
                                             │ MCP: search / get_entities / get_lineage
                                 ┌───────────▼───────────────┐
                                 │ acryldata/mcp-server-datahub│  (official)
                                 └───────────┬───────────────┘
                                             │ GraphQL / SDK
                                 ┌───────────▼───────────────┐
                                 │  DataHub (GMS + graph)      │  ← runs on a CLOUD VM
                                 └────────────────────────────┘
```

★ = the self-audit consistency engine — the differentiator.

**Two faces, one agent.** Archon *consumes* the DataHub MCP server for metadata and
*re-exposes* its audit as an MCP server of its own — so an IDE or another agent can call
`audit_catalog` and get findings + an executive summary. The LLM (narrator + the ReAct
loop) is provider-agnostic over any OpenAI-compatible endpoint (Qwen / OpenAI / Gemini
gateway); with **no key configured everything falls back to deterministic Fakes**, so the
whole agent runs offline with zero secrets and zero spend.

## Quickstart (offline — zero credentials)

```bash
npm install
npm test            # 40 unit tests
npm run coverage    # c8 gate, ≥80%
npm run slice:datahub   # the first connected slice → a self-audit finding
npm run audit:demo      # the full four-agent pipeline → findings + summary
```

`npm run slice:datahub` connects through the DataHub MCP client seam (offline Fake),
harvests the fixture catalog, runs the self-audit, and prints read-only findings —
headlined by:

```
HEADLINE SELF-AUDIT FINDING:
  Sources disagree on 'owner' for …sales_orders…: team-finance (snowflake-ingest) vs team-ops (dbt-ingest).
  → Later harvest supersedes the earlier value; recency is the default tie-breaker.
    (recommended: team-ops, confidence 0.85). Read-only — a steward decides.
```

## Running against a real DataHub

DataHub's `datahub docker quickstart` is a **~14-container stack** (GMS, Kafka,
OpenSearch, MySQL, frontend, …). **Run it on a cloud VM, not a dev laptop** — this repo
is cloud-first and deliberately does not stand the stack up locally. Once DataHub is up
and the MCP server is reachable, point the agent at it — the **same code** runs the live
client:

```bash
# .env (see .env.example)
DATAHUB_GMS_URL=http://<cloud-vm>:8080
DATAHUB_GMS_TOKEN=<personal-access-token>     # DataHub UI → Settings → Access Tokens
DATAHUB_MCP_URL=http://<cloud-vm>:8080/mcp    # or a DataHub Cloud MCP endpoint
LLM_API_KEY=<optional — enables the real LLM narrator>

npm run audit:demo
```

The live path is a thin, provisional adapter (`src/datahub/mcp-client-live.ts`) wired to
the documented DataHub MCP tools (`search`, `get_entities`, `get_lineage`) and pinned
against captured responses when it first runs against a real instance. See
[`docs/DATAHUB_RESEARCH.md`](docs/DATAHUB_RESEARCH.md) for the full DataHub + MCP
integration research.

## Read-only guarantee

Archon **recommends, a human disposes.** The DataHub MCP server's mutation tools
(`add_tags`, `set_domains`, …) are OFF by default and this agent never enables them. The
ReAct loop's terminal action (`emit_findings`) produces a `pending` report for a steward;
nothing in the pipeline or the loop writes back to DataHub.

## Testing & CI

- **Unit tests:** `node --test` over the consistency engine, governance validator, DataHub
  MCP client + harvester, and the pipeline / ReAct loop / MCP tools (40 tests).
- **Coverage gate:** `c8` at **≥80%** lines/branches/functions/statements (`.c8rc.json`).
- **CI** (`.github/workflows/ci.yml`): gitleaks (secret scan, fail-fast) → typecheck →
  test → coverage gate → dependency audit. Fully offline via the Fakes.

## Pre-existing code disclosure

This is a **new project** (Apache-2.0) that reuses **our own** prior Archon code as
libraries, re-aimed onto DataHub metadata governance. The self-audit consistency engine
and the governance validator are ported from our MemoryAgent; the LLM seam, ReAct loop,
and MCP server from our Autopilot. The DataHub MCP **client**, the domain model, the
fixtures, the harvest seam, and the four-agent pipeline are **new**. Full, file-by-file
disclosure: **[`NOTICE.md`](NOTICE.md)**.

## Design & roadmap

Multi-agent design, the mapping of each reused feature to the six judging criteria, and
the phased plan to the **Aug 10** deadline: **[`docs/DESIGN.md`](docs/DESIGN.md)**.

## License

[Apache-2.0](LICENSE).
