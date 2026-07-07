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
npm test            # 62 unit tests
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
is cloud-first and deliberately does not stand the stack up locally. The live adapter is
**pinned to the official `acryldata/mcp-server-datahub` source** (exact tool names, argument
schemas, and cleaned response shapes — see [`src/datahub/live-mappers.ts`](src/datahub/live-mappers.ts)),
so it works the moment it connects; you do not need a running instance to trust the code.

### 1 — Stand up DataHub on a cloud VM

Provision a VM with **≥2 vCPU / 8 GB RAM / ~15 GB free disk**, Docker + Compose v2, and
Python 3.10+:

```bash
# on the VM
python3 -m pip install --upgrade acryl-datahub
datahub docker quickstart            # pulls ~14 containers; UI on :9002, GMS on :8080
datahub docker ingest-sample-data    # optional: seed demo metadata
```

- UI: `http://<cloud-vm>:9002` — default login `datahub` / `datahub`.
- Create a **Personal Access Token**: UI → **Settings → Access Tokens**.
- Open the security group so your agent host can reach GMS (`:8080`) — or run the agent on
  the same VM.

### 2 — Point the DataHub MCP Server at it

The agent consumes the **official DataHub MCP Server**. Two transports (the adapter supports
both; the tool calls + mapping are identical):

- **stdio (default, reliable OSS path)** — the adapter launches the published server for you:
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh   # install uv (provides `uvx`)
  ```
  Leave `DATAHUB_MCP_URL` unset; the adapter runs `uvx mcp-server-datahub@latest` with your
  GMS URL + token in its environment.
- **HTTP (Streamable)** — set `DATAHUB_MCP_URL` to a hosted MCP endpoint (a DataHub Cloud
  tenant integrations URL, or a GMS that exposes `/mcp`).

### 3 — Configure `.env` and run the same code

```bash
# .env (see .env.example for all options)
DATAHUB_GMS_URL=http://<cloud-vm>:8080
DATAHUB_GMS_TOKEN=<personal-access-token>
# DATAHUB_MCP_URL=https://<tenant>.acryl.io/integrations/ai/mcp/   # only for the HTTP transport
ANTHROPIC_API_KEY=<optional — enables the real LLM narrator; or DASHSCOPE/GEMINI/OPENAI/LLM_API_KEY>

npm run audit:demo    # the same four-agent pipeline, now against the live catalog
```

The live path is a thin transport shell (`src/datahub/mcp-client-live.ts`) over the pinned
mappers. Read-only throughout: it calls only `search` / `get_entities` / `get_lineage` and
never enables the server's mutation tools.

**What survives the live MCP read surface (be honest about this).** DataHub aspects are
single-valued — a read returns one *current* value per aspect — so:

- **Governance (G1–G6)** and **schema completeness** audit fully and robustly (they are
  about absence of aspects on the current view).
- **Lineage-gap** detection depends on whether declared-but-uningested upstreams surface in
  the search/graph index; it is instance-dependent.
- **Cross-source contradiction** detection (the offline differentiator) **cannot fire from
  the MCP read tools alone** — two ingestion sources writing the same aspect overwrite each
  other, so only the latest is queryable. Recovering it needs aspect **version history**
  (systemMetadata / the GMS OpenAPI v3 aspect endpoints) or a cross-scan diff of stored
  harvests — a Phase-3 item. The live adapter therefore tags provenance by **scan time**
  (`scanId`), not a fabricated source.

Full DataHub + MCP integration research: [`docs/DATAHUB_RESEARCH.md`](docs/DATAHUB_RESEARCH.md).

## Read-only guarantee

Archon **recommends, a human disposes.** The DataHub MCP server's mutation tools
(`add_tags`, `set_domains`, …) are OFF by default and this agent never enables them. The
ReAct loop's terminal action (`emit_findings`) produces a `pending` report for a steward;
nothing in the pipeline or the loop writes back to DataHub.

## Testing & CI

- **Unit tests:** `node --test` over the consistency engine, governance validator, DataHub
  MCP client + harvester, and the pipeline / ReAct loop / MCP tools, the pinned live-MCP mappers, and LLM provider detection (62 tests).
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
