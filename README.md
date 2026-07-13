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
  On a **live** catalog latest-write-wins hides the conflict on the current view — so Archon
  recovers it from **aspect version history** (a direct GMS OpenAPI v3 read, gated on the
  `systemMetadata.runId` that wrote each version), firing on real, live-shaped data and not
  only on offline fixtures. See "Recovering contradictions on a live catalog" below.
- **Lineage gaps** — a dataset declares an upstream that the catalog never ingested: a
  dangling lineage edge that hides schema-break risk to everything downstream.
- **Governance violations** — ungoverned or unclassified assets (no owner, no domain, no
  description, an untyped field, an unclassified sensitive field), via deterministic
  policy rules **G1–G6**.

> **The differentiator:** a self-auditing contradiction/inconsistency engine. Most catalog
> agents *retrieve* metadata; Archon *interrogates* it for internal disagreement, with a
> **pure, deterministic engine** that runs identically on offline fixtures and on live-shaped
> data — the "self-auditing" claim is measured on the same code that ships. On a live catalog
> it recovers cross-source contradictions from **aspect version history** (a direct GMS read),
> so the differentiator fires on real data, not only fixtures — with an honest distinct-source
> gate that never flags a benign single-run edit. See "Recovering contradictions on a live
> catalog" below.

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
- **Cross-source contradiction** detection (the differentiator) **cannot fire from the MCP
  read tools alone** — two ingestion sources writing the same aspect overwrite each other, so
  only the latest is queryable through `search`/`get_entities`/`get_lineage`. Archon
  **recovers** it (see below) from a complementary **direct GMS read**, never claiming the MCP
  read tools expose what they don't.

### Recovering contradictions on a live catalog (the differentiator, live)

DataHub retains every prior write: each aspect version carries `systemMetadata` with the
`runId` that produced it (GMS **OpenAPI v3** `…/entity/dataset/{urn}/{aspect}?systemMetadata=true`;
the **Timeline API** `/openapi/v2/timeline/v1/{urn}` is the equivalent change-log surface).
So `harvestVersionHistories()` does a **direct GMS read** of each mutable aspect's version
list and feeds it to the *same* pure self-audit engine
([`src/datahub/version-history.ts`](src/datahub/version-history.ts)). Two ingestion runs
asserting conflicting values (owner=finance from the Snowflake connector, owner=ops from the
dbt manifest) resurface as a real contradiction the current view had hidden.

**Two honesty guards.** (1) This is a **direct GMS read, not an MCP tool** — we do not claim
the MCP read tools do it. (2) A value that merely *changed* across writes from **one** run is
benign **drift**, not a conflict; the engine runs with `requireDistinctSources: true`, so only
histories that **flip-flop between distinct `runId`s** are flagged. The negative case (a
single-run monotonic edit produces **zero** contradictions) is a first-class test. A
genuinely on-MCP-surface **cross-scan drift** detector (`detectDrift`) is also provided,
labeled as *drift / candidate*, never as a confirmed cross-source contradiction.

> **Seeding the live demo (important):** because the recovery is gated on **distinct
> `runId`s**, `datahub docker ingest-sample-data` alone shows *nothing* — it is a single
> bootstrap run, so every aspect shares one `runId` (correctly read as drift, not a conflict).
> To reproduce a real recovered contradiction, ingest the conflict as **two separate runs**:
> e.g. emit `owner=team-finance` in one ingestion, then re-emit `owner=team-ops` for the same
> dataset in a second ingestion. The version history then flip-flops across two `runId`s and
> the contradiction fires.

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
- **Readiness gate** (`npm run readiness` · [`scripts/readiness.ts`](scripts/readiness.ts)):
  a machine-checkable, weighted scorecard of the hackathon criteria computed from **real
  evidence** — it runs the pipeline, the ReAct loop, the MCP round-trip, and the live
  contradiction-recovery path, and statically verifies the read-only tool surface + the
  docs/NOTICE consistency. It emits `readiness.json` and **fails CI if the automatable
  completeness drops below 95%**. It reports a second number, **completeness (incl.
  user-gated)**, which stays below 100 until the user-gated live proof (a recorded live
  DataHub run, a real captured cassette, the demo video) lands — so "95% automatable" is
  never mistaken for "95% ready".
- **CI** (`.github/workflows/ci.yml`): gitleaks (secret scan, fail-fast) → typecheck →
  test → coverage gate → **readiness gate** → dependency audit. Fully offline via the Fakes.

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
