# DataHub OSS — Technical Research for Hackathon Agent Integration

_Compiled 2026-07-06. Primary sources: docs.datahub.com, github.com/datahub-project/datahub, github.com/acryldata/mcp-server-datahub._

> **Note on naming/domains (2026):** DataHub's docs now live at **docs.datahub.com** (the old `datahubproject.io` redirects). The company/product marketing site is **datahub.com**. The OSS project is **github.com/datahub-project/datahub**. The commercial/managed offering is **DataHub Cloud** (formerly Acryl); the free self-hosted edition is now branded **DataHub Core** (a.k.a. DataHub OSS). The PyPI CLI package is still **`acryl-datahub`**.

---

## 1. DataHub OSS platform — what it is & running locally

### What it is
DataHub is an open-source **metadata platform / data catalog** for the modern data stack: search & discovery, data lineage, governance (glossary, tags, domains, ownership), and observability. Originally built at LinkedIn, now a standalone project stewarded by Acryl/DataHub. Architecture is a **schema-first metadata graph** (entities + aspects) served by a Java metadata service (GMS) with Kafka, a relational store (MySQL/Postgres), a search index (OpenSearch/Elasticsearch), and a React frontend.

### Local quickstart
Requires **Docker + Docker Compose v2** and **Python 3.10+**.

```bash
# 1. Install the CLI
python3 -m pip install --upgrade acryl-datahub
#   (or: brew install datahub-project/tap/datahub)
datahub version

# 2. Spin up the whole stack locally (docker-compose under the hood)
datahub docker quickstart
#   downloads compose config to ~/.datahub/quickstart/ and pulls ~14 containers

# 3. (optional) load sample metadata
datahub docker ingest-sample-data
#   newer CLIs also expose datapacks, e.g.:
#   datahub datapack load showcase-ecommerce
```

- **UI:** http://localhost:9002 — default login **`datahub` / `datahub`**.
- **Stop:** `datahub docker quickstart --stop`
- **Wipe everything:** `datahub docker nuke`
- **Backup/restore:** `datahub docker quickstart --backup` / `--restore`
- **Pin a version:** `datahub docker quickstart --version v1.6.0`
- Options: `datahub docker quickstart --help`

### Services & ports that come up
| Service | Container | Port | Role |
|---|---|---|---|
| **Frontend** | `datahub-frontend-react` | **9002** | React UI + auth/proxy |
| **GMS** (Generalized Metadata Service) | `datahub-gms` | **8080** | Core backend — GraphQL, REST/OpenAPI, ingestion sink |
| MySQL | `mysql` | 3306 | primary metadata store (aspects) |
| Kafka + Zookeeper | `broker`, `zookeeper` | 9092 / 2181 | MCP/MCE event log |
| OpenSearch (Elasticsearch) | `opensearch` | 9200 | search + graph index |
| Schema Registry | `schema-registry` | 8081 | Avro schemas for Kafka |
| system-update / setup jobs | one-shot init containers | — | bootstrap indices/schemas |

~14 containers total. Change the GMS host port with `DATAHUB_MAPPED_GMS_PORT=58080 datahub docker quickstart`.

### System requirements
Recommended minimum: **2 CPUs, 8 GB RAM, 2 GB swap, ~13 GB free disk**. Docker Desktop must be given enough memory (8 GB); the #1 quickstart failure is under-provisioned Docker RAM (containers OOM/exit).

Sources: https://docs.datahub.com/docs/quickstart · https://docs.datahub.com/docs/cli/ · https://docs.datahub.com/docs/troubleshooting/quickstart · https://github.com/datahub-project/datahub

---

## 2. Metadata model

### Entities (primary graph nodes, each identified by a URN)
- **dataset** — tables, views, streams, topics, files
- **dashboard** and **chart** — BI visualizations
- **dataFlow** (pipeline, e.g. an Airflow DAG) and **dataJob** (task within a flow)
- **dataPlatform** — the source system (snowflake, kafka, s3, …)
- **container** — logical grouping (schema, database, folder)
- **glossaryTerm** and **glossaryNode** — business glossary
- **domain** — data-domain grouping for governance
- **tag** — lightweight labels
- **corpuser** and **corpGroup** — people/teams (owners)
- **assertion** and **dataContract** — data-quality rules and SLAs
- (also: mlModel, mlFeature, dataProduct, structuredProperty, etc.)

### Aspects
An **aspect** is "the smallest atomic unit of write in DataHub" — a typed bundle of attributes describing one facet of an entity. An entity is the sum of its aspects. Aspects are updated independently. Key governance aspects:
- `ownership` — owners (users/groups) + ownership type
- `globalTags` — attached tags
- `glossaryTerms` — attached business terms
- `domains` — domain membership
- `deprecation` — lifecycle/deprecation status
- `datasetProperties` / `editableDatasetProperties` — descriptions, custom props
- `schemaMetadata` — columns/fields + types
- `upstreamLineage` — lineage edges (see below)
- `dataContract`, `assertions` — quality/SLA
- `structuredProperties` — typed custom metadata

The model is defined schema-first in **PDL (Pegasus Data Language)**.

### URNs
`urn:<namespace>:<entityType>:<id>` — namespace is almost always `li`. Examples:
- `urn:li:dataPlatform:kafka`
- `urn:li:corpuser:jdoe`
- Nested key: `urn:li:dataset:(urn:li:dataPlatform:snowflake,prod_db.public.sales,PROD)` — the dataset key = (platform URN, name, fabric/environment). Fabric values: PROD/DEV/QA/etc.
- Parentheses, commas-inside-tuples, and the U+241F separator are reserved.

### Lineage representation
Lineage is stored as **relationships derived from aspects**, chiefly the **`upstreamLineage`** aspect on a dataset (pointing at its upstream datasets), plus dataJob input/output aspects for pipeline lineage. It supports **table-level and column-level (fine-grained)** lineage. It is directional (upstream/downstream) and traversable multi-hop through the graph index. Read it back via GraphQL `searchAcrossLineage` / `scrollAcrossLineage` or the SDK (§5).

### Change mechanisms (ingestion)
- **MCP — MetadataChangeProposal**: a proposed write of one aspect to one entity (the modern, preferred path; `MetadataChangeProposalWrapper` in Python).
- **MCE — MetadataChangeEvent**: the older/committed event form.
Both flow through GMS (sync REST or async Kafka) and update the store + search/graph indices.

Sources: https://docs.datahub.com/docs/metadata-modeling/metadata-model · https://docs.datahub.com/docs/what/urn · https://docs.datahub.com/docs/generated/lineage/lineage-feature-guide

---

## 3. DataHub MCP Server — PRIMARY INTEGRATION

**Yes, an official server exists:** **`acryldata/mcp-server-datahub`** — "The official Model Context Protocol (MCP) server for DataHub." Published to PyPI/npx as **`mcp-server-datahub`**. Works with **any DataHub instance — both DataHub Core (OSS self-hosted) and DataHub Cloud.**

### Tools exposed (exact names)
**Read-only (always on):**
- `search` — structured keyword search using DataHub's **`/q` syntax** (boolean logic, filters, pagination, sort by usage)
- `get_entities` — fetch full metadata for one or more entities by **URN** (batch-capable)
- `list_schema_fields` — list a dataset's schema fields, with keyword filter + pagination
- `get_lineage` — upstream or downstream lineage for any entity (table- or column-level), with hop control, filtering, pagination
- `get_lineage_paths_between` — exact lineage path(s) between two assets/columns, incl. intermediate transforms + the SQL query that produced the edge
- `get_dataset_queries` — real SQL queries (manual or system-generated) referencing a dataset/column

**Document/knowledge-base tools:**
- `search_documents`, `grep_documents` (regex over doc content), `save_document`

**Mutation tools — gated by `TOOLS_IS_MUTATION_ENABLED=true` (v0.5.0+):**
- `add_tags` / `remove_tags`
- `add_terms` / `remove_terms` (glossary terms)
- `add_owners` / `remove_owners`
- `set_domains` / `remove_domains`
- `update_description`
- `add_structured_properties` / `remove_structured_properties`
- (also supports creating glossary terms / submitting change proposals)

**User tools — gated by `TOOLS_IS_USER_ENABLED=true`:**
- `get_me`

> For a **metadata-governance agent**, the mutation tools (`add_tags`, `add_terms`, `add_owners`, `set_domains`, `update_description`) plus `search`/`get_entities`/`get_lineage` are exactly the surface you want. Remember they are **off by default** — you must set `TOOLS_IS_MUTATION_ENABLED=true`.

### Transport & connection
- **Local (stdio):** run via `uvx mcp-server-datahub@latest` — the standard MCP stdio server used by Claude Desktop / Cursor / Windsurf / Claude Code.
- **Remote (HTTP):** DataHub exposes an HTTP MCP endpoint.
  - Self-hosted GMS: `http://<gms-host>:8080/mcp`
  - DataHub Cloud (PAT): `https://<tenant>.acryl.io/integrations/ai/mcp/`
  - DataHub Cloud (OAuth, hosted): `https://mcp.datahub.com/mcp` (v1.0.2+, supports SSO via Okta/Azure AD, Dynamic Client Registration)

### Authentication
- **Self-hosted / OSS:** **Personal Access Token (PAT)**. Generate in the UI under **Settings → Access Tokens** (requires metadata-service auth enabled). Pass via `Authorization: Bearer <token>` or `?token=<token>`.
- **DataHub Cloud:** PAT (v0.3.12+) or OAuth+DCR (v1.0.2+, personal SSO login).

Env vars the server reads:
| Var | Purpose | Default |
|---|---|---|
| `DATAHUB_GMS_URL` | GMS endpoint (e.g. `http://localhost:8080`) | — |
| `DATAHUB_GMS_TOKEN` | PAT | — |
| `TOOLS_IS_MUTATION_ENABLED` | enable write tools | `false` |
| `TOOLS_IS_USER_ENABLED` | enable `get_me` | `false` |
| `TOOL_RESPONSE_TOKEN_LIMIT` | truncate large responses | `80000` |
| `SAVE_DOCUMENT_PARENT_TITLE` | folder for `save_document` | `Shared` |

### Client config (self-hosted OSS, stdio via uvx)
```json
{
  "mcpServers": {
    "datahub": {
      "command": "uvx",
      "args": ["mcp-server-datahub@latest"],
      "env": {
        "DATAHUB_GMS_URL": "http://localhost:8080",
        "DATAHUB_GMS_TOKEN": "<your-personal-access-token>"
      }
    }
  }
}
```
(Install uv first: `curl -LsSf https://astral.sh/uv/install.sh | sh`.)

Sources: https://github.com/acryldata/mcp-server-datahub · https://docs.datahub.com/docs/features/feature-guides/mcp · https://github.com/acryldata/mcp-server-datahub/releases

---

## 4. The extra components (Agent Context Kit / Skills / Analytics Agent)

All three are **real, current (late-2025 / 2026) DataHub-project offerings**, together marketed as the **"Context Platform for AI Agents."**

### (a) Agent Context Kit — the umbrella
"A set of guides, SDKs, and an MCP server that help you build AI agents with access to the capabilities and context in your DataHub instance." Three components:
1. **MCP Server** — the tool surface (§3). Central connection point.
2. **SDKs** — Python integration layer: **`pip install datahub-agent-context`**, with helpers for **LangChain** and **Google ADK** to build custom agents.
3. **Skills** — reusable workflow instructions (below).

Docs: https://docs.datahub.com/docs/dev-guides/agent-context/agent-context · Blog: https://datahub.com/blog/building-autonomous-data-agents/

### (b) DataHub Skills — workflow instructions layered on the tools
DataHub is "the first open-source metadata platform to ship a skills registry." **Skills vs Tools:** the MCP server gives an agent _tools_ (discrete actions); Skills give an agent _instructions_ — how to chain those tools into multi-step workflows. Distributed as **Claude Code plugins / agent skills** and installable for Cursor, GitHub Copilot, etc.

Install: `npx skills add datahub-project/datahub-skills` (from the `datahub-skills` repo).

The five shipped skills:
| Skill | What it does |
|---|---|
| `datahub-search` | Find assets via descriptions, glossary, ownership, usage, quality signals |
| `datahub-lineage` | Trace upstream sources, transforms, downstream consumers |
| **`datahub-enrich`** | **Add descriptions, tags, glossary terms, owners, domains, structured properties — "turns your agent into a data steward"** |
| `datahub-quality` | Find unhealthy assets, investigate incidents, create assertions (Cloud) |
| `datahub-setup` | Configure connection to your DataHub instance |

Docs: https://docs.datahub.com/docs/dev-guides/agent-context/skills

### (c) Analytics Agent — a reference talk-to-data app
"The first open-source talk-to-data agent built on a context platform." A **Text-to-SQL** application: connects to Snowflake / BigQuery / Databricks / Redshift / Postgres, uses DataHub context to ground SQL, BYO LLM (OpenAI / Anthropic / Gemini / open-weight), returns SQL-backed answers + auto-generated visualizations. It's an **example application**, not infrastructure.

Docs/blog: https://datahub.com/blog/datahub-analytics-agent/ · https://docs.datahub.com/docs/features/feature-guides/analytics-agent

### Which best complements a metadata-governance agent?
- **Core integration = the MCP Server** (tools) — mandatory; it's how you search, read lineage, and mutate tags/terms/owners/domains.
- **Best-fit Skill = `datahub-enrich`** — it is literally the governance/stewardship workflow (apply tags, glossary terms, owners, domains, descriptions at scale). Pair it with `datahub-search` + `datahub-lineage` for discovery/impact-analysis.
- The **Analytics Agent** is the wrong fit for a governance agent (it's a BI/query-answering demo), though it's a good architectural reference for "DataHub context → LLM."

---

## 5. Programmatic ingest / query for a demo

Package: **`acryl-datahub`** (`pip install acryl-datahub`). Modern high-level API is **`datahub.sdk.DataHubClient`**; low-level is emitters + `MetadataChangeProposalWrapper`.

### A. High-level SDK — ingest 2 datasets + a lineage edge, then read it back
```python
from datahub.sdk import DataHubClient, Dataset
from datahub.metadata.urns import DatasetUrn

client = DataHubClient(server="http://localhost:8080", token="<PAT>")

# create/emit two datasets
upstream = Dataset(platform="snowflake", name="sales_raw",
                   schema=[("id", "number"), ("region", "string")],
                   description="Raw sales")
downstream = Dataset(platform="snowflake", name="sales_cleaned",
                     schema=[("id", "number"), ("region", "string")])
client.entities.upsert(upstream)
client.entities.upsert(downstream)

up_urn   = DatasetUrn(platform="snowflake", name="sales_raw")
down_urn = DatasetUrn(platform="snowflake", name="sales_cleaned")

# add a lineage edge (table-level; column_lineage=True for fine-grained)
client.lineage.add_lineage(upstream=up_urn, downstream=down_urn)

# read lineage back
results = client.lineage.get_lineage(source_urn=up_urn,
                                     direction="downstream", max_hops=2)
print(results)
```
(Also available: `client.lineage.infer_lineage_from_sql(query_text=..., platform=..., default_db=..., default_schema=...)` to auto-parse table+column lineage from a SQL string.)

### B. Low-level emitter + MCP (aspect-level control)
```python
from datahub.emitter.rest_emitter import DatahubRestEmitter
from datahub.emitter.mcp import MetadataChangeProposalWrapper
from datahub.metadata.schema_classes import (
    UpstreamLineageClass, UpstreamClass, DatasetLineageTypeClass,
)
from datahub.emitter.mce_builder import make_dataset_urn

emitter = DatahubRestEmitter(gms_server="http://localhost:8080", token="<PAT>")

up   = make_dataset_urn("snowflake", "sales_raw", "PROD")
down = make_dataset_urn("snowflake", "sales_cleaned", "PROD")

mcp = MetadataChangeProposalWrapper(
    entityUrn=down,
    aspect=UpstreamLineageClass(upstreams=[
        UpstreamClass(dataset=up, type=DatasetLineageTypeClass.TRANSFORMED)
    ]),
)
emitter.emit(mcp)
```
There is also a **Kafka emitter** (`DatahubKafkaEmitter`) for async ingestion. Recipe-based ingestion (`datahub ingest -c recipe.yml`) is the config-driven route for real connectors.

### C. GraphQL API (read + mutate)
- Endpoint: **`POST http://localhost:8080/api/graphql`** (via frontend proxy: `http://localhost:9002/api/graphql`), `Authorization: Bearer <PAT>`.
- Lineage read: `searchAcrossLineage` / `scrollAcrossLineage`.
```graphql
query {
  scrollAcrossLineage(input:{
    urn:"urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_raw,PROD)",
    direction: DOWNSTREAM
  }) { searchResults { entity { urn type } } }
}
```
- Mutations for governance exist too: `addTags`, `addTerms`, `addOwners`, `updateLineage`, etc.

### D. OpenAPI / REST (v3)
GMS exposes **OpenAPI v3 entity endpoints** under `http://localhost:8080/openapi/` (Swagger UI at `/openapi/swagger-ui/index.html`). You can `POST` aspects (entity/aspect CRUD) directly — same MCP semantics without the Python SDK. Good for non-Python agents.

### Demo recipe (end-to-end, minimal)
1. `pip install acryl-datahub`
2. `datahub docker quickstart` → wait for http://localhost:9002 (login datahub/datahub)
3. Create a PAT: Settings → Access Tokens.
4. Run the script in **§5.A** (ingest 2 datasets + edge, read lineage back).
5. Confirm the lineage edge in the UI, or via `client.lineage.get_lineage(...)`, or GraphQL `scrollAcrossLineage`.
6. Point your agent at the MCP server (§3 config) with `DATAHUB_GMS_URL=http://localhost:8080` + the PAT; call `search` / `get_lineage`; enable `TOOLS_IS_MUTATION_ENABLED=true` to let it apply tags/terms.

Sources: https://docs.datahub.com/docs/api/tutorials/lineage · https://docs.datahub.com/docs/api/datahub-apis · https://docs.datahub.com/docs/api/graphql/overview · https://docs.datahub.com/docs/api/openapi/openapi-usage-guide

---

## Uncertainties / to verify against live env
- **Exact SDK method surface** (`client.entities.upsert` vs `Dataset` emit helpers) shifts across `acryl-datahub` releases — pin a version and check `datahub.sdk` in your installed package. The `DataHubClient` + `client.lineage.add_lineage` / `get_lineage` API is confirmed in current docs; the exact `Dataset(...)` constructor args are the most version-sensitive part.
- **MCP mutation tool names** — confirmed `add_tags/remove_tags`, `add_terms/remove_terms`, `add_owners/remove_owners`, `set_domains/remove_domains`, `update_description`, `add_structured_properties`. Newer releases may add/rename; check `mcp-server-datahub` README + `--releases` for your version.
- **Self-hosted OSS support for the built-in HTTP `/mcp` endpoint** (`http://<gms>:8080/mcp`) is documented, but the most reliable OSS path for a hackathon is the **stdio `uvx mcp-server-datahub`** wrapper pointed at your local GMS — verify which your DataHub version ships.
- **`datahub docker ingest-sample-data`** vs newer **`datahub datapack load ...`** — command name depends on CLI version; both aim to seed demo metadata.
- Container count (~14) and exact supporting images vary by DataHub version (OpenSearch vs Elasticsearch, MySQL vs Postgres).
