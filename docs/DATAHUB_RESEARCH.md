# DataHub research and Archon positioning

_Verified 2026-07-23 against primary sources. This note describes the integration
baseline used by Archon; it is not a generic installation guide._

## Executive answer

**DataHub is not a database.** It is an Apache-2.0 metadata and context platform that
builds a graph over data and AI assets: datasets, schemas, columns, lineage, owners,
domains, glossary terms, quality signals, dashboards, pipelines, and ML entities. The
actual records remain in systems such as Snowflake, PostgreSQL, CockroachDB, S3, or
Backblaze B2. DataHub stores and serves the context needed to discover, govern, and reason
about those systems. See DataHub's [project overview][datahub-repo],
[metadata model][datahub-model], and [license][datahub-license].

Archon's position is therefore:

> **DataHub catalogs the data estate; Archon audits the catalog itself.**

More precisely, Archon is a provenance-aware integrity control loop for the DataHub
Context Graph. It detects contradictions and governance regressions across retained
metadata versions, measures downstream blast radius, creates a digest-bound evidence
dossier, and permits only a human-approved, allowlisted remediation that is verified
after execution. It is not another catalog, warehouse, object store, or generic
text-to-SQL chatbot.

## What DataHub is compared with

| Product | Product category | Relationship to DataHub and Archon |
|---|---|---|
| [AWS Glue Data Catalog][aws-glue] | AWS metadata repository and metastore | A real catalog, especially strong for AWS table/schema metadata, crawlers, Athena, EMR, and Lake Formation. It is narrower than a cross-platform governance/context graph, although AWS is adding lineage and business context. |
| [Amazon SageMaker Catalog][sagemaker-catalog] / [Amazon DataZone][datazone] | Managed AWS data-and-AI catalog, governance, access, and data-product experience | The closer AWS-native alternative. SageMaker Catalog is built on DataZone and covers discovery, glossary, quality, lineage, and governed sharing. Prefer it when native AWS IAM and a single AWS operating model outweigh OSS portability. |
| [Microsoft Purview Data Map and Unified Catalog][purview] | Managed Microsoft data-governance catalog | A direct commercial alternative with multicloud scanning, lineage, domains, data products, quality, compliance, and access workflows. Prefer it for a Microsoft/Fabric-centric estate and integrated compliance operations. |
| [Google Cloud Knowledge Catalog][google-catalog] | Managed Google Cloud metadata, quality, lineage, and governance catalog | A direct GCP-native alternative. Google renamed **Dataplex Universal Catalog** to **Knowledge Catalog on 2026-04-10**; API, CLI, client-library, and IAM names did not change. |
| [Alibaba DataWorks][dataworks] | Alibaba Cloud end-to-end data engineering and governance platform | Data Map, Data Asset Governance, quality, lineage, security, development, and orchestration make it the relevant Alibaba governance comparison. It is broader and more Alibaba-native than DataHub. |
| [Alibaba Data Lake Formation][dlf] | Managed Alibaba lakehouse metadata, permissions, and storage-optimization control plane | Comparable to a cloud-native lakehouse catalog/metastore, not to Archon's cross-catalog integrity agent. |
| [Qwen / Alibaba Cloud Model Studio][model-studio] | Model API and model-service platform | **Not a data catalog or database.** It can supply an LLM to an agent, but it does not replace DataHub's metadata graph, lineage, ownership, or governance state. |
| [CockroachDB][cockroach] | Distributed SQL database | **Not a catalog competitor.** It stores application data and serves SQL transactions. DataHub can catalog it through its [CockroachDB ingestion source][datahub-cockroach]. |
| [Backblaze B2][backblaze] | Object storage with Native and S3-compatible APIs | **Not a catalog competitor.** It can hold datasets or Archon evidence artifacts. S3 compatibility does not by itself prove every S3 connector behavior; a B2 ingestion recipe must be validated before it is claimed. |

The nearest open-source category peer is [OpenMetadata][openmetadata]. Commercial
cross-platform peers include [Atlan][atlan], [Alation][alation],
[Collibra][collibra], and [Informatica][informatica]. Platform-native alternatives also
include [Databricks Unity Catalog][unity] and [Snowflake Horizon Catalog][horizon].

This is not a claim that DataHub always wins. A single-cloud organization may rationally
choose its native catalog for integrated IAM, procurement, and operations. DataHub is a
strong fit for Archon because it is open source, vendor-neutral, schema-first, API-driven,
multi-platform, and exposes both a metadata graph and an official agent tool surface.
It can also complement native catalogs rather than requiring their replacement.

## Why DataHub is the right substrate for Archon

1. **Graph-shaped evidence.** DataHub represents assets and their relationships, so one
   finding can be connected to owners, source pipelines, fields, and downstream consumers.
2. **Technical plus organizational context.** Schemas and lineage coexist with tags,
   glossary terms, domains, ownership, quality, and ML metadata.
3. **Time and provenance.** Versioned aspects and `SystemMetadata` make metadata changes
   auditable when the deployment retains the required history.
4. **Agent-native access.** The official MCP server provides bounded read tools and
   separately gated mutation tools.
5. **Governed write-back.** The challenge explicitly rewards projects that go beyond
   reading metadata and contribute context back where appropriate. Archon can do this
   without allowing an LLM to invent a tool name or mutation payload.
6. **OSS contribution path.** DataHub's Apache-2.0 repositories allow a useful generic
   improvement—such as bounded aspect-history MCP tools—to be proposed upstream.

The winning narrative is not “AI reads a catalog.” It is:

```text
retained context → deterministic integrity finding → lineage blast radius
→ evidence dossier → human decision → allowlisted write → postcondition proof
```

## Official MCP integration baseline: v0.6.0

Archon targets the official [`acryldata/mcp-server-datahub` v0.6.0 release][mcp-release],
not an unpinned `latest` invocation. The [v0.6.0 README][mcp-readme] defines this split:

### Catalog read tools

- `search`
- `get_entities`
- `list_schema_fields`
- `get_lineage`
- `get_lineage_paths_between`
- `get_dataset_queries`

The v0.6.0 release adds MCP `readOnlyHint` annotations to read tools. These tools are the
normal Archon discovery surface, but they primarily expose a current catalog view.

### Catalog mutation tools

These are hidden unless `TOOLS_IS_MUTATION_ENABLED=true`:

- `add_tags` / `remove_tags`
- `add_terms` / `remove_terms`
- `add_owners` / `remove_owners`
- `set_domains` / `remove_domains`
- `update_description`
- `add_structured_properties` / `remove_structured_properties`

Document tools are a separate surface: `search_documents`, `grep_documents`, and
`save_document`; their visibility and save behavior have their own configuration.
`get_me` is separately gated by `TOOLS_IS_USER_ENABLED=true`.

Archon's production boundary keeps catalog reads and writes separate:

- the audit API uses a read-scoped DataHub credential;
- a separate worker owns the mutation-enabled MCP client and write-scoped credential;
- the browser submits only an approval decision, never a mutation tool or arguments;
- the worker reloads the immutable plan, verifies its digests and expected pre-state,
  executes one allowlisted action, reads the result back, and emits a receipt.

Enabling mutation tools is therefore necessary but not sufficient authorization.

## Aspect history and provenance correctness

An aspect is DataHub's atomic metadata-write unit. The official
[OpenAPI guide][openapi] exposes entity/aspect reads and a
[Timeline API][timeline] for version history. Archon's direct v3 reader requests the
current aspect at `version=0`, then enumerates retained historical slots `1..N` with
`systemMetadata=true`. This path is deliberately independent of the MCP current-view
tools.

Two conditions are non-negotiable:

1. **History must actually be retained.** Archon does not assume unlimited history. A
   current-only response cannot prove a displaced value, and a truncated or malformed
   history is an error rather than “no contradiction.”
2. **A run is not a source.** DataHub's [`SystemMetadata` schema][system-metadata]
   defines `runId` as the original batch-ingestion run and `pipelineName` as the ingestion
   pipeline ID. DataHub's [ingestion stamping code][source-helpers] assigns
   `ctx.run_id` to `runId` and `ctx.pipeline_name` to `pipelineName`.

Consequently:

- two different `runId` values from one `pipelineName` are successive executions of the
  **same source**; a changed value is drift, not a cross-source contradiction;
- two different, non-empty stable `pipelineName` values may establish independent source
  provenance;
- a trusted run-to-source resolution may be supplied for older history that predates
  `pipelineName`;
- unresolved provenance collapses to `unknown-source` and cannot trigger a confirmed
  cross-source finding.

This fail-closed rule prevents ordinary re-ingestion from being mislabeled as Archon's
headline contradiction.

## Hackathon constraints that shape the project

The [official rules][challenge-rules] set the deadline at **2026-08-10 17:00 EDT**.
The project must be a working application that uses open-source DataHub plus at least one
of the MCP Server, Agent Context Kit, DataHub Skills, or Analytics Agent. The “Agents That
Do Real Work” framing explicitly favors read, action, and write-back so later humans or
agents inherit the result.

Required submission material:

- an accessible project URL for judges;
- a public source repository with all source/assets/instructions and a visible
  Apache-2.0 license;
- an English project description;
- a public demonstration video under three minutes that shows the working project;
- sample generated outputs are recommended.

Multiple submissions are allowed, but each must be **unique and substantially different**.
The five equally weighted criteria are:

1. meaningful use of DataHub;
2. technical execution and honest end-to-end behavior;
3. originality beyond built-in DataHub features;
4. real-world usefulness;
5. submission quality.

Meaningful upstream OSS contributions receive favorable bonus consideration. For Archon,
that means the demo must visibly prove the read → detect → impact → approve → verified
write-back loop; CI evidence and prose alone cannot substitute for the hosted application.

## Operational research guardrails

- Pin DataHub, MCP server, and connector versions used in recorded evidence; do not use
  `@latest` in reproducible instructions.
- Treat quickstart topology as version-dependent. Do not promise a fixed container count,
  database/search implementation, or default credential.
- Do not present fixture output as a live DataHub run. Label it explicitly.
- Do not claim Backblaze B2 ingestion until its S3-compatible recipe is exercised.
- Do not claim a confirmed contradiction when history or stable source identity is absent.
- Keep the official MCP server and DataHub GMS outside the public browser trust boundary.

## Primary-source index

[datahub-repo]: https://github.com/datahub-project/datahub
[datahub-license]: https://github.com/datahub-project/datahub/blob/master/LICENSE
[datahub-model]: https://docs.datahub.com/docs/metadata-modeling/metadata-model
[openapi]: https://docs.datahub.com/docs/api/openapi/openapi-usage-guide
[timeline]: https://docs.datahub.com/docs/dev-guides/timeline
[system-metadata]: https://github.com/datahub-project/datahub/blob/master/metadata-models/src/main/pegasus/com/linkedin/mxe/SystemMetadata.pdl
[source-helpers]: https://github.com/datahub-project/datahub/blob/master/metadata-ingestion/src/datahub/ingestion/api/source_helpers.py
[mcp-release]: https://github.com/acryldata/mcp-server-datahub/releases/tag/v0.6.0
[mcp-readme]: https://github.com/acryldata/mcp-server-datahub/blob/v0.6.0/README.md
[challenge-rules]: https://datahub.devpost.com/rules

[aws-glue]: https://docs.aws.amazon.com/glue/latest/dg/catalog-and-crawler.html
[sagemaker-catalog]: https://aws.amazon.com/sagemaker/catalog/
[datazone]: https://docs.aws.amazon.com/datazone/latest/userguide/sagemaker-datazone.html
[purview]: https://learn.microsoft.com/en-us/purview/data-governance-overview
[google-catalog]: https://docs.cloud.google.com/dataplex/docs/release-notes#April_10_2026
[dataworks]: https://www.alibabacloud.com/help/en/dataworks/user-guide/what-is-dataworks
[dlf]: https://www.alibabacloud.com/help/en/dlf/dlf-2-0/product-overview/what-is-data-lake-formation
[model-studio]: https://www.alibabacloud.com/help/en/model-studio/what-is-model-studio
[cockroach]: https://www.cockroachlabs.com/docs/stable/why-cockroachdb
[datahub-cockroach]: https://docs.datahub.com/docs/generated/ingestion/sources/cockroachdb
[backblaze]: https://www.backblaze.com/docs/cloud-storage-about-backblaze-b2-cloud-storage

[openmetadata]: https://docs.open-metadata.org/latest/features
[atlan]: https://docs.atlan.com/get-started/what-is-atlan
[alation]: https://www.alation.com/product/data-governance/
[collibra]: https://www.collibra.com/products/collibra-platform
[informatica]: https://www.informatica.com/products/data-governance.html
[unity]: https://docs.databricks.com/aws/en/data-governance/unity-catalog/
[horizon]: https://docs.snowflake.com/en/user-guide/snowflake-horizon
