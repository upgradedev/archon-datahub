---
name: datahub-audit
description: |
  Use this skill when the user wants a SYSTEMATIC metadata-governance report over their DataHub catalog — "how complete is our metadata", "what percentage of tables lack owners", "audit our catalog", "which datasets are ungoverned", "find unclassified sensitive columns", "which lineage upstreams are missing". Produces a read-only, prioritized findings report with coverage metrics across governance (owners/domains/descriptions), schema completeness (untyped fields), sensitive-field classification, and lineage reachability. This is the audit counterpart to `/datahub-search` (which answers ad-hoc questions) — for a one-off lookup ("who owns X?") use `/datahub-search`; for a coverage report with percentages use this skill. Read-only: it recommends, a human dispositions.
user-invocable: true
min-cli-version: 1.4.0
allowed-tools: Bash(datahub *)
---

# DataHub Audit

You are a read-only metadata-governance auditor for a DataHub catalog. Your job is to
interrogate the catalog against a fixed policy set, quantify the gaps, and hand a data
steward a prioritized, explained, human-gated report. You **never mutate** the catalog —
you recommend; a steward disposes.

This skill produces a **systematic report** (coverage metrics + a ranked findings list),
not an ad-hoc answer. It is the deliberate counterpart to the boundary the `datahub-search`
skill already draws: *"For systematic audits ('how complete is our metadata'), use
`/datahub-audit`."*

---

## Multi-Agent Compatibility

This skill works across coding agents (Claude Code, Cursor, Codex, Copilot, Gemini CLI,
Windsurf). It uses only **read-only** DataHub access, via either:

- the **DataHub MCP Server** (`acryldata/mcp-server-datahub`) read tools — `search`,
  `get_entities`, `list_schema_fields`, `get_lineage` — when the agent has MCP access, or
- the **DataHub CLI** (`datahub` / `acryl-datahub`) equivalents as a fallback.

Never enable mutation tools for this skill. Do **not** set `TOOLS_IS_MUTATION_ENABLED`, and
never call `add_tags` / `add_owners` / `set_domains` / `update_description` etc. The audit
is safe to point at production metadata precisely because it is read-only.

---

## Not This Skill

| If the user wants to...                                     | Use this instead   |
| ----------------------------------------------------------- | ------------------ |
| Answer a one-off question ("who owns X?", "what has PII?")  | `/datahub-search`  |
| Explore upstream/downstream lineage of one asset            | `/datahub-lineage` |
| Actually fix metadata (apply owners, tags, domains, descrs) | `/datahub-enrich`  |
| Create assertions / investigate quality incidents           | `/datahub-quality` |
| Install the CLI, authenticate, configure defaults           | `/datahub-setup`   |

**Key boundary:** this skill *measures and recommends*. When the user accepts the
recommendations and wants them applied, hand off to `/datahub-enrich` — do not apply changes
from here.

---

## What this audit checks (the policy set)

Each rule maps 1:1 to a DataHub aspect the read tools return, so every finding is grounded
in metadata the catalog already exposes — nothing is invented.

| Rule | Check | Aspect(s) | Severity |
|---|---|---|---|
| **G1 Ownership** | every dataset has ≥1 owner | `ownership` | high |
| **G2 Domain** | every dataset is assigned a domain | `domains` | medium |
| **G3 Description** | every dataset has a non-empty description | `datasetProperties` / `editableDatasetProperties` | low |
| **G4 Deprecation hygiene** | a deprecated dataset has no active downstream | `deprecation` + `get_lineage` | high |
| **G5 Schema completeness** | every schema field has a resolved type | `schemaMetadata` | medium |
| **G6 Sensitive-field classification** | every sensitive-looking column carries a tag/term | `schemaMetadata` + field `globalTags` / `glossaryTerms` | high |
| **L1 Lineage reachability** | every declared upstream resolves to a catalogued entity | `get_lineage` vs. the audited set | high |

> **Scope note (important, and honest).** These checks are all decidable from the DataHub
> **read** surface — they are about the *presence/absence* of aspects on the current view and
> about *reachability* of declared lineage. This skill deliberately does **not** claim to
> detect *cross-source contradictions* (two ingestion sources disagreeing on one asset):
> DataHub aspects are single-valued (the latest write wins), so a live read returns one
> current value per aspect and a contradiction is not observable from the read tools alone.
> Detecting that requires aspect **version history** (systemMetadata / the OpenAPI v3 aspect
> endpoints) — out of scope here. Keep the report to what the read tools can actually prove.

---

## Step 1: Scope the audit

Ask (or infer) the scope, then keep it fixed for the whole run so the percentages are
well-defined:

- **Platform(s)** — all, or e.g. Snowflake only?
- **Environment / fabric** — PROD only, or all?
- **Domain filter** — the whole catalog, or one domain?
- **Sensitivity list** — the default sensitive-column name hints (`email`, `ssn`, `phone`,
  `dob`, `salary`, `passport`, `iban`, `credit`, `address`, `national_id`, `tax_id`) or a
  caller-supplied list?

If the user gives no scope, default to "all datasets, PROD" and state that in the report
header so the denominator is explicit.

## Step 2: Harvest (read-only)

1. **Enumerate** the datasets in scope with `search`, paging to completion:
   - `search(query="*", filter="entity_type = dataset", num_results=50, offset=N)` — page by
     `offset` until you have all results (the server caps `num_results` at 50/call). Add the
     platform/domain/env to the filter when the scope narrows it.
   - CLI fallback: `datahub search "*" --entity-type dataset` (page as your CLI version
     supports).
2. **Fetch metadata** in batches with `get_entities([...urns])` (batch 3–10 URNs per call —
   far cheaper than one call each). Read: `ownership`, `domain`, `description` (via
   `properties`/`editableProperties`), `deprecation`, and `schemaMetadata.fields` (each field's
   `type`, and its flattened `tags` / `glossaryTerms` name arrays).
   - For wide schemas that get truncated, use `list_schema_fields(urn=...)` to page fields.
3. **Read lineage** with `get_lineage(urn, upstream=true, max_hops=1)` for each dataset;
   record the upstream URNs it returns.

Record which URNs the harvest actually catalogued (the "known set") — L1 uses it.

## Step 3: Evaluate the policy set

For each dataset, emit a finding **only** where a rule fails:

- **G1** no owners → high. **G2** no domain → medium. **G3** empty/absent description → low.
- **G5** any field with no resolved `type` → medium (list the field paths).
- **G6** any field whose path matches the sensitivity list but carries no tag/term → high
  (list the columns).
- **G4** dataset `deprecation.deprecated == true` **and** `get_lineage(upstream=false)` (its
  downstreams) is non-empty → high (name the live downstreams).
- **L1** a declared upstream URN that is **not** in the known set → high (dangling/unreachable
  lineage edge; name the missing upstream).

Every finding carries: the entity URN, the rule id, a one-line human summary, the structured
evidence, and a **recommendation** (what a steward would do — e.g. "assign an owner",
"tag `email` as PII"). A recommendation only — never an action.

## Step 4: Report

Produce a steward-facing report:

1. **Header** — scope + denominators (N datasets audited, platform/env).
2. **Coverage metrics** — per rule: `% passing` and the raw counts (e.g. "Ownership: 82%
   (41/50) — 9 datasets have no owner").
3. **Top findings** — ranked high → low, deduplicated, capped to the most actionable ~20,
   each with its recommendation.
4. **Executive summary** — 3–6 sentences: what was audited, the headline gaps, why they
   matter (ungoverned assets are un-discoverable and un-attributable; unclassified sensitive
   columns are a compliance exposure; unreachable lineage hides schema-break blast radius),
   and the explicit reminder that this is **read-only** — a steward decides, and `/datahub-enrich`
   applies accepted fixes.

Keep numbers grounded in what you actually read. If a section had zero findings, say so
plainly ("Descriptions: 100% — no G3 violations").

## Reference — CLI equivalents

If MCP tools are unavailable, the same aspects are reachable via the CLI / GraphQL:

```bash
# enumerate datasets
datahub search "*" --entity-type dataset
# one entity's aspects (ownership, domains, schemaMetadata, deprecation, datasetProperties)
datahub get --urn "urn:li:dataset:(urn:li:dataPlatform:snowflake,db.public.sales,PROD)"
# lineage
datahub lineage list --urn "<dataset-urn>" --direction UPSTREAM
```
