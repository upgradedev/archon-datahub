# `datahub-audit` — a DataHub Skill (staged for upstream contribution)

A read-only **metadata-governance audit** skill for DataHub, in the format of the official
[`datahub-project/datahub-skills`](https://github.com/datahub-project/datahub-skills) registry.

## What it is

An installable agent Skill (`SKILL.md` + a `catalog-audit` slash-command wrapper +
evaluations) that runs a **systematic coverage audit** over a DataHub catalog using only the
read-only DataHub MCP Server tools (`search`, `get_entities`, `list_schema_fields`,
`get_lineage`). It produces a steward-facing report: per-rule coverage percentages, a ranked
findings list with recommendations, and an executive summary. It **recommends; it never
mutates** — accepted fixes are handed off to the existing `/datahub-enrich` skill.

Policy set (each rule maps 1:1 to a DataHub aspect): **G1** ownership, **G2** domain, **G3**
description, **G4** deprecation hygiene, **G5** schema-type completeness, **G6**
sensitive-field classification, **L1** lineage reachability.

## Why upstream wants this (the gap it fills)

The registry's own `datahub-search` skill already draws the boundary and points at a skill
that **does not yet exist**:

> "For systematic audits ('how complete is our metadata'), use `/datahub-audit`."
> — `skills/datahub-search/SKILL.md`, and its "Not This Skill" table
> ("Search answers **ad-hoc questions**. Audit generates **systematic reports** …").

The registry ships `datahub-search`, `datahub-lineage`, `datahub-enrich`, `datahub-quality`,
`datahub-setup` (plus connector/MFE skills) — but **no `datahub-audit`**. This skill fills
that referenced-but-missing slot, and slots cleanly beside the others: *search* answers
one-off questions, *audit* (this) produces the coverage report, *enrich* applies the fixes.

## Intended upstream PR

- **Target repo:** `datahub-project/datahub-skills`
- **Change:** add `skills/datahub-audit/` (this directory) + a `commands/catalog-audit.md`
  wrapper, and add the one-line `/datahub-audit` cross-reference to the sibling skills'
  "Not This Skill" tables where they already gesture at an audit.
- **Format compliance:** frontmatter (`name`, `description`, `user-invocable`,
  `min-cli-version`, `allowed-tools`), the `Multi-Agent Compatibility` + `Not This Skill`
  sections, and `evaluations/*.json` all follow the registry's existing conventions.

## Honest scope

The skill's checks are exactly what the DataHub **read** surface can prove: presence/absence
of governance aspects on the current view, schema-type completeness, sensitive-field
classification, and lineage **reachability**. It deliberately does **not** claim cross-source
*contradiction* detection — DataHub aspects are single-valued (latest write wins), so a
contradiction is not observable from the read tools alone (it needs aspect version history:
systemMetadata / OpenAPI v3). Keeping the claims to what the tools deliver is what makes this
contribution-ready.

## Status

**Staged, not submitted.** This is prepared for a maintainer-reviewed upstream PR; the repo
owner decides when to open it. Nothing here is auto-published.
