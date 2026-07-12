---
name: catalog-audit
description: Audit the DataHub catalog for governance, schema, sensitivity, and lineage-reachability gaps and produce a coverage report
argument-hint: "[scope, e.g. 'PROD Snowflake datasets' or a domain]"
---

# DataHub Audit

Use the Skill tool to invoke the full `datahub-audit` skill:

```
Skill tool:
  skill: "datahub-skills:datahub-audit"
```

**User's request:** $ARGUMENTS

This skill runs a **read-only** systematic audit of the catalog and produces a report with:

1. **Coverage metrics** — per-rule pass percentages (ownership, domain, description, schema
   type completeness, sensitive-field classification, lineage reachability).
2. **Ranked findings** — high → low, each with a steward-facing recommendation.
3. **Executive summary** — what was audited, the headline gaps, and why they matter.

It recommends; it never mutates. To apply accepted fixes, hand off to `/datahub-enrich`.

If no scope is provided, default to all PROD datasets and state the denominator in the report
header. For a one-off question ("who owns X?") use `/datahub-search` instead.
