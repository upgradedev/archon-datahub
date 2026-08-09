# Examples and evidence

Judges can inspect committed evaluation cases and evidence routes without
installing the stack:

- [`audit-governance-coverage.json`](../contrib/datahub-audit/evaluations/audit-governance-coverage.json)
  is a DataHub Skill evaluation case for governance-control coverage.
- [`audit-sensitive-and-lineage.json`](../contrib/datahub-audit/evaluations/audit-sensitive-and-lineage.json)
  is a DataHub Skill evaluation case for sensitive-data and lineage evidence.
- [`manifest.json`](../contrib/mcp-get-aspect-history/manifest.json) records the
  proposed bounded aspect-history tool for the upstream MCP server and its
  validation surface.
- [`JUDGE_EVIDENCE.md`](../docs/JUDGE_EVIDENCE.md) maps product claims to exact
  repository and CI evidence.

For the customer-facing generated artifacts, open the
[live application](https://archon-datahub.web.app), select **Run live audit**,
then **Prepare & verify pack**. The browser creates and verifies `report.json`,
`report.md` and `report.sarif` before enabling download. This path keeps the
sample current with the deployed release instead of duplicating generated files
in source control.

The live catalog evidence is read from a private OSS DataHub Core instance.
Narration is deterministic and explicitly records that no provider model call
occurred. Agent Context Kit, DataHub Skills, Analytics Agent and the governed
write/read-back/rollback path are labelled as protected-CI evidence wherever
they are not exposed to the anonymous browser.
