# `contrib/` — staged open-source contributions to the DataHub ecosystem

Artifacts here are prepared for **upstream** DataHub-project repositories. They are staged in
this repo (Apache-2.0) so they can be reviewed in context; **none are opened upstream
automatically** — the repo owner decides when to submit each one.

| Contribution | Target upstream repo | What it is | Status |
|---|---|---|---|
| [`mcp-get-aspect-history/`](mcp-get-aspect-history/) | [`acryldata/mcp-server-datahub`](https://github.com/acryldata/mcp-server-datahub) | The **primary bonus candidate**: an upstream-ready, read-only `get_aspect_history` MCP tool with exact pinned source/test artifacts, registration patch, governance allowlist, hard request/response bounds, provenance projection, and fail-closed behavior. | Staged against exact commit; not submitted or locally executed |
| [`datahub-audit/`](datahub-audit/) | [`datahub-project/datahub-skills`](https://github.com/datahub-project/datahub-skills) | A supplemental read-only metadata-governance audit Skill draft (SKILL.md + command + evaluations). It is useful independently, but it is not the primary bonus evidence candidate. | Supplemental draft; staged, not submitted |

Each contribution folder carries its own `README.md` explaining the exact upstream PR intent
and the format-compliance details.
