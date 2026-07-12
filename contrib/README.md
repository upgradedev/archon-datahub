# `contrib/` — staged open-source contributions to the DataHub ecosystem

Artifacts here are prepared for **upstream** DataHub-project repositories. They are staged in
this repo (Apache-2.0) so they can be reviewed in context; **none are opened upstream
automatically** — the repo owner decides when to submit each one.

| Contribution | Target upstream repo | What it is | Status |
|---|---|---|---|
| [`datahub-audit/`](datahub-audit/) | [`datahub-project/datahub-skills`](https://github.com/datahub-project/datahub-skills) | A read-only metadata-governance **audit** Skill (SKILL.md + `catalog-audit` command + evaluations) that fills the `/datahub-audit` slot the registry's own `datahub-search` skill already references but does not ship. | Staged, not submitted |

Each contribution folder carries its own `README.md` explaining the exact upstream PR intent
and the format-compliance details.
