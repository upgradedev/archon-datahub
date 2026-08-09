# Clean architecture quality review

Final review date: 2026-08-09. Target: the exact final judge application release
`7cf2ab063312c2bf06fd2d65c798e802f7070a37`. Verification is observed in required CI,
the hosted private-DataHub/browser/DAST run, and the protected write/rollback run.

## Verdict

**Is there spaghetti?** In the active vertical slice, no: domain rules, use cases, adapters,
and delivery mechanisms have a defensible inward dependency direction. In the repository as
a whole, yes: the active GCP/Compose product still coexists with a much larger, non-deployed
AWS experiment and its workflows, dependencies, contracts, and documentation. That is
delivery and repository coupling, not entanglement in the core audit algorithm.

The safe decision is to keep the active path small and quarantine the reference estate only
after the live proof is green. A pre-deadline big-bang rewrite would violate KISS and increase
risk without improving what a judge can observe.

## Dependency rule

```text
domain values and invariants
  <- deterministic audit / governance / remediation use cases
  <- application ports (readiness, audit harvest, mutation/read-back)
  <- DataHub, HTTP, worker and CLI adapters
  <- Compose / Cloud Run / GitHub Actions delivery
```

A static import search found no AWS, OpenAI, or MCP SDK imports in `src/application`,
`src/audit`, `src/governance`, `src/remediation`, `src/pipeline`, or `src/types.ts`.
Cloud/provider dependencies remain in outer adapters.

## SOLID assessment

| Principle | Assessment | Evidence or action |
| --- | --- | --- |
| Single responsibility | Good in the core; weak in a few live adapters | audit, governance, planning, execution, receipt, rollback, and GitHub approval parsing are separate. `mcp-client-live.ts`, `worker/service.ts`, and `llm/client.ts` remain large outer adapters |
| Open/closed | Deliberately closed for mutation | one G6 action is a safety boundary, not a missing generic plugin system. New mutations require new policy, tests, and human review |
| Liskov substitution | Good | fake and live DataHub clients share contract tests; offline fixtures do not silently relax live safety limits |
| Interface segregation | Improved | readiness now depends only on `DatasetScopeLookup.search`, not the full DataHub client. Mutation and tag read-back already use separate ports |
| Dependency inversion | Good | deterministic use cases depend on typed ports and values; HTTP, MCP, cloud SDK, and credentials stay outside |

## KISS and YAGNI decisions

Kept:

- one dataset per public audit;
- one read-only public route;
- one allowed mutation and its exact inverse;
- two customer commands, not an installer framework or wizard;
- one active GCP deployment path;
- deterministic findings with an optional, one-way narrator boundary.

Rejected:

- public or anonymous mutation;
- generic policy/action engines;
- multi-tenant control planes;
- another agent framework;
- additional receipt schemas;
- deployment of the AWS reference experiment;
- local orchestration beyond Docker Compose.

## Remaining architecture debt

| ID | Debt | Impact | Disposition |
| --- | --- | --- | --- |
| AQ-1 | required CI still validates much of the frozen AWS estate | active changes pay slow, noisy checks unrelated to the supported product | quarantine after hosted audit/write proof; do not rewrite before live evidence |
| AQ-2 | root production dependencies include AWS and OpenAI adapters that the deterministic hosted path does not use | larger image and supply-chain surface | split optional model/worker adapters into a separate runtime package after deadline; lockfile and CI migration required |
| AQ-3 | `mcp-client-live.ts` combines transport, paging, mapping, registry resolution, topology and direct-history reads | harder review and more regression surface | extract by capability only when a changed behavior requires it; current contract tests are the safety net |
| AQ-4 | live adapters are excluded from c8 coverage | 97% headline overstates production-path coverage | narrow exclusions and add disposable DataHub 1.6 integration CI |
| AQ-5 | active GCP deployment and historical AWS docs coexist in README and workflow lists | new contributors can pick the wrong authority | `ACTIVE_ARCHITECTURE.md` is authoritative; add archive labels, then remove dead paths after judging |

## Quality gate

Required CI, the hosted live audit, and the protected write/read-back/rollback proof all
passed for the final judge application release, so the architecture supports the documented
**9/10 hackathon-readiness assessment**. It does not support a blanket **9/10 customer-
production claim** until AQ-1/AQ-2/AQ-4 plus the deployment-specific P1 items in
`WELL_ARCHITECTED_REVIEW.md` close. This distinction prevents submission polish from being
mistaken for production maturity.
