# Judge State — Archon-DataHub (2026-07-13)

_A fresh, adversarial judgment review of this repo against the **Build with DataHub: The
Agent Hackathon** criteria (Devpost, ~$20.5k, deadline **Aug 10 2026**, Greece-eligible).
Written so any agent/human opening this repo sees the current judged state, the discrepancy
register, and exactly what is needed to push above 95/100._

Reviewed at `origin/master` = `81f7bdd` (Phase 1 PR #1 + Phase 2 PR #3 both merged). CI
green on master (run 29202335620). `npm test` = **62/62 pass**; `npm run coverage` clears
the c8 ≥80% gate on all four axes.

---

## TL;DR verdict

**Strong, honestly-built entry — but NOT a >95 contender in its current state.** The
engineering is genuinely good (clean-room, file-by-file disclosure, real dual-face MCP, real
multi-agent + ReAct loop, deterministic findings, green CI, >80% coverage). What caps it
below 95 is not code quality — it is that the two things a DataHub-hackathon judge weights
hardest are **unproven**:

1. **It has never run against a live DataHub.** Everything demonstrated is Fakes/fixtures.
   The live adapter is "code that should work when connected," which is materially weaker on
   *DataHub-usage-depth* than a recorded live run.
2. **The flagship differentiator cannot fire on the live read surface.** The README headlines
   a "self-auditing contradiction engine" as THE differentiator, yet by the project's own
   honest disclosure, cross-source contradiction detection *"cannot fire from the MCP read
   tools alone"* — it only fires on baked-in offline fixtures constructed to contain a
   contradiction.

Honest disclosure of these limits is a **credit** (judges punish overclaiming) — but a
disclosed limitation is still a limitation, and the functional ceiling is real. Estimated
current aggregate: **~85/100**. Good placing; not a winner-tier score until the live proof
and the live-firing differentiator land (see Path-to-95).

---

## Per-criterion scorecard

Axes taken from the project's own criteria mapping (`docs/DESIGN.md` §3), which tracks the
Devpost agent-hackathon axes.

| Criterion | Score | Basis (what earns it / what caps it) |
|---|---:|---|
| **Technical Implementation** | **90/100** | Clean TypeScript, injectable seams throughout, pure deterministic engines, 62 tests, c8 ≥80% on all axes, gitleaks-first CI, dep-audit. Caps: coverage gate set at the floor (80%, not stretch); transport shell (`mcp-client-live.ts`) is out of coverage by design; a few branch gaps in `client.ts`/`server.ts`. |
| **Innovation / Originality** | **88/100** | Genuinely novel framing: a *self-auditing* catalog agent (interrogates metadata for internal disagreement) vs. the usual retriever; **dual-face MCP** (consumes the official DataHub MCP server AND re-exposes its own audit as MCP tools). Caps: the flagship contradiction engine is offline-only on the live surface. |
| **Real-World Usefulness** | **78/100** | Governance (G1–G6) + schema-completeness + lineage-reachability audits are real, useful, and **do** survive a live read. Read-only + human-gate design is production-safe. Caps: headline differentiator can't fire live; never demonstrated on a real catalog, so usefulness is asserted, not shown. |
| **Use of DataHub (depth)** | **80/100** | Consumes the *official* `acryldata/mcp-server-datahub` read tools (`search`/`get_entities`/`get_lineage`), pinned mappers from source, both stdio + Streamable-HTTP transports, strict read-only (never enables mutation tools). Caps: **never actually connected to a live DataHub**; mappers pinned from *interpretation* of source, not captured payloads (see D-3). |
| **Presentation / Submission Quality** | **unverifiable (docs ~90)** | README/DESIGN/NOTICE/DATAHUB_RESEARCH are excellent — clear architecture diagram, honest scope notes, thorough disclosure. **No demo video, blog, or Devpost write-up exists in the repo**, so the actual submission-package presentation cannot be scored from here. Do not score on faith. |
| **Bonus — OSS contribution** | **partial** | `contrib/datahub-audit/` Skill is staged in the official `datahub-project/datahub-skills` format and fills the real `/datahub-audit` gap the registry's `datahub-search` skill references. Not yet PR'd upstream — bonus credit only lands when the upstream PR is opened/accepted. |

**Composite (current state): ~85/100.** Not >95.

---

## Discrepancy register (code ↔ docs ↔ claims)

| # | Severity | Discrepancy | Evidence | Resolution |
|---|---|---|---|---|
| **D-1** | **High** | **Differentiator claim vs. live-surface limit.** README §top calls the self-auditing contradiction engine "**The differentiator**"; but README "What survives the live MCP read surface" + DESIGN §6 state cross-source contradiction "**cannot fire from the MCP read tools alone**." A probing judge hits this tension first. | `README.md` L26–32 vs L152–159; `DESIGN.md` L108–111 | *Already honestly disclosed* — this is the central tension, not a hidden defect. To neutralize it as a scoring risk, make it fire live (Path-to-95 #1). Until then, keep the headline hedged (it currently is, post-`ab84c97`). |
| **D-2** | **High** | **Never run against a live DataHub.** README/DESIGN present the live path as "works the moment it connects"; no run has occurred. All 62 tests + both demo scripts use Fakes/fixtures. | `mcp-client-live.ts` transport excluded from coverage; DESIGN §6 Phase-2 "Remaining (user-only)". | USER: stand up DataHub on a cloud VM, run `audit:demo` live, capture screenshots + a recorded finding. CODE lever: replay-cassette integration test (Path-to-95 #2). |
| **D-3** | **Medium** | **"Pinned from source" ≠ pinned from captured payloads.** The live-mapper tests assert against **hand-authored** fixtures "**modelled on** acryldata/mcp-server-datahub's own tests + graphql_helpers cleaning," not real captured MCP responses. So "pinned from source" means "pinned to our *reading* of the source, tested against our own reading." | `tests/unit/live-mappers.test.ts` L1–10 ("Fixtures below are … modelled on …"); transcript history ("Corrected every earlier guess — search uses the `entity_type = dataset` filter DSL …"). | Replace ≥1 fixture with a **real captured** cleaned MCP response from a live/docker DataHub; keep the rest. Removes the interpretation risk and doubles as the D-2 live proof. |
| **D-4** | **Low** | **Presentation artifacts absent from repo.** Task treats video/blog as "done"; repo contains none to triangulate against, so accuracy/harmonization can't be checked here. | `find` for `*blog*/*video*/*demo*/*submission*` → only `scripts/demo-audit.ts`. | If artifacts exist outside the repo, verify they hedge the differentiator exactly as the README does (don't let a video overclaim "detects contradictions in your live catalog"). Ideally commit the write-up into `docs/`. |
| **D-5** | **Low** | **MCP server `version` drift.** `mcp-client-live.ts` advertises client `version: "0.2.0"`; `mcp/server.ts` advertises server `version: "0.1.0"`; `package.json` version is separate. Cosmetic, but a sharp judge notices. | `mcp-client-live.ts` L69 vs `mcp/server.ts` L119. | Unify to a single source-of-truth version. |

No **secret leaks**, no **overclaim of a live run as done**, no **fabricated metrics**, and no
third-party/proprietary code found. Disclosure (`NOTICE.md`) is exemplary and matches the
code (ported vs. new is accurate per file).

---

## Path to >95/100 (ranked by judge impact)

### 1. [CODE] Make the differentiator fire on a live catalog — **highest leverage**
Implement Phase-3 contradiction recovery from **aspect version history** — `systemMetadata` /
the GMS **OpenAPI v3 aspect endpoints** — or a **cross-scan diff** of stored harvests. This
closes the exact hole (D-1) that undermines the headline: today the flagship only fires on
fixtures; this makes "self-auditing contradiction detection" true against a real DataHub.
Buildable by an agent (new read path + harvest-diff over the existing pure `auditConsistency`
engine; the engine itself is already correct and covered). **This single lever moves
Real-World + DataHub-depth + Originality simultaneously.**

### 2. [USER + small CODE] A recorded live run against DataHub
- **CODE:** add an integration test that replays **real captured** cleaned MCP responses
  (fixes D-3), plus a `docker-compose`/runbook the demo can execute.
- **USER-only:** stand up `datahub docker quickstart` on a cloud VM, ingest sample data, point
  the agent at it, run `npm run audit:demo`, capture screenshots + a recorded finding for the
  submission. Converts D-2 from "should work" to "did work."

### 3. [CODE] Depth features that read as production-grade
Column-level lineage gaps (`get_lineage_paths_between`); multi-hop schema-break blast-radius;
a small findings-history store (pgvector) so audits **diff across runs** (which is also the
substrate for #1's cross-scan contradiction path); a lightweight web view of findings + the
ReAct trace. Lower credibility-impact than #1/#2 — polish, not proof.

### 4. [USER] Land the OSS bonus + submission package
Open the upstream PR for `contrib/datahub-audit/` into `datahub-project/datahub-skills`
(bonus credit only lands on submission). Record the demo video and write-up; ensure both hedge
the differentiator exactly as the README does (no "detects contradictions in your live
catalog" overclaim).

### 5. [CODE] Cosmetic hardening
Unify MCP version strings (D-5); consider lifting the coverage gate above the 80% floor to
signal rigor.

---

## Honest bottom line

- **Is it a >95 contender today?** No. It is a well-built, honest, good-placing entry
  (~85/100) whose two highest-weighted axes rest on unproven/offline-only capability.
- **What flips it to >95?** Primarily **Path-to-95 #1 + #2**: make the flagship contradiction
  engine fire against a *live* DataHub, and show a *recorded live run*. Those two convert the
  entry from "excellent code that should work" to "excellent code demonstrably working on the
  hackathon's own platform" — which is where winner-tier scores live. #1 is fully
  agent-buildable; #2 needs the user for the live VM + capture.
- **Biggest credibility trap to fix first:** D-1/D-3 — do not let the submission narrative
  (video/blog) claim live cross-source contradiction detection until #1 ships. The current
  README hedging is correct; keep every artifact harmonized to it.
