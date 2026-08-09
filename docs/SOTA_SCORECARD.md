# SOTA judge and customer scorecard

Review date: 2026-08-06. Scores distinguish what exists in an unverified local candidate
from what a judge or customer can observe. No local build or test result is counted.

## Executive score

| View | Externally observable now | Target after named gates | Decision |
| --- | ---: | ---: | --- |
| official six-criterion judge score | **7.9/10** | **9.1/10** | target is credible but not earned |
| narrow-ICP customer score | **7.6/10** | **9.0/10** | trial-ready after CI/live proof; production claim still needs P1 operations |
| architecture quality of active slice | **8.7/10 static** | **9.2/10** | core is clean; repository/delivery coupling remains |

The uncommitted candidate does not raise the observable score until it is reviewed by CI,
merged, deployed, and exercised. The public origin currently serves the fixture SPA and its
`/readyz` does not prove a backend.

## Official criteria

| Criterion | Now | Target | Evidence required for target |
| --- | ---: | ---: | --- |
| Use of DataHub | 7.5 | 9.5 | hosted real audit plus approved G6 add/read-back and separately approved rollback/read-back |
| Technical execution | 7.8 | 9.2 | required CI green; truthful readiness; live adapter contracts; exact release deployed and observed |
| Originality | 9.3 | 9.6 | ingestion-registry source identity and retained-history contradiction remain the headline |
| Real-world usefulness | 8.0 | 9.1 | Compose quickstart and doctor pass against a customer DataHub; limitations stay explicit |
| Submission quality | 8.6 | 9.4 | active architecture and reviews merged; later video shows the actual live audit/write proof |
| OSS bonus | 6.0 | 8.0 | PR #183 remains open, focused, tested, and visible; an upstream merge would score higher but is not controllable |

Target average: `(9.5 + 9.2 + 9.6 + 9.1 + 9.4 + 8.0) / 6 = 9.13`.

## Named judge personas

| Judge | Target | What must withstand scrutiny |
| --- | ---: | --- |
| Maggie Hays | 9.3 | the sticky `pipelineName` claim, ingestion-registry resolution, and upstream PR must be reproducible and precisely worded |
| Alyssa Lee | 9.2 | one credible story: DataHub is the context graph, Archon audits it, and one safe repair improves inherited context |
| Nick Adams | 9.2 | real DataHub 1.6 behavior, MCP boundaries, exact query, retained history, and no fixture/live ambiguity |
| Tim Bossenmaier | 8.9 | HTTPS/token quickstart, deployment roles, runbook, cost, limits, and explicit production gaps |
| Aman Gairola | 8.8 | bounds, failure modes, live integration coverage, scale evidence, monitoring, and recovery from the single demo host |
| Wenjia You | 9.4 | deterministic authority, model-only narration, tool isolation, two human approvals, EU AI Act transparency, and rollback |
| Mike Burke | 9.2 | clean dependency direction, focused contracts, green CI, small change sets, and no claims beyond evidence |

Panel target average: **9.14**. Tim and Aman remain the hardest personas until the P1
reliability/performance controls in `WELL_ARCHITECTED_REVIEW.md` close.

## Customer score

The customer is a data-platform lead who already operates DataHub and wants a narrow catalog
integrity control, not a generic autonomous catalog administrator.

| Dimension | Now | Target | Target condition |
| --- | ---: | ---: | --- |
| problem value | 9.4 | 9.4 | unchanged |
| time to first value | 5.0 | 9.0 | two documented Docker commands succeed with no local Node, Python, or `uv` |
| reliability | 7.0 | 9.0 | required CI, disposable DataHub integration, live readiness/audit, monitoring and recovery evidence |
| safety and governance | 9.3 | 9.6 | distinct runtime/proof identities plus executed, reviewer-bound write and rollback approvals |
| workflow integration | 8.5 | 9.0 | stable JSON/Markdown/SARIF and evidence-linked findings |
| operating cost | 7.2 | 9.0 | bounded Cloud Run, measured sizing, budget alert, and demo VM teardown |
| documentation and compliance | 6.5 | 9.3 | active architecture, quickstart, six-pillar and EU control reviews remain aligned with deployment |
| product focus | 8.0 | 8.8 | one safe mutation is intentional; do not add a second action merely to inflate breadth |

The target average is **9.14**. It is a 9/10 for the narrow stated job only. A general-purpose
multi-entity remediation platform is out of scope and should not inherit this score.

## Gates that convert potential into evidence

1. **CI:** all required contexts pass on the exact candidate, including Compose schema,
   typecheck, full tests, coverage, security, and readiness.
2. **Identity:** owner creates distinct Cloud Run runtime and governed-proof service accounts;
   runtime gets only its optional read secret, proof gets only VM-describe/IAP access, and
   the Google action families remain narrowly allowlisted.
3. **Hosted read:** deploy exact SHA; `/readyz` is `ready/live`; one audit returns the expected
   contradiction, lineage gap, and G6 evidence through the Firebase origin.
4. **Governed work:** IAP access is granted to the proof identity; protected environment one
   supplies the exact content-bound reviewer comment, read-back proves the write, protected
   environment two supplies a separate reviewer-bound rollback approval, and read-back proves
   exact restoration.
5. **Customer operations:** disposable DataHub 1.6 integration, live latency baseline,
   GCP availability alert, candidate promotion/rollback, and fixture restore are exercised.
6. **Submission:** only after gates 1–4, update the video and Devpost to show the observed
   release, PR #183, and the real write/rollback proof.

No score above nine is claimed before gates 1–4. No customer-production score above nine is
claimed before gate 5.
