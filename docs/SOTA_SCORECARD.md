# SOTA judge and customer scorecard

Final evidence review: 2026-08-10. This scorecard counts only evidence that a judge can
reproduce from the public application, repository, or retained GitHub Actions runs. The
original submission tag remains frozen as historical provenance. The final judge application
release is `7cf2ab063312c2bf06fd2d65c798e802f7070a37`; later default-branch commits may update
monitoring or documentation without changing that deployed application. This release counts
because its exact CI, deploy, live-DataHub, browser and DAST receipts are green. Scores are
readiness assessments against the published criteria, not predictions of judge discretion.

## Executive score

| View | Final evidence-backed readiness | Decision |
| --- | ---: | --- |
| official six-criterion judge score | **9.37/10** | all application and submission gates pass on one exact SHA; the exact-release public video is published and embedded in Devpost |
| narrow-ICP customer score | **9.0/10** | trial-ready for the stated catalog-integrity job, not a general catalog administrator |
| active-slice architecture quality | **9.3/10** | clean authority and evidence boundaries; the single-zone demo host is the main residual risk |

The public origin is already useful without credentials: it reaches a private DataHub Core
1.6 instance through a bounded read-only Cloud Run API and returns one exact live audit. It
does not expose mutation credentials. The full write/rollback path is protected by two
reviewer-bound GitHub environments.

## Official equally weighted criteria

| Criterion | Final readiness assessment | Evidence |
| --- | ---: | --- |
| Use of DataHub | 9.7 | live DataHub graph audit; MCP + ACK + Skills + Analytics Agent; verified G6 write/read-back/rollback |
| Technical execution | 9.3 | exact-SHA CI, measured combined coverage ≥85%, hosted deploy, DAST, live e2e and governed receipts |
| Originality | 9.6 | ingestion-registry source identity recovers contradictions from retained aspect history |
| Real-world usefulness | 9.3 | contradiction, lineage blast radius and governance findings become one approval-ready action |
| Submission quality | 9.5 | exact-release public 161.48-second 1080p capture; completed Devpost entry with custom thumbnail, five captioned gallery images, proof strip and judge shortcuts |
| OSS bonus | 8.8 | focused, tested upstream PR #183 has addressed maintainer feedback; acceptance is outside entrant control |

Evidence-based readiness average: **9.37/10**. This is not a prediction of a judge's
discretionary score.

## Multi-persona review

| Persona | Target | Decisive question |
| --- | ---: | --- |
| General hackathon judge | 9.3 | Can I understand the business value, run the live audit, and verify every claim in under five minutes? |
| DataHub platform engineer | 9.4 | Is DataHub the context and action substrate, rather than a decorative integration? |
| Security/compliance lead | 9.3 | Is anonymous access read-only, is privileged action least-privilege and human-bound, and is evidence immutable? |
| Data-platform customer | 9.1 | Does this reduce catalog incident triage without introducing another autonomous administrator? |
| CDO/CIO | 9.2 | Can I immediately see the risk, affected assets, accountable decision and reversible outcome? |
| CFO | 9.0 | Is the judging deployment bounded and materially cheaper than Kubernetes? |
| Staff engineer | 9.2 | Are deterministic domain rules, ports/adapters, tests and delivery boundaries cohesive and maintainable? |

## Customer value boundary

The ideal customer already operates DataHub and needs an evidence-first integrity control.
Archon is deliberately not another metadata database: DataHub remains the system of context;
Archon reconciles conflicting evidence, computes impact, and prepares one governed repair.

| Dimension | Release target | Evidence |
| --- | ---: | --- |
| time to value | 9.2 | no-login live audit plus two-command customer quickstart |
| decision quality | 9.4 | deterministic contradictions, G1–G6 controls and bounded lineage blast radius |
| safety | 9.6 | no public write route; exact plan digest; human write approval; separate rollback approval |
| integration | 9.1 | JSON, Markdown and SARIF outputs; DataHub MCP/ACK/Skills/Analytics boundaries |
| operating cost | 9.0 | Firebase static hosting, Cloud Run scale-to-zero/max-one, one temporary GCE demo dependency |
| transparency | 9.3 | source badges, model provenance, unknown preservation, audit and remediation receipts |

## Completed release evidence

1. **Candidate:** all required CI contexts pass, including unit/integration/security/e2e
   suites, CodeQL, Gitleaks, SCA, SBOM, container/IaC scans and measured combined coverage.
2. **Hosted read:** deploy the exact candidate; `/readyz` reports `ready/live`; the public
   origin returns the expected contradiction, lineage gap, G2 and G6 findings.
3. **Governed action:** protected environment one binds one exact reviewer event to the
   plan digest; read-back proves the PII tag; protected environment two separately approves
   rollback; read-back proves exact restoration.
4. **Submission:** CI generated and sealed the 161.48-second 1080p video from that same release
   SHA; it is public and embedded in Devpost. The submitted entry has a custom thumbnail, five
   captioned gallery images, an explicit track/proof strip and direct judge shortcuts, all
   rechecked logged out.
5. **Judging window:** availability is monitored; the low-cost DataHub host remains available
   through judging and is stopped afterwards.

Application and submission gates 1–4 are complete. The hourly public-release monitor is active;
only ongoing availability and upstream maintainer review of PR #183 remain external operational
dependencies. A customer-production claim would additionally require deployment-specific SLOs,
restore testing, rate limiting and data-protection review; those are intentionally outside this
hackathon's narrow product scope.
