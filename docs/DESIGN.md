# Archon for DataHub — design

## 1. Thesis

A catalog combines claims about one asset from ingestion connectors, dbt, source systems,
and human stewards. The current view is necessarily a resolution of those writes, so it can
hide the disagreement that produced it. Lineage and governance can also drift independently
from the underlying data estate.

Archon treats DataHub as a system that can be audited:

1. harvest the current metadata graph through the official DataHub MCP read tools;
2. recover bounded retained aspect history directly from GMS;
3. distinguish stable source identity from individual execution identity;
4. detect contradictions, lineage gaps, and deterministic G1–G6 violations;
5. calculate downstream blast radius;
6. produce evidence-bound findings and exports;
7. for G6 only, construct one exact, human-approved classification-tag action; and
8. verify the postcondition and issue a tamper-evident receipt.

The deterministic engine decides; the optional LLM only narrates already-computed results.

## 2. Logical components

```text
DataHub MCP read surface ─┐
                          ├─► DataHubClient ─► four-agent audit pipeline
GMS version history ──────┘                         │
                                                   ├─► findings / blast radius
Archon MCP + synchronous read-only HTTP preview ◄──┤
                                                   └─► G6 planner
                                                          │
                                              dossier + exact plan
                                                          │
                                              authenticated approval
                                                          │
                                                isolated write worker
                                                          │
                                             official add_tags/remove_tags
                                                          │
                                              verify + receipt + rollback
```

The public Archon MCP server and HTTP audit API expose no mutation dispatch. Browser
requests reach the HTTP API only through CloudFront: a generated KMS-encrypted origin
key is overwritten at the edge, required by every API Gateway method, redacted in both
WAFs, replaced before the HTTP backend, and omitted entirely from narrow Lambda custom-
integration events. The write adapter is imported lazily by a separate, private worker
with separate credentials.

The hosted SPA does not hold an HTTP connection open for that pipeline. It must post a
narrow, non-wildcard query to `/api/control-loops`, receives a random 256-bit `auditId`, and polls its
same-origin capability URL. A dedicated no-secret Lambda may start only the Archon Standard
workflow, describe only its executions, and read the checkpoint/approval/evidence stores.
It reads only the `v1/audit/` and `v1/execution/` object prefixes. Before projecting a
governed terminal result it strictly extracts the expected remediation contract, verifies
the content-addressed execution document, approval/plan/audit bindings, receipt digest,
hash-chained events, postcondition checks, and rollback anchor. Its result contains only
outcome, receipt/evidence digests, completion time, and check summaries; it never returns
an execution ARN, raw workflow input/output, callback token, mutation response, identity,
or provider error.
`/api/audits` remains a synchronous, explicitly read-only diagnostic preview. Its fixed
profile admits exactly one dataset, bounds each provider call, runs four aspect readers
concurrently, and returns or fails within a 25-second pipeline deadline. The durable worker
profile admits at most 25 datasets and 12 retained versions per mutable aspect, uses
eight-way bounded lineage/history concurrency, and leaves 30 minutes of its two-hour
callback window unused.

## 3. Audit pipeline

| Agent | Deterministic responsibility | Main modules |
| --- | --- | --- |
| Classifier | Catalog/platform/domain/lineage/sensitivity summary | `src/agents/classifier.ts` |
| Lineage Analyzer | Contradictions, drift, gaps, temporal provenance | `src/agents/lineage-analyzer.ts`, `src/audit/consistency.ts` |
| Governance Auditor | G1–G6 policy checks | `src/agents/governance-auditor.ts`, `src/governance/validator.ts` |
| Narrator | Grounded language over computed findings | `src/agents/narrator.ts`, `src/llm/` |

The bounded ReAct loop can call only the read-side audit tools. Its terminal action emits
findings; it is not the write path.

### G1–G6

| Rule | Check |
| --- | --- |
| G1 | every dataset has an owner |
| G2 | every dataset belongs to a domain |
| G3 | every dataset has a non-empty description |
| G4 | a deprecated dataset has no active downstream |
| G5 | every schema field has a resolved type |
| G6 | every sensitive field has a classification |

Only G6 can enter the governed remediation planner. G1–G5 and every contradiction remain
manual-only because their correct resolution requires organizational judgement or a broader
action surface.

## 4. Temporal provenance

DataHub aspect version `0` is the current value; retained displaced values are read from
versions `1..N`. The reader always requests v0 and then walks history within explicit
bounds.

The critical semantic distinction is:

- `runId` identifies one ingestion execution;
- `pipelineName` identifies the stable source pipeline.

Different `runId` values from one pipeline are drift, not a cross-source contradiction.
A contradiction requires different stable pipeline identities or a trusted mapping from
executions to different ingestion sources. Unknown identity is `unknown-source` and fails
closed.

Auth, server, network, malformed-response, and history-bound failures are errors. Only the
expected not-found response for the next version ends enumeration normally.

Each audit consumes one fresh bundle. Snapshot and fact projections are derived from the
same live report list, and history uses the same complete search URN set; there is no
cross-run metadata cache. Search declares its total up front and fails if it exceeds the
profile ceiling or changes while paging. `get_entities` must return every requested URN
exactly once, without errors, malformed entries, duplicates, or extras. MCP `isError` is
terminal, and lineage requires an offset-zero envelope whose count, total, result list,
degrees, and unique URNs agree. Hosted live audits also require the direct GMS
version-history capability; MCP-only connectivity may serve standalone reads but cannot
produce an audit or governed plan. Consequently no
partial harvest can reach the G6 planner as `ACTIONABLE`.
The version-history recovery is therefore a separate bounded GMS read capability, not an
inferred feature of the MCP latest-state surface.

## 5. Governed G6 control loop

The versioned policy at `policies/archon-remediation.v1.json` controls dataset prefixes and
the one permitted classification tag. Planning binds:

- structured G6 evidence;
- exact entity and column target;
- current tag projection;
- temporal provenance and blast radius;
- policy digest;
- action-catalog digest;
- exact forward and inverse tool arguments; and
- expected before and after projections.

The approval request is content-addressed, expiring, nonce-bearing, and requires an
authenticated `DataSteward`. The browser submits only:

```json
{"decision":"APPROVE","comment":"optional"}
```

The browser uses Cognito's classic Hosted UI with authorization code + PKCE S256. The
public client has no secret or implicit/client-credentials grant; its access token must
contain `archon/approve`. API Gateway validates that scope and the request schema before
the Lambda verifies the approver group and updates DynamoDB conditionally. The Lambda has
no DataHub/LLM secret and cannot invent a mutation.

The approval request's deadline is an immutable `approvalExpiresAt` attribute, distinct
from the table's `expiresAt` TTL. Pending rows expire at the deadline; once decided, the
same conditional write extends only the TTL to 90 days after `decidedAt`. This keeps the
durable decision available for terminal evidence verification without reopening approval.

The browser keeps polling while the Standard workflow is paused at
`AWAITING_APPROVAL`. After the authenticated decision callback, the same status capability
continues through remediation and exposes terminal `VERIFIED` or `REJECTED` only after the
state machine reaches its corresponding terminal state and the status Lambda independently
verifies the execution evidence and receipt chain.

Before execution, the worker must:

1. verify every artifact digest and binding;
2. claim the approval once with an idempotency key;
3. re-read and match the approved pre-state;
4. invoke only the typed `add_tags` action;
5. re-read and verify exact postconditions; and
6. seal the receipt event chain.

Rollback is represented by the exact inverse action but requires a new approval against a
fresh current-state digest.

The domain control loop and hosted consumers are implemented. The audit worker strictly
parses `AUDIT_REQUESTED`, the secretless handoff Lambda strictly parses
`APPROVAL_REQUESTED`, and the remediation worker strictly parses
`REMEDIATION_REQUESTED`. They write canonical content-addressed evidence to the Object-Lock
bucket, persist the opaque approval task token before acknowledging its SQS message, and
dispatch a mutation only after the authenticated approval callback is rebound to the
immutable dossier and plan. Rejection traverses the same evidence path without acquiring a
mutation. The Step Functions workflow has a separate remediation callback and reaches a
successful terminal state only for a `VERIFIED` or durable `REJECTED` receipt. The React
application then renders the two content digests, completion time, exact check count,
receipt-event count, and rollback availability from that sanitized projection.

`WorkerDesiredCount` remains zero by default. It may become one only for a CI-proven image
containing both isolated worker entrypoints. The audit task receives read/LLM credentials;
the remediation task receives only the write credential; a secretless SQS Lambda persists
approval handoffs. Separate queues, DLQs, roles, and append-only evidence permissions are
hard deployment boundaries. The source is not evidence of a running deployment.

## 6. Hosted reference architecture

The AWS CDK app separates a retained shared registry, an environment-specific global edge
stack, and an environment-specific regional platform stack:

- `Archon-Registry`: immutable KMS ECR repository;
- `Archon-<stage>-Edge` in `us-east-1`: DNS-validated ACM certificate,
  CloudFront-scope WAF, and KMS-encrypted retained WAF logs;
- `Archon-<stage>` in the selected platform region: private versioned KMS S3 SPA with
  CloudFront OAC, Route 53 A/AAAA aliases, the certificate/WAF handoff from the edge stack,
  access logging, and `TLSv1.3_2025`;
- same-origin API Gateway with its own regional WAF, strict request models, throttling,
  access logs, active X-Ray, a CloudFront-only origin gate whose credential never reaches
  a backend, and an encrypted two-second cache limited to the capability-scoped status
  GET;
- private Fargate services with public IP assignment disabled through an internal
  NLB/VPC Link;
- Cognito Hosted UI, public PKCE code client, scoped approval boundary, and Node.js 24
  Lambda with locked AWS SDK clients;
- KMS SQS/DLQs, DynamoDB PITR/deletion protection, Standard Step Functions;
- separate read/write/model secrets;
- Object-Lock evidence storage, S3 versioning, CloudFront access logs, and S3
  server-access logs for the SPA/evidence buckets;
- default-deny security groups, controlled PrivateLink/gateway endpoints, rejected-traffic
  VPC flow logs, alarms, dashboard, and retained encrypted logs;
- active X-Ray on API Gateway, Step Functions, application Lambdas, and the CDK
  default-security-group restriction provider.

The hardened container has no `uvx` runtime. Hosted deployments therefore require an HTTPS
GMS URL for aspect history and exact field-tag projections, a hosted Streamable HTTP
DataHub MCP URL for official read tools, and a different hosted mutation-enabled MCP URL
plus distinct token for the isolated worker. No read-to-write credential fallback exists.

CloudFront never rewrites API authorization/errors into SPA success responses. Security
headers apply to static and API behaviors. `/runtime-config.json` is generated only after
the stack exists, contains public OAuth coordinates, is served by a caching-disabled
behavior with `no-store`, and is smoke-verified byte for byte.

The distribution has no default-certificate fallback: AWS fixes the generated
`*.cloudfront.net` certificate to the legacy `TLSv1` policy. Each environment therefore
provides its exact hostname and owning Route 53 public hosted-zone ID. The edge stack
requests the viewer certificate in `us-east-1`, completes DNS validation in that zone,
creates the CloudFront-scope WAF, and exports both ARNs. The deployment workflow validates
and hands those outputs to the regional platform stack; no operator-provisioned
certificate ARN is required. The account must be CDK-bootstrapped in both `us-east-1` and
the selected workload region. CDK then creates both IPv4 and IPv6 aliases. Every cache
behavior also runs the same viewer-request function, which returns `421` for a
non-canonical Host before CloudFront can expose an origin response through its generated
distribution hostname. The CloudFront WAF protects every cache behavior, while the
separate regional WAF remains bound to API Gateway for direct callers.

Network egress is capability-specific. Public subnets disable automatic public-IP
assignment and all three Fargate services explicitly disable public IPs. Workload security
groups begin with IPv4/IPv6 outbound disabled. The API target accepts TCP 8080 only by
security-group reference from the internal NLB; inbound evaluation is bypassed only for
the API Gateway PrivateLink path. The API and audit worker receive only the
customer-managed DataHub-read and LLM prefix lists; the remediation worker receives only
the customer-managed DataHub-write prefix list. PrivateLink, S3, and worker-only DynamoDB
paths use dedicated TCP 443 rules. The deployment pipeline validates the three
account-owned external lists and independently resolves the AWS-owned regional
`com.amazonaws.<region>.s3` and `com.amazonaws.<region>.dynamodb` lists, so cloud-service
identity is never confused with an operator-maintained endpoint allowlist. Prefix-list
`MaxEntries` weights are included in a fail-closed 60-rule security-group quota check
before either environment is deployed.

The SPA, evidence, and CloudFront log buckets are versioned and retained. SPA and evidence
requests are server-access-logged to the log bucket, while CloudFront delivery uses a
separate prefix and lifecycle. The status endpoint's cache key is the opaque `auditId`;
the API cache is encrypted and its two-second TTL bounds both replay and staleness.

## 7. Build-once promotion

CI creates:

- a tested, non-root container archive plus an inner SHA-256 manifest;
- a deterministic SPA tarball (`sorted paths`, epoch mtimes, numeric owner, gzip without
  filename/timestamp) plus its inner SHA-256;
- a deterministic, dependency-locked approval/control Lambda archive plus its inner
  SHA-256; and
- reviewed synthesized CloudFormation and policy/scanner evidence.

The deploy workflow accepts a successful default-branch CI run ID and its exact full source
SHA. It verifies GitHub's artifact-envelope digest and each inner artifact digest. For each
stage it deploys the edge stack first, validates the certificate/WAF outputs, and deploys
the regional platform with those outputs and the five resolved prefix-list IDs. Staging
receives the exact image, SPA, and Lambda code; production receives the same ECR digest,
SPA archive, and Lambda archive after a protected-environment approval. Selecting an older
retained CI run is rollback. Application artifacts are never rebuilt during deployment.
The IaC control plane is not rolled back with those application bytes: deployment checks
out the current default-branch workflow commit only after successful CI, CodeQL, and
workflow-security push runs for that exact commit. This separates safe application
rollback from forward-only reconciliation of current infrastructure security controls.

Environment-specific URLs and Secrets Manager values are configuration, not application
build inputs. The immutable SPA remains identical between stages; each deployment creates
and records a separate digest for its exact public auth runtime configuration.

## 8. Pipeline-only security

Security evidence is accepted only when generated by reproducible CI/CD:

- checksum-pinned Gitleaks;
- CodeQL SAST;
- root/web/infra/Lambda SCA and PR dependency review;
- application AuthZ, injection, data-exposure, and remediation-boundary tests;
- unit-tested project-owned CloudFormation Guard controls;
- Trivy IaC SARIF with an all-severity, zero-finding gate;
- non-root/read-only container boot contract;
- exact CI container/SPA/Lambda subject rescans with no rebuild divergence;
- Syft SBOMs and a Grype CVE gate that fails without current (≤24h), hash-validated
  vulnerability intelligence, sealing its retrieval time, exact DB manifest, status,
  policy, provenance, and v4 attestations;
- a daily latest-successful-master rescan plus an exact CI-run/SHA manual rescan path,
  with staging and production rejecting attestations older than 24 hours;
- actionlint and zizmor checks on the workflow definitions themselves;
- digest-pinned OWASP ZAP staging DAST with a Medium/High hard gate and retained reports;
- AWS OIDC, account allow-list, ECR scanning, same-digest promotion, byte-exact no-store
  auth runtime configuration, and hosted negative security/smoke checks.

No local scan is accepted as release evidence.

## 9. Judging-criteria mapping

| Criterion | Design evidence |
| --- | --- |
| Use of DataHub | Official MCP read/write adapters, direct retained-history read, aspects, lineage, tags |
| Technical execution | Deterministic engine, strict boundaries, tests, UI/API, locked IaC, pipeline security, immutable promotion |
| Originality | Auditing the catalog's own temporal contradictions and governing a minimal corrective loop |
| Real-world usefulness | Provenance, blast radius, least privilege, human approval, verification, receipts, rollback |
| Submission quality | Judge-facing app, exporters, clear setup, transparent readiness and prior-work disclosure |
| OSS bonus | Candidate DataHub Skill under `contrib/datahub-audit/`; bonus requires a real upstream contribution |

## 10. Current proof state

Source implementation is not synonymous with remote proof. The remaining authoritative
gates are tracked in [READINESS.md](READINESS.md):

- accept the current commit through remote CI/CodeQL/supply-chain workflows;
- configure GitHub environments and `master` protection;
- configure AWS OIDC/account/secrets and retain deployment smoke evidence;
- capture a real retained-history contradiction;
- configure and run the source-complete
  [`governed-canary`](../.github/workflows/governed-canary.yml) proof for one isolated G6
  write, a pre-approval sealed plan/recovery binding, PKCE approval, verified receipt,
  separately approved rollback, and exact read-after-rollback;
- contribute the OSS candidate upstream if it is accepted; and
- only then finish sample outputs, screenshots, video, text, and Devpost submission.

Full disclosure of ported versus new work is in [NOTICE.md](../NOTICE.md).
