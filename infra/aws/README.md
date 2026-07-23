# Archon AWS reference deployment

This CDK app implements a secure hosted-demo baseline without coupling release
artifacts to an environment:

- a private, versioned S3 SPA behind CloudFront Origin Access Control;
- same-origin `/api/*` routing to a regional, WAF-protected API Gateway;
- a public, bounded durable audit start/status API plus an explicitly read-only synchronous
  preview route and a scope-protected approval route;
- a Cognito Plus classic Hosted UI with enforced standard threat protection and a
  public authorization-code client for browser PKCE S256;
- a dedicated approval Lambda with strict schemas, approver-group authorization,
  DynamoDB conditional writes, and a server-held callback token;
- a separate no-secret control Lambda that starts only the Archon state machine and
  returns digest-verified, capability-scoped status projections;
- private Fargate API and worker services behind an internal NLB/VPC Link;
- Standard Step Functions, KMS-encrypted SQS/DLQs, and callback task tokens;
- separate KMS-encrypted DataHub read/write secrets;
- DynamoDB approval and idempotency/CAS stores with PITR and deletion protection;
- an Object-Lock, versioned, KMS evidence bucket;
- VPC endpoints, flow logs, retained application logs, X-Ray-enabled API/workflow,
  alarms, an SNS alarm topic, and an operations dashboard.

The Fargate API task is never granted the DataHub write secret. `POST /api/audits`
is intentionally public, synchronous, and read-only; it is a bounded diagnostic
preview rather than the SPA's production orchestration path. The judge-facing SPA
uses:

```text
POST /api/control-loops
GET  /api/control-loops/{auditId}
```

The hosted start body requires a narrow `query` and accepts only an optional `mode` beside
it. Live execution fails closed when that query matches more than 25 datasets; it never
audits a convenient prefix. The returned 256-bit
`auditId` is an unguessable polling capability. The status Lambda derives the
execution ARN server-side, verifies the DynamoDB checkpoint and content-addressed
Object-Lock evidence, and projects only the report, approval summary, and bounded
lifecycle/result. On governed `SUCCEEDED`, it parses only the exact
`remediationResult`, fetches its digest-addressed `v1/execution/` object, and verifies
the execution/audit/approval/plan bindings, receipt digest, event chain, the five exact
postcondition checks for `VERIFIED` (or their required absence for `REJECTED`), and the
rollback anchor. The browser receives only outcome, receipt and execution-evidence
digests, completion time, and a check/event/rollback summary.
The Lambda's S3 read policy is limited to `v1/audit/*` and `v1/execution/*`; it never
returns workflow input/output, task tokens, mutation responses, provider errors,
identities, or secrets. WAF, schema validation, and throttling protect both public
routes. Deploy them only against a sanitized demo DataHub tenant.
An explicit `mode: "READ_ONLY"` is reserved for safe hosted verification: the
worker still seals the report evidence but cannot create a remediation plan.
The staging pipeline exercises that mode to `READ_ONLY_COMPLETE` and retains the
sanitized terminal response hash.

The browser approval endpoint is:

```text
POST /api/approvals/{approvalId}/decisions
Content-Type: application/json

{"decision":"APPROVE","comment":"optional human comment"}
```

The SPA loads `/runtime-config.json` before it enables sign-in. That
environment-bound document contains only the public client ID, exact Cognito
authorization/token/logout endpoints, the CloudFront-root redirect/logout URI,
and `openid email archon/approve` scopes. It is created after the stack deploy,
is never baked into the build-once SPA archive, and is served by an explicit
CloudFront caching-disabled behavior with `Cache-Control:
no-cache,no-store,must-revalidate`. Access tokens remain in browser memory.

The request schema and Lambda both reject every field except `decision` and
`comment`. The Lambda reads `sub`, email, and `cognito:groups` directly from the
verified API Gateway authorizer context and requires membership in
`archon-approvers`. API Gateway additionally requires the `archon/approve`
access-token scope. A browser never sends action names, tool names, entity URNs,
mutation arguments, digests, or callback tokens. The Lambda resolves the
already-digested plan by `approvalId`, performs a conditional DynamoDB update,
and uses its server-held Step Functions token. It has no access to any DataHub
or LLM secret. The handoff persists the immutable approval deadline as
`approvalExpiresAt` separately from the DynamoDB `expiresAt` TTL. On `DECIDED`, the
TTL moves to 90 days after the decision without changing that deadline, preserving
the decision evidence needed by later terminal status verification.

The control Lambda starts `ArchonStateMachineArn` with this exact execution input
(unknown fields fail closed in the worker):

```json
{
  "schemaVersion": "archon.audit-request/v1",
  "requestId": "demo-request-0001",
  "requestedAt": "2026-07-23T10:00:00.000Z",
  "query": "optional bounded DataHub search"
}
```

Step Functions sends three strict callback envelopes. The audit worker persists a
content-addressed report and, for one actionable G6 field, a dossier, plan, and expiring
approval request. The approval consumer stores the opaque callback token in DynamoDB and
deletes its SQS message only after that handoff is durable. The approval Lambda releases
the human decision; an `APPROVE` decision creates a separate remediation task. Only a
worker result with outcome `VERIFIED` reaches `GovernedWriteComplete`; rejection has its
own terminal state and every stale, indeterminate, or unverified write fails the workflow.

## Stacks and release contract

`Archon-Registry` is shared and contains the immutable ECR repository.
`Archon-<stage>` is the environment stack. `stage` is supplied as CDK context,
for example `-c stage=staging`.

The environment stack has three mandatory promotion parameters:

| Parameter | Contract |
| --- | --- |
| `ImageDigest` | Exact `sha256:...` returned by ECR after one CI build |
| `SpaArtifactSha256` | SHA-256 of the one CI-produced SPA archive |
| `ReleaseSha` | Source commit represented by the container, SPA, and Lambda release candidates |

It also requires `DataHubReadGmsUrl`, hosted `DataHubReadMcpUrl`,
`DataHubWriteGmsUrl`, and hosted `DataHubWriteMcpUrl`. The Fargate image intentionally
contains no `uvx`, so separate read-only and mutation-enabled Streamable HTTP MCP endpoints
are mandatory. `LlmBaseUrl`, `LlmModel`, and `WorkerDesiredCount` are configurable.
`WorkerDesiredCount` accepts zero or one and defaults to zero. The exact image contains
`dist/audit-worker.js` and `dist/remediation-worker.js`, which CI checks without starting
either process. Set the parameter to one only after all live endpoint values and distinct
tokens are installed. The isolated services autoscale from their own queues.

The deployment pipeline must build once and promote the same image digest, SPA archive,
and Lambda archive. It must not rebuild application code for staging or production.

## CI deployment sequence

Run all commands in a clean CI workspace. No generated `cdk.out`, coverage, or
dependency directories should be committed.

The policy job uses the official CloudFormation Guard `3.2.0` x86-64 Ubuntu
archive
`cfn-guard-v3-x86_64-ubuntu-latest.tar.gz`, pinned to SHA-256
`9f8c4d9f15f7dd54a37ea70a5237ba00aba682fb1e6521a744d12259961dfc13`.
Do not pipe an unpinned installer from the default branch into a shell.

1. Validate the infrastructure package:

   ```bash
   npm ci --prefix infra/aws --ignore-scripts
   npm ci --prefix infra/aws/lambda/approval --omit=dev --ignore-scripts
   npm ci --prefix infra/aws/lambda/control --omit=dev --ignore-scripts
   npm --prefix infra/aws run build
   npm --prefix infra/aws test -- --ci --coverage
   npm --prefix infra/aws run synth -- \
     --all \
     --no-lookups \
     --output "${RUNNER_TEMP}/cdk.out"

   # cfn-guard 3.2.0 must be installed from its checksum-verified release.
   cfn-guard test \
     --rules-file infra/aws/policy/archon.guard \
     --test-data infra/aws/policy/archon_tests.yaml
   for template in "${RUNNER_TEMP}"/cdk.out/*.template.json; do
     cfn-guard validate \
       --data "${template}" \
       --rules infra/aws/policy/archon.guard \
       --type CFNTemplate \
       --show-summary all
   done
   ```

2. Bootstrap once per account/region outside the release workflow. The configured
   `AWS_DEPLOY_ROLE_ARN` then creates or updates the shared registry:

   ```bash
   (
     cd infra/aws
     ./node_modules/.bin/cdk deploy Archon-Registry \
       --require-approval never \
       --outputs-file "${RUNNER_TEMP}/registry-outputs.json"
   )
   ```

3. Download `container-${RELEASE_SHA}`, `web-${RELEASE_SHA}`, and
   `lambdas-${RELEASE_SHA}` from the selected successful default-branch CI run. Verify each
   GitHub artifact-envelope SHA-256, all three inner SHA-256 manifests, the OCI revision
   label, and safe regular-file-only archive paths. Replace the checked-out approval,
   handoff, and control Lambda sources with the exact verified Lambda archive before CDK
   deployment. Load and push the verified image; never call `docker build` or install
   Lambda dependencies in this workflow. Resolve and scan the immutable ECR digest:

   ```bash
   ECR_REPOSITORY_URI="$(aws cloudformation describe-stacks \
     --stack-name Archon-Registry \
     --query "Stacks[0].Outputs[?OutputKey=='ArchonEcrRepositoryUri'].OutputValue" \
     --output text)"
   ECR_REPOSITORY_NAME="$(aws cloudformation describe-stacks \
     --stack-name Archon-Registry \
     --query "Stacks[0].Outputs[?OutputKey=='ArchonEcrRepositoryName'].OutputValue" \
     --output text)"
   docker load --input "${VERIFIED_CONTAINER_ARCHIVE}"
   docker tag "archon-datahub:${RELEASE_SHA}" \
     "${ECR_REPOSITORY_URI}:${RELEASE_SHA}"
   docker push "${ECR_REPOSITORY_URI}:${RELEASE_SHA}"
   IMAGE_DIGEST="$(aws ecr describe-images \
     --repository-name "${ECR_REPOSITORY_NAME}" \
     --image-ids "imageTag=${RELEASE_SHA}" \
     --query "imageDetails[0].imageDigest" \
     --output text)"
   ```

4. Deploy a stage using only the verified identities. `SPA_ARTIFACT_SHA256` is the
   inner deterministic `archon-web.tar.gz` digest, not the GitHub ZIP envelope:

   ```bash
   STACK_NAME="Archon-${ARCHON_STAGE}"
   (
     cd infra/aws
     ./node_modules/.bin/cdk deploy "${STACK_NAME}" \
       -c "stage=${ARCHON_STAGE}" \
       --exclusively \
       --require-approval never \
       --parameters "${STACK_NAME}:ImageDigest=${IMAGE_DIGEST}" \
       --parameters "${STACK_NAME}:SpaArtifactSha256=${SPA_ARTIFACT_SHA256}" \
       --parameters "${STACK_NAME}:ReleaseSha=${RELEASE_SHA}" \
       --parameters "${STACK_NAME}:DataHubReadGmsUrl=${DATAHUB_READ_GMS_URL}" \
       --parameters "${STACK_NAME}:DataHubReadMcpUrl=${DATAHUB_READ_MCP_URL}" \
       --parameters "${STACK_NAME}:DataHubWriteGmsUrl=${DATAHUB_WRITE_GMS_URL}" \
       --parameters "${STACK_NAME}:DataHubWriteMcpUrl=${DATAHUB_WRITE_MCP_URL}" \
       --parameters "${STACK_NAME}:WorkerDesiredCount=0" \
       --outputs-file "${RUNNER_TEMP}/${ARCHON_STAGE}-outputs.json"
   )
   ```

5. Replace the bootstrap values in the three Secrets Manager resources, repeat the exact
   parameterized CDK deployment with `WorkerDesiredCount=1`, force new API/audit-worker/
   remediation-worker deployments, and wait until all three services reach their required
   desired/running counts. Only after workload readiness, upload the exact extracted SPA
   artifact to `ArchonSpaBucketName`: hashed assets use
   `Cache-Control: public,max-age=31536000,immutable`; `index.html` uses
   `Cache-Control: no-cache,no-store,must-revalidate`. Generate the exact
   `/runtime-config.json` contract from the stage outputs and upload it with
   `Cache-Control: no-cache,no-store,must-revalidate`; never put it into the
   immutable SPA archive. Publish runtime config before `index.html`, retain
   content-addressed assets for rollback, and invalidate only `/`,
   `/index.html`, and `/runtime-config.json` on
   `ArchonCloudFrontDistributionId`.

6. Configure a required, trimmed, non-wildcard `DATAHUB_DEMO_QUERY` GitHub environment
   variable that resolves to exactly one safe dataset. Smoke-test `ArchonApplicationUrl`,
   exact runtime-config bytes and no-store
   headers, the synchronous read-only `POST /api/audits` preview, and fail-closed
   control-loop schemas/status lookup. The workflow submits that query rather than `{}`,
   requires exactly one classified entity, and binds the query SHA-256 into promotion
   evidence. Then use the SPA to start
   `POST /api/control-loops`, observe `AWAITING_APPROVAL`, sign in through the
   browser's code + PKCE flow, decide through the `archon/approve` boundary, and
   retain the terminal `VERIFIED` or `REJECTED` projection with receipt digest,
   execution-evidence digest, completion timestamp, and check/event/rollback summary.
   Create an operator in the output Cognito pool and add it to
   `ArchonApproverGroupName`. The direct `ArchonApiInvokeUrl` is diagnostic only;
   clients use `ArchonApiUrl`.

7. Run the protected manual canary in
   [`../../.github/workflows/governed-canary.yml`](../../.github/workflows/governed-canary.yml)
   only against the isolated staging fixture. Its exact environment, least-privilege
   credential, pre-gate sealed plan/recovery digests, PKCE, separate rollback approval,
   and read-after-rollback contract is in
   [`../../docs/GOVERNED_CANARY.md`](../../docs/GOVERNED_CANARY.md).

The committed deployment workflow performs these checks, rotates environment-scoped
secrets, reconciles CDK, restarts ECS after rotation, and records sanitized evidence.
Production repeats steps 3–6 only after its protected-environment approval and must match
staging's exact `IMAGE_DIGEST`, SPA archive, Lambda archive, `SPA_ARTIFACT_SHA256`, and
`RELEASE_SHA`. Selecting an older retained CI run and SHA applies the same mechanism as
rollback.

## Explicit production gates

This stack keeps environment-dependent claims explicit:

- the synchronous `/api/audits` preview must complete within API Gateway's
  integration limit; its fixed live profile permits one dataset, two retained versions
  per mutable aspect, an 18-second harvest, and a 25-second end-to-end pipeline. The SPA
  uses the Standard workflow and strict
  isolated audit/remediation consumers for durable scans;
- durable live harvests permit at most 25 datasets and 12 retained versions per aspect,
  use eight-way bounded work, and fail on partial search, entity, or history responses;
- the public audit remains usable without sign-in, while approval is disabled
  until the SPA completes Cognito authorization code + PKCE and holds a
  short-lived scoped access token in memory;
- enforced standard Cognito threat protection explicitly selects the billable
  `PLUS` feature plan; approve that environment cost and attach budget alerts
  before enabling a long-lived hosted environment;
- custom Route 53/ACM names, a branded Cognito custom domain, cross-account ECR
  replication, and private DataHub connectivity depend on the target
  organization and belong in environment-specific stacks;
- CloudFront protects a read-only static origin; the regional WAF is attached to
  API Gateway so it also protects callers that bypass CloudFront.

## Stable CloudFormation outputs

The registry stack exports:

- `ArchonEcrRepositoryUri`
- `ArchonEcrRepositoryName`
- `ArchonEcrRepositoryArn`

Every environment stack exports:

- `ArchonSpaBucketName`, `ArchonEvidenceBucketName`
- `ArchonCloudFrontDistributionId`, `ArchonCloudFrontDomainName`
- `ArchonApplicationUrl`, `ArchonApiUrl`, `ArchonApiInvokeUrl`
- `ArchonUserPoolId`, `ArchonUserPoolClientId`, `ArchonApproverGroupName`
- `ArchonCognitoHostedUiOrigin`, `ArchonCognitoAuthorizationEndpoint`
- `ArchonCognitoTokenEndpoint`, `ArchonCognitoLogoutEndpoint`
- `ArchonApprovalOAuthScope`, `ArchonAuthRedirectUri`, `ArchonAuthLogoutUri`
- `ArchonStateMachineArn`, `ArchonAuditQueueUrl`, `ArchonApprovalQueueUrl`,
  `ArchonRemediationQueueUrl`
- `ArchonApprovalTableName`, `ArchonIdempotencyTableName`
- `ArchonEcsClusterName`, `ArchonApiServiceName`, `ArchonAuditWorkerServiceName`,
  `ArchonRemediationWorkerServiceName`
- `ArchonReadSecretArn`, `ArchonWriteSecretArn`, `ArchonLlmSecretArn`
- `ArchonAlarmTopicArn`
- `ArchonContainerImageDigest`, `ArchonSpaArtifactSha256`, `ArchonReleaseSha`

Data and secrets use `RETAIN`; DynamoDB and Cognito deletion protection are
enabled. Production also enables NLB deletion protection. Destruction therefore
requires an explicit, audited break-glass procedure.
