# Archon AWS reference deployment

This CDK app implements a secure hosted-demo baseline without coupling release
artifacts to an environment:

- a self-contained edge stack in `us-east-1` that creates a DNS-validated ACM
  certificate and a CloudFront-scope WAF with KMS-encrypted retained logs;
- a private, versioned S3 SPA behind CloudFront Origin Access Control, Route 53
  IPv4/IPv6 aliases, the edge certificate, the edge WAF, access logging, and the
  `TLSv1.3_2025` viewer policy;
- same-origin `/api/*` routing to a separately regional-WAF-protected API Gateway;
- a public, bounded durable audit start/status API plus an explicitly read-only synchronous
  preview route and a scope-protected approval route;
- a Cognito Plus classic Hosted UI with enforced standard threat protection and a
  public authorization-code client for browser PKCE S256;
- a dedicated approval Lambda with strict schemas, approver-group authorization,
  DynamoDB conditional writes, and a server-held callback token;
- a separate no-secret control Lambda that starts only the Archon state machine and
  returns digest-verified, capability-scoped status projections;
- private Fargate API and worker services with no public IP behind an internal NLB/VPC
  Link, using default-deny security groups and prefix-list-scoped HTTPS egress;
- Standard Step Functions, KMS-encrypted SQS/DLQs, and callback task tokens;
- separate KMS-encrypted DataHub read/write secrets;
- DynamoDB approval and idempotency/CAS stores with PITR and deletion protection;
- an Object-Lock, versioned, KMS evidence bucket plus versioned SPA and log buckets;
  the SPA and evidence buckets emit S3 server-access logs into the retained log bucket;
- VPC endpoints, flow logs, retained application logs, active X-Ray on API Gateway,
  Step Functions, and every Lambda, alarms, an SNS alarm topic, and an operations
  dashboard.

The Fargate API task is never granted the DataHub write secret. `POST /api/audits`
is publicly usable through CloudFront, synchronous, and read-only; it is a bounded
diagnostic preview rather than the SPA's production orchestration path. The
judge-facing SPA uses:

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

Every API method also requires a generated 64-character origin key. Its value is held in
KMS-encrypted Secrets Manager and referenced dynamically by both API Gateway and the
CloudFront custom origin header; it is never present in a browser bundle, runtime config,
stack output, or retained evidence. CloudFront overwrites a viewer-supplied `x-api-key`,
while the custom origin request policy excludes `host` and forwards the remaining viewer
context. API Gateway validates the overwritten edge key, then every HTTP/Lambda integration
prevents it from propagating: the HTTP proxy overwrites it with the literal `redacted`,
while custom Lambda mappings emit only the validated body, required path value, request
identifier, and selected Cognito claims. The approval method additionally requires the
Cognito access token, `archon/approve` scope, and approver group.
API-key quotas are only a best-effort aggregate throttle; WAF, bounded workloads, reserved
concurrency, alarms, and account budgets remain the abuse and cost controls.
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
`comment`. A narrow API Gateway mapping projects only `sub`, `iss`, and
`cognito:groups` from the verified access token; email is intentionally not
projected because it is an ID-token identity claim. The Lambda requires membership
in `archon-approvers`, while API Gateway additionally requires the
`archon/approve` access-token scope. A browser never sends action names, tool
names, entity URNs, mutation arguments, digests, or callback tokens. The Lambda resolves the
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
`Archon-<stage>-Edge` is the environment's global control-plane stack and is always
deployed in `us-east-1`. It owns the DNS-validated viewer certificate, CloudFront-scope
WAF, encrypted WAF log group, and their output contract. `Archon-<stage>` is the regional
platform stack. `stage` is supplied as CDK context, for example `-c stage=staging`.
Both WAFs use the moving AWS-managed default rule-group versions (no stale version pin),
an explicit 300-second IP rate window, sampled-field substitution, filtered/redacted
logging, and an exact enabled, rotating, single-Region customer KMS key binding.

The environment stack has three mandatory promotion parameters:

| Parameter | Contract |
| --- | --- |
| `ImageDigest` | Exact `sha256:...` returned by ECR after one CI build |
| `SpaArtifactSha256` | SHA-256 of the one CI-produced SPA archive |
| `ReleaseSha` | Source commit represented by the container, SPA, and Lambda release candidates |

The platform also requires `DataHubReadGmsUrl`, hosted `DataHubReadMcpUrl`,
`DataHubWriteGmsUrl`, and hosted `DataHubWriteMcpUrl`. The Fargate image intentionally
contains no `uvx`, so separate read-only and mutation-enabled Streamable HTTP MCP endpoints
are mandatory. `LlmBaseUrl`, `LlmModel`, and `WorkerDesiredCount` are configurable.
`WorkerDesiredCount` accepts zero or one and defaults to zero. The exact image contains
`dist/audit-worker.js` and `dist/remediation-worker.js`, which CI checks without starting
either process. Set the parameter to one only after all live endpoint values and distinct
tokens are installed. The isolated services autoscale from their own queues.

Each protected GitHub environment supplies only these two non-secret edge inputs; the
pipeline passes the same values to both the edge and platform stacks:

| Environment variable | CDK parameter | Contract |
| --- | --- | --- |
| `ARCHON_CLOUDFRONT_DOMAIN_NAME` | `CloudFrontDomainName` | Concrete lowercase public DNS name for that environment |
| `ARCHON_CLOUDFRONT_HOSTED_ZONE_ID` | `CloudFrontHostedZoneId` | Owning Route 53 public hosted-zone ID, without the `/hostedzone/` prefix |

There is no operator-supplied certificate ARN. The edge stack requests the certificate,
performs Route 53 DNS validation, and exports `ArchonCloudFrontCertificateArn` and
`ArchonCloudFrontWebAclArn`. The deployment pipeline validates those outputs and passes
them to the regional platform as `CloudFrontCertificateArn` and `CloudFrontWebAclArn`.
That handoff keeps CloudFront's `us-east-1` control-plane resources explicit without
requiring a certificate or WAF to be provisioned out of band.
The Web ACL parameter carries an obvious, non-deployable default solely so the exact
CloudFormation assembly remains resolvable by IaC scanners. An unconditional
CloudFormation Rule rejects that sentinel before create/update; the pipeline must supply
the independently validated live edge-stack ARN. No scanner ignore or transformed
deployment template is used.

The same protected environments provide three customer-managed egress boundaries:

| Environment variable | Platform parameter | Permitted HTTPS destination |
| --- | --- | --- |
| `ARCHON_DATAHUB_READ_EGRESS_PREFIX_LIST_ID` | `DataHubReadEgressPrefixListId` | Read-only DataHub GMS/MCP endpoints for the API and audit worker |
| `ARCHON_DATAHUB_WRITE_EGRESS_PREFIX_LIST_ID` | `DataHubWriteEgressPrefixListId` | Mutation-enabled DataHub GMS/MCP endpoints for the remediation worker |
| `ARCHON_LLM_EGRESS_PREFIX_LIST_ID` | `LlmEgressPrefixListId` | Configured inference endpoint for the API and audit worker |

These are account-owned, customer-managed IPv4 prefix lists, not security-group IDs and
not AWS service prefix lists. The deployment gate requires each list to be complete,
non-empty, no broader than `/8` per entry, and tagged with the exact
`ArchonEgressScope` value `datahub-read`, `datahub-write`, or `llm`. It also validates
each list's `MaxEntries` weight and rejects any combination that would exceed the
conservative 60-rule outbound security-group quota.

The pipeline separately resolves the AWS-owned
`com.amazonaws.${AWS_REGION}.s3` and
`com.amazonaws.${AWS_REGION}.dynamodb` managed prefix-list IDs at deployment time. It
passes them as `S3PrefixListId` and `DynamoDbPrefixListId`; operators do not configure
GitHub variables for these regional AWS service identities.

The stack creates both A and AAAA aliases to CloudFront and enforces SNI with
`TLSv1.3_2025`. It intentionally has no legacy `*.cloudfront.net` fallback because AWS
fixes that default certificate to the legacy `TLSv1` security policy. A viewer-request
CloudFront Function on every cache behavior rejects any non-canonical `Host` with `421`
before a static object or API response can be returned.

The platform WAF remains attached directly to the regional API Gateway, including for
callers that bypass CloudFront. The edge WAF protects every CloudFront behavior and keeps
only blocked/counted records after redacting authorization and cookie headers. The API's
capability-scoped `GET /api/control-loops/{auditId}` status projection is the only method
with stage caching: its cache is encrypted and expires after two seconds. API Gateway,
the state machine, all application Lambdas, and the CDK default-security-group restriction
provider use active X-Ray tracing.

Every workload security group starts with IPv4 and IPv6 outbound disabled. Workloads may
reach PrivateLink endpoints on TCP 443 and S3 through the pipeline-resolved AWS prefix
list; workers may additionally reach DynamoDB. Only the API/audit side receives read
DataHub and LLM egress, while only the remediation worker receives write DataHub egress.
The API's sole ingress is a TCP 8080 security-group reference from the internal NLB.
The NLB has its own default-deny security group, permits only API-target/health-check
egress, and bypasses inbound evaluation only for the API Gateway PrivateLink path.
Public subnets have
automatic public-IP assignment disabled, and every Fargate service sets
`AssignPublicIp=DISABLED`.

The deployment pipeline must build once and promote the same image digest, SPA archive,
and Lambda archive. It must not rebuild application code for staging or production.
Those immutable application subjects may be rolled back to an older retained CI run.
Infrastructure remains reconciled from the current default-branch deployment-control-plane
commit, which the workflow admits only after successful CI, CodeQL, and workflow-security
push runs for that exact commit; application rollback never reverts newer IaC protections.
The staging and production receipts retain compact edge-security and network-egress
contracts. They bind the exact certificate/WAF identities and edge-output digest to the
validated prefix-list identities, weights, and calculated security-group quota use.

## CI deployment sequence

Run all commands in a clean CI workspace. No generated `cdk.out`, coverage, or
dependency directories should be committed. This section describes the reproducible
pipeline contract; only evidence emitted and retained by remote CI/CD is accepted as
security or release evidence. Workstation builds, synths, scanners, or copied reports do
not satisfy any gate.

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

2. Bootstrap once per account in both the regional platform region and `us-east-1`
   outside the release workflow. The configured `AWS_DEPLOY_ROLE_ARN` then creates or
   updates the shared registry:

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
   inner deterministic `archon-web.tar.gz` digest, not the GitHub ZIP envelope. The
   pipeline resolves the two AWS service prefix lists, deploys the edge stack first,
   validates its outputs, and passes those outputs plus the three customer-managed
   allowlists to the platform stack:

   ```bash
   S3_PREFIX_LIST_ID="$(aws ec2 describe-managed-prefix-lists \
     --filters \
       "Name=owner-id,Values=AWS" \
       "Name=prefix-list-name,Values=com.amazonaws.${AWS_REGION}.s3" \
     --query 'PrefixLists[0].PrefixListId' \
     --output text)"
   DYNAMODB_PREFIX_LIST_ID="$(aws ec2 describe-managed-prefix-lists \
     --filters \
       "Name=owner-id,Values=AWS" \
       "Name=prefix-list-name,Values=com.amazonaws.${AWS_REGION}.dynamodb" \
     --query 'PrefixLists[0].PrefixListId' \
     --output text)"

   EDGE_STACK_NAME="Archon-${ARCHON_STAGE}-Edge"
   STACK_NAME="Archon-${ARCHON_STAGE}"
   (
     cd infra/aws
     ./node_modules/.bin/cdk deploy "${EDGE_STACK_NAME}" \
       -c "stage=${ARCHON_STAGE}" \
       --exclusively \
       --require-approval never \
       --parameters "${EDGE_STACK_NAME}:CloudFrontDomainName=${ARCHON_CLOUDFRONT_DOMAIN_NAME}" \
       --parameters "${EDGE_STACK_NAME}:CloudFrontHostedZoneId=${ARCHON_CLOUDFRONT_HOSTED_ZONE_ID}" \
       --outputs-file "${RUNNER_TEMP}/${ARCHON_STAGE}-edge-outputs.json"
   )
   EDGE_CERTIFICATE_ARN="$(jq -er --arg stack "${EDGE_STACK_NAME}" \
     '.[$stack].ArchonCloudFrontCertificateArn' \
     "${RUNNER_TEMP}/${ARCHON_STAGE}-edge-outputs.json")"
   EDGE_WEB_ACL_ARN="$(jq -er --arg stack "${EDGE_STACK_NAME}" \
     '.[$stack].ArchonCloudFrontWebAclArn' \
     "${RUNNER_TEMP}/${ARCHON_STAGE}-edge-outputs.json")"
   (
     cd infra/aws
     ./node_modules/.bin/cdk deploy "${STACK_NAME}" \
       -c "stage=${ARCHON_STAGE}" \
       --exclusively \
       --require-approval never \
       --parameters "${STACK_NAME}:ImageDigest=${IMAGE_DIGEST}" \
       --parameters "${STACK_NAME}:SpaArtifactSha256=${SPA_ARTIFACT_SHA256}" \
       --parameters "${STACK_NAME}:ReleaseSha=${RELEASE_SHA}" \
       --parameters "${STACK_NAME}:CloudFrontDomainName=${ARCHON_CLOUDFRONT_DOMAIN_NAME}" \
       --parameters "${STACK_NAME}:CloudFrontCertificateArn=${EDGE_CERTIFICATE_ARN}" \
       --parameters "${STACK_NAME}:CloudFrontHostedZoneId=${ARCHON_CLOUDFRONT_HOSTED_ZONE_ID}" \
       --parameters "${STACK_NAME}:CloudFrontWebAclArn=${EDGE_WEB_ACL_ARN}" \
       --parameters "${STACK_NAME}:S3PrefixListId=${S3_PREFIX_LIST_ID}" \
       --parameters "${STACK_NAME}:DynamoDbPrefixListId=${DYNAMODB_PREFIX_LIST_ID}" \
       --parameters "${STACK_NAME}:DataHubReadEgressPrefixListId=${ARCHON_DATAHUB_READ_EGRESS_PREFIX_LIST_ID}" \
       --parameters "${STACK_NAME}:DataHubWriteEgressPrefixListId=${ARCHON_DATAHUB_WRITE_EGRESS_PREFIX_LIST_ID}" \
       --parameters "${STACK_NAME}:LlmEgressPrefixListId=${ARCHON_LLM_EGRESS_PREFIX_LIST_ID}" \
       --parameters "${STACK_NAME}:DataHubReadGmsUrl=${DATAHUB_READ_GMS_URL}" \
       --parameters "${STACK_NAME}:DataHubReadMcpUrl=${DATAHUB_READ_MCP_URL}" \
       --parameters "${STACK_NAME}:DataHubWriteGmsUrl=${DATAHUB_WRITE_GMS_URL}" \
       --parameters "${STACK_NAME}:DataHubWriteMcpUrl=${DATAHUB_WRITE_MCP_URL}" \
       --parameters "${STACK_NAME}:WorkerDesiredCount=0" \
       --outputs-file "${RUNNER_TEMP}/${ARCHON_STAGE}-outputs.json"
   )
   ```

5. Replace the bootstrap values in the three Secrets Manager resources, repeat the exact
   parameterized platform deployment—including the same two validated edge outputs and
   all five prefix-list IDs—with `WorkerDesiredCount=1`, force new API/audit-worker/
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
   `ArchonApproverGroupName`. The direct `ArchonApiInvokeUrl` must reject calls without
   the non-exported origin key; all clients use `ArchonApiUrl`.

7. Run the protected manual canary in
   [`../../.github/workflows/governed-canary.yml`](../../.github/workflows/governed-canary.yml)
   only against the isolated staging fixture. Its exact environment, least-privilege
   credential, pre-gate sealed plan/recovery digests, PKCE, separate rollback approval,
   and read-after-rollback contract is in
   [`../../docs/GOVERNED_CANARY.md`](../../docs/GOVERNED_CANARY.md).

The committed deployment workflow performs these checks, rotates environment-scoped
secrets, reconciles CDK, restarts ECS after versioned secret refresh, and records
sanitized evidence.
The GitHub OIDC deployment roles must also allow the pipeline's read-only live-contract
calls: `ec2:DescribeVpcs`, `ec2:DescribeSecurityGroups`,
`ec2:DescribeSecurityGroupRules`, `elasticloadbalancing:DescribeLoadBalancers`, the
required WAFv2 getters, `logs:DescribeLogGroups`, `kms:DescribeKey`, and
`kms:GetKeyRotationStatus`. These permissions are used to observe the deployed state;
the pipeline does not infer VPC, NLB, security-group, WAF, KMS, or log-retention claims
from CloudFormation outputs alone.
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
- the public audit remains usable through CloudFront without sign-in, while approval is disabled
  until the SPA completes Cognito authorization code + PKCE and holds a
  short-lived scoped access token in memory;
- the retained CloudFront-origin secret must never be rotated independently of the API
  key and distribution. Rotate with an overlap window: add a second API key to the usage
  plan, switch CloudFront, prove propagation and direct-origin rejection, then remove the
  old key;
- enforced standard Cognito threat protection explicitly selects the billable
  `PLUS` feature plan; approve that environment cost and attach budget alerts
  before enabling a long-lived hosted environment;
- the API stage enables the smallest `0.5` encrypted cache cluster only for the
  two-second status projection; include that hourly service cost in the same budget gate;
- domain registration, an existing Route 53 public hosted zone, a branded Cognito custom
  domain, cross-account ECR replication, and private DataHub connectivity remain explicit
  environment prerequisites; the edge stack owns ACM creation and DNS validation, so a
  pre-created certificate ARN is not a prerequisite;
- account-owned, narrowly scoped DataHub-read, DataHub-write, and LLM prefix lists remain
  environment prerequisites; the pipeline validates their ownership, state, entries, and
  scope tags, while resolving the AWS-owned regional S3/DynamoDB lists itself;
- CloudFront protects the static and same-origin API behaviors with its global WAF; the
  separate regional WAF remains attached to API Gateway so it also protects callers that
  bypass CloudFront.

## Stable CloudFormation outputs

The registry stack exports:

- `ArchonEcrRepositoryUri`
- `ArchonEcrRepositoryName`
- `ArchonEcrRepositoryArn`

Every edge stack exports:

- `ArchonCloudFrontCertificateArn`
- `ArchonCloudFrontWebAclArn`
- `ArchonCloudFrontWafLogKeyArn`

Every environment stack exports:

- `ArchonSpaBucketName`, `ArchonEvidenceBucketName`
- `ArchonCloudFrontDistributionId`, `ArchonCloudFrontDomainName`
- `ArchonApplicationUrl`, `ArchonApiUrl`, `ArchonApiInvokeUrl`, `ArchonApiStageArn`
- `ArchonRegionalWebAclArn`, `ArchonRegionalWafLogGroupName`,
  `ArchonRegionalWafLogKeyArn`
- `ArchonUserPoolId`, `ArchonUserPoolClientId`, `ArchonApproverGroupName`
- `ArchonCognitoHostedUiOrigin`, `ArchonCognitoAuthorizationEndpoint`
- `ArchonCognitoTokenEndpoint`, `ArchonCognitoLogoutEndpoint`
- `ArchonApprovalOAuthScope`, `ArchonAuthRedirectUri`, `ArchonAuthLogoutUri`
- `ArchonStateMachineArn`, `ArchonAuditQueueUrl`, `ArchonApprovalQueueUrl`,
  `ArchonRemediationQueueUrl`
- `ArchonApprovalTableName`, `ArchonIdempotencyTableName`
- `ArchonEcsClusterName`, `ArchonApiServiceName`, `ArchonAuditWorkerServiceName`,
  `ArchonRemediationWorkerServiceName`
- `ArchonVpcId`, `ArchonPrivateNlbArn`, `ArchonNlbSecurityGroupId`
- `ArchonApiSecurityGroupId`, `ArchonAuditWorkerSecurityGroupId`,
  `ArchonRemediationWorkerSecurityGroupId`, `ArchonVpcEndpointSecurityGroupId`
- `ArchonReadSecretArn`, `ArchonWriteSecretArn`, `ArchonLlmSecretArn`
- `ArchonAlarmTopicArn`
- `ArchonContainerImageDigest`, `ArchonSpaArtifactSha256`, `ArchonReleaseSha`

Data and secrets use `RETAIN`; DynamoDB and Cognito deletion protection are
enabled. Production also enables NLB deletion protection. Destruction therefore
requires an explicit, audited break-glass procedure.
