# Archon AWS reference deployment

This CDK app implements a secure hosted-demo baseline without coupling release
artifacts to an environment:

- a self-contained edge stack in `us-east-1` that creates a CloudFront-scope WAF
  with KMS-encrypted retained logs;
- a private, versioned S3 SPA behind CloudFront Origin Access Control, served from the
  distribution's provider-managed `*.cloudfront.net` hostname and default certificate
  with HTTPS enforcement, the edge WAF, CloudFront access logging, and S3
  server-access logging;
- same-origin `/api/*` routing to a separately regional-WAF-protected API Gateway;
- a public, bounded durable audit start/status API plus an explicitly read-only synchronous
  preview route and a scope-protected approval route;
- a Cognito Plus classic Hosted UI with enforced standard threat protection and a
  public authorization-code client for browser PKCE S256, an exact narrow OAuth scope
  set with no Cognito self-administration scope, and a client-specific shared-judge risk
  policy;
- a dedicated approval Lambda with strict schemas, approver-group authorization,
  DynamoDB conditional writes, and a server-held callback token;
- a separate no-secret control Lambda that starts only the Archon state machine and
  returns digest-verified, capability-scoped status projections;
- private Fargate API and worker services with no public IP behind an internal NLB/VPC
  Link, using default-deny security groups and security-group-scoped DataHub PrivateLink;
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
the retained, KMS-encrypted `archon/<stage>/cloudfront-origin-api-key` secret and both API
Gateway and the sole CloudFront custom origin header use the exact stage-scoped Secrets
Manager dynamic reference for its `apiKey` field; it is never present in a browser bundle,
runtime config, stack output, or retained evidence. The IaC policy and deployed-template
pipeline gate reject any additional origin custom header, bind `api/*` to the sole custom
origin, and resolve that behavior's exact `OriginRequestPolicy` logical ID before checking
the policy. CloudFront overwrites a viewer-supplied `x-api-key`, while the bound custom
origin request policy excludes `host` and forwards the remaining viewer context. API
Gateway validates the overwritten edge key, then every HTTP/Lambda integration prevents
it from propagating: the HTTP proxy overwrites it with the literal `redacted`, while
custom Lambda mappings emit only the validated body, required path value, request
identifier, and selected Cognito claims. The approval method additionally requires the
Cognito access token, `archon/approve` scope, and approver group.
API-key quotas are only a best-effort aggregate throttle; WAF, bounded workloads, reserved
concurrency, alarms, and account budgets remain the abuse and cost controls.
An explicit `mode: "READ_ONLY"` is reserved for safe hosted verification: the
worker still seals the report evidence but cannot create a remediation plan.
The staging pipeline exercises that mode to `READ_ONLY_COMPLETE` and retains the
sanitized terminal response hash.

## Temporary bundled dependency compensation

`aws-cdk-lib@2.262.1` immutably bundles `brace-expansion@5.0.7`. That version is
affected by
[GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg);
`5.0.8` is the first patched release. npm overrides fix every ordinary
occurrence but cannot rewrite a dependency embedded in the published CDK
tarball. This is a build-time CDK dependency; it is not packaged into the
Archon application container or either Lambda release candidate.

The CI job and both protected staging/production deployment jobs therefore
apply one narrow, fail-closed compensation before any CDK typecheck, test,
synth, or deploy:

1. verify every declared npm override and require the sole exception to be the
   exact bundled path, version, package-lock metadata, and installed tree;
2. download the official `brace-expansion@5.0.8` tarball over HTTPS and verify
   its pinned npm SHA-512 integrity before bounded, path-safe extraction;
3. replace only
   `node_modules/aws-cdk-lib/node_modules/brace-expansion`, verify package
   identity and API behavior, and seal the installed tree digest in a receipt;
4. run npm audit and accept only one high finding with the exact GHSA, range,
   immutable bundled path, and zero other high/critical findings, while binding
   that report to the patch receipt and installed tree;
5. retain the receipt, audit report, decision, and checksums for 90 days. PR
   dependency review has the same single-GHSA exception and no severity-wide
   suppression.

The PR lock gate separately resolves root and infrastructure locks from only
their reviewed manifests in clean temporary directories, with npm `10.9.8`,
the HTTPS npm registry, strict engines, no lifecycle scripts, and no repository
`.npmrc`. It requires byte-for-byte equality with both committed locks before
running the full candidate validation, and seals the exact head repository,
PR, workflow SHA, run/attempt, manifest hashes, lock hashes, Node, and npm
versions in the short-lived review artifact.

This control must be removed, rather than broadened, when an exact reviewed
`aws-cdk-lib` release bundles `brace-expansion >=5.0.8`. Retirement deletes the
two compensation scripts and the Dependency Review exception, updates the lock,
and requires the ordinary zero-high npm audit plus the full CDK/Guard/Trivy
pipeline to pass. Dependabot's weekly infrastructure update remains the
upstream-release monitor.

The browser approval endpoint is:

```text
POST /api/approvals/{approvalId}/decisions
Content-Type: application/json

{"decision":"APPROVE","comment":"optional human comment"}
```

The SPA loads `/runtime-config.json` before it enables sign-in. That
environment-bound document contains only the public client ID, exact Cognito
authorization/token/logout endpoints, the CloudFront-root redirect/logout URI,
`openid email archon/approve` scopes, and the public-safe narrow demo query used to
pre-fill the read-only audit. It is created after the stack deploy,
is never baked into the build-once SPA archive, and is served by an explicit
CloudFront caching-disabled behavior with `Cache-Control:
no-cache,no-store,must-revalidate`. Access tokens remain in browser memory.
The client exposes only authorization code and refresh-token authentication and omits
`aws.cognito.signin.user.admin`, so its access token cannot authorize Cognito
`ChangePassword`. It enables user-existence-error suppression and accepts exactly the
CloudFront application root as its callback and logout URI, with no independent default
redirect. The protected lifecycle also rejects any second client in the pool, verified
recovery attribute, MFA factor, or paginated group inventory before activating access.
Its exact client-scoped threat policy keeps account-takeover
low/medium/high actions at `NO_ACTION` with notifications disabled to avoid locking out
legitimate shared judges on new networks, while compromised credentials are `BLOCK` for
exactly `SIGN_IN` and `PASSWORD_CHANGE`. WAF/rate controls, the protected strong stable
password, short tokens, monitoring, and independently approved rotation/deactivation
provide the surrounding compromise controls.

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
deployed in `us-east-1`. It owns the CloudFront-scope WAF, encrypted retained WAF log
group, and their output contract. `Archon-<stage>` is the regional platform stack and owns
the CloudFront distribution. `stage` is supplied as CDK context, for example
`-c stage=staging`.
Both WAFs use the moving AWS-managed default rule-group versions (no stale version pin),
an explicit 300-second IP rate window, sampled-field substitution, filtered/redacted
logging, and an exact enabled, rotating, single-Region customer KMS key binding.

The environment stack has nine mandatory promotion parameters:

| Parameter | Contract |
| --- | --- |
| `ImageDigest` | Exact `sha256:...` returned by ECR after one CI build |
| `SpaArtifactSha256` | SHA-256 of the one CI-produced SPA archive |
| `ContainerArchiveSha256` | SHA-256 of the exact retained CI container archive |
| `LambdaArchiveSha256` | SHA-256 of the exact retained CI Lambda archive |
| `DeploymentWorkflowRunId` | Numeric GitHub Actions deployment run that performed the promotion |
| `DeploymentWorkflowRunAttempt` | Exact attempt number of that deployment run |
| `CiRunId` | Numeric successful `master` CI run that produced all retained subjects |
| `ReleaseSha` | Source commit represented by the container, SPA, and Lambda release candidates |
| `DemoQuery` | Exact trimmed, non-wildcard dataset query shared by the hosted API, control Lambda, and SPA runtime configuration |

The platform also requires `DataHubReadGmsUrl`, hosted `DataHubReadMcpUrl`,
`DataHubWriteGmsUrl`, and hosted `DataHubWriteMcpUrl`. The Fargate image intentionally
contains no `uvx`, so separate read-only and mutation-enabled Streamable HTTP MCP endpoints
are mandatory. `WorkerDesiredCount` is configurable.
`WorkerDesiredCount` accepts zero or one and defaults to zero. The exact image contains
`dist/audit-worker.js` and `dist/remediation-worker.js`, which CI checks without starting
either process. Set the parameter to one only after all live endpoint values and distinct
tokens are installed. The isolated services autoscale from their own queues.

Protected GitHub environments supply no custom CloudFront hostname, Route 53 hosted-zone
ID, or ACM certificate input. The edge stack exports `ArchonCloudFrontWebAclArn`; the
deployment pipeline validates that output and passes it to the regional platform as
`CloudFrontWebAclArn`. The regional stack creates the distribution with no aliases, uses
its generated `*.cloudfront.net` hostname and default certificate, and derives the
Cognito callback and logout URLs from that hostname.
This handoff keeps the CloudFront-scope WAF in its required `us-east-1` control plane
without requiring a certificate, custom DNS resource, or WAF to be provisioned out of
band.
The Web ACL parameter carries an obvious, non-deployable default solely so the exact
CloudFormation assembly remains resolvable by IaC scanners. An unconditional
CloudFormation Rule rejects that sentinel before create/update; the pipeline must supply
the independently validated live edge-stack ARN. No scanner ignore or transformed
deployment template is used.

The same protected environments provide one provider-issued DataHub Cloud service:

| Environment variable | Platform parameter | Permitted HTTPS destination |
| --- | --- | --- |
| `ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME` | `DataHubPrivateLinkServiceName` | One same-region DataHub interface endpoint with verified provider private DNS |

The preflight requires the service to be discoverable from the authenticated deployment
account in `eu-west-1`, externally owned, Interface-capable, backed by verified provider
private DNS, auto-accepted, and available in two usable account AZs. Those exact AZs become
`DataHubPrivateLinkAzOne` and `DataHubPrivateLinkAzTwo`, so VPC subnet placement cannot
diverge from provider coverage. All four configured GMS/MCP URLs must be HTTPS on the
service's exact tenant origin; their paths remain explicit configuration.

Inference does not use a public-IP allowlist or a static provider secret. The stack creates
one tagged `AWS::BedrockMantle::Project` per stage and a dedicated
`com.amazonaws.eu-west-1.bedrock-mantle` interface endpoint with private DNS. Only the API
and audit-worker security groups can reach that endpoint; the write-capable remediation
worker cannot. Their task roles can invoke only `qwen.qwen3-235b-a22b-2507` on the exact
stage project and can mint only short-term bearer tokens. The OpenAI-compatible client
sets the project ID on every request for access isolation, CloudWatch visibility, and
cost attribution. No `LLM_API_KEY` or `AWS_BEARER_TOKEN_BEDROCK` is stored.

The pipeline separately resolves the AWS-owned
`com.amazonaws.${AWS_REGION}.s3` and
`com.amazonaws.${AWS_REGION}.dynamodb` managed prefix-list IDs at deployment time. It
passes them as `S3PrefixListId` and `DynamoDbPrefixListId`; operators do not configure
GitHub variables for these regional AWS service identities.

The regional stack uses the generated `*.cloudfront.net` hostname and CloudFront default
certificate directly. It creates no Route 53 aliases, ACM certificate, custom hostname,
or viewer-request CloudFront Function. The default SPA behavior redirects HTTP to HTTPS;
the API and runtime-configuration behaviors are HTTPS-only. CloudFront OAC binds private
SPA reads to the exact distribution, and the generated hostname is the sole public origin
used for application, API, and Cognito redirect/logout outputs.

The platform WAF remains attached directly to the regional API Gateway, including for
callers that bypass CloudFront. The edge WAF protects every CloudFront behavior and keeps
only blocked/counted records after redacting authorization and cookie headers. The API's
capability-scoped `GET /api/control-loops/{auditId}` status projection is the only method
with stage caching: its cache is encrypted and expires after two seconds. API Gateway,
the state machine, all application Lambdas, and the CDK default-security-group restriction
provider use active X-Ray tracing.

Every workload security group starts with IPv4 and IPv6 outbound disabled. Workloads may
reach shared AWS PrivateLink endpoints on TCP 443 and S3 through the pipeline-resolved AWS
prefix list; workers may additionally reach DynamoDB. API, audit, and remediation reach
DataHub only through a dedicated endpoint security group on TCP 443. Read/write authority
remains separated by Secrets Manager credentials and provider RBAC. Only API/audit can
reach the dedicated Bedrock Mantle PrivateLink path.
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
push runs for that exact commit. The ref and latest exact-SHA receipts are revalidated after
production approval, before each AWS OIDC trust boundary, immediately before mutation, and
after the live production byte observation immediately before promotion evidence is sealed.
That final check must reproduce the original receipt digest; the canonical receipt is
included in deployment evidence. Application rollback never reverts newer IaC protections.
The staging and production receipts retain compact edge-security and network-egress
contracts. They bind the exact provider-managed viewer hostname/default-certificate mode,
WAF identity, and edge-output digest to the AWS-managed prefix-list identities and the
preflighted plus live-verified DataHub service, provider private DNS, AZs, endpoint, and
security-group rules.

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
   pipeline resolves the two AWS service prefix lists, preflights the configured DataHub
   PrivateLink service and selects its exact supported AZ pair, deploys the edge stack
   first, and passes those validated values to the platform stack. Normal releases must use
   `.github/workflows/deploy.yml`; the following is the pipeline contract, not a manual
   operator bypass. `CONTAINER_ARCHIVE_SHA256`, `LAMBDA_ARCHIVE_SHA256`,
   `DEPLOYMENT_WORKFLOW_RUN_ID`, `DEPLOYMENT_WORKFLOW_RUN_ATTEMPT`, and `CI_RUN_ID` must
   come from the exact verified GitHub runs and artifacts:

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
       --outputs-file "${RUNNER_TEMP}/${ARCHON_STAGE}-edge-outputs.json"
   )
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
        --parameters "${STACK_NAME}:ContainerArchiveSha256=${CONTAINER_ARCHIVE_SHA256}" \
        --parameters "${STACK_NAME}:LambdaArchiveSha256=${LAMBDA_ARCHIVE_SHA256}" \
        --parameters "${STACK_NAME}:DeploymentWorkflowRunId=${DEPLOYMENT_WORKFLOW_RUN_ID}" \
        --parameters "${STACK_NAME}:DeploymentWorkflowRunAttempt=${DEPLOYMENT_WORKFLOW_RUN_ATTEMPT}" \
        --parameters "${STACK_NAME}:CiRunId=${CI_RUN_ID}" \
        --parameters "${STACK_NAME}:ReleaseSha=${RELEASE_SHA}" \
       --parameters "${STACK_NAME}:DemoQuery=${DATAHUB_DEMO_QUERY}" \
       --parameters "${STACK_NAME}:CloudFrontWebAclArn=${EDGE_WEB_ACL_ARN}" \
       --parameters "${STACK_NAME}:S3PrefixListId=${S3_PREFIX_LIST_ID}" \
       --parameters "${STACK_NAME}:DynamoDbPrefixListId=${DYNAMODB_PREFIX_LIST_ID}" \
       --parameters "${STACK_NAME}:DataHubPrivateLinkServiceName=${ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME}" \
       --parameters "${STACK_NAME}:DataHubPrivateLinkAzOne=${DATAHUB_PRIVATE_LINK_AZ_ONE}" \
       --parameters "${STACK_NAME}:DataHubPrivateLinkAzTwo=${DATAHUB_PRIVATE_LINK_AZ_TWO}" \
       --parameters "${STACK_NAME}:DataHubReadGmsUrl=${DATAHUB_READ_GMS_URL}" \
       --parameters "${STACK_NAME}:DataHubReadMcpUrl=${DATAHUB_READ_MCP_URL}" \
       --parameters "${STACK_NAME}:DataHubWriteGmsUrl=${DATAHUB_WRITE_GMS_URL}" \
       --parameters "${STACK_NAME}:DataHubWriteMcpUrl=${DATAHUB_WRITE_MCP_URL}" \
       --parameters "${STACK_NAME}:WorkerDesiredCount=0" \
       --outputs-file "${RUNNER_TEMP}/${ARCHON_STAGE}-outputs.json"
   )
   ```

5. Replace the bootstrap values in the two DataHub Secrets Manager resources, repeat the exact
   parameterized platform deployment—including the same validated edge Web ACL output,
   two AWS prefix-list IDs, and DataHub service/AZ tuple—with `WorkerDesiredCount=1`, force new API/audit-worker/
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
   variable that resolves to exactly one safe dataset. The deployment places that exact
   value in the `DemoQuery` stack parameter, the API container and control Lambda
   environments, and runtime config; the SPA pre-fills it for a one-click bounded demo.
   Smoke-test `ArchonApplicationUrl`,
   exact runtime-config bytes and no-store
   headers, the synchronous read-only `POST /api/audits` preview, and fail-closed
   control-loop schemas/status lookup. The workflow submits that query rather than `{}`,
   requires exactly one classified entity, and binds the query SHA-256 into promotion
   evidence. Then use the SPA to start
   `POST /api/control-loops`, observe `AWAITING_APPROVAL`, sign in through the
   browser's code + PKCE flow, decide through the `archon/approve` boundary, and
   retain the terminal `VERIFIED` or `REJECTED` projection with receipt digest,
   execution-evidence digest, completion timestamp, and check/event/rollback summary.
   Provision, rotate, reactivate, and deactivate the exact judge/operator identity only through the
   protected [`judge-user.yml`](../../.github/workflows/judge-user.yml) workflow and its
   [least-privilege runbook](../../docs/JUDGE_ACCESS.md). Self-sign-up stays disabled,
   and the workflow must bind the protected email to its fixed opaque account ID and avoid
   printing or retaining bootstrap or permanent password material. Provision, rotation,
   and reactivation additionally prove exact `ArchonApproverGroupName` membership, the
   24-entry password-history policy, user-existence-error suppression, and the single
   stack-derived OAuth redirect. Their final judge identity must be enabled and
   `CONFIRMED`, with no temporary-password TTL or first-login challenge. The same exact
   regional Web ACL must be associated with both API Gateway and the Cognito user pool;
   those access-enabling operations prove that live association and its fixed compatible
   rule set before any admin-user read or mutation. Emergency deactivation retains the
   exact target/identity/revocation checks but deliberately skips those
   availability-sensitive posture gates. The direct
   `ArchonApiInvokeUrl` must
   reject calls without the non-exported origin key; all clients use `ArchonApiUrl`.

7. Run the protected manual canary in
   [`../../.github/workflows/governed-canary.yml`](../../.github/workflows/governed-canary.yml)
   only against the isolated staging fixture. Its exact environment, least-privilege
   credential, pre-gate sealed plan/recovery digests, PKCE, separate rollback approval,
   and read-after-rollback contract is in
   [`../../docs/GOVERNED_CANARY.md`](../../docs/GOVERNED_CANARY.md).

The committed deployment workflow performs these checks, rotates environment-scoped
secrets, reconciles CDK, restarts ECS after versioned secret refresh, and records
sanitized evidence.
Before mutation, an existing `Archon-Registry`, stage edge stack, or stage platform stack
must already persist the exact `archonstg`/`archonprd` bootstrap CloudFormation execution
role for its region; only a genuinely absent first-deploy stack is allowed by default.
For a legacy stack, a protected manual dispatch can explicitly enable the one-time
`migrate_legacy_cloudformation_roles` path. It relaxes only preflight: the bootstrap
deployment role still requires the exact new role on every change set. After CDK
reconciliation, all three stacks must exist with those exact `RoleARN` values regardless
of that input. The account-free `archon.cloudformation-role-bindings/v1` projection is
embedded in the runtime-boundary evidence so a previous administrator execution role
cannot survive silently.
The GitHub OIDC deployment roles must also allow the pipeline's read-only live-contract
calls: `ec2:DescribeVpcs`, `ec2:DescribeSecurityGroups`,
`ec2:DescribeSecurityGroupRules`, `ec2:DescribeVpcEndpoints`,
`cloudformation:GetResource`, `iam:SimulatePrincipalPolicy`,
`elasticloadbalancing:DescribeLoadBalancers`, the
exact-ACL `wafv2:GetWebACL`, `wafv2:GetLoggingConfiguration`, and
`wafv2:GetWebACLForResource` calls, `cognito-idp:GetWebACLForResource` on the exact
`ArchonUserPoolArn`, `logs:DescribeLogGroups`, `kms:DescribeKey`, and
`kms:GetKeyRotationStatus`. The Cognito-dependent read is mandatory: promotion fails
unless the stack's exact user-pool ID and ARN resolve to the same regional Web ACL as the
API stage. These permissions are used to observe the deployed state; the pipeline does not
infer VPC, NLB, security-group, WAF, KMS, or log-retention claims from CloudFormation
outputs alone.
The compact, sorted-key `archon.regional-waf-contract/v3` receipt records
`associations.apiGatewayStage` and `associations.cognitoUserPool`, including the exact
resource ID/ARN where applicable and the identical observed Web ACL ARN. Its digest is
rechecked after the final desired-count reconciliation and retained in deployment
evidence.
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
- custom domain registration, Route 53 hosted-zone configuration, ACM certificate
  provisioning, and a branded Cognito custom domain are not deployment prerequisites; the
  regional stack uses its generated CloudFront hostname/default certificate and the
  standard Cognito managed-login domain, while cross-account ECR replication and private
  DataHub connectivity remain explicit optional environment decisions;
- a provider-issued DataHub Cloud interface service remains an environment prerequisite;
  the pipeline validates its external ownership, verified private DNS, same-region
  discovery, tenant URL binding, and exact two-AZ coverage, while resolving AWS-owned
  regional S3/DynamoDB lists itself and using a separate stack-owned Bedrock Mantle
  PrivateLink endpoint for inference;
- CloudFront protects the static and same-origin API behaviors with its global WAF; the
  separate regional WAF remains attached to both API Gateway and the Cognito user pool,
  protecting direct API callers plus managed-login/public Cognito endpoints. Its fixed
  rules deliberately exclude Cognito-incompatible ATP/ACFP groups and CAPTCHA actions.

## Stable CloudFormation outputs

The registry stack exports:

- `ArchonEcrRepositoryUri`
- `ArchonEcrRepositoryName`
- `ArchonEcrRepositoryArn`

Every edge stack exports:

- `ArchonCloudFrontWebAclArn`
- `ArchonCloudFrontWafLogKeyArn`

Every environment stack exports:

- `ArchonSpaBucketName`, `ArchonSpaKeyArn`, `ArchonEvidenceBucketName`
- `ArchonCloudFrontDistributionId`, `ArchonCloudFrontDomainName`
- `ArchonApplicationUrl`, `ArchonApiUrl`, `ArchonApiInvokeUrl`, `ArchonApiStageArn`
- `ArchonRegionalWebAclArn`, `ArchonRegionalWafLogGroupName`,
  `ArchonRegionalWafLogKeyArn`
- `ArchonUserPoolId`, `ArchonUserPoolArn`, `ArchonUserPoolClientId`,
  `ArchonApproverGroupName`
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
  `ArchonRemediationWorkerSecurityGroupId`, `ArchonVpcEndpointSecurityGroupId`,
  `ArchonBedrockMantleEndpointSecurityGroupId`
- `ArchonBedrockMantleEndpointId`, `ArchonBedrockMantleEndpointServiceName`,
  `ArchonBedrockMantleModel`, `ArchonBedrockMantleProjectId`,
  `ArchonBedrockMantleProjectArn`
- `ArchonApiTaskRoleArn`, `ArchonAuditWorkerTaskRoleArn`,
  `ArchonRemediationWorkerTaskRoleArn`
- `ArchonReadSecretArn`, `ArchonWriteSecretArn`
- `ArchonAlarmTopicArn`, `ArchonAlarmTopicKmsKeyArn`
- `ArchonAlarmDeliveryFeedbackRoleArn`, `ArchonAlarmDeliveryLogGroupName`
- `ArchonContainerImageDigest`, `ArchonSpaArtifactSha256`,
  `ArchonContainerArchiveSha256`, `ArchonLambdaArchiveSha256`
- `ArchonDeploymentWorkflowRunId`, `ArchonDeploymentWorkflowRunAttempt`,
  `ArchonCiRunId`, `ArchonReleaseSha`

Data, secrets, and each stage-scoped Bedrock Mantle project use `RETAIN`; DynamoDB and
Cognito deletion protection are enabled. Production also enables NLB deletion protection.
Destruction therefore requires an explicit, audited break-glass procedure.
