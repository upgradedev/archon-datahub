# AWS foundation runbook

Archon's AWS foundation is a manual, idempotent GitHub Actions control plane.
It creates the stage-isolated CDK bootstrap, least-privilege CloudFormation
execution policies, runtime permissions boundaries, environment-bound GitHub
OIDC roles, governed-canary read roles, and either manages or explicitly pins
the single regional API Gateway logging account without taking it over.

All executable verification, synthesis, deployment, drift detection, and
evidence generation runs in GitHub Actions. A workstation build or temporary
artifact is neither required nor accepted as release evidence.

## Final topology

Nine CloudFormation stack instances are always managed by Archon. A tenth
stack exists only in `foundation-managed` API Gateway mode:

| Purpose | Region | Stack |
| --- | --- | --- |
| Staging IAM foundation | `eu-west-1` | `Archon-Staging-IAM-Foundation` |
| Production IAM foundation | `eu-west-1` | `Archon-Production-IAM-Foundation` |
| Staging GitHub deploy role | `eu-west-1` | `Archon-GitHub-Staging-Deploy-Role` |
| Production GitHub deploy role | `eu-west-1` | `Archon-GitHub-Production-Deploy-Role` |
| Governed-canary GitHub roles | `eu-west-1` | `Archon-Governed-Canary-Roles` |
| Shared API Gateway logging (`foundation-managed` only) | `eu-west-1` | `Archon-Shared-ApiGateway-Logging` |
| Staging CDK bootstrap | `eu-west-1` | `CDKToolkit-archonstg` |
| Staging CDK bootstrap | `us-east-1` | `CDKToolkit-archonstg` |
| Production CDK bootstrap | `eu-west-1` | `CDKToolkit-archonprd` |
| Production CDK bootstrap | `us-east-1` | `CDKToolkit-archonprd` |

`foundation-managed` therefore produces ten managed stacks. `external-pinned`
produces nine managed stacks plus one pinned external account binding; the
`Archon-Shared-ApiGateway-Logging` managed stack must be absent in that mode.
The evidence and workflow summary report the exact managed-stack count instead
of describing the external binding as a CloudFormation stack.

The stage mapping is fixed:

| Stage | Qualifier | Runtime boundary | Deploy role |
| --- | --- | --- | --- |
| Staging | `archonstg` | `archon-datahub-runtime-boundary-staging` | `archon-datahub-github-staging-deploy` |
| Production | `archonprd` | `archon-datahub-runtime-boundary-production` | `archon-datahub-github-production-deploy` |

The foundation resolves the AWS CDK CLI version from the
exact committed `infra/aws/package-lock.json` entry for `node_modules/aws-cdk`;
the installed CLI version must exactly match that decoded lock entry. The
bootstrap template is pinned to version `32`. Each qualifier owns an independent
toolkit stack, asset bucket, container-assets repository, SSM version parameter,
and bootstrap role family in both regions. Every toolkit stack is termination
protected.

The canonical bootstrap template is patched four times. Each stage-and-region
variant permits its deploy role to create or update only the exact application
stacks for that target, only with the matching bootstrap CloudFormation
execution role, and only through the named `cdk-deploy-change-set`. It cannot
delete application stacks.

## Quota-safe execution-policy isolation

[`cdk-execution-policy.yml`](../infra/aws/foundation/cdk-execution-policy.yml)
is a parameterized CloudFormation template and must never be submitted to IAM
as an unresolved policy document. CloudFormation deploys it once for staging
and once for production.

The readable source is larger than CloudFormation's 51,200-byte inline
`TemplateBody` limit. Both ordinary CI and the protected foundation workflow
therefore use checksum-pinned AWS CloudFormation Rain `v1.24.4` plus the
dependency-free
[`render-canonical-flow-yaml.mjs`](../scripts/render-canonical-flow-yaml.mjs)
emitter to render the unchanged template as canonical flow-style YAML below
`RUNNER_TEMP`. The emitter removes quotes only from a strict ASCII-safe scalar
subset and leaves every other scalar JSON-quoted. Flow-style YAML removes
transport overhead without removing resources, policy statements,
descriptions, outputs, or other template semantics. The renderer rejects
non-runner use, symlinks, output outside `RUNNER_TEMP`, malformed or empty
templates, Rain JSON semantic round-trip drift, and output above 51,200 bytes.

The protected workflow hashes the rendered bytes before OIDC and uses those
exact bytes for both `ValidateTemplate` and deployment. After each stage
deploys, CloudFormation's `GetTemplate --template-stage Original` body is
canonicalized to JSON with checksum-pinned `mikefarah/yq` `v4.47.2` and its
semantic SHA-256 must equal the pre-OIDC canonical JSON SHA-256 before the
attested foundation evidence can be sealed.
The evidence records both the exact flow-YAML transport hash and the canonical
semantic hash.

Each stage receives ten customer-managed execution policies:

- `guard`
- `identity`
- `data`
- `state`
- `observability`
- `compute`
- `network`
- `endpoint`
- `delivery`
- `edge`

The `eu-west-1` bootstrap execution role attaches exactly nine policies:
`guard`, `identity`, `data`, `state`, `observability`, `compute`, `network`,
`endpoint`, and `delivery`. The `us-east-1` role attaches exactly `guard` and
`edge`.
Every policy is independently checked against IAM's 6,144-byte managed-policy
quota. No policy permits `Action: "*"`, a service-wide `service:*` allow, or
`AdministratorAccess`.

The ordinary pull-request CI also generates and seals the exact locked CDK
bootstrap template for both stages and both regions, without AWS credentials.
This rejects template drift before merge and dispatch. After the manual
environment gate, the protected foundation workflow reuses that same verifier
before requesting OIDC credentials or making any AWS call.

The guard policy denies opposite-stage S3 bucket and object names and
opposite-stage ownership tags, plus shared API Gateway account mutation,
runtime-boundary removal, foundation mutation, and identity/account
administration. The production guard also denies mutation of the staging-owned
shared registry KMS key.

The inline-template renderer parses every direct or `Fn::Sub` resource ARN under
an IAM policy document without splitting colons inside substitution tokens. It
accepts only a literal AWS partition or an exact `AWS::Partition` reference and
a literal lowercase service token; wildcard, substituted, malformed, or
incomplete service ARNs fail closed under
[AWS IAM Resource ARN rules](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html).
Deterministic negative fixtures cover direct and intrinsic substitutions,
including variable-map evasions, before the foundation workflow requests AWS
credentials.

## Runtime permissions boundary

The CDK stage applies the exact runtime boundary to every synthesized
`AWS::IAM::Role`. Each role still needs its own narrow identity policy; the
boundary is only an upper limit.

The only approved AWS managed policy is:

- `AWSLambdaBasicExecutionRole`

ECS task execution roles use the narrower CDK-synthesized inline ECR, logging,
and secret-access statements; they do not attach
`AmazonECSTaskExecutionRolePolicy`.

[`verify-aws-runtime-boundary.mjs`](../scripts/verify-aws-runtime-boundary.mjs)
compares the complete synthesized role-action inventory with the contract. It
fails when an action is uncovered, when a boundary action is unused, when a
managed policy is unapproved, or when an approved managed policy is absent
from synthesis. CI runs the proof independently for staging and production.
The live verifier then checks exact boundary ARNs, role tags, and IAM-stack
drift.

## DataHub PrivateLink network boundary

DataHub access uses one same-region interface VPC endpoint whose service name
is an explicit CloudFormation deployment input. Private DNS is enabled, and a
dedicated endpoint security group accepts HTTPS only from the API, audit
worker, and remediation worker security groups.

The execution `endpoint` policy exposes only the EC2 read and mutation actions
needed by the synthesized PrivateLink resources. DataHub endpoint creation requires exact
`Application=archon-datahub` and stage `Environment` request tags. Existing
endpoint modification, deletion, and tagging are restricted to regional
`vpc-endpoint/*` resources carrying those exact ownership tags. There is no
general EC2 write grant. The endpoint service must be same-region and its
owner must differ from the deployment account.

AWS documents `route53:AssociateVPCWithHostedZone` as a dependent permission
for `ec2:CreateVpcEndpoint` when private DNS is enabled. It is the only
PrivateLink-related Route 53 action in the endpoint policy. It is restricted to hidden
`arn:aws:route53:::hostedzone/*` resources and the documented multi-valued
condition:

```text
VPCId=vpc-*,VPCRegion=eu-west-1
```

AWS explicitly states that `route53:VPCs` does not accept a VPC ARN; using one
would make the condition ineffective. The generated VPC ID is not known when
the foundation policy is created, so the remaining scope is bounded by the
single association action, `eu-west-1`, the caller-account CloudFormation
execution role, the exact stage stack/change-set gate, and the absence of
direct trust or any other Route 53 permission. Modify and delete have no
documented Route 53 dependency, so `DisassociateVPCFromHostedZone` is not
granted.

The separate public-viewer DNS statements are parameter-bound to one
account-owned hosted zone and one exact stage hostname. They permit only the
certificate-validation CNAME and the CloudFront A/AAAA aliases described
below; they do not broaden the PrivateLink association boundary.

PrivateLink is the network boundary. The read and write DataHub tokens and
DataHub RBAC remain the authorization boundary; the endpoint does not turn a
read identity into a write identity.

S3 and DynamoDB continue to use AWS-managed gateway endpoints. The foundation
does not model changing public DataHub load-balancer addresses as customer
CIDR prefix lists.

## Shared regional resources

API Gateway has one CloudWatch logging role setting per AWS account and
region. The foundation resolves that singleton in exactly one of two modes:

- In `foundation-managed`, the protected digest pin is empty and the account
  binding is either empty or already names
  `archon-datahub-apigateway-cloudwatch-logs`. The
  `Archon-Shared-ApiGateway-Logging` stack creates or reconciles the
  `AWS::ApiGateway::Account` resource, role, and exact inline log policy.
- In `external-pinned`, an existing non-Archon binding must be a strict
  same-account IAM role ARN and its exact SHA-256 must match the protected
  `aws-foundation` variable `AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256`. The
  managed stack must be absent. This path performs no API Gateway account mutation,
  no IAM role inspection, and no takeover.

A foreign binding without an exact pin fails before mutation and exposes only
its SHA-256 for deliberate operator pinning. A malformed or cross-account ARN,
a stale or mismatched pin, a changed binding during the run, or coexistence
with the managed stack also fails closed. The raw external ARN is masked,
revalidated unchanged at the shared and drift gates, and never enters retained
evidence; the receipt records only `pinned-and-unchanged` plus its binding
hash. Archon does not claim that the external role's trust or permissions were
verified, so the shared-account owner remains responsible for CloudWatch log
delivery. Both stage execution policies explicitly deny `/account` mutation.

Staging owns creation and reconciliation of the shared immutable
`archon-datahub` ECR repository and `alias/archon/ecr` key. Production may
deploy only an already verified digest and cannot publish, delete, or retag
images. This is strong role and policy separation in one AWS account, but it
is not account-grade isolation. Separate AWS accounts are required for that.

The stage execution boundary admits only the exact ACM and Route 53 operations needed
for the reviewed CloudFront viewer contract. The `us-east-1` edge stack may create,
tag, describe, and retire its stage-owned exact-name certificate, while the regional
platform stack may reconcile only A/AAAA aliases for the configured name in the
account-owned public hosted zone. The existing single Route 53 private-DNS association
permission remains separately constrained to the caller-account VPC in `eu-west-1`.
Domain registration is never delegated to CloudFormation or GitHub OIDC:
`route53domains:*` remains denied. The public hosted-zone ID and exact stage hostnames are
protected-environment inputs, and every live certificate/zone/record read is revalidated
before promotion.

## Initial foundation identity

The AWS account must already contain the GitHub OIDC provider:

```text
arn:aws:iam::<AWS_ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com
```

The initial role is `archon-datahub-github-foundation`. It trusts only:

```text
repo:upgradedev/archon-datahub:environment:aws-foundation
```

The role has zero inline policies and exactly these attached customer-managed
policies:

- `archon-aws-foundation-control`
- `archon-aws-foundation-assets`
- `archon-aws-foundation-identity`
- `archon-aws-foundation-attachments`

[`github-actions-foundation-policy.json`](../infra/aws/foundation/github-actions-foundation-policy.json)
is a reviewed, non-attachable source bundle. It deliberately exceeds the shape
of one deployable managed policy. The renderer resolves
`${aws:PrincipalAccount}`, splits the bundle into the four named documents,
rejects any document above 6,144 bytes, and writes pipeline output only below
`RUNNER_TEMP`.

An authorized AWS administrator performs the one-time bootstrap after the
reviewed commit is merged:

```bash
EXPECTED_ACCOUNT_ID=<12-digit-account-id> \
EXPECTED_HEAD_SHA=<exact-merged-master-sha> \
CONFIRMATION=BOOTSTRAP_FOUNDATION_POLICIES \
bash scripts/bootstrap-aws-foundation-role.sh
```

The bootstrap is deliberately policy-first and does not create workstation
files. It verifies the clean, exact `master` checkout and the existing GitHub
OIDC provider, then renders and verifies all four managed policies in memory
before it inspects or creates the role. A missing policy is created; a
mismatched existing policy is never overwritten.

### Protected foundation-policy version migrations

Foundation run `30586169834` established the first two CloudFormation control-plane
dependencies, `cloudformation:DetectStackResourceDrift` and
`cloudformation:BatchDescribeTypeConfigurations`. Those actions were migrated to
`archon-aws-foundation-control` by successful protected run `30596065876` and remain
unchanged.

Exact-master foundation run `30600085506` then completed reconciliation and failed closed
at the first drift check with `DETECTION_FAILED`. The public CloudFormation resource-provider
schemas identify the missing read surface: `iam:ListEntitiesForPolicy` for
`AWS::IAM::ManagedPolicy`, plus 15 bucket-configuration reads for `AWS::S3::Bucket`.
The source adds those 16 read-only actions in two isolated statements. Both statements use
the same exact four stage-policy or bootstrap-bucket resources as their existing reconciliation
statements; neither grants object reads nor a wildcard resource.

The two statements are deliberately placed together in the previously untouched
`archon-aws-foundation-assets` shard. IAM evaluates the union of all four policies attached to
the foundation role, so this preserves the exact effective authorization while keeping the
migration an atomic, proven one-policy 1→2 transaction. The protected workflow requires the
signed exact current `master`, green CI, CodeQL, and workflow-security gates, the literal
`MIGRATE EXACT FOUNDATION ASSETS POLICY` confirmation, and separate `aws-foundation` and
`governed-canary-recovery` approvals. It derives the live previous document by removing only
the two reviewed statements, creates and canonically reads a non-default version, changes the
default exactly once, and retains the previous version as the rollback point.

A temporary 20-minute inline grant targets only the exact assets-policy ARN and is removed
after three consecutive baseline reads. The cleanup follower binds itself to the exact parent
attempt. An incomplete mutation gets a fresh rollback-only grant; a completed migration whose
evidence step failed remains migrated while authorization is revoked. Both privileged locks use
`queue: max`. Retained evidence contains only canonical document digests, version IDs, state,
and revocation proof; it excludes account identifiers, ARNs, and raw IAM documents.
On a fresh account, after the four policies are exact, the script creates the
role with the exact path, description, OIDC trust, session duration, and tags.
On an existing account, a canonical role may already have any subset of the
four approved attachments, but it must have zero inline policies.

The current policyless role is a single, explicitly contracted legacy adoption
case. Before any role update, the script requires zero inline and zero attached
policies and verifies its exact non-privileged legacy state:

- description
  `GitHub OIDC role for the Archon DataHub CDK foundation bootstrap pipeline`;
- tags `Application=archon-datahub`, `Environment=foundation`, and
  `ManagedBy=github-actions`; and
- the same exact provider, audience, subject, action, and conditions as the
  canonical trust, differing only by the missing canonical `Sid`.

Only then does it use the exact IAM trust-policy, role-description, and role-tag
update operations to converge that role to the declarative canonical shape and
reverify it before attaching policies. A retry interrupted between those three
non-privileged metadata updates accepts only components that are independently
equal to either the contracted legacy value or the canonical value, still with
zero policies. Every other mismatch fails closed. The script never detaches an
unexpected policy or creates an inline policy. It finally attaches the four
exact policies idempotently and verifies six-policy headroom under the
ten-policy role quota.

[`github-actions-foundation-role.yml`](../infra/aws/foundation/github-actions-foundation-role.yml)
is the declarative mirror of the resulting role. Its fixed managed-policy ARNs
are intentionally valid only after the policy-first phase; it is not the first
operation for a fresh account. Once bootstrapped, the foundation role cannot
mutate its own trust or policy bundle.

The legacy shared role `archon-datahub-github-deploy` must not exist.

## Governed-canary roles and variables

`Archon-Governed-Canary-Roles` creates three short-lived roles:

| Environment | GitHub variable | Role | AWS reads |
| --- | --- | --- | --- |
| `governed-canary-prepare` | `AWS_CANARY_PREPARE_ROLE_ARN` | `archon-datahub-github-governed-canary-prepare` | Exact `Archon-staging` stack |
| `governed-canary` | `AWS_CANARY_APPROVAL_ROLE_ARN` | `archon-datahub-github-governed-canary-approval` | Exact staging stack and tagged staging Cognito approver membership |
| `governed-canary-recovery` | `AWS_CANARY_RECOVERY_ROLE_ARN` | `archon-datahub-github-governed-canary-recovery` | Exact `Archon-staging` stack |

Each role trusts only its table's exact GitHub environment subject. The roles
have no managed policies and no AWS mutation permission. Canary mutation and
recovery are application-mediated and remain protected by their separate
GitHub approval environments. The rollback job makes no AWS call and therefore
does not receive a redundant AWS role.

After the foundation succeeds, set each variable to:

```text
arn:aws:iam::<AWS_ACCOUNT_ID>:role/<role-name-from-the-table>
```

The corresponding environments also require the exact account and
`eu-west-1` region variables already checked by their workflows.

## Operational roles and variables

The existing staging and production deploy-role stacks also own the
least-privilege roles used by non-deployment operational pipelines:

| GitHub environment | Variable | Exact role |
| --- | --- | --- |
| `judge-access-staging` | `AWS_JUDGE_USER_ROLE_ARN` | `archon-staging-judge-user` |
| `judge-access-production` | `AWS_JUDGE_USER_ROLE_ARN` | `archon-production-judge-user` |
| `production-observer` | `AWS_READ_ROLE_ARN` | `archon-production-posture-observer` |
| `production-observer` | `AWS_RUNTIME_READ_ROLE_ARN` | `archon-production-runtime-read` |
| `production-paging-test` | `AWS_PAGING_TEST_ROLE_ARN` | `archon-production-paging-test` |

Every role trusts only its exact GitHub environment subject, has a
3600-second maximum session duration, one bounded inline policy, no attached
managed policy, and no deployment permission. The foundation evidence records
each policy digest and an account-redacted role binding. The environment
variables use
`arn:aws:iam::<AWS_ACCOUNT_ID>:role/<exact-role-name-from-the-table>`.

## GitHub environment contract

The `aws-foundation` environment is configured with:

- admin bypass disabled;
- exactly one `User` reviewer, repository owner `upgradedev`;
- solo-owner self-review enabled with `prevent_self_review=false`;
- exactly one custom branch policy, `master`; and
- no wait timer or second reviewer.

Required `aws-foundation` variables:

| Variable | Value |
| --- | --- |
| `AWS_ACCOUNT_ID` | Exact 12-digit account ID |
| `AWS_REGION` | `eu-west-1` |
| `AWS_FOUNDATION_ROLE_ARN` | `arn:aws:iam::<AWS_ACCOUNT_ID>:role/archon-datahub-github-foundation` |
| `STAGING_CLOUDFRONT_DOMAIN_NAME` | Exact lowercase staging hostname |
| `STAGING_CLOUDFRONT_HOSTED_ZONE_ID` | Exact public hosted-zone ID owning the staging hostname |
| `PRODUCTION_CLOUDFRONT_DOMAIN_NAME` | Exact lowercase production hostname, distinct from staging |
| `PRODUCTION_CLOUDFRONT_HOSTED_ZONE_ID` | Exact public hosted-zone ID owning the production hostname |

Staging and production each use their exact environment-bound
`AWS_DEPLOY_ROLE_ARN`. No AWS access key or other long-lived credential is
stored in GitHub.

Each of those environments also supplies:

| Variable | Contract |
| --- | --- |
| `ARCHON_CLOUDFRONT_DOMAIN_NAME` | Distinct exact lowercase hostname for the stage |
| `ARCHON_CLOUDFRONT_HOSTED_ZONE_ID` | Raw ID of the account-owned public Route 53 zone containing that hostname |

The edge stack creates the Amazon-issued P-256 certificate in `us-east-1`; no
certificate ARN is stored as a mutable GitHub variable. The deploy workflow reads the
edge output, proves the certificate is issued and exact-name scoped, and passes that ARN
to the regional platform stack.

## Reconcile and deploy sequence

1. Merge the reviewed foundation commit to `master`.
2. Run the one-time administrator bootstrap above.
3. Dispatch **Bootstrap AWS foundation** with:

   ```text
   expected_head_sha=<exact lowercase 40-character master SHA>
   confirmation=BOOTSTRAP_CDK_FOUNDATION
   ```

4. The workflow verifies the protected GitHub control plane, synthesizes and
   proves both runtime boundaries, assumes the foundation role through OIDC,
   validates the four attached foundation policies by exact canonical
   equality, then resolves the API Gateway ownership mode. It either
   reconciles ten managed stacks or verifies nine managed stacks plus one
   pinned external account binding, and requires every managed stack to be
   `IN_SYNC` and the external binding, when selected, to remain unchanged.
5. Configure the deploy-role and governed-canary role variables from the
   resulting exact role names.
6. Dispatch the immutable deployment workflow. It shares concurrency group
   `archon-aws-control-plane`, so foundation and application mutations cannot
   overlap.

Existing application stacks without the exact stage bootstrap
CloudFormation-execution `RoleARN` are reported as `migration-required`.
Foundation creation remains possible. The sealed foundation receipt and the
workflow summary surface
`foundation-complete-deploy-migration-required`; the receipt also includes the
number of affected bindings, while the affected entries retain
`requires-explicit-deploy-migration`. Any other preflight result remains a
fail-closed error. Deployment must then perform the explicit, approved
migration; its final postchecks run with role migration and absence disabled
and always require every persisted stack `RoleARN` to be exact. With no legacy
binding, the receipt instead surfaces `ready-for-deploy`.

The final foundation artifact contains sanitized digests, four bootstrap
variant hashes, execution-policy bundle hashes, role-binding hashes, the
application-stack role preflight and explicit transition state, and drift
evidence for the exact nine or ten managed stacks. External mode additionally
records one takeover-forbidden, no-mutation binding as pinned and unchanged.
It contains no raw account ID, role ARN, secret, token, password, credential,
or API key and is attested before retention.

## Bounded CloudFormation drift polling

The AWS CLI has no `stack-drift-detection-complete` waiter. The protected
workflow therefore follows the documented CloudFormation API sequence: it
starts `DetectStackDrift`, retains the opaque detection ID only in a mode-0600
file below `RUNNER_TEMP`, and polls
[`DescribeStackDriftDetectionStatus`](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeStackDriftDetectionStatus.html).
The published
[AWS CLI CloudFormation waiter list](https://docs.aws.amazon.com/cli/latest/reference/cloudformation/wait/)
is also a negative contract: the nonexistent drift waiter is forbidden by CI.

Polling is fail-closed under one hard 900-second wall-clock deadline. Every AWS
call is clamped to the exact remaining time by `timeout`, SDK retries are fixed
to one attempt, and success is rechecked against the deadline before any raw or
sealed result is published. Each stack permits at most 120 status reads with a
two-second delay and at most three consecutive API failures. Every CLI call
also uses a five-second connection timeout and a 15-second read timeout.
Provider stderr is discarded. Each successful response
must bind both the exact in-memory detection ID and expected
partition/region/account/stack ARN prefix, use one of the three documented
detection statuses, and finish as `DETECTION_COMPLETE`, `IN_SYNC`, with an
integer drifted-resource count of zero. A failed, unknown, malformed, mismatched,
drifted, or timed-out result cannot create success evidence.

The terminal response contributes its exact stack ARN/UUID and detection
timestamp. The follow-up resource query targets that exact ARN, requires a real
`StackResourceDrifts` array, rejects older timestamps and accepts only exact
stack-ID entries whose status is `IN_SYNC`; `NOT_CHECKED` is not converted into
a pass. A final `DescribeStacks` read must still report the same stack ID,
`IN_SYNC`, and a `LastCheckTimestamp` equal to the exact detection timestamp.
All raw status, resource, and final-stack JSON is mode 0600 and deleted on every
success or failure exit. The sealed `drift.json` records poll attempts, elapsed
seconds, returned resource count, stack-incarnation binding, and
`coverage: cloudformation-supported-resources`. Resources that CloudFormation
does not support remain outside this claim and are never described as globally
drift-free.

Exact-master foundation run
[`30596290772`](https://github.com/upgradedev/archon-datahub/actions/runs/30596290772)
completed every reconciliation group and failed at the first drift gate because
the prior implementation invoked the unsupported waiter. It produced no
sanitized failure artifact because that command was outside the managed-stack
diagnostic wrapper; this limitation is recorded rather than fabricating a
CloudFormation failure event. The run remains durable failure evidence for the
portability fix, and the next exact-master run must provide the sealed positive
drift receipt.
## Sanitized managed-stack failure evidence

A managed foundation stack rejected in a failed preflight state, or a managed
stack command that fails, triggers a bounded diagnostic query for that exact
allowlisted stack only. Original managed CloudFormation and CDK command
stdout and stderr are suppressed before capture. The reconciler reads at most 100
recent CloudFormation events in their API-provided newest-first order, while
sanitizer input remains hard-capped at 1,048,576 bytes. It
selects the newest failed event whose safe reason category is not
`dependency-failure`; `unknown` remains eligible because it may be the true
root cause. Only when every failed event is `dependency-failure` does it
fall back to the newest failed event. The chosen event then passes the existing
fail-closed identity and reason validation before one canonical
`cfn-failure.json` record is written containing only an allowlisted stack label, stack
status, logical resource ID, resource type and status, a safe reason category,
and a SHA-256 over exactly those canonical allowlisted diagnostic fields.

The diagnostic path never stores, prints, or hashes the raw CloudFormation
reason, stack name or ARN, account identifier, URL, request token, physical
resource ID, or denied action. It seals inside a private staging directory,
requires the exact recursive inventory of two root regular non-symlink files,
and only then atomically publishes the final directory.

After the credential-clear step succeeds, the validator first proves that all
four AWS credential environment variables are empty. It then repeats the exact
recursive inventory and checksum checks and requires canonical JSON bytes. It
recomputes the diagnostic digest from the seven safe fields. Only `cfn-failure.json` and
`SHA256SUMS` are passed as explicit upload paths and retained for 90 days. A
missing, malformed, oversized, non-canonical, non-allowlisted, or digest-mismatched
diagnostic fails closed and is not uploaded.
This evidence is observational only. The workflow does not delete, recreate, or
continue rollback for a failed stack. Recovery remains a separate, explicit
operator decision after the exact state and sanitized evidence are reviewed.
## Explicit sealed-incident recovery

Foundation failure diagnostics remain observational: this workflow never
automatically deletes, recreates, or continues rollback. The one reviewed
historical `staging-iam` exception is a separate CI-only, two-environment
control plane with immutable incident coordinates, short-lived exact-stack
authorization, mandatory revocation, and sanitized attested evidence. Its
status is `recovered-delete-complete-cleanup-proven`. Cleanup run `30571619440`
and three fail-closed recovery attempts established the historical evidence and
revocation controls. Exact-master run `30582684638` then passed canonical policy
readback, issued exactly one `STANDARD` `DeleteStack`, proved the original stack
ID reached `DELETE_COMPLETE` with no active sealed stack name, revoked the
temporary policy, and proved canonical absence. Artifact `8775321544` and GitHub
attestation `38051531` retain the sanitized receipt; cleanup follower
`30582939537` skipped on success. The deleted staging IAM foundation can now be
recreated only through the ordinary idempotent foundation workflow. See
[`AWS_INCIDENT_RECOVERY.md`](AWS_INCIDENT_RECOVERY.md) and
`contracts/aws-incident-recovery-v1.json`.

Foundation holds the outer `archon-aws-control-plane` lock and its reconciliation
job also holds `archon-governed-canary-mutation-recovery`. This outer-to-inner
order prevents its governed-canary role-stack reconciliation from racing
fixture, canary, compensation, or explicit incident recovery mutations without
the parent-child deadlock an inner child would create by taking the outer lock.
