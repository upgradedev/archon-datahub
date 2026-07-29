# AWS foundation runbook

Archon's AWS foundation is a manual, idempotent GitHub Actions control plane.
It creates the stage-isolated CDK bootstrap, least-privilege CloudFormation
execution policies, runtime permissions boundaries, environment-bound GitHub
OIDC roles, governed-canary read roles, and the single regional API Gateway
logging account.

All executable verification, synthesis, deployment, drift detection, and
evidence generation runs in GitHub Actions. A workstation build or temporary
artifact is neither required nor accepted as release evidence.

## Final topology

The account contains these ten CloudFormation stack instances:

| Purpose | Region | Stack |
| --- | --- | --- |
| Staging IAM foundation | `eu-west-1` | `Archon-Staging-IAM-Foundation` |
| Production IAM foundation | `eu-west-1` | `Archon-Production-IAM-Foundation` |
| Staging GitHub deploy role | `eu-west-1` | `Archon-GitHub-Staging-Deploy-Role` |
| Production GitHub deploy role | `eu-west-1` | `Archon-GitHub-Production-Deploy-Role` |
| Governed-canary GitHub roles | `eu-west-1` | `Archon-Governed-Canary-Roles` |
| Shared API Gateway logging | `eu-west-1` | `Archon-Shared-ApiGateway-Logging` |
| Staging CDK bootstrap | `eu-west-1` | `CDKToolkit-archonstg` |
| Staging CDK bootstrap | `us-east-1` | `CDKToolkit-archonstg` |
| Production CDK bootstrap | `eu-west-1` | `CDKToolkit-archonprd` |
| Production CDK bootstrap | `us-east-1` | `CDKToolkit-archonprd` |

The stage mapping is fixed:

| Stage | Qualifier | Runtime boundary | Deploy role |
| --- | --- | --- | --- |
| Staging | `archonstg` | `archon-datahub-runtime-boundary-staging` | `archon-datahub-github-staging-deploy` |
| Production | `archonprd` | `archon-datahub-runtime-boundary-production` | `archon-datahub-github-production-deploy` |

The foundation uses the pinned CDK CLI `2.1133.0` and bootstrap template
version `32`. Each qualifier owns an independent toolkit stack, asset bucket,
container-assets repository, SSM version parameter, and bootstrap role family
in both regions. Every toolkit stack is termination protected.

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

The guard policy denies cross-stage resource names and ownership tags, shared
API Gateway account mutation, runtime-boundary removal, foundation mutation,
and identity/account administration. The production guard also denies mutation
of the staging-owned shared registry KMS key.

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
for `ec2:CreateVpcEndpoint` when private DNS is enabled. It is the only Route
53 action in any Archon policy. It is restricted to hidden
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

PrivateLink is the network boundary. The read and write DataHub tokens and
DataHub RBAC remain the authorization boundary; the endpoint does not turn a
read identity into a write identity.

S3 and DynamoDB continue to use AWS-managed gateway endpoints. The foundation
does not model changing public DataHub load-balancer addresses as customer
CIDR prefix lists.

## Shared regional resources

API Gateway has one CloudWatch logging role setting per AWS account and
region. The `Archon-Shared-ApiGateway-Logging` stack therefore owns the only
`AWS::ApiGateway::Account` binding in `eu-west-1`, the role
`archon-datahub-apigateway-cloudwatch-logs`, and its exact inline log policy.
Both stage execution policies explicitly deny `/account` mutation.

Staging owns creation and reconciliation of the shared immutable
`archon-datahub` ECR repository and `alias/archon/ecr` key. Production may
deploy only an already verified digest and cannot publish, delete, or retag
images. This is strong role and policy separation in one AWS account, but it
is not account-grade isolation. Separate AWS accounts are required for that.

No ACM permission exists. No Route 53 permission exists except the single
private-DNS association dependency above. Certificate and public hosted-zone
identifiers remain externally governed deployment inputs.

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

On a fresh account, after the four policies are exact, the script creates the
role with the exact path, description, OIDC trust, session duration, and tags.
An existing canonical role may already have any subset of the four approved
attachments, but it must have zero inline policies.

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

Staging and production each use their exact environment-bound
`AWS_DEPLOY_ROLE_ARN`. No AWS access key or other long-lived credential is
stored in GitHub.

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
   equality, reconciles all ten stacks, and requires every stack to be
   `IN_SYNC`.
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
application-stack role preflight and explicit transition state, and ten-stack
drift evidence. It contains no raw account ID, role ARN, secret, token,
password, credential, or API key and is attested before retention.
