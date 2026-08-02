# AWS foundation contract

GitHub Actions assumes separate OIDC roles for deployment, observation, alarm
delivery, Cloud runtime publication, Core AMI construction and trial bootstrap.
Trust is restricted to this repository and the matching protected environment.

The active application topology is Edge, zero-idle Core and Judge. Foundation
policies must not retain permissions that exist only for an always-on container
cluster, load balancer, NAT gateway or VpcLink.

Required specialized boundaries include:

- deploy: CloudFormation/CDK assets and exact three-stack resources;
- observer: read-only CloudFormation, CloudFront, WAF, Cognito, Lambda,
  DynamoDB, S3, Auto Scaling, CloudWatch and drift detection;
- alarm proof: DescribeStacks, DescribeAlarms/SetAlarmState and receive/delete
  on only the production proof queue;
- Cloud publisher: idempotent ownership of only
  `archon-datahub-cloud-runtime-v2`;
- trial bootstrap: DescribeStacks, Get/PutSecretValue for only the reader and
  writer outputs, plus secrets-key KMS Decrypt/GenerateDataKey constrained
  through Secrets Manager;
- Core AMI: temporary no-ingress builder resources with exact request tags and
  teardown, followed by immutable evidence.

## Exact stage deployment authority

Before any AWS trust is acquired, the protected deployment job proves that
`AWS_DEPLOY_ROLE_ARN` equals the exact foundation-owned
`archon-datahub-github-<stage>-deploy` role in the configured 12-digit account.
The validated ARN is then passed to the OIDC credential action, which also
pins the allowed account ID and clears inherited credentials.

The role-binding validator checks exactly three bindings for the selected stage:

- `Archon-<stage>-Edge` in `us-east-1`;
- `Archon-<stage>-Core` in `eu-west-1`;
- `Archon-<stage>-Judge` in `eu-west-1`.

Stage stacks use `archonstg` for staging and `archonprd` for production.
A preflight may report an absent stage stack so the first deployment can create
it, but role migration is never implicit. After CDK deploys Edge, Core and
Judge, the final check uses `ALLOW_ABSENT=false` and
`ALLOW_ROLE_MIGRATION=false`; every binding must be present and exact.

## Bounded CloudFormation drift evidence

Foundation reconciliation uses bounded CloudFormation drift polling with a
hard 900-second wall-clock deadline. SDK retries are fixed and every accepted
result is tied to the exact stack incarnation plus a monotonic
`LastCheckTimestamp` lower bound. Raw provider responses are deleted on every
exit. Coverage is recorded as `cloudformation-supported-resources`; timeout,
malformed, stale, indeterminate and drifted states all fail closed.

`contracts/aws-foundation-v1.json` and the rendered policy validator are the
machine-readable authority. Policy changes are promoted and verified in CI;
manual console grants are not evidence.

The sealed staging IAM incident is closed. Its authoritative
`contracts/aws-incident-recovery-v1.json` record has status
`recovered-delete-complete-cleanup-proven`. Exact-master run `30582684638`
executed exactly one `STANDARD` `DeleteStack`; canonical target absence and
cleanup were proven, and the short-lived recovery authorization was revoked.
Artifact `8775321544` and GitHub attestation `38051531` bind the sanitized
recovery receipt. The cleanup follower `30582939537` skipped on success. This is
retained evidence, not permission to rerun recovery against the now-absent
target; future reconciliation uses the ordinary idempotent foundation workflow.

## Protected foundation-policy version migrations

Foundation managed-policy changes are explicit protected transactions, never an
implicit side effect of reconciliation. The reviewed assets-policy target keeps
the CloudFormation drift reads `cloudformation:DetectStackResourceDrift` and
`cloudformation:BatchDescribeTypeConfigurations` and adds only the
contract-listed S3 resource-handler and IAM attachment reads required for a
complete drift result.

From the exact signed `master` revision, the repository owner dispatches
`.github/workflows/aws-foundation-policy-migration.yml` with the confirmation
`MIGRATE EXACT FOUNDATION ASSETS POLICY`. The entry, driver and automatic or
manual cleanup are serialized with the AWS control-plane lock and `queue: max`.
The driver verifies the canonical live default, creates and reads back one
nondefault version, performs one default-version switch, retains the former
default as the rollback target, and revokes its short-lived authorization on
every terminal path.

A failed or cancelled transaction is classified from the exact parent run and
attempt. Recovery installs a fresh rollback-only grant, restores the verified
former default when required, deletes only the reviewed new version, and then
proves the temporary grant absent. The checksum-sealed receipt excludes account
identifiers and role ARNs, and it never stores raw IAM documents.

## Identity-policy migration and Cloud runtime publisher handoff

The current `archon-aws-foundation-identity` default is v1. Before Foundation
can create the two Cloud-trial roles and the publisher role, dispatch
`.github/workflows/aws-foundation-cloud-runtime-publisher-policy-migration.yml`
from `master` with the exact current master SHA and confirmation
`MIGRATE EXACT CLOUD RUNTIME PUBLISHER IDENTITY POLICY`. The transaction derives
and verifies the reviewed v1 and v2 policy digests, creates v2 as nondefault,
reads it back canonically, performs one default switch, retains v1 for rollback,
and always removes its twenty-minute recovery authorization. Its receipt is
checksum-sealed and attested. Do not run Foundation until the migration and its
automatic cleanup both succeed.

Foundation creates `GitHubDataHubCloudTrialRole` in both matching
`Archon-GitHub-<Stage>-Deploy-Role` stacks and creates
`CloudRuntimeImagePublisherRole` only in production. Existing deploy roles and
prior outputs remain unchanged. Each stage adds
`GitHubDataHubCloudTrialRoleArn` and `GitHubDataHubCloudTrialRoleName`;
production additionally adds `CloudRuntimeImagePublisherRoleArn` and
`CloudRuntimeImagePublisherRoleName`.

The publisher trust is exact: protected `production` environment, `master`, this
repository, and workflow name `DataHub Cloud runtime OCI v2`. IAM uses the
supported `token.actions.githubusercontent.com:workflow` claim. The workflow
separately proves its full `github.workflow_ref` before requesting OIDC. The
session request is 1,800 seconds and the role can authenticate to ECR, create the
single repository only with the required ownership tags, publish/inspect images,
and delete bounded image tags. It cannot delete or re-policy the repository,
change lifecycle configuration, or use IAM/KMS.

The sanitized operational-role receipt is exact and ordered:
`judge-staging`, `datahub-cloud-trial-staging`, `judge-production`,
`datahub-cloud-trial-production`, `cloud-runtime-publisher`,
`posture-observer`, `runtime-read`, and `paging-test`. Both trial-role bindings
participate in the combined binding digest.

After a successful Foundation run, wire only the verified in-memory outputs:

- `steps.reconcile.outputs.datahub_cloud_trial_staging_role_arn` to staging
  `AWS_DATAHUB_CLOUD_TRIAL_ROLE_ARN`;
- `steps.reconcile.outputs.datahub_cloud_trial_production_role_arn` to
  production `AWS_DATAHUB_CLOUD_TRIAL_ROLE_ARN`;
- `steps.reconcile.outputs.cloud_runtime_publisher_role_arn` to production
  `AWS_CLOUD_RUNTIME_IMAGE_ROLE_ARN`;
- `steps.core_ami_foundation.outputs.build_role_arn` and
  `steps.core_ami_foundation.outputs.instance_profile` to staging
  `AWS_CORE_AMI_BUILD_ROLE_ARN` and
  `AWS_CORE_AMI_BUILDER_INSTANCE_PROFILE`.

Do not persist an environment or JSON handoff file. To pass a value from the
current shell without placing it in command history, omit `--body` and use
standard input, for example:
`printf '%s' "$value" | gh variable set NAME --env ENV -R upgradedev/archon-datahub`.
Then publish by pushing the intended release commit to `master`, or dispatch the
workflow manually. Manual dispatch accepts no revision input and is bound to the
exact current `master` workflow/source SHA, so it cannot reinterpret a release SHA.

Safe dispatch order for one exact signed master SHA is:

1. complete any pending assets-policy migration;
2. run the identity v1-to-v2 migration above;
3. run the Core AMI control-policy v2-to-v3 migration;
4. run AWS Foundation with `BOOTSTRAP_CDK_FOUNDATION`;
5. wire the verified staging/production trial-role, production publisher-role,
   and staging Core AMI role/profile outputs;
6. publish the companion and Cloud runtime images for the exact release push;
7. build the Core AMI from the exact signed companion push.

All steps share the AWS control-plane locks and must be allowed to finish their
mandatory cleanup before the next mutation starts.
