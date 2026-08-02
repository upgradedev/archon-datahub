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
