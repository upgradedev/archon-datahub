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

`contracts/aws-foundation-v1.json` and the rendered policy validator are the
machine-readable authority. Policy changes are promoted and verified in CI;
manual console grants are not evidence.
