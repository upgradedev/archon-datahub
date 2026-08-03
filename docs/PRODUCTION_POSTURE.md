# Production posture

Production posture is evidence, not a source-code claim.

The scheduled `production-posture.yml` workflow runs from the current reviewed
default-branch head through the protected `production-observer` environment.
Its read-only OIDC role:

- validates the three deployed stacks and production termination protection;
- runs the lean runtime observer with Core required at desired capacity zero;
- verifies KMS/PITR state, private versioned buckets, bounded no-VPC Lambdas,
  digest-bound Cloud images, WAF associations, CloudFront TLS/OAC and exact
  alarm actions;
- starts drift detection for Edge, Core and Judge and requires `IN_SYNC`;
- requires both production alarms not to be firing;
- emits only a sanitized receipt and attests it for 90 days.

The weekly alarm-delivery workflow uses a different protected role. It forces
the exact control-plane alarm through ALARM, proves receipt by the exact
customer-KMS SNS -> customer-KMS SQS route, deletes consumed messages and
restores OK under an EXIT trap. It does not require an external reviewer or
webhook.

A failed observation is a failed pipeline. No local scan or Codex Security
result is accepted as production posture.
