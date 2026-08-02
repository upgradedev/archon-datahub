# Archon AWS judge runtime

This directory defines the low-cost dual-runtime AWS reference architecture.

## Stacks

- `Archon-<stage>-Edge` (`us-east-1`): ACM certificate and CloudFront WAF.
- `Archon-<stage>-Core` (`eu-west-1`): isolated, single-host DataHub Core
  Auto Scaling Group with `min=0`, `desired=0`, `max=1`, plus Step
  Functions lifecycle and DynamoDB lease/job state.
- `Archon-<stage>-Judge` (`eu-west-1`): CloudFront OAC + private S3 SPA,
  API Gateway, Cognito, regional WAF, six bounded Lambdas, DynamoDB session
  state, checkpoint storage, encrypted failure routing and alarms.

There is no EKS, always-on container service, load balancer, NAT gateway or
VpcLink. DataHub Cloud work runs in three digest-pinned image Lambdas. DataHub
Core compute exists only for an authenticated session and returns to zero after
30 minutes idle or the two-hour hard TTL.

## Promotion

Do not build or deploy from a workstation. GitHub Actions is the control plane:

1. `ci.yml` builds and attests exact SPA and Lambda candidates.
2. `datahub-cloud-runtime-image.yml` publishes one scanned immutable
   `linux/amd64` image and a self-digesting release receipt.
3. `datahub-core-ami.yml` builds the pinned, patched and scanned Core AMI.
4. `deploy.yml` verifies exact artifact IDs, GitHub artifact digests,
   producer workflows, source SHA and attestations. Staging is deployed first;
   production requires its exact attested staging receipt.
5. Availability, posture and alarm-delivery workflows emit sanitized,
   attested 90-day receipts.

The deploy workflow writes only runner-temporary promotion material, stages the
attested Lambda archive, deploys Edge -> Core -> Judge, uploads the exact SPA
bytes, invalidates CloudFront and re-observes the live controls.

## Runtime selection

`GET /api/runtime-profiles` returns Cloud and Core capability projections.
`auto` chooses Cloud only while its generation and capability digest are
healthy; otherwise it chooses a launchable Core candidate. The judge can
explicitly select either profile. A session binds one profile and generation
for its entire evidence and approval lifecycle.

The Cloud reader, mutation and reset functions use distinct roles and commands.
Only the reader invokes the reviewed Bedrock inference profile. Only the
mutation function can read the writer secret and fetch the public verification
key. Neither can sign. Reset is driven by the exact session and Core lease
streams, is concurrency-one and writes an idempotent 90-day ledger.

## Security verification

CI synthesizes both stages and enforces `policy/archon.guard`, CDK assertion
tests, Trivy IaC/SCA scans, action pinning and negative boundary tests. Live
observation verifies zero-idle Core, PITR/KMS state, private versioned buckets,
digest-bound functions, WAF associations, CloudFront TLS/OAC and alarm wiring.

No Codex Security workflow or local scan is part of the release contract.
