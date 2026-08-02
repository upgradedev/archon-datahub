# Architecture and decision record

Archon audits the DataHub metadata context graph and closes one controlled
context-improvement loop. DataHub is not the application database: it is the
cross-platform metadata, lineage and governance plane above warehouses,
databases, BI, ML and pipelines.

The judge story intentionally uses all four challenge technologies:

1. DataHub MCP Server performs official search, entity, lineage, quality and
   one human-approved tag mutation.
2. Agent Context Kit produces the provenance-bearing context envelope used by
   the custom agent.
3. DataHub Skills provide the pinned search -> lineage -> quality -> enrich
   execution policy and receipts.
4. Analytics Agent produces grounded SQL/chart/context-quality output and an
   `/improve-context` proposal.

One canonical synthetic graph is used in fixture, DataHub Cloud and DataHub
Core modes. Every conclusion carries source evidence and uncertainty; every
mutation requires a fresh digest-bound human approval and a before/after
receipt.

## Judge runtime

The permanent path is CloudFront + private S3, API Gateway + WAF, Cognito,
Lambda, DynamoDB, KMS, SQS and SNS. DataHub Cloud is served by three
digest-pinned Lambda image commands. The OSS fallback is a pre-baked DataHub
Core single-host ASG at desired capacity zero, launched through an idempotent
Step Functions lease.

Automatic selection prefers a healthy Cloud profile. The UI also exposes an
explicit Cloud/Core switch and the Core idle countdown. Sessions never change
profile implicitly after binding.

## Non-goals

Archon does not replace DataHub, own business data, claim legal clearance,
auto-approve governance changes, expose production credentials or operate an
always-on Kubernetes/container cluster for the demo.
