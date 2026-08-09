# Architecture and decision record

> **Active implementation authority:** [ACTIVE_ARCHITECTURE.md](ACTIVE_ARCHITECTURE.md).
> The AWS judge runtime below is retained as a non-deployed reference experiment and is not
> part of the supported product, deployment, or customer path.

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

## Version-history recovery

A contradiction cannot be inferred from the current MCP read surface alone.
For the differentiator path, Archon directly reads bounded DataHub GMS
`GenericAspectV3` version 0/history records, retains their system-metadata
provenance, and resolves each per-execution `runId` through DataHub's ingestion
registry to the stable ingestion source. `pipelineName` is sticky across
independent ingestion runs and therefore remains fallback evidence only. Changes
from one resolved source remain drift; only independent retained sources can
form a contradiction. Missing, malformed, unauthorized, truncated, or
unresolved history fails closed to an unknown/manual result instead of becoming
an actionable finding.

## Judge runtime

The historical reference experiment proposes CloudFront + private S3, API
Gateway + WAF, Cognito, Lambda, DynamoDB, KMS, SQS and SNS. Its DataHub Cloud
path would use three digest-pinned Lambda image commands, while its OSS fallback
would use a pre-baked DataHub Core single-host ASG at desired capacity zero.
None of this is the active or deployed path.

Automatic selection prefers a healthy Cloud profile. The UI also exposes an
explicit Cloud/Core switch and the Core idle countdown. Sessions never change
profile implicitly after binding.

## Non-goals

Archon does not replace DataHub, own business data, claim legal clearance,
auto-approve governance changes, expose production credentials or operate an
always-on Kubernetes/container cluster for the demo.
