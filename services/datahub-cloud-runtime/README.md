# DataHub Cloud runtime v2

This directory contains the isolated AWS Lambda container runtime for the
DataHub Cloud profile. It consumes only `archon.runtime-bound-job/v2` records
whose `profileId` is `cloud`, validates the exact runtime session,
generation, capability, Cloud lease, and registry binding, and writes
`archon.runtime-bound-job-receipt/v2` with the unchanged request.

## Execution surfaces

- `handlers.read_handler` runs `ANALYZE`, `READ_TAGS`,
  `IMPROVE_CONTEXT`, `POST_ANALYZE`, and `POST_READ_TAGS`. It is the only
  role allowed to invoke Bedrock and read the Cloud reader secret.
- `handlers.mutation_handler` runs only `GOVERNED_TAG_MUTATION`. It has no
  Bedrock permission, reads only the writer secret, verifies the P-256
  authorization locally after a bounded KMS `GetPublicKey`, consumes the
  authorization through DynamoDB CAS, and calls official MCP `add_tags`
  exactly once.
- `handlers.fixture_reset_handler` is driven only by the configured session
  `EXPIRED` and Core lease `DRAINING` stream transitions. It serially
  restores only the canonical PII tag baseline with official MCP
  `remove_tags`; no human approval is represented or reused.

The three functions use the same immutable `linux/amd64` Lambda image but
different commands, IAM roles, environment bindings, event-source filters,
timeouts, memory, and reserved concurrency.

## Durable continuity and boundaries

Analytics Agent runs as a loopback-only child process inside the read Lambda.
Its SQLite state is checkpointed to a versioned S3 object with an explicit
SHA-256 checksum and SSE-KMS key. A DynamoDB revision CAS selects the only
current version. The token, OAuth master key, run-handle key, static AWS key
patterns, WAL content, provider responses, and exception details are rejected
from durable state and receipts. Every invocation uses a bounded per-job
directory under `/tmp`, terminates the child, checkpoints only on success, and
removes the directory.

The runtime has no VPC, NAT gateway, permanent compute, static AWS credentials,
or local developer build path. AWS credentials are Lambda role credentials and
Analytics Agent validates its temporary STS role identity in-process.

## CI/CD only

`.github/workflows/datahub-cloud-runtime-image.yml` is the sole build and
publication path. It verifies Git blob bindings, downloads the exact official
DataHub Skills commit with an archive checksum, runs all tests inside the
container with networking disabled, enforces dependency and image Trivy gates,
generates CycloneDX and SPDX SBOMs, seals provenance, publishes only to an
immutable ECR repository through protected OIDC authority, signs provenance and
SBOM subjects with GitHub Artifact Attestations, and emits
`archon.datahub-cloud-runtime-release/v1`.

PRs never receive AWS or publication authority. Candidate and release runner
material is removed at the end of each job, and ECR cleanup is limited to old
`cloud-v2-` tags and a bounded set of stale untagged images.

Infrastructure must consume
`infra/aws/datahub-cloud-runtime-handoff.json` and deploy only
`${imageUri}@${imageDigest}` from a release artifact whose gates are all
`true`.
