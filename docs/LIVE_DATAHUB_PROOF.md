# Live dual-runtime DataHub proof

`.github/workflows/live-datahub-proof.yml` is the operational projection of
one exact deployed release. It accepts an exact stage, merged master SHA,
deployment run ID, deployment artifact ID and GitHub artifact digest. The
workflow downloads only that artifact, validates its two-file inventory,
verifies the artifact digest and deployment attestation, and requires the
`archon.aws-deployment-evidence/v2` receipt and live observation to bind the
same release.

It then resolves `/api/runtime-profiles` through the deployed CloudFront
origin and requires exactly one selected profile with all four capabilities:

- DataHub MCP Server;
- Agent Context Kit;
- DataHub Skills;
- Analytics Agent.

## Cloud proof

Cloud must be `READY`. The protected `datahub-demo` environment supplies
`DATAHUB_CLOUD_GMS_URL` and `DATAHUB_CLOUD_GMS_TOKEN`; neither is retained.
The workflow reconstructs the checksum-pinned MCP runtime and runs the
credentialed semantic proof. Search must resolve one canonical dataset,
retained history must include at least two stable sources, and the deterministic
audit must recover a contradiction.

## Core proof

The operator first launches Core through the judge application and supplies its
random runtime session ID. The workflow polls the public, capability-scoped
session status until it is `READY`, requires the Core profile to be `BUSY`
with all four capability checks true, and binds the session and status only by
SHA-256 digest. Core functionality and supply-chain bytes are independently
proved during the AMI build; this live receipt proves that the exact deployed
generation is active inside a governed lease.

## Evidence

The final `archon.live-dual-runtime-proof/v2` subject binds:

- deployment run and attested evidence digest;
- runtime profile, generation and capability digest;
- hashed canonical query;
- credentialed Cloud semantic proof or active Core session proof;
- the four capability flags.

The subject is self-digesting, attested, retained for 90 days, and contains no
endpoint, token, account identifier, raw session ID or raw dataset URN. All
intermediates remain under `RUNNER_TEMP` and are removed unconditionally.
