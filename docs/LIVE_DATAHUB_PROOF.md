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

Cloud must be `READY`. The job enters the selected protected `staging` or
`production` environment, validates the exact stage trial-role ARN and
non-secret tenant GMS URL, and assumes that role through GitHub OIDC with a
restrictive read-only inline session policy. In the same credentialed step it
resolves `ArchonCloudReaderSecretArn` from `Archon-<stage>-Judge`, reads only
`AWSCURRENT`, and rejects `SecretBinary`, a malformed or non-exact
`archon.datahub-cloud-reader-secret/v1` value, URL mismatch, or invalid key/token
material. It masks the token, runs the checksum-pinned MCP semantic proof, and
then unsets it. No static GitHub DataHub token secret is used. The attested
subject retains only a credential-binding digest over the stage, release,
secret version, and GMS binding. Search must resolve one canonical dataset,
retained history must include at least two stable sources, and the deterministic
audit must recover a contradiction.

## Core proof

This workflow is the availability and lease projection. The operator launches
Core through the judge application, supplies its random runtime session ID, and
the job polls the already-created session to `READY`; this workflow does not own
teardown. The canonical functional lifecycle is
`.github/workflows/submission-judge-journey.yml` together with
`web/e2e/live-judge-journey.live.spec.ts`: Core is the default profile, one
pinned session is started, all four components and the governed human-approved
flow are exercised, and `Stop & teardown` runs in `finally`. The network receipt
requires exactly one session start and one stop. The availability receipt binds
the session and status only by SHA-256 digest; functionality and supply-chain
bytes remain independently proven by the lifecycle journey and AMI build.

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
