# Governed DataHub Cloud canary

The governed canary is the pipeline-native proof that Archon can use the four
DataHub challenge capabilities against the managed DataHub Cloud runtime while
preserving explicit human authority and an exact, independently approved
inverse:

1. DataHub MCP Server
2. Agent Context Kit
3. DataHub Skills
4. Analytics Agent

It is staging-only. It does not deploy DataHub Core, start an EKS cluster, use
the retired ECS runtime, or make production promotion depend on mutable canary
state.

## Runtime policy

The application exposes the resolved runtime profile to the judge. The normal
demo selects **DataHub Cloud (managed)** explicitly; Core remains the
reproducible OSS profile and may be demonstrated separately without keeping an
always-on cluster. The governed canary deliberately forces the Cloud profile so
its evidence cannot silently fall back to Core.

The live target is fixed to:

- stack: `Archon-staging-Judge`
- application: `https://staging.archon-datahub.click`
- dataset:
  `urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)`
- field: `customer_email`
- governed tag: `urn:li:tag:PII`

The endpoint binding contains a public isolation marker and four HTTPS
endpoints. All four endpoint hostnames must include the marker and resolve to
one DataHub Cloud tenant. Tokens are never part of the binding or any artifact.

## Inputs

Dispatch `.github/workflows/governed-canary.yml` from the exact current
`master` commit with values copied from a successful staging run of
`.github/workflows/deploy.yml`:

- `deployment_run_id`
- `deployment_artifact_id`
- `deployment_artifact_digest` in GitHub `sha256:<hex>` form
- `release_sha`, the exact deployed 40-character commit
- confirmation: `RUN GOVERNED DATAHUB CLOUD CANARY`

The selected deployment artifact must be named
`deployment-evidence-staging-<release-sha>-<deployment-run-id>` and contain
only `deployment-evidence.json` plus `observation.json`. The workflow accepts
only `archon.aws-deployment-evidence/v2` and
`archon.lean-runtime-observation/v1`, verifies their exact cross-digests, and
verifies the GitHub deployment attestation.

## GitHub environments

The workflow uses four intentionally distinct environments:

| Environment | Purpose | Secret access |
| --- | --- | --- |
| `governed-canary-prepare` | Read-only deployment, control-plane, endpoint, and Judge-stack binding; seals recovery before mutation | none |
| `governed-canary` | Human-approved browser journey and Cognito role proof | judge username/password only |
| `governed-canary-rollback` | Independently approved normal inverse | DataHub read/write tokens |
| `governed-canary-recovery` | Independently approved interrupted-run inverse | DataHub read/write tokens |

`governed-canary`, `governed-canary-rollback`, and
`governed-canary-recovery` must retain their human approval rules. The
preparation environment is deliberately non-mutating and may remain
reviewerless. All jobs share the non-cancelling
`archon-governed-canary-mutation-recovery` concurrency lock.

## Variables and secrets

Repository or matching environment variables:

- `AWS_REGION`
- `AWS_CANARY_PREPARE_ROLE_ARN`
- `AWS_CANARY_APPROVAL_ROLE_ARN`
- `CANARY_APPLICATION_URL`
- `CANARY_ISOLATION_MARKER`
- `CANARY_DATAHUB_READ_GMS_URL`
- `CANARY_DATAHUB_READ_MCP_URL`
- `CANARY_DATAHUB_WRITE_GMS_URL`
- `CANARY_DATAHUB_WRITE_MCP_URL`

Protected-environment secrets:

- `CANARY_COGNITO_USERNAME` and `CANARY_COGNITO_PASSWORD` in
  `governed-canary`
- `CANARY_DATAHUB_READ_TOKEN` and `CANARY_DATAHUB_WRITE_TOKEN` in both
  rollback environments

The read and write tokens must remain different capabilities. The pipeline
masks both values, passes them only to the exact protected inverse step, and
never uploads environment dumps, browser storage, headers, or raw network
bodies.

## Proof sequence

### 1. Prepare and seal

The reviewerless job:

- proves the dispatch commit is current `master`;
- authenticates the exact successful deployment run, artifact ID, name, and
  digest;
- validates lean evidence and the current GitHub control plane;
- assumes the read-only prepare role;
- proves the exact Judge stack release, deployment run, Cloud image digest,
  application origin, Cognito outputs, canonical dataset, and field;
- canonicalizes the DataHub Cloud endpoint binding; and
- writes `archon.governed-canary-recovery/v4` before any mutation.

The sealed artifact contains only `recovery.json` and
`control-plane-security-gates.json`.

### 2. Human-approved browser journey

The browser job revalidates the sealed control-plane digest and proves the
judge account belongs to exactly both `archon-runtime-operators` and
`archon-approvers`. It then performs the public UI journey:

1. creates a Cloud runtime session;
2. runs the Analytics Agent;
3. asks Agent Context Kit for an evidence-linked context improvement;
4. exercises a DataHub Skill;
5. submits the exact proposed plan for human approval;
6. performs the official DataHub MCP `add_tags` mutation;
7. waits for post-write acknowledgement and read-back;
8. reruns analytics and proves the context delta; and
9. tears down the runtime session.

The receipt records only bounded identifiers, digests, status, component names,
and security checks. It asserts that no secret material was retained.

### 3. Independently approved inverse

The rollback job runs even when the browser job fails or is cancelled, provided
preparation sealed recovery. It re-authenticates the original control-plane
digest, reads the current tag projection using the read token, removes only the
canonical PII tag when present using the write token, and reads back the exact
baseline. Any unrelated tags must remain unchanged.

The canonical recovery evidence schema is
`archon.governed-canary-recovery-evidence/v2`. Its JSON and checksum are
attested with GitHub OIDC and uploaded for 90 days together with the sealed
`recovery.json` and an exact `attestation-predicate.json` projection. The operation is idempotent:
a clean baseline produces `already-baseline`; a successful inverse produces
`restored`.

## Interrupted-run recovery

`.github/workflows/governed-canary-recovery.yml` automatically follows a
failed or cancelled governed Cloud canary and can also be dispatched manually
with:

- the exact source run ID;
- the exact run attempt; and
- `RECOVER SEALED GOVERNED DATAHUB CLOUD CANARY`.

The unprivileged resolve job accepts exactly one immutable sealed-recovery
artifact from that failed attempt. It checks canonical JSON, schema, manifest
digest, source SHA, endpoint binding, target, and sealed gate digest using the
driver's non-mutating `verify` operation. It has no secrets.

Only then can the protected recovery job run. It repeats the checks after human
approval and executes the same PII-only, read-back-proven inverse. A source run
that did not reach sealing fails closed without requesting mutation authority.

## Evidence artifacts

A successful or partially failed run can produce:

- `governed-canary-recovery-<run>-<attempt>`: sealed pre-mutation capability;
- `governed-canary-write-<run>-<attempt>`: sanitized browser receipt plus the
  sealed recovery manifest;
- `governed-canary-rollback-<run>-<attempt>`: normal inverse evidence, sealed
  recovery manifest, exact attestation predicate, and subject checksum; and
- `governed-canary-emergency-recovery-...`: interrupted-run inverse evidence.

The submission-operations collector consumes the four-file normal rollback
artifact as the Cloud-v2 governed-write proof and rejects the retired fixture
binding and rollback-v1 schema.

These artifacts supplement the immutable deployment evidence. They do not
replace deployment promotion gates and are not accepted as production release
authority.

## Cost posture

No always-on DataHub infrastructure is introduced by this canary. During the
trial or short paid extension, DataHub Cloud supplies the managed metadata
plane. The remaining work is short-lived GitHub-hosted browser time plus the
existing lean Judge/serverless staging runtime. DataHub Core remains an
optional reproducibility path rather than a permanently provisioned EKS cost.

## Failure policy

The canary fails closed on any mismatch involving source commit, deployment
artifact, attestation, stack output, runtime profile, endpoint isolation,
Cognito groups, approval digest, official MCP acknowledgement, context delta,
security headers, recovery manifest, or read-back projection. Unknown state is
never converted into a pass, and no pipeline step autonomously changes
production or broader DataHub metadata.
