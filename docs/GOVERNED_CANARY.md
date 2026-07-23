# Governed write-and-rollback canary

`.github/workflows/governed-canary.yml` is the only supported live mutation proof. It is
manual-only and pipeline-native. Local commands, workstation browser sessions, and scanner
output are not accepted as evidence.

The workflow targets only the deployed `Archon-staging` stack. Before an approval is
possible it binds the requested full release SHA and application URL to a successful
immutable deployment receipt, the live CloudFormation parameters and outputs, a
content-addressed audit object, and one exact non-production fixture:

```text
dataset name: archon_governed_canary_fixture[...]
environment:  DEV or TEST (PROD is rejected)
query:        archon_governed_canary_fixture
field:        email
tag:          urn:li:tag:PII
write:        add_tags for exactly one dataset/field/tag
rollback:     remove_tags for those same exact arguments
```

The isolated tenant must return exactly one entity for the query. Its `email` field starts
without the `urn:li:tag:PII` classification (unrelated pre-existing tags are preserved), and
the `urn:li:tag:PII` tag already exists in the tenant. Every configured
DataHub endpoint hostname must contain the dedicated tenant marker as a complete DNS label,
not a substring. These controls, the
TEST/DEV URN rule, the exact immutable plan check, and the hard-coded staging stack prevent
the workflow from approving a production or caller-selected dataset.

## Protected environment contract

Create three GitHub environments. All allow only the default branch, require at least one
reviewer, and enable prevent-self-review. Use different reviewers where possible.

The read-only `prepare` job has no environment and therefore no human approval or
environment secret. It uses repository variables for `AWS_CANARY_PREPARE_ROLE_ARN`,
`AWS_ACCOUNT_ID`, `AWS_REGION`, `CANARY_APPLICATION_URL`, `CANARY_DATASET_URN`,
`CANARY_ISOLATION_MARKER`, and the four `CANARY_DATAHUB_*_URL` bindings. It can start the
governed state machine and read immutable evidence, but it cannot authenticate an approval
or call DataHub mutation tools. Its only handoff is the content-addressed recovery artifact
and its `planDigest` / `recoveryDigest` job outputs. The artifact also seals an
`authBindingsDigest` derived from the staging CloudFormation application URL, Cognito user
pool client ID, Hosted UI origin, and exact authorization/token endpoints.

`governed-canary` owns the write approval and contains:

- variables: `AWS_CANARY_APPROVAL_ROLE_ARN`, `AWS_ACCOUNT_ID`, `AWS_REGION`,
  `CANARY_APPLICATION_URL`, `CANARY_DATASET_URN`, `CANARY_ISOLATION_MARKER`,
  `CANARY_DATAHUB_READ_GMS_URL`, `CANARY_DATAHUB_READ_MCP_URL`,
  `CANARY_DATAHUB_WRITE_GMS_URL`, `CANARY_DATAHUB_WRITE_MCP_URL`,
  `CANARY_CHROME_VERSION`, and `CANARY_CHROME_BINARY_SHA256`;
- secrets: `CANARY_COGNITO_USERNAME` and `CANARY_COGNITO_PASSWORD`.

Both OIDC roles are read-only for this proof. The prepare role trusts only
`repo:upgradedev/archon-datahub:ref:refs/heads/master`; the approval role trusts only
`repo:upgradedev/archon-datahub:environment:governed-canary`.
The prepare role needs `cloudformation:DescribeStacks` on `Archon-staging` and
`s3:GetObject` on that stack's `v1/audit/sha256/*` keys. The protected approval role needs
the same stack read, `s3:GetObject` only on `v1/execution/sha256/*`, and
`cognito-idp:AdminGetUser` plus `cognito-idp:AdminListGroupsForUser` for the dedicated
canary steward. Neither role may have DataHub or production deployment permissions.

`governed-canary-rollback` owns the separately approved inverse and contains:

- the same application, release-independent fixture, isolation, endpoint, and
  `CANARY_EVIDENCE_BUCKET` variables;
- secrets `CANARY_DATAHUB_READ_TOKEN` and `CANARY_DATAHUB_WRITE_TOKEN`.

`governed-canary-recovery` is the independent compensator boundary. It contains the same
application, evidence bucket, fixture, Cognito, isolation, and endpoint variables; a
read-only `AWS_CANARY_RECOVERY_ROLE_ARN`, `AWS_ACCOUNT_ID`, and `AWS_REGION`; and dedicated
least-privilege `CANARY_DATAHUB_READ_TOKEN` / `CANARY_DATAHUB_WRITE_TOKEN` secrets. Its
branch policy allows only `master`; its read-only AWS role trusts only
`repo:upgradedev/archon-datahub:environment:governed-canary-recovery`.

The rollback write token must be a dedicated DataHub principal limited by platform policy
to tag add/remove on the disposable fixture. The staging deployment's remediation secret
must likewise be a dedicated canary principal, never a general production PAT. DataHub does
not expose a portable token-policy introspection contract, so this least-privilege grant is
an external administrator prerequisite; endpoint, target, plan, and observed-state
bindings still fail closed in the workflow.

`CANARY_CHROME_VERSION` and `CANARY_CHROME_BINARY_SHA256` pin the preinstalled GitHub
runner Chrome payload. The workflow downloads no browser or browser automation package.
When the hosted runner image changes, update both values only after reviewing the new
runner inventory and binary digest.

The Cognito client ID and Hosted UI origin are never accepted from `runtime-config.json`
alone. Preparation derives them from the live `Archon-staging` CloudFormation outputs and
seals them in recovery evidence. The protected job re-reads those outputs, then requires
the runtime client ID and exact `/oauth2/authorize` and `/oauth2/token` origin/path bindings
to match before it reads the password or starts Chrome.

## Evidence sequence

1. The unprivileged preparation job validates environment protection, the successful
   deployment run, CloudFormation release/URL/endpoints, the isolated fixture contract,
   and the exact deployed application binding.
2. Archon starts `GOVERNED`, reaches `AWAITING_APPROVAL`, and exposes the immutable audit
   evidence digest. The driver validates the exact dossier, plan, pre-state, and inverse.
3. A content-addressed recovery manifest is uploaded **before** any protected approval or
   mutation. The completed prepare-job summary shows the fixed target, tag, inverse, and
   pre/post-state digests.
4. The first environment gate is created only after preparation. Its pending job name
   includes the exact `planDigest` and `recoveryDigest`; the reviewer therefore approves
   the sealed plan, not an earlier generic workflow dispatch. After approval, the job
   re-downloads and re-verifies that artifact, both environment-protection policies, the
   live release/endpoints, and the Cognito user's sole `archon-approvers` group before
   those secrets are used to submit `APPROVE`.
5. The driver uses Cognito Hosted UI authorization code + PKCE S256 in headless Chrome.
   It does not enable or call `USER_PASSWORD_AUTH`. The callback is intercepted before the
   SPA consumes the code, then exchanged at the runtime-config-bound token endpoint.
6. The scoped access token approves the exact plan. The workflow accepts only terminal
   `VERIFIED`, five ordered passing checks, a seven-event receipt chain, and an eligible
   content-addressed rollback proposal.
7. The second environment reviewer sees the proposal digest (or the pre-mutation recovery
   digest after a failed write job) in the rollback job name and separately authorizes it;
   its required-reviewer, self-review, and branch policy are checked again before recovery.
8. The rollback driver accepts only the exact expected post-state, calls `remove_tags` for
   the sealed inverse, and performs a direct read-after-rollback. The restored digest and
   tags must equal the original pre-state. A successful full write/rollback run signs the
   exact sanitized rollback evidence with a GitHub artifact attestation.

Rollback is deliberately idempotent. Even when a verified rollback manifest is present,
an observed digest already equal to its sealed exact pre-state succeeds as
`ALREADY_RESTORED` and emits the same sanitized manifest-bound evidence without another
mutation. The exact post-state triggers `remove_tags`; every state matching neither digest
is rejected.

Credentials and bearer tokens remain in process memory, are covered by GitHub secret
masking, and never enter artifacts or step summaries. Chrome output is suppressed and its
ephemeral profile under `RUNNER_TEMP` is deleted in `finally`. Retained artifacts contain sanitized IDs,
digests, fixed target coordinates, mutation response digests, and the restoration proof.

If the write job fails after its recovery manifest was sealed, the rollback job still
requires its own reviewer. It removes the tag only when the observed state equals the
sealed expected post-state; it performs a no-op only when the exact pre-state is already
present, and rejects every divergent state.

`.github/workflows/governed-canary-recovery.yml` closes the force-cancellation gap. A
separate, non-cancelling `workflow_run` execution starts only when the exact
`.github/workflows/governed-canary.yml` parent on `master` finishes as `failure` or
`cancelled`. It validates the parent repository, path, run ID and attempt, downloads only
that attempt's sealed recovery and optional verified-write artifacts, revalidates the
deployment and live staging bindings, then enters the dedicated protected recovery
environment. Exact pre-state is an attested idempotent success; exact post-state runs only
the sealed inverse and proves restoration; every other state fails closed. A parent that
stopped before sealing recovery could not yet authorize mutation, so the compensator
records that no recovery is required. Successful parent runs never enter the recovery job.
