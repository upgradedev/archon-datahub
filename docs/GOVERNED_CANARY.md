# Governed write-and-rollback canary

`.github/workflows/governed-canary.yml` is the only supported live mutation proof. It is
workflow-dispatch-only and pipeline-native. The immutable deployment workflow dispatches
it after staging and requires its signed rollback evidence before the production
environment can be entered. An operator may also dispatch it for an already successful
deployment. Local commands, workstation browser sessions, and scanner output are not
accepted as evidence.

The workflow targets only the deployed `Archon-staging` stack. Before an approval is
possible it binds the requested full release SHA and application URL to a successful
immutable deployment receipt, the live CloudFormation parameters and outputs, a
content-addressed audit object, and one exact non-production fixture. The workflow driver
must still be the current `master` commit, and the deployment's canonical CI / CodeQL /
workflow-security receipt must still be the latest successful exact-SHA control plane:

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
pool client ID, Hosted UI origin, and exact authorization/token endpoints. It additionally
stores `controlPlaneGatesSha256` inside the content-addressed
`archon.governed-canary-recovery/v2` manifest and carries the exact canonical
`control-plane-security-gates.json` beside it. This historical receipt remains recoverable
even if a later rerun for the old SHA fails. Version 2 is the first supported
default-branch recovery format; no legacy v1 canary was deployed.

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

Every privileged boundary invokes the repository's CI-only control-plane verifier again.
The prepare and approval jobs revalidate the exact deployment gate digest immediately
before AWS OIDC. The approval job repeats it immediately before exposing the Cognito
username and again immediately before the password-backed approval mutation. These forward
checks use the current-master view, so a moved default branch, a newer queued/failed
attempt, or any receipt change fails closed. The rollback job instead authenticates the
canonical receipt sealed before mutation and its exact successful attempts immediately
before exposing either DataHub token. That preserves compensation after routine branch
movement without accepting a different control plane.

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

1. The unprivileged preparation job validates the current `master` ref, the latest exact-SHA
   CI / CodeQL / workflow-security attempts, environment protection, and either the
   successful deployment run or the same active deployment attempt with completed,
   successful staging and production not started. It then validates CloudFormation
   release/URL/endpoints, the isolated fixture contract, and the exact deployed
   application binding.
2. Archon starts `GOVERNED`, reaches `AWAITING_APPROVAL`, and exposes the immutable audit
   evidence digest. The driver validates the exact dossier, plan, pre-state, and inverse.
3. A content-addressed recovery manifest and its exact canonical deployment-gate receipt
   are uploaded **before** any protected approval or mutation. The gate-file hash is inside
   the manifest and therefore inside `recoveryDigest`. The completed prepare-job summary
   shows the fixed target, tag, inverse, and pre/post-state digests.
4. The first environment gate is created only after preparation. Its pending job name
   includes the exact `planDigest` and `recoveryDigest`; the reviewer therefore approves
   the sealed plan, not an earlier generic workflow dispatch. After approval, the job
   re-downloads and re-verifies that artifact, both environment-protection policies, the
   exact current control-plane receipt, the live release/endpoints, and the Cognito user's
   sole `archon-approvers` group. The same receipt is checked again at the username and
   password/mutation boundaries before those secrets are used to submit `APPROVE`.
5. The driver uses Cognito Hosted UI authorization code + PKCE S256 in headless Chrome.
   It does not enable or call `USER_PASSWORD_AUTH`. The callback is intercepted before the
   SPA consumes the code, then exchanged at the runtime-config-bound token endpoint.
6. The scoped access token approves the exact plan. The workflow accepts only terminal
   `VERIFIED`, five ordered passing checks, a seven-event receipt chain, and an eligible
   content-addressed rollback proposal.
7. The second environment reviewer sees the proposal digest (or the pre-mutation recovery
   digest after a failed write job) in the rollback job name and separately authorizes it;
   its required-reviewer, self-review, branch policy, and exact sealed control-plane receipt
   are checked again before the DataHub tokens or recovery mutation are exposed.
8. The rollback driver accepts only the exact expected post-state, calls `remove_tags` for
   the sealed inverse, and performs a direct read-after-rollback. The restored digest and
   tags must equal the original pre-state. A successful full write/rollback run signs the
   exact sanitized rollback evidence with a GitHub artifact attestation.
9. The deployment gate waits for that exact workflow run, requires a successful
   default-branch/exact-control-plane result, safely extracts the unique rollback
   artifact, verifies its GitHub-recorded archive digest, subject checksum, predicate
   bindings, and GitHub attestation, and seals those digests into final production
   deployment evidence.

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
`cancelled`. An idempotent manual fallback accepts only an exact parent run ID and attempt
plus the literal `RECOVER SEALED GOVERNED CANARY` confirmation, and then applies the same
validation. The workflow derives parent coordinates from the exact-attempt API response,
cross-checks the automatic event payload, downloads only that attempt's sealed recovery and
optional verified-write artifacts, and verifies every historical workflow run ID/attempt
named by the sealed gate receipt directly. It does not ask which attempt is now latest for
the old parent SHA, because a later failed rerun must not strand an already authorized
mutation.

Before protected approval, the unprivileged `resolve-parent` job binds its own
`GITHUB_SHA` to the then-current `master`, double-reads the latest exact successful CI,
CodeQL, and workflow-security attempts, and seals their canonical receipt, digest, and
driver SHA as job outputs. That job has no AWS OIDC permission and consumes no repository
secrets. After approval, the protected job materializes and digest-checks that receipt,
checks out only the sealed driver SHA, and authenticates the receipt's exact attempts in
sealed mode before AWS OIDC and again before the DataHub token mutation. It never resolves
or executes a new current head after approval, so routine `master` advancement while a
review is pending cannot strand recovery or swap the reviewed implementation. The
immutable parent SHA remains the deployment and attestation binding. The workflow then
rechecks deployment and live staging bindings and performs the protected recovery. Exact
pre-state is an attested idempotent success; exact post-state runs only the sealed inverse
and proves restoration; every other state fails closed. A parent that stopped before
sealing recovery could not yet authorize mutation, so the compensator records that no
recovery is required. Successful parent runs never enter the automatic recovery job and
cannot pass the manual fallback's failed-or-cancelled parent validation.
