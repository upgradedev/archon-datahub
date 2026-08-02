# DataHub Cloud trial companion

DataHub Cloud is an optional scored companion to the canonical OSS Core runtime.
It is not a dependency for judge continuity. The application keeps the visible
`Auto / Cloud / Core` selector, binds one profile for the lifetime of a session,
and never silently switches a running session.

The Cloud control plane is entirely CI/CD driven by
`.github/workflows/datahub-cloud-trial.yml`. No contributor workstation receives
a Cloud service-account token, generated database, dependency environment, or
security-scan artifact.

## Why both Cloud and OSS Core

OSS Core proves that the submission is reproducible, challenge-compatible, and
not dependent on a paid managed tenant. Cloud demonstrates the managed DataHub
experience, official managed MCP endpoint, service accounts, RBAC, constrained
policies, and operational integration. If the 21-day trial ends or is not
extended, Auto detects that Cloud is unavailable before starting a session and
selects Core. An explicitly selected Cloud session fails visibly; it does not
fall back.

The planned activation date is **2026-08-04**. Twenty-one nominal calendar days
place the trial end around **2026-08-25**. Judging access is targeted through
2026-08-31, so Core remains canonical even if a short paid Cloud extension is
not purchased. A paid extension changes tenant availability only; it does not
change the runtime contract or selector behavior.

## Exact least-privilege design

Each deployment stage receives two distinct service accounts:

- `Archon <stage> DataHub reader`
- `Archon <stage> DataHub writer`

Both receive DataHub's exact `Reader` role. The writer receives one additional
active metadata policy named `Archon <stage> exact PII column writer`. That
policy grants only `EDIT_DATASET_COL_TAGS`, only on:

`urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)`

and uses `privilegeConstraints` to allow only:

`urn:li:tag:PII`

The resource and tag criteria both use `field: URN` and `condition: EQUALS`.
The writer service-account URN is the constrained policy's only direct user
actor. The workflow also fails closed if any other mutation policy applies
through that user, `allUsers`, or the `Reader` role.

The reader mutation proof accepts only one of three concrete outcomes:
`add_tags` is absent from the reader's `tools/list` inventory, the provider
returns HTTP `403`, or the provider returns text that explicitly identifies an
authorization denial. Generic JSON-RPC errors, generic tool errors, transport
failures, `401`, and `5xx` fail the operation.
The canary also re-reads the field immediately after the denial probe and
requires the PII tag to remain absent before the writer round trip begins.
The implementation is bound to official DataHub source commit
`53064c2d9b41f77a141736ad6eb037966174329b`. It uses the exact GraphQL contracts
for `createServiceAccount(displayName, description)`,
`createAccessToken(type: SERVICE_ACCOUNT, actorUrn, duration: ONE_MONTH, name,
description)`, `listRoles`, `batchAssignRole`, and policy
`privilegeConstraints`.

The managed MCP canary uses `mcp-server-datahub` 0.6.0 source commit
`9a6946daa7d30eb481c82dd8ee5e15ae6526a3c9`; its exact `add_tags` and
`remove_tags` arguments are bound by the trial contract.

## One-time preparation on 2026-08-04

1. Activate the 21-day DataHub Cloud trial and obtain the tenant GMS URL in the
   form `https://<tenant>.acryl.io/gms`.
2. Create one short-lived admin PAT with only the DataHub administrative
   privileges required to manage service accounts, tokens, roles, and policies.
   Do not paste it into a file, issue, log, workflow input, repository variable,
   or shell command.
3. In the protected GitHub `staging` environment configure:
   - secret `DATAHUB_CLOUD_ADMIN_PAT`;
   - variable `DATAHUB_CLOUD_GMS_URL`;
   - existing variables `AWS_ACCOUNT_ID` and `AWS_REGION`;
   - variable `AWS_DATAHUB_CLOUD_TRIAL_ROLE_ARN`, set to the dedicated
     `archon-datahub-github-staging-cloud-trial` role.
4. Confirm that `Archon-staging-Judge` exists and exports
   `ArchonCloudReaderSecretArn`, `ArchonCloudWriterSecretArn`, and
   `ArchonSecretsKeyArn`. The dedicated Cloud-trial role may describe, stage,
   and promote versions only on the exact
   `archon/staging/datahub-cloud/reader-*` and
   `archon/staging/datahub-cloud/writer-*` Secrets Manager resources. It may
   read only the retained reader secret to preserve its two stable Fernet keys,
   and may use only `alias/archon/staging/judge-secrets` through Secrets
   Manager. It cannot assume CDK roles or deploy infrastructure.
5. Wait for the current master SHA to have successful `CI`, `CodeQL`, and
   `Workflow security` push runs.
6. Dispatch `DataHub Cloud trial bootstrap and canary` from that exact master
   SHA with:
   - action `plan`;
   - environment `staging`;
   - the current 40-character master SHA;
   - blank confirmation.
7. Review the sanitized plan receipt. It contains only digests and counts.
8. Dispatch again with action `bootstrap` and exact confirmation:

   `BOOTSTRAP DATAHUB CLOUD TRIAL 2026-08-04`

9. Verify the attested receipt reports all of:
   - separate reader and writer service accounts;
   - Reader role assigned to both;
   - the exact constrained writer policy;
   - two distinct ONE_MONTH service-account credentials stored in separate AWS
     secrets;
   - canonical fixture seeding;
   - managed MCP health/read success;
   - reader `add_tags` denial;
   - writer `add_tags` / `remove_tags` round trip;
   - final `customers.customer_email` PII state `absent`.
10. Repeat for `production` only after the production stack and protected
    environment variables exist. The production environment's configured solo
    owner approval remains the deployment gate.

The admin PAT is supplied only to the execution step as an environment secret.
Generated service-account tokens stay in Python memory and flow to the AWS CLI
through stdin as `file:///dev/stdin`. AWS OIDC credentials are acquired only
after pinned tool setup and frozen dependency resolution, are exposed only to
the execution step through masked action outputs, and are not exported to later
artifact or attestation steps. Tokens are never command arguments,
GitHub outputs, step summaries, files, or artifacts. The retained artifact is
one canonical sanitized JSON receipt plus its GitHub attestation. The shared
fixture seeder remains loopback-only by default; this workflow can target Cloud
only by supplying the separately validated exact `<tenant>.acryl.io` host
binding to the canonical `https://<tenant>.acryl.io/gms` URL.

## Reconcile and rotation

`reconcile` is the normal safe retry. It adopts only exact marker-owned service
accounts and policy, repairs the exact policy when safe, creates a fresh
reader/writer token pair, and runs the full live canary. It then writes both
secret documents under the run-bound
`archon-trial-<run-id>-<run-attempt>` stage, verifies both version IDs,
promotes and re-verifies both `AWSCURRENT` labels, removes the staging labels,
and only then revokes superseded scoped tokens. The final provider inventory
must contain exactly the new reader/writer pair. Any failure revokes the new
tokens and rolls promoted secrets back to their previous current versions.
Confirmation:

`RECONCILE DATAHUB CLOUD TRIAL`

`rotate` requires at least one existing scoped runtime token and performs the
same no-downtime replacement sequence. Confirmation:

`ROTATE DATAHUB CLOUD TRIAL`

Raw DataHub tokens are non-retrievable from DataHub after creation. The GitHub
role never reads the writer secret. It reads the retained reader secret only in
memory to preserve `runHandleFernetKey` and `oauthMasterKey` byte-for-byte.
First bootstrap generates two independent 32-byte URL-safe base64 keys only when
`DescribeSecret` proves that the exact foundation-created reader secret has
zero versions and no `AWSCURRENT`. No other AWS failure is interpreted as an
empty secret, and malformed managed state fails closed. A retry creates a fresh
token pair, converges both exact-schema secrets,
and revokes all prior exact-namespace tokens.

## Cleanup

After judging, dispatch `cleanup` separately for each stage with:

`CLEANUP DATAHUB CLOUD TRIAL`

Cleanup revokes only Archon's exact stage-scoped runtime token namespace,
deletes only marker-owned exact policy and service accounts, removes their role
assignment, verifies the final absence of both accounts and the exact policy,
and replaces both runtime secret values with a verified non-credential
`revoked` marker. Cleanup accepts an owned zero-, one-, or two-account state,
so a retry completes safely after a prior partial account deletion. It
deliberately preserves the canonical metadata fixture.
Delete or retain the managed tenant itself through DataHub's billing controls;
that external account action is not automated by this repository.

## Security and evidence

Security validation runs in GitHub Actions:

- exact GraphQL and policy contract tests;
- workflow permission, action pin, branch, environment, and secret-flow tests;
- repository secret scanning, CodeQL, dependency review, and workflow-security
  gates before live mutation;
- managed MCP authorization and rollback canary;
- credential-exclusion checks before receipt creation;
- SHA-bound artifact retention and GitHub attestation.

No Codex-based security scan is part of this mechanism. All generated
dependencies, live checks, and evidence are confined to ephemeral GitHub-hosted
runners.
