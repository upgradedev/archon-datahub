# Protected judge access

Judge access is an explicit CI/CD operation. Cognito self-sign-up remains disabled in
`infra/aws/lib/archon-stack.ts`; operators must not create, rotate, reactivate, or disable
hosted users from a laptop or with long-lived AWS keys.

`.github/workflows/judge-user.yml` is the only supported lifecycle path:

| Operation | Preconditions | Result proved by read-back |
|---|---|---|
| `provision` | The exact lower-case email does not exist. | An enabled, email-bound `CONFIRMED` user with a pipeline-managed permanent password whose complete authorization membership is exactly the two-group set `archon-approvers` and `archon-runtime-operators`. |
| `rotate` | The exact user exists in `CONFIRMED`, is enabled, and already has the complete two-group set: `archon-approvers` plus `archon-runtime-operators`. | Global sign-out, a rotated permanent password, `CONFIRMED`, and that same exact two-group set. |
| `reactivate` | The exact immutable email/binding is disabled in `CONFIRMED` or `FORCE_CHANGE_PASSWORD`, has no recovery/MFA drift, and has no group memberships. | Global sign-out while disabled, a genuinely new permanent password, enablement, `CONFIRMED`, and the exact two-group set `archon-approvers` plus `archon-runtime-operators`, with automatic containment on every partial failure. |
| `deactivate` | The exact stage account/region/role session, stable stack, pool/group outputs, and immutable email/binding resolve. Availability-sensitive access, group, client, risk, or WAF drift is tolerated. | Disable and global sign-out are always attempted; success additionally requires an exact disabled-state read-back with no group memberships. |

Provision, rotation, reactivation, and deactivation are always explicit choices; none
silently becomes another, and deactivation never deletes evidence-bearing user history. The dispatch contains only
stage and operation; the fixed judge email is an environment secret and never enters
Actions input/event metadata. The workflow always reads `ArchonUserPoolId`,
`ArchonApproverGroupName`, and `ArchonRuntimeOperatorGroupName` from the exact
`Archon-staging` or `Archon-production` stack, accepts only a stable stack, proves the
two group outputs are distinct, and rejects either unexpected group output. Access-enabling
operations additionally read and verify the client, application-origin, and WAF outputs.

Provision writes the stage's high-entropy opaque `JUDGE_ACCOUNT_ID` into the immutable
`custom:archon_judge_binding` attribute. Every later read requires both that exact binding
and the protected email. The
compensation trap is armed before the ambiguous create call and will touch a subsequently
visible user only when its email and binding both match that fixed account. A raced
identity with the same email is therefore never disabled. Rotation binds compensation to
the already-read canonical Cognito username before changing its password. If create or
either permanent-password mutation returns an applied-then-error response, or any
required read-back fails, the trap independently attempts disable, global sign-out, and
removal of both exact runtime-authorization groups, then reads back the exact disabled
state with no group memberships. The run
remains red; containment is not presented as a successful lifecycle result.

## Protected-environment configuration

Create dedicated `judge-access-staging` and `judge-access-production` GitHub
environments. Do not reuse the deployment environments: doing so would share an OIDC
subject and make deployment secrets eligible for this workflow. Restrict both judge
environments to `master`, configure only `upgradedev` as the sole individual GitHub
**User** reviewer (no Teams), allow self-review, disable administrator bypass in the UI, and
allow only this workflow if environment workflow rules are available.

Before requesting an OIDC token, the workflow uses GitHub's environment REST API to
require the exact `judge-access-{stage}` name, one required-reviewer rule,
`prevent_self_review: false`, the sole `upgradedev` User reviewer, the configured reviewer User ID,
custom deployment-branch policies, and exactly one allowed branch named `master`.

The control-plane job selects the stage-specific 256-bit opaque account ID and the
non-secret AWS account, region, exact stage role, and application origin from repository
variables. It publishes only their target fingerprint in the summary and seals the full
target with the canonical stage, operation, operation-specific control-plane receipt
digest, and release SHA into one 64-hex `request_sha256`. The protected environment
account/region/role must match the sealed values before OIDC, and the live stack origin
must match after OIDC. The email is not an input to this job or digest. The opaque account ID
prevents dictionary recovery of plausible email addresses; only the request digest is
published.

Provision, rotation, and reactivation retain the full gate: the current exact master SHA
must have successful CI, CodeQL, and Workflow security push runs. Emergency deactivation
deliberately does not assert those statuses, so an unrelated red pipeline cannot prevent
revocation. Its separate verifier instead requires that same SHA to remain the current
master head and requires both GitHub's caller identity and the direct job identity to be
the exact active `judge-user.yml` workflow at that SHA/ref. It verifies the exact
workflow-run attempt through the Actions API, reads the workflow file at the commit,
matches its decoded content to the Content API Git-blob SHA, and binds a SHA-256 of that
content into a canonical emergency receipt. The receipt is recomputed before and after
OIDC and must retain the V3-sealed digest. The approval summary labels this exception
explicitly; it never presents emergency deactivation as a green-CI result.
The required approval comment is exactly:

```text
ARCHON_JUDGE_ACCESS_APPROVAL_V3|run_id=RUN_ID|run_attempt=RUN_ATTEMPT|request_sha256=REQUEST_SHA256
```

The protected job reads GitHub's
[workflow-run approval history](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run)
and requires exactly one matching `approved` record for the selected environment. Its
approver must be the configured `upgradedev` User ID and login and must equal both
`github.actor` and `github.triggering_actor`. A comment from
another run, rerun attempt, request, reviewer, Team, or environment cannot reach OIDC.
This receipt check is the first protected-job step, before checkout, AWS role
configuration, repository scripts, protected secrets, or OIDC.

GitHub's documented environment REST and GraphQL schemas do not expose the UI's
administrator-bypass toggle, so the workflow makes no API-enforcement claim for that
setting. Disabling bypass remains defense in depth. Even if an administrator uses the UI
bypass, the run has no exact solo-owner approval-history receipt and therefore fails
before OIDC credentials are requested.

Configure:

| Name | Kind | Contract |
|---|---|---|
| `AWS_JUDGE_USER_ROLE_ARN` | protected environment variable | Exact `arn:PARTITION:iam::ACCOUNT_ID:role/archon-STAGE-judge-user` role for this lifecycle only. It must not be the deploy role. |
| `AWS_ACCOUNT_ID` | protected environment variable | Exact 12-digit account containing the selected stack. |
| `AWS_REGION` | protected environment variable | Region containing the selected stack and user pool. |
| `JUDGE_REVIEWER_USER_ID` | protected environment variable | Numeric GitHub ID of the sole `upgradedev` User listed in the environment's required-reviewer rule. It must identify both the workflow actor and rerun actor. |
| `JUDGE_STAGING_ACCOUNT_ID` / `JUDGE_PRODUCTION_ACCOUNT_ID` | repository variables | Distinct password-manager-generated 64-character lower-case hex identifiers. They are non-secret opaque bindings, fixed for the lifetime of each judge identity. |
| `JUDGE_STAGING_AWS_ACCOUNT_ID` / `JUDGE_PRODUCTION_AWS_ACCOUNT_ID` | repository variables | Stage-specific 12-digit AWS targets sealed before approval. |
| `JUDGE_STAGING_AWS_REGION` / `JUDGE_PRODUCTION_AWS_REGION` | repository variables | Stage-specific AWS regions sealed before approval. |
| `JUDGE_STAGING_APPLICATION_URL` / `JUDGE_PRODUCTION_APPLICATION_URL` | repository variables | Exact credential-free HTTPS application origins sealed before approval and matched to `ArchonApplicationUrl`. |
| `JUDGE_USERNAME` | protected environment secret | Fixed exact lower-case judge email for the selected environment. It is used only after approval and never appears in dispatch metadata. |
| `JUDGE_PASSWORD` | protected environment secret | Stable pipeline-managed judge credential used only by `provision`, `rotate`, and `reactivate`; at least 14 characters with lower-case, upper-case, digit, and symbol and no whitespace. |

The AWS foundation creates the two exact
`archon-staging-judge-user` and `archon-production-judge-user` roles. Map each
foundation output to its matching protected environment; do not create or
broaden a second hand-managed role.

Do not define organization- or repository-level values named
`AWS_JUDGE_USER_ROLE_ARN`, `AWS_ACCOUNT_ID`, `AWS_REGION`,
`JUDGE_REVIEWER_USER_ID`, `JUDGE_USERNAME`, or `JUDGE_PASSWORD`. GitHub resolves
same-named values across scopes, so the required environment-only names must not have a
broader-scope fallback when an environment is incomplete.

Never put the judge email or password in a workflow input: dispatch inputs and run
metadata are not a secret-delivery channel. Generate and retain them in the approved
password manager, copy them to the selected protected environment secrets, and deliver
the password to the intended judge through an independent secure channel. A rotation
means replacing `JUDGE_PASSWORD` with a genuinely new value before dispatching `rotate`.
Do the same before `reactivate`; Cognito password history must reject reuse while the
identity remains disabled with no group memberships.
Do not rotate either opaque account ID; changing it intentionally makes the existing
identity ineligible and requires a separately reviewed migration.

Provision generates a separate high-entropy password only inside the runner, uses it for
`AdminCreateUser`, proves the exact workflow-bound bootstrap identity, and immediately
calls `AdminSetUserPassword` with `Permanent: true` and `JUDGE_PASSWORD`. The internal
bootstrap value is never exported or delivered and is unset after the permanent set.
Every access-enabling operation finishes by proving the complete two-group set:
`archon-approvers` plus `archon-runtime-operators`, and then re-reading `Enabled: true`
and `UserStatus: CONFIRMED`; judge access
therefore does not depend on Cognito's three-day temporary-password TTL or a
first-login password-change challenge. The Plus-tier pool retains 24 previous passwords.
The pipeline proves `PasswordHistorySize: 24` before any user read, and Cognito rejects a
same/recent value with `PasswordHistoryPolicyViolationException`; that known
non-mutating rejection occurs before global sign-out, leaves the existing account enabled
and its current credential intact, but keeps the run red.

The workflow maps `JUDGE_PASSWORD` only into the conditional
provision/rotation/reactivation step; deactivation cannot read it. It maps
`JUDGE_USERNAME` only into the selected
lifecycle step. The script immediately copies both secrets to non-exported shell values
and unsets their environment variables before starting any AWS process. It sends both
password mutations to the AWS CLI over standard input, never prints either credential,
and never retains a credential-derived hash. The control-plane job summary contains only the
opaque-identity approval phrase and never the judge username, password, or token
material. GitHub run metadata retains stage, operation, and the opaque request digest;
CloudTrail retains the privileged operation audit trail without credentials in workflow
output.

## Sanitized operation evidence

Every successful operation creates one checksum-sealed artifact named
`judge-user-operation-OPERATION-RELEASE_SHA-RUN_ATTEMPT`. The state receipt is written
by `manage-cognito-judge-user.sh` only after its exact operation precondition and final
AWS read-back succeed. It contains only the operation, stage, domain-separated opaque
identity digest, approved application-origin digest, prior/final state enums,
session-revocation outcome, timestamps, and result. It never contains the email,
password, tokens, pool/client IDs, AWS account/role/region, raw service responses, or
credential hashes. A failed operation does not produce a receipt.

For an access-enabling operation, success is not committed inside the lifecycle script
until the sanitized state receipt has been written and validated. If that write fails
after a successful AWS read-back, the script's exit trap disables the exact bound
identity, attempts global sign-out, removes both exact runtime-authorization groups, and
requires the contained state with no group memberships before the red run exits. The workflow likewise makes one bounded second
artifact-upload attempt when the first upload fails without creating an artifact. It
then resolves exactly one canonical artifact through the Actions API. If receipt sealing
or both durable-retention paths still fail after the script returned a verified enabled
state, a final protected step performs the same exact deactivation and retains a separate
sanitized incident receipt. That failed identity is not eligible for the final SQ4 chain;
create a separately reviewed replacement identity instead of presenting a red run as
evidence.

The protected AWS job adds repository, release, workflow, run/attempt, exact environment
approval-phrase digest, request/target digests, and control-plane gate bindings. The
artifact inventory is exactly `judge-operation-state.json`, `operation-receipt.json`,
`manifest.json`, `attestation-predicate.json`,
`judge-user-operation-subject.sha256`, and `SHA256SUMS`. A dependent job has no
environment, AWS credentials, or protected secrets. It uses only `actions: read`,
`contents: read`, `attestations: write`, and `id-token: write`; it resolves the exact
artifact ID through the Actions API, binds its name/digest/run/head SHA, downloads only
that ID, revalidates the inventory, checksums, receipt, manifest, and custom predicate,
then attests the three subjects with
`https://github.com/upgradedev/archon-datahub/attestations/judge-user-operation/v1`.
The artifact exports its immutable producer run attempt. If only the secretless
attestation job fails transiently, **Re-run failed jobs** verifies and signs the original
producer-attempt bytes; it does not reinterpret the new attester attempt as a new
lifecycle mutation. Do not use **Re-run all jobs** to recover `provision`.

For emergency deactivation, `sessionRevocation` is
`response-confirmed` only when global sign-out returned success. An ambiguous response
is recorded as `contained-by-disabled-state`; the run can still prove the disabled
containment boundary with no group memberships without overclaiming
session-revocation confirmation.
The project-access evidence pipeline accepts four distinct exact production
run IDs and independently verifies their artifacts and attestations. It is responsible for
enforcing the strictly ordered
`provision → rotate → deactivate → reactivate` chain, a common release, opaque identity,
and application origin. An individual judge-user run never asserts that aggregate.

The workflow deliberately does not set `email_verified=true`. A value supplied by an
operator is not proof that the recipient controls that mailbox. The judge credential
must not be used as substitute mailbox proof. Deliver the stable judge password only
after the operator has authenticated the intended recipient through the organization's
approved out-of-band channel; password recovery remains unavailable until Cognito has an
actually verified recovery attribute. Every lifecycle read rejects a verified recovery
email or any preferred, modern, or legacy MFA factor before it can activate or rotate
access. Deactivation is intentionally still allowed to disable, globally sign out, and
remove authorization from the exact immutable email/binding when either drift is found.

## Shared-judge client and threat-protection boundary

For provision, rotation, and reactivation, before any user read or mutation, the
lifecycle pipeline proves the deployed SPA client is the exact stack output and that
`ListUserPoolClients` returns exactly that one client, with no hidden next page. It then
proves the client has only `ExplicitAuthFlows:
["ALLOW_REFRESH_TOKEN_AUTH"]`, OAuth authorization code flow, Cognito as the identity
provider, and the sorted scope set `archon/approve email openid`. It derives the only
allowed callback and logout URI from the exact credential-free HTTPS
`ArchonApplicationUrl` stack output, rejects any extra redirect, and permits a default
redirect only when it is that same URI. It also requires
`PreventUserExistenceErrors: ENABLED`, `AllowedOAuthFlowsUserPoolClient: true`, and explicitly rejects
`aws.cognito.signin.user.admin`. Cognito's `ChangePassword` operation requires that
admin scope, so a judge access token cannot self-change the shared password; provision
and rotation remain explicit, protected solo-owner-approved pipeline operations.

The client-specific threat policy deliberately uses `NO_ACTION` with `Notify: false` at
low, medium, and high account-takeover risk. A shared hackathon judge identity can
legitimately appear from new devices, networks, and geographies, while it has neither a
per-reviewer MFA factor nor a verified recovery/notification mailbox. Adaptive blocking
or notification would therefore create an unsafe false-lockout and recovery path. This
does not disable compromised-credential protection: the exact `SIGN_IN` and
`PASSWORD_CHANGE` event set is configured as `BLOCK`, with no risk-exception ranges.

For provision, rotation, and reactivation, the pipeline calls
`DescribeRiskConfiguration` with both the exact user-pool ID and SPA client ID and proves
those actions and filters before it can touch the judge identity.
The stack directly associates `ArchonRegionalWebAclArn` with both API Gateway and the
exact Cognito user pool. On those access-enabling operations, before reading an admin
user, the lifecycle pipeline calls
`GetWebACLForResource` for the exact user-pool ARN and proves that association, the four
compatible managed/rate rules, the stage-specific rate limit, and the absence of
ATP/ACFP or CAPTCHA rules. That regional control protects managed login and the
unauthenticated Cognito API surface; the separate edge ACL protects the SPA and
same-origin API path. These WAF controls, a strong password-manager-generated stable
credential, 15-minute access/ID tokens, a one-day refresh token, threat protection,
CloudTrail management-event audit history, and the explicitly solo-owner-approved
rotate/reactivate/deactivate path are the
compensating controls. This policy avoids availability failures for legitimate
reviewers without treating account-takeover `NO_ACTION` as the only compromise defense.
Emergency deactivation deliberately skips these availability-sensitive posture gates
after it proves the exact account/region/role session, stable stack, pool/group outputs,
immutable email/binding, and canonical user. Access, group, client, risk, or WAF drift
must not prevent disable and global sign-out attempts; unexpected residual groups still
keep the run red after the revocation attempts.

All group reads use Cognito's maximum 60-item page and reject `NextToken`; no first-page
result can be presented as exact two-group or empty-membership proof while hidden
memberships remain.

## OIDC and least-privilege IAM

Create a separate role for each protected environment. Its trust policy must accept only
the repository's exact environment subject and GitHub's STS audience. Replace
`ENVIRONMENT` with either `judge-access-staging` or
`judge-access-production`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:upgradedev/archon-datahub:environment:ENVIRONMENT"
      }
    }
  }]
}
```

Attach only the exact stack and user-pool permissions required by the workflow:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadExactArchonStackOutputs",
      "Effect": "Allow",
      "Action": "cloudformation:DescribeStacks",
      "Resource": "arn:aws:cloudformation:REGION:ACCOUNT_ID:stack/Archon-STAGE/*"
    },
    {
      "Sid": "ManageExactArchonJudgeIdentity",
      "Effect": "Allow",
      "Action": [
        "cognito-idp:AdminAddUserToGroup",
        "cognito-idp:AdminCreateUser",
        "cognito-idp:AdminDisableUser",
        "cognito-idp:AdminEnableUser",
        "cognito-idp:AdminGetUser",
        "cognito-idp:AdminListGroupsForUser",
        "cognito-idp:AdminRemoveUserFromGroup",
        "cognito-idp:AdminSetUserPassword",
        "cognito-idp:AdminUserGlobalSignOut",
        "cognito-idp:DescribeRiskConfiguration",
        "cognito-idp:DescribeUserPool",
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:ListUserPoolClients"
      ],
      "Resource": "arn:aws:cognito-idp:REGION:ACCOUNT_ID:userpool/USER_POOL_ID"
    },
    {
      "Sid": "ReadExactArchonCognitoWebAcl",
      "Effect": "Allow",
      "Action": [
        "wafv2:GetWebACL",
        "wafv2:GetWebACLForResource"
      ],
      "Resource": "arn:aws:wafv2:REGION:ACCOUNT_ID:regional/webacl/archon-STAGE-api/WEB_ACL_ID"
    }
  ]
}
```

Replace `STAGE` with `staging` or `production`; unlike the OIDC environment name,
the stack name does not include the `judge-access-` prefix.

The workflow requests the STS minimum 900-second role session and, before any stack read,
requires `GetCallerIdentity` to return the exact stage role and
`archon-judge-RUN_ID-STAGE` session ARN—not merely an identity in the same account.

CloudTrail's management-event history provides retrospective audit evidence for these
administrative calls, subject to its service retention window. It is not described here
as real-time monitoring or alerting.

`sts:GetCallerIdentity` does not require an identity-policy grant. Do not add
`cognito-idp:ListUsers`, user deletion, group creation, pool mutation, wildcard Cognito
or WAF resources, WAF mutation, or deployment permissions. The workflow serializes all
judge-user operations per environment and refuses AWS endpoint/profile overrides,
including the official Cognito Identity Provider and WAFv2 override variables. It also
sets `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true` and uses empty AWS config/credential files
as defense in depth.

For provision, rotation, and reactivation, the script verifies the live user-pool name,
email-only username mode, disabled self-registration, case-insensitive usernames,
24-entry password history, password complexity, three-day temporary password validity
for the undisclosed bootstrap credential, deletion protection, the immutable 64-hex judge
binding, token revocation, exact code-flow/scope boundary, client-specific risk policy,
and the exact 15-minute access/ID token and one-day refresh-token lifetimes before
touching a user. Those operations also require the exact stack-exported regional Web ACL
to be directly associated with the pool and to retain the compatible fixed rule set
before any user read or mutation. Emergency deactivation uses only the core target,
stack-output, immutable-identity, and revocation checks described above.
The SPA client can read only the standard email attribute, so the workflow binding is
not projected into judge tokens. Rotation and deactivation call
`AdminUserGlobalSignOut`. Deactivation attempts disable, global sign-out, and group
removal independently even when an earlier response is ambiguous, and only evaluates
success after exact canonical-user and group read-back. This prevents new refreshes and invalidates
Cognito-managed sessions, but a downstream service that only validates a JWT signature
can still accept an already-issued access token until its configured 15-minute expiry,
as documented in
[Cognito token-revocation semantics](https://docs.aws.amazon.com/cognito/latest/developerguide/token-revocation.html).
Treat that bounded interval as the revocation SLO; use the API/WAF break-glass boundary
if immediate containment is required.

`signInCaseSensitive: false` is now explicit in the CDK source for newly created pools.
Amazon Cognito
[cannot convert an existing case-sensitive pool in place](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-case-sensitivity.html).
If a stack was already deployed with the former default, migrate that retained pool
deliberately before enabling this workflow; the live-contract check will fail closed
instead of mutating it.

Deploy the immutable `archon_judge_binding` schema addition before the first lifecycle
run. A pre-existing judge identity without that workflow-owned binding is intentionally
ineligible for rotation or deactivation through this path; migrate it under a separately
reviewed break-glass procedure instead of weakening the exact-identity check.

## Runbook

1. Generate distinct 256-bit `JUDGE_STAGING_ACCOUNT_ID` and
   `JUDGE_PRODUCTION_ACCOUNT_ID` repository variables once. Also set the stage-specific
   repository target variables for AWS account, region, and application URL. Set each protected
   environment's `JUDGE_USERNAME` secret to its fixed lower-case judge email. For
   `provision`, set `JUDGE_PASSWORD` to the password-manager value intended for the judge.
   For `rotate` or `reactivate`, replace it with a value outside the last 24 passwords before dispatch.
   `deactivate` does not read the password secret.
2. From **Actions → Manage Cognito judge user → Run workflow**, select the environment and
   explicit operation. There is deliberately no username or password input.
3. Open the completed control-plane job and copy its exact approval phrase. The configured
   solo owner enters that phrase as the environment approval comment. The
   workflow requires the exact default-branch SHA to have successful CI, CodeQL, and
   Workflow security runs for provision, rotation, and reactivation. Deactivation instead
   displays the explicit emergency/current-master warning, exact workflow SHA, and
   validated workflow-file SHA-256 because it does not claim green CI status. Both paths
   verify the attempt-bound solo-owner
   approval receipt before OIDC and recompute their sealed control-plane receipt before
   and immediately after requesting AWS credentials.
4. Require a green read-back result. A red run means the requested end state was not
   proved; inspect its generic error and CloudTrail rather than retrying a different
   operation implicitly. For evidence-bearing production runs, also require the
   dependent attestation job to be green and retain the exact run ID; an unattested
   operation must not enter the four-step project-access chain. A transient failure
   confined to the secretless attestation job may use **Re-run failed jobs**. If the
   summary says `Lifecycle evidence failure contained`, keep that identity disabled and
   establish a separately reviewed replacement identity before starting a new four-step
   final chain.
5. For provision/rotation/reactivation, send the stable judge password out of band only after the
   `CONFIRMED` read-back succeeds. For deactivation, confirm the successful run before
   treating access as revoked, then remove the unused protected password secret when the
   access window is permanently closed.
6. The final live multi-network Hosted UI journey is deliberately user-gated. After the
   protected deployment and provision succeed, an authorized judge/operator must exercise
   authorization code + PKCE and the read-only/approval journey from at least two
   representative networks, including the expected remote-judge path. Record only
   pass/fail, timestamps, and non-sensitive receipt digests—never credentials or tokens.
   CI proves the configuration contract, but this human journey remains open until the
   live environment and intended judge are available.
