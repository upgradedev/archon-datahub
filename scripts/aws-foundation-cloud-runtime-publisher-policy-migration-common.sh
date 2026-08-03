#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "AWS foundation cloud runtime publisher identity-policy migration is CI-only" >&2
  exit 1
fi
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

exec 3>&1

readonly FOUNDATION_ROLE_NAME="archon-datahub-github-foundation"
readonly RECOVERY_ROLE_NAME="archon-datahub-github-governed-canary-recovery"
readonly BASE_POLICY_NAME="archon-staging-stack-read"
readonly TEMP_POLICY_NAME="archon-foundation-cloud-runtime-publisher-identity-policy-migration"
readonly TARGET_POLICY_NAME="archon-aws-foundation-identity"
readonly CONTRACT="contracts/aws-foundation-cloud-runtime-publisher-policy-migration-v1.json"
readonly SOURCE_POLICY="infra/aws/foundation/github-actions-foundation-policy.json"
readonly RENDERER="scripts/render-aws-foundation-policy.mjs"
readonly WORK_ROOT="${RUNNER_TEMP}/archon-aws-foundation-cloud-runtime-publisher-policy-migration"
readonly RETRY_ATTEMPTS="12"
readonly RETRY_DELAY_SECONDS="5"
readonly ABSENCE_CONFIRMATIONS="3"

mkdir -p "${WORK_ROOT}"
chmod 0700 "${WORK_ROOT}"

fail() {
  printf '::error::%s\n' "$1" >&2
  return 1
}

mask_value() {
  printf '::add-mask::%s\n' "$1" >&3
}

safe_aws() {
  local label="$1"
  local output="$2"
  shift 2
  if ! aws "$@" >"${output}" 2>/dev/null; then
    fail "${label}"
    return 1
  fi
  test -f "${output}" || {
    fail "${label}: response is not a regular file"
    return 1
  }
  test ! -L "${output}" || {
    fail "${label}: response is a symlink"
    return 1
  }
  chmod 0600 "${output}" || return 1
}

canonical_iam_policy() {
  local input="$1"
  local filter="${2:-.}"
  jq -cS "
    ${filter} |
    .Version as \$version |
    (.Statement |
      map(
        .Action |= (if type == \"array\" then sort else [.] end) |
        .Resource |= (if type == \"array\" then sort else [.] end)
      ) |
      sort_by(.Sid)
    ) as \$statements |
    {Version: \$version, Statement: \$statements}
  " "${input}"
}

iam_policy_sha() {
  canonical_iam_policy "$1" "${2:-.}" |
    sha256sum |
    awk '{print $1}'
}

validate_common() {
  : "${AWS_ACCOUNT_ID:?AWS_ACCOUNT_ID is required}"
  : "${CONTROL_PLANE_SHA:?CONTROL_PLANE_SHA is required}"
  [[ "${AWS_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]] ||
    fail "AWS account binding is invalid"
  [[ "${CONTROL_PLANE_SHA}" =~ ^[0-9a-f]{40}$ ]] ||
    fail "Control-plane SHA is invalid"
  for path in "${CONTRACT}" "${SOURCE_POLICY}" "${RENDERER}"; do
    test -f "${path}"
    test ! -L "${path}"
  done
  mask_value "${AWS_ACCOUNT_ID}"
  if [[ -n "${AWS_FOUNDATION_ROLE_ARN:-}" ]]; then
    mask_value "${AWS_FOUNDATION_ROLE_ARN}"
  fi
  if [[ -n "${AWS_CANARY_RECOVERY_ROLE_ARN:-}" ]]; then
    mask_value "${AWS_CANARY_RECOVERY_ROLE_ARN}"
  fi
  jq -e '
    .schemaVersion ==
      "archon.aws-foundation-cloud-runtime-publisher-policy-migration/v1" and
    .status == "ready-for-migration" and
    .source == {
      branch: "master",
      policyBundle:
        "infra/aws/foundation/github-actions-foundation-policy.json",
      renderer: "scripts/render-aws-foundation-policy.mjs",
      repository: "upgradedev/archon-datahub"
    } and
    .workflow.entry ==
      ".github/workflows/aws-foundation-cloud-runtime-publisher-policy-migration.yml" and
    .workflow.driver ==
      ".github/workflows/aws-foundation-cloud-runtime-publisher-policy-migration-driver.yml" and
    .workflow.cleanup ==
      ".github/workflows/aws-foundation-cloud-runtime-publisher-policy-migration-cleanup.yml" and
    .workflow.branch == "master" and
    .workflow.outerConcurrencyGroup == "archon-aws-control-plane" and
    .workflow.innerConcurrencyGroup ==
      "archon-governed-canary-mutation-recovery" and
    .workflow.queue == "max" and
    .workflow.confirmation ==
      "MIGRATE EXACT CLOUD RUNTIME PUBLISHER IDENTITY POLICY" and
    .workflow.cleanupConfirmation ==
      "RECOVER EXACT CLOUD RUNTIME PUBLISHER IDENTITY POLICY MIGRATION" and
    .workflow.ownerActorOnly == true and
    .workflow.exactHeadRequired == true and
    .workflow.exactParentAttemptJobsRequired == true and
    .workflow.automaticCleanupCurrentHeadIndependent == true and
    .implementation == {
      driver:
        "scripts/run-aws-foundation-cloud-runtime-publisher-policy-migration.sh",
      environmentVerifier: "scripts/verify-github-environment-protection.sh",
      libraries: [
        "scripts/aws-foundation-cloud-runtime-publisher-policy-migration-authorization.sh",
        "scripts/aws-foundation-cloud-runtime-publisher-policy-migration-common.sh",
        "scripts/aws-foundation-cloud-runtime-publisher-policy-migration-state.sh"
      ]
    } and
    .policy.group == "identity" and
    .policy.name == "archon-aws-foundation-identity" and
    .policy.sourceBundle ==
      "infra/aws/foundation/github-actions-foundation-policy.json" and
    .policy.renderer == "scripts/render-aws-foundation-policy.mjs" and
    .policy.liveBaseline == {
      canonicalSha256:
        "afda76cf8cfddd34c876147a4b228dd51b63edc4fd810f6793eb22d462beb553",
      isDefault: true,
      versionId: "v1"
    } and
    .policy.target == {
      canonicalSha256:
        "f8aab593f428ac9d990cefb525d0919241e81c42b09f22d737a97d1fd3dc18a3",
      expectedVersionId: "v2"
    } and
    .policy.initialVersionCount == 1 and
    .policy.successfulVersionCount == 2 and
    .policy.retainPreviousDefaultForRollback == true and
    .policy.maximumDocumentBytes == 6144 and
    .policy.exactDelta.resourceAdditions == [
      {
        resources: [
          "arn:aws:iam::${aws:PrincipalAccount}:role/archon-datahub-github-staging-cloud-trial",
          "arn:aws:iam::${aws:PrincipalAccount}:role/archon-datahub-github-production-cloud-trial"
        ],
        statementSid: "ReconcileExactBootstrapAndDeployRoles"
      }
    ] and
    .policy.exactDelta.newStatements == [
      {
        actions: [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:DeleteRolePolicy",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:ListRolePolicies",
          "iam:ListRoleTags",
          "iam:PutRolePolicy",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:UpdateAssumeRolePolicy",
          "iam:UpdateRole",
          "iam:UpdateRoleDescription"
        ],
        effect: "Allow",
        resource:
          "arn:aws:iam::${aws:PrincipalAccount}:role/archon-datahub-cloud-runtime-publish-production",
        sid: "ReconcileExactCloudRuntimePublisherRole"
      }
    ] and
    .policy.exactDelta.noOtherStatementChange == true and
    .authorization.installerEnvironment == "aws-foundation" and
    .authorization.executorEnvironment == "governed-canary-recovery" and
    .authorization.executorRoleName ==
      "archon-datahub-github-governed-canary-recovery" and
    .authorization.temporaryPolicyName ==
      "archon-foundation-cloud-runtime-publisher-identity-policy-migration" and
    .authorization.ttlSeconds == 1200 and
    .authorization.managedPolicyActions == [
      "iam:CreatePolicyVersion",
      "iam:DeletePolicyVersion",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListPolicyVersions",
      "iam:SetDefaultPolicyVersion"
    ] and
    .authorization.rollbackManagedPolicyActions == [
      "iam:DeletePolicyVersion",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListPolicyVersions",
      "iam:SetDefaultPolicyVersion"
    ] and
    .authorization.temporaryPolicyReadAction == "iam:GetRolePolicy" and
    .authorization.selfPersistenceActionsAllowed == false and
    .authorization.canonicalReadbackRequired == true and
    .authorization.mandatoryRevocation == true and
    .authorization.absenceReadCount == 3 and
    .recovery.automaticFollowerOnNonSuccess == true and
    .recovery.manualDispatch == true and
    .recovery.manualDispatchMode == "cleanup-rollback" and
    .recovery.freshRollbackOnlyAuthorization == true and
    .recovery.rollbackToPreviousDefault == true and
    .recovery.deleteOnlyNewNondefaultVersion == true and
    .recovery.mandatoryAuthorizationRevocation == true and
    .recovery.revokeOnlyPreservesExactTerminalState == true and
    .recovery.parentOutcomeClassification == {
      migrateSucceeded: "cleanup-migrated",
      prepareSucceededWithoutSuccessfulMigrationOrRollback:
        "cleanup-rollback",
      rollbackSucceeded: "cleanup-revoke",
      validatedPrepareNotSucceeded: "cleanup-revoke",
      validationNotSucceeded: "no-aws"
    } and
    .evidence.schemaVersion ==
      "archon.aws-foundation-cloud-runtime-publisher-policy-migration-receipt/v1" and
    .evidence.artifactFiles == ["SHA256SUMS", "migration.json"] and
    .evidence.artifactRetentionDays == 90 and
    .evidence.canonicalJson == true and
    .evidence.checksumSealed == true and
    .evidence.attestationRequired == true and
    .evidence.sensitiveIdentifiersAllowed == false
  ' "${CONTRACT}" >/dev/null || fail "The publisher migration contract differs"
}

verify_caller() {
  local expected_role="$1"
  local identity="${WORK_ROOT}/caller-${expected_role}.json"
  safe_aws "Unable to verify the AWS migration caller" "${identity}" \
    sts get-caller-identity --output json
  jq -e \
    --arg account "${AWS_ACCOUNT_ID}" \
    --arg role "${expected_role}" '
      .Account == $account and
      (.Arn | test(
        "^arn:aws:sts::" + $account + ":assumed-role/" + $role +
        "/[A-Za-z0-9+=,.@_-]+$"
      ))
    ' "${identity}" >/dev/null || fail "AWS migration caller identity differs"
}

render_policy_documents() {
  NEW_POLICY="${WORK_ROOT}/identity-new.json"
  OLD_POLICY="${WORK_ROOT}/identity-previous.json"
  local raw="${WORK_ROOT}/identity-new.raw.json"
  node "${RENDERER}" \
    --input "${SOURCE_POLICY}" \
    --account "${AWS_ACCOUNT_ID}" \
    --stdout-group identity >"${raw}" ||
    fail "Unable to render the exact foundation identity policy"
  canonical_iam_policy "${raw}" >"${NEW_POLICY}" || {
    fail "Rendered foundation identity policy is invalid"
    return 1
  }
  chmod 0600 "${raw}" "${NEW_POLICY}"
  jq -e \
    --slurpfile contract "${CONTRACT}" \
    --arg account "${AWS_ACCOUNT_ID}" '
      . as $new |
      ($contract[0].policy.exactDelta.resourceAdditions[0]) as $addition |
      ($contract[0].policy.exactDelta.newStatements[0]) as $statement |
      ($addition.resources |
        map(gsub("\\$\\{aws:PrincipalAccount\\}"; $account)) |
        sort) as $addedResources |
      ($statement.resource |
        gsub("\\$\\{aws:PrincipalAccount\\}"; $account)) as $newResource |
      ([$new.Statement[] | select(.Sid == $addition.statementSid)]) as $targets |
      ([$new.Statement[] | select(.Sid == $statement.sid)]) as $newStatements |
      .Version == "2012-10-17" and
      ($targets | length) == 1 and
      ($targets[0].Resource | type) == "array" and
      all($addedResources[];
        . as $resource |
        ([$targets[0].Resource[] | select(. == $resource)] | length) == 1) and
      ($newStatements | length) == 1 and
      ($newStatements[0] | keys | sort) ==
        ["Action", "Effect", "Resource", "Sid"] and
      $newStatements[0].Effect == $statement.effect and
      (($newStatements[0].Action |
        if type == "array" then sort else [.] end) ==
        ($statement.actions | sort)) and
      (($newStatements[0].Resource |
        if type == "array" then . else [.] end) == [$newResource]) and
      $newResource != "*" and
      ($newResource | contains($account)) and
      (tostring | contains($account)) and
      (tostring | contains("${AWS::AccountId}") | not) and
      (tostring | contains("${aws:PrincipalAccount}") | not)
    ' "${NEW_POLICY}" >/dev/null ||
      fail "The rendered publisher identity-policy delta is invalid"
  local old_raw="${WORK_ROOT}/identity-previous.raw.json"
  jq -cS \
    --slurpfile contract "${CONTRACT}" \
    --arg account "${AWS_ACCOUNT_ID}" '
      ($contract[0].policy.exactDelta.resourceAdditions[0]) as $addition |
      ($contract[0].policy.exactDelta.newStatements[0].sid) as $newSid |
      ($addition.resources |
        map(gsub("\\$\\{aws:PrincipalAccount\\}"; $account))) as $addedResources |
      .Statement |= map(
        select(.Sid != $newSid) |
        if .Sid == $addition.statementSid then
          .Resource |= map(
            . as $resource |
            select(($addedResources | index($resource)) == null)
          )
        else . end
      )
    ' "${NEW_POLICY}" >"${old_raw}" || {
    fail "Unable to derive the exact previous identity policy"
    return 1
  }
  canonical_iam_policy "${old_raw}" >"${OLD_POLICY}" || return 1
  chmod 0600 "${old_raw}" "${OLD_POLICY}"
  jq -e \
    --slurpfile contract "${CONTRACT}" \
    --slurpfile previous "${OLD_POLICY}" \
    --arg account "${AWS_ACCOUNT_ID}" '
      . as $new |
      ($previous[0]) as $old |
      ($contract[0].policy.exactDelta.resourceAdditions[0]) as $addition |
      ($contract[0].policy.exactDelta.newStatements[0].sid) as $newSid |
      ($addition.resources |
        map(gsub("\\$\\{aws:PrincipalAccount\\}"; $account)) |
        sort) as $addedResources |
      ([$new.Statement[] | select(.Sid == $addition.statementSid)][0]) as $newTarget |
      ([$old.Statement[] | select(.Sid == $addition.statementSid)][0]) as $oldTarget |
      ($new.Statement | length) == (($old.Statement | length) + 1) and
      ([$old.Statement[] | select(.Sid == $newSid)] | length) == 0 and
      ([$new.Statement[] | select(.Sid == $newSid)] | length) == 1 and
      ($newTarget | del(.Resource)) == ($oldTarget | del(.Resource)) and
      (($newTarget.Resource | sort) ==
        (($oldTarget.Resource + $addedResources) | sort)) and
      all($addedResources[];
        . as $resource |
        ([$oldTarget.Resource[] | select(. == $resource)] | length) == 0) and
      ([$new.Statement[] |
        select(.Sid != $newSid and .Sid != $addition.statementSid)] ==
       [$old.Statement[] |
        select(.Sid != $addition.statementSid)])
    ' "${NEW_POLICY}" >/dev/null ||
      fail "The previous identity-policy derivation differs"
  NEW_POLICY_SHA="$(iam_policy_sha "${NEW_POLICY}")"
  OLD_POLICY_SHA="$(iam_policy_sha "${OLD_POLICY}")"
  local expected_old expected_new
  expected_old="$(jq -er '.policy.liveBaseline.canonicalSha256' "${CONTRACT}")"
  expected_new="$(jq -er '.policy.target.canonicalSha256' "${CONTRACT}")"
  test "${OLD_POLICY_SHA}" = "${expected_old}" ||
    fail "Derived v1 identity-policy digest differs"
  test "${NEW_POLICY_SHA}" = "${expected_new}" ||
    fail "Rendered v2 identity-policy digest differs"
  test "${NEW_POLICY_SHA}" != "${OLD_POLICY_SHA}" ||
    fail "The publisher identity-policy migration delta is empty"
  test "$(wc -c <"${NEW_POLICY}" | awk '{print $1}')" -le 6144 ||
    fail "The rendered identity policy exceeds the managed-policy limit"
  TARGET_POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${TARGET_POLICY_NAME}"
  RECOVERY_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${RECOVERY_ROLE_NAME}"
}

verify_recovery_role_baseline() {
  local role="${WORK_ROOT}/recovery-role.json"
  local inline="${WORK_ROOT}/recovery-inline.json"
  local attached="${WORK_ROOT}/recovery-attached.json"
  local base="${WORK_ROOT}/recovery-base.json"
  safe_aws "Unable to inspect the exact recovery role" "${role}" \
    iam get-role --role-name "${RECOVERY_ROLE_NAME}" --output json
  jq -e \
    --arg account "${AWS_ACCOUNT_ID}" \
    --arg roleArn "${RECOVERY_ROLE_ARN}" '
      .Role.Arn == $roleArn and
      .Role.RoleName == "archon-datahub-github-governed-canary-recovery" and
      .Role.MaxSessionDuration == 3600 and
      ([.Role.Tags[] | {key: .Key, value: .Value}] | sort_by(.key)) == [
        {key: "Application", value: "archon-datahub"},
        {key: "Environment", value: "governed-canary-recovery"},
        {key: "ManagedBy", value: "github-actions"}
      ] and
      .Role.AssumeRolePolicyDocument.Version == "2012-10-17" and
      (.Role.AssumeRolePolicyDocument.Statement | length) == 1 and
      .Role.AssumeRolePolicyDocument.Statement[0].Sid ==
        "GitHubEnvironmentOidcOnly" and
      .Role.AssumeRolePolicyDocument.Statement[0].Effect == "Allow" and
      .Role.AssumeRolePolicyDocument.Statement[0].Action ==
        "sts:AssumeRoleWithWebIdentity" and
      .Role.AssumeRolePolicyDocument.Statement[0].Principal.Federated ==
        ("arn:aws:iam::" + $account +
        ":oidc-provider/token.actions.githubusercontent.com") and
      .Role.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals[
        "token.actions.githubusercontent.com:aud"
      ] == "sts.amazonaws.com" and
      .Role.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals[
        "token.actions.githubusercontent.com:sub"
      ] == "repo:upgradedev/archon-datahub:environment:governed-canary-recovery"
    ' "${role}" >/dev/null || fail "The recovery role identity or trust differs"
  safe_aws "Unable to inspect recovery-role inline policies" "${inline}" \
    iam list-role-policies --role-name "${RECOVERY_ROLE_NAME}" --output json
  jq -e --arg base "${BASE_POLICY_NAME}" '
    (.PolicyNames | sort) == [$base]
  ' "${inline}" >/dev/null || fail "The recovery role is not at its exact baseline"
  safe_aws "Unable to inspect recovery-role attachments" "${attached}" \
    iam list-attached-role-policies \
    --role-name "${RECOVERY_ROLE_NAME}" --output json
  jq -e '.AttachedPolicies == []' "${attached}" >/dev/null ||
    fail "The recovery role contains an attached managed policy"
  safe_aws "Unable to inspect the recovery-role base policy" "${base}" \
    iam get-role-policy \
    --role-name "${RECOVERY_ROLE_NAME}" \
    --policy-name "${BASE_POLICY_NAME}" \
    --output json
  jq -e \
    --arg account "${AWS_ACCOUNT_ID}" '
      .RoleName == "archon-datahub-github-governed-canary-recovery" and
      .PolicyName == "archon-staging-stack-read" and
      .PolicyDocument.Version == "2012-10-17" and
      (.PolicyDocument.Statement | length) == 1 and
      .PolicyDocument.Statement[0].Sid == "ReadExactStagingStack" and
      .PolicyDocument.Statement[0].Effect == "Allow" and
      .PolicyDocument.Statement[0].Action == "cloudformation:DescribeStacks" and
      .PolicyDocument.Statement[0].Resource ==
        ("arn:aws:cloudformation:eu-west-1:" + $account +
        ":stack/Archon-staging/*")
    ' "${base}" >/dev/null || fail "The recovery-role base policy differs"
}