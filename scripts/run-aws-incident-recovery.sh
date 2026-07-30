#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "AWS incident recovery is CI-only" >&2
  exit 1
fi
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

# Preserve the runner command stream across command/process substitutions. Values
# written to fd 3 are masked without contaminating captured function stdout.
exec 3>&1

readonly INCIDENT_RUN_ID="30546241677"
readonly INCIDENT_RUN_ATTEMPT="1"
readonly TARGET_REGION="eu-west-1"
readonly TARGET_STACK_NAME="Archon-Staging-IAM-Foundation"
readonly TARGET_TEMPLATE_SHA="80a2b02326bbaa3ae145d0fff52cc1c20f3a330d4ef5c7fa2d816182f7c2b825"
readonly ROLE_SOURCE_SHA="0ab7fc740588232d25c16f92ccf636e45a80b7d4c1b7d8f462b853ea3c9e75c4"
readonly ROLE_STACK_NAME="Archon-Governed-Canary-Roles"
readonly RECOVERY_ROLE_NAME="archon-datahub-github-governed-canary-recovery"
readonly BASE_POLICY_NAME="archon-staging-stack-read"
readonly TEMP_POLICY_NAME="archon-incident-30546241677-delete"
readonly WORK_ROOT="${RUNNER_TEMP}/archon-aws-incident-recovery"
readonly VALIDATOR="scripts/aws-incident-recovery.mjs"
readonly IAM_PROPAGATION_ATTEMPTS="12"
readonly IAM_PROPAGATION_DELAY_SECONDS="5"
readonly IAM_ABSENCE_CONFIRMATIONS="3"

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
  fi
  test -f "${output}"
  test ! -L "${output}"
  chmod 0600 "${output}"
}

retry_safe_aws() {
  local label="$1"
  local output="$2"
  shift 2
  local attempt
  for ((attempt = 1; attempt <= IAM_PROPAGATION_ATTEMPTS; attempt++)); do
    if aws "$@" >"${output}" 2>/dev/null; then
      test -f "${output}"
      test ! -L "${output}"
      chmod 0600 "${output}"
      return 0
    fi
    if ((attempt < IAM_PROPAGATION_ATTEMPTS)); then
      sleep "${IAM_PROPAGATION_DELAY_SECONDS}"
    fi
  done
  fail "${label} after bounded IAM propagation retries"
}

wait_for_policy_digest() {
  local expected_digest="$1"
  local output="$2"
  local attempt
  local observed_digest
  [[ "${expected_digest}" =~ ^[a-f0-9]{64}$ ]] || fail "Expected policy digest is invalid"
  for ((attempt = 1; attempt <= IAM_PROPAGATION_ATTEMPTS; attempt++)); do
    if aws iam get-role-policy \
      --role-name "${RECOVERY_ROLE_NAME}" \
      --policy-name "${TEMP_POLICY_NAME}" \
      --output json >"${output}" 2>/dev/null; then
      test -f "${output}"
      test ! -L "${output}"
      chmod 0600 "${output}"
      observed_digest="$(jq -cS '.PolicyDocument' "${output}" | sha256sum | awk '{print $1}')"
      if test "${observed_digest}" = "${expected_digest}"; then
        return 0
      fi
    fi
    if ((attempt < IAM_PROPAGATION_ATTEMPTS)); then
      sleep "${IAM_PROPAGATION_DELAY_SECONDS}"
    fi
  done
  fail "The temporary recovery authorization was not canonically readable after bounded IAM propagation retries"
}

wait_for_policy_absence() {
  local output="$1"
  local attempt
  local consecutive_absent=0
  for ((attempt = 1; attempt <= IAM_PROPAGATION_ATTEMPTS; attempt++)); do
    if aws iam list-role-policies \
      --role-name "${RECOVERY_ROLE_NAME}" \
      --output json >"${output}" 2>/dev/null; then
      test -f "${output}"
      test ! -L "${output}"
      chmod 0600 "${output}"
      if jq -e --arg base "${BASE_POLICY_NAME}" '
        (.PolicyNames | sort) == [$base]
      ' "${output}" >/dev/null; then
        consecutive_absent=$((consecutive_absent + 1))
        if ((consecutive_absent >= IAM_ABSENCE_CONFIRMATIONS)); then
          return 0
        fi
      else
        consecutive_absent=0
      fi
    else
      consecutive_absent=0
    fi
    if ((attempt < IAM_PROPAGATION_ATTEMPTS)); then
      sleep "${IAM_PROPAGATION_DELAY_SECONDS}"
    fi
  done
  fail "The temporary recovery authorization lacks repeated canonical absence after bounded IAM propagation retries"
}

validate_common() {
  : "${AWS_ACCOUNT_ID:?AWS_ACCOUNT_ID is required}"
  : "${CONTROL_PLANE_SHA:?CONTROL_PLANE_SHA is required}"
  [[ "${AWS_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]] || fail "AWS account binding is invalid"
  [[ "${CONTROL_PLANE_SHA}" =~ ^[0-9a-f]{40}$ ]] || fail "Control-plane SHA is invalid"
  mask_value "${AWS_ACCOUNT_ID}"
  if [[ -n "${AWS_FOUNDATION_ROLE_ARN:-}" ]]; then
    mask_value "${AWS_FOUNDATION_ROLE_ARN}"
  fi
  if [[ -n "${AWS_CANARY_RECOVERY_ROLE_ARN:-}" ]]; then
    mask_value "${AWS_CANARY_RECOVERY_ROLE_ARN}"
  fi
}

verify_caller() {
  local expected_role="$1"
  local identity="${WORK_ROOT}/caller.json"
  safe_aws "Unable to verify the AWS recovery caller" "${identity}" \
    sts get-caller-identity --output json
  jq -e \
    --arg account "${AWS_ACCOUNT_ID}" \
    --arg role "${expected_role}" '
      .Account == $account and
      (.Arn | test(
        "^arn:aws:sts::" + $account + ":assumed-role/" + $role + "/[A-Za-z0-9+=,.@_-]+$"
      ))
    ' "${identity}" >/dev/null || fail "AWS recovery caller identity differs"
}

canonical_template_sha() {
  local response="$1"
  local body="$2"
  local yq_bin="$3"
  jq -er '.TemplateBody | if type == "string" then . else tojson end' \
    "${response}" >"${body}" || fail "CloudFormation template body is unavailable"
  "${yq_bin}" --output-format=json --indent 0 '.' "${body}" 2>/dev/null |
    jq -cS . |
    sha256sum |
    awk '{print $1}'
}

snapshot_target() {
  local prefix="$1"
  local yq_bin="$2"
  local stack="${WORK_ROOT}/${prefix}-stack.json"
  local resources="${WORK_ROOT}/${prefix}-resources.json"
  local template="${WORK_ROOT}/${prefix}-template.json"
  local body="${WORK_ROOT}/${prefix}-template.body"
  retry_safe_aws "Unable to inspect the sealed incident stack" "${stack}" \
    cloudformation describe-stacks \
    --region "${TARGET_REGION}" \
    --stack-name "${TARGET_STACK_NAME}" \
    --output json
  stack_id="$(jq -er '.Stacks[0].StackId' "${stack}")"
  mask_value "${stack_id}"
  safe_aws "Unable to inspect the sealed incident resources" "${resources}" \
    cloudformation list-stack-resources \
    --region "${TARGET_REGION}" \
    --stack-name "${stack_id}" \
    --output json
  safe_aws "Unable to inspect the sealed incident template" "${template}" \
    cloudformation get-template \
    --region "${TARGET_REGION}" \
    --stack-name "${stack_id}" \
    --template-stage Original \
    --output json
  template_sha="$(canonical_template_sha "${template}" "${body}" "${yq_bin}")"
  test "${template_sha}" = "${TARGET_TEMPLATE_SHA}" || \
    fail "The sealed incident source-template identity differs"
  printf '%s\n%s\n%s\n' "${stack}" "${resources}" "${template_sha}"
}

snapshot_stack_only() {
  local prefix="$1"
  local stack="${WORK_ROOT}/${prefix}-stack.json"
  retry_safe_aws "Unable to inspect the sealed incident stack" "${stack}" \
    cloudformation describe-stacks \
    --region "${TARGET_REGION}" \
    --stack-name "${TARGET_STACK_NAME}" \
    --output json
  local stack_id
  stack_id="$(jq -er '.Stacks[0].StackId' "${stack}")"
  mask_value "${stack_id}"
  printf '%s\n' "${stack}"
}
validate_recovery_role() {
  local yq_bin="$1"
  local expected_template_sha="$2"
  local role_stack="${WORK_ROOT}/role-stack.json"
  local role_template="${WORK_ROOT}/role-template.json"
  local role_body="${WORK_ROOT}/role-template.body"
  local role="${WORK_ROOT}/role.json"
  local policies="${WORK_ROOT}/role-policies.json"
  local attached_policies="${WORK_ROOT}/role-attached-policies.json"
  local base_policy="${WORK_ROOT}/base-policy.json"
  local expected_role_arn="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${RECOVERY_ROLE_NAME}"

  safe_aws "Unable to inspect the governed-canary role stack" "${role_stack}" \
    cloudformation describe-stacks \
    --region "${TARGET_REGION}" \
    --stack-name "${ROLE_STACK_NAME}" \
    --output json
  jq -e \
    --arg roleArn "${expected_role_arn}" '
      .Stacks | length == 1 and
      .[0].StackName == "Archon-Governed-Canary-Roles" and
      (.[0].StackStatus == "CREATE_COMPLETE" or .[0].StackStatus == "UPDATE_COMPLETE") and
      .[0].RoleARN == null and
      .[0].ParentId == null and
      .[0].RootId == null and
      .[0].EnableTerminationProtection == true and
      ([.[0].Outputs[] | select(.OutputKey == "GovernedCanaryRecoveryRoleArn")] | length) == 1 and
      ([.[0].Outputs[] | select(.OutputKey == "GovernedCanaryRecoveryRoleArn")][0].OutputValue == $roleArn)
    ' "${role_stack}" >/dev/null || fail "The governed-canary role stack binding differs"
  safe_aws "Unable to inspect the governed-canary role template" "${role_template}" \
    cloudformation get-template \
    --region "${TARGET_REGION}" \
    --stack-name "${ROLE_STACK_NAME}" \
    --template-stage Original \
    --output json
  observed_role_template_sha="$(
    canonical_template_sha "${role_template}" "${role_body}" "${yq_bin}"
  )"
  test "${observed_role_template_sha}" = "${expected_template_sha}" || \
    fail "The governed-canary role stack is not the current reviewed template"

  safe_aws "Unable to inspect the exact recovery role" "${role}" \
    iam get-role --role-name "${RECOVERY_ROLE_NAME}" --output json
  jq -e \
    --arg account "${AWS_ACCOUNT_ID}" \
    --arg roleArn "${expected_role_arn}" '
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
      .Role.AssumeRolePolicyDocument.Statement[0].Sid == "GitHubEnvironmentOidcOnly" and
      .Role.AssumeRolePolicyDocument.Statement[0].Effect == "Allow" and
      .Role.AssumeRolePolicyDocument.Statement[0].Action == "sts:AssumeRoleWithWebIdentity" and
      .Role.AssumeRolePolicyDocument.Statement[0].Principal.Federated ==
        ("arn:aws:iam::" + $account + ":oidc-provider/token.actions.githubusercontent.com") and
      .Role.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals[
        "token.actions.githubusercontent.com:aud"
      ] == "sts.amazonaws.com" and
      .Role.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals[
        "token.actions.githubusercontent.com:sub"
      ] == "repo:upgradedev/archon-datahub:environment:governed-canary-recovery"
    ' "${role}" >/dev/null || fail "The exact recovery role identity differs"

  safe_aws "Unable to inspect recovery-role inline policies" "${policies}" \
    iam list-role-policies --role-name "${RECOVERY_ROLE_NAME}" --output json
  jq -e '
    (.PolicyNames | sort) == ["archon-staging-stack-read"]
  ' "${policies}" >/dev/null || fail "The recovery role contains an unexpected inline policy"
  retry_safe_aws "Unable to inspect recovery-role attached policies" "${attached_policies}" \
    iam list-attached-role-policies --role-name "${RECOVERY_ROLE_NAME}" --output json
  jq -e '
    .AttachedPolicies == []
  ' "${attached_policies}" >/dev/null || fail "The recovery role contains an attached managed policy"
  safe_aws "Unable to inspect the recovery-role base policy" "${base_policy}" \
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
        ("arn:aws:cloudformation:eu-west-1:" + $account + ":stack/Archon-staging/*")
    ' "${base_policy}" >/dev/null || fail "The recovery-role base policy differs"
}

prepare() {
  validate_common
  : "${CANARY_ROLE_SOURCE:?CANARY_ROLE_SOURCE is required}"
  : "${CANARY_ROLE_SOURCE_SHA:?CANARY_ROLE_SOURCE_SHA is required}"
  : "${CANARY_ROLE_TEMPLATE:?CANARY_ROLE_TEMPLATE is required}"
  : "${CANARY_ROLE_TEMPLATE_SHA:?CANARY_ROLE_TEMPLATE_SHA is required}"
  : "${CANARY_ROLE_TEMPLATE_SEMANTIC_SHA:?CANARY_ROLE_TEMPLATE_SEMANTIC_SHA is required}"
  : "${CANARY_ROLE_YQ_BIN:?CANARY_ROLE_YQ_BIN is required}"
  : "${EXPIRES_AT:?EXPIRES_AT is required}"
  test -f "${CANARY_ROLE_SOURCE}"
  test ! -L "${CANARY_ROLE_SOURCE}"
  test "${CANARY_ROLE_SOURCE_SHA}" = "${ROLE_SOURCE_SHA}"
  test "$(sha256sum "${CANARY_ROLE_SOURCE}" | awk '{print $1}')" = "${ROLE_SOURCE_SHA}"
  [[ "${CANARY_ROLE_TEMPLATE_SHA}" =~ ^[a-f0-9]{64}$ ]]
  [[ "${CANARY_ROLE_TEMPLATE_SEMANTIC_SHA}" =~ ^[a-f0-9]{64}$ ]]
  test "$(sha256sum "${CANARY_ROLE_TEMPLATE}" | awk '{print $1}')" = \
    "${CANARY_ROLE_TEMPLATE_SHA}" || fail "The rendered role template changed before mutation"
  verify_caller "archon-datahub-github-foundation"

  if ! aws cloudformation deploy \
    --region "${TARGET_REGION}" \
    --stack-name "${ROLE_STACK_NAME}" \
    --template-file "${CANARY_ROLE_TEMPLATE}" \
    --capabilities CAPABILITY_NAMED_IAM \
    --no-fail-on-empty-changeset \
    --parameter-overrides \
      GitHubOrganization=upgradedev \
      GitHubRepository=archon-datahub \
    >/dev/null 2>&1; then
    fail "Unable to reconcile the exact governed-canary role stack"
  fi
  if ! aws cloudformation update-termination-protection \
    --region "${TARGET_REGION}" \
    --stack-name "${ROLE_STACK_NAME}" \
    --enable-termination-protection \
    >/dev/null 2>&1; then
    fail "Unable to protect the governed-canary role stack"
  fi
  test "$(sha256sum "${CANARY_ROLE_TEMPLATE}" | awk '{print $1}')" = \
    "${CANARY_ROLE_TEMPLATE_SHA}" || fail "The rendered role template changed"
  validate_recovery_role "${CANARY_ROLE_YQ_BIN}" \
    "${CANARY_ROLE_TEMPLATE_SEMANTIC_SHA}"

  mapfile -t target < <(snapshot_target "prepare" "${CANARY_ROLE_YQ_BIN}")
  test "${#target[@]}" -eq 3
  local plan="${WORK_ROOT}/prepare-plan.json"
  local policy="${WORK_ROOT}/prepare-policy.json"
  local safe
  safe="$(node "${VALIDATOR}" build-plan \
    "${target[0]}" "${target[1]}" "${target[2]}" \
    "${AWS_ACCOUNT_ID}" "${EXPIRES_AT}" "${CONTROL_PLANE_SHA}" \
    "${plan}" "${policy}")" || fail "Unable to seal the immutable recovery plan"
  jq -e '
    (.planDigest | test("^sha256:[a-f0-9]{64}$")) and
    (.policyDocumentSha256 | test("^sha256:[a-f0-9]{64}$")) and
    (.resourceStateSha256 | test("^sha256:[a-f0-9]{64}$")) and
    (.stackIdSha256 | test("^sha256:[a-f0-9]{64}$")) and
    (.clientRequestToken | test("^[A-Za-z0-9][-A-Za-z0-9]{0,127}$"))
  ' <<<"${safe}" >/dev/null || fail "The sealed recovery outputs are invalid"

  if ! aws iam put-role-policy \
    --role-name "${RECOVERY_ROLE_NAME}" \
    --policy-name "${TEMP_POLICY_NAME}" \
    --policy-document "file://${policy}" \
    >/dev/null 2>&1; then
    fail "Unable to install the temporary recovery authorization"
  fi
  local observed="${WORK_ROOT}/observed-temp-policy.json"
  local expected_policy_digest
  expected_policy_digest="$(jq -er '.policyDocumentSha256 | sub("^sha256:"; "")' <<<"${safe}")"
  wait_for_policy_digest "${expected_policy_digest}" "${observed}"
  {
    printf 'client_token=%s\n' "$(jq -er '.clientRequestToken' <<<"${safe}")"
    printf 'expires_at=%s\n' "$(jq -er '.expiresAt' <<<"${safe}")"
    printf 'plan_digest=%s\n' "$(jq -er '.planDigest' <<<"${safe}")"
    printf 'policy_sha256=%s\n' "$(jq -er '.policyDocumentSha256' <<<"${safe}")"
    printf 'resource_state_sha256=%s\n' "$(jq -er '.resourceStateSha256' <<<"${safe}")"
    printf 'stack_id_sha256=%s\n' "$(jq -er '.stackIdSha256' <<<"${safe}")"
  } >>"${GITHUB_OUTPUT}"
}

delete_once() {
  validate_common
  : "${EXPIRES_AT:?EXPIRES_AT is required}"
  : "${EXPECTED_PLAN_DIGEST:?EXPECTED_PLAN_DIGEST is required}"
  : "${EXPECTED_POLICY_SHA256:?EXPECTED_POLICY_SHA256 is required}"
  : "${EXPECTED_RESOURCE_STATE_SHA256:?EXPECTED_RESOURCE_STATE_SHA256 is required}"
  : "${EXPECTED_STACK_ID_SHA256:?EXPECTED_STACK_ID_SHA256 is required}"
  : "${EXPECTED_CLIENT_TOKEN:?EXPECTED_CLIENT_TOKEN is required}"
  verify_caller "${RECOVERY_ROLE_NAME}"

  local stack
  stack="$(snapshot_stack_only "delete")"
  local plan="${WORK_ROOT}/delete-plan.json"
  local policy="${WORK_ROOT}/delete-policy.json"
  local safe
  safe="$(node "${VALIDATOR}" rebuild-plan \
    "${stack}" "${EXPECTED_RESOURCE_STATE_SHA256}" \
    "${AWS_ACCOUNT_ID}" "${EXPIRES_AT}" "${CONTROL_PLANE_SHA}" \
    "${plan}" "${policy}")" || fail "Unable to rederive the immutable recovery plan"
  test "$(jq -er '.planDigest' <<<"${safe}")" = "${EXPECTED_PLAN_DIGEST}" || \
    fail "The immutable recovery plan digest differs"
  test "$(jq -er '.policyDocumentSha256' <<<"${safe}")" = \
    "${EXPECTED_POLICY_SHA256}" || fail "The temporary policy digest differs"
  test "$(jq -er '.resourceStateSha256' <<<"${safe}")" = \
    "${EXPECTED_RESOURCE_STATE_SHA256}" || fail "The sealed resource-state digest differs"
  test "$(jq -er '.stackIdSha256' <<<"${safe}")" = \
    "${EXPECTED_STACK_ID_SHA256}" || fail "The sealed stack identity differs"
  test "$(jq -er '.clientRequestToken' <<<"${safe}")" = \
    "${EXPECTED_CLIENT_TOKEN}" || fail "The deterministic delete token differs"

  local stack_id
  stack_id="$(jq -er '.target.stackId' "${plan}")"
  mask_value "${stack_id}"
  # Deliberately the only DeleteStack call in this repository-owned recovery path.
  if ! aws cloudformation delete-stack \
    --region "${TARGET_REGION}" \
    --stack-name "${stack_id}" \
    --client-request-token "${EXPECTED_CLIENT_TOKEN}" \
    --deletion-mode STANDARD \
    >/dev/null 2>&1; then
    fail "The single sealed DeleteStack request was not accepted"
  fi
  echo "delete_called=true" >>"${GITHUB_OUTPUT}"
}
revoke_policy() {
  local before="${WORK_ROOT}/revoke-policies-before.json"
  local after="${WORK_ROOT}/revoke-policies-after.json"
  retry_safe_aws "Unable to enumerate recovery-role policies before revocation" "${before}" \
    iam list-role-policies --role-name "${RECOVERY_ROLE_NAME}" --output json
  jq -e '
    (.PolicyNames | sort) == ["archon-staging-stack-read"] or
    (.PolicyNames | sort) == [
      "archon-incident-30546241677-delete",
      "archon-staging-stack-read"
    ]
  ' "${before}" >/dev/null || fail "Recovery-role policy inventory differs before revocation"
  local delete_error="${WORK_ROOT}/delete-role-policy.error"
  if ! aws iam delete-role-policy \
    --role-name "${RECOVERY_ROLE_NAME}" \
    --policy-name "${TEMP_POLICY_NAME}" \
    >/dev/null 2>"${delete_error}"; then
    test -f "${delete_error}"
    test ! -L "${delete_error}"
    chmod 0600 "${delete_error}"
    if ! LC_ALL=C grep -Eq \
      '^An error occurred \(NoSuchEntity\) when calling the DeleteRolePolicy operation: .+$' \
      "${delete_error}"; then
      rm -f -- "${delete_error}"
      fail "Unable to revoke the exact temporary recovery authorization"
    fi
  fi
  rm -f -- "${delete_error}"
  wait_for_policy_absence "${after}"
}
postverify() {
  validate_common
  : "${EXPECTED_STACK_ID_SHA256:?EXPECTED_STACK_ID_SHA256 is required}"
  verify_caller "archon-datahub-github-foundation"
  revoke_policy

  [[ "${EXPECTED_STACK_ID_SHA256}" =~ ^sha256:[a-f0-9]{64}$ ]] || \
    fail "The sealed stack identity digest is invalid"
  local expected_hash="${EXPECTED_STACK_ID_SHA256#sha256:}"
  local original_id=""
  local original_status=""
  local summaries="${WORK_ROOT}/stack-summaries.json"
  for _ in $(seq 1 90); do
    safe_aws "Unable to inspect sanitized deletion progress" "${summaries}" \
      cloudformation list-stacks --region "${TARGET_REGION}" --output json
    while IFS=$'\t' read -r candidate_id candidate_status; do
      [[ -n "${candidate_id}" ]] || continue
      mask_value "${candidate_id}"
      if test "$(printf '%s' "${candidate_id}" | sha256sum | awk '{print $1}')" = \
        "${expected_hash}"; then
        original_id="${candidate_id}"
        original_status="${candidate_status}"
        break
      fi
    done < <(
      jq -r \
        --arg name "${TARGET_STACK_NAME}" '
          .StackSummaries[] |
          select(.StackName == $name) |
          [.StackId, .StackStatus] | @tsv
        ' "${summaries}"
    )
    if [[ "${original_status}" == "DELETE_COMPLETE" ]]; then
      break
    fi
    if [[ "${original_status}" == "DELETE_FAILED" ]]; then
      fail "The sealed stack deletion reached DELETE_FAILED"
    fi
    sleep 10
  done
  test -n "${original_id}" || fail "The sealed stack identity was not observable"
  test "${original_status}" = "DELETE_COMPLETE" || \
    fail "The sealed stack did not reach DELETE_COMPLETE"
  local deleted="${WORK_ROOT}/deleted-stack.json"
  safe_aws "Unable to verify the deleted sealed stack identity" "${deleted}" \
    cloudformation describe-stacks \
    --region "${TARGET_REGION}" \
    --stack-name "${original_id}" \
    --output json
  jq -e '
    .Stacks | length == 1 and .[0].StackStatus == "DELETE_COMPLETE"
  ' "${deleted}" >/dev/null || fail "The original stack ID is not DELETE_COMPLETE"
  jq -e --arg name "${TARGET_STACK_NAME}" '
    ([.StackSummaries[] |
      select(.StackName == $name and .StackStatus != "DELETE_COMPLETE")] | length) == 0
  ' "${summaries}" >/dev/null || fail "An active stack still uses the sealed target name"

  : "${PLAN_DIGEST:?PLAN_DIGEST is required}"
  : "${POLICY_SHA256:?POLICY_SHA256 is required}"
  : "${EXPIRES_AT:?EXPIRES_AT is required}"
  local evidence_dir="${WORK_ROOT}/evidence"
  mkdir -p "${evidence_dir}"
  chmod 0700 "${evidence_dir}"
  jq -cnS \
    --arg artifactDigest "sha256:7aa20586b970ac938fba9299e0c3c2538482b92086db811ea583f84bd3b02e24" \
    --arg artifactId "8760846578" \
    --arg controlPlaneSha "${CONTROL_PLANE_SHA}" \
    --arg expiresAt "${EXPIRES_AT}" \
    --arg incidentHeadSha "aea65845e3a9456403a7fb6e9f338e4c14c0b781" \
    --arg planDigest "${PLAN_DIGEST}" \
    --arg policySha256 "${POLICY_SHA256}" '
      {
        schemaVersion: "archon.aws-incident-recovery-evidence/v1",
        authorization: {
          effectiveExpiry: $expiresAt,
          policyDocumentSha256: $policySha256,
          state: "revoked"
        },
        controlPlaneSha: $controlPlaneSha,
        incident: {
          artifactDigest: $artifactDigest,
          artifactId: $artifactId,
          headSha: $incidentHeadSha,
          runAttempt: "1",
          runId: "30546241677"
        },
        planDigest: $planDigest,
        result: "original-id-delete-complete-and-no-active-name",
        target: {label: "staging-iam"}
      }
    ' >"${evidence_dir}/recovery.json"
  chmod 0600 "${evidence_dir}/recovery.json"
  (
    cd "${evidence_dir}"
    sha256sum recovery.json >SHA256SUMS
  )
  jq -cnS \
    --arg evidenceSha256 "$(sha256sum "${evidence_dir}/recovery.json" | awk '{print $1}')" \
    --arg planDigest "${PLAN_DIGEST}" '
      {
        schemaVersion: "archon.aws-incident-recovery-attestation/v1",
        evidenceSha256: $evidenceSha256,
        planDigest: $planDigest,
        result: "sealed-incident-recovered"
      }
    ' >"${evidence_dir}/attestation-predicate.json"
  chmod 0600 "${evidence_dir}/SHA256SUMS" \
    "${evidence_dir}/attestation-predicate.json"
  {
    printf 'evidence_dir=%s\n' "${evidence_dir}"
    printf 'checksums=%s\n' "${evidence_dir}/SHA256SUMS"
    printf 'predicate=%s\n' "${evidence_dir}/attestation-predicate.json"
  } >>"${GITHUB_OUTPUT}"
}

cleanup() {
  validate_common
  verify_caller "archon-datahub-github-foundation"
  revoke_policy
  local evidence_dir="${WORK_ROOT}/cleanup-evidence"
  mkdir -p "${evidence_dir}"
  chmod 0700 "${evidence_dir}"
  jq -cnS \
    --arg controlPlaneSha "${CONTROL_PLANE_SHA}" \
    --arg trigger "${GITHUB_EVENT_NAME}" '
      {
        schemaVersion: "archon.aws-incident-recovery-cleanup/v1",
        authorization: {state: "absent"},
        controlPlaneSha: $controlPlaneSha,
        incident: {runAttempt: "1", runId: "30546241677"},
        result: "temporary-policy-absent",
        trigger: $trigger
      }
    ' >"${evidence_dir}/cleanup.json"
  chmod 0600 "${evidence_dir}/cleanup.json"
  (
    cd "${evidence_dir}"
    sha256sum cleanup.json >SHA256SUMS
  )
  jq -cnS \
    --arg cleanupSha256 "$(sha256sum "${evidence_dir}/cleanup.json" | awk '{print $1}')" '
      {
        schemaVersion: "archon.aws-incident-recovery-cleanup-attestation/v1",
        cleanupSha256: $cleanupSha256,
        result: "temporary-policy-absent"
      }
    ' >"${evidence_dir}/attestation-predicate.json"
  chmod 0600 \
    "${evidence_dir}/SHA256SUMS" \
    "${evidence_dir}/attestation-predicate.json"
  {
    printf 'evidence_dir=%s\n' "${evidence_dir}"
    printf 'checksums=%s\n' "${evidence_dir}/SHA256SUMS"
    printf 'predicate=%s\n' "${evidence_dir}/attestation-predicate.json"
  } >>"${GITHUB_OUTPUT}"
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    prepare)
      prepare
      ;;
    delete-once)
      delete_once
      ;;
    postverify)
      postverify
      ;;
    cleanup)
      cleanup
      ;;
    *)
      fail "Unsupported AWS incident recovery mode"
      ;;
  esac
fi