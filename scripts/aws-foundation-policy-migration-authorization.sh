#!/usr/bin/env bash

build_temp_policy() {
  local mode="$1"
  local expires_at="$2"
  local output="$3"
  local actions
  if [[ "${mode}" == "migrate" ]]; then
    actions='[
      "iam:CreatePolicyVersion",
      "iam:DeletePolicyVersion",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListPolicyVersions",
      "iam:SetDefaultPolicyVersion"
    ]'
  elif [[ "${mode}" == "rollback" ]]; then
    actions='[
      "iam:DeletePolicyVersion",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListPolicyVersions",
      "iam:SetDefaultPolicyVersion"
    ]'
  else
    fail "Temporary authorization mode is invalid"
    return 1
  fi
  jq -cnS \
    --arg expires "${expires_at}" \
    --arg policyArn "${CONTROL_POLICY_ARN}" \
    --arg roleArn "${RECOVERY_ROLE_ARN}" \
    --argjson actions "${actions}" '
      {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "OperateExactFoundationControlPolicy",
            Effect: "Allow",
            Action: $actions,
            Resource: $policyArn,
            Condition: {
              DateLessThan: {"aws:CurrentTime": $expires}
            }
          },
          {
            Sid: "ReadOwnTemporaryAuthorization",
            Effect: "Allow",
            Action: "iam:GetRolePolicy",
            Resource: $roleArn,
            Condition: {
              DateLessThan: {"aws:CurrentTime": $expires}
            }
          }
        ]
      }
    ' >"${output}"
  chmod 0600 "${output}"
  jq -e '
    .Version == "2012-10-17" and
    (.Statement | length) == 2 and
    all(.Statement[]; .Effect == "Allow") and
    all(.Statement[]; .Resource != "*") and
    ([.Statement[].Action] | flatten |
      any(. == "iam:PutRolePolicy" or
          . == "iam:DeleteRolePolicy" or
          . == "iam:AttachRolePolicy" or
          . == "iam:CreatePolicy" or
          . == "iam:DeletePolicy" or
          . == "iam:PassRole") | not)
  ' "${output}" >/dev/null || {
    fail "Temporary authorization contains prohibited privilege"
    return 1
  }
}

wait_for_temp_digest() {
  local expected_sha="$1"
  local output="${WORK_ROOT}/temporary-policy-readback.json"
  local attempt observed_sha
  for ((attempt = 1; attempt <= RETRY_ATTEMPTS; attempt++)); do
    if aws iam get-role-policy \
      --role-name "${RECOVERY_ROLE_NAME}" \
      --policy-name "${TEMP_POLICY_NAME}" \
      --output json >"${output}" 2>/dev/null; then
      chmod 0600 "${output}"
      if jq -e '
        .RoleName == "archon-datahub-github-governed-canary-recovery" and
        .PolicyName == "archon-foundation-control-policy-migration" and
        (.PolicyDocument | type) == "object"
      ' "${output}" >/dev/null; then
        observed_sha="$(iam_policy_sha "${output}" '.PolicyDocument')" || {
          fail "Unable to canonicalize temporary migration authorization"
          return 1
        }
        if [[ "${observed_sha}" == "${expected_sha}" ]]; then
          return 0
        fi
      fi
    fi
    if ((attempt < RETRY_ATTEMPTS)); then
      sleep "${RETRY_DELAY_SECONDS}"
    fi
  done
  fail \
}

install_temp_policy() {
  local mode="$1"
  local expires_at="$2"
  local now_epoch expiry_epoch remaining
  now_epoch="$(date --utc '+%s')"
  expiry_epoch="$(date --utc --date="${expires_at}" '+%s')" || {
    fail "Migration expiry is invalid"
    return 1
  }
  remaining=$((expiry_epoch - now_epoch))
  ((remaining >= 1140 && remaining <= 1200)) || {
    fail "Migration authorization TTL is not exactly bounded to twenty minutes"
    return 1
  }
  local temporary="${WORK_ROOT}/temporary-policy-${mode}.json"
  build_temp_policy "${mode}" "${expires_at}" "${temporary}" || return 1
  local temp_sha
  temp_sha="$(iam_policy_sha "${temporary}")" || return 1
  now_epoch="$(date --utc '+%s')"
  expiry_epoch="$(date --utc --date="${expires_at}" '+%s')" || {
    fail "Migration expiry became invalid before authorization"
    return 1
  }
  remaining=$((expiry_epoch - now_epoch))
  ((remaining >= 1140 && remaining <= 1200)) || {
    fail "Migration authorization TTL changed before installation"
    return 1
  }
  if ! aws iam put-role-policy \
    --role-name "${RECOVERY_ROLE_NAME}" \
    --policy-name "${TEMP_POLICY_NAME}" \
    --policy-document "file://${temporary}" \
    >/dev/null 2>/dev/null; then
    fail "Unable to install the temporary migration authorization"
    return 1
  fi
  wait_for_temp_digest "${temp_sha}" || return 1
  TEMP_POLICY_SHA="${temp_sha}"
}

verify_live_temp_policy() {
  local expected_mode="$1"
  local expected_sha="${2:-}"
  local observed="${WORK_ROOT}/temporary-policy-live.json"
  safe_aws "Unable to read the temporary migration authorization" "${observed}" \
    iam get-role-policy \
    --role-name "${RECOVERY_ROLE_NAME}" \
    --policy-name "${TEMP_POLICY_NAME}" \
    --output json
  jq -e '
    .RoleName == "archon-datahub-github-governed-canary-recovery" and
    .PolicyName == "archon-foundation-control-policy-migration" and
    (.PolicyDocument | type) == "object"
  ' "${observed}" >/dev/null || {
    fail "Temporary authorization response differs"
    return 1
  }
  local first_expiry second_expiry expires
  first_expiry="$(
    jq -er '.PolicyDocument.Statement[] |
      select(.Sid == "OperateExactFoundationControlPolicy") |
      .Condition.DateLessThan["aws:CurrentTime"]' "${observed}"
  )"
  second_expiry="$(
    jq -er '.PolicyDocument.Statement[] |
      select(.Sid == "ReadOwnTemporaryAuthorization") |
      .Condition.DateLessThan["aws:CurrentTime"]' "${observed}"
  )"
  test "${first_expiry}" = "${second_expiry}" || {
    fail "Temporary authorization expiry values differ"
    return 1
  }
  expires="${first_expiry}"
  local expected="${WORK_ROOT}/temporary-policy-expected-${expected_mode}.json"
  build_temp_policy "${expected_mode}" "${expires}" "${expected}" || return 1
  local expected_document_sha observed_sha
  expected_document_sha="$(iam_policy_sha "${expected}")" || return 1
  observed_sha="$(iam_policy_sha "${observed}" '.PolicyDocument')" || return 1
  test "${observed_sha}" = "${expected_document_sha}" || {
    fail "The live temporary migration authorization differs"
    return 1
  }
  if [[ -n "${expected_sha}" ]]; then
    test "${observed_sha}" = "${expected_sha}" || {
      fail "Temporary authorization digest differs"
      return 1
    }
  fi
  local now_epoch expiry_epoch remaining
  now_epoch="$(date --utc '+%s')"
  expiry_epoch="$(date --utc --date="${expires}" '+%s')" || {
    fail "Temporary authorization expiry is invalid"
    return 1
  }
  remaining=$((expiry_epoch - now_epoch))
  local minimum_remaining=180
  ((remaining >= minimum_remaining && remaining <= 1200)) || {
    fail "Temporary migration authorization has insufficient lifetime"
    return 1
  }
  LIVE_TEMP_EXPIRES_AT="${expires}"
  LIVE_TEMP_POLICY_SHA="${observed_sha}"
}

revoke_temp_policy() {
  local before="${WORK_ROOT}/revoke-before.json"
  safe_aws "Unable to inspect recovery-role policies before revocation" "${before}" \
    iam list-role-policies --role-name "${RECOVERY_ROLE_NAME}" --output json
  if jq -e --arg temp "${TEMP_POLICY_NAME}" '
    any(.PolicyNames[]; . == $temp)
  ' "${before}" >/dev/null; then
    if ! aws iam delete-role-policy \
      --role-name "${RECOVERY_ROLE_NAME}" \
      --policy-name "${TEMP_POLICY_NAME}" \
      >/dev/null 2>/dev/null; then
      :
    fi
  fi
  local attempt consecutive=0 inventory
  for ((attempt = 1; attempt <= RETRY_ATTEMPTS; attempt++)); do
    inventory="${WORK_ROOT}/revoke-inventory-${attempt}.json"
    if aws iam list-role-policies \
      --role-name "${RECOVERY_ROLE_NAME}" \
      --output json >"${inventory}" 2>/dev/null; then
      chmod 0600 "${inventory}"
      if jq -e --arg base "${BASE_POLICY_NAME}" '
        (.PolicyNames | sort) == [$base]
      ' "${inventory}" >/dev/null; then
        consecutive=$((consecutive + 1))
        if ((consecutive >= ABSENCE_CONFIRMATIONS)); then
          return 0
        fi
      else
        consecutive=0
      fi
    else
      consecutive=0
    fi
    if ((attempt < RETRY_ATTEMPTS)); then
      sleep "${RETRY_DELAY_SECONDS}"
    fi
  done
  fail \
}