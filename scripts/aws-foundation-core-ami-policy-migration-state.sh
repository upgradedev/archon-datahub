#!/usr/bin/env bash

load_policy_state() {
  local prefix="$1"
  local metadata="${WORK_ROOT}/${prefix}-policy.json"
  local versions="${WORK_ROOT}/${prefix}-versions.json"
  safe_aws "Unable to inspect the exact foundation control policy" "${metadata}" \
    iam get-policy --policy-arn "${TARGET_POLICY_ARN}" --output json ||
    return 1
  jq -e \
    --arg arn "${TARGET_POLICY_ARN}" '
      .Policy.Arn == $arn and
      .Policy.PolicyName == "archon-aws-foundation-control" and
      .Policy.Path == "/" and
      .Policy.IsAttachable == true and
      .Policy.AttachmentCount == 1 and
      .Policy.PermissionsBoundaryUsageCount == 0 and
      (.Policy.DefaultVersionId | test("^v[1-9][0-9]*$"))
    ' "${metadata}" >/dev/null || {
      fail "The foundation control policy metadata differs"
      return 1
    }
  safe_aws "Unable to list exact foundation control-policy versions" \
    "${versions}" iam list-policy-versions \
    --policy-arn "${TARGET_POLICY_ARN}" --output json || return 1
  jq -e '
    (.Versions | type) == "array" and
    ((.Versions | length) == 2 or (.Versions | length) == 3) and
    ([.Versions[].VersionId] | unique | length) == (.Versions | length) and
    all(.Versions[];
      (.VersionId | test("^v[1-9][0-9]*$")) and
      (.IsDefaultVersion | type) == "boolean" and
      (.CreateDate | type) == "string") and
    ([.Versions[] | select(.IsDefaultVersion == true)] | length) == 1
  ' "${versions}" >/dev/null || {
    fail "The foundation control-policy version inventory differs"
    return 1
  }
  POLICY_DEFAULT_VERSION="$(jq -er '.Policy.DefaultVersionId' "${metadata}")" ||
    return 1
  mapfile -t POLICY_VERSION_IDS < <(
    jq -er '.Versions |
      sort_by(.VersionId | ltrimstr("v") | tonumber)[] |
      .VersionId' "${versions}"
  )
  mapfile -t POLICY_VERSION_DEFAULTS < <(
    jq -er '.Versions |
      sort_by(.VersionId | ltrimstr("v") | tonumber)[] |
      (.IsDefaultVersion | tostring)' "${versions}"
  )
  POLICY_VERSION_SHAS=()
  local index version_id response response_default response_sha
  for index in "${!POLICY_VERSION_IDS[@]}"; do
    version_id="${POLICY_VERSION_IDS[${index}]}"
    response="${WORK_ROOT}/${prefix}-${version_id}.json"
    safe_aws "Unable to read a foundation control-policy version" \
      "${response}" iam get-policy-version \
      --policy-arn "${TARGET_POLICY_ARN}" \
      --version-id "${version_id}" --output json || return 1
    jq -e --arg version "${version_id}" '
      .PolicyVersion.VersionId == $version and
      (.PolicyVersion.IsDefaultVersion | type) == "boolean" and
      (.PolicyVersion.Document | type) == "object"
    ' "${response}" >/dev/null || {
      fail "A foundation control-policy version response differs"
      return 1
    }
    response_sha="$(iam_policy_sha "${response}" '.PolicyVersion.Document')" ||
      return 1
    POLICY_VERSION_SHAS+=("${response_sha}")
    response_default="$(
      jq -er '.PolicyVersion.IsDefaultVersion | tostring' "${response}"
    )" || return 1
    [[ "${response_default}" == "${POLICY_VERSION_DEFAULTS[${index}]}" ]] || {
      fail "Managed-policy version metadata is inconsistent"
      return 1
    }
  done
}

version_for_sha() {
  local expected_sha="$1"
  local found=""
  local index
  for index in "${!POLICY_VERSION_IDS[@]}"; do
    if [[ "${POLICY_VERSION_SHAS[${index}]}" == "${expected_sha}" ]]; then
      test -z "${found}" || {
        fail "A policy document appears in multiple versions"
        return 1
      }
      found="${POLICY_VERSION_IDS[${index}]}"
    fi
  done
  test -n "${found}" || return 1
  printf '%s\n' "${found}"
}

version_default_flag() {
  local target="$1"
  local index
  for index in "${!POLICY_VERSION_IDS[@]}"; do
    if [[ "${POLICY_VERSION_IDS[${index}]}" == "${target}" ]]; then
      printf '%s\n' "${POLICY_VERSION_DEFAULTS[${index}]}"
      return 0
    fi
  done
  return 1
}

require_baseline_state() {
  local prefix="$1"
  load_policy_state "${prefix}" || return 1
  test "${#POLICY_VERSION_IDS[@]}" -eq 2 || {
    fail "Baseline control policy must contain exactly v1 and v2"
    return 1
  }
  local historical_id old_id historical_default old_default
  historical_id="$(version_for_sha "${HISTORICAL_POLICY_SHA}")" || {
    fail "The exact historical v1 control policy is absent"
    return 1
  }
  old_id="$(version_for_sha "${OLD_POLICY_SHA}")" || {
    fail "The exact baseline v2 control policy is absent"
    return 1
  }
  test "${historical_id}" = "v1" || return 1
  test "${old_id}" = "v2" || return 1
  test "${POLICY_DEFAULT_VERSION}" = "v2" || {
    fail "The exact baseline v2 control policy is not default"
    return 1
  }
  historical_default="$(version_default_flag v1)" || return 1
  old_default="$(version_default_flag v2)" || return 1
  test "${historical_default}" = "false" || return 1
  test "${old_default}" = "true" || return 1
  printf '%s\n%s\n' "${historical_id}" "${old_id}"
}

require_migrated_state() {
  local prefix="$1"
  load_policy_state "${prefix}" || return 1
  test "${#POLICY_VERSION_IDS[@]}" -eq 3 || {
    fail "Migrated control policy must contain exactly v1, v2, and v3"
    return 1
  }
  local historical_id old_id new_id historical_default old_default new_default
  historical_id="$(version_for_sha "${HISTORICAL_POLICY_SHA}")" || return 1
  old_id="$(version_for_sha "${OLD_POLICY_SHA}")" || return 1
  new_id="$(version_for_sha "${NEW_POLICY_SHA}")" || return 1
  test "${historical_id}" = "v1" || return 1
  test "${old_id}" = "v2" || return 1
  test "${new_id}" = "v3" || return 1
  test "${POLICY_DEFAULT_VERSION}" = "v3" || {
    fail "The reviewed v3 control policy is not default"
    return 1
  }
  historical_default="$(version_default_flag v1)" || return 1
  old_default="$(version_default_flag v2)" || return 1
  new_default="$(version_default_flag v3)" || return 1
  test "${historical_default}" = "false" || return 1
  test "${old_default}" = "false" || return 1
  test "${new_default}" = "true" || return 1
  printf '%s\n%s\n%s\n' "${historical_id}" "${old_id}" "${new_id}"
}

require_rollback_pending_state() {
  local prefix="$1"
  local expected_default="$2"
  load_policy_state "${prefix}" || return 1
  test "${#POLICY_VERSION_IDS[@]}" -eq 3 || {
    fail "Rollback-pending state must contain exactly v1, v2, and v3"
    return 1
  }
  local historical_id old_id new_id
  historical_id="$(version_for_sha "${HISTORICAL_POLICY_SHA}")" || return 1
  old_id="$(version_for_sha "${OLD_POLICY_SHA}")" || return 1
  new_id="$(version_for_sha "${NEW_POLICY_SHA}")" || return 1
  test "${historical_id}" = "v1" || return 1
  test "${old_id}" = "v2" || return 1
  test "${new_id}" = "v3" || return 1
  test "$(version_default_flag v1)" = "false" || return 1
  case "${expected_default}" in
    old)
      test "${POLICY_DEFAULT_VERSION}" = "v2" || return 1
      test "$(version_default_flag v2)" = "true" || return 1
      test "$(version_default_flag v3)" = "false" || return 1
      ;;
    new)
      test "${POLICY_DEFAULT_VERSION}" = "v3" || return 1
      test "$(version_default_flag v2)" = "false" || return 1
      test "$(version_default_flag v3)" = "true" || return 1
      ;;
    *)
      fail "Rollback-pending state selector is invalid"
      return 1
      ;;
  esac
  printf '%s\n%s\n%s\n' "${historical_id}" "${old_id}" "${new_id}"
}

require_rolled_back_state() {
  require_baseline_state "$1"
}

wait_for_state() {
  local state="$1"
  local attempt
  for ((attempt = 1; attempt <= RETRY_ATTEMPTS; attempt++)); do
    if [[ "${state}" == "migrated" ]]; then
      if require_migrated_state "wait-migrated-${attempt}" >/dev/null 2>&1; then
        return 0
      fi
    elif [[ "${state}" == "rolled-back" ]]; then
      if require_rolled_back_state \
        "wait-rolled-back-${attempt}" >/dev/null 2>&1; then
        return 0
      fi
    else
      fail "Unknown expected state"
      return 1
    fi
    if ((attempt < RETRY_ATTEMPTS)); then
      sleep "${RETRY_DELAY_SECONDS}"
    fi
  done
  fail "The expected ${state} policy state was not canonically readable"
  return 1
}

wait_for_rollback_pending_state() {
  local prefix="$1"
  local expected_default="$2"
  local attempt snapshot
  for ((attempt = 1; attempt <= RETRY_ATTEMPTS; attempt++)); do
    if snapshot="$(
      require_rollback_pending_state \
        "${prefix}-${attempt}" "${expected_default}" 2>/dev/null
    )"; then
      printf '%s\n' "${snapshot}"
      return 0
    fi
    if ((attempt < RETRY_ATTEMPTS)); then
      sleep "${RETRY_DELAY_SECONDS}"
    fi
  done
  fail "Rollback-pending control-policy state was not readable"
  return 1
}

rollback_exact_migration() {
  load_policy_state rollback-inspect || return 1
  local count="${#POLICY_VERSION_IDS[@]}"
  local pending
  if [[ "${count}" -eq 2 ]]; then
    require_baseline_state rollback-already-baseline >/dev/null || return 1
  elif [[ "${count}" -eq 3 ]]; then
    test "$(version_for_sha "${HISTORICAL_POLICY_SHA}")" = "v1" || return 1
    test "$(version_for_sha "${OLD_POLICY_SHA}")" = "v2" || return 1
    test "$(version_for_sha "${NEW_POLICY_SHA}")" = "v3" || return 1
    if [[ "${POLICY_DEFAULT_VERSION}" == "v3" ]]; then
      pending="$(
        wait_for_rollback_pending_state rollback-before-switch new
      )" || return 1
      verify_live_temp_policy \
        "${AUTHORIZATION_MODE}" "${EXPECTED_TEMP_POLICY_SHA:-}" || return 1
      if ! aws iam set-default-policy-version \
        --policy-arn "${TARGET_POLICY_ARN}" \
        --version-id v2 >/dev/null 2>/dev/null; then
        fail "Unable to restore exact v2 as the default policy version"
        return 1
      fi
      local attempt restored=false
      for ((attempt = 1; attempt <= RETRY_ATTEMPTS; attempt++)); do
        if require_rollback_pending_state \
          "rollback-default-${attempt}" old >/dev/null 2>&1; then
          restored=true
          break
        fi
        if ((attempt < RETRY_ATTEMPTS)); then
          sleep "${RETRY_DELAY_SECONDS}"
        fi
      done
      [[ "${restored}" == true ]] || {
        fail "Exact v2 default was not restored"
        return 1
      }
    else
      test "${POLICY_DEFAULT_VERSION}" = "v2" || {
        fail "Historical v1 must never become default"
        return 1
      }
    fi
    require_rollback_pending_state rollback-before-delete old >/dev/null ||
      return 1
    verify_live_temp_policy \
      "${AUTHORIZATION_MODE}" "${EXPECTED_TEMP_POLICY_SHA:-}" || return 1
    if ! aws iam delete-policy-version \
      --policy-arn "${TARGET_POLICY_ARN}" \
      --version-id v3 >/dev/null 2>/dev/null; then
      fail "Unable to delete only the reviewed nondefault v3"
      return 1
    fi
  else
    fail "Rollback encountered an unexpected policy version count"
    return 1
  fi
  wait_for_state rolled-back || return 1
  require_rolled_back_state rollback-final
}