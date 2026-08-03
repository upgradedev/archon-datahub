#!/usr/bin/env bash

load_policy_state() {
  local prefix="$1"
  local metadata="${WORK_ROOT}/${prefix}-policy.json"
  local versions="${WORK_ROOT}/${prefix}-versions.json"
  safe_aws "Unable to inspect the exact foundation identity policy" "${metadata}" \
    iam get-policy --policy-arn "${TARGET_POLICY_ARN}" --output json || return 1
  jq -e \
    --arg arn "${TARGET_POLICY_ARN}" '
      .Policy.Arn == $arn and
      .Policy.PolicyName == "archon-aws-foundation-identity" and
      .Policy.Path == "/" and
      .Policy.IsAttachable == true and
      .Policy.AttachmentCount == 1 and
      .Policy.PermissionsBoundaryUsageCount == 0 and
      (.Policy.DefaultVersionId | test("^v[1-9][0-9]*$"))
    ' "${metadata}" >/dev/null || {
      fail "The foundation identity policy metadata differs"
      return 1
    }
  safe_aws "Unable to list exact foundation identity policy versions" "${versions}" \
    iam list-policy-versions --policy-arn "${TARGET_POLICY_ARN}" --output json ||
    return 1
  jq -e '
    (.Versions | type) == "array" and
    (.Versions | length) >= 1 and
    (.Versions | length) <= 2 and
    ([.Versions[].VersionId] | unique | length) == (.Versions | length) and
    all(.Versions[];
      (.VersionId | test("^v[1-9][0-9]*$")) and
      (.IsDefaultVersion | type) == "boolean" and
      (.CreateDate | type) == "string") and
    ([.Versions[] | select(.IsDefaultVersion == true)] | length) == 1
  ' "${versions}" >/dev/null || {
    fail "The foundation identity policy version inventory differs"
    return 1
  }
  POLICY_DEFAULT_VERSION="$(jq -er '.Policy.DefaultVersionId' "${metadata}")" ||
    return 1
  mapfile -t POLICY_VERSION_IDS < <(
    jq -er '.Versions | sort_by(.CreateDate)[] | .VersionId' "${versions}"
  )
  mapfile -t POLICY_VERSION_DEFAULTS < <(
    jq -er '.Versions | sort_by(.CreateDate)[] | (.IsDefaultVersion | tostring)' "${versions}"
  )
  POLICY_VERSION_SHAS=()
  local index version_id response response_default
  for index in "${!POLICY_VERSION_IDS[@]}"; do
    version_id="${POLICY_VERSION_IDS[${index}]}"
    [[ "${version_id}" =~ ^v[1-9][0-9]*$ ]] || {
      fail "A managed-policy version ID is invalid"
      return 1
    }
    response="${WORK_ROOT}/${prefix}-${version_id}.json"
    safe_aws "Unable to read a foundation identity policy version" "${response}" \
      iam get-policy-version \
      --policy-arn "${TARGET_POLICY_ARN}" \
      --version-id "${version_id}" \
      --output json || return 1
    jq -e \
      --arg version "${version_id}" '
        .PolicyVersion.VersionId == $version and
        (.PolicyVersion.IsDefaultVersion | type) == "boolean" and
        (.PolicyVersion.Document | type) == "object"
      ' "${response}" >/dev/null || {
        fail "A managed-policy version response differs"
        return 1
      }
    local response_sha
    response_sha="$(
      iam_policy_sha "${response}" '.PolicyVersion.Document'
    )" || return 1
    POLICY_VERSION_SHAS+=("${response_sha}")
    response_default="$(
      jq -er '.PolicyVersion.IsDefaultVersion | tostring' "${response}"
    )" || return 1
    test "${response_default}" = "${POLICY_VERSION_DEFAULTS[${index}]}" || {
      fail "Managed-policy version metadata is inconsistent"
      return 1
    }
  done
  test "${#POLICY_VERSION_IDS[@]}" -ge 1 || return 1
  test "${#POLICY_VERSION_IDS[@]}" -le 2 || {
    fail "Unexpected managed-policy version count"
    return 1
  }
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

require_initial_state() {
  local prefix="$1"
  load_policy_state "${prefix}" || return 1
  test "${#POLICY_VERSION_IDS[@]}" -eq 1 || {
    fail "Initial identity policy must contain exactly one version"
    return 1
  }
  local old_id old_default
  old_id="$(version_for_sha "${OLD_POLICY_SHA}")" || {
    fail "The sole live policy is not the exact previous document"
    return 1
  }
  test "${POLICY_DEFAULT_VERSION}" = "${old_id}" || {
    fail "The exact previous policy is not default"
    return 1
  }
  old_default="$(version_default_flag "${old_id}")" || return 1
  test "${old_default}" = "true" || {
    fail "The sole previous version is not default"
    return 1
  }
  printf '%s\n' "${old_id}"
}

require_migrated_state() {
  local prefix="$1"
  load_policy_state "${prefix}" || return 1
  test "${#POLICY_VERSION_IDS[@]}" -eq 2 || {
    fail "Migrated identity policy must contain exactly two versions"
    return 1
  }
  local old_id new_id old_default new_default
  old_id="$(version_for_sha "${OLD_POLICY_SHA}")" || {
    fail "The retained previous policy version is absent"
    return 1
  }
  new_id="$(version_for_sha "${NEW_POLICY_SHA}")" || {
    fail "The reviewed current policy version is absent"
    return 1
  }
  test "${old_id}" != "${new_id}" || return 1
  test "${POLICY_DEFAULT_VERSION}" = "${new_id}" || {
    fail "The reviewed current policy is not default"
    return 1
  }
  new_default="$(version_default_flag "${new_id}")" || return 1
  old_default="$(version_default_flag "${old_id}")" || return 1
  test "${new_default}" = "true" || return 1
  test "${old_default}" = "false" || return 1
  printf '%s\n%s\n' "${old_id}" "${new_id}"
}

require_rollback_pending_state() {
  local prefix="$1"
  local expected_default="$2"
  load_policy_state "${prefix}" || return 1
  test "${#POLICY_VERSION_IDS[@]}" -eq 2 || {
    fail "Rollback pending state must contain exactly two versions"
    return 1
  }
  local old_id new_id old_default new_default
  old_id="$(version_for_sha "${OLD_POLICY_SHA}")" || {
    fail "Rollback point is absent"
    return 1
  }
  new_id="$(version_for_sha "${NEW_POLICY_SHA}")" || {
    fail "The only extra version is not the reviewed migration"
    return 1
  }
  old_default="$(version_default_flag "${old_id}")" || return 1
  new_default="$(version_default_flag "${new_id}")" || return 1
  if [[ "${expected_default}" == "old" ]]; then
    test "${POLICY_DEFAULT_VERSION}" = "${old_id}" || return 1
    test "${old_default}" = "true" || return 1
    test "${new_default}" = "false" || return 1
  elif [[ "${expected_default}" == "new" ]]; then
    test "${POLICY_DEFAULT_VERSION}" = "${new_id}" || return 1
    test "${new_default}" = "true" || return 1
    test "${old_default}" = "false" || return 1
  else
    fail "Rollback pending state selector is invalid"
    return 1
  fi
  printf '%s\n%s\n' "${old_id}" "${new_id}"
}

require_rolled_back_state() {
  local prefix="$1"
  load_policy_state "${prefix}" || return 1
  test "${#POLICY_VERSION_IDS[@]}" -eq 1 || {
    fail "Rolled-back identity policy must contain exactly one version"
    return 1
  }
  local old_id old_default
  old_id="$(version_for_sha "${OLD_POLICY_SHA}")" || {
    fail "The exact previous policy version is absent"
    return 1
  }
  test "${POLICY_DEFAULT_VERSION}" = "${old_id}" || return 1
  old_default="$(version_default_flag "${old_id}")" || return 1
  test "${old_default}" = "true" || return 1
  printf '%s\n' "${old_id}"
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
      if require_rolled_back_state "wait-rolled-back-${attempt}" >/dev/null 2>&1; then
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
  fail "Rollback-pending policy state was not canonically readable"
  return 1
}
rollback_exact_migration() {
  load_policy_state rollback-inspect || return 1
  local count="${#POLICY_VERSION_IDS[@]}"
  local old_version new_version pending
  old_version="$(version_for_sha "${OLD_POLICY_SHA}")" || {
    fail "Rollback point is absent"
    return 1
  }
  if [[ "${count}" -eq 1 ]]; then
    test "${POLICY_DEFAULT_VERSION}" = "${old_version}" || {
      fail "The single rollback point is not default"
      return 1
    }
  elif [[ "${count}" -eq 2 ]]; then
    new_version="$(version_for_sha "${NEW_POLICY_SHA}")" || {
      fail "The only extra version is not the reviewed migration"
      return 1
    }
    if [[ "${POLICY_DEFAULT_VERSION}" == "${new_version}" ]]; then
      pending="$(
        wait_for_rollback_pending_state rollback-before-switch new
      )" || return 1
      mapfile -t before_switch <<<"${pending}"
      test "${before_switch[0]}" = "${old_version}" || return 1
      test "${before_switch[1]}" = "${new_version}" || return 1
      verify_live_temp_policy \
        "${AUTHORIZATION_MODE}" "${EXPECTED_TEMP_POLICY_SHA:-}" || return 1
      if ! aws iam set-default-policy-version \
        --policy-arn "${TARGET_POLICY_ARN}" \
        --version-id "${old_version}" \
        >/dev/null 2>/dev/null; then
        fail "Unable to restore the exact previous default policy version"
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
        fail "Previous default policy version was not restored"
        return 1
      }
    else
      test "${POLICY_DEFAULT_VERSION}" = "${old_version}" || {
        fail "An unknown version is default"
        return 1
      }
    fi
    pending="$(
      require_rollback_pending_state rollback-before-delete old
    )" || return 1
    mapfile -t before_delete <<<"${pending}"
    test "${before_delete[0]}" = "${old_version}" || return 1
    test "${before_delete[1]}" = "${new_version}" || return 1
    verify_live_temp_policy \
      "${AUTHORIZATION_MODE}" "${EXPECTED_TEMP_POLICY_SHA:-}" || return 1
    if ! aws iam delete-policy-version \
      --policy-arn "${TARGET_POLICY_ARN}" \
      --version-id "${new_version}" \
      >/dev/null 2>/dev/null; then
      fail "Unable to delete only the reviewed nondefault migration version"
      return 1
    fi
  else
    fail "Rollback encountered an unexpected managed-policy version count"
    return 1
  fi
  wait_for_state rolled-back || return 1
  require_rolled_back_state rollback-final
}