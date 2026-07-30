#!/usr/bin/env bash

load_policy_state() {
  local prefix="$1"
  local metadata="${WORK_ROOT}/${prefix}-policy.json"
  local versions="${WORK_ROOT}/${prefix}-versions.json"
  safe_aws "Unable to inspect the exact foundation control policy" "${metadata}" \
    iam get-policy --policy-arn "${CONTROL_POLICY_ARN}" --output json
  jq -e \
    --arg arn "${CONTROL_POLICY_ARN}" '
      .Policy.Arn == $arn and
      .Policy.PolicyName == "archon-aws-foundation-control" and
      .Policy.Path == "/" and
      .Policy.IsAttachable == true and
      .Policy.AttachmentCount == 1 and
      .Policy.PermissionsBoundaryUsageCount == 0 and
      (.Policy.DefaultVersionId | test("^v[1-9][0-9]*$"))
    ' "${metadata}" >/dev/null || fail "The foundation control policy metadata differs"
  safe_aws "Unable to list exact foundation control policy versions" "${versions}" \
    iam list-policy-versions --policy-arn "${CONTROL_POLICY_ARN}" --output json
  POLICY_DEFAULT_VERSION="$(jq -er '.Policy.DefaultVersionId' "${metadata}")"
  mapfile -t POLICY_VERSION_IDS < <(
    jq -er '.Versions | sort_by(.CreateDate)[] | .VersionId' "${versions}"
  )
  mapfile -t POLICY_VERSION_DEFAULTS < <(
    jq -er '.Versions | sort_by(.CreateDate)[] | (.IsDefaultVersion | tostring)' "${versions}"
  )
  POLICY_VERSION_SHAS=()
  local index version_id response
  for index in "${!POLICY_VERSION_IDS[@]}"; do
    version_id="${POLICY_VERSION_IDS[${index}]}"
    [[ "${version_id}" =~ ^v[1-9][0-9]*$ ]] || fail "A managed-policy version ID is invalid"
    response="${WORK_ROOT}/${prefix}-${version_id}.json"
    safe_aws "Unable to read a foundation control policy version" "${response}" \
      iam get-policy-version \
      --policy-arn "${CONTROL_POLICY_ARN}" \
      --version-id "${version_id}" \
      --output json
    jq -e \
      --arg version "${version_id}" '
        .PolicyVersion.VersionId == $version and
        (.PolicyVersion.IsDefaultVersion | type) == "boolean" and
        (.PolicyVersion.Document | type) == "object"
      ' "${response}" >/dev/null || fail "A managed-policy version response differs"
    POLICY_VERSION_SHAS+=("$(
      jq -cS '.PolicyVersion.Document' "${response}" |
        sha256sum |
        awk '{print $1}'
    )")
    test "$(jq -r '.PolicyVersion.IsDefaultVersion | tostring' "${response}")" = \
      "${POLICY_VERSION_DEFAULTS[${index}]}" ||
      fail "Managed-policy version metadata is inconsistent"
  done
  test "${#POLICY_VERSION_IDS[@]}" -ge 1
  test "${#POLICY_VERSION_IDS[@]}" -le 2 ||
    fail "Unexpected managed-policy version count"
}

version_for_sha() {
  local expected_sha="$1"
  local found=""
  local index
  for index in "${!POLICY_VERSION_IDS[@]}"; do
    if [[ "${POLICY_VERSION_SHAS[${index}]}" == "${expected_sha}" ]]; then
      test -z "${found}" || fail "A policy document appears in multiple versions"
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
  load_policy_state "${prefix}"
  test "${#POLICY_VERSION_IDS[@]}" -eq 1 ||
    fail "Initial control policy must contain exactly one version"
  local old_id
  old_id="$(version_for_sha "${OLD_POLICY_SHA}")" ||
    fail "The sole live policy is not the exact previous document"
  test "${POLICY_DEFAULT_VERSION}" = "${old_id}" ||
    fail "The exact previous policy is not default"
  test "$(version_default_flag "${old_id}")" = "true" ||
    fail "The sole previous version is not default"
  printf '%s\n' "${old_id}"
}

require_migrated_state() {
  local prefix="$1"
  load_policy_state "${prefix}"
  test "${#POLICY_VERSION_IDS[@]}" -eq 2 ||
    fail "Migrated control policy must contain exactly two versions"
  local old_id new_id
  old_id="$(version_for_sha "${OLD_POLICY_SHA}")" ||
    fail "The retained previous policy version is absent"
  new_id="$(version_for_sha "${NEW_POLICY_SHA}")" ||
    fail "The reviewed current policy version is absent"
  test "${old_id}" != "${new_id}"
  test "${POLICY_DEFAULT_VERSION}" = "${new_id}" ||
    fail "The reviewed current policy is not default"
  test "$(version_default_flag "${new_id}")" = "true"
  test "$(version_default_flag "${old_id}")" = "false"
  printf '%s\n%s\n' "${old_id}" "${new_id}"
}

require_rollback_pending_state() {
  local prefix="$1"
  local expected_default="$2"
  load_policy_state "${prefix}"
  test "${#POLICY_VERSION_IDS[@]}" -eq 2 ||
    fail "Rollback pending state must contain exactly two versions"
  local old_id new_id
  old_id="$(version_for_sha "${OLD_POLICY_SHA}")" ||
    fail "Rollback point is absent"
  new_id="$(version_for_sha "${NEW_POLICY_SHA}")" ||
    fail "The only extra version is not the reviewed migration"
  if [[ "${expected_default}" == "old" ]]; then
    test "${POLICY_DEFAULT_VERSION}" = "${old_id}"
    test "$(version_default_flag "${old_id}")" = "true"
    test "$(version_default_flag "${new_id}")" = "false"
  elif [[ "${expected_default}" == "new" ]]; then
    test "${POLICY_DEFAULT_VERSION}" = "${new_id}"
    test "$(version_default_flag "${new_id}")" = "true"
    test "$(version_default_flag "${old_id}")" = "false"
  else
    fail "Rollback pending state selector is invalid"
  fi
  printf '%s\n%s\n' "${old_id}" "${new_id}"
}

require_rolled_back_state() {
  local prefix="$1"
  load_policy_state "${prefix}"
  test "${#POLICY_VERSION_IDS[@]}" -eq 1 ||
    fail "Rolled-back control policy must contain exactly one version"
  local old_id
  old_id="$(version_for_sha "${OLD_POLICY_SHA}")" ||
    fail "The exact previous policy version is absent"
  test "${POLICY_DEFAULT_VERSION}" = "${old_id}"
  test "$(version_default_flag "${old_id}")" = "true"
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
    fi
    if ((attempt < RETRY_ATTEMPTS)); then
      sleep "${RETRY_DELAY_SECONDS}"
    fi
  done
  fail "The expected ${state} policy state was not canonically readable"
}

rollback_exact_migration() {
  load_policy_state rollback-inspect
  local count="${#POLICY_VERSION_IDS[@]}"
  local old_version new_version
  old_version="$(version_for_sha "${OLD_POLICY_SHA}")" ||
    fail "Rollback point is absent"
  if [[ "${count}" -eq 1 ]]; then
    test "${POLICY_DEFAULT_VERSION}" = "${old_version}" ||
      fail "The single rollback point is not default"
  elif [[ "${count}" -eq 2 ]]; then
    new_version="$(version_for_sha "${NEW_POLICY_SHA}")" ||
      fail "The only extra version is not the reviewed migration"
    if [[ "${POLICY_DEFAULT_VERSION}" == "${new_version}" ]]; then
      mapfile -t before_switch < <(
        require_rollback_pending_state rollback-before-switch new
      )
      test "${before_switch[0]}" = "${old_version}"
      test "${before_switch[1]}" = "${new_version}"
      if ! aws iam set-default-policy-version \
        --policy-arn "${CONTROL_POLICY_ARN}" \
        --version-id "${old_version}" \
        >/dev/null 2>/dev/null; then
        fail "Unable to restore the exact previous default policy version"
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
      [[ "${restored}" == true ]] ||
        fail "Previous default policy version was not restored"
    else
      test "${POLICY_DEFAULT_VERSION}" = "${old_version}" ||
        fail "An unknown version is default"
    fi
    mapfile -t before_delete < <(
      require_rollback_pending_state rollback-before-delete old
    )
    test "${before_delete[0]}" = "${old_version}"
    test "${before_delete[1]}" = "${new_version}"
    if ! aws iam delete-policy-version \
      --policy-arn "${CONTROL_POLICY_ARN}" \
      --version-id "${new_version}" \
      >/dev/null 2>/dev/null; then
      fail "Unable to delete only the reviewed nondefault migration version"
    fi
  else
    fail "Rollback encountered an unexpected managed-policy version count"
  fi
  wait_for_state rolled-back
  require_rolled_back_state rollback-final
}