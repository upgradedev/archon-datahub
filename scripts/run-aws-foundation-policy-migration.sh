#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for library in \
  "${script_dir}/aws-foundation-policy-migration-common.sh" \
  "${script_dir}/aws-foundation-policy-migration-authorization.sh" \
  "${script_dir}/aws-foundation-policy-migration-state.sh"; do
  test -f "${library}"
  test ! -L "${library}"
  # shellcheck source=/dev/null
  source "${library}"
done

classify_rollback_source_state() {
  load_policy_state authorize-rollback-state || return 1
  local count="${#POLICY_VERSION_IDS[@]}"
  local old_version new_version
  old_version="$(version_for_sha "${OLD_POLICY_SHA}")" || {
    fail "Rollback authorization lacks the exact rollback point"
    return 1
  }
  if [[ "${count}" -eq 1 ]]; then
    test "${POLICY_DEFAULT_VERSION}" = "${old_version}" || {
      fail "The single rollback point is not default"
      return 1
    }
    printf 'old-only\n'
    return 0
  fi
  test "${count}" -eq 2 || {
    fail "Rollback authorization found an unexpected version count"
    return 1
  }
  new_version="$(version_for_sha "${NEW_POLICY_SHA}")" || {
    fail "Rollback authorization found an unknown policy version"
    return 1
  }
  if [[ "${POLICY_DEFAULT_VERSION}" == "${old_version}" ]]; then
    printf 'old-default-new-nondefault\n'
  elif [[ "${POLICY_DEFAULT_VERSION}" == "${new_version}" ]]; then
    printf 'new-default-old-nondefault\n'
  else
    fail "Rollback authorization found an unknown default version"
    return 1
  fi
}

prepare() {
  validate_common
  : "${AUTHORIZATION_MODE:?AUTHORIZATION_MODE is required}"
  : "${EXPIRES_AT:?EXPIRES_AT is required}"
  render_policy_documents
  verify_caller "${FOUNDATION_ROLE_NAME}"
  local old_version source_state
  if [[ "${AUTHORIZATION_MODE}" == "migrate" ]]; then
    verify_recovery_role_baseline
    old_version="$(require_initial_state prepare-initial)"
    source_state="old-only"
  elif [[ "${AUTHORIZATION_MODE}" == "rollback" ]]; then
    revoke_temp_policy
    verify_recovery_role_baseline
    source_state="$(classify_rollback_source_state)"
    load_policy_state authorize-rollback-version
    old_version="$(version_for_sha "${OLD_POLICY_SHA}")"
  else
    fail "Authorization mode is invalid"
  fi
  install_temp_policy "${AUTHORIZATION_MODE}" "${EXPIRES_AT}"
  {
    printf 'authorization_mode=%s\n' "${AUTHORIZATION_MODE}"
    printf 'expires_at=%s\n' "${EXPIRES_AT}"
    printf 'new_policy_sha=%s\n' "${NEW_POLICY_SHA}"
    printf 'old_policy_sha=%s\n' "${OLD_POLICY_SHA}"
    printf 'old_version_id=%s\n' "${old_version}"
    printf 'source_state=%s\n' "${source_state}"
    printf 'temp_policy_sha=%s\n' "${TEMP_POLICY_SHA}"
  } >>"${GITHUB_OUTPUT}"
}

migrate() {
  validate_common
  : "${EXPECTED_EXPIRES_AT:?EXPECTED_EXPIRES_AT is required}"
  : "${EXPECTED_NEW_POLICY_SHA:?EXPECTED_NEW_POLICY_SHA is required}"
  : "${EXPECTED_OLD_POLICY_SHA:?EXPECTED_OLD_POLICY_SHA is required}"
  : "${EXPECTED_OLD_VERSION_ID:?EXPECTED_OLD_VERSION_ID is required}"
  : "${EXPECTED_TEMP_POLICY_SHA:?EXPECTED_TEMP_POLICY_SHA is required}"
  render_policy_documents
  test "${NEW_POLICY_SHA}" = "${EXPECTED_NEW_POLICY_SHA}"
  test "${OLD_POLICY_SHA}" = "${EXPECTED_OLD_POLICY_SHA}"
  verify_caller "${RECOVERY_ROLE_NAME}"
  verify_live_temp_policy migrate "${EXPECTED_TEMP_POLICY_SHA}"
  test "${LIVE_TEMP_EXPIRES_AT}" = "${EXPECTED_EXPIRES_AT}"
  local old_version
  old_version="$(require_initial_state migrate-initial)"
  test "${old_version}" = "${EXPECTED_OLD_VERSION_ID}"
  verify_live_temp_policy migrate "${EXPECTED_TEMP_POLICY_SHA}" || return 1
  local created="${WORK_ROOT}/create-version.json"
  safe_aws "Unable to create the reviewed nondefault policy version" "${created}" \
    iam create-policy-version \
    --policy-arn "${CONTROL_POLICY_ARN}" \
    --policy-document "file://${NEW_POLICY}" \
    --no-set-as-default \
    --output json
  local new_version
  new_version="$(jq -er '
    .PolicyVersion.VersionId |
    select(test("^v[1-9][0-9]*$"))
  ' "${created}")" || fail "The created policy version ID is invalid"
  test "$(jq -r '.PolicyVersion.IsDefaultVersion | tostring' "${created}")" = \
    "false" || fail "The reviewed policy version was unexpectedly created as default"
  local pending_snapshot
  pending_snapshot="$(
    wait_for_rollback_pending_state migrate-before-switch old
  )" || return 1
  mapfile -t before_switch <<<"${pending_snapshot}"
  test "${before_switch[0]}" = "${old_version}"
  test "${before_switch[1]}" = "${new_version}" ||
    fail "Canonical readback of the new nondefault version differs"
  verify_live_temp_policy migrate "${EXPECTED_TEMP_POLICY_SHA}"
  if ! aws iam set-default-policy-version \
    --policy-arn "${CONTROL_POLICY_ARN}" \
    --version-id "${new_version}" \
    >/dev/null 2>/dev/null; then
    fail "Unable to perform the single reviewed default-version switch"
  fi
  wait_for_state migrated
  local final_snapshot
  final_snapshot="$(require_migrated_state migrate-final)" || return 1
  mapfile -t final_versions <<<"${final_snapshot}"
  test "${final_versions[0]}" = "${old_version}"
  test "${final_versions[1]}" = "${new_version}"
  {
    printf 'new_version_id=%s\n' "${new_version}"
    printf 'old_version_id=%s\n' "${old_version}"
  } >>"${GITHUB_OUTPUT}"
}

rollback() {
  validate_common
  : "${AUTHORIZATION_MODE:?AUTHORIZATION_MODE is required}"
  : "${EXPECTED_TEMP_POLICY_SHA:?EXPECTED_TEMP_POLICY_SHA is required}"
  [[ "${AUTHORIZATION_MODE}" == "migrate" ||
    "${AUTHORIZATION_MODE}" == "rollback" ]] ||
    fail "Rollback authorization mode is invalid"
  render_policy_documents
  verify_caller "${RECOVERY_ROLE_NAME}"
  verify_live_temp_policy "${AUTHORIZATION_MODE}" "${EXPECTED_TEMP_POLICY_SHA}"
  local old_version
  old_version="$(rollback_exact_migration)"
  printf 'old_version_id=%s\n' "${old_version}" >>"${GITHUB_OUTPUT}"
}

write_receipt() {
  local expected_state="$1"
  local evidence_dir="${WORK_ROOT}/evidence"
  mkdir -p "${evidence_dir}"
  chmod 0700 "${evidence_dir}"
  local old_version new_version current_version result
  if [[ "${expected_state}" == "terminal" ]]; then
    if require_rolled_back_state receipt-terminal-old >/dev/null 2>&1; then
      expected_state="rolled-back"
    elif require_migrated_state receipt-terminal-migrated >/dev/null 2>&1; then
      expected_state="migrated"
    else
      fail "Terminal cleanup state is neither exact old-only nor exact migrated"
      return 1
    fi
  fi
  if [[ "${expected_state}" == "migrated" ]]; then
    local versions_snapshot
    versions_snapshot="$(require_migrated_state receipt-migrated)" || return 1
    mapfile -t versions <<<"${versions_snapshot}"
    old_version="${versions[0]}"
    new_version="${versions[1]}"
    current_version="${new_version}"
    result="reviewed-policy-default-previous-retained"
  elif [[ "${expected_state}" == "rolled-back" ]]; then
    old_version="$(require_rolled_back_state receipt-rolled-back)"
    new_version=""
    current_version="${old_version}"
    result="previous-policy-restored-migration-version-absent"
  else
    fail "Receipt state is invalid"
  fi
  jq -cnS \
    --arg controlPlaneSha "${CONTROL_PLANE_SHA}" \
    --arg currentVersion "${current_version}" \
    --arg newPolicySha "sha256:${NEW_POLICY_SHA}" \
    --arg oldPolicySha "sha256:${OLD_POLICY_SHA}" \
    --arg previousVersion "${old_version}" \
    --arg result "${result}" \
    --arg runAttempt "${GITHUB_RUN_ATTEMPT}" \
    --arg runId "${GITHUB_RUN_ID}" \
    --arg state "${expected_state}" '
      {
        schemaVersion: "archon.aws-foundation-policy-migration-receipt/v1",
        authorization: {
          absenceReadCount: 3,
          state: "absent"
        },
        controlPlaneSha: $controlPlaneSha,
        policy: {
          currentDefaultVersion: $currentVersion,
          name: "archon-aws-foundation-control",
          newDocumentSha256: $newPolicySha,
          previousDocumentSha256: $oldPolicySha,
          previousVersion: $previousVersion,
          state: $state
        },
        repository: "upgradedev/archon-datahub",
        result: $result,
        run: {
          attempt: ($runAttempt | tonumber),
          id: ($runId | tonumber)
        },
        sourceFailure: {runId: 30586169834}
      }
    ' >"${evidence_dir}/migration.json"
  chmod 0600 "${evidence_dir}/migration.json"
  jq -cS . "${evidence_dir}/migration.json" |
    cmp -s - "${evidence_dir}/migration.json" ||
    fail "Migration receipt is not canonical JSON"
  if grep -Fq 'arn:' "${evidence_dir}/migration.json"; then
    fail "Migration receipt contains a prohibited ARN"
  fi
  (
    cd "${evidence_dir}"
    sha256sum migration.json >SHA256SUMS
    sha256sum --check --strict SHA256SUMS >/dev/null
  )
  local receipt_sha
  receipt_sha="$(sha256sum "${evidence_dir}/migration.json" | awk '{print $1}')"
  jq -cnS \
    --arg receiptSha256 "${receipt_sha}" \
    --arg result "${result}" '
      {
        schemaVersion: "archon.aws-foundation-policy-migration-attestation/v1",
        receiptSha256: $receiptSha256,
        result: $result
      }
    ' >"${evidence_dir}/attestation-predicate.json"
  chmod 0600 \
    "${evidence_dir}/SHA256SUMS" \
    "${evidence_dir}/attestation-predicate.json"
  {
    printf 'checksums=%s\n' "${evidence_dir}/SHA256SUMS"
    printf 'evidence_dir=%s\n' "${evidence_dir}"
    printf 'predicate=%s\n' "${evidence_dir}/attestation-predicate.json"
  } >>"${GITHUB_OUTPUT}"
}

revoke() {
  validate_common
  : "${EXPECTED_STATE:?EXPECTED_STATE is required}"
  render_policy_documents
  verify_caller "${FOUNDATION_ROLE_NAME}"
  revoke_temp_policy
  verify_recovery_role_baseline
  write_receipt "${EXPECTED_STATE}"
}

case "${1:-}" in
  prepare)
    prepare
    ;;
  migrate)
    migrate
    ;;
  rollback)
    rollback
    ;;
  revoke)
    revoke
    ;;
  *)
    fail "Usage: $0 prepare|migrate|rollback|revoke"
    ;;
esac