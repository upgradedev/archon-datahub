#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for library in \
  "${script_dir}/aws-foundation-core-ami-policy-migration-common.sh" \
  "${script_dir}/aws-foundation-core-ami-policy-migration-authorization.sh" \
  "${script_dir}/aws-foundation-core-ami-policy-migration-state.sh"; do
  test -f "${library}"
  test ! -L "${library}"
  # shellcheck source=/dev/null
  source "${library}"
done

classify_rollback_source_state() {
  load_policy_state authorize-rollback-state || return 1
  local count="${#POLICY_VERSION_IDS[@]}"
  if [[ "${count}" -eq 2 ]]; then
    require_baseline_state authorize-rollback-baseline >/dev/null || return 1
    printf 'baseline\n'
  elif [[ "${count}" -eq 3 ]]; then
    test "$(version_for_sha "${HISTORICAL_POLICY_SHA}")" = v1 || return 1
    test "$(version_for_sha "${OLD_POLICY_SHA}")" = v2 || return 1
    test "$(version_for_sha "${NEW_POLICY_SHA}")" = v3 || return 1
    if [[ "${POLICY_DEFAULT_VERSION}" == v2 ]]; then
      require_rollback_pending_state \
        authorize-rollback-v2-default old >/dev/null || return 1
      printf 'v2-default-v3-nondefault\n'
    elif [[ "${POLICY_DEFAULT_VERSION}" == v3 ]]; then
      require_rollback_pending_state \
        authorize-rollback-v3-default new >/dev/null || return 1
      printf 'v3-default-v2-retained\n'
    else
      fail "Historical v1 must never become default"
      return 1
    fi
  else
    fail "Rollback authorization found an unexpected version count"
    return 1
  fi
}

prepare() {
  validate_common
  : "${AUTHORIZATION_MODE:?AUTHORIZATION_MODE is required}"
  : "${EXPIRES_AT:?EXPIRES_AT is required}"
  render_policy_documents
  verify_caller "${FOUNDATION_ROLE_NAME}"
  local historical_version old_version source_state snapshot
  if [[ "${AUTHORIZATION_MODE}" == migrate ]]; then
    verify_recovery_role_baseline
    snapshot="$(require_baseline_state prepare-baseline)" || return 1
    mapfile -t baseline_versions <<<"${snapshot}"
    historical_version="${baseline_versions[0]}"
    old_version="${baseline_versions[1]}"
    source_state=baseline
  elif [[ "${AUTHORIZATION_MODE}" == rollback ]]; then
    revoke_temp_policy
    verify_recovery_role_baseline
    source_state="$(classify_rollback_source_state)"
    load_policy_state authorize-rollback-version
    historical_version="$(version_for_sha "${HISTORICAL_POLICY_SHA}")"
    old_version="$(version_for_sha "${OLD_POLICY_SHA}")"
  else
    fail "Authorization mode is invalid"
    return 1
  fi
  test "${historical_version}" = v1
  test "${old_version}" = v2
  install_temp_policy "${AUTHORIZATION_MODE}" "${EXPIRES_AT}"
  {
    printf 'authorization_mode=%s\n' "${AUTHORIZATION_MODE}"
    printf 'expires_at=%s\n' "${EXPIRES_AT}"
    printf 'historical_policy_sha=%s\n' "${HISTORICAL_POLICY_SHA}"
    printf 'historical_version_id=%s\n' "${historical_version}"
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
  : "${EXPECTED_HISTORICAL_POLICY_SHA:?EXPECTED_HISTORICAL_POLICY_SHA is required}"
  : "${EXPECTED_HISTORICAL_VERSION_ID:?EXPECTED_HISTORICAL_VERSION_ID is required}"
  : "${EXPECTED_NEW_POLICY_SHA:?EXPECTED_NEW_POLICY_SHA is required}"
  : "${EXPECTED_OLD_POLICY_SHA:?EXPECTED_OLD_POLICY_SHA is required}"
  : "${EXPECTED_OLD_VERSION_ID:?EXPECTED_OLD_VERSION_ID is required}"
  : "${EXPECTED_TEMP_POLICY_SHA:?EXPECTED_TEMP_POLICY_SHA is required}"
  render_policy_documents
  test "${HISTORICAL_POLICY_SHA}" = "${EXPECTED_HISTORICAL_POLICY_SHA}"
  test "${NEW_POLICY_SHA}" = "${EXPECTED_NEW_POLICY_SHA}"
  test "${OLD_POLICY_SHA}" = "${EXPECTED_OLD_POLICY_SHA}"
  test "${EXPECTED_HISTORICAL_VERSION_ID}" = v1
  test "${EXPECTED_OLD_VERSION_ID}" = v2
  verify_caller "${RECOVERY_ROLE_NAME}"
  verify_live_temp_policy migrate "${EXPECTED_TEMP_POLICY_SHA}"
  test "${LIVE_TEMP_EXPIRES_AT}" = "${EXPECTED_EXPIRES_AT}"
  local snapshot
  snapshot="$(require_baseline_state migrate-baseline)" || return 1
  mapfile -t baseline_versions <<<"${snapshot}"
  test "${baseline_versions[0]}" = "${EXPECTED_HISTORICAL_VERSION_ID}"
  test "${baseline_versions[1]}" = "${EXPECTED_OLD_VERSION_ID}"
  verify_live_temp_policy migrate "${EXPECTED_TEMP_POLICY_SHA}" || return 1
  local created="${WORK_ROOT}/create-v3.json"
  safe_aws "Unable to create the reviewed nondefault v3 policy version" \
    "${created}" iam create-policy-version \
    --policy-arn "${TARGET_POLICY_ARN}" \
    --policy-document "file://${NEW_POLICY}" \
    --no-set-as-default --output json
  local new_version
  new_version="$(jq -er '.PolicyVersion.VersionId' "${created}")" ||
    fail "The created policy version ID is absent"
  test "${new_version}" = v3 ||
    fail "The exact baseline requires the new version to be v3"
  test "$(jq -r '.PolicyVersion.IsDefaultVersion | tostring' "${created}")" =
    false || fail "The reviewed v3 was unexpectedly created as default"
  local pending
  pending="$(wait_for_rollback_pending_state migrate-before-switch old)" ||
    return 1
  mapfile -t before_switch <<<"${pending}"
  test "${before_switch[0]}" = v1
  test "${before_switch[1]}" = v2
  test "${before_switch[2]}" = v3
  verify_live_temp_policy migrate "${EXPECTED_TEMP_POLICY_SHA}" || return 1
  if ! aws iam set-default-policy-version \
    --policy-arn "${TARGET_POLICY_ARN}" \
    --version-id v3 >/dev/null 2>/dev/null; then
    fail "Unable to perform the single reviewed default switch to v3"
    return 1
  fi
  wait_for_state migrated
  local final
  final="$(require_migrated_state migrate-final)" || return 1
  mapfile -t final_versions <<<"${final}"
  test "${final_versions[*]}" = "v1 v2 v3"
  {
    printf 'historical_version_id=v1\n'
    printf 'new_version_id=v3\n'
    printf 'old_version_id=v2\n'
  } >>"${GITHUB_OUTPUT}"
}

rollback() {
  validate_common
  : "${AUTHORIZATION_MODE:?AUTHORIZATION_MODE is required}"
  : "${EXPECTED_TEMP_POLICY_SHA:?EXPECTED_TEMP_POLICY_SHA is required}"
  [[ "${AUTHORIZATION_MODE}" == migrate ||
    "${AUTHORIZATION_MODE}" == rollback ]] ||
    fail "Rollback authorization mode is invalid"
  render_policy_documents
  verify_caller "${RECOVERY_ROLE_NAME}"
  verify_live_temp_policy \
    "${AUTHORIZATION_MODE}" "${EXPECTED_TEMP_POLICY_SHA}"
  local snapshot
  snapshot="$(rollback_exact_migration)" || return 1
  mapfile -t baseline_versions <<<"${snapshot}"
  test "${baseline_versions[*]}" = "v1 v2"
  {
    printf 'historical_version_id=v1\n'
    printf 'old_version_id=v2\n'
  } >>"${GITHUB_OUTPUT}"
}

write_receipt() {
  local expected_state="$1"
  local evidence_dir="${WORK_ROOT}/evidence"
  mkdir -p "${evidence_dir}"
  chmod 0700 "${evidence_dir}"
  if [[ "${expected_state}" == terminal ]]; then
    if require_rolled_back_state receipt-terminal-baseline >/dev/null 2>&1; then
      expected_state=rolled-back
    elif require_migrated_state receipt-terminal-migrated >/dev/null 2>&1; then
      expected_state=migrated
    else
      fail "Terminal cleanup state is neither exact baseline nor exact migrated"
      return 1
    fi
  fi
  local current_version result
  case "${expected_state}" in
    migrated)
      require_migrated_state receipt-migrated >/dev/null
      current_version=v3
      result=reviewed-v3-default-v1-v2-retained
      ;;
    rolled-back)
      require_rolled_back_state receipt-rolled-back >/dev/null
      current_version=v2
      result=exact-v2-default-v3-absent-v1-unchanged
      ;;
    *)
      fail "Receipt state is invalid"
      return 1
      ;;
  esac
  jq -cnS \
    --arg controlPlaneSha "${CONTROL_PLANE_SHA}" \
    --arg historicalPolicySha "sha256:${HISTORICAL_POLICY_SHA}" \
    --arg newPolicySha "sha256:${NEW_POLICY_SHA}" \
    --arg oldPolicySha "sha256:${OLD_POLICY_SHA}" \
    --arg result "${result}" \
    --arg runAttempt "${GITHUB_RUN_ATTEMPT}" \
    --arg runId "${GITHUB_RUN_ID}" \
    --arg state "${expected_state}" \
    --arg currentVersion "${current_version}" '
      {
        schemaVersion:
          "archon.aws-foundation-core-ami-policy-migration-receipt/v1",
        authorization: {absenceReadCount: 3, state: "absent"},
        controlPlaneSha: $controlPlaneSha,
        policy: {
          currentDefaultVersion: $currentVersion,
          historical: {
            documentSha256: $historicalPolicySha,
            version: "v1"
          },
          name: "archon-aws-foundation-control",
          new: {
            documentSha256: $newPolicySha,
            version: "v3"
          },
          previousDefault: {
            documentSha256: $oldPolicySha,
            version: "v2"
          },
          state: $state
        },
        repository: "upgradedev/archon-datahub",
        result: $result,
        run: {
          attempt: ($runAttempt | tonumber),
          id: ($runId | tonumber)
        }
      }
    ' >"${evidence_dir}/migration.json"
  chmod 0600 "${evidence_dir}/migration.json"
  jq -cS . "${evidence_dir}/migration.json" |
    cmp -s - "${evidence_dir}/migration.json" ||
    fail "Migration receipt is not canonical JSON"
  if grep -Fq 'arn:' "${evidence_dir}/migration.json" ||
    grep -Fq "${AWS_ACCOUNT_ID}" "${evidence_dir}/migration.json"; then
    fail "Migration receipt contains a prohibited account or ARN"
  fi
  (
    cd "${evidence_dir}"
    sha256sum migration.json >SHA256SUMS
    sha256sum --check --strict SHA256SUMS >/dev/null
  )
  local receipt_sha
  receipt_sha="$(
    sha256sum "${evidence_dir}/migration.json" | awk '{print $1}'
  )"
  jq -cnS \
    --arg receiptSha256 "${receipt_sha}" \
    --arg result "${result}" '
      {
        schemaVersion:
          "archon.aws-foundation-core-ami-policy-migration-attestation/v1",
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
  verify_caller "${FOUNDATION_ROLE_NAME}"
  revoke_temp_policy
  verify_recovery_role_baseline
  render_policy_documents
  write_receipt "${EXPECTED_STATE}"
}

case "${1:-}" in
  prepare) prepare ;;
  migrate) migrate ;;
  rollback) rollback ;;
  revoke) revoke ;;
  *) fail "Usage: $0 prepare|migrate|rollback|revoke" ;;
esac