#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." &&
    pwd
)"
host_runner_temp="${RUNNER_TEMP:-/tmp}"
test_root="$(mktemp -d "${host_runner_temp}/archon-core-policy-state-test.XXXXXX")"
case "${test_root}" in
  "${host_runner_temp}"/*) ;;
  *)
    echo "::error::Core policy state test root escaped the runner temp directory" >&2
    exit 1
    ;;
esac
trap 'rm -rf -- "${test_root}"' EXIT
mkdir -p "${test_root}/runner"
export GITHUB_ACTIONS=true
export RUNNER_TEMP="${test_root}/runner"
export GITHUB_OUTPUT="${test_root}/github-output"
: >"${GITHUB_OUTPUT}"

cd "${repository_root}"
# shellcheck source=/dev/null
source "${repository_root}/scripts/aws-foundation-core-ami-policy-migration-common.sh"
# shellcheck source=/dev/null
source "${repository_root}/scripts/aws-foundation-core-ami-policy-migration-state.sh"

TARGET_POLICY_ARN="arn:aws:iam::123456789012:policy/archon-aws-foundation-control"
fixture_v1="${test_root}/v1.json"
fixture_v2="${test_root}/v2.json"
jq -nS --arg resource "${TARGET_POLICY_ARN}" '
  {
    Version: "2012-10-17",
    Statement: [{
      Sid: "HistoricalPolicy",
      Effect: "Allow",
      Action: "iam:GetPolicy",
      Resource: $resource
    }]
  }
' >"${fixture_v1}"
jq -nS --arg resource "${TARGET_POLICY_ARN}" '
  {
    Version: "2012-10-17",
    Statement: [{
      Sid: "BaselinePolicy",
      Effect: "Allow",
      Action: ["iam:GetPolicy", "iam:ListPolicyVersions"],
      Resource: $resource
    }]
  }
' >"${fixture_v2}"
HISTORICAL_POLICY_SHA="$(iam_policy_sha "${fixture_v1}")"
OLD_POLICY_SHA="$(iam_policy_sha "${fixture_v2}")"
metadata_mode=consistent
policy_read_attempts=0
sleep_calls=0
mutation_calls=0

safe_aws() {
  local label="$1"
  local output="$2"
  shift 2
  local service="${1:-}"
  local operation="${2:-}"
  [[ "${service}" == "iam" ]] || {
    fail "${label}: unexpected service"
    return 1
  }
  case "${operation}" in
    get-policy)
      ((policy_read_attempts += 1))
      jq -n --arg arn "${TARGET_POLICY_ARN}" '
        {
          Policy: {
            Arn: $arn,
            PolicyName: "archon-aws-foundation-control",
            Path: "/",
            IsAttachable: true,
            AttachmentCount: 1,
            PermissionsBoundaryUsageCount: 0,
            DefaultVersionId: "v2"
          }
        }
      ' >"${output}"
      ;;
    list-policy-versions)
      jq -n '
        {
          Versions: [
            {
              VersionId: "v2",
              IsDefaultVersion: true,
              CreateDate: "2026-08-03T00:00:01Z"
            },
            {
              VersionId: "v1",
              IsDefaultVersion: false,
              CreateDate: "2026-08-03T00:00:00Z"
            }
          ]
        }
      ' >"${output}"
      ;;
    get-policy-version)
      local version=""
      while (($# > 0)); do
        if [[ "$1" == "--version-id" ]]; then
          version="${2:-}"
          break
        fi
        shift
      done
      local fixture is_default
      case "${version}" in
        v1)
          fixture="${fixture_v1}"
          is_default=false
          if [[ "${metadata_mode}" == "inconsistent" ||
            ( "${metadata_mode}" == "transient" &&
              "${policy_read_attempts}" -eq 1 ) ]]; then
            is_default=true
          fi
          ;;
        v2)
          fixture="${fixture_v2}"
          is_default=true
          ;;
        *)
          fail "${label}: unexpected version"
          return 1
          ;;
      esac
      jq -n \
        --arg version "${version}" \
        --argjson isDefault "${is_default}" \
        --slurpfile document "${fixture}" '
        {
          PolicyVersion: {
            Document: $document[0],
            VersionId: $version,
            IsDefaultVersion: $isDefault,
            CreateDate: "2026-08-03T00:00:00Z"
          }
        }
      ' >"${output}"
      ;;
    *)
      fail "${label}: unexpected operation"
      return 1
      ;;
  esac
  test -f "${output}"
  test ! -L "${output}"
  chmod 0600 "${output}"
}

baseline_snapshot="$(require_baseline_state consistent)"
expected_snapshot="$(printf 'v1\nv2')"
[[ "${baseline_snapshot}" == "${expected_snapshot}" ]] ||
  fail "Consistent false/true default-version metadata was rejected"

metadata_mode=inconsistent
policy_read_attempts=0
inconsistent_stderr="${test_root}/inconsistent.stderr"
if require_baseline_state inconsistent >/dev/null 2>"${inconsistent_stderr}"; then
  fail "Inconsistent version metadata must fail closed"
fi
grep -Fq "Managed-policy version metadata is inconsistent" \
  "${inconsistent_stderr}" ||
  fail "Inconsistent metadata rejection did not preserve its diagnostic"
if grep -Fq "unary operator expected" "${inconsistent_stderr}"; then
  fail "Metadata comparison regressed to a split test expression"
fi

metadata_mode=transient
policy_read_attempts=0
sleep_calls=0
mutation_calls=0
sleep() {
  ((sleep_calls += 1))
}
aws() {
  ((mutation_calls += 1))
  return 1
}
wait_for_state rolled-back
[[ "${policy_read_attempts}" -eq 2 ]] ||
  fail "Transient metadata retry must take exactly two full snapshots"
[[ "${sleep_calls}" -eq 1 ]] ||
  fail "Transient metadata retry must use exactly one bounded delay"
[[ "${mutation_calls}" -eq 0 ]] ||
  fail "State reads and retries must not mutate AWS"

for accepted_target in v3 v4 v5 v42; do
  is_target_version_id "${accepted_target}" ||
    fail "Valid monotonic target ID was rejected: ${accepted_target}"
done
for rejected_target in v1 v2 v03 v0 x3 ''; do
  if is_target_version_id "${rejected_target}"; then
    fail "Invalid or baseline target ID was accepted: ${rejected_target}"
  fi
done

run_dynamic_rollback_case() (
  local target_id="$1"
  local initial_default="$2"
  local expected_id="$3"
  local expected_result="$4"
  local initial_present="$5"
  local output="${test_root}/rollback-${target_id}-${expected_result}.out"
  local stderr="${test_root}/rollback-${target_id}-${expected_result}.stderr"
  local target_present="${initial_present}"
  local current_default="${initial_default}"
  local -a events=()
  HISTORICAL_POLICY_SHA="$(printf '1%.0s' {1..64})"
  OLD_POLICY_SHA="$(printf '2%.0s' {1..64})"
  NEW_POLICY_SHA="$(printf '3%.0s' {1..64})"
  AUTHORIZATION_MODE=rollback
  EXPECTED_TEMP_POLICY_SHA="$(printf '4%.0s' {1..64})"
  EXPECTED_NEW_VERSION_ID="${expected_id}"

  load_policy_state() {
    POLICY_DEFAULT_VERSION="${current_default}"
    POLICY_VERSION_IDS=(v1 v2)
    POLICY_VERSION_DEFAULTS=(false "$([[ "${current_default}" == v2 ]] && printf true || printf false)")
    POLICY_VERSION_SHAS=("${HISTORICAL_POLICY_SHA}" "${OLD_POLICY_SHA}")
    if [[ "${target_present}" == true ]]; then
      POLICY_VERSION_IDS+=("${target_id}")
      POLICY_VERSION_DEFAULTS+=("$([[ "${current_default}" == "${target_id}" ]] && printf true || printf false)")
      POLICY_VERSION_SHAS+=("${NEW_POLICY_SHA}")
    fi
  }
  verify_live_temp_policy() {
    test "$1" = rollback || return 97
    test "$2" = "${EXPECTED_TEMP_POLICY_SHA}" || return 97
    events+=("auth-$1")
  }
  aws() {
    local service="${1:-}"
    local operation="${2:-}"
    shift 2 || return 97
    local -a actual=("$@")
    local -a expected=()
    local index
    case "${service}:${operation}" in
      iam:set-default-policy-version)
        expected=(
          --policy-arn "${TARGET_POLICY_ARN}"
          --version-id v2
        )
        test "${#actual[@]}" -eq "${#expected[@]}" || return 97
        for index in "${!expected[@]}"; do
          test "${actual[${index}]}" = "${expected[${index}]}" || return 97
        done
        test "${target_present}" = true || return 97
        test "${current_default}" = "${target_id}" || return 97
        current_default=v2
        events+=(set-default-v2)
        ;;
      iam:delete-policy-version)
        expected=(
          --policy-arn "${TARGET_POLICY_ARN}"
          --version-id "${target_id}"
        )
        test "${#actual[@]}" -eq "${#expected[@]}" || return 97
        for index in "${!expected[@]}"; do
          test "${actual[${index}]}" = "${expected[${index}]}" || return 97
        done
        test "${target_present}" = true || return 97
        test "${current_default}" = v2 || return 97
        target_present=false
        events+=("delete-${target_id}")
        ;;
      *)
        return 97
        ;;
    esac
  }

  local status=0
  set +e
  rollback_exact_migration >"${output}" 2>"${stderr}"
  status=$?
  set -e
  if [[ "${expected_result}" == mismatch ]]; then
    test "${status}" -ne 0 ||
      fail "Rollback accepted a target ID that changed after authorization"
    grep -Fq 'Rollback target version changed after authorization' "${stderr}" ||
      fail "Rollback mismatch diagnostic differs"
    test "${#events[@]}" -eq 0 ||
      fail "Rollback mismatch crossed the mutation authorization boundary"
    test "${target_present}" = "${initial_present}" ||
      fail "Rollback mismatch mutated target presence"
    test "${current_default}" = "${initial_default}" ||
      fail "Rollback mismatch mutated the default version"
    return 0
  fi

  test "${status}" -eq 0 ||
    fail "Dynamic rollback failed for ${target_id}: $(cat "${stderr}")"
  test "${target_present}" = false ||
    fail "Dynamic rollback did not remove ${target_id}"
  test "${current_default}" = v2 ||
    fail "Dynamic rollback did not restore v2"
  local expected_output
  expected_output="$(printf 'v1\nv2\n%s' "${expected_id}")"
  test "$(cat "${output}")" = "${expected_output}" ||
    fail "Dynamic rollback output lost the authorized target ID"
  case "${expected_result}" in
    nondefault)
      test "${events[*]}" = "auth-rollback delete-${target_id}" ||
        fail "Nondefault rollback mutation order differs: ${events[*]}"
      ;;
    default)
      test "${events[*]}" = \
        "auth-rollback set-default-v2 auth-rollback delete-${target_id}" ||
        fail "Default rollback mutation order differs: ${events[*]}"
      ;;
    baseline)
      test "${#events[@]}" -eq 0 ||
        fail "Idempotent baseline rollback performed a mutation"
      ;;
    *)
      fail "Unknown dynamic rollback expectation: ${expected_result}"
      ;;
  esac
)

run_dynamic_rollback_case v4 v2 v4 nondefault true
run_dynamic_rollback_case v5 v5 v5 default true
run_dynamic_rollback_case v4 v2 v42 mismatch true
run_dynamic_rollback_case v4 v2 v4 baseline false

run_dynamic_receipt_case() (
  local state="$1"
  local observed_id="$2"
  local expected_id="$3"
  local expected_result="$4"
  local case_name="${state}-${observed_id:-absent}-${expected_id:-none}-${expected_result}"
  local case_runtime="${test_root}/receipt-${case_name}"
  case "${WORK_ROOT}" in
    "${RUNNER_TEMP}"/*) ;;
    *) fail "Receipt work root escaped the runner temp directory" ;;
  esac
  rm -rf -- "${WORK_ROOT}/evidence"
  mkdir -p "${case_runtime}"
  GITHUB_OUTPUT="${case_runtime}/github-output"
  : >"${GITHUB_OUTPUT}"
  AWS_ACCOUNT_ID=123456789012
  CONTROL_PLANE_SHA=0123456789abcdef0123456789abcdef01234567
  GITHUB_RUN_ATTEMPT=1
  GITHUB_RUN_ID=42
  HISTORICAL_POLICY_SHA="$(printf '1%.0s' {1..64})"
  OLD_POLICY_SHA="$(printf '2%.0s' {1..64})"
  NEW_POLICY_SHA="$(printf '3%.0s' {1..64})"
  EXPECTED_NEW_VERSION_ID="${expected_id}"
  local migration_runner="${repository_root}/scripts/run-aws-foundation-core-ami-policy-migration.sh"
  # shellcheck source=/dev/null
  source <(sed -n '/^write_receipt() {/,/^}/p' "${migration_runner}")
  require_migrated_state() {
    test -n "${observed_id}" || return 1
    printf 'v1\nv2\n%s\n' "${observed_id}"
  }
  require_rolled_back_state() {
    return 0
  }

  local status=0
  set +e
  write_receipt "${state}" >"${case_runtime}/stdout" 2>"${case_runtime}/stderr"
  status=$?
  set -e
  if [[ "${expected_result}" == mismatch ]]; then
    test "${status}" -ne 0 ||
      fail "Receipt accepted a target ID that changed after authorization"
    grep -Fq 'Receipt target version changed after authorization' \
      "${case_runtime}/stderr" ||
      fail "Receipt mismatch diagnostic differs"
    test ! -e "${WORK_ROOT}/evidence/migration.json" ||
      fail "Mismatched receipt must not be materialized"
    return 0
  fi

  test "${status}" -eq 0 ||
    fail "Dynamic receipt failed for ${case_name}: $(cat "${case_runtime}/stderr")"
  local receipt="${WORK_ROOT}/evidence/migration.json"
  test -f "${receipt}"
  test ! -L "${receipt}"
  case "${expected_result}" in
    migrated)
      jq -e \
        --arg version "${expected_id}" '
          .policy.state == "migrated" and
          .policy.new.present == true and
          .policy.new.version == $version and
          .policy.currentDefaultVersion == $version
        ' "${receipt}" >/dev/null ||
        fail "Migrated dynamic receipt fields differ"
      ;;
    rolled-back-known)
      jq -e \
        --arg version "${expected_id}" '
          .policy.state == "rolled-back" and
          .policy.new.present == false and
          .policy.new.version == $version and
          .policy.currentDefaultVersion == "v2"
        ' "${receipt}" >/dev/null ||
        fail "Known rolled-back target receipt fields differ"
      ;;
    rolled-back-absent)
      jq -e '
        .policy.state == "rolled-back" and
        .policy.new.present == false and
        .policy.new.version == null and
        .policy.currentDefaultVersion == "v2"
      ' "${receipt}" >/dev/null ||
        fail "Already-absent target receipt fields differ"
      ;;
    *)
      fail "Unknown dynamic receipt expectation: ${expected_result}"
      ;;
  esac
)

run_dynamic_receipt_case migrated v42 v42 migrated
run_dynamic_receipt_case migrated v42 v5 mismatch
run_dynamic_receipt_case rolled-back '' v4 rolled-back-known
run_dynamic_receipt_case rolled-back '' '' rolled-back-absent

printf 'Core AMI policy state metadata and dynamic-version regression tests passed\n'
