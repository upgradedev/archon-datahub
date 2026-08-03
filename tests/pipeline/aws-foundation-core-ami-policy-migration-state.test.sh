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

printf 'Core AMI policy state metadata regression tests passed\n'
