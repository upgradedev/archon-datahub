#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
driver="${repository_root}/scripts/run-aws-incident-recovery.sh"
test_root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/archon-recovery-driver-test.XXXXXX")"
trap 'rm -rf -- "${test_root}"' EXIT
mkdir -p "${test_root}/bin"

cat >"${test_root}/bin/aws" <<'FAKE_AWS'
#!/usr/bin/env bash
set -euo pipefail
state="${FAKE_AWS_STATE:?}"
mkdir -p "${state}"
increment() {
  local name="$1" path="${state}/${1}.count" count=0
  if [[ -f "${path}" ]]; then count="$(<"${path}")"; fi
  count=$((count + 1)); printf '%s' "${count}" >"${path}"; printf '%s' "${count}"
}
temp_removed=false
if [[ -f "${state}/temp-removed" ]]; then temp_removed=true; fi
case "${1:-}:${2:-}" in
  sts:get-caller-identity)
    printf '{"Account":"%s","Arn":"arn:aws:sts::%s:assumed-role/archon-datahub-github-foundation/test-session","UserId":"fixture"}\n' "${FAKE_ACCOUNT_ID}" "${FAKE_ACCOUNT_ID}"
    ;;
  iam:list-role-policies)
    if [[ "$#" -ne 6 || "$3" != "--role-name" ||
      "$4" != "archon-datahub-github-governed-canary-recovery" ||
      "$5" != "--output" || "$6" != "json" ]]; then
      echo "unexpected ListRolePolicies arguments" >&2
      exit 96
    fi
    list_call="$(increment list-role-policies)"
    case "${FAKE_INITIAL_INVENTORY:-base}" in
      access-denied)
        echo "An error occurred (AccessDenied): ${FAKE_PRIVATE_MARKER}" >&2
        exit 254
        ;;
      base)
        printf '%s\n' '{"PolicyNames":["archon-staging-stack-read"]}'
        ;;
      base-temp)
        if [[ "${temp_removed}" == true ]]; then
          printf '%s\n' '{"PolicyNames":["archon-staging-stack-read"]}'
        else
          printf '%s\n' '{"PolicyNames":["archon-incident-30546241677-delete","archon-staging-stack-read"]}'
        fi
        ;;
      base-temp-reset)
        if [[ "${temp_removed}" == false ]]; then
          printf '%s\n' '{"PolicyNames":["archon-incident-30546241677-delete","archon-staging-stack-read"]}'
        elif [[ "${list_call}" == 3 ]]; then
          printf '%s\n' '{"PolicyNames":["archon-staging-stack-read","transient-policy"]}'
        else
          printf '%s\n' '{"PolicyNames":["archon-staging-stack-read"]}'
        fi
        ;;
      base-other)
        printf '%s\n' '{"PolicyNames":["archon-staging-stack-read","unreviewed-policy"]}'
        ;;
      base-temp-other)
        if [[ "${temp_removed}" == true ]]; then
          printf '%s\n' '{"PolicyNames":["archon-staging-stack-read","unreviewed-policy"]}'
        else
          printf '%s\n' '{"PolicyNames":["archon-incident-30546241677-delete","archon-staging-stack-read","unreviewed-policy"]}'
        fi
        ;;
      *) exit 98 ;;
    esac
    ;;
  iam:delete-role-policy)
    if [[ "$#" -ne 6 || "$3" != "--role-name" ||
      "$4" != "archon-datahub-github-governed-canary-recovery" ||
      "$5" != "--policy-name" ||
      "$6" != "archon-incident-30546241677-delete" ]]; then
      echo "unexpected DeleteRolePolicy arguments" >&2
      exit 95
    fi
    increment delete-role-policy >/dev/null
    case "${FAKE_DELETE_MODE:-success}" in
      success)
        : >"${state}/temp-removed"
        ;;
      raced-no-such)
        : >"${state}/temp-removed"
        echo "An error occurred (NoSuchEntity) when calling the DeleteRolePolicy operation: ${FAKE_PRIVATE_MARKER}" >&2
        exit 254
        ;;
      access-denied)
        echo "An error occurred (AccessDenied) when calling the DeleteRolePolicy operation: ${FAKE_PRIVATE_MARKER}" >&2
        exit 254
        ;;
      *) exit 99 ;;
    esac
    ;;
  cloudformation:list-stacks)
    increment list-stacks >/dev/null
    echo "An error occurred (AccessDenied) when calling the ListStacks operation: ${FAKE_PRIVATE_MARKER}" >&2
    exit 254
    ;;
  *)
    echo "unexpected fake AWS call: $*" >&2
    exit 97
    ;;
esac
FAKE_AWS
chmod 0700 "${test_root}/bin/aws"
cat >"${test_root}/bin/sleep" <<'FAKE_SLEEP'
#!/usr/bin/env bash
exit 0
FAKE_SLEEP
chmod 0700 "${test_root}/bin/sleep"

fail() { echo "::error::$*" >&2; exit 1; }
call_count() {
  local path="$1"
  if [[ -f "${path}" ]]; then
    printf '%s' "$(<"${path}")"
  else
    printf '0'
  fi
}
assert_no_raw_error() {
  local case_root="$1"
  if grep -Fq 'PRIVATE_AWS_ERROR_MARKER' "${case_root}/stdout" "${case_root}/stderr"; then
    fail "raw AWS error leaked for ${case_root}"
  fi
}
run_driver() {
  local case_name="$1" mode="$2" delete_mode="$3" inventory="${4:-base}"
  local case_root="${test_root}/${case_name}"
  mkdir -p "${case_root}/state"
  : >"${case_root}/output"
  PATH="${test_root}/bin:${PATH}" \
  FAKE_AWS_STATE="${case_root}/state" \
  FAKE_ACCOUNT_ID="123456789012" \
  FAKE_DELETE_MODE="${delete_mode}" \
  FAKE_INITIAL_INVENTORY="${inventory}" \
  FAKE_PRIVATE_MARKER="PRIVATE_AWS_ERROR_MARKER" \
  GITHUB_ACTIONS=true \
  RUNNER_TEMP="${case_root}" \
  GITHUB_OUTPUT="${case_root}/output" \
  GITHUB_EVENT_NAME=workflow_dispatch \
  AWS_ACCOUNT_ID="123456789012" \
  AWS_FOUNDATION_ROLE_ARN="arn:aws:iam::123456789012:role/archon-datahub-github-foundation" \
  CONTROL_PLANE_SHA="324073874b862e08bf8d80fa70709165cee86851" \
  EXPECTED_STACK_ID_SHA256="sha256:$(printf '0%.0s' {1..64})" \
  bash "${driver}" "${mode}" >"${case_root}/stdout" 2>"${case_root}/stderr"
}

run_driver cleanup-absent cleanup ignored base || fail 'already-absent cleanup should succeed'
test "$(call_count "${test_root}/cleanup-absent/state/delete-role-policy.count")" = 0 || fail 'already-absent cleanup must not delete'
test "$(call_count "${test_root}/cleanup-absent/state/list-role-policies.count")" = 4 || fail 'already-absent cleanup must classify then prove absence three times'
test -f "${test_root}/cleanup-absent/archon-aws-incident-recovery/cleanup-evidence/cleanup.json" || fail 'already-absent cleanup evidence is missing'

for accepted in success raced-no-such; do
  run_driver "cleanup-present-${accepted}" cleanup "${accepted}" base-temp || fail "present cleanup ${accepted} should succeed"
  case_root="${test_root}/cleanup-present-${accepted}"
  test "$(call_count "${case_root}/state/delete-role-policy.count")" = 1 || fail 'present cleanup must issue exactly one delete'
  test "$(call_count "${case_root}/state/list-role-policies.count")" = 4 || fail 'present cleanup must classify then prove absence three times'
  test -f "${case_root}/archon-aws-incident-recovery/cleanup-evidence/cleanup.json" || fail 'present cleanup evidence is missing'
  assert_no_raw_error "${case_root}"
done

run_driver cleanup-consecutive-reset cleanup success base-temp-reset || fail 'cleanup should recover after a transient non-absent read'
case_root="${test_root}/cleanup-consecutive-reset"
test "$(call_count "${case_root}/state/delete-role-policy.count")" = 1 || fail 'reset sequence must delete exactly once'
test "$(call_count "${case_root}/state/list-role-policies.count")" = 6 || fail 'non-absent read must reset three-new-read confirmation count'
test -f "${case_root}/archon-aws-incident-recovery/cleanup-evidence/cleanup.json" || fail 'reset sequence cleanup evidence is missing'

if run_driver cleanup-delete-access-denied cleanup access-denied base-temp; then
  fail 'persistent policy after opaque delete failure must fail closed'
fi
case_root="${test_root}/cleanup-delete-access-denied"
test "$(call_count "${case_root}/state/delete-role-policy.count")" = 1 || fail 'failed delete path must issue exactly one delete'
test ! -e "${case_root}/archon-aws-incident-recovery/cleanup-evidence/cleanup.json" || fail 'failed cleanup created false evidence'
grep -Fq 'lacks repeated canonical absence' "${case_root}/stderr" || fail 'failed delete path did not fail canonical proof'
assert_no_raw_error "${case_root}"

if run_driver cleanup-list-access-denied cleanup ignored access-denied; then
  fail 'unreadable initial inventory must fail closed'
fi
case_root="${test_root}/cleanup-list-access-denied"
test "$(call_count "${case_root}/state/delete-role-policy.count")" = 0 || fail 'unreadable inventory must not delete'
grep -Fq 'Unable to inspect recovery-role inline policies before revocation' "${case_root}/stderr" || fail 'initial inventory failure was not generic'
assert_no_raw_error "${case_root}"

if run_driver cleanup-unexpected-only cleanup ignored base-other; then
  fail 'unexpected inventory without temporary policy must fail closed'
fi
case_root="${test_root}/cleanup-unexpected-only"
test "$(call_count "${case_root}/state/delete-role-policy.count")" = 0 || fail 'unexpected inventory without temporary policy must not delete'
grep -Fq 'unexpected inline-policy drift before revocation' "${case_root}/stderr" || fail 'unexpected inventory failure differs'

if run_driver cleanup-temp-unexpected cleanup success base-temp-other; then
  fail 'persistent unrelated inventory must fail after temporary-policy deletion'
fi
case_root="${test_root}/cleanup-temp-unexpected"
test "$(call_count "${case_root}/state/delete-role-policy.count")" = 1 || fail 'temporary policy was not deleted before drift failure'
test ! -e "${case_root}/archon-aws-incident-recovery/cleanup-evidence/cleanup.json" || fail 'unexpected inventory created false evidence'
grep -Fq 'lacks repeated canonical absence' "${case_root}/stderr" || fail 'persistent unrelated inventory did not fail canonical proof'

if run_driver postverify-generic-failure postverify ignored base; then
  fail 'generic ListStacks failure must not prove target-name absence'
fi
test ! -e "${test_root}/postverify-generic-failure/archon-aws-incident-recovery/evidence/recovery.json" || fail 'false recovery evidence was created'
grep -Fq 'Unable to inspect sanitized deletion progress' "${test_root}/postverify-generic-failure/stderr" || fail 'generic ListStacks failure did not fail closed'
assert_no_raw_error "${test_root}/postverify-generic-failure"

# Source the real driver without executing a mode, override only AWS readers, and
# prove workflow-command masking does not contaminate captured snapshot stdout.
shape_root="${test_root}/shape"
mkdir -p "${shape_root}"
: >"${shape_root}/output"
GITHUB_ACTIONS=true RUNNER_TEMP="${shape_root}" GITHUB_OUTPUT="${shape_root}/output" \
  source "${driver}"
retry_safe_aws() {
  local _label="$1" output="$2"
  printf '%s\n' '{"Stacks":[{"StackId":"arn:aws:cloudformation:eu-west-1:123456789012:stack/Archon-Staging-IAM-Foundation/11111111-2222-3333-4444-555555555555"}]}' >"${output}"
}
safe_aws() {
  local _label="$1" output="$2"
  case "${output}" in
    *-resources.json) printf '%s\n' '{"StackResourceSummaries":[]}' >"${output}" ;;
    *) printf '%s\n' '{"TemplateBody":"fixture"}' >"${output}" ;;
  esac
}
canonical_template_sha() { printf '%s\n' '80a2b02326bbaa3ae145d0fff52cc1c20f3a330d4ef5c7fa2d816182f7c2b825'; }
mapfile -t snapshot_lines < <(snapshot_target shape ignored)
test "${#snapshot_lines[@]}" = 3 || fail "snapshot_target stdout shape changed"
test "${snapshot_lines[0]}" = "${shape_root}/archon-aws-incident-recovery/shape-stack.json" || fail "snapshot stack path differs"
test "${snapshot_lines[1]}" = "${shape_root}/archon-aws-incident-recovery/shape-resources.json" || fail "snapshot resource path differs"
test "${snapshot_lines[2]}" = '80a2b02326bbaa3ae145d0fff52cc1c20f3a330d4ef5c7fa2d816182f7c2b825' || fail "snapshot template identity differs"
stack_path="$(snapshot_stack_only shape-only)"
test "${stack_path}" = "${shape_root}/archon-aws-incident-recovery/shape-only-stack.json" || fail "snapshot_stack_only stdout was contaminated"
