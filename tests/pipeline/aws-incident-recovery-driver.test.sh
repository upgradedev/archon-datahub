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
case "${1:-}:${2:-}" in
  sts:get-caller-identity)
    printf '{"Account":"%s","Arn":"arn:aws:sts::%s:assumed-role/archon-datahub-github-foundation/test-session","UserId":"fixture"}\n' "${FAKE_ACCOUNT_ID}" "${FAKE_ACCOUNT_ID}"
    ;;
  iam:list-role-policies)
    increment list-role-policies >/dev/null
    if [[ "${FAKE_LIST_MODE:-base}" == "unexpected" ]]; then
      printf '%s\n' '{"PolicyNames":["archon-staging-stack-read","unreviewed-policy"]}'
    else
      printf '%s\n' '{"PolicyNames":["archon-staging-stack-read"]}'
    fi
    ;;
  iam:delete-role-policy)
    increment delete-role-policy >/dev/null
    case "${FAKE_DELETE_MODE:-success}" in
      success) exit 0 ;;
      no-such)
        echo 'An error occurred (NoSuchEntity) when calling the DeleteRolePolicy operation: The role policy cannot be found.' >&2
        exit 254
        ;;
      access-denied)
        echo 'An error occurred (AccessDenied) when calling the DeleteRolePolicy operation: denied' >&2
        exit 254
        ;;
      throttled)
        echo 'An error occurred (Throttling) when calling the DeleteRolePolicy operation: retry' >&2
        exit 254
        ;;
      wrong-operation)
        echo 'An error occurred (NoSuchEntity) when calling the PutRolePolicy operation: missing' >&2
        exit 254
        ;;
      *) exit 99 ;;
    esac
    ;;
  cloudformation:list-stacks)
    increment list-stacks >/dev/null
    echo 'An error occurred (AccessDenied) when calling the ListStacks operation: denied' >&2
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
run_driver() {
  local case_name="$1" mode="$2" delete_mode="$3" list_mode="${4:-base}"
  local case_root="${test_root}/${case_name}"
  mkdir -p "${case_root}/state"
  : >"${case_root}/output"
  PATH="${test_root}/bin:${PATH}" \
  FAKE_AWS_STATE="${case_root}/state" \
  FAKE_ACCOUNT_ID="123456789012" \
  FAKE_DELETE_MODE="${delete_mode}" \
  FAKE_LIST_MODE="${list_mode}" \
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

for accepted in success no-such; do
  run_driver "cleanup-${accepted}" cleanup "${accepted}" || fail "cleanup ${accepted} should succeed"
  test "$(<"${test_root}/cleanup-${accepted}/state/delete-role-policy.count")" = 1 || fail "cleanup must issue one exact delete"
  test ! -e "${test_root}/cleanup-${accepted}/archon-aws-incident-recovery/delete-role-policy.error" || fail "private delete error was retained"
  test -f "${test_root}/cleanup-${accepted}/archon-aws-incident-recovery/cleanup-evidence/cleanup.json" || fail "cleanup evidence is missing"
done

for rejected in access-denied throttled wrong-operation; do
  if run_driver "cleanup-${rejected}" cleanup "${rejected}"; then
    fail "cleanup ${rejected} must fail closed"
  fi
  test "$(<"${test_root}/cleanup-${rejected}/state/delete-role-policy.count")" = 1 || fail "failed cleanup must still target delete once"
  test ! -e "${test_root}/cleanup-${rejected}/archon-aws-incident-recovery/delete-role-policy.error" || fail "private raw error was retained"
  grep -Fq 'Unable to revoke the exact temporary recovery authorization' "${test_root}/cleanup-${rejected}/stderr" || fail "generic failure was not emitted"
  if grep -Eq 'AccessDenied|Throttling|NoSuchEntity' "${test_root}/cleanup-${rejected}/stderr"; then
    fail "raw AWS error leaked to stderr"
  fi
done

if run_driver cleanup-unexpected-policy cleanup success unexpected; then
  fail 'unexpected inline policy inventory must fail evidence'
fi
test "$(<"${test_root}/cleanup-unexpected-policy/state/delete-role-policy.count")" = 1 || fail 'exact temporary policy was not deleted before drift failure'
grep -Fq 'lacks repeated canonical absence' "${test_root}/cleanup-unexpected-policy/stderr" || fail 'unexpected inventory did not fail closed'

if run_driver postverify-generic-failure postverify no-such; then
  fail 'generic ListStacks failure must not prove target-name absence'
fi
test ! -e "${test_root}/postverify-generic-failure/archon-aws-incident-recovery/evidence/recovery.json" || fail 'false recovery evidence was created'
grep -Fq 'Unable to inspect sanitized deletion progress' "${test_root}/postverify-generic-failure/stderr" || fail 'generic ListStacks failure did not fail closed'

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