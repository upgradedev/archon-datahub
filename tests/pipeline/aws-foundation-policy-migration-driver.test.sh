#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." &&
    pwd
)"
test_root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/archon-policy-migration-test.XXXXXX")"
trap 'rm -rf -- "${test_root}"' EXIT
mkdir -p "${test_root}/runner"
export GITHUB_ACTIONS=true
export RUNNER_TEMP="${test_root}/runner"
export GITHUB_OUTPUT="${test_root}/github-output"
: >"${GITHUB_OUTPUT}"

# shellcheck source=/dev/null
source "${repository_root}/scripts/aws-foundation-policy-migration-common.sh"
# shellcheck source=/dev/null
source "${repository_root}/scripts/aws-foundation-policy-migration-authorization.sh"
# shellcheck source=/dev/null
source "${repository_root}/scripts/aws-foundation-policy-migration-state.sh"

assert_equal() {
  local actual="$1"
  local expected="$2"
  local label="$3"
  test "${actual}" = "${expected}" || {
    printf '::error::%s: expected %s, got %s\n' \
      "${label}" "${expected}" "${actual}" >&2
    exit 1
  }
}

policy_a="${test_root}/policy-a.json"
policy_b="${test_root}/policy-b.json"
policy_changed="${test_root}/policy-changed.json"
policy_wrapped="${test_root}/policy-wrapped.json"
cat >"${policy_a}" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Sid":"ZReadRole","Effect":"Allow","Action":"iam:GetRole","Resource":"arn:aws:iam::123456789012:role/example"},{"Sid":"AReadObjects","Effect":"Allow","Action":["s3:ListBucket","s3:GetObject"],"Resource":["arn:aws:s3:::example/*","arn:aws:s3:::example"]}]}
JSON
cat >"${policy_b}" <<'JSON'
{"Statement":[{"Resource":["arn:aws:s3:::example","arn:aws:s3:::example/*"],"Action":["s3:GetObject","s3:ListBucket"],"Effect":"Allow","Sid":"AReadObjects"},{"Resource":["arn:aws:iam::123456789012:role/example"],"Action":["iam:GetRole"],"Effect":"Allow","Sid":"ZReadRole"}],"Version":"2012-10-17"}
JSON
cat >"${policy_changed}" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Sid":"AReadObjects","Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::example","arn:aws:s3:::example/*"]},{"Sid":"ZReadRole","Effect":"Allow","Action":["iam:GetRole"],"Resource":["arn:aws:iam::123456789012:role/example"]}]}
JSON
jq -cn --slurpfile policy "${policy_b}" \
  '{PolicyVersion: {Document: $policy[0]}}' >"${policy_wrapped}"
direct_sha="$(iam_policy_sha "${policy_a}")"
permuted_sha="$(iam_policy_sha "${policy_b}")"
wrapped_sha="$(iam_policy_sha "${policy_wrapped}" '.PolicyVersion.Document')"
changed_sha="$(iam_policy_sha "${policy_changed}")"
assert_equal "${direct_sha}" "${permuted_sha}" "statement/action/resource permutation"
assert_equal "${direct_sha}" "${wrapped_sha}" "wrapped IAM policy canonicalization"
test "${direct_sha}" != "${changed_sha}"

(
  poll_calls=0
  sleep() { :; }
  require_migrated_state() {
    poll_calls=$((poll_calls + 1))
    if ((poll_calls < 2)); then
      return 1
    fi
    printf 'v1\nv2\n'
  }
  wait_for_state migrated
  assert_equal "${poll_calls}" "2" "stale-to-migrated polling"
)

(
  api_calls=0
  sleep() { :; }
  require_migrated_state() {
    api_calls=$((api_calls + 1))
    if ((api_calls == 1)); then
      return 1
    fi
    printf 'v1\nv2\n'
  }
  wait_for_state migrated
  assert_equal "${api_calls}" "2" "API-failure-to-migrated polling"
)

(
  failed_calls=0
  sleep() { :; }
  require_migrated_state() {
    failed_calls=$((failed_calls + 1))
    return 1
  }
  if wait_for_state migrated 2>/dev/null; then
    echo '::error::persistent API failure was accepted' >&2
    exit 1
  fi
  assert_equal "${failed_calls}" "12" "bounded persistent failure polling"
)

(
  pending_counter="${test_root}/pending-counter"
  printf '0\n' >"${pending_counter}"
  sleep() { :; }
  require_rollback_pending_state() {
    local pending_calls
    pending_calls="$(cat "${pending_counter}")"
    pending_calls=$((pending_calls + 1))
    printf '%s\n' "${pending_calls}" >"${pending_counter}"
    if ((pending_calls < 2)); then
      return 1
    fi
    printf 'v1\nv2\n'
  }
  pending="$(wait_for_rollback_pending_state create-propagation old)"
  assert_equal "${pending}" $'v1\nv2' "nondefault create propagation"
  assert_equal "$(cat "${pending_counter}")" "2" "nondefault create polling"
)

(
  OLD_POLICY_SHA=old
  NEW_POLICY_SHA=new
  load_policy_state() {
    POLICY_VERSION_IDS=(v1 v2)
    POLICY_VERSION_SHAS=(old new)
    POLICY_VERSION_DEFAULTS=(true false)
    POLICY_DEFAULT_VERSION=v1
  }
  if require_migrated_state wrong-default >/dev/null 2>&1; then
    echo '::error::wrong default managed-policy version was accepted' >&2
    exit 1
  fi
)

(
  POLICY_VERSION_IDS=(v1 v2)
  POLICY_VERSION_SHAS=(old old)
  POLICY_VERSION_DEFAULTS=(true false)
  if version_for_sha old >/dev/null 2>&1; then
    echo '::error::duplicate policy documents were accepted' >&2
    exit 1
  fi
)

(
  OLD_POLICY_SHA=old
  NEW_POLICY_SHA=new
  load_policy_state() {
    POLICY_VERSION_IDS=(v1 v1)
    POLICY_VERSION_SHAS=(old new)
    POLICY_VERSION_DEFAULTS=(true false)
    POLICY_DEFAULT_VERSION=v1
  }
  if require_migrated_state duplicate-id >/dev/null 2>&1; then
    echo '::error::duplicate version IDs were accepted' >&2
    exit 1
  fi
)

(
  OLD_POLICY_SHA=old
  NEW_POLICY_SHA=new
  load_policy_state() {
    POLICY_VERSION_IDS=(v1 v3)
    POLICY_VERSION_SHAS=(old unknown)
    POLICY_VERSION_DEFAULTS=(false true)
    POLICY_DEFAULT_VERSION=v3
  }
  if require_migrated_state unknown-extra >/dev/null 2>&1; then
    echo '::error::unknown extra policy version was accepted' >&2
    exit 1
  fi
)

(
  OLD_POLICY_SHA=old
  NEW_POLICY_SHA=new
  CONTROL_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-control
  AUTHORIZATION_MODE=rollback
  EXPECTED_TEMP_POLICY_SHA=temp
  mutations=()
  ttl_checks=0
  load_policy_state() {
    POLICY_VERSION_IDS=(v1 v2)
    POLICY_VERSION_SHAS=(old new)
    POLICY_VERSION_DEFAULTS=(false true)
    POLICY_DEFAULT_VERSION=v2
  }
  wait_for_rollback_pending_state() { printf 'v1\nv2\n'; }
  require_rollback_pending_state() {
    test "$2" = old
    printf 'v1\nv2\n'
  }
  verify_live_temp_policy() { ttl_checks=$((ttl_checks + 1)); }
  aws() {
    if [[ "$*" == *'set-default-policy-version'* ]]; then
      mutations+=(set:v1)
      POLICY_DEFAULT_VERSION=v1
      POLICY_VERSION_DEFAULTS=(true false)
    elif [[ "$*" == *'delete-policy-version'* ]]; then
      mutations+=(delete:v2)
    else
      return 1
    fi
  }
  wait_for_state() { return 0; }
  require_rolled_back_state() { printf 'v1\n'; }
  rollback_exact_migration >"${test_root}/rollback-result"
  assert_equal "${mutations[*]}" "set:v1 delete:v2" "exact rollback mutations"
  assert_equal "${ttl_checks}" "2" "rollback pre-mutation authorization checks"
)

(
  OLD_POLICY_SHA=old
  NEW_POLICY_SHA=new
  CONTROL_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-control
  AUTHORIZATION_MODE=rollback
  EXPECTED_TEMP_POLICY_SHA=temp
  mutations=()
  load_policy_state() {
    POLICY_VERSION_IDS=(v1 v2)
    POLICY_VERSION_SHAS=(old new)
    POLICY_VERSION_DEFAULTS=(false true)
    POLICY_DEFAULT_VERSION=v2
  }
  wait_for_rollback_pending_state() { return 1; }
  verify_live_temp_policy() { return 0; }
  aws() { mutations+=(unexpected); }
  if rollback_exact_migration >/dev/null; then
    echo '::error::tamper before default restoration was accepted' >&2
    exit 1
  fi
  assert_equal "${#mutations[@]}" "0" "no mutation after pre-switch tamper"
)

(
  OLD_POLICY_SHA=old
  NEW_POLICY_SHA=new
  CONTROL_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-control
  AUTHORIZATION_MODE=rollback
  EXPECTED_TEMP_POLICY_SHA=temp
  mutations=()
  ttl_checks=0
  load_policy_state() {
    POLICY_VERSION_IDS=(v1 v2)
    POLICY_VERSION_SHAS=(old new)
    POLICY_VERSION_DEFAULTS=(false true)
    POLICY_DEFAULT_VERSION=v2
  }
  wait_for_rollback_pending_state() { printf 'v1\nv2\n'; }
  require_rollback_pending_state() {
    if [[ "$1" == rollback-before-delete ]]; then
      return 1
    fi
    printf 'v1\nv2\n'
  }
  verify_live_temp_policy() { ttl_checks=$((ttl_checks + 1)); }
  aws() {
    if [[ "$*" == *'set-default-policy-version'* ]]; then
      mutations+=(set:v1)
      POLICY_DEFAULT_VERSION=v1
      POLICY_VERSION_DEFAULTS=(true false)
      return 0
    fi
    mutations+=(unexpected)
  }
  if rollback_exact_migration >/dev/null; then
    echo '::error::tamper before nondefault deletion was accepted' >&2
    exit 1
  fi
  assert_equal "${mutations[*]}" "set:v1" "no deletion after pre-delete tamper"
  assert_equal "${ttl_checks}" "1" "authorization checked before restored default"
)

run_install_ttl_case() (
  local remaining="$1"
  local expected_result="$2"
  CONTROL_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-control
  RECOVERY_ROLE_ARN=arn:aws:iam::123456789012:role/archon-datahub-github-governed-canary-recovery
  FAKE_NOW=1000
  FAKE_EXPIRY=$((FAKE_NOW + remaining))
  put_calls=0
  date() {
    if [[ " $* " == *' --date='* ]]; then
      printf '%s\n' "${FAKE_EXPIRY}"
    else
      printf '%s\n' "${FAKE_NOW}"
    fi
  }
  aws() {
    if [[ "$*" == *'put-role-policy'* ]]; then
      put_calls=$((put_calls + 1))
      return 0
    fi
    return 1
  }
  wait_for_temp_digest() { return 0; }
  if [[ "${expected_result}" == success ]]; then
    install_temp_policy migrate 2099-01-01T00:00:00Z
    assert_equal "${put_calls}" "1" "accepted install TTL ${remaining}"
  else
    if install_temp_policy migrate 2099-01-01T00:00:00Z 2>/dev/null; then
      echo "::error::invalid install TTL ${remaining} was accepted" >&2
      exit 1
    fi
    assert_equal "${put_calls}" "0" "rejected install TTL ${remaining}"
  fi
)
run_install_ttl_case 1140 success
run_install_ttl_case 1200 success
run_install_ttl_case 1139 failure
run_install_ttl_case 1201 failure

(
  CONTROL_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-control
  RECOVERY_ROLE_ARN=arn:aws:iam::123456789012:role/archon-datahub-github-governed-canary-recovery
  date() {
    if [[ " $* " == *' --date='* ]]; then
      return 1
    fi
    printf '1000\n'
  }
  aws() { echo '::error::PutRolePolicy reached after malformed date' >&2; return 1; }
  if install_temp_policy migrate not-a-date 2>/dev/null; then
    echo '::error::malformed authorization date was accepted' >&2
    exit 1
  fi
)

run_live_ttl_case() (
  local test_remaining="$1"
  local expected_result="$2"
  CONTROL_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-control
  RECOVERY_ROLE_ARN=arn:aws:iam::123456789012:role/archon-datahub-github-governed-canary-recovery
  local expected_policy="${test_root}/live-expected-${test_remaining}.json"
  local live_policy="${test_root}/live-policy-${test_remaining}.json"
  build_temp_policy migrate 2099-01-01T00:00:00Z "${expected_policy}"
  local expected_sha
  expected_sha="$(iam_policy_sha "${expected_policy}")"
  jq -cn --slurpfile policy "${expected_policy}" '
    {
      RoleName: "archon-datahub-github-governed-canary-recovery",
      PolicyName: "archon-foundation-control-policy-migration",
      PolicyDocument: ($policy[0] | .Statement |= reverse)
    }
  ' >"${live_policy}"
  date() {
    if [[ " $* " == *' --date='* ]]; then
      printf '%s\n' "$((1000 + remaining))"
    else
      printf '1000\n'
    fi
  }
  aws() {
    if [[ "$*" == *'get-role-policy'* ]]; then
      cat "${live_policy}"
      return 0
    fi
    return 1
  }
  if [[ "${expected_result}" == success ]]; then
    verify_live_temp_policy migrate "${expected_sha}"
  elif verify_live_temp_policy migrate "${expected_sha}" 2>/dev/null; then
    echo "::error::invalid live TTL ${test_remaining} was accepted" >&2
    exit 1
  fi
)
run_live_ttl_case 180 success
run_live_ttl_case 179 failure
run_live_ttl_case 1201 failure

echo 'AWS foundation policy migration behavioral tests passed'
