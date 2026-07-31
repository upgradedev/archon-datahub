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
policy_unknown="${test_root}/policy-unknown.json"
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
cat >"${policy_unknown}" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Sid":"UnknownMutation","Effect":"Allow","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::example/*"}]}
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
  AWS_ACCOUNT_ID=123456789012
  render_policy_documents
  test -f "${NEW_POLICY}"
  test -f "${OLD_POLICY}"
  jq -e '
    ([.Statement[] | select(.Sid == "ReadExactBootstrapBucketsForDrift")] | length) == 1 and
    ([.Statement[] | select(.Sid == "ReadExactStagePoliciesForDrift")] | length) == 1
  ' "${NEW_POLICY}" >/dev/null
  jq -e '
    ([.Statement[] |
      select(.Sid == "ReadExactBootstrapBucketsForDrift" or
        .Sid == "ReadExactStagePoliciesForDrift")] | length) == 0
  ' "${OLD_POLICY}" >/dev/null
  expected_old="${test_root}/expected-assets-old.json"
  node "${RENDERER}" \
    --input "${SOURCE_POLICY}" \
    --account "${AWS_ACCOUNT_ID}" \
    --stdout-group assets |
    jq -cS '
      .Statement |= map(select(
        .Sid != "ReadExactBootstrapBucketsForDrift" and
        .Sid != "ReadExactStagePoliciesForDrift"))
    ' >"${expected_old}"
  canonical_iam_policy "${expected_old}" | cmp -s - "${OLD_POLICY}"

  valid_assets="${test_root}/valid-assets.json"
  cp -- "${NEW_POLICY}" "${valid_assets}"
  wrong_resource="${test_root}/assets-wrong-resource.json"
  jq -cS '
    . as $policy |
    (.Statement[] |
      select(.Sid == "ReadExactStagePoliciesForDrift") |
      .Resource) =
    ($policy.Statement[] |
      select(.Sid == "ReconcileExactBootstrapBuckets") |
      .Resource)
  ' "${valid_assets}" >"${wrong_resource}"
  missing_sid="${test_root}/assets-missing-delta-sid.json"
  jq -cS '
    .Statement |= map(
      select(.Sid != "ReadExactStagePoliciesForDrift")
    )
  ' "${valid_assets}" >"${missing_sid}"

  assert_render_rejected() {
    local fixture="$1"
    local label="$2"
    local stderr="${test_root}/render-${label}.stderr"
    local status

    set +e
    (
      set -Eeuo pipefail
      node() { cat -- "${fixture}"; }
      render_policy_documents
    ) >/dev/null 2>"${stderr}"
    status=$?
    set -e

    if ((status == 0)); then
      echo "::error::${label} render mutant was accepted" >&2
      exit 1
    fi
    grep -Fxq \
      "::error::The rendered assets policy delta is invalid" \
      "${stderr}"
    if grep -Fq "${AWS_ACCOUNT_ID}" "${stderr}"; then
      echo "::error::${label} leaked the account binding" >&2
      exit 1
    fi
  }

  assert_render_rejected "${wrong_resource}" wrong-resource
  assert_render_rejected "${missing_sid}" missing-delta-sid
)
(
  leaked_stderr="${test_root}/safe-aws-redaction.stderr"
  leaked_output="${test_root}/safe-aws-redaction.json"
  aws() {
    echo 'PRIVATE_AWS_MARKER' >&2
    return 254
  }
  if safe_aws "sanitized API failure" "${leaked_output}" \
    iam get-policy 2>"${leaked_stderr}"; then
    echo '::error::safe_aws accepted a failed AWS command' >&2
    exit 1
  fi
  grep -Fq 'sanitized API failure' "${leaked_stderr}"
  if grep -Fq 'PRIVATE_AWS_MARKER' "${leaked_stderr}"; then
    echo '::error::safe_aws exposed raw AWS stderr' >&2
    exit 1
  fi
)
run_real_state_case() (
  local scenario="$1"
  TARGET_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-assets
  OLD_POLICY_SHA="${direct_sha}"
  NEW_POLICY_SHA="${changed_sha}"
  local state_file="${test_root}/real-${scenario}-state"
  local get_policy_calls="${test_root}/real-${scenario}-get-policy"
  local get_version_calls="${test_root}/real-${scenario}-get-version"
  local mutation_calls="${test_root}/real-${scenario}-mutations"
  printf '0\n' >"${get_policy_calls}"
  printf '0\n' >"${get_version_calls}"
  printf '0\n' >"${mutation_calls}"
  printf 'unknown\n' >"${state_file}"
  sleep() { :; }

  next_counter() {
    local path="$1"
    local value
    value="$(<"${path}")"
    value=$((value + 1))
    printf '%s\n' "${value}" >"${path}"
    printf '%s\n' "${value}"
  }

  aws() {
    local service="${1:-}"
    local operation="${2:-}"
    if [[ "${service}" != "iam" ]]; then
      next_counter "${mutation_calls}" >/dev/null
      return 97
    fi
    case "${operation}" in
      get-policy)
        local snapshot state default_version
        snapshot="$(next_counter "${get_policy_calls}")"
        if [[ "${scenario}" == "persistent-api-failure" ||
              ("${scenario}" == "api-failure-then-migrated" &&
               "${snapshot}" -eq 1) ]]; then
          echo 'PRIVATE_AWS_MARKER' >&2
          return 254
        fi
        if [[ "${scenario}" == "stale-then-migrated" &&
              "${snapshot}" -eq 1 ]]; then
          state="old-only"
          default_version="v1"
        else
          state="migrated"
          default_version="v2"
        fi
        printf '%s\n' "${state}" >"${state_file}"
        jq -cn \
          --arg arn "${TARGET_POLICY_ARN}" \
          --arg default_version "${default_version}" '
            {Policy: {
              Arn: $arn,
              PolicyName: "archon-aws-foundation-assets",
              Path: "/",
              IsAttachable: true,
              AttachmentCount: 1,
              PermissionsBoundaryUsageCount: 0,
              DefaultVersionId: $default_version
            }}
          '
        ;;
      list-policy-versions)
        local state
        state="$(<"${state_file}")"
        if [[ "${scenario}" == "duplicate-inventory" ]]; then
          jq -cn '{Versions: [
            {VersionId: "v1", IsDefaultVersion: true,
             CreateDate: "2026-01-01T00:00:00Z"},
            {VersionId: "v1", IsDefaultVersion: false,
             CreateDate: "2026-01-02T00:00:00Z"}
          ]}'
        elif [[ "${state}" == "old-only" ]]; then
          jq -cn '{Versions: [
            {VersionId: "v1", IsDefaultVersion: true,
             CreateDate: "2026-01-01T00:00:00Z"}
          ]}'
        else
          jq -cn '{Versions: [
            {VersionId: "v1", IsDefaultVersion: false,
             CreateDate: "2026-01-01T00:00:00Z"},
            {VersionId: "v2", IsDefaultVersion: true,
             CreateDate: "2026-01-02T00:00:00Z"}
          ]}'
        fi
        ;;
      get-policy-version)
        next_counter "${get_version_calls}" >/dev/null
        local version_id=""
        shift 2
        while (($#)); do
          if [[ "$1" == "--version-id" ]]; then
            version_id="${2:-}"
            shift 2
          else
            shift
          fi
        done
        local state is_default document
        state="$(<"${state_file}")"
        case "${version_id}" in
          v1)
            document="${policy_a}"
            [[ "${state}" == "old-only" ]] && is_default=true || is_default=false
            ;;
          v2)
            [[ "${state}" == "migrated" ]] || return 98
            if [[ "${scenario}" == "unknown-document" ]]; then
              document="${policy_unknown}"
            else
              document="${policy_changed}"
            fi
            is_default=true
            ;;
          *) return 99 ;;
        esac
        jq -cn \
          --arg version_id "${version_id}" \
          --argjson is_default "${is_default}" \
          --slurpfile document "${document}" '
            {PolicyVersion: {
              VersionId: $version_id,
              IsDefaultVersion: $is_default,
              Document: $document[0]
            }}
          '
        ;;
      *)
        next_counter "${mutation_calls}" >/dev/null
        return 97
        ;;
    esac
  }

  local stdout_path="${test_root}/real-${scenario}.stdout"
  local stderr_path="${test_root}/real-${scenario}.stderr"
  case "${scenario}" in
    stale-then-migrated|api-failure-then-migrated)
      wait_for_state migrated >"${stdout_path}" 2>"${stderr_path}"
      assert_equal "$(<"${get_policy_calls}")" "2" \
        "${scenario} real get-policy attempts"
      ;;
    persistent-api-failure)
      if wait_for_state migrated >"${stdout_path}" 2>"${stderr_path}"; then
        echo '::error::persistent real AWS API failure was accepted' >&2
        exit 1
      fi
      assert_equal "$(<"${get_policy_calls}")" "12" \
        "bounded persistent real API failure"
      ;;
    duplicate-inventory)
      if require_migrated_state real-duplicate \
        >"${stdout_path}" 2>"${stderr_path}"; then
        echo '::error::duplicate real policy inventory was accepted' >&2
        exit 1
      fi
      assert_equal "$(<"${get_version_calls}")" "0" \
        "duplicate inventory rejected before version reads"
      ;;
    unknown-document)
      if require_migrated_state real-unknown \
        >"${stdout_path}" 2>"${stderr_path}"; then
        echo '::error::unknown real policy document was accepted' >&2
        exit 1
      fi
      assert_equal "$(<"${get_version_calls}")" "2" \
        "unknown document inspected canonically"
      ;;
    *)
      echo '::error::unknown real state scenario' >&2
      exit 1
      ;;
  esac
  assert_equal "$(<"${mutation_calls}")" "0" \
    "${scenario} read path performed no mutations"
  if grep -Fq 'PRIVATE_AWS_MARKER' "${stderr_path}"; then
    echo '::error::raw AWS stderr escaped safe_aws' >&2
    exit 1
  fi
)

run_real_state_case stale-then-migrated
run_real_state_case api-failure-then-migrated
run_real_state_case persistent-api-failure
run_real_state_case duplicate-inventory
run_real_state_case unknown-document


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
  TARGET_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-assets
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
  TARGET_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-assets
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
  TARGET_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-assets
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
  TARGET_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-assets
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
  TARGET_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-assets
  RECOVERY_ROLE_ARN=arn:aws:iam::123456789012:role/archon-datahub-github-governed-canary-recovery
  now_calls="${test_root}/ttl-second-check.calls"
  printf '0\n' >"${now_calls}"
  put_calls=0
  date() {
    if [[ " $* " == *' --date='* ]]; then
      printf '2200\n'
    else
      local count
      count="$(<"${now_calls}")"
      count=$((count + 1))
      printf '%s\n' "${count}" >"${now_calls}"
      if ((count == 1)); then
        printf '1000\n'
      else
        printf '1061\n'
      fi
    fi
  }
  aws() {
    [[ "$*" == *'put-role-policy'* ]] || return 1
    put_calls=$((put_calls + 1))
    return 1
  }
  wait_for_temp_digest() { return 0; }
  if install_temp_policy migrate 2099-01-01T00:00:00Z 2>/dev/null; then
    echo '::error::second TTL recheck accepted 1139 seconds' >&2
    exit 1
  fi
  assert_equal "${put_calls}" "0" "no put after TTL changed before mutation"
  assert_equal "$(<"${now_calls}")" "2" "TTL checked twice before put"
)
(
  TARGET_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-assets
  RECOVERY_ROLE_ARN=arn:aws:iam::123456789012:role/archon-datahub-github-governed-canary-recovery
  put_calls=0
  date() {
    if [[ " $* " == *' --date='* ]]; then
      return 1
    fi
    printf '1000\n'
  }
  aws() {
    if [[ "$*" == *'put-role-policy'* ]]; then
      put_calls=$((put_calls + 1))
    fi
    return 1
  }
  if install_temp_policy migrate not-a-date 2>/dev/null; then
    echo '::error::malformed authorization date was accepted' >&2
    exit 1
  fi
  assert_equal "${put_calls}" "0" "no put after malformed authorization date"
)

run_live_ttl_case() (
  local test_remaining="$1"
  local expected_result="$2"
  TARGET_POLICY_ARN=arn:aws:iam::123456789012:policy/archon-aws-foundation-assets
  RECOVERY_ROLE_ARN=arn:aws:iam::123456789012:role/archon-datahub-github-governed-canary-recovery
  local expected_policy="${test_root}/live-expected-${test_remaining}.json"
  local live_policy="${test_root}/live-policy-${test_remaining}.json"
  build_temp_policy migrate 2099-01-01T00:00:00Z "${expected_policy}"
  local expected_sha
  expected_sha="$(iam_policy_sha "${expected_policy}")"
  jq -cn --slurpfile policy "${expected_policy}" '
    {
      RoleName: "archon-datahub-github-governed-canary-recovery",
      PolicyName: "archon-foundation-assets-policy-migration",
      PolicyDocument: ($policy[0] | .Statement |= reverse)
    }
  ' >"${live_policy}"
  date() {
    if [[ " $* " == *' --date='* ]]; then
      printf '%s\n' "$((1000 + test_remaining))"
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
