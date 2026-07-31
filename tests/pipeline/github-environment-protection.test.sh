#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." &&
    pwd
)"
test_root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/archon-environment-test.XXXXXX")"
trap 'rm -rf -- "${test_root}"' EXIT
mkdir -p "${test_root}/bin"

cat >"${test_root}/bin/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${1:-}" == "api" ]] || exit 91
endpoint="${!#}"
scenario="${ENVIRONMENT_SCENARIO:?}"
: "${GH_CALL_LOG:?}"
printf '%s\n' "${endpoint}" >>"${GH_CALL_LOG}"
[[ "${scenario}" != "api-failure" ]] || exit 70
environment="${endpoint#*/environments/}"
environment="${environment%%/*}"

if [[ "${endpoint}" == *'/deployment-branch-policies?'* ]]; then
  branch=master
  [[ "${scenario}" != "wrong-branch" ]] || branch=develop
  jq -cn --arg branch "${branch}" '
    {total_count: 1, branch_policies: [{name: $branch, type: "branch"}]}
  '
  exit 0
fi

reviewer=upgradedev
reviewer_type=User
bypass=false
self_review=false
custom=true
protected=false
extra=false
missing=false
reverse=false
case "${scenario}" in
  pass|wrong-branch) ;;
  reversed-rules) reverse=true ;;
  admin-bypass) bypass=true ;;
  extra-rule) extra=true ;;
  missing-rule) missing=true ;;
  wrong-reviewer) reviewer=someone-else ;;
  wrong-reviewer-type) reviewer_type=Team ;;
  self-review) self_review=true ;;
  wrong-deployment-policy) custom=false; protected=true ;;
  *) exit 92 ;;
esac
jq -cn \
  --arg name "${environment}" \
  --arg reviewer "${reviewer}" \
  --arg reviewer_type "${reviewer_type}" \
  --argjson bypass "${bypass}" \
  --argjson self_review "${self_review}" \
  --argjson custom "${custom}" \
  --argjson protected "${protected}" \
  --argjson extra "${extra}" \
  --argjson missing "${missing}" \
  --argjson reverse "${reverse}" '
    ({
      name: $name,
      can_admins_bypass: $bypass,
      deployment_branch_policy: {
        custom_branch_policies: $custom,
        protected_branches: $protected
      }
    }) +
    (([
      {type: "branch_policy"},
      {
        type: "required_reviewers",
        prevent_self_review: $self_review,
        reviewers: [{
          type: $reviewer_type,
          reviewer: {login: $reviewer}
        }]
      }
    ] |
      if $missing then map(select(.type != "branch_policy")) else . end |
      if $extra then . + [{type: "wait_timer"}] else . end |
      if $reverse then reverse else . end) as $rules |
      {protection_rules: $rules})
  '
FAKE_GH
chmod 0700 "${test_root}/bin/gh"
export PATH="${test_root}/bin:${PATH}"
export GH_TOKEN=test-token
export GITHUB_ACTIONS=true
export GITHUB_REPOSITORY=upgradedev/archon-datahub
export GITHUB_REPOSITORY_OWNER=upgradedev
verifier="${repository_root}/scripts/verify-github-environment-protection.sh"

run_pass() {
  local scenario="$1"
  shift
  local call_log="${test_root}/${scenario}.calls"
  : >"${call_log}"
  GH_CALL_LOG="${call_log}" \
  ENVIRONMENT_SCENARIO="${scenario}" \
    bash "${verifier}" "$@" \
      >"${test_root}/${scenario}.stdout" \
      2>"${test_root}/${scenario}.stderr"
  test "$(wc -l <"${call_log}")" -eq "$((2 * $#))" || {
    echo "::error::environment verifier did not query every ${scenario} endpoint" >&2
    exit 1
  }
  local environment configuration_endpoint branch_endpoint
  for environment in "$@"; do
    configuration_endpoint="/repos/${GITHUB_REPOSITORY}/environments/${environment}"
    branch_endpoint="${configuration_endpoint}/deployment-branch-policies?per_page=100"
    test "$(grep -Fxc "${configuration_endpoint}" "${call_log}")" -eq 1
    test "$(grep -Fxc "${branch_endpoint}" "${call_log}")" -eq 1
  done
}

run_fail() {
  local label="$1"
  local scenario="$2"
  shift 2
  local call_log="${test_root}/${label}.calls"
  : >"${call_log}"
  if GH_CALL_LOG="${call_log}" \
    ENVIRONMENT_SCENARIO="${scenario}" \
    bash "${verifier}" "$@" \
      >"${test_root}/${label}.stdout" \
      2>"${test_root}/${label}.stderr"; then
    echo "::error::environment verifier accepted ${label}" >&2
    exit 1
  fi
}

run_pass pass aws-foundation governed-canary-recovery
run_pass reversed-rules governed-canary-recovery
run_fail api-failure api-failure aws-foundation
run_fail admin-bypass admin-bypass aws-foundation
run_fail extra-rule extra-rule aws-foundation
run_fail missing-rule missing-rule aws-foundation
run_fail wrong-reviewer wrong-reviewer aws-foundation
run_fail wrong-reviewer-type wrong-reviewer-type aws-foundation
run_fail self-review self-review aws-foundation
run_fail wrong-branch wrong-branch aws-foundation
run_fail wrong-deployment-policy wrong-deployment-policy aws-foundation
run_fail duplicate-argument pass aws-foundation aws-foundation
run_fail unapproved-environment pass production
run_fail missing-argument pass

echo 'GitHub environment protection behavioral tests passed'