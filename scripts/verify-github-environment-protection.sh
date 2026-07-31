#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}

[[ "${GITHUB_ACTIONS:-}" == "true" ]] ||
  fail "GitHub environment protection verification is CI-only"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_REPOSITORY_OWNER:?GITHUB_REPOSITORY_OWNER is required}"
[[ "${GITHUB_REPOSITORY}" == "upgradedev/archon-datahub" ]] ||
  fail "Unexpected repository: ${GITHUB_REPOSITORY}"
[[ "$#" -ge 1 && "$#" -le 2 ]] ||
  fail "Expected one or two protected environment names"

declare -A seen=()
for name in "$@"; do
  case "${name}" in
    aws-foundation | governed-canary-recovery) ;;
    *) fail "Unexpected protected environment: ${name}" ;;
  esac
  [[ -z "${seen[${name}]+x}" ]] ||
    fail "Duplicate protected environment: ${name}"
  seen["${name}"]=1

  configuration="$(gh api \
    -H 'Accept: application/vnd.github+json' \
    "/repos/${GITHUB_REPOSITORY}/environments/${name}")"
  branch_policies="$(gh api \
    -H 'Accept: application/vnd.github+json' \
    "/repos/${GITHUB_REPOSITORY}/environments/${name}/deployment-branch-policies?per_page=100")"

  jq -e \
    --arg name "${name}" \
    --arg owner "${GITHUB_REPOSITORY_OWNER}" '
      .name == $name and
      .can_admins_bypass == false and
      .deployment_branch_policy == {
        custom_branch_policies: true,
        protected_branches: false
      } and
      (.protection_rules | length) == 2 and
      ([.protection_rules[] |
        select(.type == "branch_policy")] | length) == 1 and
      ([.protection_rules[] |
        select(.type == "required_reviewers")] | length) == 1 and
      ([.protection_rules[] |
        select(.type == "required_reviewers")][0] |
        .prevent_self_review == false and
        (.reviewers | length) == 1 and
        .reviewers[0].type == "User" and
        .reviewers[0].reviewer.login == $owner)
    ' <<<"${configuration}" >/dev/null ||
    fail "Protected environment configuration drifted: ${name}"

  jq -e '
    .total_count == 1 and
    ([.branch_policies[] | {name, type}]) == [
      {name: "master", type: "branch"}
    ]
  ' <<<"${branch_policies}" >/dev/null ||
    fail "Protected environment branch policy drifted: ${name}"
done