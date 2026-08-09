#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}

[[ "${GITHUB_ACTIONS:-}" == "true" ]] || fail "GitHub approval capture is CI-only"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_REPOSITORY_OWNER:?GITHUB_REPOSITORY_OWNER is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
[[ "${GITHUB_REPOSITORY}" == "upgradedev/archon-datahub" ]] ||
  fail "Unexpected repository: ${GITHUB_REPOSITORY}"
[[ "${GITHUB_RUN_ID}" =~ ^[0-9]+$ ]] || fail "Invalid workflow run id"
[[ "${GITHUB_RUN_ATTEMPT}" =~ ^[0-9]+$ ]] || fail "Invalid workflow run attempt"
[[ "$#" -eq 4 ]] ||
  fail "Expected environment, operation, plan digest, and output path"

environment="$1"
operation="$2"
plan_digest="$3"
output="$4"
case "${environment}:${operation}" in
  governed-canary:write | governed-canary-recovery:rollback) ;;
  *) fail "Unexpected environment/operation pair: ${environment}:${operation}" ;;
esac
[[ "${plan_digest}" =~ ^sha256:[a-f0-9]{64}$ ]] || fail "Invalid plan digest"
case "${output}" in
  "${RUNNER_TEMP}"/*) ;;
  *) fail "Approval receipt must be written below RUNNER_TEMP" ;;
esac
[[ -d "$(dirname "${output}")" ]] || fail "Approval receipt directory does not exist"
[[ ! -e "${output}" ]] || fail "Approval receipt already exists"

expected_comment="APPROVE ARCHON GOVERNED PROOF run_id=${GITHUB_RUN_ID} run_attempt=${GITHUB_RUN_ATTEMPT} operation=${operation} plan_digest=${plan_digest}"
environment_json="$(gh api \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  "/repos/${GITHUB_REPOSITORY}/environments/${environment}")"
environment_id="$(jq -er \
  --arg name "${environment}" '
    select(.name == $name and (.id | type) == "number" and .id > 0) | .id
  ' <<<"${environment_json}")" || fail "Protected environment identity is invalid"
configured_reviewer="$(jq -ce \
  --arg owner "${GITHUB_REPOSITORY_OWNER}" '
    [.protection_rules[]? | select(.type == "required_reviewers")] as $rules |
    if (
      ($rules | length) == 1 and
      $rules[0].prevent_self_review == false and
      ($rules[0].reviewers | length) == 1 and
      $rules[0].reviewers[0].type == "User" and
      ($rules[0].reviewers[0].reviewer.id | type) == "number" and
      $rules[0].reviewers[0].reviewer.id > 0 and
      ($rules[0].reviewers[0].reviewer.login | ascii_downcase) ==
        ($owner | ascii_downcase)
    ) then {
      id: $rules[0].reviewers[0].reviewer.id,
      login: $rules[0].reviewers[0].reviewer.login
    } else error("invalid individual-reviewer posture") end
  ' <<<"${environment_json}")" || fail "Configured environment reviewer is not exact"

approvals="$(gh api \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  "/repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/approvals")"
matched_approval="$(jq -ce \
  --arg environment "${environment}" \
  --arg expected "${expected_comment}" \
  --argjson environmentId "${environment_id}" \
  --argjson reviewer "${configured_reviewer}" '
    if type != "array" then error("approval response is not an array") else
      [.[] | select(
        .state == "approved" and
        .comment == $expected and
        (.environments | type) == "array" and
        (.environments | length) == 1 and
        .environments[0].name == $environment and
        .environments[0].id == $environmentId and
        (.user | type) == "object" and
        .user.id == $reviewer.id and
        (.user.login | ascii_downcase) == ($reviewer.login | ascii_downcase)
      )] |
      if length == 1 then .[0] else error("expected exactly one matching approval") end
    end
  ' <<<"${approvals}")" || fail "Missing exact content-bound environment approval"

reviewer_id="$(jq -er '.user.id' <<<"${matched_approval}")"
reviewer_login="$(jq -er '.user.login' <<<"${matched_approval}")"
temporary="${output}.tmp"
[[ ! -e "${temporary}" ]] || fail "Temporary approval receipt already exists"
trap 'rm -f -- "${temporary}"' EXIT
umask 077
jq -cnS \
  --arg schemaVersion "archon.github-environment-approval/v1" \
  --arg repository "${GITHUB_REPOSITORY}" \
  --arg workflowRunId "${GITHUB_RUN_ID}" \
  --arg workflowRunAttempt "${GITHUB_RUN_ATTEMPT}" \
  --arg operation "${operation}" \
  --arg planDigest "${plan_digest}" \
  --arg state "approved" \
  --arg comment "${expected_comment}" \
  --arg environmentName "${environment}" \
  --argjson environmentId "${environment_id}" \
  --arg reviewerLogin "${reviewer_login}" \
  --argjson reviewerId "${reviewer_id}" '
    {
      schemaVersion: $schemaVersion,
      repository: $repository,
      workflowRunId: $workflowRunId,
      workflowRunAttempt: $workflowRunAttempt,
      operation: $operation,
      planDigest: $planDigest,
      state: $state,
      comment: $comment,
      environment: {name: $environmentName, id: $environmentId},
      reviewer: {login: $reviewerLogin, id: $reviewerId}
    }
  ' >"${temporary}"
chmod 0600 "${temporary}"
mv -n -- "${temporary}" "${output}"
trap - EXIT
