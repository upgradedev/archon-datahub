#!/usr/bin/env bash
set -euo pipefail

# Fail-closed GitHub control-plane verification for the protected judge-user
# workflow. Dispatch and approval use only a high-entropy opaque account binding;
# the protected judge email never enters workflow inputs or this verifier.

mode="${1:-}"

fail() {
  printf '::error::%s\n' "$1" >&2
  exit 1
}

validate_run_identity() {
  [[ "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]{0,19}$ ]] ||
    fail "GITHUB_RUN_ID is invalid"
  [[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]{0,9}$ ]] ||
    fail "GITHUB_RUN_ATTEMPT is invalid"
}

validate_target() {
  local application_host
  local application_label
  local application_tld
  local aws_partition
  local expected_role_arn
  local -a application_labels

  case "${ARCHON_STAGE:-}" in
    staging|production) ;;
    *) fail "ARCHON_STAGE is invalid" ;;
  esac
  [[ "${JUDGE_TARGET_ACCOUNT_ID:-}" =~ ^[0-9]{12}$ ]] ||
    fail "JUDGE_TARGET_ACCOUNT_ID is invalid"
  [[ "${JUDGE_TARGET_REGION:-}" =~ ^[a-z]{2}(-gov)?-[a-z]+-[1-9][0-9]*$ ]] ||
    fail "JUDGE_TARGET_REGION is invalid"
  case "${JUDGE_TARGET_REGION}" in
    cn-*) aws_partition="aws-cn" ;;
    us-gov-*) aws_partition="aws-us-gov" ;;
    *) aws_partition="aws" ;;
  esac
  expected_role_arn="arn:${aws_partition}:iam::${JUDGE_TARGET_ACCOUNT_ID}:role/archon-${ARCHON_STAGE}-judge-user"
  test "${JUDGE_TARGET_ROLE_ARN:-}" = "${expected_role_arn}" ||
    fail "JUDGE_TARGET_ROLE_ARN is not the exact stage-specific judge role"

  [[ "${JUDGE_TARGET_APPLICATION_URL:-}" == https://* ]] ||
    fail "JUDGE_TARGET_APPLICATION_URL must be an exact HTTPS origin"
  application_host="${JUDGE_TARGET_APPLICATION_URL#https://}"
  (( ${#application_host} >= 4 && ${#application_host} <= 253 )) ||
    fail "JUDGE_TARGET_APPLICATION_URL has an invalid host length"
  [[ "${application_host}" =~ ^[a-z0-9.-]+$ &&
    "${application_host}" == *.* &&
    "${application_host}" != .* &&
    "${application_host}" != *. &&
    "${application_host}" != *..* ]] ||
    fail "JUDGE_TARGET_APPLICATION_URL must contain only a lower-case DNS host"
  IFS='.' read -r -a application_labels <<<"${application_host}"
  for application_label in "${application_labels[@]}"; do
    (( ${#application_label} >= 1 && ${#application_label} <= 63 )) &&
      [[ "${application_label}" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] ||
      fail "JUDGE_TARGET_APPLICATION_URL contains an invalid DNS label"
  done
  application_tld="${application_labels[${#application_labels[@]} - 1]}"
  [[ "${application_tld}" =~ ^[a-z]([a-z0-9-]*[a-z0-9])?$ ]] ||
    fail "JUDGE_TARGET_APPLICATION_URL contains an invalid DNS suffix"
}

target_sha256() {
  local target_digest

  validate_target
  target_digest="$(
    printf \
      'archon-judge-target-v1\naccount_id=%s\nregion=%s\nrole_arn=%s\napplication_url=%s\n' \
      "${JUDGE_TARGET_ACCOUNT_ID}" \
      "${JUDGE_TARGET_REGION}" \
      "${JUDGE_TARGET_ROLE_ARN}" \
      "${JUDGE_TARGET_APPLICATION_URL}" |
      sha256sum |
      awk '{print $1}'
  )"
  [[ "${target_digest}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "Unable to seal the judge target"
  printf '%s' "${target_digest}"
}

request_sha256() {
  local request_digest

  case "${ARCHON_STAGE:-}" in
    staging|production) ;;
    *) fail "ARCHON_STAGE is invalid" ;;
  esac
  case "${JUDGE_USER_OPERATION:-}" in
    provision|rotate|reactivate|deactivate) ;;
    *) fail "JUDGE_USER_OPERATION is invalid" ;;
  esac
  [[ "${JUDGE_ACCOUNT_ID:-}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "JUDGE_ACCOUNT_ID is invalid"
  [[ "${EXPECTED_GATE_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "EXPECTED_GATE_SHA256 is invalid"
  [[ "${CONTROL_PLANE_SHA:-}" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] ||
    fail "CONTROL_PLANE_SHA is invalid"
  validate_target

  request_digest="$(
    printf \
      'archon-judge-access-request-v3\nstage=%s\noperation=%s\naccount_id=%s\ntarget_account_id=%s\ntarget_region=%s\ntarget_role_arn=%s\ntarget_application_url=%s\ngate_sha256=%s\nrelease_sha=%s\n' \
      "${ARCHON_STAGE}" \
      "${JUDGE_USER_OPERATION}" \
      "${JUDGE_ACCOUNT_ID}" \
      "${JUDGE_TARGET_ACCOUNT_ID}" \
      "${JUDGE_TARGET_REGION}" \
      "${JUDGE_TARGET_ROLE_ARN}" \
      "${JUDGE_TARGET_APPLICATION_URL}" \
      "${EXPECTED_GATE_SHA256}" \
      "${CONTROL_PLANE_SHA}" |
      sha256sum |
      awk '{print $1}'
  )"
  [[ "${request_digest}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "Unable to seal the judge-access request"
  printf '%s' "${request_digest}"
}

approval_comment() {
  validate_run_identity
  [[ "${JUDGE_REQUEST_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "JUDGE_REQUEST_SHA256 is invalid"
  printf \
    'ARCHON_JUDGE_ACCESS_APPROVAL_V3|run_id=%s|run_attempt=%s|request_sha256=%s' \
    "${GITHUB_RUN_ID}" \
    "${GITHUB_RUN_ATTEMPT}" \
    "${JUDGE_REQUEST_SHA256}"
}

case "${mode}" in
  target-digest)
    target_sha256
    exit 0
    ;;
  request-digest)
    request_sha256
    exit 0
    ;;
  approval-comment)
    approval_comment
    exit 0
    ;;
  verify)
    ;;
  *)
    fail "Usage: verify-judge-environment-approval.sh target-digest|request-digest|approval-comment|verify"
    ;;
esac

test "${GITHUB_REPOSITORY:-}" = "upgradedev/archon-datahub" ||
  fail "The repository identity is invalid"
[[ "${JUDGE_REVIEWER_USER_ID:-}" =~ ^[1-9][0-9]{0,19}$ ]] ||
  fail "JUDGE_REVIEWER_USER_ID must be an exact GitHub User ID"
[[ "${GITHUB_ACTOR:-}" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}$ ]] ||
  fail "GITHUB_ACTOR is invalid"
[[ "${GITHUB_TRIGGERING_ACTOR:-}" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}$ ]] ||
  fail "GITHUB_TRIGGERING_ACTOR is invalid"
test "${GITHUB_ACTOR,,}" = "upgradedev" ||
  fail "The workflow actor must be the solo repository owner"
test "${GITHUB_TRIGGERING_ACTOR,,}" = "upgradedev" ||
  fail "The triggering actor must be the solo repository owner"
: "${GH_TOKEN:?GH_TOKEN is required}"

computed_request_sha256="$(request_sha256)"
test "${EXPECTED_REQUEST_SHA256:-}" = "${computed_request_sha256}" ||
  fail "The protected job received a changed judge-access request seal"
JUDGE_REQUEST_SHA256="${computed_request_sha256}"
expected_comment="$(approval_comment)"
environment_name="judge-access-${ARCHON_STAGE}"

repository_json="$(
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2026-03-10" \
    "/repos/${GITHUB_REPOSITORY}"
)" || fail "Unable to verify the repository configuration"
default_branch="$(
  jq -er '.default_branch | select(type == "string")' \
    <<<"${repository_json}"
)" || fail "Unable to read the default branch"
test "${default_branch}" = "master" ||
  fail "The default branch is not master"

environment_json="$(
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2026-03-10" \
    "/repos/${GITHUB_REPOSITORY}/environments/${environment_name}"
)" || fail "Unable to verify the exact judge environment"
jq -e \
  --arg name "${environment_name}" \
  --argjson reviewer_id "${JUDGE_REVIEWER_USER_ID}" '
    (.protection_rules // []) as $rules |
    ([$rules[] | select(.type == "required_reviewers")]) as $review_rules |
    .name == $name and
    .deployment_branch_policy.protected_branches == false and
    .deployment_branch_policy.custom_branch_policies == true and
    ($review_rules | length) == 1 and
    $review_rules[0].prevent_self_review == false and
    (($review_rules[0].reviewers // []) | length) == 1 and
    all(
      ($review_rules[0].reviewers // [])[];
      .type == "User" and
      (.reviewer.id | type == "number") and
      (.reviewer.login | type == "string") and
      (.reviewer.login | ascii_downcase) == "upgradedev"
    ) and
    (
      [
        ($review_rules[0].reviewers // [])[] |
        select(.reviewer.id == $reviewer_id)
      ] |
      length
    ) == 1
  ' <<<"${environment_json}" >/dev/null ||
  fail "The exact judge environment lacks the required individual-reviewer posture"

configured_reviewer_login="$(
  jq -er \
    --argjson reviewer_id "${JUDGE_REVIEWER_USER_ID}" '
      [
        (.protection_rules // [])[] |
        select(.type == "required_reviewers") |
        (.reviewers // [])[] |
        select(.type == "User" and .reviewer.id == $reviewer_id) |
        .reviewer.login
      ] |
      select(length == 1) |
      .[0]
    ' <<<"${environment_json}"
)" || fail "The configured reviewer is missing or ambiguous"

branch_policies="$(
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2026-03-10" \
    "/repos/${GITHUB_REPOSITORY}/environments/${environment_name}/deployment-branch-policies?per_page=100"
)" || fail "Unable to verify judge-environment branch policies"
jq -e --arg branch "${default_branch}" '
  .total_count == 1 and
  (.branch_policies | length) == 1 and
  .branch_policies[0].name == $branch and
  (
    (.branch_policies[0] | has("type") | not) or
    .branch_policies[0].type == "branch"
  )
' <<<"${branch_policies}" >/dev/null ||
  fail "The judge environment is not restricted to the exact master branch"

approvals_json="$(
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2026-03-10" \
    "/repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/approvals"
)" || fail "Unable to read the workflow-run approval history"
jq -e \
  --arg environment "${environment_name}" \
  --arg comment "${expected_comment}" \
  --arg reviewer_login "${configured_reviewer_login}" \
  --arg actor "${GITHUB_ACTOR}" \
  --arg triggering_actor "${GITHUB_TRIGGERING_ACTOR}" \
  --argjson reviewer_id "${JUDGE_REVIEWER_USER_ID}" '
    type == "array" and
    (
      [
        .[] |
        select(
          .state == "approved" and
          .comment == $comment and
          .user.type == "User" and
          .user.id == $reviewer_id and
          (.user.login | ascii_downcase) ==
            ($reviewer_login | ascii_downcase) and
          (.user.login | ascii_downcase) == ($actor | ascii_downcase) and
          (.user.login | ascii_downcase) ==
            ($triggering_actor | ascii_downcase) and
          ((.environments // []) | length) == 1 and
          .environments[0].name == $environment
        )
      ] |
      length
    ) == 1
  ' <<<"${approvals_json}" >/dev/null ||
  fail "No exact solo-owner judge-access approval receipt exists for this attempt"

printf 'Verified the exact solo-owner judge-access approval receipt.\n'
