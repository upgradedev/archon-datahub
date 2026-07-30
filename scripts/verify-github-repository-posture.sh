#!/usr/bin/env bash
set -euo pipefail

# Secretless, read-only observation of repository controls exposed to the
# workflow's automatic GitHub token. Administration-only and elevated-read
# controls remain explicitly unverified; this script never upgrades that
# status into a claim or attempts to enumerate environment secret names.

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_API_URL:?GITHUB_API_URL is required}"
: "${GITHUB_EVENT_NAME:?GITHUB_EVENT_NAME is required}"
: "${GITHUB_REF:?GITHUB_REF is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
: "${OUTPUT_PATH:?OUTPUT_PATH is required}"
: "${POLICY_PATH:?POLICY_PATH is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

readonly EXPECTED_REPOSITORY="upgradedev/archon-datahub"
readonly EXPECTED_BRANCH="master"
readonly EXPECTED_REF="refs/heads/${EXPECTED_BRANCH}"
readonly EXPECTED_OUTPUT_PATH="${RUNNER_TEMP}/github-repository-posture/github-repository-posture.json"
readonly API_VERSION="2026-03-10"

test "${GITHUB_API_URL}" = "https://api.github.com"
test "${GITHUB_REPOSITORY}" = "${EXPECTED_REPOSITORY}"
test "${GITHUB_REF}" = "${EXPECTED_REF}"
case "${GITHUB_EVENT_NAME}" in
  schedule | workflow_dispatch) ;;
  *)
    echo "::error::Repository posture may run only on schedule or workflow_dispatch"
    exit 1
    ;;
esac
[[ "${GITHUB_SHA}" =~ ^[0-9a-f]{40}$ ]]
[[ "${GITHUB_RUN_ID}" =~ ^[1-9][0-9]*$ ]]
[[ "${GITHUB_RUN_ATTEMPT}" =~ ^[1-9][0-9]*$ ]]
test "${POLICY_PATH}" = \
  "${GITHUB_WORKSPACE}/contracts/github-repository-posture-v1.json"
test -f "${POLICY_PATH}"
test ! -L "${POLICY_PATH}"
test "${OUTPUT_PATH}" = "${EXPECTED_OUTPUT_PATH}"
test ! -e "${OUTPUT_PATH}"

umask 077
readonly work_dir="$(mktemp -d "${RUNNER_TEMP}/github-repository-posture.XXXXXX")"
trap 'rm -rf -- "${work_dir}"' EXIT
mkdir -p "$(dirname "${OUTPUT_PATH}")"
test -d "$(dirname "${OUTPUT_PATH}")"
test ! -L "$(dirname "${OUTPUT_PATH}")"

api_get() {
  local label="$1"
  local path="$2"
  local error_path="${work_dir}/api-error"
  local response

  : >"${error_path}"
  if ! response="$(
    gh api \
      --method GET \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: ${API_VERSION}" \
      "${path}" \
      2>"${error_path}"
  )"; then
    echo "::error::GitHub rejected the read-only ${label} observation"
    return 1
  fi
  test -n "${response}" || {
    echo "::error::GitHub returned an empty ${label} observation"
    return 1
  }
  printf '%s' "${response}"
}

jq -e '
  (keys | sort) == [
    "administrationOnly",
    "environments",
    "repository",
    "schemaVersion"
  ] and
  .schemaVersion == "archon.github-repository-posture-policy/v1" and
  (.administrationOnly | keys | sort) == [
    "actions",
    "environmentSecrets",
    "repositoryLifecycle",
    "status"
  ] and
  (.administrationOnly.status | keys | sort) == ["reason", "value"] and
  .administrationOnly.status.value ==
    "unverified-requires-administration-and-environments-read" and
  (.administrationOnly.status.reason | type) == "string" and
  (.administrationOnly.status.reason | length) >= 40 and
  (.administrationOnly.actions | keys | sort) == [
    "allowedActions",
    "githubOwnedAllowed",
    "patternsAllowed",
    "shaPinningRequired",
    "verifiedAllowed"
  ] and
  .administrationOnly.actions.allowedActions == "selected" and
  .administrationOnly.actions.githubOwnedAllowed == false and
  .administrationOnly.actions.verifiedAllowed == false and
  .administrationOnly.actions.shaPinningRequired == true and
  (.administrationOnly.actions.patternsAllowed | length) == 16 and
  .administrationOnly.actions.patternsAllowed ==
    (.administrationOnly.actions.patternsAllowed | sort | unique) and
  (.administrationOnly.environmentSecrets | keys | sort) == [
    "reason",
    "requiredFineGrainedPermissions",
    "status",
    "verification"
  ] and
  .administrationOnly.environmentSecrets.status ==
    "unverified-requires-environments-read" and
  .administrationOnly.environmentSecrets.verification == "not-performed" and
  (.administrationOnly.environmentSecrets.reason | type) == "string" and
  (.administrationOnly.environmentSecrets.reason | length) >= 80 and
  .administrationOnly.environmentSecrets.requiredFineGrainedPermissions == [
    "Actions:read",
    "Administration:read",
    "Environments:read",
    "Metadata:read"
  ] and
  (.administrationOnly.repositoryLifecycle | keys | sort) == [
    "expected",
    "requiredFineGrainedPermissions",
    "status",
    "verification"
  ] and
  .administrationOnly.repositoryLifecycle.expected == {
    allowAutoMerge: false,
    allowMergeCommit: false,
    allowRebaseMerge: false,
    allowSquashMerge: true,
    allowUpdateBranch: true,
    deleteBranchOnMerge: true
  } and
  .administrationOnly.repositoryLifecycle.requiredFineGrainedPermissions == [
    "Administration:read",
    "Metadata:read"
  ] and
  .administrationOnly.repositoryLifecycle.status ==
    "unverified-requires-administration-read" and
  .administrationOnly.repositoryLifecycle.verification == "not-performed" and
  (.repository | keys | sort) == [
    "archived",
    "branch",
    "defaultBranch",
    "disabled",
    "fullName",
    "hasWiki",
    "licenseSpdxId",
    "private",
    "privateVulnerabilityReporting",
    "visibility"
  ] and
  .repository == {
    archived: false,
    branch: {
      name: "master",
      protected: true
    },
    defaultBranch: "master",
    disabled: false,
    fullName: "upgradedev/archon-datahub",
    hasWiki: false,
    licenseSpdxId: "Apache-2.0",
    private: false,
    privateVulnerabilityReporting: true,
    visibility: "public"
  } and
  (.environments | keys | sort) == [
    "branchPolicy",
    "canAdminsBypass",
    "exactNames",
    "reviewerlessByDesign",
    "soloOwnerApproval"
  ] and
  .environments.canAdminsBypass == false and
  (.environments.branchPolicy | keys | sort) == [
    "branchName",
    "branchType",
    "customBranchPolicies",
    "protectedBranches"
  ] and
  .environments.branchPolicy == {
    branchName: "master",
    branchType: "branch",
    customBranchPolicies: true,
    protectedBranches: false
  } and
  (.environments.reviewerlessByDesign | keys | sort) == [
    "exactNames",
    "expectedProtectionRuleTypes",
    "state"
  ] and
  (.environments.soloOwnerApproval | keys | sort) == [
    "exactNames",
    "expectedProtectionRuleTypes",
    "ownerLogin",
    "preventSelfReview",
    "state"
  ] and
  .environments.reviewerlessByDesign.state ==
    "reviewerless-by-design" and
  .environments.soloOwnerApproval.state ==
    "solo-owner-approval" and
  .environments.reviewerlessByDesign.expectedProtectionRuleTypes ==
    ["branch_policy"] and
  .environments.soloOwnerApproval.expectedProtectionRuleTypes ==
    ["branch_policy", "required_reviewers"] and
  .environments.soloOwnerApproval.ownerLogin == "upgradedev" and
  .environments.soloOwnerApproval.preventSelfReview == false and
  (.environments.exactNames | length) == 17 and
  (.environments.soloOwnerApproval.exactNames | length) == 12 and
  (.environments.reviewerlessByDesign.exactNames | length) == 5 and
  .environments.exactNames == (.environments.exactNames | sort | unique) and
  .environments.reviewerlessByDesign.exactNames ==
    (.environments.reviewerlessByDesign.exactNames | sort | unique) and
  .environments.soloOwnerApproval.exactNames ==
    (.environments.soloOwnerApproval.exactNames | sort | unique) and
  (
    (
      .environments.soloOwnerApproval.exactNames +
      .environments.reviewerlessByDesign.exactNames
    ) | sort
  ) == .environments.exactNames and
  all(
    .environments.exactNames[];
    test("^[a-z0-9]+(?:-[a-z0-9]+)*$")
  )
' "${POLICY_PATH}" >/dev/null || {
  echo "::error::The repository-posture policy is not canonical or exact"
  exit 1
}

readonly policy_digest="$(
  sha256sum "${POLICY_PATH}" | awk '{print $1}'
)"
readonly administration_actions_digest="$(
  jq -cS '.administrationOnly.actions' "${POLICY_PATH}" |
    sha256sum |
    awk '{print $1}'
)"
readonly administration_pattern_count="$(
  jq -er '.administrationOnly.actions.patternsAllowed | length' \
    "${POLICY_PATH}"
)"
readonly repository_lifecycle_digest="$(
  jq -cS '.administrationOnly.repositoryLifecycle.expected' "${POLICY_PATH}" |
    sha256sum |
    awk '{print $1}'
)"
readonly administration_status="$(
  jq -er '.administrationOnly.status.value' "${POLICY_PATH}"
)"
readonly administration_reason="$(
  jq -er '.administrationOnly.status.reason' "${POLICY_PATH}"
)"
readonly environment_secret_reason="$(
  jq -er '.administrationOnly.environmentSecrets.reason' "${POLICY_PATH}"
)"
readonly environment_secret_status="$(
  jq -er '.administrationOnly.environmentSecrets.status' "${POLICY_PATH}"
)"
readonly environment_secret_permissions="$(
  jq -c \
    '.administrationOnly.environmentSecrets.requiredFineGrainedPermissions' \
    "${POLICY_PATH}"
)"
readonly repository_lifecycle_status="$(
  jq -er '.administrationOnly.repositoryLifecycle.status' "${POLICY_PATH}"
)"
readonly repository_lifecycle_permissions="$(
  jq -c \
    '.administrationOnly.repositoryLifecycle.requiredFineGrainedPermissions' \
    "${POLICY_PATH}"
)"

repository_json="$(
  api_get \
    "repository metadata" \
    "/repos/${GITHUB_REPOSITORY}"
)"
jq -e \
  --arg repository "${EXPECTED_REPOSITORY}" \
  --arg branch "${EXPECTED_BRANCH}" '
    .full_name == $repository and
    .visibility == "public" and
    .private == false and
    .has_wiki == false and
    .archived == false and
    .disabled == false and
    .default_branch == $branch
  ' <<<"${repository_json}" >/dev/null || {
  echo "::error::Public repository identity or lifecycle posture drifted"
  exit 1
}

default_ref_json="$(
  api_get \
    "default-branch ref" \
    "/repos/${GITHUB_REPOSITORY}/git/ref/heads/${EXPECTED_BRANCH}"
)"
jq -e \
  --arg ref "${EXPECTED_REF}" \
  --arg sha "${GITHUB_SHA}" '
    .ref == $ref and
    .object.type == "commit" and
    .object.sha == $sha
  ' <<<"${default_ref_json}" >/dev/null || {
  echo "::error::The observed workflow revision is not the current master head"
  exit 1
}

branch_json="$(
  api_get \
    "default branch" \
    "/repos/${GITHUB_REPOSITORY}/branches/${EXPECTED_BRANCH}"
)"
jq -e \
  --arg branch "${EXPECTED_BRANCH}" \
  --arg sha "${GITHUB_SHA}" '
    .name == $branch and
    .protected == true and
    .commit.sha == $sha
  ' <<<"${branch_json}" >/dev/null || {
  echo "::error::The public default-branch protection signal drifted"
  exit 1
}

license_json="$(
  api_get \
    "repository license" \
    "/repos/${GITHUB_REPOSITORY}/license"
)"
jq -e '
  .license.spdx_id == "Apache-2.0"
' <<<"${license_json}" >/dev/null || {
  echo "::error::GitHub no longer detects the Apache-2.0 license"
  exit 1
}

private_reporting_json="$(
  api_get \
    "private vulnerability reporting" \
    "/repos/${GITHUB_REPOSITORY}/private-vulnerability-reporting"
)"
jq -e '.enabled == true' <<<"${private_reporting_json}" >/dev/null || {
  echo "::error::Private vulnerability reporting is not enabled"
  exit 1
}

environments_json="$(
  api_get \
    "environment inventory" \
    "/repos/${GITHUB_REPOSITORY}/environments?per_page=100"
)"
expected_environment_names="$(
  jq -c '.environments.exactNames' "${POLICY_PATH}"
)"
observed_environment_names="$(
  jq -ce '
    select(
      (.total_count | type) == "number" and
      .total_count == (.environments | length)
    ) |
    [.environments[].name] | sort
  ' <<<"${environments_json}"
)" || {
  echo "::error::The environment inventory response is incomplete"
  exit 1
}
test "${observed_environment_names}" = "${expected_environment_names}" || {
  echo "::error::The exact GitHub environment inventory drifted"
  exit 1
}

observed_environments="[]"
while IFS= read -r environment_name; do
  expected_rule_types=""
  environment_mode=""
  owner_login=""

  if jq -e \
    --arg name "${environment_name}" '
      .environments.soloOwnerApproval.exactNames |
      index($name) != null
    ' "${POLICY_PATH}" >/dev/null; then
    environment_mode="solo-owner-approval"
    expected_rule_types="$(
      jq -c \
        '.environments.soloOwnerApproval.expectedProtectionRuleTypes' \
        "${POLICY_PATH}"
    )"
    owner_login="$(
      jq -er '.environments.soloOwnerApproval.ownerLogin' "${POLICY_PATH}"
    )"
  else
    environment_mode="reviewerless-by-design"
    expected_rule_types="$(
      jq -c \
        '.environments.reviewerlessByDesign.expectedProtectionRuleTypes' \
        "${POLICY_PATH}"
    )"
  fi

  environment_json="$(
    api_get \
      "${environment_name} environment" \
      "/repos/${GITHUB_REPOSITORY}/environments/${environment_name}"
  )"
  jq -e \
    --arg mode "${environment_mode}" \
    --arg name "${environment_name}" \
    --arg owner "${owner_login}" \
    --argjson expectedRuleTypes "${expected_rule_types}" '
      .name == $name and
      .can_admins_bypass == false and
      .deployment_branch_policy == {
        protected_branches: false,
        custom_branch_policies: true
      } and
      ([.protection_rules[].type] | sort) == $expectedRuleTypes and
      (
        $mode != "solo-owner-approval" or
        (
          [
            .protection_rules[] |
            select(.type == "required_reviewers")
          ] as $reviewRules |
          ($reviewRules | length) == 1 and
          $reviewRules[0].prevent_self_review == false and
          ($reviewRules[0].reviewers | length) == 1 and
          $reviewRules[0].reviewers[0].type == "User" and
          ($reviewRules[0].reviewers[0].reviewer.login | ascii_downcase) ==
            ($owner | ascii_downcase)
        )
      )
    ' <<<"${environment_json}" >/dev/null || {
    echo "::error::${environment_name} protection rules drifted"
    exit 1
  }

  branch_policies_json="$(
    api_get \
      "${environment_name} deployment-branch policies" \
      "/repos/${GITHUB_REPOSITORY}/environments/${environment_name}/deployment-branch-policies?per_page=100"
  )"
  jq -e \
    --arg branch "${EXPECTED_BRANCH}" '
      .total_count == 1 and
      (.branch_policies | length) == 1 and
      .branch_policies[0].name == $branch and
      .branch_policies[0].type == "branch"
    ' <<<"${branch_policies_json}" >/dev/null || {
    echo "::error::${environment_name} is not restricted to exactly master"
    exit 1
  }

  normalized_environment="$(
    jq -cnS \
      --arg mode "${environment_mode}" \
      --arg name "${environment_name}" \
      --argjson ruleTypes "${expected_rule_types}" \
      '
        {
          canAdminsBypass: false,
          deploymentBranchPolicy: {
            customBranchPolicies: true,
            exactPolicies: [
              {
                name: "master",
                type: "branch"
              }
            ],
            protectedBranches: false
          },
          mode: $mode,
          name: $name,
          protectionRuleTypes: $ruleTypes
        }
      '
  )"
  observed_environments="$(
    jq -cn \
      --argjson current "${observed_environments}" \
      --argjson item "${normalized_environment}" '
        $current + [$item]
      '
  )"
done < <(jq -r '.environments.exactNames[]' "${POLICY_PATH}")

test "$(
  jq -r 'length' <<<"${observed_environments}"
)" = "17"

readonly observed_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
temporary_output="${work_dir}/github-repository-posture.json"
jq -cnS \
  --arg administrationActionsDigest \
    "sha256:${administration_actions_digest}" \
  --arg administrationReason "${administration_reason}" \
  --arg administrationStatus "${administration_status}" \
  --arg environmentSecretReason "${environment_secret_reason}" \
  --arg environmentSecretStatus "${environment_secret_status}" \
  --arg eventName "${GITHUB_EVENT_NAME}" \
  --arg observedAt "${observed_at}" \
  --arg policyDigest "sha256:${policy_digest}" \
  --arg repositoryLifecycleDigest "sha256:${repository_lifecycle_digest}" \
  --arg repositoryLifecycleStatus "${repository_lifecycle_status}" \
  --arg ref "${GITHUB_REF}" \
  --arg repository "${GITHUB_REPOSITORY}" \
  --arg sha "${GITHUB_SHA}" \
  --argjson administrationPatternCount \
    "${administration_pattern_count}" \
  --argjson environments "${observed_environments}" \
  --argjson environmentSecretPermissions \
    "${environment_secret_permissions}" \
  --argjson repositoryLifecyclePermissions \
    "${repository_lifecycle_permissions}" \
  --argjson runAttempt "${GITHUB_RUN_ATTEMPT}" \
  --argjson runId "${GITHUB_RUN_ID}" '
    {
      administrationOnly: {
        expectedActionsPatternCount: $administrationPatternCount,
        expectedActionsPolicyDigest: $administrationActionsDigest,
        environmentSecrets: {
          reason: $environmentSecretReason,
          requiredFineGrainedPermissions: $environmentSecretPermissions,
          status: $environmentSecretStatus,
          verification: "not-performed"
        },
        reason: $administrationReason,
        repositoryLifecycle: {
          expectedPolicyDigest: $repositoryLifecycleDigest,
          requiredFineGrainedPermissions: $repositoryLifecyclePermissions,
          status: $repositoryLifecycleStatus,
          verification: "not-performed"
        },
        status: $administrationStatus,
        verification: "not-performed"
      },
      environments: ($environments | sort_by(.name)),
      observedAt: $observedAt,
      policyDigest: $policyDigest,
      repository: {
        archived: false,
        branch: {
          name: "master",
          protected: true
        },
        defaultBranch: "master",
        disabled: false,
        fullName: $repository,
        hasWiki: false,
        licenseSpdxId: "Apache-2.0",
        private: false,
        privateVulnerabilityReporting: true,
        visibility: "public"
      },
      result: "pass",
      schemaVersion: "archon.github-repository-posture-receipt/v1",
      source: {
        eventName: $eventName,
        ref: $ref,
        runAttempt: $runAttempt,
        runId: $runId,
        sha: $sha
      }
    }
  ' >"${temporary_output}"

test -s "${temporary_output}"
test ! -L "${temporary_output}"
test "$(stat -c '%s' "${temporary_output}")" -le 1048576
canonical_output="${work_dir}/canonical.json"
jq -cS . "${temporary_output}" >"${canonical_output}"
cmp --silent "${temporary_output}" "${canonical_output}" || {
  echo "::error::The normalized repository-posture receipt is not canonical"
  exit 1
}
mv -- "${temporary_output}" "${OUTPUT_PATH}"
chmod 0600 "${OUTPUT_PATH}"
test -f "${OUTPUT_PATH}"
test ! -L "${OUTPUT_PATH}"
echo "Verified the secretless GitHub repository posture for ${GITHUB_SHA}"
