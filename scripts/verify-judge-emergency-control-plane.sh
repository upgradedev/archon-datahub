#!/usr/bin/env bash
set -euo pipefail

# Emergency, CI/CD-only trust gate for the exact judge-user deactivation path.
# It deliberately does not assert green CI status. Instead, it binds the current
# default-branch commit, the directly executing workflow file, and this exact
# workflow-run attempt into a stable receipt that the V3 approval digest seals.
# judge-user.yml has no workflow_call entry point, so the mapped github.workflow_*
# identity below is the identity of this directly dispatched workflow.

fail() {
  printf '::error::%s\n' "$1" >&2
  exit 1
}

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_REF:?GITHUB_REF is required}"
: "${GITHUB_REF_NAME:?GITHUB_REF_NAME is required}"
: "${GITHUB_REF_TYPE:?GITHUB_REF_TYPE is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_EVENT_NAME:?GITHUB_EVENT_NAME is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
: "${GITHUB_ACTOR:?GITHUB_ACTOR is required}"
: "${GITHUB_TRIGGERING_ACTOR:?GITHUB_TRIGGERING_ACTOR is required}"
: "${GITHUB_WORKFLOW:?GITHUB_WORKFLOW is required}"
: "${GITHUB_WORKFLOW_REF:?GITHUB_WORKFLOW_REF is required}"
: "${GITHUB_WORKFLOW_SHA:?GITHUB_WORKFLOW_SHA is required}"
: "${GITHUB_SERVER_URL:?GITHUB_SERVER_URL is required}"
: "${GITHUB_API_URL:?GITHUB_API_URL is required}"
: "${EXECUTING_WORKFLOW_REPOSITORY:?EXECUTING_WORKFLOW_REPOSITORY is required}"
: "${EXECUTING_WORKFLOW_FILE_PATH:?EXECUTING_WORKFLOW_FILE_PATH is required}"
: "${EXECUTING_WORKFLOW_REF:?EXECUTING_WORKFLOW_REF is required}"
: "${EXECUTING_WORKFLOW_SHA:?EXECUTING_WORKFLOW_SHA is required}"
: "${JUDGE_USER_OPERATION:?JUDGE_USER_OPERATION is required}"
: "${CONTROL_PLANE_SHA:?CONTROL_PLANE_SHA is required}"
: "${OUTPUT_PATH:?OUTPUT_PATH is required}"

expected_branch="master"
expected_repository="upgradedev/archon-datahub"
expected_workflow_name="Manage Cognito judge user"
expected_workflow_path=".github/workflows/judge-user.yml"
expected_workflow_ref="${expected_repository}/${expected_workflow_path}@refs/heads/${expected_branch}"
expected_gate_sha256="${EXPECTED_GATE_SHA256:-}"

test "${JUDGE_USER_OPERATION}" = "deactivate" ||
  fail "The emergency control-plane gate is restricted to deactivate"
test "${GITHUB_REPOSITORY}" = "${expected_repository}" ||
  fail "The emergency repository identity is invalid"
test "${GITHUB_EVENT_NAME}" = "workflow_dispatch" ||
  fail "Emergency deactivation must be an explicit workflow dispatch"
test "${GITHUB_REF}" = "refs/heads/${expected_branch}" &&
  test "${GITHUB_REF_NAME}" = "${expected_branch}" &&
  test "${GITHUB_REF_TYPE}" = "branch" ||
  fail "Emergency deactivation must execute from the current master branch"
[[ "${CONTROL_PLANE_SHA}" =~ ^[0-9a-f]{40}$ ]] &&
  test "${GITHUB_SHA}" = "${CONTROL_PLANE_SHA}" ||
  fail "The emergency source SHA is invalid"
[[ "${GITHUB_RUN_ID}" =~ ^[1-9][0-9]{0,19}$ ]] ||
  fail "GITHUB_RUN_ID is invalid"
[[ "${GITHUB_RUN_ATTEMPT}" =~ ^[1-9][0-9]{0,9}$ ]] ||
  fail "GITHUB_RUN_ATTEMPT is invalid"
[[ "${GITHUB_ACTOR}" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}$ ]] ||
  fail "GITHUB_ACTOR is invalid"
[[ "${GITHUB_TRIGGERING_ACTOR}" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}$ ]] ||
  fail "GITHUB_TRIGGERING_ACTOR is invalid"
test "${GITHUB_WORKFLOW}" = "${expected_workflow_name}" &&
  test "${GITHUB_WORKFLOW_REF}" = "${expected_workflow_ref}" &&
  test "${GITHUB_WORKFLOW_SHA}" = "${CONTROL_PLANE_SHA}" ||
  fail "The GitHub workflow identity is not the exact current-master judge workflow"
test "${EXECUTING_WORKFLOW_REPOSITORY}" = "${expected_repository}" &&
  test "${EXECUTING_WORKFLOW_FILE_PATH}" = "${expected_workflow_path}" &&
  test "${EXECUTING_WORKFLOW_REF}" = "${expected_workflow_ref}" &&
  test "${EXECUTING_WORKFLOW_SHA}" = "${CONTROL_PLANE_SHA}" ||
  fail "The executing workflow is not the exact directly dispatched judge workflow"
test "${GITHUB_SERVER_URL}" = "https://github.com" &&
  test "${GITHUB_API_URL}" = "https://api.github.com" ||
  fail "The GitHub service endpoints are invalid"
[[ "${OUTPUT_PATH}" == /* ]] ||
  fail "OUTPUT_PATH must be absolute"
test "$(basename "${OUTPUT_PATH}")" = "judge-emergency-control-plane.json" ||
  fail "OUTPUT_PATH has an invalid basename"
if [[ -n "${expected_gate_sha256}" ]]; then
  [[ "${expected_gate_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "EXPECTED_GATE_SHA256 is invalid"
fi

export GH_HOST=github.com
umask 077
work_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/archon-judge-emergency.XXXXXX")"
trap 'rm -rf -- "${work_dir}"' EXIT
mkdir -p "$(dirname "${OUTPUT_PATH}")"
test ! -L "${OUTPUT_PATH}" ||
  fail "OUTPUT_PATH must not be a symbolic link"
if [[ -e "${OUTPUT_PATH}" ]]; then
  test -f "${OUTPUT_PATH}" ||
    fail "OUTPUT_PATH must be a regular file"
fi

gh_get() {
  gh api \
    --hostname github.com \
    --method GET \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2026-03-10" \
    "$1"
}

repository_json="$(
  gh_get "/repos/${expected_repository}"
)" || fail "Unable to verify the emergency repository"
jq -e \
  --arg repository "${expected_repository}" \
  --arg branch "${expected_branch}" '
    .full_name == $repository and
    .default_branch == $branch and
    .archived == false and
    .disabled == false and
    .fork == false
  ' <<<"${repository_json}" >/dev/null ||
  fail "The emergency repository/default-branch trust root is invalid"

read_master_sha() {
  local ref_json

  ref_json="$(
    gh_get \
      "/repos/${expected_repository}/git/ref/heads/${expected_branch}"
  )" || return 1
  jq -er \
    --arg ref "refs/heads/${expected_branch}" '
      select(
        .ref == $ref and
        .object.type == "commit" and
        (.object.sha | test("^[0-9a-f]{40}$"))
      ) |
      .object.sha
    ' <<<"${ref_json}"
}

read_run_projection() {
  local run_json

  run_json="$(
    gh_get \
      "/repos/${expected_repository}/actions/runs/${GITHUB_RUN_ID}/attempts/${GITHUB_RUN_ATTEMPT}"
  )" || return 1
  jq -ce \
    --arg repository "${expected_repository}" \
    --arg branch "${expected_branch}" \
    --arg sha "${CONTROL_PLANE_SHA}" \
    --arg workflow_name "${expected_workflow_name}" \
    --arg workflow_path "${expected_workflow_path}" \
    --arg actor "${GITHUB_ACTOR}" \
    --arg triggering_actor "${GITHUB_TRIGGERING_ACTOR}" \
    --argjson run_id "${GITHUB_RUN_ID}" \
    --argjson run_attempt "${GITHUB_RUN_ATTEMPT}" '
      select(
        .id == $run_id and
        .run_attempt == $run_attempt and
        (.workflow_id | type) == "number" and
        .workflow_id >= 1 and
        .name == $workflow_name and
        (
          .path == $workflow_path or
          .path == ($workflow_path + "@" + $branch) or
          .path == ($workflow_path + "@refs/heads/" + $branch)
        ) and
        .event == "workflow_dispatch" and
        .head_sha == $sha and
        .head_branch == $branch and
        .head_repository.full_name == $repository and
        .repository.full_name == $repository and
        .actor.type == "User" and
        (.actor.login | ascii_downcase) == ($actor | ascii_downcase) and
        .triggering_actor.type == "User" and
        (.triggering_actor.login | ascii_downcase) ==
          ($triggering_actor | ascii_downcase) and
        .html_url ==
          ("https://github.com/" + $repository + "/actions/runs/" +
            ($run_id | tostring))
      ) |
      {
        actor: .actor.login,
        attempt: .run_attempt,
        event: .event,
        headBranch: .head_branch,
        headSha: .head_sha,
        id: .id,
        triggeringActor: .triggering_actor.login,
        url: .html_url,
        workflowId: .workflow_id
      }
    ' <<<"${run_json}"
}

initial_master_sha="$(read_master_sha)" ||
  fail "Unable to read the current master ref"
test "${initial_master_sha}" = "${CONTROL_PLANE_SHA}" ||
  fail "The emergency workflow commit is no longer the master head"
first_run_projection="$(read_run_projection)" ||
  fail "The emergency workflow-run attempt identity is invalid"
workflow_id="$(
  jq -er '.workflowId' <<<"${first_run_projection}"
)" || fail "The emergency workflow ID is missing"

workflow_json="$(
  gh_get \
    "/repos/${expected_repository}/actions/workflows/${workflow_id}"
)" || fail "Unable to read the exact emergency workflow metadata"
jq -e \
  --arg name "${expected_workflow_name}" \
  --arg path "${expected_workflow_path}" \
  --argjson workflow_id "${workflow_id}" '
    .id == $workflow_id and
    .name == $name and
    .path == $path and
    .state == "active"
  ' <<<"${workflow_json}" >/dev/null ||
  fail "The emergency workflow metadata is invalid"

contents_json="$(
  gh_get \
    "/repos/${expected_repository}/contents/${expected_workflow_path}?ref=${CONTROL_PLANE_SHA}"
)" || fail "Unable to read the exact emergency workflow file"
workflow_blob_sha="$(
  jq -er \
    --arg path "${expected_workflow_path}" '
      select(
        .type == "file" and
        .path == $path and
        .name == "judge-user.yml" and
        (.sha | test("^[0-9a-f]{40}$")) and
        (.size | type) == "number" and
        .size >= 1 and
        .size <= 1048576 and
        .encoding == "base64" and
        (.content | type) == "string"
      ) |
      .sha
    ' <<<"${contents_json}"
)" || fail "The emergency workflow-file response is invalid"
workflow_api_size="$(
  jq -er '.size' <<<"${contents_json}"
)" || fail "The emergency workflow-file size is missing"
workflow_file="${work_dir}/judge-user.yml"
if ! jq -er '.content' <<<"${contents_json}" |
  tr -d '\r\n' |
  base64 --decode >"${workflow_file}"; then
  fail "The emergency workflow file is not valid base64"
fi
test -s "${workflow_file}" ||
  fail "The emergency workflow file is empty"
test "$(wc -c <"${workflow_file}" | tr -d '[:space:]')" = \
  "${workflow_api_size}" ||
  fail "The emergency workflow-file size changed"
computed_workflow_blob_sha="$(
  {
    printf 'blob %s\0' "${workflow_api_size}"
    cat "${workflow_file}"
  } |
    sha1sum |
    awk '{print $1}'
)"
test "${computed_workflow_blob_sha}" = "${workflow_blob_sha}" ||
  fail "The emergency workflow content does not match its Git blob SHA"
workflow_file_sha256="$(
  sha256sum "${workflow_file}" |
    awk '{print $1}'
)"
[[ "${workflow_file_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
  fail "Unable to digest the emergency workflow file"

second_run_projection="$(read_run_projection)" ||
  fail "Unable to re-read the emergency workflow-run attempt"
test "${second_run_projection}" = "${first_run_projection}" ||
  fail "The emergency workflow-run identity changed during verification"
test "$(read_master_sha)" = "${CONTROL_PLANE_SHA}" ||
  fail "The master branch changed during emergency verification"

temporary_output="${work_dir}/judge-emergency-control-plane.json"
jq -cnS \
  --arg repository "${expected_repository}" \
  --arg branch "${expected_branch}" \
  --arg source_sha "${CONTROL_PLANE_SHA}" \
  --arg workflow_name "${expected_workflow_name}" \
  --arg workflow_path "${expected_workflow_path}" \
  --arg workflow_ref "${expected_workflow_ref}" \
  --arg workflow_sha "${GITHUB_WORKFLOW_SHA}" \
  --arg workflow_blob_sha "${workflow_blob_sha}" \
  --arg workflow_file_sha256 "${workflow_file_sha256}" \
  --argjson workflow_id "${workflow_id}" \
  --argjson run "${first_run_projection}" '
    {
      branch: $branch,
      ciStatus: "not-asserted",
      mode: "emergency-deactivate-current-master",
      operation: "deactivate",
      repository: $repository,
      run: $run,
      schemaVersion: "archon.judge-emergency-control-plane/v1",
      sourceSha: $source_sha,
      workflow: {
        blobSha: $workflow_blob_sha,
        fileSha256: $workflow_file_sha256,
        id: $workflow_id,
        name: $workflow_name,
        path: $workflow_path,
        ref: $workflow_ref,
        sha: $workflow_sha,
        state: "active"
      }
    }
  ' >"${temporary_output}"
test -s "${temporary_output}" ||
  fail "The emergency control-plane receipt is empty"
gate_sha256="$(
  sha256sum "${temporary_output}" |
    awk '{print $1}'
)"
[[ "${gate_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
  fail "Unable to digest the emergency control-plane receipt"
if [[ -n "${expected_gate_sha256}" ]]; then
  test "${gate_sha256}" = "${expected_gate_sha256}" ||
    fail "The emergency control-plane receipt changed"
fi
mv -- "${temporary_output}" "${OUTPUT_PATH}"

printf 'Verified the exact current-master emergency deactivation control plane.\n'
