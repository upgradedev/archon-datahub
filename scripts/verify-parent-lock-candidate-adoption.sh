#!/usr/bin/env bash
set -euo pipefail

# A dependency-refresh run intentionally fails after it has generated, tested,
# and retained clean npm lock candidates. The immediately following commit may
# adopt those exact bytes without racing a second mutable-registry resolution.
# This verifier accepts only the newest completed CI run for the exact parent
# SHA, and only after revalidating its job steps, public artifact metadata,
# base/head identity, and the canonical digest of all manifests and locks.

required_environment=(
  GITHUB_ACTIONS
  GITHUB_OUTPUT
  GITHUB_REPOSITORY
  PR_BASE_SHA
  PR_HEAD_SHA
  PR_HEAD_REPOSITORY
  PR_NUMBER
)
for name in "${required_environment[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "::error::Missing required parent lock-candidate environment: ${name}"
    exit 1
  fi
done

test "${GITHUB_ACTIONS}" = "true"
test "${GITHUB_REPOSITORY}" = "upgradedev/archon-datahub"
[[ "${PR_BASE_SHA}" =~ ^[0-9a-f]{40}$ ]]
[[ "${PR_HEAD_SHA}" =~ ^[0-9a-f]{40}$ ]]
[[ "${PR_HEAD_REPOSITORY}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]
[[ "${PR_NUMBER}" =~ ^[1-9][0-9]*$ ]]
test "$(git rev-parse HEAD)" = "${PR_HEAD_SHA}"

not_adopted() {
  echo "::notice::$1"
  printf 'adopted=false\n' >>"${GITHUB_OUTPUT}"
  exit 0
}

api() {
  local path="$1"
  curl \
    --fail \
    --location \
    --proto '=https' \
    --proto-redir '=https' \
    --show-error \
    --silent \
    --tlsv1.2 \
    -H "Accept: application/vnd.github+json" \
    -H "User-Agent: archon-public-lock-candidate-verifier" \
    -H "X-GitHub-Api-Version: 2026-03-10" \
    "https://api.github.com${path}"
}

commit_line="$(git rev-list --parents -n 1 "${PR_HEAD_SHA}")"
read -r -a commit_parts <<<"${commit_line}"
if [[ "${#commit_parts[@]}" -ne 2 ]]; then
  not_adopted "The PR head is not a single-parent candidate-adoption commit"
fi
parent_sha="${commit_parts[1]}"
[[ "${parent_sha}" =~ ^[0-9a-f]{40}$ ]]

changes="$(git diff --name-status --no-renames "${parent_sha}" "${PR_HEAD_SHA}")"
if [[ -z "${changes}" ]]; then
  not_adopted "The candidate-adoption commit has no changed paths"
fi
while IFS=$'\t' read -r status path extra; do
  if [[ "${status}" != "M" || -n "${extra:-}" ]]; then
    not_adopted "Candidate adoption accepts only modifications to existing lock files"
  fi
  case "${path}" in
    package-lock.json|infra/aws/package-lock.json|web/package-lock.json) ;;
    *)
      not_adopted "Candidate adoption commit contains a non-lock path: ${path}"
      ;;
  esac
done <<<"${changes}"

manifest_paths=(
  package.json
  infra/aws/package.json
  web/package.json
)
if ! git diff --quiet "${parent_sha}" "${PR_HEAD_SHA}" -- "${manifest_paths[@]}"; then
  not_adopted "Package manifests changed; generate fresh reviewed lock candidates"
fi

runs_json=""
if ! runs_json="$(
  api \
    "/repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/runs?event=pull_request&head_sha=${parent_sha}&status=completed&per_page=20"
)"; then
  not_adopted "Public GitHub run metadata is unavailable"
fi
run_count=""
if ! run_count="$(
  jq -er \
    --arg baseRepositoryUrl "https://api.github.com/repos/${GITHUB_REPOSITORY}" \
    --arg baseSha "${PR_BASE_SHA}" \
    --arg headRepository "${PR_HEAD_REPOSITORY}" \
    --arg headSha "${parent_sha}" \
    --argjson pullRequestNumber "${PR_NUMBER}" \
    '[
      .workflow_runs[] |
      select(
        .event == "pull_request" and
        .status == "completed" and
        (.conclusion == "success" or .conclusion == "failure") and
        .head_sha == $headSha and
        .path == ".github/workflows/ci.yml" and
        .head_repository.full_name == $headRepository and
        any(
          .pull_requests[];
          .number == $pullRequestNumber and
          .base.repo.url == $baseRepositoryUrl and
          .base.sha == $baseSha and
          .head.sha == $headSha
        )
      )
    ] | length' <<<"${runs_json}"
)"; then
  not_adopted "Public GitHub run metadata is malformed"
fi
if [[ "${run_count}" -eq 0 ]]; then
  not_adopted "No completed parent-SHA CI candidate run is available"
fi
run_json=""
if ! run_json="$(
  jq -ce \
    --arg baseRepositoryUrl "https://api.github.com/repos/${GITHUB_REPOSITORY}" \
    --arg baseSha "${PR_BASE_SHA}" \
    --arg headRepository "${PR_HEAD_REPOSITORY}" \
    --arg headSha "${parent_sha}" \
    --argjson pullRequestNumber "${PR_NUMBER}" \
    '[
      .workflow_runs[] |
      select(
        .event == "pull_request" and
        .status == "completed" and
        (.conclusion == "success" or .conclusion == "failure") and
        .head_sha == $headSha and
        .path == ".github/workflows/ci.yml" and
        .head_repository.full_name == $headRepository and
        any(
          .pull_requests[];
          .number == $pullRequestNumber and
          .base.repo.url == $baseRepositoryUrl and
          .base.sha == $baseSha and
          .head.sha == $headSha
        )
      )
    ] |
    sort_by(.run_number, .run_attempt) |
    last' <<<"${runs_json}"
)"; then
  not_adopted "No unambiguous parent-SHA CI candidate run is available"
fi
run_id="$(jq -er '.id | tostring' <<<"${run_json}")"
run_attempt="$(jq -er '.run_attempt | tostring' <<<"${run_json}")"
[[ "${run_id}" =~ ^[1-9][0-9]*$ ]]
[[ "${run_attempt}" =~ ^[1-9][0-9]*$ ]]

jobs_json=""
if ! jobs_json="$(
  api \
    "/repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/jobs?filter=latest&per_page=100"
)"; then
  not_adopted "Public GitHub job metadata is unavailable"
fi
candidate_job_count=""
if ! candidate_job_count="$(
  jq -er \
    '[
      .jobs[] |
      select(.name == "Generate and validate reviewed lock candidates")
    ] | length' <<<"${jobs_json}"
)"; then
  not_adopted "Public GitHub job metadata is malformed"
fi
if [[ "${candidate_job_count}" -eq 0 ]]; then
  not_adopted "The parent run has no lock-candidate producer job"
fi
if [[ "${candidate_job_count}" -ne 1 ]]; then
  echo "::error::The parent run has an ambiguous lock-candidate job set"
  exit 1
fi
candidate_job=""
if ! candidate_job="$(
  jq -ce \
    '[
      .jobs[] |
      select(.name == "Generate and validate reviewed lock candidates")
    ][0]' <<<"${jobs_json}"
)"; then
  not_adopted "The parent lock-candidate job metadata is malformed"
fi
if ! jq -e \
  --arg headSha "${parent_sha}" \
  --argjson runAttempt "${run_attempt}" \
  --argjson runId "${run_id}" \
  '
      def successful($name):
        [.steps[] | select(.name == $name)] as $matches |
        ($matches | length) == 1 and
        $matches[0].status == "completed" and
        $matches[0].conclusion == "success";
      def failed($name):
        [.steps[] | select(.name == $name)] as $matches |
        ($matches | length) == 1 and
        $matches[0].status == "completed" and
        $matches[0].conclusion == "failure";
      def skipped($name):
        [.steps[] | select(.name == $name)] as $matches |
        ($matches | length) == 1 and
        $matches[0].status == "completed" and
        $matches[0].conclusion == "skipped";

      .status == "completed" and
      (.conclusion == "success" or .conclusion == "failure") and
      .run_id == $runId and
      .run_attempt == $runAttempt and
      .head_sha == $headSha and
      successful("Resolve all reviewed dependency policies into candidate locks") and
      successful("Seal candidate provenance before validation") and
      successful("Validate the root candidate exactly") and
      successful("Validate the infrastructure candidate exactly") and
      successful("Validate the web candidate exactly") and
      successful("Mark the exact candidates as remotely validated") and
      successful("Upload short-lived, source-bound validated lock candidates") and
      (
        if .conclusion == "failure" then
          failed("Require adoption of the remotely validated lock candidates")
        else
          skipped("Require adoption of the remotely validated lock candidates")
        end
      )
    ' <<<"${candidate_job}" >/dev/null; then
  not_adopted "The parent run did not complete an eligible candidate validation"
fi

candidate_set_digest="$(bash scripts/compute-lock-candidate-set-digest.sh)"
[[ "${candidate_set_digest}" =~ ^[0-9a-f]{64}$ ]]
artifact_name="validated-lock-candidates-${parent_sha}-${candidate_set_digest}"
artifacts_json=""
if ! artifacts_json="$(
  api \
    "/repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/artifacts?per_page=100"
)"; then
  not_adopted "Public GitHub artifact metadata is unavailable"
fi
artifact_count=""
if ! artifact_count="$(
  jq -er \
    --arg name "${artifact_name}" \
    --arg headSha "${parent_sha}" \
    --argjson runId "${run_id}" \
    '[
      .artifacts[] |
      select(
        .name == $name and
        .workflow_run.id == $runId and
        .workflow_run.head_sha == $headSha
      )
    ] | length' <<<"${artifacts_json}"
)"; then
  not_adopted "Public GitHub artifact metadata is malformed"
fi
if [[ "${artifact_count}" -eq 0 ]]; then
  not_adopted "The eligible parent run has no candidate artifact"
fi
if [[ "${artifact_count}" -ne 1 ]]; then
  echo "::error::The eligible parent run has an ambiguous candidate artifact set"
  exit 1
fi
artifact_json=""
if ! artifact_json="$(
  jq -ce \
    --arg name "${artifact_name}" \
    --arg headSha "${parent_sha}" \
    --argjson runId "${run_id}" \
    '[
      .artifacts[] |
      select(
        .name == $name and
        .workflow_run.id == $runId and
        .workflow_run.head_sha == $headSha
      )
    ][0]' <<<"${artifacts_json}"
)"; then
  not_adopted "The selected candidate artifact metadata is malformed"
fi
artifact_expired=""
if ! artifact_expired="$(jq -er '.expired | tostring' <<<"${artifact_json}")"; then
  not_adopted "The selected candidate artifact expiration is unavailable"
fi
if [[ "${artifact_expired}" != "false" ]]; then
  not_adopted "The exact parent-run candidate artifact has expired"
fi
artifact_id=""
artifact_digest=""
artifact_size=""
if ! artifact_id="$(jq -er '.id | tostring' <<<"${artifact_json}")" ||
  ! artifact_digest="$(jq -er '.digest' <<<"${artifact_json}")" ||
  ! artifact_size="$(jq -er '.size_in_bytes | tostring' <<<"${artifact_json}")"; then
  not_adopted "The selected candidate artifact identity is incomplete"
fi
[[ "${artifact_id}" =~ ^[1-9][0-9]*$ ]]
[[ "${artifact_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "${artifact_size}" =~ ^[1-9][0-9]*$ ]]
test "${artifact_size}" -le 2097152

artifact_after_selection=""
if ! artifact_after_selection="$(
  api "/repos/${GITHUB_REPOSITORY}/actions/artifacts/${artifact_id}"
)"; then
  not_adopted "The selected public artifact metadata is no longer available"
fi
jq -e \
  --arg digest "${artifact_digest}" \
  --arg name "${artifact_name}" \
  --arg headSha "${parent_sha}" \
  --argjson artifactId "${artifact_id}" \
  --argjson runId "${run_id}" \
  --argjson sizeInBytes "${artifact_size}" \
  '
    .id == $artifactId and
    .name == $name and
    .digest == $digest and
    .expired == false and
    .size_in_bytes == $sizeInBytes and
    .workflow_run.id == $runId and
    .workflow_run.head_sha == $headSha
  ' <<<"${artifact_after_selection}" >/dev/null

printf 'adopted=true\n' >>"${GITHUB_OUTPUT}"
echo "::notice::Accepted exact parent-run candidate set ${candidate_set_digest} from run ${run_id}, attempt ${run_attempt}, artifact ${artifact_id} (${artifact_digest})"
