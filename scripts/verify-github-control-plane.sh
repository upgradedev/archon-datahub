#!/usr/bin/env bash
set -euo pipefail

# CI/CD-only trust gate for privileged workflows. Current mode binds the exact
# commit to the default-branch ref and latest exact-SHA CI, CodeQL, and
# workflow-security push runs. Sealed mode authenticates the canonical receipt
# and each recorded exact attempt without consulting today's branch head.

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_REF:?GITHUB_REF is required}"
: "${CONTROL_PLANE_SHA:?CONTROL_PLANE_SHA is required}"
: "${OUTPUT_PATH:?OUTPUT_PATH is required}"

EXPECTED_BRANCH="${EXPECTED_BRANCH:-master}"
EXPECTED_GATE_SHA256="${EXPECTED_GATE_SHA256:-}"
VERIFICATION_MODE="${VERIFICATION_MODE:-current}"
SEALED_GATE_PATH="${SEALED_GATE_PATH:-}"
ATTEMPTS="${ATTEMPTS:-1}"
BACKOFF_SECONDS="${BACKOFF_SECONDS:-15}"

[[ "${CONTROL_PLANE_SHA}" =~ ^[0-9a-f]{40}$ ]]
[[ "${EXPECTED_BRANCH}" =~ ^[a-zA-Z0-9._/-]{1,255}$ ]]
[[ "${VERIFICATION_MODE}" == "current" || "${VERIFICATION_MODE}" == "sealed" ]]
[[ "${ATTEMPTS}" =~ ^[1-9][0-9]?$ ]]
[[ "${BACKOFF_SECONDS}" =~ ^[1-9][0-9]?$ ]]
(( ATTEMPTS <= 40 ))
(( BACKOFF_SECONDS <= 60 ))
[[ "${OUTPUT_PATH}" == /* ]]
test "$(basename "${OUTPUT_PATH}")" = "control-plane-security-gates.json"
if [[ -n "${EXPECTED_GATE_SHA256}" ]]; then
  [[ "${EXPECTED_GATE_SHA256}" =~ ^[0-9a-f]{64}$ ]]
fi
if [[ "${VERIFICATION_MODE}" == "sealed" ]]; then
  : "${EXPECTED_GATE_SHA256:?EXPECTED_GATE_SHA256 is required in sealed mode}"
  : "${SEALED_GATE_PATH:?SEALED_GATE_PATH is required in sealed mode}"
  [[ "${SEALED_GATE_PATH}" == /* ]]
  test "$(basename "${SEALED_GATE_PATH}")" = \
    "control-plane-security-gates.json"
fi
test "${GITHUB_REF}" = "refs/heads/${EXPECTED_BRANCH}" || {
  echo "::error::The privileged workflow must run from ${EXPECTED_BRANCH}"
  exit 1
}

umask 077
work_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/archon-control-plane.XXXXXX")"
trap 'rm -rf -- "${work_dir}"' EXIT
mkdir -p "$(dirname "${OUTPUT_PATH}")"
test ! -L "${OUTPUT_PATH}"
if [[ -e "${OUTPUT_PATH}" ]]; then
  test -f "${OUTPUT_PATH}"
fi

read_current_branch_sha() {
  local repository_json ref_json default_branch
  repository_json="$(
    gh api \
      --method GET \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2026-03-10" \
      "/repos/${GITHUB_REPOSITORY}"
  )"
  jq -e \
    --arg repository "${GITHUB_REPOSITORY}" \
    --arg branch "${EXPECTED_BRANCH}" '
      .full_name == $repository and
      .default_branch == $branch and
      .archived == false and
      .disabled == false
    ' <<<"${repository_json}" >/dev/null || {
    echo "::error::The repository/default-branch trust root is invalid"
    return 1
  }
  default_branch="$(jq -er '.default_branch' <<<"${repository_json}")"
  ref_json="$(
    gh api \
      --method GET \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2026-03-10" \
      "/repos/${GITHUB_REPOSITORY}/git/ref/heads/${default_branch}"
  )"
  jq -er \
    --arg ref "refs/heads/${default_branch}" '
      select(
        .ref == $ref and
        .object.type == "commit" and
        (.object.sha | test("^[0-9a-f]{40}$"))
      ) |
      .object.sha
    ' <<<"${ref_json}"
}

verify_sealed_gate() {
  local canonical_gate gate_sha256 receipt workflow_path workflow_name
  local workflow_id run_id run_attempt run_url sealed_run temporary_output

  test -f "${SEALED_GATE_PATH}"
  test ! -L "${SEALED_GATE_PATH}"
  canonical_gate="${work_dir}/sealed-control-plane-security-gates.json"
  jq -cS . "${SEALED_GATE_PATH}" >"${canonical_gate}"
  cmp --silent "${SEALED_GATE_PATH}" "${canonical_gate}" || {
    echo "::error::The sealed control-plane receipt is not canonical"
    return 1
  }
  gate_sha256="$(sha256sum "${SEALED_GATE_PATH}" | awk '{print $1}')"
  test "${gate_sha256}" = "${EXPECTED_GATE_SHA256}" || {
    echo "::error::The sealed control-plane receipt digest changed"
    return 1
  }
  jq -e \
    --arg sha "${CONTROL_PLANE_SHA}" \
    --arg branch "${EXPECTED_BRANCH}" '
      (keys | sort) == [
        "branch",
        "schemaVersion",
        "sourceSha",
        "workflows"
      ] and
      .schemaVersion == "archon.deployment-control-plane-gates/v1" and
      .sourceSha == $sha and
      .branch == $branch and
      (.workflows | length) == 3 and
      ([.workflows[].path] | sort) == [
        ".github/workflows/ci.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/workflow-security.yml"
      ] and
      all(
        .workflows[];
        (keys | sort) == [
          "conclusion",
          "path",
          "runAttempt",
          "runId",
          "url",
          "workflowId"
        ] and
        (.workflowId | type) == "number" and
        .workflowId >= 1 and
        (.runId | type) == "number" and
        .runId >= 1 and
        (.runAttempt | type) == "number" and
        .runAttempt >= 1 and
        (.url | type) == "string" and
        .conclusion == "success"
      )
    ' "${SEALED_GATE_PATH}" >/dev/null || {
    echo "::error::The sealed control-plane receipt schema is invalid"
    return 1
  }

  while IFS= read -r receipt; do
    workflow_path="$(jq -er '.path' <<<"${receipt}")"
    case "${workflow_path}" in
      .github/workflows/ci.yml)
        workflow_name="CI"
        ;;
      .github/workflows/codeql.yml)
        workflow_name="CodeQL"
        ;;
      .github/workflows/workflow-security.yml)
        workflow_name="Workflow security"
        ;;
      *)
        echo "::error::A sealed control-plane workflow path is invalid"
        return 1
        ;;
    esac
    workflow_id="$(jq -er '.workflowId' <<<"${receipt}")"
    run_id="$(jq -er '.runId' <<<"${receipt}")"
    run_attempt="$(jq -er '.runAttempt' <<<"${receipt}")"
    run_url="$(jq -er '.url' <<<"${receipt}")"
    sealed_run="$(
      gh api \
        --method GET \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2026-03-10" \
        "/repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/attempts/${run_attempt}"
    )" || return 1
    jq -e \
      --arg name "${workflow_name}" \
      --arg path "${workflow_path}" \
      --arg repository "${GITHUB_REPOSITORY}" \
      --arg branch "${EXPECTED_BRANCH}" \
      --arg sha "${CONTROL_PLANE_SHA}" \
      --arg url "${run_url}" \
      --argjson workflowId "${workflow_id}" \
      --argjson runId "${run_id}" \
      --argjson runAttempt "${run_attempt}" '
        .id == $runId and
        .workflow_id == $workflowId and
        .run_attempt == $runAttempt and
        .name == $name and
        .path == $path and
        .head_repository.full_name == $repository and
        .head_branch == $branch and
        .head_sha == $sha and
        .event == "push" and
        .status == "completed" and
        .conclusion == "success" and
        .html_url == $url
      ' <<<"${sealed_run}" >/dev/null || {
      echo "::error::A sealed control-plane workflow attempt is invalid"
      return 1
    }
  done < <(jq -c '.workflows[]' "${SEALED_GATE_PATH}")

  temporary_output="${work_dir}/control-plane-security-gates.json"
  cp -- "${canonical_gate}" "${temporary_output}"
  mv -- "${temporary_output}" "${OUTPUT_PATH}"
}

if [[ "${VERIFICATION_MODE}" == "sealed" ]]; then
  verify_sealed_gate
  exit 0
fi

test "$(read_current_branch_sha)" = "${CONTROL_PLANE_SHA}" || {
  echo "::error::The workflow commit is no longer the default-branch head"
  exit 1
}

read_gate_snapshot() {
  local control_plane_runs expected_name expected_path response selected
  local workflow_file

  control_plane_runs="[]"
  while IFS='|' read -r workflow_file expected_name; do
    expected_path=".github/workflows/${workflow_file}"
    response="$(
      gh api \
        --method GET \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2026-03-10" \
        "/repos/${GITHUB_REPOSITORY}/actions/workflows/${workflow_file}/runs" \
        -f "head_sha=${CONTROL_PLANE_SHA}" \
        -f "branch=${EXPECTED_BRANCH}" \
        -f event=push \
        -f per_page=100
    )" || return 1
    selected="$(
      jq -ce \
        --arg name "${expected_name}" \
        --arg path "${expected_path}" \
        --arg sha "${CONTROL_PLANE_SHA}" \
        --arg branch "${EXPECTED_BRANCH}" \
        --arg repository "${GITHUB_REPOSITORY}" '
          [
            .workflow_runs[] |
            select(
              .name == $name and
              .path == $path and
              .head_sha == $sha and
              .head_branch == $branch and
              .head_repository.full_name == $repository and
              .event == "push"
            )
          ] |
          sort_by(.id, .run_attempt) |
          last |
          select(
            . != null and
            .status == "completed" and
            .conclusion == "success"
          )
        ' <<<"${response}"
    )" || return 1
    control_plane_runs="$(
      jq -cn \
        --argjson current "${control_plane_runs}" \
        --argjson selected "${selected}" '
          $current + [{
            path: $selected.path,
            workflowId: $selected.workflow_id,
            runId: $selected.id,
            runAttempt: $selected.run_attempt,
            url: $selected.html_url,
            conclusion: $selected.conclusion
          }]
        '
    )" || return 1
  done <<'EOF'
ci.yml|CI
codeql.yml|CodeQL
workflow-security.yml|Workflow security
EOF
  test "$(jq -r 'length' <<<"${control_plane_runs}")" = "3" || return 1
  jq -cS 'sort_by(.path)' <<<"${control_plane_runs}"
}

gate_ready=false
control_plane_runs="[]"
for (( attempt = 1; attempt <= ATTEMPTS; attempt += 1 )); do
  if ! first_gate_snapshot="$(read_gate_snapshot)"; then
    if (( attempt < ATTEMPTS )); then
      sleep "${BACKOFF_SECONDS}"
    fi
    continue
  fi

  test "$(read_current_branch_sha)" = "${CONTROL_PLANE_SHA}" || {
    echo "::error::The default branch changed while workflow gates were observed"
    exit 1
  }

  second_gate_snapshot="$(read_gate_snapshot)" || {
    echo "::error::The latest exact-SHA workflow snapshot changed or is no longer successful"
    exit 1
  }
  test "${second_gate_snapshot}" = "${first_gate_snapshot}" || {
    echo "::error::The latest exact-SHA workflow snapshot changed during verification"
    exit 1
  }

  test "$(read_current_branch_sha)" = "${CONTROL_PLANE_SHA}" || {
    echo "::error::The default branch changed while workflow gates were revalidated"
    exit 1
  }

  control_plane_runs="${second_gate_snapshot}"
  gate_ready=true
  break
done

if [[ "${gate_ready}" != "true" ]]; then
  if (( ATTEMPTS > 1 )); then
    echo "::error::The latest exact-SHA CI, CodeQL, and Workflow security runs did not become ready"
  else
    echo "::error::The latest exact-SHA CI, CodeQL, and Workflow security runs must all succeed"
  fi
  exit 1
fi

temporary_output="${work_dir}/control-plane-security-gates.json"
jq -cnS \
  --arg sha "${CONTROL_PLANE_SHA}" \
  --arg branch "${EXPECTED_BRANCH}" \
  --argjson workflows "${control_plane_runs}" '
    {
      schemaVersion: "archon.deployment-control-plane-gates/v1",
      sourceSha: $sha,
      branch: $branch,
      workflows: ($workflows | sort_by(.path))
    }
  ' >"${temporary_output}"
test -s "${temporary_output}"
gate_sha256="$(sha256sum "${temporary_output}" | awk '{print $1}')"
if [[ -n "${EXPECTED_GATE_SHA256}" ]]; then
  test "${gate_sha256}" = "${EXPECTED_GATE_SHA256}" || {
    echo "::error::The exact control-plane workflow receipts changed"
    exit 1
  }
fi
mv -- "${temporary_output}" "${OUTPUT_PATH}"
