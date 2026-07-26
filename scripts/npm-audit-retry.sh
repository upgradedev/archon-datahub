#!/usr/bin/env bash
set -euo pipefail

# CI/CD-only wrapper for npm's advisory service. Registry transport failures are
# retried, while a real moderate-or-higher result fails immediately. The final
# attempt is always fail-closed, including for malformed or unavailable reports.

audit_level_count=0
for argument in "$@"; do
  case "${argument}" in
    --audit-level=moderate)
      audit_level_count=$((audit_level_count + 1))
      ;;
    --audit-level|--audit-level=*)
      echo "::error::The normal npm audit gate requires --audit-level=moderate" >&2
      exit 64
      ;;
    --json|--json=*)
      echo "::error::The npm audit wrapper owns JSON report generation" >&2
      exit 64
      ;;
  esac
done
if (( audit_level_count != 1 )); then
  echo "usage: npm-audit-retry.sh [npm audit options] --audit-level=moderate" >&2
  exit 64
fi

readonly attempts="${NPM_AUDIT_ATTEMPTS:-4}"
readonly initial_backoff="${NPM_AUDIT_INITIAL_BACKOFF_SECONDS:-10}"
[[ "${attempts}" =~ ^[1-9][0-9]?$ ]]
[[ "${initial_backoff}" =~ ^[1-9][0-9]?$ ]]
(( attempts <= 8 ))
(( initial_backoff <= 60 ))

umask 077
readonly work_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/archon-npm-audit.XXXXXX")"
trap 'rm -rf -- "${work_dir}"' EXIT

backoff="${initial_backoff}"
for (( attempt = 1; attempt <= attempts; attempt += 1 )); do
  report="${work_dir}/attempt-${attempt}.json"
  set +e
  npm audit "$@" --json >"${report}"
  status=$?
  set -e

  test -f "${report}"
  test ! -L "${report}"
  cat "${report}"
  if (( status == 0 )); then
    exit 0
  fi

  # Do not mask or retry a genuine gate result. Retry only when npm failed
  # without producing evidence of a moderate-or-higher advisory.
  if jq -e '
      (
        (.metadata.vulnerabilities.moderate // 0) > 0 or
        (.metadata.vulnerabilities.high // 0) > 0 or
        (.metadata.vulnerabilities.critical // 0) > 0
      ) or
      any(
        .vulnerabilities[]?;
        .severity == "moderate" or
        .severity == "high" or
        .severity == "critical"
      )
    ' "${report}" >/dev/null 2>&1; then
    echo "::error::npm audit reported a moderate or higher vulnerability"
    exit "${status}"
  fi

  if (( attempt == attempts )); then
    echo "::error::npm audit did not return a successful trustworthy report after ${attempts} attempts"
    exit "${status}"
  fi

  echo "::warning::npm advisory service attempt ${attempt}/${attempts} failed; retrying in ${backoff}s"
  sleep "${backoff}"
  backoff=$(( backoff * 2 ))
  if (( backoff > 60 )); then
    backoff=60
  fi
done

exit 1
