#!/usr/bin/env bash
set -euo pipefail

: "${GCP_PROJECT:?GCP_PROJECT is required}"
: "${GCP_ZONE:?GCP_ZONE is required}"
: "${DATAHUB_VM:?DATAHUB_VM is required}"
: "${DATAHUB_GMS_URL:?DATAHUB_GMS_URL is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"

if [[ "${DATAHUB_GMS_URL}" != "http://127.0.0.1:18080" ]]; then
  echo "::error::the governed proof requires the exact loopback tunnel origin" >&2
  exit 1
fi

status="$(gcloud compute instances describe "${DATAHUB_VM}" \
  --project "${GCP_PROJECT}" --zone "${GCP_ZONE}" --format='value(status)')"
if [[ "${status}" != "RUNNING" ]]; then
  echo "::error::the synthetic DataHub VM is not running" >&2
  exit 1
fi

log="${RUNNER_TEMP}/datahub-iap-${GITHUB_JOB:-job}.log"
gcloud compute start-iap-tunnel "${DATAHUB_VM}" 8080 \
  --local-host-port=127.0.0.1:18080 \
  --project "${GCP_PROJECT}" --zone "${GCP_ZONE}" >"${log}" 2>&1 &
pid=$!
cleanup() { kill "${pid}" 2>/dev/null || true; }
trap cleanup EXIT

for _attempt in {1..30}; do
  if curl -fsS --max-time 2 "${DATAHUB_GMS_URL}/health" >/dev/null; then
    printf 'IAP_PID=%s\n' "${pid}" >>"${GITHUB_ENV}"
    trap - EXIT
    exit 0
  fi
  sleep 1
done

sed -E 's/(token|authorization|credential)=[^ ]+/\1=[redacted]/gi' "${log}" >&2
echo "::error::the IAP tunnel did not become ready" >&2
exit 1
