#!/usr/bin/env bash
set -euo pipefail

readonly repository_root="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
)"
readonly materializer="${repository_root}/scripts/materialize-datahub-mcp-lock.sh"
readonly real_date="$(command -v date)"
readonly temporary="$(mktemp -d)"
trap 'rm -rf -- "${temporary}"' EXIT

mkdir -p "${temporary}/bin"
cat >"${temporary}/bin/date" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -eq 2 && "${1}" == "-u" && "${2}" == "+%s" ]]; then
  printf '%s\n' "${ARCHON_FAKE_NOW_EPOCH:?}"
  exit 0
fi
exec "${ARCHON_REAL_DATE:?}" "$@"
SH
chmod 0700 "${temporary}/bin/date"

cat >"${temporary}/bin/forbidden" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo "maintenance-only mode invoked forbidden command: ${0##*/}" >&2
exit 99
SH
chmod 0700 "${temporary}/bin/forbidden"
for command in cp curl git mkdir python3 uv; do
  ln -s forbidden "${temporary}/bin/${command}"
done

run_gate() {
  local now_epoch="$1"
  local minimum_days="$2"
  (
    cd "${repository_root}"
    env \
      ARCHON_FAKE_NOW_EPOCH="${now_epoch}" \
      ARCHON_REAL_DATE="${real_date}" \
      PATH="${temporary}/bin:${PATH}" \
      bash "${materializer}" \
        --openvex-maintenance-only \
        --minimum-remaining-days "${minimum_days}"
  )
}

readonly expires_epoch="$(
  "${real_date}" -u --date="2026-08-22T11:30:00Z" +%s
)"
readonly fifteen_days_before="$((expires_epoch - 15 * 86400))"
readonly fourteen_days_before="$((expires_epoch - 14 * 86400))"
readonly thirteen_days_before="$((expires_epoch - 13 * 86400))"

receipt="$(run_gate "${fifteen_days_before}" 14)"
jq --exit-status '
  .schemaVersion == "archon.openvex-maintenance/v1" and
  .status == "ready" and
  .maxValidityDays == 30 and
  .minimumRemainingDays == 14 and
  .remainingDays == 15 and
  .remainingSeconds == (15 * 86400)
' <<<"${receipt}" >/dev/null

receipt="$(run_gate "${fourteen_days_before}" 14)"
jq --exit-status '
  .minimumRemainingDays == 14 and
  .remainingDays == 14 and
  .remainingSeconds == (14 * 86400)
' <<<"${receipt}" >/dev/null

if failure="$(run_gate "${thirteen_days_before}" 14 2>&1)"; then
  echo "OpenVEX maintenance gate accepted fewer than 14 remaining days" >&2
  exit 1
fi
grep -F \
  "OpenVEX renewal required: 13 whole days remain; minimum is 14" \
  <<<"${failure}" >/dev/null

for invalid_days in 0 00 014 08 31 invalid; do
  if run_gate "${fifteen_days_before}" "${invalid_days}" >/dev/null 2>&1; then
    echo "OpenVEX maintenance gate accepted invalid threshold ${invalid_days}" >&2
    exit 1
  fi
done
