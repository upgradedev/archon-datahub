#!/usr/bin/env bash
set -euo pipefail

readonly RAIN_VERSION="v1.24.4"
readonly RAIN_LINUX_AMD64_ARCHIVE_SHA256="5358d6daf35322101566376a38e37d1f89c6588479af2e20240579fc2d4c660a"
readonly CLOUDFORMATION_TEMPLATE_BODY_MAX_BYTES=51200

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "This renderer is restricted to ephemeral GitHub Actions runners" >&2
  exit 1
fi

: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

if [[ "$#" -ne 2 ]]; then
  echo "Usage: $0 <repository-template> <runner-temp-output.json>" >&2
  exit 1
fi

test -f "$1"
test ! -L "$1"
source_path="$(realpath "$1")"
workspace_root="$(realpath "${GITHUB_WORKSPACE}")"
runner_temp_root="$(realpath "${RUNNER_TEMP}")"
output_path="$(realpath -m "$2")"
output_parent="$(dirname "${output_path}")"

[[ "${source_path}" == "${workspace_root}/"* ]]
[[ "${output_path}" == "${runner_temp_root}/"* ]]
test -f "${source_path}"
test ! -e "${output_path}"
mkdir -p "${output_parent}"

tool_root="$(mktemp -d "${RUNNER_TEMP}/archon-rain.XXXXXX")"
archive="${tool_root}/rain.zip"
curl --fail --silent --show-error --location \
  --output "${archive}" \
  "https://github.com/aws-cloudformation/rain/releases/download/${RAIN_VERSION}/rain-${RAIN_VERSION}_linux-amd64.zip"
echo "${RAIN_LINUX_AMD64_ARCHIVE_SHA256}  ${archive}" |
  sha256sum --check --strict
unzip -q "${archive}" -d "${tool_root}/bin"

mapfile -t rain_candidates < <(
  find "${tool_root}/bin" -type f -name rain -print
)
test "${#rain_candidates[@]}" -eq 1
rain_bin="${rain_candidates[0]}"
chmod 0755 "${rain_bin}"

pretty_json="$(mktemp "${RUNNER_TEMP}/archon-inline-cfn.pretty.XXXXXX.json")"
compact_json="$(mktemp "${output_parent}/.$(basename "$2").XXXXXX")"
"${rain_bin}" fmt --json --unsorted "${source_path}" >"${pretty_json}"
jq -cS \
  'select(
    type == "object" and
    (.Resources | type == "object" and length > 0)
  )' \
  "${pretty_json}" >"${compact_json}"
test -s "${compact_json}"

template_bytes="$(wc -c <"${compact_json}" | tr -d '[:space:]')"
[[ "${template_bytes}" =~ ^[0-9]+$ ]]
if (( template_bytes > CLOUDFORMATION_TEMPLATE_BODY_MAX_BYTES )); then
  echo \
    "Rendered template is ${template_bytes} bytes; CloudFormation TemplateBody permits at most ${CLOUDFORMATION_TEMPLATE_BODY_MAX_BYTES}" \
    >&2
  exit 1
fi

round_trip="$(mktemp "${RUNNER_TEMP}/archon-inline-cfn.round-trip.XXXXXX.json")"
"${rain_bin}" fmt --json --unsorted "${compact_json}" |
  jq -cS . >"${round_trip}"
cmp -s "${compact_json}" "${round_trip}"

mv "${compact_json}" "${output_path}"
test -f "${output_path}"
test ! -L "${output_path}"
test "$(wc -c <"${output_path}" | tr -d '[:space:]')" = \
  "${template_bytes}"
printf 'Rendered inline-safe CloudFormation template: %s bytes\n' \
  "${template_bytes}"
