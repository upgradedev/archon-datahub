#!/usr/bin/env bash
set -euo pipefail

readonly RAIN_VERSION="v1.24.4"
readonly RAIN_LINUX_AMD64_ARCHIVE_SHA256="5358d6daf35322101566376a38e37d1f89c6588479af2e20240579fc2d4c660a"
readonly YQ_VERSION="v4.47.2"
readonly YQ_LINUX_AMD64_SHA256="1bb99e1019e23de33c7e6afc23e93dad72aad6cf2cb03c797f068ea79814ddb0"
readonly CLOUDFORMATION_TEMPLATE_BODY_MAX_BYTES=51200

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "This renderer is restricted to ephemeral GitHub Actions runners" >&2
  exit 1
fi

: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

if [[ "$#" -ne 3 ]]; then
  echo \
    "Usage: $0 <repository-template> <runner-temp-output.yaml> <runner-temp-canonical.json>" \
    >&2
  exit 1
fi

test -f "$1"
test ! -L "$1"
source_path="$(realpath "$1")"
workspace_root="$(realpath "${GITHUB_WORKSPACE}")"
runner_temp_root="$(realpath "${RUNNER_TEMP}")"
output_path="$(realpath -m "$2")"
canonical_output_path="$(realpath -m "$3")"
output_parent="$(dirname "${output_path}")"
canonical_output_parent="$(dirname "${canonical_output_path}")"

[[ "${source_path}" == "${workspace_root}/"* ]]
[[ "${output_path}" == "${runner_temp_root}/"* ]]
[[ "${canonical_output_path}" == "${runner_temp_root}/"* ]]
test "${output_path}" != "${canonical_output_path}"
test -f "${source_path}"
test ! -e "${output_path}"
test ! -e "${canonical_output_path}"
mkdir -p "${output_parent}" "${canonical_output_parent}"

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

yq_bin="${RUNNER_TEMP}/archon-inline-cfn-yq"
test ! -e "${yq_bin}"
curl --fail --silent --show-error --location \
  --output "${yq_bin}" \
  "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64"
echo "${YQ_LINUX_AMD64_SHA256}  ${yq_bin}" |
  sha256sum --check --strict
chmod 0755 "${yq_bin}"
"${yq_bin}" --version | grep -Fq "version ${YQ_VERSION}"

pretty_json="$(mktemp "${RUNNER_TEMP}/archon-inline-cfn.pretty.XXXXXX.json")"
canonical_json="$(
  mktemp "${canonical_output_parent}/.$(basename "$3").XXXXXX"
)"
flow_yaml="$(mktemp "${output_parent}/.$(basename "$2").XXXXXX")"
"${rain_bin}" fmt --json --unsorted "${source_path}" >"${pretty_json}"
jq -cS \
  'select(
    type == "object" and
    (.Resources | type == "object" and length > 0)
  )' \
  "${pretty_json}" >"${canonical_json}"
test -s "${canonical_json}"

"${yq_bin}" \
  --output-format=yaml \
  --no-colors \
  '... style="" | .. style="flow"' \
  "${canonical_json}" >"${flow_yaml}"
test -s "${flow_yaml}"

template_bytes="$(wc -c <"${flow_yaml}" | tr -d '[:space:]')"
[[ "${template_bytes}" =~ ^[0-9]+$ ]]
if (( template_bytes > CLOUDFORMATION_TEMPLATE_BODY_MAX_BYTES )); then
  echo \
    "Rendered flow-YAML template is ${template_bytes} bytes; CloudFormation TemplateBody permits at most ${CLOUDFORMATION_TEMPLATE_BODY_MAX_BYTES}" \
    >&2
  exit 1
fi

round_trip="$(mktemp "${RUNNER_TEMP}/archon-inline-cfn.round-trip.XXXXXX.json")"
"${rain_bin}" fmt --json --unsorted "${flow_yaml}" |
  jq -cS . >"${round_trip}"
cmp -s "${canonical_json}" "${round_trip}"

mv "${flow_yaml}" "${output_path}"
mv "${canonical_json}" "${canonical_output_path}"
test -f "${output_path}"
test ! -L "${output_path}"
test -f "${canonical_output_path}"
test ! -L "${canonical_output_path}"
test "$(wc -c <"${output_path}" | tr -d '[:space:]')" = \
  "${template_bytes}"
printf 'Rendered inline-safe flow-YAML CloudFormation template: %s bytes\n' \
  "${template_bytes}"
