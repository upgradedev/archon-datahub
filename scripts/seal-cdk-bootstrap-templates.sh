#!/usr/bin/env bash
set -euo pipefail

repository_root="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
    pwd
)"

fail() {
  echo "::error::CDK bootstrap seal failed: $*" >&2
  exit 1
}

runtime_root="${RUNNER_TEMP:-}"
expected_version="${EXPECTED_BOOTSTRAP_VERSION:-}"
github_output="${GITHUB_OUTPUT:-}"
cdk_cli="${CDK_CLI_PATH:-${repository_root}/infra/aws/node_modules/.bin/cdk}"
patcher="${BOOTSTRAP_PATCHER_PATH:-${repository_root}/scripts/patch-cdk-bootstrap-template.mjs}"

test -n "${runtime_root}" ||
  fail "RUNNER_TEMP is required; this verifier must run in CI"
case "${runtime_root}" in
  /*) ;;
  *) fail "RUNNER_TEMP must be an absolute path" ;;
esac
test -d "${runtime_root}" ||
  fail "RUNNER_TEMP does not identify a directory"
test ! -L "${runtime_root}" ||
  fail "RUNNER_TEMP must not be a symbolic link"
test -n "${expected_version}" ||
  fail "EXPECTED_BOOTSTRAP_VERSION is required"
[[ "${expected_version}" =~ ^[1-9][0-9]*$ ]] ||
  fail "EXPECTED_BOOTSTRAP_VERSION must be a positive integer"
test -n "${github_output}" ||
  fail "GITHUB_OUTPUT is required"
test -f "${github_output}" ||
  fail "GITHUB_OUTPUT must identify an existing regular file"
test ! -L "${github_output}" ||
  fail "GITHUB_OUTPUT must not be a symbolic link"
test -w "${github_output}" ||
  fail "GITHUB_OUTPUT must be writable"
test -x "${cdk_cli}" ||
  fail "locked CDK CLI is not executable: ${cdk_cli}"
test -f "${patcher}" ||
  fail "bootstrap patcher is missing: ${patcher}"
test ! -L "${patcher}" ||
  fail "bootstrap patcher must not be a symbolic link"

if ! work_dir="$(
  mktemp -d "${runtime_root%/}/archon-cdk-bootstrap.XXXXXX"
)"; then
  fail "unable to create the CI-only bootstrap work directory"
fi
test -d "${work_dir}" ||
  fail "bootstrap work directory was not created"
test ! -L "${work_dir}" ||
  fail "bootstrap work directory must not be a symbolic link"

template="${work_dir}/cdk-bootstrap-template.yml"
if ! "${cdk_cli}" bootstrap \
  --show-template \
  --no-notices >"${template}"; then
  fail "locked CDK CLI could not render the modern bootstrap template"
fi
test -s "${template}" ||
  fail "locked CDK CLI rendered an empty bootstrap template"
test -f "${template}" ||
  fail "rendered bootstrap template is not a regular file"
test ! -L "${template}" ||
  fail "rendered bootstrap template must not be a symbolic link"

version_resource_count="$(
  grep -Ec '^  CdkBootstrapVersion:$' "${template}" || true
)"
test "${version_resource_count}" = "1" ||
  fail \
    "expected one CdkBootstrapVersion resource; found ${version_resource_count}"
if ! template_version="$(
  awk '
    $1 == "CdkBootstrapVersion:" { in_version = 1; next }
    in_version && $1 == "Value:" {
      gsub(/\047/, "", $2)
      print $2
      exit
    }
  ' "${template}"
)"; then
  fail "unable to read CdkBootstrapVersion.Value"
fi
test -n "${template_version}" ||
  fail "CdkBootstrapVersion.Value is missing"
test "${template_version}" = "${expected_version}" ||
  fail \
    "expected bootstrap version ${expected_version}; found ${template_version}"

for logical_id in \
  StagingBucket \
  StagingBucketPolicy \
  ContainerAssetsRepository \
  FilePublishingRole \
  ImagePublishingRole \
  LookupRole \
  DeploymentActionRole \
  CloudFormationExecutionRole \
  CdkBootstrapVersion; do
  grep -Fqx "  ${logical_id}:" "${template}" ||
    fail "required logical ID is missing: ${logical_id}"
done

if ! template_sha="$(
  sha256sum "${template}" | awk '{print $1}'
)"; then
  fail "unable to hash the rendered bootstrap template"
fi
[[ "${template_sha}" =~ ^[0-9a-f]{64}$ ]] ||
  fail "rendered bootstrap template hash is malformed"
for stage in staging production; do
  for region_slot in primary edge; do
    if [[ "${region_slot}" == "primary" ]]; then
      region="eu-west-1"
    else
      region="us-east-1"
    fi
    stage_template="$(
      printf '%s/cdk-bootstrap-%s-%s.yml' \
        "${work_dir}" "${stage}" "${region}"
    )"
    if ! node "${patcher}" \
      --input "${template}" \
      --output "${stage_template}" \
      --stage "${stage}" \
      --region "${region}"; then
      fail "patcher rejected the ${stage}/${region} bootstrap template"
    fi
    test -s "${stage_template}" ||
      fail "patched ${stage}/${region} bootstrap template is empty"
    test -f "${stage_template}" ||
      fail "patched ${stage}/${region} bootstrap template is not regular"
    test ! -L "${stage_template}" ||
      fail "patched ${stage}/${region} bootstrap template is a symbolic link"
    marker="Archon DataHub ${stage} ${region} isolated bootstrap v1"
    grep -Fq "${marker}" "${stage_template}" ||
      fail "patched ${stage}/${region} template is missing its isolation marker"
    if ! stage_sha="$(
      sha256sum "${stage_template}" | awk '{print $1}'
    )"; then
      fail "unable to hash the patched ${stage}/${region} template"
    fi
    [[ "${stage_sha}" =~ ^[0-9a-f]{64}$ ]] ||
      fail "patched ${stage}/${region} template hash is malformed"
    if ! {
      echo "${stage}_${region_slot}_path=${stage_template}"
      echo "${stage}_${region_slot}_sha=${stage_sha}"
    } >>"${github_output}"; then
      fail "unable to publish ${stage}/${region} template outputs"
    fi
  done
done

if ! {
  echo "path=${template}"
  echo "sha=${template_sha}"
  echo "version=${template_version}"
} >>"${github_output}"; then
  fail "unable to publish source bootstrap template outputs"
fi

echo \
  "Sealed CDK bootstrap v${template_version} for staging and production in both regions"
