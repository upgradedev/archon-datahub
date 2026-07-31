#!/usr/bin/env bash
set -Eeuo pipefail

readonly FOUNDATION_DIAGNOSTIC_SOURCE='scripts/reconcile-aws-foundation.sh'
foundation_phase='startup'

report_foundation_error() {
  local exit_code="$1"
  local source_line="$2"
  trap - ERR
  set +e
  printf '::error file=%s,line=%s,title=AWS foundation reconciliation failed::phase=%s; exit=%s\n' \
    "${FOUNDATION_DIAGNOSTIC_SOURCE}" "${source_line}" \
    "${foundation_phase}" "${exit_code}" >&2
  exit "${exit_code}"
}

trap 'report_foundation_error "$?" "$LINENO"' ERR
shopt -s inherit_errexit

readonly CFN_DRIFT_HELPER='scripts/aws-cloudformation-drift.sh'
test -f "${CFN_DRIFT_HELPER}"
test ! -L "${CFN_DRIFT_HELPER}"
# shellcheck source=scripts/aws-cloudformation-drift.sh
source "${CFN_DRIFT_HELPER}"

: "${EXPECTED_ACCOUNT_ID:?EXPECTED_ACCOUNT_ID is required}"
: "${CONTROL_PLANE_SHA:?CONTROL_PLANE_SHA is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${BOOTSTRAP_TEMPLATE:?BOOTSTRAP_TEMPLATE is required}"
: "${BOOTSTRAP_TEMPLATE_SHA:?BOOTSTRAP_TEMPLATE_SHA is required}"
: "${STAGING_PRIMARY_BOOTSTRAP_TEMPLATE:?STAGING_PRIMARY_BOOTSTRAP_TEMPLATE is required}"
: "${STAGING_PRIMARY_BOOTSTRAP_TEMPLATE_SHA:?STAGING_PRIMARY_BOOTSTRAP_TEMPLATE_SHA is required}"
: "${STAGING_EDGE_BOOTSTRAP_TEMPLATE:?STAGING_EDGE_BOOTSTRAP_TEMPLATE is required}"
: "${STAGING_EDGE_BOOTSTRAP_TEMPLATE_SHA:?STAGING_EDGE_BOOTSTRAP_TEMPLATE_SHA is required}"
: "${PRODUCTION_PRIMARY_BOOTSTRAP_TEMPLATE:?PRODUCTION_PRIMARY_BOOTSTRAP_TEMPLATE is required}"
: "${PRODUCTION_PRIMARY_BOOTSTRAP_TEMPLATE_SHA:?PRODUCTION_PRIMARY_BOOTSTRAP_TEMPLATE_SHA is required}"
: "${PRODUCTION_EDGE_BOOTSTRAP_TEMPLATE:?PRODUCTION_EDGE_BOOTSTRAP_TEMPLATE is required}"
: "${PRODUCTION_EDGE_BOOTSTRAP_TEMPLATE_SHA:?PRODUCTION_EDGE_BOOTSTRAP_TEMPLATE_SHA is required}"
: "${IAM_FOUNDATION_TEMPLATE:?IAM_FOUNDATION_TEMPLATE is required}"
: "${IAM_FOUNDATION_TEMPLATE_SHA:?IAM_FOUNDATION_TEMPLATE_SHA is required}"
: "${IAM_FOUNDATION_CANONICAL_JSON:?IAM_FOUNDATION_CANONICAL_JSON is required}"
: "${IAM_FOUNDATION_SEMANTIC_SHA:?IAM_FOUNDATION_SEMANTIC_SHA is required}"
: "${IAM_FOUNDATION_YQ_BIN:?IAM_FOUNDATION_YQ_BIN is required}"
: "${IAM_FOUNDATION_YQ_SHA:?IAM_FOUNDATION_YQ_SHA is required}"
: "${PINNED_BOOTSTRAP_VERSION:?PINNED_BOOTSTRAP_VERSION is required}"
: "${FOUNDATION_POLICY_ACTUAL_SHA:?FOUNDATION_POLICY_ACTUAL_SHA is required}"
: "${STAGING_CLOUDFRONT_DOMAIN_NAME:?STAGING_CLOUDFRONT_DOMAIN_NAME is required}"
: "${STAGING_CLOUDFRONT_HOSTED_ZONE_ID:?STAGING_CLOUDFRONT_HOSTED_ZONE_ID is required}"
: "${PRODUCTION_CLOUDFRONT_DOMAIN_NAME:?PRODUCTION_CLOUDFRONT_DOMAIN_NAME is required}"
: "${PRODUCTION_CLOUDFRONT_HOSTED_ZONE_ID:?PRODUCTION_CLOUDFRONT_HOSTED_ZONE_ID is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256="${AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256:-}"

[[ "${EXPECTED_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]]
[[ "${CONTROL_PLANE_SHA}" =~ ^[0-9a-f]{40}$ ]]
[[ "${BOOTSTRAP_TEMPLATE_SHA}" =~ ^[0-9a-f]{64}$ ]]
[[ "${IAM_FOUNDATION_TEMPLATE_SHA}" =~ ^[0-9a-f]{64}$ ]]
[[ "${IAM_FOUNDATION_SEMANTIC_SHA}" =~ ^[0-9a-f]{64}$ ]]
[[ "${IAM_FOUNDATION_YQ_SHA}" =~ ^[0-9a-f]{64}$ ]]
[[ "${FOUNDATION_POLICY_ACTUAL_SHA}" =~ ^[0-9a-f]{64}$ ]]
if [[ -n "${AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256}" ]]; then
  [[ "${AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256}" =~ ^[0-9a-f]{64}$ ]]
fi
test "${PINNED_BOOTSTRAP_VERSION}" = "32"
readonly DNS_NAME_PATTERN='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$'
readonly HOSTED_ZONE_ID_PATTERN='^Z[A-Z0-9]{1,31}$'
[[ "${STAGING_CLOUDFRONT_DOMAIN_NAME}" =~ ${DNS_NAME_PATTERN} ]]
[[ "${PRODUCTION_CLOUDFRONT_DOMAIN_NAME}" =~ ${DNS_NAME_PATTERN} ]]
[[ "${STAGING_CLOUDFRONT_HOSTED_ZONE_ID}" =~ ${HOSTED_ZONE_ID_PATTERN} ]]
[[ "${PRODUCTION_CLOUDFRONT_HOSTED_ZONE_ID}" =~ ${HOSTED_ZONE_ID_PATTERN} ]]
test "${STAGING_CLOUDFRONT_DOMAIN_NAME}" != \
  "${PRODUCTION_CLOUDFRONT_DOMAIN_NAME}"

readonly PRIMARY_REGION="eu-west-1"
readonly EDGE_REGION="us-east-1"
readonly CFN_DRIFT_MAX_ATTEMPTS=120
readonly CFN_DRIFT_DELAY_SECONDS=2
readonly CFN_DRIFT_MAX_API_FAILURES=3
readonly CFN_DRIFT_PHASE_TIMEOUT_SECONDS=900
readonly SHARED_API_STACK="Archon-Shared-ApiGateway-Logging"
readonly SHARED_API_ROLE="archon-datahub-apigateway-cloudwatch-logs"
readonly CANARY_ROLE_STACK="Archon-Governed-Canary-Roles"
readonly LEGACY_DEPLOY_ROLE="archon-datahub-github-deploy"
readonly EVIDENCE_DIR="${RUNNER_TEMP}/aws-foundation-evidence"
readonly FAILURE_EVIDENCE_DIR="${RUNNER_TEMP}/aws-foundation-failure"
shared_api_gateway_mode=""
shared_api_gateway_observed_role_arn=""
shared_api_gateway_observed_binding_sha=""
shared_api_gateway_preflight_mode=""
shared_api_gateway_preflight_binding_sha=""
shared_role_binding_sha=""
shared_policy_sha=""
shared_template_sha=""
shared_api_gateway_json=""
drift_stack_count=0

declare -A BOOTSTRAP_STACK=(
  [staging]="CDKToolkit-archonstg"
  [production]="CDKToolkit-archonprd"
)
declare -A BOOTSTRAP_TEMPLATE_BY_TARGET=(
  [staging:eu-west-1]="${STAGING_PRIMARY_BOOTSTRAP_TEMPLATE}"
  [staging:us-east-1]="${STAGING_EDGE_BOOTSTRAP_TEMPLATE}"
  [production:eu-west-1]="${PRODUCTION_PRIMARY_BOOTSTRAP_TEMPLATE}"
  [production:us-east-1]="${PRODUCTION_EDGE_BOOTSTRAP_TEMPLATE}"
)
declare -A BOOTSTRAP_TEMPLATE_SHA_BY_TARGET=(
  [staging:eu-west-1]="${STAGING_PRIMARY_BOOTSTRAP_TEMPLATE_SHA}"
  [staging:us-east-1]="${STAGING_EDGE_BOOTSTRAP_TEMPLATE_SHA}"
  [production:eu-west-1]="${PRODUCTION_PRIMARY_BOOTSTRAP_TEMPLATE_SHA}"
  [production:us-east-1]="${PRODUCTION_EDGE_BOOTSTRAP_TEMPLATE_SHA}"
)
declare -A QUALIFIER=(
  [staging]="archonstg"
  [production]="archonprd"
)
declare -A IAM_STACK=(
  [staging]="Archon-Staging-IAM-Foundation"
  [production]="Archon-Production-IAM-Foundation"
)
readonly -a EXECUTION_POLICY_FAMILIES=(
  guard
  identity
  data
  state
  observability
  compute
  network
  endpoint
  delivery
  edge
)
declare -A BOUNDARY_NAME=(
  [staging]="archon-datahub-runtime-boundary-staging"
  [production]="archon-datahub-runtime-boundary-production"
)
declare -A DEPLOY_STACK=(
  [staging]="Archon-GitHub-Staging-Deploy-Role"
  [production]="Archon-GitHub-Production-Deploy-Role"
)
declare -A DEPLOY_ROLE=(
  [staging]="archon-datahub-github-staging-deploy"
  [production]="archon-datahub-github-production-deploy"
)
declare -A CLOUDFRONT_DOMAIN_NAME=(
  [staging]="${STAGING_CLOUDFRONT_DOMAIN_NAME}"
  [production]="${PRODUCTION_CLOUDFRONT_DOMAIN_NAME}"
)
declare -A CLOUDFRONT_HOSTED_ZONE_ID=(
  [staging]="${STAGING_CLOUDFRONT_HOSTED_ZONE_ID}"
  [production]="${PRODUCTION_CLOUDFRONT_HOSTED_ZONE_ID}"
)
readonly -a CANARY_ROLE_KINDS=(
  prepare
  approval
  recovery
)
declare -A CANARY_ROLE=(
  [prepare]="archon-datahub-github-governed-canary-prepare"
  [approval]="archon-datahub-github-governed-canary-approval"
  [recovery]="archon-datahub-github-governed-canary-recovery"
)
declare -A CANARY_ENVIRONMENT=(
  [prepare]="governed-canary-prepare"
  [approval]="governed-canary"
  [recovery]="governed-canary-recovery"
)
declare -A CANARY_POLICY=(
  [prepare]="archon-staging-stack-read"
  [approval]="archon-staging-approval-read"
  [recovery]="archon-staging-stack-read"
)
declare -A EXECUTION_POLICY_ARN
declare -A EXECUTION_POLICY_ARNS_BY_TARGET
declare -A BOUNDARY_ARN
declare -A EXECUTION_POLICY_SHA
declare -A BOUNDARY_SHA
declare -A DEPLOY_POLICY_SHA
declare -A DEPLOY_ROLE_BINDING_SHA
declare -A IAM_TEMPLATE_SHA
declare -A DEPLOY_TEMPLATE_SHA
declare -A CANARY_POLICY_SHA
declare -A CANARY_ROLE_BINDING_SHA
declare -A OPERATIONAL_ROLE_BINDING_SHA
application_stack_roles_json='[]'
application_stack_role_transition_json=''

revalidate_master() {
  local remote_sha
  local region
  local stage
  local target
  remote_sha="$(
    gh api \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2026-03-10" \
      "/repos/${GITHUB_REPOSITORY}/git/ref/heads/master" |
      jq -er '.object.sha'
  )"
  test "${remote_sha}" = "${CONTROL_PLANE_SHA}"
  test "$(git rev-parse HEAD)" = "${CONTROL_PLANE_SHA}"
  test -z "$(git status --porcelain --untracked-files=all)"
  test "$(sha256sum "${BOOTSTRAP_TEMPLATE}" | awk '{print $1}')" = \
    "${BOOTSTRAP_TEMPLATE_SHA}"
  test -f "${IAM_FOUNDATION_TEMPLATE}"
  test ! -L "${IAM_FOUNDATION_TEMPLATE}"
  test "$(sha256sum "${IAM_FOUNDATION_TEMPLATE}" | awk '{print $1}')" = \
    "${IAM_FOUNDATION_TEMPLATE_SHA}"
  test "$(wc -c <"${IAM_FOUNDATION_TEMPLATE}" | tr -d '[:space:]')" \
    -le 51200
  test -f "${IAM_FOUNDATION_CANONICAL_JSON}"
  test ! -L "${IAM_FOUNDATION_CANONICAL_JSON}"
  test "$(
    sha256sum "${IAM_FOUNDATION_CANONICAL_JSON}" |
      awk '{print $1}'
  )" = "${IAM_FOUNDATION_SEMANTIC_SHA}"
  jq -e '
    type == "object" and
    (.Resources | type == "object" and length > 0)
  ' "${IAM_FOUNDATION_CANONICAL_JSON}" >/dev/null
  test -f "${IAM_FOUNDATION_YQ_BIN}"
  test ! -L "${IAM_FOUNDATION_YQ_BIN}"
  test -x "${IAM_FOUNDATION_YQ_BIN}"
  test "${IAM_FOUNDATION_YQ_SHA}" = "$(
    jq -er \
      '.aws.inlineTemplateRendering.yamlParser.linuxAmd64Sha256' \
      contracts/aws-foundation-v1.json
  )"
  test "$(sha256sum "${IAM_FOUNDATION_YQ_BIN}" | awk '{print $1}')" = \
    "${IAM_FOUNDATION_YQ_SHA}"
  for stage in staging production; do
    for region in "${PRIMARY_REGION}" "${EDGE_REGION}"; do
      target="${stage}:${region}"
      test "$(
        sha256sum "${BOOTSTRAP_TEMPLATE_BY_TARGET[${target}]}" |
          awk '{print $1}'
      )" = "${BOOTSTRAP_TEMPLATE_SHA_BY_TARGET[${target}]}"
    done
  done
}

assert_diagnostic_stack_allowlisted() {
  local stack_label="$1"
  local region="$2"
  local stack_name="$3"
  case "${stack_label}|${region}|${stack_name}" in
    "staging-iam|${PRIMARY_REGION}|${IAM_STACK[staging]}" | \
      "production-iam|${PRIMARY_REGION}|${IAM_STACK[production]}" | \
      "staging-deploy|${PRIMARY_REGION}|${DEPLOY_STACK[staging]}" | \
      "production-deploy|${PRIMARY_REGION}|${DEPLOY_STACK[production]}" | \
      "staging-bootstrap-primary|${PRIMARY_REGION}|${BOOTSTRAP_STACK[staging]}" | \
      "staging-bootstrap-edge|${EDGE_REGION}|${BOOTSTRAP_STACK[staging]}" | \
      "production-bootstrap-primary|${PRIMARY_REGION}|${BOOTSTRAP_STACK[production]}" | \
      "production-bootstrap-edge|${EDGE_REGION}|${BOOTSTRAP_STACK[production]}" | \
      "shared-api-gateway|${PRIMARY_REGION}|${SHARED_API_STACK}" | \
      "governed-canary-roles|${PRIMARY_REGION}|${CANARY_ROLE_STACK}")
      return 0
      ;;
  esac
  echo "::error::Refusing CloudFormation diagnostics for a non-allowlisted stack label" >&2
  return 1
}

cleanup_failure_evidence_staging() {
  local staging_dir="$1"
  if [[ "${staging_dir}" != "${FAILURE_EVIDENCE_DIR}.staging" ]]; then
    return 1
  fi
  if [[ ! -e "${staging_dir}" && ! -L "${staging_dir}" ]]; then
    return 0
  fi
  if [[ ! -d "${staging_dir}" || -L "${staging_dir}" ]]; then
    return 1
  fi
  rm -f -- \
    "${staging_dir}/.cfn-failure.json.tmp" \
    "${staging_dir}/.cfn-failure.canonical.tmp" \
    "${staging_dir}/cfn-failure.json" \
    "${staging_dir}/SHA256SUMS" 2>/dev/null || true
  rmdir -- "${staging_dir}" 2>/dev/null
}

capture_managed_stack_failure() {
  local stack_label="$1"
  local region="$2"
  local stack_name="$3"
  local stack_status="${4:-}"
  local staging_dir="${FAILURE_EVIDENCE_DIR}.staging"
  local diagnostic_tmp="${staging_dir}/.cfn-failure.json.tmp"
  local canonical_tmp="${staging_dir}/.cfn-failure.canonical.tmp"
  local canonical_safe_json
  local computed_digest
  local actual_inventory_sha
  local expected_inventory_sha

  if ! assert_diagnostic_stack_allowlisted \
    "${stack_label}" "${region}" "${stack_name}"; then
    return 1
  fi
  if [[ -z "${stack_status}" ]]; then
    if ! stack_status="$(
      aws cloudformation describe-stacks \
        --region "${region}" \
        --stack-name "${stack_name}" \
        --query 'Stacks[0].StackStatus' \
        --output text 2>/dev/null
    )"; then
      stack_status="UNKNOWN"
    fi
  fi
  case "${stack_status}" in
    CREATE_COMPLETE | CREATE_FAILED | CREATE_IN_PROGRESS | \
      DELETE_COMPLETE | DELETE_FAILED | DELETE_IN_PROGRESS | \
      IMPORT_COMPLETE | IMPORT_IN_PROGRESS | IMPORT_ROLLBACK_COMPLETE | \
      IMPORT_ROLLBACK_FAILED | IMPORT_ROLLBACK_IN_PROGRESS | \
      REVIEW_IN_PROGRESS | ROLLBACK_COMPLETE | ROLLBACK_FAILED | \
      ROLLBACK_IN_PROGRESS | UPDATE_COMPLETE | \
      UPDATE_COMPLETE_CLEANUP_IN_PROGRESS | UPDATE_FAILED | \
      UPDATE_IN_PROGRESS | UPDATE_ROLLBACK_COMPLETE | \
      UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS | \
      UPDATE_ROLLBACK_FAILED | UPDATE_ROLLBACK_IN_PROGRESS)
      ;;
    *)
      stack_status="UNKNOWN"
      ;;
  esac

  if [[ -e "${FAILURE_EVIDENCE_DIR}" || -L "${FAILURE_EVIDENCE_DIR}" || \
    -e "${staging_dir}" || -L "${staging_dir}" ]]; then
    echo "::error::Sanitized CloudFormation failure evidence already exists" >&2
    return 1
  fi
  if ! install -d -m 0700 "${staging_dir}"; then
    echo "::error::Unable to stage sanitized CloudFormation failure evidence" >&2
    return 1
  fi
  if [[ ! -d "${staging_dir}" || -L "${staging_dir}" ]]; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Invalid sanitized CloudFormation failure staging directory" >&2
    return 1
  fi
  if ! aws cloudformation describe-stack-events \
    --region "${region}" \
    --stack-name "${stack_name}" \
    --max-items 100 \
    --output json 2>/dev/null |
    node scripts/sanitize-cloudformation-failure.mjs \
      --stack-label "${stack_label}" \
      --stack-status "${stack_status}" >"${diagnostic_tmp}"; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Unable to author sanitized CloudFormation failure evidence for the allowlisted stack label" >&2
    return 1
  fi
  if ! test "$(wc -c <"${diagnostic_tmp}")" -le 2048; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Sanitized CloudFormation failure evidence exceeded its size limit" >&2
    return 1
  fi
  if ! jq -cS . "${diagnostic_tmp}" >"${canonical_tmp}" 2>/dev/null; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Sanitized CloudFormation failure evidence was not valid JSON" >&2
    return 1
  fi
  if ! cmp -s "${diagnostic_tmp}" "${canonical_tmp}"; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Sanitized CloudFormation failure evidence was not canonical" >&2
    return 1
  fi
  if ! rm -f -- "${canonical_tmp}"; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Unable to finalize sanitized CloudFormation failure evidence" >&2
    return 1
  fi
  if ! jq -e '
    (keys | sort) == [
      "diagnosticSha256",
      "logicalResourceId",
      "reasonCategory",
      "resourceStatus",
      "resourceType",
      "schemaVersion",
      "stackLabel",
      "stackStatus"
    ] and
    .schemaVersion == "archon.aws-foundation-cfn-failure/v1" and
    (.diagnosticSha256 | test("^[0-9a-f]{64}$"))
  ' "${diagnostic_tmp}" >/dev/null 2>&1; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Sanitized CloudFormation failure evidence failed schema validation" >&2
    return 1
  fi
  if ! canonical_safe_json="$(
    jq -cS '{
      logicalResourceId,
      reasonCategory,
      resourceStatus,
      resourceType,
      schemaVersion,
      stackLabel,
      stackStatus
    }' "${diagnostic_tmp}" 2>/dev/null
  )"; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Unable to canonicalize sanitized diagnostic fields" >&2
    return 1
  fi
  if ! computed_digest="$(
    printf '%s' "${canonical_safe_json}" |
      sha256sum |
      awk '{print $1}'
  )"; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Unable to recompute the sanitized diagnostic digest" >&2
    return 1
  fi
  if [[ ! "${computed_digest}" =~ ^[0-9a-f]{64}$ ]] || \
    ! jq -e --arg computedDigest "${computed_digest}" \
      '.diagnosticSha256 == $computedDigest' \
      "${diagnostic_tmp}" >/dev/null 2>&1; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Sanitized CloudFormation diagnostic digest mismatch" >&2
    return 1
  fi
  if ! mv -T -- "${diagnostic_tmp}" "${staging_dir}/cfn-failure.json"; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Unable to finalize sanitized CloudFormation failure evidence" >&2
    return 1
  fi
  if ! (
    cd "${staging_dir}" &&
      sha256sum cfn-failure.json >SHA256SUMS &&
      test "$(wc -l <SHA256SUMS)" -eq 1 &&
      grep -Eq '^[0-9a-f]{64}  cfn-failure.json$' SHA256SUMS &&
      sha256sum --check --strict SHA256SUMS >/dev/null 2>&1
  ); then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Unable to checksum-seal sanitized CloudFormation failure evidence" >&2
    return 1
  fi
  if ! actual_inventory_sha="$(
    find -P "${staging_dir}" -mindepth 1 -printf '%P\t%y\0' |
      LC_ALL=C sort -z |
      sha256sum |
      awk '{print $1}'
  )"; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Unable to inventory sanitized CloudFormation failure evidence" >&2
    return 1
  fi
  if ! expected_inventory_sha="$(
    printf 'SHA256SUMS\tf\0cfn-failure.json\tf\0' |
      sha256sum |
      awk '{print $1}'
  )"; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Unable to derive the expected failure evidence inventory" >&2
    return 1
  fi
  if [[ ! "${actual_inventory_sha}" =~ ^[0-9a-f]{64}$ || \
    "${actual_inventory_sha}" != "${expected_inventory_sha}" ]]; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Sanitized CloudFormation failure evidence inventory mismatch" >&2
    return 1
  fi
  if [[ -e "${FAILURE_EVIDENCE_DIR}" || -L "${FAILURE_EVIDENCE_DIR}" ]]; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Sanitized CloudFormation failure evidence destination appeared during capture" >&2
    return 1
  fi
  if ! mv -T -- "${staging_dir}" "${FAILURE_EVIDENCE_DIR}"; then
    cleanup_failure_evidence_staging "${staging_dir}" >/dev/null 2>&1 || true
    echo "::error::Unable to publish sanitized CloudFormation failure evidence" >&2
    return 1
  fi
  if [[ ! -d "${FAILURE_EVIDENCE_DIR}" || -L "${FAILURE_EVIDENCE_DIR}" ]]; then
    echo "::error::Published sanitized CloudFormation failure evidence is invalid" >&2
    return 1
  fi
  printf '::notice::Sealed sanitized CloudFormation failure evidence for stack label %s\n' \
    "${stack_label}"
  return 0
}

run_managed_stack_command() {
  local stack_label="$1"
  local region="$2"
  local stack_name="$3"
  local command_status
  shift 3

  if ! assert_diagnostic_stack_allowlisted \
    "${stack_label}" "${region}" "${stack_name}"; then
    return 1
  fi
  if "$@" >/dev/null 2>&1; then
    return 0
  else
    command_status="$?"
  fi
  if ! capture_managed_stack_failure \
    "${stack_label}" "${region}" "${stack_name}"; then
    echo "::error::Managed stack command failed and sanitized diagnostic capture was unavailable" >&2
  fi
  return "${command_status}"
}

assert_stack_role_is_null_if_present() {
  local stack_label="$1"
  local region="$2"
  local stack_name="$3"
  local output="${RUNNER_TEMP}/stack-role-${region}-${stack_name}.json"
  local error="${output}.error"
  local stack_status

  if ! assert_diagnostic_stack_allowlisted \
    "${stack_label}" "${region}" "${stack_name}"; then
    return 1
  fi
  if aws cloudformation describe-stacks \
    --region "${region}" \
    --stack-name "${stack_name}" \
    --output json >"${output}" 2>"${error}"; then
    jq -e '
      (.Stacks | length) == 1 and
      ((.Stacks[0].RoleARN // "") == "")
    ' "${output}" >/dev/null
    stack_status="$(jq -er '.Stacks[0].StackStatus' "${output}")"
    case "${stack_status}" in
      CREATE_COMPLETE | UPDATE_COMPLETE | UPDATE_ROLLBACK_COMPLETE | \
        IMPORT_COMPLETE | IMPORT_ROLLBACK_COMPLETE)
        ;;
      ROLLBACK_COMPLETE | *_FAILED)
        if ! capture_managed_stack_failure \
          "${stack_label}" "${region}" "${stack_name}" "${stack_status}"; then
          echo "::error::Blocked managed stack state could not be sanitized" >&2
        fi
        printf \
          '::error title=Blocked managed foundation stack state::stackLabel=%s; stackStatus=%s\n' \
          "${stack_label}" "${stack_status}" >&2
        return 1
        ;;
      *)
        printf \
          '::error title=Managed foundation stack is not update-safe::stackLabel=%s; stackStatus=%s\n' \
          "${stack_label}" "${stack_status}" >&2
        return 1
        ;;
    esac
  else
    grep -Eq 'does not exist|ValidationError' "${error}"
  fi
}

assert_stack_complete_without_service_role() {
  local region="$1"
  local stack_name="$2"
  local output="$3"
  aws cloudformation describe-stacks \
    --region "${region}" \
    --stack-name "${stack_name}" \
    --output json >"${output}"
  jq -e --arg stack "${stack_name}" '
    (.Stacks | length) == 1 and
    .Stacks[0].StackName == $stack and
    ((.Stacks[0].RoleARN // "") == "") and
    .Stacks[0].EnableTerminationProtection == true and
    (
      .Stacks[0].StackStatus == "CREATE_COMPLETE" or
      .Stacks[0].StackStatus == "UPDATE_COMPLETE"
    )
  ' "${output}" >/dev/null
}

assert_application_stack_role_exact_if_present() {
  local stage="$1"
  local region="$2"
  local stack_name="$3"
  local expected_role="$4"
  local output="${RUNNER_TEMP}/application-role-${region}-${stack_name}.json"
  local error="${output}.error"
  local status
  local validation
  if aws cloudformation describe-stacks \
    --region "${region}" \
    --stack-name "${stack_name}" \
    --output json >"${output}" 2>"${error}"; then
    jq -e --arg stack "${stack_name}" '
      (.Stacks | length) == 1 and
      .Stacks[0].StackName == $stack and
      (
        .Stacks[0].StackStatus == "CREATE_COMPLETE" or
        .Stacks[0].StackStatus == "UPDATE_COMPLETE" or
        .Stacks[0].StackStatus == "UPDATE_ROLLBACK_COMPLETE" or
        .Stacks[0].StackStatus == "IMPORT_COMPLETE" or
        .Stacks[0].StackStatus == "IMPORT_ROLLBACK_COMPLETE"
      )
    ' "${output}" >/dev/null
    if jq -e --arg stack "${stack_name}" --arg role "${expected_role}" '
      (.Stacks | length) == 1 and
      .Stacks[0].StackName == $stack and
      .Stacks[0].RoleARN == $role
    ' "${output}" >/dev/null; then
      status="exact-stage-cfn-exec-role"
      validation="passed"
    else
      status="migration-required"
      validation="requires-explicit-deploy-migration"
    fi
  else
    grep -Eq 'does not exist|ValidationError' "${error}"
    status="not-yet-created"
    validation="passed"
  fi
  application_stack_roles_json="$(
    jq -cnS \
      --argjson current "${application_stack_roles_json}" \
      --arg stage "${stage}" \
      --arg region "${region}" \
      --arg stackName "${stack_name}" \
      --arg status "${status}" \
      --arg validation "${validation}" '
        $current + [{
          region: $region,
          stackName: $stackName,
          stage: $stage,
          status: $status,
          validation: $validation
        }]
      '
  )"
}

assert_stack_absent() {
  local region="$1"
  local stack_name="$2"
  local output="${RUNNER_TEMP}/absent-stack-${region}-${stack_name}.json"
  local error="${output}.error"
  if aws cloudformation describe-stacks \
    --region "${region}" \
    --stack-name "${stack_name}" \
    --output json >"${output}" 2>"${error}"; then
    echo "::error::external API Gateway binding cannot coexist with the Archon managed stack"
    return 1
  fi
  grep -Eq 'does not exist|ValidationError' "${error}"
}

inspect_api_gateway_binding() {
  local account_json="${RUNNER_TEMP}/api-gateway-account-binding.json"
  local expected_arn="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/${SHARED_API_ROLE}"
  local observed
  local observed_sha
  aws apigateway get-account \
    --region "${PRIMARY_REGION}" \
    --output json >"${account_json}"
  observed="$(jq -er '(.cloudwatchRoleArn // "") | select(type == "string")' "${account_json}")"
  if [[ -n "${observed}" ]]; then
    echo "::add-mask::${observed}"
  fi
  observed_sha="$(printf '%s' "${observed}" | sha256sum | awk '{print $1}')"
  if [[ -z "${observed}" ]]; then
    if [[ -n "${AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256}" ]]; then
      echo "::error::clear the stale external API Gateway binding pin before managed reconciliation"
      return 1
    fi
    shared_api_gateway_mode="foundation-managed"
  elif [[ "${observed}" == "${expected_arn}" ]]; then
    if [[ -n "${AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256}" ]]; then
      echo "::error::clear the stale external API Gateway binding pin before managed reconciliation"
      return 1
    fi
    assert_stack_complete_without_service_role \
      "${PRIMARY_REGION}" \
      "${SHARED_API_STACK}" \
      "${RUNNER_TEMP}/managed-shared-api-stack-preflight.json"
    shared_api_gateway_mode="foundation-managed"
  else
    if [[ ! "${observed}" =~ ^arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/([A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]{1,64}$ ]]; then
      echo "::error::the existing API Gateway CloudWatch role is not one same-account role ARN"
      return 1
    fi
    if [[ "${AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256}" != "${observed_sha}" ]]; then
      echo "::error title=Pin existing API Gateway logging role::AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256=${observed_sha}"
      return 1
    fi
    assert_stack_absent "${PRIMARY_REGION}" "${SHARED_API_STACK}"
    shared_api_gateway_mode="external-pinned"
  fi
  shared_api_gateway_observed_role_arn="${observed}"
  shared_api_gateway_observed_binding_sha="${observed_sha}"
}

get_managed_policy_document() {
  local policy_arn="$1"
  local output="$2"
  local metadata="${output}.metadata"
  aws iam get-policy --policy-arn "${policy_arn}" --output json >"${metadata}"
  aws iam get-policy-version \
    --policy-arn "${policy_arn}" \
    --version-id "$(jq -er '.Policy.DefaultVersionId' "${metadata}")" \
    --output json >"${output}"
}

canonical_policy_sha() {
  local document="$1"
  jq -cS '.PolicyVersion.Document // .PolicyDocument' "${document}" |
    sha256sum |
    awk '{print $1}'
}

expected_execution_policy_arns() {
  local stage="$1"
  local region="$2"
  local -a families
  local family
  local rendered=()
  if [[ "${region}" == "${PRIMARY_REGION}" ]]; then
    families=(
      guard
      identity
      data
      state
      observability
      compute
      network
      endpoint
      delivery
    )
  else
    families=(guard edge)
  fi
  for family in "${families[@]}"; do
    rendered+=(
      "arn:aws:iam::${EXPECTED_ACCOUNT_ID}:policy/archon-datahub-cdk-${family}-${stage}"
    )
  done
  local IFS=,
  printf '%s' "${rendered[*]}"
}

deployed_template_sha() {
  local region="$1"
  local stack_name="$2"
  local response
  local body
  response="$(mktemp "${RUNNER_TEMP}/archon-deployed-template.XXXXXX.json")"
  body="$(mktemp "${RUNNER_TEMP}/archon-deployed-template.XXXXXX.body")"
  aws cloudformation get-template \
    --region "${region}" \
    --stack-name "${stack_name}" \
    --template-stage Original \
    --output json >"${response}"
  jq -er '
    .TemplateBody |
    if type == "string" then . else tojson end
  ' "${response}" >"${body}"
  "${IAM_FOUNDATION_YQ_BIN}" \
    --output-format=json \
    --indent 0 \
    '.' \
    "${body}" |
    jq -cS . |
    sha256sum |
    awk '{print $1}'
}

foundation_phase='preflight:revalidate-master'
echo "::group::Fail-closed AWS foundation preflight"
revalidate_master
foundation_phase='preflight:validate-template:api-gateway-account'
aws cloudformation validate-template \
  --region "${PRIMARY_REGION}" \
  --template-body 'file://infra/aws/foundation/api-gateway-account.yml' >/dev/null
foundation_phase='preflight:validate-template:iam-foundation'
aws cloudformation validate-template \
  --region "${PRIMARY_REGION}" \
  --template-body "file://${IAM_FOUNDATION_TEMPLATE}" >/dev/null
foundation_phase='preflight:validate-template:github-actions-deploy-role'
aws cloudformation validate-template \
  --region "${PRIMARY_REGION}" \
  --template-body 'file://infra/aws/foundation/github-actions-deploy-role.yml' >/dev/null
foundation_phase='preflight:validate-template:github-actions-foundation-role'
aws cloudformation validate-template \
  --region "${PRIMARY_REGION}" \
  --template-body 'file://infra/aws/foundation/github-actions-foundation-role.yml' >/dev/null
foundation_phase='preflight:validate-template:governed-canary-roles'
aws cloudformation validate-template \
  --region "${PRIMARY_REGION}" \
  --template-body 'file://infra/aws/foundation/governed-canary-roles.yml' >/dev/null
foundation_phase='preflight:validate-template:bootstrap:staging:eu-west-1'
aws cloudformation validate-template \
  --region "${PRIMARY_REGION}" \
  --template-body "file://${BOOTSTRAP_TEMPLATE_BY_TARGET[staging:eu-west-1]}" >/dev/null
foundation_phase='preflight:validate-template:bootstrap:staging:us-east-1'
aws cloudformation validate-template \
  --region "${PRIMARY_REGION}" \
  --template-body "file://${BOOTSTRAP_TEMPLATE_BY_TARGET[staging:us-east-1]}" >/dev/null
foundation_phase='preflight:validate-template:bootstrap:production:eu-west-1'
aws cloudformation validate-template \
  --region "${PRIMARY_REGION}" \
  --template-body "file://${BOOTSTRAP_TEMPLATE_BY_TARGET[production:eu-west-1]}" >/dev/null
foundation_phase='preflight:validate-template:bootstrap:production:us-east-1'
aws cloudformation validate-template \
  --region "${PRIMARY_REGION}" \
  --template-body "file://${BOOTSTRAP_TEMPLATE_BY_TARGET[production:us-east-1]}" >/dev/null

foundation_phase='preflight:legacy-role'
legacy_error="${RUNNER_TEMP}/legacy-deploy-role.error"
if aws iam get-role \
  --role-name "${LEGACY_DEPLOY_ROLE}" \
  --output json >/dev/null 2>"${legacy_error}"; then
  echo "::error::Legacy dual-environment GitHub deploy role still exists"
  exit 1
fi
grep -q 'NoSuchEntity' "${legacy_error}"

foundation_phase='preflight:legacy-stacks'
legacy_stacks="$(
  aws cloudformation list-stacks \
    --region "${PRIMARY_REGION}" \
    --stack-status-filter \
      CREATE_COMPLETE \
      UPDATE_COMPLETE \
      UPDATE_ROLLBACK_COMPLETE \
      IMPORT_COMPLETE \
      IMPORT_ROLLBACK_COMPLETE \
    --output json
)"
jq -e '
  [
    .StackSummaries[]?.StackName |
    select(
      . == "Archon-GitHub-Deploy-Role" or
      . == "Archon-CDK-Execution-Policy"
    )
  ] |
  length == 0
' <<<"${legacy_stacks}" >/dev/null

foundation_phase='preflight:foundation-stack-role-binding:staging:iam'
assert_stack_role_is_null_if_present "staging-iam" "${PRIMARY_REGION}" "${IAM_STACK[staging]}"
foundation_phase='preflight:foundation-stack-role-binding:staging:deploy'
assert_stack_role_is_null_if_present "staging-deploy" "${PRIMARY_REGION}" "${DEPLOY_STACK[staging]}"
foundation_phase='preflight:foundation-stack-role-binding:staging:bootstrap:eu-west-1'
assert_stack_role_is_null_if_present "staging-bootstrap-primary" "${PRIMARY_REGION}" "${BOOTSTRAP_STACK[staging]}"
foundation_phase='preflight:foundation-stack-role-binding:staging:bootstrap:us-east-1'
assert_stack_role_is_null_if_present "staging-bootstrap-edge" "${EDGE_REGION}" "${BOOTSTRAP_STACK[staging]}"
foundation_phase='preflight:foundation-stack-role-binding:production:iam'
assert_stack_role_is_null_if_present "production-iam" "${PRIMARY_REGION}" "${IAM_STACK[production]}"
foundation_phase='preflight:foundation-stack-role-binding:production:deploy'
assert_stack_role_is_null_if_present "production-deploy" "${PRIMARY_REGION}" "${DEPLOY_STACK[production]}"
foundation_phase='preflight:foundation-stack-role-binding:production:bootstrap:eu-west-1'
assert_stack_role_is_null_if_present "production-bootstrap-primary" "${PRIMARY_REGION}" "${BOOTSTRAP_STACK[production]}"
foundation_phase='preflight:foundation-stack-role-binding:production:bootstrap:us-east-1'
assert_stack_role_is_null_if_present "production-bootstrap-edge" "${EDGE_REGION}" "${BOOTSTRAP_STACK[production]}"
foundation_phase='preflight:foundation-stack-role-binding:shared-api'
assert_stack_role_is_null_if_present "shared-api-gateway" "${PRIMARY_REGION}" "${SHARED_API_STACK}"
foundation_phase='preflight:foundation-stack-role-binding:governed-canary'
assert_stack_role_is_null_if_present "governed-canary-roles" "${PRIMARY_REGION}" "${CANARY_ROLE_STACK}"
foundation_phase='preflight:shared-api-gateway'
inspect_api_gateway_binding
shared_api_gateway_preflight_mode="${shared_api_gateway_mode}"
shared_api_gateway_preflight_binding_sha="${shared_api_gateway_observed_binding_sha}"
staging_cfn_eu="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/cdk-${QUALIFIER[staging]}-cfn-exec-role-${EXPECTED_ACCOUNT_ID}-${PRIMARY_REGION}"
staging_cfn_us="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/cdk-${QUALIFIER[staging]}-cfn-exec-role-${EXPECTED_ACCOUNT_ID}-${EDGE_REGION}"
production_cfn_eu="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/cdk-${QUALIFIER[production]}-cfn-exec-role-${EXPECTED_ACCOUNT_ID}-${PRIMARY_REGION}"
production_cfn_us="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/cdk-${QUALIFIER[production]}-cfn-exec-role-${EXPECTED_ACCOUNT_ID}-${EDGE_REGION}"
foundation_phase='preflight:application-stack-role-binding:staging:registry'
assert_application_stack_role_exact_if_present \
  staging "${PRIMARY_REGION}" Archon-Registry "${staging_cfn_eu}"
foundation_phase='preflight:application-stack-role-binding:staging:primary'
assert_application_stack_role_exact_if_present \
  staging "${PRIMARY_REGION}" Archon-staging "${staging_cfn_eu}"
foundation_phase='preflight:application-stack-role-binding:staging:edge'
assert_application_stack_role_exact_if_present \
  staging "${EDGE_REGION}" Archon-staging-Edge "${staging_cfn_us}"
foundation_phase='preflight:application-stack-role-binding:production:primary'
assert_application_stack_role_exact_if_present \
  production "${PRIMARY_REGION}" Archon-production "${production_cfn_eu}"
foundation_phase='preflight:application-stack-role-binding:production:edge'
assert_application_stack_role_exact_if_present \
  production "${EDGE_REGION}" Archon-production-Edge "${production_cfn_us}"
foundation_phase='preflight:application-stack-role-transition'
application_stack_role_transition_json="$(
  jq -cnS \
    --argjson entries "${application_stack_roles_json}" '
      ($entries |
        map(select(
          .validation == "requires-explicit-deploy-migration"
        )) |
        length) as $migrationRequiredCount |
      if ($entries | length) != 5 then
        error("application stack role preflight inventory must contain five entries")
      elif (
        all($entries[];
          .validation == "passed" or
          .validation == "requires-explicit-deploy-migration"
        ) |
        not
      ) then
        error("application stack role preflight contains an unsupported result")
      elif $migrationRequiredCount > 0 then
        {
          deployRequirement: "explicit-role-migration",
          foundationOutcome: "passed",
          migrationRequiredCount: $migrationRequiredCount,
          state: "foundation-complete-deploy-migration-required"
        }
      else
        {
          deployRequirement: "exact-role-postcheck",
          foundationOutcome: "passed",
          migrationRequiredCount: 0,
          state: "ready-for-deploy"
        }
      end
    '
)"
application_stack_role_transition_state="$(
  jq -er '.state' <<<"${application_stack_role_transition_json}"
)"
if [[ "${application_stack_role_transition_state}" == \
  "foundation-complete-deploy-migration-required" ]]; then
  migration_required_count="$(
    jq -er '.migrationRequiredCount' \
      <<<"${application_stack_role_transition_json}"
  )"
  echo \
    "::warning::Foundation may complete; ${migration_required_count} application stack RoleARN binding(s) require the explicit deploy migration and exact final deploy postcheck"
fi
echo "::endgroup::"

foundation_phase='stage-iam'
echo "::group::Reconcile stage IAM foundations"
for stage in staging production; do
  revalidate_master
  assert_stack_role_is_null_if_present \
    "${stage}-iam" "${PRIMARY_REGION}" "${IAM_STACK[${stage}]}"
  run_managed_stack_command \
    "${stage}-iam" "${PRIMARY_REGION}" "${IAM_STACK[${stage}]}" \
    aws cloudformation deploy \
    --region "${PRIMARY_REGION}" \
    --stack-name "${IAM_STACK[${stage}]}" \
    --template-file "${IAM_FOUNDATION_TEMPLATE}" \
    --capabilities CAPABILITY_NAMED_IAM \
    --no-fail-on-empty-changeset \
    --parameter-overrides \
      DeploymentEnvironment="${stage}" \
      CloudFrontDomainName="${CLOUDFRONT_DOMAIN_NAME[${stage}]}" \
      CloudFrontHostedZoneId="${CLOUDFRONT_HOSTED_ZONE_ID[${stage}]}" \
    --tags \
      Application=archon-datahub \
      Environment="${stage}" \
      ManagedBy=github-actions \
      Purpose=stage-iam-foundation
  run_managed_stack_command \
    "${stage}-iam" "${PRIMARY_REGION}" "${IAM_STACK[${stage}]}" \
    aws cloudformation update-termination-protection \
    --region "${PRIMARY_REGION}" \
    --stack-name "${IAM_STACK[${stage}]}" \
    --enable-termination-protection

  iam_stack_json="${RUNNER_TEMP}/${stage}-iam-foundation-stack.json"
  assert_stack_complete_without_service_role \
    "${PRIMARY_REGION}" "${IAM_STACK[${stage}]}" "${iam_stack_json}"
  jq -e \
    --arg stage "${stage}" \
    --arg domain "${CLOUDFRONT_DOMAIN_NAME[${stage}]}" \
    --arg zone "${CLOUDFRONT_HOSTED_ZONE_ID[${stage}]}" '
      .Stacks[0].Parameters as $parameters |
      (
        [$parameters[] |
          select(.ParameterKey == "DeploymentEnvironment")][0].ParameterValue
      ) == $stage and
      (
        [$parameters[] |
          select(.ParameterKey == "CloudFrontDomainName")][0].ParameterValue
      ) == $domain and
      (
        [$parameters[] |
          select(.ParameterKey == "CloudFrontHostedZoneId")][0].ParameterValue
      ) == $zone
    ' "${iam_stack_json}" >/dev/null
  EXECUTION_POLICY_ARNS_BY_TARGET["${stage}:${PRIMARY_REGION}"]="$(
    jq -er '
      .Stacks[0].Outputs[] |
      select(.OutputKey == "ArchonCdkEuWest1ExecutionPolicyArns") |
      .OutputValue
    ' "${iam_stack_json}"
  )"
  EXECUTION_POLICY_ARNS_BY_TARGET["${stage}:${EDGE_REGION}"]="$(
    jq -er '
      .Stacks[0].Outputs[] |
      select(.OutputKey == "ArchonCdkUsEast1ExecutionPolicyArns") |
      .OutputValue
    ' "${iam_stack_json}"
  )"
  BOUNDARY_ARN["${stage}"]="$(
    jq -er '
      .Stacks[0].Outputs[] |
      select(.OutputKey == "ArchonRuntimeBoundaryArn") |
      .OutputValue
    ' "${iam_stack_json}"
  )"
  for region in "${PRIMARY_REGION}" "${EDGE_REGION}"; do
    target="${stage}:${region}"
    test "${EXECUTION_POLICY_ARNS_BY_TARGET[${target}]}" = \
      "$(expected_execution_policy_arns "${stage}" "${region}")"
  done
  test "${BOUNDARY_ARN[${stage}]}" = \
    "arn:aws:iam::${EXPECTED_ACCOUNT_ID}:policy/${BOUNDARY_NAME[${stage}]}"
  echo "::add-mask::${BOUNDARY_ARN[${stage}]}"

  execution_policy_bundle="${RUNNER_TEMP}/${stage}-execution-policy-bundle.jsonl"
  : >"${execution_policy_bundle}"
  for family in "${EXECUTION_POLICY_FAMILIES[@]}"; do
    policy_arn="$(
      printf 'arn:aws:iam::%s:policy/archon-datahub-cdk-%s-%s' \
        "${EXPECTED_ACCOUNT_ID}" "${family}" "${stage}"
    )"
    EXECUTION_POLICY_ARN["${stage}:${family}"]="${policy_arn}"
    echo "::add-mask::${policy_arn}"
    execution_document="$(
      printf '%s/%s-execution-policy-%s.json' \
        "${RUNNER_TEMP}" "${stage}" "${family}"
    )"
    get_managed_policy_document "${policy_arn}" "${execution_document}"
    compact_policy_size="$(
      jq -c '.PolicyVersion.Document' "${execution_document}" |
        wc -c |
        awk '{print $1 - 1}'
    )"
    test "${compact_policy_size}" -le 6144
    jq -e '
      (
        [.PolicyVersion.Document.Statement[] |
          select(.Effect == "Allow") |
          .Action] |
        flatten |
        all(
          . != "*" and
          (endswith(":*") | not)
        )
      ) and
      (
        .PolicyVersion.Document |
        tostring |
        contains("AdministratorAccess") |
        not
      )
    ' "${execution_document}" >/dev/null
    jq -cS '.PolicyVersion.Document' "${execution_document}" \
      >>"${execution_policy_bundle}"
  done
  jq -e '
    (
      [.PolicyVersion.Document.Statement[] |
        select(.Sid == "DenySharedApiGatewayAccountMutation")] |
      length
    ) == 1 and
    (
      [.PolicyVersion.Document.Statement[] |
        select(.Sid == "DenyRuntimeBoundaryRemoval")] |
      length
    ) == 1
  ' "${RUNNER_TEMP}/${stage}-execution-policy-guard.json" >/dev/null

  boundary_document="${RUNNER_TEMP}/${stage}-runtime-boundary.json"
  get_managed_policy_document \
    "${BOUNDARY_ARN[${stage}]}" "${boundary_document}"
  boundary_compact_size="$(
    jq -c '.PolicyVersion.Document' "${boundary_document}" |
      wc -c |
      awk '{print $1 - 1}'
  )"
  test "${boundary_compact_size}" -le 6144
  boundary_actions="${RUNNER_TEMP}/${stage}-runtime-boundary-actions.json"
  jq -cS '
    [.PolicyVersion.Document.Statement[] |
      select(.Effect == "Allow") |
      .Action] |
    flatten |
    unique
  ' "${boundary_document}" >"${boundary_actions}"
  jq -cS '.aws.runtimeBoundary.allowedActions | sort' \
    contracts/aws-foundation-v1.json |
    cmp -s - "${boundary_actions}"
  jq -e '
    (
      [.PolicyVersion.Document.Statement[] |
        select(.Sid == "DenyIdentityEscalation")] |
      length
    ) == 1 and
    (
      [.PolicyVersion.Document.Statement[] |
        select(.Sid == "DenyLongTermBedrockMantleTokens")] |
      length
    ) == 1
  ' "${boundary_document}" >/dev/null
  EXECUTION_POLICY_SHA["${stage}"]="$(
    sha256sum "${execution_policy_bundle}" |
      awk '{print $1}'
  )"
  BOUNDARY_SHA["${stage}"]="$(canonical_policy_sha "${boundary_document}")"
  IAM_TEMPLATE_SHA["${stage}"]="$(
    deployed_template_sha "${PRIMARY_REGION}" "${IAM_STACK[${stage}]}"
  )"
  if [[ "${IAM_TEMPLATE_SHA[${stage}]}" != \
    "${IAM_FOUNDATION_SEMANTIC_SHA}" ]]; then
    echo \
      "::error::${stage} deployed Original template does not match the pre-OIDC canonical template" \
      >&2
    exit 1
  fi
done
echo "::endgroup::"

foundation_phase='shared-api-gateway'
echo "::group::Reconcile or pin the shared API Gateway logging account"
revalidate_master
inspect_api_gateway_binding
test "${shared_api_gateway_mode}" = "${shared_api_gateway_preflight_mode}"
test "${shared_api_gateway_observed_binding_sha}" = \
  "${shared_api_gateway_preflight_binding_sha}"
if [[ "${shared_api_gateway_mode}" == "external-pinned" ]]; then
  shared_role_binding_sha="${shared_api_gateway_observed_binding_sha}"
  shared_api_gateway_json="$(
    jq -cnS \
      --arg bindingSha256 "${shared_role_binding_sha}" '
        {
          external: {
            bindingSha256: $bindingSha256,
            bindingSha256Variable:
              "AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256",
            bindingState: "UNCHANGED",
            managedStackAbsent: true,
            mutation: "none",
            roleArnTemplate:
              "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<PINNED_EXTERNAL_ROLE_PATH_AND_NAME>",
            sameAccountRoleArn: true
          },
          managed: null,
          mode: "external-pinned",
          roleBindingSha256: $bindingSha256,
          takeover: "forbidden",
          validation: "pinned-and-unchanged"
        }
      '
  )"
else
  assert_stack_role_is_null_if_present "shared-api-gateway" "${PRIMARY_REGION}" "${SHARED_API_STACK}"
  run_managed_stack_command \
    "shared-api-gateway" "${PRIMARY_REGION}" "${SHARED_API_STACK}" \
    aws cloudformation deploy \
    --region "${PRIMARY_REGION}" \
    --stack-name "${SHARED_API_STACK}" \
    --template-file infra/aws/foundation/api-gateway-account.yml \
    --capabilities CAPABILITY_NAMED_IAM \
    --no-fail-on-empty-changeset \
    --tags \
      Application=archon-datahub \
      Environment=shared \
      ManagedBy=github-actions \
      Purpose=shared-apigateway-logging
  run_managed_stack_command \
    "shared-api-gateway" "${PRIMARY_REGION}" "${SHARED_API_STACK}" \
    aws cloudformation update-termination-protection \
    --region "${PRIMARY_REGION}" \
    --stack-name "${SHARED_API_STACK}" \
    --enable-termination-protection
  shared_stack_json="${RUNNER_TEMP}/shared-api-gateway-stack.json"
  assert_stack_complete_without_service_role \
    "${PRIMARY_REGION}" "${SHARED_API_STACK}" "${shared_stack_json}"
  shared_role_arn="$(
    jq -er '
      .Stacks[0].Outputs[] |
      select(.OutputKey == "ApiGatewayCloudWatchLogsRoleArn") |
      .OutputValue
    ' "${shared_stack_json}"
  )"
  test "${shared_role_arn}" = \
    "arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/${SHARED_API_ROLE}"
  echo "::add-mask::${shared_role_arn}"
  api_account_json="${RUNNER_TEMP}/api-gateway-account-final.json"
  aws apigateway get-account \
    --region "${PRIMARY_REGION}" \
    --output json >"${api_account_json}"
  jq -e --arg expected "${shared_role_arn}" '
    .cloudwatchRoleArn == $expected
  ' "${api_account_json}" >/dev/null
  shared_role_json="${RUNNER_TEMP}/shared-api-gateway-role.json"
  aws iam get-role \
    --role-name "${SHARED_API_ROLE}" \
    --output json >"${shared_role_json}"
  jq -e '
    .Role.RoleName == "archon-datahub-apigateway-cloudwatch-logs" and
    (.Role.PermissionsBoundary == null) and
    (.Role.AssumeRolePolicyDocument.Statement | length) == 1 and
    .Role.AssumeRolePolicyDocument.Statement[0] == {
      Action: "sts:AssumeRole",
      Effect: "Allow",
      Principal: {Service: "apigateway.amazonaws.com"},
      Sid: "ApiGatewayServiceOnly"
    }
  ' "${shared_role_json}" >/dev/null
  aws iam list-attached-role-policies \
    --role-name "${SHARED_API_ROLE}" \
    --output json |
    jq -e '.AttachedPolicies == []' >/dev/null
  aws iam list-role-policies \
    --role-name "${SHARED_API_ROLE}" \
    --output json |
    jq -e '.PolicyNames == ["archon-apigateway-cloudwatch-logs"]' >/dev/null
  shared_inline_json="${RUNNER_TEMP}/shared-api-gateway-inline-policy.json"
  aws iam get-role-policy \
    --role-name "${SHARED_API_ROLE}" \
    --policy-name archon-apigateway-cloudwatch-logs \
    --output json >"${shared_inline_json}"
  jq -e '
    ([.PolicyDocument.Statement[].Action] | flatten | index("*") | not) and
    (.PolicyDocument | tostring | contains("AdministratorAccess") | not) and
    (.PolicyDocument | tostring | contains("API-Gateway-Execution-Logs_")) and
    (.PolicyDocument | tostring | contains("/archon/staging/api-gateway")) and
    (.PolicyDocument | tostring | contains("/archon/production/api-gateway"))
  ' "${shared_inline_json}" >/dev/null
  shared_policy_sha="$(canonical_policy_sha "${shared_inline_json}")"
  shared_template_sha="$(
    deployed_template_sha "${PRIMARY_REGION}" "${SHARED_API_STACK}"
  )"
  shared_role_binding_sha="$(
    printf '%s' "${shared_role_arn}" | sha256sum | awk '{print $1}'
  )"
  shared_api_gateway_json="$(
    jq -cnS \
      --arg bindingSha256 "${shared_role_binding_sha}" \
      --arg inlinePolicySha256 "${shared_policy_sha}" \
      --arg templateSha256 "${shared_template_sha}" '
        {
          external: null,
          managed: {
            deployedTemplateSha256: $templateSha256,
            inlinePolicySha256: $inlinePolicySha256,
            roleArnTemplate:
              "arn:aws:iam::<AWS_ACCOUNT_ID>:role/archon-datahub-apigateway-cloudwatch-logs",
            stackName: "Archon-Shared-ApiGateway-Logging"
          },
          mode: "foundation-managed",
          roleBindingSha256: $bindingSha256,
          takeover: "forbidden",
          validation: "managed-and-verified"
        }
      '
  )"
fi
echo "::endgroup::"

foundation_phase='governed-canary-roles'
echo "::group::Reconcile the three governed-canary read roles"
revalidate_master
assert_stack_role_is_null_if_present "governed-canary-roles" "${PRIMARY_REGION}" "${CANARY_ROLE_STACK}"
run_managed_stack_command \
  "governed-canary-roles" "${PRIMARY_REGION}" "${CANARY_ROLE_STACK}" \
  aws cloudformation deploy \
  --region "${PRIMARY_REGION}" \
  --stack-name "${CANARY_ROLE_STACK}" \
  --template-file infra/aws/foundation/governed-canary-roles.yml \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    GitHubOrganization=upgradedev \
    GitHubRepository=archon-datahub
run_managed_stack_command \
  "governed-canary-roles" "${PRIMARY_REGION}" "${CANARY_ROLE_STACK}" \
  aws cloudformation update-termination-protection \
  --region "${PRIMARY_REGION}" \
  --stack-name "${CANARY_ROLE_STACK}" \
  --enable-termination-protection
canary_stack_json="${RUNNER_TEMP}/governed-canary-role-stack.json"
assert_stack_complete_without_service_role \
  "${PRIMARY_REGION}" "${CANARY_ROLE_STACK}" "${canary_stack_json}"
canary_roles_json='[]'
for kind in "${CANARY_ROLE_KINDS[@]}"; do
  role_name="${CANARY_ROLE[${kind}]}"
  environment="${CANARY_ENVIRONMENT[${kind}]}"
  policy_name="${CANARY_POLICY[${kind}]}"
  case "${kind}" in
    prepare)
      output_key="GovernedCanaryPrepareRoleArn"
      ;;
    approval)
      output_key="GovernedCanaryApprovalRoleArn"
      ;;
    recovery)
      output_key="GovernedCanaryRecoveryRoleArn"
      ;;
  esac
  role_arn="$(
    jq -er \
      --arg key "${output_key}" '
        .Stacks[0].Outputs[] |
        select(.OutputKey == $key) |
        .OutputValue
      ' "${canary_stack_json}"
  )"
  test "${role_arn}" = \
    "arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/${role_name}"
  echo "::add-mask::${role_arn}"
  role_json="${RUNNER_TEMP}/governed-canary-${kind}-role.json"
  aws iam get-role \
    --role-name "${role_name}" \
    --output json >"${role_json}"
  jq -e \
    --arg account "${EXPECTED_ACCOUNT_ID}" \
    --arg role "${role_name}" \
    --arg environment "${environment}" \
    --arg subject \
      "repo:upgradedev/archon-datahub:environment:${environment}" '
      .Role.RoleName == $role and
      .Role.MaxSessionDuration == 3600 and
      (.Role.PermissionsBoundary == null) and
      (.Role.AssumeRolePolicyDocument.Statement | length) == 1 and
      .Role.AssumeRolePolicyDocument.Statement[0] == {
        Action: "sts:AssumeRoleWithWebIdentity",
        Condition: {
          StringEquals: {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
            "token.actions.githubusercontent.com:sub": $subject
          }
        },
        Effect: "Allow",
        Principal: {
          Federated: (
            "arn:aws:iam::" + $account +
            ":oidc-provider/token.actions.githubusercontent.com"
          )
        },
        Sid: "GitHubEnvironmentOidcOnly"
      } and
      (
        .Role.Tags |
        map(select(.Key | startswith("aws:") | not)) |
        sort_by(.Key)
      ) == (
        [
          {Key: "Application", Value: "archon-datahub"},
          {Key: "Environment", Value: $environment},
          {Key: "ManagedBy", Value: "github-actions"}
        ] |
        sort_by(.Key)
      )
    ' "${role_json}" >/dev/null
  aws iam list-attached-role-policies \
    --role-name "${role_name}" \
    --output json |
    jq -e '.AttachedPolicies == []' >/dev/null
  aws iam list-role-policies \
    --role-name "${role_name}" \
    --output json |
    jq -e --arg policy "${policy_name}" \
      '.PolicyNames == [$policy]' >/dev/null
  policy_json="${RUNNER_TEMP}/governed-canary-${kind}-policy.json"
  aws iam get-role-policy \
    --role-name "${role_name}" \
    --policy-name "${policy_name}" \
    --output json >"${policy_json}"
  compact_policy_size="$(
    jq -c '.PolicyDocument' "${policy_json}" |
      wc -c |
      awk '{print $1 - 1}'
  )"
  test "${compact_policy_size}" -le 2048
  jq -e \
    --arg account "${EXPECTED_ACCOUNT_ID}" \
    --arg region "${PRIMARY_REGION}" \
    --arg kind "${kind}" '
      .PolicyDocument.Version == "2012-10-17" and
      (
        [.PolicyDocument.Statement[] |
          select(.Sid == "ReadExactStagingStack")] |
        length
      ) == 1 and
      (
        .PolicyDocument.Statement[] |
        select(.Sid == "ReadExactStagingStack") |
        .Effect == "Allow" and
        .Action == "cloudformation:DescribeStacks" and
        .Resource == (
          "arn:aws:cloudformation:" + $region + ":" + $account +
          ":stack/Archon-staging/*"
        ) and
        (.Condition == null)
      ) and
      (
        if $kind == "approval" then
          (.PolicyDocument.Statement | length) == 2 and
          (
            .PolicyDocument.Statement[] |
            select(.Sid == "ReadExactStagingApproverMembership") |
            .Effect == "Allow" and
            (.Action | sort) == (
              [
                "cognito-idp:AdminGetUser",
                "cognito-idp:AdminListGroupsForUser"
              ] |
              sort
            ) and
            .Resource == (
              "arn:aws:cognito-idp:" + $region + ":" + $account +
              ":userpool/" + $region + "_*"
            ) and
            .Condition == {
              StringEquals: {
                "aws:ResourceTag/Application": "archon-datahub",
                "aws:ResourceTag/Environment": "staging",
                "aws:ResourceTag/ManagedBy": "aws-cdk"
              }
            }
          )
        else
          (.PolicyDocument.Statement | length) == 1
        end
      ) and
      (
        [.PolicyDocument.Statement[] |
          select(.Effect == "Allow") |
          .Action] |
        flatten |
        all(
          . != "*" and
          (endswith(":*") | not)
        )
      )
    ' "${policy_json}" >/dev/null
  CANARY_POLICY_SHA["${kind}"]="$(canonical_policy_sha "${policy_json}")"
  CANARY_ROLE_BINDING_SHA["${kind}"]="$(
    printf '%s' "${role_arn}" | sha256sum | awk '{print $1}'
  )"
  role_evidence="$(
    jq -cnS \
      --arg kind "${kind}" \
      --arg environment "${environment}" \
      --arg policySha256 "${CANARY_POLICY_SHA[${kind}]}" \
      --arg roleBindingSha256 "${CANARY_ROLE_BINDING_SHA[${kind}]}" '
        {
          environment: $environment,
          kind: $kind,
          policySha256: $policySha256,
          roleArnTemplate: (
            "arn:aws:iam::<AWS_ACCOUNT_ID>:role/" +
            "archon-datahub-github-governed-canary-" + $kind
          ),
          roleBindingSha256: $roleBindingSha256,
          validation: "passed"
        }
      '
  )"
  canary_roles_json="$(
    jq -cnS \
      --argjson current "${canary_roles_json}" \
      --argjson addition "${role_evidence}" \
      '$current + [$addition]'
  )"
done
canary_template_sha="$(
  deployed_template_sha "${PRIMARY_REGION}" "${CANARY_ROLE_STACK}"
)"
echo "::endgroup::"

foundation_phase='bootstrap'
echo "::group::Bootstrap both isolated stages in both regions"
for stage in staging production; do
  for region in "${PRIMARY_REGION}" "${EDGE_REGION}"; do
    target="${stage}:${region}"
    bootstrap_label="${stage}-bootstrap-primary"
    if [[ "${region}" == "${EDGE_REGION}" ]]; then
      bootstrap_label="${stage}-bootstrap-edge"
    fi
    revalidate_master
    assert_stack_role_is_null_if_present \
      "${bootstrap_label}" "${region}" "${BOOTSTRAP_STACK[${stage}]}"
    run_managed_stack_command \
      "${bootstrap_label}" "${region}" "${BOOTSTRAP_STACK[${stage}]}" \
      infra/aws/node_modules/.bin/cdk bootstrap \
      "aws://${EXPECTED_ACCOUNT_ID}/${region}" \
      --template "${BOOTSTRAP_TEMPLATE_BY_TARGET[${target}]}" \
      --toolkit-stack-name "${BOOTSTRAP_STACK[${stage}]}" \
      --qualifier "${QUALIFIER[${stage}]}" \
      --cloudformation-execution-policies \
        "${EXECUTION_POLICY_ARNS_BY_TARGET[${target}]}" \
      --termination-protection \
      --no-bootstrap-customer-key \
      --no-previous-parameters \
      --tags Application=archon-datahub \
      --tags Environment="${stage}" \
      --tags ManagedBy=github-actions \
      --tags Purpose=cdk-bootstrap \
      --no-notices
  done
done
echo "::endgroup::"

foundation_phase='deploy-roles'
echo "::group::Reconcile the two environment-bound deploy roles"
for stage in staging production; do
  revalidate_master
  assert_stack_role_is_null_if_present \
    "${stage}-deploy" "${PRIMARY_REGION}" "${DEPLOY_STACK[${stage}]}"
  run_managed_stack_command \
    "${stage}-deploy" "${PRIMARY_REGION}" "${DEPLOY_STACK[${stage}]}" \
    aws cloudformation deploy \
    --region "${PRIMARY_REGION}" \
    --stack-name "${DEPLOY_STACK[${stage}]}" \
    --template-file infra/aws/foundation/github-actions-deploy-role.yml \
    --capabilities CAPABILITY_NAMED_IAM \
    --no-fail-on-empty-changeset \
    --parameter-overrides \
      GitHubOrganization=upgradedev \
      GitHubRepository=archon-datahub \
      DeploymentEnvironment="${stage}" \
      BootstrapQualifier="${QUALIFIER[${stage}]}" \
      BootstrapStackName="${BOOTSTRAP_STACK[${stage}]}" \
      IamFoundationStackName="${IAM_STACK[${stage}]}" \
      CloudFrontHostedZoneId="${CLOUDFRONT_HOSTED_ZONE_ID[${stage}]}" \
    --tags \
      Application=archon-datahub \
      Environment="${stage}" \
      ManagedBy=github-actions \
      Purpose=github-deployment-role
  run_managed_stack_command \
    "${stage}-deploy" "${PRIMARY_REGION}" "${DEPLOY_STACK[${stage}]}" \
    aws cloudformation update-termination-protection \
    --region "${PRIMARY_REGION}" \
    --stack-name "${DEPLOY_STACK[${stage}]}" \
    --enable-termination-protection
done
echo "::endgroup::"

foundation_phase='drift-verification'
echo "::group::Require every managed foundation stack to be IN_SYNC"
revalidate_master
drift_file="${RUNNER_TEMP}/aws-foundation-drift.json"
drift_started_epoch="$(date +%s)"
[[ "${drift_started_epoch}" =~ ^[1-9][0-9]*$ ]]
readonly CFN_DRIFT_DEADLINE_EPOCH="$((drift_started_epoch + CFN_DRIFT_PHASE_TIMEOUT_SECONDS))"
printf '[]' >"${drift_file}"
check_drift() (
  local stage="$1" kind="$2" region="$3" stack_name="$4"
  local status_json="${RUNNER_TEMP}/drift-${region}-${stack_name}.json"
  local exact_stack_id detection_timestamp checked_resource_count
  cleanup_drift_raw(){ rm -f -- "${status_json}" "${drift_file}.next"; }
  trap cleanup_drift_raw EXIT
  detect_and_wait_for_cloudformation_stack_in_sync \
    "${region}" "${stack_name}" "${status_json}" "${EXPECTED_ACCOUNT_ID}"
  [[ "${CFN_DRIFT_POLL_ATTEMPTS}" =~ ^[1-9][0-9]*$ ]]
  [[ "${CFN_DRIFT_POLL_ELAPSED_SECONDS}" =~ ^[0-9]+$ ]]
  exact_stack_id="$(jq -er '.StackId' "${status_json}" 2>/dev/null)"
  detection_timestamp="$(jq -er '.Timestamp' "${status_json}" 2>/dev/null)"
  checked_resource_count="$(verify_cloudformation_stack_resource_drifts \
    "${region}" "${stack_name}" "${exact_stack_id}" "${detection_timestamp}" \
    "${EXPECTED_ACCOUNT_ID}" "${CFN_DRIFT_DEADLINE_EPOCH}")"
  [[ "${checked_resource_count}" =~ ^[0-9]+$ ]]
  cloudformation_drift_remaining_seconds "${CFN_DRIFT_DEADLINE_EPOCH}" >/dev/null
  jq --arg stage "${stage}" --arg kind "${kind}" --arg region "${region}" \
    --arg stackName "${stack_name}" --argjson checkedResourceCount "${checked_resource_count}" \
    --argjson pollAttempts "${CFN_DRIFT_POLL_ATTEMPTS}" \
    --argjson pollElapsedSeconds "${CFN_DRIFT_POLL_ELAPSED_SECONDS}" '
      . + [{
        checkedResourceCount: $checkedResourceCount,
        coverage: "cloudformation-supported-resources",
        detectionStatus: "DETECTION_COMPLETE",
        driftedResourceCount: 0,
        kind: $kind,
        pollAttempts: $pollAttempts,
        pollElapsedSeconds: $pollElapsedSeconds,
        region: $region,
        stackDriftStatus: "IN_SYNC",
        stackIncarnationBinding: "exact-stack-id-and-monotonic-detection-lower-bound",
        stackName: $stackName,
        stage: $stage,
        validation: "passed"
      }]
    ' "${drift_file}" >"${drift_file}.next"
  cloudformation_drift_remaining_seconds "${CFN_DRIFT_DEADLINE_EPOCH}" >/dev/null
  mv "${drift_file}.next" "${drift_file}"
)
for stage in staging production; do
  check_drift "${stage}" iam "${PRIMARY_REGION}" "${IAM_STACK[${stage}]}"
  check_drift "${stage}" deploy-role "${PRIMARY_REGION}" "${DEPLOY_STACK[${stage}]}"
  for region in "${PRIMARY_REGION}" "${EDGE_REGION}"; do
    check_drift \
      "${stage}" bootstrap "${region}" "${BOOTSTRAP_STACK[${stage}]}"
  done
done
inspect_api_gateway_binding
test "${shared_api_gateway_mode}" = "${shared_api_gateway_preflight_mode}"
test "${shared_api_gateway_observed_binding_sha}" = "${shared_role_binding_sha}"
if [[ "${shared_api_gateway_mode}" == "foundation-managed" ]]; then
  check_drift shared api-gateway "${PRIMARY_REGION}" "${SHARED_API_STACK}"
fi
check_drift shared governed-canary-roles \
  "${PRIMARY_REGION}" "${CANARY_ROLE_STACK}"
drift_stack_count="$(jq -er 'length' "${drift_file}")"
if [[ "${shared_api_gateway_mode}" == "foundation-managed" ]]; then
  test "${drift_stack_count}" -eq 10
else
  test "${drift_stack_count}" -eq 9
fi
jq -e '
  length > 0 and all(.[];
    keys == ["checkedResourceCount", "coverage", "detectionStatus",
      "driftedResourceCount", "kind", "pollAttempts", "pollElapsedSeconds",
      "region", "stackDriftStatus", "stackIncarnationBinding", "stackName", "stage", "validation"] and
    .coverage == "cloudformation-supported-resources" and
    .detectionStatus == "DETECTION_COMPLETE" and .driftedResourceCount == 0 and
    .stackDriftStatus == "IN_SYNC" and
    .stackIncarnationBinding == "exact-stack-id-and-monotonic-detection-lower-bound" and
    .validation == "passed" and
    (.checkedResourceCount | (type == "number" and floor == . and . >= 0)) and
    (.pollAttempts | (type == "number" and floor == . and . >= 1 and . <= 120)) and
    (.pollElapsedSeconds | (type == "number" and floor == . and . >= 0 and . <= 900)))
' "${drift_file}" >/dev/null
drift_sha="$(sha256sum "${drift_file}" | awk '{print $1}')"
echo "::endgroup::"

foundation_phase='evidence'
echo "::group::Verify live stage bindings and author sanitized evidence"
rm -rf -- "${EVIDENCE_DIR}"
mkdir -p "${EVIDENCE_DIR}"
stages_json='[]'
operational_roles_json='[]'
expected_bootstrap_logical_ids='[
  "CdkBootstrapVersion",
  "CloudFormationExecutionRole",
  "ContainerAssetsRepository",
  "DeploymentActionRole",
  "FilePublishingRole",
  "FilePublishingRoleDefaultPolicy",
  "ImagePublishingRole",
  "ImagePublishingRoleDefaultPolicy",
  "LookupRole",
  "StagingBucket",
  "StagingBucketPolicy"
]'

verify_operational_role() {
  local stack_json="$1"
  local kind="$2"
  local role_arn_output="$3"
  local role_name_output="$4"
  local role_name="$5"
  local environment="$6"
  local policy_name="$7"
  local purpose="$8"
  local role_arn
  local role_json
  local policy_json
  local policy_sha
  local binding_sha
  local role_evidence

  role_arn="$(
    jq -er \
      --arg key "${role_arn_output}" '
        .Stacks[0].Outputs[] |
        select(.OutputKey == $key) |
        .OutputValue
      ' "${stack_json}"
  )"
  test "${role_arn}" = \
    "arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/${role_name}"
  test "$(
    jq -er \
      --arg key "${role_name_output}" '
        .Stacks[0].Outputs[] |
        select(.OutputKey == $key) |
        .OutputValue
      ' "${stack_json}"
  )" = "${role_name}"
  echo "::add-mask::${role_arn}"

  role_json="${RUNNER_TEMP}/operational-${kind}-role.json"
  aws iam get-role \
    --role-name "${role_name}" \
    --output json >"${role_json}"
  jq -e \
    --arg account "${EXPECTED_ACCOUNT_ID}" \
    --arg role "${role_name}" \
    --arg environment "${environment}" \
    --arg purpose "${purpose}" \
    --arg subject \
      "repo:upgradedev/archon-datahub:environment:${environment}" '
      .Role.RoleName == $role and
      .Role.MaxSessionDuration == 3600 and
      (.Role.PermissionsBoundary == null) and
      (.Role.AssumeRolePolicyDocument.Statement | length) == 1 and
      .Role.AssumeRolePolicyDocument.Statement[0].Action ==
        "sts:AssumeRoleWithWebIdentity" and
      .Role.AssumeRolePolicyDocument.Statement[0].Effect == "Allow" and
      .Role.AssumeRolePolicyDocument.Statement[0].Principal.Federated ==
        (
          "arn:aws:iam::" + $account +
          ":oidc-provider/token.actions.githubusercontent.com"
        ) and
      .Role.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals == {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": $subject
      } and
      (
        .Role.Tags |
        map(select(.Key | startswith("aws:") | not)) |
        sort_by(.Key)
      ) == (
        [
          {Key: "Application", Value: "archon-datahub"},
          {
            Key: "Environment",
            Value: (
              if ($environment | startswith("judge-access-")) then
                ($environment | sub("^judge-access-"; ""))
              else
                "production"
              end
            )
          },
          {Key: "ManagedBy", Value: "cloudformation"},
          {Key: "Purpose", Value: $purpose}
        ] |
        sort_by(.Key)
      )
    ' "${role_json}" >/dev/null
  aws iam list-attached-role-policies \
    --role-name "${role_name}" \
    --output json |
    jq -e '.AttachedPolicies == []' >/dev/null
  aws iam list-role-policies \
    --role-name "${role_name}" \
    --output json |
    jq -e --arg policy "${policy_name}" \
      '.PolicyNames == [$policy]' >/dev/null
  policy_json="${RUNNER_TEMP}/operational-${kind}-policy.json"
  aws iam get-role-policy \
    --role-name "${role_name}" \
    --policy-name "${policy_name}" \
    --output json >"${policy_json}"
  test "$(
    jq -c '.PolicyDocument' "${policy_json}" |
      wc -c |
      awk '{print $1 - 1}'
  )" -le 10240
  jq -e '
    .PolicyDocument.Version == "2012-10-17" and
    (
      [.PolicyDocument.Statement[] |
        select(.Effect == "Allow") |
        .Action] |
      flatten |
      all(
        . != "*" and
        (endswith(":*") | not)
      )
    ) and
    (
      .PolicyDocument |
      tostring |
      contains("AdministratorAccess") |
      not
    )
  ' "${policy_json}" >/dev/null

  policy_sha="$(canonical_policy_sha "${policy_json}")"
  binding_sha="$(
    printf '%s' "${role_arn}" | sha256sum | awk '{print $1}'
  )"
  OPERATIONAL_ROLE_BINDING_SHA["${kind}"]="${binding_sha}"
  role_evidence="$(
    jq -cnS \
      --arg kind "${kind}" \
      --arg environment "${environment}" \
      --arg policySha256 "${policy_sha}" \
      --arg roleName "${role_name}" \
      --arg roleBindingSha256 "${binding_sha}" '
        {
          environment: $environment,
          kind: $kind,
          policySha256: $policySha256,
          roleArnTemplate:
            ("arn:aws:iam::<AWS_ACCOUNT_ID>:role/" + $roleName),
          roleBindingSha256: $roleBindingSha256,
          validation: "passed"
        }
      '
  )"
  operational_roles_json="$(
    jq -cnS \
      --argjson current "${operational_roles_json}" \
      --argjson addition "${role_evidence}" \
      '$current + [$addition]'
  )"
}

for stage in staging production; do
  regions_json='[]'
  for region in "${PRIMARY_REGION}" "${EDGE_REGION}"; do
    stack_json="${RUNNER_TEMP}/${stage}-bootstrap-${region}.json"
    assert_stack_complete_without_service_role \
      "${region}" "${BOOTSTRAP_STACK[${stage}]}" "${stack_json}"
    parameters="$(
      jq -c '
        .Stacks[0].Parameters |
        map({key: .ParameterKey, value: .ParameterValue}) |
        from_entries
      ' "${stack_json}"
    )"
    jq -e \
      --arg qualifier "${QUALIFIER[${stage}]}" \
      --arg policies "${EXECUTION_POLICY_ARNS_BY_TARGET[${stage}:${region}]}" \
      --arg qualifierStage "${stage}" \
      --arg region "${region}" '
        .Qualifier == $qualifier and
        .TrustedAccounts == "" and
        .TrustedAccountsForLookup == "" and
        .CloudFormationExecutionPolicies == $policies and
        .FileAssetsBucketName == "" and
        .FileAssetsBucketKmsKeyId == "AWS_MANAGED_KEY" and
        .ContainerAssetsRepositoryName == "" and
        .InputPermissionsBoundary == "" and
        .UseExamplePermissionsBoundary == "false" and
        .BootstrapVariant ==
          (
            "Archon DataHub " + $qualifierStage + " " +
            $region + " isolated bootstrap v1"
          ) and
        .PublicAccessBlockConfiguration == "true" and
        .DenyExternalId == "true"
      ' <<<"${parameters}" >/dev/null
    bootstrap_version="$(
      jq -er '
        .Stacks[0].Outputs[] |
        select(.OutputKey == "BootstrapVersion") |
        .OutputValue
      ' "${stack_json}"
    )"
    test "${bootstrap_version}" = "${PINNED_BOOTSTRAP_VERSION}"
    ssm_version="$(
      aws ssm get-parameter \
        --region "${region}" \
        --name "/cdk-bootstrap/${QUALIFIER[${stage}]}/version" \
        --query Parameter.Value \
        --output text
    )"
    test "${ssm_version}" = "${bootstrap_version}"
    resources="${RUNNER_TEMP}/${stage}-bootstrap-resources-${region}.json"
    aws cloudformation list-stack-resources \
      --region "${region}" \
      --stack-name "${BOOTSTRAP_STACK[${stage}]}" \
      --output json >"${resources}"
    jq -e \
      --argjson expected "${expected_bootstrap_logical_ids}" '
        ([.StackResourceSummaries[].LogicalResourceId] | sort) ==
          ($expected | sort) and
        all(
          .StackResourceSummaries[];
          .ResourceStatus == "CREATE_COMPLETE" or
          .ResourceStatus == "UPDATE_COMPLETE"
        )
      ' "${resources}" >/dev/null

    cfn_role="cdk-${QUALIFIER[${stage}]}-cfn-exec-role-${EXPECTED_ACCOUNT_ID}-${region}"
    cfn_attached="${RUNNER_TEMP}/${stage}-cfn-attached-${region}.json"
    aws iam list-attached-role-policies \
      --role-name "${cfn_role}" \
      --output json >"${cfn_attached}"
    jq -e \
      --arg policies "${EXECUTION_POLICY_ARNS_BY_TARGET[${stage}:${region}]}" '
      (.AttachedPolicies | sort_by(.PolicyArn)) ==
        (
          $policies |
          split(",") |
          map({
            PolicyArn: .,
            PolicyName: (split("/")[-1])
          }) |
          sort_by(.PolicyArn)
        )
    ' "${cfn_attached}" >/dev/null
    aws iam list-role-policies \
      --role-name "${cfn_role}" \
      --output json |
      jq -e '.PolicyNames == []' >/dev/null
    aws iam get-role \
      --role-name "${cfn_role}" \
      --output json |
      jq -e '.Role.PermissionsBoundary == null' >/dev/null

    lookup_role="cdk-${QUALIFIER[${stage}]}-lookup-role-${EXPECTED_ACCOUNT_ID}-${region}"
    aws iam list-attached-role-policies \
      --role-name "${lookup_role}" \
      --output json |
      jq -e '
        .AttachedPolicies == [{
          PolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess",
          PolicyName: "ReadOnlyAccess"
        }]
      ' >/dev/null

    bootstrap_deploy_role="cdk-${QUALIFIER[${stage}]}-deploy-role-${EXPECTED_ACCOUNT_ID}-${region}"
    aws iam list-attached-role-policies \
      --role-name "${bootstrap_deploy_role}" \
      --output json |
      jq -e '.AttachedPolicies == []' >/dev/null
    aws iam list-role-policies \
      --role-name "${bootstrap_deploy_role}" \
      --output json |
      jq -e '.PolicyNames == ["default"]' >/dev/null
    bootstrap_deploy_policy="${RUNNER_TEMP}/${stage}-bootstrap-deploy-policy-${region}.json"
    aws iam get-role-policy \
      --role-name "${bootstrap_deploy_role}" \
      --policy-name default \
      --output json >"${bootstrap_deploy_policy}"
    if [[ "${region}" == "${EDGE_REGION}" ]]; then
      stack_names="[\"Archon-${stage}-Edge\"]"
    elif [[ "${stage}" == "staging" ]]; then
      stack_names='["Archon-staging","Archon-Registry"]'
    else
      stack_names='["Archon-production"]'
    fi
    expected_bootstrap_deploy_policy="${RUNNER_TEMP}/${stage}-expected-bootstrap-deploy-policy-${region}.json"
    jq -cnS \
      --arg account "${EXPECTED_ACCOUNT_ID}" \
      --arg region "${region}" \
      --arg qualifier "${QUALIFIER[${stage}]}" \
      --argjson stackNames "${stack_names}" '
        def stack_arn($name):
          "arn:aws:cloudformation:" + $region + ":" + $account +
          ":stack/" + $name + "/*";
        {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "InspectOnlyStageStacks",
              Effect: "Allow",
              Action: [
                "cloudformation:DescribeStackEvents",
                "cloudformation:DescribeStackResource",
                "cloudformation:DescribeStackResources",
                "cloudformation:DescribeStacks",
                "cloudformation:GetTemplate",
                "cloudformation:ListStackResources",
                "cloudformation:UpdateTerminationProtection"
              ],
              Resource: ($stackNames | map(stack_arn(.)))
            },
            {
              Sid: "CreateOrUpdateOnlyWithBootstrapExecutionRole",
              Effect: "Allow",
              Action: [
                "cloudformation:CreateStack",
                "cloudformation:UpdateStack"
              ],
              Resource: ($stackNames | map(stack_arn(.))),
              Condition: {
                ArnEquals: {
                  "cloudformation:RoleArn": (
                    "arn:aws:iam::" + $account + ":role/cdk-" + $qualifier +
                    "-cfn-exec-role-" + $account + "-" + $region
                  )
                }
              }
            },
            {
              Sid: "CreateOnlyCdkDeployChangeSet",
              Effect: "Allow",
              Action: "cloudformation:CreateChangeSet",
              Resource: ($stackNames | map(stack_arn(.))),
              Condition: {
                ArnEquals: {
                  "cloudformation:RoleArn": (
                    "arn:aws:iam::" + $account + ":role/cdk-" + $qualifier +
                    "-cfn-exec-role-" + $account + "-" + $region
                  )
                },
                StringEquals: {
                  "cloudformation:ChangeSetName": "cdk-deploy-change-set"
                }
              }
            },
            {
              Sid: "UseOnlyCdkDeployChangeSets",
              Effect: "Allow",
              Action: [
                "cloudformation:DeleteChangeSet",
                "cloudformation:DescribeChangeSet",
                "cloudformation:ExecuteChangeSet"
              ],
              Resource: ($stackNames | map(stack_arn(.))),
              Condition: {
                StringEquals: {
                  "cloudformation:ChangeSetName": "cdk-deploy-change-set"
                }
              }
            },
            {
              Sid: "InspectTemplatesWithoutStackMutation",
              Effect: "Allow",
              Action: [
                "cloudformation:GetTemplateSummary",
                "cloudformation:ValidateTemplate"
              ],
              Resource: "*"
            },
            {
              Sid: "PassOnlyThisBootstrapExecutionRole",
              Effect: "Allow",
              Action: "iam:PassRole",
              Resource: (
                "arn:aws:iam::" + $account + ":role/cdk-" + $qualifier +
                "-cfn-exec-role-" + $account + "-" + $region
              ),
              Condition: {
                StringEquals: {
                  "iam:PassedToService": "cloudformation.amazonaws.com"
                }
              }
            },
            {
              Sid: "VerifyCaller",
              Effect: "Allow",
              Action: "sts:GetCallerIdentity",
              Resource: "*"
            },
            {
              Sid: "ReadOnlyThisBootstrapStagingBucket",
              Effect: "Allow",
              Action: [
                "s3:GetObject*",
                "s3:GetBucket*",
                "s3:List*"
              ],
              Resource: [
                (
                  "arn:aws:s3:::cdk-" + $qualifier + "-assets-" +
                  $account + "-" + $region
                ),
                (
                  "arn:aws:s3:::cdk-" + $qualifier + "-assets-" +
                  $account + "-" + $region + "/*"
                )
              ]
            },
            {
              Sid: "ReadOnlyThisBootstrapVersion",
              Effect: "Allow",
              Action: [
                "ssm:GetParameter",
                "ssm:GetParameters"
              ],
              Resource: (
                "arn:aws:ssm:" + $region + ":" + $account +
                ":parameter/cdk-bootstrap/" + $qualifier + "/version"
              )
            }
          ]
        }
      ' >"${expected_bootstrap_deploy_policy}"
    bootstrap_policy_canonical='
      def sorted_array:
        if type == "array" then sort else [.] end;
      .Statement |= (
        map(
          .Action |= sorted_array |
          .Resource |= sorted_array
        ) |
        sort_by(.Sid)
      )
    '
    jq -S "${bootstrap_policy_canonical}" \
      "${expected_bootstrap_deploy_policy}" \
      >"${expected_bootstrap_deploy_policy}.canonical"
    jq '.PolicyDocument' "${bootstrap_deploy_policy}" |
      jq -S "${bootstrap_policy_canonical}" \
        >"${bootstrap_deploy_policy}.canonical"
    cmp -s \
      "${expected_bootstrap_deploy_policy}.canonical" \
      "${bootstrap_deploy_policy}.canonical"
    bootstrap_deploy_policy_sha="$(
      sha256sum "${bootstrap_deploy_policy}.canonical" |
        awk '{print $1}'
    )"

    resource_contract_sha="$(
      jq -cS '
        [.StackResourceSummaries[] |
          {
            logicalId: .LogicalResourceId,
            resourceStatus: .ResourceStatus,
            resourceType: .ResourceType
          }] |
        sort_by(.logicalId)
      ' "${resources}" |
      sha256sum |
      awk '{print $1}'
    )"
    bootstrap_deployed_template_sha="$(
      deployed_template_sha "${region}" "${BOOTSTRAP_STACK[${stage}]}"
    )"
    region_evidence="$(
      jq -cnS \
        --arg region "${region}" \
        --argjson version "${bootstrap_version}" \
        --arg sourceTemplateSha256 \
          "${BOOTSTRAP_TEMPLATE_SHA_BY_TARGET[${stage}:${region}]}" \
        --arg resourceContractSha256 "${resource_contract_sha}" \
        --arg deployRolePolicySha256 "${bootstrap_deploy_policy_sha}" \
        --arg deployedTemplateSha256 "${bootstrap_deployed_template_sha}" '
          {
            bootstrapVersion: $version,
            deployRolePolicySha256: $deployRolePolicySha256,
            deployedTemplateSha256: $deployedTemplateSha256,
            region: $region,
            resourceContractSha256: $resourceContractSha256,
            sourceTemplateSha256: $sourceTemplateSha256,
            ssmVersion: $version,
            terminationProtection: true,
            validation: "passed"
          }
        '
    )"
    regions_json="$(
      jq -cnS \
        --argjson current "${regions_json}" \
        --argjson addition "${region_evidence}" \
        '$current + [$addition]'
    )"
  done

  deploy_stack_json="${RUNNER_TEMP}/${stage}-deploy-stack.json"
  assert_stack_complete_without_service_role \
    "${PRIMARY_REGION}" "${DEPLOY_STACK[${stage}]}" "${deploy_stack_json}"
  jq -e \
    --arg stage "${stage}" \
    --arg zone "${CLOUDFRONT_HOSTED_ZONE_ID[${stage}]}" '
      .Stacks[0].Parameters as $parameters |
      (
        [$parameters[] |
          select(.ParameterKey == "CloudFrontHostedZoneId")][0].ParameterValue
      ) == $zone and
      (
        [.Stacks[0].Outputs[].OutputKey] |
        sort
      ) == (
        if $stage == "production" then
          [
            "GitHubDeployRoleArn",
            "GitHubDeployRoleName",
            "JudgeUserRoleArn",
            "JudgeUserRoleName",
            "ProductionPagingTestRoleArn",
            "ProductionPagingTestRoleName",
            "ProductionPostureObserverRoleArn",
            "ProductionPostureObserverRoleName",
            "ProductionRuntimeReadRoleArn",
            "ProductionRuntimeReadRoleName"
          ] |
          sort
        else
          [
            "GitHubDeployRoleArn",
            "GitHubDeployRoleName",
            "JudgeUserRoleArn",
            "JudgeUserRoleName"
          ] |
          sort
        end
      )
    ' "${deploy_stack_json}" >/dev/null
  deploy_role_arn="$(
    jq -er '
      .Stacks[0].Outputs[] |
      select(.OutputKey == "GitHubDeployRoleArn") |
      .OutputValue
    ' "${deploy_stack_json}"
  )"
  test "${deploy_role_arn}" = \
    "arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/${DEPLOY_ROLE[${stage}]}"
  echo "::add-mask::${deploy_role_arn}"
  deploy_role_json="${RUNNER_TEMP}/${stage}-deploy-role.json"
  aws iam get-role \
    --role-name "${DEPLOY_ROLE[${stage}]}" \
    --output json >"${deploy_role_json}"
  jq -e \
    --arg account "${EXPECTED_ACCOUNT_ID}" \
    --arg role "${DEPLOY_ROLE[${stage}]}" \
    --arg subject \
      "repo:upgradedev/archon-datahub:environment:${stage}" '
      .Role.RoleName == $role and
      .Role.MaxSessionDuration == 7200 and
      (.Role.PermissionsBoundary == null) and
      (.Role.AssumeRolePolicyDocument.Statement | length) == 1 and
      .Role.AssumeRolePolicyDocument.Statement[0].Action ==
        "sts:AssumeRoleWithWebIdentity" and
      .Role.AssumeRolePolicyDocument.Statement[0].Principal.Federated ==
        ("arn:aws:iam::" + $account +
          ":oidc-provider/token.actions.githubusercontent.com") and
      .Role.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals[
        "token.actions.githubusercontent.com:aud"
      ] == "sts.amazonaws.com" and
      .Role.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals[
        "token.actions.githubusercontent.com:sub"
      ] == $subject
    ' "${deploy_role_json}" >/dev/null
  aws iam list-attached-role-policies \
    --role-name "${DEPLOY_ROLE[${stage}]}" \
    --output json |
    jq -e '.AttachedPolicies == []' >/dev/null
  aws iam list-role-policies \
    --role-name "${DEPLOY_ROLE[${stage}]}" \
    --output json |
    jq -e '.PolicyNames == ["archon-immutable-deployment"]' >/dev/null
  deploy_inline="${RUNNER_TEMP}/${stage}-deploy-inline-policy.json"
  aws iam get-role-policy \
    --role-name "${DEPLOY_ROLE[${stage}]}" \
    --policy-name archon-immutable-deployment \
    --output json >"${deploy_inline}"
  jq -e '
    (
      [.PolicyDocument.Statement[] |
        select(.Effect == "Allow") |
        .Action] |
      flatten |
      index("*") |
      not
    ) and
    (
      [.PolicyDocument.Statement[].Action] |
      flatten |
      index("iam:PassRole") |
      not
    ) and
    (
      .PolicyDocument |
      tostring |
      contains("AdministratorAccess") |
      not
    ) and
    (
      .PolicyDocument |
      tostring |
      contains("lookup-role") |
      not
    ) and
    (
      .PolicyDocument |
      tostring |
      contains("hnb659fds") |
      not
    )
  ' "${deploy_inline}" >/dev/null
  if [[ "${stage}" == "production" ]]; then
    jq -e '
      (
        [.PolicyDocument.Statement[].Action] |
        flatten |
        map(select(
          . == "ecr:GetAuthorizationToken" or
          . == "ecr:BatchDeleteImage" or
          . == "ecr:PutImage" or
          . == "ecr:InitiateLayerUpload" or
          . == "ecr:UploadLayerPart" or
          . == "ecr:CompleteLayerUpload"
        )) |
        length
      ) == 0
    ' "${deploy_inline}" >/dev/null
  fi
  verify_operational_role \
    "${deploy_stack_json}" \
    "judge-${stage}" \
    JudgeUserRoleArn \
    JudgeUserRoleName \
    "archon-${stage}-judge-user" \
    "judge-access-${stage}" \
    archon-judge-user-operations \
    judge-user-lifecycle
  if [[ "${stage}" == "production" ]]; then
    verify_operational_role \
      "${deploy_stack_json}" \
      posture-observer \
      ProductionPostureObserverRoleArn \
      ProductionPostureObserverRoleName \
      archon-production-posture-observer \
      production-observer \
      archon-production-posture-observer \
      production-posture-observer
    verify_operational_role \
      "${deploy_stack_json}" \
      runtime-read \
      ProductionRuntimeReadRoleArn \
      ProductionRuntimeReadRoleName \
      archon-production-runtime-read \
      production-observer \
      archon-production-runtime-read \
      production-runtime-read
    verify_operational_role \
      "${deploy_stack_json}" \
      paging-test \
      ProductionPagingTestRoleArn \
      ProductionPagingTestRoleName \
      archon-production-paging-test \
      production-paging-test \
      archon-production-paging-test \
      production-paging-test
  fi
  DEPLOY_POLICY_SHA["${stage}"]="$(canonical_policy_sha "${deploy_inline}")"
  DEPLOY_ROLE_BINDING_SHA["${stage}"]="$(
    printf '%s' "${deploy_role_arn}" | sha256sum | awk '{print $1}'
  )"
  DEPLOY_TEMPLATE_SHA["${stage}"]="$(
    deployed_template_sha "${PRIMARY_REGION}" "${DEPLOY_STACK[${stage}]}"
  )"
  stage_evidence="$(
    jq -cnS \
      --arg stage "${stage}" \
      --arg qualifier "${QUALIFIER[${stage}]}" \
      --arg bootstrapStackName "${BOOTSTRAP_STACK[${stage}]}" \
      --arg executionPolicySha256 "${EXECUTION_POLICY_SHA[${stage}]}" \
      --arg runtimeBoundarySha256 "${BOUNDARY_SHA[${stage}]}" \
      --arg deployPolicySha256 "${DEPLOY_POLICY_SHA[${stage}]}" \
      --arg deployRoleBindingSha256 "${DEPLOY_ROLE_BINDING_SHA[${stage}]}" \
      --arg cloudFrontDomainName "${CLOUDFRONT_DOMAIN_NAME[${stage}]}" \
      --arg cloudFrontHostedZoneId "${CLOUDFRONT_HOSTED_ZONE_ID[${stage}]}" \
      --arg iamDeployedTemplateSha256 "${IAM_TEMPLATE_SHA[${stage}]}" \
      --arg deployDeployedTemplateSha256 "${DEPLOY_TEMPLATE_SHA[${stage}]}" \
      --argjson regions "${regions_json}" '
        {
          bootstrapStackName: $bootstrapStackName,
          deployDeployedTemplateSha256: $deployDeployedTemplateSha256,
          deployPolicySha256: $deployPolicySha256,
          deployRoleArnTemplate:
            ("arn:aws:iam::<AWS_ACCOUNT_ID>:role/archon-datahub-github-" +
              $stage + "-deploy"),
          deployRoleBindingSha256: $deployRoleBindingSha256,
          executionPolicySha256: $executionPolicySha256,
          iamDeployedTemplateSha256: $iamDeployedTemplateSha256,
          publicViewerDns: {
            domainName: $cloudFrontDomainName,
            hostedZoneId: $cloudFrontHostedZoneId,
            validation: "passed"
          },
          qualifier: $qualifier,
          regions: $regions,
          runtimeBoundarySha256: $runtimeBoundarySha256,
          stage: $stage,
          validation: "passed"
        }
      '
  )"
  stages_json="$(
    jq -cnS \
      --argjson current "${stages_json}" \
      --argjson addition "${stage_evidence}" \
      '$current + [$addition]'
  )"
done

cp "${drift_file}" "${EVIDENCE_DIR}/drift.json"
source_hashes="$(
  for source_path in \
    .github/workflows/aws-foundation.yml \
    contracts/aws-foundation-v1.json \
    infra/aws/package.json \
    infra/aws/package-lock.json \
    infra/aws/foundation/api-gateway-account.yml \
    infra/aws/foundation/cdk-execution-policy.yml \
    infra/aws/foundation/github-actions-deploy-role.yml \
    infra/aws/foundation/github-actions-foundation-policy.json \
    infra/aws/foundation/github-actions-foundation-role.yml \
    infra/aws/foundation/governed-canary-roles.yml \
    scripts/bootstrap-aws-foundation-role.sh \
    scripts/patch-cdk-brace-expansion.sh \
    scripts/patch-cdk-bootstrap-template.mjs \
    scripts/render-canonical-flow-yaml.mjs \
    scripts/aws-cloudformation-drift.sh \
    scripts/reconcile-aws-foundation.sh \
    scripts/render-inline-cloudformation-template.sh \
    scripts/render-aws-foundation-policy.mjs \
    scripts/seal-cdk-bootstrap-templates.sh \
    scripts/verify-aws-runtime-boundary.mjs \
    scripts/verify-cdk-npm-audit-compensation.sh \
    scripts/verify-exact-npm-overrides.mjs; do
    jq -cn \
      --arg path "${source_path}" \
      --arg sha256 "$(sha256sum "${source_path}" | awk '{print $1}')" \
      '{path: $path, sha256: $sha256}'
  done |
  jq -csS 'sort_by(.path)'
)"
runtime_inventory_sha="$(
  jq -cS '.aws.runtimeBoundary' contracts/aws-foundation-v1.json |
    sha256sum |
    awk '{print $1}'
)"
foundation_json="${EVIDENCE_DIR}/foundation.json"
jq -cnS \
  --arg repository "${GITHUB_REPOSITORY}" \
  --arg ref "${GITHUB_REF}" \
  --arg controlPlaneSha "${CONTROL_PLANE_SHA}" \
  --arg workflowSha "${GITHUB_WORKFLOW_SHA}" \
  --argjson runId "${GITHUB_RUN_ID}" \
  --argjson runAttempt "${GITHUB_RUN_ATTEMPT}" \
  --arg foundationPolicyActualSha256 "${FOUNDATION_POLICY_ACTUAL_SHA}" \
  --arg iamFoundationTemplateSha256 "${IAM_FOUNDATION_TEMPLATE_SHA}" \
  --arg iamFoundationSemanticSha256 "${IAM_FOUNDATION_SEMANTIC_SHA}" \
  --arg bootstrapTemplateSha256 "${BOOTSTRAP_TEMPLATE_SHA}" \
  --argjson pinnedBootstrapVersion "${PINNED_BOOTSTRAP_VERSION}" \
  --arg driftSha256 "${drift_sha}" \
  --argjson driftStackCount "${drift_stack_count}" \
  --argjson driftGlobalTimeoutSeconds "${CFN_DRIFT_PHASE_TIMEOUT_SECONDS}" \
  --argjson driftMaximumPollAttempts "${CFN_DRIFT_MAX_ATTEMPTS}" \
  --argjson driftMaximumApiFailures "${CFN_DRIFT_MAX_API_FAILURES}" \
  --argjson driftPollDelaySeconds "${CFN_DRIFT_DELAY_SECONDS}" \
  --arg runtimeInventorySha256 "${runtime_inventory_sha}" \
  --argjson sharedApiGateway "${shared_api_gateway_json}" \
  --arg governedCanaryDeployedTemplateSha256 "${canary_template_sha}" \
  --argjson governedCanaryRoles "${canary_roles_json}" \
  --argjson operationalRoles "${operational_roles_json}" \
  --argjson applicationStackRoles "${application_stack_roles_json}" \
  --argjson applicationStackRoleTransition \
    "${application_stack_role_transition_json}" \
  --argjson sourceArtifacts "${source_hashes}" \
  --argjson stages "${stages_json}" \
  --arg completedAt "$(date --utc +'%Y-%m-%dT%H:%M:%SZ')" '
    {
      aws: {
        foundationPolicyActualSha256: $foundationPolicyActualSha256,
        iamFoundationSemanticSha256: $iamFoundationSemanticSha256,
        iamFoundationTemplateSha256: $iamFoundationTemplateSha256,
        applicationStackRolePreflight: $applicationStackRoles,
        applicationStackRoleTransition: $applicationStackRoleTransition,
        governedCanary: {
          deployedTemplateSha256: $governedCanaryDeployedTemplateSha256,
          roles: $governedCanaryRoles,
          stackName: "Archon-Governed-Canary-Roles",
          validation: "passed"
        },
        operationalRoles: $operationalRoles,
        partition: "aws",
        runtimeInventorySha256: $runtimeInventorySha256,
        sharedApiGateway: $sharedApiGateway,
        stages: $stages
      },
      bootstrapTemplate: {
        minimumVersion: 6,
        pinnedVersion: $pinnedBootstrapVersion,
        sha256: $bootstrapTemplateSha256
      },
      completedAt: $completedAt,
      drift: {
        coverage: "cloudformation-supported-resources",
        externalBindingCount:
          (if $sharedApiGateway.mode == "external-pinned" then 1 else 0 end),
        globalTimeoutSeconds: $driftGlobalTimeoutSeconds,
        managedStackCount: $driftStackCount,
        maximumConsecutiveApiFailuresPerStack: $driftMaximumApiFailures,
        maximumPollAttemptsPerStack: $driftMaximumPollAttempts,
        method: "detect-then-bounded-describe-poll",
        pollDelaySeconds: $driftPollDelaySeconds,
        stackIncarnationBinding: "exact-stack-id-and-monotonic-detection-lower-bound",
        sha256: $driftSha256,
        status: "IN_SYNC"
      },
      schemaVersion: "archon.aws-foundation-evidence/v1",
      source: {
        artifacts: $sourceArtifacts,
        controlPlaneSha: $controlPlaneSha,
        ref: $ref,
        repository: $repository,
        runAttempt: $runAttempt,
        runId: $runId,
        workflowPath: ".github/workflows/aws-foundation.yml",
        workflowSha: $workflowSha
      },
      validation: "passed"
    }
  ' >"${foundation_json}"
jq -e '
  .schemaVersion == "archon.aws-foundation-evidence/v1" and
  .validation == "passed" and
  (
    .aws.iamFoundationTemplateSha256 |
    test("^[0-9a-f]{64}$")
  ) and
  (
    .aws.iamFoundationSemanticSha256 |
    test("^[0-9a-f]{64}$")
  ) and
  (
    .aws.iamFoundationSemanticSha256 as $expected |
    all(.aws.stages[];
      .iamDeployedTemplateSha256 == $expected
    )
  ) and
  (.aws.applicationStackRolePreflight | length) == 5 and
  all(.aws.applicationStackRolePreflight[];
    .validation == "passed" or
    .validation == "requires-explicit-deploy-migration"
  ) and
  (
    (
      [
        .aws.applicationStackRolePreflight[] |
        select(.validation == "requires-explicit-deploy-migration")
      ] |
      length
    ) as $migrationRequiredCount |
    (
      if $migrationRequiredCount == 0 then
        all(.aws.applicationStackRolePreflight[];
          .validation == "passed"
        ) and
        .aws.applicationStackRoleTransition == {
          deployRequirement: "exact-role-postcheck",
          foundationOutcome: "passed",
          migrationRequiredCount: 0,
          state: "ready-for-deploy"
        }
      else
        .aws.applicationStackRoleTransition == {
          deployRequirement: "explicit-role-migration",
          foundationOutcome: "passed",
          migrationRequiredCount: $migrationRequiredCount,
          state: "foundation-complete-deploy-migration-required"
        }
      end
    )
  ) and
  (.drift.sha256 | test("^[0-9a-f]{64}$")) and
  .drift.status == "IN_SYNC" and
  .drift.coverage == "cloudformation-supported-resources" and
  .drift.method == "detect-then-bounded-describe-poll" and
  .drift.globalTimeoutSeconds == 900 and
  .drift.maximumPollAttemptsPerStack == 120 and
  .drift.pollDelaySeconds == 2 and
  .drift.maximumConsecutiveApiFailuresPerStack == 3 and
  .drift.stackIncarnationBinding == "exact-stack-id-and-monotonic-detection-lower-bound" and
  (
    if .aws.sharedApiGateway.mode == "foundation-managed" then
      .drift.managedStackCount == 10 and
      .drift.externalBindingCount == 0
    else
      .drift.managedStackCount == 9 and
      .drift.externalBindingCount == 1
    end
  ) and
  (.aws.stages | map(.stage)) == ["staging", "production"] and
  (
    [.aws.stages[].publicViewerDns.domainName] |
    unique |
    length
  ) == 2 and
  all(.aws.stages[];
    .validation == "passed" and
    .publicViewerDns.validation == "passed" and
    (.publicViewerDns.domainName |
      test("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")) and
    (.publicViewerDns.hostedZoneId | test("^Z[A-Z0-9]{1,31}$")) and
    (.regions | map(.region)) == ["eu-west-1", "us-east-1"] and
    all(.regions[];
      .bootstrapVersion == 32 and
      .ssmVersion == 32 and
      .terminationProtection == true and
      .validation == "passed"
    )
  ) and
  .aws.governedCanary.validation == "passed" and
  (.aws.governedCanary.roles | map(.kind)) ==
    ["prepare", "approval", "recovery"] and
  all(.aws.governedCanary.roles[]; .validation == "passed") and
  (.aws.operationalRoles | map(.kind)) == [
    "judge-staging",
    "judge-production",
    "posture-observer",
    "runtime-read",
    "paging-test"
  ] and
  all(.aws.operationalRoles[]; .validation == "passed") and
  .aws.sharedApiGateway.takeover == "forbidden" and
  (.aws.sharedApiGateway.roleBindingSha256 | test("^[0-9a-f]{64}$")) and
  (
    if .aws.sharedApiGateway.mode == "foundation-managed" then
      .aws.sharedApiGateway.validation == "managed-and-verified" and
      .aws.sharedApiGateway.external == null and
      .aws.sharedApiGateway.managed.stackName ==
        "Archon-Shared-ApiGateway-Logging" and
      (.aws.sharedApiGateway.managed.deployedTemplateSha256 |
        test("^[0-9a-f]{64}$")) and
      (.aws.sharedApiGateway.managed.inlinePolicySha256 |
        test("^[0-9a-f]{64}$"))
    else
      .aws.sharedApiGateway.mode == "external-pinned" and
      .aws.sharedApiGateway.validation == "pinned-and-unchanged" and
      .aws.sharedApiGateway.managed == null and
      .aws.sharedApiGateway.external == {
        bindingSha256: .aws.sharedApiGateway.roleBindingSha256,
        bindingSha256Variable:
          "AWS_SHARED_API_GATEWAY_ROLE_ARN_SHA256",
        bindingState: "UNCHANGED",
        managedStackAbsent: true,
        mutation: "none",
        roleArnTemplate:
          "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<PINNED_EXTERNAL_ROLE_PATH_AND_NAME>",
        sameAccountRoleArn: true
      }
    end
  )
' "${foundation_json}" >/dev/null

foundation_sha="$(sha256sum "${foundation_json}" | awk '{print $1}')"
manifest="${EVIDENCE_DIR}/manifest.json"
jq -cnS \
  --arg foundationSha256 "${foundation_sha}" \
  --arg driftSha256 "${drift_sha}" \
  --arg controlPlaneSha "${CONTROL_PLANE_SHA}" \
  --arg bootstrapTemplateSha256 "${BOOTSTRAP_TEMPLATE_SHA}" '
    {
      bootstrapTemplateSha256: $bootstrapTemplateSha256,
      controlPlaneSha: $controlPlaneSha,
      driftSha256: $driftSha256,
      foundationSha256: $foundationSha256,
      schemaVersion: "archon.aws-foundation-manifest/v1"
    }
  ' >"${manifest}"
manifest_sha="$(sha256sum "${manifest}" | awk '{print $1}')"
predicate="${EVIDENCE_DIR}/attestation-predicate.json"
jq -cnS \
  --arg foundationSha256 "${foundation_sha}" \
  --arg manifestSha256 "${manifest_sha}" \
  --arg driftSha256 "${drift_sha}" \
  --arg controlPlaneSha "${CONTROL_PLANE_SHA}" '
    {
      controlPlaneSha: $controlPlaneSha,
      driftSha256: $driftSha256,
      foundationSha256: $foundationSha256,
      manifestSha256: $manifestSha256,
      predicateType:
        "https://github.com/upgradedev/archon-datahub/attestations/aws-foundation/v1",
      schemaVersion: "archon.aws-foundation-predicate/v1"
    }
  ' >"${predicate}"
(
  cd "${EVIDENCE_DIR}"
  sha256sum drift.json foundation.json manifest.json \
    >foundation-subject.sha256
  sha256sum \
    attestation-predicate.json \
    drift.json \
    foundation-subject.sha256 \
    foundation.json \
    manifest.json >SHA256SUMS
  sha256sum --check --strict SHA256SUMS
)
expected_inventory="$(
  printf '%s\n' \
    SHA256SUMS \
    attestation-predicate.json \
    drift.json \
    foundation-subject.sha256 \
    foundation.json \
    manifest.json
)"
test "$(
  find "${EVIDENCE_DIR}" -mindepth 1 -maxdepth 1 \
    -type f -printf '%f\n' |
    LC_ALL=C sort
)" = "${expected_inventory}"
test -z "$(
  find "${EVIDENCE_DIR}" -mindepth 1 \
    \( -type l -o -type d \) \
    -print -quit
)"
if grep -R -F "${EXPECTED_ACCOUNT_ID}" "${EVIDENCE_DIR}"; then
  echo "::error::Foundation evidence contains the raw AWS account ID"
  exit 1
fi
if grep -R -E \
  'arn:aws:(iam|sts)::[0-9]{12}:|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}' \
  "${EVIDENCE_DIR}"; then
  echo "::error::Foundation evidence contains raw AWS identity material"
  exit 1
fi
for json_document in \
  "${EVIDENCE_DIR}/drift.json" \
  "${foundation_json}" \
  "${manifest}" \
  "${predicate}"; do
  jq -e '
    [
      paths(scalars) as $path |
      ($path[-1] | tostring) |
      select(test(
        "(^|_)(secret|token|password|credential|api[_-]?key)($|_)";
        "i"
      ))
    ] |
    length == 0
  ' "${json_document}" >/dev/null
done

combined_deploy_binding_sha="$(
  printf '%s\n' \
    "${DEPLOY_ROLE_BINDING_SHA[staging]}" \
    "${DEPLOY_ROLE_BINDING_SHA[production]}" |
    sha256sum |
    awk '{print $1}'
)"
combined_canary_binding_sha="$(
  printf '%s\n' \
    "${CANARY_ROLE_BINDING_SHA[prepare]}" \
    "${CANARY_ROLE_BINDING_SHA[approval]}" \
    "${CANARY_ROLE_BINDING_SHA[recovery]}" |
    sha256sum |
    awk '{print $1}'
)"
combined_operational_binding_sha="$(
  printf '%s\n' \
    "${OPERATIONAL_ROLE_BINDING_SHA[judge-staging]}" \
    "${OPERATIONAL_ROLE_BINDING_SHA[judge-production]}" \
    "${OPERATIONAL_ROLE_BINDING_SHA[posture-observer]}" \
    "${OPERATIONAL_ROLE_BINDING_SHA[runtime-read]}" \
    "${OPERATIONAL_ROLE_BINDING_SHA[paging-test]}" |
    sha256sum |
    awk '{print $1}'
)"
{
  echo "path=${EVIDENCE_DIR}"
  echo "subject=${EVIDENCE_DIR}/foundation-subject.sha256"
  echo "predicate=${predicate}"
  echo "foundation_sha=${foundation_sha}"
  echo "manifest_sha=${manifest_sha}"
  echo "drift_sha=${drift_sha}"
  echo "deploy_role_binding_sha=${combined_deploy_binding_sha}"
  echo "canary_role_binding_sha=${combined_canary_binding_sha}"
  echo "operational_role_binding_sha=${combined_operational_binding_sha}"
  echo "application_stack_role_transition=${application_stack_role_transition_state}"
  echo "shared_api_gateway_mode=${shared_api_gateway_mode}"
  echo "drift_stack_count=${drift_stack_count}"
} >>"${GITHUB_OUTPUT}"
echo "::endgroup::"
