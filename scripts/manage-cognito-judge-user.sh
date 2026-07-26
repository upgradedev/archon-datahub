#!/usr/bin/env bash
set -euo pipefail

# CI/CD-only lifecycle boundary for one exact Cognito judge identity. Its email and
# stable password enter only through the protected environment. Dispatch and approval
# bind an opaque immutable account ID, never the email or either credential.

mode="${1:-}"
lifecycle_output_path="${OUTPUT_PATH:-}"
lifecycle_started_at="${LIFECYCLE_STARTED_AT:-}"

fail() {
  printf '::error::%s\n' "$1" >&2
  exit 1
}

validate_application_origin() {
  local origin="$1"
  local host
  local tld
  local -a labels
  local label

  [[ "${origin}" == https://* ]] ||
    fail "The approved application URL must be an exact HTTPS origin"
  host="${origin#https://}"
  (( ${#host} >= 4 && ${#host} <= 253 )) ||
    fail "The approved application URL has an invalid host length"
  [[ "${host}" =~ ^[a-z0-9.-]+$ &&
    "${host}" == *.* &&
    "${host}" != .* &&
    "${host}" != *. &&
    "${host}" != *..* ]] ||
    fail "The approved application URL must contain only an exact lower-case DNS host"
  IFS='.' read -r -a labels <<<"${host}"
  for label in "${labels[@]}"; do
    (( ${#label} >= 1 && ${#label} <= 63 )) &&
      [[ "${label}" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] ||
      fail "The approved application URL contains an invalid DNS label"
  done
  tld="${labels[${#labels[@]} - 1]}"
  [[ "${tld}" =~ ^[a-z]([a-z0-9-]*[a-z0-9])?$ ]] ||
    fail "The approved application URL contains an invalid DNS suffix"
  case "${tld}" in
    example|invalid|localhost|test)
      fail "The approved application URL uses a reserved DNS suffix"
      ;;
  esac
}

validate_request() {
  case "${JUDGE_USER_OPERATION:-}" in
    provision|rotate|reactivate|deactivate)
      ;;
    *)
      fail "JUDGE_USER_OPERATION must be provision, rotate, reactivate, or deactivate"
      ;;
  esac
  case "${ARCHON_STAGE:-}" in
    staging|production)
      ;;
    *)
      fail "ARCHON_STAGE must be staging or production"
      ;;
  esac
  [[ "${JUDGE_ACCOUNT_ID:-}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "JUDGE_ACCOUNT_ID must be an exact opaque 64-hex binding"
}

validate_judge_username() {
  local username="${JUDGE_USERNAME:-}"
  local local_part="${username%%@*}"

  test -n "${username}" ||
    fail "JUDGE_USERNAME is required"
  (( ${#username} <= 128 )) ||
    fail "JUDGE_USERNAME is too long"
  (( ${#local_part} <= 64 )) ||
    fail "The judge email local part is too long"
  [[ "${username}" != *..* ]] ||
    fail "JUDGE_USERNAME must not contain consecutive dots"
  [[ "${username}" =~ ^[a-z0-9]([a-z0-9._%+-]{0,62}[a-z0-9])?@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] ||
    fail "JUDGE_USERNAME must be an exact lower-case email address"
}

validate_judge_password() {
  local password="$1"

  test -n "${password}" ||
    fail "The protected JUDGE_PASSWORD secret is required"
  (( ${#password} >= 14 && ${#password} <= 128 )) ||
    fail "The protected judge password does not meet the length contract"
  [[ "${password}" =~ [[:lower:]] &&
    "${password}" =~ [[:upper:]] &&
    "${password}" =~ [[:digit:]] &&
    "${password}" =~ [^[:alnum:][:space:]] &&
    "${password}" != *[[:space:]]* ]] ||
    fail "The protected judge password does not meet the Cognito policy"
}

validate_request

case "${mode}" in
  request)
    printf 'Validated the explicit %s request for %s.\n' \
      "${JUDGE_USER_OPERATION}" "${ARCHON_STAGE}"
    exit 0
    ;;
  apply)
    validate_judge_username
    : "${RUNNER_TEMP:?RUNNER_TEMP is required}"
    : "${lifecycle_output_path:?OUTPUT_PATH is required}"
    : "${lifecycle_started_at:?LIFECYCLE_STARTED_AT is required}"
    [[ "${RUNNER_TEMP}" == /* ]] ||
      fail "RUNNER_TEMP must be absolute"
    test "${lifecycle_output_path}" = \
      "${RUNNER_TEMP}/judge-user-operation-evidence/judge-operation-state.json" ||
      fail "OUTPUT_PATH must be the exact lifecycle state receipt path"
    [[ "${lifecycle_started_at}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] ||
      fail "LIFECYCLE_STARTED_AT must be a canonical UTC timestamp"
    test "$(
      date -u --date="${lifecycle_started_at}" '+%Y-%m-%dT%H:%M:%SZ'
    )" = "${lifecycle_started_at}" ||
      fail "LIFECYCLE_STARTED_AT is not a valid UTC timestamp"
    mkdir -p "${RUNNER_TEMP}/judge-user-operation-evidence"
    test ! -L "${RUNNER_TEMP}/judge-user-operation-evidence" ||
      fail "The lifecycle evidence directory must not be a symbolic link"
    test ! -L "${lifecycle_output_path}" ||
      fail "OUTPUT_PATH must not be a symbolic link"
    test ! -e "${lifecycle_output_path}" ||
      fail "OUTPUT_PATH must be fresh"
    ;;
  *)
    fail "Usage: manage-cognito-judge-user.sh request|apply"
    ;;
esac

judge_username="${JUDGE_USERNAME:-}"
judge_password="${JUDGE_PASSWORD:-}"
unset JUDGE_PASSWORD JUDGE_USERNAME

: "${EXPECTED_ACCOUNT_ID:?EXPECTED_ACCOUNT_ID is required}"
: "${AWS_REGION:?AWS_REGION is required}"
: "${EXPECTED_APPLICATION_URL:?EXPECTED_APPLICATION_URL is required}"
[[ "${EXPECTED_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]] ||
  fail "EXPECTED_ACCOUNT_ID must be an exact 12-digit account"
[[ "${AWS_REGION}" =~ ^[a-z]{2}(-gov)?-[a-z]+-[1-9][0-9]*$ ]] ||
  fail "AWS_REGION is invalid"
validate_application_origin "${EXPECTED_APPLICATION_URL}"
if [[ -n "${AWS_DEFAULT_REGION:-}" ]]; then
  test "${AWS_DEFAULT_REGION}" = "${AWS_REGION}" ||
    fail "AWS region variables disagree"
fi

for override_name in \
  AWS_ENDPOINT_URL \
  AWS_ENDPOINT_URL_CLOUDFORMATION \
  AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER \
  AWS_ENDPOINT_URL_COGNITO_IDP \
  AWS_ENDPOINT_URL_STS \
  AWS_ENDPOINT_URL_WAFV2 \
  AWS_PROFILE \
  AWS_DEFAULT_PROFILE; do
  test -z "${!override_name:-}" ||
    fail "AWS endpoint and profile overrides are forbidden"
done

if [[ "${JUDGE_USER_OPERATION}" != "deactivate" ]]; then
  validate_judge_password "${judge_password}"
fi

export AWS_CLI_AUTO_PROMPT=off
export AWS_CONFIG_FILE=/dev/null
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true
export AWS_PAGER=""
export AWS_SHARED_CREDENTIALS_FILE=/dev/null

work_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/archon-judge-user.XXXXXX")"
aws_error="${work_dir}/aws-error"
identity_document="${work_dir}/identity.json"
user_document="${work_dir}/user.json"
groups_document="${work_dir}/groups.json"
pool_document="${work_dir}/pool.json"
client_document="${work_dir}/client.json"
client_inventory_document="${work_dir}/client-inventory.json"
risk_document="${work_dir}/risk.json"
cognito_waf_document="${work_dir}/cognito-waf.json"
user_pool_id=""
user_pool_client_id=""
application_url=""
application_host=""
application_redirect_url=""
regional_web_acl_arn=""
user_pool_arn=""
aws_partition=""
approver_group=""
canonical=""
contain_on_failure=false
containment_mode=""
containment_canonical=""
operation_binding=""
operation_complete=false
prior_identity_state=""
prior_access_state=""
prior_authentication_state=""
prior_authorization_state=""
final_identity_state=""
final_access_state=""
final_authentication_state=""
final_authorization_state=""
transition_result=""
session_revocation_result=""

cleanup() {
  local exit_status=$?

  trap - EXIT
  if [[ "${contain_on_failure}" == "true" &&
    "${operation_complete}" != "true" &&
    -n "${user_pool_id}" &&
    -n "${approver_group}" ]]; then
    if ! declare -F automatic_containment >/dev/null ||
      ! automatic_containment; then
      printf '%s\n' \
        "::error::Automatic containment could not prove the exact workflow-owned judge identity safe" \
        >&2
    fi
  fi
  unset judge_password judge_username internal_temporary_password
  unset create_request password_request operation_binding
  rm -rf -- "${work_dir}"
  exit "${exit_status}"
}
trap cleanup EXIT

write_lifecycle_state_receipt() {
  local cognito_subject
  local cognito_subject_digest
  local completed_at
  local completed_epoch
  local identity_digest
  local application_origin_sha256
  local temporary_output

  completed_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  completed_epoch="$(date -u --date="${completed_at}" +%s)"
  test "$(
    date -u --date="${lifecycle_started_at}" +%s
  )" -le "${completed_epoch}" ||
    fail "The lifecycle completion timestamp precedes its start"
  identity_digest="$(
    printf 'archon-judge-identity-v1\0%s' "${JUDGE_ACCOUNT_ID}" |
      sha256sum |
      awk '{print $1}'
  )"
  cognito_subject="$(
    jq -er '
      [
        (.UserAttributes // [])[] |
        select(.Name == "sub")
      ] |
      select(length == 1) |
      .[0].Value as $subject |
      select(
        ($subject | type) == "string" and
        (
          $subject |
          test(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
          )
        )
      ) |
      $subject
    ' "${user_document}"
  )" || fail "The final Cognito subject is not one canonical lower-case UUID"
  cognito_subject_digest="$(
    printf 'archon-cognito-subject-v1\0%s' "${cognito_subject}" |
      sha256sum |
      awk '{print $1}'
  )"
  unset cognito_subject
  application_origin_sha256="$(
    printf '%s' "${EXPECTED_APPLICATION_URL}" |
      sha256sum |
      awk '{print $1}'
  )"
  [[ "${identity_digest}" =~ ^[0-9a-f]{64}$ ]]
  [[ "${cognito_subject_digest}" =~ ^[0-9a-f]{64}$ ]]
  [[ "${application_origin_sha256}" =~ ^[0-9a-f]{64}$ ]]
  for state_value in \
    "${prior_identity_state}" \
    "${prior_access_state}" \
    "${prior_authentication_state}" \
    "${prior_authorization_state}" \
    "${final_identity_state}" \
    "${final_access_state}" \
    "${final_authentication_state}" \
    "${final_authorization_state}" \
    "${session_revocation_result}" \
    "${transition_result}"; do
    [[ "${state_value}" =~ ^[a-z][a-z0-9-]{1,63}$ ]] ||
      fail "The sanitized lifecycle transition has an invalid state"
  done

  temporary_output="$(
    mktemp \
      "${RUNNER_TEMP}/judge-user-operation-evidence/.judge-operation-state.XXXXXX"
  )"
  jq -cnS \
    --arg stage "${ARCHON_STAGE}" \
    --arg operation "${JUDGE_USER_OPERATION}" \
    --arg identityDigest "${identity_digest}" \
    --arg cognitoSubjectDigest "${cognito_subject_digest}" \
    --arg applicationOriginSha256 "${application_origin_sha256}" \
    --arg startedAt "${lifecycle_started_at}" \
    --arg completedAt "${completed_at}" \
    --arg priorIdentity "${prior_identity_state}" \
    --arg priorAccess "${prior_access_state}" \
    --arg priorAuthentication "${prior_authentication_state}" \
    --arg priorAuthorization "${prior_authorization_state}" \
    --arg finalIdentity "${final_identity_state}" \
    --arg finalAccess "${final_access_state}" \
    --arg finalAuthentication "${final_authentication_state}" \
    --arg finalAuthorization "${final_authorization_state}" \
    --arg sessionRevocation "${session_revocation_result}" \
    --arg result "${transition_result}" '
      {
        schemaVersion: "archon.judge-user-state-transition/v1",
        stage: $stage,
        operation: $operation,
        identityDigest: $identityDigest,
        cognitoSubjectDigest: $cognitoSubjectDigest,
        applicationOriginSha256: $applicationOriginSha256,
        priorState: {
          identity: $priorIdentity,
          access: $priorAccess,
          authentication: $priorAuthentication,
          authorization: $priorAuthorization
        },
        finalState: {
          identity: $finalIdentity,
          access: $finalAccess,
          authentication: $finalAuthentication,
          authorization: $finalAuthorization
        },
        sessionRevocation: $sessionRevocation,
        startedAt: $startedAt,
        completedAt: $completedAt,
        observation: {
          priorState: "exact-operation-precondition",
          finalState: "exact-aws-read-back"
        },
        result: $result,
        sanitized: true,
        secretMaterialRetained: false
      }
    ' >"${temporary_output}"
  test -s "${temporary_output}"
  test ! -L "${temporary_output}"
  jq -e \
    --arg stage "${ARCHON_STAGE}" \
    --arg operation "${JUDGE_USER_OPERATION}" \
    --arg identityDigest "${identity_digest}" \
    --arg cognitoSubjectDigest "${cognito_subject_digest}" \
    --arg applicationOriginSha256 "${application_origin_sha256}" \
    --arg startedAt "${lifecycle_started_at}" \
    --arg completedAt "${completed_at}" \
    --arg priorIdentity "${prior_identity_state}" \
    --arg priorAccess "${prior_access_state}" \
    --arg priorAuthentication "${prior_authentication_state}" \
    --arg priorAuthorization "${prior_authorization_state}" \
    --arg finalIdentity "${final_identity_state}" \
    --arg finalAccess "${final_access_state}" \
    --arg finalAuthentication "${final_authentication_state}" \
    --arg finalAuthorization "${final_authorization_state}" \
    --arg sessionRevocation "${session_revocation_result}" \
    --arg result "${transition_result}" '
      (keys | sort) == [
        "applicationOriginSha256",
        "cognitoSubjectDigest",
        "completedAt",
        "finalState",
        "identityDigest",
        "observation",
        "operation",
        "priorState",
        "result",
        "sanitized",
        "schemaVersion",
        "secretMaterialRetained",
        "sessionRevocation",
        "stage",
        "startedAt"
      ] and
      .schemaVersion == "archon.judge-user-state-transition/v1" and
      .stage == $stage and
      .operation == $operation and
      .identityDigest == $identityDigest and
      .cognitoSubjectDigest == $cognitoSubjectDigest and
      .applicationOriginSha256 == $applicationOriginSha256 and
      .priorState == {
        identity: $priorIdentity,
        access: $priorAccess,
        authentication: $priorAuthentication,
        authorization: $priorAuthorization
      } and
      .finalState == {
        identity: $finalIdentity,
        access: $finalAccess,
        authentication: $finalAuthentication,
        authorization: $finalAuthorization
      } and
      .sessionRevocation == $sessionRevocation and
      .startedAt == $startedAt and
      .completedAt == $completedAt and
      .observation == {
        priorState: "exact-operation-precondition",
        finalState: "exact-aws-read-back"
      } and
      .result == $result and
      .sanitized == true and
      .secretMaterialRetained == false and
      ([.. | strings] | all(
        test(
          "(?i)(-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|Bearer[[:space:]]+[A-Za-z0-9._~+/=-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-)"
        ) | not
      ))
    ' "${temporary_output}" >/dev/null ||
    fail "The sanitized lifecycle state receipt failed validation"
  chmod 0600 "${temporary_output}"
  mv -- "${temporary_output}" "${lifecycle_output_path}"
  test -f "${lifecycle_output_path}"
  test ! -L "${lifecycle_output_path}"
}

[[ "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]{0,19}$ ]] ||
  fail "GITHUB_RUN_ID is invalid"
case "${AWS_REGION}" in
  cn-*) aws_partition="aws-cn" ;;
  us-gov-*) aws_partition="aws-us-gov" ;;
  *) aws_partition="aws" ;;
esac
expected_role_name="archon-${ARCHON_STAGE}-judge-user"
expected_session_name="archon-judge-${GITHUB_RUN_ID}-${ARCHON_STAGE}"
expected_assumed_role_arn="arn:${aws_partition}:sts::${EXPECTED_ACCOUNT_ID}:assumed-role/${expected_role_name}/${expected_session_name}"

aws sts get-caller-identity \
  --region "${AWS_REGION}" \
  --output json \
  --no-cli-pager >"${identity_document}" 2>"${aws_error}" ||
  fail "Unable to verify the assumed AWS identity"
jq -e \
  --arg account "${EXPECTED_ACCOUNT_ID}" \
  --arg arn "${expected_assumed_role_arn}" \
  --arg session "${expected_session_name}" '
    .Account == $account and
    .Arn == $arn and
    (.UserId | type == "string") and
    (.UserId | split(":") | length) == 2 and
    (.UserId | endswith(":" + $session))
  ' "${identity_document}" >/dev/null ||
  fail "The assumed principal is not the exact stage-specific judge role session"

stack_name="Archon-${ARCHON_STAGE}"
stack_document="$(
  aws cloudformation describe-stacks \
    --region "${AWS_REGION}" \
    --stack-name "${stack_name}" \
    --output json \
    --no-cli-pager 2>"${aws_error}"
)" || fail "Unable to read the exact Archon stack"

jq -e '
  (.Stacks | length) == 1 and
  (
    .Stacks[0].StackStatus == "CREATE_COMPLETE" or
    .Stacks[0].StackStatus == "UPDATE_COMPLETE"
  )
' <<<"${stack_document}" >/dev/null ||
  fail "The exact Archon stack is not in an accepted stable state"

user_pool_id="$(
  jq -er '
    [
      (.Stacks[0].Outputs // [])[] |
      select(.OutputKey == "ArchonUserPoolId") |
      .OutputValue
    ] |
    select(length == 1) |
    .[0]
  ' <<<"${stack_document}"
)" || fail "ArchonUserPoolId is missing or ambiguous"
approver_group="$(
  jq -er '
    [
      (.Stacks[0].Outputs // [])[] |
      select(.OutputKey == "ArchonApproverGroupName") |
      .OutputValue
    ] |
    select(length == 1) |
    .[0]
  ' <<<"${stack_document}"
)" || fail "ArchonApproverGroupName is missing or ambiguous"

[[ "${user_pool_id}" =~ ^${AWS_REGION}_[A-Za-z0-9]+$ ]] ||
  fail "ArchonUserPoolId does not belong to the configured region"
test "${approver_group}" = "archon-approvers" ||
  fail "The approver group output is not the exact expected group"

if [[ "${JUDGE_USER_OPERATION}" != "deactivate" ]]; then
user_pool_client_id="$(
  jq -er '
    [
      (.Stacks[0].Outputs // [])[] |
      select(.OutputKey == "ArchonUserPoolClientId") |
      .OutputValue
    ] |
    select(length == 1) |
    .[0]
  ' <<<"${stack_document}"
)" || fail "ArchonUserPoolClientId is missing or ambiguous"
application_url="$(
  jq -er '
    [
      (.Stacks[0].Outputs // [])[] |
      select(.OutputKey == "ArchonApplicationUrl") |
      .OutputValue
    ] |
    select(length == 1) |
    .[0]
  ' <<<"${stack_document}"
)" || fail "ArchonApplicationUrl is missing or ambiguous"
regional_web_acl_arn="$(
  jq -er '
    [
      (.Stacks[0].Outputs // [])[] |
      select(.OutputKey == "ArchonRegionalWebAclArn") |
      .OutputValue
    ] |
    select(length == 1) |
    .[0]
  ' <<<"${stack_document}"
)" || fail "ArchonRegionalWebAclArn is missing or ambiguous"

[[ "${user_pool_client_id}" =~ ^[A-Za-z0-9]{1,128}$ ]] ||
  fail "ArchonUserPoolClientId is invalid"
[[ "${application_url}" == https://* ]] ||
  fail "ArchonApplicationUrl must be an exact credential-free HTTPS origin"
test "${application_url}" = "${EXPECTED_APPLICATION_URL}" ||
  fail "ArchonApplicationUrl does not match the independently approved target"
application_host="${application_url#https://}"
(( ${#application_host} >= 4 && ${#application_host} <= 253 )) ||
  fail "ArchonApplicationUrl has an invalid host length"
[[ "${application_host}" =~ ^[a-z0-9.-]+$ &&
  "${application_host}" == *.* &&
  "${application_host}" != .* &&
  "${application_host}" != *. &&
  "${application_host}" != *..* ]] ||
  fail "ArchonApplicationUrl must contain only an exact lower-case DNS host"
IFS='.' read -r -a application_labels <<<"${application_host}"
for application_label in "${application_labels[@]}"; do
  (( ${#application_label} >= 1 && ${#application_label} <= 63 )) &&
    [[ "${application_label}" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] ||
    fail "ArchonApplicationUrl contains an invalid DNS label"
done
application_tld="${application_labels[${#application_labels[@]} - 1]}"
[[ "${application_tld}" =~ ^[a-z]([a-z0-9-]*[a-z0-9])?$ ]] ||
  fail "ArchonApplicationUrl contains an invalid DNS suffix"
application_redirect_url="${application_url}/"
if [[ "${regional_web_acl_arn}" =~ ^arn:(aws|aws-us-gov|aws-cn):wafv2:${AWS_REGION}:${EXPECTED_ACCOUNT_ID}:regional/webacl/archon-${ARCHON_STAGE}-api/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  test "${BASH_REMATCH[1]}" = "${aws_partition}" ||
    fail "ArchonRegionalWebAclArn has the wrong AWS partition"
else
  fail "ArchonRegionalWebAclArn is not the exact stage/account/region ACL"
fi
user_pool_arn="arn:${aws_partition}:cognito-idp:${AWS_REGION}:${EXPECTED_ACCOUNT_ID}:userpool/${user_pool_id}"

aws cognito-idp describe-user-pool \
  --region "${AWS_REGION}" \
  --user-pool-id "${user_pool_id}" \
  --output json \
  --no-cli-pager >"${pool_document}" 2>"${aws_error}" ||
  fail "Unable to verify the exact Cognito user-pool configuration"
jq -e \
  --arg id "${user_pool_id}" \
  --arg name "archon-${ARCHON_STAGE}" '
    .UserPool.Id == $id and
    .UserPool.Name == $name and
    .UserPool.UsernameAttributes == ["email"] and
    ((.UserPool.AliasAttributes // []) | length) == 0 and
    .UserPool.UsernameConfiguration.CaseSensitive == false and
    .UserPool.AdminCreateUserConfig.AllowAdminCreateUserOnly == true and
    .UserPool.AccountRecoverySetting.RecoveryMechanisms == [
      {
        Name: "verified_email",
        Priority: 1
      }
    ] and
    .UserPool.Policies.PasswordPolicy.MinimumLength == 14 and
    .UserPool.Policies.PasswordPolicy.PasswordHistorySize == 24 and
    .UserPool.Policies.PasswordPolicy.RequireLowercase == true and
    .UserPool.Policies.PasswordPolicy.RequireUppercase == true and
    .UserPool.Policies.PasswordPolicy.RequireNumbers == true and
    .UserPool.Policies.PasswordPolicy.RequireSymbols == true and
    .UserPool.Policies.PasswordPolicy.TemporaryPasswordValidityDays == 3 and
    .UserPool.DeletionProtection == "ACTIVE" and
    .UserPool.MfaConfiguration == "OPTIONAL" and
    .UserPool.UserPoolTier == "PLUS" and
    .UserPool.UserPoolAddOns.AdvancedSecurityMode == "ENFORCED" and
    (
      [
        (.UserPool.SchemaAttributes // [])[] |
        select(
          .Name == "email" and
          .Required == true and
          .Mutable == false
        )
      ] |
      length
    ) == 1 and
    (
      [
        (.UserPool.SchemaAttributes // [])[] |
        select(
          .Name == "custom:archon_judge_binding" and
          .Required == false and
          .Mutable == false and
          .AttributeDataType == "String" and
          .StringAttributeConstraints.MinLength == "64" and
          .StringAttributeConstraints.MaxLength == "64"
        )
      ] |
      length
    ) == 1
  ' "${pool_document}" >/dev/null ||
  fail "The live Cognito user pool violates the judge-access contract"

aws cognito-idp list-user-pool-clients \
  --region "${AWS_REGION}" \
  --user-pool-id "${user_pool_id}" \
  --max-results 60 \
  --no-paginate \
  --output json \
  --no-cli-pager >"${client_inventory_document}" 2>"${aws_error}" ||
  fail "Unable to verify the exact Cognito app-client inventory"
jq -e \
  --arg pool "${user_pool_id}" \
  --arg client "${user_pool_client_id}" \
  --arg name "archon-${ARCHON_STAGE}-spa" '
    (. | has("NextToken") | not) and
    (.UserPoolClients | length) == 1 and
    .UserPoolClients[0].UserPoolId == $pool and
    .UserPoolClients[0].ClientId == $client and
    .UserPoolClients[0].ClientName == $name
  ' "${client_inventory_document}" >/dev/null ||
  fail "The Cognito pool contains a missing, extra, or paginated app client"

aws cognito-idp describe-user-pool-client \
  --region "${AWS_REGION}" \
  --user-pool-id "${user_pool_id}" \
  --client-id "${user_pool_client_id}" \
  --output json \
  --no-cli-pager >"${client_document}" 2>"${aws_error}" ||
  fail "Unable to verify the exact Cognito app-client configuration"
jq -e \
  --arg pool "${user_pool_id}" \
  --arg client "${user_pool_client_id}" \
  --arg name "archon-${ARCHON_STAGE}-spa" \
  --arg redirect "${application_redirect_url}" '
    .UserPoolClient.UserPoolId == $pool and
    .UserPoolClient.ClientId == $client and
    .UserPoolClient.ClientName == $name and
    .UserPoolClient.PreventUserExistenceErrors == "ENABLED" and
    .UserPoolClient.EnableTokenRevocation == true and
    .UserPoolClient.AccessTokenValidity == 15 and
    .UserPoolClient.IdTokenValidity == 15 and
    .UserPoolClient.RefreshTokenValidity == 1 and
    .UserPoolClient.TokenValidityUnits.AccessToken == "minutes" and
    .UserPoolClient.TokenValidityUnits.IdToken == "minutes" and
    .UserPoolClient.TokenValidityUnits.RefreshToken == "days" and
    .UserPoolClient.ExplicitAuthFlows == ["ALLOW_REFRESH_TOKEN_AUTH"] and
    .UserPoolClient.AllowedOAuthFlows == ["code"] and
    .UserPoolClient.AllowedOAuthFlowsUserPoolClient == true and
    (.UserPoolClient.AllowedOAuthScopes | sort) ==
      ["archon/approve", "email", "openid"] and
    all(
      .UserPoolClient.AllowedOAuthScopes[];
      . != "aws.cognito.signin.user.admin"
    ) and
    .UserPoolClient.CallbackURLs == [$redirect] and
    .UserPoolClient.LogoutURLs == [$redirect] and
    (
      (.UserPoolClient | has("DefaultRedirectURI") | not) or
      .UserPoolClient.DefaultRedirectURI == $redirect
    ) and
    .UserPoolClient.SupportedIdentityProviders == ["COGNITO"] and
    .UserPoolClient.ReadAttributes == ["email"] and
    (.UserPoolClient | has("ClientSecret") | not)
  ' "${client_document}" >/dev/null ||
  fail "The live Cognito app client violates the judge-access contract"

aws cognito-idp describe-risk-configuration \
  --region "${AWS_REGION}" \
  --user-pool-id "${user_pool_id}" \
  --client-id "${user_pool_client_id}" \
  --output json \
  --no-cli-pager >"${risk_document}" 2>"${aws_error}" ||
  fail "Unable to verify the exact Cognito app-client risk configuration"
jq -e \
  --arg pool "${user_pool_id}" \
  --arg client "${user_pool_client_id}" '
    .RiskConfiguration.UserPoolId == $pool and
    .RiskConfiguration.ClientId == $client and
    .RiskConfiguration.AccountTakeoverRiskConfiguration.Actions == {
      LowAction: {
        EventAction: "NO_ACTION",
        Notify: false
      },
      MediumAction: {
        EventAction: "NO_ACTION",
        Notify: false
      },
      HighAction: {
        EventAction: "NO_ACTION",
        Notify: false
      }
    } and
    (
      .RiskConfiguration.AccountTakeoverRiskConfiguration |
      has("NotifyConfiguration") |
      not
    ) and
    .RiskConfiguration.CompromisedCredentialsRiskConfiguration.Actions == {
      EventAction: "BLOCK"
    } and
    (
      .RiskConfiguration.CompromisedCredentialsRiskConfiguration.EventFilter |
      sort
    ) == ["PASSWORD_CHANGE", "SIGN_IN"] and
    (.RiskConfiguration | has("RiskExceptionConfiguration") | not)
  ' "${risk_document}" >/dev/null ||
  fail "The live Cognito app-client risk policy violates the judge-access contract"

expected_rate_limit=300
if [[ "${ARCHON_STAGE}" == "production" ]]; then
  expected_rate_limit=1000
fi
aws wafv2 get-web-acl-for-resource \
  --region "${AWS_REGION}" \
  --resource-arn "${user_pool_arn}" \
  --output json \
  --no-cli-pager >"${cognito_waf_document}" 2>"${aws_error}" ||
  fail "Unable to verify the Cognito user pool's direct WAF association"
jq -e \
  --arg arn "${regional_web_acl_arn}" \
  --arg name "archon-${ARCHON_STAGE}-api" \
  --argjson rate_limit "${expected_rate_limit}" '
    .WebACL.ARN == $arn and
    .WebACL.Name == $name and
    .WebACL.Id == ($arn | split("/") | last) and
    .WebACL.DefaultAction == {Allow: {}} and
    (.WebACL.Rules | length) == 4 and
    (
      [.WebACL.Rules[].Name] |
      sort
    ) == [
      "AWSManagedRulesAmazonIpReputationList",
      "AWSManagedRulesCommonRuleSet",
      "AWSManagedRulesKnownBadInputsRuleSet",
      "PerIpRateLimit"
    ] and
    all(
      .WebACL.Rules[] |
      select(.Name | startswith("AWSManagedRules"));
      .OverrideAction == {None: {}} and
      .Statement.ManagedRuleGroupStatement.VendorName == "AWS" and
      .Statement.ManagedRuleGroupStatement.Name == .Name and
      (
        .Statement.ManagedRuleGroupStatement |
        keys |
        sort
      ) == ["Name", "VendorName"]
    ) and
    (
      [
        .WebACL.Rules[] |
        .. |
        objects |
        select(
          has("Captcha") or
          has("CaptchaConfig") or
          has("Challenge") or
          has("ChallengeConfig")
        )
      ] |
      length
    ) == 0 and
    (
      [
        .WebACL.Rules[] |
        select(
          .Name == "PerIpRateLimit" and
          .Action == {Block: {}} and
          (
            .Statement.RateBasedStatement |
            keys |
            sort
          ) == [
            "AggregateKeyType",
            "EvaluationWindowSec",
            "Limit"
          ] and
          .Statement.RateBasedStatement.AggregateKeyType == "IP" and
          .Statement.RateBasedStatement.EvaluationWindowSec == 300 and
          .Statement.RateBasedStatement.Limit == $rate_limit
        )
      ] |
      length
    ) == 1
  ' "${cognito_waf_document}" >/dev/null ||
  fail "The Cognito user pool WAF does not match the exact compatible regional ACL"
fi

read_user_exact() {
  local username="$1"

  : >"${aws_error}"
  if aws cognito-idp admin-get-user \
    --region "${AWS_REGION}" \
    --user-pool-id "${user_pool_id}" \
    --username "${username}" \
    --output json \
    --no-cli-pager >"${user_document}" 2>"${aws_error}"; then
    return 0
  fi
  if grep -Fq "UserNotFoundException" "${aws_error}"; then
    return 3
  fi
  return 4
}

get_user() {
  local read_status

  if read_user_exact "${judge_username}"; then
    return 0
  else
    read_status=$?
  fi
  (( read_status == 3 )) && return 3
  fail "Unable to read the exact Cognito judge user"
}

user_binding_matches() {
  jq -e \
    --arg binding "${JUDGE_ACCOUNT_ID}" \
    --arg email "${judge_username}" '
    (.Username | type == "string" and length >= 1 and length <= 128) and
    (
      [
        (.UserAttributes // [])[] |
        select(.Name == "email")
      ] as $email_attributes |
      ($email_attributes | length) == 1 and
      $email_attributes[0].Value == $email
    ) and
    (
      [
        (.UserAttributes // [])[] |
        select(.Name == "custom:archon_judge_binding")
      ] as $binding_attributes |
      ($binding_attributes | length) == 1 and
      $binding_attributes[0].Value == $binding
    )
  ' "${user_document}" >/dev/null
}

user_subject_matches() {
  jq -e '
    (
      [
        (.UserAttributes // [])[] |
        select(.Name == "sub")
      ] as $subject_attributes |
      ($subject_attributes | length) == 1 and
      (
        $subject_attributes[0].Value as $subject |
        ($subject | type) == "string" and
        (
          $subject |
          test(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
          )
        )
      )
    )
  ' "${user_document}" >/dev/null
}

user_identity_matches() {
  user_binding_matches && user_subject_matches
}

user_access_state_matches() {
  jq -e '
    (
      [
        (.UserAttributes // [])[] |
        select(.Name == "email_verified")
      ] as $email_verified |
      ($email_verified | length) <= 1 and
      all($email_verified[]; .Value == "false")
    ) and
    ((.UserMFASettingList // []) == []) and
    ((.MFAOptions // []) == []) and
    ((.PreferredMfaSetting // "") == "")
  ' "${user_document}" >/dev/null
}

user_identity_matches_canonical() {
  local expected_canonical="$1"

  user_identity_matches &&
    jq -e --arg canonical "${expected_canonical}" \
      '.Username == $canonical' "${user_document}" >/dev/null
}

user_identity_matches_binding() {
  local expected_binding="$1"

  user_identity_matches &&
    jq -e --arg binding "${expected_binding}" '
      (
        [
          (.UserAttributes // [])[] |
          select(
            .Name == "custom:archon_judge_binding" and
            .Value == $binding
          )
        ] |
        length
      ) == 1
    ' "${user_document}" >/dev/null
}

containment_identity_matches_canonical() {
  local expected_canonical="$1"

  user_binding_matches &&
    jq -e --arg canonical "${expected_canonical}" \
      '.Username == $canonical' "${user_document}" >/dev/null
}

containment_identity_matches_binding() {
  local expected_binding="$1"

  user_binding_matches &&
    jq -e --arg binding "${expected_binding}" '
      (
        [
          (.UserAttributes // [])[] |
          select(
            .Name == "custom:archon_judge_binding" and
            .Value == $binding
          )
        ] |
        length
      ) == 1
    ' "${user_document}" >/dev/null
}

validate_user_identity() {
  user_identity_matches ||
    fail "Cognito did not resolve the exact requested judge identity"
  user_access_state_matches ||
    fail "The exact judge identity has an external recovery or MFA factor"
}

require_enabled_user() {
  validate_user_identity
  jq -e '.Enabled == true' "${user_document}" >/dev/null ||
    fail "The exact judge identity is not enabled"
}

wait_for_enabled_status() {
  local expected_status="$1"
  local expected_canonical="${2:-}"
  local expected_binding="${3:-}"
  local query_username="${judge_username}"
  local attempt

  if [[ -n "${expected_canonical}" ]]; then
    query_username="${expected_canonical}"
  fi
  for attempt in {1..5}; do
    if read_user_exact "${query_username}" &&
      user_identity_matches &&
      user_access_state_matches &&
      jq -e \
        --arg status "${expected_status}" '
          .Enabled == true and
          .UserStatus == $status
        ' "${user_document}" >/dev/null; then
      if [[ -n "${expected_canonical}" ]] &&
        ! user_identity_matches_canonical "${expected_canonical}"; then
        :
      elif [[ -n "${expected_binding}" ]] &&
        ! user_identity_matches_binding "${expected_binding}"; then
        :
      else
        return 0
      fi
    fi
    if (( attempt < 5 )); then
      sleep 2
    fi
  done
  return 1
}

wait_for_disabled_user() {
  local expected_canonical="$1"
  local attempt

  for attempt in {1..5}; do
    if read_user_exact "${expected_canonical}" &&
      user_identity_matches_canonical "${expected_canonical}" &&
      jq -e '.Enabled == false' "${user_document}" >/dev/null; then
      return 0
    fi
    if (( attempt < 5 )); then
      sleep 2
    fi
  done
  return 1
}

canonical_username() {
  local value

  value="$(canonical_username_from_document)" ||
    fail "The Cognito username is missing"
  printf '%s' "${value}"
}

canonical_username_from_document() {
  local value

  value="$(jq -er '.Username' "${user_document}")" || return 1
  [[ "${value}" =~ ^[A-Za-z0-9._:@+-]{1,128}$ ]] ||
    return 1
  printf '%s' "${value}"
}

read_groups_exact() {
  local username="$1"

  if ! aws cognito-idp admin-list-groups-for-user \
    --region "${AWS_REGION}" \
    --user-pool-id "${user_pool_id}" \
    --username "${username}" \
    --limit 60 \
    --no-paginate \
    --output json \
    --no-cli-pager >"${groups_document}" 2>"${aws_error}"; then
    return 4
  fi
  jq -e '
    (. | has("NextToken") | not) and
    ((.Groups // []) | type) == "array" and
    all((.Groups // [])[]; .GroupName | type == "string")
  ' "${groups_document}" >/dev/null || return 4
}

read_groups() {
  local username="$1"

  read_groups_exact "${username}" ||
    fail "Cognito returned an invalid group-membership document"
}

require_only_approver_group() {
  jq -e --arg group "${approver_group}" '
    ((.Groups // []) | map(.GroupName)) as $groups |
    ($groups | length) == 1 and
    $groups[0] == $group
  ' "${groups_document}" >/dev/null ||
    fail "The judge identity does not have exactly the approver group"
}

require_no_groups() {
  jq -e '((.Groups // []) | length) == 0' \
    "${groups_document}" >/dev/null ||
    fail "The judge identity must have no group before reactivation"
}

wait_for_only_approver_group() {
  local username="$1"
  local attempt

  for attempt in {1..5}; do
    read_groups "${username}"
    if jq -e --arg group "${approver_group}" '
      ((.Groups // []) | map(.GroupName)) as $groups |
      ($groups | length) == 1 and
      $groups[0] == $group
    ' "${groups_document}" >/dev/null; then
      return 0
    fi
    if (( attempt < 5 )); then
      sleep 2
    fi
  done
  return 1
}

add_approver_group() {
  local username="$1"

  aws cognito-idp admin-add-user-to-group \
    --region "${AWS_REGION}" \
    --user-pool-id "${user_pool_id}" \
    --username "${username}" \
    --group-name "${approver_group}" \
    --no-cli-pager >/dev/null 2>"${aws_error}" ||
    fail "Unable to add the exact judge user to the approver group"
}

global_sign_out() {
  local username="$1"

  aws cognito-idp admin-user-global-sign-out \
    --region "${AWS_REGION}" \
    --user-pool-id "${user_pool_id}" \
    --username "${username}" \
    --no-cli-pager >/dev/null 2>"${aws_error}"
}

exact_contained_state_proved() {
  local username="$1"

  # Cognito exposes user state and group membership through separate reads.
  # Treat them as one proof cycle and finish with a second disabled-user read,
  # so observations from different retries can never be combined.
  read_user_exact "${username}" &&
    containment_identity_matches_canonical "${username}" &&
    jq -e '.Enabled == false' "${user_document}" >/dev/null &&
    read_groups_exact "${username}" &&
    jq -e '((.Groups // []) | length) == 0' \
      "${groups_document}" >/dev/null &&
    read_user_exact "${username}" &&
    containment_identity_matches_canonical "${username}" &&
    jq -e '.Enabled == false' "${user_document}" >/dev/null
}

wait_for_exact_contained_state() {
  local username="$1"
  local attempt

  for attempt in {1..5}; do
    if exact_contained_state_proved "${username}"; then
      return 0
    fi
    (( attempt < 5 )) && sleep 2
  done
  return 1
}

automatic_containment() {
  local attempt
  local containment_username=""
  local identity_proved=false

  for attempt in {1..5}; do
    case "${containment_mode}" in
      provision)
        if read_user_exact "${judge_username}"; then
          if ! containment_identity_matches_binding "${operation_binding}"; then
            printf '%s\n' \
              "::error::Automatic containment refused an identity not bound to this provision attempt" \
              >&2
            return 1
          fi
          containment_username="$(canonical_username_from_document)" || return 1
          identity_proved=true
        fi
        ;;
      existing)
        if read_user_exact "${containment_canonical}"; then
          if ! containment_identity_matches_canonical "${containment_canonical}"; then
            printf '%s\n' \
              "::error::Automatic containment refused a changed canonical identity" \
              >&2
            return 1
          fi
          containment_username="${containment_canonical}"
          identity_proved=true
        fi
        ;;
      *)
        return 1
        ;;
    esac
    [[ "${identity_proved}" == "true" ]] && break
    (( attempt < 5 )) && sleep 2
  done
  [[ "${identity_proved}" == "true" ]] || return 1

  if ! aws cognito-idp admin-disable-user \
    --region "${AWS_REGION}" \
    --user-pool-id "${user_pool_id}" \
    --username "${containment_username}" \
    --no-cli-pager >/dev/null 2>"${aws_error}"; then
    printf '%s\n' \
      "::warning::The containment disable response was ambiguous; exact state read-back will decide" \
      >&2
  fi
  if ! aws cognito-idp admin-user-global-sign-out \
    --region "${AWS_REGION}" \
    --user-pool-id "${user_pool_id}" \
    --username "${containment_username}" \
    --no-cli-pager >/dev/null 2>"${aws_error}"; then
    printf '%s\n' \
      "::warning::The containment global-sign-out response was ambiguous" \
      >&2
  fi
  if ! aws cognito-idp admin-remove-user-from-group \
    --region "${AWS_REGION}" \
    --user-pool-id "${user_pool_id}" \
    --username "${containment_username}" \
    --group-name "${approver_group}" \
    --no-cli-pager >/dev/null 2>"${aws_error}"; then
    printf '%s\n' \
      "::warning::The containment group-removal response was ambiguous; exact state read-back will decide" \
      >&2
  fi

  for attempt in {1..5}; do
    if exact_contained_state_proved "${containment_username}"; then
      return 0
    fi
    (( attempt < 5 )) && sleep 2
  done
  return 1
}

case "${JUDGE_USER_OPERATION}" in
  provision)
    if get_user; then
      fail "The judge identity already exists; select rotate explicitly"
    else
      get_status=$?
      (( get_status == 3 )) ||
        fail "Unable to prove that the judge identity is absent"
    fi
    prior_identity_state="absent"
    prior_access_state="absent"
    prior_authentication_state="absent"
    prior_authorization_state="none"

    operation_binding="${JUDGE_ACCOUNT_ID}"
    internal_temporary_password="Aa1!$(
      od -An -N28 -tx1 /dev/urandom |
        tr -d ' \n'
    )"
    [[ "${internal_temporary_password}" =~ ^Aa1\![0-9a-f]{56}$ ]] ||
      fail "Unable to create the internal Cognito bootstrap credential"
    test "${internal_temporary_password}" != "${judge_password}" ||
      fail "The internal and protected credentials unexpectedly match"
    create_request="$(
      printf '%s' "${internal_temporary_password}" |
        jq -Rsc \
          --arg pool "${user_pool_id}" \
          --arg username "${judge_username}" \
          --arg binding "${operation_binding}" '
            {
              UserPoolId: $pool,
              Username: $username,
              UserAttributes: [
                {Name: "email", Value: $username},
                {
                  Name: "custom:archon_judge_binding",
                  Value: $binding
                }
              ],
              TemporaryPassword: .,
              MessageAction: "SUPPRESS",
              ForceAliasCreation: false
            }
          '
    )"
    containment_mode="provision"
    contain_on_failure=true
    if ! printf '%s' "${create_request}" |
      aws cognito-idp admin-create-user \
        --region "${AWS_REGION}" \
        --cli-input-json file:///dev/stdin \
        --no-cli-pager >/dev/null 2>"${aws_error}"; then
      fail "Unable to provision the exact Cognito judge user"
    fi
    unset create_request

    wait_for_enabled_status \
      "FORCE_CHANGE_PASSWORD" "" "${operation_binding}" ||
      fail "The provisioned judge identity did not reach its internal bootstrap state"
    canonical="$(canonical_username)"

    password_request="$(
      printf '%s' "${judge_password}" |
        jq -Rsc \
          --arg pool "${user_pool_id}" \
          --arg username "${canonical}" '
            {
              UserPoolId: $pool,
              Username: $username,
              Password: .,
              Permanent: true
            }
          '
    )"
    if ! printf '%s' "${password_request}" |
      aws cognito-idp admin-set-user-password \
        --region "${AWS_REGION}" \
        --cli-input-json file:///dev/stdin \
        --no-cli-pager >/dev/null 2>"${aws_error}"; then
      fail "Unable to activate the exact Cognito judge credential"
    fi
    unset password_request internal_temporary_password

    wait_for_enabled_status "CONFIRMED" "${canonical}" ||
      fail "The provisioned judge identity is not confirmed"
    add_approver_group "${canonical}"
    wait_for_only_approver_group "${canonical}" ||
      fail "The provisioned judge group could not be read back"
    wait_for_enabled_status \
      "CONFIRMED" "${canonical}" "${operation_binding}" ||
      fail "The final provisioned judge identity is not confirmed"
    final_identity_state="exact-bound"
    final_access_state="enabled"
    final_authentication_state="confirmed-permanent"
    final_authorization_state="sole-approver-group"
    session_revocation_result="not-applicable-fresh-identity"
    transition_result="provisioned-and-readback-verified"
    ;;

  rotate)
    get_user ||
      fail "The judge identity does not exist; select provision explicitly"
    user_binding_matches ||
      fail "Cognito did not resolve the exact requested judge identity"
    canonical="$(canonical_username)"
    containment_mode="existing"
    containment_canonical="${canonical}"
    contain_on_failure=true
    require_enabled_user
    jq -e '.UserStatus == "CONFIRMED"' "${user_document}" >/dev/null ||
      fail "The exact judge identity is not in the stable confirmed state"
    read_groups "${canonical}"
    require_only_approver_group
    prior_identity_state="exact-bound"
    prior_access_state="enabled"
    prior_authentication_state="confirmed-permanent"
    prior_authorization_state="sole-approver-group"

    password_request="$(
      printf '%s' "${judge_password}" |
        jq -Rsc \
          --arg pool "${user_pool_id}" \
          --arg username "${canonical}" '
            {
              UserPoolId: $pool,
              Username: $username,
              Password: .,
              Permanent: true
            }
          '
    )"
    if ! printf '%s' "${password_request}" |
      aws cognito-idp admin-set-user-password \
        --region "${AWS_REGION}" \
        --cli-input-json file:///dev/stdin \
        --no-cli-pager >/dev/null 2>"${aws_error}"; then
      if grep -Fq "PasswordHistoryPolicyViolationException" "${aws_error}"; then
        contain_on_failure=false
        fail "The proposed judge credential violates the 24-password history policy"
      fi
      fail "Unable to rotate the exact Cognito judge user"
    fi
    unset password_request
    global_sign_out "${canonical}" ||
      fail "Unable to globally sign out the judge identity after rotation"

    wait_for_enabled_status "CONFIRMED" "${canonical}" ||
      fail "The rotated judge identity is not confirmed"
    read_groups "${canonical}"
    require_only_approver_group
    wait_for_enabled_status "CONFIRMED" "${canonical}" ||
      fail "The final rotated judge identity is not confirmed"
    final_identity_state="exact-bound"
    final_access_state="enabled"
    final_authentication_state="confirmed-permanent-rotated"
    final_authorization_state="sole-approver-group"
    session_revocation_result="response-confirmed"
    transition_result="rotated-and-readback-verified"
    ;;

  reactivate)
    get_user ||
      fail "The exact judge identity does not exist"
    validate_user_identity
    jq -e '
      .Enabled == false and
      (
        .UserStatus == "CONFIRMED" or
        .UserStatus == "FORCE_CHANGE_PASSWORD"
      )
    ' "${user_document}" >/dev/null ||
      fail "Only an exact disabled contained identity can be reactivated"
    canonical="$(canonical_username)"
    read_groups "${canonical}"
    require_no_groups
    prior_identity_state="exact-bound"
    prior_access_state="disabled"
    prior_authentication_state="$(
      jq -er '
        if .UserStatus == "CONFIRMED" then
          "confirmed-contained"
        elif .UserStatus == "FORCE_CHANGE_PASSWORD" then
          "bootstrap-contained"
        else
          empty
        end
      ' "${user_document}"
    )" || fail "The contained identity has an invalid authentication state"
    prior_authorization_state="none"

    containment_mode="existing"
    containment_canonical="${canonical}"
    contain_on_failure=true
    global_sign_out "${canonical}" ||
      fail "Unable to globally sign out the disabled identity before reactivation"

    password_request="$(
      printf '%s' "${judge_password}" |
        jq -Rsc \
          --arg pool "${user_pool_id}" \
          --arg username "${canonical}" '
            {
              UserPoolId: $pool,
              Username: $username,
              Password: .,
              Permanent: true
            }
          '
    )"
    if ! printf '%s' "${password_request}" |
      aws cognito-idp admin-set-user-password \
        --region "${AWS_REGION}" \
        --cli-input-json file:///dev/stdin \
        --no-cli-pager >/dev/null 2>"${aws_error}"; then
      if grep -Fq "PasswordHistoryPolicyViolationException" "${aws_error}" &&
        wait_for_exact_contained_state "${canonical}"; then
        contain_on_failure=false
        fail "The proposed judge credential violates the 24-password history policy"
      fi
      fail "Unable to set the contained judge credential for reactivation"
    fi
    unset password_request

    if ! aws cognito-idp admin-enable-user \
      --region "${AWS_REGION}" \
      --user-pool-id "${user_pool_id}" \
      --username "${canonical}" \
      --no-cli-pager >/dev/null 2>"${aws_error}"; then
      fail "Unable to enable the contained judge identity"
    fi
    wait_for_enabled_status "CONFIRMED" "${canonical}" ||
      fail "The reactivated judge identity did not become confirmed"
    add_approver_group "${canonical}"
    wait_for_only_approver_group "${canonical}" ||
      fail "The reactivated judge group could not be read back"
    wait_for_enabled_status "CONFIRMED" "${canonical}" ||
      fail "The final reactivated judge identity is not confirmed"
    final_identity_state="exact-bound"
    final_access_state="enabled"
    final_authentication_state="confirmed-permanent-rotated"
    final_authorization_state="sole-approver-group"
    session_revocation_result="response-confirmed"
    transition_result="reactivated-and-readback-verified"
    ;;

  deactivate)
    get_user ||
      fail "The exact judge identity does not exist"
    # A verified recovery attribute or configured MFA factor is invalid for
    # shared access, but must not prevent this exact immutable binding from
    # being disabled, signed out, and removed from its authorization group.
    user_binding_matches ||
      fail "Cognito did not resolve the exact requested judge identity"
    canonical="$(canonical_username)"
    prior_identity_state="exact-bound"
    if jq -e '.Enabled == true' "${user_document}" >/dev/null; then
      prior_access_state="enabled"
    elif jq -e '.Enabled == false' "${user_document}" >/dev/null; then
      prior_access_state="disabled"
    else
      prior_access_state="unverified"
    fi
    prior_authentication_state="not-relied-upon-for-containment"
    prior_authorization_state="not-relied-upon-for-containment"

    disable_response_proved=true
    if ! aws cognito-idp admin-disable-user \
      --region "${AWS_REGION}" \
      --user-pool-id "${user_pool_id}" \
      --username "${canonical}" \
      --no-cli-pager >/dev/null 2>"${aws_error}"; then
      disable_response_proved=false
    fi

    sign_out_response_proved=true
    if ! global_sign_out "${canonical}"; then
      sign_out_response_proved=false
    fi
    group_removal_response_proved=true
    if ! aws cognito-idp admin-remove-user-from-group \
      --region "${AWS_REGION}" \
      --user-pool-id "${user_pool_id}" \
      --username "${canonical}" \
      --group-name "${approver_group}" \
      --no-cli-pager >/dev/null 2>"${aws_error}"; then
      group_removal_response_proved=false
    fi

    wait_for_exact_contained_state "${canonical}" ||
      fail "The exact disabled and group-free judge state was not proved after all revocation attempts"

    test "${disable_response_proved}" = "true" ||
      printf '%s\n' \
        "::warning::Disable returned an ambiguous error, but exact disabled state was proved" \
        >&2
    test "${sign_out_response_proved}" = "true" ||
      printf '%s\n' \
        "::warning::Global sign-out returned an ambiguous error; disabled-state revocation is the proved boundary" \
        >&2
    test "${group_removal_response_proved}" = "true" ||
      printf '%s\n' \
        "::warning::Group removal returned an ambiguous error, but exact empty membership was proved" \
        >&2
    final_identity_state="exact-bound"
    final_access_state="disabled"
    final_authentication_state="disabled-containment-boundary"
    final_authorization_state="none"
    if [[ "${sign_out_response_proved}" == "true" ]]; then
      session_revocation_result="response-confirmed"
    else
      session_revocation_result="contained-by-disabled-state"
    fi
    transition_result="deactivated-and-readback-verified"
    ;;
esac

unset judge_password internal_temporary_password
write_lifecycle_state_receipt
operation_complete=true
printf 'Completed the explicit %s request for %s.\n' \
  "${JUDGE_USER_OPERATION}" "${ARCHON_STAGE}"
