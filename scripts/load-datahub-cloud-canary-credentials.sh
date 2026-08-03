#!/usr/bin/env bash
# Source-only loader for the two stage-scoped DataHub Cloud canary credentials.
# Plaintext exists only in the current GitHub Actions shell and is never output.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "::error::source this helper inside the exact credentialed canary step" >&2
  exit 2
fi

: "${AWS_ACCOUNT_ID:?AWS_ACCOUNT_ID is required}"
: "${AWS_REGION:?AWS_REGION is required}"
: "${CANARY_DATAHUB_READ_GMS_URL:?read GMS URL is required}"
: "${CANARY_DATAHUB_WRITE_GMS_URL:?write GMS URL is required}"
[[ "${AWS_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]]
test "${AWS_REGION}" = "eu-west-1"
test "${CANARY_DATAHUB_READ_GMS_URL}" = "${CANARY_DATAHUB_WRITE_GMS_URL}"

stack_response="$(
  aws cloudformation describe-stacks \
    --stack-name Archon-staging-Judge \
    --region "${AWS_REGION}" \
    --output json \
    --no-cli-pager
)"
jq -e '
  .Stacks | length == 1 and
  .[0].StackName == "Archon-staging-Judge"
' <<<"${stack_response}" >/dev/null

exact_output() {
  local key="$1"
  jq -er --arg key "${key}" '
    .Stacks[0].Outputs |
    [.[] | select(.OutputKey == $key)] |
    select(length == 1) | .[0].OutputValue
  ' <<<"${stack_response}"
}

read_secret_arn="$(exact_output ArchonCloudReaderSecretArn)"
write_secret_arn="$(exact_output ArchonCloudWriterSecretArn)"
[[ "${read_secret_arn}" =~ ^arn:aws:secretsmanager:eu-west-1:${AWS_ACCOUNT_ID}:secret:archon/staging/datahub-cloud/reader-[A-Za-z0-9]{6}$ ]]
[[ "${write_secret_arn}" =~ ^arn:aws:secretsmanager:eu-west-1:${AWS_ACCOUNT_ID}:secret:archon/staging/datahub-cloud/writer-[A-Za-z0-9]{6}$ ]]
test "${read_secret_arn}" != "${write_secret_arn}"

load_exact_secret() {
  local secret_arn="$1"
  local schema="$2"
  local expected_url="$3"
  local target_variable="$4"
  local secret_response secret_json token version_id

  secret_response="$(
    aws secretsmanager get-secret-value \
      --secret-id "${secret_arn}" \
      --version-stage AWSCURRENT \
      --region "${AWS_REGION}" \
      --output json \
      --no-cli-pager
  )"
  jq -e --arg arn "${secret_arn}" '
    .ARN == $arn and
    (.VersionId | type == "string" and test("^[A-Za-z0-9-]{32,64}$")) and
    (.VersionStages | type == "array" and index("AWSCURRENT") != null) and
    (has("SecretBinary") | not) and
    (.SecretString | type == "string" and
      (utf8bytelength >= 1 and utf8bytelength <= 16384))
  ' <<<"${secret_response}" >/dev/null

  version_id="$(jq -er .VersionId <<<"${secret_response}")"
  secret_json="$(jq -er .SecretString <<<"${secret_response}")"
  if [[ "${schema}" == "archon.datahub-cloud-reader-secret/v1" ]]; then
    jq -e --arg schema "${schema}" --arg url "${expected_url}" '
      type == "object" and
      keys == [
        "gmsUrl","oauthMasterKey","runHandleFernetKey","schemaVersion","token"
      ] and
      .schemaVersion == $schema and .gmsUrl == $url and
      (.token | type == "string" and length >= 16 and length <= 8192 and
        test("^[!-~]+$")) and
      (.runHandleFernetKey | test("^[A-Za-z0-9_-]{43}=$")) and
      (.oauthMasterKey | test("^[A-Za-z0-9_-]{43}=$")) and
      .runHandleFernetKey != .oauthMasterKey
    ' <<<"${secret_json}" >/dev/null
  else
    jq -e --arg schema "${schema}" --arg url "${expected_url}" '
      type == "object" and
      keys == ["gmsUrl","schemaVersion","token"] and
      .schemaVersion == $schema and .gmsUrl == $url and
      (.token | type == "string" and length >= 16 and length <= 8192 and
        test("^[!-~]+$"))
    ' <<<"${secret_json}" >/dev/null
  fi
  token="$(jq -er .token <<<"${secret_json}")"
  printf '::add-mask::%s\n' "${token}"
  printf -v "${target_variable}" '%s' "${token}"
  LOADED_SECRET_ARN="${secret_arn}"
  LOADED_SECRET_VERSION_ID="${version_id}"
  unset secret_response secret_json token version_id
}

load_exact_secret \
  "${read_secret_arn}" \
  archon.datahub-cloud-reader-secret/v1 \
  "${CANARY_DATAHUB_READ_GMS_URL}" \
  CANARY_DATAHUB_READ_TOKEN
read_version_id="${LOADED_SECRET_VERSION_ID}"
load_exact_secret \
  "${write_secret_arn}" \
  archon.datahub-cloud-writer-secret/v1 \
  "${CANARY_DATAHUB_WRITE_GMS_URL}" \
  CANARY_DATAHUB_WRITE_TOKEN
write_version_id="${LOADED_SECRET_VERSION_ID}"

test "${CANARY_DATAHUB_READ_TOKEN}" != "${CANARY_DATAHUB_WRITE_TOKEN}"
export CANARY_DATAHUB_READ_TOKEN CANARY_DATAHUB_WRITE_TOKEN
CANARY_DATAHUB_CREDENTIAL_BINDING_SHA256="sha256:$(
  jq -cnS \
    --arg stage staging \
    --arg readArn "${read_secret_arn}" \
    --arg readVersion "${read_version_id}" \
    --arg writeArn "${write_secret_arn}" \
    --arg writeVersion "${write_version_id}" \
    --arg gmsUrl "${CANARY_DATAHUB_READ_GMS_URL}" \
    '{stage:$stage,readArn:$readArn,readVersion:$readVersion,
      writeArn:$writeArn,writeVersion:$writeVersion,gmsUrl:$gmsUrl}' |
    sha256sum | awk '{print $1}'
)"
export CANARY_DATAHUB_CREDENTIAL_BINDING_SHA256
unset LOADED_SECRET_ARN LOADED_SECRET_VERSION_ID stack_response \
  read_secret_arn write_secret_arn read_version_id write_version_id
