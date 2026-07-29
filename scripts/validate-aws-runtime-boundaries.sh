#!/usr/bin/env bash
set -euo pipefail

: "${ARCHON_STACK_NAME:?ARCHON_STACK_NAME is required}"
: "${EXPECTED_ACCOUNT_ID:?EXPECTED_ACCOUNT_ID is required}"
: "${EXPECTED_STAGE:?EXPECTED_STAGE is required}"

case "${EXPECTED_STAGE}" in
  staging)
    iam_foundation_stack="Archon-Staging-IAM-Foundation"
    ;;
  production)
    iam_foundation_stack="Archon-Production-IAM-Foundation"
    ;;
  *)
    echo "::error::EXPECTED_STAGE must be staging or production" >&2
    exit 1
    ;;
esac
test "${ARCHON_STACK_NAME}" = "Archon-${EXPECTED_STAGE}"
[[ "${EXPECTED_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]]

boundary_name="archon-datahub-runtime-boundary-${EXPECTED_STAGE}"
boundary_arn="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:policy/${boundary_name}"
drift_detection_id="$(
  aws cloudformation detect-stack-drift \
    --stack-name "${iam_foundation_stack}" \
    --query StackDriftDetectionId \
    --output text
)"
[[ "${drift_detection_id}" =~ ^[0-9a-fA-F-]{36}$ ]] || {
  echo "::error::IAM foundation drift detection returned an invalid identifier" >&2
  exit 1
}
drift_status=""
for _ in $(seq 1 90); do
  drift_json="$(
    aws cloudformation describe-stack-drift-detection-status \
      --stack-drift-detection-id "${drift_detection_id}" \
      --output json
  )"
  detection_status="$(jq -er '.DetectionStatus' <<<"${drift_json}")"
  case "${detection_status}" in
    DETECTION_COMPLETE)
      drift_status="$(jq -er '.StackDriftStatus' <<<"${drift_json}")"
      break
      ;;
    DETECTION_IN_PROGRESS)
      sleep 2
      ;;
    DETECTION_FAILED)
      echo "::error::IAM foundation drift detection failed" >&2
      exit 1
      ;;
    *)
      echo "::error::IAM foundation drift detection returned an unknown state" >&2
      exit 1
      ;;
  esac
done
test "${drift_status}" = "IN_SYNC" || {
  echo "::error::${iam_foundation_stack} is not demonstrably IN_SYNC" >&2
  exit 1
}
template_json="$(aws cloudformation get-template \
  --stack-name "${ARCHON_STACK_NAME}" \
  --template-stage Processed \
  --output json)"
resources_json="$(aws cloudformation list-stack-resources \
  --stack-name "${ARCHON_STACK_NAME}" \
  --output json)"

expected_logical_ids="$(
  jq -cer '
    .TemplateBody.Resources |
    to_entries |
    map(select(.value.Type == "AWS::IAM::Role") | .key) |
    sort |
    select(length > 0)
  ' <<<"${template_json}"
)"
deployed_roles="$(
  jq -cer '
    [
      .StackResourceSummaries[] |
      select(.ResourceType == "AWS::IAM::Role") |
      {
        logicalId: .LogicalResourceId,
        roleName: .PhysicalResourceId,
        status: .ResourceStatus
      }
    ] |
    sort_by(.logicalId) |
    select(length > 0)
  ' <<<"${resources_json}"
)"
deployed_logical_ids="$(
  jq -cer 'map(.logicalId) | sort' <<<"${deployed_roles}"
)"
test "${deployed_logical_ids}" = "${expected_logical_ids}" || {
  echo "::error::live IAM role inventory differs from the processed stack template" >&2
  exit 1
}

validated_roles='[]'
while IFS= read -r role; do
  logical_id="$(jq -er '.logicalId' <<<"${role}")"
  role_name="$(jq -er '.roleName' <<<"${role}")"
  resource_status="$(jq -er '.status' <<<"${role}")"
  [[ "${role_name}" =~ ^[A-Za-z0-9+=,.@_-]{1,64}$ ]]
  [[ "${resource_status}" =~ ^(CREATE|UPDATE)_COMPLETE$ ]]
  role_json="$(aws iam get-role --role-name "${role_name}" --output json)"
  jq -e \
    --arg arn "${boundary_arn}" \
    --arg stage "${EXPECTED_STAGE}" '
      .Role.PermissionsBoundary.PermissionsBoundaryType == "Policy" and
      .Role.PermissionsBoundary.PermissionsBoundaryArn == $arn and
      any(.Role.Tags[]?; .Key == "Application" and .Value == "archon-datahub") and
      any(.Role.Tags[]?; .Key == "Environment" and .Value == $stage) and
      any(.Role.Tags[]?; .Key == "ManagedBy" and .Value == "aws-cdk")
    ' <<<"${role_json}" >/dev/null || {
    echo "::error::${logical_id} is missing the exact stage runtime boundary or ownership tags" >&2
    exit 1
  }
  validated_roles="$(
    jq -cn \
      --argjson roles "${validated_roles}" \
      --arg logicalId "${logical_id}" \
      --arg roleName "${role_name}" \
      '$roles + [{logicalId: $logicalId, roleName: $roleName}]'
  )"
done < <(jq -c '.[]' <<<"${deployed_roles}")

jq -cnS \
  --arg stackName "${ARCHON_STACK_NAME}" \
  --arg stage "${EXPECTED_STAGE}" \
  --arg iamFoundationStackName "${iam_foundation_stack}" \
  --arg iamFoundationDriftStatus "${drift_status}" \
  --arg boundaryName "${boundary_name}" \
  --argjson roles "${validated_roles}" '
    {
      schemaVersion: "archon.aws-runtime-boundaries/v1",
      stackName: $stackName,
      stage: $stage,
      iamFoundation: {
        stackName: $iamFoundationStackName,
        driftStatus: $iamFoundationDriftStatus
      },
      permissionsBoundary: $boundaryName,
      roles: ($roles | sort_by(.logicalId)),
      validation: "passed"
    }
  '
