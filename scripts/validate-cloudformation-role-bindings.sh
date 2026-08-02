#!/usr/bin/env bash
set -euo pipefail

: "${EXPECTED_ACCOUNT_ID:?EXPECTED_ACCOUNT_ID is required}"
: "${EXPECTED_STAGE:?EXPECTED_STAGE is required}"
: "${ALLOW_ABSENT:?ALLOW_ABSENT must be true or false}"
ALLOW_ROLE_MIGRATION="${ALLOW_ROLE_MIGRATION:-false}"

[[ "${EXPECTED_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]] || {
  echo "::error::EXPECTED_ACCOUNT_ID must be exactly 12 digits"
  exit 1
}
case "${EXPECTED_STAGE}" in
  staging|production) ;;
  *)
    echo "::error::EXPECTED_STAGE must be exactly staging or production"
    exit 1
    ;;
esac
case "${ALLOW_ABSENT}" in
  true|false) ;;
  *)
    echo "::error::ALLOW_ABSENT must be exactly true or false"
    exit 1
    ;;
esac
case "${ALLOW_ROLE_MIGRATION}" in
  true|false) ;;
  *)
    echo "::error::ALLOW_ROLE_MIGRATION must be exactly true or false"
    exit 1
    ;;
esac

if [[ "${EXPECTED_STAGE}" == "staging" ]]; then
  bootstrap_qualifier="archonstg"
else
  bootstrap_qualifier="archonprd"
fi
bindings=(
  "Archon-${EXPECTED_STAGE}-Edge|us-east-1|${bootstrap_qualifier}"
  "Archon-${EXPECTED_STAGE}-Core|eu-west-1|${bootstrap_qualifier}"
  "Archon-${EXPECTED_STAGE}-Judge|eu-west-1|${bootstrap_qualifier}"
)

verified='[]'
for binding in "${bindings[@]}"; do
  IFS='|' read -r stack_name region qualifier <<<"${binding}"
  expected_role_arn="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/cdk-${qualifier}-cfn-exec-role-${EXPECTED_ACCOUNT_ID}-${region}"
  error_path="$(mktemp "${RUNNER_TEMP:-/tmp}/archon-cfn-role-binding.XXXXXX")"
  stack_json=""
  if ! stack_json="$(
    aws cloudformation describe-stacks \
      --region "${region}" \
      --stack-name "${stack_name}" \
      --output json 2>"${error_path}"
  )"; then
    if grep -Fq "does not exist" "${error_path}" &&
      [[ "${ALLOW_ABSENT}" == "true" ]]; then
      rm -f -- "${error_path}"
      verified="$(
        jq -cn \
          --argjson current "${verified}" \
          --arg stack "${stack_name}" \
          --arg region "${region}" \
          --arg qualifier "${qualifier}" \
          '$current + [{
            stack: $stack,
            region: $region,
            bootstrapQualifier: $qualifier,
            state: "absent"
          }]'
      )"
      continue
    fi
    rm -f -- "${error_path}"
    echo "::error::Unable to verify the persisted CloudFormation execution role for ${stack_name}"
    exit 1
  fi
  rm -f -- "${error_path}"

  if jq -e \
    --arg stack "${stack_name}" \
    --arg role "${expected_role_arn}" \
    '
      (.Stacks | length) == 1 and
      .Stacks[0].StackName == $stack and
      .Stacks[0].RoleARN == $role
    ' <<<"${stack_json}" >/dev/null; then
    verified="$(
      jq -cn \
        --argjson current "${verified}" \
        --arg stack "${stack_name}" \
        --arg region "${region}" \
        --arg qualifier "${qualifier}" \
        '$current + [{
          stack: $stack,
          region: $region,
          bootstrapQualifier: $qualifier,
          state: "present-and-exact"
        }]'
    )"
    continue
  fi

  if [[ "${ALLOW_ROLE_MIGRATION}" != "true" ]]; then
    echo "::error::${stack_name} is not bound to its exact stage CloudFormation execution role"
    exit 1
  fi
  echo "::warning::${stack_name} requires the explicitly authorized one-time CloudFormation execution-role migration"
  verified="$(
    jq -cn \
      --argjson current "${verified}" \
      --arg stack "${stack_name}" \
      --arg region "${region}" \
      --arg qualifier "${qualifier}" \
      '$current + [{
        stack: $stack,
        region: $region,
        bootstrapQualifier: $qualifier,
        state: "migration-required"
      }]'
  )"
done

jq -cn \
  --arg stage "${EXPECTED_STAGE}" \
  --argjson allowAbsent "${ALLOW_ABSENT}" \
  --argjson allowRoleMigration "${ALLOW_ROLE_MIGRATION}" \
  --argjson bindings "${verified}" \
  '{
    schemaVersion: "archon.cloudformation-role-bindings/v1",
    stage: $stage,
    allowAbsent: $allowAbsent,
    allowRoleMigration: $allowRoleMigration,
    bindings: $bindings
  }'
