#!/usr/bin/env bash
set -euo pipefail

: "${ARCHON_STACK_NAME:?ARCHON_STACK_NAME is required}"
: "${ARCHON_STACK_OUTPUTS:?ARCHON_STACK_OUTPUTS is required}"
: "${EXPECTED_ACCOUNT_ID:?EXPECTED_ACCOUNT_ID is required}"
: "${EXPECTED_RATE_LIMIT:?EXPECTED_RATE_LIMIT is required}"
: "${AWS_REGION:?AWS_REGION is required}"

test -f "${ARCHON_STACK_OUTPUTS}"
[[ "${EXPECTED_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]]
[[ "${EXPECTED_RATE_LIMIT}" =~ ^[1-9][0-9]*$ ]]

stack_output() {
  local output_name="$1"
  jq -er \
    --arg stack "${ARCHON_STACK_NAME}" \
    --arg output "${output_name}" \
    '.[$stack][$output]' \
    "${ARCHON_STACK_OUTPUTS}"
}

web_acl_arn="$(stack_output ArchonRegionalWebAclArn)"
log_group_name="$(stack_output ArchonRegionalWafLogGroupName)"
log_key_arn="$(stack_output ArchonRegionalWafLogKeyArn)"
api_stage_arn="$(stack_output ArchonApiStageArn)"

[[ "${web_acl_arn}" =~ ^arn:aws:wafv2:${AWS_REGION}:${EXPECTED_ACCOUNT_ID}:regional/webacl/([A-Za-z0-9_-]{1,128})/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$ ]] || {
  echo "::error::Regional WAF output is not an account-owned Web ACL ARN" >&2
  exit 1
}
web_acl_name="${BASH_REMATCH[1]}"
web_acl_id="${BASH_REMATCH[2]}"
deployment_stage="${ARCHON_STACK_NAME#Archon-}"
[[ "${deployment_stage}" =~ ^[a-z][a-z0-9-]{1,15}$ ]]
expected_web_acl_name="archon-${deployment_stage}-api"
expected_rate_metric="archon-${deployment_stage}-rate-limit"
test "${web_acl_name}" = "${expected_web_acl_name}"
test "${log_group_name}" = \
  "aws-waf-logs-archon-${deployment_stage}-api"
[[ "${log_key_arn}" =~ ^arn:aws:kms:${AWS_REGION}:${EXPECTED_ACCOUNT_ID}:key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || {
  echo "::error::Regional WAF log-key output is not an account-owned KMS key ARN" >&2
  exit 1
}
[[ "${api_stage_arn}" =~ ^arn:aws:apigateway:${AWS_REGION}::/restapis/[a-z0-9]{10}/stages/[a-z][a-z0-9-]{1,15}$ ]] || {
  echo "::error::API stage output is not a regional API Gateway stage ARN" >&2
  exit 1
}

web_acl_json="$(
  aws wafv2 get-web-acl \
    --region "${AWS_REGION}" \
    --scope REGIONAL \
    --name "${web_acl_name}" \
    --id "${web_acl_id}" \
    --output json
)"
jq --exit-status \
  --arg arn "${web_acl_arn}" \
  --arg name "${web_acl_name}" \
  --arg rateMetric "${expected_rate_metric}" \
  --argjson rateLimit "${EXPECTED_RATE_LIMIT}" \
  '
    def has_managed_rule($rules; $name; $priority):
      (
        [
          $rules[] |
          select(
            .Name == $name and
            .Priority == $priority and
            .OverrideAction == {"None": {}} and
            (has("Action") | not) and
            (.Statement | keys) == ["ManagedRuleGroupStatement"] and
            .Statement.ManagedRuleGroupStatement.VendorName == "AWS" and
            .Statement.ManagedRuleGroupStatement.Name == $name and
            ((.Statement.ManagedRuleGroupStatement.ExcludedRules // []) |
              length) == 0 and
            ((.Statement.ManagedRuleGroupStatement.RuleActionOverrides // []) |
              length) == 0 and
            (.Statement.ManagedRuleGroupStatement |
              has("ScopeDownStatement") | not) and
            (.Statement.ManagedRuleGroupStatement |
              has("Version") | not) and
            (.Statement.ManagedRuleGroupStatement |
              has("ManagedRuleGroupConfigs") | not) and
            .VisibilityConfig.CloudWatchMetricsEnabled == true and
            .VisibilityConfig.SampledRequestsEnabled == true and
            .VisibilityConfig.MetricName == $name
          )
        ] |
        length
      ) == 1;
    .WebACL as $webAcl |
    .WebACL.ARN == $arn and
    $webAcl.Name == $name and
    .WebACL.DefaultAction.Allow == {} and
    $webAcl.VisibilityConfig.CloudWatchMetricsEnabled == true and
    $webAcl.VisibilityConfig.SampledRequestsEnabled == true and
    $webAcl.VisibilityConfig.MetricName == ($name + "-waf") and
    (
      [
        .WebACL.DataProtectionConfig.DataProtections[] |
        {
          action: .Action,
          fieldType: .Field.FieldType,
          fieldKeys: .Field.FieldKeys,
          excludeRateBasedDetails: .ExcludeRateBasedDetails,
          excludeRuleMatchDetails: .ExcludeRuleMatchDetails
        }
      ] |
      sort_by(.fieldKeys[0])
    ) == [
      {
        action: "SUBSTITUTION",
        fieldType: "SINGLE_HEADER",
        fieldKeys: ["authorization"],
        excludeRateBasedDetails: false,
        excludeRuleMatchDetails: false
      },
      {
        action: "SUBSTITUTION",
        fieldType: "SINGLE_HEADER",
        fieldKeys: ["cookie"],
        excludeRateBasedDetails: false,
        excludeRuleMatchDetails: false
      },
      {
        action: "SUBSTITUTION",
        fieldType: "SINGLE_HEADER",
        fieldKeys: ["x-api-key"],
        excludeRateBasedDetails: false,
        excludeRuleMatchDetails: false
      }
    ] and
    ($webAcl.Rules | length) == 4 and
    has_managed_rule(
      $webAcl.Rules;
      "AWSManagedRulesAmazonIpReputationList";
      0
    ) and
    has_managed_rule(
      $webAcl.Rules;
      "AWSManagedRulesCommonRuleSet";
      10
    ) and
    has_managed_rule(
      $webAcl.Rules;
      "AWSManagedRulesKnownBadInputsRuleSet";
      20
    ) and
    (
      [
        $webAcl.Rules[] |
        select(
          .Name == "PerIpRateLimit" and
          .Priority == 30 and
          .Action == {"Block": {}} and
          (has("OverrideAction") | not) and
          (.Statement | keys) == ["RateBasedStatement"] and
          .Statement.RateBasedStatement.AggregateKeyType == "IP" and
          .Statement.RateBasedStatement.EvaluationWindowSec == 300 and
          .Statement.RateBasedStatement.Limit == $rateLimit and
          (.Statement.RateBasedStatement |
            has("ScopeDownStatement") | not) and
          .VisibilityConfig.CloudWatchMetricsEnabled == true and
          .VisibilityConfig.SampledRequestsEnabled == true and
          .VisibilityConfig.MetricName == $rateMetric
        )
      ] |
      length
    ) == 1
  ' <<<"${web_acl_json}" >/dev/null || {
  echo "::error::Regional WAF rules or sampled-data protection violate the contract" >&2
  exit 1
}

logging_json="$(
  aws wafv2 get-logging-configuration \
    --region "${AWS_REGION}" \
    --resource-arn "${web_acl_arn}" \
    --output json
)"
expected_log_group_arn="arn:aws:logs:${AWS_REGION}:${EXPECTED_ACCOUNT_ID}:log-group:${log_group_name}"
jq --exit-status \
  --arg arn "${web_acl_arn}" \
  --arg destination "${expected_log_group_arn}" \
  '
    .LoggingConfiguration.ResourceArn == $arn and
    .LoggingConfiguration.LogDestinationConfigs == [$destination] and
    .LoggingConfiguration.LoggingFilter.DefaultBehavior == "DROP" and
    (.LoggingConfiguration.LoggingFilter.Filters | length) == 1 and
    (
      .LoggingConfiguration.LoggingFilter.Filters[0] |
      .Behavior == "KEEP" and
      .Requirement == "MEETS_ANY" and
      (.Conditions | length) == 2 and
      ([.Conditions[].ActionCondition.Action] | sort) == ["BLOCK", "COUNT"]
    ) and
    (
      [
        .LoggingConfiguration.RedactedFields[].SingleHeader.Name
      ] |
      sort
    ) == ["authorization", "cookie", "x-api-key"]
  ' <<<"${logging_json}" >/dev/null || {
  echo "::error::Regional WAF logging/filter/redaction violates the contract" >&2
  exit 1
}

association_json="$(
  aws wafv2 get-web-acl-for-resource \
    --region "${AWS_REGION}" \
    --resource-arn "${api_stage_arn}" \
    --output json
)"
jq --exit-status \
  --arg arn "${web_acl_arn}" \
  '.WebACL.ARN == $arn' \
  <<<"${association_json}" >/dev/null || {
  echo "::error::Regional WAF is not associated with the deployed API stage" >&2
  exit 1
}

log_group_json="$(
  aws logs describe-log-groups \
    --region "${AWS_REGION}" \
    --log-group-name-prefix "${log_group_name}" \
    --output json
)"
kms_key_json="$(
  aws kms describe-key \
    --region "${AWS_REGION}" \
    --key-id "${log_key_arn}" \
    --output json
)"
jq --exit-status \
  --arg arn "${log_key_arn}" \
  --arg account "${EXPECTED_ACCOUNT_ID}" \
  '
    .KeyMetadata.Arn == $arn and
    .KeyMetadata.AWSAccountId == $account and
    .KeyMetadata.Enabled == true and
    .KeyMetadata.KeyState == "Enabled" and
    .KeyMetadata.KeyManager == "CUSTOMER" and
    .KeyMetadata.KeyUsage == "ENCRYPT_DECRYPT" and
    .KeyMetadata.Origin == "AWS_KMS" and
    .KeyMetadata.MultiRegion == false and
    .KeyMetadata.KeySpec == "SYMMETRIC_DEFAULT"
  ' <<<"${kms_key_json}" >/dev/null || {
  echo "::error::Regional WAF log key is not an enabled single-Region customer encryption key" >&2
  exit 1
}
kms_rotation_json="$(
  aws kms get-key-rotation-status \
    --region "${AWS_REGION}" \
    --key-id "${log_key_arn}" \
    --output json
)"
jq --exit-status '.KeyRotationEnabled == true' \
  <<<"${kms_rotation_json}" >/dev/null || {
  echo "::error::Regional WAF log key rotation is not enabled" >&2
  exit 1
}
log_group_contract="$(
  jq --compact-output --sort-keys \
    --arg name "${log_group_name}" \
    --arg kmsKeyArn "${log_key_arn}" \
    '
      [.logGroups[] | select(.logGroupName == $name)] as $groups |
      if (
        ($groups | length) == 1 and
        ($groups[0].kmsKeyId == $kmsKeyArn) and
        ($groups[0].retentionInDays == 365)
      ) then
        {
          name: $groups[0].logGroupName,
          kmsKey: {
            arn: $groups[0].kmsKeyId,
            state: "Enabled",
            keyManager: "CUSTOMER",
            keyUsage: "ENCRYPT_DECRYPT",
            origin: "AWS_KMS",
            multiRegion: false,
            rotationEnabled: true
          },
          retentionDays: $groups[0].retentionInDays
        }
      else
        error("Regional WAF log group is not uniquely retained and KMS encrypted")
      end
    ' <<<"${log_group_json}"
)"

stack_outputs_sha="$(sha256sum "${ARCHON_STACK_OUTPUTS}" | awk '{print $1}')"
jq --null-input --compact-output --sort-keys \
  --arg stackName "${ARCHON_STACK_NAME}" \
  --arg cdkOutputsSha256 "${stack_outputs_sha}" \
  --arg apiStageArn "${api_stage_arn}" \
  --arg webAclArn "${web_acl_arn}" \
  --arg webAclName "${web_acl_name}" \
  --arg webAclId "${web_acl_id}" \
  --argjson rateLimit "${EXPECTED_RATE_LIMIT}" \
  --argjson logGroup "${log_group_contract}" \
  '{
    schemaVersion: "archon.regional-waf-contract/v2",
    stackName: $stackName,
    cdkOutputsSha256: $cdkOutputsSha256,
    apiStageArn: $apiStageArn,
    webAcl: {
      arn: $webAclArn,
      name: $webAclName,
      id: $webAclId,
      scope: "REGIONAL",
      rateLimit: $rateLimit,
      rateEvaluationWindowSeconds: 300,
      ruleCount: 4,
      sampledDataProtection: "validated"
    },
    logging: (
      $logGroup + {
        filter: "BLOCK_OR_COUNT",
        sensitiveFields: ["authorization", "cookie", "x-api-key"]
      }
    ),
    association: "validated",
    validation: "passed"
  }'
