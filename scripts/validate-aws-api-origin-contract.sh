#!/usr/bin/env bash
set -euo pipefail

: "${ARCHON_STACK_NAME:?ARCHON_STACK_NAME is required}"
: "${ARCHON_STACK_OUTPUTS:?ARCHON_STACK_OUTPUTS is required}"
: "${AWS_REGION:?AWS_REGION is required}"

test -f "${ARCHON_STACK_OUTPUTS}"
[[ "${AWS_REGION}" =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]]

fail_contract() {
  echo "::error::$1" >&2
  exit 1
}

stack_output() {
  local output_name="$1"
  jq -er \
    --arg stack "${ARCHON_STACK_NAME}" \
    --arg output "${output_name}" \
    '.[$stack][$output]' \
    "${ARCHON_STACK_OUTPUTS}"
}

sha256_text() {
  printf '%s' "$1" | sha256sum | awk '{print $1}'
}

api_stage_arn="$(stack_output ArchonApiStageArn)"
api_invoke_url="$(stack_output ArchonApiInvokeUrl)"
api_url="$(stack_output ArchonApiUrl)"
application_url="$(stack_output ArchonApplicationUrl)"
distribution_id="$(stack_output ArchonCloudFrontDistributionId)"
distribution_domain="$(stack_output ArchonCloudFrontDomainName)"

[[ "${ARCHON_STACK_NAME}" =~ ^Archon-([a-z][a-z0-9-]{1,15})$ ]] || {
  fail_contract "Stack name does not encode a valid Archon deployment stage"
}
deployment_stage="${BASH_REMATCH[1]}"
[[ "${api_stage_arn}" =~ ^arn:aws:apigateway:([a-z0-9-]+)::/restapis/([a-z0-9]{10})/stages/([a-z][a-z0-9-]{1,15})$ ]] || {
  fail_contract "API stage output is not a valid regional API Gateway stage ARN"
}
test "${BASH_REMATCH[1]}" = "${AWS_REGION}" || {
  fail_contract "API stage region does not match the deployment region"
}
rest_api_id="${BASH_REMATCH[2]}"
api_stage="${BASH_REMATCH[3]}"
test "${api_stage}" = "${deployment_stage}" || {
  fail_contract "API stage does not match the stack deployment stage"
}

case "${deployment_stage}" in
  staging)
    expected_burst_limit=20
    expected_rate_limit=10
    expected_daily_quota=25000
    ;;
  production)
    expected_burst_limit=100
    expected_rate_limit=50
    expected_daily_quota=250000
    ;;
  *)
    fail_contract "API-origin contract supports only staging and production"
    ;;
esac

expected_invoke_host="${rest_api_id}.execute-api.${AWS_REGION}.amazonaws.com"
expected_invoke_url="https://${expected_invoke_host}/${api_stage}/"
test "${api_invoke_url}" = "${expected_invoke_url}" || {
  fail_contract "Direct API Gateway invoke URL is not bound to the deployed stage"
}
[[ "${application_url}" =~ ^https://([A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9])$ ]] || {
  fail_contract "Application URL is not a canonical HTTPS origin"
}
viewer_domain="${BASH_REMATCH[1]}"
test "${api_url}" = "${application_url}/api" || {
  fail_contract "Published API URL does not use the canonical CloudFront application origin"
}
[[ "${distribution_id}" =~ ^[A-Z0-9]{10,32}$ ]] || {
  fail_contract "CloudFront distribution output is invalid"
}
[[ "${distribution_domain}" =~ ^[a-z0-9-]+\.cloudfront\.net$ ]] || {
  fail_contract "CloudFront distribution domain output is invalid"
}

stack_resources="$(
  aws cloudformation list-stack-resources \
    --region "${AWS_REGION}" \
    --stack-name "${ARCHON_STACK_NAME}" \
    --output json
)"

physical_resource_id() {
  local resource_type="$1"
  jq -er \
    --arg resourceType "${resource_type}" \
    '
      [
        .StackResourceSummaries[] |
        select(.ResourceType == $resourceType)
      ] as $resources |
      if (
        ($resources | length) == 1 and
        ($resources[0].PhysicalResourceId | type) == "string" and
        ($resources[0].PhysicalResourceId | length) > 0 and
        (
          $resources[0].ResourceStatus == "CREATE_COMPLETE" or
          $resources[0].ResourceStatus == "UPDATE_COMPLETE" or
          $resources[0].ResourceStatus == "IMPORT_COMPLETE"
        )
      ) then
        $resources[0].PhysicalResourceId
      else
        error("resource is not uniquely deployed and complete")
      end
    ' <<<"${stack_resources}"
}

deployed_rest_api_id="$(
  physical_resource_id "AWS::ApiGateway::RestApi"
)" || fail_contract "REST API CloudFormation binding is invalid"
api_key_id="$(
  physical_resource_id "AWS::ApiGateway::ApiKey"
)" || fail_contract "API key CloudFormation binding is invalid"
usage_plan_id="$(
  physical_resource_id "AWS::ApiGateway::UsagePlan"
)" || fail_contract "Usage plan CloudFormation binding is invalid"
usage_plan_key_id="$(
  physical_resource_id "AWS::ApiGateway::UsagePlanKey"
)" || fail_contract "Usage-plan key CloudFormation binding is invalid"
origin_request_policy_id="$(
  physical_resource_id "AWS::CloudFront::OriginRequestPolicy"
)" || fail_contract "Origin request policy CloudFormation binding is invalid"
deployed_distribution_id="$(
  physical_resource_id "AWS::CloudFront::Distribution"
)" || fail_contract "CloudFront distribution CloudFormation binding is invalid"

test "${deployed_rest_api_id}" = "${rest_api_id}" || {
  fail_contract "REST API output is not bound to the deployed CloudFormation resource"
}
test "${deployed_distribution_id}" = "${distribution_id}" || {
  fail_contract "CloudFront output is not bound to the deployed CloudFormation resource"
}

rest_api_json="$(
  aws apigateway get-rest-api \
    --region "${AWS_REGION}" \
    --rest-api-id "${rest_api_id}" \
    --output json
)"
jq -e \
  --arg id "${rest_api_id}" \
  --arg name "archon-${deployment_stage}" \
  '
    .id == $id and
    .name == $name and
    .apiKeySource == "HEADER" and
    .endpointConfiguration.types == ["REGIONAL"] and
    ((.endpointConfiguration.vpcEndpointIds // []) | length) == 0 and
    (.disableExecuteApiEndpoint // false) == false
  ' <<<"${rest_api_json}" >/dev/null || {
  fail_contract "REST API endpoint or API-key source violates the live contract"
}

api_resources="$(
  aws apigateway get-resources \
    --region "${AWS_REGION}" \
    --rest-api-id "${rest_api_id}" \
    --limit 500 \
    --output json
)"

resource_id_for_path() {
  local resource_path="$1"
  jq -er \
    --arg path "${resource_path}" \
    '
      [.items[] | select(.path == $path)] as $resources |
      if (
        ($resources | length) == 1 and
        ($resources[0].id | type) == "string" and
        ($resources[0].id | length) > 0
      ) then
        $resources[0].id
      else
        error("API resource path is not unique")
      end
    ' <<<"${api_resources}"
}

method_contracts='[]'
control_start_request_template="$(
  cat <<'VTL'
{
  "operation": "start",
  "requestId": "$util.escapeJavaScript($context.extendedRequestId).replaceAll("\\'","'")",
  "body": $input.json('$')
}
VTL
)"
control_status_request_template="$(
  cat <<'VTL'
{
  "operation": "status",
  "requestId": "$util.escapeJavaScript($context.extendedRequestId).replaceAll("\\'","'")",
  "auditId": "$util.escapeJavaScript($input.params('auditId')).replaceAll("\\'","'")"
}
VTL
)"
approval_decision_request_template="$(
  cat <<'VTL'
{
  "operation": "decide",
  "requestId": "$util.escapeJavaScript($context.extendedRequestId).replaceAll("\\'","'")",
  "approvalId": "$util.escapeJavaScript($input.params('approvalId')).replaceAll("\\'","'")",
  "body": $input.json('$'),
  "identity": {
    "subject": "$util.escapeJavaScript($context.authorizer.claims.sub).replaceAll("\\'","'")",
    "issuer": "$util.escapeJavaScript($context.authorizer.claims.iss).replaceAll("\\'","'")",
    "groups": "$util.escapeJavaScript($context.authorizer.claims['cognito:groups']).replaceAll("\\'","'")"
  }
}
VTL
)"

validate_method() {
  local resource_path="$1"
  local http_method="$2"
  local authorization_type="$3"
  local authorization_scopes="$4"
  local integration_type="$5"
  local connection_type="$6"
  local request_parameters="$7"
  local credential_isolation="$8"
  local expected_request_template="$9"
  local expected_method_statuses="${10}"
  local resource_id
  local method_json
  local method_contract
  local request_template_sha

  resource_id="$(resource_id_for_path "${resource_path}")" || {
    fail_contract "Required API resource ${resource_path} is not uniquely deployed"
  }
  method_json="$(
    aws apigateway get-method \
      --region "${AWS_REGION}" \
      --rest-api-id "${rest_api_id}" \
      --resource-id "${resource_id}" \
      --http-method "${http_method}" \
      --output json
  )"
  jq -e \
    --arg method "${http_method}" \
    --arg authorizationType "${authorization_type}" \
    --arg integrationType "${integration_type}" \
    --arg connectionType "${connection_type}" \
    --arg credentialIsolation "${credential_isolation}" \
    --arg expectedRequestTemplate "${expected_request_template}" \
    --argjson authorizationScopes "${authorization_scopes}" \
    --argjson requestParameters "${request_parameters}" \
    --argjson expectedMethodStatuses "${expected_method_statuses}" \
    '
      def base_response_parameters:
        {
          "method.response.header.Cache-Control": "'\''no-store'\''",
          "method.response.header.Content-Type":
            "'\''application/json; charset=utf-8'\''",
          "method.response.header.Cross-Origin-Resource-Policy":
            "'\''same-origin'\''",
          "method.response.header.Referrer-Policy":
            "'\''no-referrer'\''",
          "method.response.header.X-Content-Type-Options":
            "'\''nosniff'\''"
        };
      def success_response_parameters:
        base_response_parameters + {
          "method.response.header.Location":
            "integration.response.body.headers.location",
          "method.response.header.Retry-After":
            "integration.response.body.headers.retryAfter"
        };
      def method_response_parameters:
        {
          "method.response.header.Cache-Control": true,
          "method.response.header.Content-Type": true,
          "method.response.header.Cross-Origin-Resource-Policy": true,
          "method.response.header.Referrer-Policy": true,
          "method.response.header.X-Content-Type-Options": true,
          "method.response.header.Location": false,
          "method.response.header.Retry-After": false
        };
      .httpMethod == $method and
      .authorizationType == $authorizationType and
      .apiKeyRequired == true and
      ((.authorizationScopes // []) == $authorizationScopes) and
      (
        if $authorizationType == "COGNITO_USER_POOLS" then
          (.authorizerId | type) == "string" and
          (.authorizerId | length) > 0
        else
          (.authorizerId // null) == null
        end
      ) and
      (.requestValidatorId | type) == "string" and
      (.requestValidatorId | length) > 0 and
      ((.requestParameters // {}) == $requestParameters) and
      .methodIntegration.type == $integrationType and
      .methodIntegration.httpMethod == "POST" and
      (
        (.methodIntegration.connectionType // "INTERNET") ==
          $connectionType
      ) and
      (
        if $connectionType == "VPC_LINK" then
          (.methodIntegration.connectionId | type) == "string" and
          (.methodIntegration.connectionId | length) > 0
        else
          true
        end
      ) and
      (
        if $credentialIsolation == "static-redaction" then
          .methodIntegration.requestParameters == {
            "integration.request.header.x-api-key": "'redacted'"
          } and
          ((.methodIntegration.requestTemplates // {}) | length) == 0
        else
          ((.methodIntegration.requestParameters // {}) | length) == 0 and
          .methodIntegration.passthroughBehavior == "NEVER" and
          (.methodIntegration.requestTemplates | keys) ==
            ["application/json"] and
          .methodIntegration.requestTemplates["application/json"] ==
            $expectedRequestTemplate and
          (
            .methodIntegration.integrationResponses |
            keys |
            sort
          ) == ["200", "502"] and
          .methodIntegration.integrationResponses["502"] == {
            statusCode: "502",
            selectionPattern: "(?s).+",
            responseParameters: base_response_parameters,
            responseTemplates: {
              "application/json":
                "{\"error\":\"lambda_integration_failed\"}\n"
            }
          } and
          .methodIntegration.integrationResponses["200"] == {
            statusCode: "200",
            responseParameters: success_response_parameters,
            responseTemplates: {
              "application/json": (
                "#set($statusCode = $input.path('\''$.statusCode'\''))\n" +
                "#set($context.responseOverride.status = $statusCode)\n" +
                "$input.json('\''$.payload'\'')"
              )
            }
          } and
          (
            .methodResponses as $responses |
            (
              ($responses | keys | sort) ==
                ($expectedMethodStatuses | sort)
            ) and
            all(
              $expectedMethodStatuses[];
              . as $status |
              $responses[$status].statusCode == $status and
              $responses[$status].responseParameters ==
                method_response_parameters
            )
          )
        end
      )
    ' <<<"${method_json}" >/dev/null || {
    fail_contract "${http_method} ${resource_path} violates the API-origin method contract"
  }

  request_template_sha=""
  if [[ "${credential_isolation}" == "narrow-request-template" ]]; then
    request_template_sha="$(sha256_text "${expected_request_template}")"
  fi
  method_contract="$(
    jq -cnS \
      --arg path "${resource_path}" \
      --arg method "${http_method}" \
      --arg authorizationType "${authorization_type}" \
      --arg integrationType "${integration_type}" \
      --arg credentialIsolation "${credential_isolation}" \
      --arg requestTemplateSha256 "${request_template_sha}" \
      --argjson authorizationScopes "${authorization_scopes}" \
      '{
        path: $path,
        method: $method,
        apiKeyRequired: true,
        authorizationType: $authorizationType,
        authorizationScopes: $authorizationScopes,
        integrationType: $integrationType,
        originCredentialIsolation: $credentialIsolation
      } + (
        if ($requestTemplateSha256 | length) > 0 then
          {
            requestTemplateSha256: $requestTemplateSha256,
            responseProjection:
              "status-payload-and-sanitized-header-allowlist"
          }
        else
          {}
        end
      )'
  )"
  method_contracts="$(
    jq -cS \
      --argjson method "${method_contract}" \
      '. + [$method]' <<<"${method_contracts}"
  )"
}

validate_method \
  "/api/audits" \
  "POST" \
  "NONE" \
  '[]' \
  "HTTP_PROXY" \
  "VPC_LINK" \
  '{}' \
  "static-redaction" \
  '' \
  '[]'
validate_method \
  "/api/control-loops" \
  "POST" \
  "NONE" \
  '[]' \
  "AWS" \
  "INTERNET" \
  '{}' \
  "narrow-request-template" \
  "${control_start_request_template}" \
  '["200","202","400","404","413","502"]'
validate_method \
  "/api/control-loops/{auditId}" \
  "GET" \
  "NONE" \
  '[]' \
  "AWS" \
  "INTERNET" \
  '{"method.request.path.auditId":true}' \
  "narrow-request-template" \
  "${control_status_request_template}" \
  '["200","400","404","502"]'
validate_method \
  "/api/approvals/{approvalId}/decisions" \
  "POST" \
  "COGNITO_USER_POOLS" \
  '["archon/approve"]' \
  "AWS" \
  "INTERNET" \
  '{"method.request.path.approvalId":true}' \
  "narrow-request-template" \
  "${approval_decision_request_template}" \
  '["200","202","400","401","403","404","409","410","502"]'

# Explicitly prevent the AWS CLI from retrieving or projecting API-key material.
api_key_json="$(
  aws apigateway get-api-key \
    --region "${AWS_REGION}" \
    --api-key "${api_key_id}" \
    --no-include-value \
    --query '{id:id,enabled:enabled}' \
    --output json
)"
jq -e \
  --arg id "${api_key_id}" \
  '
    . == {
      id: $id,
      enabled: true
    }
  ' <<<"${api_key_json}" >/dev/null || {
  fail_contract "CloudFront origin API key is missing or disabled"
}

usage_plan_json="$(
  aws apigateway get-usage-plan \
    --region "${AWS_REGION}" \
    --usage-plan-id "${usage_plan_id}" \
    --output json
)"
jq -e \
  --arg id "${usage_plan_id}" \
  --arg name "archon-${deployment_stage}-cloudfront-origin" \
  --arg apiId "${rest_api_id}" \
  --arg stage "${api_stage}" \
  --argjson burstLimit "${expected_burst_limit}" \
  --argjson rateLimit "${expected_rate_limit}" \
  --argjson dailyQuota "${expected_daily_quota}" \
  '
    .id == $id and
    .name == $name and
    (.apiStages | length) == 1 and
    .apiStages[0].apiId == $apiId and
    .apiStages[0].stage == $stage and
    ((.apiStages[0].throttle // {}) | length) == 0 and
    .throttle.burstLimit == $burstLimit and
    .throttle.rateLimit == $rateLimit and
    .quota.limit == $dailyQuota and
    (.quota.offset // 0) == 0 and
    .quota.period == "DAY"
  ' <<<"${usage_plan_json}" >/dev/null || {
  fail_contract "API Gateway usage-plan limits or stage binding violate the contract"
}
api_key_usage_plans="$(
  aws apigateway get-usage-plans \
    --region "${AWS_REGION}" \
    --key-id "${api_key_id}" \
    --output json
)"
jq -e \
  --arg usagePlanId "${usage_plan_id}" \
  '
    ([.items[].id] | sort) == [$usagePlanId]
  ' <<<"${api_key_usage_plans}" >/dev/null || {
  fail_contract "API key is not uniquely associated with the deployed usage plan"
}

# GetTemplate preserves unresolved dynamic references. It proves the deployed
# CloudFormation binding without asking CloudFront or API Gateway for either
# credential value.
stack_template_json="$(
  aws cloudformation get-template \
    --region "${AWS_REGION}" \
    --stack-name "${ARCHON_STACK_NAME}" \
    --template-stage Processed \
    --output json
)"
stack_template_body="$(
  jq --compact-output --sort-keys --exit-status \
    '
      if (.TemplateBody | type) == "object" then
        .TemplateBody
      elif (.TemplateBody | type) == "string" then
        (.TemplateBody | fromjson)
      else
        error("deployed template body is not JSON")
      end
    ' <<<"${stack_template_json}"
)" || {
  fail_contract "CloudFormation did not return the deployed JSON template"
}
unset stack_template_json

jq -e \
  --arg stage "${api_stage}" \
  '
    .Resources as $resources |
    (
      $resources |
      to_entries |
      map(select(.value.Type == "AWS::ApiGateway::RestApi"))
    ) as $restApis |
    (
      $resources |
      to_entries |
      map(select(.value.Type == "AWS::ApiGateway::ApiKey"))
    ) as $apiKeys |
    (
      $resources |
      to_entries |
      map(select(.value.Type == "AWS::CloudFront::OriginRequestPolicy"))
    ) as $originPolicies |
    (
      $resources |
      to_entries |
      map(select(.value.Type == "AWS::CloudFront::Distribution"))
    ) as $distributions |
    ($restApis | length) == 1 and
    ($apiKeys | length) == 1 and
    ($originPolicies | length) == 1 and
    ($distributions | length) == 1 and
    ($apiKeys[0].value.Properties.Value | type) == "object" and
    (
      $apiKeys[0].value.Properties.Value |
      tostring |
      contains("resolve:secretsmanager")
    ) and
    (
      $apiKeys[0].value.Properties.Value |
      tostring |
      contains("apiKey")
    ) and
    (
      $distributions[0].value.Properties.DistributionConfig
    ) as $distribution |
    $distribution.Enabled == true and
    (
      [
        $distribution.Origins[] |
        select(.CustomOriginConfig != null)
      ]
    ) as $apiOrigins |
    ($apiOrigins | length) == 1 and
    ($apiOrigins[0].DomainName | tostring |
      contains($restApis[0].key)) and
    ($apiOrigins[0].DomainName | tostring |
      contains("execute-api")) and
    $apiOrigins[0].OriginPath == ("/" + $stage) and
    $apiOrigins[0].ConnectionAttempts == 3 and
    $apiOrigins[0].ConnectionTimeout == 10 and
    $apiOrigins[0].CustomOriginConfig.HTTPPort == 80 and
    $apiOrigins[0].CustomOriginConfig.HTTPSPort == 443 and
    $apiOrigins[0].CustomOriginConfig.OriginProtocolPolicy ==
      "https-only" and
    $apiOrigins[0].CustomOriginConfig.OriginSSLProtocols ==
      ["TLSv1.2"] and
    ($apiOrigins[0].OriginCustomHeaders | length) == 1 and
    $apiOrigins[0].OriginCustomHeaders[0].HeaderName ==
      "x-api-key" and
    $apiOrigins[0].OriginCustomHeaders[0].HeaderValue ==
      $apiKeys[0].value.Properties.Value and
    (
      [
        $distribution.CacheBehaviors[] |
        select(
          .PathPattern == "api/*" and
          .TargetOriginId == $apiOrigins[0].Id and
          .ViewerProtocolPolicy == "https-only" and
          .CachePolicyId ==
            "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" and
          .OriginRequestPolicyId ==
            {"Ref": $originPolicies[0].key} and
          .Compress == true and
          (.AllowedMethods | sort) == [
            "DELETE",
            "GET",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "POST",
            "PUT"
          ] and
          (.CachedMethods | sort) == ["GET", "HEAD", "OPTIONS"]
        )
      ] |
      length
    ) == 1
  ' <<<"${stack_template_body}" >/dev/null || {
  fail_contract "Deployed template violates the CloudFront API-origin binding contract"
}
deployed_template_sha="$(sha256_text "${stack_template_body}")"
unset stack_template_body

origin_request_policy_json="$(
  aws cloudfront get-origin-request-policy-config \
    --id "${origin_request_policy_id}" \
    --output json
)"
jq -e \
  --arg name "archon-${deployment_stage}-api-origin" \
  '
    .OriginRequestPolicyConfig.Name == $name and
    .OriginRequestPolicyConfig.HeadersConfig.HeaderBehavior == "allExcept" and
    .OriginRequestPolicyConfig.HeadersConfig.Headers.Quantity == 1 and
    (
      .OriginRequestPolicyConfig.HeadersConfig.Headers.Items |
      map(ascii_downcase) |
      sort
    ) == ["host"] and
    .OriginRequestPolicyConfig.CookiesConfig.CookieBehavior == "all" and
    .OriginRequestPolicyConfig.QueryStringsConfig.QueryStringBehavior == "all"
  ' <<<"${origin_request_policy_json}" >/dev/null || {
  fail_contract "CloudFront origin request policy violates the viewer-context contract"
}

probe_http_status() {
  local url="$1"
  shift
  local status
  if ! status="$(
    curl \
      --silent \
      --show-error \
      --proto '=https' \
      --tlsv1.2 \
      --connect-timeout 10 \
      --max-time 35 \
      --output /dev/null \
      --write-out '%{http_code}' \
      "$@" \
      "${url}"
  )"; then
    fail_contract "API-origin reachability probe failed to complete"
  fi
  [[ "${status}" =~ ^[0-9]{3}$ ]] || {
    fail_contract "API-origin reachability probe returned an invalid status"
  }
  printf '%s' "${status}"
}

probe_audit_id="0000000000000000000000000000000000000000000000000000000000000000"
direct_probe_url="${api_invoke_url%/}/api/control-loops/${probe_audit_id}"
cloudfront_probe_url="${api_url%/}/control-loops/${probe_audit_id}"
direct_without_key_status="$(probe_http_status "${direct_probe_url}")"
test "${direct_without_key_status}" = "403" || {
  fail_contract "Direct API Gateway origin accepted a request without an API key"
}
direct_bogus_key_status="$(
  probe_http_status \
    "${direct_probe_url}" \
    --header \
    'x-api-key: archon-intentionally-invalid-origin-credential'
)"
test "${direct_bogus_key_status}" = "403" || {
  fail_contract "Direct API Gateway origin accepted a bogus API key"
}
cloudfront_viewer_spoof_status="$(
  probe_http_status \
    "${cloudfront_probe_url}" \
    --header \
    'x-api-key: archon-intentionally-invalid-origin-credential'
)"
test "${cloudfront_viewer_spoof_status}" = "404" || {
  fail_contract "CloudFront did not overwrite a viewer-supplied API key at the origin"
}

stack_outputs_sha="$(sha256sum "${ARCHON_STACK_OUTPUTS}" | awk '{print $1}')"
rest_api_id_sha="$(sha256_text "${rest_api_id}")"
api_key_id_sha="$(sha256_text "${api_key_id}")"
usage_plan_id_sha="$(sha256_text "${usage_plan_id}")"
usage_plan_key_id_sha="$(sha256_text "${usage_plan_key_id}")"
distribution_id_sha="$(sha256_text "${distribution_id}")"
distribution_domain_sha="$(sha256_text "${distribution_domain}")"
viewer_domain_sha="$(sha256_text "${viewer_domain}")"
origin_request_policy_id_sha="$(sha256_text "${origin_request_policy_id}")"

jq -cnS \
  --arg stackName "${ARCHON_STACK_NAME}" \
  --arg cdkOutputsSha256 "${stack_outputs_sha}" \
  --arg deployedTemplateSha256 "${deployed_template_sha}" \
  --arg stage "${api_stage}" \
  --arg restApiIdSha256 "${rest_api_id_sha}" \
  --arg apiKeyIdSha256 "${api_key_id_sha}" \
  --arg usagePlanIdSha256 "${usage_plan_id_sha}" \
  --arg usagePlanKeyIdSha256 "${usage_plan_key_id_sha}" \
  --arg distributionIdSha256 "${distribution_id_sha}" \
  --arg distributionDomainSha256 "${distribution_domain_sha}" \
  --arg viewerDomainSha256 "${viewer_domain_sha}" \
  --arg originRequestPolicyIdSha256 \
    "${origin_request_policy_id_sha}" \
  --argjson methods "${method_contracts}" \
  --argjson burstLimit "${expected_burst_limit}" \
  --argjson rateLimit "${expected_rate_limit}" \
  --argjson dailyQuota "${expected_daily_quota}" \
  --argjson directWithoutKeyStatus "${direct_without_key_status}" \
  --argjson directBogusKeyStatus "${direct_bogus_key_status}" \
  --argjson cloudFrontViewerSpoofStatus \
    "${cloudfront_viewer_spoof_status}" \
  '{
    schemaVersion: "archon.api-origin-contract/v1",
    stackName: $stackName,
    cdkOutputsSha256: $cdkOutputsSha256,
    deployedTemplateSha256: $deployedTemplateSha256,
    apiGateway: {
      restApiIdSha256: $restApiIdSha256,
      stage: $stage,
      endpointType: "REGIONAL",
      executeApiEndpoint: "enabled",
      apiKeySource: "HEADER",
      methods: $methods
    },
    originCredential: {
      apiKeyIdSha256: $apiKeyIdSha256,
      enabled: true,
      materialHandling: "not-retrieved",
      usagePlan: {
        usagePlanIdSha256: $usagePlanIdSha256,
        usagePlanKeyIdSha256: $usagePlanKeyIdSha256,
        association: "validated",
        throttle: {
          burstLimit: $burstLimit,
          rateLimit: $rateLimit
        },
        quota: {
          limit: $dailyQuota,
          period: "DAY"
        }
      }
    },
    cloudFront: {
      distributionIdSha256: $distributionIdSha256,
      distributionDomainSha256: $distributionDomainSha256,
      viewerDomainSha256: $viewerDomainSha256,
      apiBehavior: {
        pathPattern: "api/*",
        cachePolicy: "CachingDisabled",
        viewerProtocolPolicy: "https-only"
      },
      apiOrigin: {
        protocolPolicy: "https-only",
        customHeaderName: "x-api-key",
        credentialBinding:
          "deployed-template-unresolved-dynamic-reference",
        credentialMaterialHandling: "not-retrieved",
        downstreamCredentialIsolation: "validated"
      },
      originRequestPolicy: {
        idSha256: $originRequestPolicyIdSha256,
        headerBehavior: "allExcept",
        viewerHeaderExclusions: ["host"],
        cookies: "all",
        queryStrings: "all"
      }
    },
    probes: {
      directOriginWithoutCredential: {
        expectedStatus: 403,
        observedStatus: $directWithoutKeyStatus,
        result: "rejected"
      },
      directOriginWithBogusCredential: {
        expectedStatus: 403,
        observedStatus: $directBogusKeyStatus,
        result: "rejected"
      },
      cloudFrontViewerCredentialSpoof: {
        expectedStatus: 404,
        observedStatus: $cloudFrontViewerSpoofStatus,
        result: "origin-overwrite-validated"
      }
    },
    validation: "passed"
  }'
