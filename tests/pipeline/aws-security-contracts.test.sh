#!/usr/bin/env bash
set -euo pipefail

repository_root="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/../.."
  pwd
)"
work_root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/archon-contract-tests.XXXXXX")"
trap 'rm -rf "${work_root}"' EXIT
mkdir -p "${work_root}/bin"

stack_outputs="${work_root}/stack-outputs.json"
datahub_service_name="com.amazonaws.vpce.eu-west-1.vpce-svc-ccccccccccccccccc"
cat >"${stack_outputs}" <<'JSON'
{
  "Archon-staging": {
    "ArchonApiSecurityGroupId": "sg-11111111111111111",
    "ArchonNlbSecurityGroupId": "sg-22222222222222222",
    "ArchonPrivateNlbArn": "arn:aws:elasticloadbalancing:eu-west-1:111111111111:loadbalancer/net/archon-staging/0123456789abcdef",
    "ArchonVpcId": "vpc-66666666666666666",
    "ArchonAuditWorkerSecurityGroupId": "sg-33333333333333333",
    "ArchonRemediationWorkerSecurityGroupId": "sg-44444444444444444",
    "ArchonVpcEndpointSecurityGroupId": "sg-55555555555555555",
    "ArchonDataHubEndpointSecurityGroupId": "sg-aaaaaaaaaaaaaaaaa",
    "ArchonDataHubEndpointId": "vpce-bbbbbbbbbbbbbbbbb",
    "ArchonDataHubEndpointServiceName": "com.amazonaws.vpce.eu-west-1.vpce-svc-ccccccccccccccccc",
    "ArchonDataHubPrivateLinkAzOne": "eu-west-1a",
    "ArchonDataHubPrivateLinkAzTwo": "eu-west-1b",
    "ArchonBedrockMantleEndpointSecurityGroupId": "sg-88888888888888888",
    "ArchonBedrockMantleEndpointId": "vpce-99999999999999999",
    "ArchonBedrockMantleEndpointServiceName": "com.amazonaws.eu-west-1.bedrock-mantle",
    "ArchonBedrockMantleModel": "qwen.qwen3-235b-a22b-2507",
    "ArchonBedrockMantleProjectId": "proj_archonstaging001",
    "ArchonBedrockMantleProjectArn": "arn:aws:bedrock-mantle:eu-west-1:111111111111:project/proj_archonstaging001",
    "ArchonApiTaskRoleArn": "arn:aws:iam::111111111111:role/archon-staging-api",
    "ArchonAuditWorkerTaskRoleArn": "arn:aws:iam::111111111111:role/archon-staging-audit",
    "ArchonRemediationWorkerTaskRoleArn": "arn:aws:iam::111111111111:role/archon-staging-remediation",
    "ArchonRegionalWebAclArn": "arn:aws:wafv2:eu-west-1:111111111111:regional/webacl/archon-staging-api/12345678-1234-0123-0123-1234567890ab",
    "ArchonRegionalWafLogGroupName": "aws-waf-logs-archon-staging-api",
    "ArchonRegionalWafLogKeyArn": "arn:aws:kms:eu-west-1:111111111111:key/87654321-4321-0321-1321-ba0987654321",
    "ArchonApiStageArn": "arn:aws:apigateway:eu-west-1::/restapis/abc123def4/stages/staging",
    "ArchonUserPoolId": "eu-west-1_ArchonStaging",
    "ArchonUserPoolArn": "arn:aws:cognito-idp:eu-west-1:111111111111:userpool/eu-west-1_ArchonStaging",
    "ArchonApiInvokeUrl": "https://abc123def4.execute-api.eu-west-1.amazonaws.com/staging/",
    "ArchonApiUrl": "https://staging.archon.example/api",
    "ArchonApplicationUrl": "https://staging.archon.example",
    "ArchonCloudFrontDistributionId": "E123456789ABCD",
    "ArchonCloudFrontDomainName": "d111111abcdef8.cloudfront.net"
  }
}
JSON

cat >"${work_root}/bin/aws" <<'FAKE_AWS'
#!/usr/bin/env bash
set -euo pipefail

api_group="sg-11111111111111111"
nlb_group="sg-22222222222222222"
audit_group="sg-33333333333333333"
remediation_group="sg-44444444444444444"
endpoint_group="sg-55555555555555555"
datahub_endpoint_group="sg-aaaaaaaaaaaaaaaaa"
datahub_endpoint_id="vpce-bbbbbbbbbbbbbbbbb"
datahub_service_name="com.amazonaws.vpce.eu-west-1.vpce-svc-ccccccccccccccccc"
bedrock_endpoint_group="sg-88888888888888888"
bedrock_endpoint_id="vpce-99999999999999999"
bedrock_project_id="proj_archonstaging001"
bedrock_project_arn="arn:aws:bedrock-mantle:eu-west-1:111111111111:project/${bedrock_project_id}"
api_task_role_arn="arn:aws:iam::111111111111:role/archon-staging-api"
audit_task_role_arn="arn:aws:iam::111111111111:role/archon-staging-audit"
remediation_task_role_arn="arn:aws:iam::111111111111:role/archon-staging-remediation"
vpc_id="vpc-66666666666666666"
web_acl_arn="arn:aws:wafv2:eu-west-1:111111111111:regional/webacl/archon-staging-api/12345678-1234-0123-0123-1234567890ab"
api_stage_arn="arn:aws:apigateway:eu-west-1::/restapis/abc123def4/stages/staging"
user_pool_arn="arn:aws:cognito-idp:eu-west-1:111111111111:userpool/eu-west-1_ArchonStaging"
rest_api_id="abc123def4"
api_key_id="key1234567890abcdef"
usage_plan_id="plan123456"
origin_request_policy_id="11111111-2222-4333-8444-555555555555"
distribution_id="E123456789ABCD"
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
narrow_success_response_template="$(
  cat <<'VTL'
#set($statusCode = $input.path('$.statusCode'))
#set($context.responseOverride.status = $statusCode)
$input.json('$.payload')
VTL
)"
narrow_error_response_template=$'{"error":"lambda_integration_failed"}\n'
narrow_no_store="'no-store'"
narrow_content_type="'application/json; charset=utf-8'"
narrow_cross_origin_resource_policy="'same-origin'"
narrow_referrer_policy="'no-referrer'"
narrow_content_type_options="'nosniff'"

case "${1:-}:${2:-}" in
  cloudformation:list-stack-resources)
    cat <<JSON
{"StackResourceSummaries":[
  {"LogicalResourceId":"RestApi","PhysicalResourceId":"${rest_api_id}","ResourceType":"AWS::ApiGateway::RestApi","ResourceStatus":"CREATE_COMPLETE"},
  {"LogicalResourceId":"CloudFrontOriginApiKey","PhysicalResourceId":"${api_key_id}","ResourceType":"AWS::ApiGateway::ApiKey","ResourceStatus":"CREATE_COMPLETE"},
  {"LogicalResourceId":"CloudFrontOriginUsagePlan","PhysicalResourceId":"${usage_plan_id}","ResourceType":"AWS::ApiGateway::UsagePlan","ResourceStatus":"CREATE_COMPLETE"},
  {"LogicalResourceId":"CloudFrontOriginUsagePlanKey","PhysicalResourceId":"usage-plan-key-binding","ResourceType":"AWS::ApiGateway::UsagePlanKey","ResourceStatus":"CREATE_COMPLETE"},
  {"LogicalResourceId":"ApiOriginRequestPolicy","PhysicalResourceId":"${origin_request_policy_id}","ResourceType":"AWS::CloudFront::OriginRequestPolicy","ResourceStatus":"CREATE_COMPLETE"},
  {"LogicalResourceId":"Distribution","PhysicalResourceId":"${distribution_id}","ResourceType":"AWS::CloudFront::Distribution","ResourceStatus":"CREATE_COMPLETE"}
]}
JSON
    ;;
  apigateway:get-rest-api)
    api_key_source="HEADER"
    if [[ "${FAKE_API_KEY_SOURCE_DRIFT:-0}" == "1" ]]; then
      api_key_source="AUTHORIZER"
    fi
    cat <<JSON
{
  "id":"${rest_api_id}",
  "name":"archon-staging",
  "apiKeySource":"${api_key_source}",
  "endpointConfiguration":{"types":["REGIONAL"]},
  "disableExecuteApiEndpoint":false
}
JSON
    ;;
  apigateway:get-resources)
    cat <<'JSON'
{"items":[
  {"id":"res-root","path":"/"},
  {"id":"res-api","path":"/api"},
  {"id":"res-audits","path":"/api/audits"},
  {"id":"res-control","path":"/api/control-loops"},
  {"id":"res-status","path":"/api/control-loops/{auditId}"},
  {"id":"res-approvals","path":"/api/approvals"},
  {"id":"res-approval","path":"/api/approvals/{approvalId}"},
  {"id":"res-decisions","path":"/api/approvals/{approvalId}/decisions"}
]}
JSON
    ;;
  apigateway:get-method)
    arguments=("$@")
    resource_id=""
    http_method=""
    lambda_statuses='[]'
    for ((index = 0; index < ${#arguments[@]}; index++)); do
      case "${arguments[index]}" in
        --resource-id)
          resource_id="${arguments[index + 1]}"
          ;;
        --http-method)
          http_method="${arguments[index + 1]}"
          ;;
      esac
    done
    case "${resource_id}:${http_method}" in
      res-audits:POST)
        response="$(
          cat <<'JSON'
{
  "httpMethod":"POST",
  "authorizationType":"NONE",
  "apiKeyRequired":true,
  "requestValidatorId":"validator-1",
  "requestParameters":{},
  "methodIntegration":{
    "type":"HTTP_PROXY",
    "httpMethod":"POST",
    "connectionType":"VPC_LINK",
    "connectionId":"vpc-link-1",
    "requestParameters":{
      "integration.request.header.x-api-key":"'redacted'"
    }
  }
}
JSON
        )"
        ;;
      res-control:POST)
        lambda_statuses='["200","202","400","404","413","502"]'
        response="$(
          jq -cn \
            --arg template "${control_start_request_template}" \
            '{
              httpMethod: "POST",
              authorizationType: "NONE",
              apiKeyRequired: true,
              requestValidatorId: "validator-1",
              requestParameters: {},
              methodIntegration: {
                type: "AWS",
                httpMethod: "POST",
                connectionType: "INTERNET",
                passthroughBehavior: "NEVER",
                requestTemplates: {
                  "application/json": $template
                }
              }
            }'
        )"
        ;;
      res-status:GET)
        lambda_statuses='["200","400","404","502"]'
        response="$(
          jq -cn \
            --arg template "${control_status_request_template}" \
            '{
              httpMethod: "GET",
              authorizationType: "NONE",
              apiKeyRequired: true,
              requestValidatorId: "validator-1",
              requestParameters: {
                "method.request.path.auditId": true
              },
              methodIntegration: {
                type: "AWS",
                httpMethod: "POST",
                connectionType: "INTERNET",
                passthroughBehavior: "NEVER",
                requestTemplates: {
                  "application/json": $template
                }
              }
            }'
        )"
        ;;
      res-decisions:POST)
        lambda_statuses='["200","202","400","401","403","404","409","410","502"]'
        response="$(
          jq -cn \
            --arg template "${approval_decision_request_template}" \
            '{
              httpMethod: "POST",
              authorizationType: "COGNITO_USER_POOLS",
              authorizerId: "authorizer-1",
              authorizationScopes: ["archon/approve"],
              apiKeyRequired: true,
              requestValidatorId: "validator-1",
              requestParameters: {
                "method.request.path.approvalId": true
              },
              methodIntegration: {
                type: "AWS",
                httpMethod: "POST",
                connectionType: "INTERNET",
                passthroughBehavior: "NEVER",
                requestTemplates: {
                  "application/json": $template
                }
              }
            }'
        )"
        ;;
      *)
        echo "unexpected API method: ${resource_id}:${http_method}" >&2
        exit 2
        ;;
    esac
    if [[ "${lambda_statuses}" != '[]' ]]; then
      response="$(
        jq \
          --argjson statuses "${lambda_statuses}" \
          --arg noStore "${narrow_no_store}" \
          --arg contentType "${narrow_content_type}" \
          --arg crossOriginResourcePolicy \
            "${narrow_cross_origin_resource_policy}" \
          --arg referrerPolicy "${narrow_referrer_policy}" \
          --arg contentTypeOptions "${narrow_content_type_options}" \
          --arg errorTemplate "${narrow_error_response_template}" \
          --arg successTemplate "${narrow_success_response_template}" \
          '
            def base_response_parameters:
              {
                "method.response.header.Cache-Control": $noStore,
                "method.response.header.Content-Type": $contentType,
                "method.response.header.Cross-Origin-Resource-Policy":
                  $crossOriginResourcePolicy,
                "method.response.header.Referrer-Policy":
                  $referrerPolicy,
                "method.response.header.X-Content-Type-Options":
                  $contentTypeOptions
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
                "method.response.header.Cross-Origin-Resource-Policy":
                  true,
                "method.response.header.Referrer-Policy": true,
                "method.response.header.X-Content-Type-Options": true,
                "method.response.header.Location": false,
                "method.response.header.Retry-After": false
              };
            .methodIntegration.integrationResponses = {
              "502": {
                statusCode: "502",
                selectionPattern: "(?s).+",
                responseParameters: base_response_parameters,
                responseTemplates: {
                  "application/json": $errorTemplate
                }
              },
              "200": {
                statusCode: "200",
                responseParameters: success_response_parameters,
                responseTemplates: {
                  "application/json": $successTemplate
                }
              }
            } |
            .methodResponses = reduce $statuses[] as $status (
              {};
              .[$status] = {
                statusCode: $status,
                responseParameters: method_response_parameters
              }
            )
          ' <<<"${response}"
      )"
    fi
    if [[ "${FAKE_API_KEY_REQUIRED_DRIFT:-0}" == "1" &&
          "${resource_id}" == "res-audits" ]]; then
      response="$(jq '.apiKeyRequired = false' <<<"${response}")"
    fi
    if [[ "${FAKE_API_AUTHORIZATION_DRIFT:-0}" == "1" &&
          "${resource_id}" == "res-decisions" ]]; then
      response="$(jq '.authorizationType = "NONE"' <<<"${response}")"
    fi
    if [[ "${FAKE_API_SCRUB_DRIFT:-0}" == "1" &&
          "${resource_id}" == "res-audits" ]]; then
      response="$(
        jq \
          '.methodIntegration.requestParameters[
            "integration.request.header.x-api-key"
          ] = "method.request.header.x-api-key"' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_LAMBDA_TEMPLATE_DRIFT:-0}" == "1" &&
          "${resource_id}" == "res-control" ]]; then
      response="$(
        jq \
          '.methodIntegration.requestTemplates["application/json"] = "{}"' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_LAMBDA_PASSTHROUGH_DRIFT:-0}" == "1" &&
          "${resource_id}" == "res-control" ]]; then
      response="$(
        jq '.methodIntegration.passthroughBehavior = "WHEN_NO_MATCH"' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_LAMBDA_RESPONSE_TEMPLATE_DRIFT:-0}" == "1" &&
          "${resource_id}" == "res-control" ]]; then
      response="$(
        jq \
          '.methodIntegration.integrationResponses["200"]
            .responseTemplates["application/json"] = "$input.body"' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_LAMBDA_RESPONSE_HEADER_DRIFT:-0}" == "1" &&
          "${resource_id}" == "res-control" ]]; then
      response="$(
        jq \
          'del(
            .methodIntegration.integrationResponses["200"]
              .responseParameters[
                "method.response.header.Cache-Control"
              ]
          )' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_LAMBDA_METHOD_STATUS_DRIFT:-0}" == "1" &&
          "${resource_id}" == "res-control" ]]; then
      response="$(jq 'del(.methodResponses["413"])' <<<"${response}")"
    fi
    printf '%s\n' "${response}"
    ;;
  apigateway:get-api-key)
    if [[ " $* " == *" --include-value "* ]]; then
      echo "API-key material retrieval is forbidden in contract tests" >&2
      exit 2
    fi
    key_enabled=true
    if [[ "${FAKE_API_KEY_ENABLED_DRIFT:-0}" == "1" ]]; then
      key_enabled=false
    fi
    printf '{"id":"%s","enabled":%s}\n' "${api_key_id}" "${key_enabled}"
    ;;
  apigateway:get-usage-plan)
    usage_rate_limit=10
    if [[ "${FAKE_USAGE_PLAN_DRIFT:-0}" == "1" ]]; then
      usage_rate_limit=11
    fi
    cat <<JSON
{
  "id":"${usage_plan_id}",
  "name":"archon-staging-cloudfront-origin",
  "apiStages":[{"apiId":"${rest_api_id}","stage":"staging"}],
  "throttle":{"burstLimit":20,"rateLimit":${usage_rate_limit}},
  "quota":{"limit":25000,"offset":0,"period":"DAY"}
}
JSON
    ;;
  apigateway:get-usage-plans)
    if [[ "${FAKE_USAGE_PLAN_ASSOCIATION_DRIFT:-0}" == "1" ]]; then
      printf '{"items":[]}\n'
    else
      printf '{"items":[{"id":"%s"}]}\n' "${usage_plan_id}"
    fi
    ;;
  cloudformation:get-template)
    response="$(
      cat <<JSON
{
  "TemplateBody":{
    "Resources":{
      "RestApiLogical":{
        "Type":"AWS::ApiGateway::RestApi",
        "Properties":{"ApiKeySourceType":"HEADER"}
      },
      "SecretsKeyLogical":{
        "Type":"AWS::KMS::Key",
        "DeletionPolicy":"Retain",
        "UpdateReplacePolicy":"Retain",
        "Properties":{
          "EnableKeyRotation":true,
          "PendingWindowInDays":30,
          "KeyPolicy":{"Version":"2012-10-17","Statement":[]},
          "Tags":[{
            "Key":"ArchonKeyPurpose",
            "Value":"secrets"
          }]
        }
      },
      "OriginSecretLogical":{
        "Type":"AWS::SecretsManager::Secret",
        "DeletionPolicy":"Retain",
        "UpdateReplacePolicy":"Retain",
        "Properties":{
          "Name":"archon/staging/cloudfront-origin-api-key",
          "KmsKeyId":{"Fn::GetAtt":["SecretsKeyLogical","Arn"]},
          "GenerateSecretString":{
            "ExcludePunctuation":true,
            "GenerateStringKey":"apiKey",
            "IncludeSpace":false,
            "PasswordLength":64,
            "SecretStringTemplate":"{}"
          }
        }
      },
      "ApiKeyLogical":{
        "Type":"AWS::ApiGateway::ApiKey",
        "DependsOn":["OriginSecretLogical"],
        "Properties":{
          "Enabled":true,
          "Value":"{{resolve:secretsmanager:archon/staging/cloudfront-origin-api-key:SecretString:apiKey::}}"
        }
      },
      "OriginPolicyLogical":{
        "Type":"AWS::CloudFront::OriginRequestPolicy"
      },
      "DistributionLogical":{
        "Type":"AWS::CloudFront::Distribution",
        "DependsOn":["OriginSecretLogical"],
        "Properties":{
          "DistributionConfig":{
            "Enabled":true,
            "Origins":[{
              "Id":"api-origin",
              "DomainName":{
                "Fn::Join":[
                  "",
                  [
                    {"Ref":"RestApiLogical"},
                    ".execute-api.",
                    {"Ref":"AWS::Region"},
                    ".",
                    {"Ref":"AWS::URLSuffix"}
                  ]
                ]
              },
              "OriginPath":"/staging",
              "ConnectionAttempts":3,
              "ConnectionTimeout":10,
              "OriginCustomHeaders":[{
                "HeaderName":"x-api-key",
                "HeaderValue":"{{resolve:secretsmanager:archon/staging/cloudfront-origin-api-key:SecretString:apiKey::}}"
              }],
              "CustomOriginConfig":{
                "HTTPPort":80,
                "HTTPSPort":443,
                "OriginProtocolPolicy":"https-only",
                "OriginSSLProtocols":["TLSv1.2"]
              }
            },{
              "Id":"spa-origin",
              "DomainName":"spa.s3.amazonaws.com",
              "S3OriginConfig":{"OriginAccessIdentity":""}
            }],
            "CacheBehaviors":[{
              "PathPattern":"api/*",
              "TargetOriginId":"api-origin",
              "ViewerProtocolPolicy":"https-only",
              "CachePolicyId":"4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
              "OriginRequestPolicyId":{"Ref":"OriginPolicyLogical"},
              "Compress":true,
              "AllowedMethods":[
                "HEAD",
                "DELETE",
                "POST",
                "GET",
                "OPTIONS",
                "PUT",
                "PATCH"
              ],
              "CachedMethods":["OPTIONS","HEAD","GET"]
            }]
          }
        }
      }
    }
  }
}
JSON
    )"
    if [[ "${FAKE_CLOUDFRONT_CUSTOM_HEADER_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          '.TemplateBody.Resources.DistributionLogical.Properties
            .DistributionConfig.Origins[0].OriginCustomHeaders = []' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_CLOUDFRONT_DUPLICATE_HEADER_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          '.TemplateBody.Resources.DistributionLogical.Properties
            .DistributionConfig.Origins[1].OriginCustomHeaders = [{
              "HeaderName": "x-api-key",
              "HeaderValue":
                "{{resolve:secretsmanager:archon/staging/cloudfront-origin-api-key:SecretString:apiKey::}}"
            }]' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_API_ORIGIN_DOMAIN_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          '.TemplateBody.Resources.DistributionLogical.Properties
            .DistributionConfig.Origins[0].DomainName["Fn::Join"][1][1] =
              ".execute-api.attacker.example"' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_DYNAMIC_REFERENCE_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          '.TemplateBody.Resources.ApiKeyLogical.Properties.Value =
            "plaintext-is-forbidden"' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_ORIGIN_SECRET_NAME_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          '.TemplateBody.Resources.OriginSecretLogical.Properties.Name =
            "archon/production/cloudfront-origin-api-key"' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_ORIGIN_SECRET_RETENTION_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          'del(
            .TemplateBody.Resources.OriginSecretLogical.UpdateReplacePolicy
          )' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_ORIGIN_SECRET_GENERATOR_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          '.TemplateBody.Resources.OriginSecretLogical.Properties
            .GenerateSecretString.PasswordLength = 32' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_ORIGIN_SECRET_KMS_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          '.TemplateBody.Resources.OriginSecretLogical.Properties.KmsKeyId =
            "alias/aws/secretsmanager"' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_ORIGIN_SECRET_KMS_PURPOSE_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          '.TemplateBody.Resources.SecretsKeyLogical.Properties
            .Tags[0].Value = "data"' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_ORIGIN_SECRET_KMS_ROTATION_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          '.TemplateBody.Resources.SecretsKeyLogical.Properties
            .EnableKeyRotation = false' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_ORIGIN_SECRET_DEPENDENCY_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          'del(.TemplateBody.Resources.ApiKeyLogical.DependsOn)' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_ORIGIN_POLICY_BINDING_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          '.TemplateBody.Resources.DistributionLogical.Properties
            .DistributionConfig.CacheBehaviors[0].OriginRequestPolicyId.Ref =
              "UnvalidatedPolicyLogical"' \
          <<<"${response}"
      )"
    fi
    printf '%s\n' "${response}"
    ;;
  cloudfront:get-origin-request-policy-config)
    response="$(
      cat <<JSON
{
  "OriginRequestPolicyConfig":{
    "Name":"archon-staging-api-origin",
    "HeadersConfig":{
      "HeaderBehavior":"allExcept",
      "Headers":{"Quantity":1,"Items":["host"]}
    },
    "CookiesConfig":{"CookieBehavior":"all"},
    "QueryStringsConfig":{"QueryStringBehavior":"all"}
  }
}
JSON
    )"
    if [[ "${FAKE_ORIGIN_POLICY_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          '.OriginRequestPolicyConfig.HeadersConfig.Headers = {
            "Quantity": 2,
            "Items": ["host", "x-api-key"]
          }' \
          <<<"${response}"
      )"
    fi
    printf '%s\n' "${response}"
    ;;
  sts:get-caller-identity)
    if [[ " $* " == *" --query Account "* &&
          " $* " == *" --output text "* ]]; then
      printf '111111111111\n'
    else
      printf '{"Account":"111111111111","Arn":"arn:aws:sts::111111111111:assumed-role/test/test","UserId":"test"}\n'
    fi
    ;;
  ec2:describe-availability-zones)
    cat <<'JSON'
{"AvailabilityZones":[
  {"ZoneName":"eu-west-1a","State":"available","OptInStatus":"opt-in-not-required"},
  {"ZoneName":"eu-west-1b","State":"available","OptInStatus":"opt-in-not-required"},
  {"ZoneName":"eu-west-1c","State":"available","OptInStatus":"opt-in-not-required"}
]}
JSON
    ;;
  ec2:describe-vpcs)
    vpc_cidr="10.42.0.0/16"
    if [[ "${FAKE_VPC_CIDR_DRIFT:-0}" == "1" ]]; then
      vpc_cidr="10.43.0.0/16"
    fi
    cat <<JSON
{"Vpcs":[{
  "VpcId":"${vpc_id}",
  "CidrBlock":"${vpc_cidr}",
  "State":"available",
  "IsDefault":false,
  "OwnerId":"111111111111"
}]}
JSON
    ;;
  ec2:describe-security-group-rules)
    group=""
    for argument in "$@"; do
      case "${argument}" in
        Name=group-id,Values=*)
          group="${argument#Name=group-id,Values=}"
          ;;
      esac
    done
    case "${group}" in
      "${api_group}")
        cat <<JSON
{
  "SecurityGroupRules": [
    {"GroupId":"${api_group}","IsEgress":false,"IpProtocol":"tcp","FromPort":8080,"ToPort":8080,"ReferencedGroupInfo":{"GroupId":"${nlb_group}"}},
    {"GroupId":"${api_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${endpoint_group}"}},
    {"GroupId":"${api_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${datahub_endpoint_group}"}},
    {"GroupId":"${api_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${bedrock_endpoint_group}"}},
    {"GroupId":"${api_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-s3"}
    $(
      if [[ "${FAKE_NETWORK_DRIFT:-0}" == "1" ]]; then
        printf ',{"GroupId":"%s","IsEgress":true,"IpProtocol":"-1","CidrIpv4":"0.0.0.0/0"}' "${api_group}"
      fi
    )
  ]
}
JSON
        ;;
      "${nlb_group}")
        cat <<JSON
{"SecurityGroupRules":[{"GroupId":"${nlb_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":8080,"ToPort":8080,"ReferencedGroupInfo":{"GroupId":"${api_group}"}}]}
JSON
        ;;
      "${audit_group}")
        cat <<JSON
{"SecurityGroupRules":[
  {"GroupId":"${audit_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${endpoint_group}"}},
  {"GroupId":"${audit_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${datahub_endpoint_group}"}},
  {"GroupId":"${audit_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${bedrock_endpoint_group}"}},
  {"GroupId":"${audit_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-s3"},
  {"GroupId":"${audit_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-dynamodb"}
]}
JSON
        ;;
      "${remediation_group}")
        cat <<JSON
{"SecurityGroupRules":[
  {"GroupId":"${remediation_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${endpoint_group}"}},
  {"GroupId":"${remediation_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${datahub_endpoint_group}"}},
  {"GroupId":"${remediation_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-s3"},
  {"GroupId":"${remediation_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-dynamodb"}
]}
JSON
        ;;
      "${endpoint_group}")
        cat <<JSON
{"SecurityGroupRules":[
  {"GroupId":"${endpoint_group}","IsEgress":false,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${api_group}"}},
  {"GroupId":"${endpoint_group}","IsEgress":false,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${audit_group}"}},
  {"GroupId":"${endpoint_group}","IsEgress":false,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${remediation_group}"}},
  {"GroupId":"${endpoint_group}","IsEgress":true,"IpProtocol":"icmp","FromPort":252,"ToPort":86,"CidrIpv4":"255.255.255.255/32"}
]}
JSON
        ;;
      "${datahub_endpoint_group}")
        cat <<JSON
{"SecurityGroupRules":[
  {"GroupId":"${datahub_endpoint_group}","IsEgress":false,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${api_group}"}},
  {"GroupId":"${datahub_endpoint_group}","IsEgress":false,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${audit_group}"}},
  {"GroupId":"${datahub_endpoint_group}","IsEgress":false,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${remediation_group}"}},
  {"GroupId":"${datahub_endpoint_group}","IsEgress":true,"IpProtocol":"icmp","FromPort":252,"ToPort":86,"CidrIpv4":"255.255.255.255/32"}
]}
JSON
        ;;
      "${bedrock_endpoint_group}")
        cat <<JSON
{"SecurityGroupRules":[
  {"GroupId":"${bedrock_endpoint_group}","IsEgress":false,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${api_group}"}},
  {"GroupId":"${bedrock_endpoint_group}","IsEgress":false,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${audit_group}"}},
  {"GroupId":"${bedrock_endpoint_group}","IsEgress":true,"IpProtocol":"icmp","FromPort":252,"ToPort":86,"CidrIpv4":"255.255.255.255/32"}
]}
JSON
        ;;
      *)
        echo "unexpected security group: ${group}" >&2
        exit 2
        ;;
    esac
    ;;
  elbv2:describe-load-balancers)
    load_balancer_vpc_id="${vpc_id}"
    load_balancer_state="active"
    load_balancer_ip_address_type="ipv4"
    if [[ "${FAKE_NLB_VPC_DRIFT:-0}" == "1" ]]; then
      load_balancer_vpc_id="vpc-88888888888888888"
    fi
    if [[ "${FAKE_NLB_STATE_DRIFT:-0}" == "1" ]]; then
      load_balancer_state="provisioning"
    fi
    if [[ "${FAKE_NLB_IP_TYPE_DRIFT:-0}" == "1" ]]; then
      load_balancer_ip_address_type="dualstack"
    fi
    cat <<JSON
{"LoadBalancers":[{
  "LoadBalancerArn":"arn:aws:elasticloadbalancing:eu-west-1:111111111111:loadbalancer/net/archon-staging/0123456789abcdef",
  "VpcId":"${load_balancer_vpc_id}",
  "State":{"Code":"${load_balancer_state}"},
  "Scheme":"internal",
  "Type":"network",
  "IpAddressType":"${load_balancer_ip_address_type}",
  "SecurityGroups":["${nlb_group}"],
  "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic":"off"
}]}
JSON
    ;;
  ec2:describe-security-groups)
    group_ids_requested="false"
    for argument in "$@"; do
      if [[ "${argument}" == "--group-ids" ]]; then
        group_ids_requested="true"
      fi
    done
    if [[ "${group_ids_requested}" == "true" ]]; then
      api_group_vpc_id="${vpc_id}"
      api_group_owner_id="111111111111"
      if [[ "${FAKE_SG_VPC_DRIFT:-0}" == "1" ]]; then
        api_group_vpc_id="vpc-88888888888888888"
      fi
      if [[ "${FAKE_SG_ACCOUNT_DRIFT:-0}" == "1" ]]; then
        api_group_owner_id="222222222222"
      fi
      cat <<JSON
{"SecurityGroups":[
  {"GroupId":"${api_group}","GroupName":"archon-api","OwnerId":"${api_group_owner_id}","VpcId":"${api_group_vpc_id}","IpPermissions":[],"IpPermissionsEgress":[]},
  {"GroupId":"${nlb_group}","GroupName":"archon-nlb","OwnerId":"111111111111","VpcId":"${vpc_id}","IpPermissions":[],"IpPermissionsEgress":[]},
  {"GroupId":"${audit_group}","GroupName":"archon-audit","OwnerId":"111111111111","VpcId":"${vpc_id}","IpPermissions":[],"IpPermissionsEgress":[]},
  {"GroupId":"${remediation_group}","GroupName":"archon-remediation","OwnerId":"111111111111","VpcId":"${vpc_id}","IpPermissions":[],"IpPermissionsEgress":[]},
  {"GroupId":"${endpoint_group}","GroupName":"archon-endpoints","OwnerId":"111111111111","VpcId":"${vpc_id}","IpPermissions":[],"IpPermissionsEgress":[]},
  {"GroupId":"${datahub_endpoint_group}","GroupName":"archon-datahub","OwnerId":"111111111111","VpcId":"${vpc_id}","IpPermissions":[],"IpPermissionsEgress":[]},
  {"GroupId":"${bedrock_endpoint_group}","GroupName":"archon-bedrock-mantle","OwnerId":"111111111111","VpcId":"${vpc_id}","IpPermissions":[],"IpPermissionsEgress":[]}
]}
JSON
    else
      response="$(
      cat <<'JSON'
{"SecurityGroups":[{
  "GroupId":"sg-77777777777777777",
  "GroupName":"default",
  "OwnerId":"111111111111",
  "VpcId":"vpc-66666666666666666",
  "IpPermissions":[],
  "IpPermissionsEgress":[]
}]}
JSON
      )"
      if [[ "${FAKE_DEFAULT_SG_DRIFT:-0}" == "1" ]]; then
        jq '.SecurityGroups[0].IpPermissionsEgress = [{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' \
          <<<"${response}"
      else
        printf '%s\n' "${response}"
      fi
    fi
    ;;
  ec2:describe-vpc-endpoints)
    if [[ " $* " == *" ${datahub_endpoint_id} "* ]]; then
      datahub_private_dns_enabled=true
      if [[ "${FAKE_DATAHUB_ENDPOINT_DRIFT:-0}" == "1" ]]; then
        datahub_private_dns_enabled=false
      fi
      jq -cn \
        --arg endpointId "${datahub_endpoint_id}" \
        --arg serviceName "${datahub_service_name}" \
        --arg vpcId "${vpc_id}" \
        --arg securityGroupId "${datahub_endpoint_group}" \
        --argjson privateDnsEnabled "${datahub_private_dns_enabled}" \
        '{
          VpcEndpoints: [{
            VpcEndpointId: $endpointId,
            VpcEndpointType: "Interface",
            ServiceName: $serviceName,
            VpcId: $vpcId,
            OwnerId: "111111111111",
            RequesterManaged: false,
            State: "available",
            PrivateDnsEnabled: $privateDnsEnabled,
            Groups: [{GroupId: $securityGroupId}],
            SubnetIds: [
              "subnet-11111111111111111",
              "subnet-22222222222222222"
            ],
            NetworkInterfaceIds: [
              "eni-33333333333333333",
              "eni-44444444444444444"
            ],
            DnsEntries: [
              {DnsName: "vpce-datahub.eu-west-1.vpce.amazonaws.com"},
              {DnsName: "vpce-datahub-a.eu-west-1.vpce.amazonaws.com"}
            ],
            PolicyDocument: null
          }]
        }'
    else
    private_dns_enabled=true
    if [[ "${FAKE_BEDROCK_ENDPOINT_DRIFT:-0}" == "1" ]]; then
      private_dns_enabled=false
    fi
    endpoint_policy="$(
      jq -cn \
        --arg apiRole "${api_task_role_arn}" \
        --arg auditRole "${audit_task_role_arn}" \
        --arg projectArn "${bedrock_project_arn}" \
        '{
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "OnlyInferenceRolesMayInvokeApprovedModel",
              Effect: "Allow",
              Principal: {AWS: [$apiRole, $auditRole]},
              Action: "bedrock-mantle:CreateInference",
              Resource: $projectArn,
              Condition: {
                StringEquals: {
                  "bedrock-mantle:Model":
                    "qwen.qwen3-235b-a22b-2507"
                }
              }
            },
            {
              Sid: "OnlyInferenceRolesMayUseShortTermTokens",
              Effect: "Allow",
              Principal: {AWS: [$apiRole, $auditRole]},
              Action: "bedrock-mantle:CallWithBearerToken",
              Resource: "*",
              Condition: {
                StringEquals: {
                  "bedrock-mantle:BearerTokenType": "SHORT_TERM"
                }
              }
            }
          ]
        }'
    )"
    jq -cn \
      --arg endpointId "${bedrock_endpoint_id}" \
      --arg vpcId "${vpc_id}" \
      --arg securityGroupId "${bedrock_endpoint_group}" \
      --arg policy "${endpoint_policy}" \
      --argjson privateDnsEnabled "${private_dns_enabled}" \
      '{
        VpcEndpoints: [{
          VpcEndpointId: $endpointId,
          VpcEndpointType: "Interface",
          ServiceName: "com.amazonaws.eu-west-1.bedrock-mantle",
          VpcId: $vpcId,
          State: "available",
          PrivateDnsEnabled: $privateDnsEnabled,
          Groups: [{GroupId: $securityGroupId}],
          SubnetIds: [
            "subnet-11111111111111111",
            "subnet-22222222222222222"
          ],
          NetworkInterfaceIds: [
            "eni-11111111111111111",
            "eni-22222222222222222"
          ],
          DnsEntries: [
            {DnsName: "bedrock-mantle.eu-west-1.api.aws"},
            {DnsName: "vpce-a.bedrock-mantle.eu-west-1.vpce.amazonaws.com"},
            {DnsName: "vpce-b.bedrock-mantle.eu-west-1.vpce.amazonaws.com"}
          ],
          PolicyDocument: $policy
        }]
      }'
    fi
    ;;
  ec2:describe-vpc-endpoint-services)
    private_dns_verification_state="verified"
    if [[ "${FAKE_DATAHUB_SERVICE_DRIFT:-0}" == "1" ]]; then
      private_dns_verification_state="failed"
    fi
    jq -cn \
      --arg serviceName "${datahub_service_name}" \
      --arg verificationState "${private_dns_verification_state}" \
      '{
        ServiceNames: [$serviceName],
        ServiceDetails: [{
          ServiceName: $serviceName,
          ServiceId: "vpce-svc-ccccccccccccccccc",
          ServiceType: [{ServiceType: "Interface"}],
          ServiceRegion: "eu-west-1",
          ServiceState: "Available",
          AvailabilityZones: ["eu-west-1a", "eu-west-1b", "eu-west-1c"],
          Owner: "222222222222",
          AcceptanceRequired: false,
          PrivateDnsName: "tenant.datahub.example",
          PrivateDnsNameVerificationState: $verificationState,
          SupportedIpAddressTypes: ["ipv4"]
        }]
      }'
    ;;
  ec2:describe-subnets)
    cat <<JSON
{"Subnets":[
  {"SubnetId":"subnet-11111111111111111","VpcId":"${vpc_id}","AvailabilityZone":"eu-west-1a","State":"available"},
  {"SubnetId":"subnet-22222222222222222","VpcId":"${vpc_id}","AvailabilityZone":"eu-west-1b","State":"available"}
]}
JSON
    ;;
  cloudcontrol:get-resource)
    project_tags='[
      {"Key":"Application","Value":"archon-datahub"},
      {"Key":"Environment","Value":"staging"},
      {"Key":"ManagedBy","Value":"aws-cdk"},
      {"Key":"CostCenter","Value":"DataHub-Agent-Hackathon"}
    ]'
    if [[ "${FAKE_BEDROCK_PROJECT_DRIFT:-0}" == "1" ]]; then
      project_tags="$(
        jq 'map(if .Key == "CostCenter" then .Value = "Untracked" else . end)' \
          <<<"${project_tags}"
      )"
    fi
    project_properties="$(
      jq -cn \
        --arg name "Archon-staging" \
        --arg id "${bedrock_project_id}" \
        --arg arn "${bedrock_project_arn}" \
        --argjson tags "${project_tags}" \
        '{Name: $name, Id: $id, Arn: $arn, Tags: $tags}'
    )"
    jq -cn \
      --arg identifier "${bedrock_project_arn}" \
      --arg properties "${project_properties}" \
      '{
        ResourceDescription: {
          Identifier: $identifier,
          Properties: $properties
        }
      }'
    ;;
  iam:simulate-principal-policy)
    arguments=("$@")
    role_arn=""
    action=""
    resource=""
    context=""
    for ((index = 0; index < ${#arguments[@]}; index++)); do
      case "${arguments[index]}" in
        --policy-source-arn)
          role_arn="${arguments[index + 1]}"
          ;;
        --action-names)
          action="${arguments[index + 1]}"
          ;;
        --resource-arns)
          resource="${arguments[index + 1]}"
          ;;
        --context-entries)
          context="${arguments[index + 1]}"
          ;;
      esac
    done
    decision="implicitDeny"
    if [[ "${role_arn}" != "${remediation_task_role_arn}" ]]; then
      case "${action}" in
        bedrock-mantle:CreateInference)
          if [[ "${context}" == *"qwen.qwen3-235b-a22b-2507"* ]]; then
            decision="allowed"
          fi
          ;;
        bedrock-mantle:CallWithBearerToken)
          if [[ "${context}" == *"SHORT_TERM"* ]]; then
            decision="allowed"
          elif [[ "${context}" == *"LONG_TERM"* ]]; then
            decision="explicitDeny"
          fi
          ;;
      esac
    fi
    if [[ "${FAKE_BEDROCK_IAM_DRIFT:-0}" == "1" &&
          "${decision}" == "allowed" ]]; then
      decision="implicitDeny"
    fi
    jq -cn \
      --arg action "${action}" \
      --arg resource "${resource}" \
      --arg decision "${decision}" \
      '{
        EvaluationResults: [{
          EvalActionName: $action,
          EvalResourceName: $resource,
          EvalDecision: $decision
        }]
      }'
    ;;
  wafv2:get-web-acl)
    response="$(
      cat <<JSON
{"WebACL":{
  "ARN":"${web_acl_arn}",
  "Name":"archon-staging-api",
  "DefaultAction":{"Allow":{}},
  "VisibilityConfig":{"CloudWatchMetricsEnabled":true,"MetricName":"archon-staging-api-waf","SampledRequestsEnabled":true},
  "DataProtectionConfig":{"DataProtections":[
    {"Action":"SUBSTITUTION","ExcludeRateBasedDetails":false,"ExcludeRuleMatchDetails":false,"Field":{"FieldType":"SINGLE_HEADER","FieldKeys":["authorization"]}},
    {"Action":"SUBSTITUTION","ExcludeRateBasedDetails":false,"ExcludeRuleMatchDetails":false,"Field":{"FieldType":"SINGLE_HEADER","FieldKeys":["cookie"]}},
    {"Action":"SUBSTITUTION","ExcludeRateBasedDetails":false,"ExcludeRuleMatchDetails":false,"Field":{"FieldType":"SINGLE_HEADER","FieldKeys":["x-api-key"]}}
  ]},
  "Rules":[
    {"Name":"AWSManagedRulesAmazonIpReputationList","Priority":0,"OverrideAction":{"None":{}},"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesAmazonIpReputationList"}},"VisibilityConfig":{"CloudWatchMetricsEnabled":true,"MetricName":"AWSManagedRulesAmazonIpReputationList","SampledRequestsEnabled":true}},
    {"Name":"AWSManagedRulesCommonRuleSet","Priority":10,"OverrideAction":{"None":{}},"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesCommonRuleSet"}},"VisibilityConfig":{"CloudWatchMetricsEnabled":true,"MetricName":"AWSManagedRulesCommonRuleSet","SampledRequestsEnabled":true}},
    {"Name":"AWSManagedRulesKnownBadInputsRuleSet","Priority":20,"OverrideAction":{"None":{}},"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesKnownBadInputsRuleSet"}},"VisibilityConfig":{"CloudWatchMetricsEnabled":true,"MetricName":"AWSManagedRulesKnownBadInputsRuleSet","SampledRequestsEnabled":true}},
    {"Name":"PerIpRateLimit","Priority":30,"Action":{"Block":{}},"Statement":{"RateBasedStatement":{"AggregateKeyType":"IP","EvaluationWindowSec":300,"Limit":300}},"VisibilityConfig":{"CloudWatchMetricsEnabled":true,"MetricName":"archon-staging-rate-limit","SampledRequestsEnabled":true}}
  ]
}}
JSON
    )"
    if [[ "${FAKE_WAF_RULE_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq '.WebACL.Rules[0].Statement.ManagedRuleGroupStatement.VendorName = "Untrusted"' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_WAF_MANAGED_VERSION_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq '.WebACL.Rules[0].Statement.ManagedRuleGroupStatement.Version = "Version_1.0"' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_WAF_MANAGED_CONFIG_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq '.WebACL.Rules[0].Statement.ManagedRuleGroupStatement.ManagedRuleGroupConfigs = [{"AWSManagedRulesATPRuleSet":{"LoginPath":"/login"}}]' \
          <<<"${response}"
      )"
    fi
    if [[ "${FAKE_WAF_RATE_WINDOW_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq '.WebACL.Rules[3].Statement.RateBasedStatement.EvaluationWindowSec = 60' \
          <<<"${response}"
      )"
    fi
    printf '%s\n' "${response}"
    ;;
  wafv2:get-logging-configuration)
    response="$(
      cat <<JSON
{"LoggingConfiguration":{
  "ResourceArn":"${web_acl_arn}",
  "LogDestinationConfigs":["arn:aws:logs:eu-west-1:111111111111:log-group:aws-waf-logs-archon-staging-api"],
  "LoggingFilter":{"DefaultBehavior":"DROP","Filters":[{"Behavior":"KEEP","Requirement":"MEETS_ANY","Conditions":[{"ActionCondition":{"Action":"BLOCK"}},{"ActionCondition":{"Action":"COUNT"}}]}]},
  "RedactedFields":[{"SingleHeader":{"Name":"authorization"}},{"SingleHeader":{"Name":"cookie"}},{"SingleHeader":{"Name":"x-api-key"}}]
}}
JSON
    )"
    if [[ "${FAKE_WAF_LOGGING_DRIFT:-0}" == "1" ]]; then
      jq '.LoggingConfiguration.LoggingFilter.Filters += [{"Behavior":"KEEP","Requirement":"MEETS_ANY","Conditions":[{"ActionCondition":{"Action":"ALLOW"}}]}]' \
        <<<"${response}"
    else
      printf '%s\n' "${response}"
    fi
    ;;
  wafv2:get-web-acl-for-resource)
    arguments=("$@")
    resource_arn=""
    for ((index = 0; index < ${#arguments[@]}; index++)); do
      if [[ "${arguments[index]}" == "--resource-arn" ]]; then
        resource_arn="${arguments[index + 1]}"
      fi
    done
    test -n "${resource_arn}"
    associated_web_acl_arn="${web_acl_arn}"
    case "${resource_arn}" in
      "${api_stage_arn}")
        if [[ "${FAKE_API_WAF_ASSOCIATION_DRIFT:-0}" == "1" ]]; then
          associated_web_acl_arn="arn:aws:wafv2:eu-west-1:111111111111:regional/webacl/unassociated/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        fi
        ;;
      "${user_pool_arn}")
        if [[ "${FAKE_COGNITO_WAF_ASSOCIATION_DRIFT:-0}" == "1" ]]; then
          associated_web_acl_arn="arn:aws:wafv2:eu-west-1:111111111111:regional/webacl/unassociated/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        fi
        ;;
      *)
        echo "unexpected WAF association resource: ${resource_arn}" >&2
        exit 2
        ;;
    esac
    if [[ -n "${FAKE_WAF_ASSOCIATION_LOG:-}" ]]; then
      printf '%s\n' "${resource_arn}" >>"${FAKE_WAF_ASSOCIATION_LOG}"
    fi
    printf '{"WebACL":{"ARN":"%s"}}\n' "${associated_web_acl_arn}"
    ;;
  logs:describe-log-groups)
    log_group_kms_arn="arn:aws:kms:eu-west-1:111111111111:key/87654321-4321-0321-1321-ba0987654321"
    log_group_retention_days=365
    if [[ "${FAKE_WAF_LOG_KMS_DRIFT:-0}" == "1" ]]; then
      log_group_kms_arn="arn:aws:kms:eu-west-1:111111111111:key/99999999-9999-0999-1999-999999999999"
    fi
    if [[ "${FAKE_WAF_LOG_RETENTION_DRIFT:-0}" == "1" ]]; then
      log_group_retention_days=30
    fi
    cat <<JSON
{"logGroups":[{
  "logGroupName":"aws-waf-logs-archon-staging-api",
  "kmsKeyId":"${log_group_kms_arn}",
  "retentionInDays":${log_group_retention_days}
}]}
JSON
    ;;
  kms:describe-key)
    key_enabled=true
    key_state="Enabled"
    if [[ "${FAKE_WAF_LOG_KEY_STATE_DRIFT:-0}" == "1" ]]; then
      key_enabled=false
      key_state="Disabled"
    fi
    cat <<JSON
{"KeyMetadata":{
  "AWSAccountId":"111111111111",
  "Arn":"arn:aws:kms:eu-west-1:111111111111:key/87654321-4321-0321-1321-ba0987654321",
  "Enabled":${key_enabled},
  "KeyManager":"CUSTOMER",
  "KeySpec":"SYMMETRIC_DEFAULT",
  "KeyState":"${key_state}",
  "KeyUsage":"ENCRYPT_DECRYPT",
  "MultiRegion":false,
  "Origin":"AWS_KMS"
}}
JSON
    ;;
  kms:get-key-rotation-status)
    rotation_enabled=true
    if [[ "${FAKE_WAF_LOG_KEY_ROTATION_DRIFT:-0}" == "1" ]]; then
      rotation_enabled=false
    fi
    printf '{"KeyRotationEnabled":%s}\n' "${rotation_enabled}"
    ;;
  *)
    echo "unexpected fake AWS command: $*" >&2
    exit 2
    ;;
esac
FAKE_AWS
chmod 700 "${work_root}/bin/aws"

cat >"${work_root}/bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail

arguments=("$@")
request_url=""
has_api_key_header="false"
for ((index = 0; index < ${#arguments[@]}; index++)); do
  case "${arguments[index]}" in
    --header)
      header_value="${arguments[index + 1]}"
      if [[ "${header_value,,}" == x-api-key:* ]]; then
        has_api_key_header="true"
      fi
      ;;
    https://*)
      request_url="${arguments[index]}"
      ;;
  esac
done

case "${request_url}" in
  https://abc123def4.execute-api.eu-west-1.amazonaws.com/staging/api/control-loops/*)
    if [[ "${has_api_key_header}" == "true" ]]; then
      status=403
      if [[ "${FAKE_DIRECT_BOGUS_KEY_DRIFT:-0}" == "1" ]]; then
        status=404
      fi
    else
      status=403
      if [[ "${FAKE_DIRECT_NO_KEY_DRIFT:-0}" == "1" ]]; then
        status=404
      fi
    fi
    ;;
  https://staging.archon.example/api/control-loops/*)
    status=404
    if [[ "${has_api_key_header}" != "true" ||
          "${FAKE_CLOUDFRONT_SPOOF_DRIFT:-0}" == "1" ]]; then
      status=403
    fi
    ;;
  *)
    echo "unexpected fake curl URL: ${request_url}" >&2
    exit 2
    ;;
esac

printf '%s' "${status}"
FAKE_CURL
chmod 700 "${work_root}/bin/curl"
export PATH="${work_root}/bin:${PATH}"

datahub_private_link_preflight="$(
  EXPECTED_ACCOUNT_ID="111111111111" \
  AWS_REGION="eu-west-1" \
  ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME="${datahub_service_name}" \
  DATAHUB_READ_GMS_URL="https://tenant.datahub.example/api/gms" \
  DATAHUB_READ_MCP_URL="https://tenant.datahub.example/configured/read-mcp" \
  DATAHUB_WRITE_GMS_URL="https://tenant.datahub.example/api/gms" \
  DATAHUB_WRITE_MCP_URL="https://tenant.datahub.example/configured/write-mcp" \
    bash "${repository_root}/scripts/validate-datahub-private-link-service.sh"
)"
jq --exit-status '
  .schemaVersion == "archon.datahub-private-link-preflight/v1" and
  .deploymentAccountId == "111111111111" and
  .region == "eu-west-1" and
  .service.type == "Interface" and
  .service.privateDnsName == "tenant.datahub.example" and
  .service.privateDnsVerificationState == "verified" and
  .service.selectedAvailabilityZones == ["eu-west-1a", "eu-west-1b"] and
  .urlBinding.tenantOrigin == "https://tenant.datahub.example" and
  .urlBinding.allSameOrigin == true and
  .urlBinding.mcp.pathSource == "environment-configuration" and
  .validation == "passed"
' <<<"${datahub_private_link_preflight}" >/dev/null

if EXPECTED_ACCOUNT_ID="111111111111" \
  AWS_REGION="eu-west-1" \
  ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME="${datahub_service_name}" \
  DATAHUB_READ_GMS_URL="https://tenant.datahub.example/api/gms" \
  DATAHUB_READ_MCP_URL="https://generic.datahub.example/mcp" \
  DATAHUB_WRITE_GMS_URL="https://tenant.datahub.example/api/gms" \
  DATAHUB_WRITE_MCP_URL="https://tenant.datahub.example/write-mcp" \
    bash "${repository_root}/scripts/validate-datahub-private-link-service.sh" \
      >/dev/null 2>&1; then
  echo "::error::DataHub PrivateLink preflight accepted a cross-origin MCP URL" >&2
  exit 1
fi

network_contract="$(
  ARCHON_STACK_NAME="Archon-staging" \
  ARCHON_STACK_OUTPUTS="${stack_outputs}" \
  S3_PREFIX_LIST_ID="pl-s3" \
  DYNAMODB_PREFIX_LIST_ID="pl-dynamodb" \
  ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME="${datahub_service_name}" \
  AWS_REGION="eu-west-1" \
    bash "${repository_root}/scripts/validate-aws-network-contract.sh"
)"
jq --exit-status \
  '.schemaVersion == "archon.live-security-group-contract/v4" and
   .deploymentAccountId == "111111111111" and
   .vpc.cidr == "10.42.0.0/16" and
   .vpc.state == "available" and
   .vpc.isDefault == false and
   .vpc.ownerAccountId == "111111111111" and
   .vpc.defaultSecurityGroup.ingressRuleCount == 0 and
   .vpc.defaultSecurityGroup.egressRuleCount == 0 and
   (.securityGroupIdentityBindings | length) == 7 and
   all(.securityGroupIdentityBindings[];
     .vpcId == "vpc-66666666666666666" and
     .ownerAccountId == "111111111111") and
   .privateNetworkLoadBalancer.vpcId == "vpc-66666666666666666" and
   .privateNetworkLoadBalancer.state == "active" and
   .privateNetworkLoadBalancer.ipAddressType == "ipv4" and
   .privateNetworkLoadBalancer.privateLinkInboundRuleEvaluation == "off" and
   .datahub.endpoint.privateDnsEnabled == true and
   .datahub.endpoint.providerPrivateDnsName ==
     "tenant.datahub.example" and
   .datahub.endpoint.endpointPolicy == "unsupported-not-configured" and
   .datahub.authentication.read == "separate-secret" and
   .datahub.authentication.write == "separate-secret" and
   .datahub.authorization == "provider-rbac" and
   .bedrockMantle.endpoint.privateDnsEnabled == true and
   .bedrockMantle.endpoint.endpointPolicy == "least-privilege-verified" and
   .bedrockMantle.project.id == "proj_archonstaging001" and
   .bedrockMantle.project.validation == "cloud-control-live" and
   .bedrockMantle.model == "qwen.qwen3-235b-a22b-2507" and
   .bedrockMantle.authentication == "task-role-short-term-token" and
   .bedrockMantle.iamSimulation.remediation == "implicit-deny" and
   .validation == "passed"' \
  <<<"${network_contract}" >/dev/null

if FAKE_NETWORK_DRIFT=1 \
  ARCHON_STACK_NAME="Archon-staging" \
  ARCHON_STACK_OUTPUTS="${stack_outputs}" \
  S3_PREFIX_LIST_ID="pl-s3" \
  DYNAMODB_PREFIX_LIST_ID="pl-dynamodb" \
  ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME="${datahub_service_name}" \
  AWS_REGION="eu-west-1" \
    bash "${repository_root}/scripts/validate-aws-network-contract.sh" \
      >/dev/null 2>&1; then
  echo "::error::Network contract accepted an unexpected 0.0.0.0/0 rule" >&2
  exit 1
fi

if FAKE_DEFAULT_SG_DRIFT=1 \
  ARCHON_STACK_NAME="Archon-staging" \
  ARCHON_STACK_OUTPUTS="${stack_outputs}" \
  S3_PREFIX_LIST_ID="pl-s3" \
  DYNAMODB_PREFIX_LIST_ID="pl-dynamodb" \
  ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME="${datahub_service_name}" \
  AWS_REGION="eu-west-1" \
    bash "${repository_root}/scripts/validate-aws-network-contract.sh" \
      >/dev/null 2>&1; then
  echo "::error::Network contract accepted default security-group egress" >&2
  exit 1
fi

for drift_variable in \
  FAKE_VPC_CIDR_DRIFT \
  FAKE_SG_VPC_DRIFT \
  FAKE_SG_ACCOUNT_DRIFT \
  FAKE_NLB_VPC_DRIFT \
  FAKE_NLB_STATE_DRIFT \
  FAKE_NLB_IP_TYPE_DRIFT \
  FAKE_DATAHUB_ENDPOINT_DRIFT \
  FAKE_DATAHUB_SERVICE_DRIFT \
  FAKE_BEDROCK_ENDPOINT_DRIFT \
  FAKE_BEDROCK_PROJECT_DRIFT \
  FAKE_BEDROCK_IAM_DRIFT; do
  if env \
    "${drift_variable}=1" \
    ARCHON_STACK_NAME="Archon-staging" \
    ARCHON_STACK_OUTPUTS="${stack_outputs}" \
    S3_PREFIX_LIST_ID="pl-s3" \
    DYNAMODB_PREFIX_LIST_ID="pl-dynamodb" \
    ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME="${datahub_service_name}" \
    AWS_REGION="eu-west-1" \
      bash "${repository_root}/scripts/validate-aws-network-contract.sh" \
        >/dev/null 2>&1; then
    echo "::error::Network contract accepted ${drift_variable}" >&2
    exit 1
  fi
done

api_origin_contract="$(
  ARCHON_STACK_NAME="Archon-staging" \
  ARCHON_STACK_OUTPUTS="${stack_outputs}" \
  AWS_REGION="eu-west-1" \
    bash "${repository_root}/scripts/validate-aws-api-origin-contract.sh"
)"
jq --exit-status \
  '
    .schemaVersion == "archon.api-origin-contract/v1" and
    (.deployedTemplateSha256 | test("^[a-f0-9]{64}$")) and
    .apiGateway.stage == "staging" and
    .apiGateway.endpointType == "REGIONAL" and
    .apiGateway.apiKeySource == "HEADER" and
    (.apiGateway.methods | length) == 4 and
    all(
      .apiGateway.methods[];
      .apiKeyRequired == true and
      (
        .originCredentialIsolation == "static-redaction" or
        (
          .originCredentialIsolation == "narrow-request-template" and
          (.requestTemplateSha256 |
            test("^[a-f0-9]{64}$"))
        )
      )
    ) and
    (
      [.apiGateway.methods[] |
       select(.originCredentialIsolation == "static-redaction")] |
      length
    ) == 1 and
    (
      [.apiGateway.methods[] |
       select(
         .originCredentialIsolation == "narrow-request-template"
       )] |
      length
    ) == 3 and
    .originCredential.enabled == true and
    .originCredential.materialHandling == "not-retrieved" and
    .originCredential.usagePlan.association == "validated" and
    .cloudFront.apiBehavior.cachePolicy == "CachingDisabled" and
    .cloudFront.apiOrigin.credentialBinding ==
      "deployed-template-unresolved-dynamic-reference" and
    .cloudFront.apiOrigin.credentialMaterialHandling == "not-retrieved" and
    .cloudFront.apiOrigin.downstreamCredentialIsolation == "validated" and
    .cloudFront.originRequestPolicy.viewerHeaderExclusions == ["host"] and
    .probes.directOriginWithoutCredential.observedStatus == 403 and
    .probes.directOriginWithBogusCredential.observedStatus == 403 and
    .probes.cloudFrontViewerCredentialSpoof.observedStatus == 404 and
    .validation == "passed"
  ' <<<"${api_origin_contract}" >/dev/null
if grep -Fq 'archon-intentionally-invalid-origin-credential' \
  <<<"${api_origin_contract}"; then
  echo "::error::API-origin evidence contains the bogus probe credential" >&2
  exit 1
fi
for raw_identifier in \
  "abc123def4" \
  "key1234567890abcdef" \
  "plan123456" \
  "E123456789ABCD" \
  "11111111-2222-4333-8444-555555555555"; do
  if grep -Fq "${raw_identifier}" <<<"${api_origin_contract}"; then
    echo "::error::API-origin evidence contains a raw resource identifier" >&2
    exit 1
  fi
done

for drift_variable in \
  FAKE_API_KEY_SOURCE_DRIFT \
  FAKE_API_KEY_REQUIRED_DRIFT \
  FAKE_API_AUTHORIZATION_DRIFT \
  FAKE_API_SCRUB_DRIFT \
  FAKE_LAMBDA_TEMPLATE_DRIFT \
  FAKE_LAMBDA_PASSTHROUGH_DRIFT \
  FAKE_LAMBDA_RESPONSE_TEMPLATE_DRIFT \
  FAKE_LAMBDA_RESPONSE_HEADER_DRIFT \
  FAKE_LAMBDA_METHOD_STATUS_DRIFT \
  FAKE_API_KEY_ENABLED_DRIFT \
  FAKE_USAGE_PLAN_DRIFT \
  FAKE_USAGE_PLAN_ASSOCIATION_DRIFT \
  FAKE_CLOUDFRONT_CUSTOM_HEADER_DRIFT \
  FAKE_CLOUDFRONT_DUPLICATE_HEADER_DRIFT \
  FAKE_API_ORIGIN_DOMAIN_DRIFT \
  FAKE_DYNAMIC_REFERENCE_DRIFT \
  FAKE_ORIGIN_SECRET_NAME_DRIFT \
  FAKE_ORIGIN_SECRET_RETENTION_DRIFT \
  FAKE_ORIGIN_SECRET_GENERATOR_DRIFT \
  FAKE_ORIGIN_SECRET_KMS_DRIFT \
  FAKE_ORIGIN_SECRET_KMS_PURPOSE_DRIFT \
  FAKE_ORIGIN_SECRET_KMS_ROTATION_DRIFT \
  FAKE_ORIGIN_SECRET_DEPENDENCY_DRIFT \
  FAKE_ORIGIN_POLICY_BINDING_DRIFT \
  FAKE_ORIGIN_POLICY_DRIFT \
  FAKE_DIRECT_NO_KEY_DRIFT \
  FAKE_DIRECT_BOGUS_KEY_DRIFT \
  FAKE_CLOUDFRONT_SPOOF_DRIFT; do
  if env \
    "${drift_variable}=1" \
    ARCHON_STACK_NAME="Archon-staging" \
    ARCHON_STACK_OUTPUTS="${stack_outputs}" \
    AWS_REGION="eu-west-1" \
      bash "${repository_root}/scripts/validate-aws-api-origin-contract.sh" \
        >/dev/null 2>&1; then
    echo "::error::API-origin contract accepted ${drift_variable}" >&2
    exit 1
  fi
done

waf_association_log="${work_root}/waf-associations.log"
waf_contract="$(
  FAKE_WAF_ASSOCIATION_LOG="${waf_association_log}" \
  ARCHON_STACK_NAME="Archon-staging" \
  ARCHON_STACK_OUTPUTS="${stack_outputs}" \
  EXPECTED_ACCOUNT_ID="111111111111" \
  EXPECTED_RATE_LIMIT=300 \
  AWS_REGION="eu-west-1" \
    bash "${repository_root}/scripts/validate-aws-waf-contract.sh"
)"
jq --exit-status \
  '.webAcl.arn as $webAclArn |
   .schemaVersion == "archon.regional-waf-contract/v3" and
   (. | keys) ==
     ["associations", "cdkOutputsSha256", "logging", "schemaVersion",
      "stackName", "validation", "webAcl"] and
   (.associations | keys) == ["apiGatewayStage", "cognitoUserPool"] and
   (.associations.apiGatewayStage | keys) ==
     ["resourceArn", "resourceType", "validation", "webAclArn"] and
   .associations.apiGatewayStage.resourceArn ==
     "arn:aws:apigateway:eu-west-1::/restapis/abc123def4/stages/staging" and
   .associations.apiGatewayStage.resourceType == "AWS::ApiGateway::Stage" and
   .associations.apiGatewayStage.validation == "passed" and
   .associations.apiGatewayStage.webAclArn == $webAclArn and
   (.associations.cognitoUserPool | keys) ==
     ["resourceArn", "resourceId", "resourceType", "validation", "webAclArn"] and
   .associations.cognitoUserPool.resourceId == "eu-west-1_ArchonStaging" and
   .associations.cognitoUserPool.resourceArn ==
     "arn:aws:cognito-idp:eu-west-1:111111111111:userpool/eu-west-1_ArchonStaging" and
   .associations.cognitoUserPool.resourceType == "AWS::Cognito::UserPool" and
   .associations.cognitoUserPool.validation == "passed" and
   .associations.cognitoUserPool.webAclArn == $webAclArn and
   .webAcl.sampledDataProtection == "validated" and
   .webAcl.rateEvaluationWindowSeconds == 300 and
   .logging.kmsKey.rotationEnabled == true and
   .logging.filter == "BLOCK_OR_COUNT" and
   .logging.sensitiveFields == ["authorization", "cookie", "x-api-key"] and
   .validation == "passed"' \
  <<<"${waf_contract}" >/dev/null
mapfile -t waf_association_resources <"${waf_association_log}"
test "${#waf_association_resources[@]}" -eq 2
test "${waf_association_resources[0]}" = \
  "arn:aws:apigateway:eu-west-1::/restapis/abc123def4/stages/staging"
test "${waf_association_resources[1]}" = \
  "arn:aws:cognito-idp:eu-west-1:111111111111:userpool/eu-west-1_ArchonStaging"

for drift_variable in \
  FAKE_WAF_RULE_DRIFT \
  FAKE_WAF_MANAGED_VERSION_DRIFT \
  FAKE_WAF_MANAGED_CONFIG_DRIFT \
  FAKE_WAF_RATE_WINDOW_DRIFT \
  FAKE_WAF_LOGGING_DRIFT \
  FAKE_API_WAF_ASSOCIATION_DRIFT \
  FAKE_COGNITO_WAF_ASSOCIATION_DRIFT \
  FAKE_WAF_LOG_KMS_DRIFT \
  FAKE_WAF_LOG_RETENTION_DRIFT \
  FAKE_WAF_LOG_KEY_STATE_DRIFT \
  FAKE_WAF_LOG_KEY_ROTATION_DRIFT; do
  if env \
    "${drift_variable}=1" \
    ARCHON_STACK_NAME="Archon-staging" \
    ARCHON_STACK_OUTPUTS="${stack_outputs}" \
    EXPECTED_ACCOUNT_ID="111111111111" \
    EXPECTED_RATE_LIMIT=300 \
    AWS_REGION="eu-west-1" \
      bash "${repository_root}/scripts/validate-aws-waf-contract.sh" \
        >/dev/null 2>&1; then
    echo "::error::Regional WAF contract accepted ${drift_variable}" >&2
    exit 1
  fi
done

for output_mutation in missing-id missing-arn mismatched-arn; do
  mutated_outputs="${work_root}/stack-outputs-${output_mutation}.json"
  case "${output_mutation}" in
    missing-id)
      jq 'del(.["Archon-staging"].ArchonUserPoolId)' \
        "${stack_outputs}" >"${mutated_outputs}"
      ;;
    missing-arn)
      jq 'del(.["Archon-staging"].ArchonUserPoolArn)' \
        "${stack_outputs}" >"${mutated_outputs}"
      ;;
    mismatched-arn)
      jq \
        '.["Archon-staging"].ArchonUserPoolArn =
          "arn:aws:cognito-idp:eu-west-1:111111111111:userpool/eu-west-1_OtherPool"' \
        "${stack_outputs}" >"${mutated_outputs}"
      ;;
  esac
  if ARCHON_STACK_NAME="Archon-staging" \
    ARCHON_STACK_OUTPUTS="${mutated_outputs}" \
    EXPECTED_ACCOUNT_ID="111111111111" \
    EXPECTED_RATE_LIMIT=300 \
    AWS_REGION="eu-west-1" \
      bash "${repository_root}/scripts/validate-aws-waf-contract.sh" \
        >/dev/null 2>&1; then
    echo "::error::Regional WAF contract accepted ${output_mutation} Cognito outputs" >&2
    exit 1
  fi
done

test "$(
  grep -Fc 'bash scripts/validate-aws-waf-contract.sh' \
    "${repository_root}/.github/workflows/deploy.yml"
)" -eq 4
test "$(
  grep -Fc \
    '.schemaVersion == "archon.regional-waf-contract/v3"' \
    "${repository_root}/.github/workflows/deploy.yml"
)" -eq 2
test "$(
  grep -Fc '"AWS::Cognito::UserPool"' \
    "${repository_root}/.github/workflows/deploy.yml"
)" -eq 2
grep -Fq '`cognito-idp:GetWebACLForResource` on the exact' \
  "${repository_root}/infra/aws/README.md"

deploy_workflow="${repository_root}/.github/workflows/deploy.yml"
deployment_mode_contract="$(
  sed -n '/^      deployment_mode:/,/^      ci_run_id:/p' \
    "${deploy_workflow}" |
    sed '$d'
)"
expected_deployment_mode_contract="$(
  cat <<'EOF'
      deployment_mode:
        description: Promote through governed canary and production, or stop after a sealed staging bootstrap
        required: true
        default: promote
        type: choice
        options:
          - promote
          - staging-bootstrap
EOF
)"
test "${deployment_mode_contract}" = \
  "${expected_deployment_mode_contract}"

bootstrap_output_contract="$(
  sed -n '/^      bootstrap_artifact_id:/,/^    steps:/p' \
    "${deploy_workflow}" |
    sed '$d'
)"
expected_bootstrap_output_contract="$(
  cat <<'EOF'
      bootstrap_artifact_id: ${{ steps.bootstrap_upload.outputs['artifact-id'] }}
      bootstrap_artifact_digest: >-
        ${{ steps.bootstrap_upload.outputs['artifact-digest'] &&
            format('sha256:{0}', steps.bootstrap_upload.outputs['artifact-digest']) ||
            '' }}
EOF
)"
test "${bootstrap_output_contract}" = \
  "${expected_bootstrap_output_contract}"

staging_job_header="$(
  sed -n '/^  staging:/,/^    steps:/p' "${deploy_workflow}"
)"
if grep -Eq '^    if:' <<<"${staging_job_header}"; then
  echo "::error::staging must run in both deployment modes" >&2
  exit 1
fi
preproduction_job_header="$(
  sed -n '/^  preproduction_canary:/,/^    runs-on:/p' \
    "${deploy_workflow}"
)"
production_job_header="$(
  sed -n '/^  production:/,/^    runs-on:/p' "${deploy_workflow}"
)"
for required_boundary in \
  "inputs.deployment_mode == 'promote'" \
  "needs.staging.result == 'success'"; do
  grep -Fq "${required_boundary}" <<<"${preproduction_job_header}"
  grep -Fq "${required_boundary}" <<<"${production_job_header}"
done
grep -Fq "needs.preproduction_canary.result == 'success'" \
  <<<"${production_job_header}"
test "$(
  grep -Fc "inputs.deployment_mode == 'promote'" \
    "${deploy_workflow}"
)" -eq 2
test "$(
  grep -Fc 'test "${DEPLOYMENT_MODE}" = "promote"' \
    "${deploy_workflow}"
)" -eq 2
grep -Fq 'promote|staging-bootstrap) ;;' "${deploy_workflow}"

test "$(
  grep -Fc './node_modules/.bin/cdk deploy Archon-Registry' \
    "${deploy_workflow}"
)" -eq 1
production_deployment_contract="$(
  sed -n '/^  production:/,$p' "${deploy_workflow}"
)"
if grep -Fq './node_modules/.bin/cdk deploy Archon-Registry' \
  <<<"${production_deployment_contract}"; then
  echo "::error::production must not mutate the staging-owned shared registry stack" >&2
  exit 1
fi
for forbidden_production_registry_mutation in \
  'docker push' \
  'aws ecr batch-delete-image' \
  'aws ecr get-login-password'; do
  if grep -Fq "${forbidden_production_registry_mutation}" \
    <<<"${production_deployment_contract}"; then
    echo "::error::production retained forbidden shared-registry mutation" >&2
    exit 1
  fi
done
for registry_read_contract in \
  'Staging is the sole infrastructure owner of the shared immutable' \
  'aws cloudformation describe-stacks' \
  '--stack-name Archon-Registry' \
  'select(.OutputKey == "ArchonEcrRepositoryUri")' \
  'select(.OutputKey == "ArchonEcrRepositoryName")' \
  'test "${image_digest}" = "${STAGING_IMAGE_DIGEST}"'; do
  grep -Fq "${registry_read_contract}" <<<"${production_deployment_contract}"
done

cdk_app="${repository_root}/infra/aws/bin/archon.ts"
for isolated_bootstrap_contract in \
  'stage !== "staging" && stage !== "production"' \
  'stage === "production" ? "archonprd" : "archonstg"' \
  'new DefaultStackSynthesizer({ qualifier: bootstrapQualifier })'; do
  grep -Fq "${isolated_bootstrap_contract}" "${cdk_app}"
done
for deployed_bootstrap_contract in \
  'CDKToolkit-archonstg' \
  '/cdk-bootstrap/archonstg/version' \
  'CDKToolkit-archonprd' \
  '/cdk-bootstrap/archonprd/version' \
  'if [[ "${version}" != "32" ]]'; do
  grep -Fq "${deployed_bootstrap_contract}" "${deploy_workflow}"
done
if grep -Eq 'CDKToolkit([^a-zA-Z0-9-]|$)|/cdk-bootstrap/hnb659fds/version' \
  "${deploy_workflow}"; then
  echo "::error::deployment workflow retained the shared default CDK bootstrap" >&2
  exit 1
fi
runtime_stack="${repository_root}/infra/aws/lib/archon-stack.ts"
grep -Fq 'iam.PermissionsBoundary.of(this).apply(runtimeBoundary)' \
  "${runtime_stack}"
grep -Fq \
  'policy/archon-datahub-runtime-boundary-${stage}' \
  "${runtime_stack}"
grep -Fq \
  'bucketName: `archon-${stage}-spa-${Aws.ACCOUNT_ID}-${Aws.REGION}`' \
  "${runtime_stack}"
for exact_spa_bucket in \
  'archon-staging-spa-${EXPECTED_ACCOUNT_ID}-eu-west-1' \
  'archon-production-spa-${EXPECTED_ACCOUNT_ID}-eu-west-1'; do
  grep -Fq "${exact_spa_bucket}" "${deploy_workflow}"
done
grep -Fq 'cloudWatchRole: false' "${runtime_stack}"
if grep -Fq 'cloudWatchRole: true' "${runtime_stack}"; then
  echo "::error::a stage stack must not own the account-wide API Gateway logging role" >&2
  exit 1
fi
grep -Fq 'rule iam_roles_require_a_permissions_boundary' \
  "${repository_root}/infra/aws/policy/archon.guard"
grep -Fq 'rule ecs_tasks_do_not_override_aws_task_role_credentials' \
  "${repository_root}/infra/aws/policy/archon.guard"
for forbidden_hosted_aws_credential in \
  'AWS_ACCESS_KEY_ID' \
  'AWS_PROFILE' \
  'AWS_WEB_IDENTITY_TOKEN_FILE' \
  'AWS_CONTAINER_CREDENTIALS_FULL_URI' \
  'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE'; do
  grep -Fq "${forbidden_hosted_aws_credential}" \
    "${repository_root}/infra/aws/policy/archon.guard"
  grep -Fq "${forbidden_hosted_aws_credential}" \
    "${repository_root}/src/llm/client.ts"
done
grep -Fq 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' \
  "${repository_root}/src/llm/client.ts"
for forbidden_hosted_llm_credential in \
  'LLM_API_KEY' \
  'AWS_BEARER_TOKEN_BEDROCK' \
  'DASHSCOPE_API_KEY' \
  'GEMINI_API_KEY' \
  'OPENAI_API_KEY' \
  'ANTHROPIC_API_KEY'; do
  grep -Fq "${forbidden_hosted_llm_credential}" \
    "${repository_root}/infra/aws/policy/archon.guard"
  grep -Fq "${forbidden_hosted_llm_credential}" \
    "${repository_root}/src/remediation-worker.ts"
done
for mirrored_provenance_consumer in \
  src/llm/provenance.ts \
  src/reporting/public-audit-report.ts \
  src/mcp/server.ts \
  infra/aws/lambda/control/index.js \
  scripts/validate-audit-report.jq \
  web/src/api.ts \
  web/src/evidence-pack.ts; do
  grep -Fq 'bedrock-api-key-' \
    "${repository_root}/${mirrored_provenance_consumer}"
done
for mirrored_provider_consumer in \
  src/llm/provenance.ts \
  infra/aws/lambda/control/index.js \
  scripts/validate-audit-report.jq \
  web/src/types.ts \
  web/src/api.ts \
  web/src/evidence-pack.ts; do
  grep -Fq '"bedrock-mantle"' \
    "${repository_root}/${mirrored_provider_consumer}"
done
grep -Fq '"bedrock": [' \
  "${repository_root}/contracts/model-provenance-v1.cases.json"
grep -Fq 'const direct = (error as { status?: unknown }).status' \
  "${repository_root}/src/worker/aws-adapters.ts"
grep -Fq 'readonly retryable = true' \
  "${repository_root}/src/llm/client.ts"
runtime_boundary_validator="$(
  cat "${repository_root}/scripts/validate-aws-runtime-boundaries.sh"
)"
cloudformation_role_binding_validator="$(
  cat "${repository_root}/scripts/validate-cloudformation-role-bindings.sh"
)"
for cloudformation_role_binding_contract in \
  'Archon-Registry|eu-west-1|archonstg' \
  'Archon-staging-Edge|us-east-1|archonstg' \
  'Archon-staging|eu-west-1|archonstg' \
  'Archon-production-Edge|us-east-1|archonprd' \
  'Archon-production|eu-west-1|archonprd' \
  'cdk-${qualifier}-cfn-exec-role-${EXPECTED_ACCOUNT_ID}-${region}' \
  '.Stacks[0].RoleARN == $role' \
  'schemaVersion: "archon.cloudformation-role-bindings/v1"' \
  'ALLOW_ROLE_MIGRATION="${ALLOW_ROLE_MIGRATION:-false}"' \
  'state: "migration-required"' \
  'state: "present-and-exact"'; do
  grep -Fq -- "${cloudformation_role_binding_contract}" \
    <<<"${cloudformation_role_binding_validator}"
done
for runtime_boundary_contract in \
  'Archon-Staging-IAM-Foundation' \
  'Archon-Production-IAM-Foundation' \
  'aws cloudformation detect-stack-drift' \
  'aws cloudformation describe-stack-drift-detection-status' \
  'test "${drift_status}" = "IN_SYNC"' \
  'aws cloudformation get-template' \
  '--template-stage Processed' \
  'aws cloudformation list-stack-resources' \
  'select(.value.Type == "AWS::IAM::Role")' \
  'aws iam get-role' \
  '.Role.PermissionsBoundary.PermissionsBoundaryArn == $arn' \
  '.Key == "Application" and .Value == "archon-datahub"' \
  '.Key == "Environment" and .Value == $stage' \
  'driftStatus: $iamFoundationDriftStatus' \
  'schemaVersion: "archon.aws-runtime-boundaries/v1"'; do
  grep -Fq -- "${runtime_boundary_contract}" <<<"${runtime_boundary_validator}"
done
test "$(
  grep -Fc 'bash scripts/validate-aws-runtime-boundaries.sh' \
    "${deploy_workflow}"
)" -eq 2
test "$(
  grep -Fc 'bash scripts/validate-cloudformation-role-bindings.sh' \
    "${deploy_workflow}"
)" -eq 4
test "$(
  grep -Fc 'ALLOW_ABSENT: "true"' "${deploy_workflow}"
)" -eq 2
test "$(
  grep -Fc 'ALLOW_ABSENT=false' "${deploy_workflow}"
)" -eq 2
test "$(
  grep -Fc 'migrate_legacy_cloudformation_roles:' "${deploy_workflow}"
)" -eq 1
test "$(
  grep -Fc 'ALLOW_ROLE_MIGRATION: ${{ inputs.migrate_legacy_cloudformation_roles }}' \
    "${deploy_workflow}"
)" -eq 2
test "$(
  grep -Fc 'ALLOW_ROLE_MIGRATION=false' "${deploy_workflow}"
)" -eq 2
test "$(
  grep -Fc 'cloudFormationRoleBindings: $roleBindings' \
    "${deploy_workflow}"
)" -eq 2
test "$(
  grep -Fc 'DataHub credentials before AWS trust' "${deploy_workflow}"
)" -eq 2
test "$(
  grep -Fc 'DataHub read and write tokens must be distinct before AWS mutation' \
    "${deploy_workflow}"
)" -eq 2
test "$(
  grep -Fc '[[ "${token}" =~ ^[A-Za-z0-9._~+/=-]+$ ]]' \
    "${deploy_workflow}"
)" -eq 2
staging_token_preflight_line="$(
  grep -nF 'Fail closed on staging DataHub credentials before AWS trust' \
    "${deploy_workflow}" | cut -d: -f1
)"
staging_aws_trust_line="$(
  grep -nF 'Configure staging AWS credentials through OIDC' \
    "${deploy_workflow}" | cut -d: -f1
)"
production_token_preflight_line="$(
  grep -nF 'Fail closed on production DataHub credentials before AWS trust' \
    "${deploy_workflow}" | cut -d: -f1
)"
production_aws_trust_line="$(
  grep -nF 'Configure production AWS credentials through OIDC' \
    "${deploy_workflow}" | cut -d: -f1
)"
test "${staging_token_preflight_line}" -lt "${staging_aws_trust_line}"
test "${production_token_preflight_line}" -lt "${production_aws_trust_line}"
for deployed_runtime_boundary_contract in \
  'EXPECTED_STAGE=staging' \
  'EXPECTED_STAGE=production' \
  'runtime_boundary_contract_sha=${runtime_boundary_contract_sha}' \
  'runtime-boundary-security-contract.json' \
  'production-runtime-boundary-security-contract.json' \
  'runtimeBoundaryContractSha256' \
  'runtimeBoundary: $runtimeBoundary' \
  'runtimeBoundary: $productionRuntimeBoundary'; do
  grep -Fq -- "${deployed_runtime_boundary_contract}" "${deploy_workflow}"
done
for assembly_inventory_contract in \
  'staging) expected_template_count=3' \
  'production) expected_template_count=2' \
  'test "${#templates[@]}" -eq "${expected_template_count}"'; do
  grep -Fq "${assembly_inventory_contract}" \
    "${repository_root}/.github/workflows/ci.yml"
done

bootstrap_contract="$(
  sed -n \
    '/- name: Prepare sealed staging bootstrap handoff/,/^  preproduction_canary:/p' \
    "${deploy_workflow}" |
    sed '$d'
)"
test "$(
  grep -Fc "if: inputs.deployment_mode == 'staging-bootstrap'" \
    <<<"${bootstrap_contract}"
)" -eq 4
if grep -Fq '${{ secrets.' <<<"${bootstrap_contract}"; then
  echo "::error::staging bootstrap handoff must remain secretless" >&2
  exit 1
fi
for required_bootstrap_contract in \
  'test "${DEPLOYMENT_MODE}" = "staging-bootstrap"' \
  'STAGING_EVIDENCE_ARTIFACT_DIGEST: "sha256:${{ steps.staging_artifact.outputs['"'"'artifact-digest'"'"'] }}"' \
  'ArchonEvidenceBucketName' \
  'ArchonUserPoolClientId' \
  'ArchonCognitoHostedUiOrigin' \
  'CANARY_APPLICATION_URL' \
  'CANARY_CHROME_BINARY_SHA256' \
  'CANARY_CHROME_VERSION' \
  'CANARY_EVIDENCE_BUCKET' \
  'CANARY_COGNITO_CLIENT_ID' \
  'CANARY_COGNITO_HOSTED_UI_ORIGIN' \
  'canary_chrome_version="$("${chrome_bin}" --product-version)"' \
  'sha256sum "${chrome_payload}"' \
  '.schemaVersion == "archon.staging-bootstrap/v1"' \
  '"archon.staging-bootstrap-predicate/v1"' \
  '(.deployment | keys | sort) == [' \
  '.deployment == {' \
  '(.canaryConfiguration | keys | sort) == [' \
  'paths(scalars)' \
  '(secret|token|password|credential|api[_-]?key)' \
  'manifestSha256' \
  'expected_inventory=' \
  'staging-bootstrap-manifest.json' \
  'attestation-predicate.json' \
  'sha256sum --check --strict SHA256SUMS' \
  'subject-checksums: ${{ steps.bootstrap.outputs.path }}/SHA256SUMS' \
  'predicate-type: https://github.com/upgradedev/archon-datahub/attestations/staging-bootstrap/v1' \
  'predicate-path: ${{ steps.bootstrap.outputs.path }}/attestation-predicate.json' \
  'name: Reverify sealed staging bootstrap handoff before upload' \
  'EXPECTED_MANIFEST_SHA256: ${{ steps.bootstrap.outputs.manifest_sha256 }}' \
  'name: staging-bootstrap-${{ inputs.release_sha }}-${{ github.run_id }}-${{ github.run_attempt }}' \
  'retention-days: 90'; do
  grep -Fq "${required_bootstrap_contract}" \
    <<<"${bootstrap_contract}"
done
test "$(
  grep -Fc \
    'uses: actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26 # v4.1.0' \
    <<<"${bootstrap_contract}"
)" -eq 1
test "$(
  grep -Fc \
    'uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1' \
    <<<"${bootstrap_contract}"
)" -eq 1
test "$(
  grep -Fc \
    'find . -mindepth 1 -maxdepth 1 ! -type f -print -quit' \
    <<<"${bootstrap_contract}"
)" -eq 2
for forbidden_bootstrap_binding in \
  'DATAHUB_READ_GMS_TOKEN' \
  'DATAHUB_WRITE_GMS_TOKEN' \
  'LLM_API_KEY' \
  'CANARY_COGNITO_PASSWORD' \
  'CANARY_DATAHUB_READ_TOKEN' \
  'CANARY_DATAHUB_WRITE_TOKEN'; do
  if grep -Fq "${forbidden_bootstrap_binding}" \
    <<<"${bootstrap_contract}"; then
    echo "::error::staging bootstrap retained forbidden secret binding ${forbidden_bootstrap_binding}" >&2
    exit 1
  fi
done

clear_credentials_line="$(
  grep -n -m1 'name: Clear staging credentials before artifact handling' \
    "${deploy_workflow}" |
    cut -d: -f1
)"
prepare_bootstrap_line="$(
  grep -n -m1 'name: Prepare sealed staging bootstrap handoff' \
    "${deploy_workflow}" |
    cut -d: -f1
)"
attest_bootstrap_line="$(
  grep -n -m1 'name: Attest sealed staging bootstrap handoff' \
    "${deploy_workflow}" |
    cut -d: -f1
)"
reverify_bootstrap_line="$(
  grep -n -m1 \
    'name: Reverify sealed staging bootstrap handoff before upload' \
    "${deploy_workflow}" |
    cut -d: -f1
)"
upload_bootstrap_line="$(
  grep -n -m1 'name: Upload sealed staging bootstrap handoff' \
    "${deploy_workflow}" |
    cut -d: -f1
)"
preproduction_line="$(
  grep -n -m1 '^  preproduction_canary:' "${deploy_workflow}" |
    cut -d: -f1
)"
(( clear_credentials_line < prepare_bootstrap_line ))
(( prepare_bootstrap_line < attest_bootstrap_line ))
(( attest_bootstrap_line < reverify_bootstrap_line ))
(( reverify_bootstrap_line < upload_bootstrap_line ))
(( upload_bootstrap_line < preproduction_line ))
