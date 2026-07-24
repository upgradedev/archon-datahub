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
    "ArchonRegionalWebAclArn": "arn:aws:wafv2:eu-west-1:111111111111:regional/webacl/archon-staging-api/12345678-1234-0123-0123-1234567890ab",
    "ArchonRegionalWafLogGroupName": "aws-waf-logs-archon-staging-api",
    "ArchonRegionalWafLogKeyArn": "arn:aws:kms:eu-west-1:111111111111:key/87654321-4321-0321-1321-ba0987654321",
    "ArchonApiStageArn": "arn:aws:apigateway:eu-west-1::/restapis/abc123def4/stages/staging",
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
vpc_id="vpc-66666666666666666"
web_acl_arn="arn:aws:wafv2:eu-west-1:111111111111:regional/webacl/archon-staging-api/12345678-1234-0123-0123-1234567890ab"
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
      "OriginSecretLogical":{
        "Type":"AWS::SecretsManager::Secret"
      },
      "ApiKeyLogical":{
        "Type":"AWS::ApiGateway::ApiKey",
        "Properties":{
          "Enabled":true,
          "Value":{
            "Fn::Join":[
              "",
              [
                "{{resolve:secretsmanager:",
                {"Ref":"OriginSecretLogical"},
                ":SecretString:apiKey::}}"
              ]
            ]
          }
        }
      },
      "OriginPolicyLogical":{
        "Type":"AWS::CloudFront::OriginRequestPolicy"
      },
      "DistributionLogical":{
        "Type":"AWS::CloudFront::Distribution",
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
                "HeaderValue":{
                  "Fn::Join":[
                    "",
                    [
                      "{{resolve:secretsmanager:",
                      {"Ref":"OriginSecretLogical"},
                      ":SecretString:apiKey::}}"
                    ]
                  ]
                }
              }],
              "CustomOriginConfig":{
                "HTTPPort":80,
                "HTTPSPort":443,
                "OriginProtocolPolicy":"https-only",
                "OriginSSLProtocols":["TLSv1.2"]
              }
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
    if [[ "${FAKE_DYNAMIC_REFERENCE_DRIFT:-0}" == "1" ]]; then
      response="$(
        jq \
          '.TemplateBody.Resources.ApiKeyLogical.Properties.Value =
            "plaintext-is-forbidden"' \
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
    {"GroupId":"${api_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-s3"},
    {"GroupId":"${api_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-read"},
    {"GroupId":"${api_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-llm"}
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
  {"GroupId":"${audit_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-s3"},
  {"GroupId":"${audit_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-dynamodb"},
  {"GroupId":"${audit_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-read"},
  {"GroupId":"${audit_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-llm"}
]}
JSON
        ;;
      "${remediation_group}")
        cat <<JSON
{"SecurityGroupRules":[
  {"GroupId":"${remediation_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"ReferencedGroupInfo":{"GroupId":"${endpoint_group}"}},
  {"GroupId":"${remediation_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-s3"},
  {"GroupId":"${remediation_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-dynamodb"},
  {"GroupId":"${remediation_group}","IsEgress":true,"IpProtocol":"tcp","FromPort":443,"ToPort":443,"PrefixListId":"pl-write"}
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
  {"GroupId":"${endpoint_group}","GroupName":"archon-endpoints","OwnerId":"111111111111","VpcId":"${vpc_id}","IpPermissions":[],"IpPermissionsEgress":[]}
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
    associated_web_acl_arn="${web_acl_arn}"
    if [[ "${FAKE_WAF_ASSOCIATION_DRIFT:-0}" == "1" ]]; then
      associated_web_acl_arn="arn:aws:wafv2:eu-west-1:111111111111:regional/webacl/unassociated/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
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

network_contract="$(
  ARCHON_STACK_NAME="Archon-staging" \
  ARCHON_STACK_OUTPUTS="${stack_outputs}" \
  S3_PREFIX_LIST_ID="pl-s3" \
  DYNAMODB_PREFIX_LIST_ID="pl-dynamodb" \
  ARCHON_DATAHUB_READ_EGRESS_PREFIX_LIST_ID="pl-read" \
  ARCHON_DATAHUB_WRITE_EGRESS_PREFIX_LIST_ID="pl-write" \
  ARCHON_LLM_EGRESS_PREFIX_LIST_ID="pl-llm" \
    bash "${repository_root}/scripts/validate-aws-network-contract.sh"
)"
jq --exit-status \
  '.schemaVersion == "archon.live-security-group-contract/v2" and
   .deploymentAccountId == "111111111111" and
   .vpc.cidr == "10.42.0.0/16" and
   .vpc.state == "available" and
   .vpc.isDefault == false and
   .vpc.ownerAccountId == "111111111111" and
   .vpc.defaultSecurityGroup.ingressRuleCount == 0 and
   .vpc.defaultSecurityGroup.egressRuleCount == 0 and
   (.securityGroupIdentityBindings | length) == 5 and
   all(.securityGroupIdentityBindings[];
     .vpcId == "vpc-66666666666666666" and
     .ownerAccountId == "111111111111") and
   .privateNetworkLoadBalancer.vpcId == "vpc-66666666666666666" and
   .privateNetworkLoadBalancer.state == "active" and
   .privateNetworkLoadBalancer.ipAddressType == "ipv4" and
   .privateNetworkLoadBalancer.privateLinkInboundRuleEvaluation == "off" and
   .validation == "passed"' \
  <<<"${network_contract}" >/dev/null

if FAKE_NETWORK_DRIFT=1 \
  ARCHON_STACK_NAME="Archon-staging" \
  ARCHON_STACK_OUTPUTS="${stack_outputs}" \
  S3_PREFIX_LIST_ID="pl-s3" \
  DYNAMODB_PREFIX_LIST_ID="pl-dynamodb" \
  ARCHON_DATAHUB_READ_EGRESS_PREFIX_LIST_ID="pl-read" \
  ARCHON_DATAHUB_WRITE_EGRESS_PREFIX_LIST_ID="pl-write" \
  ARCHON_LLM_EGRESS_PREFIX_LIST_ID="pl-llm" \
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
  ARCHON_DATAHUB_READ_EGRESS_PREFIX_LIST_ID="pl-read" \
  ARCHON_DATAHUB_WRITE_EGRESS_PREFIX_LIST_ID="pl-write" \
  ARCHON_LLM_EGRESS_PREFIX_LIST_ID="pl-llm" \
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
  FAKE_NLB_IP_TYPE_DRIFT; do
  if env \
    "${drift_variable}=1" \
    ARCHON_STACK_NAME="Archon-staging" \
    ARCHON_STACK_OUTPUTS="${stack_outputs}" \
    S3_PREFIX_LIST_ID="pl-s3" \
    DYNAMODB_PREFIX_LIST_ID="pl-dynamodb" \
    ARCHON_DATAHUB_READ_EGRESS_PREFIX_LIST_ID="pl-read" \
    ARCHON_DATAHUB_WRITE_EGRESS_PREFIX_LIST_ID="pl-write" \
    ARCHON_LLM_EGRESS_PREFIX_LIST_ID="pl-llm" \
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
  FAKE_DYNAMIC_REFERENCE_DRIFT \
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

waf_contract="$(
  ARCHON_STACK_NAME="Archon-staging" \
  ARCHON_STACK_OUTPUTS="${stack_outputs}" \
  EXPECTED_ACCOUNT_ID="111111111111" \
  EXPECTED_RATE_LIMIT=300 \
  AWS_REGION="eu-west-1" \
    bash "${repository_root}/scripts/validate-aws-waf-contract.sh"
)"
jq --exit-status \
  '.schemaVersion == "archon.regional-waf-contract/v2" and
   .webAcl.sampledDataProtection == "validated" and
   .webAcl.rateEvaluationWindowSeconds == 300 and
   .logging.kmsKey.rotationEnabled == true and
   .logging.filter == "BLOCK_OR_COUNT" and
   .logging.sensitiveFields == ["authorization", "cookie", "x-api-key"] and
   .validation == "passed"' \
  <<<"${waf_contract}" >/dev/null

for drift_variable in \
  FAKE_WAF_RULE_DRIFT \
  FAKE_WAF_MANAGED_VERSION_DRIFT \
  FAKE_WAF_MANAGED_CONFIG_DRIFT \
  FAKE_WAF_RATE_WINDOW_DRIFT \
  FAKE_WAF_LOGGING_DRIFT \
  FAKE_WAF_ASSOCIATION_DRIFT \
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
