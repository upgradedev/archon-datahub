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
    "ArchonApiStageArn": "arn:aws:apigateway:eu-west-1::/restapis/abc123def4/stages/staging"
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

case "${1:-}:${2:-}" in
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
    {"Action":"SUBSTITUTION","ExcludeRateBasedDetails":false,"ExcludeRuleMatchDetails":false,"Field":{"FieldType":"SINGLE_HEADER","FieldKeys":["cookie"]}}
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
  "RedactedFields":[{"SingleHeader":{"Name":"authorization"}},{"SingleHeader":{"Name":"cookie"}}]
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
