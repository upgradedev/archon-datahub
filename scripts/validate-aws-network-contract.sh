#!/usr/bin/env bash
set -euo pipefail

: "${ARCHON_STACK_NAME:?ARCHON_STACK_NAME is required}"
: "${ARCHON_STACK_OUTPUTS:?ARCHON_STACK_OUTPUTS is required}"
: "${S3_PREFIX_LIST_ID:?S3_PREFIX_LIST_ID is required}"
: "${DYNAMODB_PREFIX_LIST_ID:?DYNAMODB_PREFIX_LIST_ID is required}"
: "${ARCHON_DATAHUB_READ_EGRESS_PREFIX_LIST_ID:?ARCHON_DATAHUB_READ_EGRESS_PREFIX_LIST_ID is required}"
: "${ARCHON_DATAHUB_WRITE_EGRESS_PREFIX_LIST_ID:?ARCHON_DATAHUB_WRITE_EGRESS_PREFIX_LIST_ID is required}"
: "${ARCHON_LLM_EGRESS_PREFIX_LIST_ID:?ARCHON_LLM_EGRESS_PREFIX_LIST_ID is required}"

test -f "${ARCHON_STACK_OUTPUTS}"

stack_output() {
  local output_name="$1"
  jq -er \
    --arg stack "${ARCHON_STACK_NAME}" \
    --arg output "${output_name}" \
    '.[$stack][$output]' \
    "${ARCHON_STACK_OUTPUTS}"
}

api_security_group_id="$(stack_output ArchonApiSecurityGroupId)"
nlb_security_group_id="$(stack_output ArchonNlbSecurityGroupId)"
nlb_arn="$(stack_output ArchonPrivateNlbArn)"
vpc_id="$(stack_output ArchonVpcId)"
audit_security_group_id="$(stack_output ArchonAuditWorkerSecurityGroupId)"
remediation_security_group_id="$(
  stack_output ArchonRemediationWorkerSecurityGroupId
)"
endpoint_security_group_id="$(stack_output ArchonVpcEndpointSecurityGroupId)"

for security_group_id in \
  "${api_security_group_id}" \
  "${nlb_security_group_id}" \
  "${audit_security_group_id}" \
  "${remediation_security_group_id}" \
  "${endpoint_security_group_id}"; do
  [[ "${security_group_id}" =~ ^sg-([0-9a-f]{8}|[0-9a-f]{17})$ ]] || {
    echo "::error::CloudFormation returned an invalid security-group ID" >&2
    exit 1
  }
done
[[ "${nlb_arn}" =~ ^arn:aws:elasticloadbalancing:[a-z0-9-]+:([0-9]{12}):loadbalancer/net/[A-Za-z0-9-]+/[0-9a-f]{16}$ ]] || {
  echo "::error::CloudFormation returned an invalid private NLB ARN" >&2
  exit 1
}
deployment_account_id="${BASH_REMATCH[1]}"
[[ "${vpc_id}" =~ ^vpc-([0-9a-f]{8}|[0-9a-f]{17})$ ]] || {
  echo "::error::CloudFormation returned an invalid VPC ID" >&2
  exit 1
}

expected_vpc_cidr="10.42.0.0/16"
vpc_json="$(
  aws ec2 describe-vpcs \
    --vpc-ids "${vpc_id}" \
    --output json
)"
vpc_identity_json="$(
  jq --compact-output --exit-status \
    --arg vpc "${vpc_id}" \
    --arg cidr "${expected_vpc_cidr}" \
    --arg owner "${deployment_account_id}" \
    '
      if (
        (.Vpcs | length) == 1 and
        .Vpcs[0].VpcId == $vpc and
        .Vpcs[0].CidrBlock == $cidr and
        .Vpcs[0].State == "available" and
        .Vpcs[0].IsDefault == false and
        .Vpcs[0].OwnerId == $owner
      ) then
        {
          id: .Vpcs[0].VpcId,
          cidr: .Vpcs[0].CidrBlock,
          state: .Vpcs[0].State,
          isDefault: .Vpcs[0].IsDefault,
          ownerAccountId: .Vpcs[0].OwnerId
        }
      else
        error("VPC identity, address space, or lifecycle state is invalid")
      end
    ' <<<"${vpc_json}"
)" || {
  echo "::error::Deployed VPC does not match the exact live network contract" >&2
  exit 1
}

security_groups_json="$(
  aws ec2 describe-security-groups \
    --group-ids \
      "${api_security_group_id}" \
      "${nlb_security_group_id}" \
      "${audit_security_group_id}" \
      "${remediation_security_group_id}" \
      "${endpoint_security_group_id}" \
    --output json
)"
security_group_bindings_json="$(
  jq --compact-output --exit-status \
    --arg vpc "${vpc_id}" \
    --arg owner "${deployment_account_id}" \
    --arg api "${api_security_group_id}" \
    --arg nlb "${nlb_security_group_id}" \
    --arg audit "${audit_security_group_id}" \
    --arg remediation "${remediation_security_group_id}" \
    --arg endpoint "${endpoint_security_group_id}" \
    '
      if (
        (.SecurityGroups | length) == 5 and
        ([.SecurityGroups[].GroupId] | unique | length) == 5 and
        ([.SecurityGroups[].GroupId] | sort) ==
          ([$api, $nlb, $audit, $remediation, $endpoint] | sort) and
        all(
          .SecurityGroups[];
          .VpcId == $vpc and
          .OwnerId == $owner
        )
      ) then
        [
          .SecurityGroups[] |
          {
            id: .GroupId,
            ownerAccountId: .OwnerId,
            vpcId: .VpcId
          }
        ] |
        sort_by(.id)
      else
        error("Security-group VPC or account binding is invalid")
      end
    ' <<<"${security_groups_json}"
)" || {
  echo "::error::Workload security groups are not uniquely bound to the deployment account and VPC" >&2
  exit 1
}

rules_json="$(
  for security_group_id in \
    "${api_security_group_id}" \
    "${nlb_security_group_id}" \
    "${audit_security_group_id}" \
    "${remediation_security_group_id}" \
    "${endpoint_security_group_id}"; do
    aws ec2 describe-security-group-rules \
      --filters "Name=group-id,Values=${security_group_id}" \
      --output json
  done |
    jq --compact-output --sort-keys --slurp \
      '{SecurityGroupRules: [.[].SecurityGroupRules[]]}'
)"
load_balancer_json="$(
  aws elbv2 describe-load-balancers \
    --load-balancer-arns "${nlb_arn}" \
    --output json
)"
jq --exit-status \
  --arg arn "${nlb_arn}" \
  --arg securityGroup "${nlb_security_group_id}" \
  --arg vpc "${vpc_id}" \
  '
    (.LoadBalancers | length) == 1 and
    .LoadBalancers[0].LoadBalancerArn == $arn and
    .LoadBalancers[0].VpcId == $vpc and
    .LoadBalancers[0].State.Code == "active" and
    .LoadBalancers[0].Scheme == "internal" and
    .LoadBalancers[0].Type == "network" and
    .LoadBalancers[0].IpAddressType == "ipv4" and
    .LoadBalancers[0].SecurityGroups == [$securityGroup] and
    .LoadBalancers[0].EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic ==
      "off"
  ' <<<"${load_balancer_json}" >/dev/null || {
  echo "::error::Private NLB identity or PrivateLink enforcement contract is invalid" >&2
  exit 1
}
default_security_group_json="$(
  aws ec2 describe-security-groups \
    --filters \
      "Name=vpc-id,Values=${vpc_id}" \
      "Name=group-name,Values=default" \
    --output json
)"
default_security_group_id="$(
  jq --exit-status --raw-output \
    --arg vpc "${vpc_id}" \
    --arg owner "${deployment_account_id}" \
    '
      if (
        (.SecurityGroups | length) == 1 and
        .SecurityGroups[0].VpcId == $vpc and
        .SecurityGroups[0].OwnerId == $owner and
        .SecurityGroups[0].GroupName == "default" and
        (.SecurityGroups[0].IpPermissions | length) == 0 and
        (.SecurityGroups[0].IpPermissionsEgress | length) == 0
      ) then
        .SecurityGroups[0].GroupId
      else
        error("Default security group is not uniquely empty")
      end
    ' <<<"${default_security_group_json}"
)" || {
  echo "::error::Deployed VPC default security group contains live rules" >&2
  exit 1
}
[[ "${default_security_group_id}" =~ ^sg-([0-9a-f]{8}|[0-9a-f]{17})$ ]]

jq --exit-status \
  --arg api "${api_security_group_id}" \
  --arg nlb "${nlb_security_group_id}" \
  --arg audit "${audit_security_group_id}" \
  --arg remediation "${remediation_security_group_id}" \
  --arg endpoint "${endpoint_security_group_id}" \
  --arg s3 "${S3_PREFIX_LIST_ID}" \
  --arg dynamodb "${DYNAMODB_PREFIX_LIST_ID}" \
  --arg read "${ARCHON_DATAHUB_READ_EGRESS_PREFIX_LIST_ID}" \
  --arg write "${ARCHON_DATAHUB_WRITE_EGRESS_PREFIX_LIST_ID}" \
  --arg llm "${ARCHON_LLM_EGRESS_PREFIX_LIST_ID}" \
  '
    def normalized:
      {
        isEgress: .IsEgress,
        protocol: .IpProtocol,
        fromPort: (.FromPort // null),
        toPort: (.ToPort // null),
        cidrIpv4: (.CidrIpv4 // null),
        cidrIpv6: (.CidrIpv6 // null),
        prefixListId: (.PrefixListId // null),
        referencedGroupId: (.ReferencedGroupInfo.GroupId // null)
      };
    def ordered:
      sort_by([
        .isEgress,
        .protocol,
        .fromPort,
        .toPort,
        .cidrIpv4,
        .cidrIpv6,
        .prefixListId,
        .referencedGroupId
      ]);
    def group_rules($group):
      [
        .SecurityGroupRules[] |
        select(.GroupId == $group) |
        normalized
      ] |
      ordered;
    def tcp_rule($isEgress; $port; $cidr; $prefix; $group):
      {
        isEgress: $isEgress,
        protocol: "tcp",
        fromPort: $port,
        toPort: $port,
        cidrIpv4: $cidr,
        cidrIpv6: null,
        prefixListId: $prefix,
        referencedGroupId: $group
      };
    (group_rules($api) == ([
      tcp_rule(false; 8080; null; null; $nlb),
      tcp_rule(true; 443; null; null; $endpoint),
      tcp_rule(true; 443; null; $s3; null),
      tcp_rule(true; 443; null; $read; null),
      tcp_rule(true; 443; null; $llm; null)
    ] | ordered)) and
    (group_rules($nlb) == ([
      tcp_rule(true; 8080; null; null; $api)
    ] | ordered)) and
    (group_rules($audit) == ([
      tcp_rule(true; 443; null; null; $endpoint),
      tcp_rule(true; 443; null; $s3; null),
      tcp_rule(true; 443; null; $dynamodb; null),
      tcp_rule(true; 443; null; $read; null),
      tcp_rule(true; 443; null; $llm; null)
    ] | ordered)) and
    (group_rules($remediation) == ([
      tcp_rule(true; 443; null; null; $endpoint),
      tcp_rule(true; 443; null; $s3; null),
      tcp_rule(true; 443; null; $dynamodb; null),
      tcp_rule(true; 443; null; $write; null)
    ] | ordered)) and
    (group_rules($endpoint) == ([
      tcp_rule(false; 443; null; null; $api),
      tcp_rule(false; 443; null; null; $audit),
      tcp_rule(false; 443; null; null; $remediation),
      {
        isEgress: true,
        protocol: "icmp",
        fromPort: 252,
        toPort: 86,
        cidrIpv4: "255.255.255.255/32",
        cidrIpv6: null,
        prefixListId: null,
        referencedGroupId: null
      }
    ] | ordered))
  ' <<<"${rules_json}" >/dev/null || {
  echo "::error::Live workload security-group rules violate the exact egress contract" >&2
  exit 1
}

jq --compact-output --sort-keys \
  --arg api "${api_security_group_id}" \
  --arg nlb "${nlb_security_group_id}" \
  --arg nlbArn "${nlb_arn}" \
  --arg vpcId "${vpc_id}" \
  --arg deploymentAccountId "${deployment_account_id}" \
  --arg defaultSecurityGroupId "${default_security_group_id}" \
  --arg audit "${audit_security_group_id}" \
  --arg remediation "${remediation_security_group_id}" \
  --arg endpoint "${endpoint_security_group_id}" \
  --argjson vpcIdentity "${vpc_identity_json}" \
  --argjson securityGroupIdentityBindings "${security_group_bindings_json}" \
  '
    def normalized:
      {
        isEgress: .IsEgress,
        protocol: .IpProtocol,
        fromPort: (.FromPort // null),
        toPort: (.ToPort // null),
        cidrIpv4: (.CidrIpv4 // null),
        cidrIpv6: (.CidrIpv6 // null),
        prefixListId: (.PrefixListId // null),
        referencedGroupId: (.ReferencedGroupInfo.GroupId // null)
      };
    def ordered:
      sort_by([
        .isEgress,
        .protocol,
        .fromPort,
        .toPort,
        .cidrIpv4,
        .cidrIpv6,
        .prefixListId,
        .referencedGroupId
      ]);
    def group_rules($group):
      [
        .SecurityGroupRules[] |
        select(.GroupId == $group) |
        normalized
      ] |
      ordered;
    {
      schemaVersion: "archon.live-security-group-contract/v2",
      deploymentAccountId: $deploymentAccountId,
      vpc: {
        id: $vpcIdentity.id,
        cidr: $vpcIdentity.cidr,
        state: $vpcIdentity.state,
        isDefault: $vpcIdentity.isDefault,
        ownerAccountId: $vpcIdentity.ownerAccountId,
        defaultSecurityGroup: {
          id: $defaultSecurityGroupId,
          ingressRuleCount: 0,
          egressRuleCount: 0
        }
      },
      privateNetworkLoadBalancer: {
        arn: $nlbArn,
        vpcId: $vpcId,
        securityGroupId: $nlb,
        state: "active",
        scheme: "internal",
        ipAddressType: "ipv4",
        privateLinkInboundRuleEvaluation: "off"
      },
      securityGroupIdentityBindings: $securityGroupIdentityBindings,
      groups: {
        api: {
          id: $api,
          rules: group_rules($api)
        },
        networkLoadBalancer: {
          id: $nlb,
          rules: group_rules($nlb)
        },
        auditWorker: {
          id: $audit,
          rules: group_rules($audit)
        },
        remediationWorker: {
          id: $remediation,
          rules: group_rules($remediation)
        },
        privateLinkEndpoints: {
          id: $endpoint,
          rules: group_rules($endpoint)
        }
      },
      validation: "passed"
    }
  ' <<<"${rules_json}"
