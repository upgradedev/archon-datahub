#!/usr/bin/env bash
set -euo pipefail

: "${ARCHON_STACK_NAME:?ARCHON_STACK_NAME is required}"
: "${ARCHON_STACK_OUTPUTS:?ARCHON_STACK_OUTPUTS is required}"
: "${S3_PREFIX_LIST_ID:?S3_PREFIX_LIST_ID is required}"
: "${DYNAMODB_PREFIX_LIST_ID:?DYNAMODB_PREFIX_LIST_ID is required}"
: "${ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME:?ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME is required}"
: "${AWS_REGION:?AWS_REGION is required}"

expected_bedrock_region="eu-west-1"
expected_bedrock_model="qwen.qwen3-235b-a22b-2507"
[[ "${AWS_REGION}" == "${expected_bedrock_region}" ]] || {
  echo "::error::Bedrock Mantle deployment is pinned to ${expected_bedrock_region}" >&2
  exit 1
}

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
datahub_endpoint_security_group_id="$(
  stack_output ArchonDataHubEndpointSecurityGroupId
)"
datahub_endpoint_id="$(stack_output ArchonDataHubEndpointId)"
datahub_endpoint_service_name="$(
  stack_output ArchonDataHubEndpointServiceName
)"
datahub_private_link_az_one="$(
  stack_output ArchonDataHubPrivateLinkAzOne
)"
datahub_private_link_az_two="$(
  stack_output ArchonDataHubPrivateLinkAzTwo
)"
bedrock_endpoint_security_group_id="$(
  stack_output ArchonBedrockMantleEndpointSecurityGroupId
)"
bedrock_endpoint_id="$(stack_output ArchonBedrockMantleEndpointId)"
bedrock_endpoint_service_name="$(
  stack_output ArchonBedrockMantleEndpointServiceName
)"
bedrock_model="$(stack_output ArchonBedrockMantleModel)"
bedrock_project_id="$(stack_output ArchonBedrockMantleProjectId)"
bedrock_project_arn="$(stack_output ArchonBedrockMantleProjectArn)"
api_task_role_arn="$(stack_output ArchonApiTaskRoleArn)"
audit_task_role_arn="$(stack_output ArchonAuditWorkerTaskRoleArn)"
remediation_task_role_arn="$(stack_output ArchonRemediationWorkerTaskRoleArn)"

for security_group_id in \
  "${api_security_group_id}" \
  "${nlb_security_group_id}" \
  "${audit_security_group_id}" \
  "${remediation_security_group_id}" \
  "${endpoint_security_group_id}" \
  "${datahub_endpoint_security_group_id}" \
  "${bedrock_endpoint_security_group_id}"; do
  [[ "${security_group_id}" =~ ^sg-([0-9a-f]{8}|[0-9a-f]{17})$ ]] || {
    echo "::error::CloudFormation returned an invalid security-group ID" >&2
    exit 1
  }
done
[[ "${datahub_endpoint_id}" =~ ^vpce-([0-9a-f]{8}|[0-9a-f]{17})$ ]] || {
  echo "::error::CloudFormation returned an invalid DataHub endpoint ID" >&2
  exit 1
}
[[ "${datahub_endpoint_service_name}" == \
  "${ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME}" ]] || {
  echo "::error::CloudFormation returned an unexpected DataHub endpoint service" >&2
  exit 1
}
[[ "${datahub_private_link_az_one}" =~ ^eu-west-1[a-z]$ &&
  "${datahub_private_link_az_two}" =~ ^eu-west-1[a-z]$ &&
  "${datahub_private_link_az_one}" != "${datahub_private_link_az_two}" ]] || {
  echo "::error::CloudFormation returned invalid or duplicate DataHub endpoint availability zones" >&2
  exit 1
}
[[ "${bedrock_endpoint_id}" =~ ^vpce-([0-9a-f]{8}|[0-9a-f]{17})$ ]] || {
  echo "::error::CloudFormation returned an invalid Bedrock Mantle endpoint ID" >&2
  exit 1
}
[[ "${bedrock_endpoint_service_name}" == \
  "com.amazonaws.${AWS_REGION}.bedrock-mantle" ]] || {
  echo "::error::CloudFormation returned an unexpected Bedrock Mantle endpoint service" >&2
  exit 1
}
[[ "${bedrock_model}" == "${expected_bedrock_model}" ]] || {
  echo "::error::CloudFormation returned an unexpected Bedrock Mantle model" >&2
  exit 1
}
[[ "${bedrock_project_id}" =~ ^proj_[a-z0-9]{3,128}$ ]] || {
  echo "::error::CloudFormation returned an invalid Bedrock Mantle project ID" >&2
  exit 1
}
for task_role_arn in \
  "${api_task_role_arn}" \
  "${audit_task_role_arn}" \
  "${remediation_task_role_arn}"; do
  [[ "${task_role_arn}" =~ ^arn:aws:iam::[0-9]{12}:role/.+ ]] || {
    echo "::error::CloudFormation returned an invalid ECS task-role ARN" >&2
    exit 1
  }
done
[[ "${nlb_arn}" =~ ^arn:aws:elasticloadbalancing:[a-z0-9-]+:([0-9]{12}):loadbalancer/net/[A-Za-z0-9-]+/[0-9a-f]{16}$ ]] || {
  echo "::error::CloudFormation returned an invalid private NLB ARN" >&2
  exit 1
}
deployment_account_id="${BASH_REMATCH[1]}"
expected_bedrock_project_arn="$(
  printf 'arn:aws:bedrock-mantle:%s:%s:project/%s' \
    "${AWS_REGION}" \
    "${deployment_account_id}" \
    "${bedrock_project_id}"
)"
[[ "${bedrock_project_arn}" == "${expected_bedrock_project_arn}" ]] || {
  echo "::error::Bedrock Mantle project ARN is not bound to this account, Region, and project ID" >&2
  exit 1
}
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
      "${datahub_endpoint_security_group_id}" \
      "${bedrock_endpoint_security_group_id}" \
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
    --arg datahubEndpoint "${datahub_endpoint_security_group_id}" \
    --arg bedrockEndpoint "${bedrock_endpoint_security_group_id}" \
    '
      if (
        (.SecurityGroups | length) == 7 and
        ([.SecurityGroups[].GroupId] | unique | length) == 7 and
        ([.SecurityGroups[].GroupId] | sort) ==
          ([
            $api,
            $nlb,
            $audit,
            $remediation,
            $endpoint,
            $datahubEndpoint,
            $bedrockEndpoint
          ] | sort) and
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
    "${endpoint_security_group_id}" \
    "${datahub_endpoint_security_group_id}" \
    "${bedrock_endpoint_security_group_id}"; do
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
datahub_endpoint_json="$(
  aws ec2 describe-vpc-endpoints \
    --vpc-endpoint-ids "${datahub_endpoint_id}" \
    --output json
)"
datahub_service_json="$(
  aws ec2 describe-vpc-endpoint-services \
    --service-names "${datahub_endpoint_service_name}" \
    --output json
)"
datahub_subnet_ids="$(
  jq --exit-status --raw-output \
    '.VpcEndpoints[0].SubnetIds[]' \
    <<<"${datahub_endpoint_json}"
)"
mapfile -t datahub_subnet_id_array <<<"${datahub_subnet_ids}"
[[ "${#datahub_subnet_id_array[@]}" == 2 ]] || {
  echo "::error::DataHub PrivateLink endpoint must use exactly two subnets" >&2
  exit 1
}
datahub_subnets_json="$(
  aws ec2 describe-subnets \
    --subnet-ids "${datahub_subnet_id_array[@]}" \
    --output json
)"
datahub_endpoint_identity_json="$(
  jq --null-input --compact-output --sort-keys --exit-status \
    --arg endpointId "${datahub_endpoint_id}" \
    --arg serviceName "${datahub_endpoint_service_name}" \
    --arg vpcId "${vpc_id}" \
    --arg ownerAccountId "${deployment_account_id}" \
    --arg region "${AWS_REGION}" \
    --arg securityGroupId "${datahub_endpoint_security_group_id}" \
    --arg azOne "${datahub_private_link_az_one}" \
    --arg azTwo "${datahub_private_link_az_two}" \
    --argjson endpoint "${datahub_endpoint_json}" \
    --argjson service "${datahub_service_json}" \
    --argjson subnets "${datahub_subnets_json}" \
    '
      ($endpoint.VpcEndpoints[0]) as $liveEndpoint |
      ($service.ServiceDetails[0]) as $liveService |
      (
        $subnets.Subnets |
        map(.AvailabilityZone) |
        unique |
        sort
      ) as $endpointAvailabilityZones |
      if (
        ($endpoint.VpcEndpoints | length) == 1 and
        $liveEndpoint.VpcEndpointId == $endpointId and
        $liveEndpoint.VpcEndpointType == "Interface" and
        $liveEndpoint.ServiceName == $serviceName and
        $liveEndpoint.VpcId == $vpcId and
        $liveEndpoint.OwnerId == $ownerAccountId and
        $liveEndpoint.RequesterManaged == false and
        $liveEndpoint.State == "available" and
        $liveEndpoint.PrivateDnsEnabled == true and
        ($liveEndpoint.PolicyDocument == null or
          $liveEndpoint.PolicyDocument == "") and
        ($liveEndpoint.Groups | map(.GroupId)) == [$securityGroupId] and
        ($liveEndpoint.SubnetIds | length) == 2 and
        ($liveEndpoint.SubnetIds | unique | length) == 2 and
        ($liveEndpoint.NetworkInterfaceIds | length) == 2 and
        ($liveEndpoint.DnsEntries | length) >= 2 and
        ($subnets.Subnets | length) == 2 and
        all(
          $subnets.Subnets[];
          .VpcId == $vpcId and
          .State == "available"
        ) and
        ($endpointAvailabilityZones | length) == 2 and
        $endpointAvailabilityZones == ([$azOne, $azTwo] | sort) and
        ($service.ServiceNames | length) == 1 and
        $service.ServiceNames[0] == $serviceName and
        ($service.ServiceDetails | length) == 1 and
        $liveService.ServiceName == $serviceName and
        ($liveService.ServiceId | type) == "string" and
        (
          $liveService.ServiceId |
          test("^vpce-svc-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
        ) and
        $liveService.Owner != $ownerAccountId and
        (
          ($liveService.ServiceRegion // $region) ==
          $region
        ) and
        any(
          $liveService.ServiceType[];
          .ServiceType == "Interface"
        ) and
        (
          $endpointAvailabilityZones -
          ($liveService.AvailabilityZones | unique)
        ) == [] and
        ($liveService.PrivateDnsName | type) == "string" and
        (
          $liveService.PrivateDnsName |
          test(
            "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
          )
        ) and
        $liveService.PrivateDnsNameVerificationState == "verified"
      ) then
        {
          id: $liveEndpoint.VpcEndpointId,
          serviceId: $liveService.ServiceId,
          serviceName: $liveEndpoint.ServiceName,
          serviceOwnerAccountId: $liveService.Owner,
          serviceRegion:
            ($liveService.ServiceRegion // $region),
          providerPrivateDnsName: $liveService.PrivateDnsName,
          providerPrivateDnsVerificationState:
            $liveService.PrivateDnsNameVerificationState,
          vpcId: $liveEndpoint.VpcId,
          endpointOwnerAccountId: $liveEndpoint.OwnerId,
          state: $liveEndpoint.State,
          privateDnsEnabled: $liveEndpoint.PrivateDnsEnabled,
          securityGroupId: $liveEndpoint.Groups[0].GroupId,
          subnetCount: ($liveEndpoint.SubnetIds | length),
          availabilityZones: $endpointAvailabilityZones,
          networkInterfaceCount:
            ($liveEndpoint.NetworkInterfaceIds | length),
          endpointPolicy: "unsupported-not-configured"
        }
      else
        error("DataHub endpoint, service, subnet, or private-DNS identity is invalid")
      end
    '
)" || {
  echo "::error::DataHub PrivateLink endpoint violates the live fail-closed network contract" >&2
  exit 1
}
bedrock_stage="${ARCHON_STACK_NAME#Archon-}"
[[ "${bedrock_stage}" =~ ^[a-z][a-z0-9-]{1,15}$ ]] || {
  echo "::error::Cannot derive a valid Bedrock Mantle stage from ARCHON_STACK_NAME" >&2
  exit 1
}
bedrock_project_resource_json="$(
  aws cloudcontrol get-resource \
    --type-name "AWS::BedrockMantle::Project" \
    --identifier "${bedrock_project_arn}" \
    --output json
)"
bedrock_project_identity_json="$(
  jq --compact-output --exit-status \
    --arg projectId "${bedrock_project_id}" \
    --arg projectArn "${bedrock_project_arn}" \
    --arg expectedName "Archon-${bedrock_stage}" \
    --arg stage "${bedrock_stage}" \
    '
      (.ResourceDescription.Properties | fromjson) as $properties |
      if (
        .ResourceDescription.Identifier == $projectArn and
        $properties.Name == $expectedName and
        ($properties.Arn // $projectArn) == $projectArn and
        ($properties.Id // $projectId) == $projectId and
        ($properties.Tags | length) == 4 and
        any($properties.Tags[]; .Key == "Application" and .Value == "archon-datahub") and
        any($properties.Tags[]; .Key == "Environment" and .Value == $stage) and
        any($properties.Tags[]; .Key == "ManagedBy" and .Value == "aws-cdk") and
        any($properties.Tags[]; .Key == "CostCenter" and .Value == "DataHub-Agent-Hackathon")
      ) then
        {
          id: $projectId,
          arn: $projectArn,
          name: $properties.Name,
          tags: ($properties.Tags | sort_by(.Key)),
          validation: "cloud-control-live"
        }
      else
        error("Bedrock Mantle project identity or cost-allocation tags are invalid")
      end
    ' <<<"${bedrock_project_resource_json}"
)" || {
  echo "::error::Stage-scoped Bedrock Mantle project violates the live contract" >&2
  exit 1
}
bedrock_endpoint_json="$(
  aws ec2 describe-vpc-endpoints \
    --vpc-endpoint-ids "${bedrock_endpoint_id}" \
    --output json
)"
bedrock_endpoint_identity_json="$(
  jq --compact-output --exit-status \
    --arg endpointId "${bedrock_endpoint_id}" \
    --arg serviceName "${bedrock_endpoint_service_name}" \
    --arg vpcId "${vpc_id}" \
    --arg securityGroupId "${bedrock_endpoint_security_group_id}" \
    --arg apiRole "${api_task_role_arn}" \
    --arg auditRole "${audit_task_role_arn}" \
    --arg projectArn "${bedrock_project_arn}" \
    --arg model "${expected_bedrock_model}" \
    '
      def as_array:
        if type == "array" then . else [.] end;
      def policy:
        if .PolicyDocument | type == "string"
        then (.PolicyDocument | fromjson)
        else .PolicyDocument
        end;
      if (
        (.VpcEndpoints | length) == 1 and
        .VpcEndpoints[0].VpcEndpointId == $endpointId and
        .VpcEndpoints[0].VpcEndpointType == "Interface" and
        .VpcEndpoints[0].ServiceName == $serviceName and
        .VpcEndpoints[0].VpcId == $vpcId and
        .VpcEndpoints[0].State == "available" and
        .VpcEndpoints[0].PrivateDnsEnabled == true and
        (.VpcEndpoints[0].Groups | map(.GroupId)) == [$securityGroupId] and
        (.VpcEndpoints[0].SubnetIds | length) == 2 and
        (.VpcEndpoints[0].SubnetIds | unique | length) == 2 and
        (.VpcEndpoints[0].NetworkInterfaceIds | length) == 2 and
        (.VpcEndpoints[0].DnsEntries | length) >= 3 and
        (.VpcEndpoints[0] | policy | .Statement | length) == 2 and
        all(
          (.VpcEndpoints[0] | policy | .Statement[]);
          .Effect == "Allow" and
          (.Principal.AWS | as_array | sort) ==
            ([$apiRole, $auditRole] | sort)
        ) and
        any(
          (.VpcEndpoints[0] | policy | .Statement[]);
          .Sid == "OnlyInferenceRolesMayInvokeApprovedModel" and
          (.Action | as_array) == ["bedrock-mantle:CreateInference"] and
          (.Resource | as_array) == [$projectArn] and
          .Condition.StringEquals["bedrock-mantle:Model"] == $model
        ) and
        any(
          (.VpcEndpoints[0] | policy | .Statement[]);
          .Sid == "OnlyInferenceRolesMayUseShortTermTokens" and
          (.Action | as_array) == ["bedrock-mantle:CallWithBearerToken"] and
          (.Resource | as_array) == ["*"] and
          .Condition.StringEquals["bedrock-mantle:BearerTokenType"] ==
            "SHORT_TERM"
        )
      ) then
        {
          id: .VpcEndpoints[0].VpcEndpointId,
          serviceName: .VpcEndpoints[0].ServiceName,
          vpcId: .VpcEndpoints[0].VpcId,
          state: .VpcEndpoints[0].State,
          privateDnsEnabled: .VpcEndpoints[0].PrivateDnsEnabled,
          securityGroupId: .VpcEndpoints[0].Groups[0].GroupId,
          subnetCount: (.VpcEndpoints[0].SubnetIds | length),
          networkInterfaceCount:
            (.VpcEndpoints[0].NetworkInterfaceIds | length),
          endpointPolicy: "least-privilege-verified"
        }
      else
        error("Bedrock Mantle endpoint identity, topology, or policy is invalid")
      end
    ' <<<"${bedrock_endpoint_json}"
)" || {
  echo "::error::Bedrock Mantle PrivateLink endpoint violates the live contract" >&2
  exit 1
}

simulate_decision() {
  local role_arn="$1"
  local action="$2"
  local resource="$3"
  local context_key="$4"
  local context_value="$5"
  aws iam simulate-principal-policy \
    --policy-source-arn "${role_arn}" \
    --action-names "${action}" \
    --resource-arns "${resource}" \
    --context-entries \
      "ContextKeyName=${context_key},ContextKeyValues=${context_value},ContextKeyType=string" \
    --output json |
    jq -er \
      --arg action "${action}" \
      --arg resource "${resource}" \
      '
        if (
          (.EvaluationResults | length) == 1 and
          .EvaluationResults[0].EvalActionName == $action and
          .EvaluationResults[0].EvalResourceName == $resource
        ) then
          .EvaluationResults[0].EvalDecision
        else
          error("unexpected IAM simulation result")
        end
      '
}

for inference_role_arn in \
  "${api_task_role_arn}" \
  "${audit_task_role_arn}"; do
  [[ "$(
    simulate_decision \
      "${inference_role_arn}" \
      "bedrock-mantle:CreateInference" \
      "${bedrock_project_arn}" \
      "bedrock-mantle:Model" \
      "${expected_bedrock_model}"
  )" == "allowed" ]] || {
    echo "::error::Inference task role cannot invoke the approved Bedrock Mantle model" >&2
    exit 1
  }
  [[ "$(
    simulate_decision \
      "${inference_role_arn}" \
      "bedrock-mantle:CreateInference" \
      "${bedrock_project_arn}" \
      "bedrock-mantle:Model" \
      "qwen.unapproved-model"
  )" == "implicitDeny" ]] || {
    echo "::error::Inference task role can invoke an unapproved Bedrock Mantle model" >&2
    exit 1
  }
  [[ "$(
    simulate_decision \
      "${inference_role_arn}" \
      "bedrock-mantle:CallWithBearerToken" \
      "*" \
      "bedrock-mantle:BearerTokenType" \
      "SHORT_TERM"
  )" == "allowed" ]] || {
    echo "::error::Inference task role cannot use short-term Bedrock Mantle tokens" >&2
    exit 1
  }
  [[ "$(
    simulate_decision \
      "${inference_role_arn}" \
      "bedrock-mantle:CallWithBearerToken" \
      "*" \
      "bedrock-mantle:BearerTokenType" \
      "LONG_TERM"
  )" == "explicitDeny" ]] || {
    echo "::error::Inference task role does not explicitly deny long-term tokens" >&2
    exit 1
  }
done
[[ "$(
  simulate_decision \
    "${remediation_task_role_arn}" \
    "bedrock-mantle:CreateInference" \
    "${bedrock_project_arn}" \
    "bedrock-mantle:Model" \
    "${expected_bedrock_model}"
)" == "implicitDeny" ]] || {
  echo "::error::Remediation task role unexpectedly has Bedrock Mantle inference access" >&2
  exit 1
}
[[ "$(
  simulate_decision \
    "${remediation_task_role_arn}" \
    "bedrock-mantle:CallWithBearerToken" \
    "*" \
    "bedrock-mantle:BearerTokenType" \
    "SHORT_TERM"
)" == "implicitDeny" ]] || {
  echo "::error::Remediation task role unexpectedly has Bedrock Mantle token access" >&2
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
  --arg datahubEndpoint "${datahub_endpoint_security_group_id}" \
  --arg bedrockEndpoint "${bedrock_endpoint_security_group_id}" \
  --arg s3 "${S3_PREFIX_LIST_ID}" \
  --arg dynamodb "${DYNAMODB_PREFIX_LIST_ID}" \
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
      tcp_rule(true; 443; null; null; $datahubEndpoint),
      tcp_rule(true; 443; null; null; $bedrockEndpoint),
      tcp_rule(true; 443; null; $s3; null)
    ] | ordered)) and
    (group_rules($nlb) == ([
      tcp_rule(true; 8080; null; null; $api)
    ] | ordered)) and
    (group_rules($audit) == ([
      tcp_rule(true; 443; null; null; $endpoint),
      tcp_rule(true; 443; null; null; $datahubEndpoint),
      tcp_rule(true; 443; null; null; $bedrockEndpoint),
      tcp_rule(true; 443; null; $s3; null),
      tcp_rule(true; 443; null; $dynamodb; null)
    ] | ordered)) and
    (group_rules($remediation) == ([
      tcp_rule(true; 443; null; null; $endpoint),
      tcp_rule(true; 443; null; null; $datahubEndpoint),
      tcp_rule(true; 443; null; $s3; null),
      tcp_rule(true; 443; null; $dynamodb; null)
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
    ] | ordered)) and
    (group_rules($datahubEndpoint) == ([
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
    ] | ordered)) and
    (group_rules($bedrockEndpoint) == ([
      tcp_rule(false; 443; null; null; $api),
      tcp_rule(false; 443; null; null; $audit),
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
  --arg datahubEndpoint "${datahub_endpoint_security_group_id}" \
  --arg bedrockEndpoint "${bedrock_endpoint_security_group_id}" \
  --arg bedrockModel "${bedrock_model}" \
  --arg apiTaskRoleArn "${api_task_role_arn}" \
  --arg auditTaskRoleArn "${audit_task_role_arn}" \
  --arg remediationTaskRoleArn "${remediation_task_role_arn}" \
  --argjson vpcIdentity "${vpc_identity_json}" \
  --argjson securityGroupIdentityBindings "${security_group_bindings_json}" \
  --argjson datahubEndpointIdentity "${datahub_endpoint_identity_json}" \
  --argjson bedrockEndpointIdentity "${bedrock_endpoint_identity_json}" \
  --argjson bedrockProjectIdentity "${bedrock_project_identity_json}" \
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
      schemaVersion: "archon.live-security-group-contract/v4",
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
        },
        datahubPrivateLink: {
          id: $datahubEndpoint,
          rules: group_rules($datahubEndpoint)
        },
        bedrockMantlePrivateLink: {
          id: $bedrockEndpoint,
          rules: group_rules($bedrockEndpoint)
        }
      },
      datahub: {
        endpoint: $datahubEndpointIdentity,
        authentication: {
          read: "separate-secret",
          write: "separate-secret"
        },
        authorization: "provider-rbac",
        transport: "provider-private-dns"
      },
      bedrockMantle: {
        endpoint: $bedrockEndpointIdentity,
        project: $bedrockProjectIdentity,
        model: $bedrockModel,
        authentication: "task-role-short-term-token",
        taskRoles: {
          api: $apiTaskRoleArn,
          auditWorker: $auditTaskRoleArn,
          remediationWorker: $remediationTaskRoleArn
        },
        iamSimulation: {
          approvedModel: "allowed-for-api-and-audit",
          unapprovedModel: "implicit-deny-for-api-and-audit",
          shortTermToken: "allowed-for-api-and-audit",
          longTermToken: "explicit-deny-for-api-and-audit",
          remediation: "implicit-deny"
        }
      },
      validation: "passed"
    }
  ' <<<"${rules_json}"
