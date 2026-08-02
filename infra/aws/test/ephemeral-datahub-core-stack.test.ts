import { App } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { ArchonEphemeralDataHubCoreStack } from "../lib/ephemeral-datahub-core-stack";

function synthesized(): Record<string, any> {
  const app = new App();
  const stack = new ArchonEphemeralDataHubCoreStack(
    app,
    "Archon-staging-Core",
    {
      stage: "staging",
      env: { account: "123456789012", region: "eu-west-1" }
    }
  );
  return Template.fromStack(stack).toJSON();
}

function resources(
  template: Record<string, any>,
  type: string
): Record<string, any> {
  return Object.fromEntries(
    Object.entries(template.Resources).filter(
      ([, resource]: [string, any]) => resource.Type === type
    )
  );
}

describe("ephemeral DataHub Core stack", () => {
  test("is independent of Cloud profile inputs and expensive cluster primitives", () => {
    const template = synthesized();
    const parameterNames = Object.keys(template.Parameters ?? {});
    expect(parameterNames).toEqual(
      expect.arrayContaining([
        "DataHubCoreAmiId",
        "DataHubCoreGeneration",
        "DataHubCoreCapabilityDigest",
        "DataHubCoreImageManifestDigest",
        "DynamoDbPrefixListId",
        "DataHubCoreBedrockModelId"
      ])
    );
    expect(
      parameterNames.some((name) =>
        /PrivateLink|DataHubRead|DataHubWrite|CloudEnabled/u.test(name)
      )
    ).toBe(false);
    for (const forbidden of [
      "AWS::EKS::Cluster",
      "AWS::EC2::NatGateway",
      "AWS::EC2::InternetGateway",
      "AWS::EC2::EIP",
      "AWS::EC2::KeyPair",
      "AWS::ElasticLoadBalancingV2::LoadBalancer",
      "AWS::ElasticLoadBalancingV2::TargetGroup"
    ]) {
      expect(Object.keys(resources(template, forbidden))).toHaveLength(0);
    }
  });

  test("keeps exactly one private encrypted host at zero desired capacity", () => {
    const template = synthesized();
    const groups = Object.values(
      resources(template, "AWS::AutoScaling::AutoScalingGroup")
    ) as any[];
    expect(groups).toHaveLength(1);
    expect(groups[0].Properties.MinSize).toBe("0");
    expect(groups[0].Properties.MaxSize).toBe("1");
    expect(groups[0].Properties.DesiredCapacity).toBeUndefined();

    const launchTemplates = Object.values(
      resources(template, "AWS::EC2::LaunchTemplate")
    ) as any[];
    expect(launchTemplates).toHaveLength(1);
    const data = launchTemplates[0].Properties.LaunchTemplateData;
    expect(data.KeyName).toBeUndefined();
    expect(data.MetadataOptions.HttpTokens).toBe("required");
    expect(data.MetadataOptions.HttpEndpoint).toBe("enabled");
    expect(data.BlockDeviceMappings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          Ebs: expect.objectContaining({
            DeleteOnTermination: true,
            Encrypted: true,
            VolumeSize: 50,
            VolumeType: "gp3"
          })
        })
      ])
    );
    const serialized = JSON.stringify(data);
    expect(serialized).not.toContain('"AssociatePublicIpAddress":true');
  });

  test("uses a runtime-created inference endpoint and exact security-group paths", () => {
    const template = synthesized();
    const ingress = Object.values(
      resources(template, "AWS::EC2::SecurityGroupIngress")
    ) as any[];
    expect(ingress).toHaveLength(1);
    expect(ingress[0].Properties).toEqual(
      expect.objectContaining({
        IpProtocol: "tcp",
        FromPort: 443,
        ToPort: 443,
        SourceSecurityGroupId: expect.any(Object),
        GroupId: expect.any(Object)
      })
    );
    const egress = Object.values(
      resources(template, "AWS::EC2::SecurityGroupEgress")
    ) as any[];
    expect(egress).toHaveLength(2);
    expect(egress).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          Properties: expect.objectContaining({
            DestinationPrefixListId: { Ref: "DynamoDbPrefixListId" }
          })
        }),
        expect.objectContaining({
          Properties: expect.objectContaining({
            DestinationSecurityGroupId: expect.any(Object)
          })
        })
      ])
    );
    const endpoints = Object.values(
      resources(template, "AWS::EC2::VPCEndpoint")
    ) as any[];
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0].Properties.VpcEndpointType).toBe("Gateway");
    const serialized = JSON.stringify(template);
    expect(serialized).toContain("ec2:CreateVpcEndpoint");
    expect(serialized).toContain("ec2:DeleteVpcEndpoints");
    expect(serialized).toContain("CORE_BEDROCK_SERVICE_NAME");
  });
  test("uses Step Functions as the sole Auto Scaling owner", () => {
    const template = synthesized();
    const serialized = JSON.stringify(template);
    expect(serialized).toContain("autoscaling:updateAutoScalingGroup");
    expect(serialized).toContain("DesiredCapacity");
    expect(serialized).toContain("WaitForExactCoreLeaseDeadline");
    expect(serialized).toContain("ReapExactCoreLeaseRevision");

    const functions = Object.values(
      resources(template, "AWS::Lambda::Function")
    ) as any[];
    expect(functions).toHaveLength(2);
    const lifecycle = functions.find(
      (resource) =>
        resource.Properties.Handler === "lifecycle.handler"
    );
    expect(lifecycle).toBeDefined();
    expect(lifecycle.Properties.Environment.Variables).toEqual(
      expect.objectContaining({
        CORE_IDLE_SECONDS: "1800",
        CORE_HARD_SECONDS: "7200",
        CORE_OPERATION_SECONDS: "300"
      })
    );

    const lambdaRoleRefs = new Set(
      functions.map(
        (resource) => resource.Properties.Role["Fn::GetAtt"][0]
      )
    );
    const policies = Object.entries(
      resources(template, "AWS::IAM::Policy")
    ) as [string, any][];
    for (const [, policy] of policies) {
      const attached = (policy.Properties.Roles ?? [])
        .map((role: any) => role.Ref)
        .filter(Boolean);
      if (!attached.some((role: string) => lambdaRoleRefs.has(role))) continue;
      expect(JSON.stringify(policy)).not.toContain(
        "autoscaling:UpdateAutoScalingGroup"
      );
    }
  });

  test("persists authoritative leases and exact-deadline plus failsafe teardown", () => {
    const template = synthesized();
    const tables = Object.values(
      resources(template, "AWS::DynamoDB::Table")
    ) as any[];
    expect(tables).toHaveLength(1);
    expect(tables[0].Properties).toEqual(
      expect.objectContaining({
        BillingMode: "PAY_PER_REQUEST",
        DeletionProtectionEnabled: true,
        PointInTimeRecoverySpecification: {
          PointInTimeRecoveryEnabled: true
        },
        TimeToLiveSpecification: {
          AttributeName: "expiresAt",
          Enabled: true
        },
        StreamSpecification: {
          StreamViewType: "NEW_AND_OLD_IMAGES"
        }
      })
    );
    const rules = Object.values(
      resources(template, "AWS::Events::Rule")
    ) as any[];
    expect(rules).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          Properties: expect.objectContaining({
            ScheduleExpression: "rate(5 minutes)"
          })
        })
      ])
    );
    const machines = Object.values(
      resources(template, "AWS::StepFunctions::StateMachine")
    ) as any[];
    expect(machines).toHaveLength(1);
    expect(machines[0].Properties.StateMachineType).toBe("STANDARD");
  });

  test("exports stable deploy hooks for the runtime control API", () => {
    const template = synthesized();
    expect(template.Outputs).toEqual(
      expect.objectContaining({
        ArchonCoreSessionStateMachineArn: expect.objectContaining({
          Export: {
            Name: "archon-staging-core-session-state-machine-arn"
          }
        }),
        ArchonCoreLeaseTableName: expect.objectContaining({
          Export: { Name: "archon-staging-core-lease-table-name" }
        }),
        ArchonCoreAutoScalingGroupName: expect.objectContaining({
          Export: { Name: "archon-staging-core-asg-name" }
        })
      })
    );
  });
});
