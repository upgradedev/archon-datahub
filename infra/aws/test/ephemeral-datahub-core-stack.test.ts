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
        "DataHubCoreBedrockModelId",
        "DataHubCoreBedrockBaseModelId",
        "DataHubCoreDemoQuery",
        "DataHubCoreAnalyticsQuestion"
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

    const launchDefinitions = [
      ...Object.values(resources(template, "AWS::EC2::LaunchTemplate")),
      ...Object.values(
        resources(template, "AWS::AutoScaling::LaunchConfiguration")
      )
    ] as any[];
    expect(launchDefinitions).toHaveLength(1);
    const launch = launchDefinitions[0];
    const data =
      launch.Type === "AWS::EC2::LaunchTemplate"
        ? launch.Properties.LaunchTemplateData
        : launch.Properties;
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
    const allEgress = Object.values(
      resources(template, "AWS::EC2::SecurityGroupEgress")
    ) as any[];
    const egress = allEgress.filter(
      (resource) =>
        resource.Properties.IpProtocol === "tcp" &&
        resource.Properties.FromPort === 443 &&
        resource.Properties.ToPort === 443
    );
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
    expect(serialized).toContain("CORE_KMS_SERVICE_NAME");
    expect(serialized).toContain("CORE_INTERFACE_SECURITY_GROUP_ID");
  });

  test("pins one portable SQLite question and exact EU Bedrock resources", () => {
    const template = synthesized();
    expect(template.Parameters.DataHubCoreDemoQuery.Default).toBe(
      "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
    );
    expect(template.Parameters.DataHubCoreAnalyticsQuestion.Default).toBe(
      "Which customer segment generated the highest net revenue in Q2 2026, and is customers.customer_email governed as PII?"
    );
    expect(template.Parameters.DataHubCoreBedrockModelId.AllowedValues).toEqual([
      "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
    ]);
    expect(
      template.Parameters.DataHubCoreBedrockBaseModelId.AllowedValues
    ).toEqual(["anthropic.claude-sonnet-4-5-20250929-v1:0"]);
    const serialized = JSON.stringify(template);
    for (const region of [
      "eu-central-1",
      "eu-north-1",
      "eu-south-1",
      "eu-west-1",
      "eu-south-2",
      "eu-west-3"
    ]) {
      expect(serialized).toContain(`bedrock:${region}::foundation-model/`);
    }
    expect(serialized).toContain("ARCHON_CHART_LLM_MODEL");
    expect(serialized).toContain("ARCHON_QUALITY_LLM_MODEL");
    expect(serialized).toContain("ARCHON_DELIGHT_LLM_MODEL");
    expect(serialized).toContain("ARCHON_DEMO_QUERY");
    expect(serialized).toContain("ARCHON_ANALYTICS_QUESTION");
    expect(serialized).toContain("http://127.0.0.1:18080");
    expect(serialized).not.toContain("https://127.0.0.1:9443");
  });

  test("uses Step Functions as the sole Auto Scaling owner", () => {
    const template = synthesized();
    const serialized = JSON.stringify(template);
    expect(serialized).toContain("autoscaling:updateAutoScalingGroup");
    expect(serialized).toContain("DesiredCapacity");
    expect(serialized).toContain("WaitForExactCoreLeaseDeadline");
    expect(serialized).toContain("ReapExactCoreLeaseRevision");

    const functions = (
      Object.values(resources(template, "AWS::Lambda::Function")) as any[]
    ).filter((resource) =>
      ["lifecycle.handler", "observer.handler"].includes(
        resource.Properties.Handler
      )
    );
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
        CORE_OPERATION_SECONDS: "300",
        CORE_KMS_SERVICE_NAME: expect.anything(),
        CORE_DATA_KEY_ARN: expect.anything(),
        CORE_MUTATION_SIGNING_KEY_ARN: expect.anything(),
        CORE_ANALYTICS_ROLE_ARN: expect.anything(),
        CORE_INSTANCE_ROLE_ARN: expect.anything(),
        CORE_BEDROCK_RESOURCE_ARNS: expect.anything()
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

  test("limits host writes to health publication and existing transitions", () => {
    const template = synthesized();
    const policies = Object.values(
      resources(template, "AWS::IAM::Policy")
    ) as any[];
    const statements = policies.flatMap((policy) => {
      const value = policy.Properties.PolicyDocument.Statement;
      return Array.isArray(value) ? value : [value];
    });
    const bySid = Object.fromEntries(
      statements
        .filter((statement: any) => typeof statement.Sid === "string")
        .map((statement: any) => [statement.Sid, statement])
    );
    const actions = (statement: any): string[] =>
      Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action];

    expect(actions(bySid.DescribeOnlyCoreRuntimeTable)).toEqual([
      "dynamodb:DescribeTable"
    ]);
    expect(bySid.DescribeOnlyCoreRuntimeTable.Condition).toBeUndefined();
    expect(actions(bySid.ReadOnlyCoreRuntimeRecords).sort()).toEqual([
      "dynamodb:GetItem",
      "dynamodb:Query"
    ]);
    expect(actions(bySid.PublishOnlyCoreRuntimeHealth)).toEqual([
      "dynamodb:PutItem"
    ]);
    expect(
      bySid.PublishOnlyCoreRuntimeHealth.Condition[
        "ForAllValues:StringEquals"
      ]["dynamodb:LeadingKeys"]
    ).toEqual(["RUNTIME#core"]);
    expect(actions(bySid.TransitionOnlyExistingCoreRuntimeRecords)).toEqual([
      "dynamodb:UpdateItem"
    ]);
    expect(
      bySid.TransitionOnlyExistingCoreRuntimeRecords.Condition[
        "ForAllValues:StringLike"
      ]["dynamodb:LeadingKeys"]
    ).toEqual(["CORE#LEASE", "SESSION#rs_*", "MUTATION#rs_*"]);
    expect(actions(bySid.ReadAndTransitionOnlyCoreLease).sort()).toEqual([
      "dynamodb:GetItem",
      "dynamodb:UpdateItem"
    ]);
    expect(
      bySid.ReadAndTransitionOnlyCoreLease.Condition[
        "ForAllValues:StringEquals"
      ]["dynamodb:LeadingKeys"]
    ).toEqual(["CORE#LEASE"]);
    expect(actions(bySid.ReadOnlyActiveCoreLease)).toEqual([
      "dynamodb:GetItem"
    ]);
    expect(
      bySid.ReadOnlyActiveCoreLease.Condition["ForAllValues:StringEquals"][
        "dynamodb:LeadingKeys"
      ]
    ).toEqual(["CORE#LEASE"]);
    expect(actions(bySid.ConsumeOnlyBoundMutationJobs)).toEqual([
      "dynamodb:UpdateItem"
    ]);
    expect(
      bySid.ConsumeOnlyBoundMutationJobs.Condition["ForAllValues:StringLike"][
        "dynamodb:LeadingKeys"
      ]
    ).toEqual(["MUTATION#rs_*"]);
    expect(actions(bySid.PublishOnlyStoppedCoreHealth)).toEqual([
      "dynamodb:PutItem"
    ]);
    expect(
      bySid.PublishOnlyStoppedCoreHealth.Condition[
        "ForAllValues:StringEquals"
      ]["dynamodb:LeadingKeys"]
    ).toEqual(["RUNTIME#core"]);
    expect(actions(bySid.AssumeOnlyCoreScopedRuntimeRoles)).toEqual([
      "sts:AssumeRole"
    ]);
    expect(actions(bySid.EncryptOnlyBoundScopedCredentials)).toEqual([
      "kms:Encrypt"
    ]);
    expect(actions(bySid.DecryptOnlyActiveScopedCredentials)).toEqual([
      "kms:Decrypt"
    ]);
    expect(actions(bySid.GetOnlyPinnedMutationVerificationKey).sort()).toEqual([
      "kms:DescribeKey",
      "kms:GetPublicKey"
    ]);
    expect(actions(bySid.InvokeOnlyConfiguredBedrockModel).sort()).toEqual([
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream"
    ]);
    expect(JSON.stringify(template)).not.toContain(
      "dynamodb:TransactWriteItems"
    );
  });

  test("binds both rotating least-privilege sessions without lifecycle Bedrock invoke", () => {
    const template = synthesized();
    const serialized = JSON.stringify(template);
    const keys = Object.values(resources(template, "AWS::KMS::Key")) as any[];
    expect(keys).toHaveLength(3);
    expect(serialized).toContain("ECC_NIST_P256");
    expect(serialized).toContain("SIGN_VERIFY");
    expect(serialized).toContain("AllowExactGovernedGatewayPublicKeyRead");
    expect(serialized).toContain("AllowExactLifecycleCredentialEncryption");
    expect(serialized).toContain("AllowExactHostCredentialDecryption");
    expect(serialized).toContain("kms:EncryptionContext:stage");
    expect(serialized).toContain("kms:EncryptionContext:sessionId");
    expect(serialized).toContain("analytics-agent-bedrock");
    expect(serialized).toContain("governed-gateway-control");
    expect(serialized).toContain("archon-staging-datahub-core-analytics");
    expect(serialized).toContain("archon-staging-datahub-core-gateway");
    expect(serialized).toContain("CORE_GATEWAY_ROLE_ARN");
    expect(serialized).toContain("archon-staging-datahub-core-lifecycle");
    expect(serialized).toContain("eu-south-2");
    expect(serialized).not.toContain("eu-west-2");
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
        ArchonCoreLeaseTableStreamArn: expect.objectContaining({
          Export: { Name: "archon-staging-core-lease-table-stream-arn" }
        }),
        ArchonCoreAutoScalingGroupName: expect.objectContaining({
          Export: { Name: "archon-staging-core-asg-name" }
        }),
        ArchonCoreDataKeyArn: expect.objectContaining({
          Export: { Name: "archon-staging-core-data-key-arn" }
        }),
        ArchonCoreMutationSigningKeyArn: expect.objectContaining({
          Export: {
            Name: "archon-staging-core-mutation-signing-key-arn"
          }
        }),
        ArchonCoreBedrockBaseModelId: expect.objectContaining({
          Export: { Name: "archon-staging-core-bedrock-base-model-id" }
        })
      })
    );
  });
});