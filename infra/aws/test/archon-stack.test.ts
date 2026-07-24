import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import { ArchonPlatformStack, ArchonRegistryStack } from "../lib/archon-stack";

function templates(): { registry: Template; platform: Template } {
  const app = new App();
  const env = { account: "111111111111", region: "eu-west-1" };
  const registryStack = new ArchonRegistryStack(app, "TestRegistry", { env });
  const platformStack = new ArchonPlatformStack(app, "TestPlatform", {
    env,
    stage: "staging",
    repository: registryStack.repository
  });
  return {
    registry: Template.fromStack(registryStack),
    platform: Template.fromStack(platformStack)
  };
}

function platformTemplate(stage: string): Template {
  const app = new App();
  const env = { account: "111111111111", region: "eu-west-1" };
  const registryStack = new ArchonRegistryStack(
    app,
    `TestRegistry-${stage}`,
    { env }
  );
  const platformStack = new ArchonPlatformStack(app, `TestPlatform-${stage}`, {
    env,
    stage,
    repository: registryStack.repository
  });
  return Template.fromStack(platformStack);
}

describe("Archon AWS reference architecture", () => {
  test("uses one immutable, retained, scan-on-push ECR repository", () => {
    const { registry } = templates();
    registry.resourceCountIs("AWS::ECR::Repository", 1);
    registry.hasResourceProperties("AWS::ECR::Repository", {
      RepositoryName: "archon-datahub",
      ImageScanningConfiguration: { ScanOnPush: true },
      ImageTagMutability: "IMMUTABLE",
      EncryptionConfiguration: { EncryptionType: "KMS" }
    });
    registry.hasResource("AWS::ECR::Repository", {
      DeletionPolicy: "Retain",
      UpdateReplacePolicy: "Retain"
    });
    registry.hasOutput("ArchonEcrRepositoryUri", {});
    registry.hasOutput("ArchonEcrRepositoryName", {});
  });

  test("requires digest-addressed image and build-once SPA parameters", () => {
    const { platform } = templates();
    const json = platform.toJSON();
    expect(json.Parameters.ImageDigest).toEqual(
      expect.objectContaining({
        AllowedPattern: "^sha256:[a-f0-9]{64}$"
      })
    );
    expect(json.Parameters.SpaArtifactSha256).toEqual(
      expect.objectContaining({
        AllowedPattern: "^[a-f0-9]{64}$"
      })
    );
    expect(json.Parameters.CloudFrontDomainName).toEqual(
      expect.objectContaining({
        MaxLength: 253,
        AllowedPattern:
          "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
      })
    );
    expect(json.Parameters.CloudFrontCertificateArn).toEqual(
      expect.objectContaining({
        AllowedPattern:
          "^arn:aws:acm:us-east-1:[0-9]{12}:certificate/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
      })
    );
    expect(json.Parameters.CloudFrontHostedZoneId).toEqual(
      expect.objectContaining({
        AllowedPattern: "^Z[A-Z0-9]{1,31}$"
      })
    );
    expect(json.Parameters.CloudFrontWebAclArn).toEqual(
      expect.objectContaining({
        Default:
          "arn:aws:wafv2:us-east-1:000000000000:global/webacl/required-override/00000000-0000-0000-0000-000000000000",
        AllowedPattern:
          "^arn:aws:wafv2:us-east-1:[0-9]{12}:global/webacl/[A-Za-z0-9_-]{1,128}/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
      })
    );
    expect(json.Rules.RequireCloudFrontWebAclOverride).toEqual({
      Assertions: [
        {
          Assert: {
            "Fn::Not": [
              {
                "Fn::Equals": [
                  { Ref: "CloudFrontWebAclArn" },
                  "arn:aws:wafv2:us-east-1:000000000000:global/webacl/required-override/00000000-0000-0000-0000-000000000000"
                ]
              }
            ]
          },
          AssertDescription:
            "CloudFrontWebAclArn must be overridden with the deployed Archon edge-stack Web ACL ARN"
        }
      ]
    });
    expect(json.Parameters.CloudFrontWebAclArn.Default).toMatch(
      new RegExp(json.Parameters.CloudFrontWebAclArn.AllowedPattern)
    );
    for (const parameterName of [
      "S3PrefixListId",
      "DynamoDbPrefixListId",
      "DataHubReadEgressPrefixListId",
      "DataHubWriteEgressPrefixListId",
      "LlmEgressPrefixListId"
    ]) {
      expect(json.Parameters[parameterName]).toEqual(
        expect.objectContaining({
          AllowedPattern: "^pl-(?:[0-9a-f]{8}|[0-9a-f]{17})$"
        })
      );
    }
    expect(json.Parameters.DataHubReadMcpUrl).toEqual(
      expect.objectContaining({
        AllowedPattern: "^https://[^\\s]+$"
      })
    );
    expect(json.Parameters.DataHubWriteMcpUrl).toEqual(
      expect.objectContaining({
        AllowedPattern: "^https://[^\\s]+$"
      })
    );
    expect(json.Parameters.WorkerDesiredCount).toEqual(
      expect.objectContaining({
        Default: 0,
        MinValue: 0,
        MaxValue: 1
      })
    );
    const taskDefinitions = platform.findResources("AWS::ECS::TaskDefinition");
    const serialized = JSON.stringify(taskDefinitions);
    expect(serialized).toContain('"ImageDigest"');
    expect(serialized).toContain('"@"');
    expect(serialized).toContain('"Name":"DATAHUB_MCP_URL"');
    expect(serialized).toContain('"Name":"DATAHUB_WRITE_MCP_URL"');
  });

  test("resolves exactly two VPC availability zones at deploy time", () => {
    const { platform } = templates();
    const subnets = Object.values(
      platform.findResources("AWS::EC2::Subnet")
    ) as any[];
    const subnetAvailabilityZones = new Set(
      subnets.map((resource) =>
        JSON.stringify(resource.Properties.AvailabilityZone)
      )
    );
    expect(subnetAvailabilityZones).toEqual(
      new Set([
        JSON.stringify({
          "Fn::Select": [0, { "Fn::GetAZs": "" }]
        }),
        JSON.stringify({
          "Fn::Select": [1, { "Fn::GetAZs": "" }]
        })
      ])
    );
    expect(
      subnets.every(
        (resource) => resource.Properties.MapPublicIpOnLaunch === false
      )
    ).toBe(true);
  });

  test("keeps every S3 store private, versioned, retained, and audit logged", () => {
    const { platform } = templates();
    platform.hasResourceProperties("AWS::S3::Bucket", {
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true
      },
      VersioningConfiguration: { Status: "Enabled" },
      BucketEncryption: {
        ServerSideEncryptionConfiguration: Match.arrayWith([
          Match.objectLike({
            ServerSideEncryptionByDefault: {
              SSEAlgorithm: "aws:kms"
            }
          })
        ])
      }
    });
    platform.hasResourceProperties("AWS::S3::Bucket", {
      ObjectLockEnabled: true,
      VersioningConfiguration: { Status: "Enabled" }
    });
    expect(
      Object.values(platform.findResources("AWS::S3::Bucket")).filter(
        (resource: any) => resource.DeletionPolicy === "Retain"
      )
    ).toHaveLength(3);
    const buckets = Object.values(
      platform.findResources("AWS::S3::Bucket")
    ) as any[];
    expect(
      buckets.every(
        (resource) =>
          resource.Properties.VersioningConfiguration?.Status === "Enabled"
      )
    ).toBe(true);
    const serverAccessLoggedBuckets = buckets.filter(
      (resource) => resource.Properties.LoggingConfiguration
    );
    expect(serverAccessLoggedBuckets).toHaveLength(2);
    expect(
      serverAccessLoggedBuckets
        .map(
          (resource) =>
            resource.Properties.LoggingConfiguration.LogFilePrefix
        )
        .sort()
    ).toEqual(["s3-access/evidence/", "s3-access/spa/"]);
    expect(
      buckets
        .map((resource) =>
          resource.Properties.Tags?.find(
            (tag: { Key: string }) => tag.Key === "ArchonBucketRole"
          )?.Value
        )
        .sort()
    ).toEqual(["access-log-sink", "application", "application"]);
    expect(
      buckets
        .map((resource) =>
          resource.Properties.Tags?.find(
            (tag: { Key: string }) => tag.Key === "ArchonBucketPurpose"
          )?.Value
        )
        .sort()
    ).toEqual(["access-logs", "evidence", "spa"]);
    const applicationBuckets = buckets.filter((resource) =>
      resource.Properties.Tags?.some(
        (tag: { Key: string; Value: string }) =>
          tag.Key === "ArchonBucketRole" && tag.Value === "application"
      )
    );
    expect(applicationBuckets).toHaveLength(2);
    expect(
      applicationBuckets.every(
        (resource) =>
          resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration.every(
            (configuration: any) =>
              configuration.BucketKeyEnabled === true &&
              configuration.ServerSideEncryptionByDefault.SSEAlgorithm ===
                "aws:kms" &&
              configuration.ServerSideEncryptionByDefault.KMSMasterKeyID
          )
      )
    ).toBe(true);
  });

  test("serves the private SPA through CloudFront OAC and routes same-origin API", () => {
    const { platform } = templates();
    platform.resourceCountIs("AWS::CloudFront::OriginAccessControl", 1);
    platform.resourceCountIs("AWS::CloudFront::Function", 1);
    platform.resourceCountIs("AWS::Route53::RecordSet", 2);
    platform.hasResourceProperties("AWS::CloudFront::Function", {
      AutoPublish: true,
      FunctionConfig: Match.objectLike({
        Runtime: "cloudfront-js-2.0"
      })
    });
    const canonicalHostFunction = Object.values(
      platform.findResources("AWS::CloudFront::Function")
    )[0] as any;
    expect(JSON.stringify(canonicalHostFunction.Properties.FunctionCode)).toContain(
      "CloudFrontDomainName"
    );
    expect(JSON.stringify(canonicalHostFunction.Properties.FunctionCode)).toContain(
      "421"
    );
    platform.hasResourceProperties("AWS::CloudFront::Distribution", {
      DistributionConfig: Match.objectLike({
        DefaultRootObject: "index.html",
        HttpVersion: "http2and3",
        Enabled: true,
        Aliases: [{ Ref: "CloudFrontDomainName" }],
        WebACLId: { Ref: "CloudFrontWebAclArn" },
        ViewerCertificate: Match.objectLike({
          AcmCertificateArn: Match.anyValue(),
          SslSupportMethod: "sni-only",
          MinimumProtocolVersion: "TLSv1.3_2025",
          CloudFrontDefaultCertificate: Match.absent()
        }),
        DefaultCacheBehavior: Match.objectLike({
          ViewerProtocolPolicy: "redirect-to-https",
          FunctionAssociations: Match.arrayWith([
            Match.objectLike({
              EventType: "viewer-request",
              FunctionARN: Match.anyValue()
            })
          ])
        }),
        Origins: Match.arrayWith([
          Match.objectLike({
            S3OriginConfig: Match.anyValue(),
            OriginAccessControlId: Match.anyValue()
          })
        ]),
        CacheBehaviors: Match.arrayWith([
          Match.objectLike({
            PathPattern: "api/*",
            ViewerProtocolPolicy: "https-only",
            ResponseHeadersPolicyId: Match.anyValue()
          })
        ]),
        CustomErrorResponses: Match.absent()
      })
    });
    for (const recordType of ["A", "AAAA"]) {
      platform.hasResourceProperties("AWS::Route53::RecordSet", {
        Type: recordType,
        Name: { Ref: "CloudFrontDomainName" },
        HostedZoneId: { Ref: "CloudFrontHostedZoneId" },
        AliasTarget: Match.objectLike({
          HostedZoneId: "Z2FDTNDATAQYW2",
          EvaluateTargetHealth: false
        })
      });
    }
    const distribution = Object.values(
      platform.findResources("AWS::CloudFront::Distribution")
    )[0] as any;
    const runtimeConfigBehavior =
      distribution.Properties.DistributionConfig.CacheBehaviors.find(
        (behavior: any) => behavior.PathPattern === "runtime-config.json"
      );
    expect(
      distribution.Properties.DistributionConfig.CacheBehaviors.every(
        (behavior: any) =>
          behavior.FunctionAssociations?.length === 1 &&
          behavior.FunctionAssociations[0].EventType === "viewer-request"
      )
    ).toBe(true);
    expect(runtimeConfigBehavior).toEqual(
      expect.objectContaining({
        CachePolicyId: cloudfront.CachePolicy.CACHING_DISABLED.cachePolicyId,
        ViewerProtocolPolicy: "https-only",
        Compress: true
      })
    );
    expect(runtimeConfigBehavior.TargetOriginId).toEqual(
      distribution.Properties.DistributionConfig.DefaultCacheBehavior
        .TargetOriginId
    );
  });

  test("uses workload-specific prefix-list egress and one locked PrivateLink boundary", () => {
    const { platform } = templates();
    const securityGroups = Object.values(
      platform.findResources("AWS::EC2::SecurityGroup")
    ) as any[];
    const standaloneEgress = Object.values(
      platform.findResources("AWS::EC2::SecurityGroupEgress")
    ) as any[];
    const serializedSecurityRules = JSON.stringify([
      ...securityGroups.map((resource) => resource.Properties.SecurityGroupEgress),
      ...standaloneEgress.map((resource) => resource.Properties)
    ]);
    expect(serializedSecurityRules).not.toContain('"CidrIp":"0.0.0.0/0"');
    expect(serializedSecurityRules).not.toContain('"CidrIpv6":"::/0"');
    const noTrafficEgress = standaloneEgress.filter(
      (resource) =>
        resource.Properties.CidrIp === "255.255.255.255/32" &&
        resource.Properties.IpProtocol === "icmp"
    );
    expect(noTrafficEgress).toHaveLength(1);
    expect(noTrafficEgress[0]!.Properties).toEqual(
      expect.objectContaining({
        CidrIp: "255.255.255.255/32",
        FromPort: 252,
        IpProtocol: "icmp",
        ToPort: 86
      })
    );
    platform.hasResourceProperties(
      "AWS::ElasticLoadBalancingV2::LoadBalancer",
      {
        Scheme: "internal",
        Type: "network",
        EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic: "off",
        SecurityGroups: [Match.anyValue()]
      }
    );
    const apiIngressRules = Object.values(
      platform.findResources("AWS::EC2::SecurityGroupIngress")
    ).filter(
      (resource: any) =>
        resource.Properties.IpProtocol === "tcp" &&
        resource.Properties.FromPort === 8080 &&
        resource.Properties.ToPort === 8080
    ) as any[];
    expect(apiIngressRules).toHaveLength(1);
    expect(JSON.stringify(apiIngressRules[0]!.Properties)).toContain(
      "NlbSecurityGroup"
    );
    expect(apiIngressRules[0]!.Properties.CidrIp).toBeUndefined();
    const nlbTargetEgressRules = standaloneEgress.filter(
      (resource) =>
        resource.Properties.IpProtocol === "tcp" &&
        resource.Properties.FromPort === 8080 &&
        resource.Properties.ToPort === 8080
    );
    expect(nlbTargetEgressRules).toHaveLength(1);
    expect(JSON.stringify(nlbTargetEgressRules[0]!.Properties)).toContain(
      "ApiSecurityGroup"
    );
    expect(nlbTargetEgressRules[0]!.Properties.CidrIp).toBeUndefined();

    const prefixListRefs = standaloneEgress
      .map((resource) => resource.Properties.DestinationPrefixListId?.Ref)
      .filter(Boolean);
    expect(
      prefixListRefs.filter((value) => value === "S3PrefixListId")
    ).toHaveLength(3);
    expect(
      prefixListRefs.filter((value) => value === "DynamoDbPrefixListId")
    ).toHaveLength(2);
    expect(
      prefixListRefs.filter(
        (value) => value === "DataHubReadEgressPrefixListId"
      )
    ).toHaveLength(2);
    expect(
      prefixListRefs.filter(
        (value) => value === "DataHubWriteEgressPrefixListId"
      )
    ).toHaveLength(1);
    expect(
      prefixListRefs.filter((value) => value === "LlmEgressPrefixListId")
    ).toHaveLength(2);

    const interfaceEndpoints = Object.values(
      platform.findResources("AWS::EC2::VPCEndpoint")
    ).filter(
      (resource: any) => resource.Properties.VpcEndpointType === "Interface"
    ) as any[];
    expect(interfaceEndpoints).toHaveLength(7);
    const endpointSecurityGroupRefs = new Set(
      interfaceEndpoints.map((resource) =>
        JSON.stringify(resource.Properties.SecurityGroupIds)
      )
    );
    expect(endpointSecurityGroupRefs.size).toBe(1);
    expect([...endpointSecurityGroupRefs][0]).toContain(
      "VpcEndpointSecurityGroup"
    );
  });

  test("keeps audit public but makes the strict approval contract Cognito-only", () => {
    const { platform } = templates();
    platform.resourceCountIs("AWS::Cognito::UserPool", 1);
    platform.hasResourceProperties("AWS::Cognito::UserPool", {
      UserPoolTier: "PLUS",
      UserPoolAddOns: {
        AdvancedSecurityMode: "ENFORCED"
      }
    });
    platform.hasResourceProperties("AWS::ApiGateway::Model", {
      Schema: Match.objectLike({
        additionalProperties: false,
        required: ["decision"],
        properties: {
          decision: {
            type: "string",
            enum: ["APPROVE", "REJECT"]
          },
          comment: Match.objectLike({
            type: "string",
            maxLength: 1000
          })
        }
      })
    });
    const requestModels = Object.values(
      platform.findResources("AWS::ApiGateway::Model")
    ).filter(
      (resource: any) =>
        resource.Properties?.Schema?.required?.length === 1 &&
        resource.Properties.Schema.required[0] === "query"
    );
    expect(requestModels).toHaveLength(2);

    const methods = platform.findResources("AWS::ApiGateway::Method");
    const postMethods = Object.values(methods).filter(
      (resource: any) =>
        resource.Properties?.HttpMethod === "POST"
    );
    expect(postMethods).toHaveLength(3);
    expect(
      postMethods.filter(
        (resource: any) => resource.Properties?.AuthorizationType === "NONE"
      )
    ).toHaveLength(2);
    const approvalMethod = postMethods.find(
      (resource: any) =>
        resource.Properties?.AuthorizationType === "COGNITO_USER_POOLS" &&
        JSON.stringify(resource.Properties?.Integration?.Uri).includes(
          "ApprovalFunction"
        )
    ) as any;
    expect(approvalMethod).toBeDefined();
    expect(approvalMethod.Properties.AuthorizationScopes).toEqual([
      "archon/approve"
    ]);
    expect(approvalMethod.Properties.Integration.Type).toBe("AWS_PROXY");
    expect(JSON.stringify(approvalMethod.Properties.Integration.Uri)).toContain(
      "ApprovalFunction"
    );

    platform.hasResourceProperties("AWS::Lambda::Function", {
      FunctionName: "archon-staging-approval",
      Runtime: "nodejs24.x",
      TracingConfig: { Mode: "Active" },
      Environment: {
        Variables: {
          APPROVAL_TABLE: Match.anyValue(),
          APPROVER_GROUP: "archon-approvers"
        }
      }
    });
    platform.resourceCountIs("Custom::VpcRestrictDefaultSG", 1);
    const functions = Object.values(
      platform.findResources("AWS::Lambda::Function")
    ) as any[];
    expect(functions).toHaveLength(4);
    expect(
      functions.every(
        (resource) => resource.Properties.TracingConfig?.Mode === "Active"
      )
    ).toBe(true);
    expect(
      JSON.stringify(platform.findResources("AWS::IAM::Role"))
    ).toContain("xray:PutTraceSegments");
    expect(
      JSON.stringify(platform.findResources("AWS::IAM::Role"))
    ).toContain("xray:PutTelemetryRecords");
  });

  test("exposes capability-scoped async start and status through a read-only control Lambda", () => {
    const { platform } = templates();
    platform.hasResourceProperties("AWS::Lambda::Function", {
      FunctionName: "archon-staging-control",
      Runtime: "nodejs24.x",
      TracingConfig: { Mode: "Active" },
      Environment: {
        Variables: {
          STATE_MACHINE_ARN: Match.anyValue(),
          CHECKPOINT_TABLE: Match.anyValue(),
          APPROVAL_TABLE: Match.anyValue(),
          EVIDENCE_BUCKET: Match.anyValue()
        }
      }
    });

    const methods = Object.values(
      platform.findResources("AWS::ApiGateway::Method")
    ) as any[];
    const controlMethods = methods.filter((resource) =>
      JSON.stringify(resource.Properties?.Integration?.Uri).includes("ControlFunction")
    );
    expect(controlMethods).toHaveLength(2);
    expect(
      controlMethods.map((resource) => resource.Properties.HttpMethod).sort()
    ).toEqual(["GET", "POST"]);
    expect(
      controlMethods.every(
        (resource) => resource.Properties.AuthorizationType === "NONE"
      )
    ).toBe(true);
    const statusMethod = controlMethods.find(
      (resource) => resource.Properties.HttpMethod === "GET"
    );
    expect(statusMethod.Properties.RequestParameters).toEqual({
      "method.request.path.auditId": true
    });
    expect(statusMethod.Properties.Integration).toEqual(
      expect.objectContaining({
        CacheKeyParameters: ["method.request.path.auditId"],
        CacheNamespace: "audit-status"
      })
    );
    platform.hasResourceProperties("AWS::ApiGateway::Stage", {
      CacheClusterEnabled: true,
      CacheClusterSize: "0.5",
      MethodSettings: Match.arrayWith([
        Match.objectLike({
          ResourcePath: "/~1api~1control-loops~1{auditId}",
          HttpMethod: "GET",
          CacheDataEncrypted: true,
          CacheTtlInSeconds: 2,
          CachingEnabled: true,
          DataTraceEnabled: false,
          LoggingLevel: "ERROR",
          MetricsEnabled: true,
          ThrottlingBurstLimit: 20,
          ThrottlingRateLimit: 10
        })
      ])
    });
    const apiStage = Object.values(
      platform.findResources("AWS::ApiGateway::Stage")
    )[0] as any;
    expect(apiStage.Properties.MethodSettings).toHaveLength(1);

    const iamPolicies = Object.values(
      platform.findResources("AWS::IAM::Policy")
    ) as any[];
    const policies = JSON.stringify(iamPolicies);
    expect(policies).toContain("states:StartExecution");
    expect(policies).toContain("states:DescribeExecution");
    expect(policies).toContain("DescribeOnlyThisControlLoopExecutions");
    expect(policies).toContain("ReadOnlyBoundEvidenceProjection");
    expect(policies).toContain("v1/audit/*");
    expect(policies).toContain("v1/execution/*");
  });

  test("uses a public Cognito code client with exact hosted-SPA OAuth boundaries", () => {
    const { platform } = templates();
    platform.hasResourceProperties("AWS::Cognito::UserPoolDomain", {
      ManagedLoginVersion: 1,
      Domain: Match.anyValue()
    });
    platform.hasResourceProperties("AWS::Cognito::UserPoolResourceServer", {
      Identifier: "archon",
      Scopes: [
        {
          ScopeName: "approve",
          ScopeDescription:
            "Submit an exact human decision for a server-owned Archon proposal"
        }
      ]
    });
    platform.hasResourceProperties("AWS::Cognito::UserPoolClient", {
      GenerateSecret: false,
      ExplicitAuthFlows: ["ALLOW_REFRESH_TOKEN_AUTH"],
      AllowedOAuthFlows: ["code"],
      AllowedOAuthFlowsUserPoolClient: true,
      CallbackURLs: [Match.anyValue()],
      LogoutURLs: [Match.anyValue()],
      SupportedIdentityProviders: ["COGNITO"]
    });

    const client = Object.values(
      platform.findResources("AWS::Cognito::UserPoolClient")
    )[0] as any;
    const resourceServerLogicalId = Object.keys(
      platform.findResources("AWS::Cognito::UserPoolResourceServer")
    )[0]!;
    expect(client.Properties.AllowedOAuthScopes).toEqual([
      "openid",
      "email",
      {
        "Fn::Join": ["", [{ Ref: resourceServerLogicalId }, "/approve"]]
      }
    ]);
    expect(client.Properties.CallbackURLs).toEqual([
      {
        "Fn::Join": [
          "",
          ["https://", { Ref: "CloudFrontDomainName" }, "/"]
        ]
      }
    ]);
    expect(client.Properties.CallbackURLs).toEqual(
      client.Properties.LogoutURLs
    );

    const headersPolicy = Object.values(
      platform.findResources("AWS::CloudFront::ResponseHeadersPolicy")
    )[0] as any;
    const csp =
      headersPolicy.Properties.ResponseHeadersPolicyConfig
        .SecurityHeadersConfig.ContentSecurityPolicy.ContentSecurityPolicy;
    expect(JSON.stringify(csp)).toContain("amazoncognito.com");
    expect(JSON.stringify(csp)).not.toContain("cognito-idp.");

    const outputs = platform.toJSON().Outputs;
    expect(outputs.ArchonAuthRedirectUri.Value).toEqual(
      outputs.ArchonAuthLogoutUri.Value
    );
    expect(outputs.ArchonAuthRedirectUri.Value).toEqual({
      "Fn::Join": [
        "",
        ["https://", { Ref: "CloudFrontDomainName" }, "/"]
      ]
    });
    expect(outputs.ArchonApprovalOAuthScope.Value).toBe("archon/approve");
  });

  test("isolates write credentials from the public API task", () => {
    const { platform } = templates();
    const taskDefinitions = Object.values(
      platform.findResources("AWS::ECS::TaskDefinition")
    ) as any[];
    const api = taskDefinitions.find(
      (resource) => resource.Properties.ContainerDefinitions[0].Name === "Api"
    );
    const auditWorker = taskDefinitions.find(
      (resource) =>
        resource.Properties.ContainerDefinitions[0].Name === "AuditWorker"
    );
    const remediationWorker = taskDefinitions.find(
      (resource) =>
        resource.Properties.ContainerDefinitions[0].Name ===
        "RemediationWorker"
    );
    expect(api).toBeDefined();
    expect(auditWorker).toBeDefined();
    expect(remediationWorker).toBeDefined();

    const apiSecretNames = api.Properties.ContainerDefinitions[0].Secrets.map(
      (secret: any) => secret.Name
    );
    const auditWorkerSecretNames =
      auditWorker.Properties.ContainerDefinitions[0].Secrets.map(
      (secret: any) => secret.Name
    );
    const remediationWorkerSecretNames =
      remediationWorker.Properties.ContainerDefinitions[0].Secrets.map(
        (secret: any) => secret.Name
      );
    expect(apiSecretNames).toEqual(
      expect.arrayContaining(["DATAHUB_GMS_TOKEN", "LLM_API_KEY"])
    );
    expect(apiSecretNames).not.toContain("DATAHUB_WRITE_GMS_TOKEN");
    const apiEnvironment = api.Properties.ContainerDefinitions[0].Environment.map(
      (entry: any) => entry.Name
    );
    expect(apiEnvironment).not.toEqual(
      expect.arrayContaining([
        "ARCHON_APPROVAL_TABLE",
        "ARCHON_IDEMPOTENCY_TABLE",
        "ARCHON_EVIDENCE_BUCKET"
      ])
    );
    expect(auditWorkerSecretNames.sort()).toEqual(
      ["DATAHUB_GMS_TOKEN", "LLM_API_KEY"].sort()
    );
    expect(remediationWorkerSecretNames).toEqual([
      "DATAHUB_WRITE_GMS_TOKEN"
    ]);
    const remediationEnvironment =
      remediationWorker.Properties.ContainerDefinitions[0].Environment.map(
        (entry: any) => entry.Name
      );
    expect(remediationEnvironment).not.toEqual(
      expect.arrayContaining([
        "ARCHON_APPROVAL_TABLE",
        "DATAHUB_GMS_URL",
        "DATAHUB_MCP_URL",
        "LLM_BASE_URL",
        "LLM_MODEL"
      ])
    );
  });

  test("binds both worker autoscaling floors to the activation parameter", () => {
    const { platform } = templates();
    const scalableTargets = Object.values(
      platform.findResources("AWS::ApplicationAutoScaling::ScalableTarget")
    ) as any[];
    const parameterBoundTargets = scalableTargets.filter(
      (resource) =>
        resource.Properties.MinCapacity?.Ref === "WorkerDesiredCount"
    );
    expect(parameterBoundTargets).toHaveLength(2);
  });

  test("uses durable queues, CAS stores, and a traced Standard workflow", () => {
    const { platform } = templates();
    platform.resourceCountIs("AWS::SQS::Queue", 6);
    platform.hasResourceProperties("AWS::SQS::Queue", {
      KmsMasterKeyId: Match.anyValue(),
      RedrivePolicy: Match.anyValue()
    });
    const queues = platform.findResources("AWS::SQS::Queue") as Record<
      string,
      any
    >;
    const queueByName = new Map(
      Object.entries(queues).map(([logicalId, resource]) => [
        resource.Properties.QueueName,
        { logicalId, resource }
      ])
    );
    expect([...queueByName.keys()].sort()).toEqual([
      "archon-staging-approval-dlq",
      "archon-staging-approval-events",
      "archon-staging-audit-dlq",
      "archon-staging-audit-jobs",
      "archon-staging-remediation-dlq",
      "archon-staging-remediation-jobs"
    ]);
    for (const [sourceName, dlqName] of [
      ["archon-staging-audit-jobs", "archon-staging-audit-dlq"],
      ["archon-staging-approval-events", "archon-staging-approval-dlq"],
      [
        "archon-staging-remediation-jobs",
        "archon-staging-remediation-dlq"
      ]
    ] as const) {
      const source = queueByName.get(sourceName)!;
      const dlq = queueByName.get(dlqName)!;
      expect(source.resource.Properties.VisibilityTimeout).toBe(300);
      expect(source.resource.Properties.RedrivePolicy).toEqual({
        deadLetterTargetArn: { "Fn::GetAtt": [dlq.logicalId, "Arn"] },
        maxReceiveCount: 5
      });
      expect(dlq.resource.Properties.RedrivePolicy).toBeUndefined();
    }
    platform.resourceCountIs("AWS::DynamoDB::Table", 2);
    platform.hasResourceProperties("AWS::DynamoDB::Table", {
      BillingMode: "PAY_PER_REQUEST",
      DeletionProtectionEnabled: true,
      PointInTimeRecoverySpecification: {
        PointInTimeRecoveryEnabled: true
      },
      ContributorInsightsSpecification: {
        Enabled: true
      },
      SSESpecification: {
        KMSMasterKeyId: Match.anyValue(),
        SSEEnabled: true,
        SSEType: "KMS"
      },
      TimeToLiveSpecification: {
        AttributeName: "expiresAt",
        Enabled: true
      }
    });
    platform.hasResourceProperties("AWS::StepFunctions::StateMachine", {
      StateMachineType: "STANDARD",
      TracingConfiguration: { Enabled: true },
      LoggingConfiguration: Match.objectLike({
        IncludeExecutionData: false,
        Level: "ERROR"
      })
    });
    const stateMachine = Object.values(
      platform.findResources("AWS::StepFunctions::StateMachine")
    )[0] as any;
    const definition = JSON.stringify(stateMachine.Properties.DefinitionString);
    expect(definition).toContain("REMEDIATION_REQUESTED");
    expect(definition.match(/HeartbeatSeconds/g)).toHaveLength(2);
    expect(definition.match(/900/g)?.length ?? 0).toBeGreaterThanOrEqual(2);
    expect(definition).toContain("7200");
    expect(definition).toContain("604800");
    expect(definition).toContain("VerifyRemediationOutcome");
    expect(definition).toContain("GovernedWriteNotVerified");
    expect(definition).toContain("REJECTED");
    platform.hasResourceProperties("AWS::Lambda::Function", {
      FunctionName: "archon-staging-approval-handoff",
      Handler: "handoff.handler",
      Environment: {
        Variables: {
          APPROVAL_TABLE: Match.anyValue()
        }
      }
    });
    const iamPolicies = Object.values(
      platform.findResources("AWS::IAM::Policy")
    ) as any[];
    const policies = JSON.stringify(iamPolicies);
    expect(policies).toContain("CheckpointOnlyAuditExecutions");
    expect(policies).toContain("JournalOnlyGovernedExecutions");
    expect(policies).toContain("NeverDeleteOrBypassEvidenceRetention");
    expect(policies).toContain("PersistOnlyApprovalHandoffsAndPoisonEvidence");
    expect(policies).toContain("ReadAndDecideOnlyBoundApprovals");
    expect(policies).toContain("ReadOnlyBoundAuditCheckpoints");
    expect(policies).toContain("ReadOnlyBoundApprovalStatus");
    expect(policies).toContain("ReadOnlyBoundEvidenceProjection");

    const policyStatements = iamPolicies.flatMap((policy) => {
      const statements = policy.Properties.PolicyDocument.Statement;
      return Array.isArray(statements) ? statements : [statements];
    });
    const constrainedEvidenceKeyStatements = policyStatements.filter(
      (statement) => statement.Sid === "UseEvidenceKeyOnlyThroughS3"
    );
    expect(constrainedEvidenceKeyStatements).toHaveLength(3);
    for (const statement of constrainedEvidenceKeyStatements) {
      expect(statement.Resource).not.toBe("*");
      expect(JSON.stringify(statement.Condition)).toContain("kms:ViaService");
      expect(JSON.stringify(statement.Condition)).toContain(
        "kms:EncryptionContext:aws:s3:arn"
      );
      expect(JSON.stringify(statement.Condition)).toContain("EvidenceBucket");
    }

    const lambdaFunctions = Object.values(
      platform.findResources("AWS::Lambda::Function")
    ) as any[];
    const roleStatementsFor = (functionName: string): any[] => {
      const lambdaFunction = lambdaFunctions.find(
        (resource) => resource.Properties.FunctionName === functionName
      );
      expect(lambdaFunction).toBeDefined();
      const roleLogicalId = lambdaFunction.Properties.Role["Fn::GetAtt"][0];
      return iamPolicies
        .filter((policy) =>
          (policy.Properties.Roles ?? []).some(
            (role: any) => role.Ref === roleLogicalId
          )
        )
        .flatMap((policy) => {
          const statements = policy.Properties.PolicyDocument.Statement;
          return Array.isArray(statements) ? statements : [statements];
        });
    };
    const actionsFor = (statement: any): string[] =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).filter(
        (action: unknown): action is string => typeof action === "string"
      );
    const isKmsStatement = (statement: any): boolean =>
      actionsFor(statement).some((action) => action.startsWith("kms:"));

    const approvalKmsStatements = roleStatementsFor(
      "archon-staging-approval"
    ).filter(isKmsStatement);
    expect(approvalKmsStatements).toEqual([]);

    // Lambda's SQS event-source poller must decrypt the CMK-encrypted approval
    // queue. Keep that sole exception bound to QueueKey and decrypt-only.
    const handoffKmsStatements = roleStatementsFor(
      "archon-staging-approval-handoff"
    ).filter(isKmsStatement);
    expect(handoffKmsStatements).toHaveLength(1);
    expect(actionsFor(handoffKmsStatements[0])).toEqual(["kms:Decrypt"]);
    const queueKeyAlias = Object.values(
      platform.findResources("AWS::KMS::Alias")
    ).find(
      (resource: any) =>
        resource.Properties.AliasName === "alias/archon/staging/queues"
    ) as any;
    expect(queueKeyAlias).toBeDefined();
    const queueKeyTarget = queueKeyAlias.Properties.TargetKeyId;
    const queueKeyLogicalId =
      queueKeyTarget.Ref ?? queueKeyTarget["Fn::GetAtt"]?.[0];
    expect(queueKeyLogicalId).toEqual(expect.any(String));
    expect(handoffKmsStatements[0].Resource).toEqual({
      "Fn::GetAtt": [queueKeyLogicalId, "Arn"]
    });
  });

  test("has private Fargate services, WAF, observability, and stable outputs", () => {
    const { platform } = templates();
    platform.hasResourceProperties("AWS::ECS::Cluster", {
      ClusterSettings: [
        {
          Name: "containerInsights",
          Value: "enabled"
        }
      ]
    });
    platform.hasResourceProperties("AWS::ApiGateway::RestApi", {
      MinimumCompressionSize: 1024
    });
    platform.resourceCountIs("AWS::ECS::Service", 3);
    const services = Object.values(platform.findResources("AWS::ECS::Service")) as any[];
    for (const service of services) {
      expect(
        service.Properties.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp
      ).toBe("DISABLED");
    }
    platform.resourceCountIs("AWS::WAFv2::WebACL", 1);
    platform.hasResourceProperties("AWS::WAFv2::WebACL", {
      Scope: "REGIONAL",
      DataProtectionConfig: {
        DataProtections: [
          {
            Action: "SUBSTITUTION",
            ExcludeRateBasedDetails: false,
            ExcludeRuleMatchDetails: false,
            Field: {
              FieldType: "SINGLE_HEADER",
              FieldKeys: ["authorization"]
            }
          },
          {
            Action: "SUBSTITUTION",
            ExcludeRateBasedDetails: false,
            ExcludeRuleMatchDetails: false,
            Field: {
              FieldType: "SINGLE_HEADER",
              FieldKeys: ["cookie"]
            }
          }
        ]
      }
    });
    const regionalWebAcl = Object.values(
      platform.findResources("AWS::WAFv2::WebACL")
    )[0] as any;
    for (const name of [
      "AWSManagedRulesAmazonIpReputationList",
      "AWSManagedRulesCommonRuleSet",
      "AWSManagedRulesKnownBadInputsRuleSet"
    ]) {
      const managedRule = regionalWebAcl.Properties.Rules.find(
        (rule: any) => rule.Name === name
      );
      expect(managedRule.Statement.ManagedRuleGroupStatement).toEqual({
        Name: name,
        VendorName: "AWS"
      });
    }
    const stagingRateRule = regionalWebAcl.Properties.Rules.find(
      (rule: any) => rule.Name === "PerIpRateLimit"
    );
    expect(stagingRateRule.Statement.RateBasedStatement).toEqual({
      AggregateKeyType: "IP",
      EvaluationWindowSec: 300,
      Limit: 300
    });
    platform.hasResourceProperties("AWS::Logs::LogGroup", {
      LogGroupName: "aws-waf-logs-archon-staging-api",
      KmsKeyId: Match.anyValue(),
      RetentionInDays: 365
    });
    platform.hasResourceProperties("AWS::WAFv2::LoggingConfiguration", {
      LogDestinationConfigs: [Match.anyValue()],
      LoggingFilter: {
        DefaultBehavior: "DROP",
        Filters: [
          {
            Behavior: "KEEP",
            Conditions: [
              { ActionCondition: { Action: "BLOCK" } },
              { ActionCondition: { Action: "COUNT" } }
            ],
            Requirement: "MEETS_ANY"
          }
        ]
      },
      RedactedFields: [
        { SingleHeader: { Name: "authorization" } },
        { SingleHeader: { Name: "cookie" } }
      ],
      ResourceArn: Match.anyValue()
    });
    const logsKeyAlias = Object.values(
      platform.findResources("AWS::KMS::Alias")
    ).find(
      (resource: any) =>
        resource.Properties.AliasName === "alias/archon/staging/logs"
    ) as any;
    expect(logsKeyAlias).toBeDefined();
    const logsKeyLogicalId =
      logsKeyAlias.Properties.TargetKeyId.Ref ??
      logsKeyAlias.Properties.TargetKeyId["Fn::GetAtt"]?.[0];
    const logsKey = platform.findResources("AWS::KMS::Key")[
      logsKeyLogicalId
    ] as any;
    expect(logsKey).toBeDefined();
    const logsKeyStatements = logsKey.Properties.KeyPolicy.Statement;
    const cloudWatchLogsStatement = logsKeyStatements.find(
      (statement: any) => statement.Sid === "AllowCloudWatchLogsEncryption"
    );
    expect(cloudWatchLogsStatement).toBeDefined();
    expect(cloudWatchLogsStatement.Action).toEqual([
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]);
    expect(JSON.stringify(cloudWatchLogsStatement.Principal)).toContain(
      "logs."
    );
    expect(JSON.stringify(cloudWatchLogsStatement.Condition)).toContain(
      "kms:EncryptionContext:aws:logs:arn"
    );
    expect(JSON.stringify(cloudWatchLogsStatement.Condition)).toContain(
      "aws-waf-logs-archon-staging-api"
    );
    expect(JSON.stringify(cloudWatchLogsStatement.Condition)).toContain(
      "/archon/staging/*"
    );
    expect(JSON.stringify(cloudWatchLogsStatement.Condition)).not.toContain(
      "kms:ViaService"
    );
    // Ten explicit operational alarms plus upper/lower alarms generated by
    // each of the two worker step-scaling policies.
    platform.resourceCountIs("AWS::CloudWatch::Alarm", 14);
    platform.resourceCountIs("AWS::CloudWatch::Dashboard", 1);

    for (const outputName of [
      "ArchonSpaBucketName",
      "ArchonEvidenceBucketName",
      "ArchonCloudFrontDistributionId",
      "ArchonCloudFrontDomainName",
      "ArchonApplicationUrl",
      "ArchonApiUrl",
      "ArchonApiInvokeUrl",
      "ArchonApiStageArn",
      "ArchonRegionalWebAclArn",
      "ArchonRegionalWafLogGroupName",
      "ArchonRegionalWafLogKeyArn",
      "ArchonUserPoolId",
      "ArchonUserPoolClientId",
      "ArchonCognitoHostedUiOrigin",
      "ArchonCognitoAuthorizationEndpoint",
      "ArchonCognitoTokenEndpoint",
      "ArchonCognitoLogoutEndpoint",
      "ArchonApprovalOAuthScope",
      "ArchonAuthRedirectUri",
      "ArchonAuthLogoutUri",
      "ArchonApproverGroupName",
      "ArchonStateMachineArn",
      "ArchonAuditQueueUrl",
      "ArchonApprovalQueueUrl",
      "ArchonRemediationQueueUrl",
      "ArchonApprovalTableName",
      "ArchonIdempotencyTableName",
      "ArchonEcsClusterName",
      "ArchonApiServiceName",
      "ArchonAuditWorkerServiceName",
      "ArchonRemediationWorkerServiceName",
      "ArchonApiSecurityGroupId",
      "ArchonNlbSecurityGroupId",
      "ArchonPrivateNlbArn",
      "ArchonVpcId",
      "ArchonAuditWorkerSecurityGroupId",
      "ArchonRemediationWorkerSecurityGroupId",
      "ArchonVpcEndpointSecurityGroupId",
      "ArchonReadSecretArn",
      "ArchonWriteSecretArn",
      "ArchonLlmSecretArn",
      "ArchonContainerImageDigest",
      "ArchonSpaArtifactSha256",
      "ArchonReleaseSha"
    ]) {
      platform.hasOutput(outputName, {});
    }
  });

  test("applies production capacity, availability, and edge hardening", () => {
    const production = platformTemplate("production");

    production.resourceCountIs("AWS::EC2::NatGateway", 2);
    production.hasResourceProperties("AWS::ECS::Service", {
      DesiredCount: 2,
      DeploymentConfiguration: Match.objectLike({
        MinimumHealthyPercent: 100,
        MaximumPercent: 200
      })
    });

    const scalableTargets = Object.values(
      production.findResources("AWS::ApplicationAutoScaling::ScalableTarget")
    ) as any[];
    expect(
      scalableTargets.some(
        (target) =>
          target.Properties.MinCapacity === 2 &&
          target.Properties.MaxCapacity === 20
      )
    ).toBe(true);
    const workerTargets = scalableTargets.filter(
      (target) => target.Properties.MinCapacity?.Ref === "WorkerDesiredCount"
    );
    expect(
      workerTargets.map((target) => target.Properties.MaxCapacity).sort()
    ).toEqual([10, 20]);

    production.hasResourceProperties(
      "AWS::ElasticLoadBalancingV2::LoadBalancer",
      {
        LoadBalancerAttributes: Match.arrayWith([
          {
            Key: "deletion_protection.enabled",
            Value: "true"
          }
        ])
      }
    );
    production.hasResourceProperties("AWS::Lambda::Function", {
      FunctionName: "archon-production-control",
      ReservedConcurrentExecutions: 50
    });
    production.hasResourceProperties("AWS::ApiGateway::Stage", {
      MethodSettings: Match.arrayWith([
        Match.objectLike({
          ThrottlingBurstLimit: 100,
          ThrottlingRateLimit: 50
        })
      ])
    });

    const webAcl = Object.values(
      production.findResources("AWS::WAFv2::WebACL")
    )[0] as any;
    const rateLimitRule = webAcl.Properties.Rules.find(
      (rule: any) => rule.Name === "PerIpRateLimit"
    );
    expect(rateLimitRule.Statement.RateBasedStatement).toEqual({
      AggregateKeyType: "IP",
      EvaluationWindowSec: 300,
      Limit: 1_000
    });
  });
});
