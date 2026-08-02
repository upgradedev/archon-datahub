import { App } from "aws-cdk-lib";
import {
  Match,
  Template
} from "aws-cdk-lib/assertions";
import { ArchonJudgeStack } from "../lib/archon-judge-stack";

function judgeTemplate(
  stage: "staging" | "production" = "staging"
): Template {
  const app = new App();
  const stack = new ArchonJudgeStack(
    app,
    `Archon-${stage}-Judge-Test`,
    {
      stage,
      env: {
        account: "123456789012",
        region: "eu-west-1"
      }
    }
  );
  return Template.fromStack(stack);
}

describe("ArchonJudgeStack", () => {
  test("synthesizes the exact low-cost serverless topology", () => {
    const template = judgeTemplate();

    for (const forbidden of [
      "AWS::ECS::Cluster",
      "AWS::ECS::Service",
      "AWS::ECS::TaskDefinition",
      "AWS::EC2::NatGateway",
      "AWS::EC2::VPC",
      "AWS::EKS::Cluster",
      "AWS::ElasticLoadBalancingV2::LoadBalancer",
      "AWS::ApiGateway::VpcLink",
      "AWS::StepFunctions::StateMachine"
    ]) {
      template.resourceCountIs(forbidden, 0);
    }
    template.resourceCountIs("AWS::CloudFront::Distribution", 1);
    template.resourceCountIs("AWS::ApiGateway::RestApi", 1);
    template.resourceCountIs("AWS::Cognito::UserPool", 1);
    template.resourceCountIs("AWS::DynamoDB::Table", 1);
    template.resourceCountIs("AWS::Lambda::Function", 6);
    template.resourceCountIs(
      "AWS::Lambda::EventSourceMapping",
      6
    );
    template.resourceCountIs("AWS::S3::Bucket", 2);
    template.resourceCountIs("AWS::SQS::Queue", 2);
    template.resourceCountIs("AWS::SNS::Topic", 1);
    template.resourceCountIs("AWS::SNS::Subscription", 1);
    template.resourceCountIs("AWS::CloudWatch::Alarm", 2);
    template.resourceCountIs("AWS::SecretsManager::Secret", 3);
    template.resourceCountIs("AWS::WAFv2::WebACLAssociation", 2);
  });

  test("keeps every function outside a VPC and bounds compute", () => {
    const template = judgeTemplate();
    const functions = Object.values(
      template.findResources("AWS::Lambda::Function")
    ) as any[];
    expect(functions).toHaveLength(6);
    for (const fn of functions) {
      expect(fn.Properties.VpcConfig).toBeUndefined();
      expect(fn.Properties.ReservedConcurrentExecutions).toBeGreaterThan(0);
    }
    const images = functions.filter(
      (fn) => fn.Properties.PackageType === "Image"
    );
    expect(images).toHaveLength(3);
    expect(
      images.map((fn) => fn.Properties.ReservedConcurrentExecutions)
        .sort()
    ).toEqual([1, 1, 2]);
    for (const fn of images) {
      expect(fn.Properties.Code.ImageUri).toEqual({
        Ref: "CloudRuntimeImageUri"
      });
      expect(fn.Properties.Architectures).toEqual(["x86_64"]);
    }
    template.hasResourceProperties("AWS::Lambda::Function", {
      FunctionName: "archon-staging-cloud-read",
      MemorySize: 4096,
      Timeout: 900,
      EphemeralStorage: { Size: 1024 },
      ImageConfig: { Command: ["handlers.read_handler"] }
    });
    template.hasResourceProperties("AWS::Lambda::Function", {
      FunctionName: "archon-staging-cloud-mutation",
      ReservedConcurrentExecutions: 1,
      ImageConfig: {
        Command: ["handlers.mutation_handler"]
      }
    });
    template.hasResourceProperties("AWS::Lambda::Function", {
      FunctionName: "archon-staging-cloud-reset",
      ReservedConcurrentExecutions: 1,
      ImageConfig: {
        Command: ["handlers.fixture_reset_handler"]
      }
    });
  });

  test("separates read, governed-write, reset and signing authority", () => {
    const template = judgeTemplate();
    const policies = Object.values(
      template.findResources("AWS::IAM::Policy")
    ) as any[];
    const statements = policies.flatMap(
      (policy) =>
        policy.Properties.PolicyDocument.Statement ?? []
    );
    const actions = (statement: any): string[] =>
      Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action];

    const sign = statements.filter((statement) =>
      actions(statement).includes("kms:Sign")
    );
    expect(sign).toHaveLength(1);
    expect(actions(sign[0])).toEqual(["kms:Sign"]);
    expect(sign[0]).toMatchObject({
      Condition: {
        StringEquals: {
          "kms:SigningAlgorithm": "ECDSA_SHA_256"
        }
      },
      Sid: "SignOnlyGovernedMutationAuthorization"
    });
    expect(
      statements.filter((statement) =>
        actions(statement).includes("kms:GetPublicKey")
      )
    ).toHaveLength(1);
    expect(
      statements.some((statement) =>
        actions(statement).includes("kms:Verify")
      )
    ).toBe(false);

    const functions = Object.values(
      template.findResources("AWS::Lambda::Function")
    ) as any[];
    const byName = (name: string) =>
      functions.find(
        (fn) => fn.Properties.FunctionName === name
      );
    const readEnv =
      byName("archon-staging-cloud-read").Properties.Environment
        .Variables;
    const mutationEnv =
      byName("archon-staging-cloud-mutation").Properties.Environment
        .Variables;
    const resetEnv =
      byName("archon-staging-cloud-reset").Properties.Environment
        .Variables;
    expect(readEnv).toHaveProperty(
      "DATAHUB_CLOUD_READER_SECRET_ARN"
    );
    expect(readEnv).not.toHaveProperty(
      "DATAHUB_CLOUD_WRITER_SECRET_ARN"
    );
    expect(mutationEnv).toHaveProperty(
      "DATAHUB_CLOUD_WRITER_SECRET_ARN"
    );
    expect(mutationEnv).not.toHaveProperty(
      "DATAHUB_CLOUD_READER_SECRET_ARN"
    );
    expect(mutationEnv).not.toHaveProperty(
      "CLOUD_CHECKPOINT_BUCKET"
    );
    expect(resetEnv).toHaveProperty(
      "DATAHUB_CLOUD_WRITER_SECRET_ARN"
    );
    expect(resetEnv).not.toHaveProperty(
      "MUTATION_SIGNING_KEY_ARN"
    );
  });

  test("isolates four Cloud mappings and bounds poison retries", () => {
    const template = judgeTemplate();
    const mappings = Object.values(
      template.findResources(
        "AWS::Lambda::EventSourceMapping"
      )
    ) as any[];
    expect(mappings).toHaveLength(6);
    for (const mapping of mappings) {
      expect(mapping.Properties.StartingPosition).toBe("LATEST");
      expect(mapping.Properties.FunctionResponseTypes).toEqual([
        "ReportBatchItemFailures"
      ]);
      expect(
        mapping.Properties.DestinationConfig.OnFailure.Destination
      ).toBeDefined();
    }
    const cloudMappings = mappings.filter(
      (mapping) =>
        mapping.Properties.BisectBatchOnFunctionError === true
    );
    const remediationMappings = mappings.filter(
      (mapping) =>
        mapping.Properties.BisectBatchOnFunctionError === false
    );
    expect(cloudMappings).toHaveLength(4);
    expect(remediationMappings).toHaveLength(2);
    for (const mapping of cloudMappings) {
      expect(mapping.Properties.MaximumRetryAttempts).toBe(5);
      expect(mapping.Properties.MaximumRecordAgeInSeconds).toBe(3600);
    }
    expect(
      cloudMappings
        .map(
          (mapping) =>
            mapping.Properties.ScalingConfig?.MaximumConcurrency
        )
        .filter((value) => value !== undefined)
    ).toEqual([2]);
    for (const mapping of remediationMappings) {
      expect(mapping.Properties.MaximumRetryAttempts).toBe(3);
    }
    const filterPatterns = mappings.map((mapping) =>
      JSON.parse(
        mapping.Properties.FilterCriteria.Filters[0].Pattern
      )
    );
    const serialized = JSON.stringify(filterPatterns);
    expect(serialized).toContain(
      "archon.runtime-bound-job/v2"
    );
    expect(serialized).toContain("GOVERNED_TAG_MUTATION");
    expect(serialized).toContain("IMPROVE_CONTEXT");
    expect(serialized).toContain("CORE#LEASE");
    expect(serialized).toContain('"cloud"');
    expect(filterPatterns).toContainEqual({
      eventName: ["MODIFY"],
      dynamodb: {
        NewImage: {
          pk: { S: [{ prefix: "SESSION#rs_" }] },
          sk: { S: ["RUNTIME"] }
        }
      }
    });
  });

  test("uses private versioned KMS buckets and CloudFront OAC", () => {
    const template = judgeTemplate();
    const buckets = Object.values(
      template.findResources("AWS::S3::Bucket")
    ) as any[];
    expect(buckets).toHaveLength(2);
    for (const bucket of buckets) {
      expect(bucket.Properties.VersioningConfiguration).toEqual({
        Status: "Enabled"
      });
      const encryption =
        bucket.Properties.BucketEncryption
          .ServerSideEncryptionConfiguration;
      expect(encryption).toHaveLength(1);
      expect(encryption[0]).toMatchObject({
        BucketKeyEnabled: true,
        ServerSideEncryptionByDefault: {
          SSEAlgorithm: "aws:kms"
        }
      });
      expect(
        encryption[0].ServerSideEncryptionByDefault.KMSMasterKeyID
      ).toBeDefined();
      expect(bucket.Properties.PublicAccessBlockConfiguration).toEqual({
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true
      });
    }
    template.hasResourceProperties(
      "AWS::CloudFront::OriginAccessControl",
      {
        OriginAccessControlConfig: {
          OriginAccessControlOriginType: "s3",
          SigningBehavior: "always",
          SigningProtocol: "sigv4"
        }
      }
    );
  });

  test("forwards Authorization only through a zero-TTL API cache policy", () => {
    const template = judgeTemplate();
    const cachePolicies = Object.values(
      template.findResources("AWS::CloudFront::CachePolicy")
    ) as any[];
    const apiCache = cachePolicies.find(
      (policy) =>
        policy.Properties.CachePolicyConfig.Name ===
        "archon-staging-api-no-cache"
    );
    expect(apiCache).toBeDefined();
    expect(apiCache.Properties.CachePolicyConfig).toMatchObject({
      DefaultTTL: 0,
      MinTTL: 0,
      MaxTTL: 0
    });
    const cacheHeaders =
      apiCache.Properties.CachePolicyConfig
        .ParametersInCacheKeyAndForwardedToOrigin.HeadersConfig
        .Headers;
    expect(cacheHeaders.map((header: string) => header.toLowerCase()))
      .toEqual(["authorization"]);

    const originPolicies = Object.values(
      template.findResources(
        "AWS::CloudFront::OriginRequestPolicy"
      )
    ) as any[];
    const apiOrigin = originPolicies.find(
      (policy) =>
        policy.Properties.OriginRequestPolicyConfig.Name ===
        "archon-staging-api-origin"
    );
    expect(apiOrigin).toBeDefined();
    const originHeaders =
      apiOrigin.Properties.OriginRequestPolicyConfig.HeadersConfig
        .Headers.map((header: string) => header.toLowerCase());
    expect(originHeaders).toEqual(
      expect.arrayContaining(["accept", "content-type"])
    );
    expect(originHeaders).not.toContain("authorization");
  });

  test("binds Cognito, WAF and the canonical judge fixture", () => {
    const template = judgeTemplate();
    template.hasResourceProperties("AWS::Cognito::UserPool", {
      AdminCreateUserConfig: {
        AllowAdminCreateUserOnly: true
      },
      DeletionProtection: "ACTIVE",
      Policies: {
        PasswordPolicy: Match.objectLike({
          MinimumLength: 14,
          PasswordHistorySize: 24
        })
      }
    });
    template.hasResourceProperties(
      "AWS::Cognito::UserPoolGroup",
      { GroupName: "archon-runtime-operators" }
    );
    template.hasResourceProperties(
      "AWS::Cognito::UserPoolGroup",
      { GroupName: "archon-approvers" }
    );
    template.hasResourceProperties(
      "AWS::Cognito::UserPoolClient",
      {
        AllowedOAuthScopes: Match.arrayWith([
          "openid",
          "email",
          "profile"
        ])
      }
    );
    template.hasOutput("ArchonCanonicalDatasetUrn", {
      Value:
        "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
    });
    template.hasOutput("ArchonGovernedColumnPath", {
      Value: "customer_email"
    });
    template.hasOutput("ArchonCloudAnalyticsRoleArn", {});
    template.hasOutput("ArchonCloudReaderFunctionName", {});
    template.hasOutput("ArchonCloudReaderRoleArn", {});
    template.hasOutput("ArchonCloudMutationFunctionName", {});
    template.hasOutput("ArchonCloudFixtureResetFunctionName", {});
    template.hasOutput("ArchonCloudFixtureResetRoleArn", {});
    template.hasOutput("ArchonRuntimeMutationSigningKeyArn", {});
    template.hasOutput("ArchonCloudReaderSecretArn", {});
    template.hasOutput("ArchonCloudWriterSecretArn", {});
    template.hasOutput("ArchonCloudCheckpointKeyArn", {});
    template.hasOutput("ArchonSecretsKeyArn", {});
    template.hasOutput("ArchonLambdaArtifactSha256", {});
    template.hasOutput("ArchonCloudRuntimeReleaseDigest", {});
    template.hasOutput("ArchonCiRunId", {});
    template.hasOutput("ArchonDeploymentWorkflowRunId", {});
    template.hasOutput("ArchonAlarmTopicArn", {});
    template.hasOutput("ArchonAlarmProofQueueUrl", {});
    template.hasOutput("ArchonControlPlaneAlarmName", {});
    template.hasResourceProperties("AWS::CloudWatch::Alarm", {
      AlarmName: "archon-staging-control-plane-errors",
      AlarmActions: Match.anyValue(),
      OKActions: Match.anyValue()
    });
  });

  test("retains all Judge logs for one year and disables every WAF sample", () => {
    const template = judgeTemplate();
    const logGroups = Object.values(
      template.findResources("AWS::Logs::LogGroup")
    ) as any[];
    expect(logGroups).toHaveLength(8);
    for (const logGroup of logGroups) {
      expect(logGroup.Properties.KmsKeyId).toBeDefined();
      expect(logGroup.Properties.RetentionInDays).toBe(365);
    }

    const webAcls = Object.values(
      template.findResources("AWS::WAFv2::WebACL")
    ) as any[];
    expect(webAcls).toHaveLength(1);
    const visibility = [
      webAcls[0].Properties.VisibilityConfig,
      ...webAcls[0].Properties.Rules.map(
        (rule: any) => rule.VisibilityConfig
      )
    ];
    expect(visibility.length).toBeGreaterThan(1);
    for (const config of visibility) {
      expect(config.SampledRequestsEnabled).toBe(false);
    }

    const loggingConfigurations = Object.values(
      template.findResources("AWS::WAFv2::LoggingConfiguration")
    ) as any[];
    expect(loggingConfigurations).toHaveLength(1);
    const loggingFilter =
      loggingConfigurations[0].Properties.LoggingFilter;
    expect(loggingFilter).toEqual({
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
    });
    expect(loggingFilter).not.toHaveProperty("defaultBehavior");
    expect(loggingFilter).not.toHaveProperty("filters");
  });

  test("pins the Cloud image to account, region and digest", () => {
    const template = judgeTemplate().toJSON();
    const allowedPattern =
      template.Parameters.CloudRuntimeImageUri.AllowedPattern;
    expect(allowedPattern).toContain(
      "^123456789012\\.dkr\\.ecr\\.eu-west-1\\.amazonaws\\.com"
    );
    expect(allowedPattern).toContain("@sha256:[a-f0-9]{64}$");
    expect(JSON.stringify(template.Rules ?? {})).not.toContain(
      "Fn::Split"
    );
  });
});
