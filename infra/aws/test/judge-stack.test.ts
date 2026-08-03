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
  test("rejects an unsupported deployment stage", () => {
    const app = new App();
    expect(
      () =>
        new ArchonJudgeStack(
          app,
          "Archon-Unsupported-Judge-Test",
          {
            stage: "development" as any,
            env: {
              account: "123456789012",
              region: "eu-west-1"
            }
          }
        )
    ).toThrow(
      "ArchonJudgeStack stage must be staging or production"
    );
  });

  test("rejects unresolved deployment account and region", () => {
    const app = new App();
    expect(
      () =>
        new ArchonJudgeStack(
          app,
          "Archon-Unresolved-Judge-Test",
          { stage: "staging" }
        )
    ).toThrow(
      "ArchonJudgeStack requires an explicit AWS account and region"
    );
  });
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
    template.resourceCountIs("AWS::S3::Bucket", 4);
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

  test("scopes Cloud stream discovery and exact EU Bedrock inference", () => {
    const template = judgeTemplate();
    const statements = Object.values(
      template.findResources("AWS::IAM::Policy")
    ).flatMap(
      (policy: any) =>
        policy.Properties.PolicyDocument.Statement ?? []
    );
    const actions = (statement: any): string[] =>
      Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action];

    const inventories = statements.filter(
      (statement) =>
        actions(statement).includes("dynamodb:ListStreams") &&
        typeof statement.Sid === "string" &&
        statement.Sid.endsWith("StreamInventory")
    );
    expect(inventories).toHaveLength(4);
    for (const statement of inventories) {
      expect(statement.Resource).toBe("*");
      expect(JSON.stringify(statement.Condition)).toContain(
        "aws:RequestedRegion"
      );
    }
    const streamReads = statements.filter(
      (statement) =>
        actions(statement).includes("dynamodb:GetRecords") &&
        typeof statement.Sid === "string" &&
        statement.Sid.endsWith("Stream")
    );
    expect(streamReads).toHaveLength(4);
    for (const statement of streamReads) {
      expect(statement.Resource).not.toBe("*");
      expect(actions(statement)).not.toContain(
        "dynamodb:ListStreams"
      );
    }

    const profile = statements.find(
      (statement) =>
        statement.Sid === "InvokeOnlyReviewedAnalyticsProfile"
    );
    const models = statements.find(
      (statement) =>
        statement.Sid ===
        "InvokeReviewedModelsOnlyThroughAnalyticsProfile"
    );
    expect(profile).toBeDefined();
    expect(models).toBeDefined();
    expect(JSON.stringify(profile.Resource)).toContain(
      "inference-profile/eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
    );
    expect(JSON.stringify(models.Resource)).toContain(
      "foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0"
    );
    expect(JSON.stringify(models.Condition)).toContain(
      "bedrock:InferenceProfileArn"
    );
    expect(JSON.stringify([profile, models])).not.toContain(
      "application-inference-profile"
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

  test("logs through KMS CloudFront storage into one terminal sink", () => {
    const template = judgeTemplate();
    const bucketEntries = Object.entries(
      template.findResources("AWS::S3::Bucket")
    ) as [string, any][];
    expect(bucketEntries).toHaveLength(4);
    expect(
      bucketEntries
        .map(([, bucket]) => bucket.Properties.BucketName)
        .sort()
    ).toEqual([
      "archon-staging-access-logs-123456789012-eu-west-1",
      "archon-staging-cloud-checkpoints-123456789012-eu-west-1",
      "archon-staging-cloudfront-logs-123456789012-eu-west-1",
      "archon-staging-spa-123456789012-eu-west-1"
    ]);
    const productionBuckets = Object.values(
      judgeTemplate("production").findResources("AWS::S3::Bucket")
    ) as any[];
    expect(
      productionBuckets
        .map((bucket) => bucket.Properties.BucketName)
        .sort()
    ).toEqual([
      "archon-production-access-logs-123456789012-eu-west-1",
      "archon-production-cloud-checkpoints-123456789012-eu-west-1",
      "archon-production-cloudfront-logs-123456789012-eu-west-1",
      "archon-production-spa-123456789012-eu-west-1"
    ]);

    const [accessLogLogicalId, accessLogBucket] =
      bucketEntries.find(([, bucket]) =>
        bucket.Properties.BucketName.includes("-access-logs-")
      )!;
    expect(accessLogBucket.Properties.AccessControl)
      .toBe("LogDeliveryWrite");
    expect(accessLogBucket.Properties.LoggingConfiguration)
      .toBeUndefined();
    expect(accessLogBucket.Properties.OwnershipControls).toEqual({
      Rules: [{ ObjectOwnership: "ObjectWriter" }]
    });
    expect(accessLogBucket.Properties.VersioningConfiguration)
      .toEqual({ Status: "Enabled" });
    expect(
      accessLogBucket.Properties.BucketEncryption
        .ServerSideEncryptionConfiguration
    ).toEqual([
      {
        ServerSideEncryptionByDefault: {
          SSEAlgorithm: "AES256"
        }
      }
    ]);
    expect(accessLogBucket.Properties.LifecycleConfiguration.Rules)
      .toEqual([
        expect.objectContaining({
          AbortIncompleteMultipartUpload: {
            DaysAfterInitiation: 1
          },
          ExpirationInDays: 30,
          NoncurrentVersionExpiration: {
            NoncurrentDays: 7
          },
          Status: "Enabled"
        })
      ]);
    expect(accessLogBucket.Properties.Tags).toEqual(
      expect.arrayContaining([
        {
          Key: "SecurityProfile",
          Value: "terminal-access-log-sink"
        }
      ])
    );

    const [cloudFrontLogLogicalId, cloudFrontLogBucket] =
      bucketEntries.find(([, bucket]) =>
        bucket.Properties.BucketName.includes("-cloudfront-logs-")
      )!;
    expect(cloudFrontLogBucket.Properties.OwnershipControls)
      .toEqual({ Rules: [{ ObjectOwnership: "ObjectWriter" }] });
    expect(cloudFrontLogBucket.Properties.LoggingConfiguration)
      .toEqual({
        DestinationBucketName: { Ref: accessLogLogicalId },
        LogFilePrefix: "staging/s3/cloudfront-log-bucket/"
      });
    const cloudFrontEncryption =
      cloudFrontLogBucket.Properties.BucketEncryption
        .ServerSideEncryptionConfiguration;
    expect(cloudFrontEncryption).toHaveLength(1);
    expect(cloudFrontEncryption[0]).toMatchObject({
      BucketKeyEnabled: true,
      ServerSideEncryptionByDefault: {
        SSEAlgorithm: "aws:kms",
        KMSMasterKeyID: expect.any(Object)
      }
    });
    expect(cloudFrontLogBucket.Properties.Tags).toEqual(
      expect.arrayContaining([
        {
          Key: "SecurityProfile",
          Value: "cloudfront-access-log-bucket"
        }
      ])
    );

    const sourceBuckets = bucketEntries.filter(
      ([logicalId]) =>
        ![
          accessLogLogicalId,
          cloudFrontLogLogicalId
        ].includes(logicalId)
    );
    expect(
      sourceBuckets
        .map(([, bucket]) => {
          const logging = bucket.Properties.LoggingConfiguration;
          expect(logging.DestinationBucketName).toEqual({
            Ref: accessLogLogicalId
          });
          expect(
            bucket.Properties.BucketEncryption
              .ServerSideEncryptionConfiguration[0]
              .ServerSideEncryptionByDefault.SSEAlgorithm
          ).toBe("aws:kms");
          return logging.LogFilePrefix;
        })
        .sort()
    ).toEqual([
      "staging/s3/cloud-checkpoints/",
      "staging/s3/spa/"
    ]);

    for (const [, bucket] of bucketEntries) {
      expect(bucket.Properties.PublicAccessBlockConfiguration).toEqual({
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true
      });
    }
    const distributions = Object.values(
      template.findResources("AWS::CloudFront::Distribution")
    ) as any[];
    expect(distributions).toHaveLength(1);
    const logging =
      distributions[0].Properties.DistributionConfig.Logging;
    expect(logging).toEqual(
      expect.objectContaining({
        IncludeCookies: false,
        Prefix: "staging/cloudfront/"
      })
    );
    expect(JSON.stringify(logging)).toContain(
      cloudFrontLogLogicalId
    );
    expect(JSON.stringify(logging)).not.toContain(
      accessLogLogicalId
    );

    const keys = Object.values(
      template.findResources("AWS::KMS::Key")
    ) as any[];
    const deliveryStatements = keys.flatMap((key) =>
      key.Properties.KeyPolicy.Statement.filter(
        (statement: any) =>
          statement.Sid ===
            "AllowExactCloudFrontStandardLogDelivery"
      )
    );
    expect(deliveryStatements).toHaveLength(1);
    expect(deliveryStatements[0]).toMatchObject({
      Effect: "Allow",
      Principal: {
        Service: "delivery.logs.amazonaws.com"
      },
      Resource: "*"
    });
    expect(deliveryStatements[0].Action.sort()).toEqual([
      "kms:Decrypt",
      "kms:GenerateDataKey*"
    ]);

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

    const redactedFields =
      loggingConfigurations[0].Properties.RedactedFields;
    expect(redactedFields).toEqual([
      { SingleHeader: { Name: "authorization" } },
      { SingleHeader: { Name: "cookie" } },
      { SingleHeader: { Name: "x-api-key" } }
    ]);
    for (const field of redactedFields) {
      expect(field).not.toHaveProperty("singleHeader");
      expect(field.SingleHeader).not.toHaveProperty("name");
    }
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
