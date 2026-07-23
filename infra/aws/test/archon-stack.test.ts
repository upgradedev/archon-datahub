import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
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

  test("keeps SPA and evidence private, encrypted, versioned, and retained", () => {
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
  });

  test("serves the private SPA through CloudFront OAC and routes same-origin API", () => {
    const { platform } = templates();
    platform.resourceCountIs("AWS::CloudFront::OriginAccessControl", 1);
    platform.hasResourceProperties("AWS::CloudFront::Distribution", {
      DistributionConfig: Match.objectLike({
        DefaultRootObject: "index.html",
        HttpVersion: "http2and3",
        Enabled: true,
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
    const distribution = Object.values(
      platform.findResources("AWS::CloudFront::Distribution")
    )[0] as any;
    const runtimeConfigBehavior =
      distribution.Properties.DistributionConfig.CacheBehaviors.find(
        (behavior: any) => behavior.PathPattern === "runtime-config.json"
      );
    expect(runtimeConfigBehavior).toEqual(
      expect.objectContaining({
        CachePolicyId: "413f1605-6b67-4c00-958e-290d4c248f7f",
        ViewerProtocolPolicy: "https-only",
        Compress: true
      })
    );
    expect(runtimeConfigBehavior.TargetOriginId).toEqual(
      distribution.Properties.DistributionConfig.DefaultCacheBehavior
        .TargetOriginId
    );
  });

  test("keeps audit public but makes the strict approval contract Cognito-only", () => {
    const { platform } = templates();
    platform.resourceCountIs("AWS::Cognito::UserPool", 1);
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
      AllowedOAuthScopes: ["openid", "email", "archon/approve"],
      CallbackURLs: [Match.anyValue()],
      LogoutURLs: [Match.anyValue()],
      SupportedIdentityProviders: ["COGNITO"]
    });

    const client = Object.values(
      platform.findResources("AWS::Cognito::UserPoolClient")
    )[0] as any;
    expect(JSON.stringify(client.Properties.CallbackURLs)).toContain(
      "Distribution"
    );
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
    expect(JSON.stringify(outputs.ArchonAuthRedirectUri.Value)).toContain(
      "Distribution"
    );
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
    for (const queueName of [
      "archon-staging-audit-jobs",
      "archon-staging-remediation-jobs"
    ]) {
      platform.hasResourceProperties("AWS::SQS::Queue", {
        QueueName: queueName,
        VisibilityTimeout: 300
      });
    }
    platform.resourceCountIs("AWS::DynamoDB::Table", 2);
    platform.hasResourceProperties("AWS::DynamoDB::Table", {
      BillingMode: "PAY_PER_REQUEST",
      DeletionProtectionEnabled: true,
      PointInTimeRecoverySpecification: {
        PointInTimeRecoveryEnabled: true
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
    const policies = JSON.stringify(platform.findResources("AWS::IAM::Policy"));
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
    for (const functionName of [
      "archon-staging-approval-handoff",
      "archon-staging-approval"
    ]) {
      const lambdaFunction = lambdaFunctions.find(
        (resource) => resource.Properties.FunctionName === functionName
      );
      expect(lambdaFunction).toBeDefined();
      const roleLogicalId = lambdaFunction.Properties.Role["Fn::GetAtt"][0];
      const roleActions = iamPolicies
        .filter((policy) =>
          (policy.Properties.Roles ?? []).some(
            (role: any) => role.Ref === roleLogicalId
          )
        )
        .flatMap((policy) => {
          const statements = policy.Properties.PolicyDocument.Statement;
          return (Array.isArray(statements) ? statements : [statements]).flatMap(
            (statement: any) =>
              Array.isArray(statement.Action)
                ? statement.Action
                : [statement.Action]
          );
        });
      expect(roleActions.filter((action) => action?.startsWith("kms:"))).toEqual([]);
    }
  });

  test("has private Fargate services, WAF, observability, and stable outputs", () => {
    const { platform } = templates();
    platform.resourceCountIs("AWS::ECS::Service", 3);
    const services = Object.values(platform.findResources("AWS::ECS::Service")) as any[];
    for (const service of services) {
      expect(
        service.Properties.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp
      ).toBe("DISABLED");
    }
    platform.resourceCountIs("AWS::WAFv2::WebACL", 1);
    platform.resourceCountIs("AWS::CloudWatch::Alarm", 10);
    platform.resourceCountIs("AWS::CloudWatch::Dashboard", 1);

    for (const outputName of [
      "ArchonSpaBucketName",
      "ArchonEvidenceBucketName",
      "ArchonCloudFrontDistributionId",
      "ArchonCloudFrontDomainName",
      "ArchonApplicationUrl",
      "ArchonApiUrl",
      "ArchonApiInvokeUrl",
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
});
