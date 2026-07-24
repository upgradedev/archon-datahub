import {
  ArnFormat,
  Aws,
  CfnOutput,
  CfnParameter,
  CfnResource,
  CfnRule,
  CustomResourceProviderBase,
  Duration,
  Fn,
  RemovalPolicy,
  Size,
  Stack,
  type StackProps,
  Tags
} from "aws-cdk-lib";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as appscaling from "aws-cdk-lib/aws-applicationautoscaling";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatchActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as logs from "aws-cdk-lib/aws-logs";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as sns from "aws-cdk-lib/aws-sns";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as sfn from "aws-cdk-lib/aws-stepfunctions";
import * as tasks from "aws-cdk-lib/aws-stepfunctions-tasks";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import { Construct } from "constructs";
import { join } from "node:path";

// CloudFormation config scanners resolve parameter Refs from Default. This sentinel
// keeps the exact deploy template analyzable, while the unconditional Rule below
// rejects it before any create/update unless the edge stack's live ARN is supplied.
const REQUIRED_CLOUDFRONT_WEB_ACL_ARN =
  "arn:aws:wafv2:us-east-1:000000000000:global/webacl/required-override/00000000-0000-0000-0000-000000000000";

export class ArchonRegistryStack extends Stack {
  readonly repository: ecr.Repository;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const registryKey = new kms.Key(this, "RegistryKey", {
      alias: "alias/archon/ecr",
      description: "KMS key for immutable Archon container images",
      enableKeyRotation: true,
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN
    });

    this.repository = new ecr.Repository(this, "Repository", {
      repositoryName: "archon-datahub",
      encryption: ecr.RepositoryEncryption.KMS,
      encryptionKey: registryKey,
      imageScanOnPush: true,
      imageTagMutability: ecr.TagMutability.IMMUTABLE,
      emptyOnDelete: false,
      lifecycleRules: [
        {
          description: "Keep the latest 100 promoted release images",
          maxImageCount: 100,
          rulePriority: 1,
          tagStatus: ecr.TagStatus.ANY
        }
      ],
      removalPolicy: RemovalPolicy.RETAIN
    });

    new CfnOutput(this, "ArchonEcrRepositoryUri", {
      value: this.repository.repositoryUri,
      description: "Push the build-once image here, then deploy every stage by its digest"
    });
    new CfnOutput(this, "ArchonEcrRepositoryName", {
      value: this.repository.repositoryName
    });
    new CfnOutput(this, "ArchonEcrRepositoryArn", {
      value: this.repository.repositoryArn
    });
  }
}

export interface ArchonPlatformStackProps extends StackProps {
  readonly stage: string;
  readonly repository: ecr.IRepository;
}

export class ArchonPlatformStack extends Stack {
  public override get availabilityZones(): string[] {
    // The base Stack getter performs an account/region context lookup for
    // concrete environments. This stack intentionally selects two AZs at
    // deploy time so credential-free CI and real deployments synthesize the
    // same template without cached environmental context.
    return [
      Fn.select(0, Fn.getAzs()),
      Fn.select(1, Fn.getAzs())
    ];
  }

  constructor(scope: Construct, id: string, props: ArchonPlatformStackProps) {
    super(scope, id, props);

    const { stage, repository } = props;
    const isProduction = stage === "prod" || stage === "production";
    const imageDigest = new CfnParameter(this, "ImageDigest", {
      type: "String",
      description: "Immutable ECR digest produced once by CI (sha256:...)",
      allowedPattern: "^sha256:[a-f0-9]{64}$",
      constraintDescription: "must be a sha256 ECR image digest"
    });
    const spaArtifactSha256 = new CfnParameter(this, "SpaArtifactSha256", {
      type: "String",
      description: "SHA-256 of the build-once SPA archive promoted to this environment",
      allowedPattern: "^[a-f0-9]{64}$",
      constraintDescription: "must be a lowercase 64-character SHA-256"
    });
    const releaseSha = new CfnParameter(this, "ReleaseSha", {
      type: "String",
      description: "Source commit represented by ImageDigest and SpaArtifactSha256",
      allowedPattern: "^[a-f0-9]{7,64}$"
    });
    const cloudFrontDomainName = new CfnParameter(
      this,
      "CloudFrontDomainName",
      {
        type: "String",
        description:
          "Environment-specific DNS name covered by the CloudFront ACM certificate",
        minLength: 4,
        maxLength: 253,
        allowedPattern:
          "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$",
        constraintDescription: "must be a valid fully qualified DNS name"
      }
    );
    const cloudFrontCertificateArn = new CfnParameter(
      this,
      "CloudFrontCertificateArn",
      {
        type: "String",
        description:
          "ACM certificate ARN in us-east-1 covering CloudFrontDomainName",
        allowedPattern:
          "^arn:aws:acm:us-east-1:[0-9]{12}:certificate/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        constraintDescription:
          "must be an ACM certificate ARN from us-east-1 in the standard AWS partition"
      }
    );
    const cloudFrontHostedZoneId = new CfnParameter(
      this,
      "CloudFrontHostedZoneId",
      {
        type: "String",
        description:
          "Route 53 public hosted-zone ID that owns CloudFrontDomainName",
        allowedPattern: "^Z[A-Z0-9]{1,31}$",
        constraintDescription:
          "must be a Route 53 hosted-zone ID without the /hostedzone/ prefix"
      }
    );
    const cloudFrontWebAclArn = new CfnParameter(
      this,
      "CloudFrontWebAclArn",
      {
        type: "String",
        description:
          "CLOUDFRONT-scope WAFv2 Web ACL ARN created by the us-east-1 Archon edge stack",
        default: REQUIRED_CLOUDFRONT_WEB_ACL_ARN,
        allowedPattern:
          "^arn:aws:wafv2:us-east-1:[0-9]{12}:global/webacl/[A-Za-z0-9_-]{1,128}/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        constraintDescription:
          "must be a CLOUDFRONT-scope WAFv2 Web ACL ARN from us-east-1"
      }
    );
    const requireCloudFrontWebAclOverride = new CfnRule(
      this,
      "RequireCloudFrontWebAclOverride",
      {
        assertions: [
          {
            assert: Fn.conditionNot(
              Fn.conditionEquals(
                cloudFrontWebAclArn.valueAsString,
                REQUIRED_CLOUDFRONT_WEB_ACL_ARN
              )
            ),
            assertDescription:
              "CloudFrontWebAclArn must be overridden with the deployed Archon edge-stack Web ACL ARN"
          }
        ]
      }
    );
    requireCloudFrontWebAclOverride.overrideLogicalId(
      "RequireCloudFrontWebAclOverride"
    );
    const s3PrefixListId = prefixListIdParameter(
      this,
      "S3PrefixListId",
      "AWS-managed regional S3 prefix list used by the gateway endpoint"
    );
    const dynamoDbPrefixListId = prefixListIdParameter(
      this,
      "DynamoDbPrefixListId",
      "AWS-managed regional DynamoDB prefix list used by the gateway endpoint"
    );
    const dataHubReadEgressPrefixListId = prefixListIdParameter(
      this,
      "DataHubReadEgressPrefixListId",
      "Customer-managed CIDR allowlist for read-only DataHub GMS and MCP endpoints"
    );
    const dataHubWriteEgressPrefixListId = prefixListIdParameter(
      this,
      "DataHubWriteEgressPrefixListId",
      "Customer-managed CIDR allowlist for write-enabled DataHub GMS and MCP endpoints"
    );
    const llmEgressPrefixListId = prefixListIdParameter(
      this,
      "LlmEgressPrefixListId",
      "Customer-managed CIDR allowlist for the configured inference endpoint"
    );
    const dataHubReadUrl = httpsUrlParameter(
      this,
      "DataHubReadGmsUrl",
      "Read-only DataHub GMS URL used for retained aspect-version reads"
    );
    const dataHubReadMcpUrl = httpsUrlParameter(
      this,
      "DataHubReadMcpUrl",
      "Hosted read-only DataHub MCP Streamable HTTP endpoint"
    );
    const dataHubWriteUrl = httpsUrlParameter(
      this,
      "DataHubWriteGmsUrl",
      "Write-enabled DataHub GMS/MCP gateway URL; worker only"
    );
    const dataHubWriteMcpUrl = httpsUrlParameter(
      this,
      "DataHubWriteMcpUrl",
      "Hosted mutation-enabled DataHub MCP Streamable HTTP endpoint; worker only"
    );
    const llmBaseUrl = httpsUrlParameter(
      this,
      "LlmBaseUrl",
      "OpenAI-compatible inference endpoint",
      "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
    );
    const llmModel = new CfnParameter(this, "LlmModel", {
      type: "String",
      default: "qwen-plus",
      minLength: 1,
      maxLength: 128,
      allowedPattern: "^[A-Za-z0-9._:/-]+$"
    });
    const workerDesiredCount = new CfnParameter(this, "WorkerDesiredCount", {
      type: "Number",
      default: 0,
      minValue: 0,
      maxValue: 1,
      description:
        "Bootstrap at 0; set to 1 only for a tested image to activate both isolated workers and their autoscaling floor"
    });

    const dataKey = retainedKey(this, "DataKey", `alias/archon/${stage}/data`);
    const spaKey = retainedKey(this, "SpaKey", `alias/archon/${stage}/spa`);
    const logsKey = retainedKey(this, "LogsKey", `alias/archon/${stage}/logs`);
    grantCloudWatchLogsKeyAccess(this, logsKey, [
      `/archon/${stage}/*`,
      `aws-waf-logs-archon-${stage}-api`
    ]);
    const queueKey = retainedKey(this, "QueueKey", `alias/archon/${stage}/queues`);
    const secretsKey = retainedKey(this, "SecretsKey", `alias/archon/${stage}/secrets`);

    const vpc = new ec2.Vpc(this, "Vpc", {
      ipAddresses: ec2.IpAddresses.cidr("10.42.0.0/16"),
      maxAzs: 2,
      natGateways: isProduction ? 2 : 1,
      restrictDefaultSecurityGroup: true,
      subnetConfiguration: [
        {
          name: "public-ingress",
          subnetType: ec2.SubnetType.PUBLIC,
          mapPublicIpOnLaunch: false,
          cidrMask: 24
        },
        {
          name: "private-workload",
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 22
        },
        {
          name: "isolated-data",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 24
        }
      ]
    });
    const defaultSecurityGroupProvider = this.node.tryFindChild(
      "Custom::VpcRestrictDefaultSGCustomResourceProvider"
    );
    if (!(defaultSecurityGroupProvider instanceof CustomResourceProviderBase)) {
      throw new Error("CDK default-security-group restriction provider was not created");
    }
    defaultSecurityGroupProvider.addToRolePolicy({
      Effect: "Allow",
      Action: ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
      Resource: "*"
    });
    const defaultSecurityGroupHandler =
      defaultSecurityGroupProvider.node.tryFindChild("Handler");
    if (!(defaultSecurityGroupHandler instanceof CfnResource)) {
      throw new Error("CDK default-security-group restriction handler was not created");
    }
    defaultSecurityGroupHandler.addPropertyOverride("TracingConfig", {
      Mode: "Active"
    });

    const apiSecurityGroup = workloadSecurityGroup(
      this,
      "ApiSecurityGroup",
      vpc,
      "Only the private NLB security group reaches the Archon API"
    );
    const nlbSecurityGroup = workloadSecurityGroup(
      this,
      "NlbSecurityGroup",
      vpc,
      "Identity boundary for the API Gateway VPC Link network load balancer"
    );
    const auditWorkerSecurityGroup = workloadSecurityGroup(
      this,
      "AuditWorkerSecurityGroup",
      vpc,
      "Read-only audit worker has no inbound path"
    );
    const remediationWorkerSecurityGroup = workloadSecurityGroup(
      this,
      "RemediationWorkerSecurityGroup",
      vpc,
      "Write-capable remediation worker has no inbound path"
    );
    const vpcEndpointSecurityGroup = workloadSecurityGroup(
      this,
      "VpcEndpointSecurityGroup",
      vpc,
      "Shared stateful ingress boundary for AWS PrivateLink endpoints"
    );
    for (const workloadGroup of [
      apiSecurityGroup,
      auditWorkerSecurityGroup,
      remediationWorkerSecurityGroup
    ]) {
      workloadGroup.connections.allowTo(
        vpcEndpointSecurityGroup,
        ec2.Port.tcp(443),
        "AWS PrivateLink HTTPS"
      );
      workloadGroup.addEgressRule(
        ec2.Peer.prefixList(s3PrefixListId.valueAsString),
        ec2.Port.tcp(443),
        "S3 gateway endpoint and ECR image layers"
      );
    }
    for (const workerGroup of [
      auditWorkerSecurityGroup,
      remediationWorkerSecurityGroup
    ]) {
      workerGroup.addEgressRule(
        ec2.Peer.prefixList(dynamoDbPrefixListId.valueAsString),
        ec2.Port.tcp(443),
        "DynamoDB gateway endpoint"
      );
    }
    for (const readGroup of [apiSecurityGroup, auditWorkerSecurityGroup]) {
      readGroup.addEgressRule(
        ec2.Peer.prefixList(dataHubReadEgressPrefixListId.valueAsString),
        ec2.Port.tcp(443),
        "Allowlisted read-only DataHub endpoints"
      );
      readGroup.addEgressRule(
        ec2.Peer.prefixList(llmEgressPrefixListId.valueAsString),
        ec2.Port.tcp(443),
        "Allowlisted inference endpoint"
      );
    }
    remediationWorkerSecurityGroup.addEgressRule(
      ec2.Peer.prefixList(dataHubWriteEgressPrefixListId.valueAsString),
      ec2.Port.tcp(443),
      "Allowlisted write-enabled DataHub endpoints"
    );

    vpc.addGatewayEndpoint("S3Endpoint", {
      service: ec2.GatewayVpcEndpointAwsService.S3
    });
    vpc.addGatewayEndpoint("DynamoDbEndpoint", {
      service: ec2.GatewayVpcEndpointAwsService.DYNAMODB
    });
    for (const [name, service] of [
      ["EcrApiEndpoint", ec2.InterfaceVpcEndpointAwsService.ECR],
      ["EcrDockerEndpoint", ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER],
      ["LogsEndpoint", ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS],
      ["KmsEndpoint", ec2.InterfaceVpcEndpointAwsService.KMS],
      ["SecretsEndpoint", ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER],
      ["SqsEndpoint", ec2.InterfaceVpcEndpointAwsService.SQS],
      ["StatesEndpoint", ec2.InterfaceVpcEndpointAwsService.STEP_FUNCTIONS]
    ] as const) {
      vpc.addInterfaceEndpoint(name, {
        service,
        open: false,
        privateDnsEnabled: true,
        securityGroups: [vpcEndpointSecurityGroup],
        subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }
      });
    }

    const flowLogGroup = retainedLogGroup(
      this,
      "VpcFlowLogs",
      `/archon/${stage}/vpc-flow`,
      logsKey
    );
    vpc.addFlowLog("RejectedTraffic", {
      destination: ec2.FlowLogDestination.toCloudWatchLogs(flowLogGroup),
      trafficType: ec2.FlowLogTrafficType.REJECT
    });

    const cloudFrontLogBucket = new s3.Bucket(this, "CloudFrontLogBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      objectOwnership: s3.ObjectOwnership.OBJECT_WRITER,
      accessControl: s3.BucketAccessControl.LOG_DELIVERY_WRITE,
      versioned: true,
      lifecycleRules: [
        {
          expiration: Duration.days(400),
          noncurrentVersionExpiration: Duration.days(30)
        }
      ],
      removalPolicy: RemovalPolicy.RETAIN,
      autoDeleteObjects: false
    });
    Tags.of(cloudFrontLogBucket).add(
      "ArchonBucketRole",
      "access-log-sink"
    );
    Tags.of(cloudFrontLogBucket).add("ArchonBucketPurpose", "access-logs");

    const spaBucket = new s3.Bucket(this, "SpaBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: spaKey,
      bucketKeyEnabled: true,
      enforceSSL: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      versioned: true,
      serverAccessLogsBucket: cloudFrontLogBucket,
      serverAccessLogsPrefix: "s3-access/spa/",
      lifecycleRules: [
        {
          noncurrentVersionTransitions: [
            {
              storageClass: s3.StorageClass.INFREQUENT_ACCESS,
              transitionAfter: Duration.days(30)
            }
          ]
        }
      ],
      removalPolicy: RemovalPolicy.RETAIN,
      autoDeleteObjects: false
    });
    Tags.of(spaBucket).add("ArchonBucketRole", "application");
    Tags.of(spaBucket).add("ArchonBucketPurpose", "spa");
    Tags.of(spaBucket).add("ArtifactSha256", spaArtifactSha256.valueAsString);

    const evidenceBucket = new s3.Bucket(this, "EvidenceBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: dataKey,
      bucketKeyEnabled: true,
      enforceSSL: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      versioned: true,
      serverAccessLogsBucket: cloudFrontLogBucket,
      serverAccessLogsPrefix: "s3-access/evidence/",
      objectLockEnabled: true,
      objectLockDefaultRetention: s3.ObjectLockRetention.governance(Duration.days(30)),
      lifecycleRules: [
        {
          transitions: [
            {
              storageClass: s3.StorageClass.GLACIER_INSTANT_RETRIEVAL,
              transitionAfter: Duration.days(90)
            }
          ],
          noncurrentVersionTransitions: [
            {
              storageClass: s3.StorageClass.GLACIER,
              transitionAfter: Duration.days(90)
            }
          ]
        }
      ],
      removalPolicy: RemovalPolicy.RETAIN,
      autoDeleteObjects: false
    });
    Tags.of(evidenceBucket).add("ArchonBucketRole", "application");
    Tags.of(evidenceBucket).add("ArchonBucketPurpose", "evidence");

    const approvalTable = retainedTable(this, "ApprovalTable", `${stage}-approvals`, dataKey);
    const idempotencyTable = retainedTable(
      this,
      "IdempotencyTable",
      `${stage}-idempotency`,
      dataKey
    );

    const readSecret = bootstrapSecret(
      this,
      "DataHubReadSecret",
      `archon/${stage}/datahub-read`,
      "Read-only DataHub token",
      secretsKey
    );
    const writeSecret = bootstrapSecret(
      this,
      "DataHubWriteSecret",
      `archon/${stage}/datahub-write`,
      "Write-enabled DataHub token; never granted to the API task",
      secretsKey
    );
    const llmSecret = bootstrapSecret(
      this,
      "LlmSecret",
      `archon/${stage}/llm`,
      "Inference provider API key",
      secretsKey,
      "apiKey"
    );

    const auditDlq = encryptedQueue(this, "AuditDlq", `${stage}-audit-dlq`, queueKey, {
      retentionPeriod: Duration.days(14)
    });
    const approvalDlq = encryptedQueue(
      this,
      "ApprovalDlq",
      `${stage}-approval-dlq`,
      queueKey,
      { retentionPeriod: Duration.days(14) }
    );
    const remediationDlq = encryptedQueue(
      this,
      "RemediationDlq",
      `${stage}-remediation-dlq`,
      queueKey,
      { retentionPeriod: Duration.days(14) }
    );
    const auditQueue = encryptedQueue(this, "AuditQueue", `${stage}-audit-jobs`, queueKey, {
      retentionPeriod: Duration.days(14),
      visibilityTimeout: Duration.minutes(5),
      deadLetterQueue: { queue: auditDlq, maxReceiveCount: 5 }
    });
    const approvalQueue = encryptedQueue(
      this,
      "ApprovalQueue",
      `${stage}-approval-events`,
      queueKey,
      {
        retentionPeriod: Duration.days(14),
        visibilityTimeout: Duration.minutes(5),
        deadLetterQueue: { queue: approvalDlq, maxReceiveCount: 5 }
      }
    );
    const remediationQueue = encryptedQueue(
      this,
      "RemediationQueue",
      `${stage}-remediation-jobs`,
      queueKey,
      {
        retentionPeriod: Duration.days(14),
        visibilityTimeout: Duration.minutes(5),
        deadLetterQueue: { queue: remediationDlq, maxReceiveCount: 5 }
      }
    );

    const cluster = new ecs.Cluster(this, "Cluster", {
      vpc,
      containerInsightsV2: ecs.ContainerInsights.ENABLED,
      enableFargateCapacityProviders: true
    });
    // An unresolved parameter cannot be classified as a tag vs digest by
    // ContainerImage.fromEcrRepository(), so construct the digest URI explicitly.
    const image = ecs.ContainerImage.fromRegistry(
      Fn.join("", [repository.repositoryUri, "@", imageDigest.valueAsString])
    );

    const apiLogGroup = retainedLogGroup(
      this,
      "ApiContainerLogs",
      `/archon/${stage}/api`,
      logsKey
    );
    const auditWorkerLogGroup = retainedLogGroup(
      this,
      "AuditWorkerContainerLogs",
      `/archon/${stage}/audit-worker`,
      logsKey
    );
    const remediationWorkerLogGroup = retainedLogGroup(
      this,
      "RemediationWorkerContainerLogs",
      `/archon/${stage}/remediation-worker`,
      logsKey
    );
    const apiTaskDefinition = new ecs.FargateTaskDefinition(this, "ApiTaskDefinition", {
      cpu: 512,
      memoryLimitMiB: 1024,
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.X86_64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX
      }
    });
    const apiContainer = apiTaskDefinition.addContainer("Api", {
      image,
      readonlyRootFilesystem: true,
      user: "1000",
      logging: ecs.LogDrivers.awsLogs({
        logGroup: apiLogGroup,
        streamPrefix: "api",
        mode: ecs.AwsLogDriverMode.NON_BLOCKING,
        maxBufferSize: Size.mebibytes(4)
      }),
      environment: {
        NODE_ENV: "production",
        PORT: "8080",
        ARCHON_RELEASE_SHA: releaseSha.valueAsString,
        DATAHUB_GMS_URL: dataHubReadUrl.valueAsString,
        DATAHUB_MCP_URL: dataHubReadMcpUrl.valueAsString,
        LLM_BASE_URL: llmBaseUrl.valueAsString,
        LLM_MODEL: llmModel.valueAsString
      },
      secrets: {
        DATAHUB_GMS_TOKEN: ecs.Secret.fromSecretsManager(readSecret, "token"),
        LLM_API_KEY: ecs.Secret.fromSecretsManager(llmSecret, "apiKey")
      },
      healthCheck: {
        command: [
          "CMD-SHELL",
          "node -e \"fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))\""
        ],
        interval: Duration.seconds(30),
        timeout: Duration.seconds(5),
        retries: 3,
        startPeriod: Duration.seconds(20)
      },
      stopTimeout: Duration.seconds(120)
    });
    apiContainer.addPortMappings({
      containerPort: 8080,
      protocol: ecs.Protocol.TCP,
      name: "http"
    });
    readSecret.grantRead(apiTaskDefinition.executionRole!);
    llmSecret.grantRead(apiTaskDefinition.executionRole!);
    repository.grantPull(apiTaskDefinition.executionRole!);

    nlbSecurityGroup.connections.allowTo(
      apiSecurityGroup,
      ec2.Port.tcp(8080),
      "Only the private NLB may reach API targets and health checks"
    );
    const apiService = new ecs.FargateService(this, "ApiService", {
      cluster,
      taskDefinition: apiTaskDefinition,
      desiredCount: isProduction ? 2 : 1,
      assignPublicIp: false,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [apiSecurityGroup],
      minHealthyPercent: 100,
      maxHealthyPercent: 200,
      circuitBreaker: { rollback: true },
      healthCheckGracePeriod: Duration.seconds(60),
      enableExecuteCommand: false,
      platformVersion: ecs.FargatePlatformVersion.LATEST
    });
    const apiScaling = apiService.autoScaleTaskCount({
      minCapacity: isProduction ? 2 : 1,
      maxCapacity: isProduction ? 20 : 5
    });
    apiScaling.scaleOnCpuUtilization("ApiCpuScaling", {
      targetUtilizationPercent: 55,
      scaleInCooldown: Duration.minutes(5),
      scaleOutCooldown: Duration.minutes(1)
    });

    const loadBalancer = new elbv2.NetworkLoadBalancer(this, "PrivateNlb", {
      vpc,
      internetFacing: false,
      crossZoneEnabled: true,
      securityGroups: [nlbSecurityGroup],
      enforceSecurityGroupInboundRulesOnPrivateLinkTraffic: false,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      deletionProtection: isProduction
    });
    const listener = loadBalancer.addListener("HttpListener", {
      port: 80,
      protocol: elbv2.Protocol.TCP
    });
    listener.addTargets("ApiTargets", {
      port: 8080,
      protocol: elbv2.Protocol.TCP,
      preserveClientIp: false,
      targets: [
        apiService.loadBalancerTarget({
          containerName: apiContainer.containerName,
          containerPort: 8080
        })
      ],
      deregistrationDelay: Duration.seconds(30),
      healthCheck: {
        enabled: true,
        protocol: elbv2.Protocol.HTTP,
        path: "/healthz",
        healthyHttpCodes: "200",
        interval: Duration.seconds(30),
        timeout: Duration.seconds(10)
      }
    });

    const auditWorkerTaskDefinition = new ecs.FargateTaskDefinition(
      this,
      "AuditWorkerTaskDefinition",
      {
        cpu: 1024,
        memoryLimitMiB: 2048,
        ephemeralStorageGiB: 30,
        runtimePlatform: {
          cpuArchitecture: ecs.CpuArchitecture.X86_64,
          operatingSystemFamily: ecs.OperatingSystemFamily.LINUX
        }
      }
    );
    auditWorkerTaskDefinition.addContainer("AuditWorker", {
      image,
      command: ["node", "dist/audit-worker.js"],
      readonlyRootFilesystem: true,
      user: "1000",
      logging: ecs.LogDrivers.awsLogs({
        logGroup: auditWorkerLogGroup,
        streamPrefix: "audit-worker",
        mode: ecs.AwsLogDriverMode.NON_BLOCKING,
        maxBufferSize: Size.mebibytes(8)
      }),
      environment: {
        NODE_ENV: "production",
        ARCHON_RELEASE_SHA: releaseSha.valueAsString,
        DATAHUB_GMS_URL: dataHubReadUrl.valueAsString,
        DATAHUB_MCP_URL: dataHubReadMcpUrl.valueAsString,
        LLM_BASE_URL: llmBaseUrl.valueAsString,
        LLM_MODEL: llmModel.valueAsString,
        ARCHON_AUDIT_QUEUE_URL: auditQueue.queueUrl,
        ARCHON_AUDIT_DLQ_URL: auditDlq.queueUrl,
        ARCHON_IDEMPOTENCY_TABLE: idempotencyTable.tableName,
        ARCHON_EVIDENCE_BUCKET: evidenceBucket.bucketName
      },
      secrets: {
        DATAHUB_GMS_TOKEN: ecs.Secret.fromSecretsManager(readSecret, "token"),
        LLM_API_KEY: ecs.Secret.fromSecretsManager(llmSecret, "apiKey")
      },
      healthCheck: {
        command: ["CMD-SHELL", "kill -0 1"],
        interval: Duration.seconds(30),
        timeout: Duration.seconds(5),
        retries: 3,
        startPeriod: Duration.seconds(20)
      },
      stopTimeout: Duration.seconds(120)
    });
    readSecret.grantRead(auditWorkerTaskDefinition.executionRole!);
    llmSecret.grantRead(auditWorkerTaskDefinition.executionRole!);
    repository.grantPull(auditWorkerTaskDefinition.executionRole!);
    auditQueue.grantConsumeMessages(auditWorkerTaskDefinition.taskRole);
    auditDlq.grantSendMessages(auditWorkerTaskDefinition.taskRole);
    auditWorkerTaskDefinition.taskRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        sid: "CheckpointOnlyAuditExecutions",
        actions: ["dynamodb:GetItem", "dynamodb:PutItem"],
        resources: [idempotencyTable.tableArn],
        conditions: {
          "ForAllValues:StringLike": { "dynamodb:LeadingKeys": ["AUDIT#*"] }
        }
      })
    );
    grantImmutableEvidenceAccess(
      evidenceBucket,
      dataKey,
      auditWorkerTaskDefinition.taskRole,
      ["v1/audit/*"],
      ["v1/audit/*"]
    );

    const remediationWorkerTaskDefinition = new ecs.FargateTaskDefinition(
      this,
      "RemediationWorkerTaskDefinition",
      {
      cpu: 1024,
      memoryLimitMiB: 2048,
      ephemeralStorageGiB: 30,
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.X86_64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX
      }
      }
    );
    remediationWorkerTaskDefinition.addContainer("RemediationWorker", {
      image,
      command: ["node", "dist/remediation-worker.js"],
      readonlyRootFilesystem: true,
      user: "1000",
      logging: ecs.LogDrivers.awsLogs({
        logGroup: remediationWorkerLogGroup,
        streamPrefix: "remediation-worker",
        mode: ecs.AwsLogDriverMode.NON_BLOCKING,
        maxBufferSize: Size.mebibytes(8)
      }),
      environment: {
        NODE_ENV: "production",
        ARCHON_RELEASE_SHA: releaseSha.valueAsString,
        DATAHUB_WRITE_GMS_URL: dataHubWriteUrl.valueAsString,
        DATAHUB_WRITE_MCP_URL: dataHubWriteMcpUrl.valueAsString,
        ARCHON_REMEDIATION_QUEUE_URL: remediationQueue.queueUrl,
        ARCHON_REMEDIATION_DLQ_URL: remediationDlq.queueUrl,
        ARCHON_IDEMPOTENCY_TABLE: idempotencyTable.tableName,
        ARCHON_EVIDENCE_BUCKET: evidenceBucket.bucketName
      },
      secrets: {
        DATAHUB_WRITE_GMS_TOKEN: ecs.Secret.fromSecretsManager(writeSecret, "token")
      },
      healthCheck: {
        command: ["CMD-SHELL", "kill -0 1"],
        interval: Duration.seconds(30),
        timeout: Duration.seconds(5),
        retries: 3,
        startPeriod: Duration.seconds(20)
      },
      stopTimeout: Duration.seconds(120)
    });
    writeSecret.grantRead(remediationWorkerTaskDefinition.executionRole!);
    repository.grantPull(remediationWorkerTaskDefinition.executionRole!);
    remediationQueue.grantConsumeMessages(remediationWorkerTaskDefinition.taskRole);
    remediationDlq.grantSendMessages(remediationWorkerTaskDefinition.taskRole);
    remediationWorkerTaskDefinition.taskRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        sid: "JournalOnlyGovernedExecutions",
        actions: [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:TransactWriteItems"
        ],
        resources: [idempotencyTable.tableArn],
        conditions: {
          "ForAllValues:StringLike": {
            "dynamodb:LeadingKeys": ["EXECUTION#*", "APPROVAL_EXECUTION#*"]
          }
        }
      })
    );
    grantImmutableEvidenceAccess(
      evidenceBucket,
      dataKey,
      remediationWorkerTaskDefinition.taskRole,
      ["v1/audit/*", "v1/execution/*"],
      ["v1/execution/*"]
    );

    const callbackPolicy = (actions: readonly string[]): iam.PolicyStatement =>
      new iam.PolicyStatement({
        sid: "ReturnOpaqueStepFunctionsTaskTokens",
        actions: [...actions],
        resources: ["*"]
      });
    // Step Functions callback APIs do not support resource-level permissions.
    const workerCallbackActions = [
      "states:SendTaskSuccess",
      "states:SendTaskFailure",
      "states:SendTaskHeartbeat"
    ];
    auditWorkerTaskDefinition.taskRole.addToPrincipalPolicy(
      callbackPolicy(workerCallbackActions)
    );
    remediationWorkerTaskDefinition.taskRole.addToPrincipalPolicy(
      callbackPolicy(workerCallbackActions)
    );

    const auditWorkerService = new ecs.FargateService(this, "AuditWorkerService", {
      cluster,
      taskDefinition: auditWorkerTaskDefinition,
      desiredCount: workerDesiredCount.valueAsNumber,
      assignPublicIp: false,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [auditWorkerSecurityGroup],
      minHealthyPercent: 0,
      maxHealthyPercent: 200,
      circuitBreaker: { rollback: true },
      enableExecuteCommand: false,
      platformVersion: ecs.FargatePlatformVersion.LATEST
    });
    const remediationWorkerService = new ecs.FargateService(
      this,
      "RemediationWorkerService",
      {
        cluster,
        taskDefinition: remediationWorkerTaskDefinition,
        desiredCount: workerDesiredCount.valueAsNumber,
        assignPublicIp: false,
        vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
        securityGroups: [remediationWorkerSecurityGroup],
        minHealthyPercent: 0,
        maxHealthyPercent: 200,
        circuitBreaker: { rollback: true },
        enableExecuteCommand: false,
        platformVersion: ecs.FargatePlatformVersion.LATEST
      }
    );
    const auditWorkerScaling = auditWorkerService.autoScaleTaskCount({
      minCapacity: workerDesiredCount.valueAsNumber,
      maxCapacity: isProduction ? 20 : 5
    });
    auditWorkerScaling.scaleOnMetric("AuditQueueDepthScaling", {
      metric: auditQueue.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(1)
      }),
      scalingSteps: [
        { upper: 0, change: -1 },
        { lower: 1, upper: 20, change: +1 },
        { lower: 20, upper: 100, change: +3 },
        { lower: 100, change: +5 }
      ],
      adjustmentType: appscaling.AdjustmentType.CHANGE_IN_CAPACITY,
      cooldown: Duration.minutes(1)
    });
    const remediationWorkerScaling = remediationWorkerService.autoScaleTaskCount({
      minCapacity: workerDesiredCount.valueAsNumber,
      maxCapacity: isProduction ? 10 : 3
    });
    remediationWorkerScaling.scaleOnMetric("RemediationQueueDepthScaling", {
      metric: remediationQueue.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(1)
      }),
      scalingSteps: [
        { upper: 0, change: -1 },
        { lower: 1, upper: 5, change: +1 },
        { lower: 5, upper: 20, change: +2 },
        { lower: 20, change: +3 }
      ],
      adjustmentType: appscaling.AdjustmentType.CHANGE_IN_CAPACITY,
      cooldown: Duration.minutes(1)
    });

    const stateMachineLogGroup = retainedLogGroup(
      this,
      "StateMachineLogs",
      `/archon/${stage}/orchestration`,
      logsKey
    );
    const dispatchAudit = new tasks.SqsSendMessage(this, "DispatchAudit", {
      queue: auditQueue,
      integrationPattern: sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
      messageBody: sfn.TaskInput.fromObject({
        type: "AUDIT_REQUESTED",
        taskToken: sfn.JsonPath.taskToken,
        executionId: sfn.JsonPath.stringAt("$$.Execution.Id"),
        request: sfn.JsonPath.objectAt("$")
      }),
      resultPath: "$.auditResult",
      heartbeatTimeout: sfn.Timeout.duration(Duration.minutes(15)),
      taskTimeout: sfn.Timeout.duration(Duration.hours(2))
    });
    const dispatchApproval = new tasks.SqsSendMessage(this, "DispatchApproval", {
      queue: approvalQueue,
      integrationPattern: sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
      messageBody: sfn.TaskInput.fromObject({
        type: "APPROVAL_REQUESTED",
        taskToken: sfn.JsonPath.taskToken,
        executionId: sfn.JsonPath.stringAt("$$.Execution.Id"),
        approvalId: sfn.JsonPath.stringAt("$.auditResult.approvalId"),
        planDigest: sfn.JsonPath.stringAt("$.auditResult.planDigest"),
        evidenceDigest: sfn.JsonPath.stringAt("$.auditResult.evidenceDigest"),
        approvalRequestDigest: sfn.JsonPath.stringAt(
          "$.auditResult.approvalRequestDigest"
        ),
        requestedAt: sfn.JsonPath.stringAt("$.auditResult.approvalRequestedAt"),
        expiresAt: sfn.JsonPath.stringAt("$.auditResult.approvalExpiresAt")
      }),
      resultPath: "$.approvalResult",
      taskTimeout: sfn.Timeout.duration(Duration.days(7))
    });
    const dispatchRemediation = new tasks.SqsSendMessage(this, "DispatchRemediation", {
      queue: remediationQueue,
      integrationPattern: sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
      messageBody: sfn.TaskInput.fromObject({
        type: "REMEDIATION_REQUESTED",
        taskToken: sfn.JsonPath.taskToken,
        executionId: sfn.JsonPath.stringAt("$$.Execution.Id"),
        approvalId: sfn.JsonPath.stringAt("$.auditResult.approvalId"),
        planDigest: sfn.JsonPath.stringAt("$.auditResult.planDigest"),
        evidenceDigest: sfn.JsonPath.stringAt("$.auditResult.evidenceDigest"),
        approvalResult: sfn.JsonPath.objectAt("$.approvalResult")
      }),
      resultPath: "$.remediationResult",
      heartbeatTimeout: sfn.Timeout.duration(Duration.minutes(15)),
      taskTimeout: sfn.Timeout.duration(Duration.hours(2))
    });
    const governedWriteComplete = new sfn.Succeed(this, "GovernedWriteComplete");
    const approvalRejected = new sfn.Succeed(this, "ApprovalRejected");
    const invalidApprovalResult = new sfn.Fail(this, "InvalidApprovalResult", {
      error: "InvalidApprovalResult",
      cause: "Approval callback did not contain an exact APPROVE or REJECT decision"
    });
    const governedWriteNotVerified = new sfn.Fail(this, "GovernedWriteNotVerified", {
      error: "GovernedWriteNotVerified",
      cause: "The worker did not prove the exact approved postcondition"
    });
    const verifyRemediation = new sfn.Choice(this, "VerifyRemediationOutcome")
      .when(
        sfn.Condition.stringEquals("$.remediationResult.outcome", "VERIFIED"),
        governedWriteComplete
      )
      .when(
        sfn.Condition.stringEquals("$.remediationResult.outcome", "REJECTED"),
        approvalRejected
      )
      .otherwise(governedWriteNotVerified);
    dispatchRemediation.next(verifyRemediation);
    const routeApproval = new sfn.Choice(this, "RouteApprovalDecision")
      .when(
        sfn.Condition.stringEquals(
          "$.approvalResult.decision.decision",
          "APPROVE"
        ),
        dispatchRemediation
      )
      .when(
        sfn.Condition.stringEquals(
          "$.approvalResult.decision.decision",
          "REJECT"
        ),
        dispatchRemediation
      )
      .otherwise(invalidApprovalResult);
    dispatchApproval.next(routeApproval);
    const definition = dispatchAudit.next(
      new sfn.Choice(this, "RequiresHumanApproval")
        .when(
          sfn.Condition.booleanEquals("$.auditResult.requiresApproval", true),
          dispatchApproval
        )
        .otherwise(new sfn.Succeed(this, "ReadOnlyAuditComplete"))
    );
    const stateMachine = new sfn.StateMachine(this, "ControlLoop", {
      stateMachineName: `archon-${stage}-control-loop`,
      stateMachineType: sfn.StateMachineType.STANDARD,
      definitionBody: sfn.DefinitionBody.fromChainable(definition),
      logs: {
        destination: stateMachineLogGroup,
        level: sfn.LogLevel.ERROR,
        includeExecutionData: false
      },
      tracingEnabled: true,
      removalPolicy: RemovalPolicy.RETAIN
    });

    const userPool = new cognito.UserPool(this, "UserPool", {
      userPoolName: `archon-${stage}`,
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      standardAttributes: {
        email: { required: true, mutable: false }
      },
      passwordPolicy: {
        minLength: 14,
        requireDigits: true,
        requireLowercase: true,
        requireSymbols: true,
        requireUppercase: true,
        tempPasswordValidity: Duration.days(3)
      },
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: { otp: true, sms: false },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      featurePlan: cognito.FeaturePlan.PLUS,
      standardThreatProtectionMode:
        cognito.StandardThreatProtectionMode.FULL_FUNCTION,
      deletionProtection: true,
      removalPolicy: RemovalPolicy.RETAIN
    });
    const approvalScopeName = "archon/approve";
    const approvalScope = new cognito.ResourceServerScope({
      scopeName: "approve",
      scopeDescription: "Submit an exact human decision for a server-owned Archon proposal"
    });
    const resourceServer = userPool.addResourceServer("ApprovalResourceServer", {
      identifier: "archon",
      userPoolResourceServerName: `archon-${stage}-approval-api`,
      scopes: [approvalScope]
    });
    const userPoolDomain = userPool.addDomain("HostedDomain", {
      cognitoDomain: {
        domainPrefix: `archon-${stage}-${Aws.ACCOUNT_ID}`
      },
      managedLoginVersion: cognito.ManagedLoginVersion.CLASSIC_HOSTED_UI
    });
    const approverGroup = new cognito.CfnUserPoolGroup(this, "ApproverGroup", {
      userPoolId: userPool.userPoolId,
      groupName: "archon-approvers",
      description: "Users allowed to decide governed remediation proposals"
    });

    const approvalLambdaLogGroup = retainedLogGroup(
      this,
      "ApprovalLambdaLogs",
      `/archon/${stage}/approval-lambda`,
      logsKey
    );
    const approvalHandoffLogGroup = retainedLogGroup(
      this,
      "ApprovalHandoffLambdaLogs",
      `/archon/${stage}/approval-handoff-lambda`,
      logsKey
    );
    const approvalHandoffFunction = new lambda.Function(
      this,
      "ApprovalHandoffFunction",
      {
        functionName: `archon-${stage}-approval-handoff`,
        description:
          "Persists opaque approval callbacks without DataHub or inference credentials",
        runtime: lambda.Runtime.NODEJS_24_X,
        architecture: lambda.Architecture.X86_64,
        handler: "handoff.handler",
        code: lambda.Code.fromAsset(join(__dirname, "../lambda/approval")),
        timeout: Duration.seconds(30),
        memorySize: 256,
        reservedConcurrentExecutions: 10,
        tracing: lambda.Tracing.ACTIVE,
        logGroup: approvalHandoffLogGroup,
        environment: {
          APPROVAL_TABLE: approvalTable.tableName
        }
      }
    );
    approvalHandoffFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "PersistOnlyApprovalHandoffsAndPoisonEvidence",
        actions: ["dynamodb:GetItem", "dynamodb:PutItem"],
        resources: [approvalTable.tableArn],
        conditions: {
          "ForAllValues:StringLike": {
            "dynamodb:LeadingKeys": ["APPROVAL#*", "HANDOFF_FAILURE#*"]
          }
        }
      })
    );
    approvalHandoffFunction.addToRolePolicy(
      callbackPolicy(["states:SendTaskFailure"])
    );
    approvalHandoffFunction.addEventSource(
      new lambdaEventSources.SqsEventSource(approvalQueue, {
        batchSize: 1,
        reportBatchItemFailures: true
      })
    );

    const approvalFunction = new lambda.Function(this, "ApprovalFunction", {
      functionName: `archon-${stage}-approval`,
      description:
        "Records a human decision with DynamoDB CAS and releases a server-held callback token",
      runtime: lambda.Runtime.NODEJS_24_X,
      architecture: lambda.Architecture.X86_64,
      handler: "index.handler",
      code: lambda.Code.fromAsset(join(__dirname, "../lambda/approval")),
      timeout: Duration.seconds(15),
      memorySize: 256,
      reservedConcurrentExecutions: 10,
      tracing: lambda.Tracing.ACTIVE,
      logGroup: approvalLambdaLogGroup,
      environment: {
        APPROVAL_TABLE: approvalTable.tableName,
        APPROVER_GROUP: approverGroup.groupName!
      }
    });
    approvalFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "ReadAndDecideOnlyBoundApprovals",
        actions: ["dynamodb:GetItem", "dynamodb:UpdateItem"],
        resources: [approvalTable.tableArn],
        conditions: {
          "ForAllValues:StringLike": {
            "dynamodb:LeadingKeys": ["APPROVAL#*"]
          }
        }
      })
    );
    // Callback APIs intentionally have no resource-level IAM scope. The Lambda has
    // no DataHub or LLM secret grants and cannot invent or execute a mutation.
    approvalFunction.addToRolePolicy(callbackPolicy(["states:SendTaskSuccess"]));

    const controlLambdaLogGroup = retainedLogGroup(
      this,
      "ControlLambdaLogs",
      `/archon/${stage}/control-lambda`,
      logsKey
    );
    const controlFunction = new lambda.Function(this, "ControlFunction", {
      functionName: `archon-${stage}-control`,
      description:
        "Starts and safely projects capability-scoped asynchronous audit executions",
      runtime: lambda.Runtime.NODEJS_24_X,
      architecture: lambda.Architecture.X86_64,
      handler: "index.handler",
      code: lambda.Code.fromAsset(join(__dirname, "../lambda/control")),
      timeout: Duration.seconds(20),
      memorySize: 512,
      reservedConcurrentExecutions: isProduction ? 50 : 15,
      tracing: lambda.Tracing.ACTIVE,
      logGroup: controlLambdaLogGroup,
      environment: {
        STATE_MACHINE_ARN: stateMachine.stateMachineArn,
        CHECKPOINT_TABLE: idempotencyTable.tableName,
        APPROVAL_TABLE: approvalTable.tableName,
        EVIDENCE_BUCKET: evidenceBucket.bucketName
      }
    });
    stateMachine.grantStartExecution(controlFunction);
    controlFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "DescribeOnlyThisControlLoopExecutions",
        actions: ["states:DescribeExecution"],
        resources: [
          this.formatArn({
            service: "states",
            resource: "execution",
            resourceName: `${stateMachine.stateMachineName}:*`
          })
        ]
      })
    );
    controlFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "ReadOnlyBoundAuditCheckpoints",
        actions: ["dynamodb:GetItem"],
        resources: [idempotencyTable.tableArn],
        conditions: {
          "ForAllValues:StringLike": {
            "dynamodb:LeadingKeys": ["AUDIT#*"]
          }
        }
      })
    );
    controlFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "ReadOnlyBoundApprovalStatus",
        actions: ["dynamodb:GetItem"],
        resources: [approvalTable.tableArn],
        conditions: {
          "ForAllValues:StringLike": {
            "dynamodb:LeadingKeys": ["APPROVAL#*"]
          }
        }
      })
    );
    controlFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "ReadOnlyBoundEvidenceProjection",
        actions: ["s3:GetObject", "s3:GetObjectAttributes", "s3:GetObjectVersion"],
        resources: [
          evidenceBucket.arnForObjects("v1/audit/*"),
          evidenceBucket.arnForObjects("v1/execution/*")
        ]
      })
    );
    grantEvidenceKeyAccess(
      evidenceBucket,
      dataKey,
      controlFunction.role!,
      ["v1/audit/*", "v1/execution/*"],
      []
    );

    const apiAccessLogGroup = retainedLogGroup(
      this,
      "ApiGatewayAccessLogs",
      `/archon/${stage}/api-gateway`,
      logsKey
    );
    const api = new apigateway.RestApi(this, "RestApi", {
      restApiName: `archon-${stage}`,
      description: "Public read-only audit plus authenticated Archon approval control plane",
      endpointTypes: [apigateway.EndpointType.REGIONAL],
      deployOptions: {
        stageName: stage,
        cacheClusterEnabled: true,
        cacheClusterSize: "0.5",
        methodOptions: {
          "/api/control-loops/{auditId}/GET": {
            cacheDataEncrypted: true,
            cacheTtl: Duration.seconds(2),
            cachingEnabled: true
          }
        },
        accessLogDestination: new apigateway.LogGroupLogDestination(apiAccessLogGroup),
        accessLogFormat: apigateway.AccessLogFormat.jsonWithStandardFields({
          caller: false,
          httpMethod: true,
          ip: true,
          protocol: true,
          requestTime: true,
          resourcePath: true,
          responseLength: true,
          status: true,
          user: false
        }),
        loggingLevel: apigateway.MethodLoggingLevel.ERROR,
        dataTraceEnabled: false,
        metricsEnabled: true,
        tracingEnabled: true,
        throttlingBurstLimit: isProduction ? 100 : 20,
        throttlingRateLimit: isProduction ? 50 : 10
      },
      cloudWatchRole: true,
      binaryMediaTypes: [],
      minCompressionSize: Size.bytes(1024),
      retainDeployments: true
    });
    const authorizer = new apigateway.CognitoUserPoolsAuthorizer(this, "Authorizer", {
      cognitoUserPools: [userPool],
      authorizerName: `archon-${stage}-cognito`,
      resultsCacheTtl: Duration.minutes(5),
      identitySource: "method.request.header.Authorization"
    });
    const requestValidator = new apigateway.RequestValidator(this, "BodyValidator", {
      restApi: api,
      requestValidatorName: "strict-body-and-parameters",
      validateRequestBody: true,
      validateRequestParameters: true
    });
    const vpcLink = new apigateway.VpcLink(this, "VpcLink", {
      vpcLinkName: `archon-${stage}`,
      targets: [loadBalancer]
    });

    const auditModel = api.addModel("AuditRequest", {
      modelName: `ArchonAuditRequest${pascal(stage)}`,
      contentType: "application/json",
      schema: {
        schema: apigateway.JsonSchemaVersion.DRAFT4,
        type: apigateway.JsonSchemaType.OBJECT,
        additionalProperties: false,
        required: ["query"],
        properties: {
          query: {
            type: apigateway.JsonSchemaType.STRING,
            minLength: 1,
            maxLength: 256,
            pattern: "^[^\\u0000-\\u001F\\u007F]*$"
          }
        }
      }
    });
    const controlLoopModel = api.addModel("ControlLoopRequest", {
      modelName: `ArchonControlLoopRequest${pascal(stage)}`,
      contentType: "application/json",
      schema: {
        schema: apigateway.JsonSchemaVersion.DRAFT4,
        type: apigateway.JsonSchemaType.OBJECT,
        additionalProperties: false,
        required: ["query"],
        properties: {
          query: {
            type: apigateway.JsonSchemaType.STRING,
            minLength: 1,
            maxLength: 256,
            pattern: "^[^\\u0000-\\u001F\\u007F]*$"
          },
          mode: {
            type: apigateway.JsonSchemaType.STRING,
            enum: ["READ_ONLY", "GOVERNED"]
          }
        }
      }
    });
    const decisionModel = api.addModel("ApprovalDecisionRequest", {
      modelName: `ArchonApprovalDecision${pascal(stage)}`,
      contentType: "application/json",
      schema: {
        schema: apigateway.JsonSchemaVersion.DRAFT4,
        type: apigateway.JsonSchemaType.OBJECT,
        additionalProperties: false,
        required: ["decision"],
        properties: {
          decision: {
            type: apigateway.JsonSchemaType.STRING,
            enum: ["APPROVE", "REJECT"]
          },
          comment: {
            type: apigateway.JsonSchemaType.STRING,
            maxLength: 1000,
            pattern: "^[^\\u0000\\u007F]*$"
          }
        }
      }
    });

    const authenticatedMethod: apigateway.MethodOptions = {
      authorizationType: apigateway.AuthorizationType.COGNITO,
      authorizer,
      requestValidator,
      apiKeyRequired: false
    };
    const apiResource = api.root.addResource("api");
    const auditsResource = apiResource.addResource("audits");
    auditsResource.addMethod(
      "POST",
      privateHttpIntegration(
        vpcLink,
        "POST",
        `http://${loadBalancer.loadBalancerDnsName}/api/audits`
      ),
      {
        // Judges can exercise the sanitized, read-only audit without credentials.
        // WAF, request validation, stage throttling, and the application's bounded
        // query contract remain in force. No mutation route reaches this container.
        authorizationType: apigateway.AuthorizationType.NONE,
        requestValidator,
        apiKeyRequired: false,
        requestModels: { "application/json": auditModel }
      }
    );

    const controlLoopsResource = apiResource.addResource("control-loops");
    controlLoopsResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(controlFunction, {
        proxy: true,
        allowTestInvoke: false
      }),
      {
        // Audit initiation is read-first and public for the judge journey. A random
        // 256-bit audit id is the status capability; the Lambda never returns the
        // execution ARN, workflow input/output, callback tokens, or provider errors.
        authorizationType: apigateway.AuthorizationType.NONE,
        requestValidator,
        apiKeyRequired: false,
        requestModels: { "application/json": controlLoopModel }
      }
    );
    controlLoopsResource
      .addResource("{auditId}")
      .addMethod(
        "GET",
        new apigateway.LambdaIntegration(controlFunction, {
          proxy: true,
          allowTestInvoke: false,
          cacheKeyParameters: ["method.request.path.auditId"],
          cacheNamespace: "audit-status"
        }),
        {
          authorizationType: apigateway.AuthorizationType.NONE,
          requestValidator,
          apiKeyRequired: false,
          requestParameters: {
            "method.request.path.auditId": true
          }
        }
      );

    const approvalIdResource = apiResource
      .addResource("approvals")
      .addResource("{approvalId}");
    const decisionsResource = approvalIdResource.addResource("decisions");
    decisionsResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(approvalFunction, {
        proxy: true,
        allowTestInvoke: false
      }),
      {
        ...authenticatedMethod,
        authorizationScopes: [approvalScopeName],
        requestParameters: {
          "method.request.path.approvalId": true
        },
        requestModels: { "application/json": decisionModel }
      }
    );

    const webAcl = new wafv2.CfnWebACL(this, "RegionalWebAcl", {
      name: `archon-${stage}-api`,
      scope: "REGIONAL",
      defaultAction: { allow: {} },
      dataProtectionConfig: {
        dataProtections: [
          {
            action: "SUBSTITUTION",
            excludeRateBasedDetails: false,
            excludeRuleMatchDetails: false,
            field: {
              fieldType: "SINGLE_HEADER",
              fieldKeys: ["authorization"]
            }
          },
          {
            action: "SUBSTITUTION",
            excludeRateBasedDetails: false,
            excludeRuleMatchDetails: false,
            field: {
              fieldType: "SINGLE_HEADER",
              fieldKeys: ["cookie"]
            }
          }
        ]
      },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: `archon-${stage}-api-waf`,
        sampledRequestsEnabled: true
      },
      rules: [
        managedWafRule("AWSManagedRulesAmazonIpReputationList", 0),
        managedWafRule("AWSManagedRulesCommonRuleSet", 10),
        managedWafRule("AWSManagedRulesKnownBadInputsRuleSet", 20),
        {
          name: "PerIpRateLimit",
          priority: 30,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              aggregateKeyType: "IP",
              evaluationWindowSec: 300,
              limit: isProduction ? 1_000 : 300
            }
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: `archon-${stage}-rate-limit`,
            sampledRequestsEnabled: true
          }
        }
      ]
    });
    const apiStageArn = `arn:${Aws.PARTITION}:apigateway:${Aws.REGION}::/restapis/${api.restApiId}/stages/${api.deploymentStage.stageName}`;
    const webAclAssociation = new wafv2.CfnWebACLAssociation(
      this,
      "WebAclAssociation",
      {
        resourceArn: apiStageArn,
        webAclArn: webAcl.attrArn
      }
    );
    webAclAssociation.node.addDependency(api.deploymentStage);
    const apiWafLogGroup = retainedLogGroup(
      this,
      "ApiWafLogGroup",
      `aws-waf-logs-archon-${stage}-api`,
      logsKey
    );
    const apiWafLogGroupResourceArn = this.formatArn({
      service: "logs",
      resource: "log-group",
      resourceName: apiWafLogGroup.logGroupName,
      arnFormat: ArnFormat.COLON_RESOURCE_NAME
    });
    const apiWafLogging = new wafv2.CfnLoggingConfiguration(
      this,
      "ApiWafLogging",
      {
        resourceArn: webAcl.attrArn,
        logDestinationConfigs: [apiWafLogGroupResourceArn],
        loggingFilter: {
          defaultBehavior: "DROP",
          filters: [
            {
              behavior: "KEEP",
              conditions: [
                { actionCondition: { action: "BLOCK" } },
                { actionCondition: { action: "COUNT" } }
              ],
              requirement: "MEETS_ANY"
            }
          ]
        },
        redactedFields: [
          { singleHeader: { name: "authorization" } },
          { singleHeader: { name: "cookie" } }
        ]
      }
    );
    apiWafLogging.node.addDependency(webAcl, apiWafLogGroup);

    const responseHeadersPolicy = new cloudfront.ResponseHeadersPolicy(
      this,
      "SecurityHeaders",
      {
        responseHeadersPolicyName: `archon-${stage}-security`,
        securityHeadersBehavior: {
          contentSecurityPolicy: {
            contentSecurityPolicy: [
              "default-src 'self'",
              "base-uri 'self'",
              `connect-src 'self' ${userPoolDomain.baseUrl()}`,
              "font-src 'self'",
              "form-action 'self'",
              "frame-ancestors 'none'",
              "img-src 'self' data:",
              "object-src 'none'",
              "script-src 'self'",
              "style-src 'self'"
            ].join("; "),
            override: true
          },
          contentTypeOptions: { override: true },
          frameOptions: {
            frameOption: cloudfront.HeadersFrameOption.DENY,
            override: true
          },
          referrerPolicy: {
            referrerPolicy: cloudfront.HeadersReferrerPolicy.NO_REFERRER,
            override: true
          },
          strictTransportSecurity: {
            accessControlMaxAge: Duration.days(730),
            includeSubdomains: true,
            preload: true,
            override: true
          },
          xssProtection: {
            protection: true,
            modeBlock: true,
            override: true
          }
        }
      }
    );
    const apiOrigin = new origins.HttpOrigin(
      `${api.restApiId}.execute-api.${Aws.REGION}.${Aws.URL_SUFFIX}`,
      {
        protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
        originPath: `/${api.deploymentStage.stageName}`,
        connectionAttempts: 3,
        connectionTimeout: Duration.seconds(10)
      }
    );
    const spaOrigin = origins.S3BucketOrigin.withOriginAccessControl(spaBucket);
    const canonicalHostFunction = new cloudfront.Function(
      this,
      "CanonicalHost",
      {
        comment: `Reject non-canonical Archon ${stage} viewer hosts`,
        runtime: cloudfront.FunctionRuntime.JS_2_0,
        code: cloudfront.FunctionCode.fromInline(
          [
            "function handler(event) {",
            "  var request = event.request;",
            '  var host = (request.headers.host && request.headers.host.value || "").toLowerCase();',
            `  if (host !== "${cloudFrontDomainName.valueAsString}") {`,
            "    return {",
            "      statusCode: 421,",
            '      statusDescription: "Misdirected Request",',
            "      headers: {",
            '        "cache-control": { value: "no-store" },',
            '        "content-type": { value: "text/plain; charset=utf-8" }',
            "      }",
            "    };",
            "  }",
            "  return request;",
            "}"
          ].join("\n")
        )
      }
    );
    const canonicalHostAssociation = {
      function: canonicalHostFunction,
      eventType: cloudfront.FunctionEventType.VIEWER_REQUEST
    };
    const viewerCertificate = acm.Certificate.fromCertificateArn(
      this,
      "ViewerCertificate",
      cloudFrontCertificateArn.valueAsString
    );
    const distribution = new cloudfront.Distribution(this, "Distribution", {
      comment: `Archon ${stage}: private SPA plus same-origin authenticated API`,
      defaultRootObject: "index.html",
      certificate: viewerCertificate,
      domainNames: [cloudFrontDomainName.valueAsString],
      webAclId: cloudFrontWebAclArn.valueAsString,
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_3_2025,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      enableIpv6: true,
      enableLogging: true,
      logBucket: cloudFrontLogBucket,
      logFilePrefix: `${stage}/`,
      defaultBehavior: {
        origin: spaOrigin,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
        cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        compress: true,
        functionAssociations: [canonicalHostAssociation],
        responseHeadersPolicy,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS
      },
      additionalBehaviors: {
        "runtime-config.json": {
          origin: spaOrigin,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
          cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          compress: true,
          functionAssociations: [canonicalHostAssociation],
          responseHeadersPolicy,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY
        },
        "api/*": {
          origin: apiOrigin,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          compress: true,
          functionAssociations: [canonicalHostAssociation],
          originRequestPolicy:
            cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
          responseHeadersPolicy,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY
        }
      },
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100
    });
    const cloudFrontAliasTarget = {
      dnsName: distribution.distributionDomainName,
      // CloudFront's canonical hosted-zone ID is global for Route 53 aliases.
      hostedZoneId: "Z2FDTNDATAQYW2",
      evaluateTargetHealth: false
    };
    for (const recordType of ["A", "AAAA"]) {
      new route53.CfnRecordSet(this, `CloudFrontAlias${recordType}`, {
        name: cloudFrontDomainName.valueAsString,
        type: recordType,
        hostedZoneId: cloudFrontHostedZoneId.valueAsString,
        aliasTarget: cloudFrontAliasTarget
      });
    }
    const applicationRootUrl = `https://${cloudFrontDomainName.valueAsString}/`;
    const userPoolClient = userPool.addClient("SpaClient", {
      userPoolClientName: `archon-${stage}-spa`,
      // Supplying a non-empty AuthFlow object prevents Cognito's default
      // USER_SRP/CUSTOM direct-auth surfaces. The remaining explicit flow is
      // refresh-token auth; interactive sign-in is OAuth code + browser PKCE.
      authFlows: { userSrp: false },
      generateSecret: false,
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
      accessTokenValidity: Duration.minutes(15),
      idTokenValidity: Duration.minutes(15),
      refreshTokenValidity: Duration.days(1),
      supportedIdentityProviders: [
        cognito.UserPoolClientIdentityProvider.COGNITO
      ],
      oAuth: {
        callbackUrls: [applicationRootUrl],
        logoutUrls: [applicationRootUrl],
        flows: {
          authorizationCodeGrant: true,
          implicitCodeGrant: false,
          clientCredentials: false
        },
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.resourceServer(resourceServer, approvalScope)
        ]
      }
    });
    // Keep the CloudFront grant on a key dedicated to SPA objects. An exact
    // distribution reference here would create SpaBucket -> SpaKey ->
    // Distribution -> SpaBucket; the OAC bucket policy still binds reads to
    // this stack's exact distribution.
    spaKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: "AllowCloudFrontOacToDecryptSpaObjects",
        principals: [new iam.ServicePrincipal("cloudfront.amazonaws.com")],
        actions: ["kms:Decrypt"],
        resources: ["*"],
        conditions: {
          ArnLike: {
            "AWS:SourceArn": `arn:${Aws.PARTITION}:cloudfront::${Aws.ACCOUNT_ID}:distribution/*`
          }
        }
      })
    );

    const alarmTopic = new sns.Topic(this, "AlarmTopic", {
      topicName: `archon-${stage}-alarms`,
      masterKey: logsKey,
      enforceSSL: true
    });
    alarmTopic.applyRemovalPolicy(RemovalPolicy.RETAIN);
    const alarmAction = new cloudwatchActions.SnsAction(alarmTopic);
    const alarms = [
      new cloudwatch.Alarm(this, "Api5xxAlarm", {
        metric: new cloudwatch.Metric({
          namespace: "AWS/ApiGateway",
          metricName: "5XXError",
          dimensionsMap: {
            ApiName: api.restApiName,
            Stage: api.deploymentStage.stageName
          },
          statistic: "Sum",
          period: Duration.minutes(5)
        }),
        threshold: 5,
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
      }),
      new cloudwatch.Alarm(this, "ApiLatencyAlarm", {
        metric: new cloudwatch.Metric({
          namespace: "AWS/ApiGateway",
          metricName: "Latency",
          dimensionsMap: {
            ApiName: api.restApiName,
            Stage: api.deploymentStage.stageName
          },
          statistic: "p95",
          period: Duration.minutes(5)
        }),
        threshold: 10_000,
        evaluationPeriods: 2,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
      }),
      new cloudwatch.Alarm(this, "ApiCpuAlarm", {
        metric: apiService.metricCpuUtilization({
          statistic: "Average",
          period: Duration.minutes(5)
        }),
        threshold: 80,
        evaluationPeriods: 3,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
      }),
      new cloudwatch.Alarm(this, "AuditDlqAlarm", {
        metric: auditDlq.metricApproximateNumberOfMessagesVisible({
          statistic: "Maximum",
          period: Duration.minutes(1)
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
      }),
      new cloudwatch.Alarm(this, "ApprovalDlqAlarm", {
        metric: approvalDlq.metricApproximateNumberOfMessagesVisible({
          statistic: "Maximum",
          period: Duration.minutes(1)
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
      }),
      new cloudwatch.Alarm(this, "RemediationDlqAlarm", {
        metric: remediationDlq.metricApproximateNumberOfMessagesVisible({
          statistic: "Maximum",
          period: Duration.minutes(1)
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
      }),
      new cloudwatch.Alarm(this, "StateMachineFailuresAlarm", {
        metric: stateMachine.metricFailed({
          statistic: "Sum",
          period: Duration.minutes(5)
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
      }),
      new cloudwatch.Alarm(this, "ApprovalLambdaErrorsAlarm", {
        metric: approvalFunction.metricErrors({
          statistic: "Sum",
          period: Duration.minutes(5)
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
      }),
      new cloudwatch.Alarm(this, "ApprovalHandoffLambdaErrorsAlarm", {
        metric: approvalHandoffFunction.metricErrors({
          statistic: "Sum",
          period: Duration.minutes(5)
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
      }),
      new cloudwatch.Alarm(this, "ControlLambdaErrorsAlarm", {
        metric: controlFunction.metricErrors({
          statistic: "Sum",
          period: Duration.minutes(5)
        }),
        threshold: 5,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
      })
    ];
    for (const alarm of alarms) {
      alarm.addAlarmAction(alarmAction);
      alarm.addOkAction(alarmAction);
    }

    new cloudwatch.Dashboard(this, "OperationsDashboard", {
      dashboardName: `archon-${stage}`,
      widgets: [
        [
          new cloudwatch.GraphWidget({
            title: "API health",
            left: [alarms[0]!.metric, alarms[1]!.metric],
            width: 12
          }),
          new cloudwatch.GraphWidget({
            title: "ECS API",
            left: [apiService.metricCpuUtilization(), apiService.metricMemoryUtilization()],
            width: 12
          })
        ],
        [
          new cloudwatch.GraphWidget({
            title: "Control-loop queues",
            left: [
              auditQueue.metricApproximateNumberOfMessagesVisible(),
              approvalQueue.metricApproximateNumberOfMessagesVisible(),
              remediationQueue.metricApproximateNumberOfMessagesVisible(),
              auditDlq.metricApproximateNumberOfMessagesVisible(),
              approvalDlq.metricApproximateNumberOfMessagesVisible(),
              remediationDlq.metricApproximateNumberOfMessagesVisible()
            ],
            width: 12
          }),
          new cloudwatch.GraphWidget({
            title: "Step Functions",
            left: [stateMachine.metricStarted(), stateMachine.metricSucceeded()],
            right: [stateMachine.metricFailed(), stateMachine.metricTimedOut()],
            width: 12
          })
        ],
        [
          new cloudwatch.GraphWidget({
            title: "Isolated workers",
            left: [
              auditWorkerService.metricCpuUtilization(),
              auditWorkerService.metricMemoryUtilization()
            ],
            right: [
              remediationWorkerService.metricCpuUtilization(),
              remediationWorkerService.metricMemoryUtilization()
            ],
            width: 24
          })
        ]
      ]
    });

    const preferredApiUrl = `https://${cloudFrontDomainName.valueAsString}/api`;
    output(this, "ArchonSpaBucketName", spaBucket.bucketName);
    output(this, "ArchonEvidenceBucketName", evidenceBucket.bucketName);
    output(this, "ArchonCloudFrontDistributionId", distribution.distributionId);
    output(this, "ArchonCloudFrontDomainName", distribution.distributionDomainName);
    output(this, "ArchonApplicationUrl", `https://${cloudFrontDomainName.valueAsString}`);
    output(this, "ArchonApiUrl", preferredApiUrl);
    output(this, "ArchonApiInvokeUrl", api.url);
    output(this, "ArchonApiStageArn", apiStageArn);
    output(this, "ArchonRegionalWebAclArn", webAcl.attrArn);
    output(this, "ArchonRegionalWafLogGroupName", apiWafLogGroup.logGroupName);
    output(this, "ArchonRegionalWafLogKeyArn", logsKey.keyArn);
    output(this, "ArchonUserPoolId", userPool.userPoolId);
    output(this, "ArchonUserPoolClientId", userPoolClient.userPoolClientId);
    output(this, "ArchonCognitoHostedUiOrigin", userPoolDomain.baseUrl());
    output(
      this,
      "ArchonCognitoAuthorizationEndpoint",
      `${userPoolDomain.baseUrl()}/oauth2/authorize`
    );
    output(
      this,
      "ArchonCognitoTokenEndpoint",
      `${userPoolDomain.baseUrl()}/oauth2/token`
    );
    output(
      this,
      "ArchonCognitoLogoutEndpoint",
      `${userPoolDomain.baseUrl()}/logout`
    );
    output(this, "ArchonApprovalOAuthScope", approvalScopeName);
    output(this, "ArchonAuthRedirectUri", applicationRootUrl);
    output(this, "ArchonAuthLogoutUri", applicationRootUrl);
    output(this, "ArchonApproverGroupName", approverGroup.groupName!);
    output(this, "ArchonStateMachineArn", stateMachine.stateMachineArn);
    output(this, "ArchonAuditQueueUrl", auditQueue.queueUrl);
    output(this, "ArchonApprovalQueueUrl", approvalQueue.queueUrl);
    output(this, "ArchonRemediationQueueUrl", remediationQueue.queueUrl);
    output(this, "ArchonApprovalTableName", approvalTable.tableName);
    output(this, "ArchonIdempotencyTableName", idempotencyTable.tableName);
    output(this, "ArchonEcsClusterName", cluster.clusterName);
    output(this, "ArchonApiServiceName", apiService.serviceName);
    output(this, "ArchonAuditWorkerServiceName", auditWorkerService.serviceName);
    output(
      this,
      "ArchonRemediationWorkerServiceName",
      remediationWorkerService.serviceName
    );
    output(this, "ArchonApiSecurityGroupId", apiSecurityGroup.securityGroupId);
    output(this, "ArchonNlbSecurityGroupId", nlbSecurityGroup.securityGroupId);
    output(this, "ArchonPrivateNlbArn", loadBalancer.loadBalancerArn);
    output(this, "ArchonVpcId", vpc.vpcId);
    output(
      this,
      "ArchonAuditWorkerSecurityGroupId",
      auditWorkerSecurityGroup.securityGroupId
    );
    output(
      this,
      "ArchonRemediationWorkerSecurityGroupId",
      remediationWorkerSecurityGroup.securityGroupId
    );
    output(
      this,
      "ArchonVpcEndpointSecurityGroupId",
      vpcEndpointSecurityGroup.securityGroupId
    );
    output(this, "ArchonReadSecretArn", readSecret.secretArn);
    output(this, "ArchonWriteSecretArn", writeSecret.secretArn);
    output(this, "ArchonLlmSecretArn", llmSecret.secretArn);
    output(this, "ArchonAlarmTopicArn", alarmTopic.topicArn);
    output(this, "ArchonContainerImageDigest", imageDigest.valueAsString);
    output(this, "ArchonSpaArtifactSha256", spaArtifactSha256.valueAsString);
    output(this, "ArchonReleaseSha", releaseSha.valueAsString);
  }
}

function retainedKey(scope: Construct, id: string, alias: string): kms.Key {
  return new kms.Key(scope, id, {
    alias,
    enableKeyRotation: true,
    pendingWindow: Duration.days(30),
    removalPolicy: RemovalPolicy.RETAIN
  });
}

function retainedLogGroup(
  scope: Construct,
  id: string,
  logGroupName: string,
  encryptionKey: kms.IKey
): logs.LogGroup {
  return new logs.LogGroup(scope, id, {
    logGroupName,
    encryptionKey,
    retention: logs.RetentionDays.ONE_YEAR,
    removalPolicy: RemovalPolicy.RETAIN
  });
}

function grantCloudWatchLogsKeyAccess(
  scope: Construct,
  key: kms.Key,
  logGroupNamePatterns: readonly string[]
): void {
  const stack = Stack.of(scope);
  const logGroupArnPatterns = logGroupNamePatterns.map((logGroupName) =>
    stack.formatArn({
      service: "logs",
      resource: "log-group",
      resourceName: logGroupName,
      arnFormat: ArnFormat.COLON_RESOURCE_NAME
    })
  );
  key.addToResourcePolicy(
    new iam.PolicyStatement({
      sid: "AllowCloudWatchLogsEncryption",
      principals: [
        new iam.ServicePrincipal(`logs.${Aws.REGION}.${Aws.URL_SUFFIX}`)
      ],
      actions: [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:Describe*"
      ],
      resources: ["*"],
      conditions: {
        ArnLike: {
          "kms:EncryptionContext:aws:logs:arn": logGroupArnPatterns
        }
      }
    })
  );
}

function retainedTable(
  scope: Construct,
  id: string,
  purpose: string,
  encryptionKey: kms.IKey
): dynamodb.Table {
  const table = new dynamodb.Table(scope, id, {
    partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
    sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
    encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
    encryptionKey,
    deletionProtection: true,
    pointInTimeRecoverySpecification: {
      pointInTimeRecoveryEnabled: true
    },
    timeToLiveAttribute: "expiresAt",
    stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
    contributorInsightsSpecification: { enabled: true },
    removalPolicy: RemovalPolicy.RETAIN,
    tableClass: dynamodb.TableClass.STANDARD
  });
  Tags.of(table).add("Purpose", purpose);
  return table;
}

function bootstrapSecret(
  scope: Construct,
  id: string,
  secretName: string,
  description: string,
  encryptionKey: kms.IKey,
  valueKey = "token"
): secretsmanager.Secret {
  const secret = new secretsmanager.Secret(scope, id, {
    secretName,
    description,
    encryptionKey,
    generateSecretString: {
      secretStringTemplate: JSON.stringify({ [valueKey]: "replace-after-deploy" }),
      generateStringKey: "bootstrapNonce",
      excludePunctuation: true,
      passwordLength: 32
    }
  });
  secret.applyRemovalPolicy(RemovalPolicy.RETAIN);
  return secret;
}

function encryptedQueue(
  scope: Construct,
  id: string,
  queueName: string,
  encryptionMasterKey: kms.IKey,
  props: Omit<sqs.QueueProps, "queueName" | "encryption" | "encryptionMasterKey">
): sqs.Queue {
  return new sqs.Queue(scope, id, {
    ...props,
    queueName: `archon-${queueName}`,
    encryption: sqs.QueueEncryption.KMS,
    encryptionMasterKey,
    enforceSSL: true
  });
}

function grantImmutableEvidenceAccess(
  bucket: s3.IBucket,
  encryptionKey: kms.IKey,
  role: iam.IRole,
  readPrefixes: readonly string[],
  writePrefixes: readonly string[]
): void {
  if (readPrefixes.length > 0) {
    role.addToPrincipalPolicy(
      new iam.PolicyStatement({
        sid: "ReadBoundEvidenceObjects",
        actions: ["s3:GetObject", "s3:GetObjectAttributes", "s3:GetObjectVersion"],
        resources: readPrefixes.map((prefix) => bucket.arnForObjects(prefix))
      })
    );
  }
  if (writePrefixes.length > 0) {
    role.addToPrincipalPolicy(
      new iam.PolicyStatement({
        sid: "AppendBoundEvidenceObjects",
        actions: ["s3:PutObject"],
        resources: writePrefixes.map((prefix) => bucket.arnForObjects(prefix))
      })
    );
  }
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      sid: "NeverDeleteOrBypassEvidenceRetention",
      effect: iam.Effect.DENY,
      actions: [
        "s3:BypassGovernanceRetention",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:PutObjectRetention"
      ],
      resources: [bucket.arnForObjects("*")]
    })
  );
  grantEvidenceKeyAccess(
    bucket,
    encryptionKey,
    role,
    readPrefixes,
    writePrefixes
  );
}

function grantEvidenceKeyAccess(
  bucket: s3.IBucket,
  encryptionKey: kms.IKey,
  role: iam.IRole,
  readPrefixes: readonly string[],
  writePrefixes: readonly string[]
): void {
  const actions = new Set<string>();
  if (readPrefixes.length > 0) actions.add("kms:Decrypt");
  if (writePrefixes.length > 0) {
    actions.add("kms:Encrypt");
    actions.add("kms:GenerateDataKey*");
  }
  if (actions.size === 0) return;

  const scopedPrefixes = [...new Set([...readPrefixes, ...writePrefixes])];
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      sid: "UseEvidenceKeyOnlyThroughS3",
      actions: [...actions],
      resources: [encryptionKey.keyArn],
      conditions: {
        StringEquals: {
          "kms:ViaService": `s3.${Stack.of(role).region}.${Stack.of(role).urlSuffix}`
        },
        StringLike: {
          // S3 Bucket Keys use the bucket ARN as encryption context; direct
          // object-key operations use the object ARN.
          "kms:EncryptionContext:aws:s3:arn": [
            bucket.bucketArn,
            ...scopedPrefixes.map((prefix) => bucket.arnForObjects(prefix))
          ]
        }
      }
    })
  );
}

function httpsUrlParameter(
  scope: Construct,
  id: string,
  description: string,
  defaultValue?: string
): CfnParameter {
  return new CfnParameter(scope, id, {
    type: "String",
    description,
    ...(defaultValue ? { default: defaultValue } : {}),
    minLength: 12,
    maxLength: 2048,
    allowedPattern: "^https://[^\\s]+$",
    constraintDescription: "must be an HTTPS URL"
  });
}

function prefixListIdParameter(
  scope: Construct,
  id: string,
  description: string
): CfnParameter {
  return new CfnParameter(scope, id, {
    type: "String",
    description,
    allowedPattern: "^pl-(?:[0-9a-f]{8}|[0-9a-f]{17})$",
    constraintDescription:
      "must be a managed prefix-list ID such as pl-0123456789abcdef0"
  });
}

function workloadSecurityGroup(
  scope: Construct,
  id: string,
  vpc: ec2.IVpc,
  description: string
): ec2.SecurityGroup {
  return new ec2.SecurityGroup(scope, id, {
    vpc,
    description,
    allowAllOutbound: false,
    allowAllIpv6Outbound: false,
    disableInlineRules: true
  });
}

function privateHttpIntegration(
  vpcLink: apigateway.IVpcLink,
  method: string,
  uri: string,
  requestParameters?: Record<string, string>
): apigateway.Integration {
  return new apigateway.Integration({
    type: apigateway.IntegrationType.HTTP_PROXY,
    integrationHttpMethod: method,
    uri,
    options: {
      connectionType: apigateway.ConnectionType.VPC_LINK,
      vpcLink,
      timeout: Duration.seconds(29),
      requestParameters
    }
  });
}

function managedWafRule(name: string, priority: number): wafv2.CfnWebACL.RuleProperty {
  return {
    name,
    priority,
    overrideAction: { none: {} },
    statement: {
      managedRuleGroupStatement: {
        name,
        vendorName: "AWS"
      }
    },
    visibilityConfig: {
      cloudWatchMetricsEnabled: true,
      metricName: name,
      sampledRequestsEnabled: true
    }
  };
}

function output(scope: Construct, id: string, value: string): void {
  new CfnOutput(scope, id, { value });
}

function pascal(value: string): string {
  return value
    .split("-")
    .filter(Boolean)
    .map((part) => `${part[0]!.toUpperCase()}${part.slice(1)}`)
    .join("");
}
