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
  SecretValue,
  Size,
  Stack,
  type StackProps,
  Tags
} from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as appscaling from "aws-cdk-lib/aws-applicationautoscaling";
import * as bedrockmantle from "aws-cdk-lib/aws-bedrockmantle";
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
const BEDROCK_MANTLE_PROVIDER = "bedrock-mantle";
const BEDROCK_MANTLE_REGION = "eu-west-1";
const BEDROCK_MANTLE_MODEL = "qwen.qwen3-235b-a22b-2507";
const BEDROCK_MANTLE_BASE_URL =
  "https://bedrock-mantle.eu-west-1.api.aws/v1";

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
  readonly repository?: ecr.IRepository;
}

export class ArchonPlatformStack extends Stack {
  private dataHubPrivateLinkAvailabilityZones?: string[];

  public override get availabilityZones(): string[] {
    // The base Stack getter performs an account/region context lookup for
    // concrete environments. Once the deployment parameters exist, every
    // construct uses the exact provider-supported AZ pair selected by
    // preflight. The deploy-time fallback keeps any earlier construction-time
    // access context-free.
    return (
      this.dataHubPrivateLinkAvailabilityZones ?? [
        Fn.select(0, Fn.getAzs()),
        Fn.select(1, Fn.getAzs())
      ]
    );
  }

  constructor(scope: Construct, id: string, props: ArchonPlatformStackProps) {
    super(scope, id, props);

    const { stage } = props;
    if (stage !== "staging" && stage !== "production") {
      throw new Error(
        "ArchonPlatformStack stage must be exactly staging or production"
      );
    }
    const repository =
      props.repository ??
      ecr.Repository.fromRepositoryName(
        this,
        "SharedImmutableRepository",
        "archon-datahub"
      );
    const isProduction = stage === "production";
    const runtimeBoundary = iam.ManagedPolicy.fromManagedPolicyArn(
      this,
      "RuntimePermissionsBoundary",
      `arn:${Aws.PARTITION}:iam::${Aws.ACCOUNT_ID}:policy/archon-datahub-runtime-boundary-${stage}`
    );
    iam.PermissionsBoundary.of(this).apply(runtimeBoundary);
    const publicApiBurstLimit = isProduction ? 100 : 20;
    const publicApiRateLimit = isProduction ? 50 : 10;
    const publicApiDailyQuota = isProduction ? 250_000 : 25_000;
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
    const containerArchiveSha256 = new CfnParameter(
      this,
      "ContainerArchiveSha256",
      {
        type: "String",
        description:
          "SHA-256 of the build-once container archive promoted to this environment",
        allowedPattern: "^[a-f0-9]{64}$",
        constraintDescription: "must be a lowercase 64-character SHA-256"
      }
    );
    const lambdaArchiveSha256 = new CfnParameter(
      this,
      "LambdaArchiveSha256",
      {
        type: "String",
        description:
          "SHA-256 of the build-once Lambda archive promoted to this environment",
        allowedPattern: "^[a-f0-9]{64}$",
        constraintDescription: "must be a lowercase 64-character SHA-256"
      }
    );
    const deploymentWorkflowRunId = new CfnParameter(
      this,
      "DeploymentWorkflowRunId",
      {
        type: "String",
        description: "GitHub Actions deployment workflow run ID",
        allowedPattern: "^[1-9][0-9]{0,19}$",
        constraintDescription: "must be a positive decimal GitHub Actions run ID"
      }
    );
    const deploymentWorkflowRunAttempt = new CfnParameter(
      this,
      "DeploymentWorkflowRunAttempt",
      {
        type: "String",
        description: "GitHub Actions deployment workflow run attempt",
        allowedPattern: "^[1-9][0-9]{0,19}$",
        constraintDescription:
          "must be a positive decimal GitHub Actions run attempt"
      }
    );
    const ciRunId = new CfnParameter(this, "CiRunId", {
      type: "String",
      description:
        "GitHub Actions CI workflow run ID that produced the promoted archives",
      allowedPattern: "^[1-9][0-9]{0,19}$",
      constraintDescription: "must be a positive decimal GitHub Actions run ID"
    });
    const releaseSha = new CfnParameter(this, "ReleaseSha", {
      type: "String",
      description:
        "Source commit represented by the immutable image and promoted archives",
      allowedPattern: "^[a-f0-9]{7,64}$"
    });
    const demoQuery = new CfnParameter(this, "DemoQuery", {
      type: "String",
      description:
        "Exact non-wildcard dataset query exposed by the public judge application",
      minLength: 1,
      maxLength: 256,
      allowedPattern:
        "^(?!\\s)(?!.*\\s$)(?!\\{\\}$)(?!.*[*?])[^\\u0000-\\u001F\\u007F]{1,256}$",
      constraintDescription:
        "must be a trimmed, non-wildcard, control-free query"
    });
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
    const dataHubPrivateLinkServiceName = new CfnParameter(
      this,
      "DataHubPrivateLinkServiceName",
      {
        type: "String",
        description:
          "DataHub Cloud interface VPC endpoint service in eu-west-1; provider private DNS must be verified",
        allowedPattern:
          "^com\\.amazonaws\\.vpce\\.eu-west-1\\.vpce-svc-(?:[0-9a-f]{8}|[0-9a-f]{17})$",
        constraintDescription:
          "must be an eu-west-1 interface endpoint service name such as com.amazonaws.vpce.eu-west-1.vpce-svc-0123456789abcdef0"
      }
    );
    const dataHubPrivateLinkAzOne = dataHubAvailabilityZoneParameter(
      this,
      "DataHubPrivateLinkAzOne"
    );
    const dataHubPrivateLinkAzTwo = dataHubAvailabilityZoneParameter(
      this,
      "DataHubPrivateLinkAzTwo"
    );
    this.dataHubPrivateLinkAvailabilityZones = [
      dataHubPrivateLinkAzOne.valueAsString,
      dataHubPrivateLinkAzTwo.valueAsString
    ];
    const requireDistinctDataHubPrivateLinkAvailabilityZones = new CfnRule(
      this,
      "RequireDistinctDataHubPrivateLinkAvailabilityZones",
      {
        assertions: [
          {
            assert: Fn.conditionNot(
              Fn.conditionEquals(
                dataHubPrivateLinkAzOne.valueAsString,
                dataHubPrivateLinkAzTwo.valueAsString
              )
            ),
            assertDescription:
              "DataHubPrivateLinkAzOne and DataHubPrivateLinkAzTwo must be distinct provider-supported availability zones"
          }
        ]
      }
    );
    requireDistinctDataHubPrivateLinkAvailabilityZones.overrideLogicalId(
      "RequireDistinctDataHubPrivateLinkAvailabilityZones"
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
    const workerDesiredCount = new CfnParameter(this, "WorkerDesiredCount", {
      type: "Number",
      default: 0,
      minValue: 0,
      maxValue: 1,
      description:
        "Bootstrap at 0; set to 1 only for a tested image to activate both isolated workers and their autoscaling floor"
    });
    const bedrockMantleProject = new bedrockmantle.CfnProject(
      this,
      "BedrockMantleProject",
      {
        name: `Archon-${stage}`,
        tags: [
          { key: "Application", value: "archon-datahub" },
          { key: "Environment", value: stage },
          { key: "ManagedBy", value: "aws-cdk" },
          { key: "CostCenter", value: "DataHub-Agent-Hackathon" }
        ]
      }
    );
    bedrockMantleProject.applyRemovalPolicy(RemovalPolicy.RETAIN);

    const dataKey = retainedKey(this, "DataKey", `alias/archon/${stage}/data`);
    const spaKey = retainedKey(this, "SpaKey", `alias/archon/${stage}/spa`);
    const logsKey = retainedKey(this, "LogsKey", `alias/archon/${stage}/logs`);
    grantCloudWatchLogsKeyAccess(this, logsKey, [
      `/archon/${stage}/*`,
      `aws-waf-logs-archon-${stage}-api`,
      `sns/${Aws.REGION}/${Aws.ACCOUNT_ID}/archon-${stage}-alarms`
    ]);
    const queueKey = retainedKey(this, "QueueKey", `alias/archon/${stage}/queues`);
    const secretsKey = retainedKey(this, "SecretsKey", `alias/archon/${stage}/secrets`);
    Tags.of(secretsKey).add("ArchonKeyPurpose", "secrets");

    const vpc = new ec2.Vpc(this, "Vpc", {
      ipAddresses: ec2.IpAddresses.cidr("10.42.0.0/16"),
      availabilityZones: this.availabilityZones,
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
    const dataHubEndpointSecurityGroup = workloadSecurityGroup(
      this,
      "DataHubEndpointSecurityGroup",
      vpc,
      "Dedicated DataHub Cloud PrivateLink boundary reachable only by Archon workloads"
    );
    const bedrockMantleEndpointSecurityGroup = workloadSecurityGroup(
      this,
      "BedrockMantleEndpointSecurityGroup",
      vpc,
      "Dedicated Bedrock Mantle PrivateLink boundary reachable only by inference workloads"
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
      workloadGroup.connections.allowTo(
        dataHubEndpointSecurityGroup,
        ec2.Port.tcp(443),
        "DataHub Cloud PrivateLink HTTPS"
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
      readGroup.connections.allowTo(
        bedrockMantleEndpointSecurityGroup,
        ec2.Port.tcp(443),
        "Bedrock Mantle PrivateLink HTTPS"
      );
    }

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
    const dataHubEndpoint = vpc.addInterfaceEndpoint("DataHubEndpoint", {
      service: new ec2.InterfaceVpcEndpointService(
        dataHubPrivateLinkServiceName.valueAsString,
        443
      ),
      open: false,
      privateDnsEnabled: true,
      securityGroups: [dataHubEndpointSecurityGroup],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }
    });
    const bedrockMantleEndpoint = vpc.addInterfaceEndpoint(
      "BedrockMantleEndpoint",
      {
        service: new ec2.InterfaceVpcEndpointService(
          `com.amazonaws.${Aws.REGION}.bedrock-mantle`,
          443
        ),
        open: false,
        privateDnsEnabled: true,
        securityGroups: [bedrockMantleEndpointSecurityGroup],
        subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }
      }
    );

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
      bucketName: `archon-${stage}-spa-${Aws.ACCOUNT_ID}-${Aws.REGION}`,
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
    const cloudFrontOriginApiKeySecretName =
      `archon/${stage}/cloudfront-origin-api-key`;
    const cloudFrontOriginApiKeySecret = new secretsmanager.Secret(
      this,
      "CloudFrontOriginApiKeySecret",
      {
        secretName: cloudFrontOriginApiKeySecretName,
        description:
          "CloudFront-to-API-Gateway origin credential; never exposed to viewers or stack outputs",
        encryptionKey: secretsKey,
        generateSecretString: {
          secretStringTemplate: JSON.stringify({}),
          generateStringKey: "apiKey",
          excludePunctuation: true,
          includeSpace: false,
          passwordLength: 64
        }
      }
    );
    cloudFrontOriginApiKeySecret.applyRemovalPolicy(RemovalPolicy.RETAIN);
    const cloudFrontOriginApiKeyValue = SecretValue.secretsManager(
      cloudFrontOriginApiKeySecretName,
      { jsonField: "apiKey" }
    ).unsafeUnwrap();

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
        ARCHON_DEMO_QUERY: demoQuery.valueAsString,
        DATAHUB_GMS_URL: dataHubReadUrl.valueAsString,
        DATAHUB_MCP_URL: dataHubReadMcpUrl.valueAsString,
        LLM_PROVIDER: BEDROCK_MANTLE_PROVIDER,
        AWS_REGION: BEDROCK_MANTLE_REGION,
        LLM_BASE_URL: BEDROCK_MANTLE_BASE_URL,
        LLM_MODEL: BEDROCK_MANTLE_MODEL,
        LLM_PROJECT_ID: bedrockMantleProject.attrId
      },
      secrets: {
        DATAHUB_GMS_TOKEN: ecs.Secret.fromSecretsManager(readSecret, "token")
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
        LLM_PROVIDER: BEDROCK_MANTLE_PROVIDER,
        AWS_REGION: BEDROCK_MANTLE_REGION,
        LLM_BASE_URL: BEDROCK_MANTLE_BASE_URL,
        LLM_MODEL: BEDROCK_MANTLE_MODEL,
        LLM_PROJECT_ID: bedrockMantleProject.attrId,
        ARCHON_AUDIT_QUEUE_URL: auditQueue.queueUrl,
        ARCHON_AUDIT_DLQ_URL: auditDlq.queueUrl,
        ARCHON_IDEMPOTENCY_TABLE: idempotencyTable.tableName,
        ARCHON_EVIDENCE_BUCKET: evidenceBucket.bucketName
      },
      secrets: {
        DATAHUB_GMS_TOKEN: ecs.Secret.fromSecretsManager(readSecret, "token")
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
    const bedrockMantleProjectArn = bedrockMantleProject.attrArn;
    const bedrockMantlePrincipals = [
      new iam.ArnPrincipal(apiTaskDefinition.taskRole.roleArn),
      new iam.ArnPrincipal(auditWorkerTaskDefinition.taskRole.roleArn)
    ];
    for (const taskRole of [
      apiTaskDefinition.taskRole,
      auditWorkerTaskDefinition.taskRole
    ]) {
      taskRole.addToPrincipalPolicy(
        new iam.PolicyStatement({
          sid: "InvokeOnlyApprovedBedrockMantleModel",
          actions: ["bedrock-mantle:CreateInference"],
          resources: [bedrockMantleProjectArn],
          conditions: {
            StringEquals: {
              "bedrock-mantle:Model": BEDROCK_MANTLE_MODEL
            }
          }
        })
      );
      taskRole.addToPrincipalPolicy(
        new iam.PolicyStatement({
          sid: "MintOnlyShortTermBedrockMantleBearerTokens",
          actions: ["bedrock-mantle:CallWithBearerToken"],
          resources: ["*"],
          conditions: {
            StringEquals: {
              "bedrock-mantle:BearerTokenType": "SHORT_TERM"
            }
          }
        })
      );
      taskRole.addToPrincipalPolicy(
        new iam.PolicyStatement({
          sid: "DenyLongTermBedrockMantleBearerTokens",
          effect: iam.Effect.DENY,
          actions: ["bedrock-mantle:CallWithBearerToken"],
          resources: ["*"],
          conditions: {
            StringEquals: {
              "bedrock-mantle:BearerTokenType": "LONG_TERM"
            }
          }
        })
      );
    }
    bedrockMantleEndpoint.addToPolicy(
      new iam.PolicyStatement({
        sid: "OnlyInferenceRolesMayInvokeApprovedModel",
        principals: bedrockMantlePrincipals,
        actions: ["bedrock-mantle:CreateInference"],
        resources: [bedrockMantleProjectArn],
        conditions: {
          StringEquals: {
            "bedrock-mantle:Model": BEDROCK_MANTLE_MODEL
          }
        }
      })
    );
    bedrockMantleEndpoint.addToPolicy(
      new iam.PolicyStatement({
        sid: "OnlyInferenceRolesMayUseShortTermTokens",
        principals: bedrockMantlePrincipals,
        actions: ["bedrock-mantle:CallWithBearerToken"],
        resources: ["*"],
        conditions: {
          StringEquals: {
            "bedrock-mantle:BearerTokenType": "SHORT_TERM"
          }
        }
      })
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
      signInCaseSensitive: false,
      standardAttributes: {
        email: { required: true, mutable: false }
      },
      customAttributes: {
        // A random, immutable value written only by the protected judge-user
        // workflow lets compensation distinguish its create from a raced user.
        archon_judge_binding: new cognito.StringAttribute({
          minLen: 64,
          maxLen: 64,
          mutable: false
        })
      },
      passwordPolicy: {
        minLength: 14,
        passwordHistorySize: 24,
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
        EVIDENCE_BUCKET: evidenceBucket.bucketName,
        ARCHON_DEMO_QUERY: demoQuery.valueAsString
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
      apiKeySourceType: apigateway.ApiKeySourceType.HEADER,
      deployOptions: {
        stageName: stage,
        cacheClusterEnabled: true,
        cacheClusterSize: "0.5",
        methodOptions: {
          "/api/control-loops/{auditId}/GET": {
            cacheDataEncrypted: true,
            cacheTtl: Duration.seconds(2),
            cachingEnabled: true,
            dataTraceEnabled: false,
            loggingLevel: apigateway.MethodLoggingLevel.ERROR,
            metricsEnabled: true,
            throttlingBurstLimit: publicApiBurstLimit,
            throttlingRateLimit: publicApiRateLimit
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
        tracingEnabled: true
      },
      // API Gateway's CloudWatch role is an account/region singleton. The
      // foundation stack owns that shared setting so stage stacks cannot
      // overwrite each other's logging identity.
      cloudWatchRole: false,
      binaryMediaTypes: [],
      minCompressionSize: Size.bytes(1024),
      retainDeployments: true
    });
    const cloudFrontOriginApiKey = new apigateway.ApiKey(
      this,
      "CloudFrontOriginApiKey",
      {
        description:
          "High-entropy edge credential injected by CloudFront and never delivered to browsers",
        enabled: true,
        value: cloudFrontOriginApiKeyValue
      }
    );
    cloudFrontOriginApiKey.node.addDependency(cloudFrontOriginApiKeySecret);
    const cloudFrontOriginUsagePlan = new apigateway.UsagePlan(
      this,
      "CloudFrontOriginUsagePlan",
      {
        name: `archon-${stage}-cloudfront-origin`,
        description:
          "Best-effort aggregate throttle and quota guardrail for CloudFront origin-gated requests",
        apiStages: [{ api, stage: api.deploymentStage }],
        throttle: {
          burstLimit: publicApiBurstLimit,
          rateLimit: publicApiRateLimit
        },
        quota: {
          limit: publicApiDailyQuota,
          period: apigateway.Period.DAY
        }
      }
    );
    cloudFrontOriginUsagePlan.addApiKey(cloudFrontOriginApiKey);
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
      apiKeyRequired: true
    };
    const scrubbedOriginCredential = {
      "integration.request.header.x-api-key": "'redacted'"
    };
    const controlStartRequestTemplate = `{
  "operation": "start",
  "requestId": "$util.escapeJavaScript($context.extendedRequestId).replaceAll("\\\\'","'")",
  "body": $input.json('$')
}`;
    const controlStatusRequestTemplate = `{
  "operation": "status",
  "requestId": "$util.escapeJavaScript($context.extendedRequestId).replaceAll("\\\\'","'")",
  "auditId": "$util.escapeJavaScript($input.params('auditId')).replaceAll("\\\\'","'")"
}`;
    const approvalDecisionRequestTemplate = `{
  "operation": "decide",
  "requestId": "$util.escapeJavaScript($context.extendedRequestId).replaceAll("\\\\'","'")",
  "approvalId": "$util.escapeJavaScript($input.params('approvalId')).replaceAll("\\\\'","'")",
  "body": $input.json('$'),
  "identity": {
    "subject": "$util.escapeJavaScript($context.authorizer.claims.sub).replaceAll("\\\\'","'")",
    "issuer": "$util.escapeJavaScript($context.authorizer.claims.iss).replaceAll("\\\\'","'")",
    "groups": "$util.escapeJavaScript($context.authorizer.claims['cognito:groups']).replaceAll("\\\\'","'")"
  }
}`;
    const apiResource = api.root.addResource("api");
    const auditsResource = apiResource.addResource("audits");
    auditsResource.addMethod(
      "POST",
      privateHttpIntegration(
        vpcLink,
        "POST",
        `http://${loadBalancer.loadBalancerDnsName}/api/audits`,
        scrubbedOriginCredential
      ),
      {
        // Judges use the public CloudFront URL without handling credentials. CloudFront
        // overwrites x-api-key with a secret origin credential; direct API Gateway
        // bypasses fail closed. No mutation route reaches this container.
        authorizationType: apigateway.AuthorizationType.NONE,
        requestValidator,
        apiKeyRequired: true,
        requestModels: { "application/json": auditModel }
      }
    );

    const controlLoopsResource = apiResource.addResource("control-loops");
    controlLoopsResource.addMethod(
      "POST",
      narrowLambdaIntegration(controlFunction, controlStartRequestTemplate),
      {
        // The judge journey remains public through CloudFront, while the edge credential
        // prevents direct-origin bypass. A custom integration maps only the validated
        // body and request id, so origin/browser credentials never enter the Lambda event.
        authorizationType: apigateway.AuthorizationType.NONE,
        requestValidator,
        apiKeyRequired: true,
        requestModels: { "application/json": controlLoopModel },
        methodResponses: narrowLambdaMethodResponses([
          "200",
          "202",
          "400",
          "404",
          "413",
          "502"
        ])
      }
    );
    controlLoopsResource
      .addResource("{auditId}")
      .addMethod(
        "GET",
        narrowLambdaIntegration(controlFunction, controlStatusRequestTemplate, {
          cacheKeyParameters: ["method.request.path.auditId"],
          cacheNamespace: "audit-status"
        }),
        {
          authorizationType: apigateway.AuthorizationType.NONE,
          requestValidator,
          apiKeyRequired: true,
          requestParameters: {
            "method.request.path.auditId": true
          },
          methodResponses: narrowLambdaMethodResponses([
            "200",
            "400",
            "404",
            "410",
            "502"
          ])
        }
      );

    const approvalIdResource = apiResource
      .addResource("approvals")
      .addResource("{approvalId}");
    const decisionsResource = approvalIdResource.addResource("decisions");
    decisionsResource.addMethod(
      "POST",
      narrowLambdaIntegration(approvalFunction, approvalDecisionRequestTemplate),
      {
        ...authenticatedMethod,
        authorizationScopes: [approvalScopeName],
        requestParameters: {
          "method.request.path.approvalId": true
        },
        requestModels: { "application/json": decisionModel },
        methodResponses: narrowLambdaMethodResponses([
          "200",
          "202",
          "400",
          "401",
          "403",
          "404",
          "409",
          "410",
          "502"
        ])
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
          },
          {
            action: "SUBSTITUTION",
            excludeRateBasedDetails: false,
            excludeRuleMatchDetails: false,
            field: {
              fieldType: "SINGLE_HEADER",
              fieldKeys: ["x-api-key"]
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
        redactedFields: [
          { singleHeader: { Name: "authorization" } },
          { singleHeader: { Name: "cookie" } },
          { singleHeader: { Name: "x-api-key" } }
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
    const apiOriginRequestPolicy = new cloudfront.OriginRequestPolicy(
      this,
      "ApiOriginRequestPolicy",
      {
        originRequestPolicyName: `archon-${stage}-api-origin`,
        comment:
          "Forward viewer context except Host; CloudFront overwrites the origin credential",
        cookieBehavior: cloudfront.OriginRequestCookieBehavior.all(),
        headerBehavior: cloudfront.OriginRequestHeaderBehavior.denyList("host"),
        queryStringBehavior: cloudfront.OriginRequestQueryStringBehavior.all()
      }
    );
    const apiOrigin = new origins.HttpOrigin(
      `${api.restApiId}.execute-api.${Aws.REGION}.${Aws.URL_SUFFIX}`,
      {
        protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
        originPath: `/${api.deploymentStage.stageName}`,
        customHeaders: {
          "x-api-key": cloudFrontOriginApiKeyValue
        },
        connectionAttempts: 3,
        connectionTimeout: Duration.seconds(10)
      }
    );
    const spaOrigin = origins.S3BucketOrigin.withOriginAccessControl(spaBucket);
    const distribution = new cloudfront.Distribution(this, "Distribution", {
      comment: `Archon ${stage}: private SPA plus same-origin authenticated API`,
      defaultRootObject: "index.html",
      webAclId: cloudFrontWebAclArn.valueAsString,
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
          responseHeadersPolicy,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY
        },
        "api/*": {
          origin: apiOrigin,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          compress: true,
          originRequestPolicy: apiOriginRequestPolicy,
          responseHeadersPolicy,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY
        }
      },
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100
    });
    const cfnDistribution = distribution.node
      .defaultChild as cloudfront.CfnDistribution;
    // CDK omits this object because CloudFront treats the default certificate
    // as implicit. Keep the synthesized and read-back contract explicit so
    // preventive controls can distinguish it from a drifting custom
    // certificate or legacy TLS configuration.
    cfnDistribution.addPropertyOverride(
      "DistributionConfig.ViewerCertificate",
      { CloudFrontDefaultCertificate: true }
    );
    distribution.node.addDependency(cloudFrontOriginApiKeySecret);
    const applicationRootUrl = Fn.join("", [
      "https://",
      distribution.distributionDomainName,
      "/"
    ]);
    const userPoolClient = userPool.addClient("SpaClient", {
      userPoolClientName: `archon-${stage}-spa`,
      // Supplying a non-empty AuthFlow object prevents Cognito's default
      // USER_SRP/CUSTOM direct-auth surfaces. The remaining explicit flow is
      // refresh-token auth; interactive sign-in is OAuth code + browser PKCE.
      authFlows: { userSrp: false },
      generateSecret: false,
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
      readAttributes: new cognito.ClientAttributes().withStandardAttributes({
        email: true
      }),
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
          // Deliberately omit aws.cognito.signin.user.admin. The shared judge
          // credential can approve through its narrow API scope but cannot use
          // an access token to invoke Cognito ChangePassword.
          cognito.OAuthScope.resourceServer(resourceServer, approvalScope)
        ]
      }
    });
    const cfnUserPoolClient = userPoolClient.node
      .defaultChild as cognito.CfnUserPoolClient;
    // Keep the deployed/read-back contract canonical. The L2 currently serializes a
    // one-day refresh token as 1,440 minutes, which is semantically equivalent but
    // would defeat the exact lifecycle drift guard.
    cfnUserPoolClient.refreshTokenValidity = 1;
    cfnUserPoolClient.tokenValidityUnits = {
      accessToken: "minutes",
      idToken: "minutes",
      refreshToken: "days"
    };
    new cognito.CfnUserPoolRiskConfigurationAttachment(
      this,
      "SpaRiskConfiguration",
      {
        userPoolId: userPool.userPoolId,
        clientId: userPoolClient.userPoolClientId,
        // A shared judge account legitimately moves between reviewers,
        // networks, and geographies. Avoid adaptive lockout or email/MFA
        // challenges that this identity has no per-reviewer recovery path for.
        accountTakeoverRiskConfiguration: {
          actions: {
            lowAction: { eventAction: "NO_ACTION", notify: false },
            mediumAction: { eventAction: "NO_ACTION", notify: false },
            highAction: { eventAction: "NO_ACTION", notify: false }
          }
        },
        // Known-compromised credentials remain a hard stop for every event in
        // which this client can submit an existing password.
        compromisedCredentialsRiskConfiguration: {
          actions: { eventAction: "BLOCK" },
          eventFilter: ["SIGN_IN", "PASSWORD_CHANGE"]
        }
      }
    );
    const cognitoWebAclAssociation = new wafv2.CfnWebACLAssociation(
      this,
      "CognitoWebAclAssociation",
      {
        resourceArn: userPool.userPoolArn,
        webAclArn: webAcl.attrArn
      }
    );
    // The same regional ACL protects both the API stage and the Cognito
    // hosted-UI/public API surface. Its rules deliberately exclude Cognito
    // ATP/ACFP managed groups and CAPTCHA actions, which are incompatible with
    // or unsafe for a shared managed-login judge path.
    cognitoWebAclAssociation.node.addDependency(userPool);
    cognitoWebAclAssociation.node.addDependency(webAcl);
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

    const alarmTopicName = `archon-${stage}-alarms`;
    const alarmTopicArn =
      `arn:${Aws.PARTITION}:sns:${Aws.REGION}:${Aws.ACCOUNT_ID}:${alarmTopicName}`;
    const alarmDeliveryLogGroupName =
      `sns/${Aws.REGION}/${Aws.ACCOUNT_ID}/${alarmTopicName}`;
    const alarmDeliveryLogGroupArn = this.formatArn({
      service: "logs",
      resource: "log-group",
      resourceName: alarmDeliveryLogGroupName,
      arnFormat: ArnFormat.COLON_RESOURCE_NAME
    });
    const alarmDeliveryLogGroup = retainedLogGroup(
      this,
      "AlarmDeliveryLogGroup",
      alarmDeliveryLogGroupName,
      logsKey
    );
    const alarmDeliveryStatusRole = new iam.Role(
      this,
      "AlarmDeliveryStatusRole",
      {
        roleName: `archon-${stage}-sns-delivery-status`,
        description:
          "Lets Amazon SNS write only Archon alarm delivery status to CloudWatch Logs",
        assumedBy: new iam.ServicePrincipal("sns.amazonaws.com", {
          conditions: {
            StringEquals: {
              "aws:SourceAccount": Aws.ACCOUNT_ID
            },
            ArnEqualsIfExists: {
              "aws:SourceArn": alarmTopicArn
            }
          }
        })
      }
    );
    alarmDeliveryStatusRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "CreateOnlyArchonAlarmDeliveryLogGroups",
        actions: ["logs:CreateLogGroup"],
        resources: [alarmDeliveryLogGroupArn]
      })
    );
    alarmDeliveryStatusRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "WriteOnlyArchonAlarmDeliveryLogStreams",
        actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
        resources: [`${alarmDeliveryLogGroupArn}:log-stream:*`]
      })
    );
    alarmDeliveryStatusRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "UseExactLogsKeyOnlyThroughCloudWatchLogs",
        actions: [
          "kms:Encrypt",
          "kms:ReEncrypt*",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ],
        resources: [logsKey.keyArn],
        conditions: {
          StringEquals: {
            "kms:ViaService":
              `logs.${Aws.REGION}.${Aws.URL_SUFFIX}`
          }
        }
      })
    );
    alarmDeliveryStatusRole.applyRemovalPolicy(RemovalPolicy.RETAIN);
    logsKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: "AllowAccountCloudWatchAlarmsToPublishEncryptedAlerts",
        principals: [new iam.ServicePrincipal("cloudwatch.amazonaws.com")],
        actions: ["kms:GenerateDataKey*", "kms:Decrypt"],
        resources: ["*"],
        conditions: {
          StringEquals: {
            "aws:SourceAccount": Aws.ACCOUNT_ID,
            "kms:EncryptionContext:aws:sns:topicArn":
              alarmTopicArn
          },
          ArnLike: {
            "aws:SourceArn":
              `arn:${Aws.PARTITION}:cloudwatch:${Aws.REGION}:${Aws.ACCOUNT_ID}:alarm:*`
          }
        }
      })
    );

    const alarmTopic = new sns.Topic(this, "AlarmTopic", {
      topicName: alarmTopicName,
      masterKey: logsKey,
      enforceSSL: true,
      loggingConfigs: [
        {
          protocol: sns.LoggingProtocol.HTTP,
          failureFeedbackRole: alarmDeliveryStatusRole,
          successFeedbackRole: alarmDeliveryStatusRole,
          successFeedbackSampleRate: 100
        }
      ]
    });
    alarmTopic.node.addDependency(alarmDeliveryLogGroup);
    alarmTopic.applyRemovalPolicy(RemovalPolicy.RETAIN);
    alarmTopic.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: "AllowAccountCloudWatchAlarmsToPublishAlerts",
        principals: [new iam.ServicePrincipal("cloudwatch.amazonaws.com")],
        actions: ["sns:Publish"],
        resources: [alarmTopic.topicArn],
        conditions: {
          StringEquals: {
            "aws:SourceAccount": Aws.ACCOUNT_ID
          },
          ArnLike: {
            "aws:SourceArn":
              `arn:${Aws.PARTITION}:cloudwatch:${Aws.REGION}:${Aws.ACCOUNT_ID}:alarm:*`
          }
        }
      })
    );
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

    const preferredApiUrl = Fn.join("", [
      "https://",
      distribution.distributionDomainName,
      "/api"
    ]);
    output(this, "ArchonSpaBucketName", spaBucket.bucketName);
    output(this, "ArchonSpaKeyArn", spaKey.keyArn);
    output(this, "ArchonEvidenceBucketName", evidenceBucket.bucketName);
    output(this, "ArchonCloudFrontDistributionId", distribution.distributionId);
    output(this, "ArchonCloudFrontDomainName", distribution.distributionDomainName);
    output(
      this,
      "ArchonApplicationUrl",
      Fn.join("", ["https://", distribution.distributionDomainName])
    );
    output(this, "ArchonApiUrl", preferredApiUrl);
    output(this, "ArchonApiInvokeUrl", api.url);
    output(this, "ArchonApiStageArn", apiStageArn);
    output(this, "ArchonRegionalWebAclArn", webAcl.attrArn);
    output(this, "ArchonRegionalWafLogGroupName", apiWafLogGroup.logGroupName);
    output(this, "ArchonRegionalWafLogKeyArn", logsKey.keyArn);
    output(this, "ArchonUserPoolId", userPool.userPoolId);
    output(this, "ArchonUserPoolArn", userPool.userPoolArn);
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
    output(
      this,
      "ArchonDataHubEndpointSecurityGroupId",
      dataHubEndpointSecurityGroup.securityGroupId
    );
    output(
      this,
      "ArchonDataHubEndpointId",
      dataHubEndpoint.vpcEndpointId
    );
    output(
      this,
      "ArchonDataHubEndpointServiceName",
      dataHubPrivateLinkServiceName.valueAsString
    );
    output(
      this,
      "ArchonDataHubPrivateLinkAzOne",
      dataHubPrivateLinkAzOne.valueAsString
    );
    output(
      this,
      "ArchonDataHubPrivateLinkAzTwo",
      dataHubPrivateLinkAzTwo.valueAsString
    );
    output(
      this,
      "ArchonBedrockMantleEndpointSecurityGroupId",
      bedrockMantleEndpointSecurityGroup.securityGroupId
    );
    output(
      this,
      "ArchonBedrockMantleEndpointId",
      bedrockMantleEndpoint.vpcEndpointId
    );
    output(
      this,
      "ArchonBedrockMantleEndpointServiceName",
      `com.amazonaws.${Aws.REGION}.bedrock-mantle`
    );
    output(this, "ArchonBedrockMantleModel", BEDROCK_MANTLE_MODEL);
    output(
      this,
      "ArchonBedrockMantleProjectId",
      bedrockMantleProject.attrId
    );
    output(
      this,
      "ArchonBedrockMantleProjectArn",
      bedrockMantleProject.attrArn
    );
    output(
      this,
      "ArchonApiTaskRoleArn",
      apiTaskDefinition.taskRole.roleArn
    );
    output(
      this,
      "ArchonAuditWorkerTaskRoleArn",
      auditWorkerTaskDefinition.taskRole.roleArn
    );
    output(
      this,
      "ArchonRemediationWorkerTaskRoleArn",
      remediationWorkerTaskDefinition.taskRole.roleArn
    );
    output(this, "ArchonReadSecretArn", readSecret.secretArn);
    output(this, "ArchonWriteSecretArn", writeSecret.secretArn);
    output(this, "ArchonAlarmTopicArn", alarmTopic.topicArn);
    output(this, "ArchonAlarmTopicKmsKeyArn", logsKey.keyArn);
    output(
      this,
      "ArchonAlarmDeliveryFeedbackRoleArn",
      alarmDeliveryStatusRole.roleArn
    );
    output(
      this,
      "ArchonAlarmDeliveryLogGroupName",
      alarmDeliveryLogGroup.logGroupName
    );
    output(this, "ArchonContainerImageDigest", imageDigest.valueAsString);
    output(this, "ArchonSpaArtifactSha256", spaArtifactSha256.valueAsString);
    output(
      this,
      "ArchonContainerArchiveSha256",
      containerArchiveSha256.valueAsString
    );
    output(
      this,
      "ArchonLambdaArchiveSha256",
      lambdaArchiveSha256.valueAsString
    );
    output(
      this,
      "ArchonDeploymentWorkflowRunId",
      deploymentWorkflowRunId.valueAsString
    );
    output(
      this,
      "ArchonDeploymentWorkflowRunAttempt",
      deploymentWorkflowRunAttempt.valueAsString
    );
    output(this, "ArchonCiRunId", ciRunId.valueAsString);
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

function dataHubAvailabilityZoneParameter(
  scope: Construct,
  id: string
): CfnParameter {
  return new CfnParameter(scope, id, {
    type: "String",
    description:
      "Provider-supported eu-west-1 availability zone selected by the deployment preflight",
    allowedPattern: "^eu-west-1[a-z]$",
    constraintDescription:
      "must be a concrete eu-west-1 availability zone such as eu-west-1a"
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

const narrowLambdaBaseResponseParameters: Record<string, string> = {
  "method.response.header.Cache-Control": "'no-store'",
  "method.response.header.Content-Type":
    "'application/json; charset=utf-8'",
  "method.response.header.Cross-Origin-Resource-Policy": "'same-origin'",
  "method.response.header.Referrer-Policy": "'no-referrer'",
  "method.response.header.X-Content-Type-Options": "'nosniff'"
};

const narrowLambdaResponseParameters: Record<string, string> = {
  ...narrowLambdaBaseResponseParameters,
  "method.response.header.Location":
    "integration.response.body.headers.location",
  "method.response.header.Retry-After":
    "integration.response.body.headers.retryAfter"
};

const narrowLambdaMethodResponseParameters: Record<string, boolean> =
  Object.fromEntries(
    Object.keys(narrowLambdaResponseParameters).map((parameter) => [
      parameter,
      parameter !== "method.response.header.Location" &&
        parameter !== "method.response.header.Retry-After"
    ])
  );

function narrowLambdaIntegration(
  handler: lambda.IFunction,
  requestTemplate: string,
  cache: {
    cacheKeyParameters?: string[];
    cacheNamespace?: string;
  } = {}
): apigateway.LambdaIntegration {
  return new apigateway.LambdaIntegration(handler, {
    proxy: false,
    allowTestInvoke: false,
    passthroughBehavior: apigateway.PassthroughBehavior.NEVER,
    requestTemplates: {
      "application/json": requestTemplate
    },
    cacheKeyParameters: cache.cacheKeyParameters,
    cacheNamespace: cache.cacheNamespace,
    integrationResponses: [
      {
        selectionPattern: "(?s).+",
        statusCode: "502",
        responseParameters: narrowLambdaBaseResponseParameters,
        responseTemplates: {
          "application/json": '{"error":"lambda_integration_failed"}\n'
        }
      },
      {
        statusCode: "200",
        responseParameters: narrowLambdaResponseParameters,
        responseTemplates: {
          "application/json": [
            "#set($statusCode = $input.path('$.statusCode'))",
            "#set($context.responseOverride.status = $statusCode)",
            "$input.json('$.payload')"
          ].join("\n")
        }
      }
    ]
  });
}

function narrowLambdaMethodResponses(
  statusCodes: string[]
): apigateway.MethodResponse[] {
  return [...new Set(statusCodes)].map((statusCode) => ({
    statusCode,
    responseParameters: narrowLambdaMethodResponseParameters
  }));
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
