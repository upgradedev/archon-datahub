import {
  ArnFormat,
  Aws,
  CfnOutput,
  CfnParameter,
  CfnResource,
  Duration,
  Fn,
  RemovalPolicy,
  Stack,
  Tags,
  type StackProps
} from "aws-cdk-lib";
import * as autoscaling from "aws-cdk-lib/aws-autoscaling";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as events from "aws-cdk-lib/aws-events";
import * as eventTargets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as logs from "aws-cdk-lib/aws-logs";
import * as sfn from "aws-cdk-lib/aws-stepfunctions";
import * as tasks from "aws-cdk-lib/aws-stepfunctions-tasks";
import { Construct } from "constructs";
import { join } from "node:path";

export interface ArchonEphemeralDataHubCoreStackProps extends StackProps {
  readonly stage: "staging" | "production";
}

/**
 * A zero-idle-compute, independently deployable DataHub Core runtime.
 *
 * This stack deliberately has no dependency on DataHub Cloud, the primary
 * Archon platform VPC, or any Cloud-only URL/token. The EC2 host has no public
 * path. A tiny adapter on the pre-baked image exchanges bounded jobs and
 * receipts through the lease table, calls the companion on loopback :8080,
 * and keeps Analytics Agent loopback-only on :8100.
 */
export class ArchonEphemeralDataHubCoreStack extends Stack {
  readonly leaseTable: dynamodb.Table;
  readonly sessionStateMachine: sfn.StateMachine;
  readonly autoScalingGroup: autoscaling.AutoScalingGroup;

  public override get availabilityZones(): string[] {
    return [Fn.select(0, Fn.getAzs(""))];
  }

  constructor(
    scope: Construct,
    id: string,
    props: ArchonEphemeralDataHubCoreStackProps
  ) {
    super(scope, id, props);
    const { stage } = props;

    const runtimeBoundary = iam.ManagedPolicy.fromManagedPolicyArn(
      this,
      "RuntimePermissionsBoundary",
      `arn:${Aws.PARTITION}:iam::${Aws.ACCOUNT_ID}:policy/archon-datahub-runtime-boundary-${stage}`
    );
    iam.PermissionsBoundary.of(this).apply(runtimeBoundary);

    const imageId = new CfnParameter(this, "DataHubCoreAmiId", {
      type: "AWS::EC2::Image::Id",
      description:
        "Exact CI-baked DataHub Core AMI. The lifecycle gate also verifies immutable AMI tags before any scale-up."
    });
    const generation = new CfnParameter(this, "DataHubCoreGeneration", {
      type: "String",
      description: "Immutable runtime generation bound to the CI-baked AMI",
      minLength: 1,
      maxLength: 128,
      allowedPattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
    });
    const capabilityDigest = new CfnParameter(
      this,
      "DataHubCoreCapabilityDigest",
      {
        type: "String",
        description:
          "Exact canonical capability digest attested by the Core AMI build",
        allowedPattern: "^sha256:[a-f0-9]{64}$"
      }
    );
    const imageManifestDigest = new CfnParameter(
      this,
      "DataHubCoreImageManifestDigest",
      {
        type: "String",
        description:
          "SHA-256 of the signed AMI component and container inventory",
        allowedPattern: "^sha256:[a-f0-9]{64}$"
      }
    );
    const dynamoDbPrefixListId = new CfnParameter(
      this,
      "DynamoDbPrefixListId",
      {
        type: "String",
        description:
          "AWS-managed regional DynamoDB prefix-list ID used as the host's only network egress",
        allowedPattern: "^pl-(?:[0-9a-f]{8}|[0-9a-f]{17})$"
      }
    );

    const exactInferenceProfile =
      "eu.anthropic.claude-sonnet-4-5-20250929-v1:0";
    const exactBaseModel = "anthropic.claude-sonnet-4-5-20250929-v1:0";
    const llmModelId = new CfnParameter(this, "DataHubCoreBedrockModelId", {
      type: "String",
      description:
        "Exact EU Bedrock inference-profile ID preflighted before Core readiness",
      default: exactInferenceProfile,
      allowedValues: [exactInferenceProfile]
    });
    const llmBaseModelId = new CfnParameter(
      this,
      "DataHubCoreBedrockBaseModelId",
      {
        type: "String",
        description:
          "Exact underlying foundation model bound by the AMI manifest and IAM",
        default: exactBaseModel,
        allowedValues: [exactBaseModel]
      }
    );
    const demoQuery = new CfnParameter(this, "DataHubCoreDemoQuery", {
      type: "String",
      description: "The one exact source dataset admitted by the judge demo",
      default:
        "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)",
      allowedValues: [
        "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
      ]
    });
    const analyticsQuestion = new CfnParameter(
      this,
      "DataHubCoreAnalyticsQuestion",
      {
        type: "String",
        description: "The one exact portable Analytics Agent judge question",
        default:
          "Which customer segment generated the highest net revenue in Q2 2026, and is customers.customer_email governed as PII?",
        allowedValues: [
          "Which customer segment generated the highest net revenue in Q2 2026, and is customers.customer_email governed as PII?"
        ]
      }
    );
    const bedrockRuntimeServiceName =
      `com.amazonaws.${Aws.REGION}.bedrock-runtime`;
    const kmsServiceName = `com.amazonaws.${Aws.REGION}.kms`;
    const stsServiceName = `com.amazonaws.${Aws.REGION}.sts`;
    const exactBedrockInferenceProfileArn =
      "arn:" + Aws.PARTITION + ":bedrock:" + Aws.REGION + ":" +
      Aws.ACCOUNT_ID + ":inference-profile/" + llmModelId.valueAsString;
    const exactBedrockFoundationModelArns = [
      "eu-central-1",
      "eu-north-1",
      "eu-south-1",
      "eu-south-2",
      "eu-west-1",
      "eu-west-3"
    ].map(
      (region) =>
        "arn:" + Aws.PARTITION + ":bedrock:" + region +
        "::foundation-model/" + llmBaseModelId.valueAsString
    );
    const exactBedrockResources = [
      exactBedrockInferenceProfileArn,
      ...exactBedrockFoundationModelArns
    ];

    const dataKey = new kms.Key(this, "DataKey", {
      alias: `alias/archon/${stage}/datahub-core-data`,
      description: "DataHub Core lease, health, job, and receipt encryption",
      enableKeyRotation: true,
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN
    });
    const mutationSigningKey = new kms.Key(this, "MutationSigningKey", {
      alias: `alias/archon/${stage}/datahub-core-mutation-signing`,
      description:
        "Off-host remediation authorization; Core receives public verification material only",
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN
    });
    const logsKey = new kms.Key(this, "LogsKey", {
      alias: `alias/archon/${stage}/datahub-core-logs`,
      description: "DataHub Core lifecycle observability encryption",
      enableKeyRotation: true,
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN
    });
    allowCloudWatchLogs(logsKey, stage);

    this.leaseTable = new dynamodb.Table(this, "CoreLeaseTable", {
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dataKey,
      deletionProtection: true,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true
      },
      timeToLiveAttribute: "expiresAt",
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      contributorInsightsSpecification: { enabled: true },
      removalPolicy: RemovalPolicy.RETAIN
    });
    Tags.of(this.leaseTable).add("Purpose", `${stage}-datahub-core-runtime`);

    const vpc = new ec2.Vpc(this, "CoreVpc", {
      ipAddresses: ec2.IpAddresses.cidr("10.77.0.0/24"),
      availabilityZones: [Fn.select(0, Fn.getAzs(""))],
      natGateways: 0,
      restrictDefaultSecurityGroup: true,
      subnetConfiguration: [
        {
          name: "isolated-core",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 26
        }
      ]
    });

    const flowLogGroup = new logs.LogGroup(
      this,
      "CoreVpcFlowLogGroup",
      {
        logGroupName:
          `/archon/${stage}/datahub-core/vpc-flow`,
        encryptionKey: logsKey,
        retention: logs.RetentionDays.ONE_YEAR,
        removalPolicy: RemovalPolicy.RETAIN
      }
    );
    const flowLogRole = new iam.Role(this, "CoreVpcFlowLogRole", {
      description:
        "Exact VPC Flow Logs delivery role for the isolated Core VPC",
      assumedBy:
        new iam.ServicePrincipal("vpc-flow-logs.amazonaws.com")
    });
    new ec2.FlowLog(this, "CoreVpcFlowLog", {
      resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
      destination:
        ec2.FlowLogDestination.toCloudWatchLogs(
          flowLogGroup,
          flowLogRole
        ),
      trafficType: ec2.FlowLogTrafficType.ALL,
      maxAggregationInterval:
        ec2.FlowLogMaxAggregationInterval.TEN_MINUTES
    });

    // CDK's default-SG restriction is a framework custom resource. Keep that
    // defense in depth, while bringing its generated provider under the same
    // bounded-concurrency and X-Ray controls as every application Lambda.
    const restrictDefaultSgProvider = this.node.tryFindChild(
      "Custom::VpcRestrictDefaultSGCustomResourceProvider"
    );
    const restrictDefaultSgHandler =
      restrictDefaultSgProvider?.node.tryFindChild("Handler");
    const restrictDefaultSgRole =
      restrictDefaultSgProvider?.node.tryFindChild("Role");
    if (
      !(restrictDefaultSgHandler instanceof CfnResource) ||
      !(restrictDefaultSgRole instanceof CfnResource)
    ) {
      throw new Error("CDK default-security-group provider contract changed");
    }
    restrictDefaultSgHandler.addPropertyOverride(
      "ReservedConcurrentExecutions",
      1
    );
    restrictDefaultSgHandler.addPropertyOverride("TracingConfig.Mode", "Active");
    new iam.CfnPolicy(this, "RestrictDefaultSgProviderXRayPolicy", {
      policyName: `archon-${stage}-default-sg-provider-xray`,
      roles: [restrictDefaultSgRole.ref],
      policyDocument: new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            actions: ["xray:PutTelemetryRecords", "xray:PutTraceSegments"],
            resources: ["*"]
          })
        ]
      })
    });

    const dynamoEndpoint = vpc.addGatewayEndpoint("DynamoDbEndpoint", {
      service: ec2.GatewayVpcEndpointAwsService.DYNAMODB,
      subnets: [{ subnetType: ec2.SubnetType.PRIVATE_ISOLATED }]
    });
    dynamoEndpoint.addToPolicy(
      new iam.PolicyStatement({
        sid: "OnlyCoreRuntimeTable",
        principals: [new iam.AnyPrincipal()],
        actions: [
          "dynamodb:DescribeTable",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem"
        ],
        resources: [this.leaseTable.tableArn]
      })
    );

    const hostSecurityGroup = new ec2.SecurityGroup(
      this,
      "CoreHostSecurityGroup",
      {
        vpc,
        description:
          "No ingress; HTTPS egress can only follow the DynamoDB gateway route",
        allowAllOutbound: false,
        allowAllIpv6Outbound: false,
        disableInlineRules: true
      }
    );
    hostSecurityGroup.addEgressRule(
      ec2.Peer.prefixList(dynamoDbPrefixListId.valueAsString),
      ec2.Port.tcp(443),
      "DynamoDB gateway endpoint only"
    );
    const inferenceEndpointSecurityGroup = new ec2.SecurityGroup(
      this,
      "CoreInferenceEndpointSecurityGroup",
      {
        vpc,
        description:
          "Ephemeral Bedrock Runtime, KMS, and STS endpoints accept TLS only from the Core host",
        allowAllOutbound: false,
        allowAllIpv6Outbound: false,
        disableInlineRules: true
      }
    );
    inferenceEndpointSecurityGroup.addIngressRule(
      hostSecurityGroup,
      ec2.Port.tcp(443),
      "Core host to ephemeral Bedrock Runtime, KMS, and STS endpoints"
    );
    hostSecurityGroup.addEgressRule(
      inferenceEndpointSecurityGroup,
      ec2.Port.tcp(443),
      "Ephemeral session-owned Bedrock Runtime, KMS, and STS interface endpoints only"
    );

    const instanceRole = new iam.Role(this, "CoreInstanceRole", {
      roleName: `archon-${stage}-datahub-core-host`,
      assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
      description:
        "DataHub Core host reads its lease and exchanges bounded health/job receipts",
      maxSessionDuration: Duration.hours(1)
    });
    instanceRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "DescribeOnlyCoreRuntimeTable",
        actions: ["dynamodb:DescribeTable"],
        resources: [this.leaseTable.tableArn]
      })
    );
    instanceRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "ReadOnlyCoreRuntimeRecords",
        actions: ["dynamodb:GetItem", "dynamodb:Query"],
        resources: [this.leaseTable.tableArn],
        conditions: {
          "ForAllValues:StringLike": {
            "dynamodb:LeadingKeys": [
              "CORE#LEASE",
              "RUNTIME#core",
              "SESSION#rs_*",
              "MUTATION#rs_*"
            ]
          },
          Null: { "dynamodb:LeadingKeys": "false" }
        }
      })
    );
    instanceRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "PublishOnlyCoreRuntimeHealth",
        actions: ["dynamodb:PutItem"],
        resources: [this.leaseTable.tableArn],
        conditions: {
          "ForAllValues:StringEquals": {
            "dynamodb:LeadingKeys": ["RUNTIME#core"]
          },
          Null: { "dynamodb:LeadingKeys": "false" }
        }
      })
    );
    instanceRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "TransitionOnlyExistingCoreRuntimeRecords",
        actions: ["dynamodb:UpdateItem"],
        resources: [this.leaseTable.tableArn],
        conditions: {
          "ForAllValues:StringLike": {
            "dynamodb:LeadingKeys": [
              "CORE#LEASE",
              "SESSION#rs_*",
              "MUTATION#rs_*"
            ]
          },
          Null: { "dynamodb:LeadingKeys": "false" }
        }
      })
    );


    const lifecycleRole = new iam.Role(this, "CoreLifecycleRole", {
      roleName: `archon-${stage}-datahub-core-lifecycle`,
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      description:
        "Exact lease, endpoint, KMS-encryption, and scoped-credential authority; no Bedrock invoke",
      maxSessionDuration: Duration.hours(1)
    });
    const analyticsRole = new iam.Role(this, "CoreAnalyticsRole", {
      roleName: `archon-${stage}-datahub-core-analytics`,
      assumedBy: new iam.ArnPrincipal(lifecycleRole.roleArn),
      description:
        "One-hour role-chained credentials for the Analytics Agent; Bedrock invoke only",
      maxSessionDuration: Duration.hours(1)
    });
    const bedrockInvokeActions = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream"
    ];
    analyticsRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "InvokeOnlyConfiguredBedrockInferenceProfile",
        actions: bedrockInvokeActions,
        resources: [exactBedrockInferenceProfileArn]
      })
    );
    analyticsRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "InvokeConfiguredBedrockModelsOnlyThroughProfile",
        actions: bedrockInvokeActions,
        resources: exactBedrockFoundationModelArns,
        conditions: {
          StringEquals: {
            "bedrock:InferenceProfileArn":
              exactBedrockInferenceProfileArn
          }
        }
      })
    );
    const gatewayRole = new iam.Role(this, "CoreGovernedGatewayRole", {
      roleName: `archon-${stage}-datahub-core-gateway`,
      assumedBy: new iam.ArnPrincipal(lifecycleRole.roleArn),
      description:
        "One-hour governed gateway credentials; exact lease/job CAS and mutation public-key verification only",
      maxSessionDuration: Duration.hours(1)
    });
    gatewayRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "ReadOnlyActiveCoreLease",
        actions: ["dynamodb:GetItem"],
        resources: [this.leaseTable.tableArn],
        conditions: {
          "ForAllValues:StringEquals": {
            "dynamodb:LeadingKeys": ["CORE#LEASE"]
          },
          Null: { "dynamodb:LeadingKeys": "false" }
        }
      })
    );
    gatewayRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "ConsumeOnlyBoundMutationJobs",
        actions: ["dynamodb:UpdateItem"],
        resources: [this.leaseTable.tableArn],
        conditions: {
          "ForAllValues:StringLike": {
            "dynamodb:LeadingKeys": ["MUTATION#rs_*"]
          },
          Null: { "dynamodb:LeadingKeys": "false" }
        }
      })
    );
    const credentialContextEquals = {
      "kms:EncryptionContext:stage": stage,
      "kms:EncryptionContext:generation": generation.valueAsString,
      "kms:EncryptionContext:capabilityDigest": capabilityDigest.valueAsString,
      "kms:EncryptionContext:capability": [
        "analytics-agent-bedrock",
        "governed-gateway-control"
      ]
    };
    const credentialContextLike = {
      "kms:EncryptionContext:sessionId": "rs_*"
    };
    mutationSigningKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: "AllowExactGovernedGatewayPublicKeyRead",
        principals: [new iam.ArnPrincipal(gatewayRole.roleArn)],
        actions: ["kms:GetPublicKey", "kms:DescribeKey"],
        resources: ["*"]
      })
    );
    gatewayRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "GetOnlyPinnedMutationVerificationKey",
        actions: ["kms:GetPublicKey", "kms:DescribeKey"],
        resources: [mutationSigningKey.keyArn]
      })
    );
    instanceRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "DecryptOnlyActiveScopedCredentials",
        actions: ["kms:Decrypt"],
        resources: [dataKey.keyArn],
        conditions: {
          StringEquals: credentialContextEquals,
          StringLike: credentialContextLike
        }
      })
    );
    dataKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: "AllowExactLifecycleCredentialEncryption",
        principals: [new iam.ArnPrincipal(lifecycleRole.roleArn)],
        actions: ["kms:Encrypt"],
        resources: ["*"],
        conditions: {
          StringEquals: credentialContextEquals,
          StringLike: credentialContextLike
        }
      })
    );
    dataKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: "AllowExactHostCredentialDecryption",
        principals: [new iam.ArnPrincipal(instanceRole.roleArn)],
        actions: ["kms:Decrypt"],
        resources: ["*"],
        conditions: {
          StringEquals: credentialContextEquals,
          StringLike: credentialContextLike
        }
      })
    );

    const userData = ec2.UserData.forLinux();
    userData.addCommands(
      "set -euo pipefail",
      "umask 077",
      "install -d -m 0750 -o root -g root /etc/archon",
      "cat > /etc/archon/datahub-core.env <<'ARCHON_ENV'",
      `AWS_REGION=${Aws.REGION}`,
      `ARCHON_STAGE=${stage}`,
      `CORE_LEASE_TABLE=${this.leaseTable.tableName}`,
      "ARCHON_RUNTIME_PROFILE_ID=core",
      `ARCHON_RUNTIME_GENERATION=${generation.valueAsString}`,
      `ARCHON_RUNTIME_CAPABILITY_DIGEST=${capabilityDigest.valueAsString}`,
      `ARCHON_IMAGE_MANIFEST_DIGEST=${imageManifestDigest.valueAsString}`,
      `ARCHON_CORE_DATA_KEY_ARN=${dataKey.keyArn}`,
      `ARCHON_MUTATION_SIGNING_KEY_ARN=${mutationSigningKey.keyArn}`,
      `ARCHON_EXPECTED_ANALYTICS_ROLE_ARN=${analyticsRole.roleArn}`,
      "AWS_STS_REGIONAL_ENDPOINTS=regional",
      "ARCHON_LLM_PROVIDER=bedrock",
      `ARCHON_LLM_MODEL=${llmModelId.valueAsString}`,
      `ARCHON_CHART_LLM_MODEL=${llmModelId.valueAsString}`,
      `ARCHON_QUALITY_LLM_MODEL=${llmModelId.valueAsString}`,
      `ARCHON_DELIGHT_LLM_MODEL=${llmModelId.valueAsString}`,
      `ARCHON_DEMO_QUERY=${demoQuery.valueAsString}`,
      `ARCHON_ANALYTICS_QUESTION=${analyticsQuestion.valueAsString}`,
      "ARCHON_COMPANION_URL=http://127.0.0.1:8080",
      "ARCHON_ANALYTICS_AGENT_URL=http://127.0.0.1:8100",
      "ARCHON_DATAHUB_GMS_URL=http://127.0.0.1:18080",
      "ARCHON_ENV",
      "chmod 0600 /etc/archon/datahub-core.env",
      "systemctl enable --now archon-datahub-core.service"
    );

    const coreLaunchTemplate = new ec2.LaunchTemplate(
      this,
      "CoreLaunchTemplate",
      {
        associatePublicIpAddress: false,
        blockDevices: [
          {
            deviceName: "/dev/xvda",
            volume: ec2.BlockDeviceVolume.ebs(50, {
              encrypted: true,
              deleteOnTermination: true,
              volumeType: ec2.EbsDeviceVolumeType.GP3,
              iops: 3000,
              throughput: 125
            })
          }
        ],
        httpEndpoint: true,
        instanceType: new ec2.InstanceType("t3a.xlarge"),
        machineImage: ec2.MachineImage.genericLinux({
          "eu-west-1": imageId.valueAsString
        }),
        requireImdsv2: true,
        role: instanceRole,
        securityGroup: hostSecurityGroup,
        userData
      }
    );
    this.autoScalingGroup = new autoscaling.AutoScalingGroup(
      this,
      "CoreAutoScalingGroup",
      {
        autoScalingGroupName: `archon-${stage}-datahub-core`,
        vpc,
        vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
        launchTemplate: coreLaunchTemplate,
        minCapacity: 0,
        desiredCapacity: 0,
        maxCapacity: 1,
        healthChecks: autoscaling.HealthChecks.ec2({
          gracePeriod: Duration.minutes(20)
        }),
        groupMetrics: [autoscaling.GroupMetrics.all()],
        terminationPolicies: [autoscaling.TerminationPolicy.OLDEST_INSTANCE]
      }
    );
    Tags.of(this.autoScalingGroup).add("Runtime", "datahub-core", {
      applyToLaunchedInstances: true
    });
    Tags.of(this.autoScalingGroup).add("Generation", generation.valueAsString, {
      applyToLaunchedInstances: true
    });

    const lifecycleLogGroup = new logs.LogGroup(
      this,
      "CoreLifecycleLogGroup",
      {
        logGroupName: `/archon/${stage}/datahub-core/lifecycle`,
        encryptionKey: logsKey,
        retention: logs.RetentionDays.ONE_YEAR,
        removalPolicy: RemovalPolicy.RETAIN
      }
    );
    lifecycleRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "WriteOnlyLifecycleLogGroup",
        actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
        resources: [`${lifecycleLogGroup.logGroupArn}:*`]
      })
    );
    lifecycleRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "PublishOnlyXRayTelemetry",
        actions: ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
        resources: ["*"]
      })
    );
    const lifecycleFunction = new lambda.Function(
      this,
      "CoreLifecycleFunction",
      {
        functionName: `Archon-${stage}-datahub-core-lifecycle`,
        description:
          "Owns lease/CAS decisions and AMI verification; it has no Auto Scaling permission",
        runtime: lambda.Runtime.PYTHON_3_13,
        architecture: lambda.Architecture.X86_64,
        handler: "lifecycle.handler",
        code: lambda.Code.fromAsset(
          join(__dirname, "../lambda/core-lifecycle")
        ),
        timeout: Duration.minutes(4),
        memorySize: 256,
        reservedConcurrentExecutions: 5,
        tracing: lambda.Tracing.ACTIVE,
        logGroup: lifecycleLogGroup,
        role: lifecycleRole,
        environment: {
          CORE_LEASE_TABLE: this.leaseTable.tableName,
          CORE_AMI_ID: imageId.valueAsString,
          CORE_GENERATION: generation.valueAsString,
          CORE_CAPABILITY_DIGEST: capabilityDigest.valueAsString,
          CORE_IMAGE_MANIFEST_DIGEST: imageManifestDigest.valueAsString,
          CORE_STAGE: stage,
          CORE_VPC_ID: vpc.vpcId,
          CORE_SUBNET_ID: vpc.isolatedSubnets[0]!.subnetId,
          CORE_INFERENCE_SECURITY_GROUP_ID:
            inferenceEndpointSecurityGroup.securityGroupId,
          CORE_INTERFACE_SECURITY_GROUP_ID:
            inferenceEndpointSecurityGroup.securityGroupId,
          CORE_BEDROCK_SERVICE_NAME: bedrockRuntimeServiceName,
          CORE_KMS_SERVICE_NAME: kmsServiceName,
          CORE_STS_SERVICE_NAME: stsServiceName,
          CORE_DATA_KEY_ARN: dataKey.keyArn,
          CORE_MUTATION_SIGNING_KEY_ARN: mutationSigningKey.keyArn,
          CORE_ANALYTICS_ROLE_ARN: analyticsRole.roleArn,
          CORE_GATEWAY_ROLE_ARN: gatewayRole.roleArn,
          CORE_INSTANCE_ROLE_ARN: instanceRole.roleArn,
          CORE_BEDROCK_RESOURCE_ARNS:
            Stack.of(this).toJsonString(exactBedrockResources),
          CORE_IDLE_SECONDS: "1800",
          CORE_HARD_SECONDS: "7200",
          CORE_OPERATION_SECONDS: "300"
        }
      }
    );
    lifecycleFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "ReadAndTransitionOnlyCoreLease",
        actions: ["dynamodb:GetItem", "dynamodb:UpdateItem"],
        resources: [this.leaseTable.tableArn],
        conditions: {
          "ForAllValues:StringEquals": {
            "dynamodb:LeadingKeys": ["CORE#LEASE"]
          },
          Null: { "dynamodb:LeadingKeys": "false" }
        }
      })
    );
    lifecycleFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "PublishOnlyStoppedCoreHealth",
        actions: ["dynamodb:PutItem"],
        resources: [this.leaseTable.tableArn],
        conditions: {
          "ForAllValues:StringEquals": {
            "dynamodb:LeadingKeys": ["RUNTIME#core"]
          },
          Null: { "dynamodb:LeadingKeys": "false" }
        }
      })
    );
    lifecycleFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "AssumeOnlyCoreScopedRuntimeRoles",
        actions: ["sts:AssumeRole"],
        resources: [analyticsRole.roleArn, gatewayRole.roleArn]
      })
    );
    lifecycleFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "EncryptOnlyBoundScopedCredentials",
        actions: ["kms:Encrypt"],
        resources: [dataKey.keyArn],
        conditions: {
          StringEquals: credentialContextEquals,
          StringLike: credentialContextLike
        }
      })
    );
    lifecycleFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "InspectOnlyConfiguredCoreImageAndEndpoints",
        actions: ["ec2:DescribeImages", "ec2:DescribeVpcEndpoints"],
        resources: ["*"],
        conditions: {
          StringEquals: { "aws:RequestedRegion": "eu-west-1" }
        }
      })
    );
    lifecycleFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "UseOnlyExactCoreNetworkForSessionEndpoints",
        actions: ["ec2:CreateVpcEndpoint"],
        resources: [
          "arn:" + Aws.PARTITION + ":ec2:" + Aws.REGION + ":" +
            Aws.ACCOUNT_ID + ":vpc/" + vpc.vpcId,
          "arn:" + Aws.PARTITION + ":ec2:" + Aws.REGION + ":" +
            Aws.ACCOUNT_ID + ":subnet/" + vpc.isolatedSubnets[0]!.subnetId,
          "arn:" + Aws.PARTITION + ":ec2:" + Aws.REGION + ":" +
            Aws.ACCOUNT_ID + ":security-group/" +
            inferenceEndpointSecurityGroup.securityGroupId
        ],
        conditions: {
          StringEquals: { "aws:RequestedRegion": "eu-west-1" }
        }
      })
    );
    lifecycleFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "CreateOnlySessionScopedCoreEndpoints",
        actions: ["ec2:CreateVpcEndpoint"],
        resources: [
          "arn:" + Aws.PARTITION + ":ec2:" + Aws.REGION + ":" +
            Aws.ACCOUNT_ID + ":vpc-endpoint/*"
        ],
        conditions: {
          StringEquals: {
            "aws:RequestTag/Application": "archon-datahub",
            "aws:RequestTag/Environment": stage,
            "aws:RequestTag/ManagedBy": "archon-core-lifecycle",
            "aws:RequestedRegion": "eu-west-1",
            "ec2:VpceServiceName": [
              bedrockRuntimeServiceName,
              kmsServiceName,
              stsServiceName
            ],
            "ec2:VpceServiceOwner": "amazon"
          },
          "ForAllValues:StringEquals": {
            "aws:TagKeys": [
              "Application",
              "Environment",
              "ManagedBy",
              "ArchonSessionId",
              "ArchonCapability"
            ]
          }
        }
      })
    );
    lifecycleFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "TagOnlyNewSessionScopedCoreEndpoints",
        actions: ["ec2:CreateTags"],
        resources: [
          "arn:" + Aws.PARTITION + ":ec2:" + Aws.REGION + ":" +
            Aws.ACCOUNT_ID + ":vpc-endpoint/*"
        ],
        conditions: {
          StringEquals: {
            "aws:RequestTag/Application": "archon-datahub",
            "aws:RequestTag/Environment": stage,
            "aws:RequestTag/ManagedBy": "archon-core-lifecycle",
            "aws:RequestedRegion": "eu-west-1",
            "ec2:CreateAction": "CreateVpcEndpoint"
          },
          "ForAllValues:StringEquals": {
            "aws:TagKeys": [
              "Application",
              "Environment",
              "ManagedBy",
              "ArchonSessionId",
              "ArchonCapability"
            ]
          }
        }
      })
    );
    lifecycleFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "DeleteOnlyOwnedSessionScopedCoreEndpoints",
        actions: ["ec2:DeleteVpcEndpoints"],
        resources: [
          "arn:" + Aws.PARTITION + ":ec2:" + Aws.REGION + ":" +
            Aws.ACCOUNT_ID + ":vpc-endpoint/*"
        ],
        conditions: {
          StringEquals: {
            "aws:RequestedRegion": "eu-west-1",
            "ec2:ResourceTag/Application": "archon-datahub",
            "ec2:ResourceTag/Environment": stage,
            "ec2:ResourceTag/ManagedBy": "archon-core-lifecycle"
          },
          StringLike: {
            "ec2:ResourceTag/ArchonSessionId": "rs_*"
          }
        }
      })
    );

    const stateMachineLogGroup = new logs.LogGroup(
      this,
      "CoreStateMachineLogGroup",
      {
        logGroupName: `/archon/${stage}/datahub-core/state-machine`,
        encryptionKey: logsKey,
        retention: logs.RetentionDays.ONE_YEAR,
        removalPolicy: RemovalPolicy.RETAIN
      }
    );
    const normalize = new sfn.Pass(this, "NormalizeCoreCommand", {
      parameters: { "command.$": "$" }
    });
    const prepare = new tasks.LambdaInvoke(this, "PrepareCoreLifecycle", {
      lambdaFunction: lifecycleFunction,
      payload: sfn.TaskInput.fromJsonPathAt("$.command"),
      payloadResponseOnly: true,
      resultPath: "$.lifecycle",
      retryOnServiceExceptions: true
    });
    prepare.addRetry({
      errors: ["Lambda.Unknown", "States.TaskFailed"],
      interval: Duration.seconds(5),
      backoffRate: 2,
      maxAttempts: 2
    });
    const scaleUp = new tasks.CallAwsService(this, "ScaleCoreUp", {
      service: "autoscaling",
      action: "updateAutoScalingGroup",
      parameters: {
        AutoScalingGroupName: this.autoScalingGroup.autoScalingGroupName,
        DesiredCapacity: 1
      },
      iamResources: [this.autoScalingGroup.autoScalingGroupArn],
      resultPath: sfn.JsonPath.DISCARD
    });
    const scaleDown = new tasks.CallAwsService(this, "ScaleCoreDown", {
      service: "autoscaling",
      action: "updateAutoScalingGroup",
      parameters: {
        AutoScalingGroupName: this.autoScalingGroup.autoScalingGroupName,
        DesiredCapacity: 0
      },
      iamResources: [this.autoScalingGroup.autoScalingGroupArn],
      resultPath: sfn.JsonPath.DISCARD
    });
    const finalize = new tasks.LambdaInvoke(this, "FinalizeCoreLifecycle", {
      lambdaFunction: lifecycleFunction,
      payload: sfn.TaskInput.fromObject({
        schema: "archon.core-runtime-command/v1",
        action: "FINALIZE",
        "decision.$": "$.lifecycle.decision",
        "operationId.$": "$.lifecycle.operationId",
        "sessionId.$": "$.lifecycle.sessionId",
        "expectedRevision.$": "$.lifecycle.revision"
      }),
      payloadResponseOnly: true,
      resultPath: "$.lifecycle"
    });
    const complete = new sfn.Succeed(this, "CoreLifecycleComplete");
    const rejected = new sfn.Fail(this, "CoreLifecycleRejected", {
      error: "CoreLifecycleRejected",
      cause: "The authoritative lease rejected the command"
    });
    const watchdog = new sfn.Wait(this, "WaitForExactCoreLeaseDeadline", {
      time: sfn.WaitTime.timestampPath("$.lifecycle.watchdogDeadline")
    });
    const watchdogReap = new tasks.LambdaInvoke(
      this,
      "ReapExactCoreLeaseRevision",
      {
        lambdaFunction: lifecycleFunction,
        payload: sfn.TaskInput.fromObject({
          schema: "archon.core-runtime-command/v1",
          action: "REAP",
          "expectedSessionId.$": "$.lifecycle.sessionId",
          "expectedRevision.$": "$.lifecycle.revision",
          "deadlineEpoch.$": "$.lifecycle.watchdogDeadlineEpoch"
        }),
        payloadResponseOnly: true,
        resultPath: "$.lifecycle"
      }
    );
    const watchdogScaleDown = new tasks.CallAwsService(
      this,
      "ScaleExpiredCoreDown",
      {
        service: "autoscaling",
        action: "updateAutoScalingGroup",
        parameters: {
          AutoScalingGroupName: this.autoScalingGroup.autoScalingGroupName,
          DesiredCapacity: 0
        },
        iamResources: [this.autoScalingGroup.autoScalingGroupArn],
        resultPath: sfn.JsonPath.DISCARD
      }
    );
    const watchdogFinalize = new tasks.LambdaInvoke(
      this,
      "FinalizeExpiredCoreLease",
      {
        lambdaFunction: lifecycleFunction,
        payload: sfn.TaskInput.fromObject({
          schema: "archon.core-runtime-command/v1",
          action: "FINALIZE",
          "decision.$": "$.lifecycle.decision",
          "operationId.$": "$.lifecycle.operationId",
          "sessionId.$": "$.lifecycle.sessionId",
          "expectedRevision.$": "$.lifecycle.revision"
        }),
        payloadResponseOnly: true,
        resultPath: "$.lifecycle"
      }
    );
    watchdogScaleDown.next(watchdogFinalize).next(complete);
    const watchdogDecision = new sfn.Choice(this, "ExactWatchdogScaleDecision")
      .when(
        sfn.Condition.stringEquals("$.lifecycle.decision", "DOWNSCALE"),
        watchdogScaleDown
      )
      .when(sfn.Condition.stringEquals("$.lifecycle.decision", "NONE"), complete)
      .otherwise(rejected);
    watchdog.next(watchdogReap).next(watchdogDecision);
    const maybeWatchdog = new sfn.Choice(this, "ScheduleExactCoreWatchdog")
      .when(
        sfn.Condition.and(
          sfn.Condition.isPresent("$.lifecycle.watchdog"),
          sfn.Condition.booleanEquals("$.lifecycle.watchdog", true)
        ),
        watchdog
      )
      .otherwise(complete);
    scaleUp.next(finalize);
    scaleDown.next(finalize);
    finalize.next(maybeWatchdog);
    const decide = new sfn.Choice(this, "CoreScaleDecision")
      .when(sfn.Condition.stringEquals("$.lifecycle.decision", "UPSCALE"), scaleUp)
      .when(
        sfn.Condition.stringEquals("$.lifecycle.decision", "DOWNSCALE"),
        scaleDown
      )
      .when(
        sfn.Condition.stringEquals("$.lifecycle.decision", "NONE"),
        maybeWatchdog
      )
      .otherwise(rejected);
    const definition = normalize.next(prepare).next(decide);

    this.sessionStateMachine = new sfn.StateMachine(
      this,
      "CoreSessionStateMachine",
      {
        stateMachineName: `archon-${stage}-datahub-core-session`,
        stateMachineType: sfn.StateMachineType.STANDARD,
        definitionBody: sfn.DefinitionBody.fromChainable(definition),
        timeout: Duration.hours(3),
        logs: {
          destination: stateMachineLogGroup,
          level: sfn.LogLevel.ALL,
          includeExecutionData: false
        },
        tracingEnabled: true,
        removalPolicy: RemovalPolicy.RETAIN
      }
    );

    new events.Rule(this, "CoreLeaseReaper", {
      description:
        "Five-minute independent fail-safe for the 30-minute idle and two-hour hard leases",
      schedule: events.Schedule.rate(Duration.minutes(5)),
      targets: [
        new eventTargets.SfnStateMachine(this.sessionStateMachine, {
          input: events.RuleTargetInput.fromObject({
            schema: "archon.core-runtime-command/v1",
            action: "REAP"
          }),
          retryAttempts: 2,
          maxEventAge: Duration.minutes(10)
        })
      ]
    });

    const observerLogGroup = new logs.LogGroup(
      this,
      "CoreObserverLogGroup",
      {
        logGroupName: `/archon/${stage}/datahub-core/observer`,
        encryptionKey: logsKey,
        retention: logs.RetentionDays.ONE_YEAR,
        removalPolicy: RemovalPolicy.RETAIN
      }
    );
    const observerFunction = new lambda.Function(this, "CoreObserverFunction", {
      functionName: `Archon-${stage}-datahub-core-observer`,
      description:
        "Projects redacted lease and health transitions to CloudWatch; never owns liveness",
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.X86_64,
      handler: "observer.handler",
      code: lambda.Code.fromAsset(
        join(__dirname, "../lambda/core-lifecycle")
      ),
      timeout: Duration.seconds(15),
      memorySize: 192,
      reservedConcurrentExecutions: 2,
      tracing: lambda.Tracing.ACTIVE,
      logGroup: observerLogGroup,
      environment: {
        CORE_STAGE: stage,
        CORE_METRIC_NAMESPACE: "Archon/DataHubCore"
      }
    });
    observerFunction.addEventSource(
      new lambdaEventSources.DynamoEventSource(this.leaseTable, {
        startingPosition: lambda.StartingPosition.LATEST,
        batchSize: 10,
        bisectBatchOnError: true,
        retryAttempts: 3
      })
    );
    observerFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "EmitOnlyCoreMetrics",
        actions: ["cloudwatch:PutMetricData"],
        resources: ["*"],
        conditions: {
          StringEquals: {
            "cloudwatch:namespace": "Archon/DataHubCore"
          }
        }
      })
    );

    const lifecycleFailures = new cloudwatch.Alarm(
      this,
      "CoreLifecycleFailuresAlarm",
      {
        metric: this.sessionStateMachine.metricFailed({
          period: Duration.minutes(5),
          statistic: "Sum"
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
      }
    );
    const activeHosts = new cloudwatch.Alarm(this, "CoreHostCountAlarm", {
      metric: new cloudwatch.Metric({
        namespace: "AWS/AutoScaling",
        metricName: "GroupTotalInstances",
        dimensionsMap: {
          AutoScalingGroupName:
            this.autoScalingGroup.autoScalingGroupName
        },
        period: Duration.minutes(5),
        statistic: "Maximum"
      }),
      threshold: 1,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
    });
    new cloudwatch.Dashboard(this, "CoreOperationsDashboard", {
      dashboardName: `archon-${stage}-datahub-core`,
      widgets: [
        [
          new cloudwatch.GraphWidget({
            title: "Ephemeral Core lifecycle",
            left: [
              this.sessionStateMachine.metricStarted(),
              this.sessionStateMachine.metricSucceeded()
            ],
            right: [lifecycleFailures.metric],
            width: 12
          }),
          new cloudwatch.GraphWidget({
            title: "Core host count (must remain <= 1)",
            left: [activeHosts.metric],
            width: 12
          })
        ]
      ]
    });

    output(
      this,
      "ArchonCoreSessionStateMachineArn",
      this.sessionStateMachine.stateMachineArn,
      `archon-${stage}-core-session-state-machine-arn`
    );
    output(
      this,
      "ArchonCoreLeaseTableName",
      this.leaseTable.tableName,
      `archon-${stage}-core-lease-table-name`
    );
    output(
      this,
      "ArchonCoreLeaseTableStreamArn",
      this.leaseTable.tableStreamArn!,
      `archon-${stage}-core-lease-table-stream-arn`
    );
    output(
      this,
      "ArchonCoreAutoScalingGroupName",
      this.autoScalingGroup.autoScalingGroupName,
      `archon-${stage}-core-asg-name`
    );
    output(
      this,
      "ArchonCoreGeneration",
      generation.valueAsString,
      `archon-${stage}-core-generation`
    );
    output(
      this,
      "ArchonCoreCapabilityDigest",
      capabilityDigest.valueAsString,
      `archon-${stage}-core-capability-digest`
    );
    output(this, "ArchonCoreVpcId", vpc.vpcId);
    output(
      this,
      "ArchonCoreInferenceEndpointSecurityGroupId",
      inferenceEndpointSecurityGroup.securityGroupId
    );
    output(
      this,
      "ArchonCoreDataKeyArn",
      dataKey.keyArn,
      "archon-" + stage + "-core-data-key-arn"
    );
    output(
      this,
      "ArchonCoreMutationSigningKeyArn",
      mutationSigningKey.keyArn,
      `archon-${stage}-core-mutation-signing-key-arn`
    );
    output(
      this,
      "ArchonCoreBedrockModelId",
      llmModelId.valueAsString,
      `archon-${stage}-core-bedrock-model-id`
    );
    output(
      this,
      "ArchonCoreBedrockBaseModelId",
      llmBaseModelId.valueAsString,
      `archon-${stage}-core-bedrock-base-model-id`
    );
  }
}

function allowCloudWatchLogs(key: kms.Key, stage: string): void {
  const stack = Stack.of(key);
  key.addToResourcePolicy(
    new iam.PolicyStatement({
      sid: "AllowCloudWatchLogsEncryption",
      principals: [
        new iam.ServicePrincipal(`logs.${Aws.REGION}.${Aws.URL_SUFFIX}`)
      ],
      actions: [
        "kms:Decrypt",
        "kms:Describe*",
        "kms:Encrypt",
        "kms:GenerateDataKey*",
        "kms:ReEncrypt*"
      ],
      resources: ["*"],
      conditions: {
        ArnLike: {
          "kms:EncryptionContext:aws:logs:arn": stack.formatArn({
            service: "logs",
            resource: "log-group",
            resourceName: `/archon/${stage}/datahub-core/*`,
            arnFormat: ArnFormat.COLON_RESOURCE_NAME
          })
        }
      }
    })
  );
}

function output(
  scope: Construct,
  id: string,
  value: string,
  exportName?: string
): void {
  new CfnOutput(scope, id, {
    value,
    ...(exportName ? { exportName } : {})
  });
}