import {
  ArnFormat,
  Aws,
  CfnOutput,
  CfnParameter,
  Duration,
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

    const dataKey = new kms.Key(this, "DataKey", {
      alias: `alias/archon/${stage}/datahub-core-data`,
      description: "DataHub Core lease, health, job, and receipt encryption",
      enableKeyRotation: true,
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
      maxAzs: 1,
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
          "dynamodb:TransactWriteItems",
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

    const instanceRole = new iam.Role(this, "CoreInstanceRole", {
      assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
      description:
        "DataHub Core host reads its lease and exchanges bounded health/job receipts",
      maxSessionDuration: Duration.hours(1)
    });
    instanceRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "ExchangeOnlyCoreRuntimeRecords",
        actions: [
          "dynamodb:DescribeTable",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query",
          "dynamodb:TransactWriteItems",
          "dynamodb:UpdateItem"
        ],
        resources: [this.leaseTable.tableArn],
        conditions: {
          "ForAllValues:StringLike": {
            "dynamodb:LeadingKeys": ["CORE#LEASE", "RUNTIME#core", "SESSION#rs_*"]
          }
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
      "ARCHON_COMPANION_URL=http://127.0.0.1:8080",
      "ARCHON_ANALYTICS_AGENT_URL=http://127.0.0.1:8100",
      "ARCHON_DATAHUB_GMS_URL=https://127.0.0.1:9443/gms",
      "ARCHON_ENV",
      "chmod 0600 /etc/archon/datahub-core.env",
      "systemctl enable --now archon-datahub-core.service"
    );

    this.autoScalingGroup = new autoscaling.AutoScalingGroup(
      this,
      "CoreAutoScalingGroup",
      {
        autoScalingGroupName: `archon-${stage}-datahub-core`,
        vpc,
        vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
        instanceType: new ec2.InstanceType("t3a.xlarge"),
        machineImage: ec2.MachineImage.genericLinux({
          "eu-west-1": imageId.valueAsString
        }),
        minCapacity: 0,
        maxCapacity: 1,
        associatePublicIpAddress: false,
        requireImdsv2: true,
        securityGroup: hostSecurityGroup,
        role: instanceRole,
        userData,
        healthCheck: autoscaling.HealthCheck.ec2({
          grace: Duration.minutes(20)
        }),
        groupMetrics: [autoscaling.GroupMetrics.all()],
        terminationPolicies: [autoscaling.TerminationPolicy.OLDEST_INSTANCE],
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
        ]
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
        retention: logs.RetentionDays.ONE_MONTH,
        removalPolicy: RemovalPolicy.RETAIN
      }
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
        timeout: Duration.seconds(30),
        memorySize: 256,
        reservedConcurrentExecutions: 5,
        tracing: lambda.Tracing.ACTIVE,
        logGroup: lifecycleLogGroup,
        environment: {
          CORE_LEASE_TABLE: this.leaseTable.tableName,
          CORE_AMI_ID: imageId.valueAsString,
          CORE_GENERATION: generation.valueAsString,
          CORE_CAPABILITY_DIGEST: capabilityDigest.valueAsString,
          CORE_IMAGE_MANIFEST_DIGEST: imageManifestDigest.valueAsString,
          CORE_STAGE: stage,
          CORE_IDLE_SECONDS: "1800",
          CORE_HARD_SECONDS: "7200",
          CORE_OPERATION_SECONDS: "300"
        }
      }
    );
    this.leaseTable.grantReadWriteData(lifecycleFunction);
    lifecycleFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "VerifyOnlyConfiguredCoreImage",
        actions: ["ec2:DescribeImages"],
        resources: ["*"],
        conditions: {
          StringEquals: { "aws:RequestedRegion": "eu-west-1" }
        }
      })
    );

    const stateMachineLogGroup = new logs.LogGroup(
      this,
      "CoreStateMachineLogGroup",
      {
        logGroupName: `/archon/${stage}/datahub-core/state-machine`,
        encryptionKey: logsKey,
        retention: logs.RetentionDays.ONE_MONTH,
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
          level: sfn.LogLevel.ERROR,
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
        retention: logs.RetentionDays.ONE_MONTH,
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
