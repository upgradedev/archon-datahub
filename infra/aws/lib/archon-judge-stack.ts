import {
  Aws,
  CfnParameter,
  Duration,
  Fn,
  RemovalPolicy,
  Size,
  Stack,
  Tags,
  Token,
  type StackProps
} from "aws-cdk-lib";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatchActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as logs from "aws-cdk-lib/aws-logs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as sns from "aws-cdk-lib/aws-sns";
import * as snsSubscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import { Construct } from "constructs";
import { join } from "node:path";
import {
  CANONICAL_DATASET_URN,
  CANONICAL_QUESTION,
  GOVERNED_COLUMN_PATH,
  RUNTIME_APPROVER_GROUP,
  RUNTIME_OPERATOR_GROUP,
  allowCloudWatchLogs,
  output,
  retainedKey,
  retainedLogGroup,
  type ArchonStage
} from "./judge-contract";
import { addCloudRuntime } from "./judge-cloud-runtime";
import {
  addJudgeEdgeApi,
  createJudgeIdentity
} from "./judge-edge-api";

export interface ArchonJudgeStackProps extends StackProps {
  readonly stage: ArchonStage;
}

export class ArchonJudgeStack extends Stack {
  constructor(
    scope: Construct,
    id: string,
    props: ArchonJudgeStackProps
  ) {
    super(scope, id, props);
    const { stage } = props;
    if (!["staging", "production"].includes(stage)) {
      throw new Error(
        "ArchonJudgeStack stage must be staging or production"
      );
    }
    const isProduction = stage === "production";
    const physicalNameSuffix =
      `${Stack.of(this).account}-${Stack.of(this).region}`;
    const boundary = iam.ManagedPolicy.fromManagedPolicyArn(
      this,
      "RuntimePermissionsBoundary",
      `arn:${Aws.PARTITION}:iam::${Aws.ACCOUNT_ID}:policy/archon-datahub-runtime-boundary-${stage}`
    );
    iam.PermissionsBoundary.of(this).apply(boundary);

    const applicationDomain = parameter(
      this,
      "CloudFrontDomainName",
      "Exact environment application DNS name",
      "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    );
    const hostedZoneId = parameter(
      this,
      "CloudFrontHostedZoneId",
      "Route 53 hosted-zone ID owning the exact application name",
      "^Z[A-Z0-9]{1,31}$"
    );
    const certificateArn = parameter(
      this,
      "CloudFrontCertificateArn",
      "Exact us-east-1 ACM viewer certificate ARN",
      "^arn:aws:acm:us-east-1:[0-9]{12}:certificate/[0-9a-fA-F-]{36}$"
    );
    const cloudFrontWebAclArn = parameter(
      this,
      "CloudFrontWebAclArn",
      "Exact CLOUDFRONT-scope WAF ARN from ArchonEdgeStack",
      "^arn:aws:wafv2:us-east-1:[0-9]{12}:global/webacl/[A-Za-z0-9_-]{1,128}/[0-9a-fA-F-]{36}$"
    );
    const deploymentAccount = this.account;
    const deploymentRegion = this.region;
    if (
      Token.isUnresolved(deploymentAccount) ||
      Token.isUnresolved(deploymentRegion) ||
      !/^[0-9]{12}$/u.test(deploymentAccount) ||
      !/^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]$/u.test(deploymentRegion)
    ) {
      throw new Error(
        "ArchonJudgeStack requires an explicit AWS account and region"
      );
    }
    const cloudRuntimeImageUri = parameter(
      this,
      "CloudRuntimeImageUri",
      "CI-scanned immutable DataHub Cloud Lambda image URI",
      `^${deploymentAccount}\\.dkr\\.ecr\\.${deploymentRegion}\\.amazonaws\\.com(?:\\.cn)?/[a-z0-9][a-z0-9._/-]{1,255}@sha256:[a-f0-9]{64}$`
    );
    const spaArtifactSha256 = parameter(
      this,
      "SpaArtifactSha256",
      "SHA-256 of the CI-built SPA archive uploaded after CDK",
      "^[a-f0-9]{64}$"
    );
    const lambdaArtifactSha256 = parameter(
      this,
      "LambdaArtifactSha256",
      "SHA-256 of the exact CI-built Node Lambda archive",
      "^[a-f0-9]{64}$"
    );
    const cloudRuntimeReleaseDigest = parameter(
      this,
      "CloudRuntimeReleaseDigest",
      "SHA-256 seal from the attested Cloud runtime release receipt",
      "^sha256:[a-f0-9]{64}$"
    );
    const ciRunId = parameter(
      this,
      "CiRunId",
      "Exact successful CI workflow run promoted by this deployment",
      "^[1-9][0-9]{0,19}$"
    );
    const deploymentWorkflowRunId = parameter(
      this,
      "DeploymentWorkflowRunId",
      "Exact GitHub deployment workflow run recorded in CloudFormation",
      "^[1-9][0-9]{0,19}$"
    );
    const releaseSha = parameter(
      this,
      "ReleaseSha",
      "Exact source commit represented by every deployed artifact",
      "^[a-f0-9]{40}$"
    );

    const dataKey = retainedKey(
      this,
      "DataKey",
      `alias/archon/${stage}/judge-data`,
      "Runtime session table and state-bucket encryption"
    );
    const spaKey = retainedKey(
      this,
      "SpaKey",
      `alias/archon/${stage}/judge-spa`,
      "Private judge SPA object encryption"
    );
    const logsKey = retainedKey(
      this,
      "LogsKey",
      `alias/archon/${stage}/judge-logs`,
      "API, WAF, Lambda and worker log encryption"
    );
    const secretsKey = retainedKey(
      this,
      "SecretsKey",
      `alias/archon/${stage}/judge-secrets`,
      "Separate DataHub Cloud runtime credential encryption"
    );
    const queueKey = retainedKey(
      this,
      "QueueKey",
      `alias/archon/${stage}/judge-queues`,
      "Cloud runtime failure-queue encryption"
    );
    allowCloudWatchLogs(logsKey, stage);

    // AWS requires S3 server-access-log destinations to use SSE-S3. This
    // single terminal sink is intentionally not self-logged: self-delivery
    // creates recursive, unbounded log objects. Every source bucket delivers
    // here; CloudFront first writes to a KMS bucket whose own access logs also
    // terminate here under a stage-scoped prefix.
    const accessLogBucket = new s3.Bucket(
      this,
      "AccessLogBucket",
      {
        bucketName:
          `archon-${stage}-access-logs-${physicalNameSuffix}`,
        accessControl:
          s3.BucketAccessControl.LOG_DELIVERY_WRITE,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        encryption: s3.BucketEncryption.S3_MANAGED,
        enforceSSL: true,
        objectOwnership: s3.ObjectOwnership.OBJECT_WRITER,
        versioned: true,
        lifecycleRules: [
          {
            id: "BoundedTerminalAccessLogs",
            abortIncompleteMultipartUploadAfter: Duration.days(1),
            noncurrentVersionExpiration:
              Duration.days(isProduction ? 30 : 7),
            expiration: Duration.days(isProduction ? 180 : 30)
          }
        ],
        removalPolicy: RemovalPolicy.RETAIN
      }
    );
    Tags.of(accessLogBucket).add(
      "SecurityProfile",
      "terminal-access-log-sink"
    );

    logsKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: "AllowExactCloudFrontStandardLogDelivery",
        principals: [
          new iam.ServicePrincipal(
            "delivery.logs.amazonaws.com"
          )
        ],
        actions: ["kms:GenerateDataKey*", "kms:Decrypt"],
        resources: ["*"]
      })
    );
    const cloudFrontLogBucket = new s3.Bucket(
      this,
      "CloudFrontLogBucket",
      {
        bucketName:
          `archon-${stage}-cloudfront-logs-${physicalNameSuffix}`,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        bucketKeyEnabled: true,
        encryption: s3.BucketEncryption.KMS,
        encryptionKey: logsKey,
        enforceSSL: true,
        objectOwnership: s3.ObjectOwnership.OBJECT_WRITER,
        serverAccessLogsBucket: accessLogBucket,
        serverAccessLogsPrefix:
          `${stage}/s3/cloudfront-log-bucket/`,
        versioned: true,
        lifecycleRules: [
          {
            id: "BoundedCloudFrontStandardLogs",
            abortIncompleteMultipartUploadAfter: Duration.days(1),
            noncurrentVersionExpiration:
              Duration.days(isProduction ? 30 : 7),
            expiration: Duration.days(isProduction ? 180 : 30)
          }
        ],
        removalPolicy: RemovalPolicy.RETAIN
      }
    );
    Tags.of(cloudFrontLogBucket).add(
      "SecurityProfile",
      "cloudfront-access-log-bucket"
    );

    const spaBucket = new s3.Bucket(this, "SpaBucket", {
      bucketName:
        `archon-${stage}-spa-${physicalNameSuffix}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      bucketKeyEnabled: true,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: spaKey,
      enforceSSL: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      serverAccessLogsBucket: accessLogBucket,
      serverAccessLogsPrefix: `${stage}/s3/spa/`,
      versioned: true,
      lifecycleRules: [
        {
          id: "RetainCurrentSpaRelease",
          noncurrentVersionExpiration:
            Duration.days(isProduction ? 90 : 30)
        }
      ],
      removalPolicy: RemovalPolicy.RETAIN
    });
    const checkpointBucket = new s3.Bucket(
      this,
      "CloudCheckpointBucket",
      {
        bucketName:
          `archon-${stage}-cloud-checkpoints-${physicalNameSuffix}`,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        bucketKeyEnabled: true,
        encryption: s3.BucketEncryption.KMS,
        encryptionKey: dataKey,
        enforceSSL: true,
        objectOwnership:
          s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
        serverAccessLogsBucket: accessLogBucket,
        serverAccessLogsPrefix:
          `${stage}/s3/cloud-checkpoints/`,
        versioned: true,
        lifecycleRules: [
          {
            id: "BoundedVersionedCloudCheckpoints",
            prefix: "cloud-runtime/v2/",
            noncurrentVersionExpiration: Duration.days(30),
            expiration: Duration.days(90)
          }
        ],
        removalPolicy: RemovalPolicy.RETAIN
      }
    );
    const runtimeSessionTable = new dynamodb.Table(
      this,
      "RuntimeSessionTable",
      {
        partitionKey: {
          name: "pk",
          type: dynamodb.AttributeType.STRING
        },
        sortKey: {
          name: "sk",
          type: dynamodb.AttributeType.STRING
        },
        billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
        encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
        encryptionKey: dataKey,
        deletionProtection: true,
        pointInTimeRecoverySpecification: {
          pointInTimeRecoveryEnabled: true
        },
        contributorInsightsSpecification: { enabled: true },
        timeToLiveAttribute: "expiresAt",
        stream:
          dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
        removalPolicy: RemovalPolicy.RETAIN
      }
    );

    const coreTableName = Fn.importValue(
      `archon-${stage}-core-lease-table-name`
    );
    const coreTableStreamArn = Fn.importValue(
      `archon-${stage}-core-lease-table-stream-arn`
    );
    const coreStateMachineArn = Fn.importValue(
      `archon-${stage}-core-session-state-machine-arn`
    );
    const mutationSigningKeyArn = Fn.importValue(
      `archon-${stage}-core-mutation-signing-key-arn`
    );
    const coreGeneration = Fn.importValue(
      `archon-${stage}-core-generation`
    );
    const coreCapabilityDigest = Fn.importValue(
      `archon-${stage}-core-capability-digest`
    );
    const runtimeJobTable = dynamodb.Table.fromTableAttributes(
      this,
      "ImportedCoreRuntimeJobTable",
      {
        tableName: coreTableName,
        tableStreamArn: coreTableStreamArn
      }
    );

    const cloudReaderSecret = new secretsmanager.Secret(
      this,
      "CloudReaderSecret",
      {
        secretName:
          `archon/${stage}/datahub-cloud/reader`,
        description:
          "Trial bootstrap writes only the reader service-account contract",
        encryptionKey: secretsKey
      }
    );
    const cloudWriterSecret = new secretsmanager.Secret(
      this,
      "CloudWriterSecret",
      {
        secretName:
          `archon/${stage}/datahub-cloud/writer`,
        description:
          "Trial bootstrap writes only the dataset-scoped writer contract",
        encryptionKey: secretsKey
      }
    );
    cloudReaderSecret.applyRemovalPolicy(RemovalPolicy.RETAIN);
    cloudWriterSecret.applyRemovalPolicy(RemovalPolicy.RETAIN);
    const originKeySecret = new secretsmanager.Secret(
      this,
      "CloudFrontOriginKey",
      {
        secretName:
          `archon/${stage}/cloudfront-origin-key`,
        description:
          "CloudFront-only API Gateway origin credential",
        encryptionKey: secretsKey,
        generateSecretString: {
          excludePunctuation: true,
          includeSpace: false,
          passwordLength: 48
        }
      }
    );
    originKeySecret.applyRemovalPolicy(RemovalPolicy.RETAIN);

    const failureQueue = new sqs.Queue(
      this,
      "RuntimeFailureQueue",
      {
        queueName: `archon-${stage}-runtime-failures`,
        encryption: sqs.QueueEncryption.KMS,
        encryptionMasterKey: queueKey,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
        visibilityTimeout: Duration.minutes(16)
      }
    );
    failureQueue.applyRemovalPolicy(RemovalPolicy.RETAIN);

    const identity = createJudgeIdentity(this, {
      stage,
      applicationDomain
    });
    const runtimeControl = nodeFunction(this, {
      id: "RuntimeControlFunction",
      functionName: `archon-${stage}-runtime-control`,
      handler: "index.handler",
      directory: "runtime-control",
      memorySize: 384,
      timeout: 20,
      concurrency: isProduction ? 30 : 10,
      logsKey,
      stage,
      environment: {
        RUNTIME_SESSION_TABLE: runtimeSessionTable.tableName,
        CORE_LEASE_TABLE: runtimeJobTable.tableName,
        CORE_SESSION_STATE_MACHINE_ARN:
          coreStateMachineArn,
        RUNTIME_OPERATOR_GROUP: RUNTIME_OPERATOR_GROUP,
        RUNTIME_APPROVER_GROUP: RUNTIME_APPROVER_GROUP,
        EXPECTED_COGNITO_ISSUER: identity.issuer
      }
    });
    addRuntimeControlPolicy(
      runtimeControl,
      runtimeSessionTable,
      runtimeJobTable,
      coreStateMachineArn
    );

    const control = nodeFunction(this, {
      id: "ControlFunction",
      functionName: `archon-${stage}-control`,
      handler: "index.handler",
      directory: "control",
      memorySize: 512,
      timeout: 20,
      concurrency: isProduction ? 50 : 15,
      logsKey,
      stage,
      environment: {
        RUNTIME_SESSION_TABLE: runtimeSessionTable.tableName,
        CORE_LEASE_TABLE: runtimeJobTable.tableName,
        RUNTIME_JOB_TABLE: runtimeJobTable.tableName,
        CORE_SESSION_STATE_MACHINE_ARN:
          coreStateMachineArn,
        RUNTIME_OPERATOR_GROUP: RUNTIME_OPERATOR_GROUP,
        RUNTIME_APPROVER_GROUP: RUNTIME_APPROVER_GROUP,
        EXPECTED_COGNITO_ISSUER: identity.issuer,
        ARCHON_STAGE: stage,
        ARCHON_AGENT_STACK_DATASET_URN:
          CANONICAL_DATASET_URN,
        ARCHON_ANALYTICS_QUESTION: CANONICAL_QUESTION,
        ARCHON_GOVERNED_COLUMN_PATH:
          GOVERNED_COLUMN_PATH,
        MUTATION_SIGNING_KEY_ARN:
          mutationSigningKeyArn,
        MUTATION_SIGNING_ALGORITHM: "ECDSA_SHA_256"
      }
    });
    addControlPolicy(
      control,
      runtimeSessionTable,
      runtimeJobTable,
      coreStateMachineArn
    );

    const remediation = nodeFunction(this, {
      id: "RemediationFunction",
      functionName:
        `archon-${stage}-runtime-remediation`,
      handler: "remediation.handler",
      directory: "control",
      memorySize: 256,
      timeout: 30,
      concurrency: isProduction ? 10 : 3,
      logsKey,
      stage,
      environment: {
        RUNTIME_SESSION_TABLE: runtimeSessionTable.tableName,
        CORE_LEASE_TABLE: runtimeJobTable.tableName,
        RUNTIME_JOB_TABLE: runtimeJobTable.tableName,
        CORE_SESSION_STATE_MACHINE_ARN:
          coreStateMachineArn,
        RUNTIME_OPERATOR_GROUP: RUNTIME_OPERATOR_GROUP,
        RUNTIME_APPROVER_GROUP: RUNTIME_APPROVER_GROUP,
        EXPECTED_COGNITO_ISSUER: identity.issuer,
        ARCHON_STAGE: stage,
        ARCHON_AGENT_STACK_DATASET_URN:
          CANONICAL_DATASET_URN,
        ARCHON_ANALYTICS_QUESTION: CANONICAL_QUESTION,
        ARCHON_GOVERNED_COLUMN_PATH:
          GOVERNED_COLUMN_PATH,
        MUTATION_SIGNING_KEY_ARN:
          mutationSigningKeyArn,
        MUTATION_SIGNING_ALGORITHM: "ECDSA_SHA_256"
      }
    });
    addRemediationPolicy(
      remediation,
      runtimeSessionTable,
      runtimeJobTable,
      mutationSigningKeyArn
    );
    const streamDlq =
      new lambdaEventSources.SqsDlq(failureQueue);
    remediation.addEventSource(
      new lambdaEventSources.DynamoEventSource(
        runtimeSessionTable,
        {
          startingPosition: lambda.StartingPosition.LATEST,
          batchSize: 5,
          bisectBatchOnError: false,
          retryAttempts: 3,
          reportBatchItemFailures: true,
          onFailure: streamDlq,
          filters: [
            lambda.FilterCriteria.filter({
              eventName: ["INSERT"],
              dynamodb: {
                NewImage: { sk: { S: ["APPROVAL"] } }
              }
            })
          ]
        }
      )
    );
    remediation.addEventSource(
      new lambdaEventSources.DynamoEventSource(
        runtimeJobTable,
        {
          startingPosition: lambda.StartingPosition.LATEST,
          batchSize: 5,
          bisectBatchOnError: false,
          retryAttempts: 3,
          reportBatchItemFailures: true,
          onFailure: streamDlq,
          filters: [
            lambda.FilterCriteria.filter({
              eventName: ["INSERT", "MODIFY"],
              dynamodb: {
                NewImage: {
                  operation: {
                    S: ["GOVERNED_TAG_MUTATION"]
                  },
                  state: { S: ["SUCCEEDED"] }
                }
              }
            })
          ]
        }
      )
    );

    const cloudRuntime = addCloudRuntime(this, {
      stage,
      imageUri: cloudRuntimeImageUri,
      jobTable: runtimeJobTable,
      sessionTable: runtimeSessionTable,
      checkpointBucket,
      checkpointKey: dataKey,
      readerSecret: cloudReaderSecret,
      writerSecret: cloudWriterSecret,
      mutationSigningKeyArn,
      failureQueue,
      logsKey
    });
    addJudgeEdgeApi(this, {
      stage,
      applicationDomain,
      hostedZoneId,
      certificateArn,
      cloudFrontWebAclArn,
      identity,
      runtimeControlFunction: runtimeControl,
      controlFunction: control,
      spaBucket,
      spaKey,
      cloudFrontLogBucket,
      logsKey,
      originKeySecret
    });

    const alarmTopic = new sns.Topic(this, "AlarmTopic", {
      topicName: `archon-${stage}-alarms`,
      displayName: `Archon ${stage} judge runtime alarms`,
      enforceSSL: true,
      masterKey: queueKey
    });
    alarmTopic.applyRemovalPolicy(RemovalPolicy.RETAIN);
    const alarmProofQueue = new sqs.Queue(
      this,
      "AlarmProofQueue",
      {
        queueName: `archon-${stage}-alarm-proof`,
        encryption: sqs.QueueEncryption.KMS,
        encryptionMasterKey: queueKey,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
        visibilityTimeout: Duration.minutes(2)
      }
    );
    alarmProofQueue.applyRemovalPolicy(RemovalPolicy.RETAIN);
    alarmTopic.addSubscription(
      new snsSubscriptions.SqsSubscription(alarmProofQueue, {
        rawMessageDelivery: true
      })
    );
    queueKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: "AllowAccountCloudWatchToEncryptAlarmNotifications",
        principals: [
          new iam.ServicePrincipal("cloudwatch.amazonaws.com")
        ],
        actions: ["kms:Decrypt", "kms:GenerateDataKey*"],
        resources: ["*"],
        conditions: {
          StringEquals: { "aws:SourceAccount": Aws.ACCOUNT_ID }
        }
      })
    );
    queueKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: "AllowAccountSnsToDeliverAlarmProof",
        principals: [
          new iam.ServicePrincipal("sns.amazonaws.com")
        ],
        actions: ["kms:Decrypt", "kms:GenerateDataKey*"],
        resources: ["*"],
        conditions: {
          StringEquals: { "aws:SourceAccount": Aws.ACCOUNT_ID }
        }
      })
    );
    alarmTopic.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: "AllowOnlyAccountCloudWatchAlarmsToPublish",
        principals: [
          new iam.ServicePrincipal("cloudwatch.amazonaws.com")
        ],
        actions: ["sns:Publish"],
        resources: [alarmTopic.topicArn],
        conditions: {
          StringEquals: { "aws:SourceAccount": Aws.ACCOUNT_ID },
          ArnLike: {
            "aws:SourceArn":
              `arn:${Aws.PARTITION}:cloudwatch:${Aws.REGION}:${Aws.ACCOUNT_ID}:alarm:archon-${stage}-*`
          }
        }
      })
    );

    const functionErrors = [
      runtimeControl,
      control,
      remediation
    ].map((fn) => fn.metricErrors({
      period: Duration.minutes(5),
      statistic: "Sum"
    }));
    const controlPlaneErrors = new cloudwatch.Alarm(
      this,
      "ControlPlaneErrors",
      {
      alarmName: `archon-${stage}-control-plane-errors`,
      alarmDescription:
        "Serverless judge control plane returned errors",
      metric: new cloudwatch.MathExpression({
        expression: functionErrors
          .map((_, index) => `m${index}`)
          .join("+"),
        usingMetrics: Object.fromEntries(
          functionErrors.map((metric, index) => [
            `m${index}`,
            metric
          ])
        ),
        period: Duration.minutes(5)
      }),
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData:
        cloudwatch.TreatMissingData.NOT_BREACHING
    });
    const runtimeFailureQueueVisible = new cloudwatch.Alarm(
      this,
      "RuntimeFailureQueueVisible",
      {
      alarmName:
        `archon-${stage}-runtime-failure-queue-visible`,
      alarmDescription:
        "A bounded DataHub worker event exhausted retries",
      metric:
        failureQueue.metricApproximateNumberOfMessagesVisible({
          period: Duration.minutes(5),
          statistic: "Maximum"
        }),
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData:
        cloudwatch.TreatMissingData.NOT_BREACHING
      }
    );
    for (const alarm of [
      controlPlaneErrors,
      runtimeFailureQueueVisible
    ]) {
      alarm.addAlarmAction(
        new cloudwatchActions.SnsAction(alarmTopic)
      );
      alarm.addOkAction(
        new cloudwatchActions.SnsAction(alarmTopic)
      );
    }
    new cloudwatch.Dashboard(this, "JudgeDashboard", {
      dashboardName: `archon-${stage}-judge`,
      widgets: [
        [
          new cloudwatch.GraphWidget({
            title: "Serverless control errors",
            left: functionErrors,
            width: 12
          }),
          new cloudwatch.GraphWidget({
            title: "Bounded runtime failures",
            left: [
              failureQueue
                .metricApproximateNumberOfMessagesVisible()
            ],
            width: 12
          })
        ]
      ]
    });

    output(this, "ArchonAlarmTopicArn", alarmTopic.topicArn);
    output(
      this,
      "ArchonAlarmProofQueueUrl",
      alarmProofQueue.queueUrl
    );
    output(
      this,
      "ArchonAlarmProofQueueArn",
      alarmProofQueue.queueArn
    );
    output(
      this,
      "ArchonControlPlaneAlarmName",
      controlPlaneErrors.alarmName
    );
    output(this, "ArchonSpaBucketName", spaBucket.bucketName);
    output(this, "ArchonSpaKeyArn", spaKey.keyArn);
    output(this, "ArchonSecretsKeyArn", secretsKey.keyArn);
    output(
      this,
      "ArchonCloudCheckpointBucketName",
      checkpointBucket.bucketName
    );
    output(
      this,
      "ArchonCloudCheckpointKeyArn",
      dataKey.keyArn
    );
    output(
      this,
      "ArchonRuntimeSessionTableName",
      runtimeSessionTable.tableName
    );
    output(
      this,
      "ArchonRuntimeSessionTableStreamArn",
      runtimeSessionTable.tableStreamArn!
    );
    output(
      this,
      "ArchonRuntimeJobTableName",
      runtimeJobTable.tableName
    );
    output(
      this,
      "ArchonRuntimeJobTableStreamArn",
      runtimeJobTable.tableStreamArn!
    );
    output(
      this,
      "ArchonCoreSessionStateMachineArn",
      coreStateMachineArn
    );
    output(
      this,
      "ArchonCoreGeneration",
      coreGeneration
    );
    output(
      this,
      "ArchonCoreCapabilityDigest",
      coreCapabilityDigest
    );
    output(
      this,
      "ArchonRuntimeMutationSigningKeyArn",
      mutationSigningKeyArn
    );
    output(
      this,
      "ArchonCloudReaderSecretArn",
      cloudReaderSecret.secretArn
    );
    output(
      this,
      "ArchonCloudWriterSecretArn",
      cloudWriterSecret.secretArn
    );
    output(
      this,
      "ArchonRuntimeFailureQueueUrl",
      failureQueue.queueUrl
    );
    output(
      this,
      "ArchonRuntimeControlFunctionArn",
      runtimeControl.functionArn
    );
    output(
      this,
      "ArchonRuntimeRemediationFunctionArn",
      remediation.functionArn
    );
    output(
      this,
      "ArchonCloudReadFunctionArn",
      cloudRuntime.readFunctionArn
    );
    output(
      this,
      "ArchonCloudReaderFunctionName",
      cloudRuntime.readFunctionName
    );
    output(
      this,
      "ArchonCloudMutationFunctionArn",
      cloudRuntime.mutationFunctionArn
    );
    output(
      this,
      "ArchonCloudMutationFunctionName",
      cloudRuntime.mutationFunctionName
    );
    output(
      this,
      "ArchonCloudResetFunctionArn",
      cloudRuntime.resetFunctionArn
    );
    output(
      this,
      "ArchonCloudFixtureResetFunctionName",
      cloudRuntime.resetFunctionName
    );
    output(
      this,
      "ArchonCloudAnalyticsRoleArn",
      cloudRuntime.readRoleArn
    );
    output(
      this,
      "ArchonCloudReaderRoleArn",
      cloudRuntime.readRoleArn
    );
    output(
      this,
      "ArchonCloudMutationRoleArn",
      cloudRuntime.mutationRoleArn
    );
    output(
      this,
      "ArchonCloudResetRoleArn",
      cloudRuntime.resetRoleArn
    );
    output(
      this,
      "ArchonCloudFixtureResetRoleArn",
      cloudRuntime.resetRoleArn
    );
    output(
      this,
      "ArchonCloudRuntimeImageUri",
      cloudRuntimeImageUri
    );
    output(
      this,
      "ArchonSpaArtifactSha256",
      spaArtifactSha256
    );
    output(
      this,
      "ArchonLambdaArtifactSha256",
      lambdaArtifactSha256
    );
    output(
      this,
      "ArchonCloudRuntimeReleaseDigest",
      cloudRuntimeReleaseDigest
    );
    output(this, "ArchonCiRunId", ciRunId);
    output(
      this,
      "ArchonDeploymentWorkflowRunId",
      deploymentWorkflowRunId
    );
    output(this, "ArchonReleaseSha", releaseSha);
    output(
      this,
      "ArchonCanonicalDatasetUrn",
      CANONICAL_DATASET_URN
    );
    output(
      this,
      "ArchonCanonicalQuestion",
      CANONICAL_QUESTION
    );
    output(
      this,
      "ArchonGovernedColumnPath",
      GOVERNED_COLUMN_PATH
    );
  }
}

interface NodeFunctionProps {
  readonly id: string;
  readonly functionName: string;
  readonly handler: string;
  readonly directory: string;
  readonly memorySize: number;
  readonly timeout: number;
  readonly concurrency: number;
  readonly logsKey: kms.IKey;
  readonly stage: ArchonStage;
  readonly environment: Record<string, string>;
}

function nodeFunction(
  scope: Construct,
  props: NodeFunctionProps
): lambda.Function {
  const logGroup = retainedLogGroup(
    scope,
    `${props.id}Logs`,
    `/archon/${props.stage}/${props.functionName}`,
    props.logsKey,
    logs.RetentionDays.ONE_YEAR
  );
  return new lambda.Function(scope, props.id, {
    functionName: props.functionName,
    description:
      "Digest-bound DataHub dual-runtime serverless control function",
    runtime: lambda.Runtime.NODEJS_24_X,
    architecture: lambda.Architecture.X86_64,
    handler: props.handler,
    code: lambda.Code.fromAsset(
      join(__dirname, `../lambda/${props.directory}`)
    ),
    memorySize: props.memorySize,
    timeout: Duration.seconds(props.timeout),
    reservedConcurrentExecutions: props.concurrency,
    tracing: lambda.Tracing.ACTIVE,
    logGroup,
    environment: props.environment,
    ephemeralStorageSize: Size.mebibytes(512)
  });
}

function addRuntimeControlPolicy(
  fn: lambda.Function,
  sessions: dynamodb.ITable,
  jobs: dynamodb.ITable,
  stateMachineArn: string
): void {
  fn.addToRolePolicy(
    ddbPolicy(
      "OwnOnlyRuntimeSessionsAndCloudHealth",
      ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
      sessions.tableArn,
      ["RUNTIME#cloud", "SESSION#rs_*"]
    )
  );
  fn.addToRolePolicy(
    ddbPolicy(
      "ObserveOnlyCoreLeaseAndHealth",
      ["dynamodb:GetItem"],
      jobs.tableArn,
      ["CORE#LEASE", "RUNTIME#core"]
    )
  );
  fn.addToRolePolicy(
    new iam.PolicyStatement({
      sid: "StartOnlyCoreLifecycleCommands",
      actions: ["states:StartExecution"],
      resources: [stateMachineArn]
    })
  );
}

function addControlPolicy(
  fn: lambda.Function,
  sessions: dynamodb.ITable,
  jobs: dynamodb.ITable,
  stateMachineArn: string
): void {
  fn.addToRolePolicy(
    ddbPolicy(
      "OwnOnlyBoundAgentRunsAndApprovals",
      [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:TransactWriteItems",
        "dynamodb:UpdateItem"
      ],
      sessions.tableArn,
      ["AUDIT#*", "SESSION#rs_*"]
    )
  );
  fn.addToRolePolicy(
    ddbPolicy(
      "DispatchAndReadOnlyBoundRuntimeJobs",
      [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:TransactWriteItems",
        "dynamodb:UpdateItem"
      ],
      jobs.tableArn,
      ["MUTATION#rs_*", "SESSION#rs_*"]
    )
  );
  fn.addToRolePolicy(
    new iam.PolicyStatement({
      sid: "RecordOnlyCoreRuntimeActivity",
      actions: ["states:StartExecution"],
      resources: [stateMachineArn]
    })
  );
}

function addRemediationPolicy(
  fn: lambda.Function,
  sessions: dynamodb.ITable,
  jobs: dynamodb.ITable,
  signingKeyArn: string
): void {
  fn.addToRolePolicy(
    ddbPolicy(
      "SealOnlyBoundApprovalsAndPostWriteState",
      [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:TransactWriteItems",
        "dynamodb:UpdateItem"
      ],
      sessions.tableArn,
      ["AUDIT#*", "SESSION#rs_*"]
    )
  );
  fn.addToRolePolicy(
    ddbPolicy(
      "EnqueueOnlyApprovedMutationAndVerification",
      [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:TransactWriteItems",
        "dynamodb:UpdateItem"
      ],
      jobs.tableArn,
      ["MUTATION#rs_*", "SESSION#rs_*"]
    )
  );
  fn.addToRolePolicy(
    new iam.PolicyStatement({
      sid: "SignOnlyGovernedMutationAuthorization",
      actions: ["kms:Sign"],
      resources: [signingKeyArn],
      conditions: {
        StringEquals: {
          "kms:SigningAlgorithm": "ECDSA_SHA_256"
        }
      }
    })
  );
}

function ddbPolicy(
  sid: string,
  actions: string[],
  resource: string,
  leadingKeys: string[]
): iam.PolicyStatement {
  return new iam.PolicyStatement({
    sid,
    actions,
    resources: [resource],
    conditions: {
      "ForAllValues:StringLike": {
        "dynamodb:LeadingKeys": leadingKeys
      }
    }
  });
}

function parameter(
  scope: Construct,
  id: string,
  description: string,
  allowedPattern: string
): string {
  return new CfnParameter(scope, id, {
    type: "String",
    description,
    allowedPattern
  }).valueAsString;
}
