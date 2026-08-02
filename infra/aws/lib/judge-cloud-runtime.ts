import {
  Aws,
  Stack
} from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as sqs from "aws-cdk-lib/aws-sqs";
import { Construct } from "constructs";
import {
  BEDROCK_BASE_MODEL,
  BEDROCK_BASE_REGIONS,
  BEDROCK_INFERENCE_PROFILE,
  CANONICAL_DATASET_URN,
  CANONICAL_QUESTION,
  retainedLogGroup,
  type ArchonStage
} from "./judge-contract";

export interface CloudRuntimeProps {
  readonly stage: ArchonStage;
  readonly imageUri: string;
  readonly jobTable: dynamodb.ITable;
  readonly sessionTable: dynamodb.ITable;
  readonly checkpointBucket: s3.IBucket;
  readonly checkpointKey: kms.IKey;
  readonly readerSecret: secretsmanager.ISecret;
  readonly writerSecret: secretsmanager.ISecret;
  readonly mutationSigningKeyArn: string;
  readonly failureQueue: sqs.IQueue;
  readonly logsKey: kms.IKey;
}

export interface CloudRuntime {
  readonly readFunctionArn: string;
  readonly readFunctionName: string;
  readonly readRoleArn: string;
  readonly mutationFunctionArn: string;
  readonly mutationFunctionName: string;
  readonly mutationRoleArn: string;
  readonly resetFunctionArn: string;
  readonly resetFunctionName: string;
  readonly resetRoleArn: string;
}

interface ImageFunctionConfig {
  readonly id: string;
  readonly functionName: string;
  readonly command: string;
  readonly memoryMiB: number;
  readonly timeoutSeconds: number;
  readonly ephemeralStorageMiB: number;
  readonly reservedConcurrency: number;
  readonly role: iam.Role;
  readonly logGroup: logs.ILogGroup;
  readonly environment: Record<string, string>;
}

interface MappingConfig {
  readonly id: string;
  readonly functionResource: lambda.CfnFunction;
  readonly role: iam.Role;
  readonly streamArn: string;
  readonly batchSize: number;
  readonly batchingWindowSeconds: number;
  readonly maximumConcurrency: number;
  readonly filter: Record<string, unknown>;
}

function requireStreamArn(
  table: dynamodb.ITable,
  label: string
): string {
  if (!table.tableStreamArn) {
    throw new Error(label + " must expose a DynamoDB stream ARN");
  }
  return table.tableStreamArn;
}

function runtimeRole(
  scope: Construct,
  id: string,
  name: string
): iam.Role {
  const role = new iam.Role(scope, id, {
    roleName: name,
    assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
    description:
      "Least-privilege Archon DataHub Cloud image Lambda role"
  });
  role.addToPolicy(
    new iam.PolicyStatement({
      sid: "WriteOnlyXrayTelemetry",
      actions: ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
      resources: ["*"]
    })
  );
  return role;
}

function imageFunction(
  scope: Construct,
  imageUri: string,
  config: ImageFunctionConfig
): lambda.CfnFunction {
  config.role.addToPolicy(
    new iam.PolicyStatement({
      sid: "WriteOnlyOwnEncryptedLogStream",
      actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
      resources: [config.logGroup.logGroupArn + ":*"]
    })
  );
  const fn = new lambda.CfnFunction(scope, config.id, {
    functionName: config.functionName,
    packageType: "Image",
    code: { imageUri },
    role: config.role.roleArn,
    architectures: ["x86_64"],
    memorySize: config.memoryMiB,
    timeout: config.timeoutSeconds,
    ephemeralStorage: { size: config.ephemeralStorageMiB },
    reservedConcurrentExecutions: config.reservedConcurrency,
    tracingConfig: { mode: "Active" },
    imageConfig: { command: [config.command] },
    environment: { variables: config.environment },
    description:
      "Digest-pinned, no-VPC Archon DataHub Cloud runtime worker"
  });
  fn.node.addDependency(config.role);
  fn.node.addDependency(config.logGroup);
  return fn;
}

function streamReadPolicy(
  sid: string,
  streamArn: string
): iam.PolicyStatement {
  return new iam.PolicyStatement({
    sid,
    actions: [
      "dynamodb:DescribeStream",
      "dynamodb:GetRecords",
      "dynamodb:GetShardIterator",
      "dynamodb:ListStreams"
    ],
    resources: [streamArn]
  });
}

function tablePolicy(
  sid: string,
  actions: string[],
  table: dynamodb.ITable
): iam.PolicyStatement {
  return new iam.PolicyStatement({
    sid,
    actions,
    resources: [table.tableArn]
  });
}

function secretReadPolicy(
  sid: string,
  secret: secretsmanager.ISecret
): iam.PolicyStatement {
  return new iam.PolicyStatement({
    sid,
    actions: ["secretsmanager:GetSecretValue"],
    resources: [secret.secretArn],
    conditions: {
      StringEquals: {
        "secretsmanager:VersionStage": "AWSCURRENT"
      }
    }
  });
}

function eventMapping(
  scope: Construct,
  failureQueue: sqs.IQueue,
  config: MappingConfig
): lambda.CfnEventSourceMapping {
  config.role.addToPolicy(
    streamReadPolicy(
      "Consume" + config.id + "Stream",
      config.streamArn
    )
  );
  failureQueue.grantSendMessages(config.role);
  const mapping = new lambda.CfnEventSourceMapping(
    scope,
    config.id,
    {
      functionName: config.functionResource.ref,
      eventSourceArn: config.streamArn,
      startingPosition: "LATEST",
      batchSize: config.batchSize,
      maximumBatchingWindowInSeconds:
        config.batchingWindowSeconds,
      parallelizationFactor: 1,
      scalingConfig: {
        maximumConcurrency: config.maximumConcurrency
      },
      maximumRetryAttempts: 5,
      maximumRecordAgeInSeconds: 3600,
      bisectBatchOnFunctionError: true,
      functionResponseTypes: ["ReportBatchItemFailures"],
      destinationConfig: {
        onFailure: { destination: failureQueue.queueArn }
      },
      filterCriteria: {
        filters: [{ pattern: JSON.stringify(config.filter) }]
      }
    }
  );
  mapping.addDependency(config.functionResource);
  return mapping;
}

export function addCloudRuntime(
  scope: Construct,
  props: CloudRuntimeProps
): CloudRuntime {
  const {
    stage,
    imageUri,
    jobTable,
    sessionTable,
    checkpointBucket,
    checkpointKey,
    readerSecret,
    writerSecret,
    mutationSigningKeyArn,
    failureQueue,
    logsKey
  } = props;
  const jobStreamArn =
    requireStreamArn(jobTable, "Core runtime job/lease table");
  const sessionStreamArn =
    requireStreamArn(sessionTable, "Runtime session table");

  const readName = `archon-${stage}-cloud-read`;
  const mutationName = `archon-${stage}-cloud-mutation`;
  const resetName = `archon-${stage}-cloud-reset`;
  const readRole = runtimeRole(
    scope,
    "CloudReadRole",
    `archon-${stage}-cloud-reader`
  );
  const mutationRole = runtimeRole(
    scope,
    "CloudMutationRole",
    `archon-${stage}-cloud-mutation`
  );
  const resetRole = runtimeRole(
    scope,
    "CloudResetRole",
    `archon-${stage}-cloud-fixture-reset`
  );

  readRole.addToPolicy(
    tablePolicy(
      "ClaimAndCompleteOnlyCloudReadJobs",
      ["dynamodb:GetItem", "dynamodb:UpdateItem"],
      jobTable
    )
  );
  readRole.addToPolicy(
    tablePolicy(
      "ReadAndCreateOnlyCloudLeaseCheckpoints",
      ["dynamodb:GetItem", "dynamodb:PutItem"],
      sessionTable
    )
  );
  readRole.addToPolicy(
    secretReadPolicy("ReadOnlyCloudReaderSecret", readerSecret)
  );
  readerSecret.encryptionKey?.grantDecrypt(readRole);
  readRole.addToPolicy(
    new iam.PolicyStatement({
      sid: "ReadVersionAndWriteOnlyCloudCheckpoints",
      actions: [
        "s3:GetObjectVersion",
        "s3:PutObject",
        "s3:DeleteObjectVersion"
      ],
      resources: [
        `${checkpointBucket.bucketArn}/cloud-runtime/v2/*`
      ]
    })
  );
  readRole.addToPolicy(
    new iam.PolicyStatement({
      sid: "ObserveOnlyCheckpointVersioning",
      actions: ["s3:GetBucketVersioning"],
      resources: [checkpointBucket.bucketArn]
    })
  );
  readRole.addToPolicy(
    new iam.PolicyStatement({
      sid: "UseOnlyCheckpointEnvelopeKeyThroughS3",
      actions: ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
      resources: [checkpointKey.keyArn],
      conditions: {
        StringEquals: {
          "kms:ViaService":
            `s3.${Aws.REGION}.${Aws.URL_SUFFIX}`
        }
      }
    })
  );
  readRole.addToPolicy(
    new iam.PolicyStatement({
      sid: "InvokeOnlyReviewedAnalyticsModels",
      actions: [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      resources: [
        `arn:${Aws.PARTITION}:bedrock:${Aws.REGION}:${Aws.ACCOUNT_ID}:inference-profile/${BEDROCK_INFERENCE_PROFILE}`,
        ...BEDROCK_BASE_REGIONS.map(
          (region) =>
            `arn:${Aws.PARTITION}:bedrock:${region}::foundation-model/${BEDROCK_BASE_MODEL}`
        )
      ]
    })
  );
  readRole.addToPolicy(
    new iam.PolicyStatement({
      sid: "ConfirmExpectedAnalyticsRoleOnly",
      actions: ["sts:GetCallerIdentity"],
      resources: ["*"]
    })
  );

  mutationRole.addToPolicy(
    tablePolicy(
      "ConsumeOnlyGovernedMutationJobs",
      ["dynamodb:GetItem", "dynamodb:UpdateItem"],
      jobTable
    )
  );
  mutationRole.addToPolicy(
    tablePolicy(
      "ObserveOnlyCloudSessionBinding",
      ["dynamodb:GetItem"],
      sessionTable
    )
  );
  mutationRole.addToPolicy(
    secretReadPolicy("ReadOnlyCloudWriterSecret", writerSecret)
  );
  writerSecret.encryptionKey?.grantDecrypt(mutationRole);
  mutationRole.addToPolicy(
    new iam.PolicyStatement({
      sid: "FetchOnlyMutationVerificationPublicKey",
      actions: ["kms:GetPublicKey"],
      resources: [mutationSigningKeyArn]
    })
  );

  resetRole.addToPolicy(
    tablePolicy(
      "WriteOnlyFixtureResetLedger",
      [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem"
      ],
      sessionTable
    )
  );
  resetRole.addToPolicy(
    secretReadPolicy("ReadOnlyFixtureResetWriterSecret", writerSecret)
  );
  writerSecret.encryptionKey?.grantDecrypt(resetRole);

  const readLog = retainedLogGroup(
    scope,
    "CloudReadLogGroup",
    `/archon/${stage}/lambda/cloud-read`,
    logsKey,
    logs.RetentionDays.ONE_YEAR
  );
  const mutationLog = retainedLogGroup(
    scope,
    "CloudMutationLogGroup",
    `/archon/${stage}/lambda/cloud-mutation`,
    logsKey,
    logs.RetentionDays.ONE_YEAR
  );
  const resetLog = retainedLogGroup(
    scope,
    "CloudResetLogGroup",
    `/archon/${stage}/lambda/cloud-reset`,
    logsKey,
    logs.RetentionDays.ONE_YEAR
  );

  const common = {
    ARCHON_STAGE: stage,
    RUNTIME_JOB_TABLE: jobTable.tableName,
    RUNTIME_SESSION_TABLE: sessionTable.tableName,
    CLOUD_RUNTIME_LEASE_TABLE: sessionTable.tableName
  };
  const readFunction = imageFunction(scope, imageUri, {
    id: "CloudReadFunction",
    functionName: readName,
    command: "handlers.read_handler",
    memoryMiB: 4096,
    timeoutSeconds: 900,
    ephemeralStorageMiB: 1024,
    reservedConcurrency: 2,
    role: readRole,
    logGroup: readLog,
    environment: {
      ...common,
      ARCHON_BEDROCK_MODEL: BEDROCK_INFERENCE_PROFILE,
      ARCHON_EXPECTED_ANALYTICS_ROLE_ARN: readRole.roleArn,
      RUNTIME_JOB_STREAM_ARN: jobStreamArn,
      CLOUD_CHECKPOINT_BUCKET: checkpointBucket.bucketName,
      CLOUD_CHECKPOINT_KMS_KEY_ARN: checkpointKey.keyArn,
      DATAHUB_CLOUD_READER_SECRET_ARN: readerSecret.secretArn,
      ARCHON_DEMO_QUERY: CANONICAL_DATASET_URN,
      ARCHON_ANALYTICS_QUESTION: CANONICAL_QUESTION
    }
  });
  const mutationFunction = imageFunction(scope, imageUri, {
    id: "CloudMutationFunction",
    functionName: mutationName,
    command: "handlers.mutation_handler",
    memoryMiB: 512,
    timeoutSeconds: 180,
    ephemeralStorageMiB: 512,
    reservedConcurrency: 1,
    role: mutationRole,
    logGroup: mutationLog,
    environment: {
      ...common,
      RUNTIME_JOB_STREAM_ARN: jobStreamArn,
      DATAHUB_CLOUD_WRITER_SECRET_ARN: writerSecret.secretArn,
      MUTATION_SIGNING_KEY_ARN: mutationSigningKeyArn
    }
  });
  const resetFunction = imageFunction(scope, imageUri, {
    id: "CloudResetFunction",
    functionName: resetName,
    command: "handlers.fixture_reset_handler",
    memoryMiB: 512,
    timeoutSeconds: 180,
    ephemeralStorageMiB: 512,
    reservedConcurrency: 1,
    role: resetRole,
    logGroup: resetLog,
    environment: {
      ARCHON_STAGE: stage,
      FIXTURE_RESET_SOURCE_STREAM_ARNS:
        Stack.of(scope).toJsonString(
          [sessionStreamArn, jobStreamArn]
        ),
      FIXTURE_RESET_TABLE: sessionTable.tableName,
      DATAHUB_CLOUD_WRITER_SECRET_ARN: writerSecret.secretArn
    }
  });

  eventMapping(scope, failureQueue, {
    id: "CloudReadJobs",
    functionResource: readFunction,
    role: readRole,
    streamArn: jobStreamArn,
    batchSize: 5,
    batchingWindowSeconds: 1,
    maximumConcurrency: 2,
    filter: {
      eventName: ["INSERT", "MODIFY"],
      dynamodb: {
        NewImage: {
          schema: { S: ["archon.runtime-bound-job/v2"] },
          profileId: { S: ["cloud"] },
          state: { S: ["QUEUED"] },
          operation: {
            S: [
              "ANALYZE",
              "READ_TAGS",
              "IMPROVE_CONTEXT",
              "POST_ANALYZE",
              "POST_READ_TAGS"
            ]
          }
        }
      }
    }
  });
  eventMapping(scope, failureQueue, {
    id: "CloudMutationJobs",
    functionResource: mutationFunction,
    role: mutationRole,
    streamArn: jobStreamArn,
    batchSize: 1,
    batchingWindowSeconds: 0,
    maximumConcurrency: 1,
    filter: {
      eventName: ["INSERT", "MODIFY"],
      dynamodb: {
        NewImage: {
          schema: { S: ["archon.runtime-bound-job/v2"] },
          profileId: { S: ["cloud"] },
          state: { S: ["QUEUED"] },
          operation: { S: ["GOVERNED_TAG_MUTATION"] }
        }
      }
    }
  });
  eventMapping(scope, failureQueue, {
    id: "CloudFixtureResetSessions",
    functionResource: resetFunction,
    role: resetRole,
    streamArn: sessionStreamArn,
    batchSize: 1,
    batchingWindowSeconds: 0,
    maximumConcurrency: 1,
    filter: {
      eventName: ["MODIFY"],
      dynamodb: {
        NewImage: { sk: { S: ["RUNTIME"] } }
      }
    }
  });
  eventMapping(scope, failureQueue, {
    id: "CloudFixtureResetCoreLease",
    functionResource: resetFunction,
    role: resetRole,
    streamArn: jobStreamArn,
    batchSize: 1,
    batchingWindowSeconds: 0,
    maximumConcurrency: 1,
    filter: {
      eventName: ["MODIFY"],
      dynamodb: {
        NewImage: {
          pk: { S: ["CORE#LEASE"] },
          sk: { S: ["CURRENT"] },
          state: { S: ["DRAINING"] }
        }
      }
    }
  });

  return {
    readFunctionArn: readFunction.attrArn,
    readFunctionName: readFunction.ref,
    readRoleArn: readRole.roleArn,
    mutationFunctionArn: mutationFunction.attrArn,
    mutationFunctionName: mutationFunction.ref,
    mutationRoleArn: mutationRole.roleArn,
    resetFunctionArn: resetFunction.attrArn,
    resetFunctionName: resetFunction.ref,
    resetRoleArn: resetRole.roleArn
  };
}
