import { createHash } from "node:crypto";
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  TransactWriteItemsCommand,
  UpdateItemCommand,
  type AttributeValue,
} from "@aws-sdk/client-dynamodb";
import {
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import {
  ChangeMessageVisibilityCommand,
  DeleteMessageCommand,
  ReceiveMessageCommand,
  SendMessageCommand,
  SQSClient,
  type Message,
  type ReceiveMessageCommandOutput,
} from "@aws-sdk/client-sqs";
import {
  SendTaskFailureCommand,
  SendTaskHeartbeatCommand,
  SendTaskSuccessCommand,
  SFNClient,
} from "@aws-sdk/client-sfn";
import type {
  ExecutionClaim,
  ExecutionJournal,
  ExecutionReceiptV1,
} from "../remediation/contracts.js";
import { RemediationError } from "../remediation/control-loop.js";
import {
  canonicalize,
  type Sha256Digest,
} from "../remediation/integrity.js";
import { verifyExecutionReceipt } from "../remediation/receipt.js";
import type {
  AsyncMessageKind,
  AuditCallbackOutputV1,
  AuditEvidenceV1,
  ExecutionEvidenceV1,
  AuditQueueMessageV1,
  RemediationQueueMessageV1,
  WorkerQueueMessage,
} from "./contracts.js";
import {
  parseQueueMessage,
  WorkerContractError,
} from "./contracts.js";
import type {
  AuditResultCheckpoint,
  ExecutionLease,
  ImmutableEvidenceStore,
} from "./service.js";
import {
  AuditWorkerService,
  RemediationWorkerService,
  verifyAuditEvidence,
} from "./service.js";

const MAX_STORED_EVIDENCE_BYTES = 6 * 1024 * 1024;
const JOURNAL_TTL_SECONDS = 90 * 24 * 60 * 60;
const EXECUTION_LEASE_SECONDS = 10 * 60;

class WorkerLeaseError extends Error {
  constructor(readonly terminal: boolean) {
    super("The Step Functions callback task is not currently usable.");
    this.name = "WorkerLeaseError";
  }
}

class RetryableExecutionJournalError extends Error {
  readonly retryable = true;

  constructor(cause: unknown) {
    super(
      "DynamoDB canceled the execution claim without enough state to classify the result.",
      { cause }
    );
    this.name = "RetryableExecutionJournalError";
  }
}

const RETRYABLE_ERROR_NAMES = new Set([
  "AbortError",
  "ECONNRESET",
  "EAI_AGAIN",
  "ETIMEDOUT",
  "InternalError",
  "InternalServerError",
  "NetworkingError",
  "RequestTimeout",
  "ServiceUnavailable",
  "SlowDown",
  "Throttling",
  "ThrottlingException",
  "TimeoutError",
  "TooManyRequestsException",
]);

const TERMINAL_CONFIGURATION_ERROR_NAMES = new Set([
  "AccessDenied",
  "AccessDeniedException",
  "CredentialsProviderError",
  "InvalidSignatureException",
  "ResourceNotFoundException",
  "UnrecognizedClientException",
  "ValidationException",
]);

function isTerminalTaskError(error: unknown): boolean {
  return ["TaskDoesNotExist", "TaskTimedOut", "InvalidToken"].includes(
    awsErrorName(error)
  );
}

function awsErrorName(error: unknown): string {
  return error instanceof Error ? error.name : "UnknownError";
}

function isRetryableError(error: unknown): boolean {
  if (error instanceof WorkerContractError) return false;
  const metadata = (error as {
    $metadata?: { httpStatusCode?: number };
    retryable?: boolean;
  })?.$metadata;
  const status = metadata?.httpStatusCode;
  const name = awsErrorName(error);
  if ((error as { retryable?: boolean })?.retryable === true) return true;
  if (RETRYABLE_ERROR_NAMES.has(name)) return true;
  if (TERMINAL_CONFIGURATION_ERROR_NAMES.has(name)) return false;
  if (status === 408 || status === 429 || (status !== undefined && status >= 500)) {
    return true;
  }
  if (status !== undefined && status >= 400 && status < 500) return false;
  return true;
}

function isConditionalFailure(error: unknown): boolean {
  const status = (error as { $metadata?: { httpStatusCode?: number } })?.$metadata
    ?.httpStatusCode;
  const name = awsErrorName(error);
  if (name === "TransactionCanceledException") {
    const reasons = (
      error as {
        CancellationReasons?: Array<{ Code?: string }>;
      }
    ).CancellationReasons;
    return (
      Array.isArray(reasons) &&
      reasons.some((reason) => reason.Code === "ConditionalCheckFailed") &&
      reasons.every(
        (reason) =>
          reason.Code === "ConditionalCheckFailed" ||
          reason.Code === "None" ||
          reason.Code === undefined
      )
    );
  }
  return (
    status === 409 ||
    status === 412 ||
    name === "ConditionalCheckFailedException" ||
    name === "PreconditionFailed"
  );
}

function isTransactionCancellationWithoutReasons(error: unknown): boolean {
  if (awsErrorName(error) !== "TransactionCanceledException") return false;
  const reasons = (
    error as {
      CancellationReasons?: Array<{ Code?: string }>;
    }
  ).CancellationReasons;
  return !Array.isArray(reasons) || reasons.length === 0;
}

function stringAttribute(
  item: Record<string, AttributeValue> | undefined,
  name: string
): string | undefined {
  const value = item?.[name];
  return value && "S" in value ? value.S : undefined;
}

function numberAttribute(
  item: Record<string, AttributeValue> | undefined,
  name: string
): number | undefined {
  const value = item?.[name];
  if (!value || !("N" in value) || value.N === undefined) return undefined;
  const parsed = Number(value.N);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function evidenceKey(kind: "audit" | "execution", digest: Sha256Digest): string {
  return `v1/${kind}/sha256/${digest.slice("sha256:".length)}.json`;
}

async function bodyText(
  body: { transformToByteArray(): Promise<Uint8Array> } | undefined
): Promise<string> {
  if (!body) {
    throw new WorkerContractError("INVALID_EVIDENCE", "Evidence object has no body.");
  }
  const bytes = await body.transformToByteArray();
  if (bytes.byteLength > MAX_STORED_EVIDENCE_BYTES) {
    throw new WorkerContractError("INVALID_EVIDENCE", "Stored evidence exceeds the read limit.");
  }
  return Buffer.from(bytes).toString("utf8");
}

export class S3ImmutableEvidenceStore implements ImmutableEvidenceStore {
  constructor(
    private readonly client: S3Client,
    private readonly bucket: string
  ) {}

  async put(document: AuditEvidenceV1 | ExecutionEvidenceV1): Promise<void> {
    const kind = document.schemaVersion === "archon.audit-evidence/v1" ? "audit" : "execution";
    const key = evidenceKey(kind, document.digest);
    const body = canonicalize(document);
    const checksum = createHash("sha256").update(body, "utf8").digest("base64");
    try {
      await this.client.send(
        new PutObjectCommand({
          Bucket: this.bucket,
          Key: key,
          Body: body,
          ContentType: "application/json",
          CacheControl: "no-store",
          ChecksumSHA256: checksum,
          IfNoneMatch: "*",
          Metadata: {
            "archon-schema": document.schemaVersion,
            "archon-digest": document.digest,
          },
        })
      );
    } catch (error) {
      if (!isConditionalFailure(error)) throw error;
      const existing = await this.readText(key);
      if (existing !== body) {
        throw new WorkerContractError(
          "INVALID_EVIDENCE",
          "A content-addressed evidence key already contains different bytes."
        );
      }
    }
  }

  async getAuditEvidence(expectedDigest: Sha256Digest): Promise<AuditEvidenceV1> {
    const text = await this.readText(evidenceKey("audit", expectedDigest));
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new WorkerContractError("INVALID_EVIDENCE", "Stored audit evidence is not JSON.");
    }
    if (!verifyAuditEvidence(parsed, expectedDigest)) {
      throw new WorkerContractError(
        "INVALID_EVIDENCE",
        "Stored audit evidence failed digest or artifact verification."
      );
    }
    return parsed;
  }

  private async readText(key: string): Promise<string> {
    const response = await this.client.send(
      new GetObjectCommand({
        Bucket: this.bucket,
        Key: key,
        ChecksumMode: "ENABLED",
      })
    );
    return bodyText(response.Body);
  }
}

function auditOutput(value: string | undefined): AuditCallbackOutputV1 | null {
  if (!value) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const candidate = parsed as Partial<AuditCallbackOutputV1>;
  const digestPattern = /^sha256:[a-f0-9]{64}$/u;
  if (
    candidate.schemaVersion !== "archon.audit-result/v1" ||
    typeof candidate.requiresApproval !== "boolean" ||
    typeof candidate.reportDigest !== "string" ||
    !digestPattern.test(candidate.reportDigest) ||
    typeof candidate.evidenceDigest !== "string" ||
    !digestPattern.test(candidate.evidenceDigest)
  ) {
    return null;
  }
  if (
    candidate.requiresApproval &&
    (typeof candidate.approvalId !== "string" ||
      typeof candidate.planDigest !== "string" ||
      !digestPattern.test(candidate.planDigest) ||
      typeof candidate.approvalRequestDigest !== "string" ||
      !digestPattern.test(candidate.approvalRequestDigest) ||
      typeof candidate.approvalRequestedAt !== "string" ||
      !Number.isFinite(Date.parse(candidate.approvalRequestedAt)) ||
      typeof candidate.approvalExpiresAt !== "string" ||
      !Number.isFinite(Date.parse(candidate.approvalExpiresAt)) ||
      Date.parse(candidate.approvalExpiresAt) <=
        Date.parse(candidate.approvalRequestedAt))
  ) {
    return null;
  }
  if (!candidate.requiresApproval && typeof candidate.manualOnlyReason !== "string") {
    return null;
  }
  return candidate as AuditCallbackOutputV1;
}

export class DynamoAuditResultCheckpoint implements AuditResultCheckpoint {
  constructor(
    private readonly client: DynamoDBClient,
    private readonly tableName: string,
    private readonly clock: () => Date = () => new Date()
  ) {}

  async get(
    executionId: string,
    requestDigest: Sha256Digest
  ): Promise<AuditCallbackOutputV1 | null> {
    const response = await this.client.send(
      new GetItemCommand({
        TableName: this.tableName,
        Key: {
          pk: { S: `AUDIT#${executionId}` },
          sk: { S: "RESULT" },
        },
        ConsistentRead: true,
      })
    );
    if (!response.Item) return null;
    if (stringAttribute(response.Item, "requestDigest") !== requestDigest) {
      throw new WorkerContractError(
        "INVALID_EVIDENCE",
        "Audit execution id is already bound to a different request."
      );
    }
    const output = auditOutput(stringAttribute(response.Item, "output"));
    if (!output) {
      throw new WorkerContractError(
        "INVALID_EVIDENCE",
        "Durable audit result is malformed."
      );
    }
    return output;
  }

  async put(
    executionId: string,
    requestDigest: Sha256Digest,
    output: AuditCallbackOutputV1
  ): Promise<AuditCallbackOutputV1> {
    const now = this.clock();
    try {
      await this.client.send(
        new PutItemCommand({
          TableName: this.tableName,
          Item: {
            pk: { S: `AUDIT#${executionId}` },
            sk: { S: "RESULT" },
            requestDigest: { S: requestDigest },
            output: { S: canonicalize(output) },
            evidenceDigest: { S: output.evidenceDigest },
            createdAt: { S: now.toISOString() },
            expiresAt: {
              N: String(Math.floor(now.getTime() / 1000) + JOURNAL_TTL_SECONDS),
            },
          },
          ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
        })
      );
      return output;
    } catch (error) {
      if (!isConditionalFailure(error)) throw error;
    }
    const existing = await this.get(executionId, requestDigest);
    if (!existing) {
      throw new WorkerContractError(
        "INVALID_EVIDENCE",
        "Audit checkpoint conflict did not resolve to a durable result."
      );
    }
    return existing;
  }
}

export class DynamoExecutionJournal implements ExecutionJournal {
  constructor(
    private readonly client: DynamoDBClient,
    private readonly tableName: string,
    private readonly clock: () => Date = () => new Date()
  ) {}

  async claim(input: {
    approvalId: string;
    approvalDecisionDigest: Sha256Digest;
    idempotencyKey: string;
  }): Promise<ExecutionClaim> {
    const executionKey = {
      pk: { S: `EXECUTION#${input.idempotencyKey}` },
      sk: { S: "STATE" },
    };
    const approvalKey = {
      pk: { S: `APPROVAL_EXECUTION#${input.approvalId}` },
      sk: { S: "STATE" },
    };
    const now = this.clock();
    const nowEpoch = Math.floor(now.getTime() / 1000);
    const expiresAt = nowEpoch + JOURNAL_TTL_SECONDS;
    const leaseExpiresAt = nowEpoch + EXECUTION_LEASE_SECONDS;
    let unclassifiedCancellation: unknown;
    try {
      await this.client.send(
        new TransactWriteItemsCommand({
          TransactItems: [
            {
              Put: {
                TableName: this.tableName,
                Item: {
                  ...executionKey,
                  status: { S: "IN_PROGRESS" },
                  approvalId: { S: input.approvalId },
                  decisionDigest: { S: input.approvalDecisionDigest },
                  createdAt: { S: now.toISOString() },
                  fencingToken: { N: "1" },
                  leaseExpiresAt: { N: String(leaseExpiresAt) },
                  attemptCount: { N: "1" },
                  expiresAt: { N: String(expiresAt) },
                },
                ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
              },
            },
            {
              Put: {
                TableName: this.tableName,
                Item: {
                  ...approvalKey,
                  idempotencyKey: { S: input.idempotencyKey },
                  decisionDigest: { S: input.approvalDecisionDigest },
                  expiresAt: { N: String(expiresAt) },
                },
                ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
              },
            },
          ],
        })
      );
      return { disposition: "CLAIMED", fencingToken: 1 };
    } catch (error) {
      if (!isConditionalFailure(error)) {
        if (!isTransactionCancellationWithoutReasons(error)) throw error;
        unclassifiedCancellation = error;
      }
    }

    const [execution, approval] = await Promise.all([
      this.client.send(
        new GetItemCommand({
          TableName: this.tableName,
          Key: executionKey,
          ConsistentRead: true,
        })
      ),
      this.client.send(
        new GetItemCommand({
          TableName: this.tableName,
          Key: approvalKey,
          ConsistentRead: true,
        })
      ),
    ]);
    if (
      unclassifiedCancellation !== undefined &&
      !execution.Item &&
      !approval.Item
    ) {
      throw new RetryableExecutionJournalError(unclassifiedCancellation);
    }
    const sameBinding =
      stringAttribute(execution.Item, "approvalId") === input.approvalId &&
      stringAttribute(execution.Item, "decisionDigest") === input.approvalDecisionDigest &&
      stringAttribute(approval.Item, "idempotencyKey") === input.idempotencyKey &&
      stringAttribute(approval.Item, "decisionDigest") === input.approvalDecisionDigest;
    if (!sameBinding) return { disposition: "APPROVAL_ALREADY_USED" };
    const status = stringAttribute(execution.Item, "status");
    if (status === "IN_PROGRESS" || status === "RECONCILING") {
      const currentLease = numberAttribute(execution.Item, "leaseExpiresAt");
      const currentFencingToken = numberAttribute(execution.Item, "fencingToken");
      if (
        currentLease === undefined ||
        currentFencingToken === undefined ||
        !Number.isSafeInteger(currentFencingToken) ||
        currentFencingToken < 1 ||
        currentFencingToken >= Number.MAX_SAFE_INTEGER
      ) {
        throw new WorkerContractError(
          "INVALID_EVIDENCE",
          "Execution journal has no valid bounded, fenced lease."
        );
      }
      if (currentLease > nowEpoch) return { disposition: "IN_PROGRESS" };
      const nextFencingToken = currentFencingToken + 1;
      try {
        await this.client.send(
          new UpdateItemCommand({
            TableName: this.tableName,
            Key: executionKey,
            ConditionExpression:
              "#status = :currentStatus AND leaseExpiresAt = :currentLease AND fencingToken = :currentFencingToken",
            UpdateExpression:
              "SET #status = :reconciling, leaseExpiresAt = :newLease, " +
              "fencingToken = :nextFencingToken, reconciliationStartedAt = :now, " +
              "recoveryCount = if_not_exists(recoveryCount, :zero) + :one",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: {
              ":currentStatus": { S: status },
              ":currentLease": { N: String(currentLease) },
              ":currentFencingToken": { N: String(currentFencingToken) },
              ":nextFencingToken": { N: String(nextFencingToken) },
              ":reconciling": { S: "RECONCILING" },
              ":newLease": { N: String(leaseExpiresAt) },
              ":now": { S: now.toISOString() },
              ":zero": { N: "0" },
              ":one": { N: "1" },
            },
          })
        );
        return {
          disposition: "RECONCILE",
          fencingToken: nextFencingToken,
        };
      } catch (error) {
        if (isConditionalFailure(error)) return { disposition: "IN_PROGRESS" };
        throw error;
      }
    }
    if (status !== "COMPLETED") {
      return { disposition: "APPROVAL_ALREADY_USED" };
    }
    const receiptJson = stringAttribute(execution.Item, "receipt");
    if (!receiptJson) return { disposition: "APPROVAL_ALREADY_USED" };
    let receipt: ExecutionReceiptV1;
    try {
      receipt = JSON.parse(receiptJson) as ExecutionReceiptV1;
    } catch {
      return { disposition: "APPROVAL_ALREADY_USED" };
    }
    if (!verifyExecutionReceipt(receipt).valid) {
      return { disposition: "APPROVAL_ALREADY_USED" };
    }
    if (
      receipt.idempotencyKey !== input.idempotencyKey ||
      receipt.approvalDecisionDigest !== input.approvalDecisionDigest
    ) {
      throw new WorkerContractError(
        "INVALID_EVIDENCE",
        "Completed journal receipt does not match its immutable execution binding."
      );
    }
    return { disposition: "COMPLETED", receipt };
  }

  async resume(lease: {
    idempotencyKey: string;
    fencingToken: number;
  }): Promise<boolean> {
    const now = this.clock();
    const nowEpoch = Math.floor(now.getTime() / 1000);
    try {
      await this.client.send(
        new UpdateItemCommand({
          TableName: this.tableName,
          Key: {
            pk: { S: `EXECUTION#${lease.idempotencyKey}` },
            sk: { S: "STATE" },
          },
          ConditionExpression:
            "#status = :reconciling AND leaseExpiresAt >= :nowEpoch AND fencingToken = :fencingToken",
          UpdateExpression:
            "SET #status = :inProgress, leaseExpiresAt = :newLease, resumedAt = :now, " +
            "attemptCount = if_not_exists(attemptCount, :zero) + :one",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":reconciling": { S: "RECONCILING" },
            ":inProgress": { S: "IN_PROGRESS" },
            ":fencingToken": { N: String(lease.fencingToken) },
            ":nowEpoch": { N: String(nowEpoch) },
            ":newLease": { N: String(nowEpoch + EXECUTION_LEASE_SECONDS) },
            ":now": { S: now.toISOString() },
            ":zero": { N: "0" },
            ":one": { N: "1" },
          },
        })
      );
      return true;
    } catch (error) {
      if (isConditionalFailure(error)) return false;
      throw error;
    }
  }

  async complete(
    lease: { idempotencyKey: string; fencingToken: number },
    receipt: ExecutionReceiptV1
  ): Promise<void> {
    if (!verifyExecutionReceipt(receipt).valid) {
      throw new WorkerContractError("INVALID_EVIDENCE", "Journal rejected an invalid receipt.");
    }
    if (receipt.idempotencyKey !== lease.idempotencyKey) {
      throw new WorkerContractError(
        "INVALID_EVIDENCE",
        "Receipt idempotency key does not match the claimed execution."
      );
    }
    const approvalDecisionDigest = receipt.approvalDecisionDigest;
    if (!approvalDecisionDigest) {
      throw new WorkerContractError(
        "INVALID_EVIDENCE",
        "Journal receipt has no approval decision binding."
      );
    }
    const receiptJson = canonicalize(receipt);
    if (Buffer.byteLength(receiptJson, "utf8") > 300 * 1024) {
      throw new WorkerContractError("INVALID_EVIDENCE", "Receipt exceeds the journal limit.");
    }
    try {
      await this.client.send(
        new UpdateItemCommand({
          TableName: this.tableName,
          Key: {
            pk: { S: `EXECUTION#${lease.idempotencyKey}` },
            sk: { S: "STATE" },
          },
          ConditionExpression:
            "(#status = :inProgress OR #status = :reconciling) AND " +
            "fencingToken = :fencingToken AND decisionDigest = :decisionDigest",
          UpdateExpression:
            "SET #status = :completed, receiptDigest = :receiptDigest, receipt = :receipt, completedAt = :completedAt REMOVE leaseExpiresAt",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":inProgress": { S: "IN_PROGRESS" },
            ":reconciling": { S: "RECONCILING" },
            ":completed": { S: "COMPLETED" },
            ":fencingToken": { N: String(lease.fencingToken) },
            ":decisionDigest": { S: approvalDecisionDigest },
            ":receiptDigest": { S: receipt.digest },
            ":receipt": { S: receiptJson },
            ":completedAt": { S: receipt.completedAt },
          },
        })
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw new RemediationError(
          "EXECUTION_IN_PROGRESS",
          "A newer worker owns this execution lease."
        );
      }
      throw error;
    }
  }
}

export class StepFunctionsCallbacks {
  constructor(private readonly client: SFNClient) {}

  async success(taskToken: string, output: unknown): Promise<void> {
    await this.client.send(
      new SendTaskSuccessCommand({
        taskToken,
        output: canonicalize(output),
      })
    );
  }

  async failure(taskToken: string, code: string): Promise<void> {
    await this.client.send(
      new SendTaskFailureCommand({
        taskToken,
        error: "ArchonWorkerFailure",
        cause: canonicalize({ code: code.slice(0, 128) }),
      })
    );
  }

  async heartbeat(taskToken: string): Promise<void> {
    await this.client.send(new SendTaskHeartbeatCommand({ taskToken }));
  }
}

type CallbackWorkerKind = Exclude<AsyncMessageKind, "approval">;

const CALLBACK_VISIBILITY_SECONDS = 300;
const CALLBACK_RETRY_VISIBILITY_SECONDS = 5;
const EXECUTION_IN_PROGRESS_RETRY_VISIBILITY_SECONDS = 180;

export function retryVisibilitySeconds(error: unknown): number {
  return error instanceof RemediationError &&
    error.code === "EXECUTION_IN_PROGRESS"
    ? EXECUTION_IN_PROGRESS_RETRY_VISIBILITY_SECONDS
    : CALLBACK_RETRY_VISIBILITY_SECONDS;
}

export function shouldFinalizePoisonDelivery(
  error: unknown,
  receiveCount: number,
  maxReceiveCount: number
): boolean {
  if (
    error instanceof RemediationError &&
    error.code === "EXECUTION_IN_PROGRESS"
  ) {
    return false;
  }
  return !isRetryableError(error) || receiveCount >= maxReceiveCount;
}

interface AwsQueueWorkerBaseOptions {
  queueUrl: string;
  quarantineQueueUrl: string;
  sqs?: SQSClient;
  callbacks?: StepFunctionsCallbacks;
  signal?: AbortSignal;
  maxReceiveCount?: number;
  clock?: () => string;
}

export type AwsQueueWorkerOptions = AwsQueueWorkerBaseOptions &
  (
    | {
        kind: "audit";
        service: AuditWorkerService;
      }
    | {
        kind: "remediation";
        service: RemediationWorkerService;
      }
  );

class CallbackLease implements ExecutionLease {
  #lost?: WorkerLeaseError;
  #renewal?: Promise<void>;
  #timer?: NodeJS.Timeout;
  readonly #abort = new AbortController();

  constructor(
    private readonly callbacks: StepFunctionsCallbacks,
    private readonly sqs: SQSClient,
    private readonly taskToken: string,
    private readonly queueUrl: string,
    private readonly receiptHandle: string,
    private readonly onRenewalFailure: (error: unknown) => void
  ) {}

  get signal(): AbortSignal {
    return this.#abort.signal;
  }

  async assertActive(): Promise<void> {
    if (this.#lost) throw this.#lost;
    this.#renewal ??= this.renew().finally(() => {
      this.#renewal = undefined;
    });
    try {
      await this.#renewal;
    } catch (error) {
      const lost =
        error instanceof WorkerLeaseError
          ? error
          : new WorkerLeaseError(false);
      this.#lost = lost;
      this.#abort.abort(lost);
      throw lost;
    }
    if (this.#lost) throw this.#lost;
  }

  start(): void {
    this.#timer = setInterval(() => {
      void this.assertActive().catch((error) => {
        this.onRenewalFailure(error);
      });
    }, 60_000);
    this.#timer.unref();
  }

  stop(): void {
    if (this.#timer) clearInterval(this.#timer);
  }

  private async renew(): Promise<void> {
    try {
      await this.callbacks.heartbeat(this.taskToken);
    } catch (error) {
      throw new WorkerLeaseError(isTerminalTaskError(error));
    }
    try {
      await this.sqs.send(
        new ChangeMessageVisibilityCommand({
          QueueUrl: this.queueUrl,
          ReceiptHandle: this.receiptHandle,
          VisibilityTimeout: CALLBACK_VISIBILITY_SECONDS,
        })
      );
    } catch {
      throw new WorkerLeaseError(false);
    }
  }
}

export class AwsQueueWorker {
  readonly #sqs: SQSClient;
  readonly #callbacks: StepFunctionsCallbacks;
  readonly #maxReceiveCount: number;
  readonly #clock: () => string;

  constructor(private readonly options: AwsQueueWorkerOptions) {
    this.#sqs = options.sqs ?? new SQSClient({});
    this.#callbacks = options.callbacks ?? new StepFunctionsCallbacks(new SFNClient({}));
    this.#maxReceiveCount = options.maxReceiveCount ?? 5;
    this.#clock = options.clock ?? (() => new Date().toISOString());
  }

  async run(): Promise<void> {
    while (!this.options.signal?.aborted) {
      let response: ReceiveMessageCommandOutput;
      try {
        response = await this.#sqs.send(
          new ReceiveMessageCommand({
            QueueUrl: this.options.queueUrl,
            MaxNumberOfMessages: 1,
            WaitTimeSeconds: 20,
            VisibilityTimeout: CALLBACK_VISIBILITY_SECONDS,
            MessageSystemAttributeNames: ["ApproximateReceiveCount"],
          }),
          { abortSignal: this.options.signal }
        );
      } catch (error) {
        if (this.options.signal?.aborted) return;
        throw error;
      }
      for (const message of response.Messages ?? []) {
        await this.process(message);
      }
    }
  }

  private async process(received: Message): Promise<void> {
    if (!received.Body || !received.ReceiptHandle) return;
    const receiveCount = Math.max(
      1,
      Number.parseInt(received.Attributes?.ApproximateReceiveCount ?? "1", 10) || 1
    );
    let message: AuditQueueMessageV1 | RemediationQueueMessageV1;
    try {
      const parsed = parseQueueMessage(this.options.kind, received.Body);
      if (
        (this.options.kind === "audit" && parsed.type !== "AUDIT_REQUESTED") ||
        (this.options.kind === "remediation" &&
          parsed.type !== "REMEDIATION_REQUESTED")
      ) {
        throw new WorkerContractError(
          "INVALID_MESSAGE",
          "Queue and callback-worker capability do not match."
        );
      }
      if (
        parsed.type !== "AUDIT_REQUESTED" &&
        parsed.type !== "REMEDIATION_REQUESTED"
      ) {
        throw new WorkerContractError(
          "INVALID_MESSAGE",
          "Callback workers cannot consume approval messages."
        );
      }
      message = parsed;
    } catch (error) {
      this.log("message_rejected", received.MessageId, undefined, error, receiveCount);
      await this.finalizePoison({
        received,
        receiveCount,
        error,
        taskToken: recoverTaskToken(received.Body),
      });
      return;
    }

    let output: unknown;
    try {
      output = await this.withLease(
        message.taskToken,
        received.ReceiptHandle,
        async (lease) => {
          if (message.type === "AUDIT_REQUESTED" && this.options.kind === "audit") {
            return (this.options.service as AuditWorkerService).audit(message);
          }
          if (
            message.type === "REMEDIATION_REQUESTED" &&
            this.options.kind === "remediation"
          ) {
            return (this.options.service as RemediationWorkerService).remediate(
              message,
              lease
            );
          }
          throw new WorkerContractError(
            "INVALID_MESSAGE",
            "Queue and callback-worker capability do not match."
          );
        }
      );
    } catch (error) {
      this.log("message_failed", received.MessageId, message.type, error, receiveCount);
      if (error instanceof WorkerLeaseError) {
        if (error.terminal) {
          await this.delete(received.ReceiptHandle).catch((deleteError) => {
            this.log(
              "terminal_message_delete_failed",
              received.MessageId,
              message.type,
              deleteError,
              receiveCount
            );
          });
        } else {
          await this.retrySoon(
            received.ReceiptHandle,
            received.MessageId,
            message.type
          );
        }
        return;
      }
      if (!shouldFinalizePoisonDelivery(error, receiveCount, this.#maxReceiveCount)) {
        await this.retrySoon(
          received.ReceiptHandle,
          received.MessageId,
          message.type,
          retryVisibilitySeconds(error)
        );
        return;
      }
      await this.finalizePoison({
        received,
        receiveCount,
        error,
        taskToken: message.taskToken,
        type: message.type,
      });
      return;
    }

    try {
      await this.#callbacks.success(message.taskToken, output);
      await this.delete(received.ReceiptHandle);
      this.log("message_completed", received.MessageId, message.type, undefined, receiveCount);
    } catch (error) {
      if (isTerminalTaskError(error)) {
        await this.delete(received.ReceiptHandle).catch((deleteError) => {
          this.log(
            "terminal_message_delete_failed",
            received.MessageId,
            message.type,
            deleteError,
            receiveCount
          );
        });
        return;
      }
      // The operation is already durable. A transient callback failure is retried
      // through the idempotent audit checkpoint or remediation execution journal.
      this.log(
        "success_callback_failed",
        received.MessageId,
        message.type,
        error,
        receiveCount
      );
      await this.retrySoon(
        received.ReceiptHandle,
        received.MessageId,
        message.type
      );
    }
  }

  private async withLease<T>(
    taskToken: string,
    receiptHandle: string,
    operation: (lease: ExecutionLease) => Promise<T>
  ): Promise<T> {
    const lease = new CallbackLease(
      this.#callbacks,
      this.#sqs,
      taskToken,
      this.options.queueUrl,
      receiptHandle,
      (error) => this.log("lease_renewal_failed", undefined, undefined, error)
    );
    await lease.assertActive();
    lease.start();
    try {
      const output = await operation(lease);
      await lease.assertActive();
      return output;
    } finally {
      lease.stop();
    }
  }

  private async finalizePoison(input: {
    received: Message;
    receiveCount: number;
    error: unknown;
    taskToken?: string;
    type?: WorkerQueueMessage["type"];
  }): Promise<void> {
    if (!input.received.ReceiptHandle || !input.received.Body) return;
    try {
      await this.#sqs.send(
        new SendMessageCommand({
          QueueUrl: this.options.quarantineQueueUrl,
          MessageBody: canonicalize({
            schemaVersion: "archon.worker-quarantine/v1",
            queueKind: this.options.kind,
            messageId: input.received.MessageId ?? "unknown",
            bodyDigest: `sha256:${createHash("sha256")
              .update(input.received.Body, "utf8")
              .digest("hex")}`,
            error: awsErrorName(input.error),
            receiveCount: input.receiveCount,
            failedAt: this.#clock(),
          }),
        })
      );
    } catch (error) {
      this.log(
        "quarantine_write_failed",
        input.received.MessageId,
        input.type,
        error,
        input.receiveCount
      );
      await this.retrySoon(
        input.received.ReceiptHandle,
        input.received.MessageId,
        input.type
      );
      return;
    }

    if (input.taskToken) {
      try {
        await this.#callbacks.failure(input.taskToken, awsErrorName(input.error));
      } catch (error) {
        if (!isTerminalTaskError(error)) {
          this.log(
            "failure_callback_failed",
            input.received.MessageId,
            input.type,
            error,
            input.receiveCount
          );
          await this.retrySoon(
            input.received.ReceiptHandle,
            input.received.MessageId,
            input.type
          );
          return;
        }
      }
    }
    await this.delete(input.received.ReceiptHandle).catch((error) => {
      this.log(
        "poison_message_delete_failed",
        input.received.MessageId,
        input.type,
        error,
        input.receiveCount
      );
    });
  }

  private async delete(receiptHandle: string): Promise<void> {
    await this.#sqs.send(
      new DeleteMessageCommand({
        QueueUrl: this.options.queueUrl,
        ReceiptHandle: receiptHandle,
      })
    );
  }

  private async retrySoon(
    receiptHandle: string,
    messageId?: string,
    type?: WorkerQueueMessage["type"],
    visibilitySeconds = CALLBACK_RETRY_VISIBILITY_SECONDS
  ): Promise<void> {
    await this.#sqs
      .send(
        new ChangeMessageVisibilityCommand({
          QueueUrl: this.options.queueUrl,
          ReceiptHandle: receiptHandle,
          VisibilityTimeout: visibilitySeconds,
        })
      )
      .catch((error) => {
        this.log("retry_visibility_change_failed", messageId, type, error);
      });
  }

  private log(
    event: string,
    messageId?: string,
    type?: WorkerQueueMessage["type"],
    error?: unknown,
    receiveCount?: number
  ): void {
    console.log(
      canonicalize({
        event,
        queueKind: this.options.kind,
        ...(messageId ? { messageId } : {}),
        ...(type ? { type } : {}),
        ...(error ? { error: awsErrorName(error) } : {}),
        ...(receiveCount === undefined ? {} : { receiveCount }),
      })
    );
  }
}

function recoverTaskToken(body: string): string | undefined {
  try {
    const parsed = JSON.parse(body) as { taskToken?: unknown };
    return typeof parsed?.taskToken === "string" &&
      parsed.taskToken.length >= 16 &&
      parsed.taskToken.length <= 1024
      ? parsed.taskToken
      : undefined;
  } catch {
    return undefined;
  }
}
