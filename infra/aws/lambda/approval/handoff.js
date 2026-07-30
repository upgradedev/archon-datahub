"use strict";

const { createHash } = require("node:crypto");
const {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand
} = require("@aws-sdk/client-dynamodb");
const { SFNClient, SendTaskFailureCommand } = require("@aws-sdk/client-sfn");

const dynamodb = new DynamoDBClient({});
const stepFunctions = new SFNClient({});
const tableName = process.env.APPROVAL_TABLE;
const MAX_BODY_BYTES = 128 * 1024;
const RETENTION_SECONDS = 90 * 24 * 60 * 60;
const ID = /^[A-Za-z0-9._:-]{8,160}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const EXECUTION =
  /^arn:(?:aws|aws-us-gov|aws-cn):states:[a-z0-9-]+:\d{12}:execution:[A-Za-z0-9-_]+:[A-Za-z0-9-_]+$/;

class TerminalHandoffError extends Error {
  constructor(code) {
    super(code);
    this.name = "TerminalHandoffError";
    this.code = code;
  }
}

function terminal(code) {
  throw new TerminalHandoffError(code);
}

function exactObject(value, allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    terminal("INVALID_MESSAGE");
  }
  const keys = Object.keys(value);
  if (
    keys.length !== allowed.length ||
    keys.some((key) => !allowed.includes(key))
  ) {
    terminal("INVALID_MESSAGE");
  }
  return value;
}

function strictString(value, pattern, minLength, maxLength) {
  if (
    typeof value !== "string" ||
    value.length < minLength ||
    value.length > maxLength ||
    !pattern.test(value)
  ) {
    terminal("INVALID_MESSAGE");
  }
  return value;
}

function instant(value) {
  if (
    typeof value !== "string" ||
    value.length < 20 ||
    value.length > 40 ||
    !Number.isFinite(Date.parse(value))
  ) {
    terminal("INVALID_MESSAGE");
  }
  return value;
}

function parse(body) {
  if (
    typeof body !== "string" ||
    Buffer.byteLength(body, "utf8") > MAX_BODY_BYTES
  ) {
    terminal("BODY_TOO_LARGE");
  }
  let value;
  try {
    value = JSON.parse(body);
  } catch {
    terminal("INVALID_JSON");
  }
  const input = exactObject(value, [
    "type",
    "taskToken",
    "executionId",
    "approvalId",
    "planDigest",
    "evidenceDigest",
    "approvalRequestDigest",
    "requestedAt",
    "expiresAt"
  ]);
  if (input.type !== "APPROVAL_REQUESTED") terminal("QUEUE_CONFUSION");
  const requestedAt = instant(input.requestedAt);
  const expiresAt = instant(input.expiresAt);
  const requestedEpoch = Math.floor(Date.parse(requestedAt) / 1000);
  const expiresEpoch = Math.floor(Date.parse(expiresAt) / 1000);
  const nowEpoch = Math.floor(Date.now() / 1000);
  if (
    expiresEpoch <= nowEpoch ||
    expiresEpoch <= requestedEpoch ||
    expiresEpoch - requestedEpoch > 7 * 24 * 60 * 60
  ) {
    terminal("INVALID_APPROVAL_WINDOW");
  }
  return {
    type: "APPROVAL_REQUESTED",
    taskToken: strictString(input.taskToken, /^[^\u0000-\u001f\u007f]+$/, 16, 1024),
    executionId: strictString(input.executionId, EXECUTION, 32, 2048),
    approvalId: strictString(input.approvalId, ID, 8, 160),
    planDigest: strictString(input.planDigest, DIGEST, 71, 71),
    evidenceDigest: strictString(input.evidenceDigest, DIGEST, 71, 71),
    approvalRequestDigest: strictString(
      input.approvalRequestDigest,
      DIGEST,
      71,
      71
    ),
    requestedAt,
    expiresAt,
    expiresEpoch
  };
}

function stringAttribute(item, name) {
  return item?.[name]?.S;
}

async function persist(message) {
  const key = {
    pk: { S: `APPROVAL#${message.approvalId}` },
    sk: { S: "STATE" }
  };
  try {
    await dynamodb.send(
      new PutItemCommand({
        TableName: tableName,
        Item: {
          ...key,
          status: { S: "PENDING" },
          taskToken: { S: message.taskToken },
          executionId: { S: message.executionId },
          evidenceDigest: { S: message.evidenceDigest },
          planDigest: { S: message.planDigest },
          requestDigest: { S: message.approvalRequestDigest },
          requestedAt: { S: message.requestedAt },
          createdAt: { S: new Date().toISOString() },
          approvalExpiresAt: { S: message.expiresAt },
          expiresAt: { N: String(message.expiresEpoch) },
          callbackDelivered: { BOOL: false }
        },
        ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)"
      })
    );
    return;
  } catch (error) {
    if (error?.name !== "ConditionalCheckFailedException") throw error;
  }

  const current = (
    await dynamodb.send(
      new GetItemCommand({
        TableName: tableName,
        Key: key,
        ConsistentRead: true
      })
    )
  ).Item;
  const status = stringAttribute(current, "status");
  const sameBinding =
    stringAttribute(current, "executionId") === message.executionId &&
    stringAttribute(current, "evidenceDigest") === message.evidenceDigest &&
    stringAttribute(current, "planDigest") === message.planDigest &&
    stringAttribute(current, "requestDigest") === message.approvalRequestDigest &&
    stringAttribute(current, "requestedAt") === message.requestedAt &&
    stringAttribute(current, "approvalExpiresAt") === message.expiresAt;
  if (
    sameBinding &&
    ((status === "PENDING" &&
      stringAttribute(current, "taskToken") === message.taskToken) ||
      status === "DECIDED")
  ) {
    return;
  }
  terminal("IMMUTABLE_BINDING_CONFLICT");
}

async function recordPoison(record, error) {
  const body = typeof record.body === "string" ? record.body : "";
  const now = new Date();
  try {
    await dynamodb.send(
      new PutItemCommand({
        TableName: tableName,
        Item: {
          pk: { S: `HANDOFF_FAILURE#${record.messageId}` },
          sk: { S: "STATE" },
          status: { S: "QUARANTINED" },
          bodyDigest: {
            S: `sha256:${createHash("sha256").update(body, "utf8").digest("hex")}`
          },
          failureCode: {
            S: error instanceof TerminalHandoffError
              ? error.code
              : "TRANSIENT_EXHAUSTION_PENDING"
          },
          createdAt: { S: now.toISOString() },
          expiresAt: {
            N: String(Math.floor(now.getTime() / 1000) + RETENTION_SECONDS)
          }
        },
        ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)"
      })
    );
  } catch (writeError) {
    if (writeError?.name !== "ConditionalCheckFailedException") throw writeError;
  }
}

function recoverTaskToken(body) {
  try {
    const value = JSON.parse(body);
    return typeof value?.taskToken === "string" &&
      value.taskToken.length >= 16 &&
      value.taskToken.length <= 1024
      ? value.taskToken
      : undefined;
  } catch {
    return undefined;
  }
}

async function failCallback(taskToken, code) {
  if (!taskToken) return;
  try {
    await stepFunctions.send(
      new SendTaskFailureCommand({
        taskToken,
        error: "ArchonApprovalHandoffRejected",
        cause: JSON.stringify({ code })
      })
    );
  } catch (error) {
    if (!["TaskDoesNotExist", "TaskTimedOut", "InvalidToken"].includes(error?.name)) {
      throw error;
    }
  }
}

exports.handler = async (event) => {
  const failures = [];
  for (const record of event?.Records || []) {
    try {
      const message = parse(record.body);
      await persist(message);
    } catch (error) {
      if (error instanceof TerminalHandoffError) {
        await recordPoison(record, error);
        await failCallback(recoverTaskToken(record.body), error.code);
        continue;
      }
      failures.push({ itemIdentifier: record.messageId });
    }
  }
  return { batchItemFailures: failures };
};
