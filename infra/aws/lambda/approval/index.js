"use strict";

const { createHash } = require("node:crypto");
const {
  DynamoDBClient,
  GetItemCommand,
  UpdateItemCommand
} = require("@aws-sdk/client-dynamodb");
const { SFNClient, SendTaskSuccessCommand } = require("@aws-sdk/client-sfn");

const dynamodb = new DynamoDBClient({});
const stepFunctions = new SFNClient({});
const tableName = process.env.APPROVAL_TABLE;
const approverGroup = process.env.APPROVER_GROUP || "archon-approvers";
const DECIDED_RETENTION_SECONDS = 90 * 24 * 60 * 60;

function response(statusCode, body) {
  return {
    statusCode,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff"
    },
    body: `${JSON.stringify(body)}\n`
  };
}

function groupsFrom(claim) {
  if (Array.isArray(claim)) return claim.map(String);
  if (typeof claim !== "string") return [];
  return claim
    .replace(/[\[\]"]/g, "")
    .split(/[,\s]+/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function canonicalDigest(value) {
  return `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

function parseRequest(event) {
  const approvalId = event.pathParameters?.approvalId;
  if (
    typeof approvalId !== "string" ||
    !/^[A-Za-z0-9._:-]{8,160}$/.test(approvalId)
  ) {
    return { error: response(400, { error: "invalid_approval_id" }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { error: response(400, { error: "invalid_json" }) };
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { error: response(400, { error: "invalid_body" }) };
  }
  if (Object.keys(body).some((key) => key !== "comment" && key !== "decision")) {
    return { error: response(400, { error: "unexpected_field" }) };
  }
  if (body.decision !== "APPROVE" && body.decision !== "REJECT") {
    return { error: response(400, { error: "invalid_decision" }) };
  }
  if (
    body.comment !== undefined &&
    (typeof body.comment !== "string" ||
      body.comment.length > 1000 ||
      /[\u0000\u007f]/u.test(body.comment))
  ) {
    return { error: response(400, { error: "invalid_comment" }) };
  }

  const claims = event.requestContext?.authorizer?.claims || {};
  const subject = claims.sub;
  const issuer = claims.iss;
  if (typeof subject !== "string" || subject.length < 1) {
    return { error: response(401, { error: "missing_identity" }) };
  }
  if (typeof issuer !== "string" || !issuer.startsWith("https://")) {
    return { error: response(401, { error: "missing_issuer" }) };
  }
  if (!groupsFrom(claims["cognito:groups"]).includes(approverGroup)) {
    return { error: response(403, { error: "approver_role_required" }) };
  }
  return {
    approvalId,
    decision: body.decision,
    comment: body.comment || "",
    subject,
    issuer,
    email: typeof claims.email === "string" ? claims.email : ""
  };
}

async function readApproval(approvalId) {
  return dynamodb.send(
    new GetItemCommand({
      TableName: tableName,
      ConsistentRead: true,
      Key: {
        pk: { S: `APPROVAL#${approvalId}` },
        sk: { S: "STATE" }
      }
    })
  );
}

exports.handler = async (event) => {
  const parsed = parseRequest(event);
  if (parsed.error) return parsed.error;

  const now = new Date().toISOString();
  const nowEpoch = Math.floor(Date.now() / 1000);
  const decisionRecord = {
    approvalId: parsed.approvalId,
    decision: parsed.decision,
    comment: parsed.comment,
    approverSub: parsed.subject,
    approverIssuer: parsed.issuer
  };
  const decisionDigest = canonicalDigest(decisionRecord);
  let current = (await readApproval(parsed.approvalId)).Item;
  if (!current) return response(404, { error: "approval_not_found" });
  const approvalExpiresAt = current.approvalExpiresAt?.S;
  const approvalExpiresEpoch =
    typeof approvalExpiresAt === "string" &&
    Number.isFinite(Date.parse(approvalExpiresAt))
      ? Math.floor(Date.parse(approvalExpiresAt) / 1000)
      : NaN;
  if (!Number.isFinite(approvalExpiresEpoch)) {
    throw new Error("approval has no immutable deadline");
  }
  if (
    current.status?.S === "PENDING" &&
    approvalExpiresEpoch <= nowEpoch
  ) {
    return response(410, { error: "approval_expired" });
  }
  const decisionEvidence = {
    schemaVersion: "archon.approval-decision/v1",
    approvalId: parsed.approvalId,
    executionId: current.executionId?.S || "",
    evidenceDigest: current.evidenceDigest?.S || "",
    planDigest: current.planDigest?.S || "",
    requestDigest: current.requestDigest?.S || "",
    decision: parsed.decision,
    approver: {
      subject: parsed.subject,
      issuer: parsed.issuer,
      roles: ["DataSteward"],
      authenticated: true
    },
    commentDigest: canonicalDigest(parsed.comment)
  };
  const decisionEvidenceDigest = canonicalDigest(decisionEvidence);

  if (current.status?.S === "PENDING") {
    try {
      await dynamodb.send(
        new UpdateItemCommand({
          TableName: tableName,
          Key: {
            pk: { S: `APPROVAL#${parsed.approvalId}` },
            sk: { S: "STATE" }
          },
          ConditionExpression: "#status = :pending",
          UpdateExpression:
            "SET #status = :decided, #decision = :decision, #comment = :comment, " +
            "approverSub = :sub, approverIssuer = :issuer, approverEmail = :email, decisionDigest = :digest, " +
            "decisionEvidenceSchema = :evidenceSchema, decisionEvidenceDigest = :evidenceDigest, " +
            "decisionEvidence = :evidence, decidedAt = :now, callbackDelivered = :false, " +
            "expiresAt = :retentionExpiresAt",
          ExpressionAttributeNames: {
            "#status": "status",
            "#decision": "decision",
            "#comment": "comment"
          },
          ExpressionAttributeValues: {
            ":pending": { S: "PENDING" },
            ":decided": { S: "DECIDED" },
            ":decision": { S: parsed.decision },
            ":comment": { S: parsed.comment },
            ":sub": { S: parsed.subject },
            ":issuer": { S: parsed.issuer },
            ":email": { S: parsed.email },
            ":digest": { S: decisionDigest },
            ":evidenceSchema": { S: "archon.approval-decision/v1" },
            ":evidenceDigest": { S: decisionEvidenceDigest },
            ":evidence": { S: JSON.stringify(decisionEvidence) },
            ":now": { S: now },
            ":retentionExpiresAt": {
              N: String(nowEpoch + DECIDED_RETENTION_SECONDS)
            },
            ":false": { BOOL: false }
          }
        })
      );
      current = (await readApproval(parsed.approvalId)).Item;
    } catch (error) {
      if (error?.name !== "ConditionalCheckFailedException") throw error;
      current = (await readApproval(parsed.approvalId)).Item;
    }
  }

  if (
    current?.status?.S !== "DECIDED" ||
    current?.decisionDigest?.S !== decisionDigest ||
    current?.decisionEvidenceDigest?.S !== decisionEvidenceDigest ||
    current?.approverSub?.S !== parsed.subject ||
    current?.approverIssuer?.S !== parsed.issuer
  ) {
    return response(409, { error: "approval_already_decided" });
  }
  if (current.callbackDelivered?.BOOL === true) {
    return response(200, {
      approvalId: parsed.approvalId,
      decision: parsed.decision,
      status: "recorded",
      decisionId: decisionDigest,
      disposition: "already_recorded"
    });
  }
  if (current.callbackClosed?.BOOL === true) {
    return response(202, {
      approvalId: parsed.approvalId,
      decision: parsed.decision,
      status: "recorded",
      decisionId: decisionDigest,
      disposition: "recorded_callback_closed"
    });
  }

  const taskToken = current.taskToken?.S;
  if (!taskToken) throw new Error("approval has no server-held callback token");
  const decidedAt = current.decidedAt?.S;
  if (!decidedAt || !Number.isFinite(Date.parse(decidedAt))) {
    throw new Error("approval has no valid server-held decision timestamp");
  }
  const callbackAttemptId = canonicalDigest({
    decisionDigest,
    requestId: event.requestContext?.requestId || "unknown",
    attemptedAt: now
  });
  try {
    await dynamodb.send(
      new UpdateItemCommand({
        TableName: tableName,
        Key: {
          pk: { S: `APPROVAL#${parsed.approvalId}` },
          sk: { S: "STATE" }
        },
        ConditionExpression:
          "decisionDigest = :digest AND callbackDelivered = :false AND " +
          "(attribute_not_exists(callbackLeaseUntil) OR callbackLeaseUntil < :nowEpoch)",
        UpdateExpression:
          "SET callbackState = :delivering, callbackAttemptId = :attemptId, " +
          "callbackAttemptedAt = :now, callbackLeaseUntil = :leaseUntil",
        ExpressionAttributeValues: {
          ":digest": { S: decisionDigest },
          ":false": { BOOL: false },
          ":delivering": { S: "DELIVERING" },
          ":attemptId": { S: callbackAttemptId },
          ":now": { S: now },
          ":nowEpoch": { N: String(nowEpoch) },
          ":leaseUntil": { N: String(nowEpoch + 30) }
        }
      })
    );
  } catch (error) {
    if (error?.name !== "ConditionalCheckFailedException") throw error;
    current = (await readApproval(parsed.approvalId)).Item;
    if (current?.callbackDelivered?.BOOL === true) {
      return response(200, {
        approvalId: parsed.approvalId,
        decision: parsed.decision,
        status: "recorded",
        decisionId: decisionDigest,
        disposition: "already_recorded"
      });
    }
    if (current?.callbackClosed?.BOOL === true) {
      return response(202, {
        approvalId: parsed.approvalId,
        decision: parsed.decision,
        status: "recorded",
        decisionId: decisionDigest,
        disposition: "recorded_callback_closed"
      });
    }
    return response(202, {
      approvalId: parsed.approvalId,
      decision: parsed.decision,
      status: "recorded",
      decisionId: decisionDigest,
      disposition: "callback_delivery_in_progress"
    });
  }

  try {
    await stepFunctions.send(
      new SendTaskSuccessCommand({
        taskToken,
        output: JSON.stringify({
          approvalId: parsed.approvalId,
          decision: {
            decision: parsed.decision,
            approver: {
              subject: parsed.subject,
              issuer: parsed.issuer,
              roles: ["DataSteward"],
              authenticated: true
            },
            decidedAt
          }
        })
      })
    );
  } catch (error) {
    if (!["TaskDoesNotExist", "TaskTimedOut", "InvalidToken"].includes(error?.name)) {
      throw error;
    }
    await dynamodb.send(
      new UpdateItemCommand({
        TableName: tableName,
        Key: {
          pk: { S: `APPROVAL#${parsed.approvalId}` },
          sk: { S: "STATE" }
        },
        ConditionExpression:
          "decisionDigest = :digest AND callbackAttemptId = :attemptId AND callbackDelivered = :false",
        UpdateExpression:
          "SET callbackState = :closed, callbackClosed = :true, callbackClosedAt = :now " +
          "REMOVE taskToken, callbackLeaseUntil",
        ExpressionAttributeValues: {
          ":digest": { S: decisionDigest },
          ":attemptId": { S: callbackAttemptId },
          ":false": { BOOL: false },
          ":closed": { S: "CLOSED" },
          ":true": { BOOL: true },
          ":now": { S: now }
        }
      })
    );
    return response(202, {
      approvalId: parsed.approvalId,
      decision: parsed.decision,
      status: "recorded",
      decisionId: decisionDigest,
      disposition: "recorded_callback_closed"
    });
  }
  await dynamodb.send(
    new UpdateItemCommand({
      TableName: tableName,
      Key: {
        pk: { S: `APPROVAL#${parsed.approvalId}` },
        sk: { S: "STATE" }
      },
      ConditionExpression:
        "decisionDigest = :digest AND callbackAttemptId = :attemptId AND callbackDelivered = :false",
      UpdateExpression:
        "SET callbackState = :delivered, callbackDelivered = :true, callbackDeliveredAt = :now " +
        "REMOVE taskToken, callbackLeaseUntil",
      ExpressionAttributeValues: {
        ":digest": { S: decisionDigest },
        ":attemptId": { S: callbackAttemptId },
        ":false": { BOOL: false },
        ":delivered": { S: "DELIVERED" },
        ":true": { BOOL: true },
        ":now": { S: now }
      }
    })
  );

  return response(200, {
    approvalId: parsed.approvalId,
    decision: parsed.decision,
    status: "recorded",
    decisionId: decisionDigest,
    disposition: "recorded"
  });
};
