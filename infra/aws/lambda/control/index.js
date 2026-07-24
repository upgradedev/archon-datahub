"use strict";

const { createHash, randomBytes } = require("node:crypto");
const {
  DynamoDBClient,
  GetItemCommand
} = require("@aws-sdk/client-dynamodb");
const {
  GetObjectCommand,
  S3Client
} = require("@aws-sdk/client-s3");
const {
  DescribeExecutionCommand,
  SFNClient,
  StartExecutionCommand
} = require("@aws-sdk/client-sfn");

const dynamodb = new DynamoDBClient({});
const s3 = new S3Client({});
const stepFunctions = new SFNClient({});
const stateMachineArn = process.env.STATE_MACHINE_ARN;
const checkpointTable = process.env.CHECKPOINT_TABLE;
const approvalTable = process.env.APPROVAL_TABLE;
const evidenceBucket = process.env.EVIDENCE_BUCKET;

const AUDIT_ID = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const MAX_BODY_BYTES = 4096;
const MAX_EVIDENCE_BYTES = 6 * 1024 * 1024;
const MAX_EXECUTION_OUTPUT_BYTES = 256 * 1024;
const DECIDED_RETENTION_SECONDS = 90 * 24 * 60 * 60;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const VERIFICATION_CHECK_IDS = [
  "TARGET_UNCHANGED",
  "PREEXISTING_TAGS_PRESERVED",
  "POLICY_TAG_PRESENT",
  "NO_UNEXPECTED_TAGS",
  "APPROVAL_BINDING_VALID"
];
const RECEIPT_EVENT_KINDS = [
  "DOSSIER_BOUND",
  "PLAN_BOUND",
  "APPROVAL_BOUND",
  "PRECONDITION_CHECKED",
  "MUTATION_INVOKED",
  "POSTCONDITION_CHECKED",
  "ROLLBACK_ANCHORED"
];

function response(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      "content-type": "application/json; charset=utf-8",
      "cross-origin-resource-policy": "same-origin",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      ...extraHeaders
    },
    payload: body
  };
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, required, optional = []) {
  if (!record(value)) return false;
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return (
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    keys.every((key) => allowed.has(key))
  );
}

function instant(value) {
  return (
    typeof value === "string" &&
    value.length <= 64 &&
    Number.isFinite(Date.parse(value))
  );
}

function boundedString(value, maximum = 2048) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    !/[\u0000-\u001f\u007f]/u.test(value)
  );
}

function without(value, keys) {
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => !keys.includes(key))
  );
}

function sameCanonical(left, right) {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function parseStartBody(input) {
  let body = input;
  let text;
  if (record(input)) {
    text = JSON.stringify(input);
  } else if (typeof input === "string") {
    text = input;
    try {
      body = JSON.parse(text || "{}");
    } catch {
      return { error: response(400, { error: "invalid_json" }) };
    }
  } else {
    return { error: response(400, { error: "invalid_body" }) };
  }
  if (Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES) {
    return { error: response(413, { error: "request_too_large" }) };
  }
  if (!record(body)) {
    return { error: response(400, { error: "invalid_body" }) };
  }
  if (Object.keys(body).some((key) => key !== "query" && key !== "mode")) {
    return { error: response(400, { error: "unexpected_field" }) };
  }
  if (
    body.mode !== undefined &&
    body.mode !== "READ_ONLY" &&
    body.mode !== "GOVERNED"
  ) {
    return { error: response(400, { error: "invalid_mode" }) };
  }
  const mode = body.mode;
  if (body.query === undefined || body.query === null || body.query === "") {
    return { error: response(400, { error: "query_required" }) };
  }
  if (
    typeof body.query !== "string" ||
    body.query.length > 256 ||
    /[\u0000-\u001f\u007f]/u.test(body.query)
  ) {
    return { error: response(400, { error: "invalid_query" }) };
  }
  const query = body.query.trim();
  if (!query || query === "*") {
    return { error: response(400, { error: "query_must_be_narrow" }) };
  }
  return { query, mode };
}

function canonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite JSON number");
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (!record(value)) throw new Error("non-JSON evidence");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
}

function digest(value) {
  return `sha256:${createHash("sha256").update(canonicalize(value), "utf8").digest("hex")}`;
}

function stringAttribute(item, name) {
  const value = item?.[name];
  return value && typeof value.S === "string" ? value.S : undefined;
}

function numberAttribute(item, name) {
  const value = item?.[name];
  if (!value || typeof value.N !== "string") return undefined;
  const parsed = Number(value.N);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

function executionArn(auditId) {
  if (
    typeof stateMachineArn !== "string" ||
    !stateMachineArn.includes(":stateMachine:")
  ) {
    throw new Error("invalid state machine configuration");
  }
  return `${stateMachineArn.replace(":stateMachine:", ":execution:")}:${auditId}`;
}

async function bodyBytes(body) {
  if (!body || typeof body.transformToByteArray !== "function") {
    throw new Error("evidence object has no body");
  }
  const bytes = await body.transformToByteArray();
  if (bytes.byteLength > MAX_EVIDENCE_BYTES) {
    throw new Error("evidence exceeds status projection limit");
  }
  return bytes;
}

async function readEvidenceObject(kind, expectedDigest) {
  if (!DIGEST.test(expectedDigest)) {
    throw new Error("invalid evidence digest");
  }
  const key =
    `v1/${kind}/sha256/` +
    `${expectedDigest.slice("sha256:".length)}.json`;
  const object = await s3.send(
    new GetObjectCommand({
      Bucket: evidenceBucket,
      Key: key,
      ChecksumMode: "ENABLED"
    })
  );
  const text = Buffer.from(await bodyBytes(object.Body)).toString("utf8");
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("evidence is not JSON");
  }
}

function verifyDigestField(value, omitted = ["digest"]) {
  if (!record(value) || !DIGEST.test(value.digest)) return false;
  try {
    return digest(without(value, omitted)) === value.digest;
  } catch {
    return false;
  }
}

function verifyNamedDigest(value, idField, prefix) {
  if (
    !record(value) ||
    !boundedString(value[idField], 160) ||
    !DIGEST.test(value.digest)
  ) {
    return false;
  }
  let expected;
  try {
    expected = digest(without(value, [idField, "digest"]));
  } catch {
    return false;
  }
  return (
    value.digest === expected &&
    value[idField] ===
      `${prefix}${expected.slice(
        "sha256:".length,
        "sha256:".length + 24
      )}`
  );
}

function verifyApprover(value) {
  if (
    !exactKeys(value, ["subject", "issuer", "roles", "authenticated"]) ||
    !boundedString(value.subject, 512) ||
    !boundedString(value.issuer, 2048) ||
    value.authenticated !== true ||
    !Array.isArray(value.roles) ||
    value.roles.length === 0 ||
    value.roles.length > 16 ||
    value.roles.some((role) => !boundedString(role, 128))
  ) {
    return false;
  }
  let issuer;
  try {
    issuer = new URL(value.issuer);
  } catch {
    return false;
  }
  return (
    issuer.protocol === "https:" &&
    issuer.username === "" &&
    issuer.password === "" &&
    value.roles.includes("DataSteward") &&
    sameCanonical(
      value.roles,
      [...new Set(value.roles)].sort((left, right) => left.localeCompare(right))
    )
  );
}

function verifyApprovalDecision(value, expected) {
  return (
    exactKeys(value, [
      "schemaVersion",
      "approvalId",
      "requestDigest",
      "planDigest",
      "decision",
      "approver",
      "decidedAt",
      "digest"
    ]) &&
    value.schemaVersion === "archon.approval-decision/v1" &&
    value.approvalId === expected.approvalId &&
    value.requestDigest === expected.requestDigest &&
    value.planDigest === expected.planDigest &&
    value.decision === expected.decision &&
    instant(value.decidedAt) &&
    value.decidedAt === expected.decidedAt &&
    verifyApprover(value.approver) &&
    sameCanonical(value.approver, expected.approver) &&
    verifyDigestField(value)
  );
}

function verifyTagProjection(value) {
  return (
    exactKeys(value, ["entityUrn", "columnPath", "tags", "digest"]) &&
    boundedString(value.entityUrn, 2048) &&
    boundedString(value.columnPath, 1024) &&
    Array.isArray(value.tags) &&
    value.tags.length <= 256 &&
    value.tags.every((tag) => boundedString(tag, 2048)) &&
    sameCanonical(
      value.tags,
      [...new Set(value.tags)].sort((left, right) => left.localeCompare(right))
    ) &&
    verifyDigestField(value)
  );
}

function validMutationArguments(value) {
  return (
    exactKeys(value, ["tag_urns", "entity_urns", "column_paths"]) &&
    Array.isArray(value.tag_urns) &&
    value.tag_urns.length === 1 &&
    boundedString(value.tag_urns[0], 2048) &&
    Array.isArray(value.entity_urns) &&
    value.entity_urns.length === 1 &&
    boundedString(value.entity_urns[0], 2048) &&
    Array.isArray(value.column_paths) &&
    value.column_paths.length === 1 &&
    boundedString(value.column_paths[0], 1024)
  );
}

function verifyAction(value) {
  return (
    exactKeys(value, [
      "actionId",
      "tool",
      "arguments",
      "inverse",
      "digest"
    ]) &&
    value.actionId === "datahub.add-classification-tag.v1" &&
    value.tool === "add_tags" &&
    validMutationArguments(value.arguments) &&
    value.arguments.tag_urns[0] === "urn:li:tag:PII" &&
    value.arguments.entity_urns[0].startsWith("urn:li:dataset:") &&
    exactKeys(value.inverse, ["tool", "arguments"]) &&
    value.inverse.tool === "remove_tags" &&
    validMutationArguments(value.inverse.arguments) &&
    sameCanonical(value.arguments, value.inverse.arguments) &&
    verifyDigestField(value)
  );
}

function verifyMutation(value, action) {
  return (
    exactKeys(value, ["requestDigest", "responseDigest"]) &&
    DIGEST.test(value.requestDigest) &&
    DIGEST.test(value.responseDigest) &&
    value.requestDigest ===
      digest({
        tagUrns: [...action.arguments.tag_urns],
        entityUrns: [...action.arguments.entity_urns],
        columnPaths: [...action.arguments.column_paths]
      })
  );
}

function verifyDossier(value) {
  if (
    !exactKeys(value, [
      "schemaVersion",
      "dossierId",
      "scanId",
      "findingDigest",
      "finding",
      "target",
      "provenance",
      "blastRadius",
      "before",
      "policyDigest",
      "createdAt",
      "digest"
    ]) ||
    value.schemaVersion !== "archon.evidence-dossier/v1" ||
    !boundedString(value.scanId, 512) ||
    !DIGEST.test(value.findingDigest) ||
    !exactKeys(value.finding, [
      "type",
      "severity",
      "subject",
      "ruleId",
      "unclassifiedFields"
    ]) ||
    value.finding.type !== "governance_violation" ||
    !["low", "medium", "high"].includes(value.finding.severity) ||
    !boundedString(value.finding.subject, 2048) ||
    value.finding.ruleId !== "G6" ||
    !Array.isArray(value.finding.unclassifiedFields) ||
    value.finding.unclassifiedFields.length === 0 ||
    value.finding.unclassifiedFields.some(
      (field) => !boundedString(field, 1024)
    ) ||
    !exactKeys(value.target, ["entityUrn", "columnPath"]) ||
    !boundedString(value.target.entityUrn, 2048) ||
    !boundedString(value.target.columnPath, 1024) ||
    !Array.isArray(value.provenance) ||
    !exactKeys(value.blastRadius, [
      "downstreamUrns",
      "maxHops",
      "truncated"
    ]) ||
    !Array.isArray(value.blastRadius.downstreamUrns) ||
    value.blastRadius.downstreamUrns.some(
      (urn) => !boundedString(urn, 2048)
    ) ||
    value.blastRadius.maxHops !== 3 ||
    typeof value.blastRadius.truncated !== "boolean" ||
    !verifyTagProjection(value.before) ||
    !DIGEST.test(value.policyDigest) ||
    !instant(value.createdAt) ||
    value.findingDigest !== digest(value.finding) ||
    value.finding.subject !== value.target.entityUrn ||
    !value.finding.unclassifiedFields.includes(value.target.columnPath) ||
    value.before.entityUrn !== value.target.entityUrn ||
    value.before.columnPath !== value.target.columnPath ||
    !verifyNamedDigest(value, "dossierId", "dossier-")
  ) {
    return false;
  }
  return true;
}

function verifyPlan(value, dossier) {
  return (
    exactKeys(value, [
      "schemaVersion",
      "planId",
      "dossierDigest",
      "policyDigest",
      "actionCatalogDigest",
      "action",
      "expectedBefore",
      "expectedAfter",
      "risk",
      "requiresHumanApproval",
      "digest"
    ]) &&
    value.schemaVersion === "archon.remediation-plan/v1" &&
    value.dossierDigest === dossier.digest &&
    value.policyDigest === dossier.policyDigest &&
    DIGEST.test(value.actionCatalogDigest) &&
    value.risk === "low" &&
    value.requiresHumanApproval === true &&
    verifyAction(value.action) &&
    verifyTagProjection(value.expectedBefore) &&
    verifyTagProjection(value.expectedAfter) &&
    sameCanonical(value.expectedBefore, dossier.before) &&
    value.expectedBefore.entityUrn === value.action.arguments.entity_urns[0] &&
    value.expectedBefore.columnPath === value.action.arguments.column_paths[0] &&
    value.expectedAfter.entityUrn === value.expectedBefore.entityUrn &&
    value.expectedAfter.columnPath === value.expectedBefore.columnPath &&
    sameCanonical(
      value.expectedAfter.tags,
      [
        ...new Set([
          ...value.expectedBefore.tags,
          value.action.arguments.tag_urns[0]
        ])
      ].sort((left, right) => left.localeCompare(right))
    ) &&
    verifyNamedDigest(value, "planId", "plan-")
  );
}

function verifyApprovalRequest(value, dossier, plan) {
  return (
    exactKeys(value, [
      "schemaVersion",
      "approvalId",
      "dossierDigest",
      "planDigest",
      "actionCatalogDigest",
      "expectedBeforeDigest",
      "requestedAt",
      "expiresAt",
      "nonce",
      "digest"
    ]) &&
    value.schemaVersion === "archon.approval-request/v1" &&
    value.dossierDigest === dossier.digest &&
    value.planDigest === plan.digest &&
    value.actionCatalogDigest === plan.actionCatalogDigest &&
    value.expectedBeforeDigest === plan.expectedBefore.digest &&
    instant(value.requestedAt) &&
    instant(value.expiresAt) &&
    Date.parse(value.expiresAt) > Date.parse(value.requestedAt) &&
    Date.parse(value.expiresAt) - Date.parse(value.requestedAt) <=
      7 * 24 * 60 * 60 * 1000 &&
    boundedString(value.nonce, 512) &&
    value.nonce.length >= 8 &&
    verifyNamedDigest(value, "approvalId", "approval-")
  );
}

function expectedCheckPasses(receipt) {
  const before = receipt.before;
  const after = receipt.after;
  const tag = receipt.action.arguments.tag_urns[0];
  return new Map([
    [
      "TARGET_UNCHANGED",
      Boolean(
        before &&
          after &&
          before.entityUrn === after.entityUrn &&
          before.columnPath === after.columnPath
      )
    ],
    [
      "PREEXISTING_TAGS_PRESERVED",
      Boolean(
        before &&
          after &&
          before.tags.every((existing) => after.tags.includes(existing))
      )
    ],
    ["POLICY_TAG_PRESENT", Boolean(after?.tags.includes(tag))],
    [
      "NO_UNEXPECTED_TAGS",
      Boolean(
        before &&
          after &&
          sameCanonical(
            after.tags,
            [...new Set([...before.tags, tag])].sort((left, right) =>
              left.localeCompare(right)
            )
          )
      )
    ],
    [
      "APPROVAL_BINDING_VALID",
      Boolean(
        receipt.approvalDecisionDigest &&
          receipt.mutation &&
          verifyMutation(receipt.mutation, receipt.action)
      )
    ]
  ]);
}

function verifyChecks(receipt) {
  if (!Array.isArray(receipt.checks)) return false;
  if (receipt.outcome === "REJECTED") return receipt.checks.length === 0;
  if (receipt.outcome !== "VERIFIED" || receipt.checks.length !== 5) {
    return false;
  }
  const expected = expectedCheckPasses(receipt);
  return receipt.checks.every(
    (check, index) =>
      exactKeys(check, ["checkId", "passed", "evidence"]) &&
      check.checkId === VERIFICATION_CHECK_IDS[index] &&
      check.passed === true &&
      check.passed === expected.get(check.checkId) &&
      boundedString(check.evidence, 4096)
  );
}

function verifyRollback(receipt) {
  const rollback = receipt.rollback;
  if (receipt.outcome === "REJECTED") {
    return (
      exactKeys(rollback, ["availability"]) &&
      rollback.availability === "NOT_APPLICABLE"
    );
  }
  return (
    receipt.outcome === "VERIFIED" &&
    exactKeys(rollback, [
      "availability",
      "inverseActionDigest",
      "restoreStateDigest"
    ]) &&
    rollback.availability === "ELIGIBLE" &&
    rollback.inverseActionDigest === digest(receipt.action.inverse) &&
    rollback.restoreStateDigest === receipt.before?.digest
  );
}

function expectedReceiptEventPayloads(receipt) {
  const values = [
    {
      kind: "DOSSIER_BOUND",
      payload: { dossierDigest: receipt.dossierDigest },
      occurredAt: receipt.startedAt
    },
    {
      kind: "PLAN_BOUND",
      payload: { planDigest: receipt.planDigest },
      occurredAt: receipt.startedAt
    },
    {
      kind: "APPROVAL_BOUND",
      payload: { approvalDecisionDigest: receipt.approvalDecisionDigest },
      occurredAt: receipt.startedAt
    },
    {
      kind: "PRECONDITION_CHECKED",
      payload: { beforeDigest: receipt.before?.digest ?? null },
      occurredAt: receipt.startedAt
    }
  ];
  if (receipt.mutation) {
    values.push({
      kind: "MUTATION_INVOKED",
      payload: {
        requestDigest: receipt.mutation.requestDigest,
        responseDigest: receipt.mutation.responseDigest
      },
      occurredAt: receipt.completedAt
    });
  }
  if (receipt.after || receipt.checks.length > 0) {
    values.push({
      kind: "POSTCONDITION_CHECKED",
      payload: {
        afterDigest: receipt.after?.digest ?? null,
        checks: receipt.checks
      },
      occurredAt: receipt.completedAt
    });
  }
  values.push({
    kind: "ROLLBACK_ANCHORED",
    payload: receipt.rollback,
    occurredAt: receipt.completedAt
  });
  return values;
}

function verifyReceiptEvents(receipt) {
  if (
    !Array.isArray(receipt.events) ||
    receipt.events.length < 5 ||
    receipt.events.length > RECEIPT_EVENT_KINDS.length
  ) {
    return false;
  }
  const expected = expectedReceiptEventPayloads(receipt);
  if (expected.length !== receipt.events.length) return false;
  let previousHash = digest("archon-execution-receipt-chain-genesis-v1");
  for (let index = 0; index < receipt.events.length; index += 1) {
    const event = receipt.events[index];
    const expectedEvent = expected[index];
    if (
      !exactKeys(event, [
        "sequence",
        "kind",
        "occurredAt",
        "payloadDigest",
        "previousHash",
        "eventHash"
      ]) ||
      event.sequence !== index ||
      event.kind !== expectedEvent.kind ||
      !RECEIPT_EVENT_KINDS.includes(event.kind) ||
      event.occurredAt !== expectedEvent.occurredAt ||
      event.payloadDigest !== digest(expectedEvent.payload) ||
      event.previousHash !== previousHash ||
      event.eventHash !==
        digest({
          sequence: index,
          kind: event.kind,
          occurredAt: event.occurredAt,
          payloadDigest: event.payloadDigest,
          previousHash
        })
    ) {
      return false;
    }
    previousHash = event.eventHash;
  }
  return true;
}

function verifyExecutionReceipt(receipt, expected) {
  if (
    !exactKeys(
      receipt,
      [
        "schemaVersion",
        "receiptId",
        "executionId",
        "outcome",
        "dossierDigest",
        "planDigest",
        "approvalDecisionDigest",
        "action",
        "idempotencyKey",
        "checks",
        "rollback",
        "events",
        "startedAt",
        "completedAt",
        "digest"
      ],
      ["before", "after", "mutation"]
    ) ||
    receipt.schemaVersion !== "archon.execution-receipt/v1" ||
    receipt.outcome !== expected.outcome ||
    receipt.dossierDigest !== expected.dossierDigest ||
    receipt.planDigest !== expected.planDigest ||
    receipt.approvalDecisionDigest !== expected.decisionDigest ||
    !instant(receipt.startedAt) ||
    !instant(receipt.completedAt) ||
    Date.parse(receipt.startedAt) + MAX_CLOCK_SKEW_MS <
      Date.parse(expected.decidedAt) ||
    Date.parse(receipt.completedAt) + MAX_CLOCK_SKEW_MS <
      Date.parse(receipt.startedAt) ||
    !verifyAction(receipt.action) ||
    !sameCanonical(receipt.action, expected.action)
  ) {
    return undefined;
  }
  const expectedIdempotencyKey = digest({
    schemaVersion: "archon.worker-execution-key/v1",
    executionId: expected.executionArn,
    approvalId: expected.approvalId,
    decisionDigest: expected.decisionDigest
  });
  const expectedReceiptExecutionId = digest({
    decisionDigest: expected.decisionDigest,
    idempotencyKey: expectedIdempotencyKey
  });
  if (
    receipt.idempotencyKey !== expectedIdempotencyKey ||
    receipt.executionId !==
      `execution-${expectedReceiptExecutionId.slice(
        "sha256:".length,
        "sha256:".length + 24
      )}` ||
    !DIGEST.test(receipt.digest) ||
    digest(without(receipt, ["receiptId", "digest"])) !== receipt.digest ||
    receipt.receiptId !==
      `receipt-${receipt.digest.slice(
        "sha256:".length,
        "sha256:".length + 24
      )}`
  ) {
    return undefined;
  }
  if (receipt.outcome === "VERIFIED") {
    if (
      !verifyTagProjection(receipt.before) ||
      !verifyTagProjection(receipt.after) ||
      !sameCanonical(receipt.before, expected.before) ||
      !sameCanonical(receipt.after, expected.after) ||
      !verifyMutation(receipt.mutation, receipt.action)
    ) {
      return undefined;
    }
  } else if (
    receipt.before !== undefined ||
    receipt.after !== undefined ||
    receipt.mutation !== undefined
  ) {
    return undefined;
  }
  if (
    !verifyChecks(receipt) ||
    !verifyRollback(receipt) ||
    !verifyReceiptEvents(receipt)
  ) {
    return undefined;
  }
  return {
    outcome: receipt.outcome,
    receiptDigest: receipt.digest,
    completedAt: receipt.completedAt,
    verification: {
      checks: receipt.checks.map((check) => ({
        checkId: check.checkId,
        passed: check.passed
      })),
      eventCount: receipt.events.length,
      rollbackAvailability: receipt.rollback.availability
    }
  };
}

function parseRemediationResult(rawOutput) {
  if (
    typeof rawOutput !== "string" ||
    Buffer.byteLength(rawOutput, "utf8") > MAX_EXECUTION_OUTPUT_BYTES
  ) {
    throw new Error("governed execution has no bounded output");
  }
  let output;
  try {
    output = JSON.parse(rawOutput);
  } catch {
    throw new Error("governed execution output is not JSON");
  }
  const result = record(output) ? output.remediationResult : undefined;
  if (
    !exactKeys(result, [
      "schemaVersion",
      "approvalId",
      "planDigest",
      "evidenceDigest",
      "receiptDigest",
      "executionEvidenceDigest",
      "outcome"
    ]) ||
    result.schemaVersion !== "archon.remediation-result/v1" ||
    !boundedString(result.approvalId, 160) ||
    !DIGEST.test(result.planDigest) ||
    !DIGEST.test(result.evidenceDigest) ||
    !DIGEST.test(result.receiptDigest) ||
    !DIGEST.test(result.executionEvidenceDigest) ||
    !["VERIFIED", "REJECTED"].includes(result.outcome)
  ) {
    throw new Error("governed execution result is invalid");
  }
  return result;
}

function parseAuditCheckpoint(item) {
  const text = stringAttribute(item, "output");
  if (!text) return undefined;
  let output;
  try {
    output = JSON.parse(text);
  } catch {
    throw new Error("malformed audit checkpoint");
  }
  if (
    !record(output) ||
    output.schemaVersion !== "archon.audit-result/v1" ||
    typeof output.requiresApproval !== "boolean" ||
    !DIGEST.test(output.reportDigest) ||
    !DIGEST.test(output.evidenceDigest)
  ) {
    throw new Error("invalid audit checkpoint");
  }
  if (
    output.requiresApproval &&
    (typeof output.approvalId !== "string" ||
      !/^[A-Za-z0-9._:-]{8,160}$/.test(output.approvalId) ||
      !DIGEST.test(output.planDigest))
  ) {
    throw new Error("invalid approval checkpoint");
  }
  return output;
}

function validAuditReport(report) {
  return (
    record(report) &&
    typeof report.scanId === "string" &&
    record(report.classification) &&
    Array.isArray(report.findings) &&
    typeof report.narrative === "string" &&
    Array.isArray(report.trace)
  );
}

function verifyAuditEvidence(value, expectedDigest, expectedExecutionArn, reportDigest) {
  if (
    !record(value) ||
    value.schemaVersion !== "archon.audit-evidence/v1" ||
    value.executionId !== expectedExecutionArn ||
    value.digest !== expectedDigest ||
    value.reportDigest !== reportDigest ||
    !validAuditReport(value.report) ||
    !record(value.remediation)
  ) {
    return false;
  }
  const { digest: _storedDigest, ...unsigned } = value;
  return digest(unsigned) === expectedDigest && digest(value.report) === reportDigest;
}

async function readAuditEvidence(checkpoint, expectedExecutionArn) {
  const evidence = await readEvidenceObject("audit", checkpoint.evidenceDigest);
  if (
    !verifyAuditEvidence(
      evidence,
      checkpoint.evidenceDigest,
      expectedExecutionArn,
      checkpoint.reportDigest
    )
  ) {
    throw new Error("evidence integrity verification failed");
  }
  return evidence;
}

function projectReport(evidence) {
  const report = JSON.parse(JSON.stringify(evidence.report));
  if (evidence.remediation.disposition !== "ACTIONABLE") return report;

  const { dossier, plan, approvalRequest } = evidence.remediation;
  if (
    !record(dossier) ||
    !record(dossier.finding) ||
    !record(dossier.target) ||
    !record(plan) ||
    !record(plan.action) ||
    !record(plan.action.arguments) ||
    !record(plan.expectedBefore) ||
    !record(plan.expectedAfter) ||
    !record(approvalRequest)
  ) {
    throw new Error("actionable evidence projection is malformed");
  }
  const finding = report.findings.find(
    (candidate) =>
      record(candidate) &&
      candidate.subject === dossier.finding.subject &&
      record(candidate.detail) &&
      candidate.detail.ruleId === "G6"
  );
  if (!finding) throw new Error("actionable finding is absent from report");
  const before = Array.isArray(plan.expectedBefore.tags)
    ? plan.expectedBefore.tags.filter((tag) => typeof tag === "string")
    : [];
  const after = Array.isArray(plan.expectedAfter.tags)
    ? plan.expectedAfter.tags.filter((tag) => typeof tag === "string")
    : [];
  const tagUrns = Array.isArray(plan.action.arguments.tag_urns)
    ? plan.action.arguments.tag_urns
    : [];
  if (
    typeof approvalRequest.approvalId !== "string" ||
    typeof approvalRequest.expiresAt !== "string" ||
    typeof dossier.target.columnPath !== "string" ||
    typeof plan.digest !== "string" ||
    plan.risk !== "low" ||
    typeof tagUrns[0] !== "string"
  ) {
    throw new Error("actionable evidence has no safe approval projection");
  }
  finding.detail = {
    ...finding.detail,
    dossier: {
      dossierId: dossier.dossierId,
      digest: dossier.digest,
      policyDigest: dossier.policyDigest,
      generatedAt: dossier.createdAt,
      evidenceCount:
        (Array.isArray(dossier.provenance) ? dossier.provenance.length : 0) +
        (Array.isArray(dossier.blastRadius?.downstreamUrns)
          ? dossier.blastRadius.downstreamUrns.length
          : 0) +
        2
    },
    approval: {
      approvalId: approvalRequest.approvalId,
      expiresAt: approvalRequest.expiresAt,
      targetField: dossier.target.columnPath,
      proposedTag: tagUrns[0],
      before,
      after,
      planDigest: plan.digest,
      risk: plan.risk
    }
  };
  return report;
}

function parseDecisionEvidence(item, checkpoint, expectedExecutionArn, evidence) {
  const text = stringAttribute(item, "decisionEvidence");
  const expectedDigest = stringAttribute(item, "decisionEvidenceDigest");
  const decidedAt = stringAttribute(item, "decidedAt");
  if (!text || !DIGEST.test(expectedDigest) || !instant(decidedAt)) {
    throw new Error("approval decision evidence is unavailable");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("approval decision evidence is not JSON");
  }
  const requestDigest =
    evidence?.remediation?.disposition === "ACTIONABLE"
      ? evidence.remediation.approvalRequest?.digest
      : undefined;
  if (
    !exactKeys(value, [
      "schemaVersion",
      "approvalId",
      "executionId",
      "evidenceDigest",
      "planDigest",
      "requestDigest",
      "decision",
      "approver",
      "commentDigest"
    ]) ||
    value.schemaVersion !== "archon.approval-decision/v1" ||
    value.approvalId !== checkpoint.approvalId ||
    value.executionId !== expectedExecutionArn ||
    value.evidenceDigest !== checkpoint.evidenceDigest ||
    value.planDigest !== checkpoint.planDigest ||
    value.requestDigest !== requestDigest ||
    !["APPROVE", "REJECT"].includes(value.decision) ||
    !verifyApprover(value.approver) ||
    !DIGEST.test(value.commentDigest) ||
    `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}` !==
      expectedDigest
  ) {
    throw new Error("approval decision evidence binding is invalid");
  }
  return { value, decidedAt };
}

async function readApproval(checkpoint, expectedExecutionArn, evidence) {
  if (!checkpoint?.requiresApproval) return undefined;
  const result = await dynamodb.send(
    new GetItemCommand({
      TableName: approvalTable,
      Key: {
        pk: { S: `APPROVAL#${checkpoint.approvalId}` },
        sk: { S: "STATE" }
      },
      ConsistentRead: true
    })
  );
  const item = result.Item;
  if (!item) return undefined;
  if (
    stringAttribute(item, "evidenceDigest") !== checkpoint.evidenceDigest ||
    stringAttribute(item, "planDigest") !== checkpoint.planDigest
  ) {
    throw new Error("approval record is not bound to the audit checkpoint");
  }
  const status = stringAttribute(item, "status");
  if (status !== "PENDING" && status !== "DECIDED") {
    throw new Error("approval status is invalid");
  }
  const approvalExpiresAt = stringAttribute(item, "approvalExpiresAt");
  const retentionExpiresAt = numberAttribute(item, "expiresAt");
  const immutableApprovalExpiresAt =
    evidence?.remediation?.disposition === "ACTIONABLE"
      ? evidence.remediation.approvalRequest?.expiresAt
      : undefined;
  if (
    !instant(approvalExpiresAt) ||
    approvalExpiresAt !== immutableApprovalExpiresAt ||
    retentionExpiresAt === undefined
  ) {
    throw new Error("approval retention is not bound to its immutable deadline");
  }
  const projection = {
    approvalId: checkpoint.approvalId,
    status,
    expiresAt: approvalExpiresAt,
    planDigest: checkpoint.planDigest,
    evidenceDigest: checkpoint.evidenceDigest,
    ...(status === "DECIDED" &&
    ["APPROVE", "REJECT"].includes(stringAttribute(item, "decision"))
      ? { decision: stringAttribute(item, "decision") }
      : {})
  };
  if (status === "PENDING") return { projection };
  const decisionEvidence = parseDecisionEvidence(
    item,
    checkpoint,
    expectedExecutionArn,
    evidence
  );
  if (projection.decision !== decisionEvidence.value.decision) {
    throw new Error("approval decision does not match its durable evidence");
  }
  if (
    retentionExpiresAt <
    Math.floor(Date.parse(decisionEvidence.decidedAt) / 1000) +
      DECIDED_RETENTION_SECONDS
  ) {
    throw new Error("decided approval retention is below the evidence contract");
  }
  return {
    projection,
    decisionEvidence: decisionEvidence.value,
    decidedAt: decisionEvidence.decidedAt
  };
}

function publicStatus(awsStatus, approval) {
  if (
    awsStatus === "RUNNING" &&
    approval?.projection?.status === "PENDING"
  ) {
    return "AWAITING_APPROVAL";
  }
  return awsStatus;
}

function actionableArtifacts(evidence, checkpoint) {
  const remediation = evidence?.remediation;
  const dossier = remediation?.dossier;
  const plan = remediation?.plan;
  const approvalRequest = remediation?.approvalRequest;
  const reportFinding = Array.isArray(evidence?.report?.findings)
    ? evidence.report.findings.find(
        (finding) =>
          record(finding) &&
          finding.type === "governance_violation" &&
          finding.subject === dossier?.finding?.subject &&
          finding.detail?.ruleId === "G6"
      )
    : undefined;
  if (
    remediation?.disposition !== "ACTIONABLE" ||
    !record(dossier) ||
    !record(plan) ||
    !record(approvalRequest) ||
    !verifyDossier(dossier) ||
    !verifyPlan(plan, dossier) ||
    !verifyApprovalRequest(approvalRequest, dossier, plan) ||
    !record(reportFinding) ||
    !record(reportFinding.detail) ||
    reportFinding.severity !== dossier.finding.severity ||
    !Array.isArray(reportFinding.detail.unclassifiedFields) ||
    !reportFinding.detail.unclassifiedFields.includes(
      dossier.target.columnPath
    ) ||
    dossier.scanId !== evidence.report.scanId ||
    dossier.createdAt !== evidence.createdAt ||
    approvalRequest.requestedAt !== evidence.createdAt ||
    plan.digest !== checkpoint.planDigest ||
    approvalRequest.approvalId !== checkpoint.approvalId ||
    approvalRequest.planDigest !== checkpoint.planDigest
  ) {
    throw new Error("terminal audit evidence binding is invalid");
  }
  return { dossier, plan, approvalRequest };
}

function verifyExecutionEvidence(
  value,
  remediationResult,
  expectedExecutionArn,
  checkpoint,
  approval,
  auditEvidence
) {
  if (
    !exactKeys(value, [
      "schemaVersion",
      "executionId",
      "approvalId",
      "auditEvidenceDigest",
      "decision",
      "receipt",
      "createdAt",
      "digest"
    ]) ||
    value.schemaVersion !== "archon.execution-evidence/v1" ||
    value.executionId !== expectedExecutionArn ||
    value.approvalId !== checkpoint.approvalId ||
    value.auditEvidenceDigest !== checkpoint.evidenceDigest ||
    value.digest !== remediationResult.executionEvidenceDigest ||
    !instant(value.createdAt) ||
    !verifyDigestField(value)
  ) {
    return undefined;
  }
  const artifacts = actionableArtifacts(auditEvidence, checkpoint);
  const decisionEvidence = approval.decisionEvidence;
  if (
    Date.parse(approval.decidedAt) <
      Date.parse(artifacts.approvalRequest.requestedAt) ||
    Date.parse(approval.decidedAt) >
      Date.parse(artifacts.approvalRequest.expiresAt)
  ) {
    return undefined;
  }
  const expectedDecision = {
    approvalId: checkpoint.approvalId,
    requestDigest: artifacts.approvalRequest.digest,
    planDigest: checkpoint.planDigest,
    decision: approval.projection.decision,
    approver: decisionEvidence.approver,
    decidedAt: approval.decidedAt
  };
  if (!verifyApprovalDecision(value.decision, expectedDecision)) {
    return undefined;
  }
  const expectedOutcome =
    approval.projection.decision === "APPROVE" ? "VERIFIED" : "REJECTED";
  if (
    remediationResult.outcome !== expectedOutcome ||
    !DIGEST.test(remediationResult.receiptDigest)
  ) {
    return undefined;
  }
  const receiptProjection = verifyExecutionReceipt(value.receipt, {
    outcome: expectedOutcome,
    dossierDigest: artifacts.dossier.digest,
    planDigest: checkpoint.planDigest,
    decisionDigest: value.decision.digest,
    decidedAt: value.decision.decidedAt,
    action: artifacts.plan.action,
    before: artifacts.plan.expectedBefore,
    after: artifacts.plan.expectedAfter,
    executionArn: expectedExecutionArn,
    approvalId: checkpoint.approvalId
  });
  if (
    !receiptProjection ||
    receiptProjection.receiptDigest !== remediationResult.receiptDigest ||
    Date.parse(value.createdAt) + MAX_CLOCK_SKEW_MS <
      Date.parse(receiptProjection.completedAt)
  ) {
    return undefined;
  }
  return {
    ...receiptProjection,
    executionEvidenceDigest: remediationResult.executionEvidenceDigest
  };
}

async function resultProjection(
  execution,
  checkpoint,
  approval,
  evidence,
  expectedExecutionArn
) {
  if (execution.status !== "SUCCEEDED") return undefined;
  if (!checkpoint) {
    throw new Error("successful execution has no audit checkpoint");
  }
  if (!checkpoint.requiresApproval) {
    return { outcome: "READ_ONLY_COMPLETE" };
  }
  if (
    !evidence ||
    approval?.projection?.status !== "DECIDED" ||
    !["APPROVE", "REJECT"].includes(approval.projection.decision) ||
    !approval.decisionEvidence ||
    !instant(approval.decidedAt)
  ) {
    throw new Error("successful governed execution has no bound decision");
  }
  const remediationResult = parseRemediationResult(execution.output);
  if (
    remediationResult.approvalId !== checkpoint.approvalId ||
    remediationResult.planDigest !== checkpoint.planDigest ||
    remediationResult.evidenceDigest !== checkpoint.evidenceDigest
  ) {
    throw new Error("remediation result is not bound to the audit checkpoint");
  }
  const executionEvidence = await readEvidenceObject(
    "execution",
    remediationResult.executionEvidenceDigest
  );
  const projection = verifyExecutionEvidence(
    executionEvidence,
    remediationResult,
    expectedExecutionArn,
    checkpoint,
    approval,
    evidence
  );
  if (!projection) {
    throw new Error("execution evidence integrity verification failed");
  }
  return projection;
}

async function start(body) {
  const parsed = parseStartBody(body);
  if (parsed.error) return parsed.error;

  const auditId = randomBytes(32).toString("hex");
  const submittedAt = new Date().toISOString();
  const input = {
    schemaVersion: "archon.audit-request/v1",
    requestId: auditId,
    requestedAt: submittedAt,
    mode: parsed.mode ?? "GOVERNED",
    ...(parsed.query ? { query: parsed.query } : {})
  };
  await stepFunctions.send(
    new StartExecutionCommand({
      stateMachineArn,
      name: auditId,
      input: JSON.stringify(input)
    })
  );
  const pollUrl = `/api/control-loops/${auditId}`;
  return response(
    202,
    {
      schemaVersion: "archon.control-loop-start/v1",
      auditId,
      status: "RUNNING",
      pollUrl,
      submittedAt
    },
    {
      location: pollUrl,
      retryAfter: "2"
    }
  );
}

async function status(auditId) {
  if (typeof auditId !== "string" || !AUDIT_ID.test(auditId)) {
    return response(400, { error: "invalid_audit_id" });
  }
  const expectedExecutionArn = executionArn(auditId);
  let execution;
  try {
    execution = await stepFunctions.send(
      new DescribeExecutionCommand({ executionArn: expectedExecutionArn })
    );
  } catch (error) {
    if (error?.name === "ExecutionDoesNotExist") {
      return response(404, { error: "audit_not_found" });
    }
    throw error;
  }
  if (
    !["RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"].includes(
      execution.status
    )
  ) {
    throw new Error("unsupported execution status");
  }

  const checkpointItem = (
    await dynamodb.send(
      new GetItemCommand({
        TableName: checkpointTable,
        Key: {
          pk: { S: `AUDIT#${expectedExecutionArn}` },
          sk: { S: "RESULT" }
        },
        ConsistentRead: true
      })
    )
  ).Item;
  const checkpoint = parseAuditCheckpoint(checkpointItem);
  const evidence = checkpoint
    ? await readAuditEvidence(checkpoint, expectedExecutionArn)
    : undefined;
  const approval = await readApproval(
    checkpoint,
    expectedExecutionArn,
    evidence
  );
  const result = await resultProjection(
    execution,
    checkpoint,
    approval,
    evidence,
    expectedExecutionArn
  );
  return response(200, {
    schemaVersion: "archon.control-loop-status/v1",
    auditId,
    status: publicStatus(execution.status, approval),
    submittedAt:
      execution.startDate instanceof Date
        ? execution.startDate.toISOString()
        : undefined,
    updatedAt: new Date().toISOString(),
    ...(execution.stopDate instanceof Date
      ? { completedAt: execution.stopDate.toISOString() }
      : {}),
    ...(evidence
      ? {
          releaseSha: evidence.releaseSha,
          report: projectReport(evidence)
        }
      : {}),
    ...(approval ? { approval: approval.projection } : {}),
    ...(checkpoint?.manualOnlyReason
      ? { manualOnlyReason: checkpoint.manualOnlyReason }
      : {}),
    ...(result ? { result } : {})
  });
}

exports.handler = async (event) => {
  try {
    if (
      exactKeys(event, ["operation", "requestId", "body"]) &&
      event.operation === "start"
    ) {
      return await start(event.body);
    }
    if (
      exactKeys(event, ["operation", "requestId", "auditId"]) &&
      event.operation === "status"
    ) {
      return await status(event.auditId);
    }
    return response(404, { error: "not_found" });
  } catch {
    const requestId =
      typeof event?.requestId === "string" &&
      /^[A-Za-z0-9=+/_-]{1,256}$/.test(event.requestId)
        ? event.requestId
        : undefined;
    process.stderr.write(
      `[control] request_failed${requestId ? ` request_id=${requestId}` : ""}\n`
    );
    return response(502, { error: "control_plane_unavailable" });
  }
};
