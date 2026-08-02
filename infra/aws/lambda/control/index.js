"use strict";

const { createHash, randomBytes } = require("node:crypto");
const {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand
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
const demoQuery = process.env.ARCHON_DEMO_QUERY;
const runtimeSessionTable = process.env.RUNTIME_SESSION_TABLE;
const coreLeaseTable = process.env.CORE_LEASE_TABLE;
const coreSessionStateMachineArn =
  process.env.CORE_SESSION_STATE_MACHINE_ARN;
const runtimeOperatorGroup =
  process.env.RUNTIME_OPERATOR_GROUP || "archon-approvers";

const AUDIT_ID = /^[a-f0-9]{64}$/;
const RUNTIME_SESSION_ID = /^rs_[A-Za-z0-9_-]{43}$/u;
const RUNTIME_GENERATION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const RUNTIME_STATES = [
  "STARTING",
  "ACTIVE",
  "STOPPING",
  "STOPPED",
  "EXPIRED",
  "FAILED"
];
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const RFC3339_INSTANT =
  /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/u;
const MAX_BODY_BYTES = 4096;
const MAX_EVIDENCE_BYTES = 6 * 1024 * 1024;
const MAX_EXECUTION_OUTPUT_BYTES = 256 * 1024;
const DECIDED_RETENTION_SECONDS = 90 * 24 * 60 * 60;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const CREDENTIAL_SHAPED_IDENTIFIER =
  /(?:bedrock-api-key-[A-Za-z0-9_+/=-]{16,}|sk-(?:ant-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/u;
const MANUAL_ONLY_REASONS = [
  "READ_ONLY_REQUEST",
  "NO_ACTIONABLE_G6_FINDING",
  "REMEDIATION_PRESTATE_UNAVAILABLE",
  "POLICY_REJECTED_PROPOSAL"
];
const FORBIDDEN_PUBLIC_KEYS = new Set([
  "accesstoken",
  "accesstokens",
  "apikey",
  "authorization",
  "clientsecret",
  "cookie",
  "credential",
  "credentials",
  "idtoken",
  "jwt",
  "password",
  "privatekey",
  "rawresponse",
  "refreshtoken",
  "secret",
  "secretaccesskey",
  "sessiontoken",
  "tasktoken",
  "token",
  "tokens"
]);
const PUBLIC_CREDENTIAL_PATTERNS = [
  /bedrock-api-key-[A-Za-z0-9_+/=-]{16,}/u,
  /(?:AKIA|ASIA)[A-Z0-9]{16}/u,
  /gh[pousr]_[A-Za-z0-9_]{20,}/u,
  /github_pat_[A-Za-z0-9_]{20,}/u,
  /xox[baprs]-[A-Za-z0-9-]{10,}/u,
  /AIza[0-9A-Za-z_-]{35}/u,
  /Bearer\s+[A-Za-z0-9._~+/=-]{12,}/iu,
  /sk-(?:ant-)?[A-Za-z0-9._~+/=-]{12,}/iu,
  /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/u,
  /(?:api[_ -]?key|password|passwd|pwd|secret|token)\s*[:=]\s*["']?[^\s"',;]{8,}/iu,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u
];
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

class RetiredAuditSchemaError extends Error {
  constructor() {
    super("retired audit evidence schema");
    this.name = "RetiredAuditSchemaError";
  }
}

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
    RFC3339_INSTANT.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function boundedString(value, maximum = 2048) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    !/[\u0000-\u001F\u007F]/u.test(value)
  );
}

function configuredDemoQuery() {
  if (
    typeof demoQuery !== "string" ||
    demoQuery !== demoQuery.trim() ||
    demoQuery.length < 1 ||
    demoQuery.length > 256 ||
    /[\u0000-\u001F\u007F]/u.test(demoQuery) ||
    /[*?]/u.test(demoQuery) ||
    demoQuery === "{}"
  ) {
    throw new Error("invalid demo query configuration");
  }
  return demoQuery;
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
    /[\u0000-\u001F\u007F]/u.test(body.query)
  ) {
    return { error: response(400, { error: "invalid_query" }) };
  }
  const query = body.query.trim();
  if (query !== body.query) {
    return { error: response(400, { error: "query_must_be_trimmed" }) };
  }
  if (!query || /[*?]/u.test(query) || query === "{}") {
    return { error: response(400, { error: "query_must_be_narrow" }) };
  }
  if (query !== configuredDemoQuery()) {
    return { error: response(400, { error: "query_outside_demo_scope" }) };
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
  const baseKeys = [
    "schemaVersion",
    "requiresApproval",
    "reportDigest",
    "evidenceDigest"
  ];
  if (
    !record(output) ||
    !["archon.audit-result/v1", "archon.audit-result/v2"].includes(
      output.schemaVersion
    ) ||
    typeof output.requiresApproval !== "boolean" ||
    !DIGEST.test(output.reportDigest) ||
    !DIGEST.test(output.evidenceDigest)
  ) {
    throw new Error("invalid audit checkpoint");
  }
  if (output.requiresApproval) {
    const approvalBindingKeys = [
      "approvalRequestDigest",
      "approvalRequestedAt",
      "approvalExpiresAt"
    ];
    const isCurrentCheckpoint =
      output.schemaVersion === "archon.audit-result/v2";
    if (
      !exactKeys(
        output,
        [
          ...baseKeys,
          "approvalId",
          "planDigest",
          ...(isCurrentCheckpoint ? approvalBindingKeys : [])
        ],
        isCurrentCheckpoint ? [] : approvalBindingKeys
      ) ||
      typeof output.approvalId !== "string" ||
      !/^[A-Za-z0-9._:-]{8,160}$/.test(output.approvalId) ||
      !DIGEST.test(output.planDigest)
    ) {
      throw new Error("invalid approval checkpoint");
    }
    const presentApprovalKeys = approvalBindingKeys.filter((key) =>
      Object.prototype.hasOwnProperty.call(output, key)
    );
    if (
      (isCurrentCheckpoint || presentApprovalKeys.length !== 0) &&
      (presentApprovalKeys.length !== approvalBindingKeys.length ||
        !DIGEST.test(output.approvalRequestDigest) ||
        !instant(output.approvalRequestedAt) ||
        !instant(output.approvalExpiresAt) ||
        Date.parse(output.approvalExpiresAt) <=
          Date.parse(output.approvalRequestedAt))
    ) {
      throw new Error("invalid approval checkpoint");
    }
  } else if (
    !exactKeys(output, [...baseKeys, "manualOnlyReason"]) ||
    !MANUAL_ONLY_REASONS.includes(output.manualOnlyReason)
  ) {
    throw new Error("invalid manual-only checkpoint");
  }
  return output;
}

function safeReportCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function boundedReportText(value, maximum) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    !/[\u0000-\u001F\u007F]/u.test(value)
  );
}

function validCountMap(value) {
  return (
    record(value) &&
    Object.keys(value).length <= 1000 &&
    Object.entries(value).every(
      ([key, count]) => boundedReportText(key, 256) && safeReportCount(count)
    )
  );
}

function validModelId(value) {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/u.test(value) &&
    !value.includes("://") &&
    !CREDENTIAL_SHAPED_IDENTIFIER.test(value)
  );
}

function validTokenUsage(value) {
  return (
    exactKeys(value, ["inputTokens", "outputTokens", "totalTokens"]) &&
    safeReportCount(value.inputTokens) &&
    safeReportCount(value.outputTokens) &&
    safeReportCount(value.totalTokens) &&
    value.totalTokens === value.inputTokens + value.outputTokens
  );
}

function validModelProvenance(value) {
  if (
    !exactKeys(value, [
      "schemaVersion",
      "source",
      "modelCall",
      "provider",
      "requestedModel",
      "returnedModel",
      "providerResponseId",
      "tokenUsage",
      "latencyMs"
    ]) ||
    value.schemaVersion !== "archon.model-runtime-provenance/v1" ||
    !validModelId(value.requestedModel)
  ) {
    return false;
  }
  if (value.source === "deterministic-fixture") {
    return (
      value.modelCall === false &&
      value.provider === "fixture" &&
      value.returnedModel === null &&
      value.providerResponseId === null &&
      value.tokenUsage === null &&
      value.latencyMs === null
    );
  }
  return (
    value.source === "live-provider" &&
    value.modelCall === true &&
    [
      "bedrock-mantle",
      "custom",
      "qwen",
      "gemini",
      "openai",
      "anthropic"
    ].includes(value.provider) &&
    validModelId(value.returnedModel) &&
    typeof value.providerResponseId === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{5,199}$/u.test(value.providerResponseId) &&
    !CREDENTIAL_SHAPED_IDENTIFIER.test(value.providerResponseId) &&
    (value.tokenUsage === null || validTokenUsage(value.tokenUsage)) &&
    Number.isSafeInteger(value.latencyMs) &&
    value.latencyMs >= 0 &&
    value.latencyMs <= 3600000
  );
}

function validAuditFinding(value) {
  return (
    exactKeys(
      value,
      ["type", "severity", "subject", "summary", "detail"],
      ["recommendation"]
    ) &&
    ["contradiction", "lineage_gap", "governance_violation"].includes(
      value.type
    ) &&
    ["low", "medium", "high"].includes(value.severity) &&
    boundedReportText(value.subject, 2048) &&
    boundedReportText(value.summary, 4000) &&
    record(value.detail) &&
    (value.recommendation === undefined ||
      boundedReportText(value.recommendation, 4000))
  );
}

function validAuditReport(report) {
  return (
    exactKeys(report, [
      "schemaVersion",
      "scanId",
      "classification",
      "findings",
      "narrative",
      "modelProvenance",
      "trace"
    ]) &&
    report.schemaVersion === "archon.audit-report/v1" &&
    boundedReportText(report.scanId, 512) &&
    exactKeys(report.classification, [
      "totalEntities",
      "withLineage",
      "sensitiveEntities",
      "domains",
      "platforms"
    ]) &&
    safeReportCount(report.classification.totalEntities) &&
    safeReportCount(report.classification.withLineage) &&
    safeReportCount(report.classification.sensitiveEntities) &&
    report.classification.withLineage <=
      report.classification.totalEntities &&
    report.classification.sensitiveEntities <=
      report.classification.totalEntities &&
    validCountMap(report.classification.domains) &&
    validCountMap(report.classification.platforms) &&
    Array.isArray(report.findings) &&
    report.findings.length <= 10000 &&
    report.findings.every(validAuditFinding) &&
    boundedReportText(report.narrative, 8000) &&
    validModelProvenance(report.modelProvenance) &&
    Array.isArray(report.trace) &&
    report.trace.length <= 32 &&
    report.trace.every(
      (step) =>
        exactKeys(step, ["agent", "produced"]) &&
        boundedReportText(step.agent, 128) &&
        boundedReportText(step.produced, 2000)
    )
  );
}

function validRetiredAuditReport(report) {
  return (
    exactKeys(report, [
      "scanId",
      "classification",
      "findings",
      "narrative",
      "trace"
    ]) &&
    // This mirrors the historical five-key report acceptance contract, including
    // an empty scan id. The report is digest-verified and never returned; it only
    // identifies evidence that must be rerun under the current provenance schema.
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

function verifyRetiredAuditEvidence(
  value,
  expectedDigest,
  expectedExecutionArn,
  reportDigest
) {
  if (
    !record(value) ||
    value.schemaVersion !== "archon.audit-evidence/v1" ||
    value.executionId !== expectedExecutionArn ||
    value.digest !== expectedDigest ||
    value.reportDigest !== reportDigest ||
    !validRetiredAuditReport(value.report) ||
    !record(value.remediation)
  ) {
    return false;
  }
  const { digest: _storedDigest, ...unsigned } = value;
  return digest(unsigned) === expectedDigest && digest(value.report) === reportDigest;
}

function auditCheckpointBindsEvidence(checkpoint, evidence) {
  const remediation = evidence?.remediation;
  if (!record(remediation)) return false;
  if (!checkpoint.requiresApproval) {
    return (
      remediation.disposition === "MANUAL_ONLY" &&
      remediation.reason === checkpoint.manualOnlyReason
    );
  }
  if (
    remediation.disposition !== "ACTIONABLE" ||
    !record(remediation.plan) ||
    !record(remediation.approvalRequest) ||
    remediation.plan.digest !== checkpoint.planDigest ||
    remediation.approvalRequest.approvalId !== checkpoint.approvalId
  ) {
    return false;
  }
  if (
    checkpoint.schemaVersion === "archon.audit-result/v1" &&
    checkpoint.approvalRequestDigest === undefined
  ) {
    return true;
  }
  return (
    remediation.approvalRequest.digest === checkpoint.approvalRequestDigest &&
    remediation.approvalRequest.requestedAt ===
      checkpoint.approvalRequestedAt &&
    remediation.approvalRequest.expiresAt === checkpoint.approvalExpiresAt
  );
}

function assertPublicOutputSafe(value) {
  if (typeof value === "string") {
    if (PUBLIC_CREDENTIAL_PATTERNS.some((pattern) => pattern.test(value))) {
      throw new Error("unsafe public audit value");
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(assertPublicOutputSafe);
    return;
  }
  if (!record(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    const normalized = key.replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
    if (
      FORBIDDEN_PUBLIC_KEYS.has(normalized) ||
      PUBLIC_CREDENTIAL_PATTERNS.some((pattern) => pattern.test(key))
    ) {
      throw new Error("unsafe public audit field");
    }
    assertPublicOutputSafe(entry);
  }
}

function projectPublicBlastRadius(value) {
  if (
    !exactKeys(value, [
      "rootUrn",
      "downstream",
      "maxHops",
      "truncated",
      "impact"
    ]) ||
    !boundedReportText(value.rootUrn, 2048) ||
    !Array.isArray(value.downstream) ||
    value.downstream.length > 10000 ||
    !Number.isSafeInteger(value.maxHops) ||
    value.maxHops < 0 ||
    value.maxHops > 10 ||
    typeof value.truncated !== "boolean" ||
    !["none", "low", "medium", "high", "critical"].includes(value.impact)
  ) {
    throw new Error("invalid public blast radius");
  }
  return {
    rootUrn: value.rootUrn,
    downstream: value.downstream.map((asset) => {
      if (
        !exactKeys(asset, ["urn", "minHops"]) ||
        !boundedReportText(asset.urn, 2048) ||
        !Number.isSafeInteger(asset.minHops) ||
        asset.minHops < 0 ||
        asset.minHops > 10
      ) {
        throw new Error("invalid public impacted asset");
      }
      return { urn: asset.urn, minHops: asset.minHops };
    }),
    maxHops: value.maxHops,
    truncated: value.truncated,
    impact: value.impact
  };
}

function projectExplicitPublicProvenance(value) {
  if (!Array.isArray(value) || value.length > 1000) {
    throw new Error("invalid public provenance");
  }
  return value.map((event) => {
    if (
      !exactKeys(
        event,
        ["source", "runId", "observedAt", "status"],
        ["actor", "value"]
      ) ||
      !boundedReportText(event.source, 512) ||
      !boundedReportText(event.runId, 512) ||
      !instant(event.observedAt) ||
      !["trusted", "conflicting", "observed"].includes(event.status)
    ) {
      throw new Error("invalid public provenance event");
    }
    return {
      source: event.source,
      runId: event.runId,
      observedAt: event.observedAt,
      status: event.status
    };
  });
}

function contradictionProvenance(detail) {
  if (!Array.isArray(detail.values) || detail.values.length > 1000) {
    return undefined;
  }
  const recommendedFactId =
    record(detail.resolution) &&
    boundedReportText(detail.resolution.recommendedFactId, 512)
      ? detail.resolution.recommendedFactId
      : undefined;
  const events = detail.values.map((entry) => {
    if (
      !record(entry) ||
      !boundedReportText(entry.factId, 512) ||
      (entry.source !== null && !boundedReportText(entry.source, 512)) ||
      !instant(entry.createdAt)
    ) {
      throw new Error("invalid contradiction provenance");
    }
    return {
      source: entry.source ?? "unattributed-source",
      runId: entry.factId,
      observedAt: entry.createdAt,
      status:
        entry.factId === recommendedFactId ? "trusted" : "conflicting"
    };
  });
  return events;
}

function projectPublicFinding(finding) {
  const detail = {};
  if (finding.detail.ruleId !== undefined) {
    if (!boundedReportText(finding.detail.ruleId, 128)) {
      throw new Error("invalid public rule id");
    }
    detail.ruleId = finding.detail.ruleId;
  }
  if (finding.detail.rule !== undefined) {
    if (!boundedReportText(finding.detail.rule, 2048)) {
      throw new Error("invalid public rule");
    }
    detail.rule = finding.detail.rule;
  }
  if (finding.detail.attribute !== undefined) {
    if (!boundedReportText(finding.detail.attribute, 512)) {
      throw new Error("invalid public attribute");
    }
    detail.attribute = finding.detail.attribute;
  }
  if (finding.detail.unclassifiedFields !== undefined) {
    if (
      !Array.isArray(finding.detail.unclassifiedFields) ||
      finding.detail.unclassifiedFields.length > 1000 ||
      !finding.detail.unclassifiedFields.every((field) =>
        boundedReportText(field, 1024)
      )
    ) {
      throw new Error("invalid public field list");
    }
    detail.unclassifiedFields = [...finding.detail.unclassifiedFields];
  }
  if (finding.detail.blastRadius !== undefined) {
    detail.blastRadius = projectPublicBlastRadius(
      finding.detail.blastRadius
    );
  }
  if (finding.detail.provenance !== undefined) {
    detail.provenance = projectExplicitPublicProvenance(
      finding.detail.provenance
    );
  } else {
    const derived = contradictionProvenance(finding.detail);
    if (derived !== undefined) detail.provenance = derived;
  }
  const projected = {
    type: finding.type,
    severity: finding.severity,
    subject: finding.subject,
    summary: finding.summary,
    detail,
    ...(finding.recommendation === undefined
      ? {}
      : { recommendation: finding.recommendation })
  };
  assertPublicOutputSafe(projected);
  return projected;
}

function actionableDossierProvenance(dossier) {
  if (!Array.isArray(dossier.provenance) || dossier.provenance.length > 1000) {
    throw new Error("actionable dossier provenance is malformed");
  }
  return dossier.provenance.map((event) => {
    if (
      !record(event) ||
      !boundedReportText(event.sourceKind, 128) ||
      !boundedReportText(event.aspect, 256) ||
      !instant(event.observedAt) ||
      !DIGEST.test(event.valueDigest)
    ) {
      throw new Error("actionable dossier provenance is malformed");
    }
    return {
      source: `${event.sourceKind}:${event.aspect}`,
      runId: event.valueDigest,
      observedAt: event.observedAt,
      status: "trusted"
    };
  });
}

function projectActionableDossier(dossier) {
  const evidenceCount =
    dossier.provenance.length + dossier.blastRadius.downstreamUrns.length + 2;
  const projected = {
    dossierId: dossier.dossierId,
    digest: dossier.digest,
    policyDigest: dossier.policyDigest,
    generatedAt: dossier.createdAt,
    evidenceCount
  };
  if (
    !exactKeys(projected, [
      "dossierId",
      "digest",
      "policyDigest",
      "generatedAt",
      "evidenceCount"
    ]) ||
    !/^dossier-[a-f0-9]{24}$/u.test(projected.dossierId) ||
    !DIGEST.test(projected.digest) ||
    !DIGEST.test(projected.policyDigest) ||
    !instant(projected.generatedAt) ||
    !Number.isSafeInteger(projected.evidenceCount) ||
    projected.evidenceCount < 2 ||
    projected.evidenceCount > 100000
  ) {
    throw new Error("actionable dossier projection is malformed");
  }
  return projected;
}

function projectActionableApproval(dossier, plan, approvalRequest) {
  const projected = {
    approvalId: approvalRequest.approvalId,
    expiresAt: approvalRequest.expiresAt,
    targetField: dossier.target.columnPath,
    proposedTag: plan.action.arguments.tag_urns[0],
    before: [...plan.expectedBefore.tags],
    after: [...plan.expectedAfter.tags],
    planDigest: plan.digest,
    risk: plan.risk
  };
  if (
    !exactKeys(projected, [
      "approvalId",
      "expiresAt",
      "targetField",
      "proposedTag",
      "before",
      "after",
      "planDigest",
      "risk"
    ]) ||
    !/^approval-[a-f0-9]{24}$/u.test(projected.approvalId) ||
    !instant(projected.expiresAt) ||
    !boundedReportText(projected.targetField, 1024) ||
    !boundedReportText(projected.proposedTag, 2048) ||
    !Array.isArray(projected.before) ||
    projected.before.length > 256 ||
    !projected.before.every((tag) => boundedReportText(tag, 2048)) ||
    !Array.isArray(projected.after) ||
    projected.after.length > 256 ||
    !projected.after.every((tag) => boundedReportText(tag, 2048)) ||
    !DIGEST.test(projected.planDigest) ||
    projected.risk !== "low"
  ) {
    throw new Error("actionable approval projection is malformed");
  }
  return projected;
}

async function readAuditEvidence(checkpoint, expectedExecutionArn) {
  const evidence = await readEvidenceObject("audit", checkpoint.evidenceDigest);
  if (checkpoint.schemaVersion === "archon.audit-result/v2") {
    if (
      verifyAuditEvidence(
        evidence,
        checkpoint.evidenceDigest,
        expectedExecutionArn,
        checkpoint.reportDigest
      ) &&
      auditCheckpointBindsEvidence(checkpoint, evidence)
    ) {
      if (checkpoint.requiresApproval) {
        actionableArtifacts(evidence, checkpoint);
      }
      return evidence;
    }
    throw new Error("evidence integrity verification failed");
  }
  if (
    checkpoint.schemaVersion === "archon.audit-result/v1" &&
    verifyRetiredAuditEvidence(
      evidence,
      checkpoint.evidenceDigest,
      expectedExecutionArn,
      checkpoint.reportDigest
    ) &&
    auditCheckpointBindsEvidence(checkpoint, evidence)
  ) {
    // Historical evidence remains immutable and digest-verified, but it predates
    // model-runtime provenance. Returning or inventing a provenance claim would be
    // misleading, so callers receive an explicit rerun-required cutover response.
    throw new RetiredAuditSchemaError();
  }
  throw new Error("evidence integrity verification failed");
}

function projectReport(evidence, checkpoint) {
  const artifacts =
    evidence.remediation.disposition === "ACTIONABLE"
      ? actionableArtifacts(evidence, checkpoint)
      : undefined;
  const report = {
    schemaVersion: "archon.audit-report/v1",
    scanId: evidence.report.scanId,
    classification: {
      totalEntities: evidence.report.classification.totalEntities,
      withLineage: evidence.report.classification.withLineage,
      sensitiveEntities: evidence.report.classification.sensitiveEntities,
      domains: { ...evidence.report.classification.domains },
      platforms: { ...evidence.report.classification.platforms }
    },
    findings: evidence.report.findings.map(projectPublicFinding),
    narrative: evidence.report.narrative,
    modelProvenance: JSON.parse(
      JSON.stringify(evidence.report.modelProvenance)
    ),
    trace: evidence.report.trace.map((step) => ({
      agent: step.agent,
      produced: step.produced
    }))
  };
  assertPublicOutputSafe(report);
  if (!artifacts) return report;

  const { dossier, plan, approvalRequest } = artifacts;
  const finding = report.findings.find(
    (candidate) =>
      record(candidate) &&
      candidate.subject === dossier.finding.subject &&
      record(candidate.detail) &&
      candidate.detail.ruleId === "G6"
  );
  if (!finding) throw new Error("actionable finding is absent from report");
  finding.detail = {
    ...finding.detail,
    provenance: actionableDossierProvenance(dossier),
    dossier: projectActionableDossier(dossier),
    approval: projectActionableApproval(dossier, plan, approvalRequest)
  };
  assertPublicOutputSafe(report);
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
    checkpoint?.schemaVersion !== "archon.audit-result/v2" ||
    checkpoint.requiresApproval !== true ||
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
    approvalRequest.planDigest !== checkpoint.planDigest ||
    approvalRequest.digest !== checkpoint.approvalRequestDigest ||
    approvalRequest.requestedAt !== checkpoint.approvalRequestedAt ||
    approvalRequest.expiresAt !== checkpoint.approvalExpiresAt
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

function runtimeGroupsFrom(claim) {
  if (typeof claim !== "string") return [];
  return claim
    .replace(/[\[\]"]/gu, "")
    .split(/[,\s]+/u)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parseRuntimeIdentity(value) {
  if (
    !exactKeys(value, ["subject", "issuer", "groups"]) ||
    typeof value.subject !== "string" ||
    value.subject.length < 1 ||
    value.subject.length > 512 ||
    /[\x00-\x1f\x7f]/u.test(value.subject) ||
    typeof value.issuer !== "string" ||
    value.issuer.length < 8 ||
    value.issuer.length > 2048 ||
    /[\x00-\x1f\x7f]/u.test(value.issuer) ||
    typeof value.groups !== "string" ||
    value.groups.length > 2048 ||
    /[\x00-\x1f\x7f]/u.test(value.groups)
  ) {
    return { error: response(401, {
      error: "authenticated_runtime_operator_required"
    }) };
  }
  let issuer;
  try {
    issuer = new URL(value.issuer);
  } catch {
    return { error: response(401, {
      error: "authenticated_runtime_operator_required"
    }) };
  }
  if (
    issuer.protocol !== "https:" ||
    issuer.username !== "" ||
    issuer.password !== "" ||
    issuer.search !== "" ||
    issuer.hash !== "" ||
    issuer.toString() !== value.issuer
  ) {
    return { error: response(401, {
      error: "authenticated_runtime_operator_required"
    }) };
  }
  if (!runtimeGroupsFrom(value.groups).includes(runtimeOperatorGroup)) {
    return { error: response(403, {
      error: "runtime_operator_role_required"
    }) };
  }
  return {
    identity: {
      subject: value.subject,
      issuer: value.issuer
    },
    ownerDigest: digest({
      issuer: value.issuer,
      subject: value.subject
    })
  };
}

function runtimeTableName() {
  if (
    typeof runtimeSessionTable !== "string" ||
    runtimeSessionTable.length < 1 ||
    runtimeSessionTable.length > 255
  ) {
    throw new Error("runtime session table is not configured");
  }
  return runtimeSessionTable;
}

function coreTableName() {
  if (
    typeof coreLeaseTable !== "string" ||
    coreLeaseTable.length < 1 ||
    coreLeaseTable.length > 255
  ) {
    throw new Error("Core lease table is not configured");
  }
  return coreLeaseTable;
}

function validateRuntimeBindingDocument(value) {
  if (
    !exactKeys(value, [
      "schemaVersion",
      "profileId",
      "generation",
      "capabilityDigest",
      "resolution",
      "boundAt",
      "leaseExpiresAt"
    ]) ||
    value.schemaVersion !== "archon.runtime-binding/v1" ||
    !["cloud", "core"].includes(value.profileId) ||
    typeof value.generation !== "string" ||
    !RUNTIME_GENERATION.test(value.generation) ||
    typeof value.capabilityDigest !== "string" ||
    !DIGEST.test(value.capabilityDigest) ||
    !["auto", "explicit"].includes(value.resolution) ||
    !instant(value.boundAt) ||
    !instant(value.leaseExpiresAt)
  ) {
    throw new Error("invalid stored runtime binding");
  }
  const boundAt = Date.parse(value.boundAt);
  const leaseExpiresAt = Date.parse(value.leaseExpiresAt);
  if (
    leaseExpiresAt <= boundAt ||
    leaseExpiresAt - boundAt > 2 * 60 * 60_000
  ) {
    throw new Error("invalid stored runtime binding lease");
  }
  return value;
}

function parseStoredRuntimeSession(item, options = {}) {
  const payloadText = stringAttribute(item, "payload");
  const itemRevision = numberAttribute(item, "revision");
  const principalHash = stringAttribute(item, "principalHash");
  if (
    !payloadText ||
    Buffer.byteLength(payloadText, "utf8") > 16 * 1024 ||
    itemRevision === undefined ||
    !principalHash ||
    !DIGEST.test(principalHash)
  ) {
    throw new Error("runtime session item is malformed");
  }
  let value;
  try {
    value = JSON.parse(payloadText);
  } catch {
    throw new Error("runtime session payload is not JSON");
  }
  if (
    !exactKeys(value, [
      "schemaVersion",
      "sessionId",
      "requestedProfile",
      "binding",
      "state",
      "createdAt",
      "updatedAt",
      "lastActivityAt",
      "idleExpiresAt",
      "hardExpiresAt",
      "revision",
      "endReason",
      "failureCode"
    ]) ||
    value.schemaVersion !== "archon.runtime-session/v1" ||
    !RUNTIME_SESSION_ID.test(value.sessionId) ||
    !["auto", "cloud", "core"].includes(value.requestedProfile) ||
    !RUNTIME_STATES.includes(value.state) ||
    !instant(value.createdAt) ||
    !instant(value.updatedAt) ||
    !instant(value.lastActivityAt) ||
    !instant(value.idleExpiresAt) ||
    !instant(value.hardExpiresAt) ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 0 ||
    value.revision !== itemRevision
  ) {
    throw new Error("stored runtime session has an invalid contract");
  }
  const binding = validateRuntimeBindingDocument(value.binding);
  if (
    value.createdAt !== binding.boundAt ||
    value.hardExpiresAt !== binding.leaseExpiresAt ||
    Date.parse(value.updatedAt) < Date.parse(value.createdAt) ||
    Date.parse(value.lastActivityAt) < Date.parse(value.createdAt) ||
    Date.parse(value.lastActivityAt) > Date.parse(value.updatedAt) ||
    Date.parse(value.idleExpiresAt) <= Date.parse(value.lastActivityAt) ||
    Date.parse(value.idleExpiresAt) > Date.parse(value.hardExpiresAt) ||
    (value.requestedProfile === "auto" &&
      binding.resolution !== "auto") ||
    (value.requestedProfile !== "auto" &&
      (binding.resolution !== "explicit" ||
        binding.profileId !== value.requestedProfile))
  ) {
    throw new Error("stored runtime session binding is inconsistent");
  }
  if (
    options.ownerDigest !== undefined &&
    principalHash !== options.ownerDigest
  ) {
    return { error: response(403, {
      error: "runtime_session_owner_mismatch"
    }) };
  }
  if (options.requireActive === true) {
    const currentTime = Date.parse(options.now);
    if (
      value.state !== "ACTIVE" ||
      currentTime >= Date.parse(value.idleExpiresAt) ||
      currentTime >= Date.parse(value.hardExpiresAt)
    ) {
      return { error: response(409, {
        error: "runtime_session_not_active"
      }) };
    }
  }
  return {
    session: { ...value, binding },
    principalHash
  };
}

async function readRuntimeSession(sessionId) {
  if (typeof sessionId !== "string" || !RUNTIME_SESSION_ID.test(sessionId)) {
    return { error: response(400, {
      error: "invalid_runtime_session_id"
    }) };
  }
  const result = await dynamodb.send(
    new GetItemCommand({
      TableName: runtimeTableName(),
      Key: {
        pk: { S: "SESSION#" + sessionId },
        sk: { S: "RUNTIME" }
      },
      ConsistentRead: true,
      ProjectionExpression: "payload, revision, principalHash"
    })
  );
  if (!result.Item) {
    return { error: response(404, {
      error: "runtime_session_not_found"
    }) };
  }
  return { item: result.Item };
}

function parseStartV2Body(input) {
  let body = input;
  let text;
  if (record(input)) {
    text = JSON.stringify(input);
  } else if (typeof input === "string") {
    text = input;
    try {
      body = JSON.parse(text);
    } catch {
      return { error: response(400, { error: "invalid_json" }) };
    }
  } else {
    return { error: response(400, { error: "invalid_body" }) };
  }
  if (Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES) {
    return { error: response(413, { error: "request_too_large" }) };
  }
  if (
    !record(body) ||
    Object.keys(body).some(
      (key) => !["query", "mode", "sessionId"].includes(key)
    ) ||
    typeof body.sessionId !== "string" ||
    !RUNTIME_SESSION_ID.test(body.sessionId)
  ) {
    return { error: response(400, {
      error: "invalid_runtime_control_request"
    }) };
  }
  const audit = parseStartBody({
    query: body.query,
    ...(body.mode === undefined ? {} : { mode: body.mode })
  });
  if (audit.error) return audit;
  return {
    query: audit.query,
    mode: audit.mode,
    sessionId: body.sessionId
  };
}

async function readCoreLeaseForRuntime(sessionId) {
  const result = await dynamodb.send(
    new GetItemCommand({
      TableName: coreTableName(),
      Key: {
        pk: { S: "CORE#LEASE" },
        sk: { S: "CURRENT" }
      },
      ConsistentRead: true,
      ProjectionExpression: "sessionId, #state, revision",
      ExpressionAttributeNames: { "#state": "state" }
    })
  );
  const state = stringAttribute(result.Item, "state");
  const currentSessionId = stringAttribute(result.Item, "sessionId");
  const revision = numberAttribute(result.Item, "revision");
  if (
    state !== "READY" ||
    currentSessionId !== sessionId ||
    revision === undefined
  ) {
    return { error: response(409, {
      error: "runtime_identity_mismatch"
    }) };
  }
  return { revision };
}

async function dispatchCoreActivity(session) {
  if (session.binding.profileId !== "core") return {};
  const lease = await readCoreLeaseForRuntime(session.sessionId);
  if (lease.error) return lease;
  if (
    typeof coreSessionStateMachineArn !== "string" ||
    !coreSessionStateMachineArn.includes(":stateMachine:")
  ) {
    throw new Error("Core session state machine is not configured");
  }
  await stepFunctions.send(
    new StartExecutionCommand({
      stateMachineArn: coreSessionStateMachineArn,
      name: (
        "activity-" +
        session.sessionId +
        "-" +
        String(lease.revision)
      ).slice(0, 80),
      input: JSON.stringify({
        schema: "archon.core-runtime-command/v1",
        action: "ACTIVITY",
        sessionId: session.sessionId,
        expectedRevision: lease.revision,
        binding: session.binding
      })
    })
  );
  return {};
}

async function recordRuntimeActivity(session, at) {
  const core = await dispatchCoreActivity(session);
  if (core.error) return core;
  const hardExpiresAt = Date.parse(session.hardExpiresAt);
  const next = {
    ...session,
    updatedAt: at,
    lastActivityAt: at,
    idleExpiresAt: new Date(
      Math.min(Date.parse(at) + 30 * 60_000, hardExpiresAt)
    ).toISOString(),
    revision: session.revision + 1
  };
  await dynamodb.send(
    new UpdateItemCommand({
      TableName: runtimeTableName(),
      Key: {
        pk: { S: "SESSION#" + session.sessionId },
        sk: { S: "RUNTIME" }
      },
      UpdateExpression: "SET payload = :payload, revision = :next",
      ConditionExpression: "revision = :expected",
      ExpressionAttributeValues: {
        ":payload": { S: JSON.stringify(next) },
        ":next": { N: String(next.revision) },
        ":expected": { N: String(session.revision) }
      }
    })
  );
  return { session: next };
}

function runtimeEvidenceFor(auditId, session, recordedAt) {
  const payload = {
    schemaVersion: "archon.runtime-binding-evidence/v1",
    auditId,
    runtimeSessionId: session.sessionId,
    profileId: session.binding.profileId,
    generation: session.binding.generation,
    capabilityDigest: session.binding.capabilityDigest,
    bindingDigest: digest(session.binding),
    sessionRevision: session.revision,
    recordedAt
  };
  return {
    ...payload,
    digest: digest(payload)
  };
}

function verifyRuntimeEvidence(value, auditId) {
  return (
    exactKeys(value, [
      "schemaVersion",
      "auditId",
      "runtimeSessionId",
      "profileId",
      "generation",
      "capabilityDigest",
      "bindingDigest",
      "sessionRevision",
      "recordedAt",
      "digest"
    ]) &&
    value.schemaVersion === "archon.runtime-binding-evidence/v1" &&
    value.auditId === auditId &&
    RUNTIME_SESSION_ID.test(value.runtimeSessionId) &&
    ["cloud", "core"].includes(value.profileId) &&
    typeof value.generation === "string" &&
    RUNTIME_GENERATION.test(value.generation) &&
    DIGEST.test(value.capabilityDigest) &&
    DIGEST.test(value.bindingDigest) &&
    Number.isSafeInteger(value.sessionRevision) &&
    value.sessionRevision >= 1 &&
    instant(value.recordedAt) &&
    DIGEST.test(value.digest) &&
    digest(without(value, ["digest"])) === value.digest
  );
}

async function putRuntimeEvidence(evidence, principalHash) {
  await dynamodb.send(
    new PutItemCommand({
      TableName: runtimeTableName(),
      Item: {
        pk: { S: "AUDIT#" + evidence.auditId },
        sk: { S: "RUNTIME" },
        payload: { S: JSON.stringify(evidence) },
        principalHash: { S: principalHash },
        expiresAt: {
          N: String(
            Math.floor(Date.parse(evidence.recordedAt) / 1000) +
              DECIDED_RETENTION_SECONDS
          )
        }
      },
      ConditionExpression: "attribute_not_exists(pk)"
    })
  );
}

async function readRuntimeEvidence(auditId) {
  const result = await dynamodb.send(
    new GetItemCommand({
      TableName: runtimeTableName(),
      Key: {
        pk: { S: "AUDIT#" + auditId },
        sk: { S: "RUNTIME" }
      },
      ConsistentRead: true,
      ProjectionExpression: "payload"
    })
  );
  const text = stringAttribute(result.Item, "payload");
  if (!text || Buffer.byteLength(text, "utf8") > 16 * 1024) {
    return { error: response(404, {
      error: "runtime_bound_audit_not_found"
    }) };
  }
  let evidence;
  try {
    evidence = JSON.parse(text);
  } catch {
    throw new Error("runtime evidence is not JSON");
  }
  if (!verifyRuntimeEvidence(evidence, auditId)) {
    throw new Error("runtime evidence integrity verification failed");
  }
  return { evidence };
}

async function startV2(body, identity) {
  const parsedIdentity = parseRuntimeIdentity(identity);
  if (parsedIdentity.error) return parsedIdentity.error;
  const parsed = parseStartV2Body(body);
  if (parsed.error) return parsed.error;
  const submittedAt = new Date().toISOString();
  const loaded = await readRuntimeSession(parsed.sessionId);
  if (loaded.error) return loaded.error;
  const stored = parseStoredRuntimeSession(loaded.item, {
    ownerDigest: parsedIdentity.ownerDigest,
    requireActive: true,
    now: submittedAt
  });
  if (stored.error) return stored.error;
  const touched = await recordRuntimeActivity(
    stored.session,
    submittedAt
  );
  if (touched.error) return touched.error;

  const auditId = randomBytes(32).toString("hex");
  const evidence = runtimeEvidenceFor(
    auditId,
    touched.session,
    submittedAt
  );
  await putRuntimeEvidence(evidence, parsedIdentity.ownerDigest);
  const input = {
    schemaVersion: "archon.audit-request/v1",
    requestId: auditId,
    requestedAt: submittedAt,
    mode: parsed.mode ?? "GOVERNED",
    query: parsed.query
  };
  await stepFunctions.send(
    new StartExecutionCommand({
      stateMachineArn,
      name: auditId,
      input: JSON.stringify(input)
    })
  );
  const pollUrl = "/api/control-loops-v2/" + auditId;
  return response(
    202,
    {
      schemaVersion: "archon.control-loop-start/v2",
      auditId,
      status: "RUNNING",
      pollUrl,
      submittedAt,
      runtimeEvidence: evidence
    },
    {
      location: pollUrl,
      retryAfter: "2"
    }
  );
}

async function statusV2(auditId) {
  if (typeof auditId !== "string" || !AUDIT_ID.test(auditId)) {
    return response(400, { error: "invalid_audit_id" });
  }
  const runtime = await readRuntimeEvidence(auditId);
  if (runtime.error) return runtime.error;
  const loaded = await readRuntimeSession(
    runtime.evidence.runtimeSessionId
  );
  if (loaded.error) return loaded.error;
  const stored = parseStoredRuntimeSession(loaded.item);
  if (stored.error) return stored.error;
  if (
    stored.session.binding.profileId !==
      runtime.evidence.profileId ||
    stored.session.binding.generation !==
      runtime.evidence.generation ||
    stored.session.binding.capabilityDigest !==
      runtime.evidence.capabilityDigest ||
    digest(stored.session.binding) !==
      runtime.evidence.bindingDigest
  ) {
    throw new Error("runtime binding changed after audit start");
  }
  const base = await status(auditId);
  if (base.statusCode !== 200) return base;
  return response(200, {
    schemaVersion: "archon.control-loop-status/v2",
    ...without(base.payload, ["schemaVersion"]),
    runtimeEvidence: runtime.evidence
  });
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
          report: projectReport(evidence, checkpoint)
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
      exactKeys(event, [
        "operation",
        "requestId",
        "body",
        "identity"
      ]) &&
      event.operation === "startV2"
    ) {
      return await startV2(event.body, event.identity);
    }
    if (
      exactKeys(event, ["operation", "requestId", "auditId"]) &&
      event.operation === "statusV2"
    ) {
      return await statusV2(event.auditId);
    }
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
  } catch (error) {
    if (error?.name === "ConditionalCheckFailedException") {
      return response(409, { error: "runtime_session_conflict" });
    }
    if (error instanceof RetiredAuditSchemaError) {
      return response(410, {
        error: "audit_schema_retired",
        rerunRequired: true
      });
    }
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
