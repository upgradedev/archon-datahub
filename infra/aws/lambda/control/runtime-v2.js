"use strict";

const { createHash, randomBytes } = require("node:crypto");
const {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
  TransactWriteItemsCommand
} = require("@aws-sdk/client-dynamodb");
const { SFNClient, StartExecutionCommand } = require("@aws-sdk/client-sfn");
const { KMSClient, SignCommand } = require("@aws-sdk/client-kms");

const dynamodb = new DynamoDBClient({});
const stepFunctions = new SFNClient({});
const kmsClient = new KMSClient({});
const runtimeSessionTable = process.env.RUNTIME_SESSION_TABLE;
const coreLeaseTable = process.env.CORE_LEASE_TABLE;
const runtimeJobTable = process.env.RUNTIME_JOB_TABLE || coreLeaseTable;
const coreSessionStateMachineArn = process.env.CORE_SESSION_STATE_MACHINE_ARN;
const runtimeOperatorGroup = process.env.RUNTIME_OPERATOR_GROUP || "archon-runtime-operators";
const runtimeApproverGroup = process.env.RUNTIME_APPROVER_GROUP || "archon-approvers";
const expectedCognitoIssuer = process.env.EXPECTED_COGNITO_ISSUER;
const configuredStage = process.env.ARCHON_STAGE;
const mutationSigningKeyArn = process.env.MUTATION_SIGNING_KEY_ARN;
const mutationSigningAlgorithm = process.env.MUTATION_SIGNING_ALGORITHM || "ECDSA_SHA_256";
const configuredDatasetUrn = process.env.ARCHON_AGENT_STACK_DATASET_URN;
const configuredQuestion = process.env.ARCHON_ANALYTICS_QUESTION;
const configuredColumnPath = process.env.ARCHON_GOVERNED_COLUMN_PATH;

const AUDIT_ID = /^[a-f0-9]{64}$/u;
const SESSION_ID = /^rs_[A-Za-z0-9_-]{43}$/u;
const JOB_ID = /^job_[A-Za-z0-9_-]{22}$/u;
const RUN_HANDLE = /^run_[A-Za-z0-9_-]{80,2048}$/u;
const GENERATION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const DATASET_URN = /^urn:li:dataset:\(.{1,900}\)$/u;
const RFC3339 = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?Z$/u;
const CAPABILITY_KEYS = ["mcpRead", "mcpGovernedWrite", "agentContextKit", "dataHubSkills", "analyticsAgent"];
const SESSION_STATES = ["STARTING", "ACTIVE", "STOPPING", "STOPPED", "EXPIRED", "FAILED"];
const RETENTION_SECONDS = 90 * 24 * 60 * 60;
const MAX_BODY_BYTES = 4096;
const MAX_ITEM_BYTES = 350 * 1024;
const HEALTH_MAX_AGE_MS = 2 * 60 * 1000;
const PII_TAG = "urn:li:tag:PII";
const MUTATION_CANONICALIZATION = "archon.sorted-json-utf8/v1";
const KMS_KEY_ARN = /^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:\d{12}:key\/[0-9a-f-]{36}$/u;
const STAGE = /^[a-z][a-z0-9-]{0,31}$/u;
const PUBLIC_FORBIDDEN_KEY = /(?:access.?token|api.?key|authorization|client.?secret|cookie|credential|id.?token|jwt|password|private.?key|refresh.?token|run.?handle|secret|session.?token|task.?token)/iu;
const PUBLIC_CREDENTIAL = /(?:bedrock-api-key-[A-Za-z0-9_+/=-]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|Bearer\s+[A-Za-z0-9._~+/=-]{12,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/iu;

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function exactKeys(value, required, optional) {
  if (!record(value)) return false;
  const allowed = new Set(required.concat(optional || []));
  const keys = Object.keys(value);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) && keys.every((key) => allowed.has(key));
}
function instant(value) {
  return typeof value === "string" && value.length <= 64 && RFC3339.test(value) && Number.isFinite(Date.parse(value));
}
function boundedString(value, maximum) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum && !/[\u0000-\u001F\u007F]/u.test(value);
}
function canonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite JSON number");
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  if (!record(value)) throw new Error("non-JSON value");
  return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonicalize(value[key])).join(",") + "}";
}
function digest(value) {
  return "sha256:" + createHash("sha256").update(canonicalize(value), "utf8").digest("hex");
}
function without(value, keys) {
  return Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));
}
function same(left, right) {
  try { return canonicalize(left) === canonicalize(right); } catch { return false; }
}
function response(statusCode, payload, extraHeaders) {
  return {
    statusCode,
    headers: {
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      "content-type": "application/json; charset=utf-8",
      "cross-origin-resource-policy": "same-origin",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      ...(extraHeaders || {})
    },
    payload
  };
}
function tableName(label, value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 255) throw new Error(label + " is not configured");
  return value;
}
function stringAttribute(item, key) {
  const value = item && item[key];
  return value && typeof value.S === "string" ? value.S : undefined;
}
function numberAttribute(item, key) {
  const value = item && item[key];
  if (!value || typeof value.N !== "string") return undefined;
  const parsed = Number(value.N);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}
function toAttribute(value, depth) {
  const level = depth || 0;
  if (level > 14) throw new Error("DynamoDB value is too deep");
  if (value === null) return { NULL: true };
  if (typeof value === "string") return { S: value };
  if (typeof value === "boolean") return { BOOL: value };
  if (typeof value === "number" && Number.isFinite(value)) return { N: String(value) };
  if (Array.isArray(value)) return { L: value.map((item) => toAttribute(item, level + 1)) };
  if (record(value)) return { M: Object.fromEntries(Object.entries(value).map(([key, item]) => [key, toAttribute(item, level + 1)])) };
  throw new Error("unsupported DynamoDB value");
}
function fromAttribute(value, depth) {
  const level = depth || 0;
  if (!record(value) || level > 14 || Object.keys(value).length !== 1) throw new Error("invalid DynamoDB value");
  if (typeof value.S === "string") return value.S;
  if (typeof value.BOOL === "boolean") return value.BOOL;
  if (value.NULL === true) return null;
  if (typeof value.N === "string") {
    const parsed = Number(value.N);
    if (!Number.isFinite(parsed)) throw new Error("invalid DynamoDB number");
    return parsed;
  }
  if (Array.isArray(value.L)) return value.L.map((item) => fromAttribute(item, level + 1));
  if (record(value.M)) return Object.fromEntries(Object.entries(value.M).map(([key, item]) => [key, fromAttribute(item, level + 1)]));
  throw new Error("unsupported DynamoDB value");
}
function fromAttributeMap(value) {
  if (!record(value)) throw new Error("invalid DynamoDB item");
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, fromAttribute(item, 0)]));
}
function capabilityDocument(value) {
  if (!exactKeys(value, CAPABILITY_KEYS) || CAPABILITY_KEYS.some((key) => typeof value[key] !== "boolean")) throw new Error("invalid runtime capabilities");
  return Object.fromEntries(CAPABILITY_KEYS.map((key) => [key, value[key]]));
}
function capabilityDigest(profileId, generation, capabilities) {
  return digest({ schemaVersion: "archon.runtime-capabilities/v1", profileId, generation, capabilities: capabilityDocument(capabilities) });
}
function runtimeGroups(value) {
  if (Array.isArray(value)) return value.filter((group) => typeof group === "string");
  if (typeof value !== "string") return [];
  const trimmed = value.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) return parsed.filter((group) => typeof group === "string");
    } catch {
      return trimmed.slice(1, -1).split(",").map((group) => group.trim()).filter(Boolean);
    }
  }
  return trimmed.split(",").map((group) => group.trim()).filter(Boolean);
}
function configuredIssuer() {
  if (!boundedString(expectedCognitoIssuer, 2048)) throw new Error("expected Cognito issuer is not configured");
  let issuer;
  try { issuer = new URL(expectedCognitoIssuer); } catch { throw new Error("expected Cognito issuer is invalid"); }
  if (issuer.protocol !== "https:" || issuer.username || issuer.password || issuer.search || issuer.hash ||
      !/^cognito-idp\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$/u.test(issuer.hostname) ||
      !/^\/[a-z0-9-]+_[A-Za-z0-9]+$/u.test(issuer.pathname) || issuer.toString() !== expectedCognitoIssuer) {
    throw new Error("expected Cognito issuer is invalid");
  }
  return expectedCognitoIssuer;
}
function parseIdentity(value, requiredGroup) {
  if (!exactKeys(value, ["subject", "issuer", "groups"]) || !boundedString(value.subject, 512) || !boundedString(value.issuer, 2048)) {
    return { error: response(401, { error: "authenticated_runtime_operator_required" }) };
  }
  if (!boundedString(runtimeOperatorGroup, 128) || !boundedString(runtimeApproverGroup, 128) ||
      runtimeOperatorGroup === runtimeApproverGroup || ![runtimeOperatorGroup, runtimeApproverGroup].includes(requiredGroup)) {
    throw new Error("runtime authority groups are invalid");
  }
  let issuer;
  try { issuer = new URL(value.issuer); } catch { return { error: response(401, { error: "authenticated_runtime_operator_required" }) }; }
  if (issuer.protocol !== "https:" || issuer.username || issuer.password || issuer.search || issuer.hash || issuer.toString() !== value.issuer) {
    return { error: response(401, { error: "authenticated_runtime_operator_required" }) };
  }
  if (value.issuer !== configuredIssuer()) {
    return { error: response(403, { error: "runtime_identity_issuer_mismatch" }) };
  }
  if (!runtimeGroups(value.groups).includes(requiredGroup)) {
    return {
      error: response(403, {
        error: requiredGroup === runtimeApproverGroup
          ? "runtime_approver_role_required"
          : "runtime_operator_role_required"
      })
    };
  }
  return { identity: { subject: value.subject, issuer: value.issuer }, ownerDigest: digest({ issuer: value.issuer, subject: value.subject }) };
}
function validateBinding(value) {
  if (!exactKeys(value, ["schemaVersion", "profileId", "generation", "capabilityDigest", "resolution", "boundAt", "leaseExpiresAt"]) ||
      value.schemaVersion !== "archon.runtime-binding/v1" || !["cloud", "core"].includes(value.profileId) || !GENERATION.test(value.generation) ||
      !DIGEST.test(value.capabilityDigest) || !["auto", "explicit"].includes(value.resolution) || !instant(value.boundAt) || !instant(value.leaseExpiresAt) ||
      Date.parse(value.leaseExpiresAt) <= Date.parse(value.boundAt) || Date.parse(value.leaseExpiresAt) - Date.parse(value.boundAt) > 2 * 60 * 60 * 1000) {
    throw new Error("invalid stored runtime binding");
  }
  return value;
}
function parseSessionItem(item, ownerDigest, requireActive, now) {
  const payloadText = stringAttribute(item, "payload");
  const revision = numberAttribute(item, "revision");
  const principalHash = stringAttribute(item, "principalHash");
  if (!payloadText || Buffer.byteLength(payloadText, "utf8") > 16 * 1024 || revision === undefined || !DIGEST.test(principalHash || "")) throw new Error("runtime session item is malformed");
  if (ownerDigest && principalHash !== ownerDigest) return { error: response(403, { error: "runtime_session_owner_mismatch" }) };
  let session;
  try { session = JSON.parse(payloadText); } catch { throw new Error("runtime session payload is not JSON"); }
  if (!exactKeys(session, ["schemaVersion", "sessionId", "requestedProfile", "binding", "state", "createdAt", "updatedAt", "lastActivityAt", "idleExpiresAt", "hardExpiresAt", "revision", "endReason", "failureCode"]) ||
      session.schemaVersion !== "archon.runtime-session/v1" || !SESSION_ID.test(session.sessionId) || !["auto", "cloud", "core"].includes(session.requestedProfile) ||
      !SESSION_STATES.includes(session.state) || !instant(session.createdAt) || !instant(session.updatedAt) || !instant(session.lastActivityAt) || !instant(session.idleExpiresAt) ||
      !instant(session.hardExpiresAt) || !Number.isSafeInteger(session.revision) || session.revision !== revision) throw new Error("stored runtime session has an invalid contract");
  const binding = validateBinding(session.binding);
  if (session.createdAt !== binding.boundAt || session.hardExpiresAt !== binding.leaseExpiresAt || Date.parse(session.updatedAt) < Date.parse(session.createdAt) ||
      Date.parse(session.lastActivityAt) < Date.parse(session.createdAt) || Date.parse(session.lastActivityAt) > Date.parse(session.updatedAt) ||
      Date.parse(session.idleExpiresAt) <= Date.parse(session.lastActivityAt) || Date.parse(session.idleExpiresAt) > Date.parse(session.hardExpiresAt) ||
      (session.requestedProfile === "auto" && binding.resolution !== "auto") ||
      (session.requestedProfile !== "auto" && (binding.resolution !== "explicit" || binding.profileId !== session.requestedProfile))) throw new Error("stored runtime session binding is inconsistent");
  if (requireActive && (session.state !== "ACTIVE" || Date.parse(now) >= Date.parse(session.idleExpiresAt) || Date.parse(now) >= Date.parse(session.hardExpiresAt))) {
    return { error: response(409, { error: "runtime_session_not_active" }) };
  }
  return { session: { ...session, binding }, principalHash };
}
async function getItem(table, pk, sk, projection) {
  const result = await dynamodb.send(new GetItemCommand({
    TableName: table,
    Key: { pk: { S: pk }, sk: { S: sk } },
    ConsistentRead: true,
    ...(projection ? { ProjectionExpression: projection } : {})
  }));
  return result.Item;
}
async function readSession(sessionId, ownerDigest, requireActive, now) {
  if (!SESSION_ID.test(sessionId || "")) return { error: response(400, { error: "invalid_runtime_session_id" }) };
  const item = await getItem(tableName("runtime session table", runtimeSessionTable), "SESSION#" + sessionId, "RUNTIME", "payload, revision, principalHash");
  if (!item) return { error: response(404, { error: "runtime_session_not_found" }) };
  return parseSessionItem(item, ownerDigest, requireActive, now);
}
function healthCapabilities(item, session, now) {
  const profileId = session.binding.profileId;
  const health = fromAttributeMap(item || {});
  const coreIdentityValid = profileId !== "core" || health.sessionId === session.sessionId;
  const cloudIdentityValid = profileId !== "cloud" || health.sessionId === undefined || health.sessionId === null;
  if (health.pk !== "RUNTIME#" + profileId || health.sk !== "HEALTH" || health.status !== "READY" ||
      !coreIdentityValid || !cloudIdentityValid || health.generation !== session.binding.generation ||
      health.capabilityDigest !== session.binding.capabilityDigest || !instant(health.checkedAt) ||
      Date.parse(health.checkedAt) > Date.parse(now) || Date.parse(now) - Date.parse(health.checkedAt) > HEALTH_MAX_AGE_MS) {
    throw new Error("selected runtime health identity mismatch");
  }
  const capabilities = capabilityDocument(health.capabilities);
  if (CAPABILITY_KEYS.some((key) => capabilities[key] !== true) ||
      capabilityDigest(profileId, health.generation, capabilities) !== health.capabilityDigest) {
    throw new Error("selected runtime closed-loop capabilities are incomplete");
  }
  return capabilities;
}
async function readRuntimeCapabilities(session, now) {
  const profileId = session.binding.profileId;
  const sourceTable = profileId === "cloud" ? runtimeSessionTable : coreLeaseTable;
  const item = await getItem(tableName("runtime health table", sourceTable), "RUNTIME#" + profileId, "HEALTH");
  if (!item) return { error: response(409, { error: "runtime_runner_unavailable" }) };
  try { return { capabilities: healthCapabilities(item, session, now) }; }
  catch { return { error: response(409, { error: "runtime_identity_mismatch" }) }; }
}
async function recordActivity(session, at) {
  if (session.binding.profileId === "core") {
    const leaseItem = await getItem(tableName("Core lease table", coreLeaseTable), "CORE#LEASE", "CURRENT");
    const lease = fromAttributeMap(leaseItem || {});
    if (lease.sessionId !== session.sessionId || lease.state !== "READY" || !Number.isSafeInteger(lease.revision)) {
      return { error: response(409, { error: "runtime_identity_mismatch" }) };
    }
    if (typeof coreSessionStateMachineArn !== "string" || !coreSessionStateMachineArn.includes(":stateMachine:")) {
      throw new Error("Core session state machine is not configured");
    }
    await stepFunctions.send(new StartExecutionCommand({
      stateMachineArn: coreSessionStateMachineArn,
      name: ("activity-" + session.sessionId + "-" + String(lease.revision)).slice(0, 80),
      input: JSON.stringify({ schema: "archon.core-runtime-command/v1", action: "ACTIVITY", sessionId: session.sessionId, expectedRevision: lease.revision, binding: session.binding })
    }));
  }
  const next = { ...session, updatedAt: at, lastActivityAt: at, idleExpiresAt: new Date(Math.min(Date.parse(at) + 30 * 60 * 1000, Date.parse(session.hardExpiresAt))).toISOString(), revision: session.revision + 1 };
  await dynamodb.send(new UpdateItemCommand({
    TableName: tableName("runtime session table", runtimeSessionTable),
    Key: { pk: { S: "SESSION#" + session.sessionId }, sk: { S: "RUNTIME" } },
    UpdateExpression: "SET payload = :payload, revision = :next",
    ConditionExpression: "revision = :expected",
    ExpressionAttributeValues: { ":payload": { S: JSON.stringify(next) }, ":next": { N: String(next.revision) }, ":expected": { N: String(session.revision) } }
  }));
  return { session: next };
}
function configuredInputs() {
  if (!DATASET_URN.test(configuredDatasetUrn || "") || !boundedString(configuredQuestion, 512) || !boundedString(configuredColumnPath, 512)) throw new Error("agent stack demo inputs are not configured");
  return { datasetUrn: configuredDatasetUrn, question: configuredQuestion, columnPath: configuredColumnPath };
}
function parseStartBody(input) {
  let body = input;
  let text;
  if (record(input)) text = JSON.stringify(input);
  else if (typeof input === "string") {
    text = input;
    try { body = JSON.parse(input); } catch { return { error: response(400, { error: "invalid_json" }) }; }
  } else return { error: response(400, { error: "invalid_body" }) };
  if (Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES) return { error: response(413, { error: "request_too_large" }) };
  if (!exactKeys(body, ["query", "question", "datasetUrn", "sessionId"], ["mode"]) || !SESSION_ID.test(body.sessionId || "") ||
      !boundedString(body.query, 256) || !boundedString(body.question, 512) || !DATASET_URN.test(body.datasetUrn || "") ||
      (body.mode !== undefined && !["READ_ONLY", "GOVERNED"].includes(body.mode))) return { error: response(400, { error: "invalid_runtime_control_request" }) };
  if (body.query !== body.query.trim() || /[*?]/u.test(body.query) || body.query === "{}") return { error: response(400, { error: "query_must_be_narrow" }) };
  const expected = configuredInputs();
  if (body.query !== expected.datasetUrn || body.datasetUrn !== expected.datasetUrn || body.question !== expected.question) return { error: response(400, { error: "request_outside_demo_scope" }) };
  return { query: body.query, question: body.question, datasetUrn: body.datasetUrn, sessionId: body.sessionId, mode: body.mode || "GOVERNED" };
}
function jobId(kind, auditId) {
  const suffix = createHash("sha256").update(kind + ":" + auditId, "utf8").digest().subarray(0, 16).toString("base64url");
  const value = "job_" + suffix;
  if (!JOB_ID.test(value)) throw new Error("invalid derived job id");
  return value;
}
function runtimeEvidence(auditId, session, capabilities, recordedAt) {
  const payload = {
    schemaVersion: "archon.runtime-binding-evidence/v2",
    auditId,
    runtimeSessionId: session.sessionId,
    runtimeBinding: session.binding,
    capabilities: capabilityDocument(capabilities),
    bindingDigest: digest(session.binding),
    sessionRevision: session.revision,
    recordedAt
  };
  return { ...payload, digest: digest(payload) };
}
function verifyRuntimeEvidence(value, auditId) {
  if (!exactKeys(value, ["schemaVersion", "auditId", "runtimeSessionId", "runtimeBinding", "capabilities", "bindingDigest", "sessionRevision", "recordedAt", "digest"]) ||
      value.schemaVersion !== "archon.runtime-binding-evidence/v2" || value.auditId !== auditId || !SESSION_ID.test(value.runtimeSessionId || "") ||
      !DIGEST.test(value.bindingDigest || "") || !Number.isSafeInteger(value.sessionRevision) || value.sessionRevision < 1 || !instant(value.recordedAt) ||
      !DIGEST.test(value.digest || "") || digest(without(value, ["digest"])) !== value.digest) return false;
  try {
    const binding = validateBinding(value.runtimeBinding);
    const capabilities = capabilityDocument(value.capabilities);
    return ["cloud", "core"].includes(binding.profileId) && value.bindingDigest === digest(binding) && CAPABILITY_KEYS.every((key) => capabilities[key] === true) &&
      capabilityDigest(binding.profileId, binding.generation, capabilities) === binding.capabilityDigest;
  } catch { return false; }
}
function runtimeJobItem(session, job, operation, request, evidence, submittedAt) {
  return {
    pk: { S: "SESSION#" + session.sessionId },
    sk: { S: "JOB#" + job },
    schema: { S: "archon.runtime-bound-job/v2" },
    profileId: { S: session.binding.profileId },
    jobId: { S: job },
    auditId: { S: evidence.auditId },
    runtimeEvidenceDigest: { S: evidence.digest },
    sessionId: { S: session.sessionId },
    generation: { S: session.binding.generation },
    capabilityDigest: { S: session.binding.capabilityDigest },
    state: { S: "QUEUED" },
    operation: { S: operation },
    request: toAttribute(request),
    submittedAt: { S: submittedAt },
    expiresAt: { N: String(Math.floor(Date.parse(session.hardExpiresAt) / 1000) + RETENTION_SECONDS) }
  };
}
function auditRecord(parsed, evidence, analysisJobId, readJobId, submittedAt) {
  const payload = {
    schemaVersion: "archon.runtime-bound-agent-run/v2",
    auditId: evidence.auditId,
    query: parsed.query,
    question: parsed.question,
    datasetUrn: parsed.datasetUrn,
    governedColumnPath: configuredInputs().columnPath,
    mode: parsed.mode,
    runtimeEvidence: evidence,
    analysisJobId,
    readJobId,
    submittedAt
  };
  return { ...payload, digest: digest(payload) };
}
function verifyAuditRecord(value, auditId) {
  if (!exactKeys(value, ["schemaVersion", "auditId", "query", "question", "datasetUrn", "governedColumnPath", "mode", "runtimeEvidence", "analysisJobId", "readJobId", "submittedAt", "digest"]) ||
      value.schemaVersion !== "archon.runtime-bound-agent-run/v2" || value.auditId !== auditId || !boundedString(value.query, 256) ||
      !boundedString(value.question, 512) || !DATASET_URN.test(value.datasetUrn || "") || !boundedString(value.governedColumnPath, 512) ||
      !["READ_ONLY", "GOVERNED"].includes(value.mode) || !JOB_ID.test(value.analysisJobId || "") ||
      (value.readJobId !== null && !JOB_ID.test(value.readJobId || "")) || !instant(value.submittedAt) || !DIGEST.test(value.digest || "") ||
      digest(without(value, ["digest"])) !== value.digest || !verifyRuntimeEvidence(value.runtimeEvidence, auditId)) return false;
  const expected = configuredInputs();
  return value.query === expected.datasetUrn && value.datasetUrn === expected.datasetUrn && value.question === expected.question &&
    value.governedColumnPath === expected.columnPath && ((value.mode === "READ_ONLY" && value.readJobId === null) || (value.mode === "GOVERNED" && JOB_ID.test(value.readJobId)));
}
async function putRunAndJobs(run, session) {
  const evidence = run.runtimeEvidence;
  const items = [
    {
      Put: {
        TableName: tableName("runtime session table", runtimeSessionTable),
        Item: {
          pk: { S: "AUDIT#" + run.auditId }, sk: { S: "RUNTIME" }, payload: { S: JSON.stringify(without(run, ["ownerDigest"])) },
          principalHash: { S: run.ownerDigest },
          expiresAt: { N: String(Math.floor(Date.parse(session.hardExpiresAt) / 1000) + RETENTION_SECONDS) }
        },
        ConditionExpression: "attribute_not_exists(pk)"
      }
    },
    {
      Put: {
        TableName: tableName("runtime job table", runtimeJobTable),
        Item: runtimeJobItem(session, run.analysisJobId, "ANALYZE", {
          schemaVersion: "archon.datahub-companion-request/v2",
          query: run.query,
          question: run.question,
          runtimeBinding: evidence.runtimeBinding
        }, evidence, run.submittedAt),
        ConditionExpression: "attribute_not_exists(pk)"
      }
    }
  ];
  if (run.readJobId) {
    items.push({
      Put: {
        TableName: tableName("runtime job table", runtimeJobTable),
        Item: runtimeJobItem(session, run.readJobId, "READ_TAGS", {
          schemaVersion: "archon.core-tag-read/v1",
          auditId: run.auditId,
          runtimeEvidenceDigest: evidence.digest,
          entityUrn: run.datasetUrn,
          columnPath: run.governedColumnPath
        }, evidence, run.submittedAt),
        ConditionExpression: "attribute_not_exists(pk)"
      }
    });
  }
  await dynamodb.send(new TransactWriteItemsCommand({ TransactItems: items }));
}
async function start(body, identity) {
  const owner = parseIdentity(identity, runtimeOperatorGroup);
  if (owner.error) return owner.error;
  const parsed = parseStartBody(body);
  if (parsed.error) return parsed.error;
  const submittedAt = new Date().toISOString();
  const loaded = await readSession(parsed.sessionId, owner.ownerDigest, true, submittedAt);
  if (loaded.error) return loaded.error;
  const health = await readRuntimeCapabilities(loaded.session, submittedAt);
  if (health.error) return health.error;
  const touched = await recordActivity(loaded.session, submittedAt);
  if (touched.error) return touched.error;
  const auditId = randomBytes(32).toString("hex");
  const evidence = runtimeEvidence(auditId, touched.session, health.capabilities, submittedAt);
  const run = auditRecord(parsed, evidence, jobId("analyze", auditId), parsed.mode === "GOVERNED" ? jobId("read-tags", auditId) : null, submittedAt);
  await putRunAndJobs({ ...run, ownerDigest: owner.ownerDigest }, touched.session);
  const pollUrl = "/api/control-loops-v2/" + auditId;
  return response(202, {
    schemaVersion: "archon.control-loop-start/v2", auditId, status: "RUNNING", phase: "ANALYZING", pollUrl, submittedAt, runtimeEvidence: evidence
  }, { location: pollUrl, "retry-after": "2" });
}
async function readRun(auditId, ownerDigest, requireActive, observedAt) {
  const item = await getItem(tableName("runtime session table", runtimeSessionTable), "AUDIT#" + auditId, "RUNTIME", "payload, principalHash");
  if (!item) return { error: response(404, { error: "runtime_bound_run_not_found" }) };
  const principalHash = stringAttribute(item, "principalHash");
  if (principalHash !== ownerDigest) return { error: response(403, { error: "runtime_run_owner_mismatch" }) };
  const text = stringAttribute(item, "payload");
  if (!text || Buffer.byteLength(text, "utf8") > MAX_ITEM_BYTES) throw new Error("runtime run item is malformed");
  let run;
  try { run = JSON.parse(text); } catch { throw new Error("runtime run payload is not JSON"); }
  if (!verifyAuditRecord(run, auditId)) throw new Error("runtime run integrity verification failed");
  const session = await readSession(run.runtimeEvidence.runtimeSessionId, ownerDigest, requireActive === true, observedAt || run.submittedAt);
  if (session.error) return session;
  if (!same(session.session.binding, run.runtimeEvidence.runtimeBinding) || digest(session.session.binding) !== run.runtimeEvidence.bindingDigest ||
      capabilityDigest(session.session.binding.profileId, session.session.binding.generation, run.runtimeEvidence.capabilities) !== session.session.binding.capabilityDigest) {
    throw new Error("runtime binding changed after run start");
  }
  return { run, session: session.session };
}
function verifyReceipt(receipt, run, expectedJobId) {
  if (!record(receipt) || receipt.schema !== "archon.runtime-bound-job-receipt/v2" || receipt.profileId !== run.runtimeEvidence.runtimeBinding.profileId ||
      receipt.jobId !== expectedJobId || receipt.sessionId !== run.runtimeEvidence.runtimeSessionId || receipt.generation !== run.runtimeEvidence.runtimeBinding.generation ||
      receipt.capabilityDigest !== run.runtimeEvidence.runtimeBinding.capabilityDigest || !["SUCCEEDED", "FAILED"].includes(receipt.state) ||
      !instant(receipt.completedAt) || !DIGEST.test(receipt.receiptDigest || "") || digest(without(receipt, ["receiptDigest"])) !== receipt.receiptDigest) {
    throw new Error("runtime job receipt integrity verification failed");
  }
  if (receipt.state === "SUCCEEDED" ? !record(receipt.result) || receipt.error !== undefined : !record(receipt.error) || receipt.result !== undefined) {
    throw new Error("runtime job receipt terminal state is inconsistent");
  }
  return receipt;
}
async function readJob(run, job, partition) {
  const item = await getItem(tableName("runtime job table", runtimeJobTable), partition + run.runtimeEvidence.runtimeSessionId, "JOB#" + job);
  if (!item) return { state: "QUEUED" };
  const value = fromAttributeMap(item);
  if (value.schema !== "archon.runtime-bound-job/v2" || value.profileId !== run.runtimeEvidence.runtimeBinding.profileId ||
      value.jobId !== job || value.auditId !== run.auditId || value.runtimeEvidenceDigest !== run.runtimeEvidence.digest || value.sessionId !== run.runtimeEvidence.runtimeSessionId || value.generation !== run.runtimeEvidence.runtimeBinding.generation ||
      value.capabilityDigest !== run.runtimeEvidence.runtimeBinding.capabilityDigest || !["QUEUED", "RUNNING", "SUCCEEDED", "FAILED"].includes(value.state)) {
    throw new Error("runtime job identity verification failed");
  }
  if (!record(value.request)) throw new Error("runtime job request is missing");
  if (["QUEUED", "RUNNING"].includes(value.state)) return { state: value.state, request: value.request };
  return { state: value.state, request: value.request, receipt: verifyReceipt(value.receipt, run, job) };
}
function verifyDigestObject(value) {
  return record(value) && DIGEST.test(value.digest || "") && digest(without(value, ["digest"])) === value.digest;
}
function safeProjection(value, depth) {
  const level = depth || 0;
  if (level > 10) return "[depth-limit]";
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string") return PUBLIC_CREDENTIAL.test(value) || RUN_HANDLE.test(value) ? "[redacted]" : value.slice(0, 4096);
  if (Array.isArray(value)) return value.slice(0, 256).map((item) => safeProjection(item, level + 1));
  if (!record(value)) return String(value).slice(0, 512);
  return Object.fromEntries(Object.keys(value).sort().filter((key) => !PUBLIC_FORBIDDEN_KEY.test(key) && key !== "runHandle").map((key) => [key, safeProjection(value[key], level + 1)]));
}
function safePublicValue(value, depth) {
  const level = depth || 0;
  if (level > 12) return false;
  if (value === null || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value === "string") return value.length <= 64 * 1024 && !PUBLIC_CREDENTIAL.test(value) && !RUN_HANDLE.test(value);
  if (Array.isArray(value)) return value.length <= 512 && value.every((item) => safePublicValue(item, level + 1));
  if (!record(value) || Object.keys(value).length > 512) return false;
  return Object.entries(value).every(([key, item]) => !PUBLIC_FORBIDDEN_KEY.test(key) && safePublicValue(item, level + 1));
}
function agentStackProjection(raw, run) {
  if (!exactKeys(raw, ["schemaVersion", "runtimeBinding", "context", "skills", "skillGrounding", "analytics", "enrichment", "digest"]) ||
      raw.schemaVersion !== "archon.datahub-agent-stack-result/v2" || !same(raw.runtimeBinding, run.runtimeEvidence.runtimeBinding) || !verifyDigestObject(raw) ||
      !verifyDigestObject(raw.context) || !verifyDigestObject(raw.skills) || !verifyDigestObject(raw.skillGrounding) || !verifyDigestObject(raw.analytics) ||
      !exactKeys(raw.enrichment, ["status", "writeAuthority", "requiresFreshDigestBoundApproval"]) || raw.enrichment.status !== "preview-only" ||
      raw.enrichment.writeAuthority !== "archon-remediation-worker" || raw.enrichment.requiresFreshDigestBoundApproval !== true) {
    throw new Error("agent stack result integrity verification failed");
  }
  const payload = {
    schemaVersion: "archon.datahub-agent-stack-result-projection/v2",
    resultDigest: raw.digest,
    runtimeBinding: raw.runtimeBinding,
    context: safeProjection(raw.context),
    skills: safeProjection(raw.skills),
    skillGrounding: safeProjection(raw.skillGrounding),
    analytics: safeProjection(raw.analytics),
    enrichment: raw.enrichment
  };
  if (!safePublicValue(payload) || Buffer.byteLength(JSON.stringify(payload), "utf8") > 300 * 1024) throw new Error("agent stack result projection is unsafe");
  return { ...payload, digest: digest(payload) };
}
function improveContextProjection(raw, run, analysisResult) {
  if (!exactKeys(raw, ["schemaVersion", "runtimeBinding", "events", "contextQuality", "runHandle", "preflightDigest", "contextDigest", "skillGroundingDigest", "status", "writeAuthority", "requiresFreshDigestBoundApproval", "digest"]) ||
      raw.schemaVersion !== "archon.datahub-improve-context/v2" || !same(raw.runtimeBinding, run.runtimeEvidence.runtimeBinding) ||
      !Array.isArray(raw.events) || !record(raw.contextQuality) || !RUN_HANDLE.test(raw.runHandle || "") ||
      !DIGEST.test(raw.preflightDigest || "") || raw.contextDigest !== analysisResult.context.digest ||
      raw.skillGroundingDigest !== analysisResult.skillGrounding.digest || raw.status !== "proposal-only" ||
      raw.writeAuthority !== "archon-remediation-worker" || raw.requiresFreshDigestBoundApproval !== true || !verifyDigestObject(raw)) {
    throw new Error("improve-context result integrity verification failed");
  }
  const payload = {
    schemaVersion: "archon.datahub-improve-context-projection/v2",
    resultDigest: raw.digest,
    runtimeBinding: raw.runtimeBinding,
    events: safeProjection(raw.events),
    contextQuality: safeProjection(raw.contextQuality),
    preflightDigest: raw.preflightDigest,
    contextDigest: raw.contextDigest,
    skillGroundingDigest: raw.skillGroundingDigest,
    status: raw.status,
    writeAuthority: raw.writeAuthority,
    requiresFreshDigestBoundApproval: true
  };
  if (!safePublicValue(payload) || Buffer.byteLength(JSON.stringify(payload), "utf8") > 200 * 1024) throw new Error("improve-context projection is unsafe");
  return { ...payload, digest: digest(payload) };
}
function improveCapability(run, analysisReceipt, statusValue, dispatchDigest) {
  const payload = {
    schemaVersion: "archon.datahub-improve-context-capability/v2",
    auditId: run.auditId,
    command: "/improve-context",
    status: statusValue || "AVAILABLE",
    analysisReceiptDigest: analysisReceipt.receiptDigest,
    runtimeEvidenceDigest: run.runtimeEvidence.digest,
    writeAuthority: "archon-remediation-worker",
    requiresExplicitUserAction: true,
    requiresFreshDigestBoundApproval: true,
    ...(dispatchDigest ? { dispatchDigest } : {})
  };
  return { ...payload, digest: digest(payload) };
}
function improveMarkerPayload(run, analysisReceipt, submittedAt) {
  const analysisResult = analysisReceipt.result;
  if (!record(analysisResult.analytics) || analysisResult.analytics.improveContextCommandAvailable !== true || !RUN_HANDLE.test(analysisResult.analytics.runHandle || "")) {
    throw new Error("improve-context capability is unavailable");
  }
  const request = {
    schemaVersion: "archon.datahub-companion-improve/v2",
    runHandle: analysisResult.analytics.runHandle,
    runtimeBinding: run.runtimeEvidence.runtimeBinding
  };
  const payload = {
    schemaVersion: "archon.runtime-improve-context-dispatch/v2",
    auditId: run.auditId,
    runtimeEvidenceDigest: run.runtimeEvidence.digest,
    analysisReceiptDigest: analysisReceipt.receiptDigest,
    jobId: jobId("improve-context", run.auditId),
    requestDigest: digest(request),
    submittedAt
  };
  return { marker: { ...payload, digest: digest(payload) }, request };
}
function verifyImproveMarker(value, run, analysisReceipt) {
  return exactKeys(value, ["schemaVersion", "auditId", "runtimeEvidenceDigest", "analysisReceiptDigest", "jobId", "requestDigest", "submittedAt", "digest"]) &&
    value.schemaVersion === "archon.runtime-improve-context-dispatch/v2" && value.auditId === run.auditId &&
    value.runtimeEvidenceDigest === run.runtimeEvidence.digest && value.analysisReceiptDigest === analysisReceipt.receiptDigest &&
    value.jobId === jobId("improve-context", run.auditId) && DIGEST.test(value.requestDigest || "") && instant(value.submittedAt) &&
    verifyDigestObject(value);
}
async function readImproveMarker(run, analysisReceipt) {
  const item = await getItem(tableName("runtime session table", runtimeSessionTable), "AUDIT#" + run.auditId, "IMPROVE", "payload, principalHash");
  if (!item) return undefined;
  if (stringAttribute(item, "principalHash") !== run.ownerDigest) throw new Error("improve-context owner binding mismatch");
  const text = stringAttribute(item, "payload");
  if (!text || Buffer.byteLength(text, "utf8") > 64 * 1024) throw new Error("improve-context marker is malformed");
  let value;
  try { value = JSON.parse(text); } catch { throw new Error("improve-context marker is not JSON"); }
  if (!verifyImproveMarker(value, run, analysisReceipt)) throw new Error("improve-context marker integrity verification failed");
  return value;
}
function tagState(result, run) {
  if (!exactKeys(result, ["schemaVersion", "entityUrn", "columnPath", "tagUrns", "stateDigest"]) ||
      result.schemaVersion !== "archon.core-tag-read-result/v1" || result.entityUrn !== run.datasetUrn || result.columnPath !== run.governedColumnPath ||
      !Array.isArray(result.tagUrns) || result.tagUrns.length > 256 || result.tagUrns.some((tag) => !boundedString(tag, 256) || !tag.startsWith("urn:li:tag:")) ||
      !same(result.tagUrns, [...new Set(result.tagUrns)].sort()) ||
      result.stateDigest !== digest({ entityUrn: result.entityUrn, columnPath: result.columnPath, tagUrns: result.tagUrns })) {
    throw new Error("Core tag read result integrity verification failed");
  }
  return {
    entityUrn: result.entityUrn,
    columnPath: result.columnPath,
    tagUrns: [...result.tagUrns],
    stateDigest: result.stateDigest
  };
}
function planFor(run, analysisReceipt, readReceipt, improveReceipt) {
  const before = tagState(readReceipt.result, run);
  const improve = improveContextProjection(improveReceipt.result, run, analysisReceipt.result);
  const afterTags = [...new Set(before.tagUrns.concat([PII_TAG]))].sort();
  const expectedAfter = { entityUrn: before.entityUrn, columnPath: before.columnPath, tagUrns: afterTags };
  const expectedAfterDigest = digest(expectedAfter);
  const policyDigest = digest({
    schemaVersion: "archon.governed-mcp-mutation-policy/v1",
    action: "ADD_TAGS",
    tool: "add_tags",
    tagUrns: [PII_TAG],
    entityUrn: run.datasetUrn,
    columnPath: run.governedColumnPath,
    writeAuthority: "archon-remediation-worker"
  });
  const auditEvidenceDigest = digest({
    agentStackResultDigest: analysisReceipt.result.digest,
    analysisReceiptDigest: analysisReceipt.receiptDigest,
    readReceiptDigest: readReceipt.receiptDigest,
    improveContextResultDigest: improve.resultDigest,
    improveReceiptDigest: improveReceipt.receiptDigest
  });
  const planPayload = {
    schemaVersion: "archon.runtime-remediation-plan/v2",
    auditId: run.auditId,
    runtimeEvidenceDigest: run.runtimeEvidence.digest,
    auditEvidenceDigest,
    policyDigest,
    agentStackResultDigest: analysisReceipt.result.digest,
    analysisReceiptDigest: analysisReceipt.receiptDigest,
    readReceiptDigest: readReceipt.receiptDigest,
    improveContextResultDigest: improve.resultDigest,
    improveReceiptDigest: improveReceipt.receiptDigest,
    action: "ADD_TAGS",
    arguments: { tagUrns: [PII_TAG], entityUrns: [run.datasetUrn], columnPaths: [run.governedColumnPath] },
    expectedBefore: before,
    expectedBeforeDigest: before.stateDigest,
    expectedAfter: { ...expectedAfter, stateDigest: expectedAfterDigest },
    expectedAfterDigest,
    requiresHumanApproval: true,
    createdAt: improveReceipt.completedAt
  };
  const plan = { ...planPayload, digest: digest(planPayload) };
  const requestPayload = {
    schemaVersion: "archon.runtime-approval-request/v2",
    approvalId: "approval-" + plan.digest.slice("sha256:".length, "sha256:".length + 24),
    auditId: run.auditId,
    runtimeEvidenceDigest: run.runtimeEvidence.digest,
    planDigest: plan.digest,
    requestedAt: improveReceipt.completedAt,
    expiresAt: new Date(Math.min(Date.parse(improveReceipt.completedAt) + 30 * 60 * 1000, Date.parse(run.runtimeEvidence.runtimeBinding.leaseExpiresAt))).toISOString()
  };
  return { plan, improve, approvalRequest: { ...requestPayload, digest: digest(requestPayload) } };
}
async function readApproval(run) {
  const item = await getItem(tableName("runtime session table", runtimeSessionTable), "AUDIT#" + run.auditId, "APPROVAL", "payload, principalHash");
  if (!item) return undefined;
  if (stringAttribute(item, "principalHash") !== run.ownerDigest) throw new Error("approval owner binding mismatch");
  const text = stringAttribute(item, "payload");
  if (!text || Buffer.byteLength(text, "utf8") > 64 * 1024) throw new Error("approval item is malformed");
  let value;
  try { value = JSON.parse(text); } catch { throw new Error("approval payload is not JSON"); }
  return value;
}
function verifyApprovalEnvelope(value, run, plan, request, ownerDigest) {
  return exactKeys(value, ["schemaVersion", "auditId", "ownerDigest", "runtimeEvidence", "plan", "approvalRequest", "decision", "mutationJobId", "createdAt", "digest"]) &&
    value.schemaVersion === "archon.runtime-approved-action/v2" && value.auditId === run.auditId && value.ownerDigest === ownerDigest &&
    same(value.runtimeEvidence, run.runtimeEvidence) && same(value.plan, plan) && same(value.approvalRequest, request) && JOB_ID.test(value.mutationJobId || "") &&
    instant(value.createdAt) && exactKeys(value.decision, ["schemaVersion", "approvalId", "auditId", "requestDigest", "planDigest", "decision", "approverDigest", "decidedAt", "commentDigest", "digest"]) &&
    value.decision.schemaVersion === "archon.runtime-approval-decision/v2" && value.decision.approvalId === request.approvalId && value.decision.auditId === run.auditId &&
    value.decision.requestDigest === request.digest && value.decision.planDigest === plan.digest && ["APPROVE", "REJECT"].includes(value.decision.decision) &&
    value.decision.approverDigest === ownerDigest && instant(value.decision.decidedAt) && DIGEST.test(value.decision.commentDigest || "") &&
    verifyDigestObject(value.decision) && verifyDigestObject(value);
}
function mutationApproval(envelope) {
  const payload = {
    approvalId: envelope.decision.approvalId,
    decision: "APPROVE",
    approverDigest: envelope.decision.approverDigest,
    decidedAt: envelope.decision.decidedAt
  };
  return { ...payload, digest: digest(payload) };
}
function configuredMutationSigner() {
  if (!STAGE.test(configuredStage || "") || !KMS_KEY_ARN.test(mutationSigningKeyArn || "") || mutationSigningAlgorithm !== "ECDSA_SHA_256") {
    throw new Error("governed mutation signer is not configured");
  }
  return { stage: configuredStage, keyArn: mutationSigningKeyArn, algorithm: mutationSigningAlgorithm, canonicalization: MUTATION_CANONICALIZATION };
}
function canonicalMutationEnvelope(value) {
  function validate(item, depth) {
    if (depth > 12) throw new Error("mutation authorization exceeds canonicalization depth");
    if (item === null || typeof item === "boolean") return;
    if (typeof item === "string") {
      if (!/^[\x20-\x7E]*$/u.test(item)) throw new Error("mutation authorization must use printable ASCII strings");
      return;
    }
    if (typeof item === "number") {
      if (!Number.isSafeInteger(item)) throw new Error("mutation authorization numbers must be safe integers");
      return;
    }
    if (Array.isArray(item)) {
      item.forEach((entry) => validate(entry, depth + 1));
      return;
    }
    if (!record(item)) throw new Error("mutation authorization contains a non-JSON value");
    Object.entries(item).forEach(([key, entry]) => {
      if (!/^[\x20-\x7E]+$/u.test(key)) throw new Error("mutation authorization keys must use printable ASCII");
      validate(entry, depth + 1);
    });
  }
  validate(value, 0);
  return canonicalize(value);
}
function mutationEnvelopeDigest(value) {
  return "sha256:" + createHash("sha256").update(canonicalMutationEnvelope(value), "utf8").digest("hex");
}
function strictBase64(value) {
  if (typeof value !== "string" || value.length < 8 || value.length > 512 || !/^[A-Za-z0-9+/]+={0,2}$/u.test(value) || value.length % 4 !== 0) return undefined;
  try {
    const bytes = Buffer.from(value, "base64");
    return bytes.length >= 8 && bytes.length <= 256 && bytes.toString("base64") === value ? bytes : undefined;
  } catch { return undefined; }
}
function verifyMutationRequestAuthorization(request, run, prepared, approvalEnvelope) {
  const signer = configuredMutationSigner();
  const expectedApproval = mutationApproval(approvalEnvelope);
  if (!exactKeys(request, [
    "schemaVersion", "auditId", "runtimeEvidenceDigest", "auditEvidenceDigest", "planDigest", "policyDigest",
    "approval", "action", "arguments", "expectedBeforeDigest", "expectedAfterDigest", "authorization", "requestDigest"
  ]) || request.schemaVersion !== "archon.core-governed-tag-mutation/v1" || request.auditId !== run.auditId ||
      request.runtimeEvidenceDigest !== run.runtimeEvidence.digest || request.auditEvidenceDigest !== prepared.plan.auditEvidenceDigest ||
      request.planDigest !== prepared.plan.digest || request.policyDigest !== prepared.plan.policyDigest || !same(request.approval, expectedApproval) ||
      request.action !== prepared.plan.action || !same(request.arguments, prepared.plan.arguments) ||
      request.expectedBeforeDigest !== prepared.plan.expectedBeforeDigest || request.expectedAfterDigest !== prepared.plan.expectedAfterDigest ||
      !DIGEST.test(request.requestDigest || "") || request.requestDigest !== digest(without(request, ["requestDigest"])) ||
      !exactKeys(request.authorization, ["envelope", "signature"])) {
    throw new Error("governed mutation request binding verification failed");
  }
  const authorizationEnvelope = request.authorization.envelope;
  const signature = request.authorization.signature;
  const officialArguments = {
    tag_urns: prepared.plan.arguments.tagUrns,
    entity_urns: prepared.plan.arguments.entityUrns,
    column_paths: prepared.plan.arguments.columnPaths
  };
  if (!exactKeys(authorizationEnvelope, [
    "schemaVersion", "stage", "sessionId", "generation", "capabilityDigest", "jobId", "approvalId", "planDigest",
    "policyDigest", "target", "tool", "arguments", "issuedAt", "expiresAt"
  ]) || authorizationEnvelope.schemaVersion !== "archon.core-mutation-authorization/v1" || authorizationEnvelope.stage !== signer.stage ||
      authorizationEnvelope.sessionId !== run.runtimeEvidence.runtimeSessionId ||
      authorizationEnvelope.generation !== run.runtimeEvidence.runtimeBinding.generation ||
      authorizationEnvelope.capabilityDigest !== run.runtimeEvidence.runtimeBinding.capabilityDigest ||
      authorizationEnvelope.jobId !== approvalEnvelope.mutationJobId || authorizationEnvelope.approvalId !== prepared.approvalRequest.approvalId ||
      authorizationEnvelope.planDigest !== prepared.plan.digest || authorizationEnvelope.policyDigest !== prepared.plan.policyDigest ||
      !exactKeys(authorizationEnvelope.target, ["entityUrn", "columnPath"]) ||
      authorizationEnvelope.target.entityUrn !== run.datasetUrn || authorizationEnvelope.target.columnPath !== run.governedColumnPath ||
      authorizationEnvelope.tool !== "add_tags" || !same(authorizationEnvelope.arguments, officialArguments) ||
      !instant(authorizationEnvelope.issuedAt) || !instant(authorizationEnvelope.expiresAt) ||
      Date.parse(authorizationEnvelope.issuedAt) < Date.parse(approvalEnvelope.decision.decidedAt) ||
      Date.parse(authorizationEnvelope.expiresAt) <= Date.parse(authorizationEnvelope.issuedAt) ||
      Date.parse(authorizationEnvelope.expiresAt) - Date.parse(authorizationEnvelope.issuedAt) > 5 * 60 * 1000 ||
      Date.parse(authorizationEnvelope.expiresAt) > Date.parse(run.runtimeEvidence.runtimeBinding.leaseExpiresAt) ||
      !exactKeys(signature, ["keyArn", "algorithm", "canonicalization", "envelopeDigest", "signatureBase64"]) ||
      signature.keyArn !== signer.keyArn || signature.algorithm !== signer.algorithm ||
      signature.canonicalization !== signer.canonicalization ||
      signature.envelopeDigest !== mutationEnvelopeDigest(authorizationEnvelope)) {
    throw new Error("governed mutation authorization envelope verification failed");
  }
  const signatureBytes = strictBase64(signature.signatureBase64);
  if (!signatureBytes) throw new Error("governed mutation authorization signature is malformed");
  return {
    keyArn: signer.keyArn,
    algorithm: signer.algorithm,
    canonicalization: signer.canonicalization,
    envelopeDigest: signature.envelopeDigest,
    signatureDigest: "sha256:" + createHash("sha256").update(signatureBytes).digest("hex"),
    issuedAt: authorizationEnvelope.issuedAt,
    expiresAt: authorizationEnvelope.expiresAt
  };
}
async function createMutationAuthorization(run, prepared, approvalEnvelope, issuedAt) {
  const signer = configuredMutationSigner();
  const expiresAt = new Date(Math.min(
    Date.parse(issuedAt) + 5 * 60 * 1000,
    Date.parse(prepared.approvalRequest.expiresAt),
    Date.parse(run.runtimeEvidence.runtimeBinding.leaseExpiresAt)
  )).toISOString();
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) throw new Error("governed mutation authorization cannot be issued after expiry");
  const authorizationEnvelope = {
    schemaVersion: "archon.core-mutation-authorization/v1",
    stage: signer.stage,
    sessionId: run.runtimeEvidence.runtimeSessionId,
    generation: run.runtimeEvidence.runtimeBinding.generation,
    capabilityDigest: run.runtimeEvidence.runtimeBinding.capabilityDigest,
    jobId: approvalEnvelope.mutationJobId,
    approvalId: prepared.approvalRequest.approvalId,
    planDigest: prepared.plan.digest,
    policyDigest: prepared.plan.policyDigest,
    target: { entityUrn: run.datasetUrn, columnPath: run.governedColumnPath },
    tool: "add_tags",
    arguments: {
      tag_urns: prepared.plan.arguments.tagUrns,
      entity_urns: prepared.plan.arguments.entityUrns,
      column_paths: prepared.plan.arguments.columnPaths
    },
    issuedAt,
    expiresAt
  };
  const envelopeHash = createHash("sha256").update(canonicalMutationEnvelope(authorizationEnvelope), "utf8").digest();
  const signed = await kmsClient.send(new SignCommand({
    KeyId: signer.keyArn,
    Message: envelopeHash,
    MessageType: "DIGEST",
    SigningAlgorithm: signer.algorithm
  }));
  if (signed.KeyId !== signer.keyArn || signed.SigningAlgorithm !== signer.algorithm || !signed.Signature) {
    throw new Error("KMS returned an invalid governed mutation signature");
  }
  const signatureBytes = Buffer.from(signed.Signature);
  if (signatureBytes.length < 8 || signatureBytes.length > 256) throw new Error("KMS returned a malformed governed mutation signature");
  return {
    envelope: authorizationEnvelope,
    signature: {
      keyArn: signer.keyArn,
      algorithm: signer.algorithm,
      canonicalization: signer.canonicalization,
      envelopeDigest: "sha256:" + envelopeHash.toString("hex"),
      signatureBase64: signatureBytes.toString("base64")
    }
  };
}
function governedMutationResult(receipt, prepared, envelope, request, run) {
  const result = receipt.result;
  const expectedApproval = mutationApproval(envelope);
  const authorization = verifyMutationRequestAuthorization(request, run, prepared, envelope);
  if (!exactKeys(result, [
    "schemaVersion", "requestDigest", "policyDigest", "beforeDigest", "afterDigest", "verified",
    "mutationExecutor", "officialMcpMutation", "authorizationEvidence", "responseDigest"
  ]) || result.schemaVersion !== "archon.core-governed-tag-result/v1" || result.requestDigest !== request.requestDigest ||
      result.policyDigest !== prepared.plan.policyDigest || result.beforeDigest !== prepared.plan.expectedBeforeDigest ||
      result.afterDigest !== prepared.plan.expectedAfterDigest || result.verified !== true ||
      result.mutationExecutor !== "official-datahub-mcp" ||
      !exactKeys(result.officialMcpMutation, ["tool", "policyDigest", "approvalDigest", "requestDigest", "responseDigest"]) ||
      result.officialMcpMutation.tool !== "add_tags" || result.officialMcpMutation.policyDigest !== prepared.plan.policyDigest ||
      result.officialMcpMutation.approvalDigest !== expectedApproval.digest || result.officialMcpMutation.requestDigest !== result.requestDigest ||
      !DIGEST.test(result.officialMcpMutation.responseDigest || "") ||
      !exactKeys(result.authorizationEvidence, ["keyArn", "algorithm", "canonicalization", "envelopeDigest", "signatureDigest", "consumedAt"]) ||
      result.authorizationEvidence.keyArn !== authorization.keyArn || result.authorizationEvidence.algorithm !== authorization.algorithm ||
      result.authorizationEvidence.canonicalization !== authorization.canonicalization || result.authorizationEvidence.envelopeDigest !== authorization.envelopeDigest ||
      result.authorizationEvidence.signatureDigest !== authorization.signatureDigest || !instant(result.authorizationEvidence.consumedAt) ||
      Date.parse(result.authorizationEvidence.consumedAt) < Date.parse(authorization.issuedAt) ||
      Date.parse(result.authorizationEvidence.consumedAt) > Date.parse(authorization.expiresAt) ||
      !DIGEST.test(result.responseDigest || "") || result.responseDigest !== digest(without(result, ["responseDigest"]))) {
    throw new Error("official DataHub MCP mutation receipt integrity verification failed");
  }
  return result;
}
function exactSatisfiedCalls(value, requiredTools) {
  return Array.isArray(value) && value.length === requiredTools.length &&
    value.every((entry, index) => exactKeys(entry, ["tool", "receiptDigest"]) &&
      entry.tool === requiredTools[index] && DIGEST.test(entry.receiptDigest || ""));
}
function enrichSkillCompletion(analysisReceipt, approvalEnvelope, mutationReceipt) {
  const result = analysisReceipt && analysisReceipt.result;
  const skills = result && result.skills;
  const grounding = result && result.skillGrounding;
  const receipts = grounding && grounding.receipts;
  const skillWorkflow = [
    "datahub-search", "datahub-lineage", "datahub-quality", "datahub-audit", "datahub-enrich"
  ];
  const expectedOfficialSkills = [
    "datahub-search", "datahub-lineage", "datahub-quality", "datahub-enrich", "using-datahub"
  ];
  const expectedCustomSkills = ["datahub-audit"];
  const ackTools = [
    "search", "get_entities", "list_schema_fields",
    "get_lineage_upstream", "get_lineage_downstream", "get_dataset_assertions"
  ];
  const officialMcpTools = [
    "search", "get_entities", "list_schema_fields", "get_lineage", "get_dataset_queries"
  ];
  const officialArtifacts = skills && skills.official;
  const customArtifacts = skills && skills.custom;
  if (!record(result) || !record(skills) || !exactKeys(skills, [
        "schemaVersion", "sourceCommit", "official", "custom", "workflow",
        "reviewedSkillCount", "mutationAuthority", "digest"
      ]) || skills.schemaVersion !== "archon.datahub-skills-receipt/v2" ||
      skills.sourceCommit !== "f7c7c53648b71dc0841742781e108051d46fa360" ||
      !Array.isArray(officialArtifacts) || !Array.isArray(customArtifacts) ||
      !same(officialArtifacts.map((item) => record(item) && item.skill), expectedOfficialSkills) ||
      !same(customArtifacts.map((item) => record(item) && item.skill), expectedCustomSkills) ||
      !same(skills.workflow, skillWorkflow) || skills.reviewedSkillCount !== 6 ||
      skills.mutationAuthority !== "archon-remediation-worker" || !verifyDigestObject(skills) ||
      !record(result.context) || !record(result.analytics) || !record(grounding) ||
      !exactKeys(grounding, [
        "schemaVersion", "skillsReceiptDigest", "ackContextDigest", "officialMcpReadReceiptsDigest",
        "executionOrder", "allRequiredCallsSatisfied", "receipts", "digest"
      ]) || grounding.schemaVersion !== "archon.datahub-skill-grounding/v2" || !verifyDigestObject(grounding) ||
      grounding.skillsReceiptDigest !== skills.digest || grounding.ackContextDigest !== result.context.digest ||
      !DIGEST.test(grounding.officialMcpReadReceiptsDigest || "") ||
      !same(grounding.executionOrder, skillWorkflow) ||
      grounding.allRequiredCallsSatisfied !== true || result.analytics.skillGroundingDigest !== grounding.digest ||
      !Array.isArray(receipts)) {
    throw new Error("datahub-enrich grounding evidence is unavailable");
  }
  const matching = receipts.filter((receipt) => record(receipt) && receipt.skill === "datahub-enrich");
  const matchingArtifacts = officialArtifacts.filter(
    (artifact) => record(artifact) && artifact.skill === "datahub-enrich"
  );
  const enrich = matching[0];
  const artifact = matchingArtifacts[0];
  const reviewedExecution = artifact && artifact.reviewedExecution;
  const executionPlan = enrich && enrich.executionPlan;
  const requiredCalls = executionPlan && executionPlan.requiredCalls;
  if (matching.length !== 1 || matchingArtifacts.length !== 1 ||
      !exactKeys(artifact, ["skill", "artifactDigest", "gitBlob", "bytes", "reviewedExecution"]) ||
      artifact.skill !== "datahub-enrich" || !DIGEST.test(artifact.artifactDigest || "") ||
      !/^[a-f0-9]{40}$/u.test(artifact.gitBlob || "") ||
      !Number.isSafeInteger(artifact.bytes) || artifact.bytes < 1 ||
      !exactKeys(reviewedExecution, ["executionPlan", "executionPlanDigest"]) ||
      !exactKeys(enrich, [
        "schemaVersion", "skill", "sourceArtifactDigest", "executionPlan", "executionPlanDigest", "status",
        "satisfiedAckCalls", "satisfiedOfficialMcpCalls", "ackReceiptDigests", "officialMcpReadReceiptDigests",
        "mode", "requiredCallsSatisfied", "mutationsEnabled", "providerPayloadStored", "digest"
      ]) || enrich.schemaVersion !== "archon.datahub-skill-execution-receipt/v2" || !verifyDigestObject(enrich) ||
      enrich.sourceArtifactDigest !== artifact.artifactDigest || !record(executionPlan) ||
      !exactKeys(executionPlan, ["phase", "requiredCalls", "mode"]) || executionPlan.phase !== "governed-enrichment-preview" ||
      executionPlan.mode !== "preview-only" || !record(requiredCalls) || !exactKeys(requiredCalls, ["ack", "officialMcp"]) ||
      !same(requiredCalls.ack, ackTools) || !same(requiredCalls.officialMcp, officialMcpTools) ||
      !same(reviewedExecution.executionPlan, executionPlan) ||
      reviewedExecution.executionPlanDigest !== enrich.executionPlanDigest ||
      !DIGEST.test(enrich.executionPlanDigest || "") ||
      enrich.executionPlanDigest !== digest({ sourceArtifactDigest: enrich.sourceArtifactDigest, executionPlan }) ||
      enrich.status !== "previewed" || enrich.mode !== "preview-only" || enrich.requiredCallsSatisfied !== true ||
      enrich.mutationsEnabled !== false || enrich.providerPayloadStored !== false ||
      !exactSatisfiedCalls(enrich.satisfiedAckCalls, ackTools) ||
      !exactSatisfiedCalls(enrich.satisfiedOfficialMcpCalls, officialMcpTools) ||
      !same(enrich.ackReceiptDigests, enrich.satisfiedAckCalls.map((entry) => entry.receiptDigest)) ||
      !same(enrich.officialMcpReadReceiptDigests, enrich.satisfiedOfficialMcpCalls.map((entry) => entry.receiptDigest))) {
    throw new Error("datahub-enrich preview receipt is not bound to its skill artifact and required reads");
  }
  if (!record(approvalEnvelope) || !record(approvalEnvelope.decision) ||
      !DIGEST.test(approvalEnvelope.decision.digest || "") || !record(mutationReceipt) ||
      !DIGEST.test(mutationReceipt.receiptDigest || "") || !instant(mutationReceipt.completedAt)) {
    throw new Error("datahub-enrich completion authority is invalid");
  }
  const payload = {
    schemaVersion: "archon.datahub-skill-completion/v1",
    skill: "datahub-enrich",
    status: "executed-with-human-approval",
    sourceArtifactDigest: enrich.sourceArtifactDigest,
    executionPlanDigest: enrich.executionPlanDigest,
    previewSkillReceiptDigest: enrich.digest,
    skillGroundingDigest: grounding.digest,
    approvalDigest: approvalEnvelope.decision.digest,
    officialMcpMutationReceiptDigest: mutationReceipt.receiptDigest,
    completedAt: mutationReceipt.completedAt
  };
  return { ...payload, digest: digest(payload) };
}
function postVerificationDispatch(run, prepared, mutationReceipt) {
  const common = {
    sourceMutationAuditId: run.auditId,
    sourceMutationReceiptDigest: mutationReceipt.receiptDigest,
    postMutationExpectedTagState: prepared.plan.expectedAfter
  };
  const analysisRequest = {
    schemaVersion: "archon.datahub-post-mutation-analysis/v1",
    originalRequest: {
      schemaVersion: "archon.datahub-companion-request/v2",
      query: run.query,
      question: run.question,
      runtimeBinding: run.runtimeEvidence.runtimeBinding
    },
    ...common
  };
  const readRequest = {
    schemaVersion: "archon.core-post-mutation-tag-read/v1",
    originalRequest: {
      schemaVersion: "archon.core-tag-read/v1",
      auditId: run.auditId,
      runtimeEvidenceDigest: run.runtimeEvidence.digest,
      entityUrn: run.datasetUrn,
      columnPath: run.governedColumnPath
    },
    ...common
  };
  const markerPayload = {
    schemaVersion: "archon.runtime-post-mutation-verification-dispatch/v1",
    auditId: run.auditId,
    runtimeEvidenceDigest: run.runtimeEvidence.digest,
    sourceMutationJobId: jobId("mutation", run.auditId),
    sourceMutationReceiptDigest: mutationReceipt.receiptDigest,
    postMutationExpectedTagState: prepared.plan.expectedAfter,
    analysisJobId: jobId("post-analyze", run.auditId),
    analysisRequestDigest: digest(analysisRequest),
    readJobId: jobId("post-read-tags", run.auditId),
    readRequestDigest: digest(readRequest),
    submittedAt: mutationReceipt.completedAt
  };
  return {
    marker: { ...markerPayload, digest: digest(markerPayload) },
    analysisRequest,
    readRequest
  };
}
async function readPostVerificationMarker(run, prepared, mutationReceipt) {
  const item = await getItem(tableName("runtime session table", runtimeSessionTable), "AUDIT#" + run.auditId, "POST_VERIFY", "payload, principalHash");
  if (!item) return undefined;
  if (stringAttribute(item, "principalHash") !== run.ownerDigest) throw new Error("post-mutation verification owner binding mismatch");
  const text = stringAttribute(item, "payload");
  if (!text || Buffer.byteLength(text, "utf8") > 64 * 1024) throw new Error("post-mutation verification marker is malformed");
  let value;
  try { value = JSON.parse(text); } catch { throw new Error("post-mutation verification marker is not JSON"); }
  const expected = postVerificationDispatch(run, prepared, mutationReceipt).marker;
  if (!same(value, expected) || !verifyDigestObject(value)) throw new Error("post-mutation verification marker integrity verification failed");
  return value;
}
function postMutationResult(wrapper, schemaVersion, marker) {
  if (!exactKeys(wrapper, [
    "schemaVersion", "sourceMutationAuditId", "sourceMutationReceiptDigest",
    "postMutationExpectedTagState", "postMutationResult", "postMutationResultDigest"
  ]) || wrapper.schemaVersion !== schemaVersion || wrapper.sourceMutationAuditId !== marker.auditId ||
      wrapper.sourceMutationReceiptDigest !== marker.sourceMutationReceiptDigest ||
      !same(wrapper.postMutationExpectedTagState, marker.postMutationExpectedTagState) ||
      !record(wrapper.postMutationResult) || wrapper.postMutationResultDigest !== digest(wrapper.postMutationResult)) {
    throw new Error("post-mutation verification result integrity verification failed");
  }
  return wrapper.postMutationResult;
}
function containsExactString(value, expected, depth) {
  const level = depth || 0;
  if (level > 12) return false;
  if (value === expected) return true;
  if (Array.isArray(value)) return value.some((item) => containsExactString(item, expected, level + 1));
  if (record(value)) return Object.values(value).some((item) => containsExactString(item, expected, level + 1));
  return false;
}
function verifiedContextDelta(run, prepared, mutationReceipt, marker, beforeAnalysis, postAnalysisReceipt, postReadReceipt) {
  const postRaw = postMutationResult(
    postAnalysisReceipt.result,
    "archon.datahub-post-mutation-analysis-result/v1",
    marker
  );
  const postReadRaw = postMutationResult(
    postReadReceipt.result,
    "archon.core-post-mutation-tag-read-result/v1",
    marker
  );
  const postAgentStackResult = agentStackProjection(postRaw, run);
  const postGovernedState = tagState(postReadRaw, run);
  if (!same(postGovernedState, prepared.plan.expectedAfter) || !postGovernedState.tagUrns.includes(PII_TAG) ||
      beforeAnalysis.result.context.digest === postRaw.context.digest ||
      beforeAnalysis.result.analytics.digest === postRaw.analytics.digest ||
      postRaw.analytics.contextDigest !== postRaw.context.digest || !containsExactString(postRaw.context, PII_TAG)) {
    throw new Error("post-mutation context delta verification failed");
  }
  const deltaPayload = {
    schemaVersion: "archon.context-delta/v1",
    sourceMutationReceiptDigest: mutationReceipt.receiptDigest,
    beforeContextDigest: beforeAnalysis.result.context.digest,
    afterContextDigest: postRaw.context.digest,
    beforeAnalyticsDigest: beforeAnalysis.result.analytics.digest,
    afterAnalyticsDigest: postRaw.analytics.digest,
    beforeTagStateDigest: prepared.plan.expectedBeforeDigest,
    afterTagStateDigest: postGovernedState.stateDigest,
    addedTagUrns: [PII_TAG],
    ackContextChanged: true,
    analyticsResultChanged: true,
    sourceReadVerified: true,
    postAnalysisReceiptDigest: postAnalysisReceipt.receiptDigest,
    postReadReceiptDigest: postReadReceipt.receiptDigest
  };
  const contextDelta = { ...deltaPayload, digest: digest(deltaPayload) };
  if (!safePublicValue(contextDelta)) throw new Error("post-mutation context delta projection is unsafe");
  return { postAgentStackResult, postGovernedState, contextDelta };
}
function approvalProjection(request, decision) {
  return {
    approvalId: request.approvalId,
    status: decision ? (decision.decision === "APPROVE" ? "APPROVED" : "REJECTED") : (Date.parse(request.expiresAt) <= Date.now() ? "EXPIRED" : "PENDING"),
    requestedAt: request.requestedAt,
    expiresAt: request.expiresAt,
    planDigest: request.planDigest,
    requestDigest: request.digest,
    ...(decision ? { decision: decision.decision, decisionDigest: decision.digest, decidedAt: decision.decidedAt } : {})
  };
}
function baseStatus(run, statusValue, phase) {
  return {
    schemaVersion: "archon.control-loop-status/v2",
    auditId: run.auditId,
    status: statusValue,
    phase,
    submittedAt: run.submittedAt,
    updatedAt: new Date().toISOString(),
    runtimeEvidence: run.runtimeEvidence
  };
}
async function status(auditId, identity) {
  if (!AUDIT_ID.test(auditId || "")) return response(400, { error: "invalid_audit_id" });
  const owner = parseIdentity(identity, runtimeOperatorGroup);
  if (owner.error) return owner.error;
  const loaded = await readRun(auditId, owner.ownerDigest);
  if (loaded.error) return loaded.error;
  const run = { ...loaded.run, ownerDigest: owner.ownerDigest };
  const analysis = await readJob(run, run.analysisJobId, "SESSION#");
  if (["QUEUED", "RUNNING"].includes(analysis.state)) return response(200, baseStatus(run, "RUNNING", "ANALYZING"));
  if (analysis.state === "FAILED") return response(200, { ...baseStatus(run, "FAILED", "ANALYZING"), completedAt: analysis.receipt.completedAt, error: { code: analysis.receipt.error.code, retryable: analysis.receipt.error.retryable === true } });
  const agentStackResult = agentStackProjection(analysis.receipt.result, run);
  if (run.mode === "READ_ONLY") return response(200, { ...baseStatus(run, "SUCCEEDED", "COMPLETE"), completedAt: analysis.receipt.completedAt, agentStackResult, runtimeExecution: { jobId: run.analysisJobId, receiptDigest: analysis.receipt.receiptDigest } });
  const read = await readJob(run, run.readJobId, "SESSION#");
  if (["QUEUED", "RUNNING"].includes(read.state)) return response(200, { ...baseStatus(run, "RUNNING", "READING_GOVERNED_STATE"), agentStackResult });
  if (read.state === "FAILED") return response(200, { ...baseStatus(run, "FAILED", "READING_GOVERNED_STATE"), completedAt: read.receipt.completedAt, agentStackResult, error: { code: read.receipt.error.code, retryable: read.receipt.error.retryable === true } });
  const governedState = tagState(read.receipt.result, run);
  const marker = await readImproveMarker(run, analysis.receipt);
  if (!marker) {
    return response(200, {
      ...baseStatus(run, "AWAITING_IMPROVEMENT", "IMPROVING_CONTEXT"),
      agentStackResult,
      governedState,
      improveContext: improveCapability(run, analysis.receipt)
    });
  }
  const improveJob = await readJob(run, marker.jobId, "SESSION#");
  if (["QUEUED", "RUNNING"].includes(improveJob.state)) {
    return response(200, {
      ...baseStatus(run, "RUNNING", "IMPROVING_CONTEXT"),
      agentStackResult,
      governedState,
      improveContext: improveCapability(run, analysis.receipt, "RUNNING", marker.digest)
    });
  }
  if (improveJob.state === "FAILED") return response(200, {
    ...baseStatus(run, "FAILED", "IMPROVING_CONTEXT"),
    completedAt: improveJob.receipt.completedAt,
    agentStackResult,
    governedState,
    improveContext: improveCapability(run, analysis.receipt, "FAILED", marker.digest),
    error: { code: improveJob.receipt.error.code, retryable: improveJob.receipt.error.retryable === true }
  });
  const prepared = planFor(run, analysis.receipt, read.receipt, improveJob.receipt);
  const storedApproval = await readApproval(run);
  if (!storedApproval) {
    const expired = Date.parse(prepared.approvalRequest.expiresAt) <= Date.now();
    return response(200, { ...baseStatus(run, expired ? "FAILED" : "AWAITING_APPROVAL", "HUMAN_APPROVAL"), agentStackResult, governedState, improveContext: prepared.improve, plan: prepared.plan, approval: approvalProjection(prepared.approvalRequest), ...(expired ? { completedAt: prepared.approvalRequest.expiresAt, error: { code: "APPROVAL_EXPIRED", retryable: false } } : {}) });
  }
  if (!verifyApprovalEnvelope(storedApproval, run, prepared.plan, prepared.approvalRequest, owner.ownerDigest)) throw new Error("approval envelope integrity verification failed");
  const approval = approvalProjection(prepared.approvalRequest, storedApproval.decision);
  if (storedApproval.decision.decision === "REJECT") return response(200, { ...baseStatus(run, "REJECTED", "COMPLETE"), completedAt: storedApproval.decision.decidedAt, agentStackResult, governedState, improveContext: prepared.improve, plan: prepared.plan, approval });
  const mutation = await readJob(run, storedApproval.mutationJobId, "MUTATION#");
  if (["QUEUED", "RUNNING"].includes(mutation.state)) return response(200, { ...baseStatus(run, "RUNNING", "APPLYING_GOVERNED_WRITE"), agentStackResult, governedState, improveContext: prepared.improve, plan: prepared.plan, approval });
  if (mutation.state === "FAILED") return response(200, { ...baseStatus(run, "FAILED", "APPLYING_GOVERNED_WRITE"), completedAt: mutation.receipt.completedAt, agentStackResult, governedState, improveContext: prepared.improve, plan: prepared.plan, approval, error: { code: mutation.receipt.error.code, retryable: mutation.receipt.error.retryable === true } });
  const result = governedMutationResult(mutation.receipt, prepared, storedApproval, mutation.request, run);
  const postMarker = await readPostVerificationMarker(run, prepared, mutation.receipt);
  const remediation = {
    schemaVersion: "archon.governed-remediation-projection/v2",
    jobId: storedApproval.mutationJobId,
    receiptDigest: mutation.receipt.receiptDigest,
    requestDigest: result.requestDigest,
    beforeDigest: result.beforeDigest,
    afterDigest: result.afterDigest,
    responseDigest: result.responseDigest,
    policyDigest: result.policyDigest,
    mutationExecutor: result.mutationExecutor,
    officialMcpMutation: result.officialMcpMutation,
    authorizationEvidence: {
      algorithm: result.authorizationEvidence.algorithm,
      canonicalization: result.authorizationEvidence.canonicalization,
      keyReferenceDigest: digest({ schemaVersion: "archon.kms-key-reference/v1", keyArn: result.authorizationEvidence.keyArn }),
      envelopeDigest: result.authorizationEvidence.envelopeDigest,
      signatureDigest: result.authorizationEvidence.signatureDigest,
      consumedAt: result.authorizationEvidence.consumedAt
    },
    verified: true
  };
  if (!postMarker) return response(200, {
    ...baseStatus(run, "RUNNING", "VERIFYING_CONTEXT_DELTA"),
    agentStackResult,
    governedState,
    improveContext: prepared.improve,
    plan: prepared.plan,
    approval,
    remediation
  });
  const postAnalysis = await readJob(run, postMarker.analysisJobId, "SESSION#");
  const postRead = await readJob(run, postMarker.readJobId, "SESSION#");
  if (["QUEUED", "RUNNING"].includes(postAnalysis.state) || ["QUEUED", "RUNNING"].includes(postRead.state)) {
    return response(200, {
      ...baseStatus(run, "RUNNING", "VERIFYING_CONTEXT_DELTA"),
      agentStackResult,
      governedState,
      improveContext: prepared.improve,
      plan: prepared.plan,
      approval,
      remediation
    });
  }
  if (postAnalysis.state === "FAILED" || postRead.state === "FAILED") {
    const failed = postAnalysis.state === "FAILED" ? postAnalysis : postRead;
    return response(200, {
      ...baseStatus(run, "FAILED", "VERIFYING_CONTEXT_DELTA"),
      completedAt: failed.receipt.completedAt,
      agentStackResult,
      governedState,
      improveContext: prepared.improve,
      plan: prepared.plan,
      approval,
      remediation,
      error: { code: failed.receipt.error.code, retryable: failed.receipt.error.retryable === true }
    });
  }
  const verified = verifiedContextDelta(
    run,
    prepared,
    mutation.receipt,
    postMarker,
    analysis.receipt,
    postAnalysis.receipt,
    postRead.receipt
  );
  const completedAt = Date.parse(postAnalysis.receipt.completedAt) >= Date.parse(postRead.receipt.completedAt)
    ? postAnalysis.receipt.completedAt
    : postRead.receipt.completedAt;
  const skillCompletion = enrichSkillCompletion(
    analysis.receipt,
    storedApproval,
    mutation.receipt
  );
  return response(200, {
    ...baseStatus(run, "SUCCEEDED", "COMPLETE"),
    completedAt,
    agentStackResult: verified.postAgentStackResult,
    governedState: verified.postGovernedState,
    improveContext: prepared.improve,
    plan: prepared.plan,
    approval,
    remediation,
    skillCompletion,
    contextDelta: verified.contextDelta
  });
}
function parseEmptyBody(input) {
  let body = input;
  let text;
  if (record(input)) text = JSON.stringify(input);
  else if (typeof input === "string") {
    text = input;
    try { body = JSON.parse(input); } catch { return { error: response(400, { error: "invalid_json" }) }; }
  } else return { error: response(400, { error: "invalid_body" }) };
  if (Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES || !exactKeys(body, [])) return { error: response(400, { error: "invalid_improve_context_request" }) };
  return { body };
}
async function existingImproveDispatchIsExact(run, analysisReceipt, marker, request) {
  if (!verifyImproveMarker(marker, run, analysisReceipt) || marker.requestDigest !== digest(request)) return false;
  const item = await getItem(tableName("runtime job table", runtimeJobTable), "SESSION#" + run.runtimeEvidence.runtimeSessionId, "JOB#" + marker.jobId);
  if (!item) return false;
  const value = fromAttributeMap(item);
  return value.schema === "archon.runtime-bound-job/v2" && value.profileId === run.runtimeEvidence.runtimeBinding.profileId && value.jobId === marker.jobId && value.auditId === run.auditId &&
    value.runtimeEvidenceDigest === run.runtimeEvidence.digest && value.sessionId === run.runtimeEvidence.runtimeSessionId &&
    value.generation === run.runtimeEvidence.runtimeBinding.generation && value.capabilityDigest === run.runtimeEvidence.runtimeBinding.capabilityDigest &&
    value.operation === "IMPROVE_CONTEXT" && same(value.request, request) && ["QUEUED", "RUNNING", "SUCCEEDED", "FAILED"].includes(value.state);
}
function improveStartResponse(run, marker, statusCode) {
  return response(statusCode, {
    schemaVersion: "archon.runtime-improve-context-start/v2",
    auditId: run.auditId,
    status: "RUNNING",
    phase: "IMPROVING_CONTEXT",
    pollUrl: "/api/control-loops-v2/" + run.auditId,
    jobId: marker.jobId,
    requestDigest: marker.requestDigest,
    submittedAt: marker.submittedAt
  }, { location: "/api/control-loops-v2/" + run.auditId, "retry-after": "2" });
}
async function requestImprove(auditId, body, identity) {
  if (!AUDIT_ID.test(auditId || "")) return response(400, { error: "invalid_audit_id" });
  const owner = parseIdentity(identity, runtimeOperatorGroup);
  if (owner.error) return owner.error;
  const parsed = parseEmptyBody(body);
  if (parsed.error) return parsed.error;
  const loaded = await readRun(auditId, owner.ownerDigest, true, new Date().toISOString());
  if (loaded.error) return loaded.error;
  const run = { ...loaded.run, ownerDigest: owner.ownerDigest };
  if (run.mode !== "GOVERNED") return response(409, { error: "improve_context_not_available" });
  const analysis = await readJob(run, run.analysisJobId, "SESSION#");
  const read = await readJob(run, run.readJobId, "SESSION#");
  if (analysis.state !== "SUCCEEDED" || read.state !== "SUCCEEDED") return response(409, { error: "improve_context_not_ready" });
  agentStackProjection(analysis.receipt.result, run);
  tagState(read.receipt.result, run);
  const existingApproval = await readApproval(run);
  if (existingApproval) return response(409, { error: "approval_already_decided" });
  const submittedAt = new Date().toISOString();
  const dispatch = improveMarkerPayload(run, analysis.receipt, submittedAt);
  const existing = await readImproveMarker(run, analysis.receipt);
  if (existing) {
    if (!(await existingImproveDispatchIsExact(run, analysis.receipt, existing, dispatch.request))) throw new Error("existing improve-context dispatch is inconsistent");
    return improveStartResponse(run, existing, 200);
  }
  const job = runtimeJobItem(loaded.session, dispatch.marker.jobId, "IMPROVE_CONTEXT", dispatch.request, run.runtimeEvidence, submittedAt);
  const markerItem = {
    pk: { S: "AUDIT#" + run.auditId }, sk: { S: "IMPROVE" }, payload: { S: JSON.stringify(dispatch.marker) }, principalHash: { S: owner.ownerDigest },
    expiresAt: { N: String(Math.floor(Date.parse(run.runtimeEvidence.runtimeBinding.leaseExpiresAt) / 1000) + RETENTION_SECONDS) }
  };
  try {
    await dynamodb.send(new TransactWriteItemsCommand({ TransactItems: [
      { Put: { TableName: tableName("runtime session table", runtimeSessionTable), Item: markerItem, ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)" } },
      { Put: { TableName: tableName("runtime job table", runtimeJobTable), Item: job, ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)" } }
    ] }));
  } catch (error) {
    const concurrent = await readImproveMarker(run, analysis.receipt);
    if (!concurrent || !(await existingImproveDispatchIsExact(run, analysis.receipt, concurrent, dispatch.request))) throw error;
    return improveStartResponse(run, concurrent, 200);
  }
  return improveStartResponse(run, dispatch.marker, 202);
}
function parseDecisionBody(input) {
  let body = input;
  let text;
  if (record(input)) text = JSON.stringify(input);
  else if (typeof input === "string") {
    text = input;
    try { body = JSON.parse(input); } catch { return { error: response(400, { error: "invalid_json" }) }; }
  } else return { error: response(400, { error: "invalid_body" }) };
  if (Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES || !exactKeys(body, ["decision"], ["comment"]) || !["APPROVE", "REJECT"].includes(body.decision) ||
      (body.comment !== undefined && (typeof body.comment !== "string" || body.comment.length > 1000 || /[\u0000\u007F]/u.test(body.comment)))) {
    return { error: response(400, { error: "invalid_approval_decision" }) };
  }
  return { decision: body.decision, comment: body.comment || "" };
}
async function decide(auditId, body, identity) {
  if (!AUDIT_ID.test(auditId || "")) return response(400, { error: "invalid_audit_id" });
  const owner = parseIdentity(identity, runtimeApproverGroup);
  if (owner.error) return owner.error;
  const parsed = parseDecisionBody(body);
  if (parsed.error) return parsed.error;
  const loaded = await readRun(auditId, owner.ownerDigest, true, new Date().toISOString());
  if (loaded.error) return loaded.error;
  const run = { ...loaded.run, ownerDigest: owner.ownerDigest };
  const analysis = await readJob(run, run.analysisJobId, "SESSION#");
  const read = run.readJobId ? await readJob(run, run.readJobId, "SESSION#") : undefined;
  if (run.mode !== "GOVERNED" || analysis.state !== "SUCCEEDED" || !read || read.state !== "SUCCEEDED") return response(409, { error: "approval_not_ready" });
  agentStackProjection(analysis.receipt.result, run);
  tagState(read.receipt.result, run);
  const marker = await readImproveMarker(run, analysis.receipt);
  if (!marker) return response(409, { error: "improve_context_required" });
  const improve = await readJob(run, marker.jobId, "SESSION#");
  if (improve.state !== "SUCCEEDED") return response(409, { error: "improve_context_not_ready" });
  const prepared = planFor(run, analysis.receipt, read.receipt, improve.receipt);
  if (Date.parse(prepared.approvalRequest.expiresAt) <= Date.now()) return response(409, { error: "approval_expired" });
  const existing = await readApproval(run);
  if (existing) {
    if (!verifyApprovalEnvelope(existing, run, prepared.plan, prepared.approvalRequest, owner.ownerDigest)) throw new Error("approval envelope integrity verification failed");
    if (existing.decision.decision !== parsed.decision) return response(409, { error: "approval_already_decided" });
    return response(200, { schemaVersion: "archon.runtime-approval-decision-response/v2", auditId, approval: approvalProjection(prepared.approvalRequest, existing.decision) });
  }
  const decidedAt = new Date().toISOString();
  const decisionPayload = {
    schemaVersion: "archon.runtime-approval-decision/v2",
    approvalId: prepared.approvalRequest.approvalId,
    auditId,
    requestDigest: prepared.approvalRequest.digest,
    planDigest: prepared.plan.digest,
    decision: parsed.decision,
    approverDigest: owner.ownerDigest,
    decidedAt,
    commentDigest: digest({ comment: parsed.comment })
  };
  const decision = { ...decisionPayload, digest: digest(decisionPayload) };
  const envelopePayload = {
    schemaVersion: "archon.runtime-approved-action/v2",
    auditId,
    ownerDigest: owner.ownerDigest,
    runtimeEvidence: run.runtimeEvidence,
    plan: prepared.plan,
    approvalRequest: prepared.approvalRequest,
    decision,
    mutationJobId: jobId("mutation", auditId),
    createdAt: decidedAt
  };
  const envelope = { ...envelopePayload, digest: digest(envelopePayload) };
  await dynamodb.send(new PutItemCommand({
    TableName: tableName("runtime session table", runtimeSessionTable),
    Item: {
      pk: { S: "AUDIT#" + auditId }, sk: { S: "APPROVAL" }, payload: { S: JSON.stringify(envelope) }, principalHash: { S: owner.ownerDigest },
      expiresAt: { N: String(Math.floor(Date.parse(run.runtimeEvidence.runtimeBinding.leaseExpiresAt) / 1000) + RETENTION_SECONDS) }
    },
    ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)"
  }));
  return response(202, { schemaVersion: "archon.runtime-approval-decision-response/v2", auditId, approval: approvalProjection(prepared.approvalRequest, decision) }, { "retry-after": "2" });
}
function verifyExistingMutationJob(value, run, session, prepared, envelope) {
  if (value.schema !== "archon.runtime-bound-job/v2" || value.profileId !== session.binding.profileId || value.pk !== "MUTATION#" + session.sessionId ||
      value.sk !== "JOB#" + envelope.mutationJobId || value.jobId !== envelope.mutationJobId || value.auditId !== run.auditId ||
      value.runtimeEvidenceDigest !== run.runtimeEvidence.digest || value.sessionId !== session.sessionId ||
      value.generation !== session.binding.generation || value.capabilityDigest !== session.binding.capabilityDigest ||
      value.operation !== "GOVERNED_TAG_MUTATION" || !["QUEUED", "RUNNING", "SUCCEEDED", "FAILED"].includes(value.state) ||
      !record(value.request)) throw new Error("existing governed mutation job binding verification failed");
  const authorization = verifyMutationRequestAuthorization(value.request, run, prepared, envelope);
  if (value.submittedAt !== authorization.issuedAt) throw new Error("existing governed mutation job issue time mismatch");
  return value;
}
async function processApprovalEnvelope(envelope) {
  if (!record(envelope) || !AUDIT_ID.test(envelope.auditId || "") || !DIGEST.test(envelope.ownerDigest || "")) throw new Error("invalid approval stream envelope");
  const loaded = await readRun(envelope.auditId, envelope.ownerDigest);
  if (loaded.error) throw new Error("approval source run is unavailable");
  const run = { ...loaded.run, ownerDigest: envelope.ownerDigest };
  const analysis = await readJob(run, run.analysisJobId, "SESSION#");
  const read = await readJob(run, run.readJobId, "SESSION#");
  if (analysis.state !== "SUCCEEDED" || read.state !== "SUCCEEDED") throw new Error("approval source receipts are incomplete");
  agentStackProjection(analysis.receipt.result, run);
  tagState(read.receipt.result, run);
  const marker = await readImproveMarker(run, analysis.receipt);
  if (!marker) throw new Error("approval lacks an improve-context dispatch");
  const improve = await readJob(run, marker.jobId, "SESSION#");
  if (improve.state !== "SUCCEEDED") throw new Error("approval improve-context receipt is incomplete");
  const prepared = planFor(run, analysis.receipt, read.receipt, improve.receipt);
  if (!verifyApprovalEnvelope(envelope, run, prepared.plan, prepared.approvalRequest, envelope.ownerDigest)) throw new Error("approval stream integrity verification failed");
  if (envelope.decision.decision !== "APPROVE") return;
  const existingKey = ["MUTATION#" + loaded.session.sessionId, "JOB#" + envelope.mutationJobId];
  const existing = await getItem(tableName("runtime job table", runtimeJobTable), existingKey[0], existingKey[1]);
  if (existing) {
    verifyExistingMutationJob(fromAttributeMap(existing), run, loaded.session, prepared, envelope);
    return;
  }
  const issuedAt = new Date().toISOString();
  if (loaded.session.state !== "ACTIVE" || Date.parse(issuedAt) >= Date.parse(loaded.session.idleExpiresAt) ||
      Date.parse(issuedAt) >= Date.parse(loaded.session.hardExpiresAt) || Date.parse(issuedAt) >= Date.parse(prepared.approvalRequest.expiresAt)) {
    throw new Error("approval source runtime session is not active");
  }
  const approval = mutationApproval(envelope);
  const authorization = await createMutationAuthorization(run, prepared, envelope, issuedAt);
  const requestPayload = {
    schemaVersion: "archon.core-governed-tag-mutation/v1",
    auditId: run.auditId,
    runtimeEvidenceDigest: run.runtimeEvidence.digest,
    auditEvidenceDigest: prepared.plan.auditEvidenceDigest,
    planDigest: prepared.plan.digest,
    policyDigest: prepared.plan.policyDigest,
    approval,
    action: prepared.plan.action,
    arguments: prepared.plan.arguments,
    expectedBeforeDigest: prepared.plan.expectedBeforeDigest,
    expectedAfterDigest: prepared.plan.expectedAfterDigest,
    authorization
  };
  const request = { ...requestPayload, requestDigest: digest(requestPayload) };
  verifyMutationRequestAuthorization(request, run, prepared, envelope);
  const item = runtimeJobItem(loaded.session, envelope.mutationJobId, "GOVERNED_TAG_MUTATION", request, run.runtimeEvidence, issuedAt);
  item.pk = { S: existingKey[0] };
  try {
    await dynamodb.send(new PutItemCommand({
      TableName: tableName("runtime job table", runtimeJobTable),
      Item: item,
      ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)"
    }));
  } catch (error) {
    if (error && error.name === "ConditionalCheckFailedException") {
      const raced = await getItem(tableName("runtime job table", runtimeJobTable), existingKey[0], existingKey[1]);
      if (raced) {
        verifyExistingMutationJob(fromAttributeMap(raced), run, loaded.session, prepared, envelope);
        return;
      }
    }
    throw error;
  }
}
async function processMutationReceipt(image) {
  if (image.schema !== "archon.runtime-bound-job/v2" || !["cloud", "core"].includes(image.profileId) || image.operation !== "GOVERNED_TAG_MUTATION" ||
      image.state !== "SUCCEEDED" || !AUDIT_ID.test(image.auditId || "") || !JOB_ID.test(image.jobId || "") ||
      !SESSION_ID.test(image.sessionId || "") || image.pk !== "MUTATION#" + image.sessionId ||
      image.sk !== "JOB#" + image.jobId || !record(image.receipt)) {
    throw new Error("invalid governed mutation stream image");
  }
  const runItem = await getItem(
    tableName("runtime session table", runtimeSessionTable),
    "AUDIT#" + image.auditId,
    "RUNTIME",
    "principalHash"
  );
  const ownerDigest = stringAttribute(runItem, "principalHash");
  if (!DIGEST.test(ownerDigest || "")) throw new Error("post-mutation run owner is unavailable");
  const loaded = await readRun(image.auditId, ownerDigest, true, new Date().toISOString());
  if (loaded.error) throw new Error("post-mutation source run is unavailable");
  const run = { ...loaded.run, ownerDigest };
  const analysis = await readJob(run, run.analysisJobId, "SESSION#");
  const read = await readJob(run, run.readJobId, "SESSION#");
  if (analysis.state !== "SUCCEEDED" || read.state !== "SUCCEEDED") throw new Error("post-mutation source receipts are incomplete");
  agentStackProjection(analysis.receipt.result, run);
  tagState(read.receipt.result, run);
  const improveMarker = await readImproveMarker(run, analysis.receipt);
  if (!improveMarker) throw new Error("post-mutation source improve-context dispatch is missing");
  const improve = await readJob(run, improveMarker.jobId, "SESSION#");
  if (improve.state !== "SUCCEEDED") throw new Error("post-mutation source improve-context receipt is incomplete");
  const prepared = planFor(run, analysis.receipt, read.receipt, improve.receipt);
  const approval = await readApproval(run);
  if (!approval || !verifyApprovalEnvelope(approval, run, prepared.plan, prepared.approvalRequest, ownerDigest) ||
      approval.decision.decision !== "APPROVE" || approval.mutationJobId !== image.jobId) {
    throw new Error("post-mutation source approval is invalid");
  }
  const mutation = await readJob(run, approval.mutationJobId, "MUTATION#");
  if (mutation.state !== "SUCCEEDED" || !same(mutation.receipt, image.receipt) || !same(mutation.request, image.request)) {
    throw new Error("post-mutation receipt does not match the durable job");
  }
  governedMutationResult(mutation.receipt, prepared, approval, mutation.request, run);
  const dispatch = postVerificationDispatch(run, prepared, mutation.receipt);
  const markerItem = {
    pk: { S: "AUDIT#" + run.auditId },
    sk: { S: "POST_VERIFY" },
    payload: { S: JSON.stringify(dispatch.marker) },
    principalHash: { S: ownerDigest },
    expiresAt: { N: String(Math.floor(Date.parse(run.runtimeEvidence.runtimeBinding.leaseExpiresAt) / 1000) + RETENTION_SECONDS) }
  };
  const analysisItem = runtimeJobItem(
    loaded.session,
    dispatch.marker.analysisJobId,
    "POST_ANALYZE",
    dispatch.analysisRequest,
    run.runtimeEvidence,
    dispatch.marker.submittedAt
  );
  const readItem = runtimeJobItem(
    loaded.session,
    dispatch.marker.readJobId,
    "POST_READ_TAGS",
    dispatch.readRequest,
    run.runtimeEvidence,
    dispatch.marker.submittedAt
  );
  try {
    await dynamodb.send(new TransactWriteItemsCommand({ TransactItems: [
      { Put: { TableName: tableName("runtime session table", runtimeSessionTable), Item: markerItem, ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)" } },
      { Put: { TableName: tableName("runtime job table", runtimeJobTable), Item: analysisItem, ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)" } },
      { Put: { TableName: tableName("runtime job table", runtimeJobTable), Item: readItem, ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)" } }
    ] }));
  } catch (error) {
    if (!error || !["ConditionalCheckFailedException", "TransactionCanceledException"].includes(error.name)) throw error;
    const existingMarker = await readPostVerificationMarker(run, prepared, mutation.receipt);
    const existingAnalysis = fromAttributeMap(await getItem(
      tableName("runtime job table", runtimeJobTable),
      "SESSION#" + run.runtimeEvidence.runtimeSessionId,
      "JOB#" + dispatch.marker.analysisJobId
    ) || {});
    const existingRead = fromAttributeMap(await getItem(
      tableName("runtime job table", runtimeJobTable),
      "SESSION#" + run.runtimeEvidence.runtimeSessionId,
      "JOB#" + dispatch.marker.readJobId
    ) || {});
    if (!existingMarker || !same(existingAnalysis.request, dispatch.analysisRequest) ||
        !same(existingRead.request, dispatch.readRequest) ||
        existingAnalysis.operation !== "POST_ANALYZE" || existingRead.operation !== "POST_READ_TAGS") {
      throw error;
    }
  }
}
async function remediationStream(event) {
  if (!record(event) || !Array.isArray(event.Records)) throw new Error("invalid DynamoDB stream event");
  for (const streamRecord of event.Records) {
    if (!["INSERT", "MODIFY"].includes(streamRecord.eventName) ||
        !record(streamRecord.dynamodb) || !record(streamRecord.dynamodb.NewImage)) continue;
    const image = fromAttributeMap(streamRecord.dynamodb.NewImage);
    if (streamRecord.eventName === "INSERT" && image.sk === "APPROVAL" && typeof image.payload === "string") {
      let envelope;
      try { envelope = JSON.parse(image.payload); } catch { throw new Error("approval stream payload is not JSON"); }
      await processApprovalEnvelope(envelope);
      continue;
    }
    if (image.pk === "MUTATION#" + image.sessionId && image.operation === "GOVERNED_TAG_MUTATION" &&
        image.state === "SUCCEEDED" && record(image.receipt)) {
      await processMutationReceipt(image);
    }
  }
  return { batchItemFailures: [] };
}
module.exports = {
  decideRuntimeV2: decide,
  remediationStream,
  requestImproveRuntimeV2: requestImprove,
  startRuntimeV2: start,
  statusRuntimeV2: status,
  _test: { canonicalize, canonicalMutationEnvelope, capabilityDigest, digest, enrichSkillCompletion, fromAttributeMap, jobId, mutationEnvelopeDigest, toAttribute }
};