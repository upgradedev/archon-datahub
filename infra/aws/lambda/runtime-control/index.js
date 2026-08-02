"use strict";

const { createHash } = require("node:crypto");
const {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand
} = require("@aws-sdk/client-dynamodb");
const {
  SFNClient,
  StartExecutionCommand
} = require("@aws-sdk/client-sfn");
const {
  activity,
  capabilityDigest,
  completeStop,
  createSession,
  failSession,
  generateSessionId,
  markReady,
  publicStatus,
  requestStop,
  tick,
  validateHealth,
  validateSession,
  validateSessionId
} = require("./session.js");

const dynamodb = new DynamoDBClient({});
const stepFunctions = new SFNClient({});
const runtimeSessionTable = process.env.RUNTIME_SESSION_TABLE;
const coreLeaseTable = process.env.CORE_LEASE_TABLE;
const coreStateMachineArn = process.env.CORE_SESSION_STATE_MACHINE_ARN;
const runtimeOperatorGroup =
  process.env.RUNTIME_OPERATOR_GROUP || "archon-approvers";

const MAX_BODY_BYTES = 1024;
const REQUESTS = ["auto", "cloud", "core"];
const PROFILE_IDS = ["cloud", "core"];
const SESSION_RETENTION_SECONDS = 24 * 60 * 60;

class PublicError extends Error {
  constructor(statusCode, code) {
    super(code);
    this.name = "PublicError";
    this.statusCode = statusCode;
    this.code = code;
  }
}

function response(statusCode, payload, extraHeaders = {}) {
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
    payload
  };
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, required) {
  if (!record(value)) return false;
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === required.length &&
    keys.every(
      (key) => typeof key === "string" && required.includes(key)
    ) &&
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

function groupsFrom(claim) {
  if (typeof claim !== "string") return [];
  return claim
    .replace(/[\[\]"]/gu, "")
    .split(/[,\s]+/u)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parseIdentity(value) {
  if (
    !exactKeys(value, ["subject", "issuer", "groups"]) ||
    typeof value.subject !== "string" ||
    value.subject.length < 1 ||
    value.subject.length > 512 ||
    /[^@-^_\u007f]/u.test(value.subject) ||
    typeof value.issuer !== "string" ||
    value.issuer.length < 8 ||
    value.issuer.length > 2048 ||
    !value.issuer.startsWith("https://") ||
    /[^@-^_\u007f]/u.test(value.issuer) ||
    typeof value.groups !== "string" ||
    value.groups.length > 2048 ||
    /[^@-^_\u007f]/u.test(value.groups)
  ) {
    throw new PublicError(401, "authenticated_runtime_operator_required");
  }
  if (!groupsFrom(value.groups).includes(runtimeOperatorGroup)) {
    throw new PublicError(403, "runtime_operator_role_required");
  }
  return {
    subject: value.subject,
    issuer: value.issuer
  };
}

function ownerDigest(identity) {
  return (
    "sha256:" +
    createHash("sha256")
      .update(
        JSON.stringify({
          issuer: identity.issuer,
          subject: identity.subject
        }),
        "utf8"
      )
      .digest("hex")
  );
}

function configured(name, value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 2048) {
    throw new Error(name + " is not configured");
  }
  return value;
}

function now() {
  return new Date().toISOString();
}

function parseBody(input) {
  let body = input;
  let text;
  if (record(input)) {
    text = JSON.stringify(input);
  } else if (typeof input === "string") {
    text = input;
    try {
      body = JSON.parse(text);
    } catch {
      throw new PublicError(400, "invalid_json");
    }
  } else {
    throw new PublicError(400, "invalid_body");
  }
  if (Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES || !record(body)) {
    throw new PublicError(
      Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES ? 413 : 400,
      Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES
        ? "request_too_large"
        : "invalid_body"
    );
  }
  return body;
}

function parseStartBody(input) {
  const body = parseBody(input);
  if (
    !exactKeys(body, ["requestedProfile"]) ||
    !REQUESTS.includes(body.requestedProfile)
  ) {
    throw new PublicError(400, "invalid_runtime_request");
  }
  return body.requestedProfile;
}

function stringAttribute(item, key) {
  const attribute = item && item[key];
  return attribute && typeof attribute.S === "string"
    ? attribute.S
    : undefined;
}

function numberAttribute(item, key) {
  const attribute = item && item[key];
  if (!attribute || typeof attribute.N !== "string") return undefined;
  const value = Number(attribute.N);
  return Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function capabilitiesAttribute(item) {
  const value = item && item.capabilities;
  if (!value || !record(value.M)) return undefined;
  const expected = [
    "mcpRead",
    "mcpGovernedWrite",
    "agentContextKit",
    "dataHubSkills",
    "analyticsAgent"
  ];
  if (
    Reflect.ownKeys(value.M).length !== expected.length ||
    expected.some(
      (key) =>
        !value.M[key] ||
        typeof value.M[key].BOOL !== "boolean" ||
        Reflect.ownKeys(value.M[key]).length !== 1
    )
  ) {
    return undefined;
  }
  return Object.fromEntries(
    expected.map((key) => [key, value.M[key].BOOL])
  );
}

function healthFromItem(profileId, item) {
  if (!item) throw new Error("runtime health is absent");
  const generation = stringAttribute(item, "generation");
  const status = stringAttribute(item, "status");
  const checkedAt = stringAttribute(item, "checkedAt");
  const capabilities = capabilitiesAttribute(item);
  const digest = stringAttribute(item, "capabilityDigest");
  if (
    !generation ||
    !status ||
    !checkedAt ||
    !capabilities ||
    !digest
  ) {
    throw new Error("runtime health is malformed");
  }
  return {
    profileId,
    generation,
    status,
    checkedAt,
    capabilities,
    capabilityDigest: digest,
    sessionId: stringAttribute(item, "sessionId") ?? null
  };
}

async function getItem(tableName, pk, sk) {
  const result = await dynamodb.send(
    new GetItemCommand({
      TableName: configured("DynamoDB table", tableName),
      Key: { pk: { S: pk }, sk: { S: sk } },
      ConsistentRead: true,
      ProjectionExpression:
        "pk, sk, payload, revision, principalHash, generation, #status, #state, checkedAt, capabilities, capabilityDigest, sessionId, expiresAt",
      ExpressionAttributeNames: { "#status": "status", "#state": "state" }
    })
  );
  return result.Item;
}

async function readHealth(profileId) {
  if (!PROFILE_IDS.includes(profileId)) {
    throw new Error("unsupported runtime profile");
  }
  const table =
    profileId === "cloud" ? runtimeSessionTable : coreLeaseTable;
  return healthFromItem(
    profileId,
    await getItem(table, "RUNTIME#" + profileId, "HEALTH")
  );
}

async function readCoreLease() {
  const item = await getItem(coreLeaseTable, "CORE#LEASE", "CURRENT");
  if (!item) return { revision: 0, sessionId: null, state: "STOPPED" };
  const revision = numberAttribute(item, "revision");
  const state = stringAttribute(item, "state");
  if (
    revision === undefined ||
    !state ||
    !["STARTING", "READY", "DRAINING", "STOPPED", "FAILED"].includes(state)
  ) {
    throw new Error("Core lease is malformed");
  }
  return {
    revision,
    sessionId: stringAttribute(item, "sessionId") ?? null,
    state
  };
}

function unavailableProfile(profileId) {
  return {
    profileId,
    availability: "UNAVAILABLE",
    generation: null,
    checkedAt: null,
    capabilities: {
      mcpRead: false,
      mcpGovernedWrite: false,
      agentContextKit: false,
      dataHubSkills: false,
      analyticsAgent: false
    },
    capabilityDigest: null
  };
}

function projectProfile(profileId, raw, currentTime) {
  try {
    if (profileId === "cloud") {
      const health = validateHealth(raw, "cloud", currentTime);
      if (health.status !== "READY") return unavailableProfile("cloud");
      return {
        profileId: "cloud",
        availability: "READY",
        generation: health.generation,
        checkedAt: health.checkedAt,
        capabilities: health.capabilities,
        capabilityDigest: health.capabilityDigest
      };
    }
    if (raw.status === "STOPPED") {
      const candidate = validateHealth(raw, "core", currentTime, {
        candidate: true
      });
      return {
        profileId: "core",
        availability: "LAUNCHABLE",
        generation: candidate.generation,
        checkedAt: candidate.checkedAt,
        capabilities: candidate.capabilities,
        capabilityDigest: candidate.capabilityDigest
      };
    }
    const health = validateHealth(raw, "core", currentTime);
    return {
      profileId: "core",
      availability:
        health.status === "STARTING"
          ? "STARTING"
          : health.status === "READY"
            ? "BUSY"
            : "UNAVAILABLE",
      generation: health.generation,
      checkedAt: health.checkedAt,
      capabilities: health.capabilities,
      capabilityDigest: health.capabilityDigest
    };
  } catch {
    return unavailableProfile(profileId);
  }
}

async function profiles() {
  const currentTime = now();
  const [cloudResult, coreResult] = await Promise.allSettled([
    readHealth("cloud"),
    readHealth("core")
  ]);
  const cloud = projectProfile(
    "cloud",
    cloudResult.status === "fulfilled" ? cloudResult.value : {},
    currentTime
  );
  const core = projectProfile(
    "core",
    coreResult.status === "fulfilled" ? coreResult.value : {},
    currentTime
  );
  return response(200, {
    schemaVersion: "archon.runtime-profiles/v1",
    serverTime: currentTime,
    profiles: [cloud, core],
    autoSelection:
      cloud.availability === "READY"
        ? "cloud"
        : core.availability === "LAUNCHABLE"
          ? "core"
          : null
  });
}

function bindingFor(requestedProfile, health, currentTime) {
  const boundAtMs = Date.parse(currentTime);
  return {
    schemaVersion: "archon.runtime-binding/v1",
    profileId: health.profileId,
    generation: health.generation,
    capabilityDigest: health.capabilityDigest,
    resolution: requestedProfile === "auto" ? "auto" : "explicit",
    boundAt: currentTime,
    leaseExpiresAt: new Date(boundAtMs + 2 * 60 * 60_000).toISOString()
  };
}

async function selectStartProfile(requestedProfile, currentTime) {
  const cloudPromise =
    requestedProfile === "core"
      ? Promise.resolve(null)
      : readHealth("cloud").catch(() => null);
  const corePromise =
    requestedProfile === "cloud"
      ? Promise.resolve(null)
      : readHealth("core").catch(() => null);
  const [cloudRaw, coreRaw] = await Promise.all([cloudPromise, corePromise]);

  if (requestedProfile !== "core" && cloudRaw) {
    try {
      const cloud = validateHealth(cloudRaw, "cloud", currentTime);
      if (cloud.status === "READY") return { health: cloud, state: "ACTIVE" };
    } catch {
      if (requestedProfile === "cloud") {
        throw new PublicError(409, "runtime_not_ready");
      }
    }
  }
  if (requestedProfile === "cloud") {
    throw new PublicError(409, "runtime_not_ready");
  }

  if (coreRaw) {
    try {
      const core = validateHealth(coreRaw, "core", currentTime, {
        candidate: true
      });
      const lease = await readCoreLease();
      if (
        lease.state !== "STOPPED" &&
        !(lease.state === "FAILED" && lease.sessionId === null)
      ) {
        throw new PublicError(409, "runtime_busy");
      }
      return {
        health: core,
        state: "STARTING",
        coreExpectedRevision: lease.revision
      };
    } catch (error) {
      if (error instanceof PublicError) throw error;
    }
  }
  throw new PublicError(409, "runtime_not_ready");
}

function sessionItem(session, principalHash) {
  return {
    pk: { S: "SESSION#" + session.sessionId },
    sk: { S: "RUNTIME" },
    payload: { S: JSON.stringify(session) },
    revision: { N: String(session.revision) },
    principalHash: { S: principalHash },
    expiresAt: {
      N: String(
        Math.floor(Date.parse(session.hardExpiresAt) / 1000) +
          SESSION_RETENTION_SECONDS
      )
    }
  };
}

async function putSession(session, principalHash) {
  if (!/^sha256:[a-f0-9]{64}$/u.test(principalHash)) {
    throw new Error("invalid runtime session owner digest");
  }
  await dynamodb.send(
    new PutItemCommand({
      TableName: configured("RUNTIME_SESSION_TABLE", runtimeSessionTable),
      Item: sessionItem(session, principalHash),
      ConditionExpression: "attribute_not_exists(pk)"
    })
  );
}

async function readSession(sessionId) {
  try {
    validateSessionId(sessionId);
  } catch {
    throw new PublicError(400, "invalid_runtime_session_id");
  }
  const item = await getItem(
    runtimeSessionTable,
    "SESSION#" + sessionId,
    "RUNTIME"
  );
  const payload = stringAttribute(item, "payload");
  const revision = numberAttribute(item, "revision");
  if (!payload || revision === undefined) {
    throw new PublicError(404, "runtime_session_not_found");
  }
  let session;
  try {
    session = validateSession(JSON.parse(payload));
  } catch {
    throw new Error("stored runtime session is invalid");
  }
  if (session.revision !== revision) {
    throw new Error("stored runtime session revision drift");
  }
  const principalHash = stringAttribute(item, "principalHash");
  if (!principalHash || !/^sha256:[a-f0-9]{64}$/u.test(principalHash)) {
    throw new Error("stored runtime session owner is invalid");
  }
  return { session, principalHash };
}

async function readOwnedSession(sessionId, identity) {
  const stored = await readSession(sessionId);
  if (stored.principalHash !== ownerDigest(parseIdentity(identity))) {
    throw new PublicError(403, "runtime_session_owner_mismatch");
  }
  return stored.session;
}

async function updateSession(previous, next) {
  if (previous.revision === next.revision) return next;
  await dynamodb.send(
    new UpdateItemCommand({
      TableName: configured("RUNTIME_SESSION_TABLE", runtimeSessionTable),
      Key: {
        pk: { S: "SESSION#" + previous.sessionId },
        sk: { S: "RUNTIME" }
      },
      UpdateExpression:
        "SET payload = :payload, revision = :next, expiresAt = :expiresAt",
      ConditionExpression: "revision = :expected",
      ExpressionAttributeValues: {
        ":payload": { S: JSON.stringify(next) },
        ":next": { N: String(next.revision) },
        ":expected": { N: String(previous.revision) },
        ":expiresAt": {
          N: String(
            Math.floor(Date.parse(next.hardExpiresAt) / 1000) +
              SESSION_RETENTION_SECONDS
          )
        }
      }
    })
  );
  return next;
}

async function coreCommand(action, session, expectedRevision) {
  const stateMachineArn = configured(
    "CORE_SESSION_STATE_MACHINE_ARN",
    coreStateMachineArn
  );
  const input = {
    schema: "archon.core-runtime-command/v1",
    action,
    sessionId: session.sessionId,
    expectedRevision,
    binding: session.binding
  };
  const name =
    action.toLowerCase() +
    "-" +
    session.sessionId +
    "-" +
    String(session.revision);
  await stepFunctions.send(
    new StartExecutionCommand({
      stateMachineArn,
      name: name.slice(0, 80),
      input: JSON.stringify(input)
    })
  );
}

async function startSession(body, identity) {
  const owner = ownerDigest(parseIdentity(identity));
  const requestedProfile = parseStartBody(body);
  const currentTime = now();
  const selected = await selectStartProfile(requestedProfile, currentTime);
  const session = createSession({
    sessionId: generateSessionId(),
    requestedProfile,
    binding: bindingFor(requestedProfile, selected.health, currentTime),
    state: selected.state
  });
  await putSession(session, owner);
  if (session.binding.profileId === "core") {
    try {
      await coreCommand(
        "START",
        session,
        0
      );
    } catch {
      const failed = failSession(session, "PROVISIONING_FAILED", now());
      await updateSession(session, failed).catch(() => undefined);
      throw new PublicError(502, "runtime_provisioning_failed");
    }
  }
  const status = publicStatus(session, currentTime);
  return response(
    status.state === "STARTING" ? 202 : 201,
    status,
    { location: "/api/runtime-sessions/" + session.sessionId }
  );
}

function healthMatchesSession(health, session) {
  return (
    health.generation === session.binding.generation &&
    health.capabilityDigest === session.binding.capabilityDigest &&
    (session.binding.profileId !== "core" ||
      health.sessionId === session.sessionId)
  );
}

async function reconcile(value, currentTime) {
  const original = validateSession(value);
  let session = tick(original, currentTime);

  if (
    session.binding.profileId === "core" &&
    ["STARTING", "ACTIVE", "STOPPING"].includes(session.state)
  ) {
    let raw;
    try {
      raw = await readHealth("core");
    } catch {
      if (session.state === "ACTIVE") {
        session = failSession(session, "HEALTH_CHECK_FAILED", currentTime);
      }
    }
    if (raw) {
      if (
        session.state === "STOPPING" &&
        raw.status === "STOPPED" &&
        raw.sessionId === session.sessionId
      ) {
        session = completeStop(session, currentTime);
      } else if (raw.status === "UNHEALTHY") {
        session = failSession(session, "HEALTH_CHECK_FAILED", currentTime);
      } else if (raw.status === "READY") {
        try {
          const health = validateHealth(raw, "core", currentTime);
          if (!healthMatchesSession(health, session)) {
            session = failSession(session, "RUNTIME_DRIFT", currentTime);
          } else if (session.state === "STARTING") {
            session = markReady(session, session.binding, currentTime);
          }
        } catch {
          session = failSession(session, "HEALTH_CHECK_FAILED", currentTime);
        }
      } else if (session.state === "ACTIVE") {
        session = failSession(session, "RUNTIME_DRIFT", currentTime);
      }
    }
  }

  if (
    session.binding.profileId === "cloud" &&
    session.state === "ACTIVE"
  ) {
    try {
      const health = validateHealth(
        await readHealth("cloud"),
        "cloud",
        currentTime
      );
      if (!healthMatchesSession(health, session)) {
        session = failSession(session, "RUNTIME_DRIFT", currentTime);
      }
    } catch {
      session = failSession(session, "HEALTH_CHECK_FAILED", currentTime);
    }
  }

  if (
    original.state !== "EXPIRED" &&
    session.state === "EXPIRED" &&
    session.binding.profileId === "core"
  ) {
    const lease = await readCoreLease();
    await coreCommand("STOP", session, lease.revision);
  }
  return updateSession(original, session);
}

async function sessionStatus(sessionId) {
  const currentTime = now();
  const stored = await readSession(sessionId);
  const session = await reconcile(stored.session, currentTime);
  return response(200, publicStatus(session, currentTime));
}

async function recordActivity(sessionId, identity) {
  const currentTime = now();
  const original = await reconcile(
    await readOwnedSession(sessionId, identity),
    currentTime
  );
  if (original.state !== "ACTIVE") {
    throw new PublicError(409, "runtime_session_not_active");
  }
  if (original.binding.profileId === "core") {
    const lease = await readCoreLease();
    if (
      lease.sessionId !== original.sessionId ||
      lease.state !== "READY"
    ) {
      throw new PublicError(409, "runtime_identity_mismatch");
    }
    await coreCommand("ACTIVITY", original, lease.revision);
  }
  const next = activity(original, original.binding, currentTime);
  await updateSession(original, next);
  return response(200, publicStatus(next, currentTime));
}

async function stopSession(sessionId, identity) {
  const currentTime = now();
  const original = await reconcile(
    await readOwnedSession(sessionId, identity),
    currentTime
  );
  let next = requestStop(original, currentTime);
  if (next.revision === original.revision) {
    return response(200, publicStatus(next, currentTime));
  }
  await updateSession(original, next);
  if (next.binding.profileId === "core") {
    try {
      const lease = await readCoreLease();
      await coreCommand("STOP", next, lease.revision);
    } catch {
      const failed = failSession(next, "CONTROL_PLANE_ERROR", now());
      await updateSession(next, failed).catch(() => undefined);
      throw new PublicError(502, "runtime_stop_failed");
    }
    return response(202, publicStatus(next, currentTime));
  }
  const stopped = completeStop(next, currentTime);
  await updateSession(next, stopped);
  return response(200, publicStatus(stopped, currentTime));
}

exports.handler = async (event) => {
  try {
    if (
      exactKeys(event, ["operation", "requestId"]) &&
      event.operation === "profiles"
    ) {
      return await profiles();
    }
    if (
      exactKeys(event, ["operation", "requestId", "body", "identity"]) &&
      event.operation === "sessionStart"
    ) {
      return await startSession(event.body, event.identity);
    }
    if (
      exactKeys(event, ["operation", "requestId", "sessionId"]) &&
      event.operation === "sessionStatus"
    ) {
      return await sessionStatus(event.sessionId);
    }
    if (
      exactKeys(event, ["operation", "requestId", "sessionId", "identity"]) &&
      event.operation === "sessionActivity"
    ) {
      return await recordActivity(event.sessionId, event.identity);
    }
    if (
      exactKeys(event, ["operation", "requestId", "sessionId", "identity"]) &&
      event.operation === "sessionStop"
    ) {
      return await stopSession(event.sessionId, event.identity);
    }
    return response(404, { error: "not_found" });
  } catch (error) {
    if (error instanceof PublicError) {
      return response(error.statusCode, { error: error.code });
    }
    if (error && error.name === "ConditionalCheckFailedException") {
      return response(409, { error: "runtime_session_conflict" });
    }
    const requestId =
      typeof event?.requestId === "string" &&
      /^[A-Za-z0-9=+/_-]{1,256}$/u.test(event.requestId)
        ? event.requestId
        : undefined;
    process.stderr.write(
      "[runtime-control] request_failed" +
        (requestId ? " request_id=" + requestId : "") +
        "\n"
    );
    return response(502, { error: "runtime_control_unavailable" });
  }
};
