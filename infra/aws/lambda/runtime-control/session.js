"use strict";

const { createHash, randomBytes } = require("node:crypto");

const PROFILE_IDS = ["cloud", "core"];
const REQUESTS = ["auto", "cloud", "core"];
const REQUIRED_CAPABILITIES = [
  "mcpRead",
  "mcpGovernedWrite",
  "agentContextKit",
  "dataHubSkills",
  "analyticsAgent"
];
const STATES = [
  "STARTING",
  "ACTIVE",
  "STOPPING",
  "STOPPED",
  "EXPIRED",
  "FAILED"
];
const SESSION_ID = /^rs_[A-Za-z0-9_-]{43}$/u;
const GENERATION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const RUNTIME_IDLE_LEASE_MS = 30 * 60_000;
const RUNTIME_HARD_LEASE_MS = 2 * 60 * 60_000;
const HEALTH_MAX_AGE_MS = 90_000;
const CORE_CANDIDATE_MAX_AGE_MS = 7 * 24 * 60 * 60_000;

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected) {
  if (!record(value)) return false;
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expected.length &&
    keys.every(
      (key) => typeof key === "string" && expected.includes(key)
    ) &&
    expected.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

function instant(value, label) {
  if (typeof value !== "string") {
    throw new Error(label + " is invalid");
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new Error(label + " must be an exact ISO-8601 UTC instant");
  }
  return parsed;
}

function iso(value) {
  return new Date(value).toISOString();
}

function canonicalCapabilities(capabilities) {
  return {
    mcpRead: capabilities.mcpRead,
    mcpGovernedWrite: capabilities.mcpGovernedWrite,
    agentContextKit: capabilities.agentContextKit,
    dataHubSkills: capabilities.dataHubSkills,
    analyticsAgent: capabilities.analyticsAgent
  };
}

function validateCapabilities(value) {
  if (!exactKeys(value, REQUIRED_CAPABILITIES)) {
    throw new Error("runtime capabilities must use the exact schema");
  }
  for (const name of REQUIRED_CAPABILITIES) {
    if (typeof value[name] !== "boolean") {
      throw new Error("runtime capability " + name + " must be boolean");
    }
  }
  return Object.freeze(canonicalCapabilities(value));
}

function capabilityDigest(profileId, generation, capabilities) {
  if (!PROFILE_IDS.includes(profileId) || !GENERATION.test(generation)) {
    throw new Error("invalid runtime identity");
  }
  const canonical = JSON.stringify({
    schemaVersion: "archon.runtime-capabilities/v1",
    profileId,
    generation,
    capabilities: canonicalCapabilities(validateCapabilities(capabilities))
  });
  return "sha256:" + createHash("sha256").update(canonical, "utf8").digest("hex");
}

function validateHealth(value, profileId, now, options = {}) {
  if (
    !record(value) ||
    value.profileId !== profileId ||
    !GENERATION.test(value.generation) ||
    !["STARTING", "READY", "UNHEALTHY", "STOPPED"].includes(value.status) ||
    !DIGEST.test(value.capabilityDigest)
  ) {
    throw new Error("invalid runtime health identity");
  }
  const checkedAtMs = instant(value.checkedAt, "checkedAt");
  const nowMs = instant(now, "now");
  if (checkedAtMs > nowMs) {
    throw new Error("runtime health is from the future");
  }
  const capabilities = validateCapabilities(value.capabilities);
  if (
    capabilityDigest(profileId, value.generation, capabilities) !==
    value.capabilityDigest
  ) {
    throw new Error("runtime capability digest mismatch");
  }
  if (
    value.status === "READY" &&
    (nowMs - checkedAtMs > HEALTH_MAX_AGE_MS ||
      REQUIRED_CAPABILITIES.some((name) => !capabilities[name]))
  ) {
    throw new Error("runtime readiness is stale or incomplete");
  }
  if (
    options.candidate === true &&
    (value.status !== "STOPPED" ||
      nowMs - checkedAtMs > CORE_CANDIDATE_MAX_AGE_MS ||
      REQUIRED_CAPABILITIES.some((name) => !capabilities[name]))
  ) {
    throw new Error("Core launch candidate is stale or incomplete");
  }
  return Object.freeze({
    profileId,
    generation: value.generation,
    status: value.status,
    checkedAt: value.checkedAt,
    capabilities,
    capabilityDigest: value.capabilityDigest,
    sessionId: value.sessionId ?? null
  });
}

function generateSessionId(entropy = randomBytes(32)) {
  if (!(entropy instanceof Uint8Array) || entropy.byteLength !== 32) {
    throw new Error("session id requires exactly 256 bits");
  }
  const value = "rs_" + Buffer.from(entropy).toString("base64url");
  if (!SESSION_ID.test(value)) throw new Error("invalid session id");
  return value;
}

function validateSessionId(value) {
  if (typeof value !== "string" || !SESSION_ID.test(value)) {
    throw new Error("invalid session id");
  }
  return value;
}

function validateBinding(value) {
  const expected = [
    "schemaVersion",
    "profileId",
    "generation",
    "capabilityDigest",
    "resolution",
    "boundAt",
    "leaseExpiresAt"
  ];
  if (
    !exactKeys(value, expected) ||
    value.schemaVersion !== "archon.runtime-binding/v1" ||
    !PROFILE_IDS.includes(value.profileId) ||
    !GENERATION.test(value.generation) ||
    !DIGEST.test(value.capabilityDigest) ||
    !["auto", "explicit"].includes(value.resolution)
  ) {
    throw new Error("invalid runtime binding");
  }
  const boundAt = instant(value.boundAt, "boundAt");
  const expiresAt = instant(value.leaseExpiresAt, "leaseExpiresAt");
  if (
    expiresAt <= boundAt ||
    expiresAt - boundAt > RUNTIME_HARD_LEASE_MS
  ) {
    throw new Error("invalid runtime binding lease");
  }
  return Object.freeze({ ...value });
}

function sameBinding(left, right) {
  const a = validateBinding(left);
  const b = validateBinding(right);
  return (
    a.schemaVersion === b.schemaVersion &&
    a.profileId === b.profileId &&
    a.generation === b.generation &&
    a.capabilityDigest === b.capabilityDigest &&
    a.resolution === b.resolution &&
    a.boundAt === b.boundAt &&
    a.leaseExpiresAt === b.leaseExpiresAt
  );
}

function createSession(input) {
  if (
    !record(input) ||
    !REQUESTS.includes(input.requestedProfile) ||
    !["STARTING", "ACTIVE"].includes(input.state)
  ) {
    throw new Error("invalid runtime session input");
  }
  const binding = validateBinding(input.binding);
  if (
    (input.requestedProfile === "auto" &&
      binding.resolution !== "auto") ||
    (input.requestedProfile !== "auto" &&
      (binding.resolution !== "explicit" ||
        binding.profileId !== input.requestedProfile))
  ) {
    throw new Error("runtime request and binding do not match");
  }
  const created = instant(binding.boundAt, "boundAt");
  const hard = instant(binding.leaseExpiresAt, "leaseExpiresAt");
  return validateSession({
    schemaVersion: "archon.runtime-session/v1",
    sessionId: validateSessionId(input.sessionId),
    requestedProfile: input.requestedProfile,
    binding,
    state: input.state,
    createdAt: binding.boundAt,
    updatedAt: binding.boundAt,
    lastActivityAt: binding.boundAt,
    idleExpiresAt: iso(Math.min(created + RUNTIME_IDLE_LEASE_MS, hard)),
    hardExpiresAt: binding.leaseExpiresAt,
    revision: 0,
    endReason: null,
    failureCode: null
  });
}

function validateSession(value) {
  const expected = [
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
  ];
  if (
    !exactKeys(value, expected) ||
    value.schemaVersion !== "archon.runtime-session/v1" ||
    !REQUESTS.includes(value.requestedProfile) ||
    !STATES.includes(value.state)
  ) {
    throw new Error("invalid runtime session");
  }
  validateSessionId(value.sessionId);
  const binding = validateBinding(value.binding);
  if (
    (value.requestedProfile === "auto" &&
      binding.resolution !== "auto") ||
    (value.requestedProfile !== "auto" &&
      (binding.resolution !== "explicit" ||
        binding.profileId !== value.requestedProfile))
  ) {
    throw new Error("runtime request and binding do not match");
  }
  const created = instant(value.createdAt, "createdAt");
  const updated = instant(value.updatedAt, "updatedAt");
  const activity = instant(value.lastActivityAt, "lastActivityAt");
  const idle = instant(value.idleExpiresAt, "idleExpiresAt");
  const hard = instant(value.hardExpiresAt, "hardExpiresAt");
  if (
    value.createdAt !== binding.boundAt ||
    value.hardExpiresAt !== binding.leaseExpiresAt ||
    updated < created ||
    activity < created ||
    activity > updated ||
    idle <= activity ||
    idle > hard ||
    hard <= created
  ) {
    throw new Error("invalid runtime session chronology");
  }
  if (!Number.isSafeInteger(value.revision) || value.revision < 0) {
    throw new Error("invalid runtime session revision");
  }
  const reasons = [
    null,
    "USER_REQUEST",
    "IDLE_TIMEOUT",
    "HARD_TIMEOUT",
    "CONTROL_FAILURE"
  ];
  const failures = [
    null,
    "PROVISIONING_FAILED",
    "HEALTH_CHECK_FAILED",
    "CONTROL_PLANE_ERROR",
    "RUNTIME_DRIFT"
  ];
  if (
    !reasons.includes(value.endReason) ||
    !failures.includes(value.failureCode)
  ) {
    throw new Error("invalid runtime session terminal metadata");
  }
  if (
    ["STARTING", "ACTIVE"].includes(value.state) &&
    (value.endReason !== null || value.failureCode !== null)
  ) {
    throw new Error("live runtime session has terminal metadata");
  }
  if (
    value.state === "EXPIRED" &&
    !["IDLE_TIMEOUT", "HARD_TIMEOUT"].includes(value.endReason)
  ) {
    throw new Error("expired runtime session has no timeout");
  }
  if (
    value.state === "FAILED" &&
    (value.endReason !== "CONTROL_FAILURE" || value.failureCode === null)
  ) {
    throw new Error("failed runtime session has no safe code");
  }
  if (
    value.endReason === "CONTROL_FAILURE"
      ? value.failureCode === null
      : value.failureCode !== null
  ) {
    throw new Error("runtime failure metadata is inconsistent");
  }
  return Object.freeze({ ...value, binding });
}

function evolve(value, change) {
  const session = validateSession(value);
  if (session.revision >= Number.MAX_SAFE_INTEGER) {
    throw new Error("runtime session revision exhausted");
  }
  return validateSession({
    ...session,
    ...change,
    revision: session.revision + 1
  });
}

function tick(value, at) {
  const session = validateSession(value);
  const now = instant(at, "event.at");
  if (now < instant(session.updatedAt, "updatedAt")) {
    throw new Error("runtime session clock moved backwards");
  }
  if (!["STARTING", "ACTIVE"].includes(session.state)) return session;
  if (now >= instant(session.hardExpiresAt, "hardExpiresAt")) {
    return evolve(session, {
      state: "EXPIRED",
      updatedAt: at,
      endReason: "HARD_TIMEOUT"
    });
  }
  if (now >= instant(session.idleExpiresAt, "idleExpiresAt")) {
    return evolve(session, {
      state: "EXPIRED",
      updatedAt: at,
      endReason: "IDLE_TIMEOUT"
    });
  }
  return session;
}

function markReady(value, binding, at) {
  const session = tick(value, at);
  if (session.state !== "STARTING") return session;
  if (!sameBinding(session.binding, binding)) {
    return failSession(session, "RUNTIME_DRIFT", at);
  }
  const now = instant(at, "event.at");
  const hard = instant(session.hardExpiresAt, "hardExpiresAt");
  return evolve(session, {
    state: "ACTIVE",
    updatedAt: at,
    lastActivityAt: at,
    idleExpiresAt: iso(Math.min(now + RUNTIME_IDLE_LEASE_MS, hard))
  });
}

function activity(value, binding, at) {
  const session = tick(value, at);
  if (session.state !== "ACTIVE") return session;
  if (!sameBinding(session.binding, binding)) {
    return failSession(session, "RUNTIME_DRIFT", at);
  }
  const now = instant(at, "event.at");
  const hard = instant(session.hardExpiresAt, "hardExpiresAt");
  return evolve(session, {
    updatedAt: at,
    lastActivityAt: at,
    idleExpiresAt: iso(Math.min(now + RUNTIME_IDLE_LEASE_MS, hard))
  });
}

function requestStop(value, at) {
  const session = tick(value, at);
  if (["STOPPING", "STOPPED", "EXPIRED", "FAILED"].includes(session.state)) {
    return session;
  }
  return evolve(session, {
    state: "STOPPING",
    updatedAt: at,
    endReason: "USER_REQUEST"
  });
}

function completeStop(value, at) {
  const session = validateSession(value);
  if (session.state === "STOPPED") return session;
  if (session.state !== "STOPPING") {
    throw new Error("stop completion requires STOPPING");
  }
  return evolve(session, { state: "STOPPED", updatedAt: at });
}

function failSession(value, failureCode, at) {
  const session = validateSession(value);
  if (![
    "PROVISIONING_FAILED",
    "HEALTH_CHECK_FAILED",
    "CONTROL_PLANE_ERROR",
    "RUNTIME_DRIFT"
  ].includes(failureCode)) {
    throw new Error("invalid runtime failure code");
  }
  if (["EXPIRED", "STOPPED", "FAILED"].includes(session.state)) {
    return session;
  }
  return evolve(session, {
    state: "FAILED",
    updatedAt: at,
    endReason: "CONTROL_FAILURE",
    failureCode
  });
}

function publicStatus(value, now) {
  const session = tick(value, now);
  const live = ["STARTING", "ACTIVE"].includes(session.state);
  const deadline = Math.min(
    instant(session.idleExpiresAt, "idleExpiresAt"),
    instant(session.hardExpiresAt, "hardExpiresAt")
  );
  const state =
    session.state === "ACTIVE"
      ? "READY"
      : session.state === "FAILED"
        ? "UNAVAILABLE"
        : session.state;
  return Object.freeze({
    schemaVersion: "archon.runtime-session-status/v1",
    sessionId: session.sessionId,
    requestedProfile: session.requestedProfile,
    resolvedProfile: session.binding.profileId,
    state,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    idleExpiresAt: session.idleExpiresAt,
    hardExpiresAt: session.hardExpiresAt,
    remainingSeconds: live
      ? Math.max(0, Math.ceil((deadline - instant(now, "now")) / 1000))
      : 0,
    canRun: session.state === "ACTIVE",
    canExtend:
      session.state === "ACTIVE" &&
      session.idleExpiresAt !== session.hardExpiresAt
  });
}

module.exports = {
  CORE_CANDIDATE_MAX_AGE_MS,
  HEALTH_MAX_AGE_MS,
  PROFILE_IDS,
  REQUIRED_CAPABILITIES,
  RUNTIME_HARD_LEASE_MS,
  RUNTIME_IDLE_LEASE_MS,
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
  validateBinding,
  validateHealth,
  validateSession,
  validateSessionId
};
