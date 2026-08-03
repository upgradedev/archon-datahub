import { randomBytes } from "node:crypto";
import {
  RUNTIME_REQUESTS,
  assertPinnedRuntime,
  validateRuntimeBinding,
  type RuntimeBinding,
  type RuntimeProfileId,
  type RuntimeRequest,
} from "./runtime-profile.js";

export const RUNTIME_IDLE_LEASE_MS = 30 * 60_000;
export const RUNTIME_HARD_LEASE_MS = 2 * 60 * 60_000;

const SESSION_ID = /^rs_[A-Za-z0-9_-]{43}$/u;
const STATES = [
  "STARTING",
  "ACTIVE",
  "STOPPING",
  "STOPPED",
  "EXPIRED",
  "FAILED",
] as const;
const FAILURES = [
  "PROVISIONING_FAILED",
  "HEALTH_CHECK_FAILED",
  "CONTROL_PLANE_ERROR",
  "RUNTIME_DRIFT",
] as const;
const END_REASONS = [
  "USER_REQUEST",
  "IDLE_TIMEOUT",
  "HARD_TIMEOUT",
  "CONTROL_FAILURE",
] as const;

declare const sessionIdBrand: unique symbol;
export type RuntimeSessionId = string & {
  readonly [sessionIdBrand]: true;
};
export type RuntimeSessionState = (typeof STATES)[number];
export type RuntimeSessionFailureCode = (typeof FAILURES)[number];
export type RuntimeSessionEndReason = (typeof END_REASONS)[number];

export interface RuntimeSession {
  readonly schemaVersion: "archon.runtime-session/v1";
  readonly sessionId: RuntimeSessionId;
  readonly requestedProfile: RuntimeRequest;
  readonly binding: Readonly<RuntimeBinding>;
  readonly state: RuntimeSessionState;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly lastActivityAt: string;
  readonly idleExpiresAt: string;
  readonly hardExpiresAt: string;
  readonly revision: number;
  readonly endReason: RuntimeSessionEndReason | null;
  readonly failureCode: RuntimeSessionFailureCode | null;
}

export type RuntimeSessionEvent =
  | {
      readonly type: "RUNTIME_READY";
      readonly at: string;
      readonly binding: RuntimeBinding;
    }
  | {
      readonly type: "ACTIVITY";
      readonly at: string;
      readonly binding: RuntimeBinding;
    }
  | { readonly type: "STOP_REQUESTED"; readonly at: string }
  | { readonly type: "STOP_COMPLETED"; readonly at: string }
  | {
      readonly type: "FAIL";
      readonly at: string;
      readonly failureCode: RuntimeSessionFailureCode;
    }
  | { readonly type: "TICK"; readonly at: string };

export type PublicRuntimeSessionState =
  | "STARTING"
  | "READY"
  | "STOPPING"
  | "STOPPED"
  | "EXPIRED"
  | "UNAVAILABLE";

export interface PublicRuntimeSessionStatus {
  readonly schemaVersion: "archon.runtime-session-status/v1";
  readonly sessionId: RuntimeSessionId;
  readonly requestedProfile: RuntimeRequest;
  readonly resolvedProfile: RuntimeProfileId;
  readonly state: PublicRuntimeSessionState;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly idleExpiresAt: string;
  readonly hardExpiresAt: string;
  readonly remainingSeconds: number;
  readonly canRun: boolean;
  readonly canExtend: boolean;
}

export class RuntimeSessionError extends Error {
  constructor(
    readonly code:
      | "INVALID_SESSION_ID"
      | "INVALID_RUNTIME_SESSION"
      | "INVALID_SESSION_EVENT"
      | "INVALID_TRANSITION"
      | "NON_MONOTONIC_TIME",
    message: string
  ) {
    super(message);
    this.name = "RuntimeSessionError";
  }
}

function fail(
  code: RuntimeSessionError["code"],
  message: string
): never {
  throw new RuntimeSessionError(code, message);
}

function instant(value: unknown, label: string): number {
  if (typeof value !== "string") {
    return fail("INVALID_RUNTIME_SESSION", label + " is invalid");
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    return fail(
      "INVALID_RUNTIME_SESSION",
      label + " must be an exact ISO-8601 UTC instant"
    );
  }
  return parsed;
}

function iso(value: number): string {
  return new Date(value).toISOString();
}

export function parseRuntimeSessionId(value: unknown): RuntimeSessionId {
  if (typeof value !== "string" || !SESSION_ID.test(value)) {
    return fail("INVALID_SESSION_ID", "runtime session id is invalid");
  }
  return value as RuntimeSessionId;
}

export function generateRuntimeSessionId(
  entropy: Uint8Array = randomBytes(32)
): RuntimeSessionId {
  if (!(entropy instanceof Uint8Array) || entropy.byteLength !== 32) {
    return fail("INVALID_SESSION_ID", "session id requires exactly 256 bits");
  }
  return parseRuntimeSessionId(
    "rs_" + Buffer.from(entropy).toString("base64url")
  );
}

function parseRequestedProfile(value: unknown): RuntimeRequest {
  if (
    typeof value !== "string" ||
    !(RUNTIME_REQUESTS as readonly string[]).includes(value)
  ) {
    return fail("INVALID_RUNTIME_SESSION", "requested profile is invalid");
  }
  return value as RuntimeRequest;
}

function nextRevision(session: Readonly<RuntimeSession>): number {
  if (session.revision >= Number.MAX_SAFE_INTEGER) {
    return fail("INVALID_RUNTIME_SESSION", "session revision is exhausted");
  }
  return session.revision + 1;
}

function evolve(
  session: Readonly<RuntimeSession>,
  change: Partial<RuntimeSession>
): Readonly<RuntimeSession> {
  return validateRuntimeSession({
    ...session,
    ...change,
    revision: nextRevision(session),
  });
}

export function validateRuntimeSession(
  value: unknown
): Readonly<RuntimeSession> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return fail("INVALID_RUNTIME_SESSION", "runtime session must be an object");
  }
  const input = value as Record<string, unknown>;
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
    "failureCode",
  ];
  const keys = Reflect.ownKeys(input);
  if (
    keys.length !== expected.length ||
    keys.some(
      (key) => typeof key !== "string" || !expected.includes(key)
    ) ||
    expected.some(
      (key) => !Object.prototype.hasOwnProperty.call(input, key)
    )
  ) {
    return fail(
      "INVALID_RUNTIME_SESSION",
      "runtime session must use the exact schema"
    );
  }
  if (input.schemaVersion !== "archon.runtime-session/v1") {
    return fail("INVALID_RUNTIME_SESSION", "unsupported session schema");
  }

  const id = parseRuntimeSessionId(input.sessionId);
  const requested = parseRequestedProfile(input.requestedProfile);
  let binding: Readonly<RuntimeBinding>;
  try {
    binding = validateRuntimeBinding(input.binding as RuntimeBinding);
  } catch {
    return fail("INVALID_RUNTIME_SESSION", "runtime binding is invalid");
  }
  if (
    (requested === "auto" && binding.resolution !== "auto") ||
    (requested !== "auto" &&
      (binding.resolution !== "explicit" ||
        binding.profileId !== requested))
  ) {
    return fail(
      "INVALID_RUNTIME_SESSION",
      "request is not bound to its resolved profile"
    );
  }

  const state = input.state;
  if (
    typeof state !== "string" ||
    !(STATES as readonly string[]).includes(state)
  ) {
    return fail("INVALID_RUNTIME_SESSION", "session state is invalid");
  }

  const created = instant(input.createdAt, "createdAt");
  const updated = instant(input.updatedAt, "updatedAt");
  const lastActivity = instant(input.lastActivityAt, "lastActivityAt");
  const idle = instant(input.idleExpiresAt, "idleExpiresAt");
  const hard = instant(input.hardExpiresAt, "hardExpiresAt");
  if (
    input.createdAt !== binding.boundAt ||
    input.hardExpiresAt !== binding.leaseExpiresAt ||
    updated < created ||
    lastActivity < created ||
    lastActivity > updated ||
    idle <= lastActivity ||
    idle > hard ||
    hard <= created ||
    hard - created > RUNTIME_HARD_LEASE_MS
  ) {
    return fail(
      "INVALID_RUNTIME_SESSION",
      "session lease chronology is invalid"
    );
  }

  if (
    !Number.isSafeInteger(input.revision) ||
    (input.revision as number) < 0
  ) {
    return fail("INVALID_RUNTIME_SESSION", "session revision is invalid");
  }

  const endReason = input.endReason;
  const failureCode = input.failureCode;
  const validReason =
    endReason === null ||
    (typeof endReason === "string" &&
      (END_REASONS as readonly string[]).includes(endReason));
  const validFailure =
    failureCode === null ||
    (typeof failureCode === "string" &&
      (FAILURES as readonly string[]).includes(failureCode));
  if (!validReason || !validFailure) {
    return fail(
      "INVALID_RUNTIME_SESSION",
      "session terminal metadata is invalid"
    );
  }

  if (
    (state === "STARTING" || state === "ACTIVE") &&
    (endReason !== null || failureCode !== null)
  ) {
    return fail(
      "INVALID_RUNTIME_SESSION",
      "live session contains terminal metadata"
    );
  }
  if (
    state === "EXPIRED" &&
    endReason !== "IDLE_TIMEOUT" &&
    endReason !== "HARD_TIMEOUT"
  ) {
    return fail("INVALID_RUNTIME_SESSION", "expired session has no timeout");
  }
  if (
    state === "FAILED" &&
    (endReason !== "CONTROL_FAILURE" || failureCode === null)
  ) {
    return fail("INVALID_RUNTIME_SESSION", "failed session has no safe code");
  }
  if (
    endReason === "CONTROL_FAILURE"
      ? failureCode === null
      : failureCode !== null
  ) {
    return fail(
      "INVALID_RUNTIME_SESSION",
      "failure code and reason are inconsistent"
    );
  }

  return Object.freeze({
    schemaVersion: "archon.runtime-session/v1",
    sessionId: id,
    requestedProfile: requested,
    binding,
    state: state as RuntimeSessionState,
    createdAt: input.createdAt as string,
    updatedAt: input.updatedAt as string,
    lastActivityAt: input.lastActivityAt as string,
    idleExpiresAt: input.idleExpiresAt as string,
    hardExpiresAt: input.hardExpiresAt as string,
    revision: input.revision as number,
    endReason: endReason as RuntimeSessionEndReason | null,
    failureCode: failureCode as RuntimeSessionFailureCode | null,
  });
}

export function createRuntimeSession(input: {
  readonly sessionId: RuntimeSessionId;
  readonly requestedProfile: RuntimeRequest;
  readonly binding: RuntimeBinding;
}): Readonly<RuntimeSession> {
  const binding = validateRuntimeBinding(input.binding);
  const created = instant(binding.boundAt, "boundAt");
  const hard = instant(binding.leaseExpiresAt, "leaseExpiresAt");

  return validateRuntimeSession({
    schemaVersion: "archon.runtime-session/v1",
    sessionId: parseRuntimeSessionId(input.sessionId),
    requestedProfile: parseRequestedProfile(input.requestedProfile),
    binding,
    state: "STARTING",
    createdAt: binding.boundAt,
    updatedAt: binding.boundAt,
    lastActivityAt: binding.boundAt,
    idleExpiresAt: iso(Math.min(created + RUNTIME_IDLE_LEASE_MS, hard)),
    hardExpiresAt: binding.leaseExpiresAt,
    revision: 0,
    endReason: null,
    failureCode: null,
  });
}

function expireIfDue(
  session: Readonly<RuntimeSession>,
  at: string
): Readonly<RuntimeSession> {
  if (session.state !== "STARTING" && session.state !== "ACTIVE") {
    return session;
  }
  const atMs = instant(at, "event.at");
  const hardMs = instant(session.hardExpiresAt, "hardExpiresAt");
  const idleMs = instant(session.idleExpiresAt, "idleExpiresAt");
  if (atMs >= hardMs) {
    return evolve(session, {
      state: "EXPIRED",
      updatedAt: at,
      endReason: "HARD_TIMEOUT",
    });
  }
  if (atMs >= idleMs) {
    return evolve(session, {
      state: "EXPIRED",
      updatedAt: at,
      endReason: "IDLE_TIMEOUT",
    });
  }
  return session;
}

export function transitionRuntimeSession(
  value: Readonly<RuntimeSession>,
  event: RuntimeSessionEvent
): Readonly<RuntimeSession> {
  const original = validateRuntimeSession(value);
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    return fail("INVALID_SESSION_EVENT", "session event must be an object");
  }
  const atMs = instant(event.at, "event.at");
  if (atMs < instant(original.updatedAt, "updatedAt")) {
    return fail("NON_MONOTONIC_TIME", "session event time moved backwards");
  }

  const session = expireIfDue(original, event.at);
  if (event.type === "TICK") return session;

  if (event.type === "RUNTIME_READY") {
    if (session.state === "STARTING") {
      assertPinnedRuntime(session.binding, event.binding);
      const hard = instant(session.hardExpiresAt, "hardExpiresAt");
      return evolve(session, {
        state: "ACTIVE",
        updatedAt: event.at,
        lastActivityAt: event.at,
        idleExpiresAt: iso(Math.min(atMs + RUNTIME_IDLE_LEASE_MS, hard)),
      });
    }
    if (session.state === "ACTIVE") {
      assertPinnedRuntime(session.binding, event.binding);
      return session;
    }
    return session;
  }

  if (event.type === "ACTIVITY") {
    if (session.state !== "ACTIVE") {
      if (
        session.state === "EXPIRED" ||
        session.state === "STOPPING" ||
        session.state === "STOPPED" ||
        session.state === "FAILED"
      ) {
        return session;
      }
      return fail(
        "INVALID_TRANSITION",
        "activity requires an active session"
      );
    }
    assertPinnedRuntime(session.binding, event.binding);
    const hard = instant(session.hardExpiresAt, "hardExpiresAt");
    return evolve(session, {
      updatedAt: event.at,
      lastActivityAt: event.at,
      idleExpiresAt: iso(Math.min(atMs + RUNTIME_IDLE_LEASE_MS, hard)),
    });
  }

  if (event.type === "STOP_REQUESTED") {
    if (session.state === "STOPPING" || session.state === "STOPPED") {
      return session;
    }
    return evolve(session, {
      state: "STOPPING",
      updatedAt: event.at,
      endReason: session.endReason ?? "USER_REQUEST",
    });
  }

  if (event.type === "STOP_COMPLETED") {
    if (session.state === "STOPPED") return session;
    if (session.state !== "STOPPING") {
      return fail(
        "INVALID_TRANSITION",
        "stop completion requires STOPPING"
      );
    }
    return evolve(session, {
      state: "STOPPED",
      updatedAt: event.at,
    });
  }

  if (event.type === "FAIL") {
    if (
      !(FAILURES as readonly string[]).includes(event.failureCode)
    ) {
      return fail("INVALID_SESSION_EVENT", "failure code is not allowlisted");
    }
    if (
      session.state === "EXPIRED" ||
      session.state === "STOPPED" ||
      session.state === "FAILED"
    ) {
      return session;
    }
    return evolve(session, {
      state: "FAILED",
      updatedAt: event.at,
      endReason: "CONTROL_FAILURE",
      failureCode: event.failureCode,
    });
  }

  return fail("INVALID_SESSION_EVENT", "unsupported session event");
}

export function publicRuntimeSessionStatus(
  value: Readonly<RuntimeSession>,
  now: string
): Readonly<PublicRuntimeSessionStatus> {
  const session = transitionRuntimeSession(value, {
    type: "TICK",
    at: now,
  });
  const publicState: PublicRuntimeSessionState =
    session.state === "ACTIVE"
      ? "READY"
      : session.state === "FAILED"
        ? "UNAVAILABLE"
        : session.state;
  const live =
    session.state === "STARTING" || session.state === "ACTIVE";
  const deadline = Math.min(
    instant(session.idleExpiresAt, "idleExpiresAt"),
    instant(session.hardExpiresAt, "hardExpiresAt")
  );
  const nowMs = instant(now, "now");

  return Object.freeze({
    schemaVersion: "archon.runtime-session-status/v1",
    sessionId: session.sessionId,
    requestedProfile: session.requestedProfile,
    resolvedProfile: session.binding.profileId,
    state: publicState,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    idleExpiresAt: session.idleExpiresAt,
    hardExpiresAt: session.hardExpiresAt,
    remainingSeconds: live
      ? Math.max(0, Math.ceil((deadline - nowMs) / 1000))
      : 0,
    canRun: session.state === "ACTIVE",
    canExtend:
      session.state === "ACTIVE" &&
      session.idleExpiresAt !== session.hardExpiresAt,
  });
}
