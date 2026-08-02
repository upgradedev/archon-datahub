import assert from "node:assert/strict";
import { test } from "node:test";
import {
  selectRuntime,
  type RuntimeBinding,
  type RuntimeCapabilities,
  type RuntimeProfileSnapshot,
} from "../../src/datahub/runtime-profile.js";
import {
  RuntimeSessionError,
  createRuntimeSession,
  generateRuntimeSessionId,
  parseRuntimeSessionId,
  publicRuntimeSessionStatus,
  transitionRuntimeSession,
  validateRuntimeSession,
  type RuntimeSession,
} from "../../src/datahub/runtime-session.js";

const CREATED = "2026-08-02T08:00:00.000Z";
const HALF_HOUR = "2026-08-02T08:30:00.000Z";
const ONE_HOUR = "2026-08-02T09:00:00.000Z";
const TWO_HOURS = "2026-08-02T10:00:00.000Z";

const capabilities: RuntimeCapabilities = {
  mcpRead: true,
  mcpGovernedWrite: true,
  agentContextKit: true,
  dataHubSkills: true,
  analyticsAgent: true,
};

function snapshot(profileId: "cloud" | "core"): RuntimeProfileSnapshot {
  return {
    profileId,
    generation: profileId + "-generation-1",
    status: "ready",
    checkedAt: "2026-08-02T07:59:45.000Z",
    capabilities,
  };
}

function binding(
  request: "auto" | "cloud" | "core" = "auto",
  expires = TWO_HOURS
): Readonly<RuntimeBinding> {
  return selectRuntime(
    request,
    request === "core" ? [snapshot("core")] : [snapshot("cloud")],
    { now: CREATED, leaseExpiresAt: expires }
  );
}

function starting(
  request: "auto" | "cloud" | "core" = "auto",
  expires = TWO_HOURS
): Readonly<RuntimeSession> {
  return createRuntimeSession({
    sessionId: generateRuntimeSessionId(new Uint8Array(32)),
    requestedProfile: request,
    binding: binding(request, expires),
  });
}

test("runtime session ids require exactly 256 bits of opaque entropy", () => {
  const id = generateRuntimeSessionId(new Uint8Array(32));
  assert.equal(id, "rs_" + "A".repeat(43));
  assert.equal(id.length, 46);
  assert.equal(parseRuntimeSessionId(id), id);
  for (const candidate of [
    "550e8400-e29b-41d4-a716-446655440000",
    "a".repeat(64),
    "rs_short",
  ]) {
    assert.throws(() => parseRuntimeSessionId(candidate), /session id is invalid/);
  }
  assert.throws(
    () => generateRuntimeSessionId(new Uint8Array(31)),
    /exactly 256 bits/
  );
  assert.throws(
    () => generateRuntimeSessionId(new Uint8Array(33)),
    /exactly 256 bits/
  );
});

test("session creation pins Auto or explicit profile and caps idle at 30 minutes", () => {
  const auto = starting("auto");
  assert.equal(auto.state, "STARTING");
  assert.equal(auto.binding.profileId, "cloud");
  assert.equal(auto.binding.resolution, "auto");
  assert.equal(auto.idleExpiresAt, HALF_HOUR);
  assert.equal(auto.hardExpiresAt, TWO_HOURS);
  assert.equal(auto.revision, 0);
  assert.equal(Object.isFrozen(auto), true);

  const explicit = starting("core");
  assert.equal(explicit.binding.profileId, "core");
  assert.equal(explicit.binding.resolution, "explicit");

  assert.throws(
    () =>
      createRuntimeSession({
        sessionId: auto.sessionId,
        requestedProfile: "core",
        binding: auto.binding,
      }),
    /request is not bound/
  );
});

test("ready callback activates once and never extends an idempotent callback", () => {
  const initial = starting();
  const ready = transitionRuntimeSession(initial, {
    type: "RUNTIME_READY",
    at: "2026-08-02T08:05:00.000Z",
    binding: initial.binding,
  });
  assert.equal(ready.state, "ACTIVE");
  assert.equal(ready.idleExpiresAt, "2026-08-02T08:35:00.000Z");
  assert.equal(ready.revision, 1);
  const duplicate = transitionRuntimeSession(ready, {
    type: "RUNTIME_READY",
    at: "2026-08-02T08:06:00.000Z",
    binding: ready.binding,
  });
  assert.deepEqual(duplicate, ready);
});

test("runtime readiness and activity reject every pinned binding drift", () => {
  const initial = starting();
  for (const changed of [
    { ...initial.binding, profileId: "core" as const },
    { ...initial.binding, generation: "cloud-generation-2" },
    {
      ...initial.binding,
      capabilityDigest:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as const,
    },
    { ...initial.binding, resolution: "explicit" as const },
    {
      ...initial.binding,
      leaseExpiresAt: "2026-08-02T09:59:59.000Z",
    },
  ]) {
    assert.throws(
      () =>
        transitionRuntimeSession(initial, {
          type: "RUNTIME_READY",
          at: "2026-08-02T08:05:00.000Z",
          binding: changed,
        }),
      /runtime binding/
    );
  }
});

test("activity extends idle by 30 minutes but never changes the hard lease", () => {
  const initial = starting();
  const ready = transitionRuntimeSession(initial, {
    type: "RUNTIME_READY",
    at: "2026-08-02T08:05:00.000Z",
    binding: initial.binding,
  });
  let active = ready;
  for (const at of [
    "2026-08-02T08:25:00.000Z",
    "2026-08-02T08:50:00.000Z",
    "2026-08-02T09:15:00.000Z",
    "2026-08-02T09:40:00.000Z",
  ]) {
    active = transitionRuntimeSession(active, {
      type: "ACTIVITY",
      at,
      binding: ready.binding,
    });
  }
  assert.equal(active.idleExpiresAt, TWO_HOURS);
  assert.equal(active.hardExpiresAt, TWO_HOURS);
  assert.deepEqual(active.binding, initial.binding);
  assert.equal(active.revision, 5);
});

test("idle and hard deadlines expire without allowing revival", () => {
  const initial = starting();
  const ready = transitionRuntimeSession(initial, {
    type: "RUNTIME_READY",
    at: "2026-08-02T08:00:00.000Z",
    binding: initial.binding,
  });
  const idle = transitionRuntimeSession(ready, {
    type: "ACTIVITY",
    at: HALF_HOUR,
    binding: ready.binding,
  });
  assert.equal(idle.state, "EXPIRED");
  assert.equal(idle.endReason, "IDLE_TIMEOUT");
  assert.equal(idle.revision, 2);

  const short = starting("auto", HALF_HOUR);
  const hard = transitionRuntimeSession(short, {
    type: "TICK",
    at: HALF_HOUR,
  });
  assert.equal(hard.state, "EXPIRED");
  assert.equal(hard.endReason, "HARD_TIMEOUT");
  assert.equal(
    transitionRuntimeSession(hard, {
      type: "RUNTIME_READY",
      at: "2026-08-02T08:31:00.000Z",
      binding: hard.binding,
    }).state,
    "EXPIRED"
  );
});

test("stop and failure transitions are idempotent and allowlisted", () => {
  const initial = starting();
  const stopping = transitionRuntimeSession(initial, {
    type: "STOP_REQUESTED",
    at: "2026-08-02T08:01:00.000Z",
  });
  assert.equal(stopping.state, "STOPPING");
  assert.equal(stopping.endReason, "USER_REQUEST");
  assert.deepEqual(
    transitionRuntimeSession(stopping, {
      type: "STOP_REQUESTED",
      at: "2026-08-02T08:02:00.000Z",
    }),
    stopping
  );
  const stopped = transitionRuntimeSession(stopping, {
    type: "STOP_COMPLETED",
    at: "2026-08-02T08:03:00.000Z",
  });
  assert.equal(stopped.state, "STOPPED");

  const failed = transitionRuntimeSession(initial, {
    type: "FAIL",
    at: "2026-08-02T08:01:00.000Z",
    failureCode: "HEALTH_CHECK_FAILED",
  });
  assert.equal(failed.state, "FAILED");
  assert.equal(failed.endReason, "CONTROL_FAILURE");
  assert.equal(failed.failureCode, "HEALTH_CHECK_FAILED");
  assert.throws(
    () =>
      transitionRuntimeSession(initial, {
        type: "FAIL",
        at: "2026-08-02T08:01:00.000Z",
        failureCode: "raw exception text",
      } as never),
    /not allowlisted/
  );
});

test("persisted session validation rejects schema, chronology, and metadata drift", () => {
  const initial = starting();
  const invalid: unknown[] = [
    { ...initial, endpoint: "https://forbidden.example" },
    { ...initial, updatedAt: "2026-08-02T07:59:59.000Z" },
    { ...initial, idleExpiresAt: CREATED },
    { ...initial, state: "ACTIVE", endReason: "USER_REQUEST" },
    {
      ...initial,
      state: "FAILED",
      endReason: "CONTROL_FAILURE",
      failureCode: null,
    },
  ];
  for (const candidate of invalid) {
    assert.throws(
      () => validateRuntimeSession(candidate),
      (error: unknown) =>
        error instanceof RuntimeSessionError &&
        error.code === "INVALID_RUNTIME_SESSION"
    );
  }
});

test("public status is redacted, frozen, and server-time authoritative", () => {
  const initial = starting();
  const active = transitionRuntimeSession(initial, {
    type: "RUNTIME_READY",
    at: "2026-08-02T08:05:00.000Z",
    binding: initial.binding,
  });
  const status = publicRuntimeSessionStatus(
    active,
    "2026-08-02T08:10:00.000Z"
  );
  assert.equal(status.state, "READY");
  assert.equal(status.remainingSeconds, 25 * 60);
  assert.equal(status.canRun, true);
  assert.equal(status.canExtend, true);
  assert.equal(Object.isFrozen(status), true);
  assert.deepEqual(Object.keys(status).sort(), [
    "canExtend",
    "canRun",
    "createdAt",
    "hardExpiresAt",
    "idleExpiresAt",
    "remainingSeconds",
    "requestedProfile",
    "resolvedProfile",
    "schemaVersion",
    "sessionId",
    "state",
    "updatedAt",
  ]);
  assert.doesNotMatch(
    JSON.stringify(status),
    /(?:binding|generation|digest|endpoint|arn|token|credential|secret)/iu
  );

  const expired = publicRuntimeSessionStatus(active, ONE_HOUR);
  assert.equal(expired.state, "EXPIRED");
  assert.equal(expired.remainingSeconds, 0);
  assert.equal(expired.canRun, false);
});

test("event time cannot move backwards", () => {
  const initial = starting();
  assert.throws(
    () =>
      transitionRuntimeSession(initial, {
        type: "TICK",
        at: "2026-08-02T07:59:59.000Z",
      }),
    (error: unknown) =>
      error instanceof RuntimeSessionError &&
      error.code === "NON_MONOTONIC_TIME"
  );
});
