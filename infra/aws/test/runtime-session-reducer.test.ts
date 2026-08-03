export {};

const {
  activity,
  capabilityDigest,
  createSession,
  generateSessionId,
  markReady,
  publicStatus,
  requestStop,
  tick,
  validateHealth
} = require("../lambda/runtime-control/session.js") as {
  activity: (session: any, binding: any, at: string) => any;
  capabilityDigest: (
    profileId: "cloud" | "core",
    generation: string,
    capabilities: Record<string, boolean>
  ) => string;
  createSession: (input: any) => any;
  generateSessionId: (entropy?: Uint8Array) => string;
  markReady: (session: any, binding: any, at: string) => any;
  publicStatus: (session: any, now: string) => any;
  requestStop: (session: any, at: string) => any;
  tick: (session: any, at: string) => any;
  validateHealth: (
    value: any,
    profileId: "cloud" | "core",
    now: string,
    options?: { candidate?: boolean }
  ) => any;
};

const capabilities = {
  mcpRead: true,
  mcpGovernedWrite: true,
  agentContextKit: true,
  dataHubSkills: true,
  analyticsAgent: true
};

function binding(profileId: "cloud" | "core" = "core") {
  return {
    schemaVersion: "archon.runtime-binding/v1",
    profileId,
    generation: "ami-2026-08-02.1",
    capabilityDigest: capabilityDigest(
      profileId,
      "ami-2026-08-02.1",
      capabilities
    ),
    resolution: "explicit",
    boundAt: "2026-08-02T08:00:00.000Z",
    leaseExpiresAt: "2026-08-02T10:00:00.000Z"
  };
}

function session(state: "STARTING" | "ACTIVE" = "STARTING") {
  return createSession({
    sessionId: generateSessionId(new Uint8Array(32).fill(7)),
    requestedProfile: "core",
    binding: binding(),
    state
  });
}

describe("runtime control session reducer", () => {
  test("uses a 256-bit opaque capability and pins an immutable runtime identity", () => {
    const value = session();

    expect(value.sessionId).toMatch(/^rs_[A-Za-z0-9_-]{43}$/);
    expect(value.state).toBe("STARTING");
    expect(value.idleExpiresAt).toBe("2026-08-02T08:30:00.000Z");
    expect(value.hardExpiresAt).toBe("2026-08-02T10:00:00.000Z");
    expect(value.binding).toEqual(binding());
    expect(value.revision).toBe(0);
  });

  test("becomes ready only for the exact pinned binding", () => {
    const starting = session();
    const ready = markReady(
      starting,
      starting.binding,
      "2026-08-02T08:02:00.000Z"
    );
    const drifted = markReady(
      starting,
      {
        ...starting.binding,
        generation: "ami-tampered"
      },
      "2026-08-02T08:02:00.000Z"
    );

    expect(ready.state).toBe("ACTIVE");
    expect(ready.revision).toBe(1);
    expect(ready.idleExpiresAt).toBe("2026-08-02T08:32:00.000Z");
    expect(drifted.state).toBe("FAILED");
    expect(drifted.failureCode).toBe("RUNTIME_DRIFT");
  });

  test("extends only the idle lease and never the hard two-hour ceiling", () => {
    let value = session("ACTIVE");
    value = activity(
      value,
      value.binding,
      "2026-08-02T08:25:00.000Z"
    );
    value = activity(
      value,
      value.binding,
      "2026-08-02T08:50:00.000Z"
    );
    value = activity(
      value,
      value.binding,
      "2026-08-02T09:15:00.000Z"
    );
    value = activity(
      value,
      value.binding,
      "2026-08-02T09:40:00.000Z"
    );

    expect(value.idleExpiresAt).toBe("2026-08-02T10:00:00.000Z");
    expect(value.hardExpiresAt).toBe("2026-08-02T10:00:00.000Z");
    expect(publicStatus(value, "2026-08-02T09:59:30.000Z")).toMatchObject({
      state: "READY",
      remainingSeconds: 30,
      canRun: true,
      canExtend: false
    });
  });

  test("expires deterministically and cannot be revived by late activity", () => {
    const active = session("ACTIVE");
    const expired = tick(active, "2026-08-02T08:30:00.000Z");
    const late = activity(
      expired,
      expired.binding,
      "2026-08-02T08:31:00.000Z"
    );

    expect(expired.state).toBe("EXPIRED");
    expect(expired.endReason).toBe("IDLE_TIMEOUT");
    expect(late).toEqual(expired);
    expect(publicStatus(late, "2026-08-02T08:31:00.000Z")).toMatchObject({
      state: "EXPIRED",
      remainingSeconds: 0,
      canRun: false
    });
  });

  test("moves an active session to a server-owned stopping state", () => {
    const active = session("ACTIVE");
    const stopping = requestStop(active, "2026-08-02T08:10:00.000Z");

    expect(stopping.state).toBe("STOPPING");
    expect(stopping.endReason).toBe("USER_REQUEST");
    expect(stopping.revision).toBe(1);
  });

  test("requires fresh all-capability health and exact provenance digest", () => {
    const profile = {
      profileId: "cloud",
      generation: "cloud-2026-08-02",
      status: "READY",
      checkedAt: "2026-08-02T08:00:00.000Z",
      capabilities,
      capabilityDigest: capabilityDigest(
        "cloud",
        "cloud-2026-08-02",
        capabilities
      ),
      sessionId: null
    };

    expect(
      validateHealth(
        profile,
        "cloud",
        "2026-08-02T08:01:20.000Z"
      )
    ).toMatchObject({ status: "READY" });
    expect(() =>
      validateHealth(
        profile,
        "cloud",
        "2026-08-02T08:01:31.000Z"
      )
    ).toThrow(/stale/i);
    expect(() =>
      validateHealth(
        {
          ...profile,
          capabilityDigest: "sha256:" + "0".repeat(64)
        },
        "cloud",
        "2026-08-02T08:01:00.000Z"
      )
    ).toThrow(/digest/i);
  });

  test("allows only a recent, fully capable STOPPED Core launch candidate", () => {
    const profile = {
      profileId: "core",
      generation: "ami-2026-08-02.1",
      status: "STOPPED",
      checkedAt: "2026-08-02T08:00:00.000Z",
      capabilities,
      capabilityDigest: capabilityDigest(
        "core",
        "ami-2026-08-02.1",
        capabilities
      ),
      sessionId: null
    };

    expect(
      validateHealth(
        profile,
        "core",
        "2026-08-03T08:00:00.000Z",
        { candidate: true }
      )
    ).toMatchObject({ status: "STOPPED" });
    expect(() =>
      validateHealth(
        profile,
        "core",
        "2026-08-10T08:00:00.001Z",
        { candidate: true }
      )
    ).toThrow(/candidate/i);
  });
});