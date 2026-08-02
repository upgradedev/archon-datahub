import { afterEach, describe, expect, it, vi } from "vitest";
import {
  extendRuntimeSession,
  getRuntimeProfiles,
  getRuntimeSession,
  startRuntimeSession,
  stopRuntimeSession,
} from "./runtime-api";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function json(value: unknown, status = 200): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: {
      get: (name: string) =>
        name.toLowerCase() === "content-type" ? "application/json" : null,
    },
    json: async () => value,
  } as unknown as Response;
}

const ACCESS_TOKEN = "TEST_ONLY_TOKEN_000000000000";

const allCapabilities = {
  mcpRead: true,
  mcpGovernedWrite: true,
  agentContextKit: true,
  dataHubSkills: true,
  analyticsAgent: true,
};

const noCapabilities = {
  mcpRead: false,
  mcpGovernedWrite: false,
  agentContextKit: false,
  dataHubSkills: false,
  analyticsAgent: false,
};

function status(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: "archon.runtime-session-status/v1",
    sessionId: "rs_" + "A".repeat(43),
    requestedProfile: "auto",
    resolvedProfile: "core",
    state: "STARTING",
    createdAt: "2026-08-02T08:00:00.000Z",
    updatedAt: "2026-08-02T08:00:00.000Z",
    idleExpiresAt: "2026-08-02T08:30:00.000Z",
    hardExpiresAt: "2026-08-02T10:00:00.000Z",
    remainingSeconds: 1800,
    canRun: false,
    canExtend: false,
    ...overrides,
  };
}

describe("runtime API trust boundary", () => {
  it("accepts an explicit unavailable registry without pretending readiness", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      json({
        schemaVersion: "archon.runtime-profiles/v1",
        serverTime: "2026-08-02T08:00:00.000Z",
        profiles: [
          {
            profileId: "cloud",
            availability: "UNAVAILABLE",
            generation: null,
            checkedAt: null,
            capabilities: noCapabilities,
            capabilityDigest: null,
          },
          {
            profileId: "core",
            availability: "UNAVAILABLE",
            generation: null,
            checkedAt: null,
            capabilities: noCapabilities,
            capabilityDigest: null,
          },
        ],
        autoSelection: null,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const registry = await getRuntimeProfiles();

    expect(registry.autoSelection).toBeNull();
    expect(registry.profiles.every((profile) =>
      profile.availability === "UNAVAILABLE"
    )).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/runtime-profiles",
      expect.objectContaining({
        method: "GET",
        credentials: "same-origin",
      }),
    );
  });

  it("rejects partial, contradictory, credential-bearing, or private projections", async () => {
    const base = {
      schemaVersion: "archon.runtime-profiles/v1",
      serverTime: "2026-08-02T08:00:00.000Z",
      profiles: [
        {
          profileId: "cloud",
          availability: "READY",
          generation: "cloud-2026-08-02",
          checkedAt: "2026-08-02T08:00:00.000Z",
          capabilities: allCapabilities,
          capabilityDigest: "sha256:" + "1".repeat(64),
        },
        {
          profileId: "core",
          availability: "UNAVAILABLE",
          generation: null,
          checkedAt: null,
          capabilities: noCapabilities,
          capabilityDigest: null,
        },
      ],
      autoSelection: "cloud",
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        json({
          ...base,
          profiles: [
            {
              ...base.profiles[0],
              capabilities: {
                ...allCapabilities,
                analyticsAgent: false,
              },
            },
            base.profiles[1],
          ],
        }),
      )
      .mockResolvedValueOnce(
        json({
          ...base,
          accessToken: "must-never-cross-the-browser-boundary",
        }),
      )
      .mockResolvedValueOnce(
        json({
          ...base,
          profiles: [
            {
              ...base.profiles[0],
              endpoint: "https://10.0.0.5:9443",
            },
            base.profiles[1],
          ],
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    await expect(getRuntimeProfiles()).rejects.toMatchObject({ status: 502 });
    await expect(getRuntimeProfiles()).rejects.toMatchObject({ status: 502 });
    await expect(getRuntimeProfiles()).rejects.toMatchObject({ status: 502 });
  });

  it("submits only the selected profile and validates server-owned identity", async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(status()));
    vi.stubGlobal("fetch", fetchMock);

    const result = await startRuntimeSession("auto", ACCESS_TOKEN);

    expect(result.resolvedProfile).toBe("core");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/runtime-sessions",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        body: JSON.stringify({ requestedProfile: "auto" }),
      }),
    );
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual({
      requestedProfile: "auto",
    });
    expect(JSON.parse(String(init.body))).not.toHaveProperty("binding");
    expect(JSON.parse(String(init.body))).not.toHaveProperty("generation");
    expect(JSON.parse(String(init.body))).not.toHaveProperty("endpoint");
  });

  it("uses opaque session capabilities for status, extend, and stop", async () => {
    const sessionId = "rs_" + "B".repeat(43);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(status({ sessionId })))
      .mockResolvedValueOnce(
        json(
          status({
            sessionId,
            state: "READY",
            updatedAt: "2026-08-02T08:01:00.000Z",
            idleExpiresAt: "2026-08-02T08:31:00.000Z",
            canRun: true,
            canExtend: true,
          }),
        ),
      )
      .mockResolvedValueOnce(
        json(
          status({
            sessionId,
            state: "STOPPING",
            updatedAt: "2026-08-02T08:02:00.000Z",
            remainingSeconds: 0,
          }),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    await getRuntimeSession(sessionId);
    await extendRuntimeSession(sessionId, ACCESS_TOKEN);
    await stopRuntimeSession(sessionId, ACCESS_TOKEN);

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "/api/runtime-sessions/" + sessionId,
      expect.objectContaining({ method: "GET" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "/api/runtime-sessions/" + sessionId + "/activity",
      expect.objectContaining({ method: "POST", body: "{}" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      "/api/runtime-sessions/" + sessionId + "/stop",
      expect.objectContaining({ method: "POST", body: "{}" }),
    );
  });

  it("fails closed before the network for malformed session capabilities", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(getRuntimeSession("rs_short")).rejects.toMatchObject({
      status: 400,
    });
    await expect(extendRuntimeSession("https://internal", ACCESS_TOKEN)).rejects.toMatchObject({
      status: 400,
    });
    await expect(stopRuntimeSession("../admin", ACCESS_TOKEN)).rejects.toMatchObject({
      status: 400,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects client-visible binding data and inconsistent ready state", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        json({
          ...status(),
          binding: {
            profileId: "core",
            endpoint: "dynamodb://core-session/private",
          },
        }),
      )
      .mockResolvedValueOnce(
        json(
          status({
            state: "READY",
            canRun: false,
          }),
        ),
      )
      .mockResolvedValueOnce(
        json(
          status({
            requestedProfile: "cloud",
            resolvedProfile: "core",
          }),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    await expect(startRuntimeSession("auto", ACCESS_TOKEN)).rejects.toMatchObject({
      status: 502,
    });
    await expect(startRuntimeSession("auto", ACCESS_TOKEN)).rejects.toMatchObject({
      status: 502,
    });
    await expect(startRuntimeSession("auto", ACCESS_TOKEN)).rejects.toMatchObject({
      status: 502,
    });
  });

  it("rejects absent or malformed authentication before runtime mutations", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(startRuntimeSession("auto", "")).rejects.toMatchObject({
      status: 401,
    });
    await expect(
      startRuntimeSession("auto", "not a bearer token"),
    ).rejects.toMatchObject({ status: 401 });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("maps only stable runtime errors and never reflects upstream bodies", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      json(
        {
          error: "runtime_not_ready",
          endpoint: "https://private.example",
          secret: "must-not-be-reflected",
        },
        409,
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(startRuntimeSession("cloud", ACCESS_TOKEN)).rejects.toMatchObject({
      status: 409,
      message:
        "That DataHub runtime is not fully ready with all five capabilities.",
    });
  });
});
