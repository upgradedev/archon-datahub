export {};

const mockDdbSend = jest.fn();
const mockSfnSend = jest.fn();

jest.mock(
  "@aws-sdk/client-dynamodb",
  () => ({
    DynamoDBClient: class {
      send = mockDdbSend;
    },
    GetItemCommand: class {
      readonly kind = "GetItemCommand";
      constructor(readonly input: Record<string, any>) {}
    },
    PutItemCommand: class {
      readonly kind = "PutItemCommand";
      constructor(readonly input: Record<string, any>) {}
    },
    UpdateItemCommand: class {
      readonly kind = "UpdateItemCommand";
      constructor(readonly input: Record<string, any>) {}
    }
  }),
  { virtual: true }
);
jest.mock(
  "@aws-sdk/client-sfn",
  () => ({
    SFNClient: class {
      send = mockSfnSend;
    },
    StartExecutionCommand: class {
      readonly kind = "StartExecutionCommand";
      constructor(readonly input: Record<string, any>) {}
    }
  }),
  { virtual: true }
);

process.env.RUNTIME_SESSION_TABLE = "runtime-session-table";
process.env.CORE_LEASE_TABLE = "core-lease-table";
process.env.CORE_SESSION_STATE_MACHINE_ARN =
  "arn:aws:states:eu-west-1:111111111111:stateMachine:archon-core-session";

const { handler } = require("../lambda/runtime-control/index.js") as {
  handler: (event: Record<string, unknown>) => Promise<{
    statusCode: number;
    headers: Record<string, string>;
    payload: Record<string, any>;
  }>;
};
const {
  capabilityDigest
} = require("../lambda/runtime-control/session.js") as {
  capabilityDigest: (
    profileId: "cloud" | "core",
    generation: string,
    capabilities: Record<string, boolean>
  ) => string;
};

const capabilities = {
  mcpRead: true,
  mcpGovernedWrite: true,
  agentContextKit: true,
  dataHubSkills: true,
  analyticsAgent: true
};

function boolMap(value: Record<string, boolean>) {
  return {
    M: Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        { BOOL: entry }
      ])
    )
  };
}

function healthItem(
  profileId: "cloud" | "core",
  status: "READY" | "STOPPED" | "STARTING" | "UNHEALTHY",
  sessionId?: string
) {
  const generation =
    profileId === "cloud" ? "cloud-2026-08-02" : "ami-2026-08-02.1";
  return {
    pk: { S: "RUNTIME#" + profileId },
    sk: { S: "HEALTH" },
    generation: { S: generation },
    status: { S: status },
    checkedAt: { S: "2026-08-02T08:00:00.000Z" },
    capabilities: boolMap(capabilities),
    capabilityDigest: {
      S: capabilityDigest(profileId, generation, capabilities)
    },
    ...(sessionId ? { sessionId: { S: sessionId } } : {})
  };
}

function event(
  operation: string,
  extra: Record<string, unknown> = {}
): Record<string, unknown> {
  return { operation, requestId: "request-runtime-123", ...extra };
}

describe("runtime session control Lambda", () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date("2026-08-02T08:01:00.000Z"));
    mockDdbSend.mockReset();
    mockSfnSend.mockReset();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  test("projects both profiles as unavailable when no genuine health exists", async () => {
    mockDdbSend.mockResolvedValue({});

    const result = await handler(event("profiles"));

    expect(result.statusCode).toBe(200);
    expect(result.payload).toEqual({
      schemaVersion: "archon.runtime-profiles/v1",
      serverTime: "2026-08-02T08:01:00.000Z",
      profiles: [
        expect.objectContaining({
          profileId: "cloud",
          availability: "UNAVAILABLE"
        }),
        expect.objectContaining({
          profileId: "core",
          availability: "UNAVAILABLE"
        })
      ],
      autoSelection: null
    });
    expect(JSON.stringify(result.payload)).not.toContain("endpoint");
    expect(JSON.stringify(result.payload)).not.toContain("instanceId");
  });

  test("starts Cloud only when all five registered capabilities are fresh", async () => {
    mockDdbSend.mockImplementation(async (command: any) => {
      if (command.kind === "GetItemCommand") {
        return { Item: healthItem("cloud", "READY") };
      }
      if (command.kind === "PutItemCommand") return {};
      throw new Error("unexpected command");
    });

    const result = await handler(
      event("sessionStart", {
        body: { requestedProfile: "cloud" }
      })
    );

    expect(result.statusCode).toBe(201);
    expect(result.payload).toMatchObject({
      schemaVersion: "archon.runtime-session-status/v1",
      requestedProfile: "cloud",
      resolvedProfile: "cloud",
      state: "READY",
      remainingSeconds: 1800,
      canRun: true
    });
    expect(result.payload.sessionId).toMatch(/^rs_[A-Za-z0-9_-]{43}$/);
    expect(mockSfnSend).not.toHaveBeenCalled();
    const put = mockDdbSend.mock.calls
      .map(([command]) => command)
      .find((command) => command.kind === "PutItemCommand");
    const stored = JSON.parse(put.input.Item.payload.S);
    expect(stored.binding).toMatchObject({
      profileId: "cloud",
      generation: "cloud-2026-08-02",
      resolution: "explicit",
      boundAt: "2026-08-02T08:01:00.000Z",
      leaseExpiresAt: "2026-08-02T10:01:00.000Z"
    });
  });

  test("does not fall back when explicit Cloud is unavailable", async () => {
    mockDdbSend.mockResolvedValue({});

    const result = await handler(
      event("sessionStart", {
        body: { requestedProfile: "cloud" }
      })
    );

    expect(result.statusCode).toBe(409);
    expect(result.payload).toEqual({ error: "runtime_not_ready" });
    expect(mockSfnSend).not.toHaveBeenCalled();
  });

  test("Auto launches Core with an immutable candidate when Cloud is absent", async () => {
    mockDdbSend.mockImplementation(async (command: any) => {
      if (command.kind === "GetItemCommand") {
        const pk = command.input.Key.pk.S;
        if (pk === "RUNTIME#cloud") return {};
        if (pk === "RUNTIME#core") {
          return { Item: healthItem("core", "STOPPED") };
        }
        if (pk === "CORE#LEASE") {
          return {
            Item: {
              pk: { S: "CORE#LEASE" },
              sk: { S: "CURRENT" },
              state: { S: "STOPPED" },
              revision: { N: "0" }
            }
          };
        }
      }
      if (command.kind === "PutItemCommand") return {};
      throw new Error("unexpected command " + command.kind);
    });
    mockSfnSend.mockResolvedValue({
      executionArn:
        "arn:aws:states:eu-west-1:111111111111:execution:archon-core-session:start"
    });

    const result = await handler(
      event("sessionStart", {
        body: { requestedProfile: "auto" }
      })
    );

    expect(result.statusCode).toBe(202);
    expect(result.payload).toMatchObject({
      requestedProfile: "auto",
      resolvedProfile: "core",
      state: "STARTING",
      canRun: false
    });
    const command = mockSfnSend.mock.calls[0]![0] as any;
    expect(command.kind).toBe("StartExecutionCommand");
    const input = JSON.parse(command.input.input);
    expect(input).toEqual({
      schema: "archon.core-runtime-command/v1",
      action: "START",
      sessionId: result.payload.sessionId,
      expectedRevision: 0,
      binding: expect.objectContaining({
        schemaVersion: "archon.runtime-binding/v1",
        profileId: "core",
        resolution: "auto"
      })
    });
    expect(JSON.stringify(input)).not.toContain("endpoint");
  });

  test("rejects unexpected fields before any AWS request", async () => {
    const result = await handler({
      ...event("sessionStart", {
        body: { requestedProfile: "auto" }
      }),
      headers: { authorization: "must-not-cross" }
    });

    expect(result.statusCode).toBe(404);
    expect(result.payload).toEqual({ error: "not_found" });
    expect(mockDdbSend).not.toHaveBeenCalled();
    expect(mockSfnSend).not.toHaveBeenCalled();
  });

  test.each([
    {},
    { requestedProfile: "private" },
    { requestedProfile: "auto", binding: {} },
    { requestedProfile: "core", sessionId: "client-chosen" }
  ])("rejects malformed or client-bound starts %#", async (body) => {
    const result = await handler(event("sessionStart", { body }));

    expect(result.statusCode).toBe(400);
    expect(result.payload).toEqual({ error: "invalid_runtime_request" });
    expect(mockDdbSend).not.toHaveBeenCalled();
    expect(mockSfnSend).not.toHaveBeenCalled();
  });

  test("rejects malformed session capabilities without reading a broad key", async () => {
    const result = await handler(
      event("sessionStatus", { sessionId: "not-a-session" })
    );

    expect(result.statusCode).toBe(400);
    expect(result.payload).toEqual({
      error: "invalid_runtime_session_id"
    });
    expect(mockDdbSend).not.toHaveBeenCalled();
  });
});
