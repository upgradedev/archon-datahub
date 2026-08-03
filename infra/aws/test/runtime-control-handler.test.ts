export {};

const mockDdbSend = jest.fn();
const mockSfnSend = jest.fn();
const { createHash } = require("node:crypto") as typeof import("node:crypto");

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
process.env.RUNTIME_OPERATOR_GROUP = "archon-approvers";

const { handler } = require("../lambda/runtime-control/index.js") as {
  handler: (event: Record<string, unknown>) => Promise<{
    statusCode: number;
    headers: Record<string, string>;
    payload: Record<string, any>;
  }>;
};
const {
  capabilityDigest,
  createSession
} = require("../lambda/runtime-control/session.js") as {
  capabilityDigest: (
    profileId: "cloud" | "core",
    generation: string,
    capabilities: Record<string, boolean>
  ) => string;
  createSession: (input: Record<string, unknown>) => Record<string, any>;
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

const identity = {
  subject: "2f6dcb5a-9f76-4f65-960d-f2637d65b9cb",
  issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TEST",
  groups: "[archon-approvers]"
};

function event(
  operation: string,
  extra: Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    operation,
    requestId: "request-runtime-123",
    ...(["sessionStart", "sessionActivity", "sessionStop"].includes(operation)
      ? { identity }
      : {}),
    ...extra
  };
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
              revision: { N: "17" }
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
      expectedRevision: 17,
      binding: expect.objectContaining({
        schemaVersion: "archon.runtime-binding/v1",
        profileId: "core",
        resolution: "auto"
      })
    });
    expect(JSON.stringify(input)).not.toContain("endpoint");
  });

  test.each([
    [
      "missing identity",
      {
        operation: "sessionStart",
        requestId: "request-runtime-123",
        body: { requestedProfile: "auto" }
      },
      401,
      "authenticated_runtime_operator_required"
    ],
    [
      "wrong operator group",
      event("sessionStart", {
        body: { requestedProfile: "auto" },
        identity: { ...identity, groups: "[another-group]" }
      }),
      403,
      "runtime_operator_role_required"
    ],
    [
      "malformed issuer",
      event("sessionStart", {
        body: { requestedProfile: "auto" },
        identity: { ...identity, issuer: "http://not-trusted.example" }
      }),
      401,
      "authenticated_runtime_operator_required"
    ],
    [
      "control character in subject",
      event("sessionStart", {
        body: { requestedProfile: "auto" },
        identity: {
          ...identity,
          subject: "2f6dcb5a-9f76-4f65-960d-f2637d65b9cb" + String.fromCharCode(0)
        }
      }),
      401,
      "authenticated_runtime_operator_required"
    ]
  ])("rejects %s before paid orchestration", async (_label, input, status, code) => {
    const result = await handler(input as Record<string, unknown>);

    expect(result.statusCode).toBe(status);
    expect(result.payload).toEqual({ error: code });
    expect(mockDdbSend).not.toHaveBeenCalled();
    expect(mockSfnSend).not.toHaveBeenCalled();
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

  test("awaits durable Core STOP dispatch before projecting an expired session", async () => {
    jest.setSystemTime(new Date("2026-08-02T08:31:00.000Z"));
    const sessionId = "rs_" + "E".repeat(43);
    const binding = {
      schemaVersion: "archon.runtime-binding/v1",
      profileId: "core",
      generation: "ami-2026-08-02.1",
      capabilityDigest: capabilityDigest(
        "core",
        "ami-2026-08-02.1",
        capabilities
      ),
      resolution: "explicit",
      boundAt: "2026-08-02T08:00:00.000Z",
      leaseExpiresAt: "2026-08-02T10:00:00.000Z"
    };
    const stored = createSession({
      sessionId,
      requestedProfile: "core",
      binding,
      state: "ACTIVE"
    });
    const principalHash =
      "sha256:" +
      createHash("sha256")
        .update(
          JSON.stringify({
            issuer: identity.issuer,
            subject: identity.subject
          }),
          "utf8"
        )
        .digest("hex");
    mockDdbSend.mockImplementation(async (command: any) => {
      if (command.kind === "GetItemCommand") {
        const pk = command.input.Key.pk.S;
        if (pk === "SESSION#" + sessionId) {
          return {
            Item: {
              pk: { S: pk },
              sk: { S: "RUNTIME" },
              payload: { S: JSON.stringify(stored) },
              revision: { N: "0" },
              principalHash: { S: principalHash }
            }
          };
        }
        if (pk === "CORE#LEASE") {
          return {
            Item: {
              state: { S: "READY" },
              revision: { N: "8" },
              sessionId: { S: sessionId }
            }
          };
        }
      }
      if (command.kind === "UpdateItemCommand") return {};
      throw new Error("unexpected command " + command.kind);
    });
    let releaseStop!: () => void;
    const stopAccepted = new Promise<void>((resolve) => {
      releaseStop = resolve;
    });
    mockSfnSend.mockImplementation(async () => stopAccepted);

    let settled = false;
    const resultPromise = handler(
      event("sessionStatus", { sessionId })
    ).finally(() => {
      settled = true;
    });
    for (let index = 0; index < 8; index += 1) {
      await Promise.resolve();
    }

    expect(mockSfnSend).toHaveBeenCalledTimes(1);
    expect(settled).toBe(false);
    const stopCommand = mockSfnSend.mock.calls[0]![0] as any;
    expect(JSON.parse(stopCommand.input.input)).toMatchObject({
      schema: "archon.core-runtime-command/v1",
      action: "STOP",
      sessionId,
      expectedRevision: 8
    });

    releaseStop();
    const result = await resultPromise;

    expect(result.statusCode).toBe(200);
    expect(result.payload).toMatchObject({
      state: "EXPIRED",
      remainingSeconds: 0,
      canRun: false
    });
    const update = mockDdbSend.mock.calls
      .map(([command]) => command)
      .find((command) => command.kind === "UpdateItemCommand");
    expect(JSON.parse(update.input.ExpressionAttributeValues[":payload"].S))
      .toMatchObject({
        state: "EXPIRED",
        endReason: "IDLE_TIMEOUT"
      });
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
