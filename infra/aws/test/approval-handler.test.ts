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
      constructor(readonly input: Record<string, unknown>) {}
    },
    UpdateItemCommand: class {
      readonly kind = "UpdateItemCommand";
      constructor(readonly input: Record<string, any>) {}
    },
  }),
  { virtual: true }
);
jest.mock(
  "@aws-sdk/client-sfn",
  () => ({
    SFNClient: class {
      send = mockSfnSend;
    },
    SendTaskSuccessCommand: class {
      readonly kind = "SendTaskSuccessCommand";
      constructor(readonly input: Record<string, any>) {}
    },
  }),
  { virtual: true }
);

process.env.APPROVAL_TABLE = "approval-table";
process.env.APPROVER_GROUP = "archon-approvers";
const { handler } = require("../lambda/approval/index.js") as {
  handler: (event: Record<string, any>) => Promise<{
    statusCode: number;
    body: string;
  }>;
};

function event(
  body: Record<string, unknown>,
  claims: Record<string, unknown> = {
    sub: "cognito-sub-123",
    iss: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example",
    email: "approver@example.test",
    "cognito:groups": "archon-approvers"
  }
): Record<string, unknown> {
  return {
    pathParameters: { approvalId: "approval-1234" },
    requestContext: { authorizer: { claims } },
    body: JSON.stringify(body)
  };
}

describe("approval control Lambda", () => {
  beforeEach(() => {
    mockDdbSend.mockReset();
    mockSfnSend.mockReset();
  });

  test("rejects browser-supplied mutation fields before touching AWS", async () => {
    const result = await handler(
      event({
        decision: "APPROVE",
        comment: "looks correct",
        tool: "add_tags",
        arguments: { entityUrn: "urn:li:dataset:forbidden" }
      })
    );
    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body)).toEqual({ error: "unexpected_field" });
    expect(mockDdbSend).not.toHaveBeenCalled();
    expect(mockSfnSend).not.toHaveBeenCalled();
  });

  test("requires the Cognito approver group", async () => {
    const result = await handler(
      event(
        { decision: "REJECT", comment: "needs evidence" },
        {
          sub: "ordinary-user",
          iss: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example",
          "cognito:groups": "archon-viewers"
        }
      )
    );
    expect(result.statusCode).toBe(403);
    expect(JSON.parse(result.body)).toEqual({ error: "approver_role_required" });
    expect(mockDdbSend).not.toHaveBeenCalled();
  });

  test("binds the decision to Cognito claims, CAS, and the server-held token", async () => {
    const decisionStartedAt = Math.floor(Date.now() / 1000);
    let getCount = 0;
    let capturedDigest = "";
    let capturedEvidenceDigest = "";
    mockDdbSend.mockImplementation(async (command: any) => {
      if (command.kind === "GetItemCommand") {
        getCount += 1;
        if (getCount === 1) {
          return {
            Item: {
              status: { S: "PENDING" },
              taskToken: { S: "opaque-server-token" },
              approvalExpiresAt: {
                S: new Date(Date.now() + 3600 * 1000).toISOString()
              },
              expiresAt: { N: String(Math.floor(Date.now() / 1000) + 3600) }
            }
          };
        }
        return {
          Item: {
            status: { S: "DECIDED" },
            taskToken: { S: "opaque-server-token" },
            decisionDigest: { S: capturedDigest },
            decisionEvidenceDigest: { S: capturedEvidenceDigest },
            approverSub: { S: "cognito-sub-123" },
            approverIssuer: {
              S: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example"
            },
            decidedAt: { S: "2026-07-23T10:02:00.000Z" },
            callbackDelivered: { BOOL: false },
            approvalExpiresAt: {
              S: new Date(Date.now() + 3600 * 1000).toISOString()
            },
            expiresAt: { N: String(Math.floor(Date.now() / 1000) + 3600) }
          }
        };
      }
      if (command.kind === "UpdateItemCommand" && !capturedDigest) {
        capturedDigest = command.input.ExpressionAttributeValues[":digest"].S;
        capturedEvidenceDigest =
          command.input.ExpressionAttributeValues[":evidenceDigest"].S;
      }
      return {};
    });
    mockSfnSend.mockResolvedValue({});

    const result = await handler(
      event({ decision: "APPROVE", comment: "evidence verified" })
    );

    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body)).toEqual({
      approvalId: "approval-1234",
      decision: "APPROVE",
      status: "recorded",
      decisionId: capturedDigest,
      disposition: "recorded"
    });
    const decisionWrite = mockDdbSend.mock.calls
      .map(([command]) => command)
      .find(
        (command) =>
          command.kind === "UpdateItemCommand" &&
          command.input.ExpressionAttributeValues[":pending"]
      ) as { input: Record<string, any> };
    expect(decisionWrite.input.ExpressionAttributeValues[":sub"]).toEqual({
      S: "cognito-sub-123"
    });
    expect(decisionWrite.input.ExpressionAttributeValues[":issuer"]).toEqual({
      S: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example"
    });
    expect(decisionWrite.input.ConditionExpression).toBe("#status = :pending");
    expect(decisionWrite.input.UpdateExpression).not.toContain(
      "approvalExpiresAt"
    );
    const retentionExpiresAt = Number(
      decisionWrite.input.ExpressionAttributeValues[":retentionExpiresAt"].N
    );
    expect(retentionExpiresAt).toBeGreaterThanOrEqual(
      decisionStartedAt + 90 * 24 * 60 * 60
    );
    expect(retentionExpiresAt).toBeLessThanOrEqual(
      Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60
    );

    const callback = mockSfnSend.mock.calls[0]![0] as {
      input: Record<string, any>;
    };
    expect(callback.input.taskToken).toBe("opaque-server-token");
    const callbackOutput = JSON.parse(callback.input.output);
    expect(callbackOutput.decision.approver).toEqual({
      subject: "cognito-sub-123",
      issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example",
      roles: ["DataSteward"],
      authenticated: true
    });
    expect(callbackOutput.decision.decidedAt).toBe("2026-07-23T10:02:00.000Z");
  });

  test("keeps a decided response idempotent after its immutable approval deadline", async () => {
    const crypto = require("node:crypto") as typeof import("node:crypto");
    const digestPayload = {
      approvalId: "approval-1234",
      decision: "REJECT",
      comment: "not safe",
      approverSub: "cognito-sub-123",
      approverIssuer:
        "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example"
    };
    const digest = `sha256:${crypto
      .createHash("sha256")
      .update(JSON.stringify(digestPayload))
      .digest("hex")}`;
    const decidedAt = "2026-07-23T10:02:00.000Z";
    const evidencePayload = {
      schemaVersion: "archon.approval-decision/v1",
      approvalId: "approval-1234",
      executionId: "execution-1234",
      evidenceDigest: `sha256:${"a".repeat(64)}`,
      planDigest: `sha256:${"b".repeat(64)}`,
      requestDigest: `sha256:${"c".repeat(64)}`,
      decision: "REJECT",
      approver: {
        subject: "cognito-sub-123",
        issuer:
          "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example",
        roles: ["DataSteward"],
        authenticated: true
      },
      commentDigest: `sha256:${crypto
        .createHash("sha256")
        .update(JSON.stringify("not safe"))
        .digest("hex")}`
    };
    const evidenceDigest = `sha256:${crypto
      .createHash("sha256")
      .update(JSON.stringify(evidencePayload))
      .digest("hex")}`;
    mockDdbSend.mockResolvedValue({
      Item: {
        status: { S: "DECIDED" },
        decisionDigest: { S: digest },
        decisionEvidenceDigest: { S: evidenceDigest },
        executionId: { S: "execution-1234" },
        evidenceDigest: { S: `sha256:${"a".repeat(64)}` },
        planDigest: { S: `sha256:${"b".repeat(64)}` },
        requestDigest: { S: `sha256:${"c".repeat(64)}` },
        approverSub: { S: "cognito-sub-123" },
        approverIssuer: {
          S: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example"
        },
        callbackDelivered: { BOOL: true },
        decidedAt: { S: decidedAt },
        approvalExpiresAt: {
          S: new Date(Date.now() - 3600 * 1000).toISOString()
        },
        expiresAt: {
          N: String(Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60)
        }
      }
    });

    const result = await handler(
      event({ decision: "REJECT", comment: "not safe" })
    );
    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).disposition).toBe("already_recorded");
    expect(mockSfnSend).not.toHaveBeenCalled();
  });

  test("records a terminal callback replay without a permanent false 5xx", async () => {
    let getCount = 0;
    let decisionDigest = "";
    let decisionEvidenceDigest = "";
    mockDdbSend.mockImplementation(async (command: any) => {
      if (command.kind === "GetItemCommand") {
        getCount += 1;
        if (getCount === 1) {
          return {
            Item: {
              status: { S: "PENDING" },
              taskToken: { S: "opaque-server-token" },
              executionId: { S: "execution-1234" },
              evidenceDigest: { S: `sha256:${"a".repeat(64)}` },
              planDigest: { S: `sha256:${"b".repeat(64)}` },
              requestDigest: { S: `sha256:${"c".repeat(64)}` },
              approvalExpiresAt: {
                S: new Date(Date.now() + 3600 * 1000).toISOString()
              },
              expiresAt: { N: String(Math.floor(Date.now() / 1000) + 3600) }
            }
          };
        }
        return {
          Item: {
            status: { S: "DECIDED" },
            taskToken: { S: "opaque-server-token" },
            executionId: { S: "execution-1234" },
            evidenceDigest: { S: `sha256:${"a".repeat(64)}` },
            planDigest: { S: `sha256:${"b".repeat(64)}` },
            requestDigest: { S: `sha256:${"c".repeat(64)}` },
            decisionDigest: { S: decisionDigest },
            decisionEvidenceDigest: { S: decisionEvidenceDigest },
            approverSub: { S: "cognito-sub-123" },
            approverIssuer: {
              S: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example"
            },
            decidedAt: { S: "2026-07-23T10:02:00.000Z" },
            callbackDelivered: { BOOL: false },
            approvalExpiresAt: {
              S: new Date(Date.now() + 3600 * 1000).toISOString()
            },
            expiresAt: { N: String(Math.floor(Date.now() / 1000) + 3600) }
          }
        };
      }
      if (
        command.kind === "UpdateItemCommand" &&
        command.input.ExpressionAttributeValues[":pending"]
      ) {
        decisionDigest = command.input.ExpressionAttributeValues[":digest"].S;
        decisionEvidenceDigest =
          command.input.ExpressionAttributeValues[":evidenceDigest"].S;
      }
      return {};
    });
    mockSfnSend.mockRejectedValue(
      Object.assign(new Error("already consumed"), { name: "TaskTimedOut" })
    );

    const result = await handler(
      event({ decision: "REJECT", comment: "do not apply" })
    );

    expect(result.statusCode).toBe(202);
    expect(JSON.parse(result.body).disposition).toBe(
      "recorded_callback_closed"
    );
    const closeWrite = mockDdbSend.mock.calls
      .map(([command]) => command)
      .find(
        (command) =>
          command.kind === "UpdateItemCommand" &&
          command.input.ExpressionAttributeValues[":closed"]
      );
    expect(closeWrite).toBeDefined();
  });
});
