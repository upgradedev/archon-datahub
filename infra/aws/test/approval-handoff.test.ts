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
    PutItemCommand: class {
      readonly kind = "PutItemCommand";
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
    SendTaskFailureCommand: class {
      readonly kind = "SendTaskFailureCommand";
      constructor(readonly input: Record<string, any>) {}
    },
  }),
  { virtual: true }
);

process.env.APPROVAL_TABLE = "approval-table";
const { handler } = require("../lambda/approval/handoff.js") as {
  handler: (event: Record<string, any>) => Promise<{
    batchItemFailures: Array<{ itemIdentifier: string }>;
  }>;
};

const DIGEST = `sha256:${"a".repeat(64)}`;
const EXECUTION =
  "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:execution-0001";

function message(overrides: Record<string, unknown> = {}) {
  const requestedAt = new Date(Date.now() - 60_000).toISOString();
  const expiresAt = new Date(Date.now() + 6 * 24 * 60 * 60 * 1000).toISOString();
  return {
    type: "APPROVAL_REQUESTED",
    taskToken: "opaque-approval-task-token-0001",
    executionId: EXECUTION,
    approvalId: "approval-0001",
    planDigest: DIGEST,
    evidenceDigest: DIGEST,
    approvalRequestDigest: DIGEST,
    requestedAt,
    expiresAt,
    ...overrides,
  };
}

function sqs(body: Record<string, unknown>) {
  return {
    Records: [{ messageId: "message-0001", body: JSON.stringify(body) }],
  };
}

describe("approval handoff Lambda", () => {
  beforeEach(() => {
    mockDdbSend.mockReset();
    mockSfnSend.mockReset();
  });

  test("persists the server-held callback with an immutable binding", async () => {
    mockDdbSend.mockResolvedValue({});
    const body = message();

    const result = await handler(sqs(body));

    expect(result.batchItemFailures).toEqual([]);
    const write = mockDdbSend.mock.calls[0]![0];
    expect(write.kind).toBe("PutItemCommand");
    expect(write.input.Item.pk).toEqual({ S: "APPROVAL#approval-0001" });
    expect(write.input.Item.taskToken).toEqual({
      S: "opaque-approval-task-token-0001",
    });
    expect(write.input.Item.approvalExpiresAt).toEqual({
      S: body.expiresAt,
    });
    expect(write.input.Item.expiresAt).toEqual({
      N: String(Math.floor(Date.parse(String(body.expiresAt)) / 1000)),
    });
    expect(write.input.ConditionExpression).toContain(
      "attribute_not_exists"
    );
    expect(mockSfnSend).not.toHaveBeenCalled();
  });

  test("accepts an idempotent redelivery only with the same binding", async () => {
    const body = message();
    mockDdbSend
      .mockRejectedValueOnce(
        Object.assign(new Error("exists"), {
          name: "ConditionalCheckFailedException",
        })
      )
      .mockResolvedValueOnce({
        Item: {
          status: { S: "PENDING" },
          taskToken: { S: body.taskToken },
          executionId: { S: body.executionId },
          evidenceDigest: { S: body.evidenceDigest },
          planDigest: { S: body.planDigest },
          requestDigest: { S: body.approvalRequestDigest },
          requestedAt: { S: body.requestedAt },
          approvalExpiresAt: { S: body.expiresAt },
        },
      });

    const result = await handler(sqs(body));

    expect(result.batchItemFailures).toEqual([]);
    expect(mockSfnSend).not.toHaveBeenCalled();
  });

  test("quarantines terminal poison and fails the callback without redundant redrive", async () => {
    mockDdbSend.mockResolvedValue({});
    mockSfnSend.mockResolvedValue({});

    const result = await handler(
      sqs(message({ unexpectedMutationTool: "add_tags" }))
    );

    expect(result.batchItemFailures).toEqual([]);
    const poison = mockDdbSend.mock.calls[0]![0];
    expect(poison.input.Item.pk).toEqual({
      S: "HANDOFF_FAILURE#message-0001",
    });
    expect(poison.input.Item).not.toHaveProperty("taskToken");
    expect(mockSfnSend.mock.calls[0]![0].input.error).toBe(
      "ArchonApprovalHandoffRejected"
    );
  });
});
