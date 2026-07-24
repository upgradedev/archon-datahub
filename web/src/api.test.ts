import { afterEach, describe, expect, it, vi } from "vitest";
import {
  getControlLoopStatus,
  loadAudit,
  requestAudit,
  startControlLoop,
  submitApprovalDecision,
} from "./api";
import { previewAudit } from "./fixtures";

afterEach(() => {
  vi.useRealTimers();
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

function verifiedResult() {
  return {
    outcome: "VERIFIED",
    receiptDigest: `sha256:${"5".repeat(64)}`,
    executionEvidenceDigest: `sha256:${"6".repeat(64)}`,
    completedAt: "2026-07-23T12:00:12.000Z",
    verification: {
      checks: [
        { checkId: "TARGET_UNCHANGED", passed: true },
        { checkId: "PREEXISTING_TAGS_PRESERVED", passed: true },
        { checkId: "POLICY_TAG_PRESENT", passed: true },
        { checkId: "NO_UNEXPECTED_TAGS", passed: true },
        { checkId: "APPROVAL_BINDING_VALID", passed: true },
      ],
      eventCount: 7,
      rollbackAvailability: "ELIGIBLE",
    },
  };
}

describe("audit API", () => {
  it("posts a bounded catalog scope and validates the envelope", async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(previewAudit));
    vi.stubGlobal("fetch", fetchMock);

    const result = await requestAudit("  domain:Commerce  ");

    expect(result.report.scanId).toBe(previewAudit.report.scanId);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/audits",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        body: JSON.stringify({ query: "domain:Commerce" }),
      }),
    );
  });

  it("falls back deterministically only when the hosted API is unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("network unavailable")));

    const result = await loadAudit();

    expect(result.source).toBe("fixture");
    expect(result.envelope).toBe(previewAudit);
    expect(result.fallbackReason).toMatch(/deterministic/i);
  });

  it("starts and polls only the same-origin opaque control-loop capability", async () => {
    const auditId = "b".repeat(64);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        json({
          schemaVersion: "archon.control-loop-start/v1",
          auditId,
          status: "RUNNING",
          pollUrl: `/api/control-loops/${auditId}`,
          submittedAt: "2026-07-23T12:00:00.000Z",
        }, 202),
      )
      .mockResolvedValueOnce(
        json({
          schemaVersion: "archon.control-loop-status/v1",
          auditId,
          status: "AWAITING_APPROVAL",
          submittedAt: "2026-07-23T12:00:00.000Z",
          updatedAt: "2026-07-23T12:00:10.000Z",
          releaseSha: "release-123",
          report: previewAudit.report,
          approval: {
            approvalId: "approval-live-1234",
            status: "PENDING",
            expiresAt: "2026-07-30T12:00:00.000Z",
            planDigest: `sha256:${"1".repeat(64)}`,
            evidenceDigest: `sha256:${"2".repeat(64)}`,
          },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const started = await startControlLoop(" domain:Commerce ");
    const status = await getControlLoopStatus(started);

    expect(started.auditId).toBe(auditId);
    expect(status.status).toBe("AWAITING_APPROVAL");
    expect(status.report?.scanId).toBe(previewAudit.report.scanId);
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "/api/control-loops",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ query: "domain:Commerce" }),
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      `/api/control-loops/${auditId}`,
      expect.objectContaining({ method: "GET", credentials: "same-origin" }),
    );
  });

  it("keeps polling through human approval and returns the terminal verified report", async () => {
    vi.useFakeTimers();
    const auditId = "c".repeat(64);
    const progress = vi.fn();
    const baseStatus = {
      schemaVersion: "archon.control-loop-status/v1",
      auditId,
      submittedAt: "2026-07-23T12:00:00.000Z",
      releaseSha: "release-verified",
      report: previewAudit.report,
      approval: {
        approvalId: "approval-live-5678",
        status: "PENDING",
        expiresAt: "2026-07-30T12:00:00.000Z",
        planDigest: `sha256:${"3".repeat(64)}`,
        evidenceDigest: `sha256:${"4".repeat(64)}`,
      },
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        json({
          schemaVersion: "archon.control-loop-start/v1",
          auditId,
          status: "RUNNING",
          pollUrl: `/api/control-loops/${auditId}`,
          submittedAt: "2026-07-23T12:00:00.000Z",
        }, 202),
      )
      .mockResolvedValueOnce(
        json({
          ...baseStatus,
          status: "AWAITING_APPROVAL",
          updatedAt: "2026-07-23T12:00:10.000Z",
        }),
      )
      .mockResolvedValueOnce(
        json({
          ...baseStatus,
          status: "SUCCEEDED",
          updatedAt: "2026-07-23T12:00:13.000Z",
          completedAt: "2026-07-23T12:00:13.000Z",
          approval: { ...baseStatus.approval, status: "DECIDED", decision: "APPROVE" },
          result: verifiedResult(),
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const resultPromise = loadAudit("", undefined, progress);
    await vi.advanceTimersByTimeAsync(3000);
    const result = await resultPromise;

    expect(result.source).toBe("live");
    expect(result.controlLoop?.result?.outcome).toBe("VERIFIED");
    expect(progress.mock.calls.map(([status]) => status.status)).toEqual([
      "AWAITING_APPROVAL",
      "SUCCEEDED",
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("rejects legacy, malformed, or raw terminal result projections", async () => {
    const auditId = "d".repeat(64);
    const start = {
      auditId,
      pollUrl: `/api/control-loops/${auditId}`,
    };
    const base = {
      schemaVersion: "archon.control-loop-status/v1",
      auditId,
      status: "SUCCEEDED",
      updatedAt: "2026-07-23T12:00:13.000Z",
      completedAt: "2026-07-23T12:00:13.000Z",
      releaseSha: "release-terminal",
      report: previewAudit.report,
      approval: {
        approvalId: "approval-live-5678",
        status: "DECIDED",
        expiresAt: "2026-07-30T12:00:00.000Z",
        planDigest: `sha256:${"3".repeat(64)}`,
        evidenceDigest: `sha256:${"4".repeat(64)}`,
        decision: "APPROVE",
      },
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ ...base, result: { outcome: "COMPLETED" } }))
      .mockResolvedValueOnce(
        json({
          ...base,
          result: {
            ...verifiedResult(),
            taskToken: "must-not-cross-the-browser-contract",
          },
        }),
      )
      .mockResolvedValueOnce(
        json({
          ...base,
          result: {
            ...verifiedResult(),
            verification: {
              ...verifiedResult().verification,
              eventCount: 6,
            },
          },
        }),
      )
      .mockResolvedValueOnce(
        json({
          ...base,
          executionArn: "arn:aws:states:eu-west-1:111111111111:execution:must-not-cross",
          result: verifiedResult(),
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    await expect(getControlLoopStatus(start)).rejects.toMatchObject({ status: 502 });
    await expect(getControlLoopStatus(start)).rejects.toMatchObject({ status: 502 });
    await expect(getControlLoopStatus(start)).rejects.toMatchObject({ status: 502 });
    await expect(getControlLoopStatus(start)).rejects.toMatchObject({ status: 502 });
  });
});

describe("approval API trust boundary", () => {
  it("sends only the steward decision and optional comment in the body", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      json({
        approvalId: "approval-123",
        decision: "APPROVE",
        status: "recorded",
        decisionId: "decision-server-123",
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", {
      randomUUID: () => "00000000-0000-4000-8000-000000000001",
    });

    await submitApprovalDecision({
      approvalId: "approval-123",
      decision: "APPROVE",
      accessToken: "TEST_ONLY_TOKEN_000000000000",
      comment: "  Evidence reviewed.  ",
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.headers).toMatchObject({
      Authorization: "Bearer TEST_ONLY_TOKEN_000000000000",
    });
    expect(JSON.parse(String(init.body))).toEqual({
      decision: "APPROVE",
      comment: "Evidence reviewed.",
    });
    expect(JSON.parse(String(init.body))).not.toHaveProperty("tool");
    expect(JSON.parse(String(init.body))).not.toHaveProperty("arguments");
    expect(JSON.parse(String(init.body))).not.toHaveProperty("actor");
    expect(JSON.parse(String(init.body))).not.toHaveProperty("accessToken");
  });

  it("fails closed before the network when the access token is absent or malformed", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      submitApprovalDecision({
        approvalId: "approval-123",
        decision: "REJECT",
        accessToken: "not valid",
      }),
    ).rejects.toMatchObject({ status: 401 });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
