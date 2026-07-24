import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { previewAudit } from "./fixtures";

const authMocks = vi.hoisted(() => ({
  snapshot: { status: "anonymous" } as const,
  beginSignIn: vi.fn(async () => undefined),
  signOut: vi.fn(),
}));

vi.mock("./auth", () => ({
  beginSignIn: authMocks.beginSignIn,
  getAccessToken: vi.fn(() => "TEST_ONLY_TOKEN_000000000000"),
  getAuthSnapshot: () => authMocks.snapshot,
  initializeAuthentication: vi.fn(async () => undefined),
  signOut: authMocks.signOut,
  subscribeToAuth: () => () => undefined,
}));

import { App } from "./App";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function json(value: unknown): Response {
  return {
    status: 200,
    ok: true,
    headers: {
      get: (name: string) =>
        name.toLowerCase() === "content-type" ? "application/json" : null,
    },
    json: async () => value,
  } as unknown as Response;
}

describe("Archon control plane", () => {
  it("renders the product-specific integrity view with an explicit fixture label", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", { name: /know when your catalog/i }),
    ).toBeInTheDocument();
    expect(screen.getByText("Fixture preview")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Integrity findings" })).toBeInTheDocument();
    expect(screen.getByText("5 results")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Blast radius" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Source provenance" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Evidence dossier" })).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: /integrity score/i }),
    ).not.toHaveAttribute("style");
  });

  it("filters findings without losing accessible labels", () => {
    render(<App />);

    fireEvent.change(screen.getByLabelText("Filter findings by severity"), {
      target: { value: "medium" },
    });

    expect(screen.getByText("2 results")).toBeInTheDocument();
    const list = screen.getByRole("list", { name: "Audit findings" });
    expect(within(list).getAllByRole("button")).toHaveLength(2);
  });

  it("makes fixture approval behavior explicit and non-mutating", () => {
    render(<App />);

    expect(screen.getByText(/fixture preview is non-mutating/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Approve exact plan" }));

    expect(screen.getByText(/preview only: approve selected/i)).toBeInTheDocument();
    expect(screen.getByText(/no backend decision or mutation was sent/i)).toBeInTheDocument();
  });

  it("locks live approval controls until Cognito authenticates the steward", async () => {
    const auditId = "a".repeat(64);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        json({
          schemaVersion: "archon.control-loop-start/v1",
          auditId,
          status: "RUNNING",
          pollUrl: `/api/control-loops/${auditId}`,
          submittedAt: "2026-07-23T12:00:00.000Z",
        }),
      )
      .mockResolvedValueOnce(
        json({
          schemaVersion: "archon.control-loop-status/v1",
          auditId,
          status: "AWAITING_APPROVAL",
          submittedAt: "2026-07-23T12:00:00.000Z",
          updatedAt: "2026-07-23T12:00:02.000Z",
          releaseSha: "live-release-sha",
          report: previewAudit.report,
          approval: {
            approvalId: "approval-g6-customer-email-001",
            status: "PENDING",
            expiresAt: "2026-08-10T20:59:00.000Z",
            planDigest: `sha256:${"1".repeat(64)}`,
            evidenceDigest: `sha256:${"2".repeat(64)}`,
          },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Run audit" }));

    expect(await screen.findByText("Live DataHub")).toBeInTheDocument();
    expect(
      screen.getByText(/live decisions are locked until cognito sign-in/i),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve exact plan" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Reject proposal" })).toBeDisabled();
    expect(screen.getByText(/immutable evidence is ready/i)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "/api/control-loops",
      expect.objectContaining({ method: "POST" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      `/api/control-loops/${auditId}`,
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("renders only the sanitized, verified terminal evidence projection", async () => {
    const auditId = "b".repeat(64);
    const receiptDigest = `sha256:${"7".repeat(64)}`;
    const executionEvidenceDigest = `sha256:${"8".repeat(64)}`;
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        json({
          schemaVersion: "archon.control-loop-start/v1",
          auditId,
          status: "RUNNING",
          pollUrl: `/api/control-loops/${auditId}`,
          submittedAt: "2026-07-23T12:00:00.000Z",
        }),
      )
      .mockResolvedValueOnce(
        json({
          schemaVersion: "archon.control-loop-status/v1",
          auditId,
          status: "SUCCEEDED",
          submittedAt: "2026-07-23T12:00:00.000Z",
          updatedAt: "2026-07-23T12:01:03.000Z",
          completedAt: "2026-07-23T12:01:03.000Z",
          releaseSha: "live-terminal-release",
          report: previewAudit.report,
          approval: {
            approvalId: "approval-g6-customer-email-001",
            status: "DECIDED",
            expiresAt: "2026-07-30T12:00:00.000Z",
            planDigest: `sha256:${"1".repeat(64)}`,
            evidenceDigest: `sha256:${"2".repeat(64)}`,
            decision: "APPROVE",
          },
          result: {
            outcome: "VERIFIED",
            receiptDigest,
            executionEvidenceDigest,
            completedAt: "2026-07-23T12:01:02.000Z",
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
          },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Run audit" }));

    const evidence = await screen.findByTestId("terminal-evidence");
    expect(within(evidence).getByText("VERIFIED")).toBeInTheDocument();
    expect(within(evidence).getByText("5/5 passed")).toBeInTheDocument();
    expect(within(evidence).getByText("7")).toBeInTheDocument();
    expect(within(evidence).getByText("ELIGIBLE")).toBeInTheDocument();
    expect(
      within(evidence).getByText("APPROVAL_BINDING_VALID"),
    ).toBeInTheDocument();
    expect(within(evidence).getByTitle(receiptDigest)).toBeInTheDocument();
    expect(within(evidence).getByTitle(executionEvidenceDigest)).toBeInTheDocument();
    expect(evidence).not.toHaveTextContent("taskToken");
    expect(evidence).not.toHaveTextContent("private-steward-subject");
  });
});
