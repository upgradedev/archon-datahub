import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const authMocks = vi.hoisted(() => ({
  snapshot: { status: "anonymous" } as
    | { status: "anonymous" }
    | { status: "authenticated"; expiresAt: number },
  beginSignIn: vi.fn(async () => undefined),
  signOut: vi.fn(),
}));

vi.mock("./auth", () => ({
  beginSignIn: authMocks.beginSignIn,
  getAccessToken: vi.fn(() => "TEST_ONLY_TOKEN_000000000000"),
  getAuthSnapshot: () => authMocks.snapshot,
  getDemoQuery: () => "customer_pii",
  initializeAuthentication: vi.fn(async () => undefined),
  signOut: authMocks.signOut,
  subscribeToAuth: () => () => undefined,
}));

const runtimeMocks = vi.hoisted(() => ({
  loadRuntimeAgentStack: vi.fn(),
  requestRuntimeImproveContext: vi.fn(),
  resumeRuntimeAgentStack: vi.fn(),
  submitRuntimeApproval: vi.fn(),
}));

vi.mock("./runtime-api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./runtime-api")>();
  return {
    ...actual,
    loadRuntimeAgentStack: runtimeMocks.loadRuntimeAgentStack,
    requestRuntimeImproveContext: runtimeMocks.requestRuntimeImproveContext,
    resumeRuntimeAgentStack: runtimeMocks.resumeRuntimeAgentStack,
    submitRuntimeApproval: runtimeMocks.submitRuntimeApproval,
  };
});

vi.mock("./RuntimeControl", async () => {
  const React = await vi.importActual<typeof import("react")>("react");
  return {
    RuntimeControl: ({
      onSessionChange,
    }: {
      onSessionChange?: (session: unknown) => void;
    }) => {
      React.useEffect(() => {
        onSessionChange?.({
          schemaVersion: "archon.runtime-session-status/v1",
          sessionId: `rs_${"R".repeat(43)}`,
          requestedProfile: "auto",
          resolvedProfile: "cloud",
          state: "READY",
          createdAt: "2026-08-02T08:00:00.000Z",
          updatedAt: "2026-08-02T08:00:01.000Z",
          idleExpiresAt: "2026-08-02T08:30:01.000Z",
          hardExpiresAt: "2026-08-02T10:00:00.000Z",
          remainingSeconds: 1800,
          canRun: true,
          canExtend: true,
        });
      }, [onSessionChange]);
      return React.createElement(
        "div",
        { "data-testid": "runtime-control-fixture" },
        "Pinned Cloud runtime ready",
      );
    },
  };
});

const apiMocks = vi.hoisted(() => ({
  probeRuntimeReadiness: vi.fn(),
  requestAudit: vi.fn(),
}));

vi.mock("./api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api")>();
  return {
    ...actual,
    probeRuntimeReadiness: apiMocks.probeRuntimeReadiness,
    requestAudit: apiMocks.requestAudit,
  };
});

import { App } from "./App";
import { previewAudit } from "./fixtures";

beforeEach(() => {
  authMocks.snapshot = { status: "anonymous" };
  runtimeMocks.loadRuntimeAgentStack.mockReset();
  runtimeMocks.requestRuntimeImproveContext.mockReset();
  runtimeMocks.resumeRuntimeAgentStack.mockReset();
  runtimeMocks.submitRuntimeApproval.mockReset();
  apiMocks.probeRuntimeReadiness.mockReset();
  apiMocks.probeRuntimeReadiness.mockResolvedValue(undefined);
  apiMocks.requestAudit.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

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
    const modelProvenance = screen.getByTestId("model-provenance");
    expect(
      within(modelProvenance).getByRole("heading", {
        name: "Model runtime provenance",
      }),
    ).toBeInTheDocument();
    expect(within(modelProvenance).getByText("No model call")).toBeInTheDocument();
    expect(modelProvenance).toHaveTextContent(
      /No provider model API call occurred/i,
    );
    expect(modelProvenance).toHaveTextContent(
      /there is no provider response ID, token usage, or client latency/i,
    );
    expect(document.getElementById("judge-tour-run-audit")).toBeInstanceOf(
      HTMLButtonElement,
    );
    expect(document.getElementById("judge-tour-provenance")).toBeInstanceOf(
      HTMLElement,
    );
    expect(document.getElementById("control-review")).toBeInstanceOf(HTMLElement);
    expect(document.getElementById("judge-evidence")).toBeInstanceOf(HTMLElement);
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

    fireEvent.click(screen.getByRole("button", { name: "Reject proposal" }));
    expect(screen.getByText(/preview only: reject selected/i)).toBeInTheDocument();
    expect(screen.getByText(/no backend decision or mutation was sent/i)).toBeInTheDocument();
  });

  it("locks the live Agent Stack until Cognito authenticates the steward", async () => {
    render(<App />);

    expect(
      await screen.findByLabelText("Canonical DataHub dataset URN"),
    ).toBeInTheDocument();
    const run = screen.getByRole("button", {
      name: "Run canonical Agent Stack",
    });
    expect(run).toBeDisabled();
    fireEvent.click(run);
    expect(runtimeMocks.loadRuntimeAgentStack).not.toHaveBeenCalled();
    expect(screen.getByText("Pinned Cloud runtime ready")).toBeInTheDocument();
  });

  it("renders the bounded four-component DataHub execution receipt", async () => {
    authMocks.snapshot = {
      status: "authenticated",
      expiresAt: Date.now() + 60_000,
    };
    const status = {
      schemaVersion: "archon.runtime-control-loop-status/v2",
      auditId: "e".repeat(64),
      status: "SUCCEEDED",
      phase: "COMPLETE",
      runtimeEvidence: {
        digest: `sha256:${"1".repeat(64)}`,
        runtimeBinding: { profileId: "cloud" },
      },
      agentStackResult: {
        context: {
          digest: `sha256:${"2".repeat(64)}`,
          entityUrns: [
            "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)",
          ],
          receipts: [
            { tool: "search" },
            { tool: "get_entities" },
            { tool: "get_lineage_downstream" },
          ],
          unknownPreserved: false,
        },
        skills: {
          digest: `sha256:${"3".repeat(64)}`,
          workflow: [
            "datahub-search",
            "datahub-lineage",
            "datahub-quality",
            "datahub-audit",
            "datahub-enrich",
          ],
        },
        analytics: {
          digest: `sha256:${"4".repeat(64)}`,
          events: [
            { event: "SQL", statementDigest: `sha256:${"5".repeat(64)}` },
            { event: "RESULT", rowCount: 1 },
            { event: "CHART", chart: "bar" },
            { event: "COMPLETE", answer: "Enterprise generated the highest Q2 net revenue." },
          ],
          contextQuality: {
            status: "verified",
            score: 5,
            label: "excellent",
            reason: "Grounded by ACK, official MCP reads, and reviewed Skills.",
          },
        },
      },
    };
    runtimeMocks.loadRuntimeAgentStack.mockResolvedValueOnce(status);
    render(<App />);

    const run = await screen.findByRole("button", {
      name: "Run canonical Agent Stack",
    });
    await waitFor(() => expect(run).toBeEnabled());
    fireEvent.click(run);

    const panel = await screen.findByTestId("agent-stack-panel");
    await waitFor(() =>
      expect(within(panel).getByText("SUCCEEDED · COMPLETE")).toBeInTheDocument(),
    );
    expect(within(panel).getByText("DataHub Cloud · managed")).toBeInTheDocument();
    expect(within(panel).getByText("5/5")).toBeInTheDocument();
    expect(within(panel).getByText("excellent")).toBeInTheDocument();
    expect(within(panel).getByText("SQL")).toBeInTheDocument();
    expect(within(panel).getByText("CHART")).toBeInTheDocument();
    expect(panel).not.toHaveTextContent("run_private_backend_handle");
    expect(runtimeMocks.loadRuntimeAgentStack).toHaveBeenCalledWith(
      "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)",
      "Which customer segment generated the highest net revenue in Q2 2026, and is customers.customer_email governed as PII?",
      `rs_${"R".repeat(43)}`,
      "TEST_ONLY_TOKEN_000000000000",
      expect.any(AbortSignal),
      expect.any(Function),
    );
  });

  it("renders only the sanitized governed MCP and KMS proof", async () => {
    authMocks.snapshot = {
      status: "authenticated",
      expiresAt: Date.now() + 60_000,
    };
    const status = {
      schemaVersion: "archon.runtime-control-loop-status/v2",
      auditId: "b".repeat(64),
      status: "SUCCEEDED",
      phase: "COMPLETE",
      runtimeEvidence: {
        digest: `sha256:${"6".repeat(64)}`,
        runtimeBinding: { profileId: "core" },
      },
      agentStackResult: {
        context: {
          digest: `sha256:${"7".repeat(64)}`,
          entityUrns: [
            "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)",
          ],
          receipts: [{ tool: "get_entities" }],
          unknownPreserved: false,
        },
        skills: {
          digest: `sha256:${"8".repeat(64)}`,
          workflow: ["datahub-search", "datahub-enrich"],
        },
        analytics: {
          digest: `sha256:${"9".repeat(64)}`,
          events: [{ event: "COMPLETE" }],
          contextQuality: { score: 5, label: "excellent" },
        },
      },
      remediation: {
        verified: true,
        mutationExecutor: "official-datahub-mcp",
        receiptDigest: `sha256:${"a".repeat(64)}`,
        policyDigest: `sha256:${"b".repeat(64)}`,
        afterDigest: `sha256:${"c".repeat(64)}`,
        authorizationEvidence: {
          keyReferenceDigest: `sha256:${"d".repeat(64)}`,
          envelopeDigest: `sha256:${"e".repeat(64)}`,
        },
        officialMcpMutation: {
          approvalDigest: `sha256:${"f".repeat(64)}`,
        },
      },
      contextDelta: {
        ackContextChanged: true,
        analyticsResultChanged: true,
      },
      skillCompletion: {
        sourceArtifactDigest: `sha256:${"1".repeat(64)}`,
        previewSkillReceiptDigest: `sha256:${"2".repeat(64)}`,
        skillGroundingDigest: `sha256:${"3".repeat(64)}`,
        officialMcpMutationReceiptDigest: `sha256:${"4".repeat(64)}`,
      },
    };
    runtimeMocks.loadRuntimeAgentStack.mockResolvedValueOnce(status);
    render(<App />);

    const run = await screen.findByRole("button", {
      name: "Run canonical Agent Stack",
    });
    await waitFor(() => expect(run).toBeEnabled());
    fireEvent.click(run);

    const proof = await screen.findByTestId("governed-proof");
    expect(within(proof).getByText("Official MCP · add_tags")).toBeInTheDocument();
    expect(within(proof).getByTestId("kms-authority-proof")).toHaveTextContent(
      "KMS-signed authority verified",
    );
    expect(within(proof).getByTestId("enrich-skill-completion")).toHaveTextContent(
      "executed-with-human-approval",
    );
    expect(screen.getByTestId("agent-runtime-profile")).toHaveTextContent(
      "DataHub Core · ephemeral",
    );
    expect(proof).not.toHaveTextContent("privateKey");
    expect(proof).not.toHaveTextContent("accessToken");
  });

  it("executes improve-context, approval, governed write-back, and rerun proof", async () => {
    authMocks.snapshot = {
      status: "authenticated",
      expiresAt: Date.now() + 60_000,
    };
    const baseResult = {
      context: {
        digest: `sha256:${"1".repeat(64)}`,
        entityUrns: [
          "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)",
        ],
        receipts: [
          { tool: "search" },
          { tool: "get_entities" },
          { tool: "get_lineage_downstream" },
          { tool: "list_schema_fields" },
        ],
        unknownPreserved: false,
      },
      skills: {
        digest: `sha256:${"2".repeat(64)}`,
        workflow: [
          "datahub-search",
          "datahub-lineage",
          "datahub-quality",
          "datahub-audit",
          "datahub-enrich",
        ],
      },
      analytics: {
        digest: `sha256:${"3".repeat(64)}`,
        events: [
          { event: "SQL" },
          { event: "RESULT" },
          { event: "CHART" },
          { event: "COMPLETE" },
        ],
        contextQuality: { score: 4, label: "good" },
      },
    };
    const runtimeEvidence = {
      digest: `sha256:${"4".repeat(64)}`,
      runtimeBinding: { profileId: "cloud" },
    };
    const awaitingImprovement = {
      schemaVersion: "archon.runtime-control-loop-status/v2",
      auditId: "c".repeat(64),
      status: "AWAITING_IMPROVEMENT",
      phase: "IMPROVING_CONTEXT",
      runtimeEvidence,
      agentStackResult: baseResult,
      improveContext: {
        schemaVersion: "archon.datahub-improve-context-capability/v2",
        status: "AVAILABLE",
      },
    };
    const awaitingApproval = {
      ...awaitingImprovement,
      status: "AWAITING_APPROVAL",
      phase: "AWAITING_APPROVAL",
      improveContext: {
        schemaVersion: "archon.datahub-improve-context-projection/v2",
        resultDigest: `sha256:${"5".repeat(64)}`,
        events: [
          { event: "TEXT", text: "Propose PII tag for customer_email." },
          { event: "COMPLETE", status: "proposal-only" },
        ],
      },
      plan: {
        expectedBefore: { tagUrns: [] },
        expectedBeforeDigest: `sha256:${"6".repeat(64)}`,
        expectedAfter: { tagUrns: ["urn:li:tag:PII"] },
        expectedAfterDigest: `sha256:${"7".repeat(64)}`,
        improveReceiptDigest: `sha256:${"8".repeat(64)}`,
      },
      approval: { status: "PENDING" },
    };
    const completed = {
      ...awaitingApproval,
      status: "SUCCEEDED",
      phase: "COMPLETE",
      approval: { status: "APPROVED" },
      remediation: {
        verified: true,
        mutationExecutor: "official-datahub-mcp",
        receiptDigest: `sha256:${"9".repeat(64)}`,
        policyDigest: `sha256:${"a".repeat(64)}`,
        afterDigest: `sha256:${"b".repeat(64)}`,
        authorizationEvidence: {
          keyReferenceDigest: `sha256:${"c".repeat(64)}`,
          envelopeDigest: `sha256:${"d".repeat(64)}`,
        },
        officialMcpMutation: {
          approvalDigest: `sha256:${"e".repeat(64)}`,
        },
      },
      contextDelta: {
        ackContextChanged: true,
        analyticsResultChanged: true,
      },
      skillCompletion: {
        sourceArtifactDigest: `sha256:${"f".repeat(64)}`,
        previewSkillReceiptDigest: `sha256:${"0".repeat(64)}`,
        skillGroundingDigest: `sha256:${"1".repeat(64)}`,
        officialMcpMutationReceiptDigest: `sha256:${"2".repeat(64)}`,
      },
    };
    const rerun = {
      ...completed,
      auditId: "d".repeat(64),
      remediation: undefined,
      contextDelta: undefined,
      skillCompletion: undefined,
      agentStackResult: {
        ...baseResult,
        context: {
          ...baseResult.context,
          digest: `sha256:${"3".repeat(64)}`,
          receipts: [
            ...baseResult.context.receipts,
            {
              tool: "get_entities",
              tagUrns: ["urn:li:tag:PII"],
            },
          ],
        },
      },
    };

    runtimeMocks.loadRuntimeAgentStack
      .mockResolvedValueOnce(awaitingImprovement)
      .mockResolvedValueOnce(rerun);
    runtimeMocks.requestRuntimeImproveContext.mockResolvedValueOnce(
      awaitingApproval,
    );
    runtimeMocks.submitRuntimeApproval.mockResolvedValueOnce(undefined);
    runtimeMocks.resumeRuntimeAgentStack.mockResolvedValueOnce(completed);
    render(<App />);

    const run = await screen.findByRole("button", {
      name: "Run canonical Agent Stack",
    });
    await waitFor(() => expect(run).toBeEnabled());
    fireEvent.click(run);

    const panel = await screen.findByTestId("agent-stack-panel");
    const improve = await within(panel).findByRole("button", {
      name: "Generate proposal",
    });
    await waitFor(() => expect(improve).toBeEnabled());
    fireEvent.click(improve);

    const approve = await within(panel).findByRole("button", {
      name: "Approve exact plan",
    });
    await waitFor(() => expect(approve).toBeEnabled());
    expect(within(panel).getAllByText("urn:li:tag:PII")).not.toHaveLength(0);
    fireEvent.click(approve);
    await waitFor(() =>
      expect(runtimeMocks.submitRuntimeApproval).toHaveBeenCalledTimes(1),
    );
    await waitFor(() =>
      expect(runtimeMocks.resumeRuntimeAgentStack).toHaveBeenCalledTimes(1),
    );

    expect(await within(panel).findByTestId("governed-proof")).toHaveTextContent(
      "Official DataHub MCP add_tags + post-write ACK and Analytics rerun verified.",
    );
    expect(runtimeMocks.submitRuntimeApproval).toHaveBeenCalledWith(
      "c".repeat(64),
      "APPROVE",
      "TEST_ONLY_TOKEN_000000000000",
      "Judge approved the exact content-addressed PII tag plan.",
      expect.any(AbortSignal),
    );

    const rerunButton = await screen.findByRole("button", {
      name: "Run canonical Agent Stack again",
    });
    await waitFor(() => expect(rerunButton).toBeEnabled());
    fireEvent.click(rerunButton);

    expect(
      await screen.findByText(
        "Run-again proof: a new ACK context read observed PII on the source column.",
      ),
    ).toBeInTheDocument();
    expect(runtimeMocks.loadRuntimeAgentStack).toHaveBeenCalledTimes(2);
  });
});

describe("public live audit", () => {
  const LIVE_RUN = "Run the live read-only audit";

  const bindLiveOrigin = () => {
    apiMocks.probeRuntimeReadiness.mockResolvedValue({
      releaseSha: "6d1f0ac",
      datahubMode: "live",
    });
  };

  it("stays hidden when the origin serves no audit API", async () => {
    render(<App />);

    expect(
      await screen.findByLabelText("Canonical DataHub dataset URN"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: LIVE_RUN })).not.toBeInTheDocument();
  });

  it("stays hidden when the origin is bound to a fixture runtime", async () => {
    apiMocks.probeRuntimeReadiness.mockResolvedValue({
      releaseSha: "6d1f0ac",
      datahubMode: "fixture",
    });

    render(<App />);

    expect(
      await screen.findByLabelText("Canonical DataHub dataset URN"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: LIVE_RUN })).not.toBeInTheDocument();
  });

  it("runs a real read-only audit with no sign-in and relabels the source", async () => {
    bindLiveOrigin();
    apiMocks.requestAudit.mockResolvedValue(previewAudit);

    render(<App />);

    const run = await screen.findByRole("button", { name: LIVE_RUN });
    expect(run).toBeEnabled();
    fireEvent.click(run);

    await waitFor(() => {
      expect(apiMocks.requestAudit).toHaveBeenCalledTimes(1);
    });
    await waitFor(() => {
      expect(screen.getAllByLabelText("Live DataHub").length).toBeGreaterThan(0);
    });
  });

  it("reports why a live audit failed and keeps the visible report labelled", async () => {
    bindLiveOrigin();
    apiMocks.requestAudit.mockRejectedValue(new Error("DataHub GMS is unreachable"));

    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: LIVE_RUN }));

    expect(
      await screen.findByText("DataHub GMS is unreachable"),
    ).toBeInTheDocument();
    expect(screen.getByText("Fixture preview")).toBeInTheDocument();
  });

  it("falls back to a plain message when the failure is not an Error", async () => {
    bindLiveOrigin();
    apiMocks.requestAudit.mockRejectedValue("socket hang up");

    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: LIVE_RUN }));

    expect(
      await screen.findByText("The live audit could not be completed."),
    ).toBeInTheDocument();
  });
});
