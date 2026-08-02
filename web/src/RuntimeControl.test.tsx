import {
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RuntimeControl } from "./RuntimeControl";

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

function session(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: "archon.runtime-session-status/v1",
    sessionId: "rs_" + "C".repeat(43),
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

describe("judge runtime control", () => {
  it("shows the visible Auto, Cloud, and Core switch without hidden network work", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    render(<RuntimeControl />);

    const selector = screen.getByLabelText("DataHub runtime preference");
    expect(selector).toHaveValue("auto");
    expect(screen.getByRole("option", { name: "Auto · best available" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "DataHub Cloud" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "DataHub Core sandbox" })).toBeInTheDocument();
    expect(screen.getByText(/Explicit Cloud never falls back/i)).toBeInTheDocument();
    expect(screen.getByText(/DynamoDB is the lease authority/i)).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("renders all five capability receipts for each registry profile", async () => {
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
            availability: "LAUNCHABLE",
            generation: "ami-2026-08-02.1",
            checkedAt: "2026-08-02T08:00:00.000Z",
            capabilities: allCapabilities,
            capabilityDigest: "sha256:" + "1".repeat(64),
          },
        ],
        autoSelection: "core",
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    render(<RuntimeControl />);
    fireEvent.click(screen.getByRole("button", { name: "Check readiness" }));

    expect(await screen.findByText("LAUNCHABLE")).toBeInTheDocument();
    expect(screen.getByText("UNAVAILABLE")).toBeInTheDocument();
    expect(screen.getAllByText("MCP")).toHaveLength(2);
    expect(screen.getAllByText("Context Kit")).toHaveLength(2);
    expect(screen.getAllByText("Skills")).toHaveLength(2);
    expect(screen.getAllByText("Analytics")).toHaveLength(2);
  });

  it("submits the visible preference and publishes only the server-bound session", async () => {
    const onSessionChange = vi.fn();
    const fetchMock = vi.fn().mockResolvedValue(json(session()));
    vi.stubGlobal("fetch", fetchMock);

    render(<RuntimeControl onSessionChange={onSessionChange} />);
    fireEvent.change(screen.getByLabelText("DataHub runtime preference"), {
      target: { value: "auto" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Launch pinned session" }),
    );

    expect(await screen.findByText("STARTING")).toBeInTheDocument();
    expect(screen.getByText("Ephemeral DataHub Core")).toBeInTheDocument();
    expect(screen.getByText("resolved automatically")).toBeInTheDocument();
    expect(screen.getByText("30:00")).toBeInTheDocument();
    expect(onSessionChange).toHaveBeenCalledWith(
      expect.objectContaining({
        resolvedProfile: "core",
        state: "STARTING",
      }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/runtime-sessions",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ requestedProfile: "auto" }),
      }),
    );
  });

  it("does not silently fall back after an explicit Cloud refusal", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      json({ error: "runtime_not_ready" }, 409),
    );
    vi.stubGlobal("fetch", fetchMock);

    render(<RuntimeControl />);
    fireEvent.change(screen.getByLabelText("DataHub runtime preference"), {
      target: { value: "cloud" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Launch pinned session" }),
    );

    expect(
      await screen.findByRole("alert"),
    ).toHaveTextContent(/not fully ready with all five capabilities/i);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("Ephemeral DataHub Core")).not.toBeInTheDocument();
  });

  it("anchors the visible countdown to the server remainingSeconds value", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-02T08:00:00.000Z"));
    const fetchMock = vi.fn().mockResolvedValue(
      json(
        session({
          state: "READY",
          canRun: true,
          canExtend: true,
          remainingSeconds: 65,
        }),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    render(<RuntimeControl />);
    fireEvent.click(
      screen.getByRole("button", { name: "Launch pinned session" }),
    );
    await waitFor(() => expect(screen.getByText("01:05")).toBeInTheDocument());

    vi.advanceTimersByTime(5000);

    expect(screen.getByText("01:00")).toBeInTheDocument();
  });

  it("sends awaited explicit activity and teardown requests", async () => {
    const sessionId = "rs_" + "D".repeat(43);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        json(
          session({
            sessionId,
            state: "READY",
            canRun: true,
            canExtend: true,
          }),
        ),
      )
      .mockResolvedValueOnce(
        json(
          session({
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
          session({
            sessionId,
            state: "STOPPING",
            updatedAt: "2026-08-02T08:02:00.000Z",
            remainingSeconds: 0,
          }),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    render(<RuntimeControl />);
    fireEvent.click(
      screen.getByRole("button", { name: "Launch pinned session" }),
    );
    await screen.findByText("READY");

    fireEvent.click(screen.getByRole("button", { name: "Extend 30 min" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenNthCalledWith(
        2,
        "/api/runtime-sessions/" + sessionId + "/activity",
        expect.objectContaining({ method: "POST" }),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "Stop & teardown" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenNthCalledWith(
        3,
        "/api/runtime-sessions/" + sessionId + "/stop",
        expect.objectContaining({ method: "POST" }),
      ),
    );
    expect(await screen.findByText("STOPPING")).toBeInTheDocument();
  });
});