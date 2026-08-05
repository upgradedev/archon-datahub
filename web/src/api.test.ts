import { afterEach, describe, expect, it, vi } from "vitest";
import {
  getControlLoopStatus,
  loadAudit,
  probeRuntimeReadiness,
  requestAudit,
  startControlLoop,
  submitApprovalDecision,
} from "./api";
import { previewAudit } from "./fixtures";
import modelProvenanceCorpus from "../../contracts/model-provenance-v1.cases.json";

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

function materializeCredentialMacros(value: unknown): unknown {
  let encoded = JSON.stringify(value);
  for (const [name, fragments] of Object.entries(
    modelProvenanceCorpus.credentialMacros,
  )) {
    encoded = encoded.replaceAll(
      `{{credential:${name}}}`,
      fragments.join(""),
    );
  }
  return JSON.parse(encoded) as unknown;
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
  it("keeps the API provenance validator conformant with the shared runtime corpus", async () => {
    expect(modelProvenanceCorpus.schemaVersion).toBe(
      "archon.model-provenance-conformance/v1",
    );
    for (const candidate of modelProvenanceCorpus.cases) {
      const provenance = materializeCredentialMacros(candidate.value);
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          json({
            ...previewAudit,
            report: {
              ...previewAudit.report,
              modelProvenance: provenance,
            },
          }),
        ),
      );

      if (candidate.valid) {
        await expect(requestAudit("domain:Commerce")).resolves.toMatchObject({
          report: { modelProvenance: provenance },
        });
      } else {
        await expect(requestAudit("domain:Commerce")).rejects.toMatchObject({
          status: 502,
        });
      }
    }
  });

  it("posts a bounded catalog scope and validates the envelope", async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(previewAudit));
    vi.stubGlobal("fetch", fetchMock);

    const result = await requestAudit("  domain:Commerce  ");

    expect(result.report.scanId).toBe(previewAudit.report.scanId);
    expect(result.report.schemaVersion).toBe("archon.audit-report/v1");
    expect(result.report.modelProvenance).toEqual({
      schemaVersion: "archon.model-runtime-provenance/v1",
      source: "deterministic-fixture",
      modelCall: false,
      provider: "fixture",
      requestedModel: "archon-deterministic-fixture-narrator-v1",
      returnedModel: null,
      providerResponseId: null,
      tokenUsage: null,
      latencyMs: null,
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/audits",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        body: JSON.stringify({ query: "domain:Commerce" }),
      }),
    );
  });

  it("rejects credential-shaped substrings embedded in model identifiers", async () => {
    const base = structuredClone(previewAudit);
    base.report.modelProvenance = {
      schemaVersion: "archon.model-runtime-provenance/v1",
      source: "live-provider",
      modelCall: true,
      provider: "custom",
      requestedModel: "custom-model",
      returnedModel: `model_sk-${"x".repeat(32)}`,
      providerResponseId: "response-safe-001",
      tokenUsage: null,
      latencyMs: 12,
    };
    const fetcher = vi.fn(async () => json(base));
    vi.stubGlobal("fetch", fetcher);

    await expect(requestAudit("sales")).rejects.toMatchObject({ status: 502 });

    base.report.modelProvenance.returnedModel = "custom-model";
    base.report.modelProvenance.providerResponseId =
      `resp_sk-${"x".repeat(32)}`;
    await expect(requestAudit("sales")).rejects.toMatchObject({ status: 502 });
  });

  it("accepts only bounded live model runtime provenance", async () => {
    const liveEnvelope = {
      ...previewAudit,
      report: {
        ...previewAudit.report,
        modelProvenance: {
          schemaVersion: "archon.model-runtime-provenance/v1",
          source: "live-provider",
          modelCall: true,
          provider: "openai",
          requestedModel: "gpt-5.6",
          returnedModel: "gpt-5.6-2026-07-01",
          providerResponseId: "resp_archon_123456",
          tokenUsage: {
            inputTokens: 200,
            outputTokens: 50,
            totalTokens: 250,
          },
          latencyMs: 731,
        },
      },
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(liveEnvelope)));

    const result = await requestAudit("customer_pii");

    expect(result.report.modelProvenance).toEqual(
      liveEnvelope.report.modelProvenance,
    );
  });

  it("rejects private, extra, or internally inconsistent model provenance", async () => {
    const fixtureProvenance = previewAudit.report.modelProvenance;
    const liveProvenance = {
      schemaVersion: "archon.model-runtime-provenance/v1",
      source: "live-provider",
      modelCall: true,
      provider: "qwen",
      requestedModel: "qwen-plus",
      returnedModel: "qwen-plus-2026-07",
      providerResponseId: "chatcmpl_archon_123",
      tokenUsage: {
        inputTokens: 100,
        outputTokens: 20,
        totalTokens: 120,
      },
      latencyMs: 640,
    };
    const invalidReports = [
      {
        ...previewAudit.report,
        modelProvenance: {
          ...fixtureProvenance,
          prompt: "private prompt body",
        },
      },
      {
        ...previewAudit.report,
        modelProvenance: {
          ...fixtureProvenance,
          endpoint: "https://provider.example.test/v1",
        },
      },
      {
        ...previewAudit.report,
        modelProvenance: {
          ...fixtureProvenance,
          error: "private provider error",
        },
      },
      {
        ...previewAudit.report,
        modelProvenance: {
          ...fixtureProvenance,
          rawResponse: { private: true },
        },
      },
      {
        ...previewAudit.report,
        modelProvenance: {
          ...fixtureProvenance,
          modelCall: true,
        },
      },
      {
        ...previewAudit.report,
        modelProvenance: {
          ...liveProvenance,
          tokenUsage: {
            inputTokens: 100,
            outputTokens: 20,
            totalTokens: 121,
          },
        },
      },
      {
        ...previewAudit.report,
        modelProvenance: {
          ...liveProvenance,
          latencyMs: 3_600_001,
        },
      },
      {
        ...previewAudit.report,
        modelProvenance: {
          ...liveProvenance,
          requestedModel: "https://provider.example.test/model",
        },
      },
      {
        ...previewAudit.report,
        debug: "not part of archon.audit-report/v1",
      },
    ];
    const fetchMock = vi.fn();
    for (const report of invalidReports) {
      fetchMock.mockResolvedValueOnce(json({ ...previewAudit, report }));
    }
    vi.stubGlobal("fetch", fetchMock);

    for (const _report of invalidReports) {
      await expect(requestAudit("customer_pii")).rejects.toMatchObject({
        status: 502,
      });
    }
  });

  it("rejects non-allowlisted detail, private provenance, and credential-shaped output", async () => {
    const rawDetail = structuredClone(previewAudit);
    (
      rawDetail.report.findings[0]!.detail as unknown as Record<
        string,
        unknown
      >
    )["rawResponse"] = { providerDebug: "private" };

    const actorBearing = structuredClone(previewAudit);
    (
      actorBearing.report.findings[0]!.detail.provenance![
        0
      ]! as unknown as Record<string, unknown>
    )["actor"] = "urn:li:corpuser:private-ingestion";

    const shortSecret = structuredClone(previewAudit);
    shortSecret.report.narrative = `Provider diagnostic sk-${"x".repeat(12)}`;

    const shortJwt = structuredClone(previewAudit);
    shortJwt.report.findings[0]!.summary =
      `Provider diagnostic eyJ${"a".repeat(8)}.${"b".repeat(8)}.${"c".repeat(8)}`;

    const invalidEnvelopes: unknown[] = [
      rawDetail,
      actorBearing,
      shortSecret,
      shortJwt,
      { ...previewAudit, unexpectedEnvelopeField: true },
    ];
    const fetchMock = vi.fn();
    for (const envelope of invalidEnvelopes) {
      fetchMock.mockResolvedValueOnce(json(envelope));
    }
    vi.stubGlobal("fetch", fetchMock);

    for (const _envelope of invalidEnvelopes) {
      await expect(requestAudit("customer_pii")).rejects.toMatchObject({
        status: 502,
      });
    }
  });

  it("falls back deterministically only when the hosted API is unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("network unavailable")));

    const result = await loadAudit("customer_pii");

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

  it("surfaces a friendly rerun instruction for retired audit evidence", async () => {
    const auditId = "9".repeat(64);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        json(
          {
            error: "audit_schema_retired",
            rerunRequired: true,
          },
          410,
        ),
      ),
    );

    await expect(
      getControlLoopStatus({
        auditId,
        pollUrl: `/api/control-loops/${auditId}`,
      }),
    ).rejects.toMatchObject({
      status: 410,
      message: expect.stringMatching(/rerun.*current provenance-bound report/iu),
    });
  });

  it("never surfaces an untrusted control-plane error body", async () => {
    const sentinel = `sk-${"browser-provider-secret".repeat(2)}`;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        json(
          {
            message: `Provider rejected ${sentinel} at https://gateway.example/v1`,
          },
          502,
        ),
      ),
    );

    await expect(requestAudit("customer_pii")).rejects.toMatchObject({
      status: 502,
      message: "Control-plane request failed (502).",
    });
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

    const resultPromise = loadAudit("customer_pii", undefined, progress);
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

  it("rejects empty and wildcard scopes before the network boundary", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    for (const query of ["", "   ", "*", " * ", "?", "**", "{}"]) {
      await expect(startControlLoop(query)).rejects.toMatchObject({ status: 400 });
      await expect(requestAudit(query)).rejects.toMatchObject({ status: 400 });
    }
    expect(fetchMock).not.toHaveBeenCalled();
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

describe("probeRuntimeReadiness", () => {
  it("reports the live binding advertised by the hosted API", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        json({ status: "ready", releaseSha: "6d1f0ac", datahubMode: "live" }),
      ),
    );
    await expect(probeRuntimeReadiness()).resolves.toEqual({
      releaseSha: "6d1f0ac",
      datahubMode: "live",
    });
  });

  it("reports fixture mode when the API has no DataHub credentials", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        json({ status: "ready", releaseSha: "6d1f0ac", datahubMode: "fixture" }),
      ),
    );
    await expect(probeRuntimeReadiness()).resolves.toEqual({
      releaseSha: "6d1f0ac",
      datahubMode: "fixture",
    });
  });

  it("treats the static SPA shell as no audit API", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          ({
            status: 200,
            ok: true,
            headers: { get: () => "text/html" },
            json: async () => {
              throw new SyntaxError("Unexpected token <");
            },
          }) as unknown as Response,
      ),
    );
    await expect(probeRuntimeReadiness()).resolves.toBeUndefined();
  });

  it("rejects a readiness body that is missing its release binding", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ datahubMode: "live" })));
    await expect(probeRuntimeReadiness()).resolves.toBeUndefined();
  });

  it("stays silent when the probe cannot reach the origin", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    await expect(probeRuntimeReadiness()).resolves.toBeUndefined();
  });
});
