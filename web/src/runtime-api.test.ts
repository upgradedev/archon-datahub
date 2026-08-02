import { afterEach, describe, expect, it, vi } from "vitest";
import {
  extendRuntimeSession,
  getRuntimeAgentStackStatus,
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

function digest(character: string): string {
  return "sha256:" + character.repeat(64);
}

function successfulAgentStatus(
  profileId: "core" | "cloud" = "core",
): Record<string, unknown> {
  const auditId = "a".repeat(64);
  const runtimeBinding = {
    schemaVersion: "archon.runtime-binding/v1",
    profileId,
    generation: profileId + "-g1",
    capabilityDigest: digest("1"),
    resolution: "auto",
    boundAt: "2026-08-02T08:00:00.000Z",
    leaseExpiresAt: "2026-08-02T08:30:00.000Z",
  };
  const runtimeEvidence = {
    schemaVersion: "archon.runtime-binding-evidence/v2",
    auditId,
    runtimeSessionId: "rs_" + "B".repeat(43),
    runtimeBinding,
    capabilities: allCapabilities,
    bindingDigest: digest("2"),
    sessionRevision: 1,
    recordedAt: "2026-08-02T08:00:01.000Z",
    digest: digest("3"),
  };
  const beforeState = {
    entityUrn:
      "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)",
    columnPath: "customer_email",
    tagUrns: [],
    stateDigest: digest("4"),
  };
  const afterState = {
    ...beforeState,
    tagUrns: ["urn:li:tag:PII"],
    stateDigest: digest("5"),
  };
  const ackTools = [
    "search",
    "get_entities",
    "list_schema_fields",
    "get_lineage_upstream",
    "get_lineage_downstream",
    "get_dataset_assertions",
  ];
  const officialMcpTools = [
    "search",
    "get_entities",
    "list_schema_fields",
    "get_lineage",
    "get_dataset_queries",
  ];
  const executionPlan = {
    phase: "governed-enrichment-preview",
    requiredCalls: {
      ack: ackTools,
      officialMcp: officialMcpTools,
    },
    mode: "preview-only",
  };
  const enrichArtifact = {
    skill: "datahub-enrich",
    artifactDigest: digest("3"),
    gitBlob: "3".repeat(40),
    bytes: 4096,
    reviewedExecution: {
      executionPlan,
      executionPlanDigest: digest("4"),
    },
  };
  const skills = {
    schemaVersion: "archon.datahub-skills-receipt/v2",
    sourceCommit: "f7c7c53648b71dc0841742781e108051d46fa360",
    official: [
      { skill: "datahub-search" },
      { skill: "datahub-lineage" },
      { skill: "datahub-quality" },
      enrichArtifact,
      { skill: "using-datahub" },
    ],
    custom: [{ skill: "datahub-audit" }],
    workflow: [
      "datahub-search",
      "datahub-lineage",
      "datahub-quality",
      "datahub-audit",
      "datahub-enrich",
    ],
    reviewedSkillCount: 6,
    mutationAuthority: "archon-remediation-worker",
    digest: digest("8"),
  };
  const satisfiedAckCalls = ackTools.map((tool, index) => ({
    tool,
    receiptDigest: digest(String((index + 1) % 10)),
  }));
  const satisfiedOfficialMcpCalls = officialMcpTools.map((tool, index) => ({
    tool,
    receiptDigest: digest(String.fromCharCode("a".charCodeAt(0) + index)),
  }));
  const previewSkillReceipt = {
    schemaVersion: "archon.datahub-skill-execution-receipt/v2",
    skill: "datahub-enrich",
    sourceArtifactDigest: enrichArtifact.artifactDigest,
    executionPlan,
    executionPlanDigest: enrichArtifact.reviewedExecution.executionPlanDigest,
    status: "previewed",
    satisfiedAckCalls,
    satisfiedOfficialMcpCalls,
    ackReceiptDigests: satisfiedAckCalls.map((call) => call.receiptDigest),
    officialMcpReadReceiptDigests: satisfiedOfficialMcpCalls.map(
      (call) => call.receiptDigest,
    ),
    mode: "preview-only",
    requiredCallsSatisfied: true,
    mutationsEnabled: false,
    providerPayloadStored: false,
    digest: digest("5"),
  };
  const skillGrounding = {
    schemaVersion: "archon.datahub-skill-grounding/v2",
    skillsReceiptDigest: skills.digest,
    ackContextDigest: digest("7"),
    officialMcpReadReceiptsDigest: digest("6"),
    executionOrder: skills.workflow,
    allRequiredCallsSatisfied: true,
    receipts: [previewSkillReceipt],
    digest: digest("9"),
  };
  const agentStackResult = {
    schemaVersion: "archon.datahub-agent-stack-result-projection/v2",
    resultDigest: digest("6"),
    runtimeBinding,
    context: { digest: digest("7"), source: "DataHub Agent Context Kit" },
    skills,
    skillGrounding,
    analytics: {
      digest: digest("a"),
      answer: "Enterprise",
      skillGroundingDigest: skillGrounding.digest,
    },
    enrichment: {
      status: "preview-only",
      writeAuthority: "archon-remediation-worker",
      requiresFreshDigestBoundApproval: true,
    },
    digest: digest("b"),
  };
  const improveContext = {
    schemaVersion: "archon.datahub-improve-context-projection/v2",
    resultDigest: digest("c"),
    runtimeBinding,
    events: [],
    contextQuality: { score: 92 },
    preflightDigest: digest("d"),
    contextDigest: digest("e"),
    skillGroundingDigest: digest("f"),
    status: "proposal-only",
    writeAuthority: "archon-remediation-worker",
    requiresFreshDigestBoundApproval: true,
    digest: digest("0"),
  };
  const plan = {
    schemaVersion: "archon.runtime-remediation-plan/v2",
    auditId,
    runtimeEvidenceDigest: runtimeEvidence.digest,
    auditEvidenceDigest: digest("1"),
    policyDigest: digest("2"),
    agentStackResultDigest: agentStackResult.resultDigest,
    analysisReceiptDigest: digest("3"),
    readReceiptDigest: digest("4"),
    improveContextResultDigest: improveContext.resultDigest,
    improveReceiptDigest: digest("5"),
    action: "ADD_TAGS",
    arguments: {
      tagUrns: ["urn:li:tag:PII"],
      entityUrns: [afterState.entityUrn],
      columnPaths: ["customer_email"],
    },
    expectedBefore: beforeState,
    expectedBeforeDigest: beforeState.stateDigest,
    expectedAfter: afterState,
    expectedAfterDigest: afterState.stateDigest,
    requiresHumanApproval: true,
    createdAt: "2026-08-02T08:00:03.000Z",
    digest: digest("6"),
  };
  const approval = {
    approvalId: "approval-" + "b".repeat(24),
    status: "APPROVED",
    requestedAt: "2026-08-02T08:00:04.000Z",
    expiresAt: "2026-08-02T08:05:04.000Z",
    planDigest: plan.digest,
    requestDigest: digest("7"),
    decision: "APPROVE",
    decisionDigest: digest("8"),
    decidedAt: "2026-08-02T08:00:05.000Z",
  };
  const remediation = {
    schemaVersion: "archon.governed-remediation-projection/v2",
    jobId: "job_" + "C".repeat(22),
    receiptDigest: digest("9"),
    requestDigest: digest("a"),
    beforeDigest: beforeState.stateDigest,
    afterDigest: afterState.stateDigest,
    responseDigest: digest("b"),
    policyDigest: plan.policyDigest,
    mutationExecutor: "official-datahub-mcp",
    officialMcpMutation: {
      tool: "add_tags",
      policyDigest: plan.policyDigest,
      approvalDigest: approval.decisionDigest,
      requestDigest: digest("a"),
      responseDigest: digest("b"),
    },
    authorizationEvidence: {
      algorithm: "ECDSA_SHA_256",
      canonicalization: "archon.sorted-json-utf8/v1",
      keyReferenceDigest: digest("c"),
      envelopeDigest: digest("d"),
      signatureDigest: digest("e"),
      consumedAt: "2026-08-02T08:00:06.000Z",
    },
    verified: true,
  };
  return {
    schemaVersion: "archon.control-loop-status/v2",
    auditId,
    status: "SUCCEEDED",
    phase: "COMPLETE",
    submittedAt: "2026-08-02T08:00:00.000Z",
    updatedAt: "2026-08-02T08:00:08.000Z",
    completedAt: "2026-08-02T08:00:08.000Z",
    runtimeEvidence,
    agentStackResult,
    governedState: afterState,
    improveContext,
    plan,
    approval,
    remediation,
    skillCompletion: {
      schemaVersion: "archon.datahub-skill-completion/v1",
      skill: "datahub-enrich",
      status: "executed-with-human-approval",
      sourceArtifactDigest: previewSkillReceipt.sourceArtifactDigest,
      executionPlanDigest: previewSkillReceipt.executionPlanDigest,
      previewSkillReceiptDigest: previewSkillReceipt.digest,
      skillGroundingDigest: agentStackResult.skillGrounding.digest,
      approvalDigest: approval.decisionDigest,
      officialMcpMutationReceiptDigest: remediation.receiptDigest,
      completedAt: "2026-08-02T08:00:07.000Z",
      digest: digest("6"),
    },
    contextDelta: {
      schemaVersion: "archon.context-delta/v1",
      sourceMutationReceiptDigest: remediation.receiptDigest,
      beforeContextDigest: improveContext.contextDigest,
      afterContextDigest: agentStackResult.context.digest,
      beforeAnalyticsDigest: digest("f"),
      afterAnalyticsDigest: agentStackResult.analytics.digest,
      beforeTagStateDigest: beforeState.stateDigest,
      afterTagStateDigest: afterState.stateDigest,
      addedTagUrns: ["urn:li:tag:PII"],
      ackContextChanged: true,
      analyticsResultChanged: true,
      sourceReadVerified: true,
      postAnalysisReceiptDigest: digest("0"),
      postReadReceiptDigest: digest("1"),
      digest: digest("2"),
    },
  };
}

describe("v2 governed agent-stack projection", () => {
  it("accepts a KMS-authorized official MCP mutation and verified post-write delta", async () => {
    const value = successfulAgentStatus();
    const fetchMock = vi.fn().mockResolvedValue(json(value));
    vi.stubGlobal("fetch", fetchMock);

    const result = await getRuntimeAgentStackStatus(
      "a".repeat(64),
      ACCESS_TOKEN,
    );

    expect(result.remediation).toMatchObject({
      mutationExecutor: "official-datahub-mcp",
      verified: true,
      authorizationEvidence: {
        algorithm: "ECDSA_SHA_256",
        canonicalization: "archon.sorted-json-utf8/v1",
        keyReferenceDigest: digest("c"),
      },
    });
    expect(result.skillCompletion).toMatchObject({
      skill: "datahub-enrich",
      status: "executed-with-human-approval",
      approvalDigest: result.approval?.decisionDigest,
      officialMcpMutationReceiptDigest: result.remediation?.receiptDigest,
    });
    expect(result.contextDelta).toMatchObject({
      ackContextChanged: true,
      analyticsResultChanged: true,
      sourceReadVerified: true,
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/control-loops-v2/" + "a".repeat(64),
      expect.objectContaining({
        method: "GET",
        credentials: "same-origin",
        headers: expect.objectContaining({
          Authorization: "Bearer " + ACCESS_TOKEN,
        }),
      }),
    );
  });

  it("accepts the same closed-loop contract for an immutable Cloud binding", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      json(successfulAgentStatus("cloud")),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await getRuntimeAgentStackStatus(
      "a".repeat(64),
      ACCESS_TOKEN,
    );

    expect(result.runtimeEvidence.runtimeBinding.profileId).toBe("cloud");
    expect(result.agentStackResult?.runtimeBinding.profileId).toBe("cloud");
    expect(result.remediation?.verified).toBe(true);
    expect(result.contextDelta?.ackContextChanged).toBe(true);
  });

  it("fails closed if raw KMS material crosses the browser boundary", async () => {
    const withKeyArn = successfulAgentStatus();
    const keyEvidence = (
      withKeyArn.remediation as { authorizationEvidence: Record<string, unknown> }
    ).authorizationEvidence;
    keyEvidence.keyArn =
      "arn:aws:kms:eu-west-1:111111111111:key/00000000-0000-0000-0000-000000000000";
    const withSignature = successfulAgentStatus();
    const signatureEvidence = (
      withSignature.remediation as { authorizationEvidence: Record<string, unknown> }
    ).authorizationEvidence;
    signatureEvidence.signatureBase64 = "MEQCIFIXTURE";
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(withKeyArn))
      .mockResolvedValueOnce(json(withSignature));
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      getRuntimeAgentStackStatus("a".repeat(64), ACCESS_TOKEN),
    ).rejects.toMatchObject({ status: 502 });
    await expect(
      getRuntimeAgentStackStatus("a".repeat(64), ACCESS_TOKEN),
    ).rejects.toMatchObject({ status: 502 });
  });

  it("rejects an unbound or unverified context delta", async () => {
    const wrongReceipt = successfulAgentStatus();
    (wrongReceipt.contextDelta as Record<string, unknown>).sourceMutationReceiptDigest =
      digest("f");
    const unverified = successfulAgentStatus();
    (unverified.contextDelta as Record<string, unknown>).sourceReadVerified = false;
    const unboundSkill = successfulAgentStatus();
    (unboundSkill.skillCompletion as Record<string, unknown>).approvalDigest =
      digest("f");
    const unboundPreviewReceipt = successfulAgentStatus();
    (
      unboundPreviewReceipt.skillCompletion as Record<string, unknown>
    ).previewSkillReceiptDigest = digest("f");
    const unboundArtifact = successfulAgentStatus();
    (
      unboundArtifact.skillCompletion as Record<string, unknown>
    ).sourceArtifactDigest = digest("f");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(wrongReceipt))
      .mockResolvedValueOnce(json(unverified))
      .mockResolvedValueOnce(json(unboundSkill))
      .mockResolvedValueOnce(json(unboundPreviewReceipt))
      .mockResolvedValueOnce(json(unboundArtifact));
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      getRuntimeAgentStackStatus("a".repeat(64), ACCESS_TOKEN),
    ).rejects.toMatchObject({ status: 502 });
    await expect(
      getRuntimeAgentStackStatus("a".repeat(64), ACCESS_TOKEN),
    ).rejects.toMatchObject({ status: 502 });
    await expect(
      getRuntimeAgentStackStatus("a".repeat(64), ACCESS_TOKEN),
    ).rejects.toMatchObject({ status: 502 });
    await expect(
      getRuntimeAgentStackStatus("a".repeat(64), ACCESS_TOKEN),
    ).rejects.toMatchObject({ status: 502 });
    await expect(
      getRuntimeAgentStackStatus("a".repeat(64), ACCESS_TOKEN),
    ).rejects.toMatchObject({ status: 502 });
  });
});