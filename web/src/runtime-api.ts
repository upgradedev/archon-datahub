export type RuntimeRequest = "auto" | "cloud" | "core";
export type RuntimeProfileId = "cloud" | "core";
export type RuntimeProfileAvailability =
  | "READY"
  | "LAUNCHABLE"
  | "STARTING"
  | "BUSY"
  | "UNAVAILABLE";

export interface RuntimeCapabilities {
  mcpRead: boolean;
  mcpGovernedWrite: boolean;
  agentContextKit: boolean;
  dataHubSkills: boolean;
  analyticsAgent: boolean;
}

export interface RuntimeProfileProjection {
  profileId: RuntimeProfileId;
  availability: RuntimeProfileAvailability;
  generation: string | null;
  checkedAt: string | null;
  capabilities: RuntimeCapabilities;
  capabilityDigest: string | null;
}

export interface RuntimeProfilesResponse {
  schemaVersion: "archon.runtime-profiles/v1";
  serverTime: string;
  profiles: [RuntimeProfileProjection, RuntimeProfileProjection];
  autoSelection: RuntimeProfileId | null;
}

export type RuntimeSessionState =
  | "STARTING"
  | "READY"
  | "STOPPING"
  | "STOPPED"
  | "EXPIRED"
  | "UNAVAILABLE";

export interface RuntimeSessionStatus {
  schemaVersion: "archon.runtime-session-status/v1";
  sessionId: string;
  requestedProfile: RuntimeRequest;
  resolvedProfile: RuntimeProfileId;
  state: RuntimeSessionState;
  createdAt: string;
  updatedAt: string;
  idleExpiresAt: string;
  hardExpiresAt: string;
  remainingSeconds: number;
  canRun: boolean;
  canExtend: boolean;
}

const RUNTIME_PROFILES_PATH = "/api/runtime-profiles";
const RUNTIME_SESSIONS_PATH = "/api/runtime-sessions";
const SESSION_ID = /^rs_[A-Za-z0-9_-]{43}$/u;
const GENERATION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const RFC3339 =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;
const REQUESTS = ["auto", "cloud", "core"] as const;
const PROFILE_IDS = ["cloud", "core"] as const;
const AVAILABILITY = [
  "READY",
  "LAUNCHABLE",
  "STARTING",
  "BUSY",
  "UNAVAILABLE",
] as const;
const SESSION_STATES = [
  "STARTING",
  "READY",
  "STOPPING",
  "STOPPED",
  "EXPIRED",
  "UNAVAILABLE",
] as const;
const CAPABILITY_KEYS = [
  "mcpRead",
  "mcpGovernedWrite",
  "agentContextKit",
  "dataHubSkills",
  "analyticsAgent",
] as const;
const FORBIDDEN_KEYS = new Set([
  "accesstoken",
  "apikey",
  "authorization",
  "clientsecret",
  "cookie",
  "credential",
  "idtoken",
  "jwt",
  "password",
  "privatekey",
  "refreshtoken",
  "runhandle",
  "secret",
  "sessiontoken",
  "token",
]);
const PRIVATE_RUN_HANDLE = /^run_[A-Za-z0-9_-]{80,2048}$/u;
const CREDENTIAL_PATTERNS = [
  /(?:AKIA|ASIA)[A-Z0-9]{16}/u,
  /gh[pousr]_[A-Za-z0-9_]{20,}/u,
  /github_pat_[A-Za-z0-9_]{20,}/u,
  /(?:Bearer\s+|sk-(?:ant-)?)[A-Za-z0-9._~+/=-]{12,}/iu,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
] as const;

export class RuntimeApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "RuntimeApiError";
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expected.length &&
    keys.every(
      (key) => typeof key === "string" && expected.includes(key),
    ) &&
    expected.every((key) =>
      Object.prototype.hasOwnProperty.call(value, key),
    )
  );
}

function safePublicValue(value: unknown): boolean {
  if (typeof value === "string") {
    return !PRIVATE_RUN_HANDLE.test(value) && !CREDENTIAL_PATTERNS.some((pattern) => pattern.test(value));
  }
  if (Array.isArray(value)) return value.every(safePublicValue);
  if (!record(value)) return true;
  return Object.entries(value).every(([key, entry]) => {
    const normalized = key.replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
    return (
      !FORBIDDEN_KEYS.has(normalized) &&
      !CREDENTIAL_PATTERNS.some((pattern) => pattern.test(key)) &&
      safePublicValue(entry)
    );
  });
}

function instant(value: unknown): value is string {
  if (typeof value !== "string" || !RFC3339.test(value)) return false;
  const parsed = Date.parse(value);
  return (
    Number.isFinite(parsed) &&
    new Date(parsed).toISOString() === value
  );
}

function capabilities(value: unknown): value is RuntimeCapabilities {
  return (
    record(value) &&
    exactKeys(value, CAPABILITY_KEYS) &&
    CAPABILITY_KEYS.every((key) => typeof value[key] === "boolean")
  );
}

function profile(
  value: unknown,
  expectedProfileId: RuntimeProfileId,
): value is RuntimeProfileProjection {
  if (!record(value)) return false;
  const projectedCapabilities = value.capabilities;
  if (
    !exactKeys(value, [
      "profileId",
      "availability",
      "generation",
      "checkedAt",
      "capabilities",
      "capabilityDigest",
    ]) ||
    value.profileId !== expectedProfileId ||
    !AVAILABILITY.includes(
      value.availability as RuntimeProfileAvailability,
    ) ||
    !capabilities(projectedCapabilities)
  ) {
    return false;
  }
  if (value.availability === "UNAVAILABLE") {
    return (
      value.generation === null &&
      value.checkedAt === null &&
      value.capabilityDigest === null &&
      CAPABILITY_KEYS.every(
        (key) => projectedCapabilities[key] === false,
      )
    );
  }
  return (
    typeof value.generation === "string" &&
    GENERATION.test(value.generation) &&
    instant(value.checkedAt) &&
    typeof value.capabilityDigest === "string" &&
    DIGEST.test(value.capabilityDigest) &&
    CAPABILITY_KEYS.every(
      (key) => projectedCapabilities[key] === true,
    )
  );
}
function parseProfiles(value: unknown): RuntimeProfilesResponse {
  if (
    !record(value) ||
    !exactKeys(value, [
      "schemaVersion",
      "serverTime",
      "profiles",
      "autoSelection",
    ]) ||
    value.schemaVersion !== "archon.runtime-profiles/v1" ||
    !instant(value.serverTime) ||
    !Array.isArray(value.profiles) ||
    value.profiles.length !== 2 ||
    !profile(value.profiles[0], "cloud") ||
    !profile(value.profiles[1], "core") ||
    !(
      value.autoSelection === null ||
      PROFILE_IDS.includes(value.autoSelection as RuntimeProfileId)
    ) ||
    (value.autoSelection === "cloud" &&
      value.profiles[0].availability !== "READY") ||
    (value.autoSelection === "core" &&
      value.profiles[0].availability === "READY") ||
    (value.autoSelection === "core" &&
      value.profiles[1].availability !== "LAUNCHABLE") ||
    !safePublicValue(value)
  ) {
    throw new RuntimeApiError(
      "The runtime registry returned an invalid public contract.",
      502,
    );
  }
  return value as unknown as RuntimeProfilesResponse;
}

function parseSession(value: unknown): RuntimeSessionStatus {
  if (
    !record(value) ||
    !exactKeys(value, [
      "schemaVersion",
      "sessionId",
      "requestedProfile",
      "resolvedProfile",
      "state",
      "createdAt",
      "updatedAt",
      "idleExpiresAt",
      "hardExpiresAt",
      "remainingSeconds",
      "canRun",
      "canExtend",
    ]) ||
    value.schemaVersion !== "archon.runtime-session-status/v1" ||
    typeof value.sessionId !== "string" ||
    !SESSION_ID.test(value.sessionId) ||
    !REQUESTS.includes(value.requestedProfile as RuntimeRequest) ||
    !PROFILE_IDS.includes(value.resolvedProfile as RuntimeProfileId) ||
    !SESSION_STATES.includes(value.state as RuntimeSessionState) ||
    !instant(value.createdAt) ||
    !instant(value.updatedAt) ||
    !instant(value.idleExpiresAt) ||
    !instant(value.hardExpiresAt) ||
    Date.parse(value.updatedAt) < Date.parse(value.createdAt) ||
    Date.parse(value.idleExpiresAt) <= Date.parse(value.createdAt) ||
    Date.parse(value.hardExpiresAt) < Date.parse(value.idleExpiresAt) ||
    Date.parse(value.hardExpiresAt) - Date.parse(value.createdAt) >
      2 * 60 * 60_000 ||
    !Number.isSafeInteger(value.remainingSeconds) ||
    (value.remainingSeconds as number) < 0 ||
    (value.remainingSeconds as number) > 2 * 60 * 60 ||
    typeof value.canRun !== "boolean" ||
    typeof value.canExtend !== "boolean" ||
    (value.state === "READY" ? value.canRun !== true : value.canRun !== false) ||
    (value.canExtend === true && value.state !== "READY") ||
    (value.requestedProfile === "cloud" &&
      value.resolvedProfile !== "cloud") ||
    (value.requestedProfile === "core" &&
      value.resolvedProfile !== "core") ||
    !safePublicValue(value)
  ) {
    throw new RuntimeApiError(
      "The runtime control plane returned an invalid session contract.",
      502,
    );
  }
  return value as unknown as RuntimeSessionStatus;
}

async function jsonResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new RuntimeApiError(
      "The runtime control plane returned a non-JSON response.",
      502,
    );
  }
  let value: unknown;
  try {
    value = await response.json();
  } catch {
    throw new RuntimeApiError(
      "The runtime control plane returned malformed JSON.",
      502,
    );
  }
  if (!response.ok) {
    const known =
      record(value) && typeof value.error === "string"
        ? value.error
        : "runtime_request_failed";
    const messages: Record<string, string> = {
      runtime_not_ready:
        "That DataHub runtime is not fully ready with all five capabilities.",
      runtime_runner_unavailable:
        "The pinned DataHub runtime worker is unavailable for this generation.",
      runtime_busy:
        "The ephemeral DataHub Core sandbox is currently leased.",
      runtime_session_not_active:
        "This runtime session is no longer active.",
      runtime_identity_mismatch:
        "The runtime identity changed; start a new pinned session.",
      runtime_provisioning_failed:
        "The DataHub Core sandbox could not be provisioned.",
      runtime_stop_failed:
        "The runtime teardown request could not be confirmed.",
      runtime_session_conflict:
        "The runtime session changed concurrently. Refresh and retry.",
    };
    throw new RuntimeApiError(
      messages[known] ??
        "Runtime control request failed (" + response.status + ").",
      response.status,
    );
  }
  return value;
}

async function request(
  path: string,
  init: RequestInit,
): Promise<unknown> {
  return jsonResponse(
    await fetch(path, {
      credentials: "same-origin",
      ...init,
      headers: {
        Accept: "application/json",
        ...(init.body === undefined
          ? {}
          : { "Content-Type": "application/json" }),
        ...init.headers,
      },
    }),
  );
}

function authorizationHeaders(accessToken: string): {
  Authorization: string;
} {
  if (
    accessToken.length < 20 ||
    accessToken.length > 16_384 ||
    /[\u0000-\u0020\u007F]/u.test(accessToken)
  ) {
    throw new RuntimeApiError(
      "An authenticated judge or steward session is required.",
      401,
    );
  }
  return { Authorization: "Bearer " + accessToken };
}

function sessionPath(sessionId: string): string {
  if (!SESSION_ID.test(sessionId)) {
    throw new RuntimeApiError("The runtime session capability is invalid.", 400);
  }
  return RUNTIME_SESSIONS_PATH + "/" + encodeURIComponent(sessionId);
}

export async function getRuntimeProfiles(
  signal?: AbortSignal,
): Promise<RuntimeProfilesResponse> {
  return parseProfiles(
    await request(RUNTIME_PROFILES_PATH, { method: "GET", signal }),
  );
}

export async function startRuntimeSession(
  requestedProfile: RuntimeRequest,
  accessToken: string,
  signal?: AbortSignal,
): Promise<RuntimeSessionStatus> {
  if (!REQUESTS.includes(requestedProfile)) {
    throw new RuntimeApiError("The runtime request is invalid.", 400);
  }
  return parseSession(
    await request(RUNTIME_SESSIONS_PATH, {
      method: "POST",
      body: JSON.stringify({ requestedProfile }),
      headers: authorizationHeaders(accessToken),
      signal,
    }),
  );
}

export async function getRuntimeSession(
  sessionId: string,
  signal?: AbortSignal,
): Promise<RuntimeSessionStatus> {
  return parseSession(
    await request(sessionPath(sessionId), { method: "GET", signal }),
  );
}

export async function extendRuntimeSession(
  sessionId: string,
  accessToken: string,
  signal?: AbortSignal,
): Promise<RuntimeSessionStatus> {
  return parseSession(
    await request(sessionPath(sessionId) + "/activity", {
      method: "POST",
      body: "{}",
      headers: authorizationHeaders(accessToken),
      signal,
    }),
  );
}

export async function stopRuntimeSession(
  sessionId: string,
  accessToken: string,
  signal?: AbortSignal,
): Promise<RuntimeSessionStatus> {
  return parseSession(
    await request(sessionPath(sessionId) + "/stop", {
      method: "POST",
      body: "{}",
      headers: authorizationHeaders(accessToken),
      signal,
    }),
  );
}

export const AGENT_STACK_DATASET_URN =
  "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)";
export const AGENT_STACK_QUESTION =
  "Which customer segment generated the highest net revenue in Q2 2026, and is customers.customer_email governed as PII?";
export const GOVERNED_COLUMN_PATH = "customer_email";

export interface RuntimeBinding {
  schemaVersion: "archon.runtime-binding/v1";
  profileId: RuntimeProfileId;
  generation: string;
  capabilityDigest: string;
  resolution: "auto" | "explicit";
  boundAt: string;
  leaseExpiresAt: string;
}

export interface RuntimeBindingEvidence {
  schemaVersion: "archon.runtime-binding-evidence/v2";
  auditId: string;
  runtimeSessionId: string;
  runtimeBinding: RuntimeBinding;
  capabilities: RuntimeCapabilities;
  bindingDigest: string;
  sessionRevision: number;
  recordedAt: string;
  digest: string;
}

export type RuntimeAgentPhase =
  | "ANALYZING"
  | "READING_GOVERNED_STATE"
  | "IMPROVING_CONTEXT"
  | "HUMAN_APPROVAL"
  | "APPLYING_GOVERNED_WRITE"
  | "VERIFYING_CONTEXT_DELTA"
  | "COMPLETE";
export type RuntimeAgentStatus =
  | "RUNNING"
  | "AWAITING_IMPROVEMENT"
  | "AWAITING_APPROVAL"
  | "SUCCEEDED"
  | "REJECTED"
  | "FAILED";
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export interface RuntimeAgentStackResult {
  schemaVersion: "archon.datahub-agent-stack-result-projection/v2";
  resultDigest: string;
  runtimeBinding: RuntimeBinding;
  context: JsonObject;
  skills: JsonObject;
  skillGrounding: JsonObject;
  analytics: JsonObject;
  enrichment: {
    status: "preview-only";
    writeAuthority: "archon-remediation-worker";
    requiresFreshDigestBoundApproval: true;
  };
  digest: string;
}

export interface RuntimeTagState {
  entityUrn: string;
  columnPath: string;
  tagUrns: string[];
  stateDigest: string;
}

export interface RuntimeRemediationPlan {
  schemaVersion: "archon.runtime-remediation-plan/v2";
  auditId: string;
  runtimeEvidenceDigest: string;
  auditEvidenceDigest: string;
  policyDigest: string;
  agentStackResultDigest: string;
  analysisReceiptDigest: string;
  readReceiptDigest: string;
  improveContextResultDigest: string;
  improveReceiptDigest: string;
  action: "ADD_TAGS";
  arguments: {
    tagUrns: string[];
    entityUrns: string[];
    columnPaths: string[];
  };
  expectedBefore: RuntimeTagState;
  expectedBeforeDigest: string;
  expectedAfter: RuntimeTagState;
  expectedAfterDigest: string;
  requiresHumanApproval: true;
  createdAt: string;
  digest: string;
}

export interface RuntimeImproveContextCapability {
  schemaVersion: "archon.datahub-improve-context-capability/v2";
  auditId: string;
  command: "/improve-context";
  status: "AVAILABLE" | "RUNNING" | "FAILED";
  analysisReceiptDigest: string;
  runtimeEvidenceDigest: string;
  writeAuthority: "archon-remediation-worker";
  requiresExplicitUserAction: true;
  requiresFreshDigestBoundApproval: true;
  dispatchDigest?: string;
  digest: string;
}

export interface RuntimeImproveContextResult {
  schemaVersion: "archon.datahub-improve-context-projection/v2";
  resultDigest: string;
  runtimeBinding: RuntimeBinding;
  events: JsonValue[];
  contextQuality: JsonObject;
  preflightDigest: string;
  contextDigest: string;
  skillGroundingDigest: string;
  status: "proposal-only";
  writeAuthority: "archon-remediation-worker";
  requiresFreshDigestBoundApproval: true;
  digest: string;
}

export type RuntimeImproveContextProjection =
  | RuntimeImproveContextCapability
  | RuntimeImproveContextResult;

export interface RuntimeApprovalProjection {
  approvalId: string;
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
  requestedAt: string;
  expiresAt: string;
  planDigest: string;
  requestDigest: string;
  decision?: "APPROVE" | "REJECT";
  decisionDigest?: string;
  decidedAt?: string;
}

export interface RuntimeRemediationProjection {
  schemaVersion: "archon.governed-remediation-projection/v2";
  jobId: string;
  receiptDigest: string;
  requestDigest: string;
  beforeDigest: string;
  afterDigest: string;
  responseDigest: string;
  policyDigest: string;
  mutationExecutor: "official-datahub-mcp";
  officialMcpMutation: {
    tool: "add_tags";
    policyDigest: string;
    approvalDigest: string;
    requestDigest: string;
    responseDigest: string;
  };
  authorizationEvidence: {
    algorithm: "ECDSA_SHA_256";
    canonicalization: "archon.sorted-json-utf8/v1";
    keyReferenceDigest: string;
    envelopeDigest: string;
    signatureDigest: string;
    consumedAt: string;
  };
  verified: true;
}

export interface RuntimeSkillCompletion {
  schemaVersion: "archon.datahub-skill-completion/v1";
  skill: "datahub-enrich";
  status: "executed-with-human-approval";
  sourceArtifactDigest: string;
  executionPlanDigest: string;
  previewSkillReceiptDigest: string;
  skillGroundingDigest: string;
  approvalDigest: string;
  officialMcpMutationReceiptDigest: string;
  completedAt: string;
  digest: string;
}

export interface RuntimeContextDelta {
  schemaVersion: "archon.context-delta/v1";
  sourceMutationReceiptDigest: string;
  beforeContextDigest: string;
  afterContextDigest: string;
  beforeAnalyticsDigest: string;
  afterAnalyticsDigest: string;
  beforeTagStateDigest: string;
  afterTagStateDigest: string;
  addedTagUrns: ["urn:li:tag:PII"];
  ackContextChanged: true;
  analyticsResultChanged: true;
  sourceReadVerified: true;
  postAnalysisReceiptDigest: string;
  postReadReceiptDigest: string;
  digest: string;
}

export interface RuntimeControlLoopStart {
  schemaVersion: "archon.control-loop-start/v2";
  auditId: string;
  status: "RUNNING";
  phase: "ANALYZING";
  pollUrl: string;
  submittedAt: string;
  runtimeEvidence: RuntimeBindingEvidence;
}

export interface RuntimeControlLoopStatus {
  schemaVersion: "archon.control-loop-status/v2";
  auditId: string;
  status: RuntimeAgentStatus;
  phase: RuntimeAgentPhase;
  submittedAt: string;
  updatedAt: string;
  runtimeEvidence: RuntimeBindingEvidence;
  completedAt?: string;
  agentStackResult?: RuntimeAgentStackResult;
  governedState?: RuntimeTagState;
  improveContext?: RuntimeImproveContextProjection;
  plan?: RuntimeRemediationPlan;
  approval?: RuntimeApprovalProjection;
  remediation?: RuntimeRemediationProjection;
  skillCompletion?: RuntimeSkillCompletion;
  contextDelta?: RuntimeContextDelta;
  runtimeExecution?: JsonObject;
  error?: { code: string; retryable: boolean };
}

export interface RuntimeImproveContextStart {
  schemaVersion: "archon.runtime-improve-context-start/v2";
  auditId: string;
  status: "RUNNING";
  phase: "IMPROVING_CONTEXT";
  pollUrl: string;
  jobId: string;
  requestDigest: string;
  submittedAt: string;
}

export interface RuntimeApprovalDecisionResponse {
  schemaVersion: "archon.runtime-approval-decision-response/v2";
  auditId: string;
  approval: RuntimeApprovalProjection;
}

const RUNTIME_CONTROL_LOOP_PATH = "/api/control-loops-v2";
const AUDIT_ID = /^[a-f0-9]{64}$/u;
const JOB_ID = /^job_[A-Za-z0-9_-]{22}$/u;
const DATASET_URN = /^urn:li:dataset:\(.{1,900}\)$/u;
const AGENT_STATUSES = [
  "RUNNING",
  "AWAITING_IMPROVEMENT",
  "AWAITING_APPROVAL",
  "SUCCEEDED",
  "REJECTED",
  "FAILED",
] as const;
const AGENT_PHASES = [
  "ANALYZING",
  "READING_GOVERNED_STATE",
  "IMPROVING_CONTEXT",
  "HUMAN_APPROVAL",
  "APPLYING_GOVERNED_WRITE",
  "VERIFYING_CONTEXT_DELTA",
  "COMPLETE",
] as const;
const STATUS_KEYS = [
  "schemaVersion",
  "auditId",
  "status",
  "phase",
  "submittedAt",
  "updatedAt",
  "runtimeEvidence",
  "completedAt",
  "agentStackResult",
  "governedState",
  "improveContext",
  "plan",
  "approval",
  "remediation",
  "skillCompletion",
  "contextDelta",
  "runtimeExecution",
  "error",
] as const;

function allowedKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  allowed: readonly string[],
): boolean {
  const keys = Reflect.ownKeys(value);
  return (
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    keys.every(
      (key) => typeof key === "string" && allowed.includes(key),
    )
  );
}

function sameJson(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (Array.isArray(left) && Array.isArray(right)) {
    return (
      left.length === right.length &&
      left.every((entry, index) => sameJson(entry, right[index]))
    );
  }
  if (!record(left) || !record(right)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key, index) =>
        key === rightKeys[index] && sameJson(left[key], right[key]),
    )
  );
}

function runtimeBinding(value: unknown): value is RuntimeBinding {
  return (
    record(value) &&
    exactKeys(value, [
      "schemaVersion",
      "profileId",
      "generation",
      "capabilityDigest",
      "resolution",
      "boundAt",
      "leaseExpiresAt",
    ]) &&
    value.schemaVersion === "archon.runtime-binding/v1" &&
    PROFILE_IDS.includes(value.profileId as RuntimeProfileId) &&
    typeof value.generation === "string" &&
    GENERATION.test(value.generation) &&
    typeof value.capabilityDigest === "string" &&
    DIGEST.test(value.capabilityDigest) &&
    (value.resolution === "auto" || value.resolution === "explicit") &&
    instant(value.boundAt) &&
    instant(value.leaseExpiresAt) &&
    Date.parse(value.leaseExpiresAt) > Date.parse(value.boundAt) &&
    Date.parse(value.leaseExpiresAt) - Date.parse(value.boundAt) <=
      2 * 60 * 60_000
  );
}

function runtimeBindingEvidence(
  value: unknown,
  expectedAuditId: string,
): value is RuntimeBindingEvidence {
  if (!record(value)) return false;
  const binding = value.runtimeBinding;
  const projectedCapabilities = value.capabilities;
  return (
    exactKeys(value, [
      "schemaVersion",
      "auditId",
      "runtimeSessionId",
      "runtimeBinding",
      "capabilities",
      "bindingDigest",
      "sessionRevision",
      "recordedAt",
      "digest",
    ]) &&
    value.schemaVersion === "archon.runtime-binding-evidence/v2" &&
    value.auditId === expectedAuditId &&
    typeof value.runtimeSessionId === "string" &&
    SESSION_ID.test(value.runtimeSessionId) &&
    runtimeBinding(binding) &&
    capabilities(projectedCapabilities) &&
    CAPABILITY_KEYS.every((key) => projectedCapabilities[key] === true) &&
    typeof value.bindingDigest === "string" &&
    DIGEST.test(value.bindingDigest) &&
    Number.isSafeInteger(value.sessionRevision) &&
    (value.sessionRevision as number) >= 1 &&
    instant(value.recordedAt) &&
    typeof value.digest === "string" &&
    DIGEST.test(value.digest) &&
    safePublicValue(value)
  );
}

function jsonObject(value: unknown): value is JsonObject {
  return record(value) && safePublicValue(value);
}

function agentStackResult(
  value: unknown,
  evidence: RuntimeBindingEvidence,
): value is RuntimeAgentStackResult {
  if (!record(value)) return false;
  const enrichment = value.enrichment;
  return (
    exactKeys(value, [
      "schemaVersion",
      "resultDigest",
      "runtimeBinding",
      "context",
      "skills",
      "skillGrounding",
      "analytics",
      "enrichment",
      "digest",
    ]) &&
    value.schemaVersion ===
      "archon.datahub-agent-stack-result-projection/v2" &&
    typeof value.resultDigest === "string" &&
    DIGEST.test(value.resultDigest) &&
    runtimeBinding(value.runtimeBinding) &&
    sameJson(value.runtimeBinding, evidence.runtimeBinding) &&
    jsonObject(value.context) &&
    typeof value.context.digest === "string" &&
    DIGEST.test(value.context.digest) &&
    jsonObject(value.skills) &&
    typeof value.skills.digest === "string" &&
    DIGEST.test(value.skills.digest) &&
    jsonObject(value.skillGrounding) &&
    typeof value.skillGrounding.digest === "string" &&
    DIGEST.test(value.skillGrounding.digest) &&
    jsonObject(value.analytics) &&
    typeof value.analytics.digest === "string" &&
    DIGEST.test(value.analytics.digest) &&
    record(enrichment) &&
    exactKeys(enrichment, [
      "status",
      "writeAuthority",
      "requiresFreshDigestBoundApproval",
    ]) &&
    enrichment.status === "preview-only" &&
    enrichment.writeAuthority === "archon-remediation-worker" &&
    enrichment.requiresFreshDigestBoundApproval === true &&
    typeof value.digest === "string" &&
    DIGEST.test(value.digest) &&
    safePublicValue(value)
  );
}

function tagState(value: unknown): value is RuntimeTagState {
  return (
    record(value) &&
    exactKeys(value, [
      "entityUrn",
      "columnPath",
      "tagUrns",
      "stateDigest",
    ]) &&
    typeof value.entityUrn === "string" &&
    DATASET_URN.test(value.entityUrn) &&
    typeof value.columnPath === "string" &&
    value.columnPath.length > 0 &&
    value.columnPath.length <= 512 &&
    Array.isArray(value.tagUrns) &&
    value.tagUrns.length <= 256 &&
    value.tagUrns.every(
      (tag) => typeof tag === "string" && tag.startsWith("urn:li:tag:"),
    ) &&
    typeof value.stateDigest === "string" &&
    DIGEST.test(value.stateDigest)
  );
}

function improveContextProjection(
  value: unknown,
  auditId: string,
  evidence: RuntimeBindingEvidence,
  agent?: RuntimeAgentStackResult,
): value is RuntimeImproveContextProjection {
  if (!record(value)) return false;
  if (value.schemaVersion === "archon.datahub-improve-context-capability/v2") {
    const required = [
      "schemaVersion", "auditId", "command", "status",
      "analysisReceiptDigest", "runtimeEvidenceDigest", "writeAuthority",
      "requiresExplicitUserAction", "requiresFreshDigestBoundApproval", "digest",
    ];
    const allowed = required.concat(["dispatchDigest"]);
    return (
      allowedKeys(value, required, allowed) &&
      value.auditId === auditId &&
      value.command === "/improve-context" &&
      ["AVAILABLE", "RUNNING", "FAILED"].includes(value.status as string) &&
      typeof value.analysisReceiptDigest === "string" &&
      DIGEST.test(value.analysisReceiptDigest) &&
      value.runtimeEvidenceDigest === evidence.digest &&
      value.writeAuthority === "archon-remediation-worker" &&
      value.requiresExplicitUserAction === true &&
      value.requiresFreshDigestBoundApproval === true &&
      (value.status === "AVAILABLE"
        ? value.dispatchDigest === undefined
        : typeof value.dispatchDigest === "string" && DIGEST.test(value.dispatchDigest)) &&
      typeof value.digest === "string" &&
      DIGEST.test(value.digest) &&
      safePublicValue(value)
    );
  }
  return (
    exactKeys(value, [
      "schemaVersion", "resultDigest", "runtimeBinding", "events",
      "contextQuality", "preflightDigest", "contextDigest",
      "skillGroundingDigest", "status", "writeAuthority",
      "requiresFreshDigestBoundApproval", "digest",
    ]) &&
    value.schemaVersion === "archon.datahub-improve-context-projection/v2" &&
    typeof value.resultDigest === "string" && DIGEST.test(value.resultDigest) &&
    runtimeBinding(value.runtimeBinding) &&
    sameJson(value.runtimeBinding, evidence.runtimeBinding) &&
    Array.isArray(value.events) &&
    value.events.length <= 512 &&
    value.events.every(safePublicValue) &&
    jsonObject(value.contextQuality) &&
    [value.preflightDigest, value.contextDigest, value.skillGroundingDigest, value.digest].every(
      (entry) => typeof entry === "string" && DIGEST.test(entry),
    ) &&
    (agent === undefined ||
      (value.contextDigest === agent.context.digest &&
        value.skillGroundingDigest === agent.skillGrounding.digest)) &&
    value.status === "proposal-only" &&
    value.writeAuthority === "archon-remediation-worker" &&
    value.requiresFreshDigestBoundApproval === true &&
    safePublicValue(value)
  );
}

function remediationPlan(
  value: unknown,
  auditId: string,
  evidence: RuntimeBindingEvidence,
): value is RuntimeRemediationPlan {
  if (!record(value)) return false;
  const args = value.arguments;
  return (
    exactKeys(value, [
      "schemaVersion",
      "auditId",
      "runtimeEvidenceDigest",
      "auditEvidenceDigest",
      "policyDigest",
      "agentStackResultDigest",
      "analysisReceiptDigest",
      "readReceiptDigest",
      "improveContextResultDigest",
      "improveReceiptDigest",
      "action",
      "arguments",
      "expectedBefore",
      "expectedBeforeDigest",
      "expectedAfter",
      "expectedAfterDigest",
      "requiresHumanApproval",
      "createdAt",
      "digest",
    ]) &&
    value.schemaVersion === "archon.runtime-remediation-plan/v2" &&
    value.auditId === auditId &&
    value.runtimeEvidenceDigest === evidence.digest &&
    [
      value.auditEvidenceDigest,
      value.policyDigest,
      value.agentStackResultDigest,
      value.analysisReceiptDigest,
      value.readReceiptDigest,
      value.improveContextResultDigest,
      value.improveReceiptDigest,
      value.expectedBeforeDigest,
      value.expectedAfterDigest,
      value.digest,
    ].every((entry) => typeof entry === "string" && DIGEST.test(entry)) &&
    value.action === "ADD_TAGS" &&
    record(args) &&
    exactKeys(args, ["tagUrns", "entityUrns", "columnPaths"]) &&
    Array.isArray(args.tagUrns) &&
    args.tagUrns.length === 1 &&
    args.tagUrns[0] === "urn:li:tag:PII" &&
    Array.isArray(args.entityUrns) &&
    args.entityUrns.length === 1 &&
    args.entityUrns[0] === AGENT_STACK_DATASET_URN &&
    Array.isArray(args.columnPaths) &&
    args.columnPaths.length === 1 &&
    args.columnPaths[0] === GOVERNED_COLUMN_PATH &&
    tagState(value.expectedBefore) &&
    tagState(value.expectedAfter) &&
    value.expectedBeforeDigest === value.expectedBefore.stateDigest &&
    value.expectedAfterDigest === value.expectedAfter.stateDigest &&
    value.expectedAfter.tagUrns.includes("urn:li:tag:PII") &&
    value.requiresHumanApproval === true &&
    instant(value.createdAt) &&
    safePublicValue(value)
  );
}

function approvalProjection(
  value: unknown,
  expectedPlanDigest?: string,
): value is RuntimeApprovalProjection {
  if (!record(value)) return false;
  const required = [
    "approvalId",
    "status",
    "requestedAt",
    "expiresAt",
    "planDigest",
    "requestDigest",
  ];
  const allowed = required.concat(["decision", "decisionDigest", "decidedAt"]);
  const pending = value.status === "PENDING" || value.status === "EXPIRED";
  return (
    allowedKeys(value, required, allowed) &&
    typeof value.approvalId === "string" &&
    /^approval-[a-f0-9]{24}$/u.test(value.approvalId) &&
    ["PENDING", "APPROVED", "REJECTED", "EXPIRED"].includes(
      value.status as string,
    ) &&
    instant(value.requestedAt) &&
    instant(value.expiresAt) &&
    typeof value.planDigest === "string" &&
    DIGEST.test(value.planDigest) &&
    (expectedPlanDigest === undefined || value.planDigest === expectedPlanDigest) &&
    typeof value.requestDigest === "string" &&
    DIGEST.test(value.requestDigest) &&
    (pending
      ? value.decision === undefined &&
        value.decisionDigest === undefined &&
        value.decidedAt === undefined
      : (value.decision === "APPROVE" || value.decision === "REJECT") &&
        typeof value.decisionDigest === "string" &&
        DIGEST.test(value.decisionDigest) &&
        instant(value.decidedAt)) &&
    safePublicValue(value)
  );
}

function remediationProjection(
  value: unknown,
  plan: RuntimeRemediationPlan,
): value is RuntimeRemediationProjection {
  return (
    record(value) &&
    exactKeys(value, [
      "schemaVersion",
      "jobId",
      "receiptDigest",
      "requestDigest",
      "beforeDigest",
      "afterDigest",
      "responseDigest",
      "policyDigest",
      "mutationExecutor",
      "officialMcpMutation",
      "authorizationEvidence",
      "verified",
    ]) &&
    value.schemaVersion === "archon.governed-remediation-projection/v2" &&
    typeof value.jobId === "string" &&
    JOB_ID.test(value.jobId) &&
    [
      value.receiptDigest,
      value.requestDigest,
      value.responseDigest,
      value.policyDigest,
    ].every((entry) => typeof entry === "string" && DIGEST.test(entry)) &&
    value.policyDigest === plan.policyDigest &&
    value.mutationExecutor === "official-datahub-mcp" &&
    record(value.officialMcpMutation) &&
    exactKeys(value.officialMcpMutation, [
      "tool",
      "policyDigest",
      "approvalDigest",
      "requestDigest",
      "responseDigest",
    ]) &&
    value.officialMcpMutation.tool === "add_tags" &&
    value.officialMcpMutation.policyDigest === plan.policyDigest &&
    value.officialMcpMutation.requestDigest === value.requestDigest &&
    [
      value.officialMcpMutation.approvalDigest,
      value.officialMcpMutation.responseDigest,
    ].every((entry) => typeof entry === "string" && DIGEST.test(entry)) &&
    record(value.authorizationEvidence) &&
    exactKeys(value.authorizationEvidence, [
      "algorithm",
      "canonicalization",
      "keyReferenceDigest",
      "envelopeDigest",
      "signatureDigest",
      "consumedAt",
    ]) &&
    value.authorizationEvidence.algorithm === "ECDSA_SHA_256" &&
    value.authorizationEvidence.canonicalization === "archon.sorted-json-utf8/v1" &&
    [
      value.authorizationEvidence.keyReferenceDigest,
      value.authorizationEvidence.envelopeDigest,
      value.authorizationEvidence.signatureDigest,
    ].every((entry) => typeof entry === "string" && DIGEST.test(entry)) &&
    instant(value.authorizationEvidence.consumedAt) &&
    value.beforeDigest === plan.expectedBeforeDigest &&
    value.afterDigest === plan.expectedAfterDigest &&
    value.verified === true &&
    safePublicValue(value)
  );
}

function exactSkillCallReceipts(
  value: unknown,
  expectedTools: readonly string[],
): value is Array<{ tool: string; receiptDigest: string }> {
  return (
    Array.isArray(value) &&
    value.length === expectedTools.length &&
    value.every(
      (entry, index) =>
        record(entry) &&
        exactKeys(entry, ["tool", "receiptDigest"]) &&
        entry.tool === expectedTools[index] &&
        typeof entry.receiptDigest === "string" &&
        DIGEST.test(entry.receiptDigest),
    )
  );
}

function enrichPreviewReceipt(
  agent: RuntimeAgentStackResult,
): Record<string, unknown> | undefined {
  const skills = agent.skills;
  const grounding = agent.skillGrounding;
  const analytics = agent.analytics;
  const workflow = [
    "datahub-search",
    "datahub-lineage",
    "datahub-quality",
    "datahub-audit",
    "datahub-enrich",
  ] as const;
  const expectedOfficial = [
    "datahub-search",
    "datahub-lineage",
    "datahub-quality",
    "datahub-enrich",
    "using-datahub",
  ] as const;
  const ackTools = [
    "search",
    "get_entities",
    "list_schema_fields",
    "get_lineage_upstream",
    "get_lineage_downstream",
    "get_dataset_assertions",
  ] as const;
  const officialMcpTools = [
    "search",
    "get_entities",
    "list_schema_fields",
    "get_lineage",
    "get_dataset_queries",
  ] as const;
  if (
    !exactKeys(skills, [
      "schemaVersion",
      "sourceCommit",
      "official",
      "custom",
      "workflow",
      "reviewedSkillCount",
      "mutationAuthority",
      "digest",
    ]) ||
    skills.schemaVersion !== "archon.datahub-skills-receipt/v2" ||
    skills.sourceCommit !== "f7c7c53648b71dc0841742781e108051d46fa360" ||
    !Array.isArray(skills.official) ||
    !Array.isArray(skills.custom) ||
    !sameJson(
      skills.official.map((artifact) => record(artifact) && artifact.skill),
      expectedOfficial,
    ) ||
    !sameJson(
      skills.custom.map((artifact) => record(artifact) && artifact.skill),
      ["datahub-audit"],
    ) ||
    !sameJson(skills.workflow, workflow) ||
    skills.reviewedSkillCount !== 6 ||
    skills.mutationAuthority !== "archon-remediation-worker" ||
    typeof skills.digest !== "string" ||
    !DIGEST.test(skills.digest) ||
    !exactKeys(grounding, [
      "schemaVersion",
      "skillsReceiptDigest",
      "ackContextDigest",
      "officialMcpReadReceiptsDigest",
      "executionOrder",
      "allRequiredCallsSatisfied",
      "receipts",
      "digest",
    ]) ||
    grounding.schemaVersion !== "archon.datahub-skill-grounding/v2" ||
    grounding.skillsReceiptDigest !== skills.digest ||
    grounding.ackContextDigest !== agent.context.digest ||
    typeof grounding.officialMcpReadReceiptsDigest !== "string" ||
    !DIGEST.test(grounding.officialMcpReadReceiptsDigest) ||
    !sameJson(grounding.executionOrder, workflow) ||
    grounding.allRequiredCallsSatisfied !== true ||
    !Array.isArray(grounding.receipts) ||
    typeof grounding.digest !== "string" ||
    !DIGEST.test(grounding.digest) ||
    analytics.skillGroundingDigest !== grounding.digest
  ) {
    return undefined;
  }
  const matchingReceipts = grounding.receipts.filter(
    (receipt) => record(receipt) && receipt.skill === "datahub-enrich",
  );
  const matchingArtifacts = skills.official.filter(
    (artifact) => record(artifact) && artifact.skill === "datahub-enrich",
  );
  if (matchingReceipts.length !== 1 || matchingArtifacts.length !== 1) {
    return undefined;
  }
  const receipt = matchingReceipts[0];
  const artifact = matchingArtifacts[0];
  if (!record(receipt) || !record(artifact)) return undefined;
  const reviewedExecution = artifact.reviewedExecution;
  const executionPlan = receipt.executionPlan;
  if (!record(reviewedExecution) || !record(executionPlan)) return undefined;
  const requiredCalls = executionPlan.requiredCalls;
  if (!record(requiredCalls)) return undefined;
  const satisfiedAckCalls = receipt.satisfiedAckCalls;
  const satisfiedOfficialMcpCalls = receipt.satisfiedOfficialMcpCalls;
  if (
    !exactKeys(artifact, [
      "skill",
      "artifactDigest",
      "gitBlob",
      "bytes",
      "reviewedExecution",
    ]) ||
    artifact.skill !== "datahub-enrich" ||
    typeof artifact.artifactDigest !== "string" ||
    !DIGEST.test(artifact.artifactDigest) ||
    typeof artifact.gitBlob !== "string" ||
    !/^[a-f0-9]{40}$/u.test(artifact.gitBlob) ||
    typeof artifact.bytes !== "number" ||
    !Number.isSafeInteger(artifact.bytes) ||
    artifact.bytes < 1 ||
    !exactKeys(reviewedExecution, ["executionPlan", "executionPlanDigest"]) ||
    !exactKeys(receipt, [
      "schemaVersion",
      "skill",
      "sourceArtifactDigest",
      "executionPlan",
      "executionPlanDigest",
      "status",
      "satisfiedAckCalls",
      "satisfiedOfficialMcpCalls",
      "ackReceiptDigests",
      "officialMcpReadReceiptDigests",
      "mode",
      "requiredCallsSatisfied",
      "mutationsEnabled",
      "providerPayloadStored",
      "digest",
    ]) ||
    receipt.schemaVersion !== "archon.datahub-skill-execution-receipt/v2" ||
    receipt.skill !== "datahub-enrich" ||
    receipt.sourceArtifactDigest !== artifact.artifactDigest ||
    !exactKeys(executionPlan, ["phase", "requiredCalls", "mode"]) ||
    executionPlan.phase !== "governed-enrichment-preview" ||
    executionPlan.mode !== "preview-only" ||
    !exactKeys(requiredCalls, ["ack", "officialMcp"]) ||
    !sameJson(requiredCalls.ack, ackTools) ||
    !sameJson(requiredCalls.officialMcp, officialMcpTools) ||
    !sameJson(reviewedExecution.executionPlan, executionPlan) ||
    reviewedExecution.executionPlanDigest !== receipt.executionPlanDigest ||
    typeof receipt.executionPlanDigest !== "string" ||
    !DIGEST.test(receipt.executionPlanDigest) ||
    receipt.status !== "previewed" ||
    receipt.mode !== "preview-only" ||
    receipt.requiredCallsSatisfied !== true ||
    receipt.mutationsEnabled !== false ||
    receipt.providerPayloadStored !== false ||
    !exactSkillCallReceipts(satisfiedAckCalls, ackTools) ||
    !exactSkillCallReceipts(satisfiedOfficialMcpCalls, officialMcpTools) ||
    !sameJson(
      receipt.ackReceiptDigests,
      satisfiedAckCalls.map((entry) => entry.receiptDigest),
    ) ||
    !sameJson(
      receipt.officialMcpReadReceiptDigests,
      satisfiedOfficialMcpCalls.map((entry) => entry.receiptDigest),
    ) ||
    typeof receipt.digest !== "string" ||
    !DIGEST.test(receipt.digest)
  ) {
    return undefined;
  }
  return receipt;
}

function skillCompletionProjection(
  value: unknown,
  agent: RuntimeAgentStackResult,
  approval: RuntimeApprovalProjection,
  remediation: RuntimeRemediationProjection,
): value is RuntimeSkillCompletion {
  const previewReceipt = enrichPreviewReceipt(agent);
  return (
    record(value) &&
    exactKeys(value, [
      "schemaVersion",
      "skill",
      "status",
      "sourceArtifactDigest",
      "executionPlanDigest",
      "previewSkillReceiptDigest",
      "skillGroundingDigest",
      "approvalDigest",
      "officialMcpMutationReceiptDigest",
      "completedAt",
      "digest",
    ]) &&
    value.schemaVersion === "archon.datahub-skill-completion/v1" &&
    value.skill === "datahub-enrich" &&
    value.status === "executed-with-human-approval" &&
    [
      value.sourceArtifactDigest,
      value.executionPlanDigest,
      value.previewSkillReceiptDigest,
      value.skillGroundingDigest,
      value.approvalDigest,
      value.officialMcpMutationReceiptDigest,
      value.digest,
    ].every((entry) => typeof entry === "string" && DIGEST.test(entry)) &&
    previewReceipt !== undefined &&
    value.sourceArtifactDigest === previewReceipt.sourceArtifactDigest &&
    value.executionPlanDigest === previewReceipt.executionPlanDigest &&
    value.previewSkillReceiptDigest === previewReceipt.digest &&
    value.skillGroundingDigest === agent.skillGrounding.digest &&
    value.approvalDigest === approval.decisionDigest &&
    value.officialMcpMutationReceiptDigest === remediation.receiptDigest &&
    instant(value.completedAt) &&
    safePublicValue(value)
  );
}

function contextDeltaProjection(
  value: unknown,
  plan: RuntimeRemediationPlan,
  remediation: RuntimeRemediationProjection,
  agent: RuntimeAgentStackResult,
  governed: RuntimeTagState,
  improve: RuntimeImproveContextProjection,
): value is RuntimeContextDelta {
  if (!record(value) || !exactKeys(value, [
    "schemaVersion",
    "sourceMutationReceiptDigest",
    "beforeContextDigest",
    "afterContextDigest",
    "beforeAnalyticsDigest",
    "afterAnalyticsDigest",
    "beforeTagStateDigest",
    "afterTagStateDigest",
    "addedTagUrns",
    "ackContextChanged",
    "analyticsResultChanged",
    "sourceReadVerified",
    "postAnalysisReceiptDigest",
    "postReadReceiptDigest",
    "digest",
  ])) return false;
  const agentContextDigest = agent.context.digest;
  const agentAnalyticsDigest = agent.analytics.digest;
  const improveContextDigest =
    improve.schemaVersion === "archon.datahub-improve-context-projection/v2"
      ? improve.contextDigest
      : undefined;
  return (
    value.schemaVersion === "archon.context-delta/v1" &&
    [
      value.sourceMutationReceiptDigest,
      value.beforeContextDigest,
      value.afterContextDigest,
      value.beforeAnalyticsDigest,
      value.afterAnalyticsDigest,
      value.beforeTagStateDigest,
      value.afterTagStateDigest,
      value.postAnalysisReceiptDigest,
      value.postReadReceiptDigest,
      value.digest,
    ].every((entry) => typeof entry === "string" && DIGEST.test(entry)) &&
    value.sourceMutationReceiptDigest === remediation.receiptDigest &&
    value.beforeContextDigest === improveContextDigest &&
    value.afterContextDigest === agentContextDigest &&
    value.beforeContextDigest !== value.afterContextDigest &&
    value.afterAnalyticsDigest === agentAnalyticsDigest &&
    value.beforeAnalyticsDigest !== value.afterAnalyticsDigest &&
    value.beforeTagStateDigest === plan.expectedBeforeDigest &&
    value.afterTagStateDigest === plan.expectedAfterDigest &&
    value.afterTagStateDigest === governed.stateDigest &&
    Array.isArray(value.addedTagUrns) &&
    sameJson(value.addedTagUrns, ["urn:li:tag:PII"]) &&
    value.ackContextChanged === true &&
    value.analyticsResultChanged === true &&
    value.sourceReadVerified === true &&
    governed.tagUrns.includes("urn:li:tag:PII") &&
    safePublicValue(value)
  );
}

function parseRuntimeControlLoopStart(
  value: unknown,
): RuntimeControlLoopStart {
  if (
    !record(value) ||
    !exactKeys(value, [
      "schemaVersion",
      "auditId",
      "status",
      "phase",
      "pollUrl",
      "submittedAt",
      "runtimeEvidence",
    ]) ||
    value.schemaVersion !== "archon.control-loop-start/v2" ||
    typeof value.auditId !== "string" ||
    !AUDIT_ID.test(value.auditId) ||
    value.status !== "RUNNING" ||
    value.phase !== "ANALYZING" ||
    value.pollUrl !== RUNTIME_CONTROL_LOOP_PATH + "/" + value.auditId ||
    !instant(value.submittedAt) ||
    !runtimeBindingEvidence(value.runtimeEvidence, value.auditId) ||
    !safePublicValue(value)
  ) {
    throw new RuntimeApiError(
      "The agent-stack control plane returned an invalid start contract.",
      502,
    );
  }
  return value as unknown as RuntimeControlLoopStart;
}

function parseRuntimeControlLoopStatus(
  value: unknown,
  expectedAuditId: string,
): RuntimeControlLoopStatus {
  const required = [
    "schemaVersion", "auditId", "status", "phase", "submittedAt",
    "updatedAt", "runtimeEvidence",
  ];
  if (
    !record(value) ||
    !allowedKeys(value, required, STATUS_KEYS) ||
    value.schemaVersion !== "archon.control-loop-status/v2" ||
    value.auditId !== expectedAuditId ||
    !AGENT_STATUSES.includes(value.status as RuntimeAgentStatus) ||
    !AGENT_PHASES.includes(value.phase as RuntimeAgentPhase) ||
    !instant(value.submittedAt) ||
    !instant(value.updatedAt) ||
    Date.parse(value.updatedAt) < Date.parse(value.submittedAt) ||
    !runtimeBindingEvidence(value.runtimeEvidence, expectedAuditId) ||
    !safePublicValue(value)
  ) {
    throw new RuntimeApiError(
      "The agent-stack control plane returned an invalid status contract.",
      502,
    );
  }
  const evidence = value.runtimeEvidence as RuntimeBindingEvidence;
  if (value.completedAt !== undefined && !instant(value.completedAt)) {
    throw new RuntimeApiError("The agent-stack completion time is invalid.", 502);
  }
  const rawAgent = value.agentStackResult;
  if (rawAgent !== undefined && !agentStackResult(rawAgent, evidence)) {
    throw new RuntimeApiError("The agent-stack result projection is invalid.", 502);
  }
  const agent = rawAgent as RuntimeAgentStackResult | undefined;
  const rawGoverned = value.governedState;
  if (rawGoverned !== undefined && !tagState(rawGoverned)) {
    throw new RuntimeApiError("The governed-state projection is invalid.", 502);
  }
  const governed = rawGoverned as RuntimeTagState | undefined;
  const rawImprove = value.improveContext;
  if (
    rawImprove !== undefined &&
    !improveContextProjection(
      rawImprove,
      expectedAuditId,
      evidence,
      value.contextDelta === undefined ? agent : undefined,
    )
  ) {
    throw new RuntimeApiError("The improve-context projection is invalid.", 502);
  }
  const improve = rawImprove as RuntimeImproveContextProjection | undefined;
  const rawPlan = value.plan;
  if (rawPlan !== undefined && !remediationPlan(rawPlan, expectedAuditId, evidence)) {
    throw new RuntimeApiError("The remediation plan projection is invalid.", 502);
  }
  const plan = rawPlan as RuntimeRemediationPlan | undefined;
  if (
    plan !== undefined &&
    improve?.schemaVersion === "archon.datahub-improve-context-projection/v2" &&
    plan.improveContextResultDigest !== improve.resultDigest
  ) {
    throw new RuntimeApiError("The plan is not bound to the proposal.", 502);
  }
  const rawApproval = value.approval;
  if (
    rawApproval !== undefined &&
    !approvalProjection(rawApproval, plan?.digest)
  ) {
    throw new RuntimeApiError("The approval projection is invalid.", 502);
  }
  const approval = rawApproval as RuntimeApprovalProjection | undefined;
  const rawRemediation = value.remediation;
  if (
    rawRemediation !== undefined &&
    (plan === undefined || !remediationProjection(rawRemediation, plan))
  ) {
    throw new RuntimeApiError("The remediation receipt projection is invalid.", 502);
  }
  const remediation = rawRemediation as RuntimeRemediationProjection | undefined;
  const rawSkillCompletion = value.skillCompletion;
  if (
    rawSkillCompletion !== undefined &&
    (agent === undefined || approval === undefined || remediation === undefined ||
      !skillCompletionProjection(
        rawSkillCompletion,
        agent,
        approval,
        remediation,
      ))
  ) {
    throw new RuntimeApiError("The skill-completion projection is invalid.", 502);
  }
  const skillCompletion = rawSkillCompletion as RuntimeSkillCompletion | undefined;
  const rawContextDelta = value.contextDelta;
  if (
    rawContextDelta !== undefined &&
    (plan === undefined || remediation === undefined || agent === undefined ||
      governed === undefined || improve === undefined ||
      !contextDeltaProjection(
        rawContextDelta,
        plan,
        remediation,
        agent,
        governed,
        improve,
      ))
  ) {
    throw new RuntimeApiError("The context-delta projection is invalid.", 502);
  }
  const contextDelta = rawContextDelta as RuntimeContextDelta | undefined;
  if (value.runtimeExecution !== undefined && !jsonObject(value.runtimeExecution)) {
    throw new RuntimeApiError("The runtime execution projection is invalid.", 502);
  }
  if (
    value.error !== undefined &&
    (!record(value.error) ||
      !exactKeys(value.error, ["code", "retryable"]) ||
      typeof value.error.code !== "string" ||
      typeof value.error.retryable !== "boolean")
  ) {
    throw new RuntimeApiError("The runtime error projection is invalid.", 502);
  }
  const status = value as unknown as RuntimeControlLoopStatus;
  const governedEvidenceComplete =
    agent !== undefined && governed !== undefined && improve !== undefined;
  const isImproveResult =
    improve?.schemaVersion === "archon.datahub-improve-context-projection/v2";
  const improveCapabilityStatus =
    improve?.schemaVersion === "archon.datahub-improve-context-capability/v2"
      ? improve.status
      : undefined;
  const skillCompletionPlacementIsValid =
    skillCompletion === undefined ||
    (status.status === "SUCCEEDED" && status.phase === "COMPLETE");
  const semanticContractIsValid =
    skillCompletionPlacementIsValid &&
    ((status.status === "RUNNING" &&
      ["ANALYZING", "READING_GOVERNED_STATE", "IMPROVING_CONTEXT", "APPLYING_GOVERNED_WRITE", "VERIFYING_CONTEXT_DELTA"].includes(status.phase) &&
      (status.phase !== "IMPROVING_CONTEXT" ||
        (governedEvidenceComplete && improveCapabilityStatus === "RUNNING")) &&
      (status.phase !== "APPLYING_GOVERNED_WRITE" ||
        (governedEvidenceComplete && isImproveResult && plan !== undefined && approval?.status === "APPROVED")) &&
      (status.phase !== "VERIFYING_CONTEXT_DELTA" ||
        (governedEvidenceComplete && isImproveResult && plan !== undefined &&
          approval?.status === "APPROVED" && remediation?.verified === true &&
          contextDelta === undefined))) ||
    (status.status === "AWAITING_IMPROVEMENT" &&
      status.phase === "IMPROVING_CONTEXT" &&
      governedEvidenceComplete && improveCapabilityStatus === "AVAILABLE" &&
      plan === undefined && approval === undefined && remediation === undefined) ||
    (status.status === "AWAITING_APPROVAL" &&
      status.phase === "HUMAN_APPROVAL" &&
      governedEvidenceComplete && isImproveResult &&
      plan !== undefined && approval?.status === "PENDING") ||
    (status.status === "SUCCEEDED" &&
      status.phase === "COMPLETE" &&
      status.completedAt !== undefined &&
      agent !== undefined &&
      (plan === undefined
        ? skillCompletion === undefined && contextDelta === undefined
        : (governedEvidenceComplete && isImproveResult &&
          approval?.status === "APPROVED" && remediation?.verified === true &&
          skillCompletion !== undefined && contextDelta !== undefined))) ||
    (status.status === "REJECTED" &&
      status.phase === "COMPLETE" &&
      status.completedAt !== undefined &&
      governedEvidenceComplete && isImproveResult &&
      plan !== undefined && approval?.status === "REJECTED") ||
    (status.status === "FAILED" &&
      status.error !== undefined && status.completedAt !== undefined));
  if (!semanticContractIsValid) {
    throw new RuntimeApiError(
      "The agent-stack status transition is internally inconsistent.",
      502,
    );
  }
  return status;
}

function narrowAgentInput(
  datasetUrn: string,
  question: string,
  sessionId: string,
): void {
  if (!SESSION_ID.test(sessionId)) {
    throw new RuntimeApiError("The runtime session capability is invalid.", 400);
  }
  if (
    datasetUrn !== AGENT_STACK_DATASET_URN ||
    question !== AGENT_STACK_QUESTION
  ) {
    throw new RuntimeApiError(
      "Use the canonical, deterministic DataHub judge fixture shown in the form.",
      400,
    );
  }
}

function controlLoopPath(auditId: string): string {
  if (!AUDIT_ID.test(auditId)) {
    throw new RuntimeApiError("The agent-stack run identifier is invalid.", 400);
  }
  return RUNTIME_CONTROL_LOOP_PATH + "/" + auditId;
}

export async function startRuntimeAgentStack(
  datasetUrn: string,
  question: string,
  sessionId: string,
  accessToken: string,
  signal?: AbortSignal,
): Promise<RuntimeControlLoopStart> {
  narrowAgentInput(datasetUrn, question, sessionId);
  return parseRuntimeControlLoopStart(
    await request(RUNTIME_CONTROL_LOOP_PATH, {
      method: "POST",
      body: JSON.stringify({
        query: datasetUrn,
        question,
        datasetUrn,
        sessionId,
        mode: "GOVERNED",
      }),
      headers: authorizationHeaders(accessToken),
      signal,
    }),
  );
}

export async function getRuntimeAgentStackStatus(
  auditId: string,
  accessToken: string,
  signal?: AbortSignal,
): Promise<RuntimeControlLoopStatus> {
  return parseRuntimeControlLoopStatus(
    await request(controlLoopPath(auditId), {
      method: "GET",
      headers: authorizationHeaders(accessToken),
      signal,
    }),
    auditId,
  );
}

function parseRuntimeImproveStart(
  value: unknown,
  expectedAuditId: string,
): RuntimeImproveContextStart {
  if (
    !record(value) ||
    !exactKeys(value, [
      "schemaVersion", "auditId", "status", "phase", "pollUrl",
      "jobId", "requestDigest", "submittedAt",
    ]) ||
    value.schemaVersion !== "archon.runtime-improve-context-start/v2" ||
    value.auditId !== expectedAuditId ||
    value.status !== "RUNNING" ||
    value.phase !== "IMPROVING_CONTEXT" ||
    value.pollUrl !== controlLoopPath(expectedAuditId) ||
    typeof value.jobId !== "string" || !JOB_ID.test(value.jobId) ||
    typeof value.requestDigest !== "string" || !DIGEST.test(value.requestDigest) ||
    !instant(value.submittedAt) ||
    !safePublicValue(value)
  ) {
    throw new RuntimeApiError(
      "The improve-context service returned an invalid dispatch receipt.",
      502,
    );
  }
  return value as unknown as RuntimeImproveContextStart;
}

export async function requestRuntimeImproveContext(
  auditId: string,
  accessToken: string,
  signal?: AbortSignal,
  onProgress?: (status: RuntimeControlLoopStatus) => void,
): Promise<RuntimeControlLoopStatus> {
  parseRuntimeImproveStart(
    await request(controlLoopPath(auditId) + "/improve-context", {
      method: "POST",
      body: "{}",
      headers: authorizationHeaders(accessToken),
      signal,
    }),
    auditId,
  );
  return pollRuntimeAgentStack(
    auditId,
    accessToken,
    true,
    signal,
    onProgress,
  );
}

export async function submitRuntimeApproval(
  auditId: string,
  decision: "APPROVE" | "REJECT",
  accessToken: string,
  comment = "",
  signal?: AbortSignal,
): Promise<RuntimeApprovalDecisionResponse> {
  if (!(["APPROVE", "REJECT"] as const).includes(decision)) {
    throw new RuntimeApiError("The approval decision is invalid.", 400);
  }
  if (comment.length > 512 || /[\u0000-\u001F\u007F]/u.test(comment)) {
    throw new RuntimeApiError("The approval comment is invalid.", 400);
  }
  const value = await request(controlLoopPath(auditId) + "/approval", {
    method: "POST",
    body: JSON.stringify({ decision, comment }),
    headers: authorizationHeaders(accessToken),
    signal,
  });
  if (
    !record(value) ||
    !exactKeys(value, ["schemaVersion", "auditId", "approval"]) ||
    value.schemaVersion !== "archon.runtime-approval-decision-response/v2" ||
    value.auditId !== auditId ||
    !approvalProjection(value.approval) ||
    !safePublicValue(value)
  ) {
    throw new RuntimeApiError(
      "The approval service returned an invalid decision receipt.",
      502,
    );
  }
  return value as unknown as RuntimeApprovalDecisionResponse;
}

function waitRuntimePoll(
  milliseconds: number,
  signal?: AbortSignal,
): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const onAbort = () => {
      window.clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = window.setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

async function pollRuntimeAgentStack(
  auditId: string,
  accessToken: string,
  stopAtApproval: boolean,
  signal?: AbortSignal,
  onProgress?: (status: RuntimeControlLoopStatus) => void,
): Promise<RuntimeControlLoopStatus> {
  let transientFailures = 0;
  while (!signal?.aborted) {
    let status: RuntimeControlLoopStatus;
    try {
      status = await getRuntimeAgentStackStatus(auditId, accessToken, signal);
      transientFailures = 0;
    } catch (error) {
      if (signal?.aborted) throw error;
      const retryable =
        error instanceof TypeError ||
        (error instanceof RuntimeApiError &&
          [502, 503, 504].includes(error.status));
      if (!retryable || ++transientFailures > 3) throw error;
      await waitRuntimePoll(800 * transientFailures, signal);
      continue;
    }
    onProgress?.(status);
    if (
      (stopAtApproval &&
        ["AWAITING_IMPROVEMENT", "AWAITING_APPROVAL"].includes(status.status)) ||
      ["SUCCEEDED", "REJECTED", "FAILED"].includes(status.status)
    ) {
      return status;
    }
    await waitRuntimePoll(
      status.phase === "APPLYING_GOVERNED_WRITE" ? 1600 : 1000,
      signal,
    );
  }
  throw (
    signal?.reason ??
    new DOMException("The agent-stack run was cancelled.", "AbortError")
  );
}

export async function loadRuntimeAgentStack(
  datasetUrn: string,
  question: string,
  sessionId: string,
  accessToken: string,
  signal?: AbortSignal,
  onProgress?: (status: RuntimeControlLoopStatus) => void,
): Promise<RuntimeControlLoopStatus> {
  const start = await startRuntimeAgentStack(
    datasetUrn,
    question,
    sessionId,
    accessToken,
    signal,
  );
  return pollRuntimeAgentStack(
    start.auditId,
    accessToken,
    true,
    signal,
    onProgress,
  );
}

export async function resumeRuntimeAgentStack(
  auditId: string,
  accessToken: string,
  signal?: AbortSignal,
  onProgress?: (status: RuntimeControlLoopStatus) => void,
): Promise<RuntimeControlLoopStatus> {
  return pollRuntimeAgentStack(
    auditId,
    accessToken,
    false,
    signal,
    onProgress,
  );
}
