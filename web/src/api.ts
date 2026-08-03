import { previewAudit } from "./fixtures";
import type {
  ApprovalAck,
  ApprovalDecision,
  AuditEnvelope,
  AuditReport,
  ControlLoopApproval,
  ControlLoopResult,
  ControlLoopStart,
  ControlLoopStatus,
  Finding,
  LoadedAudit,
  LiveModelProvider,
  ModelRuntimeProvenance,
} from "./types";

const AUDIT_PATH = "/api/audits";
const CONTROL_LOOP_PATH = "/api/control-loops";
const AUDIT_ID_PATTERN = /^[a-f0-9]{64}$/;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const MODEL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/u;
const RESPONSE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{5,199}$/u;
const RFC3339_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const CREDENTIAL_SHAPED_IDENTIFIER =
  /(?:bedrock-api-key-[A-Za-z0-9_+/=-]{16,}|sk-(?:ant-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/u;
const MAX_MODEL_LATENCY_MS = 3_600_000;
const LIVE_MODEL_PROVIDERS = new Set<LiveModelProvider>([
  "bedrock-mantle",
  "custom",
  "qwen",
  "gemini",
  "openai",
  "anthropic",
]);
const MODEL_PROVENANCE_KEYS = [
  "schemaVersion",
  "source",
  "modelCall",
  "provider",
  "requestedModel",
  "returnedModel",
  "providerResponseId",
  "tokenUsage",
  "latencyMs",
] as const;
const MODEL_TOKEN_USAGE_KEYS = [
  "inputTokens",
  "outputTokens",
  "totalTokens",
] as const;
const CLASSIFICATION_KEYS = [
  "totalEntities",
  "withLineage",
  "sensitiveEntities",
  "domains",
  "platforms",
] as const;
const FINDING_KEYS = [
  "type",
  "severity",
  "subject",
  "summary",
  "detail",
] as const;
const FINDING_DETAIL_KEYS = [
  "ruleId",
  "rule",
  "attribute",
  "unclassifiedFields",
  "blastRadius",
  "provenance",
  "dossier",
  "approval",
] as const;
const AUDIT_REPORT_KEYS = [
  "schemaVersion",
  "scanId",
  "classification",
  "findings",
  "narrative",
  "modelProvenance",
  "trace",
] as const;
const FORBIDDEN_PUBLIC_KEYS = new Set([
  "accesstoken",
  "accesstokens",
  "apikey",
  "authorization",
  "clientsecret",
  "cookie",
  "credential",
  "credentials",
  "idtoken",
  "jwt",
  "password",
  "privatekey",
  "rawresponse",
  "refreshtoken",
  "secret",
  "secretaccesskey",
  "sessiontoken",
  "tasktoken",
  "token",
  "tokens",
]);
const PUBLIC_CREDENTIAL_PATTERNS = [
  /bedrock-api-key-[A-Za-z0-9_+/=-]{16,}/u,
  /(?:AKIA|ASIA)[A-Z0-9]{16}/u,
  /gh[pousr]_[A-Za-z0-9_]{20,}/u,
  /github_pat_[A-Za-z0-9_]{20,}/u,
  /xox[baprs]-[A-Za-z0-9-]{10,}/u,
  /AIza[0-9A-Za-z_-]{35}/u,
  /(?:Bearer\s+|sk-(?:ant-)?)[A-Za-z0-9._~+/=-]{12,}/iu,
  /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/u,
  /(?:api[_ -]?key|password|passwd|pwd|secret|token)\s*[:=]\s*["']?[^\s"',;]{8,}/iu,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
] as const;
const TERMINAL_CONTROL_STATES = new Set(["SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"]);
const VERIFICATION_CHECK_IDS = [
  "TARGET_UNCHANGED",
  "PREEXISTING_TAGS_PRESERVED",
  "POLICY_TAG_PRESENT",
  "NO_UNEXPECTED_TAGS",
  "APPROVAL_BINDING_VALID",
] as const;

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

function narrowAuditQuery(value: string): string {
  const query = value.trim();
  if (
    query.length < 1 ||
    query.length > 256 ||
    /[*?]/u.test(query) ||
    query === "{}" ||
    /[\u0000-\u001F\u007F]/u.test(query)
  ) {
    throw new ApiError(
      "A narrow, non-wildcard dataset query is required.",
      400,
    );
  }
  return query;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  return (
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
  );
}

function isBoundedText(value: unknown, maximum: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    !/[\u0000-\u001F\u007F]/u.test(value)
  );
}

function isNumberRecord(value: unknown): value is Record<string, number> {
  return (
    isRecord(value) &&
    Object.keys(value).length <= 1_000 &&
    Object.entries(value).every(
      ([key, entry]) => isBoundedText(key, 256) && isSafeCount(entry),
    )
  );
}

function isPublicOutputSafe(value: unknown): boolean {
  if (typeof value === "string") {
    return !PUBLIC_CREDENTIAL_PATTERNS.some((pattern) => pattern.test(value));
  }
  if (Array.isArray(value)) return value.every(isPublicOutputSafe);
  if (!isRecord(value)) return true;
  return Object.entries(value).every(([key, entry]) => {
    const normalizedKey = key.replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
    return (
      !FORBIDDEN_PUBLIC_KEYS.has(normalizedKey) &&
      !PUBLIC_CREDENTIAL_PATTERNS.some((pattern) => pattern.test(key)) &&
      isPublicOutputSafe(entry)
    );
  });
}

function isSafeModelId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    MODEL_ID_PATTERN.test(value) &&
    !value.includes("://") &&
    !CREDENTIAL_SHAPED_IDENTIFIER.test(value)
  );
}

function isSafeProviderResponseId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    RESPONSE_ID_PATTERN.test(value) &&
    !CREDENTIAL_SHAPED_IDENTIFIER.test(value)
  );
}

function isSafeCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isModelTokenUsage(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, MODEL_TOKEN_USAGE_KEYS) &&
    isSafeCount(value.inputTokens) &&
    isSafeCount(value.outputTokens) &&
    isSafeCount(value.totalTokens) &&
    value.totalTokens === value.inputTokens + value.outputTokens
  );
}

function isModelRuntimeProvenance(
  value: unknown,
): value is ModelRuntimeProvenance {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, MODEL_PROVENANCE_KEYS) ||
    value.schemaVersion !== "archon.model-runtime-provenance/v1" ||
    !isSafeModelId(value.requestedModel)
  ) {
    return false;
  }

  if (value.source === "deterministic-fixture") {
    return (
      value.modelCall === false &&
      value.provider === "fixture" &&
      value.returnedModel === null &&
      value.providerResponseId === null &&
      value.tokenUsage === null &&
      value.latencyMs === null
    );
  }

  return (
    value.source === "live-provider" &&
    value.modelCall === true &&
    typeof value.provider === "string" &&
    LIVE_MODEL_PROVIDERS.has(value.provider as LiveModelProvider) &&
    isSafeModelId(value.returnedModel) &&
    isSafeProviderResponseId(value.providerResponseId) &&
    (value.tokenUsage === null || isModelTokenUsage(value.tokenUsage)) &&
    Number.isSafeInteger(value.latencyMs) &&
    (value.latencyMs as number) >= 0 &&
    (value.latencyMs as number) <= MAX_MODEL_LATENCY_MS
  );
}

function isBlastRadius(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "rootUrn",
      "downstream",
      "maxHops",
      "truncated",
      "impact",
    ]) &&
    isBoundedText(value.rootUrn, 2_048) &&
    Array.isArray(value.downstream) &&
    value.downstream.length <= 10_000 &&
    value.downstream.every(
      (asset) =>
        isRecord(asset) &&
        hasExactKeys(asset, ["urn", "minHops"]) &&
        isBoundedText(asset.urn, 2_048) &&
        isSafeCount(asset.minHops) &&
        asset.minHops <= 10,
    ) &&
    isSafeCount(value.maxHops) &&
    value.maxHops <= 10 &&
    typeof value.truncated === "boolean" &&
    ["none", "low", "medium", "high", "critical"].includes(String(value.impact))
  );
}

function isProvenance(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.length <= 1_000 &&
    value.every(
      (event) =>
        isRecord(event) &&
        hasExactKeys(event, ["source", "runId", "observedAt", "status"]) &&
        isBoundedText(event.source, 512) &&
        isBoundedText(event.runId, 512) &&
        isInstant(event.observedAt) &&
        ["trusted", "conflicting", "observed"].includes(String(event.status)),
    )
  );
}

function isDossier(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "dossierId",
      "digest",
      "policyDigest",
      "generatedAt",
      "evidenceCount",
    ]) &&
    isBoundedText(value.dossierId, 512) &&
    isBoundedText(value.digest, 256) &&
    DIGEST_PATTERN.test(value.digest) &&
    isBoundedText(value.policyDigest, 256) &&
    DIGEST_PATTERN.test(value.policyDigest) &&
    isInstant(value.generatedAt) &&
    isSafeCount(value.evidenceCount) &&
    value.evidenceCount <= 100_000
  );
}

function isApproval(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "approvalId",
      "expiresAt",
      "targetField",
      "proposedTag",
      "before",
      "after",
      "planDigest",
      "risk",
    ]) &&
    isBoundedText(value.approvalId, 512) &&
    isInstant(value.expiresAt) &&
    isBoundedText(value.targetField, 1_024) &&
    isBoundedText(value.proposedTag, 2_048) &&
    Array.isArray(value.before) &&
    value.before.length <= 1_000 &&
    value.before.every((entry) => isBoundedText(entry, 2_048)) &&
    Array.isArray(value.after) &&
    value.after.length <= 1_000 &&
    value.after.every((entry) => isBoundedText(entry, 2_048)) &&
    isBoundedText(value.planDigest, 256) &&
    DIGEST_PATTERN.test(value.planDigest) &&
    ["low", "medium", "high"].includes(String(value.risk))
  );
}

function isFinding(value: unknown): value is Finding {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, FINDING_KEYS, ["recommendation"]) &&
    (value.type === "contradiction" ||
      value.type === "lineage_gap" ||
      value.type === "governance_violation") &&
    (value.severity === "high" || value.severity === "medium" || value.severity === "low") &&
    isBoundedText(value.subject, 2_048) &&
    isBoundedText(value.summary, 4_000) &&
    isRecord(value.detail) &&
    hasOnlyKeys(value.detail, [], FINDING_DETAIL_KEYS) &&
    (value.detail.ruleId === undefined ||
      isBoundedText(value.detail.ruleId, 128)) &&
    (value.detail.rule === undefined ||
      isBoundedText(value.detail.rule, 2_048)) &&
    (value.detail.attribute === undefined ||
      isBoundedText(value.detail.attribute, 512)) &&
    (value.detail.unclassifiedFields === undefined ||
      (Array.isArray(value.detail.unclassifiedFields) &&
        value.detail.unclassifiedFields.length <= 1_000 &&
        value.detail.unclassifiedFields.every((entry) =>
          isBoundedText(entry, 1_024),
        ))) &&
    (value.detail.blastRadius === undefined || isBlastRadius(value.detail.blastRadius)) &&
    (value.detail.provenance === undefined || isProvenance(value.detail.provenance)) &&
    (value.detail.dossier === undefined || isDossier(value.detail.dossier)) &&
    (value.detail.approval === undefined || isApproval(value.detail.approval)) &&
    (value.recommendation === undefined ||
      isBoundedText(value.recommendation, 4_000))
  );
}

function isAuditReport(value: unknown): value is AuditReport {
  return (
    isRecord(value) &&
    hasExactKeys(value, AUDIT_REPORT_KEYS) &&
    value.schemaVersion === "archon.audit-report/v1" &&
    isBoundedText(value.scanId, 512) &&
    isRecord(value.classification) &&
    hasExactKeys(value.classification, CLASSIFICATION_KEYS) &&
    isSafeCount(value.classification.totalEntities) &&
    isSafeCount(value.classification.withLineage) &&
    isSafeCount(value.classification.sensitiveEntities) &&
    value.classification.withLineage <= value.classification.totalEntities &&
    value.classification.sensitiveEntities <=
      value.classification.totalEntities &&
    isNumberRecord(value.classification.domains) &&
    isNumberRecord(value.classification.platforms) &&
    Array.isArray(value.findings) &&
    value.findings.length <= 10_000 &&
    value.findings.every(isFinding) &&
    isBoundedText(value.narrative, 8_000) &&
    isModelRuntimeProvenance(value.modelProvenance) &&
    Array.isArray(value.trace) &&
    value.trace.length <= 32 &&
    value.trace.every(
      (step) =>
        isRecord(step) &&
        hasExactKeys(step, ["agent", "produced"]) &&
        isBoundedText(step.agent, 128) &&
        isBoundedText(step.produced, 2_000),
    ) &&
    isPublicOutputSafe(value)
  );
}

function parseAuditEnvelope(value: unknown): AuditEnvelope {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["requestId", "releaseSha", "report"]) ||
    !isBoundedText(value.requestId, 128) ||
    !isBoundedText(value.releaseSha, 128) ||
    !isAuditReport(value.report)
  ) {
    throw new ApiError("The audit API returned an invalid response contract.", 502);
  }
  return value as unknown as AuditEnvelope;
}

function isInstant(value: unknown): value is string {
  return (
    isBoundedText(value, 128) &&
    RFC3339_INSTANT.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function parseControlLoopStart(value: unknown): ControlLoopStart {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "schemaVersion",
      "auditId",
      "status",
      "pollUrl",
      "submittedAt",
    ]) ||
    value.schemaVersion !== "archon.control-loop-start/v1" ||
    typeof value.auditId !== "string" ||
    !AUDIT_ID_PATTERN.test(value.auditId) ||
    value.status !== "RUNNING" ||
    value.pollUrl !== `${CONTROL_LOOP_PATH}/${value.auditId}` ||
    !isInstant(value.submittedAt)
  ) {
    throw new ApiError("The control plane returned an invalid start contract.", 502);
  }
  return value as unknown as ControlLoopStart;
}

function isControlLoopApproval(value: unknown): value is ControlLoopApproval {
  return (
    isRecord(value) &&
    hasOnlyKeys(
      value,
      ["approvalId", "status", "expiresAt", "planDigest", "evidenceDigest"],
      ["decision"],
    ) &&
    typeof value.approvalId === "string" &&
    (value.status === "PENDING" || value.status === "DECIDED") &&
    isInstant(value.expiresAt) &&
    typeof value.planDigest === "string" &&
    DIGEST_PATTERN.test(value.planDigest) &&
    typeof value.evidenceDigest === "string" &&
    DIGEST_PATTERN.test(value.evidenceDigest) &&
    ((value.status === "PENDING" && value.decision === undefined) ||
      (value.status === "DECIDED" &&
        (value.decision === "APPROVE" || value.decision === "REJECT")))
  );
}

function isControlLoopResult(value: unknown): value is ControlLoopResult {
  if (!isRecord(value)) return false;
  if (value.outcome === "READ_ONLY_COMPLETE") {
    return hasExactKeys(value, ["outcome"]);
  }
  if (
    (value.outcome !== "VERIFIED" && value.outcome !== "REJECTED") ||
    !hasExactKeys(value, [
      "outcome",
      "receiptDigest",
      "executionEvidenceDigest",
      "completedAt",
      "verification",
    ]) ||
    typeof value.receiptDigest !== "string" ||
    !DIGEST_PATTERN.test(value.receiptDigest) ||
    typeof value.executionEvidenceDigest !== "string" ||
    !DIGEST_PATTERN.test(value.executionEvidenceDigest) ||
    !isInstant(value.completedAt) ||
    !isRecord(value.verification) ||
    !hasExactKeys(value.verification, [
      "checks",
      "eventCount",
      "rollbackAvailability",
    ]) ||
    typeof value.verification.eventCount !== "number" ||
    !Number.isSafeInteger(value.verification.eventCount) ||
    !Array.isArray(value.verification.checks)
  ) {
    return false;
  }
  const checksValid = value.verification.checks.every(
    (check, index) =>
      isRecord(check) &&
      hasExactKeys(check, ["checkId", "passed"]) &&
      check.checkId === VERIFICATION_CHECK_IDS[index] &&
      check.passed === true,
  );
  if (!checksValid) return false;
  if (value.outcome === "VERIFIED") {
    return (
      value.verification.checks.length === VERIFICATION_CHECK_IDS.length &&
      value.verification.eventCount === 7 &&
      value.verification.rollbackAvailability === "ELIGIBLE"
    );
  }
  return (
    value.verification.checks.length === 0 &&
    value.verification.eventCount === 5 &&
    value.verification.rollbackAvailability === "NOT_APPLICABLE"
  );
}

export function parseControlLoopStatus(
  value: unknown,
  expectedAuditId: string,
): ControlLoopStatus {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(
      value,
      ["schemaVersion", "auditId", "status", "updatedAt"],
      [
        "submittedAt",
        "completedAt",
        "releaseSha",
        "report",
        "approval",
        "manualOnlyReason",
        "result",
      ],
    ) ||
    value.schemaVersion !== "archon.control-loop-status/v1" ||
    value.auditId !== expectedAuditId ||
    ![
      "RUNNING",
      "AWAITING_APPROVAL",
      "SUCCEEDED",
      "FAILED",
      "TIMED_OUT",
      "ABORTED",
    ].includes(String(value.status)) ||
    !isInstant(value.updatedAt) ||
    (value.submittedAt !== undefined && !isInstant(value.submittedAt)) ||
    (value.completedAt !== undefined && !isInstant(value.completedAt)) ||
    (value.report !== undefined && !isAuditReport(value.report)) ||
    (value.releaseSha !== undefined && typeof value.releaseSha !== "string") ||
    (value.report === undefined) !== (value.releaseSha === undefined) ||
    (value.approval !== undefined && !isControlLoopApproval(value.approval)) ||
    (value.manualOnlyReason !== undefined && typeof value.manualOnlyReason !== "string") ||
    (value.result !== undefined && !isControlLoopResult(value.result)) ||
    (value.status === "SUCCEEDED") !== (value.result !== undefined) ||
    (isRecord(value.result) &&
      value.result.outcome === "READ_ONLY_COMPLETE" &&
      value.approval !== undefined) ||
    (isRecord(value.result) &&
      (value.result.outcome === "VERIFIED" || value.result.outcome === "REJECTED") &&
      (!isRecord(value.approval) ||
        value.approval.status !== "DECIDED" ||
        (value.result.outcome === "VERIFIED" && value.approval.decision !== "APPROVE") ||
        (value.result.outcome === "REJECTED" && value.approval.decision !== "REJECT")))
  ) {
    throw new ApiError("The control plane returned an invalid status contract.", 502);
  }
  return value as unknown as ControlLoopStatus;
}

async function jsonResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new ApiError("The control plane returned a non-JSON response.", response.status || 502);
  }
  const value = await response.json();
  if (!response.ok) {
    if (
      response.status === 410 &&
      isRecord(value) &&
      value.error === "audit_schema_retired" &&
      value.rerunRequired === true
    ) {
      throw new ApiError(
        "This audit uses a retired evidence schema. Rerun it to generate a current provenance-bound report.",
        410,
      );
    }
    // Error bodies are untrusted and may include upstream endpoints, request
    // payloads, or credentials. The browser receives only a stable status-bound
    // message; operational detail belongs in access-controlled telemetry.
    throw new ApiError(
      `Control-plane request failed (${response.status}).`,
      response.status,
    );
  }
  return value;
}

export async function requestAudit(query = "", signal?: AbortSignal): Promise<AuditEnvelope> {
  const scope = narrowAuditQuery(query);
  const response = await fetch(AUDIT_PATH, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query: scope }),
    signal,
  });
  return parseAuditEnvelope(await jsonResponse(response));
}

export async function startControlLoop(
  query = "",
  signal?: AbortSignal,
): Promise<ControlLoopStart> {
  const scope = narrowAuditQuery(query);
  const response = await fetch(CONTROL_LOOP_PATH, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query: scope }),
    signal,
  });
  return parseControlLoopStart(await jsonResponse(response));
}

export async function getControlLoopStatus(
  start: Pick<ControlLoopStart, "auditId" | "pollUrl">,
  signal?: AbortSignal,
): Promise<ControlLoopStatus> {
  if (
    !AUDIT_ID_PATTERN.test(start.auditId) ||
    start.pollUrl !== `${CONTROL_LOOP_PATH}/${start.auditId}`
  ) {
    throw new ApiError("The audit polling capability is invalid.", 400);
  }
  const response = await fetch(start.pollUrl, {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    signal,
  });
  return parseControlLoopStatus(await jsonResponse(response), start.auditId);
}

function canUseFixture(error: unknown): boolean {
  return (
    error instanceof TypeError ||
    (error instanceof ApiError && [404, 502, 503, 504].includes(error.status))
  );
}

function waitForNextPoll(milliseconds: number, signal?: AbortSignal): Promise<void> {
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

function loadedFromStatus(status: ControlLoopStatus): LoadedAudit | undefined {
  if (!status.report || !status.releaseSha) return undefined;
  return {
    envelope: {
      requestId: status.auditId,
      releaseSha: status.releaseSha,
      report: status.report,
    },
    source: "live",
    controlLoop: status,
  };
}

export async function loadAudit(
  query = "",
  signal?: AbortSignal,
  onProgress?: (status: ControlLoopStatus, audit?: LoadedAudit) => void,
): Promise<LoadedAudit> {
  let start: ControlLoopStart;
  try {
    start = await startControlLoop(query, signal);
  } catch (error) {
    if (signal?.aborted) throw error;
    if (!canUseFixture(error)) throw error;
    return {
      envelope: previewAudit,
      source: "fixture",
      fallbackReason:
        "The hosted audit API is unavailable, so this view is using a deterministic, non-mutating showcase dataset.",
    };
  }

  let latest: LoadedAudit | undefined;
  let transientFailures = 0;
  while (!signal?.aborted) {
    let status: ControlLoopStatus;
    try {
      status = await getControlLoopStatus(start, signal);
      transientFailures = 0;
    } catch (error) {
      if (signal?.aborted) throw error;
      if (!canUseFixture(error) || ++transientFailures > 3) throw error;
      await waitForNextPoll(1000 * transientFailures, signal);
      continue;
    }
    latest = loadedFromStatus(status) ?? latest;
    onProgress?.(status, loadedFromStatus(status));
    if (TERMINAL_CONTROL_STATES.has(status.status)) {
      if (status.status === "SUCCEEDED" && latest) return latest;
      throw new ApiError(
        `The durable audit ended with status ${status.status.toLowerCase()}.`,
        502,
      );
    }
    await waitForNextPoll(status.status === "AWAITING_APPROVAL" ? 3000 : 1200, signal);
  }
  throw signal?.reason ?? new DOMException("The audit was cancelled.", "AbortError");
}

export interface SubmitApprovalDecisionInput {
  approvalId: string;
  decision: ApprovalDecision;
  accessToken: string;
  comment?: string;
  signal?: AbortSignal;
}

export async function submitApprovalDecision({
  approvalId,
  decision,
  accessToken,
  comment,
  signal,
}: SubmitApprovalDecisionInput): Promise<ApprovalAck> {
  if (
    accessToken.length < 20 ||
    accessToken.length > 16_384 ||
    /[\u0000-\u0020\u007F]/u.test(accessToken)
  ) {
    throw new ApiError("A valid steward access token is required.", 401);
  }
  const decisionId = crypto.randomUUID();
  const response = await fetch(
    `/api/approvals/${encodeURIComponent(approvalId)}/decisions`,
    {
      method: "POST",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "Idempotency-Key": decisionId,
      },
      // The browser submits disposition only. The server rehydrates the immutable,
      // digest-bound plan; mutation tools and arguments never cross this trust boundary.
      body: JSON.stringify({
        decision,
        ...(comment?.trim() ? { comment: comment.trim().slice(0, 500) } : {}),
      }),
      signal,
    },
  );
  const value = await jsonResponse(response);
  if (
    !isRecord(value) ||
    value.approvalId !== approvalId ||
    value.decision !== decision ||
    (value.status !== "recorded" && value.status !== "queued") ||
    typeof value.decisionId !== "string"
  ) {
    throw new ApiError("The approval API returned an invalid response contract.", 502);
  }
  return value as unknown as ApprovalAck;
}
