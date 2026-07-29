// Privacy boundary for audit results returned by the hosted HTTP and MCP surfaces.
//
// Internal reports remain complete and content-addressed. Public responses are rebuilt
// from an exact allowlist so arbitrary provider/catalog fields in `finding.detail` can
// never cross the boundary by accident. The projection deliberately retains the
// archon.audit-report/v1 wire shape consumed by the hosted UI; it is not the immutable
// internal evidence object and must never be used to verify an internal report digest.

import type { AuditRunResult, AuditTraceStep } from "../ap/loop.js";
import {
  assertAuditReport,
  type AuditReport,
} from "../pipeline/pipeline.js";
import {
  parseModelRuntimeProvenance,
  type ModelRuntimeProvenance,
} from "../llm/provenance.js";
import type { Finding } from "../types.js";

const FINDING_TYPES = new Set([
  "contradiction",
  "lineage_gap",
  "governance_violation",
]);
const SEVERITIES = new Set(["low", "medium", "high"]);
const IMPACTS = new Set(["none", "low", "medium", "high", "critical"]);
const PROVENANCE_STATUSES = new Set(["trusted", "conflicting", "observed"]);
const APPROVAL_RISKS = new Set(["low", "medium", "high"]);
const LOOP_STOP_REASONS = new Set([
  "emitted_findings",
  "no_progress_fallback",
  "max_steps_fallback",
]);
const RFC3339_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/u;

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

const CREDENTIAL_PATTERNS = [
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

export class PublicAuditProjectionError extends Error {
  readonly code = "UNSAFE_PUBLIC_AUDIT_PROJECTION";

  constructor() {
    super("Audit output cannot be represented by the public response contract.");
    this.name = "PublicAuditProjectionError";
  }
}

function invalid(): never {
  throw new PublicAuditProjectionError();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  required: readonly string[] = allowed
): boolean {
  const actual = Object.keys(value);
  return (
    actual.every((key) => allowed.includes(key)) &&
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

function text(value: unknown, maximum: number): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(value)
  ) {
    invalid();
  }
  return value;
}

function count(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 0 ||
    (value as number) > maximum
  ) {
    invalid();
  }
  return value as number;
}

function instant(value: unknown): string {
  const candidate = text(value, 128);
  if (
    !RFC3339_INSTANT.test(candidate) ||
    !Number.isFinite(Date.parse(candidate))
  ) {
    invalid();
  }
  return candidate;
}

function stringArray(
  value: unknown,
  maximumEntries: number,
  maximumText: number
): string[] {
  if (!Array.isArray(value) || value.length > maximumEntries) invalid();
  return value.map((entry) => text(entry, maximumText));
}

function digest(value: unknown): string {
  const candidate = text(value, 256);
  if (!SHA256_DIGEST.test(candidate)) invalid();
  return candidate;
}

function projectBlastRadius(value: unknown): Record<string, unknown> {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "rootUrn",
      "downstream",
      "maxHops",
      "truncated",
      "impact",
    ]) ||
    !Array.isArray(value["downstream"]) ||
    value["downstream"].length > 10_000 ||
    typeof value["truncated"] !== "boolean" ||
    typeof value["impact"] !== "string" ||
    !IMPACTS.has(value["impact"])
  ) {
    invalid();
  }
  const downstream = value["downstream"].map((asset) => {
    if (
      !isRecord(asset) ||
      !hasExactKeys(asset, ["urn", "minHops"])
    ) {
      invalid();
    }
    return {
      urn: text(asset["urn"], 2_048),
      minHops: count(asset["minHops"], 10),
    };
  });
  return {
    rootUrn: text(value["rootUrn"], 2_048),
    downstream,
    maxHops: count(value["maxHops"], 10),
    truncated: value["truncated"],
    impact: value["impact"],
  };
}

function projectProvenance(value: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(value) || value.length > 1_000) invalid();
  return value.map((event) => {
    if (
      !isRecord(event) ||
      !hasExactKeys(
        event,
        ["source", "runId", "observedAt", "actor", "value", "status"],
        ["source", "runId", "observedAt", "status"]
      ) ||
      typeof event["status"] !== "string" ||
      !PROVENANCE_STATUSES.has(event["status"])
    ) {
      invalid();
    }
    // actor/value may contain private catalog values. They are deliberately validated
    // only structurally and then excluded from the public projection.
    if (event["actor"] !== undefined) text(event["actor"], 1_024);
    if (event["value"] !== undefined) text(event["value"], 4_000);
    return {
      source: text(event["source"], 512),
      runId: text(event["runId"], 512),
      observedAt: instant(event["observedAt"]),
      status: event["status"],
    };
  });
}

function projectContradictionProvenance(
  detail: Record<string, unknown>
): Array<Record<string, unknown>> | undefined {
  if (!Array.isArray(detail["values"])) return undefined;
  if (detail["values"].length > 1_000) invalid();
  const resolution = detail["resolution"];
  const recommendedFactId =
    isRecord(resolution) &&
    typeof resolution["recommendedFactId"] === "string"
      ? text(resolution["recommendedFactId"], 512)
      : undefined;
  return detail["values"].map((entry) => {
    if (
      !isRecord(entry) ||
      (entry["source"] !== null && typeof entry["source"] !== "string")
    ) {
      invalid();
    }
    const factId = text(entry["factId"], 512);
    const source = entry["source"];
    return {
      source:
        source === null
          ? "unattributed-source"
          : text(source, 512),
      runId: factId,
      observedAt: instant(entry["createdAt"]),
      status: factId === recommendedFactId ? "trusted" : "conflicting",
    };
  });
}

function projectDossier(value: unknown): Record<string, unknown> {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "dossierId",
      "digest",
      "policyDigest",
      "generatedAt",
      "evidenceCount",
    ])
  ) {
    invalid();
  }
  return {
    dossierId: text(value["dossierId"], 512),
    digest: digest(value["digest"]),
    policyDigest: digest(value["policyDigest"]),
    generatedAt: instant(value["generatedAt"]),
    evidenceCount: count(value["evidenceCount"], 100_000),
  };
}

function projectApproval(value: unknown): Record<string, unknown> {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "approvalId",
      "expiresAt",
      "targetField",
      "proposedTag",
      "before",
      "after",
      "planDigest",
      "risk",
    ]) ||
    typeof value["risk"] !== "string" ||
    !APPROVAL_RISKS.has(value["risk"])
  ) {
    invalid();
  }
  return {
    approvalId: text(value["approvalId"], 512),
    expiresAt: instant(value["expiresAt"]),
    targetField: text(value["targetField"], 1_024),
    proposedTag: text(value["proposedTag"], 2_048),
    before: stringArray(value["before"], 1_000, 2_048),
    after: stringArray(value["after"], 1_000, 2_048),
    planDigest: digest(value["planDigest"]),
    risk: value["risk"],
  };
}

function projectFindingDetail(
  value: Record<string, unknown>
): Record<string, unknown> {
  const detail: Record<string, unknown> = {};
  if (value["ruleId"] !== undefined) {
    detail["ruleId"] = text(value["ruleId"], 128);
  }
  if (value["rule"] !== undefined) {
    detail["rule"] = text(value["rule"], 2_048);
  }
  if (value["attribute"] !== undefined) {
    detail["attribute"] = text(value["attribute"], 512);
  }
  if (value["unclassifiedFields"] !== undefined) {
    detail["unclassifiedFields"] = stringArray(
      value["unclassifiedFields"],
      1_000,
      1_024
    );
  }
  if (value["blastRadius"] !== undefined) {
    detail["blastRadius"] = projectBlastRadius(value["blastRadius"]);
  }
  if (value["provenance"] !== undefined) {
    detail["provenance"] = projectProvenance(value["provenance"]);
  } else {
    const derived = projectContradictionProvenance(value);
    if (derived !== undefined) detail["provenance"] = derived;
  }
  if (value["dossier"] !== undefined) {
    detail["dossier"] = projectDossier(value["dossier"]);
  }
  if (value["approval"] !== undefined) {
    detail["approval"] = projectApproval(value["approval"]);
  }
  return detail;
}

export function projectPublicFinding(finding: Finding): Finding {
  if (
    !FINDING_TYPES.has(finding.type) ||
    !SEVERITIES.has(finding.severity) ||
    !isRecord(finding.detail)
  ) {
    invalid();
  }
  const projected: Finding = {
    type: finding.type,
    severity: finding.severity,
    subject: text(finding.subject, 2_048),
    summary: text(finding.summary, 4_000),
    detail: projectFindingDetail(finding.detail),
    ...(finding.recommendation === undefined
      ? {}
      : { recommendation: text(finding.recommendation, 4_000) }),
  };
  assertPublicOutputSafe(projected);
  return projected;
}

export function assertPublicOutputSafe(value: unknown): void {
  if (typeof value === "string") {
    if (CREDENTIAL_PATTERNS.some((pattern) => pattern.test(value))) invalid();
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(assertPublicOutputSafe);
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    const normalizedKey = key.replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
    if (
      FORBIDDEN_PUBLIC_KEYS.has(normalizedKey) ||
      CREDENTIAL_PATTERNS.some((pattern) => pattern.test(key))
    ) {
      invalid();
    }
    assertPublicOutputSafe(entry);
  }
}

function projectModelProvenance(
  value: ModelRuntimeProvenance
): ModelRuntimeProvenance {
  return parseModelRuntimeProvenance(value);
}

export function projectPublicAuditReport(report: AuditReport): AuditReport {
  assertAuditReport(report);
  const projected: AuditReport = {
    schemaVersion: "archon.audit-report/v1",
    scanId: text(report.scanId, 512),
    classification: {
      totalEntities: count(report.classification.totalEntities),
      withLineage: count(report.classification.withLineage),
      sensitiveEntities: count(report.classification.sensitiveEntities),
      domains: Object.fromEntries(
        Object.entries(report.classification.domains).map(([key, value]) => [
          text(key, 256),
          count(value),
        ])
      ),
      platforms: Object.fromEntries(
        Object.entries(report.classification.platforms).map(([key, value]) => [
          text(key, 256),
          count(value),
        ])
      ),
    },
    findings: report.findings.map(projectPublicFinding),
    narrative: text(report.narrative, 8_000),
    modelProvenance: projectModelProvenance(report.modelProvenance),
    trace: report.trace.map((step) => ({
      agent: text(step.agent, 128),
      produced: text(step.produced, 2_000),
    })),
  };
  assertPublicOutputSafe(projected);
  return projected;
}

function projectLoopTrace(step: AuditTraceStep): AuditTraceStep {
  return {
    step: count(step.step, 12),
    tool: text(step.tool, 128),
    observation: text(step.observation, 2_000),
  };
}

export function projectPublicAuditRunResult(
  result: AuditRunResult
): AuditRunResult {
  if (
    result.disposition !== "pending" ||
    !LOOP_STOP_REASONS.has(result.stopReason) ||
    !Array.isArray(result.findings) ||
    result.findings.length > 10_000 ||
    !Array.isArray(result.trace) ||
    result.trace.length > 12 ||
    !Array.isArray(result.modelProvenance) ||
    result.modelProvenance.length > 12
  ) {
    invalid();
  }
  const projected: AuditRunResult = {
    disposition: "pending",
    findings: result.findings.map(projectPublicFinding),
    trace: result.trace.map(projectLoopTrace),
    modelProvenance: result.modelProvenance.map(projectModelProvenance),
    stopReason: result.stopReason,
  };
  assertPublicOutputSafe(projected);
  return projected;
}
