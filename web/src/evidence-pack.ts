import type {
  ControlLoopResult,
  ControlLoopStatus,
  Finding,
  LoadedAudit,
} from "./types";

export type BrowserDigest = `sha256:${string}`;

export interface EvidencePackFile {
  path: string;
  mediaType: string;
  bytes: number;
  sha256: BrowserDigest;
  content: string;
}

interface EvidencePackSource {
  requestId: string;
  releaseSha: string;
  scanId: string;
  sourceKind: "fixture" | "live";
}

export interface PublicAuditProjection {
  schemaVersion: "archon.browser-audit-projection/v1";
  source: EvidencePackSource;
  classification: {
    totalEntities: number;
    withLineage: number;
    sensitiveEntities: number;
    domains: Record<string, number>;
    platforms: Record<string, number>;
  };
  findings: PublicFindingProjection[];
  narrative: string;
}

export interface PublicFindingProjection {
  ruleId: string;
  type: Finding["type"];
  severity: Finding["severity"];
  subject: string;
  summary: string;
  recommendation: string | null;
  evidence: {
    rule: string | null;
    attribute: string | null;
    unclassifiedFields: string[];
    blastRadius: {
      rootUrn: string;
      downstream: Array<{ urn: string; minHops: number }>;
      maxHops: number;
      truncated: boolean;
      impact: "none" | "low" | "medium" | "high" | "critical";
    } | null;
    provenance: Array<{
      source: string;
      runId: string;
      observedAt: string;
      status: "trusted" | "conflicting" | "observed";
    }>;
    dossier: {
      dossierId: string;
      digest: string;
      policyDigest: string;
      generatedAt: string;
      evidenceCount: number;
    } | null;
    approval: {
      approvalId: string;
      expiresAt: string;
      targetField: string;
      proposedTag: string;
      before: string[];
      after: string[];
      planDigest: string;
      risk: "low" | "medium" | "high";
    } | null;
  };
}

interface PublicTerminalProjection {
  schemaVersion: "archon.browser-terminal-projection/v1";
  auditId: string;
  releaseSha: string;
  lifecycle: "SUCCEEDED";
  result: ControlLoopResult;
}

export interface EvidencePackManifest {
  schemaVersion: "archon.browser-evidence-pack/v1";
  evidenceClass:
    | "SYNTHETIC_SHOWCASE_FIXTURE"
    | "LIVE_ALLOWLISTED_PROJECTION";
  integrity: {
    model: "SELF_CONSISTENCY_ONLY";
    authenticityClaimed: false;
    sourceBinding: "INTERNAL_FIELDS_CONSISTENT";
  };
  source: EvidencePackSource;
  claims: {
    projectionPolicy: "EXACT_PUBLIC_ALLOWLIST_V1";
    credentialHandling: "SCHEMA_EXCLUDED_AND_PATTERN_REJECTED";
    includesRawOrchestrationState: false;
    includesPrivateEvidenceObjects: false;
  };
  summary: {
    entities: number;
    findings: number;
    contradictions: number;
    lineageGaps: number;
    governanceViolations: number;
    terminalOutcome:
      | "NOT_AVAILABLE"
      | "READ_ONLY_COMPLETE"
      | "VERIFIED"
      | "REJECTED";
  };
  files: Array<{
    path: string;
    mediaType: string;
    bytes: number;
    sha256: BrowserDigest;
  }>;
}

export interface EvidencePackVerification {
  valid: boolean;
  checks: Array<{
    checkId:
      | "MANIFEST_SCHEMA_VALID"
      | "MANIFEST_DIGEST_VALID"
      | "FILE_SET_EXACT"
      | "FILE_DIGESTS_VALID"
      | "PUBLIC_PROJECTION_VALID"
      | "TERMINAL_PROJECTION_VALID"
      | "SUMMARY_CONSISTENT"
      | "SOURCE_FIELDS_CONSISTENT"
      | "PRIVACY_SCAN_VALID";
    passed: boolean;
  }>;
}

export interface BrowserEvidencePack {
  manifest: EvidencePackManifest;
  manifestDigest: BrowserDigest;
  files: EvidencePackFile[];
  verification: EvidencePackVerification;
}

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const RULE_ID_PATTERN = /^ARCHON-[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_PACK_BYTES = 8 * 1024 * 1024;
const BASE_FILE_CONTRACT = [
  { path: "audit/report.json", mediaType: "application/json" },
  { path: "audit/report.md", mediaType: "text/markdown" },
  { path: "audit/report.sarif", mediaType: "application/sarif+json" },
] as const;
const TERMINAL_FILE_CONTRACT = {
  path: "control/terminal-proof.json",
  mediaType: "application/json",
} as const;
const MANIFEST_FILE_CONTRACT = {
  path: "manifest.json",
  mediaType: "application/json",
} as const;
const VERIFICATION_CHECK_IDS = [
  "TARGET_UNCHANGED",
  "PREEXISTING_TAGS_PRESERVED",
  "POLICY_TAG_PRESENT",
  "NO_UNEXPECTED_TAGS",
  "APPROVAL_BINDING_VALID",
] as const;

const FORBIDDEN_EXPORT_KEYS = new Set([
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
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/u,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/u,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/u,
  /\bAIza[0-9A-Za-z_-]{35}\b/u,
  /\b(?:Bearer\s+|sk-(?:ant-)?)[A-Za-z0-9._~+/=-]{12,}\b/iu,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/u,
  /\b(?:api[_ -]?key|password|passwd|pwd|secret|token)\s*[:=]\s*["']?[^\s"',;]{8,}/iu,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function isDigest(value: unknown): value is BrowserDigest {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isNumberRecord(value: unknown): value is Record<string, number> {
  return (
    isRecord(value) &&
    Object.values(value).every((entry) => isCount(entry))
  );
}

function assertExportSafe(value: unknown, path: string): void {
  if (typeof value === "string") {
    if (CREDENTIAL_PATTERNS.some((pattern) => pattern.test(value))) {
      throw new Error(
        `Evidence export rejected a credential-shaped value at ${path}.`,
      );
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      assertExportSafe(entry, `${path}[${index}]`),
    );
    return;
  }
  if (typeof value !== "object" || value === null) return;
  for (const [key, entry] of Object.entries(value)) {
    const normalizedKey = key.replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
    if (FORBIDDEN_EXPORT_KEYS.has(normalizedKey)) {
      throw new Error(
        `Evidence export rejected a forbidden field at ${path}.${key}.`,
      );
    }
    if (CREDENTIAL_PATTERNS.some((pattern) => pattern.test(key))) {
      throw new Error(
        `Evidence export rejected a credential-shaped key at ${path}.${key}.`,
      );
    }
    assertExportSafe(entry, `${path}.${key}`);
  }
}

function normalize(value: unknown, ancestors: Set<object>): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Evidence contains a non-finite number.");
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (
    value === undefined ||
    typeof value === "bigint" ||
    typeof value === "function" ||
    typeof value === "symbol"
  ) {
    throw new Error("Evidence contains a value that cannot be canonicalized.");
  }
  if (typeof value !== "object" || value === null) {
    throw new Error("Evidence contains a value that cannot be canonicalized.");
  }
  if (ancestors.has(value)) {
    throw new Error("Circular evidence cannot be canonicalized.");
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((entry) => normalize(entry, ancestors));
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("Evidence must contain only plain JSON objects.");
    }
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) =>
          left < right ? -1 : left > right ? 1 : 0,
        )
        .map(([key, entry]) => [key, normalize(entry, ancestors)]),
    );
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value, new Set<object>()));
}

export async function sha256(value: string): Promise<BrowserDigest> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto SHA-256 is unavailable in this browser.");
  }
  const bytes = new TextEncoder().encode(value);
  const result = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  const hex = [...new Uint8Array(result)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}

function findingRuleId(finding: Finding): string {
  return typeof finding.detail.ruleId === "string"
    ? `ARCHON-${finding.detail.ruleId}`
    : `ARCHON-${finding.type.toUpperCase().replaceAll("_", "-")}`;
}

function sortedNumberRecord(
  value: Record<string, number>,
): Record<string, number> {
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => compareText(left, right)),
  );
}

function projectFinding(finding: Finding): PublicFindingProjection {
  const blast = finding.detail.blastRadius;
  const provenance = finding.detail.provenance ?? [];
  const dossier = finding.detail.dossier;
  const approval = finding.detail.approval;
  return {
    ruleId: findingRuleId(finding),
    type: finding.type,
    severity: finding.severity,
    subject: finding.subject,
    summary: finding.summary,
    recommendation: finding.recommendation ?? null,
    evidence: {
      rule:
        typeof finding.detail.rule === "string"
          ? finding.detail.rule
          : null,
      attribute:
        typeof finding.detail.attribute === "string"
          ? finding.detail.attribute
          : null,
      unclassifiedFields: [
        ...(finding.detail.unclassifiedFields ?? []),
      ].sort(),
      blastRadius: blast
        ? {
            rootUrn: blast.rootUrn,
            downstream: [...blast.downstream]
              .map((asset) => ({
                urn: asset.urn,
                minHops: asset.minHops,
              }))
              .sort(
                (left, right) =>
                  left.minHops - right.minHops ||
                  compareText(left.urn, right.urn),
              ),
            maxHops: blast.maxHops,
            truncated: blast.truncated,
            impact: blast.impact,
          }
        : null,
      provenance: provenance
        .map((event) => ({
          source: event.source,
          runId: event.runId,
          observedAt: event.observedAt,
          status: event.status,
        }))
        .sort(
          (left, right) =>
            compareText(left.observedAt, right.observedAt) ||
            compareText(left.source, right.source) ||
            compareText(left.runId, right.runId),
        ),
      dossier: dossier
        ? {
            dossierId: dossier.dossierId,
            digest: dossier.digest,
            policyDigest: dossier.policyDigest,
            generatedAt: dossier.generatedAt,
            evidenceCount: dossier.evidenceCount,
          }
        : null,
      approval: approval
        ? {
            approvalId: approval.approvalId,
            expiresAt: approval.expiresAt,
            targetField: approval.targetField,
            proposedTag: approval.proposedTag,
            before: [...approval.before].sort(),
            after: [...approval.after].sort(),
            planDigest: approval.planDigest,
            risk: approval.risk,
          }
        : null,
    },
  };
}

function projectAudit(audit: LoadedAudit): PublicAuditProjection {
  const report = audit.envelope.report;
  const findings = report.findings
    .map(projectFinding)
    .sort(
      (left, right) =>
        compareText(left.ruleId, right.ruleId) ||
        compareText(left.subject, right.subject) ||
        compareText(left.summary, right.summary),
    );
  return {
    schemaVersion: "archon.browser-audit-projection/v1",
    source: {
      requestId: audit.envelope.requestId,
      releaseSha: audit.envelope.releaseSha,
      scanId: report.scanId,
      sourceKind: audit.source,
    },
    classification: {
      totalEntities: report.classification.totalEntities,
      withLineage: report.classification.withLineage,
      sensitiveEntities: report.classification.sensitiveEntities,
      domains: sortedNumberRecord(report.classification.domains),
      platforms: sortedNumberRecord(report.classification.platforms),
    },
    findings,
    narrative: report.narrative,
  };
}

function projectTerminal(
  status: ControlLoopStatus | undefined,
): PublicTerminalProjection | undefined {
  if (!status?.result) return undefined;
  if (status.status !== "SUCCEEDED" || !status.releaseSha) {
    throw new Error(
      "Terminal evidence is unavailable without a succeeded, release-bound status.",
    );
  }
  const result: ControlLoopResult =
    status.result.outcome === "READ_ONLY_COMPLETE"
      ? { outcome: "READ_ONLY_COMPLETE" }
      : {
          outcome: status.result.outcome,
          receiptDigest: status.result.receiptDigest,
          executionEvidenceDigest: status.result.executionEvidenceDigest,
          completedAt: status.result.completedAt,
          verification: {
            checks: status.result.verification.checks.map((check) => ({
              checkId: check.checkId,
              passed: true,
            })),
            eventCount: status.result.verification.eventCount,
            rollbackAvailability:
              status.result.verification.rollbackAvailability,
          },
        };
  return {
    schemaVersion: "archon.browser-terminal-projection/v1",
    auditId: status.auditId,
    releaseSha: status.releaseSha,
    lifecycle: "SUCCEEDED",
    result,
  };
}

function assertStatusMatchesAudit(
  audit: LoadedAudit,
  status: ControlLoopStatus | undefined,
): void {
  if (!status) return;
  if (status.auditId !== audit.envelope.requestId) {
    throw new Error("Control-loop status does not match the audit request.");
  }
  if (
    status.releaseSha !== undefined &&
    status.releaseSha !== audit.envelope.releaseSha
  ) {
    throw new Error("Control-loop status does not match the audit release.");
  }
  if (
    status.report !== undefined &&
    (status.report.scanId !== audit.envelope.report.scanId ||
      canonicalJson(status.report) !==
        canonicalJson(audit.envelope.report))
  ) {
    throw new Error("Control-loop status does not match the audit report.");
  }
}

function markdownText(value: unknown): string {
  return String(value)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/gu, " ")
    .replaceAll("\\", "\\\\")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("|", "\\|")
    .replaceAll("`", "'")
    .replaceAll("[", "\\[")
    .replaceAll("]", "\\]")
    .replaceAll("\r", " ")
    .replaceAll("\n", " ");
}

function reportMarkdown(report: PublicAuditProjection): string {
  const lines = [
    "# Archon DataHub audit",
    "",
    `- Request: \`${markdownText(report.source.requestId)}\``,
    `- Release: \`${markdownText(report.source.releaseSha)}\``,
    `- Scan: \`${markdownText(report.source.scanId)}\``,
    `- Findings: ${report.findings.length}`,
    `- Entities: ${report.classification.totalEntities}`,
    "",
    "## Findings",
    "",
    "| Severity | Rule | Type | Subject | Finding | Downstream |",
    "|---|---|---|---|---|---:|",
  ];
  for (const finding of report.findings) {
    const blast = finding.evidence.blastRadius;
    lines.push(
      `| ${finding.severity} | ${markdownText(finding.ruleId)} | ${finding.type} | \`${markdownText(finding.subject)}\` | ${markdownText(finding.summary)} | ${blast ? `${blast.downstream.length}${blast.truncated ? "+" : ""}` : "0"} |`,
    );
  }
  lines.push("", "## Executive summary", "", markdownText(report.narrative), "");
  return lines.join("\n");
}

async function reportSarif(report: PublicAuditProjection): Promise<string> {
  const rules = new Map<string, PublicFindingProjection>();
  for (const finding of report.findings) rules.set(finding.ruleId, finding);
  const results = await Promise.all(
    report.findings.map(async (finding) => ({
      ruleId: finding.ruleId,
      level:
        finding.severity === "high"
          ? ("error" as const)
          : finding.severity === "medium"
            ? ("warning" as const)
            : ("note" as const),
      message: { text: finding.summary },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: `datahub://entity/${encodeURIComponent(finding.subject)}`,
            },
          },
        },
      ],
      partialFingerprints: {
        archonFindingDigest: (
          await sha256(canonicalJson(finding))
        ).slice("sha256:".length),
      },
      properties: {
        findingType: finding.type,
        severity: finding.severity,
        subject: finding.subject,
        evidence: finding.evidence,
      },
    })),
  );
  return `${JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "Archon-DataHub",
              version: "0.1.0",
              informationUri: "https://github.com/upgradedev/archon-datahub",
              rules: [...rules]
                .sort(([left], [right]) => compareText(left, right))
                .map(([id, finding]) => ({
                  id,
                  name: finding.type,
                  shortDescription: { text: finding.summary },
                })),
            },
          },
          results,
        },
      ],
    },
    null,
    2,
  )}\n`;
}

async function makeFile(
  path: string,
  mediaType: string,
  content: string,
): Promise<EvidencePackFile> {
  const bytes = new TextEncoder().encode(content).byteLength;
  if (bytes === 0 || bytes > MAX_FILE_BYTES) {
    throw new Error(`Evidence file ${path} exceeds the browser export limit.`);
  }
  return {
    path,
    mediaType,
    bytes,
    sha256: await sha256(content),
    content,
  };
}

function isPublicBlastRadius(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "rootUrn",
      "downstream",
      "maxHops",
      "truncated",
      "impact",
    ]) &&
    isNonEmptyString(value.rootUrn) &&
    Array.isArray(value.downstream) &&
    value.downstream.every(
      (asset) =>
        isRecord(asset) &&
        hasExactKeys(asset, ["urn", "minHops"]) &&
        isNonEmptyString(asset.urn) &&
        isCount(asset.minHops),
    ) &&
    isCount(value.maxHops) &&
    typeof value.truncated === "boolean" &&
    ["none", "low", "medium", "high", "critical"].includes(
      String(value.impact),
    )
  );
}

function isPublicFinding(value: unknown): value is PublicFindingProjection {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "ruleId",
      "type",
      "severity",
      "subject",
      "summary",
      "recommendation",
      "evidence",
    ]) ||
    !isNonEmptyString(value.ruleId) ||
    !RULE_ID_PATTERN.test(value.ruleId) ||
    !["contradiction", "lineage_gap", "governance_violation"].includes(
      String(value.type),
    ) ||
    !["high", "medium", "low"].includes(String(value.severity)) ||
    !isNonEmptyString(value.subject) ||
    typeof value.summary !== "string" ||
    (value.recommendation !== null &&
      typeof value.recommendation !== "string") ||
    !isRecord(value.evidence) ||
    !hasExactKeys(value.evidence, [
      "rule",
      "attribute",
      "unclassifiedFields",
      "blastRadius",
      "provenance",
      "dossier",
      "approval",
    ])
  ) {
    return false;
  }
  const evidence = value.evidence;
  if (
    (evidence.rule !== null && typeof evidence.rule !== "string") ||
    (evidence.attribute !== null &&
      typeof evidence.attribute !== "string") ||
    !Array.isArray(evidence.unclassifiedFields) ||
    !evidence.unclassifiedFields.every((entry) => typeof entry === "string") ||
    (evidence.blastRadius !== null &&
      !isPublicBlastRadius(evidence.blastRadius)) ||
    !Array.isArray(evidence.provenance) ||
    !evidence.provenance.every(
      (event) =>
        isRecord(event) &&
        hasExactKeys(event, ["source", "runId", "observedAt", "status"]) &&
        isNonEmptyString(event.source) &&
        isNonEmptyString(event.runId) &&
        isNonEmptyString(event.observedAt) &&
        ["trusted", "conflicting", "observed"].includes(String(event.status)),
    )
  ) {
    return false;
  }
  if (
    evidence.dossier !== null &&
    (!isRecord(evidence.dossier) ||
      !hasExactKeys(evidence.dossier, [
        "dossierId",
        "digest",
        "policyDigest",
        "generatedAt",
        "evidenceCount",
      ]) ||
      !isNonEmptyString(evidence.dossier.dossierId) ||
      !isDigest(evidence.dossier.digest) ||
      !isDigest(evidence.dossier.policyDigest) ||
      !isNonEmptyString(evidence.dossier.generatedAt) ||
      !isCount(evidence.dossier.evidenceCount))
  ) {
    return false;
  }
  if (evidence.approval !== null) {
    if (
      !isRecord(evidence.approval) ||
      !hasExactKeys(evidence.approval, [
        "approvalId",
        "expiresAt",
        "targetField",
        "proposedTag",
        "before",
        "after",
        "planDigest",
        "risk",
      ]) ||
      !isNonEmptyString(evidence.approval.approvalId) ||
      !isNonEmptyString(evidence.approval.expiresAt) ||
      !isNonEmptyString(evidence.approval.targetField) ||
      !isNonEmptyString(evidence.approval.proposedTag) ||
      !Array.isArray(evidence.approval.before) ||
      !evidence.approval.before.every((entry) => typeof entry === "string") ||
      !Array.isArray(evidence.approval.after) ||
      !evidence.approval.after.every((entry) => typeof entry === "string") ||
      !isDigest(evidence.approval.planDigest) ||
      !["low", "medium", "high"].includes(String(evidence.approval.risk))
    ) {
      return false;
    }
  }
  return true;
}

function isEvidenceSource(value: unknown): value is EvidencePackSource {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "requestId",
      "releaseSha",
      "scanId",
      "sourceKind",
    ]) &&
    isNonEmptyString(value.requestId) &&
    isNonEmptyString(value.releaseSha) &&
    isNonEmptyString(value.scanId) &&
    (value.sourceKind === "fixture" || value.sourceKind === "live")
  );
}

function isPublicAuditProjection(
  value: unknown,
): value is PublicAuditProjection {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "schemaVersion",
      "source",
      "classification",
      "findings",
      "narrative",
    ]) &&
    value.schemaVersion === "archon.browser-audit-projection/v1" &&
    isEvidenceSource(value.source) &&
    isRecord(value.classification) &&
    hasExactKeys(value.classification, [
      "totalEntities",
      "withLineage",
      "sensitiveEntities",
      "domains",
      "platforms",
    ]) &&
    isCount(value.classification.totalEntities) &&
    isCount(value.classification.withLineage) &&
    isCount(value.classification.sensitiveEntities) &&
    isNumberRecord(value.classification.domains) &&
    isNumberRecord(value.classification.platforms) &&
    Array.isArray(value.findings) &&
    value.findings.every(isPublicFinding) &&
    typeof value.narrative === "string"
  );
}

function isVerificationResult(value: unknown): boolean {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "checks",
      "eventCount",
      "rollbackAvailability",
    ]) ||
    !Array.isArray(value.checks) ||
    !isCount(value.eventCount)
  ) {
    return false;
  }
  return value.checks.every(
    (check, index) =>
      isRecord(check) &&
      hasExactKeys(check, ["checkId", "passed"]) &&
      check.checkId === VERIFICATION_CHECK_IDS[index] &&
      check.passed === true,
  );
}

function isPublicTerminalProjection(
  value: unknown,
): value is PublicTerminalProjection {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "schemaVersion",
      "auditId",
      "releaseSha",
      "lifecycle",
      "result",
    ]) ||
    value.schemaVersion !== "archon.browser-terminal-projection/v1" ||
    !isNonEmptyString(value.auditId) ||
    !isNonEmptyString(value.releaseSha) ||
    value.lifecycle !== "SUCCEEDED" ||
    !isRecord(value.result)
  ) {
    return false;
  }
  if (value.result.outcome === "READ_ONLY_COMPLETE") {
    return hasExactKeys(value.result, ["outcome"]);
  }
  if (
    !["VERIFIED", "REJECTED"].includes(String(value.result.outcome)) ||
    !hasExactKeys(value.result, [
      "outcome",
      "receiptDigest",
      "executionEvidenceDigest",
      "completedAt",
      "verification",
    ]) ||
    !isDigest(value.result.receiptDigest) ||
    !isDigest(value.result.executionEvidenceDigest) ||
    !isNonEmptyString(value.result.completedAt) ||
    !isVerificationResult(value.result.verification)
  ) {
    return false;
  }
  const verification = value.result.verification as Record<string, unknown>;
  if (value.result.outcome === "VERIFIED") {
    return (
      Array.isArray(verification.checks) &&
      verification.checks.length === 5 &&
      verification.eventCount === 7 &&
      verification.rollbackAvailability === "ELIGIBLE"
    );
  }
  return (
    Array.isArray(verification.checks) &&
    verification.checks.length === 0 &&
    verification.eventCount === 5 &&
    verification.rollbackAvailability === "NOT_APPLICABLE"
  );
}

function isManifestFile(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["path", "mediaType", "bytes", "sha256"]) &&
    isNonEmptyString(value.path) &&
    isNonEmptyString(value.mediaType) &&
    isCount(value.bytes) &&
    Number(value.bytes) > 0 &&
    Number(value.bytes) <= MAX_FILE_BYTES &&
    isDigest(value.sha256)
  );
}

function isEvidencePackManifest(
  value: unknown,
): value is EvidencePackManifest {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "schemaVersion",
      "evidenceClass",
      "integrity",
      "source",
      "claims",
      "summary",
      "files",
    ]) &&
    value.schemaVersion === "archon.browser-evidence-pack/v1" &&
    [
      "SYNTHETIC_SHOWCASE_FIXTURE",
      "LIVE_ALLOWLISTED_PROJECTION",
    ].includes(String(value.evidenceClass)) &&
    isRecord(value.integrity) &&
    hasExactKeys(value.integrity, [
      "model",
      "authenticityClaimed",
      "sourceBinding",
    ]) &&
    value.integrity.model === "SELF_CONSISTENCY_ONLY" &&
    value.integrity.authenticityClaimed === false &&
    value.integrity.sourceBinding === "INTERNAL_FIELDS_CONSISTENT" &&
    isEvidenceSource(value.source) &&
    value.evidenceClass ===
      (value.source.sourceKind === "live"
        ? "LIVE_ALLOWLISTED_PROJECTION"
        : "SYNTHETIC_SHOWCASE_FIXTURE") &&
    isRecord(value.claims) &&
    hasExactKeys(value.claims, [
      "projectionPolicy",
      "credentialHandling",
      "includesRawOrchestrationState",
      "includesPrivateEvidenceObjects",
    ]) &&
    value.claims.projectionPolicy === "EXACT_PUBLIC_ALLOWLIST_V1" &&
    value.claims.credentialHandling ===
      "SCHEMA_EXCLUDED_AND_PATTERN_REJECTED" &&
    value.claims.includesRawOrchestrationState === false &&
    value.claims.includesPrivateEvidenceObjects === false &&
    isRecord(value.summary) &&
    hasExactKeys(value.summary, [
      "entities",
      "findings",
      "contradictions",
      "lineageGaps",
      "governanceViolations",
      "terminalOutcome",
    ]) &&
    isCount(value.summary.entities) &&
    isCount(value.summary.findings) &&
    isCount(value.summary.contradictions) &&
    isCount(value.summary.lineageGaps) &&
    isCount(value.summary.governanceViolations) &&
    [
      "NOT_AVAILABLE",
      "READ_ONLY_COMPLETE",
      "VERIFIED",
      "REJECTED",
    ].includes(String(value.summary.terminalOutcome)) &&
    Array.isArray(value.files) &&
    value.files.every(isManifestFile)
  );
}

function isEvidencePackFile(value: unknown): value is EvidencePackFile {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "path",
      "mediaType",
      "bytes",
      "sha256",
      "content",
    ]) &&
    isNonEmptyString(value.path) &&
    isNonEmptyString(value.mediaType) &&
    isCount(value.bytes) &&
    Number(value.bytes) > 0 &&
    Number(value.bytes) <= MAX_FILE_BYTES &&
    isDigest(value.sha256) &&
    typeof value.content === "string"
  );
}

function expectedFileContract(
  terminalOutcome: EvidencePackManifest["summary"]["terminalOutcome"],
) {
  return terminalOutcome === "NOT_AVAILABLE"
    ? [...BASE_FILE_CONTRACT]
    : [...BASE_FILE_CONTRACT, TERMINAL_FILE_CONTRACT];
}

function summaryFor(
  report: PublicAuditProjection,
  terminal: PublicTerminalProjection | undefined,
): EvidencePackManifest["summary"] {
  return {
    entities: report.classification.totalEntities,
    findings: report.findings.length,
    contradictions: report.findings.filter(
      (finding) => finding.type === "contradiction",
    ).length,
    lineageGaps: report.findings.filter(
      (finding) => finding.type === "lineage_gap",
    ).length,
    governanceViolations: report.findings.filter(
      (finding) => finding.type === "governance_violation",
    ).length,
    terminalOutcome: terminal?.result.outcome ?? "NOT_AVAILABLE",
  };
}

export async function buildBrowserEvidencePack(
  audit: LoadedAudit,
  status?: ControlLoopStatus,
): Promise<BrowserEvidencePack> {
  assertStatusMatchesAudit(audit, status);
  const report = projectAudit(audit);
  const terminal = projectTerminal(status);
  if (!isPublicAuditProjection(report)) {
    throw new Error("The public audit projection is invalid.");
  }
  if (terminal && !isPublicTerminalProjection(terminal)) {
    throw new Error("The public terminal projection is invalid.");
  }
  assertExportSafe(report, "report");
  if (terminal) assertExportSafe(terminal, "terminal");

  const artifacts = [
    await makeFile(
      "audit/report.json",
      "application/json",
      `${JSON.stringify(report, null, 2)}\n`,
    ),
    await makeFile("audit/report.md", "text/markdown", reportMarkdown(report)),
    await makeFile(
      "audit/report.sarif",
      "application/sarif+json",
      await reportSarif(report),
    ),
  ];
  if (terminal) {
    artifacts.push(
      await makeFile(
        TERMINAL_FILE_CONTRACT.path,
        TERMINAL_FILE_CONTRACT.mediaType,
        `${JSON.stringify(terminal, null, 2)}\n`,
      ),
    );
  }
  artifacts.sort((left, right) => compareText(left.path, right.path));
  if (
    artifacts.reduce((total, artifact) => total + artifact.bytes, 0) >
    MAX_PACK_BYTES
  ) {
    throw new Error("The browser evidence pack exceeds its total size limit.");
  }

  const manifest: EvidencePackManifest = {
    schemaVersion: "archon.browser-evidence-pack/v1",
    evidenceClass:
      audit.source === "live"
        ? "LIVE_ALLOWLISTED_PROJECTION"
        : "SYNTHETIC_SHOWCASE_FIXTURE",
    integrity: {
      model: "SELF_CONSISTENCY_ONLY",
      authenticityClaimed: false,
      sourceBinding: "INTERNAL_FIELDS_CONSISTENT",
    },
    source: { ...report.source },
    claims: {
      projectionPolicy: "EXACT_PUBLIC_ALLOWLIST_V1",
      credentialHandling: "SCHEMA_EXCLUDED_AND_PATTERN_REJECTED",
      includesRawOrchestrationState: false,
      includesPrivateEvidenceObjects: false,
    },
    summary: summaryFor(report, terminal),
    files: artifacts.map(({ path, mediaType, bytes, sha256: fileDigest }) => ({
      path,
      mediaType,
      bytes,
      sha256: fileDigest,
    })),
  };
  const manifestDigest = await sha256(canonicalJson(manifest));
  const provisional: BrowserEvidencePack = {
    manifest,
    manifestDigest,
    files: artifacts,
    verification: { valid: false, checks: [] },
  };
  const verification = await verifyBrowserEvidencePack(provisional);
  if (!verification.valid) {
    throw new Error("The generated browser evidence pack failed verification.");
  }
  return {
    ...provisional,
    verification,
  };
}

export async function verifyBrowserEvidencePack(
  pack: Omit<BrowserEvidencePack, "verification"> | BrowserEvidencePack,
): Promise<EvidencePackVerification> {
  let manifestSchemaValid = false;
  let manifestDigestValid = false;
  let fileSetExact = false;
  let fileDigestsValid = false;
  let publicProjectionValid = false;
  let terminalProjectionValid = false;
  let summaryConsistent = false;
  let sourceFieldsConsistent = false;
  let privacyScanValid = false;

  try {
    const candidate = pack as unknown;
    if (!isRecord(candidate)) throw new Error("Pack must be an object.");
    const manifest = candidate.manifest;
    const files = candidate.files;
    const manifestDigest = candidate.manifestDigest;
    if (!isEvidencePackManifest(manifest) || !Array.isArray(files)) {
      throw new Error("Pack manifest is invalid.");
    }
    manifestSchemaValid = true;
    const actualFilesValid = files.every(isEvidencePackFile);
    if (!actualFilesValid) throw new Error("Pack files are invalid.");
    const typedFiles = files as EvidencePackFile[];
    manifestDigestValid =
      isDigest(manifestDigest) &&
      (await sha256(canonicalJson(manifest))) === manifestDigest;

    const contract = expectedFileContract(manifest.summary.terminalOutcome);
    fileSetExact =
      typedFiles.length === contract.length &&
      manifest.files.length === contract.length &&
      typedFiles.every(
        (file, index) =>
          file.path === contract[index]?.path &&
          file.mediaType === contract[index]?.mediaType &&
          manifest.files[index]?.path === contract[index]?.path &&
          manifest.files[index]?.mediaType === contract[index]?.mediaType,
      );

    if (fileSetExact) {
      const digestChecks = await Promise.all(
        typedFiles.map(async (file, index) => {
          const manifestFile = manifest.files[index];
          const actualBytes = new TextEncoder().encode(file.content).byteLength;
          return (
            manifestFile !== undefined &&
            file.bytes === actualBytes &&
            manifestFile.bytes === actualBytes &&
            manifestFile.sha256 === file.sha256 &&
            (await sha256(file.content)) === file.sha256
          );
        }),
      );
      fileDigestsValid =
        digestChecks.every(Boolean) &&
        typedFiles.reduce((total, file) => total + file.bytes, 0) <=
          MAX_PACK_BYTES;
    }

    const reportJsonFile = typedFiles.find(
      (file) => file.path === "audit/report.json",
    );
    const reportMarkdownFile = typedFiles.find(
      (file) => file.path === "audit/report.md",
    );
    const reportSarifFile = typedFiles.find(
      (file) => file.path === "audit/report.sarif",
    );
    let report: PublicAuditProjection | undefined;
    if (reportJsonFile && reportMarkdownFile && reportSarifFile) {
      const parsed: unknown = JSON.parse(reportJsonFile.content);
      if (isPublicAuditProjection(parsed)) {
        report = parsed;
        publicProjectionValid =
          reportJsonFile.content === `${JSON.stringify(parsed, null, 2)}\n` &&
          reportMarkdownFile.content === reportMarkdown(parsed) &&
          reportSarifFile.content === (await reportSarif(parsed));
      }
    }

    const expectsTerminal =
      manifest.summary.terminalOutcome !== "NOT_AVAILABLE";
    let terminal: PublicTerminalProjection | undefined;
    if (expectsTerminal) {
      const terminalFile = typedFiles.find(
        (file) => file.path === TERMINAL_FILE_CONTRACT.path,
      );
      if (terminalFile) {
        const parsed: unknown = JSON.parse(terminalFile.content);
        if (isPublicTerminalProjection(parsed)) {
          terminal = parsed;
          terminalProjectionValid =
            terminalFile.content === `${JSON.stringify(parsed, null, 2)}\n` &&
            parsed.result.outcome === manifest.summary.terminalOutcome;
        }
      }
    } else {
      terminalProjectionValid = true;
    }

    if (report && publicProjectionValid && terminalProjectionValid) {
      summaryConsistent =
        canonicalJson(summaryFor(report, terminal)) ===
        canonicalJson(manifest.summary);
      sourceFieldsConsistent =
        canonicalJson(report.source) === canonicalJson(manifest.source) &&
        (!terminal ||
          (terminal.auditId === manifest.source.requestId &&
            terminal.releaseSha === manifest.source.releaseSha));
      try {
        assertExportSafe(report, "report");
        if (terminal) assertExportSafe(terminal, "terminal");
        privacyScanValid = true;
      } catch {
        privacyScanValid = false;
      }
    }
  } catch {
    // A verifier returns named failed checks for malformed or unverifiable packs.
  }

  const checks: EvidencePackVerification["checks"] = [
    { checkId: "MANIFEST_SCHEMA_VALID", passed: manifestSchemaValid },
    { checkId: "MANIFEST_DIGEST_VALID", passed: manifestDigestValid },
    { checkId: "FILE_SET_EXACT", passed: fileSetExact },
    { checkId: "FILE_DIGESTS_VALID", passed: fileDigestsValid },
    { checkId: "PUBLIC_PROJECTION_VALID", passed: publicProjectionValid },
    { checkId: "TERMINAL_PROJECTION_VALID", passed: terminalProjectionValid },
    { checkId: "SUMMARY_CONSISTENT", passed: summaryConsistent },
    {
      checkId: "SOURCE_FIELDS_CONSISTENT",
      passed: sourceFieldsConsistent,
    },
    { checkId: "PRIVACY_SCAN_VALID", passed: privacyScanValid },
  ];
  return { valid: checks.every((check) => check.passed), checks };
}

export async function manifestFile(
  pack: BrowserEvidencePack,
): Promise<EvidencePackFile> {
  const verification = await verifyBrowserEvidencePack(pack);
  if (!verification.valid) {
    throw new Error("An invalid evidence pack cannot produce a manifest.");
  }
  const content = `${JSON.stringify(
    {
      ...pack.manifest,
      digest: pack.manifestDigest,
    },
    null,
    2,
  )}\n`;
  return makeFile(
    MANIFEST_FILE_CONTRACT.path,
    MANIFEST_FILE_CONTRACT.mediaType,
    content,
  );
}

export async function downloadEvidenceFile(
  file: EvidencePackFile,
  mayDownload: () => boolean = () => true,
): Promise<void> {
  if (!isEvidencePackFile(file)) {
    throw new Error("The requested evidence download is invalid.");
  }
  const allowed = [
    ...BASE_FILE_CONTRACT,
    TERMINAL_FILE_CONTRACT,
    MANIFEST_FILE_CONTRACT,
  ].some(
    (entry) =>
      entry.path === file.path && entry.mediaType === file.mediaType,
  );
  if (!allowed) {
    throw new Error("The requested evidence download is outside the file contract.");
  }
  const actualBytes = new TextEncoder().encode(file.content).byteLength;
  if (actualBytes !== file.bytes) {
    throw new Error("The requested evidence download has an invalid byte count.");
  }
  if ((await sha256(file.content)) !== file.sha256) {
    throw new Error("The requested evidence download has an invalid digest.");
  }
  if (!mayDownload()) return;

  const blob = new Blob([file.content], {
    type: `${file.mediaType};charset=utf-8`,
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = file.path.replaceAll("/", "-");
  anchor.rel = "noopener";
  anchor.hidden = true;
  document.body.append(anchor);
  try {
    if (!mayDownload()) return;
    anchor.click();
  } finally {
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}
