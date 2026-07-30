// AuditPipeline — the multi-agent orchestration: classifier → lineage-analyzer →
// governance-auditor → narrator, over metadata harvested from DataHub through the MCP
// client seam. Deterministic order; every agent is injectable so the whole pipeline
// runs offline against the Fakes in CI. The pipeline is READ-ONLY end to end — it
// harvests, audits, and NARRATES; it never mutates DataHub.

import type { DataHubClient } from "../datahub/mcp-client.js";
import { ClassifierAgent, type Classification } from "../agents/classifier.js";
import { LineageAnalyzerAgent } from "../agents/lineage-analyzer.js";
import { GovernanceAuditorAgent } from "../agents/governance-auditor.js";
import { NarratorAgent } from "../agents/narrator.js";
import type { Finding } from "../types.js";
import {
  isModelRuntimeProvenance,
  type ModelRuntimeProvenance,
} from "../llm/provenance.js";
import { computeBlastRadius } from "../datahub/blast-radius.js";
import {
  deadlineSignal,
  harvestPolicy,
  waitWithinDeadline,
  type AuditExecutionProfile,
} from "../datahub/harvest-policy.js";

export interface AuditReport {
  schemaVersion: "archon.audit-report/v1";
  scanId: string;
  classification: Classification;
  findings: Finding[];
  narrative: string;
  modelProvenance: ModelRuntimeProvenance;
  // A compact record of the agents that ran, for observability + the demo.
  trace: Array<{ agent: string; produced: string }>;
}

const AUDIT_REPORT_KEYS = [
  "schemaVersion",
  "scanId",
  "classification",
  "findings",
  "narrative",
  "modelProvenance",
  "trace",
] as const;
const CLASSIFICATION_KEYS = [
  "totalEntities",
  "withLineage",
  "sensitiveEntities",
  "domains",
  "platforms",
] as const;

function reportRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactReportKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  required: readonly string[] = allowed
): boolean {
  const keys = Object.keys(value);
  const allowedSet = new Set(allowed);
  return (
    keys.every((key) => allowedSet.has(key)) &&
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

function boundedText(
  value: unknown,
  maximum: number,
  allowEmpty = false
): value is string {
  return (
    typeof value === "string" &&
    (allowEmpty || value.length > 0) &&
    value.length <= maximum &&
    !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(value)
  );
}

function safeReportCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isCountMap(value: unknown): value is Record<string, number> {
  if (!reportRecord(value) || Object.keys(value).length > 1_000) return false;
  return Object.entries(value).every(
    ([key, count]) =>
      boundedText(key, 256) &&
      safeReportCount(count)
  );
}

function isClassification(value: unknown): value is Classification {
  if (
    !reportRecord(value) ||
    !exactReportKeys(value, CLASSIFICATION_KEYS)
  ) {
    return false;
  }
  return (
    safeReportCount(value["totalEntities"]) &&
    safeReportCount(value["withLineage"]) &&
    safeReportCount(value["sensitiveEntities"]) &&
    (value["withLineage"] as number) <= (value["totalEntities"] as number) &&
    (value["sensitiveEntities"] as number) <=
      (value["totalEntities"] as number) &&
    isCountMap(value["domains"]) &&
    isCountMap(value["platforms"])
  );
}

function isFinding(value: unknown): value is Finding {
  if (!reportRecord(value)) return false;
  const allowed = [
    "type",
    "severity",
    "subject",
    "summary",
    "detail",
    "recommendation",
  ];
  const required = ["type", "severity", "subject", "summary", "detail"];
  if (!exactReportKeys(value, allowed, required)) return false;
  return (
    ["contradiction", "lineage_gap", "governance_violation"].includes(
      value["type"] as string
    ) &&
    ["low", "medium", "high"].includes(value["severity"] as string) &&
    boundedText(value["subject"], 2_048) &&
    boundedText(value["summary"], 4_000) &&
    reportRecord(value["detail"]) &&
    (value["recommendation"] === undefined ||
      boundedText(value["recommendation"], 4_000))
  );
}

function isTrace(value: unknown): value is AuditReport["trace"] {
  return (
    Array.isArray(value) &&
    value.length <= 32 &&
    value.every(
      (step) =>
        reportRecord(step) &&
        exactReportKeys(step, ["agent", "produced"]) &&
        boundedText(step["agent"], 128) &&
        boundedText(step["produced"], 2_000)
    )
  );
}

export function isAuditReport(value: unknown): value is AuditReport {
  if (
    !reportRecord(value) ||
    !exactReportKeys(value, AUDIT_REPORT_KEYS) ||
    value["schemaVersion"] !== "archon.audit-report/v1"
  ) {
    return false;
  }
  return (
    boundedText(value["scanId"], 512) &&
    isClassification(value["classification"]) &&
    Array.isArray(value["findings"]) &&
    value["findings"].length <= 10_000 &&
    value["findings"].every(isFinding) &&
    boundedText(value["narrative"], 8_000) &&
    isModelRuntimeProvenance(value["modelProvenance"]) &&
    isTrace(value["trace"])
  );
}

export function assertAuditReport(value: unknown): asserts value is AuditReport {
  if (!isAuditReport(value)) {
    throw new Error("Audit report is absent or does not satisfy archon.audit-report/v1.");
  }
}

export interface PipelineAgents {
  classifier?: ClassifierAgent;
  lineage?: LineageAnalyzerAgent;
  governance?: GovernanceAuditorAgent;
  narrator?: NarratorAgent;
}

export interface AuditRunOptions {
  executionProfile?: AuditExecutionProfile;
}

export class AuditPipeline {
  private classifier: ClassifierAgent;
  private lineage: LineageAnalyzerAgent;
  private governance: GovernanceAuditorAgent;
  private narrator: NarratorAgent;

  constructor(agents: PipelineAgents = {}) {
    this.classifier = agents.classifier ?? new ClassifierAgent();
    this.lineage = agents.lineage ?? new LineageAnalyzerAgent();
    this.governance = agents.governance ?? new GovernanceAuditorAgent();
    this.narrator = agents.narrator ?? new NarratorAgent();
  }

  async run(
    client: DataHubClient,
    query?: string,
    options: AuditRunOptions = {}
  ): Promise<AuditReport> {
    const executionProfile = options.executionProfile ?? "synchronous-preview";
    const policy = harvestPolicy(executionProfile);
    const signal = deadlineSignal(policy.pipelineDeadlineMs);
    return waitWithinDeadline(
      this.runWithinDeadline(client, query, executionProfile, signal),
      signal,
      "PIPELINE_DEADLINE_EXCEEDED"
    );
  }

  private async runWithinDeadline(
    client: DataHubClient,
    query: string | undefined,
    executionProfile: AuditExecutionProfile,
    signal: AbortSignal
  ): Promise<AuditReport> {
    const harvest = await client.harvestAudit(query, {
      profile: executionProfile,
      signal,
    });
    const { snapshot, facts } = harvest;

    const classification = this.classifier.classify(snapshot);
    const factFindings = this.lineage.analyze(facts);

    // Version-history recovery (the LIVE contradiction path): the same harvest bundle may
    // include direct-GMS aspect history (OpenAPI v3 / Timeline), which is audited here.
    // On a live catalog latest-write-wins hides cross-source contradictions on
    // the current view, so THIS is where they resurface; offline it re-derives the same
    // fixture contradictions, which we DEDUPE against the fact-based ones below.
    const historyFindings = this.lineage.analyzeVersionHistory(
      harvest.versionHistories
    );
    const lineageFindings = dedupeFindings([...factFindings, ...historyFindings]);
    const versionHistoryContradictions = historyFindings.filter((f) => f.type === "contradiction").length;

    const governanceFindings = this.governance.audit(snapshot);

    // Deterministic ordering: highest severity first, then by type + subject.
    const findings = [...lineageFindings, ...governanceFindings]
      .map((finding) => ({
        ...finding,
        detail: {
          ...finding.detail,
          blastRadius: computeBlastRadius(snapshot, finding.subject),
        },
      }))
      .sort(
      (a, b) =>
        sev(b.severity) - sev(a.severity) ||
        a.type.localeCompare(b.type) ||
        a.subject.localeCompare(b.subject)
      );

    const narration = await this.narrator.summarize(findings, classification);

    const report: AuditReport = {
      schemaVersion: "archon.audit-report/v1",
      scanId: snapshot.scanId,
      classification,
      findings,
      narrative: narration.narrative,
      modelProvenance: narration.modelProvenance,
      trace: [
        { agent: "classifier", produced: `${classification.totalEntities} entities classified` },
        {
          agent: "lineage-analyzer",
          produced:
            `${lineageFindings.length} contradiction/lineage finding(s)` +
            ` (${versionHistoryContradictions} recovered from aspect version history)`,
        },
        { agent: "governance-auditor", produced: `${governanceFindings.length} governance finding(s)` },
        { agent: "narrator", produced: "executive summary" },
      ],
    };
    assertAuditReport(report);
    return report;
  }
}

function sev(s: Finding["severity"]): number {
  return s === "high" ? 3 : s === "medium" ? 2 : 1;
}

// Dedupe findings by their identity (type + subject + attribute). The fact-based path and
// the version-history path can independently derive the SAME contradiction (offline they
// both see the fixture conflict); we keep one. First occurrence wins (fact-based first).
function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const attr = (f.detail as { attribute?: unknown } | undefined)?.attribute;
    const key = `${f.type}␟${f.subject}␟${typeof attr === "string" ? attr : ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}
