import {
  assertAuditReport,
  type AuditReport,
} from "../pipeline/pipeline.js";
import type { Finding } from "../types.js";
import { digest } from "../remediation/integrity.js";
import {
  parseModelRuntimeProvenance,
  type ModelRuntimeProvenance,
} from "../llm/provenance.js";

export interface SarifLog {
  version: "2.1.0";
  $schema: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
        }>;
      };
    };
    properties: {
      modelProvenance: ModelRuntimeProvenance;
    };
    results: Array<{
      ruleId: string;
      level: "error" | "warning" | "note";
      message: { text: string };
      locations: Array<{
        physicalLocation: { artifactLocation: { uri: string } };
      }>;
      partialFingerprints: { archonFindingDigest: string };
      properties: Record<string, unknown>;
    }>;
  }>;
}

function ruleId(finding: Finding): string {
  const governanceRule = finding.detail["ruleId"];
  return typeof governanceRule === "string"
    ? `ARCHON-${governanceRule}`
    : `ARCHON-${finding.type.toUpperCase().replaceAll("_", "-")}`;
}

function sarifLevel(severity: Finding["severity"]): "error" | "warning" | "note" {
  return severity === "high" ? "error" : severity === "medium" ? "warning" : "note";
}

function fingerprint(finding: Finding): string {
  return digest({
    type: finding.type,
    severity: finding.severity,
    subject: finding.subject,
    summary: finding.summary,
    detail: finding.detail,
  }).slice("sha256:".length);
}

export function auditReportToSarif(
  report: AuditReport,
  version = "0.1.0"
): SarifLog {
  assertAuditReport(report);
  const modelProvenance = parseModelRuntimeProvenance(
    report.modelProvenance
  );
  const rules = new Map<string, Finding>();
  for (const finding of report.findings) rules.set(ruleId(finding), finding);
  return {
    version: "2.1.0",
    $schema:
      "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Archon-DataHub",
            version,
            informationUri: "https://github.com/upgradedev/archon-datahub",
            rules: [...rules]
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([id, finding]) => ({
                id,
                name: finding.type,
                shortDescription: { text: finding.summary },
              })),
          },
        },
        properties: { modelProvenance },
        results: report.findings.map((finding) => ({
          ruleId: ruleId(finding),
          level: sarifLevel(finding.severity),
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
          partialFingerprints: { archonFindingDigest: fingerprint(finding) },
          properties: {
            findingType: finding.type,
            severity: finding.severity,
            subject: finding.subject,
            detail: finding.detail,
          },
        })),
      },
    ],
  };
}

function markdownText(value: unknown): string {
  return String(value)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/gu, " ")
    .replace(/[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/gu, "")
    .replace(/\b(?:javascript|vbscript|data):/giu, "blocked-active-scheme ")
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

export function auditReportToMarkdown(report: AuditReport): string {
  assertAuditReport(report);
  const provenance = parseModelRuntimeProvenance(report.modelProvenance);
  const returnedModel =
    provenance.returnedModel === null ? "not applicable" : provenance.returnedModel;
  const responseId =
    provenance.providerResponseId === null
      ? "not applicable"
      : provenance.providerResponseId;
  const usage =
    provenance.tokenUsage === null
      ? "not available"
      : `${provenance.tokenUsage.inputTokens} input / ` +
        `${provenance.tokenUsage.outputTokens} output / ` +
        `${provenance.tokenUsage.totalTokens} total`;
  const latency =
    provenance.latencyMs === null
      ? "not applicable"
      : `${provenance.latencyMs} ms (client measured)`;
  const lines = [
    "# Archon DataHub audit",
    "",
    `- Scan: \`${markdownText(report.scanId)}\``,
    `- Findings: ${report.findings.length}`,
    `- Entities: ${report.classification.totalEntities}`,
    `- Runtime: ${markdownText(provenance.source)}`,
    `- Model call: ${provenance.modelCall ? "yes" : "no"}`,
    `- Provider: ${markdownText(provenance.provider)}`,
    `- Requested model: ${markdownText(provenance.requestedModel)}`,
    `- Returned model: ${markdownText(returnedModel)}`,
    `- Provider response ID: ${markdownText(responseId)}`,
    `- Token usage: ${markdownText(usage)}`,
    `- Latency: ${markdownText(latency)}`,
    "",
    "## Findings",
    "",
    "| Severity | Type | Subject | Finding | Downstream |",
    "|---|---|---|---|---:|",
  ];
  for (const finding of report.findings) {
    const blast = finding.detail["blastRadius"] as
      | { downstream?: unknown[]; truncated?: boolean }
      | undefined;
    const downstream = Array.isArray(blast?.downstream)
      ? `${blast.downstream.length}${blast.truncated ? "+" : ""}`
      : "0";
    lines.push(
      `| ${finding.severity} | ${finding.type} | \`${markdownText(finding.subject)}\` | ${markdownText(
        finding.summary
      )} | ${downstream} |`
    );
  }
  lines.push("", "## Executive summary", "", markdownText(report.narrative), "");
  return lines.join("\n");
}

export function auditReportToJson(report: AuditReport): string {
  assertAuditReport(report);
  const modelProvenance = parseModelRuntimeProvenance(
    report.modelProvenance
  );
  return `${JSON.stringify({ ...report, modelProvenance }, null, 2)}\n`;
}
