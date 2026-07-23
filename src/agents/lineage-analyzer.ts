// LineageAnalyzerAgent — runs the SELF-AUDIT (the differentiator) over the harvested
// fact stream and turns its output into read-only Findings: cross-source
// contradictions and dangling lineage edges (gaps). It owns nothing beyond translating
// the pure consistency engine's report into the agent's Finding vocabulary — the logic
// lives in src/audit/consistency.ts and is exercised on the same engine that ships.

import { auditConsistency, type Contradiction, type ConsistencyReport } from "../audit/consistency.js";
import { auditVersionHistory, type AspectVersionHistory } from "../datahub/version-history.js";
import type { AuditFact, Finding } from "../types.js";

// Map one consistency-engine contradiction onto the agent's Finding vocabulary. Shared by
// the fixture/multi-source path and the version-history recovery path so a live-recovered
// contradiction reads identically to an offline one.
function contradictionFinding(c: Contradiction): Finding {
  // A disagreement on a field TYPE risks silent schema breaks downstream → high.
  const severity = c.attribute === "fieldType" ? "high" : "medium";
  return {
    type: "contradiction",
    severity,
    subject: c.subject,
    summary: `Sources disagree on '${c.attribute}' for ${c.subject}: ${c.values
      .map((v) => `${JSON.stringify(v.value)} (${v.source})`)
      .join(" vs ")}.`,
    detail: { attribute: c.attribute, values: c.values, resolution: c.resolution },
    recommendation: `${c.resolution.rationale} (recommended: ${JSON.stringify(
      c.resolution.recommendedValue
    )}, confidence ${c.resolution.confidence}). Read-only — a steward decides.`,
  };
}

export class LineageAnalyzerAgent {
  analyze(facts: AuditFact[]): Finding[] {
    return this.toFindings(auditConsistency(facts));
  }

  // Run the self-audit over aspect VERSION HISTORY (recovered from a direct GMS read —
  // OpenAPI v3 / Timeline). This is what makes the flagship cross-source contradiction
  // detection fire on a LIVE catalog: latest-write-wins hid the conflict on the current
  // view, but the history still carries every retained write. The distinct-source gate
  // (inside auditVersionHistory) uses stable pipeline/source identity, so changes between
  // executions of one pipeline are NOT reported as cross-source conflicts.
  analyzeVersionHistory(histories: AspectVersionHistory[]): Finding[] {
    return this.toFindings(auditVersionHistory(histories));
  }

  private toFindings(report: ConsistencyReport): Finding[] {
    const findings: Finding[] = [];

    for (const c of report.contradictions) {
      findings.push(contradictionFinding(c));
    }

    for (const a of report.absences) {
      findings.push({
        type: "lineage_gap",
        severity: "medium",
        subject: a.subject,
        summary: `Declared upstream ${a.subject} is not catalogued — a dangling lineage edge (schema-break risk to ${a.referencedBy.length} downstream consumer(s)).`,
        detail: { referencedBy: a.referencedBy },
        recommendation: `Ingest ${a.subject} or correct the lineage declaration. Read-only — a steward decides.`,
      });
    }

    return findings;
  }
}
