// LineageAnalyzerAgent — runs the SELF-AUDIT (the differentiator) over the harvested
// fact stream and turns its output into read-only Findings: cross-source
// contradictions and dangling lineage edges (gaps). It owns nothing beyond translating
// the pure consistency engine's report into the agent's Finding vocabulary — the logic
// lives in src/audit/consistency.ts and is exercised on the same engine that ships.

import { auditConsistency } from "../audit/consistency.js";
import type { AuditFact, Finding } from "../types.js";

export class LineageAnalyzerAgent {
  analyze(facts: AuditFact[]): Finding[] {
    const report = auditConsistency(facts);
    const findings: Finding[] = [];

    for (const c of report.contradictions) {
      // A disagreement on a field TYPE risks silent schema breaks downstream → high.
      const severity = c.attribute === "fieldType" ? "high" : "medium";
      findings.push({
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
      });
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
