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

export interface AuditReport {
  scanId: string;
  classification: Classification;
  findings: Finding[];
  narrative: string;
  // A compact record of the agents that ran, for observability + the demo.
  trace: Array<{ agent: string; produced: string }>;
}

export interface PipelineAgents {
  classifier?: ClassifierAgent;
  lineage?: LineageAnalyzerAgent;
  governance?: GovernanceAuditorAgent;
  narrator?: NarratorAgent;
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

  async run(client: DataHubClient, query?: string): Promise<AuditReport> {
    const snapshot = await client.harvestSnapshot(query);
    const facts = await client.harvestFacts(query);

    const classification = this.classifier.classify(snapshot);
    const factFindings = this.lineage.analyze(facts);

    // Version-history recovery (the LIVE contradiction path): if the client can supply
    // aspect version history (a direct GMS read — OpenAPI v3 / Timeline), run the self-audit
    // over it too. On a live catalog latest-write-wins hides cross-source contradictions on
    // the current view, so THIS is where they resurface; offline it re-derives the same
    // fixture contradictions, which we DEDUPE against the fact-based ones below.
    const historyFindings = client.harvestVersionHistories
      ? this.lineage.analyzeVersionHistory(await client.harvestVersionHistories(query))
      : [];
    const lineageFindings = dedupeFindings([...factFindings, ...historyFindings]);
    const versionHistoryContradictions = historyFindings.filter((f) => f.type === "contradiction").length;

    const governanceFindings = this.governance.audit(snapshot);

    // Deterministic ordering: highest severity first, then by type + subject.
    const findings = [...lineageFindings, ...governanceFindings].sort(
      (a, b) =>
        sev(b.severity) - sev(a.severity) ||
        a.type.localeCompare(b.type) ||
        a.subject.localeCompare(b.subject)
    );

    const narrative = await this.narrator.summarize(findings, classification);

    return {
      scanId: snapshot.scanId,
      classification,
      findings,
      narrative,
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
