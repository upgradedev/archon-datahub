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
    const lineageFindings = this.lineage.analyze(facts);
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
        { agent: "lineage-analyzer", produced: `${lineageFindings.length} contradiction/lineage finding(s)` },
        { agent: "governance-auditor", produced: `${governanceFindings.length} governance finding(s)` },
        { agent: "narrator", produced: "executive summary" },
      ],
    };
  }
}

function sev(s: Finding["severity"]): number {
  return s === "high" ? 3 : s === "medium" ? 2 : 1;
}
