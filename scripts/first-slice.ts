// First connected slice — the end-to-end proof of Phase 1.
//
// The agent connects to DataHub through the MCP client seam, harvests metadata +
// lineage, runs the ONE self-audit check (the ported consistency engine), and emits a
// read-only FINDING. Offline it uses the FakeDataHubMcpClient (deterministic fixtures)
// so it runs in CI with zero credentials; point DATAHUB_MCP_URL / DATAHUB_GMS_URL at a
// real DataHub instance and the SAME code runs the live client. Nothing is ever
// mutated — Archon recommends, a human disposes.
//
//   npm run slice:datahub

import "../src/config/env.js"; // load .env first (honors the live path); no-op offline
import { createDataHubClient, hasDataHubCreds } from "../src/datahub/mcp-client.js";
import { auditConsistency } from "../src/audit/consistency.js";
import { validateSnapshot } from "../src/governance/validator.js";
import type { Finding } from "../src/types.js";

function contradictionToFinding(c: ReturnType<typeof auditConsistency>["contradictions"][number]): Finding {
  return {
    type: "contradiction",
    severity: "high",
    subject: c.subject,
    summary: `Sources disagree on '${c.attribute}' for ${c.subject}: ${c.values
      .map((v) => `${v.value} (${v.source})`)
      .join(" vs ")}.`,
    detail: { attribute: c.attribute, values: c.values },
    recommendation: `${c.resolution.rationale} (recommended: ${JSON.stringify(
      c.resolution.recommendedValue
    )}, confidence ${c.resolution.confidence}). Read-only — a steward decides.`,
  };
}

async function main(): Promise<void> {
  const mode = hasDataHubCreds() ? "LIVE (DataHub MCP endpoint configured)" : "OFFLINE (Fake DataHub MCP — fixtures)";
  console.log(`Archon-DataHub first slice — ${mode}\n`);

  const client = await createDataHubClient();

  // 1. Connect + query metadata/lineage over the MCP client seam.
  const urns = await client.search();
  const snapshot = await client.harvestSnapshot();
  console.log(`Harvested ${urns.length} dataset(s); ${snapshot.knownUrns.size} URN(s) catalogued.`);

  // 2. The ONE self-audit check — cross-source consistency + lineage-gap detection.
  const facts = await client.harvestFacts();
  const audit = auditConsistency(facts);
  console.log(
    `Self-audit examined ${audit.audited} fact(s) over ${audit.subjects} subject(s) → ` +
      `${audit.contradictions.length} contradiction(s), ${audit.absences.length} lineage gap(s).\n`
  );

  // 3. Produce read-only findings.
  const findings: Finding[] = [];
  for (const c of audit.contradictions) findings.push(contradictionToFinding(c));
  for (const a of audit.absences) {
    findings.push({
      type: "lineage_gap",
      severity: "medium",
      subject: a.subject,
      summary: `Declared upstream ${a.subject} is not catalogued in DataHub — a dangling lineage edge.`,
      detail: { referencedBy: a.referencedBy },
      recommendation: `Ingest ${a.subject} or correct the lineage declaration. Read-only — a steward decides.`,
    });
  }
  for (const g of validateSnapshot(snapshot)) {
    if (g.passed) continue;
    findings.push({
      type: "governance_violation",
      severity: g.severity,
      subject: g.subject,
      summary: `${g.ruleId}: ${g.message}`,
      detail: { rule: g.rule },
      recommendation: `Remediate ${g.ruleId}. Read-only — a steward decides.`,
    });
  }

  console.log(`FINDINGS (${findings.length}) — read-only recommendations:\n`);
  console.log(JSON.stringify(findings, null, 2));

  // The headline self-audit finding for the demo.
  const headline = findings.find((f) => f.type === "contradiction");
  if (headline) {
    console.log(`\nHEADLINE SELF-AUDIT FINDING:\n  ${headline.summary}\n  → ${headline.recommendation}`);
  }
}

main().catch((err) => {
  console.error(`first-slice failed: ${(err as Error).message}`);
  process.exit(1);
});
