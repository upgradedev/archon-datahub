// Demo — the full multi-agent audit pipeline over the DataHub MCP client seam.
//
// Runs classifier → lineage-analyzer → governance-auditor → narrator and prints the
// findings + the executive summary. Offline it uses the Fakes (deterministic fixtures +
// Fake LLM); set DATAHUB_MCP_URL / LLM_API_KEY to run against a real DataHub + LLM. The
// pipeline is READ-ONLY end to end — nothing is mutated.
//
//   npm run audit:demo

import { createDataHubClient, hasDataHubCreds } from "../src/datahub/mcp-client.js";
import { AuditPipeline } from "../src/pipeline/pipeline.js";
import { hasLlmCreds } from "../src/llm/client.js";

async function main(): Promise<void> {
  console.log(
    `Archon-DataHub audit — DataHub: ${hasDataHubCreds() ? "LIVE" : "Fake"}, ` +
      `LLM: ${hasLlmCreds() ? "LIVE" : "Fake"}\n`
  );
  const client = await createDataHubClient();
  const report = await new AuditPipeline().run(client);

  console.log(`CLASSIFICATION: ${JSON.stringify(report.classification)}\n`);
  console.log(`AGENT TRACE:`);
  for (const t of report.trace) console.log(`  • ${t.agent}: ${t.produced}`);

  console.log(`\nFINDINGS (${report.findings.length}):`);
  for (const f of report.findings) console.log(`  [${f.type}/${f.severity}] ${f.summary}`);

  console.log(`\nEXECUTIVE SUMMARY:\n${report.narrative}`);
}

main().catch((err) => {
  console.error(`demo-audit failed: ${(err as Error).message}`);
  process.exit(1);
});
