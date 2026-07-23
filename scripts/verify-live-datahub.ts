// Credentialed live-proof gate. This script intentionally writes no local artifact: its
// compact JSON summary goes to stdout and GitHub Actions retains the immutable run log.
//
// It proves the flagship path, not merely connectivity:
//   1. DataHub + official MCP read surface can be reached;
//   2. aspect retention exposes current v0 plus at least one historical value;
//   3. stable provenance resolves at least two sources for a planted conflict;
//   4. the production audit engine emits at least one recovered contradiction.

import {
  createDataHubClient,
  hasDataHubCreds,
} from "../src/datahub/mcp-client.js";
import {
  auditVersionHistory,
  versionHistoryToFacts,
} from "../src/datahub/version-history.js";

function fail(message: string): never {
  throw new Error(`LIVE_PROOF_FAILED: ${message}`);
}

async function main(): Promise<void> {
  if (!hasDataHubCreds()) {
    fail("DATAHUB_GMS_URL or DATAHUB_MCP_URL is required");
  }
  const query = process.env.ARCHON_DEMO_QUERY?.trim() || undefined;
  const client = await createDataHubClient();
  if (!client.harvestVersionHistories) {
    fail("configured client does not support version history");
  }

  // Prove the official MCP read path independently from the direct history read.
  const urns = await client.search(query);
  if (urns.length === 0) fail("search returned no datasets for the demo query");

  const histories = await client.harvestVersionHistories(query);
  const retained = histories.filter((history) => history.versions.length >= 2);
  if (retained.length === 0) {
    fail("no aspect exposed current v0 plus a retained historical version; check retention policy");
  }

  const stableSources = new Set(
    retained
      .flatMap(versionHistoryToFacts)
      .map((fact) => fact.source)
      .filter((source) => source !== "unknown-source")
  );
  if (stableSources.size < 2) {
    fail("fewer than two stable pipeline/source identities were resolved");
  }

  const report = auditVersionHistory(retained);
  if (report.contradictions.length === 0) {
    fail("retained history contained no confirmed cross-source contradiction");
  }

  process.stdout.write(
    `${JSON.stringify(
      {
        ok: true,
        datasetsDiscovered: urns.length,
        aspectHistories: histories.length,
        retainedHistories: retained.length,
        stableSourceCount: stableSources.size,
        recoveredContradictions: report.contradictions.length,
        attributes: [...new Set(report.contradictions.map((item) => item.attribute))].sort(),
      },
      null,
      2
    )}\n`
  );
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
