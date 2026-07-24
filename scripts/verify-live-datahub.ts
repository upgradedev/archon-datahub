// Credentialed live-proof gate. Its compact, sanitized JSON summary goes to stdout; the
// pipeline digest-binds, attests, and retains that exact document.
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
import { createHash } from "node:crypto";
import {
  auditVersionHistory,
  versionHistoryToFacts,
} from "../src/datahub/version-history.js";

const MAX_QUERY_CHARS = 256;

function fail(message: string): never {
  throw new Error(`LIVE_PROOF_FAILED: ${message}`);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function requiredNarrowQuery(): string {
  const raw = process.env.ARCHON_DEMO_QUERY;
  if (raw === undefined || raw.length === 0) {
    fail("ARCHON_DEMO_QUERY is required");
  }
  if (raw !== raw.trim()) {
    fail("ARCHON_DEMO_QUERY must already be trimmed");
  }
  if (raw.length > MAX_QUERY_CHARS) {
    fail(`ARCHON_DEMO_QUERY must be at most ${MAX_QUERY_CHARS} characters`);
  }
  if (/[\u0000-\u001f\u007f]/u.test(raw)) {
    fail("ARCHON_DEMO_QUERY contains a control character");
  }
  if (raw === "{}" || /[*?]/u.test(raw)) {
    fail("ARCHON_DEMO_QUERY must be narrow and cannot contain wildcard operators");
  }
  return raw;
}

async function main(): Promise<void> {
  if (!hasDataHubCreds()) {
    fail("a live DataHub connection is required");
  }
  const query = requiredNarrowQuery();
  const client = await createDataHubClient();
  if (!client.harvestVersionHistories) {
    fail("configured client does not support version history");
  }

  // Prove the official MCP read path independently from the direct history read.
  const urns = await client.search(query);
  if (urns.length !== 1) {
    fail(`search must resolve exactly one dataset; received ${urns.length}`);
  }
  const [datasetUrn] = urns;
  if (!datasetUrn) fail("search returned an invalid dataset identity");

  const histories = await client.harvestVersionHistories(query);
  const historyUrns = new Set(histories.map((history) => history.urn));
  if (historyUrns.size !== 1 || !historyUrns.has(datasetUrn)) {
    fail("history harvest did not remain bound to the one searched dataset");
  }
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
        schemaVersion: "archon.live-datahub-proof/v1",
        ok: true,
        result: "retained-history-contradiction-proven",
        querySha256: sha256(JSON.stringify({ query })),
        datasetUrnSha256: sha256(datasetUrn),
        datasetsDiscovered: 1,
        aspectHistories: histories.length,
        retainedHistories: retained.length,
        stableSourceCount: stableSources.size,
        recoveredContradictions: report.contradictions.length,
        contradictionAttributeCount: new Set(
          report.contradictions.map((item) => item.attribute)
        ).size,
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
