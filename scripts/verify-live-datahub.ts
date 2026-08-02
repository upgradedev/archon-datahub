// Credentialed live-proof gate. Its compact, sanitized JSON summary goes to stdout;
// the workflow digest-binds, attests, and retains that exact document.
//
// It proves the flagship path, not merely connectivity:
//   1. DataHub + official MCP read surface can be reached;
//   2. aspect retention exposes current v0 plus one historical value;
//   3. stable provenance resolves exactly two sources for the planted conflict;
//   4. the production audit engine emits the exact G6, lineage-gap, and retained
//      contradiction semantics used by the submission evidence receipt.

import { createHash } from "node:crypto";
import { ClassifierAgent } from "../src/agents/classifier.js";
import { GovernanceAuditorAgent } from "../src/agents/governance-auditor.js";
import { LineageAnalyzerAgent } from "../src/agents/lineage-analyzer.js";
import { computeBlastRadius } from "../src/datahub/blast-radius.js";
import {
  createDataHubClient,
  hasDataHubCreds,
} from "../src/datahub/mcp-client.js";
import {
  auditVersionHistory,
  versionHistoryToFacts,
} from "../src/datahub/version-history.js";
import type { Finding } from "../src/types.js";

const MAX_QUERY_CHARS = 256;

function fail(message: string): never {
  throw new Error(`LIVE_PROOF_FAILED: ${message}`);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  return value;
}

function exactOne<T>(values: T[], label: string): T {
  if (values.length !== 1 || values[0] === undefined) {
    fail(`${label} must contain exactly one value`);
  }
  return values[0];
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

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];
  for (const finding of findings) {
    const attribute = finding.detail["attribute"];
    const key = [
      finding.type,
      finding.subject,
      typeof attribute === "string" ? attribute : "",
    ].join("\u001f");
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(finding);
  }
  return result;
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

  // Prove the official MCP read path independently from direct completeness reads.
  const urns = await client.search(query);
  if (urns.length !== 1) {
    fail(`search must resolve exactly one dataset; received ${urns.length}`);
  }
  const datasetUrn = urns[0];
  if (!datasetUrn) fail("search returned an invalid dataset identity");

  const histories = await client.harvestVersionHistories(query);
  const historyUrns = new Set(histories.map((history) => history.urn));
  if (historyUrns.size !== 1 || !historyUrns.has(datasetUrn)) {
    fail("history harvest did not remain bound to the searched dataset");
  }
  const retained = histories.filter((history) => history.versions.length >= 2);
  if (retained.length !== 1) {
    fail("exactly one aspect must expose current plus retained history");
  }

  const stableSources = new Set(
    retained
      .flatMap(versionHistoryToFacts)
      .map((fact) => fact.source)
      .filter((source) => source !== "unknown-source")
  );
  if (stableSources.size !== 2) {
    fail("retained history must resolve exactly two stable sources");
  }

  const historyReport = auditVersionHistory(retained);
  if (
    historyReport.contradictions.length !== 1 ||
    historyReport.contradictions[0]?.attribute !== "owner"
  ) {
    fail("retained history must prove the exact owner contradiction");
  }

  const harvest = await client.harvestAudit(query, {
    profile: "synchronous-preview",
  });
  if (
    harvest.snapshot.entities.length !== 1 ||
    harvest.snapshot.entities[0]?.urn !== datasetUrn
  ) {
    fail("semantic harvest escaped the exact searched dataset");
  }
  const classification = new ClassifierAgent().classify(harvest.snapshot);
  if (
    classification.totalEntities !== 1 ||
    classification.withLineage !== 1 ||
    classification.sensitiveEntities !== 1
  ) {
    fail("live classification differs from the reviewed semantic contract");
  }

  const lineage = new LineageAnalyzerAgent();
  const findings = dedupeFindings([
    ...lineage.analyze(harvest.facts),
    ...lineage.analyzeVersionHistory(harvest.versionHistories),
    ...new GovernanceAuditorAgent().audit(harvest.snapshot),
  ]).map((finding) => ({
    ...finding,
    detail: {
      ...finding.detail,
      blastRadius: computeBlastRadius(harvest.snapshot, finding.subject),
    },
  }));
  if (findings.length !== 3) {
    fail("live audit must yield exactly three reviewed findings");
  }

  const g6 = exactOne(
    findings.filter(
      (finding) =>
        finding.type === "governance_violation" &&
        finding.subject === datasetUrn &&
        finding.detail["ruleId"] === "G6"
    ),
    "G6 findings"
  );
  const gap = exactOne(
    findings.filter((finding) => finding.type === "lineage_gap"),
    "lineage-gap findings"
  );
  const contradiction = exactOne(
    findings.filter(
      (finding) =>
        finding.type === "contradiction" &&
        finding.subject === datasetUrn &&
        finding.detail["attribute"] === "owner"
    ),
    "retained contradiction findings"
  );

  const g6Fields = array(
    g6.detail["unclassifiedFields"],
    "G6 unclassifiedFields"
  );
  if (
    g6Fields.length !== 1 ||
    g6Fields[0] !== "email"
  ) {
    fail("G6 must bind only the reviewed email field");
  }
  const g6Blast = record(g6.detail["blastRadius"], "G6 blast radius");
  const gapBlast = record(gap.detail["blastRadius"], "gap blast radius");
  const retainedDetail = record(
    contradiction.detail,
    "retained contradiction detail"
  );
  const values = array(
    retainedDetail["values"],
    "retained contradiction values"
  ).map((value, index) =>
    record(value, `retained contradiction values[${index}]`)
  );
  const resolution = record(
    retainedDetail["resolution"],
    "retained contradiction resolution"
  );
  const recommendedFactId = resolution["recommendedFactId"];
  if (typeof recommendedFactId !== "string" || values.length !== 2) {
    fail("retained contradiction resolution is incomplete");
  }
  const sources = new Set(
    values.map((value) => value["source"]).filter(
      (source): source is string => typeof source === "string"
    )
  );
  if (sources.size !== 2) {
    fail("retained contradiction must preserve two source identities");
  }
  const statuses = values
    .map((value) =>
      value["factId"] === recommendedFactId ? "trusted" : "conflicting"
    )
    .sort();
  if (
    statuses.length !== 2 ||
    statuses[0] !== "conflicting" ||
    statuses[1] !== "trusted"
  ) {
    fail("retained contradiction statuses are invalid");
  }

  const g6Downstream = array(g6Blast["downstream"], "G6 downstream");
  const gapDownstream = array(gapBlast["downstream"], "gap downstream");
  const targetConsumer = exactOne(
    gapDownstream
      .map((value, index) => record(value, `gap downstream[${index}]`))
      .filter((value) => value["urn"] === datasetUrn),
    "gap target consumer"
  );
  if (
    g6Downstream.length !== 0 ||
    gapDownstream.length !== 1 ||
    targetConsumer["minHops"] !== 1 ||
    g6Blast["maxHops"] !== 3 ||
    gapBlast["maxHops"] !== 3 ||
    g6Blast["truncated"] !== false ||
    gapBlast["truncated"] !== false ||
    g6Blast["impact"] !== "none" ||
    gapBlast["impact"] !== "low"
  ) {
    fail("live blast-radius semantics differ from the reviewed contract");
  }

  const semanticProof = {
    schemaVersion: "archon.deployed-datahub-semantic-proof/v2",
    evidenceClass: "credentialed-live-cloud",
    classification: {
      totalEntities: classification.totalEntities,
      withLineage: classification.withLineage,
      sensitiveEntities: classification.sensitiveEntities,
    },
    findings: {
      totalCount: findings.length,
      g6: {
        exactTarget: true,
        fieldPath: "email",
        classificationAbsent: true,
        blastRootBound: g6Blast["rootUrn"] === datasetUrn,
        downstreamCount: g6Downstream.length,
        maxHops: g6Blast["maxHops"],
        truncated: g6Blast["truncated"],
        impact: g6Blast["impact"],
      },
      danglingLineage: {
        exactUpstream: gapBlast["rootUrn"] === gap.subject,
        upstreamAbsent: true,
        blastRootBound: gapBlast["rootUrn"] === gap.subject,
        targetConsumerMinHops: targetConsumer["minHops"],
        downstreamCount: gapDownstream.length,
        maxHops: gapBlast["maxHops"],
        truncated: gapBlast["truncated"],
        impact: gapBlast["impact"],
      },
      retainedHistory: {
        exactTarget: contradiction.subject === datasetUrn,
        attribute: "owner",
        provenanceCount: values.length,
        stableSourceCount: sources.size,
        statuses,
        retainedOwnershipHistorySha256: sha256(JSON.stringify(retained)),
      },
    },
  };

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
        recoveredContradictions: historyReport.contradictions.length,
        contradictionAttributeCount: new Set(
          historyReport.contradictions.map((item) => item.attribute)
        ).size,
        semanticProof,
      },
      null,
      2
    )}\n`
  );
}

main().catch((error: unknown) => {
  process.stderr.write(
    `${error instanceof Error ? error.message : String(error)}\n`
  );
  process.exitCode = 1;
});