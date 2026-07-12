// Unit tests for the DataHub MCP client seam + the harvester.
//
// Proves the offline FakeDataHubMcpClient serves the fixture catalog through the same
// interface the live adapter implements (search → get_entities → get_lineage → harvest),
// that the current-view merge picks the latest report per URN, and that the harvested
// fact stream is exactly what the self-audit needs to surface the baked-in
// contradiction + lineage gap.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  FakeDataHubMcpClient,
  mergeLatest,
  snapshotFromReports,
  hasDataHubCreds,
} from "../../src/datahub/mcp-client.js";
import { reportsToFacts, entityToFacts } from "../../src/audit/harvest.js";
import { FIXTURE_REPORTS, UNCATALOGUED_UPSTREAM } from "../../src/datahub/fixtures.js";
import { auditConsistency } from "../../src/audit/consistency.js";

const SALES = "urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)";

test("search returns the distinct catalogued dataset URNs", async () => {
  const urns = await new FakeDataHubMcpClient().search();
  assert.equal(urns.length, 3); // sales_orders, raw_orders, customer_pii
  assert.ok(urns.includes(SALES));
});

test("search filters by query", async () => {
  const urns = await new FakeDataHubMcpClient().search("customer");
  assert.deepEqual(urns, [
    "urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)",
  ]);
});

test("get_entities returns the CURRENT (latest) view per URN", async () => {
  const [sales] = await new FakeDataHubMcpClient().getEntities([SALES]);
  // latest report is the dbt scan → owner team-ops, amount:string
  assert.equal(sales!.source, "dbt-ingest");
  assert.equal(sales!.owners![0], "urn:li:corpGroup:team-ops");
});

test("get_lineage returns declared upstream edges", async () => {
  const edges = await new FakeDataHubMcpClient().getLineage(
    "urn:li:dataset:(urn:li:dataPlatform:snowflake,raw_orders,PROD)"
  );
  assert.equal(edges.length, 1);
  assert.equal(edges[0]!.upstream, UNCATALOGUED_UPSTREAM);
  assert.equal(edges[0]!.upstreamResolved, false);
});

test("mergeLatest keeps the newest report per URN, sorted by URN", () => {
  const merged = mergeLatest(FIXTURE_REPORTS);
  assert.equal(merged.length, 3);
  const sales = merged.find((e) => e.urn === SALES)!;
  assert.equal(sales.source, "dbt-ingest");
});

test("harvestSnapshot yields the current-view snapshot with knownUrns", async () => {
  const snap = await new FakeDataHubMcpClient().harvestSnapshot();
  assert.equal(snap.entities.length, 3);
  assert.equal(snap.knownUrns.has(SALES), true);
  assert.equal(snap.knownUrns.has(UNCATALOGUED_UPSTREAM), false); // the gap
});

test("harvestFacts feeds the self-audit the baked-in contradiction + lineage gap", async () => {
  const facts = await new FakeDataHubMcpClient().harvestFacts();
  const report = auditConsistency(facts);
  // owner contradiction on sales_orders + field-type contradiction on sales_orders.amount
  const subjects = report.contradictions.map((c) => `${c.subject}::${c.attribute}`);
  assert.ok(subjects.includes(`${SALES}::owner`), JSON.stringify(subjects));
  assert.ok(subjects.some((s) => s.endsWith("#amount::fieldType")), JSON.stringify(subjects));
  // lineage gap: external_feed referenced by raw_orders but never catalogued.
  assert.ok(report.absences.some((a) => a.subject === UNCATALOGUED_UPSTREAM));
});

test("entityToFacts emits no owner fact when ownership is empty", () => {
  const facts = entityToFacts({
    source: "s",
    scanId: "sc",
    createdAt: "2026-06-01T00:00:00.000Z",
    entity: {
      urn: "urn:ds:x",
      name: "x",
      platform: "p",
      source: "s",
      owners: [],
      fields: [],
      upstreams: [],
    },
  });
  assert.equal(facts.some((f) => f.kind === "ownership"), false);
});

test("snapshotFromReports uses the max scanId as the snapshot scanId", () => {
  const snap = snapshotFromReports(FIXTURE_REPORTS);
  assert.equal(snap.scanId, "scan-2026-07-01");
});

test("reportsToFacts flattens every report", () => {
  const facts = reportsToFacts(FIXTURE_REPORTS);
  assert.ok(facts.length > FIXTURE_REPORTS.length);
});

test("hasDataHubCreds is false when no DataHub env is set", () => {
  const saved = { mcp: process.env.DATAHUB_MCP_URL, gms: process.env.DATAHUB_GMS_URL };
  delete process.env.DATAHUB_MCP_URL;
  delete process.env.DATAHUB_GMS_URL;
  try {
    assert.equal(hasDataHubCreds(), false);
    process.env.DATAHUB_GMS_URL = "http://localhost:8080";
    assert.equal(hasDataHubCreds(), true);
  } finally {
    if (saved.mcp === undefined) delete process.env.DATAHUB_MCP_URL;
    else process.env.DATAHUB_MCP_URL = saved.mcp;
    if (saved.gms === undefined) delete process.env.DATAHUB_GMS_URL;
    else process.env.DATAHUB_GMS_URL = saved.gms;
  }
});
