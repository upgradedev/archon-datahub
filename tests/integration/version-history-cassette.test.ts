// Replay-cassette integration test (closes D-3 as far as an offline build honestly can).
//
// The earlier live-mapper fixtures were "modelled on" the source. This test instead replays
// REAL-SHAPE GMS OpenAPI v3 responses from a cassette (tests/cassettes/…), whose envelope +
// systemMetadata fields are taken VERBATIM from DataHub's own published OpenAPI docs. It
// reconstructs an aspect version history exactly as the live client's readAspectVersions()
// does — pulling the `{ value, systemMetadata }` wrapper out of each per-version response —
// and runs the real recovery audit over it. So the version-history contradiction path is
// proven against the genuine response shape, not our reading of it.
//
// The one thing this CANNOT prove offline is a capture from a running instance; that stays
// USER-GATED (readiness marks it so). Replacing the cassette's history entries with a real
// captured batch on the demo VM upgrades this from real-SHAPE to real-CAPTURE with no code
// change.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  auditVersionHistory,
  type AspectVersionHistory,
  type DhVersionedAspect,
} from "../../src/datahub/version-history.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CASSETTE = resolve(HERE, "../cassettes/openapi-v3-versioned-aspects.json");

interface CassetteEntry {
  request: string;
  response: Record<string, unknown>;
}
interface Cassette {
  entries: CassetteEntry[];
}

function loadCassette(): Cassette {
  return JSON.parse(readFileSync(CASSETTE, "utf8")) as Cassette;
}

// Reconstruct an aspect version history from the per-version cassette responses, exactly as
// the live client does: for each response, pull out the `{ value, systemMetadata }` wrapper
// under the aspect key.
function historyFromCassette(entries: CassetteEntry[], urn: string, aspect: string): AspectVersionHistory {
  const versions = entries
    .filter((e) => e.response["urn"] === urn && e.response[aspect])
    .map((e) => e.response[aspect] as DhVersionedAspect);
  return { urn, aspect: aspect as AspectVersionHistory["aspect"], versions };
}

const SALES = "urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)";
const HIVE = "urn:li:dataset:(urn:li:dataPlatform:hive,fct_users_created,PROD)";

test("cassette parses and carries the real GMS systemMetadata envelope", () => {
  const { entries } = loadCassette();
  const globalTags = entries.find((e) => e.response["urn"] === HIVE)!;
  const wrapped = globalTags.response["globalTags"] as DhVersionedAspect;
  // The exact fields DataHub's OpenAPI docs publish must round-trip through our pinned type.
  assert.equal(wrapped.systemMetadata!.version, "1");
  assert.equal(wrapped.systemMetadata!.runId, "no-run-id-provided");
  assert.equal(typeof wrapped.systemMetadata!.lastObserved, "number");
});

test("replaying the real-shape ownership history recovers the cross-run contradiction", () => {
  const { entries } = loadCassette();
  const history = historyFromCassette(entries, SALES, "ownership");
  assert.equal(history.versions.length, 2, "two recorded ownership versions");

  const report = auditVersionHistory([history]);
  assert.equal(report.contradictions.length, 1);
  const c = report.contradictions[0]!;
  assert.equal(c.subject, SALES);
  assert.equal(c.attribute, "owner");
  // both conflicting runIds are named in the evidence (finance run vs ops run).
  const sources = c.values.map((v) => v.source).sort();
  assert.deepEqual(sources, ["dbt-manifest-2026-07-01", "snowflake-connector-2026-06-01"]);
  assert.equal(c.resolution.recommendedValue, "urn:li:corpGroup:team-ops");
});
