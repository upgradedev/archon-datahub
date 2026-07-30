import { test } from "node:test";
import assert from "node:assert/strict";
import { computeBlastRadius } from "../../src/datahub/blast-radius.js";
import type {
  CatalogEntity,
  CatalogSnapshot,
  LineageTopologyNode,
} from "../../src/datahub/models.js";
import { DataHubHarvestError } from "../../src/datahub/harvest-policy.js";

function entity(urn: string, upstreams: string[] = []): CatalogEntity {
  return {
    urn,
    name: urn,
    platform: "snowflake",
    source: "fixture",
    upstreams: upstreams.map((upstream) => ({ upstream, upstreamResolved: true })),
  };
}

function node(
  urn: string,
  minHops: number,
  deprecated = false
): LineageTopologyNode {
  return { urn, minHops, entityType: "DATASET", deprecated };
}

function snapshot(
  entities: CatalogEntity[],
  downstreamByRoot: Map<string, LineageTopologyNode[]>
): CatalogSnapshot {
  return {
    scanId: "scan",
    entities,
    knownUrns: new Set(entities.map((item) => item.urn)),
    downstreamByRoot,
  };
}

test("blast radius prefers proven topology, strips field suffixes, and exposes hop truncation", () => {
  const data = snapshot(
    [entity("urn:root")],
    new Map([
      [
        "urn:root",
        [
          node("urn:a", 1),
          node("urn:b", 2),
          node("urn:c", 3),
          node("urn:beyond", 4),
        ],
      ],
    ])
  );
  const result = computeBlastRadius(data, "urn:root#email");
  assert.deepEqual(result.downstream, [
    { urn: "urn:a", minHops: 1 },
    { urn: "urn:b", minHops: 2 },
    { urn: "urn:c", minHops: 3 },
  ]);
  assert.equal(result.impact, "medium");
  assert.equal(result.truncated, true);
});

test("blast radius reports explicit truncation at asset and hop bounds", () => {
  const data = snapshot(
    [entity("urn:root")],
    new Map([
      [
        "urn:root",
        [
          node("urn:a", 1),
          node("urn:b", 1),
          node("urn:c", 1),
          node("urn:deep", 2),
        ],
      ],
    ])
  );
  const limited = computeBlastRadius(data, "urn:root", { maxHops: 1, maxAssets: 2 });
  assert.equal(limited.downstream.length, 2);
  assert.equal(limited.truncated, true);
});

test("blast radius fails closed when an audited root lacks topology coverage", () => {
  const data = snapshot([entity("urn:root")], new Map());
  assert.throws(
    () => computeBlastRadius(data, "urn:root"),
    (error: unknown) =>
      error instanceof DataHubHarvestError &&
      error.code === "LINEAGE_RESPONSE_INCOMPLETE"
  );
});

test("reverse-edge fallback remains bounded and cycle-safe for a non-root subject", () => {
  const a = entity("urn:a", ["urn:outside", "urn:c"]);
  const b = entity("urn:b", ["urn:a"]);
  const c = entity("urn:c", ["urn:b"]);
  const data = snapshot(
    [a, b, c],
    new Map([
      ["urn:a", []],
      ["urn:b", []],
      ["urn:c", []],
    ])
  );
  const result = computeBlastRadius(data, "urn:outside");
  assert.deepEqual(result.downstream, [
    { urn: "urn:a", minHops: 1 },
    { urn: "urn:b", minHops: 2 },
    { urn: "urn:c", minHops: 3 },
  ]);
  assert.equal(result.truncated, true);
});

test("a dangling upstream composes its audited consumer with proven out-of-scope topology", () => {
  const root = entity("urn:root", ["urn:missing"]);
  const data = snapshot(
    [root],
    new Map([
      [
        root.urn,
        [
          node("urn:dashboard:direct", 1),
          node("urn:dataset:indirect", 2),
        ],
      ],
    ])
  );

  const result = computeBlastRadius(data, "urn:missing");
  assert.deepEqual(result.downstream, [
    { urn: "urn:root", minHops: 1 },
    { urn: "urn:dashboard:direct", minHops: 2 },
    { urn: "urn:dataset:indirect", minHops: 3 },
  ]);
  assert.equal(result.truncated, false);
});

test("a dangling upstream fails closed when its audited consumer lacks topology coverage", () => {
  const root = entity("urn:root", ["urn:missing"]);
  assert.throws(
    () => computeBlastRadius(snapshot([root], new Map()), "urn:missing"),
    (error: unknown) =>
      error instanceof DataHubHarvestError &&
      error.code === "LINEAGE_RESPONSE_INCOMPLETE"
  );
});
