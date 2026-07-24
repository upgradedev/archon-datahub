import { test } from "node:test";
import assert from "node:assert/strict";
import { computeBlastRadius } from "../../src/datahub/blast-radius.js";
import type { CatalogEntity, CatalogSnapshot } from "../../src/datahub/models.js";

function entity(urn: string, upstreams: string[] = []): CatalogEntity {
  return {
    urn,
    name: urn,
    platform: "snowflake",
    source: "fixture",
    upstreams: upstreams.map((upstream) => ({ upstream, upstreamResolved: true })),
  };
}

function snapshot(entities: CatalogEntity[]): CatalogSnapshot {
  return { scanId: "scan", entities, knownUrns: new Set(entities.map((item) => item.urn)) };
}

test("blast radius walks downstream, strips field suffixes, and remains cycle-safe", () => {
  const data = snapshot([
    entity("urn:root", ["urn:c"]),
    entity("urn:a", ["urn:root"]),
    entity("urn:b", ["urn:a"]),
    entity("urn:c", ["urn:b"]),
  ]);
  const result = computeBlastRadius(data, "urn:root#email");
  assert.deepEqual(result.downstream, [
    { urn: "urn:a", minHops: 1 },
    { urn: "urn:b", minHops: 2 },
    { urn: "urn:c", minHops: 3 },
  ]);
  assert.equal(result.impact, "medium");
  assert.equal(result.truncated, true, "the cycle continues beyond the configured hop bound");
});

test("blast radius reports explicit truncation at asset and hop bounds", () => {
  const data = snapshot([
    entity("urn:root"),
    entity("urn:a", ["urn:root"]),
    entity("urn:b", ["urn:root"]),
    entity("urn:c", ["urn:root"]),
    entity("urn:deep", ["urn:a"]),
  ]);
  const limited = computeBlastRadius(data, "urn:root", { maxHops: 1, maxAssets: 2 });
  assert.equal(limited.downstream.length, 2);
  assert.equal(limited.truncated, true);
});
