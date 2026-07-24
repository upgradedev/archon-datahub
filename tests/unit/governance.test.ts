// Unit tests for the deterministic governance validator (G1–G6) and the sensitive-
// field heuristic. Proves each policy rule fires (and skips) on real-shaped catalog
// entities, and that the whole-snapshot pass returns one result per rule per entity.

import { test } from "node:test";
import assert from "node:assert/strict";
import { validateEntity, validateSnapshot, GovernanceValidator } from "../../src/governance/validator.js";
import { looksSensitive } from "../../src/datahub/models.js";
import type { CatalogEntity, CatalogSnapshot } from "../../src/datahub/models.js";

function snapshot(entities: CatalogEntity[]): CatalogSnapshot {
  return { scanId: "scan-1", entities, knownUrns: new Set(entities.map((e) => e.urn)) };
}

const clean: CatalogEntity = {
  urn: "urn:ds:clean",
  name: "clean",
  platform: "snowflake",
  source: "s",
  description: "A well-governed dataset.",
  owners: ["urn:corpGroup:team-a"],
  domain: "urn:domain:sales",
  deprecated: false,
  fields: [{ path: "id", type: "number" }, { path: "email", type: "string", tags: ["pii"] }],
  upstreams: [],
};

test("a fully governed entity passes every rule", () => {
  const results = validateEntity(clean, snapshot([clean]));
  assert.equal(results.length, 6);
  assert.ok(results.every((r) => r.passed), JSON.stringify(results.filter((r) => !r.passed)));
});

test("G1/G2/G3 fail on an ungoverned entity", () => {
  const e: CatalogEntity = { ...clean, urn: "urn:ds:bad", owners: [], domain: null, description: "" };
  const results = validateEntity(e, snapshot([e]));
  const failed = new Set(results.filter((r) => !r.passed).map((r) => r.ruleId));
  assert.ok(failed.has("G1"));
  assert.ok(failed.has("G2"));
  assert.ok(failed.has("G3"));
});

test("G4 flags a deprecated entity that still feeds a live downstream", () => {
  const parent: CatalogEntity = { ...clean, urn: "urn:ds:parent", deprecated: true };
  const child: CatalogEntity = {
    ...clean,
    urn: "urn:ds:child",
    upstreams: [{ upstream: "urn:ds:parent", upstreamResolved: true }],
  };
  const results = validateEntity(parent, snapshot([parent, child]));
  const g4 = results.find((r) => r.ruleId === "G4")!;
  assert.equal(g4.passed, false);
  assert.match(g4.message, /urn:ds:child/);
});

test("G4 skips a non-deprecated entity", () => {
  const g4 = validateEntity(clean, snapshot([clean])).find((r) => r.ruleId === "G4")!;
  assert.equal(g4.passed, true);
  assert.match(g4.message, /skipped/);
});

test("G5 flags an untyped schema field", () => {
  const e: CatalogEntity = { ...clean, urn: "urn:ds:untyped", fields: [{ path: "mystery", type: null }] };
  const g5 = validateEntity(e, snapshot([e])).find((r) => r.ruleId === "G5")!;
  assert.equal(g5.passed, false);
  assert.match(g5.message, /mystery/);
});

test("G6 flags an unclassified sensitive field", () => {
  const e: CatalogEntity = {
    ...clean,
    urn: "urn:ds:pii",
    fields: [{ path: "email", type: "string" }], // sensitive, no tags/terms
  };
  const g6 = validateEntity(e, snapshot([e])).find((r) => r.ruleId === "G6")!;
  assert.equal(g6.passed, false);
  assert.match(g6.message, /email/);
  assert.deepEqual(g6.evidence?.["unclassifiedFields"], ["email"]);
});

test("looksSensitive matches known sensitive hints and ignores plain fields", () => {
  assert.equal(looksSensitive("customer_email"), true);
  assert.equal(looksSensitive("national_id"), true);
  assert.equal(looksSensitive("order_id"), false);
});

test("validateSnapshot returns one result per rule per entity", () => {
  const e2: CatalogEntity = { ...clean, urn: "urn:ds:two" };
  const results = new GovernanceValidator().validate(snapshot([clean, e2]));
  assert.equal(results.length, 12); // 2 entities × 6 rules
  assert.equal(validateSnapshot(snapshot([clean])).length, 6);
});
