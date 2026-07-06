// Unit tests for the self-audit consistency engine — the differentiator.
//
// These prove the ported engine on METADATA-shaped facts: two sources disagreeing on
// one entity's attribute is a contradiction; a referenced-but-uncatalogued upstream is
// an absence (lineage gap); agreeing facts are silent; and the recommender's priority
// ladder (importance → source-authority → recency) picks a defensible winner without
// ever mutating anything.

import { test } from "node:test";
import assert from "node:assert/strict";
import { auditConsistency, resolveContradiction } from "../../src/audit/consistency.js";
import type { AuditFact } from "../../src/types.js";

function fact(p: Partial<AuditFact> & Pick<AuditFact, "id">): AuditFact {
  return {
    id: p.id,
    kind: p.kind ?? "ownership",
    source: p.source ?? "src",
    scan: p.scan ?? "scan-1",
    sourceRef: p.sourceRef ?? null,
    content: p.content ?? "",
    metadata: p.metadata ?? null,
    createdAt: p.createdAt ?? "2026-06-01T00:00:00.000Z",
    importance: p.importance ?? null,
  };
}

test("flags a cross-source owner contradiction on the same entity", () => {
  const rep = auditConsistency([
    fact({ id: "a", source: "snowflake", metadata: { record: "ds:1", owner: "team-finance" } }),
    fact({
      id: "b",
      source: "dbt",
      createdAt: "2026-07-01T00:00:00.000Z",
      metadata: { record: "ds:1", owner: "team-ops" },
    }),
  ]);
  assert.equal(rep.ok, false);
  assert.equal(rep.contradictions.length, 1);
  const c = rep.contradictions[0]!;
  assert.equal(c.subject, "ds:1");
  assert.equal(c.attribute, "owner");
  assert.equal(c.values.length, 2);
  // recency default → the later dbt harvest (team-ops) is recommended.
  assert.equal(c.resolution.recommendedValue, "team-ops");
  assert.equal(c.resolution.rule, "recency");
});

test("agreeing facts across sources produce no findings", () => {
  const rep = auditConsistency([
    fact({ id: "a", source: "snowflake", metadata: { record: "ds:1", owner: "team-a" } }),
    fact({ id: "b", source: "dbt", metadata: { record: "ds:1", owner: "team-a" } }),
  ]);
  assert.equal(rep.ok, true);
  assert.equal(rep.contradictions.length, 0);
  assert.equal(rep.absences.length, 0);
});

test("numeric tolerance treats near-equal numbers as agreement", () => {
  const rep = auditConsistency(
    [
      fact({ id: "a", metadata: { record: "ds:1", rows: 1000 } }),
      fact({ id: "b", source: "dbt", metadata: { record: "ds:1", rows: 1000.4 } }),
    ],
    { numericTolerance: 0.5 }
  );
  assert.equal(rep.ok, true);
});

test("a referenced-but-uncatalogued upstream is a lineage-gap absence", () => {
  const rep = auditConsistency([
    fact({
      id: "a",
      kind: "lineage",
      metadata: { record: "ds:child", refs: ["ds:missing_upstream"] },
    }),
  ]);
  assert.equal(rep.absences.length, 1);
  assert.equal(rep.absences[0]!.subject, "ds:missing_upstream");
  assert.equal(rep.absences[0]!.referencedBy[0]!.factId, "a");
});

test("a referenced upstream that IS catalogued is not an absence", () => {
  const rep = auditConsistency([
    fact({ id: "a", kind: "lineage", metadata: { record: "ds:child", refs: ["ds:parent"] } }),
    fact({ id: "b", metadata: { record: "ds:parent", owner: "team-x" } }),
  ]);
  assert.equal(rep.absences.length, 0);
});

test("importance outranks recency in the recommender", () => {
  const res = resolveContradiction([
    { value: "pinned", facts: [fact({ id: "p", importance: 0.9, createdAt: "2026-01-01T00:00:00.000Z" })] },
    { value: "later", facts: [fact({ id: "l", createdAt: "2026-08-01T00:00:00.000Z" })] },
  ]);
  assert.equal(res.rule, "importance");
  assert.equal(res.recommendedValue, "pinned");
});

test("a structured fact outranks a derived insight for a raw value", () => {
  const res = resolveContradiction([
    { value: "structured", facts: [fact({ id: "s", kind: "schema" })] },
    { value: "narrated", facts: [fact({ id: "n", kind: "insight" })] },
  ]);
  assert.equal(res.rule, "source-authority");
  assert.equal(res.recommendedValue, "structured");
});

test("facts with no entity key are counted but never flagged", () => {
  const rep = auditConsistency([fact({ id: "x", sourceRef: null, metadata: { owner: "a" } })]);
  assert.equal(rep.audited, 1);
  assert.equal(rep.subjects, 0);
  assert.equal(rep.ok, true);
});
