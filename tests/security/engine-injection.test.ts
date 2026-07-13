// PEN-TEST — injection into the governance / contradiction engine.
//
// Threat: the version-history recovery path (the differentiator) reads UNTRUSTED aspect
// values + systemMetadata straight from GMS. An attacker who controls an ingestion run
// could try to (a) forge a FALSE contradiction to trigger alarm fatigue, (b) MASK a real
// contradiction with adversarial runIds, (c) CRASH the recovery with malformed shapes, or
// (d) POLLUTE the prototype via a crafted aspect value. These tests drive the real
// `auditVersionHistory` / `auditConsistency` engine with adversarial inputs and prove:
//   • the requireDistinctSources guard holds — same/absent runId ⇒ ZERO contradictions
//     (no forged conflict), even when values differ;
//   • a genuine two-run conflict STILL fires when mixed with adversarial single-run noise
//     (the guard does not mask real disagreements);
//   • malformed / hostile shapes (null systemMetadata, missing value, huge strings,
//     __proto__ keys) never throw and never pollute Object.prototype.
// Pure functions; fully offline.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  auditVersionHistory,
  type AspectVersionHistory,
} from "../../src/datahub/version-history.js";
import { auditConsistency } from "../../src/audit/consistency.js";
import type { AuditFact } from "../../src/types.js";

const URN = "urn:li:dataset:(urn:li:dataPlatform:snowflake,adversarial,PROD)";

test("engine-injection: differing values under ONE runId do NOT forge a contradiction (drift, not conflict)", () => {
  const history: AspectVersionHistory = {
    urn: URN,
    aspect: "ownership",
    versions: [
      { value: { owners: [{ owner: "urn:li:corpGroup:a" }] }, systemMetadata: { version: "1", lastObserved: 1, runId: "same-run" } },
      { value: { owners: [{ owner: "urn:li:corpGroup:b" }] }, systemMetadata: { version: "2", lastObserved: 2, runId: "same-run" } },
    ],
  };
  assert.equal(auditVersionHistory([history]).contradictions.length, 0);
});

test("engine-injection: absent/placeholder runIds collapse to one source ⇒ no forged contradiction", () => {
  const history: AspectVersionHistory = {
    urn: URN,
    aspect: "ownership",
    versions: [
      { value: { owners: [{ owner: "urn:li:corpGroup:a" }] }, systemMetadata: { version: "1", lastObserved: 1, runId: "no-run-id-provided" } },
      { value: { owners: [{ owner: "urn:li:corpGroup:b" }] }, systemMetadata: { version: "2", lastObserved: 2 /* no runId */ } },
      { value: { owners: [{ owner: "urn:li:corpGroup:c" }] }, systemMetadata: null },
    ],
  };
  // sourceOf() maps every placeholder/missing runId to "unknown-run" → one distinct source.
  assert.equal(auditVersionHistory([history]).contradictions.length, 0);
});

test("engine-injection: a genuine two-run conflict STILL fires alongside adversarial single-run noise", () => {
  const genuine: AspectVersionHistory = {
    urn: URN,
    aspect: "ownership",
    versions: [
      { value: { owners: [{ owner: "urn:li:corpGroup:finance" }] }, systemMetadata: { version: "1", lastObserved: 1, runId: "run-snowflake" } },
      { value: { owners: [{ owner: "urn:li:corpGroup:ops" }] }, systemMetadata: { version: "2", lastObserved: 2, runId: "run-dbt" } },
    ],
  };
  const noise: AspectVersionHistory = {
    urn: "urn:li:dataset:(urn:li:dataPlatform:snowflake,noise,PROD)",
    aspect: "ownership",
    versions: [
      { value: { owners: [{ owner: "urn:li:corpGroup:x" }] }, systemMetadata: { version: "1", lastObserved: 1, runId: "no-run-id-provided" } },
      { value: { owners: [{ owner: "urn:li:corpGroup:y" }] }, systemMetadata: { version: "2", lastObserved: 2, runId: "no-run-id-provided" } },
    ],
  };
  const report = auditVersionHistory([genuine, noise]);
  assert.equal(report.contradictions.length, 1, "the real conflict must not be masked by the noise");
  assert.equal(report.contradictions[0]!.subject, URN);
  assert.equal(report.contradictions[0]!.attribute, "owner");
});

test("engine-injection: malformed / hostile aspect shapes never throw", () => {
  const hostile: AspectVersionHistory[] = [
    // null value / missing systemMetadata / empty versions
    { urn: URN, aspect: "ownership", versions: [{ value: null, systemMetadata: null }] },
    { urn: URN, aspect: "schemaMetadata", versions: [] },
    // huge string as an owner + weird nested types
    {
      urn: URN,
      aspect: "ownership",
      versions: [
        { value: { owners: [{ owner: "z".repeat(200_000) }] }, systemMetadata: { runId: "r1", lastObserved: 1 } },
        { value: { owners: "not-an-array" as unknown as [] }, systemMetadata: { runId: "r2", lastObserved: 2 } },
      ],
    },
    // schemaMetadata with malformed fields
    {
      urn: URN,
      aspect: "schemaMetadata",
      versions: [
        { value: { fields: [{ fieldPath: 123, nativeDataType: null }] as unknown as [] }, systemMetadata: { runId: "r1" } },
      ],
    },
  ];
  assert.doesNotThrow(() => auditVersionHistory(hostile));
});

test("engine-injection: a __proto__-laden aspect value does NOT pollute Object.prototype", () => {
  // Simulate untrusted GMS input arriving via JSON (the real transport path).
  const value = JSON.parse('{"owners":[{"owner":"urn:li:corpGroup:a"}],"__proto__":{"polluted":"yes"}}');
  const value2 = JSON.parse('{"owners":[{"owner":"urn:li:corpGroup:b"}],"constructor":{"prototype":{"polluted":"yes"}}}');
  const history: AspectVersionHistory = {
    urn: URN,
    aspect: "ownership",
    versions: [
      { value, systemMetadata: { version: "1", lastObserved: 1, runId: "run-a" } },
      { value: value2, systemMetadata: { version: "2", lastObserved: 2, runId: "run-b" } },
    ],
  };
  assert.doesNotThrow(() => auditVersionHistory([history]));
  assert.equal(({} as Record<string, unknown>)["polluted"], undefined, "Object.prototype must not be polluted");
});

test("engine-injection: requireDistinctSources holds directly on the consistency engine", () => {
  // Two conflicting facts from the SAME source must never be flagged when the gate is on.
  const facts: AuditFact[] = [
    { id: "f1", kind: "ownership", source: "s1", scan: "v1", sourceRef: URN, content: "", metadata: { record: URN, owner: "a" }, createdAt: "2026-01-01T00:00:00Z" },
    { id: "f2", kind: "ownership", source: "s1", scan: "v2", sourceRef: URN, content: "", metadata: { record: URN, owner: "b" }, createdAt: "2026-02-01T00:00:00Z" },
  ];
  assert.equal(auditConsistency(facts, { requireDistinctSources: true }).contradictions.length, 0);
  // …but two DISTINCT sources disagreeing is a real contradiction.
  facts[1]!.source = "s2";
  assert.equal(auditConsistency(facts, { requireDistinctSources: true }).contradictions.length, 1);
});
