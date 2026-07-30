// Unit tests for the deterministic governance validator (G1–G6) and the sensitive-
// field heuristic. Proves each policy rule fires (and skips) on real-shaped catalog
// entities, and that the whole-snapshot pass returns one result per rule per entity.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validateEntity,
  validateSnapshot,
  GovernanceValidator,
} from "../../src/governance/validator.js";
import type { GovernancePolicy } from "../../src/governance/validator.js";
import { looksSensitive } from "../../src/datahub/models.js";
import type {
  CatalogEntity,
  CatalogSnapshot,
  LineageTopologyNode,
} from "../../src/datahub/models.js";
import { DataHubHarvestError } from "../../src/datahub/harvest-policy.js";
import { GovernanceAuditorAgent } from "../../src/agents/governance-auditor.js";

function derivedTopology(
  entities: CatalogEntity[]
): Map<string, LineageTopologyNode[]> {
  const byUrn = new Map(entities.map((entity) => [entity.urn, entity]));
  const consumers = new Map<string, string[]>();
  for (const entity of entities) {
    for (const edge of entity.upstreams ?? []) {
      if (!edge.upstreamResolved || !byUrn.has(edge.upstream)) continue;
      const values = consumers.get(edge.upstream) ?? [];
      values.push(entity.urn);
      consumers.set(edge.upstream, values);
    }
  }
  const result = new Map<string, LineageTopologyNode[]>();
  for (const root of entities) {
    const distances = new Map<string, number>();
    const queue = [{ urn: root.urn, hops: 0 }];
    for (let cursor = 0; cursor < queue.length; cursor += 1) {
      const current = queue[cursor]!;
      for (const urn of consumers.get(current.urn) ?? []) {
        if (urn === root.urn || distances.has(urn)) continue;
        const minHops = current.hops + 1;
        distances.set(urn, minHops);
        queue.push({ urn, hops: minHops });
      }
    }
    result.set(
      root.urn,
      [...distances].map(([urn, minHops]) => ({
        urn,
        minHops,
        entityType: "DATASET",
        deprecated: byUrn.get(urn)?.deprecated === true,
      }))
    );
  }
  return result;
}

function snapshot(
  entities: CatalogEntity[],
  downstreamByRoot: Map<string, LineageTopologyNode[]> = derivedTopology(
    entities
  )
): CatalogSnapshot {
  return {
    scanId: "scan-1",
    entities,
    knownUrns: new Set(entities.map((e) => e.urn)),
    downstreamByRoot,
  };
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

test("G4 ignores deprecated consumers and non-direct descendants", () => {
  const parent: CatalogEntity = {
    ...clean,
    urn: "urn:ds:parent",
    deprecated: true,
  };
  const deprecatedChild: CatalogEntity = {
    ...clean,
    urn: "urn:ds:deprecated-child",
    deprecated: true,
  };
  const topology = new Map<string, LineageTopologyNode[]>([
    [
      parent.urn,
      [
        {
          urn: deprecatedChild.urn,
          minHops: 1,
          entityType: "DATASET",
          deprecated: true,
        },
        {
          urn: "urn:ds:indirect-active",
          minHops: 2,
          entityType: "DASHBOARD",
          deprecated: false,
        },
      ],
    ],
    [deprecatedChild.urn, []],
  ]);
  const g4 = validateEntity(
    parent,
    snapshot([parent, deprecatedChild], topology)
  ).find((result) => result.ruleId === "G4")!;
  assert.equal(g4.passed, true);
  assert.match(g4.message, /no active downstream/i);
});

test("G4 fails closed when deprecated-root topology is unavailable", () => {
  const parent: CatalogEntity = {
    ...clean,
    urn: "urn:ds:parent",
    deprecated: true,
  };
  assert.throws(
    () => validateEntity(parent, snapshot([parent], new Map())),
    (error: unknown) =>
      error instanceof DataHubHarvestError &&
      error.code === "LINEAGE_RESPONSE_INCOMPLETE"
  );
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

test("G6 rejects unrelated metadata and substring lookalikes", () => {
  const e: CatalogEntity = {
    ...clean,
    urn: "urn:ds:unrelated-classification",
    fields: [
      {
        path: "customer_email",
        type: "string",
        tags: ["tier-1", "NOT_PII"],
        glossaryTerms: ["Customer", "Classification.PII.Future"],
      },
    ],
  };
  const g6 = validateEntity(e, snapshot([e])).find((r) => r.ruleId === "G6")!;
  assert.equal(g6.passed, false);
  assert.deepEqual(g6.evidence?.["unclassifiedFields"], ["customer_email"]);
});

test("G6 accepts only the default exact PII tag and glossary-term identifiers", () => {
  const acceptedTags = ["PII", "pii", "urn:li:tag:PII"];
  const acceptedTerms = [
    "PII",
    "pii",
    "Classification.PII",
    "urn:li:glossaryTerm:Classification.PII",
  ];

  for (const [index, tag] of acceptedTags.entries()) {
    const e: CatalogEntity = {
      ...clean,
      urn: `urn:ds:accepted-tag-${index}`,
      fields: [{ path: "customer_email", type: "string", tags: [tag] }],
    };
    const g6 = validateEntity(e, snapshot([e])).find((r) => r.ruleId === "G6")!;
    assert.equal(g6.passed, true, `expected tag ${tag} to satisfy G6`);
  }

  for (const [index, term] of acceptedTerms.entries()) {
    const e: CatalogEntity = {
      ...clean,
      urn: `urn:ds:accepted-term-${index}`,
      fields: [
        {
          path: "customer_email",
          type: "string",
          glossaryTerms: [term],
        },
      ],
    };
    const g6 = validateEntity(e, snapshot([e])).find((r) => r.ruleId === "G6")!;
    assert.equal(g6.passed, true, `expected term ${term} to satisfy G6`);
  }
});

test("G6 supports a custom sensitive hint and exact classification policy", () => {
  const policy: GovernancePolicy = {
    sensitiveFieldHints: ["account_code"],
    acceptedClassificationTagIdentifiers: ["regulated.exact"],
    acceptedClassificationTermIdentifiers: ["urn:custom:term:regulated"],
  };
  const withDefaultPii: CatalogEntity = {
    ...clean,
    urn: "urn:ds:custom-unclassified",
    fields: [
      {
        path: "merchant_account_code",
        type: "string",
        tags: ["PII"],
      },
    ],
  };
  const customTag: CatalogEntity = {
    ...withDefaultPii,
    urn: "urn:ds:custom-tag",
    fields: [
      {
        path: "merchant_account_code",
        type: "string",
        tags: ["regulated.exact"],
      },
    ],
  };
  const customTerm: CatalogEntity = {
    ...withDefaultPii,
    urn: "urn:ds:custom-term",
    fields: [
      {
        path: "merchant_account_code",
        type: "string",
        glossaryTerms: ["urn:custom:term:regulated"],
      },
    ],
  };

  const unclassified = validateEntity(
    withDefaultPii,
    snapshot([withDefaultPii]),
    policy
  ).find((r) => r.ruleId === "G6")!;
  assert.equal(unclassified.passed, false);

  const tagged = validateSnapshot(snapshot([customTag]), policy).find(
    (r) => r.ruleId === "G6"
  )!;
  assert.equal(tagged.passed, true);

  const termed = new GovernanceValidator(policy)
    .validate(snapshot([customTerm]))
    .find((r) => r.ruleId === "G6")!;
  assert.equal(termed.passed, true);

  const injectedAgentFindings = new GovernanceAuditorAgent(policy).audit(
    snapshot([withDefaultPii])
  );
  assert.equal(
    injectedAgentFindings.some(
      (finding) =>
        finding.type === "governance_violation" &&
        finding.detail["ruleId"] === "G6"
    ),
    true
  );
});

test("governance policy compilation rejects ambiguous or empty configuration", () => {
  const valid: GovernancePolicy = {
    sensitiveFieldHints: ["email"],
    acceptedClassificationTagIdentifiers: ["PII"],
    acceptedClassificationTermIdentifiers: [],
  };
  const invalidPolicies: unknown[] = [
    null,
    { ...valid, sensitiveFieldHints: [] },
    { ...valid, sensitiveFieldHints: ["   "] },
    { ...valid, acceptedClassificationTagIdentifiers: [" PII"] },
    {
      ...valid,
      acceptedClassificationTagIdentifiers: [],
      acceptedClassificationTermIdentifiers: [],
    },
    {
      ...valid,
      acceptedClassificationTagIdentifiers: "PII",
    },
  ];

  for (const policy of invalidPolicies) {
    assert.throws(
      () => new GovernanceValidator(policy as GovernancePolicy),
      TypeError
    );
  }
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
