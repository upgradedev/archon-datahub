// Unit tests for the PINNED DataHub MCP response mappers (src/datahub/live-mappers.ts).
//
// Fixtures below are the CLEANED response shapes the official DataHub MCP server actually
// returns — modelled on acryldata/mcp-server-datahub's own tests + graphql_helpers cleaning:
//   • dataset-level ownership/domain/globalTags/glossaryTerms stay NESTED,
//   • field-level tags/glossaryTerms are FLATTENED to name arrays by _clean_schema_fields,
//   • field `type` is an UPPERCASE enum, description lives under `properties`,
//   • search / lineage wrap entities in a `searchResults[]` envelope,
//   • get_entities returns a LIST (array in → array out), with { error, urn } for failures.
// These pin the adapter to the real server so it works the moment it connects.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mapEntity,
  mapEntities,
  mapSearchUrns,
  mapUpstreamEdges,
  type DhCleanedEntity,
  type DhLineageResponse,
  type DhSearchResponse,
} from "../../src/datahub/live-mappers.js";

const SALES = "urn:li:dataset:(urn:li:dataPlatform:snowflake,db.public.sales_orders,PROD)";
const RAW = "urn:li:dataset:(urn:li:dataPlatform:snowflake,db.public.raw_orders,PROD)";
const EXTERNAL = "urn:li:dataset:(urn:li:dataPlatform:external,external_feed,PROD)";

// A fully-populated cleaned dataset entity, exactly as get_entities returns it.
const salesEntity: DhCleanedEntity = {
  urn: SALES,
  type: "DATASET",
  name: "sales_orders",
  platform: { urn: "urn:li:dataPlatform:snowflake", name: "snowflake" },
  properties: { name: "sales_orders", description: "Curated sales orders." },
  ownership: {
    owners: [
      { owner: { urn: "urn:li:corpGroup:team-finance" }, type: "DATAOWNER" },
      { owner: { urn: "urn:li:corpuser:jdoe" }, type: "TECHNICAL_OWNER" },
    ],
  },
  domain: { domain: { urn: "urn:li:domain:sales", properties: { name: "Sales" } } },
  globalTags: {
    tags: [{ tag: { urn: "urn:li:tag:tier-1", properties: { name: "tier-1" } } }],
  },
  glossaryTerms: {
    terms: [{ term: { urn: "urn:li:glossaryTerm:Revenue", properties: { name: "Revenue" } } }],
  },
  deprecation: { deprecated: false },
  schemaMetadata: {
    fields: [
      { fieldPath: "order_id", type: "NUMBER", isPartOfKey: true },
      { fieldPath: "amount", type: "NUMBER", nativeDataType: "NUMBER(38,2)" },
      // field-level tags/terms arrive already flattened to name arrays:
      { fieldPath: "customer_email", type: "STRING", tags: ["pii"], glossaryTerms: ["Classification.PII"] },
    ],
  },
};

test("mapEntity maps nested dataset aspects + flattened field aspects", () => {
  const e = mapEntity(salesEntity, "datahub");
  assert.equal(e.urn, SALES);
  assert.equal(e.name, "sales_orders");
  assert.equal(e.platform, "snowflake");
  assert.equal(e.source, "datahub");
  assert.equal(e.description, "Curated sales orders.");
  // ownership.owners[].owner.urn (primary first)
  assert.deepEqual(e.owners, ["urn:li:corpGroup:team-finance", "urn:li:corpuser:jdoe"]);
  assert.equal(e.domain, "urn:li:domain:sales");
  assert.deepEqual(e.tags, ["tier-1"]); // globalTags.tags[].tag.properties.name
  assert.deepEqual(e.glossaryTerms, ["Revenue"]);
  assert.equal(e.deprecated, false);
  // field type normalized to lowercase for Fake<->live parity
  const amount = e.fields!.find((f) => f.path === "amount")!;
  assert.equal(amount.type, "number");
  const email = e.fields!.find((f) => f.path === "customer_email")!;
  assert.deepEqual(email.tags, ["pii"]);
  assert.deepEqual(email.glossaryTerms, ["Classification.PII"]);
});

test("mapEntity description falls back editableProperties -> top-level; platform from urn", () => {
  const e = mapEntity(
    {
      urn: EXTERNAL,
      editableProperties: { description: "edited desc" },
      // no platform object — must be parsed from the URN's dataPlatform
    },
    "datahub"
  );
  assert.equal(e.description, "edited desc");
  assert.equal(e.platform, "external");
  assert.equal(e.owners!.length, 0);
  assert.equal(e.domain, null);
});

test("mapEntity handles a bare/minimal entity without throwing", () => {
  const e = mapEntity({ urn: RAW }, "datahub");
  assert.equal(e.urn, RAW);
  assert.equal(e.name, RAW); // no properties.name/name → falls back to urn
  assert.deepEqual(e.fields, []);
  assert.equal(e.deprecated, false);
});

test("mapEntities skips per-URN error objects and empties", () => {
  const res: DhCleanedEntity[] = [
    salesEntity,
    { error: "Entity ... not found", urn: "urn:li:dataset:(...,missing,PROD)" },
    {}, // no urn
  ];
  const entities = mapEntities(res, "datahub");
  assert.equal(entities.length, 1);
  assert.equal(entities[0]!.urn, SALES);
});

test("mapEntities accepts a single-object payload wrapped in {entities}", () => {
  const entities = mapEntities({ entities: [salesEntity] }, "datahub");
  assert.equal(entities.length, 1);
});

test("mapEntities returns [] for null/empty", () => {
  assert.deepEqual(mapEntities(null, "datahub"), []);
  assert.deepEqual(mapEntities([], "datahub"), []);
});

test("mapSearchUrns pulls URNs from the searchAcrossEntities envelope", () => {
  const res: DhSearchResponse = {
    start: 0,
    count: 2,
    total: 2,
    searchResults: [
      { entity: { urn: SALES, type: "DATASET" } },
      { entity: { urn: RAW, type: "DATASET" } },
      { entity: {} }, // no urn → dropped
    ],
  };
  assert.deepEqual(mapSearchUrns(res), [SALES, RAW]);
  assert.deepEqual(mapSearchUrns(null), []);
  assert.deepEqual(mapSearchUrns({}), []);
});

test("mapUpstreamEdges reads upstreams.searchResults and resolves against knownUrns", () => {
  const res: DhLineageResponse = {
    upstreams: {
      searchResults: [
        { entity: { urn: RAW, type: "DATASET" }, degree: 1 },
        { entity: { urn: EXTERNAL, type: "DATASET" }, degree: 1 },
      ],
    },
  };
  const known = new Set([RAW]); // EXTERNAL is not catalogued → the lineage gap
  const edges = mapUpstreamEdges(res, (u) => known.has(u));
  assert.equal(edges.length, 2);
  const raw = edges.find((e) => e.upstream === RAW)!;
  const ext = edges.find((e) => e.upstream === EXTERNAL)!;
  assert.equal(raw.upstreamResolved, true);
  assert.equal(ext.upstreamResolved, false);
});

test("mapUpstreamEdges returns [] when there is no upstream lineage", () => {
  assert.deepEqual(mapUpstreamEdges(null, () => true), []);
  assert.deepEqual(mapUpstreamEdges({ upstreams: {} }, () => true), []);
  assert.deepEqual(mapUpstreamEdges({ downstreams: { searchResults: [] } }, () => true), []);
});
