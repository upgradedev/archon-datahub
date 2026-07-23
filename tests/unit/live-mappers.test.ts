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
  mapEntitiesStrict,
  mapSearchPageStrict,
  mapSearchUrns,
  mapUpstreamEdges,
  mapUpstreamEdgesStrict,
  parseMcpReadToolResult,
  type DhCleanedEntity,
  type DhLineageResponse,
  type DhSearchResponse,
} from "../../src/datahub/live-mappers.js";
import { DataHubHarvestError } from "../../src/datahub/harvest-policy.js";
import { LiveDataHubMcpClient } from "../../src/datahub/mcp-client-live.js";

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

test("strict get_entities mapping requires each requested URN exactly once", () => {
  const rawEntity: DhCleanedEntity = {
    urn: RAW,
    properties: { name: "raw_orders" },
  };
  const entities = mapEntitiesStrict(
    [rawEntity, salesEntity],
    [RAW, SALES],
    "datahub"
  );
  assert.deepEqual(
    entities.map((entity) => entity.urn),
    [RAW, SALES],
    "output follows the deterministic request order"
  );
});

test("strict get_entities mapping fails on per-URN errors, missing, duplicates, and extras", () => {
  const missing = "urn:li:dataset:(urn:li:dataPlatform:snowflake,missing,PROD)";
  const cases: Array<DhCleanedEntity[]> = [
    [salesEntity, { urn: missing, error: "not found" }],
    [salesEntity],
    [salesEntity, salesEntity],
    [salesEntity, { urn: EXTERNAL }],
    [salesEntity, {}],
  ];
  for (const response of cases) {
    assert.throws(
      () => mapEntitiesStrict(response, [SALES, missing], "datahub"),
      (error: unknown) =>
        error instanceof DataHubHarvestError &&
        error.code === "ENTITY_RESPONSE_INCOMPLETE"
    );
  }
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

test("strict search mapping accepts a complete page at the configured ceiling", () => {
  const page = mapSearchPageStrict(
    {
      start: 0,
      count: 2,
      total: 2,
      searchResults: [
        { entity: { urn: SALES } },
        { entity: { urn: RAW } },
      ],
    },
    0,
    2
  );
  assert.deepEqual(page, { urns: [SALES, RAW], total: 2 });
});

test("strict search mapping fails closed before returning a partial result above the ceiling", () => {
  assert.throws(
    () =>
      mapSearchPageStrict(
        {
          start: 0,
          count: 2,
          total: 3,
          searchResults: [
            { entity: { urn: SALES } },
            { entity: { urn: RAW } },
          ],
        },
        0,
        2
      ),
    (error: unknown) =>
      error instanceof DataHubHarvestError &&
      error.code === "SEARCH_LIMIT_EXCEEDED"
  );
});

test("strict search mapping rejects malformed counts, missing URNs, and duplicates", () => {
  const cases: DhSearchResponse[] = [
    {
      start: 1,
      count: 1,
      total: 1,
      searchResults: [{ entity: { urn: SALES } }],
    },
    {
      start: 0,
      count: 2,
      total: 2,
      searchResults: [{ entity: { urn: SALES } }],
    },
    {
      start: 0,
      count: 1,
      total: 1,
      searchResults: [{ entity: {} }],
    },
    {
      start: 0,
      count: 2,
      total: 2,
      searchResults: [
        { entity: { urn: SALES } },
        { entity: { urn: SALES } },
      ],
    },
  ];
  for (const response of cases) {
    assert.throws(
      () => mapSearchPageStrict(response, 0, 2),
      (error: unknown) =>
        error instanceof DataHubHarvestError &&
        error.code === "SEARCH_RESPONSE_INCOMPLETE"
    );
  }
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

test("MCP read envelope rejects isError, ambiguity, and non-JSON content", () => {
  assert.deepEqual(
    parseMcpReadToolResult({
      structuredContent: { total: 0 },
      content: [],
    }),
    { total: 0 }
  );
  assert.deepEqual(
    parseMcpReadToolResult({
      content: [{ type: "text", text: "{\"total\":0}" }],
    }),
    { total: 0 }
  );
  const cases = [
    {
      value: {
        isError: true,
        content: [{ type: "text", text: "{\"error\":\"provider\"}" }],
      },
      code: "MCP_TOOL_ERROR",
    },
    { value: null, code: "MCP_RESPONSE_INVALID" },
    { value: { content: [] }, code: "MCP_RESPONSE_INVALID" },
    {
      value: {
        content: [
          { type: "text", text: "{}" },
          { type: "text", text: "{}" },
        ],
      },
      code: "MCP_RESPONSE_INVALID",
    },
    {
      value: { content: [{ type: "text", text: "not-json" }] },
      code: "MCP_RESPONSE_INVALID",
    },
  ] as const;
  for (const { value, code } of cases) {
    assert.throws(
      () => parseMcpReadToolResult(value),
      (error: unknown) =>
        error instanceof DataHubHarvestError && error.code === code
    );
  }
});

test("strict lineage mapping requires one complete offset-zero upstream page", () => {
  const edges = mapUpstreamEdgesStrict(
    {
      upstreams: {
        start: 0,
        count: 2,
        total: 2,
        searchResults: [
          { entity: { urn: RAW }, degree: 1 },
          { entity: { urn: EXTERNAL }, degree: 1 },
        ],
      },
    },
    (urn) => urn === RAW,
    50
  );
  assert.deepEqual(
    edges.map(({ upstream, upstreamResolved }) => ({
      upstream,
      upstreamResolved,
    })),
    [
      { upstream: RAW, upstreamResolved: true },
      { upstream: EXTERNAL, upstreamResolved: false },
    ]
  );
  assert.deepEqual(
    mapUpstreamEdgesStrict(
      {
        upstreams: {
          start: 0,
          count: 0,
          total: 0,
          searchResults: [],
        },
      },
      () => false,
      50
    ),
    []
  );
});

test("strict lineage mapping aborts malformed, truncated, or duplicate responses", () => {
  const cases: Array<DhLineageResponse | null> = [
    null,
    {},
    { upstreams: { start: 1, count: 0, total: 0, searchResults: [] } },
    {
      upstreams: {
        start: 0,
        count: 1,
        total: 2,
        searchResults: [{ entity: { urn: RAW }, degree: 1 }],
      },
    },
    {
      upstreams: {
        start: 0,
        count: 1,
        total: 1,
        searchResults: [{ entity: {}, degree: 1 }],
      },
    },
    {
      upstreams: {
        start: 0,
        count: 1,
        total: 1,
        searchResults: [{ entity: { urn: RAW } }],
      },
    },
    {
      upstreams: {
        start: 0,
        count: 2,
        total: 2,
        searchResults: [
          { entity: { urn: RAW }, degree: 1 },
          { entity: { urn: RAW }, degree: 1 },
        ],
      },
    },
  ];
  for (const response of cases) {
    assert.throws(
      () => mapUpstreamEdgesStrict(response, () => true, 50),
      (error: unknown) =>
        error instanceof DataHubHarvestError &&
        error.code === "LINEAGE_RESPONSE_INCOMPLETE"
    );
  }
  assert.throws(
    () => mapUpstreamEdgesStrict(
      {
        upstreams: {
          start: 0,
          count: 0,
          total: 0,
          searchResults: [],
        },
      },
      () => true,
      0
    ),
    RangeError
  );
});

test("MCP-only live hosted audits fail before harvesting without direct GMS history", async () => {
  const saved = {
    gms: process.env.DATAHUB_GMS_URL,
    mcp: process.env.DATAHUB_MCP_URL,
  };
  delete process.env.DATAHUB_GMS_URL;
  process.env.DATAHUB_MCP_URL = "https://read-only.example.test/mcp";
  try {
    await assert.rejects(
      new LiveDataHubMcpClient().harvestAudit("archon_demo", {
        profile: "async-worker",
      }),
      (error: unknown) =>
        error instanceof DataHubHarvestError &&
        error.code === "HISTORY_CAPABILITY_REQUIRED"
    );
  } finally {
    if (saved.gms === undefined) delete process.env.DATAHUB_GMS_URL;
    else process.env.DATAHUB_GMS_URL = saved.gms;
    if (saved.mcp === undefined) delete process.env.DATAHUB_MCP_URL;
    else process.env.DATAHUB_MCP_URL = saved.mcp;
  }
});
