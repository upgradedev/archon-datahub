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
  assertLineageRelationLimit,
  completeEntitySchema,
  mapDownstreamTopologyStrict,
  mapEntity,
  mapEntities,
  mapEntitiesStrict,
  mapSchemaFieldPageStrict,
  mapSearchPageStrict,
  mapSearchUrns,
  mapUpstreamEdges,
  mapUpstreamEdgesStrict,
  parseMcpReadToolResult,
  reconcileUpstreamEdgesStrict,
  schemaCompletionRequirement,
  type DhCleanedEntity,
  type DhCleanedSchemaField,
  type DhLineageResponse,
  type DhSchemaFieldPageResponse,
  type DhSearchResponse,
} from "../../src/datahub/live-mappers.js";
import type {
  CatalogEntity,
  LineageEdge,
  LineageTopologyNode,
  Urn,
} from "../../src/datahub/models.js";
import {
  DataHubHarvestError,
  harvestPolicy,
  type LiveHarvestPolicy,
} from "../../src/datahub/harvest-policy.js";
import { LiveDataHubMcpClient } from "../../src/datahub/mcp-client-live.js";
import type { DeclaredUpstreamLineage } from "../../src/datahub/version-history-reader.js";

const SALES = "urn:li:dataset:(urn:li:dataPlatform:snowflake,db.public.sales_orders,PROD)";
const RAW = "urn:li:dataset:(urn:li:dataPlatform:snowflake,db.public.raw_orders,PROD)";
const EXTERNAL = "urn:li:dataset:(urn:li:dataPlatform:external,external_feed,PROD)";

type LiveSearchHarness = {
  call(
    name: string,
    args: Record<string, unknown>,
    signal: AbortSignal,
    timeoutMs: number
  ): Promise<unknown>;
  searchWithinPolicy(
    query: string | undefined,
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<string[]>;
};

type LiveEntityHarness = {
  call(
    name: string,
    args: Record<string, unknown>,
    signal: AbortSignal,
    timeoutMs: number
  ): Promise<unknown>;
  getEntitiesWithinPolicy(
    urns: Urn[],
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<CatalogEntity[]>;
};

type LiveLineageHarness = {
  call(
    name: string,
    args: Record<string, unknown>,
    signal: AbortSignal,
    timeoutMs: number
  ): Promise<unknown>;
  getLineageTopologyWithinPolicy(
    urns: readonly Urn[],
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<{
    upstreamByRoot: Map<Urn, LineageEdge[]>;
    downstreamByRoot: Map<Urn, LineageTopologyNode[]>;
    knownLineageUrns: Set<Urn>;
  }>;
};

function mockedLiveSearch(pages: readonly DhSearchResponse[]): {
  search(): Promise<string[]>;
  offsets: number[];
  remaining(): number;
} {
  const pending = [...pages];
  const offsets: number[] = [];
  const client = new LiveDataHubMcpClient() as unknown as LiveSearchHarness;
  client.call = async (name, args) => {
    assert.equal(name, "search");
    assert.equal(args["num_results"], 50);
    assert.equal(typeof args["offset"], "number");
    offsets.push(args["offset"] as number);
    const page = pending.shift();
    assert.ok(page, "live search made an unexpected extra MCP request");
    return page;
  };
  return {
    search: () =>
      client.searchWithinPolicy(
        undefined,
        harvestPolicy("async-worker"),
        new AbortController().signal
      ),
    offsets,
    remaining: () => pending.length,
  };
}

function mockedLiveEntities(
  entity: DhCleanedEntity,
  pages: readonly DhSchemaFieldPageResponse[]
): {
  load(policy?: Readonly<LiveHarvestPolicy>): Promise<CatalogEntity[]>;
  offsets: number[];
  remaining(): number;
} {
  const pending = [...pages];
  const offsets: number[] = [];
  const client = new LiveDataHubMcpClient() as unknown as LiveEntityHarness;
  client.call = async (name, args) => {
    if (name === "get_entities") return [entity];
    assert.equal(name, "list_schema_fields");
    assert.equal(args["urn"], entity.urn);
    assert.equal(args["limit"], 100);
    assert.equal(typeof args["offset"], "number");
    offsets.push(args["offset"] as number);
    const page = pending.shift();
    assert.ok(page, "schema completion made an unexpected extra MCP request");
    return page;
  };
  return {
    load: (policy = harvestPolicy("synchronous-preview")) =>
      client.getEntitiesWithinPolicy(
        [entity.urn!],
        policy,
        new AbortController().signal
      ),
    offsets,
    remaining: () => pending.length,
  };
}

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
      {
        fieldPath: "customer_email",
        type: "STRING",
        tags: ["pii"],
        editedTags: ["restricted", "pii"],
        glossaryTerms: ["Classification.PII"],
        editedGlossaryTerms: ["CustomerIdentifier", "Classification.PII"],
      },
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
  assert.deepEqual(email.tags, ["pii", "restricted"]);
  assert.deepEqual(email.glossaryTerms, [
    "Classification.PII",
    "CustomerIdentifier",
  ]);
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

test("schema completion marker blocks mapping until the exact full schema is supplied", () => {
  const partial: DhCleanedEntity = {
    ...salesEntity,
    schemaMetadata: {
      fields: salesEntity.schemaMetadata!.fields!.slice(0, 1),
      schemaFieldsTruncated: {
        totalFields: 3,
        includedFields: 1,
        offset: 0,
      },
    },
  };
  assert.deepEqual(schemaCompletionRequirement(partial, 3), {
    required: true,
    totalFields: 3,
  });
  assert.throws(
    () => mapEntity(partial, "datahub"),
    (error: unknown) =>
      error instanceof DataHubHarvestError &&
      error.code === "SCHEMA_RESPONSE_INCOMPLETE"
  );

  const complete = completeEntitySchema(
    partial,
    salesEntity.schemaMetadata!.fields!,
    3
  );
  assert.equal(
    complete.schemaMetadata?.schemaFieldsTruncated,
    undefined
  );
  assert.equal(mapEntity(complete, "datahub").fields?.length, 3);
  assert.deepEqual(schemaCompletionRequirement(complete, 3), {
    required: false,
    totalFields: 3,
  });
});

test("schema completeness enforces marker integrity and the per-entity field ceiling", () => {
  const first = salesEntity.schemaMetadata!.fields!.slice(0, 1);
  const malformedMarkers = [
    { totalFields: 3, includedFields: 2, offset: 0 },
    { totalFields: 1, includedFields: 1, offset: 0 },
    { totalFields: 3, includedFields: 1, offset: 1 },
  ];
  for (const marker of malformedMarkers) {
    assert.throws(
      () =>
        schemaCompletionRequirement(
          {
            urn: SALES,
            schemaMetadata: {
              fields: first,
              schemaFieldsTruncated: marker,
            },
          },
          3
        ),
      (error: unknown) =>
        error instanceof DataHubHarvestError &&
        error.code === "SCHEMA_RESPONSE_INCOMPLETE"
    );
  }
  assert.throws(
    () =>
      schemaCompletionRequirement(
        {
          urn: SALES,
          schemaMetadata: {
            fields: first,
            schemaFieldsTruncated: {
              totalFields: 4,
              includedFields: 1,
              offset: 0,
            },
          },
        },
        3
      ),
    (error: unknown) =>
      error instanceof DataHubHarvestError &&
      error.code === "SCHEMA_LIMIT_EXCEEDED"
  );
});

test("strict schema-field pages accept token-short pages and exact pagination metadata", () => {
  const fields = salesEntity.schemaMetadata!.fields!;
  const page = mapSchemaFieldPageStrict(
    {
      urn: SALES,
      fields: fields.slice(0, 1),
      totalFields: 3,
      returned: 1,
      remainingCount: 2,
      matchingCount: null,
      offset: 0,
    },
    SALES,
    0,
    100,
    3
  );
  assert.equal(page.total, 3);
  assert.deepEqual(page.fields, fields.slice(0, 1));

  const finalPage = mapSchemaFieldPageStrict(
    {
      urn: SALES,
      fields: fields.slice(1),
      totalFields: 3,
      returned: 2,
      remainingCount: 0,
      matchingCount: null,
      offset: 1,
    },
    SALES,
    1,
    100,
    3
  );
  assert.equal(finalPage.fields.length, 2);
});

test("strict schema-field pages reject zero progress, duplicates, drift, and limits", () => {
  const duplicate: DhCleanedSchemaField = {
    fieldPath: "order_id",
    type: "NUMBER",
  };
  const cases: Array<{
    response: DhSchemaFieldPageResponse;
    code: "SCHEMA_RESPONSE_INCOMPLETE" | "SCHEMA_LIMIT_EXCEEDED";
  }> = [
    {
      response: {
        urn: SALES,
        totalFields: 0,
        returned: 0,
        remainingCount: 0,
        matchingCount: null,
        offset: 0,
      },
      code: "SCHEMA_RESPONSE_INCOMPLETE",
    },
    {
      response: {
        urn: SALES,
        fields: [],
        totalFields: 2,
        returned: 0,
        remainingCount: 2,
        matchingCount: null,
        offset: 0,
      },
      code: "SCHEMA_RESPONSE_INCOMPLETE",
    },
    {
      response: {
        urn: SALES,
        fields: [duplicate, duplicate],
        totalFields: 2,
        returned: 2,
        remainingCount: 0,
        matchingCount: null,
        offset: 0,
      },
      code: "SCHEMA_RESPONSE_INCOMPLETE",
    },
    {
      response: {
        urn: SALES,
        fields: [duplicate],
        totalFields: 2,
        returned: 1,
        remainingCount: 0,
        matchingCount: null,
        offset: 0,
      },
      code: "SCHEMA_RESPONSE_INCOMPLETE",
    },
    {
      response: {
        urn: SALES,
        fields: [duplicate],
        totalFields: 4,
        returned: 1,
        remainingCount: 3,
        matchingCount: null,
        offset: 0,
      },
      code: "SCHEMA_LIMIT_EXCEEDED",
    },
  ];
  for (const scenario of cases) {
    assert.throws(
      () =>
        mapSchemaFieldPageStrict(
          scenario.response,
          SALES,
          0,
          100,
          3
        ),
      (error: unknown) =>
        error instanceof DataHubHarvestError &&
        error.code === scenario.code
    );
  }
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

test("live schema completion advances by returned fields and maps only after completion", async () => {
  const allFields = salesEntity.schemaMetadata!.fields!;
  const partial: DhCleanedEntity = {
    ...salesEntity,
    schemaMetadata: {
      fields: allFields.slice(0, 1),
      schemaFieldsTruncated: {
        totalFields: 3,
        includedFields: 1,
        offset: 0,
      },
    },
  };
  const mocked = mockedLiveEntities(partial, [
    {
      urn: SALES,
      fields: allFields.slice(0, 1),
      totalFields: 3,
      returned: 1,
      remainingCount: 2,
      matchingCount: null,
      offset: 0,
    },
    {
      urn: SALES,
      fields: allFields.slice(1),
      totalFields: 3,
      returned: 2,
      remainingCount: 0,
      matchingCount: null,
      offset: 1,
    },
  ]);
  const [entity] = await mocked.load();
  assert.equal(entity?.fields?.length, 3);
  assert.deepEqual(mocked.offsets, [0, 1]);
  assert.equal(mocked.remaining(), 0);
  assert.deepEqual(
    entity?.fields?.find((field) => field.path === "customer_email")?.tags,
    ["pii", "restricted"]
  );
});

test("live schema completion rejects cross-page duplicates and page-ceiling exhaustion", async () => {
  const allFields = salesEntity.schemaMetadata!.fields!;
  const partial: DhCleanedEntity = {
    ...salesEntity,
    schemaMetadata: {
      fields: allFields.slice(0, 1),
      schemaFieldsTruncated: {
        totalFields: 3,
        includedFields: 1,
        offset: 0,
      },
    },
  };
  const duplicate = mockedLiveEntities(partial, [
    {
      urn: SALES,
      fields: allFields.slice(0, 1),
      totalFields: 3,
      returned: 1,
      remainingCount: 2,
      matchingCount: null,
      offset: 0,
    },
    {
      urn: SALES,
      fields: allFields.slice(0, 1),
      totalFields: 3,
      returned: 1,
      remainingCount: 1,
      matchingCount: null,
      offset: 1,
    },
  ]);
  await assert.rejects(
    duplicate.load(),
    (error: unknown) =>
      error instanceof DataHubHarvestError &&
      error.code === "SCHEMA_RESPONSE_INCOMPLETE"
  );

  const limited = mockedLiveEntities(partial, [
    {
      urn: SALES,
      fields: allFields.slice(0, 1),
      totalFields: 3,
      returned: 1,
      remainingCount: 2,
      matchingCount: null,
      offset: 0,
    },
  ]);
  await assert.rejects(
    limited.load({
      ...harvestPolicy("synchronous-preview"),
      maxSchemaFieldPages: 1,
    }),
    (error: unknown) =>
      error instanceof DataHubHarvestError &&
      error.code === "SCHEMA_LIMIT_EXCEEDED"
  );
  assert.deepEqual(limited.offsets, [0]);
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

test("mapUpstreamEdges treats every returned DataHub lineage node as resolved", () => {
  const res: DhLineageResponse = {
    upstreams: {
      searchResults: [
        { entity: { urn: RAW, type: "DATASET" }, degree: 1 },
        { entity: { urn: EXTERNAL, type: "DATASET" }, degree: 1 },
      ],
    },
  };
  const edges = mapUpstreamEdges(res);
  assert.equal(edges.length, 2);
  const raw = edges.find((e) => e.upstream === RAW)!;
  const ext = edges.find((e) => e.upstream === EXTERNAL)!;
  assert.equal(raw.upstreamResolved, true);
  assert.equal(ext.upstreamResolved, true);
});

test("mapUpstreamEdges returns [] when there is no upstream lineage", () => {
  assert.deepEqual(mapUpstreamEdges(null), []);
  assert.deepEqual(mapUpstreamEdges({ upstreams: {} }), []);
  assert.deepEqual(mapUpstreamEdges({ downstreams: { searchResults: [] } }), []);
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
        offset: 0,
        returned: 2,
        hasMore: false,
      },
    },
    50
  );
  assert.deepEqual(
    edges.map(({ upstream, upstreamResolved }) => ({
      upstream,
      upstreamResolved,
    })),
    [
      { upstream: EXTERNAL, upstreamResolved: true },
      { upstream: RAW, upstreamResolved: true },
    ]
  );
  // v0.6.0 omits the derived pagination metadata for a canonical empty result.
  assert.deepEqual(
    mapUpstreamEdgesStrict(
      {
        upstreams: {
          total: 0,
        },
      },
      50
    ),
    []
  );
  assert.throws(
    () =>
      mapDownstreamTopologyStrict(
        {
          downstreams: {
            start: 0,
            count: 1,
            total: 1,
            searchResults: [
              {
                entity: {
                  urn: RAW,
                  type: "DATASET",
                  deprecation:
                    "invalid" as unknown as DhCleanedEntity["deprecation"],
                },
                degree: 1,
              },
            ],
            offset: 0,
            returned: 1,
            hasMore: false,
          },
        },
        50
      ),
      (error: unknown) =>
        error instanceof DataHubHarvestError &&
        error.code === "LINEAGE_RESPONSE_INCOMPLETE"
    );
});

test("current aspect reconciliation marks declared dangling upstreams without inventing gaps", () => {
  const declared: DeclaredUpstreamLineage[] = [
    { upstream: RAW, type: "COPY" },
    { upstream: EXTERNAL, type: "TRANSFORMED" },
  ];
  const resolved: LineageEdge[] = [
    {
      upstream: RAW,
      upstreamResolved: true,
      type: undefined,
    },
  ];

  assert.deepEqual(
    reconcileUpstreamEdgesStrict(declared, resolved, 50),
    [
      {
        upstream: EXTERNAL,
        upstreamResolved: false,
        type: "TRANSFORMED",
      },
      {
        upstream: RAW,
        upstreamResolved: true,
        type: "COPY",
      },
    ]
  );
});

test("current aspect reconciliation accepts proven absence only with no resolved upstreams", () => {
  assert.deepEqual(reconcileUpstreamEdgesStrict([], [], 50), []);
  assert.throws(
    () =>
      reconcileUpstreamEdgesStrict(
        [],
        [
          {
            upstream: RAW,
            upstreamResolved: true,
          },
        ],
        50
      ),
    (error: unknown) =>
      error instanceof DataHubHarvestError &&
      error.code === "LINEAGE_RESPONSE_INCOMPLETE"
  );
});

test("current aspect reconciliation rejects malformed or duplicate evidence", () => {
  const cases: Array<{
    declared: DeclaredUpstreamLineage[];
    resolved: LineageEdge[];
  }> = [
    {
      declared: [
        { upstream: RAW, type: "COPY" },
        { upstream: RAW, type: "VIEW" },
      ],
      resolved: [],
    },
    {
      declared: [
        {
          upstream: "urn:li:chart:(looker,not-a-dataset)",
          type: "COPY",
        },
      ],
      resolved: [],
    },
    {
      declared: [{ upstream: RAW, type: "COPY" }],
      resolved: [
        {
          upstream: RAW,
          upstreamResolved: false,
        },
      ],
    },
  ];
  for (const evidence of cases) {
    assert.throws(
      () =>
        reconcileUpstreamEdgesStrict(
          evidence.declared,
          evidence.resolved,
          50
        ),
      (error: unknown) =>
        error instanceof DataHubHarvestError &&
      error.code === "LINEAGE_RESPONSE_INCOMPLETE"
    );
  }
  assert.throws(
    () =>
      reconcileUpstreamEdgesStrict(
        [
          { upstream: RAW, type: "COPY" },
          { upstream: EXTERNAL, type: "VIEW" },
        ],
        [],
        1
      ),
    (error: unknown) =>
      error instanceof DataHubHarvestError &&
      error.code === "LINEAGE_RESPONSE_INCOMPLETE"
  );
});

test("final lineage ceiling counts declared dangling edges with downstream topology", () => {
  const upstreamByRoot = new Map<Urn, LineageEdge[]>([
    [
      SALES,
      [
        {
          upstream: RAW,
          upstreamResolved: true,
        },
        {
          upstream: EXTERNAL,
          upstreamResolved: false,
        },
      ],
    ],
  ]);
  const downstreamByRoot = new Map<Urn, LineageTopologyNode[]>([
    [
      SALES,
      [
        {
          urn: EXTERNAL,
          minHops: 1,
          entityType: "DASHBOARD",
          deprecated: false,
        },
      ],
    ],
  ]);

  assert.doesNotThrow(() =>
    assertLineageRelationLimit(
      upstreamByRoot,
      downstreamByRoot,
      3
    )
  );
  assert.throws(
    () =>
      assertLineageRelationLimit(
        upstreamByRoot,
        downstreamByRoot,
        2
      ),
    (error: unknown) =>
      error instanceof DataHubHarvestError &&
      error.code === "LINEAGE_RESPONSE_INCOMPLETE"
  );
});

test("strict downstream lineage maps unlimited-hop topology metadata deterministically", () => {
  const nodes = mapDownstreamTopologyStrict(
    {
      downstreams: {
        start: 0,
        count: 2,
        total: 2,
        searchResults: [
          {
            entity: {
              urn: EXTERNAL,
              type: "DASHBOARD",
              deprecation: { deprecated: true },
            },
            degree: 3,
          },
          {
            entity: {
              urn: RAW,
              type: "DATASET",
            },
            degree: 1,
          },
        ],
        offset: 0,
        returned: 2,
        hasMore: false,
      },
    },
    50
  );
  assert.deepEqual(nodes, [
    {
      urn: RAW,
      minHops: 1,
      entityType: "DATASET",
      deprecated: false,
    },
    {
      urn: EXTERNAL,
      minHops: 3,
      entityType: "DASHBOARD",
      deprecated: true,
    },
  ]);
  assert.deepEqual(
    mapDownstreamTopologyStrict(
      {
        downstreams: {
          total: 0,
        },
      },
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
        offset: 0,
        returned: 1,
        hasMore: true,
        truncatedDueToTokenBudget: true,
      },
    },
    {
      upstreams: {
        start: 0,
        count: 1,
        total: 1,
        searchResults: [{ entity: { urn: RAW }, degree: 1 }],
        offset: 0,
        returned: 1,
        hasMore: false,
        truncatedDueToTokenBudget:
          "false" as unknown as boolean,
      },
    },
    {
      upstreams: {
        start: 0,
        count: 1,
        total: 1,
        searchResults: [{ entity: {}, degree: 1 }],
        offset: 0,
        returned: 1,
        hasMore: false,
      },
    },
    {
      upstreams: {
        start: 0,
        count: 1,
        total: 1,
        searchResults: [{ entity: { urn: RAW } }],
        offset: 0,
        returned: 1,
        hasMore: false,
      },
    },
    {
      upstreams: {
        start: 0,
        count: 1,
        total: 1,
        searchResults: [{ entity: { urn: RAW }, degree: 2 }],
        offset: 0,
        returned: 1,
        hasMore: false,
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
        offset: 0,
        returned: 2,
        hasMore: false,
      },
    },
    {
      upstreams: {
        start: 0,
        count: 0,
        total: 0,
        searchResults: [],
      },
      downstreams: {
        start: 0,
        count: 0,
        total: 0,
        searchResults: [],
      },
    },
  ];
  for (const response of cases) {
    assert.throws(
      () => mapUpstreamEdgesStrict(response, 50),
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
      0
    ),
    RangeError
  );
});

test("live lineage task queue reads both directions without expanding audited roots", async () => {
  const calls: Array<Record<string, unknown>> = [];
  const client =
    new LiveDataHubMcpClient() as unknown as LiveLineageHarness;
  client.call = async (name, args) => {
    assert.equal(name, "get_lineage");
    assert.equal(args["max_results"], 50);
    assert.equal(args["offset"], 0);
    assert.equal(
      args["filter"],
      args["upstream"] === true
        ? "entity_type = dataset"
        : undefined
    );
    calls.push({ ...args });
    if (args["upstream"] === true) {
      return {
        upstreams: {
          start: 0,
          count: 1,
          total: 1,
          searchResults: [
            { entity: { urn: RAW, type: "DATASET" }, degree: 1 },
          ],
          offset: 0,
          returned: 1,
          hasMore: false,
        },
      } satisfies DhLineageResponse;
    }
    return {
      downstreams: {
        start: 0,
        count: 1,
        total: 1,
        searchResults: [
          {
            entity: {
              urn: EXTERNAL,
              type: "DASHBOARD",
              deprecation: { deprecated: false },
            },
            degree: 3,
          },
        ],
        offset: 0,
        returned: 1,
        hasMore: false,
      },
    } satisfies DhLineageResponse;
  };

  const topology = await client.getLineageTopologyWithinPolicy(
    [SALES],
    harvestPolicy("synchronous-preview"),
    new AbortController().signal
  );
  assert.deepEqual(
    calls
      .map((call) => ({
        upstream: call["upstream"],
        maxHops: call["max_hops"],
      }))
      .sort((a, b) => Number(b.upstream) - Number(a.upstream)),
    [
      { upstream: true, maxHops: 1 },
      { upstream: false, maxHops: 3 },
    ]
  );
  assert.deepEqual(topology.upstreamByRoot.get(SALES), [
    { upstream: RAW, upstreamResolved: true, type: undefined },
  ]);
  assert.deepEqual(topology.downstreamByRoot.get(SALES), [
    {
      urn: EXTERNAL,
      minHops: 3,
      entityType: "DASHBOARD",
      deprecated: false,
    },
  ]);
  assert.deepEqual(
    [...topology.knownLineageUrns].sort(),
    [EXTERNAL, RAW].sort()
  );
  assert.equal(topology.upstreamByRoot.has(EXTERNAL), false);
  assert.equal(topology.downstreamByRoot.has(EXTERNAL), false);
});

test("live harvest policies pin schema and relation ceilings per execution profile", () => {
  const preview = harvestPolicy("synchronous-preview");
  assert.deepEqual(
    {
      schemaFieldPageSize: preview.schemaFieldPageSize,
      maxSchemaFieldsPerEntity: preview.maxSchemaFieldsPerEntity,
      maxSchemaFieldPages: preview.maxSchemaFieldPages,
      schemaCompletionConcurrency: preview.schemaCompletionConcurrency,
      maxLineageResultsPerDirection:
        preview.maxLineageResultsPerDirection,
      maxLineageRelations: preview.maxLineageRelations,
      lineageConcurrency: preview.lineageConcurrency,
    },
    {
      schemaFieldPageSize: 100,
      maxSchemaFieldsPerEntity: 500,
      maxSchemaFieldPages: 10,
      schemaCompletionConcurrency: 1,
      maxLineageResultsPerDirection: 50,
      maxLineageRelations: 100,
      lineageConcurrency: 2,
    }
  );
  const worker = harvestPolicy("async-worker");
  assert.equal(worker.maxSchemaFieldsPerEntity, 5_000);
  assert.equal(worker.maxSchemaFieldPages, 100);
  assert.equal(worker.schemaCompletionConcurrency, 4);
  assert.equal(worker.maxLineageResultsPerDirection, 50);
  assert.equal(worker.maxLineageRelations, 2_500);
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

test("live search accepts zero-total and complete multi-page results", async () => {
  const empty = mockedLiveSearch([
    { start: 0, count: 0, total: 0, searchResults: [] },
  ]);
  assert.deepEqual(await empty.search(), []);
  assert.deepEqual(empty.offsets, [0]);
  assert.equal(empty.remaining(), 0);

  const complete = mockedLiveSearch([
    {
      start: 0,
      count: 1,
      total: 2,
      searchResults: [{ entity: { urn: SALES } }],
    },
    {
      start: 1,
      count: 1,
      total: 2,
      searchResults: [{ entity: { urn: RAW } }],
    },
  ]);
  assert.deepEqual(await complete.search(), [SALES, RAW]);
  assert.deepEqual(complete.offsets, [0, 1]);
  assert.equal(complete.remaining(), 0);
});

test("live search rejects truncated pages and totals that change mid-harvest", async () => {
  const cases: Array<{
    label: string;
    pages: DhSearchResponse[];
  }> = [
    {
      label: "truncated result set",
      pages: [
        {
          start: 0,
          count: 1,
          total: 2,
          searchResults: [{ entity: { urn: SALES } }],
        },
        { start: 1, count: 0, total: 2, searchResults: [] },
      ],
    },
    {
      label: "changed declared total",
      pages: [
        {
          start: 0,
          count: 1,
          total: 2,
          searchResults: [{ entity: { urn: SALES } }],
        },
        {
          start: 1,
          count: 1,
          total: 3,
          searchResults: [{ entity: { urn: RAW } }],
        },
      ],
    },
  ];

  for (const scenario of cases) {
    const mocked = mockedLiveSearch(scenario.pages);
    await assert.rejects(
      mocked.search(),
      (error: unknown) =>
        error instanceof DataHubHarvestError &&
        error.code === "SEARCH_RESPONSE_INCOMPLETE",
      scenario.label
    );
    assert.deepEqual(mocked.offsets, [0, 1], scenario.label);
    assert.equal(mocked.remaining(), 0, scenario.label);
  }
});

// Pinned from a real DataHub Core v1.6.0 response through the official MCP server:
// `count` echoes the REQUESTED page size (50), while `searchResults` carries only
// what exists (7). Asserting equality rejected every live page, which is why the
// live path had never worked.
test("strict search mapping accepts a real partial page from DataHub", () => {
  const page = mapSearchPageStrict(
    {
      start: 0,
      count: 50,
      total: 7,
      searchResults: [{ entity: { urn: SALES } }, { entity: { urn: RAW } }],
    } as DhSearchResponse,
    0,
    50
  );
  assert.deepEqual(page.urns, [SALES, RAW]);
  assert.equal(page.total, 7);
});

test("strict search mapping still fails closed on impossible pages", () => {
  // The server returned MORE than the page size it was asked for.
  assert.throws(
    () =>
      mapSearchPageStrict(
        {
          start: 0,
          count: 1,
          total: 5,
          searchResults: [
            { entity: { urn: SALES } },
            { entity: { urn: RAW } },
          ],
        } as DhSearchResponse,
        0,
        50
      ),
    (error: unknown) => error instanceof DataHubHarvestError
  );

  // This page claims to run past the declared total.
  assert.throws(
    () =>
      mapSearchPageStrict(
        {
          start: 0,
          count: 50,
          total: 1,
          searchResults: [
            { entity: { urn: SALES } },
            { entity: { urn: RAW } },
          ],
        } as DhSearchResponse,
        0,
        50
      ),
    (error: unknown) => error instanceof DataHubHarvestError
  );
});
