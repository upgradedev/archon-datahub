// Pinned DataHub MCP response shapes + pure mappers.
//
// These types + mappers are PINNED from the SOURCE of the official DataHub MCP server
// (`acryldata/mcp-server-datahub`, src/mcp_server_datahub/tools/{search,entities,lineage}.py
// + graphql_helpers.py). They describe the *cleaned* JSON the server returns over MCP —
// after `clean_gql_response` / `clean_get_entities_response` strip __typename, nulls, and
// empties, and after `_clean_schema_fields` flattens field-level tags/terms to name arrays.
//
// This module is PURE (no transport, no network) so it is unit-tested offline against
// captured example payloads and stays inside the coverage gate. The network shell that
// calls the tools lives in `mcp-client-live.ts` (excluded from coverage, as a transport
// client should be). Keeping the two apart means the *pinned logic* is the part CI proves.
//
// Source anchors (exact, from the repo):
//   • search(query, filter, num_results, sort_by, sort_order, offset) -> dict
//       returns the cleaned GraphQL `searchAcrossEntities`:
//         { start, count, total, searchResults: [ { entity: <cleaned entity> } ], facets? }
//   • get_entities(urns: list|str) -> list|dict  (list when an array is passed)
//       each item is a cleaned entity dict, OR { error, urn } for a missing/failed URN.
//   • list_schema_fields(urn, keywords, limit, offset) -> dict
//       { urn, fields, totalFields, returned, remainingCount, matchingCount, offset }
//   • get_lineage(urn, upstream=bool, max_hops, max_results, offset, ...) -> dict
//         { upstreams|downstreams: { total, searchResults, offset, returned, hasMore,
//             truncatedDueToTokenBudget? } } (empty results omit derived page metadata)

import type {
  CatalogEntity,
  LineageEdge,
  LineageTopologyNode,
  SchemaField,
  Urn,
} from "./models.js";
import { DataHubHarvestError } from "./harvest-policy.js";
import type {
  DatasetLineageType,
  DeclaredUpstreamLineage,
} from "./version-history-reader.js";

// ── Pinned cleaned-response types (the exact shapes the MCP server returns) ────

// A DataHub URN reference wrapper the GraphQL layer uses everywhere: { urn, properties? }.
export interface DhNamed {
  urn?: string;
  name?: string;
  properties?: { name?: string; description?: string | null } | null;
}

// dataset-level ownership aspect (nested — NOT flattened by the server).
export interface DhOwnership {
  owners?: Array<{ owner?: { urn?: string } | null; type?: string; ownershipType?: unknown }>;
}

// dataset-level domains aspect (DomainAssociation).
export interface DhDomainAssociation {
  domain?: { urn?: string; properties?: { name?: string } | null } | null;
}

// dataset-level globalTags aspect (nested).
export interface DhGlobalTags {
  tags?: Array<{ tag?: { urn?: string; properties?: { name?: string } | null } | null }>;
}

// dataset-level glossaryTerms aspect (nested).
export interface DhGlossaryTerms {
  terms?: Array<{ term?: { urn?: string; properties?: { name?: string } | null } | null }>;
}

// A schema field AFTER `_clean_schema_fields`: field-level tags/glossaryTerms are already
// FLATTENED to arrays of names (strings), unlike the dataset-level aspects above.
export interface DhCleanedSchemaField {
  fieldPath: string;
  type?: string | null; // SchemaFieldDataType enum, e.g. "STRING" | "NUMBER" | "TIMESTAMP"
  nativeDataType?: string | null; // e.g. "VARCHAR"
  description?: string | null;
  nullable?: boolean;
  isPartOfKey?: boolean;
  tags?: string[]; // flattened names
  glossaryTerms?: string[]; // flattened names
  editedTags?: string[]; // editableSchemaMetadata, flattened and kept separately upstream
  editedGlossaryTerms?: string[]; // editableSchemaMetadata, flattened upstream
}

export interface DhSchemaFieldsTruncated {
  totalFields?: number;
  includedFields?: number;
  offset?: number;
}

// A cleaned entity as returned by get_entities / embedded in search & lineage results.
export interface DhCleanedEntity {
  urn?: string;
  type?: string; // "DATASET", "CORP_USER", ...
  name?: string;
  platform?: { urn?: string; name?: string } | null;
  description?: string | null; // sometimes top-level in cleaned output
  properties?: { name?: string; description?: string | null; qualifiedName?: string } | null;
  editableProperties?: { description?: string | null } | null;
  ownership?: DhOwnership | null;
  domain?: DhDomainAssociation | null;
  globalTags?: DhGlobalTags | null;
  glossaryTerms?: DhGlossaryTerms | null;
  deprecation?: { deprecated?: boolean; note?: string | null } | null;
  schemaMetadata?: {
    fields?: DhCleanedSchemaField[];
    schemaFieldsTruncated?: DhSchemaFieldsTruncated;
  } | null;
  // present on an error result for one URN in a batch:
  error?: string;
}

// search / get_lineage share the searchResults envelope shape.
export interface DhSearchResult {
  entity?: DhCleanedEntity;
  degree?: number; // lineage only
}
export interface DhSearchResponse {
  start?: number;
  count?: number;
  total?: number;
  searchResults?: DhSearchResult[];
}
export interface DhLineageEnvelope {
  total?: number;
  searchResults?: DhSearchResult[];
  offset?: number;
  returned?: number;
  hasMore?: boolean;
  truncatedDueToTokenBudget?: boolean;
  // searchAcrossLineage fields retained by clean_gql_response in v0.6.0.
  start?: number;
  count?: number;
}
export interface DhLineageResponse {
  upstreams?: DhLineageEnvelope;
  downstreams?: DhLineageEnvelope;
}

export interface DhSchemaFieldPageResponse {
  urn?: string;
  fields?: DhCleanedSchemaField[];
  totalFields?: number;
  returned?: number;
  remainingCount?: number;
  matchingCount?: number | null;
  offset?: number;
}

export interface StrictSearchPage {
  urns: Urn[];
  total: number;
}

export interface StrictSchemaFieldPage {
  fields: DhCleanedSchemaField[];
  total: number;
}

export interface SchemaCompletionRequirement {
  required: boolean;
  totalFields: number;
}

// MCP tool failures are part of the wire contract. A text block attached to isError=true
// is provider diagnostics, never successful data, and must not flow into a mapper. Successful
// read tools must return JSON either as structuredContent or as one JSON text block.
export function parseMcpReadToolResult(result: unknown): unknown {
  if (!result || typeof result !== "object") {
    throw new DataHubHarvestError(
      "MCP_RESPONSE_INVALID",
      "DataHub MCP returned an invalid read-tool envelope."
    );
  }
  const response = result as {
    isError?: unknown;
    structuredContent?: unknown;
    content?: unknown;
  };
  if (response.isError === true) {
    throw new DataHubHarvestError(
      "MCP_TOOL_ERROR",
      "DataHub MCP reported a read-tool failure."
    );
  }
  if (
    response.isError !== undefined &&
    typeof response.isError !== "boolean"
  ) {
    throw new DataHubHarvestError(
      "MCP_RESPONSE_INVALID",
      "DataHub MCP returned an invalid read-tool status."
    );
  }
  if (response.structuredContent !== undefined) {
    return response.structuredContent;
  }
  if (!Array.isArray(response.content)) {
    throw new DataHubHarvestError(
      "MCP_RESPONSE_INVALID",
      "DataHub MCP returned no readable JSON content."
    );
  }
  const textBlocks = response.content.filter(
    (item): item is { type: "text"; text: string } =>
      Boolean(item) &&
      typeof item === "object" &&
      (item as { type?: unknown }).type === "text" &&
      typeof (item as { text?: unknown }).text === "string"
  );
  if (response.content.length !== 1 || textBlocks.length !== 1) {
    throw new DataHubHarvestError(
      "MCP_RESPONSE_INVALID",
      "DataHub MCP returned an ambiguous read-tool payload."
    );
  }
  try {
    return JSON.parse(textBlocks[0]!.text);
  } catch {
    throw new DataHubHarvestError(
      "MCP_RESPONSE_INVALID",
      "DataHub MCP returned non-JSON read-tool content."
    );
  }
}

// ── Pure mappers ──────────────────────────────────────────────────────────────

const asStr = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

function schemaFailure(message: string): never {
  throw new DataHubHarvestError("SCHEMA_RESPONSE_INCOMPLETE", message);
}

function strictSortedUnion(
  values: readonly unknown[],
  fieldPath: string,
  metadataName: string
): string[] {
  const strings: string[] = [];
  for (const value of values) {
    if (value === undefined) continue;
    if (!Array.isArray(value)) {
      schemaFailure(
        `DataHub schema field ${fieldPath} returned a non-array ${metadataName} value.`
      );
    }
    for (const item of value) {
      if (typeof item !== "string" || item.length === 0) {
        schemaFailure(
          `DataHub schema field ${fieldPath} returned an invalid ${metadataName} entry.`
        );
      }
      strings.push(item);
    }
  }
  return [...new Set(strings)].sort((a, b) => a.localeCompare(b));
}

function validateCleanedSchemaField(
  value: DhCleanedSchemaField,
  context: string
): void {
  if (
    !value ||
    typeof value !== "object" ||
    typeof value.fieldPath !== "string" ||
    value.fieldPath.length === 0 ||
    (value.type !== undefined &&
      value.type !== null &&
      typeof value.type !== "string") ||
    (value.nativeDataType !== undefined &&
      value.nativeDataType !== null &&
      typeof value.nativeDataType !== "string")
  ) {
    schemaFailure(`DataHub ${context} returned a malformed schema field.`);
  }
  strictSortedUnion(
    [value.tags, value.editedTags],
    value.fieldPath,
    "tag"
  );
  strictSortedUnion(
    [value.glossaryTerms, value.editedGlossaryTerms],
    value.fieldPath,
    "glossary-term"
  );
}

function validateSchemaFields(
  value: unknown,
  context: string
): DhCleanedSchemaField[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    schemaFailure(`DataHub ${context} returned a non-array schema field list.`);
  }
  const fields = value as DhCleanedSchemaField[];
  for (const field of fields) validateCleanedSchemaField(field, context);
  const paths = fields.map((field) => field.fieldPath);
  if (new Set(paths).size !== paths.length) {
    schemaFailure(`DataHub ${context} returned duplicate schema field paths.`);
  }
  return fields;
}

// Platform is nested { urn, name } in cleaned output; fall back to parsing the dataPlatform
// out of the dataset URN, e.g. urn:li:dataset:(urn:li:dataPlatform:snowflake,foo,PROD).
function platformOf(e: DhCleanedEntity): string {
  const p = e.platform?.name ?? e.platform?.urn;
  if (p) return p.replace(/^urn:li:dataPlatform:/, "");
  const m = /urn:li:dataPlatform:([^,)]+)/.exec(e.urn ?? "");
  return m?.[1] ?? "unknown";
}

// datasetProperties.description → editableProperties.description → top-level description.
function descriptionOf(e: DhCleanedEntity): string | null {
  return (
    e.properties?.description ??
    e.editableProperties?.description ??
    e.description ??
    null
  );
}

function ownersOf(e: DhCleanedEntity): Urn[] {
  return (e.ownership?.owners ?? [])
    .map((o) => asStr(o.owner?.urn))
    .filter((u): u is string => Boolean(u));
}

// Prefer the human tag/term name (properties.name); fall back to the URN.
function tagNamesOf(e: DhCleanedEntity): string[] {
  return (e.globalTags?.tags ?? [])
    .map((t) => t.tag?.properties?.name ?? asStr(t.tag?.urn))
    .filter((n): n is string => Boolean(n));
}
function termNamesOf(e: DhCleanedEntity): string[] {
  return (e.glossaryTerms?.terms ?? [])
    .map((t) => t.term?.properties?.name ?? asStr(t.term?.urn))
    .filter((n): n is string => Boolean(n));
}

// Field type comes back as an UPPERCASE enum ("STRING"/"NUMBER"); the offline Fake uses
// lowercase. Normalize to lowercase so Fake↔live parity holds for the audit (G5 + demo).
function fieldTypeOf(f: DhCleanedSchemaField): string | null {
  const t = f.type ?? f.nativeDataType;
  return t ? t.toLowerCase() : null;
}

function mapField(f: DhCleanedSchemaField): SchemaField {
  validateCleanedSchemaField(f, "entity");
  return {
    path: f.fieldPath,
    type: fieldTypeOf(f),
    // The pinned server keeps editable values separate when they differ from ingested
    // metadata. Governance consumes the deterministic union so steward edits are visible.
    tags: strictSortedUnion(
      [f.tags, f.editedTags],
      f.fieldPath,
      "tag"
    ),
    glossaryTerms: strictSortedUnion(
      [f.glossaryTerms, f.editedGlossaryTerms],
      f.fieldPath,
      "glossary-term"
    ),
  };
}

// Map a cleaned DataHub entity onto our provider-neutral CatalogEntity.
//
// `source` and `scanId` are the harvest's PROVENANCE, supplied by the caller — NOT
// invented from the entity. DataHub's MCP read surface returns a single CURRENT view per
// URN (aspects are single-valued), so a live harvest is one source at one scan; the honest
// provenance axis on a live instance is TIME (this harvest vs. a stored prior one), which
// the caller controls. We never fabricate cross-source `source` diversity here.
export function mapEntity(e: DhCleanedEntity, source: string): CatalogEntity {
  if (e.schemaMetadata?.schemaFieldsTruncated !== undefined) {
    schemaFailure(
      "DataHub entity mapping was attempted before its truncated schema was completed."
    );
  }
  const urn = asStr(e.urn) ?? "";
  return {
    urn,
    name: e.properties?.name ?? asStr(e.name) ?? urn,
    platform: platformOf(e),
    source,
    description: descriptionOf(e),
    owners: ownersOf(e),
    domain: asStr(e.domain?.domain?.urn) ?? null,
    tags: tagNamesOf(e),
    glossaryTerms: termNamesOf(e),
    deprecated: typeof e.deprecation?.deprecated === "boolean" ? e.deprecation.deprecated : false,
    fields: validateSchemaFields(
      e.schemaMetadata?.fields,
      "entity"
    ).map(mapField),
    upstreams: [],
  };
}

// Pull the dataset URNs out of a `search` response. We only need the URNs (then batch
// get_entities). Error/foreign entities without a urn are dropped.
export function mapSearchUrns(res: DhSearchResponse | null | undefined): Urn[] {
  const results = res?.searchResults ?? [];
  return results
    .map((r) => asStr(r.entity?.urn))
    .filter((u): u is string => Boolean(u));
}

// Search drives the completeness boundary for the whole audit. A malformed page, an
// unstable total, a duplicate, or a declared total above the fixed execution ceiling is
// therefore an error. Returning a convenient prefix would make a partial catalog appear
// complete and could incorrectly feed the governed planner.
export function mapSearchPageStrict(
  res: DhSearchResponse | null | undefined,
  expectedOffset: number,
  maxEntities: number
): StrictSearchPage {
  const start = res?.start;
  const count = res?.count;
  const total = res?.total;
  const results = res?.searchResults;
  if (
    !Number.isInteger(start) ||
    start !== expectedOffset ||
    !Number.isInteger(count) ||
    !Number.isInteger(total) ||
    (count as number) < 0 ||
    (total as number) < 0 ||
    !Array.isArray(results) ||
    count !== results.length ||
    expectedOffset + (count as number) > (total as number)
  ) {
    throw new DataHubHarvestError(
      "SEARCH_RESPONSE_INCOMPLETE",
      "DataHub search returned an invalid or incomplete page."
    );
  }
  if ((total as number) > maxEntities) {
    throw new DataHubHarvestError(
      "SEARCH_LIMIT_EXCEEDED",
      `DataHub search matched more than the ${maxEntities}-entity hosted safety limit. Use a narrower query.`
    );
  }

  const urns = results.map((result) => result.entity?.urn);
  if (
    urns.some((urn) => typeof urn !== "string" || urn.length === 0) ||
    new Set(urns as string[]).size !== urns.length
  ) {
    throw new DataHubHarvestError(
      "SEARCH_RESPONSE_INCOMPLETE",
      "DataHub search returned a missing or duplicate dataset URN."
    );
  }
  return { urns: urns as Urn[], total: total as number };
}

export function schemaCompletionRequirement(
  entity: DhCleanedEntity,
  maxFields: number
): SchemaCompletionRequirement {
  if (!Number.isInteger(maxFields) || maxFields < 0) {
    throw new RangeError("maxFields must be a non-negative integer");
  }
  const fields = validateSchemaFields(
    entity.schemaMetadata?.fields,
    "get_entities"
  );
  const marker = entity.schemaMetadata?.schemaFieldsTruncated;
  if (marker === undefined) {
    if (fields.length > maxFields) {
      throw new DataHubHarvestError(
        "SCHEMA_LIMIT_EXCEEDED",
        `DataHub schema exceeds the ${maxFields}-field hosted safety limit.`
      );
    }
    return { required: false, totalFields: fields.length };
  }
  if (
    !marker ||
    typeof marker !== "object" ||
    Array.isArray(marker) ||
    !Number.isInteger(marker.totalFields) ||
    !Number.isInteger(marker.includedFields) ||
    marker.offset !== 0 ||
    (marker.totalFields as number) < 1 ||
    (marker.includedFields as number) < 0 ||
    marker.includedFields !== fields.length ||
    (marker.includedFields as number) >= (marker.totalFields as number)
  ) {
    schemaFailure(
      "DataHub get_entities returned an invalid schemaFieldsTruncated marker."
    );
  }
  if ((marker.totalFields as number) > maxFields) {
    throw new DataHubHarvestError(
      "SCHEMA_LIMIT_EXCEEDED",
      `DataHub schema exceeds the ${maxFields}-field hosted safety limit.`
    );
  }
  return {
    required: true,
    totalFields: marker.totalFields as number,
  };
}

export function mapSchemaFieldPageStrict(
  response: DhSchemaFieldPageResponse | null | undefined,
  expectedUrn: Urn,
  expectedOffset: number,
  pageSize: number,
  maxFields: number
): StrictSchemaFieldPage {
  if (
    !Number.isInteger(expectedOffset) ||
    expectedOffset < 0 ||
    !Number.isInteger(pageSize) ||
    pageSize < 1 ||
    !Number.isInteger(maxFields) ||
    maxFields < 0
  ) {
    throw new RangeError(
      "Schema paging bounds must be non-negative integers and pageSize must be positive."
    );
  }
  if (!response || typeof response !== "object") {
    schemaFailure("DataHub list_schema_fields returned no response object.");
  }
  if (!Array.isArray(response.fields)) {
    schemaFailure(
      "DataHub list_schema_fields returned no schema field array."
    );
  }
  const fields = validateSchemaFields(
    response.fields,
    "list_schema_fields"
  );
  const total = response.totalFields;
  const returned = response.returned;
  const remaining = response.remainingCount;
  if (
    response.urn !== expectedUrn ||
    response.offset !== expectedOffset ||
    !Number.isInteger(total) ||
    (total as number) < 0 ||
    !Number.isInteger(returned) ||
    (returned as number) < 0 ||
    returned !== fields.length ||
    (returned as number) > pageSize ||
    !Number.isInteger(remaining) ||
    (remaining as number) < 0 ||
    expectedOffset > (total as number) ||
    expectedOffset + (returned as number) > (total as number) ||
    remaining !==
      (total as number) - expectedOffset - (returned as number) ||
    (response.matchingCount !== undefined &&
      response.matchingCount !== null)
  ) {
    schemaFailure(
      "DataHub list_schema_fields returned invalid pagination metadata."
    );
  }
  if ((total as number) > maxFields) {
    throw new DataHubHarvestError(
      "SCHEMA_LIMIT_EXCEEDED",
      `DataHub schema exceeds the ${maxFields}-field hosted safety limit.`
    );
  }
  if (fields.length === 0 && expectedOffset < (total as number)) {
    schemaFailure(
      "DataHub list_schema_fields made no progress before reaching its declared total."
    );
  }
  return { fields, total: total as number };
}

export function completeEntitySchema(
  entity: DhCleanedEntity,
  fields: readonly DhCleanedSchemaField[],
  expectedTotal: number
): DhCleanedEntity {
  if (
    !Number.isInteger(expectedTotal) ||
    expectedTotal < 0 ||
    fields.length !== expectedTotal
  ) {
    schemaFailure(
      "DataHub schema completion did not collect its exact declared field count."
    );
  }
  const completed = validateSchemaFields(
    [...fields],
    "completed schema"
  );
  const schemaMetadata: NonNullable<DhCleanedEntity["schemaMetadata"]> =
    entity.schemaMetadata ?? {};
  const {
    schemaFieldsTruncated: _schemaFieldsTruncated,
    ...preservedSchemaMetadata
  } = schemaMetadata;
  return {
    ...entity,
    schemaMetadata: {
      ...preservedSchemaMetadata,
      fields: [...completed],
    },
  };
}

// Permissive mapper retained for isolated fixture/shape diagnostics. Live audit assembly
// must use mapEntitiesStrict below so a provider error can never become a partial snapshot.
export function mapEntities(
  res: DhCleanedEntity[] | { entities?: DhCleanedEntity[] } | null | undefined,
  source: string
): CatalogEntity[] {
  const raw: DhCleanedEntity[] = Array.isArray(res) ? res : (res?.entities ?? []);
  return raw.filter((e) => e && !e.error && e.urn).map((e) => mapEntity(e, source));
}

// Strict batch hydration used by the live audit. The official tool can return a mixed
// list of entities and per-URN error objects; every requested URN must occur exactly once,
// without errors or extras, before any entity is admitted to an audit snapshot.
export function mapEntitiesStrict(
  res: DhCleanedEntity[] | { entities?: DhCleanedEntity[] } | null | undefined,
  requestedUrns: readonly Urn[],
  source: string
): CatalogEntity[] {
  return orderedEntitiesStrict(res, requestedUrns).map((entity) =>
    mapEntity(entity, source)
  );
}

export function orderedEntitiesStrict(
  res: DhCleanedEntity[] | { entities?: DhCleanedEntity[] } | null | undefined,
  requestedUrns: readonly Urn[]
): DhCleanedEntity[] {
  const requested = new Set(requestedUrns);
  if (
    requested.size !== requestedUrns.length ||
    requestedUrns.some((urn) => typeof urn !== "string" || urn.length === 0)
  ) {
    throw new DataHubHarvestError(
      "ENTITY_RESPONSE_INCOMPLETE",
      "The get_entities request contained a missing or duplicate URN."
    );
  }

  const raw: DhCleanedEntity[] = Array.isArray(res) ? res : (res?.entities ?? []);
  const byUrn = new Map<Urn, DhCleanedEntity>();
  for (const item of raw) {
    const urn = item?.urn;
    if (
      !item ||
      typeof urn !== "string" ||
      urn.length === 0 ||
      item.error !== undefined ||
      !requested.has(urn) ||
      byUrn.has(urn)
    ) {
      throw new DataHubHarvestError(
        "ENTITY_RESPONSE_INCOMPLETE",
        "DataHub get_entities returned an error, malformed item, unexpected URN, or duplicate."
      );
    }
    byUrn.set(urn, item);
  }
  if (byUrn.size !== requested.size) {
    throw new DataHubHarvestError(
      "ENTITY_RESPONSE_INCOMPLETE",
      "DataHub get_entities did not return every requested URN."
    );
  }
  return requestedUrns.map((urn) => byUrn.get(urn)!);
}

// Every node returned by searchAcrossLineage is a resolved DataHub entity. A true dangling
// upstream is not returned by this search surface, so returned direct upstreams are always
// marked resolved rather than compared with the narrower audited-root set.
export function mapUpstreamEdges(
  res: DhLineageResponse | null | undefined
): LineageEdge[] {
  const results = res?.upstreams?.searchResults ?? [];
  return results
    .map((r) => asStr(r.entity?.urn))
    .filter((u): u is string => Boolean(u))
    .map((upstream) => ({
      upstream,
      upstreamResolved: true,
      type: undefined,
    }))
    .sort((a, b) => a.upstream.localeCompare(b.upstream));
}

type LineageDirection = "upstream" | "downstream";

function strictLineageResults(
  res: DhLineageResponse | null | undefined,
  direction: LineageDirection,
  maxResults: number
): DhSearchResult[] {
  if (!Number.isInteger(maxResults) || maxResults < 1) {
    throw new RangeError("maxResults must be a positive integer");
  }
  const key = direction === "upstream" ? "upstreams" : "downstreams";
  const oppositeKey =
    direction === "upstream" ? "downstreams" : "upstreams";
  const envelope = res?.[key];
  if (!envelope || res?.[oppositeKey] !== undefined) {
    throw new DataHubHarvestError(
      "LINEAGE_RESPONSE_INCOMPLETE",
      `DataHub lineage returned a missing or ambiguous ${direction} envelope.`
    );
  }
  const total = envelope.total;
  if (
    !Number.isInteger(total) ||
    (total as number) < 0 ||
    (total as number) > maxResults
  ) {
    throw new DataHubHarvestError(
      "LINEAGE_RESPONSE_INCOMPLETE",
      `DataHub lineage returned invalid ${direction} totals or results.`
    );
  }

  // In v0.6.0 the pagination metadata is attached only inside
  // `if search_results`; clean_gql_response also removes the empty searchResults
  // array, so the canonical zero-result envelope may be only `{ total: 0 }`.
  const results = envelope.searchResults;
  if (
    (total as number) === 0 &&
    (results === undefined || (Array.isArray(results) && results.length === 0))
  ) {
    if (
      (envelope.offset !== undefined && envelope.offset !== 0) ||
      (envelope.returned !== undefined && envelope.returned !== 0) ||
      (envelope.hasMore !== undefined && envelope.hasMore !== false) ||
      (envelope.truncatedDueToTokenBudget !== undefined &&
        envelope.truncatedDueToTokenBudget !== false) ||
      (envelope.start !== undefined && envelope.start !== 0) ||
      (envelope.count !== undefined && envelope.count !== 0)
    ) {
      throw new DataHubHarvestError(
        "LINEAGE_RESPONSE_INCOMPLETE",
        `DataHub lineage returned non-canonical empty ${direction} metadata.`
      );
    }
    return [];
  }

  if (
    !Array.isArray(results) ||
    envelope.offset !== 0 ||
    !Number.isInteger(envelope.returned) ||
    envelope.returned !== results.length ||
    envelope.hasMore !== false ||
    (envelope.truncatedDueToTokenBudget !== undefined &&
      envelope.truncatedDueToTokenBudget !== false) ||
    total !== results.length ||
    (envelope.start !== undefined && envelope.start !== 0) ||
    (envelope.count !== undefined && envelope.count !== results.length)
  ) {
    throw new DataHubHarvestError(
      "LINEAGE_RESPONSE_INCOMPLETE",
      `DataHub lineage returned an incomplete or token-truncated ${direction} envelope.`
    );
  }
  return results;
}

function strictLineageUrns(
  results: readonly DhSearchResult[],
  direction: LineageDirection,
  directOnly: boolean
): Urn[] {
  const urns = results.map((result) => result.entity?.urn);
  if (
    urns.some(
      (urn) =>
        typeof urn !== "string" ||
        !urn.startsWith("urn:li:")
    ) ||
    results.some(
      (result) =>
        !Number.isInteger(result.degree) ||
        (result.degree as number) < 1 ||
        (directOnly && result.degree !== 1)
    ) ||
    new Set(urns as string[]).size !== urns.length
  ) {
    throw new DataHubHarvestError(
      "LINEAGE_RESPONSE_INCOMPLETE",
      `DataHub lineage returned a malformed or duplicate ${direction} entity.`
    );
  }
  return urns as Urn[];
}

export function mapUpstreamEdgesStrict(
  res: DhLineageResponse | null | undefined,
  maxResults: number
): LineageEdge[] {
  const results = strictLineageResults(res, "upstream", maxResults);
  return strictLineageUrns(results, "upstream", true)
    .map((upstream) => ({
      upstream,
      upstreamResolved: true,
      type: undefined,
    }))
    .sort((a, b) => a.upstream.localeCompare(b.upstream));
}

const VALID_DATASET_LINEAGE_TYPES = new Set<DatasetLineageType>([
  "COPY",
  "TRANSFORMED",
  "VIEW",
]);

function isExactDatasetUrn(value: unknown): value is Urn {
  const prefix = "urn:li:dataset:(urn:li:dataPlatform:";
  if (
    typeof value !== "string" ||
    !value.startsWith(prefix) ||
    !value.endsWith(")") ||
    /[\s\u0000-\u001f\u007f]/u.test(value)
  ) {
    return false;
  }
  const tuple = value.slice(prefix.length, -1).split(",");
  return (
    tuple.length === 3 &&
    tuple.every(
      (part) =>
        part.length > 0 &&
        !part.includes("(") &&
        !part.includes(")")
    )
  );
}

export function reconcileUpstreamEdgesStrict(
  declared: readonly DeclaredUpstreamLineage[],
  resolved: readonly LineageEdge[],
  maxResults: number
): LineageEdge[] {
  if (!Number.isInteger(maxResults) || maxResults < 1) {
    throw new RangeError("maxResults must be a positive integer");
  }
  if (declared.length > maxResults) {
    throw new DataHubHarvestError(
      "LINEAGE_RESPONSE_INCOMPLETE",
      `DataHub current upstreamLineage exceeds the ${maxResults}-result direction limit.`
    );
  }
  const declaredByUrn = new Map<Urn, DeclaredUpstreamLineage>();
  for (const edge of declared) {
    if (
      !edge ||
      !isExactDatasetUrn(edge.upstream) ||
      !VALID_DATASET_LINEAGE_TYPES.has(edge.type) ||
      declaredByUrn.has(edge.upstream)
    ) {
      throw new DataHubHarvestError(
        "LINEAGE_RESPONSE_INCOMPLETE",
        "DataHub current upstreamLineage contained a malformed or duplicate declaration."
      );
    }
    declaredByUrn.set(edge.upstream, edge);
  }

  const resolvedUrns = new Set<Urn>();
  for (const edge of resolved) {
    if (
      !edge ||
      !isExactDatasetUrn(edge.upstream) ||
      edge.upstreamResolved !== true ||
      resolvedUrns.has(edge.upstream)
    ) {
      throw new DataHubHarvestError(
        "LINEAGE_RESPONSE_INCOMPLETE",
        "DataHub MCP returned a malformed or duplicate direct resolved upstream."
      );
    }
    if (!declaredByUrn.has(edge.upstream)) {
      throw new DataHubHarvestError(
        "LINEAGE_RESPONSE_INCOMPLETE",
        "DataHub MCP returned a direct resolved upstream absent from the current upstreamLineage aspect."
      );
    }
    resolvedUrns.add(edge.upstream);
  }

  return [...declaredByUrn.values()]
    .map((edge): LineageEdge => ({
      upstream: edge.upstream,
      upstreamResolved: resolvedUrns.has(edge.upstream),
      type: edge.type,
    }))
    .sort((left, right) =>
      left.upstream < right.upstream
        ? -1
        : left.upstream > right.upstream
          ? 1
          : 0
    );
}

export function assertLineageRelationLimit(
  upstreamByRoot: ReadonlyMap<Urn, readonly LineageEdge[]>,
  downstreamByRoot: ReadonlyMap<Urn, readonly LineageTopologyNode[]>,
  maxRelations: number
): void {
  if (!Number.isInteger(maxRelations) || maxRelations < 0) {
    throw new RangeError("maxRelations must be a non-negative integer");
  }
  let relationCount = 0;
  for (const edges of upstreamByRoot.values()) {
    relationCount += edges.length;
  }
  for (const nodes of downstreamByRoot.values()) {
    relationCount += nodes.length;
  }
  if (relationCount > maxRelations) {
    throw new DataHubHarvestError(
      "LINEAGE_RESPONSE_INCOMPLETE",
      `DataHub lineage exceeds the ${maxRelations}-relation hosted safety limit.`
    );
  }
}

export function mapDownstreamTopologyStrict(
  res: DhLineageResponse | null | undefined,
  maxResults: number
): LineageTopologyNode[] {
  const results = strictLineageResults(res, "downstream", maxResults);
  const urns = strictLineageUrns(results, "downstream", false);
  const nodes = results.map((result, index): LineageTopologyNode => {
    const entityType = result.entity?.type;
    const deprecation = result.entity?.deprecation;
    const deprecated = deprecation?.deprecated;
    if (
      typeof entityType !== "string" ||
      entityType.length === 0 ||
      (deprecation !== undefined &&
        deprecation !== null &&
        (typeof deprecation !== "object" ||
          Array.isArray(deprecation))) ||
      (deprecated !== undefined && typeof deprecated !== "boolean")
    ) {
      throw new DataHubHarvestError(
        "LINEAGE_RESPONSE_INCOMPLETE",
        "DataHub lineage returned downstream topology without valid type/deprecation metadata."
      );
    }
    return {
      urn: urns[index]!,
      minHops: result.degree as number,
      entityType,
      deprecated: deprecated ?? false,
    };
  });
  return nodes.sort(
    (a, b) =>
      a.minHops - b.minHops ||
      a.urn.localeCompare(b.urn)
  );
}
