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
//   • get_lineage(urn, upstream=bool, max_hops, max_results, offset, ...) -> dict
//         { upstreams?: { searchResults: [ { entity: <cleaned entity>, degree } ], ... },
//           downstreams?: { ... } }   (upstream=True yields `upstreams`)

import type { CatalogEntity, LineageEdge, SchemaField, Urn } from "./models.js";

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
  schemaMetadata?: { fields?: DhCleanedSchemaField[] } | null;
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
export interface DhLineageResponse {
  upstreams?: DhSearchResponse;
  downstreams?: DhSearchResponse;
}

// ── Pure mappers ──────────────────────────────────────────────────────────────

const asStr = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

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
  return {
    path: f.fieldPath ?? "",
    type: fieldTypeOf(f),
    // field-level tags/terms are already flattened to name arrays by the server.
    tags: Array.isArray(f.tags) ? f.tags : [],
    glossaryTerms: Array.isArray(f.glossaryTerms) ? f.glossaryTerms : [],
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
    fields: (e.schemaMetadata?.fields ?? []).map(mapField),
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

// Map a `get_entities` response (array when we pass an array of URNs) to CatalogEntity[].
// Per-URN error objects ({ error, urn }) are skipped — a missing entity is simply absent
// from the harvest, which the lineage-gap / governance audit treats correctly.
export function mapEntities(
  res: DhCleanedEntity[] | { entities?: DhCleanedEntity[] } | null | undefined,
  source: string
): CatalogEntity[] {
  const raw: DhCleanedEntity[] = Array.isArray(res) ? res : (res?.entities ?? []);
  return raw.filter((e) => e && !e.error && e.urn).map((e) => mapEntity(e, source));
}

// Map a `get_lineage` (upstream) response to our LineageEdge[]. Every node returned by
// searchAcrossLineage is a RESOLVED graph node, so `upstreamResolved` is decided by the
// caller against the set of URNs the harvest actually catalogued (`knownUrns`) — a declared
// upstream that is not in that set is the lineage gap. (A truly dangling edge — a URN never
// ingested at all — may not appear here; see mcp-client-live.ts + README for that limit.)
export function mapUpstreamEdges(
  res: DhLineageResponse | null | undefined,
  isKnown: (urn: Urn) => boolean
): LineageEdge[] {
  const results = res?.upstreams?.searchResults ?? [];
  return results
    .map((r) => asStr(r.entity?.urn))
    .filter((u): u is string => Boolean(u))
    .map((upstream) => ({
      upstream,
      upstreamResolved: isKnown(upstream),
      type: undefined,
    }));
}
