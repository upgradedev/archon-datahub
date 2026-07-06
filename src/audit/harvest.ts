// Harvest — turn DataHub catalog metadata into the neutral AuditFact stream the
// self-audit engine reasons over.
//
// This is the SEAM between the DataHub domain models (src/datahub/models.ts) and the
// provider-neutral audit engine (src/audit/consistency.ts). It is a PURE function:
// given the metadata a DataHub source reported (an entity, tagged with WHICH source
// reported it and WHEN), it emits one AuditFact per auditable aspect value. No I/O,
// no DataHub calls — the FakeDataHubMcpClient and a live client both feed the same
// shapes through here, so the self-audit runs identically offline and online.
//
// The key move: DataHub already carries provenance — the SAME logical dataset can be
// reported by DIFFERENT ingestion sources (a Snowflake connector, a dbt manifest, a
// manual catalog edit) or by successive scans, and nothing forces those to AGREE.
// Each report becomes facts tagged with its `source` + `scan`, so when two sources
// assign different owners (or types) to one entity, the consistency engine sees two
// facts about the same record disagreeing on the same attribute — a contradiction.

import type { AuditFact } from "../types.js";
import type { CatalogEntity } from "../datahub/models.js";

// One metadata report: an entity snapshot as a specific source reported it at a
// specific scan. The unit DataHub provenance is expressed in.
export interface SourceReport {
  source: string; // the ingestion source id that reported this (e.g. "dbt-ingest")
  scanId: string; // the harvest/scan label
  createdAt: string; // ISO timestamp of the report (drives the recency tie-break)
  entity: CatalogEntity;
}

// The first owner URN as a comparable scalar (the ownership aspect can list several;
// the audit compares the primary owner across sources — a differing primary owner is
// the metadata contradiction stewards care about).
function primaryOwner(e: CatalogEntity): string | null {
  const owners = e.owners ?? [];
  return owners.length > 0 ? owners[0]! : null;
}

// Emit the auditable facts for ONE source's report of ONE entity. Every fact maps
// 1:1 to an aspect DataHub already exposes — no invented data. Facts are only emitted
// where there is a comparable VALUE (an absent aspect is a governance concern, handled
// by the governance validator, not a contradiction).
export function entityToFacts(report: SourceReport): AuditFact[] {
  const { source, scanId, createdAt, entity } = report;
  const facts: AuditFact[] = [];
  const base = { source, scan: scanId, createdAt } as const;

  // Ownership aspect → a comparable primary-owner value.
  const owner = primaryOwner(entity);
  if (owner !== null) {
    facts.push({
      ...base,
      id: `${scanId}:${entity.urn}:ownership`,
      kind: "ownership",
      sourceRef: entity.urn,
      content: `${entity.name} is owned by ${owner}`,
      metadata: { record: entity.urn, owner },
    });
  }

  // Domain aspect → a comparable domain value.
  if (entity.domain) {
    facts.push({
      ...base,
      id: `${scanId}:${entity.urn}:domain`,
      kind: "domain",
      sourceRef: entity.urn,
      content: `${entity.name} is in domain ${entity.domain}`,
      metadata: { record: entity.urn, domain: entity.domain },
    });
  }

  // Deprecation aspect → a comparable lifecycle flag.
  if (typeof entity.deprecated === "boolean") {
    facts.push({
      ...base,
      id: `${scanId}:${entity.urn}:deprecation`,
      kind: "deprecation",
      sourceRef: entity.urn,
      content: `${entity.name} deprecated=${entity.deprecated}`,
      metadata: { record: entity.urn, deprecated: entity.deprecated },
    });
  }

  // schemaMetadata → one fact per typed field, keyed on the FIELD (urn#path) so two
  // sources typing the same column differently contradict at the field level.
  for (const f of entity.fields ?? []) {
    if (!f.type || f.type.trim().length === 0) continue;
    facts.push({
      ...base,
      id: `${scanId}:${entity.urn}#${f.path}:schema`,
      kind: "schema",
      sourceRef: `${entity.urn}#${f.path}`,
      content: `${entity.name}.${f.path} : ${f.type}`,
      metadata: { record: `${entity.urn}#${f.path}`, fieldType: f.type },
    });
  }

  // upstreamLineage → one fact carrying the referenced upstream URNs. An upstream that
  // no report catalogues (no fact has it as a record) surfaces as an absence — a
  // dangling lineage edge / lineage gap.
  const upstreams = entity.upstreams ?? [];
  if (upstreams.length > 0) {
    facts.push({
      ...base,
      id: `${scanId}:${entity.urn}:lineage`,
      kind: "lineage",
      sourceRef: entity.urn,
      content: `${entity.name} reads from ${upstreams.map((u) => u.upstream).join(", ")}`,
      metadata: { record: entity.urn, refs: upstreams.map((u) => u.upstream) },
    });
  }

  return facts;
}

// Flatten every source report into the full AuditFact stream the self-audit consumes.
export function reportsToFacts(reports: SourceReport[]): AuditFact[] {
  return reports.flatMap(entityToFacts);
}
