// Aspect version-history recovery — make the self-audit's flagship CONTRADICTION
// detection fire on a LIVE DataHub, not only on offline fixtures.
//
// THE PROBLEM IT SOLVES (the D-1 credibility hole). DataHub aspects are single-valued:
// the MCP read tools (`search` / `get_entities` / `get_lineage`) return one CURRENT view
// per aspect. So when two ingestion pipelines — a Snowflake connector and a dbt manifest —
// write different owners for the same dataset, latest-write-wins collapses the conflict
// and the MCP read surface can never see it. The contradiction is real; it is just no
// longer queryable through the read tools.
//
// THE RECOVERY. DataHub DOES retain every prior write. Each aspect version carries
// `systemMetadata` with the `runId` that produced it (OpenAPI v3
// `GET /openapi/v3/entity/{entityName}/batchGet?systemMetadata=true`, or the Timeline
// API `/openapi/v2/timeline/v1/{urn}`). Reading an aspect's VERSION HISTORY therefore
// re-exposes the conflicting values and their write provenance. A run id alone is NOT a
// source identity: DataHub creates a new run id whenever the same ingestion pipeline runs
// again. We therefore resolve a stable pipeline/source identity before classifying a
// disagreement as cross-source.
//
// HONESTY — WHAT SURFACE THIS IS. Version history is a DIRECT GMS read (OpenAPI v3 /
// Timeline), NOT one of the DataHub MCP read tools. We never claim contradiction fires
// "from the MCP read tools alone" — it fires from this complementary direct read. The
// transport lives in `mcp-client-live.ts` (coverage-excluded shell); this module is the
// PURE, in-coverage mapping + audit logic, unit-tested offline against the exact response
// shapes DataHub's own docs publish.
//
// THE SEMANTIC GUARD (why this is not just "the value changed"). A value that merely
// changed across successive executions of the SAME ingestion pipeline is drift, not a
// contradiction. A true cross-source conflict requires DIFFERENT stable source identities.
// We use `systemMetadata.pipelineName` when present, or an explicitly resolved
// run-id→source map supplied by the caller. Unresolved provenance fails closed to the
// single identity `unknown-source`; distinct run ids alone can never manufacture a
// conflict. `auditVersionHistory` then runs the shared consistency engine with
// `requireDistinctSources: true`.

import type { AuditFact } from "../types.js";
import { auditConsistency, type ConsistencyReport } from "../audit/consistency.js";

// ── Pinned OpenAPI v3 versioned-aspect response shapes ─────────────────────────
// Source: docs.datahub.com/docs/api/openapi/openapi-usage-guide — the batchGet response
// wraps each aspect as { value, systemMetadata }, and `?systemMetadata=true` includes the
// systemMetadata block. Verbatim example (globalTags) is captured in
// tests/cassettes/openapi-v3-versioned-aspects.json.

// systemMetadata as GMS returns it. `runId` identifies the ingestion EXECUTION that wrote
// the metadata; `pipelineName` identifies the stable ingestion pipeline when the source
// enables DataHub's `set_system_metadata_pipeline_name`; `version` is the aspect version
// ordinal; `lastObserved` is the write's epoch-ms timestamp.
export interface DhSystemMetadata {
  version?: string;
  lastObserved?: number;
  runId?: string;
  lastRunId?: string;
  pipelineName?: string;
  properties?: Record<string, unknown> | null;
}

// One versioned aspect entry: the raw PDL aspect value + the systemMetadata for that
// version. `value` is null for a soft-deleted/absent version.
export interface DhVersionedAspect {
  value: Record<string, unknown> | null;
  systemMetadata?: DhSystemMetadata | null;
}

// The full version history of ONE mutable aspect on ONE entity, assembled by the direct
// GMS reader (one entry per stored version). Order-independent — we sort by version.
export interface AspectVersionHistory {
  urn: string;
  aspect: MutableAspectName;
  versions: DhVersionedAspect[];
  // Optional trusted resolution assembled by the GMS adapter from
  // DataHubExecutionRequest/DataHubIngestionSource metadata. It exists for deployments
  // whose historical systemMetadata predates `pipelineName`.
  sourceIdentityByRunId?: Readonly<Record<string, string>>;
}

// The mutable governance aspects whose history the recovery reads. Each maps to a
// comparable attribute the consistency engine already understands (owner / fieldType /
// domain / deprecated), so a version-history finding reads identically to an offline one.
export type MutableAspectName = "ownership" | "schemaMetadata" | "domains" | "deprecation";

// ── Pure value extractors over the RAW PDL aspect shapes ───────────────────────

const asStr = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

// ownership.owners[].owner is a URN string (OpenAPI v3 raw PDL). Primary = first owner.
function primaryOwnerOf(value: Record<string, unknown> | null): string | null {
  const owners = (value?.["owners"] as Array<{ owner?: unknown }> | undefined) ?? [];
  const first = owners[0]?.owner;
  return asStr(first) ?? null;
}

// domains.domains is a URN string[] (raw PDL). Compare the primary domain.
function primaryDomainOf(value: Record<string, unknown> | null): string | null {
  const domains = (value?.["domains"] as unknown[] | undefined) ?? [];
  return asStr(domains[0]) ?? null;
}

// deprecation.deprecated is a boolean.
function deprecatedOf(value: Record<string, unknown> | null): boolean | null {
  const d = value?.["deprecated"];
  return typeof d === "boolean" ? d : null;
}

// schemaMetadata.fields[] → [path, type]. `type` is the nested SchemaFieldDataType
// (`{ type: { type: { com.linkedin...: {} } } }`) OR a `nativeDataType` string; we prefer
// the human `nativeDataType`, lowercased for Fake↔live parity, and skip untyped fields.
function schemaFieldTypesOf(value: Record<string, unknown> | null): Array<{ path: string; type: string }> {
  const fields = (value?.["fields"] as Array<Record<string, unknown>> | undefined) ?? [];
  const out: Array<{ path: string; type: string }> = [];
  for (const f of fields) {
    const path = asStr(f["fieldPath"]);
    const native = asStr(f["nativeDataType"]);
    if (!path || !native) continue;
    out.push({ path, type: native.toLowerCase() });
  }
  return out;
}

// ISO timestamp for a version, from lastObserved (epoch-ms). Falls back to the epoch so a
// missing timestamp is deterministic (the recency tie-break stays stable).
function isoOf(sm: DhSystemMetadata | null | undefined): string {
  const ms = typeof sm?.lastObserved === "number" && sm.lastObserved > 0 ? sm.lastObserved : 0;
  return new Date(ms).toISOString();
}

const PLACEHOLDER_IDENTITIES = new Set([
  "",
  "no-run-id-provided",
  "unknown",
  "unknown-run",
  "unknown-source",
]);

function meaningfulIdentity(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  return PLACEHOLDER_IDENTITIES.has(normalized.toLowerCase()) ? null : normalized;
}

function runOf(sm: DhSystemMetadata | null | undefined): string | null {
  return meaningfulIdentity(sm?.runId);
}

// Resolve the stable SOURCE independently from the per-execution run id. Provenance is
// fail-closed: if neither pipelineName nor an explicit trusted mapping is available, every
// unresolved write shares `unknown-source` and cannot pass the distinct-source gate.
function sourceOf(
  history: AspectVersionHistory,
  sm: DhSystemMetadata | null | undefined
): string {
  const pipeline = meaningfulIdentity(sm?.pipelineName);
  if (pipeline) return pipeline;

  const runId = runOf(sm);
  const resolved = runId
    ? meaningfulIdentity(history.sourceIdentityByRunId?.[runId])
    : null;
  return resolved ?? "unknown-source";
}

// ── History → neutral AuditFact stream ─────────────────────────────────────────
// One fact per (version × comparable attribute). Facts are tagged with the version's
// stable pipeline/source identity as `source`, its execution `runId` as `scan`, and
// `lastObserved` as `createdAt`, so the consistency engine compares true sources while
// retaining the exact write execution as evidence.
export function versionHistoryToFacts(history: AspectVersionHistory): AuditFact[] {
  const { urn, aspect, versions } = history;
  const facts: AuditFact[] = [];
  for (const [index, v] of versions.entries()) {
    const sm = v.systemMetadata ?? null;
    const source = sourceOf(history, sm);
    const runId = runOf(sm);
    const scan = runId;
    const version = meaningfulIdentity(sm?.version) ?? String(index + 1);
    const evidenceId = `v${version}:${runId ?? "unknown-run"}`;
    const createdAt = isoOf(sm);
    const base = { source, scan, createdAt } as const;

    if (aspect === "ownership") {
      const owner = primaryOwnerOf(v.value);
      if (owner !== null) {
        facts.push({
          ...base,
          id: `${urn}:ownership:${evidenceId}`,
          kind: "ownership",
          sourceRef: urn,
          content: `${urn} owned by ${owner} (source ${source}; run ${runId ?? "unknown"})`,
          metadata: { record: urn, owner },
        });
      }
    } else if (aspect === "domains") {
      const domain = primaryDomainOf(v.value);
      if (domain !== null) {
        facts.push({
          ...base,
          id: `${urn}:domain:${evidenceId}`,
          kind: "domain",
          sourceRef: urn,
          content: `${urn} in domain ${domain} (source ${source}; run ${runId ?? "unknown"})`,
          metadata: { record: urn, domain },
        });
      }
    } else if (aspect === "deprecation") {
      const deprecated = deprecatedOf(v.value);
      if (deprecated !== null) {
        facts.push({
          ...base,
          id: `${urn}:deprecation:${evidenceId}`,
          kind: "deprecation",
          sourceRef: urn,
          content: `${urn} deprecated=${deprecated} (source ${source}; run ${runId ?? "unknown"})`,
          metadata: { record: urn, deprecated },
        });
      }
    } else {
      // schemaMetadata → one fact per typed field, keyed on the FIELD, so two sources typing
      // one column differently contradict at the field level (the silent schema break).
      for (const { path, type } of schemaFieldTypesOf(v.value)) {
        facts.push({
          ...base,
          id: `${urn}#${path}:schema:${evidenceId}`,
          kind: "schema",
          sourceRef: `${urn}#${path}`,
          content: `${urn}.${path} : ${type} (source ${source}; run ${runId ?? "unknown"})`,
          metadata: { record: `${urn}#${path}`, fieldType: type },
        });
      }
    }
  }
  return facts;
}

// Audit a set of aspect version histories for CROSS-SOURCE contradictions recovered from
// history. Runs the SAME pure consistency engine that ships (the "self-auditing" claim is
// measured on the identical code), with the distinct-source gate ON so that only genuine
// cross-source disagreements — not changes between executions of one pipeline — are
// reported.
export function auditVersionHistory(histories: AspectVersionHistory[]): ConsistencyReport {
  const facts = histories.flatMap(versionHistoryToFacts);
  return auditConsistency(facts, { requireDistinctSources: true });
}

// ── Cross-scan drift (the MCP-native secondary, honestly labeled as DRIFT) ──────
// The genuinely on-MCP-surface path: diff two of OUR OWN harvests (each a current-view
// read via the MCP tools). A value that differs between an earlier stored harvest and the
// current one is DRIFT — a candidate contradiction, not a confirmed cross-source conflict
// (we only know it changed after scan 1, not who wrote it). Kept deliberately separate
// from `auditVersionHistory` and labeled accordingly so no artifact overclaims.
export interface Drift {
  subject: string;
  attribute: string;
  from: unknown;
  to: unknown;
}

const RESERVED = new Set(["record", "refs"]);

function scalarAttrs(f: AuditFact): Map<string, unknown> {
  const out = new Map<string, unknown>();
  for (const [k, v] of Object.entries(f.metadata ?? {})) {
    if (RESERVED.has(k)) continue;
    const t = typeof v;
    if (t === "string" || t === "number" || t === "boolean") out.set(k, v);
  }
  return out;
}

// Detect attribute-level drift between a PRIOR harvest's facts and the CURRENT harvest's
// facts (both current-view reads via the MCP tools). Pure; deterministic ordering.
export function detectDrift(prior: AuditFact[], current: AuditFact[]): Drift[] {
  const index = (facts: AuditFact[]): Map<string, unknown> => {
    const m = new Map<string, unknown>();
    for (const f of facts) {
      const subject = (f.metadata?.["record"] as string | undefined) ?? f.sourceRef ?? undefined;
      if (!subject) continue;
      for (const [attr, val] of scalarAttrs(f)) m.set(`${subject}␟${attr}`, val);
    }
    return m;
  };
  const before = index(prior);
  const after = index(current);
  const drifts: Drift[] = [];
  for (const [key, to] of after) {
    if (!before.has(key)) continue;
    const from = before.get(key);
    if (JSON.stringify(from) === JSON.stringify(to)) continue;
    const [subject, attribute] = key.split("␟");
    drifts.push({ subject: subject!, attribute: attribute!, from, to });
  }
  return drifts.sort((a, b) =>
    a.subject !== b.subject
      ? a.subject < b.subject
        ? -1
        : 1
      : a.attribute < b.attribute
        ? -1
        : a.attribute > b.attribute
          ? 1
          : 0
  );
}
