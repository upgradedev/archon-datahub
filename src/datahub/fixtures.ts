// Deterministic DataHub metadata fixtures — a tiny, hand-built catalog that carries
// exactly the problems the self-audit is built to find, so the offline slice + CI
// prove the agent on real-shaped (if synthetic) DataHub metadata with zero network.
//
// The catalog is three datasets reported by two ingestion sources across two scans,
// engineered to contain ONE of each finding class:
//
//   • OWNER CONTRADICTION   — `sales_orders` is owned by team-finance per the Snowflake
//                             connector but by team-ops per the dbt manifest.
//   • FIELD-TYPE CONTRADICTION — the same connector/manifest disagree on the type of
//                             `sales_orders.amount` (number vs string).
//   • LINEAGE GAP           — `raw_orders` declares an upstream `external_feed` that no
//                             report catalogues — a dangling lineage edge.
//   • GOVERNANCE VIOLATIONS — `customer_pii` has no owner (G1), no domain (G2), no
//                             description (G3), and an unclassified sensitive `email`
//                             field (G6).
//
// Every value is provider-neutral metadata DataHub genuinely exposes (URNs, aspects,
// schema fields, lineage edges). Nothing here is domain-specific beyond generic data
// catalog concepts.

import type { SourceReport } from "../audit/harvest.js";
import type { CatalogEntity } from "./models.js";
import type { AspectVersionHistory } from "./version-history.js";

const SALES_ORDERS = "urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)";
const RAW_ORDERS = "urn:li:dataset:(urn:li:dataPlatform:snowflake,raw_orders,PROD)";
const CUSTOMER_PII = "urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)";
// Declared as an upstream of raw_orders but never catalogued → the lineage gap.
export const UNCATALOGUED_UPSTREAM =
  "urn:li:dataset:(urn:li:dataPlatform:external,external_feed,PROD)";

// sales_orders as the Snowflake connector reported it (scan 1).
const salesOrdersSnowflake: CatalogEntity = {
  urn: SALES_ORDERS,
  name: "sales_orders",
  platform: "snowflake",
  source: "snowflake-ingest",
  fabric: "PROD",
  description: "Curated sales orders, one row per confirmed order.",
  owners: ["urn:li:corpGroup:team-finance"],
  domain: "urn:li:domain:sales",
  tags: ["tier-1"],
  glossaryTerms: [],
  deprecated: false,
  fields: [
    { path: "order_id", type: "number" },
    { path: "amount", type: "number" },
    { path: "customer_email", type: "string", tags: ["pii"], glossaryTerms: ["Classification.PII"] },
  ],
  upstreams: [{ upstream: RAW_ORDERS, upstreamResolved: true, type: "TRANSFORMED" }],
};

// sales_orders as the dbt manifest reported it (scan 2) — SAME entity, DISAGREEING on
// the owner and on the type of `amount`. This is the contradiction pair.
const salesOrdersDbt: CatalogEntity = {
  ...salesOrdersSnowflake,
  source: "dbt-ingest",
  owners: ["urn:li:corpGroup:team-ops"], // ← disagrees with team-finance
  fields: [
    { path: "order_id", type: "number" },
    { path: "amount", type: "string" }, // ← disagrees with number
    { path: "customer_email", type: "string", tags: ["pii"], glossaryTerms: ["Classification.PII"] },
  ],
};

// raw_orders — catalogued (so sales_orders' upstream resolves) but itself declares an
// UNCATALOGUED upstream → the lineage gap.
const rawOrders: CatalogEntity = {
  urn: RAW_ORDERS,
  name: "raw_orders",
  platform: "snowflake",
  source: "snowflake-ingest",
  fabric: "PROD",
  description: "Landing table for raw order events.",
  owners: ["urn:li:corpGroup:team-data"],
  domain: "urn:li:domain:sales",
  deprecated: false,
  fields: [{ path: "order_id", type: "number" }],
  upstreams: [{ upstream: UNCATALOGUED_UPSTREAM, upstreamResolved: false, type: "COPY" }],
};

// customer_pii — the ungoverned asset: no owner, no domain, no description, and a
// sensitive `email` field with no classification tag/term.
const customerPii: CatalogEntity = {
  urn: CUSTOMER_PII,
  name: "customer_pii",
  platform: "snowflake",
  source: "snowflake-ingest",
  fabric: "PROD",
  description: "",
  owners: [],
  domain: null,
  deprecated: false,
  fields: [
    { path: "customer_id", type: "number" },
    { path: "email", type: "string" }, // sensitive + unclassified → G6
    { path: "signup_ts", type: "number" },
  ],
};

// The provenance-aware report stream: successive scans / distinct sources, exactly as
// DataHub would have recorded them. Ordered oldest → newest.
export const FIXTURE_REPORTS: SourceReport[] = [
  {
    source: "snowflake-ingest",
    scanId: "scan-2026-06-01",
    createdAt: "2026-06-01T09:00:00.000Z",
    entity: salesOrdersSnowflake,
  },
  {
    source: "snowflake-ingest",
    scanId: "scan-2026-06-01",
    createdAt: "2026-06-01T09:00:00.000Z",
    entity: rawOrders,
  },
  {
    source: "snowflake-ingest",
    scanId: "scan-2026-06-01",
    createdAt: "2026-06-01T09:00:00.000Z",
    entity: customerPii,
  },
  {
    source: "dbt-ingest",
    scanId: "scan-2026-07-01",
    createdAt: "2026-07-01T09:00:00.000Z",
    entity: salesOrdersDbt,
  },
];

// A clean single-source catalog (latest report per URN), handy for tests that want a
// no-findings baseline for the consistency engine.
export const FIXTURE_CLEAN_REPORTS: SourceReport[] = FIXTURE_REPORTS.filter(
  (r) => r.source === "snowflake-ingest"
);

// ── Aspect version-history fixtures (the LIVE contradiction-recovery path) ──────
// Shaped as the OpenAPI v3 versioned-aspect read returns them: each version wraps the raw
// PDL aspect `value` with `systemMetadata` (version, lastObserved epoch-ms, runId). These
// mirror what a direct GMS read of an aspect's history yields on a real DataHub — the
// provenance the MCP read tools' current-view collapses. See version-history.ts.
//
// Two histories, each proving one half of the honest semantics:
//   • sales_orders ownership FLIP-FLOPS between two ingestion runs (snowflake-connector
//     asserts team-finance; dbt-manifest asserts team-ops) → a GENUINE cross-source
//     contradiction that latest-write-wins hid. MUST fire.
//   • sales_orders.amount field type flip-flops between the same two runs (number vs
//     string) → the silent schema-break contradiction. MUST fire.
//   • raw_orders ownership is edited monotonically within ONE run (a correction:
//     team-data → team-dataeng, both from snowflake-connector) → benign DRIFT. MUST NOT
//     fire — this is the negative case the distinct-source gate must respect.
const RUN_SNOWFLAKE = "snowflake-connector-2026-06-01";
const RUN_DBT = "dbt-manifest-2026-07-01";
const T1 = new Date("2026-06-01T09:00:00.000Z").getTime();
const T2 = new Date("2026-07-01T09:00:00.000Z").getTime();
const T3 = new Date("2026-07-15T09:00:00.000Z").getTime();

export const FIXTURE_VERSION_HISTORY: AspectVersionHistory[] = [
  {
    urn: SALES_ORDERS,
    aspect: "ownership",
    versions: [
      {
        value: { owners: [{ owner: "urn:li:corpGroup:team-finance" }] },
        systemMetadata: { version: "1", lastObserved: T1, runId: RUN_SNOWFLAKE },
      },
      {
        value: { owners: [{ owner: "urn:li:corpGroup:team-ops" }] },
        systemMetadata: { version: "2", lastObserved: T2, runId: RUN_DBT },
      },
      {
        value: { owners: [{ owner: "urn:li:corpGroup:team-finance" }] },
        systemMetadata: { version: "3", lastObserved: T3, runId: RUN_SNOWFLAKE },
      },
    ],
  },
  {
    urn: SALES_ORDERS,
    aspect: "schemaMetadata",
    versions: [
      {
        value: { fields: [{ fieldPath: "amount", nativeDataType: "NUMBER" }] },
        systemMetadata: { version: "1", lastObserved: T1, runId: RUN_SNOWFLAKE },
      },
      {
        value: { fields: [{ fieldPath: "amount", nativeDataType: "STRING" }] },
        systemMetadata: { version: "2", lastObserved: T2, runId: RUN_DBT },
      },
    ],
  },
  {
    // Negative case: a single-run monotonic correction — DRIFT, not a contradiction.
    urn: RAW_ORDERS,
    aspect: "ownership",
    versions: [
      {
        value: { owners: [{ owner: "urn:li:corpGroup:team-data" }] },
        systemMetadata: { version: "1", lastObserved: T1, runId: RUN_SNOWFLAKE },
      },
      {
        value: { owners: [{ owner: "urn:li:corpGroup:team-dataeng" }] },
        systemMetadata: { version: "2", lastObserved: T2, runId: RUN_SNOWFLAKE },
      },
    ],
  },
];
