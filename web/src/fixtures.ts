import type { AuditEnvelope, BlastRadius, Finding } from "./types";

const generatedAt = "2026-07-23T09:42:18.000Z";

const blast = (
  rootUrn: string,
  downstream: Array<[string, number]>,
  impact: BlastRadius["impact"],
): BlastRadius => ({
  rootUrn,
  downstream: downstream.map(([urn, minHops]) => ({ urn, minHops })),
  maxHops: 3,
  truncated: false,
  impact,
});

const findings: Finding[] = [
  {
    type: "governance_violation",
    severity: "high",
    subject: "urn:li:dataset:(urn:li:dataPlatform:snowflake,prod.customer_360,PROD)#email",
    summary: "Sensitive field email has no approved governance classification.",
    recommendation: "Add the PII tag through the digest-bound G6 approval workflow.",
    detail: {
      ruleId: "G6",
      rule: "Sensitive fields carry a governance classification",
      unclassifiedFields: ["email"],
      blastRadius: blast(
        "urn:li:dataset:(urn:li:dataPlatform:snowflake,prod.customer_360,PROD)",
        [
          ["urn:li:dataset:(urn:li:dataPlatform:dbt,analytics.customer_ltv,PROD)", 1],
          ["urn:li:dashboard:(looker,executive-retention)", 2],
          ["urn:li:dataset:(urn:li:dataPlatform:snowflake,marts.growth_segments,PROD)", 2],
          ["urn:li:dashboard:(powerbi,customer-health)", 2],
          ["urn:li:mlModel:(vertex,propensity-to-churn,PROD)", 3],
        ],
        "medium",
      ),
      provenance: [
        {
          source: "pipeline:snowflake-prod",
          runId: "snowflake-20260723-0918",
          observedAt: "2026-07-23T09:18:05.000Z",
          actor: "urn:li:corpuser:archon-ingestion",
          value: "SchemaField(email), tags=[]",
          status: "trusted",
        },
        {
          source: "pipeline:dbt-cloud-prod",
          runId: "dbt-20260723-0927",
          observedAt: "2026-07-23T09:27:41.000Z",
          actor: "urn:li:corpuser:dbt-cloud",
          value: "SchemaField(email), glossary=[Customer identifier]",
          status: "observed",
        },
      ],
      dossier: {
        dossierId: "dossier-46ef41af90d2",
        digest: "sha256:46ef41af90d21be1d4e89e2c369823daf2ab5da5125ddf4549f01a3f4fd4db65",
        policyDigest: "sha256:10f7946113825248ab7d8b914d0968c0b47264042903fd7573c482362dc62b85",
        generatedAt,
        evidenceCount: 7,
      },
      approval: {
        approvalId: "approval-g6-customer-email-001",
        expiresAt: "2026-08-10T20:59:00.000Z",
        targetField: "customer_360.email",
        proposedTag: "urn:li:tag:PII",
        before: ["urn:li:glossaryTerm:CustomerIdentifier"],
        after: ["urn:li:glossaryTerm:CustomerIdentifier", "urn:li:tag:PII"],
        planDigest: "sha256:e6325c683b8c30605a0391d4915a22b17d0c27ba63dc378327ebfc5cb9d23b7f",
        risk: "low",
      },
    },
  },
  {
    type: "contradiction",
    severity: "high",
    subject: "urn:li:dataset:(urn:li:dataPlatform:snowflake,prod.orders,PROD)",
    summary: "Two stable ingestion pipelines disagree on the orders owner.",
    recommendation: "Ask the Commerce steward to select the authoritative ownership source.",
    detail: {
      attribute: "owner",
      values: {
        "pipeline:snowflake-prod": "urn:li:corpGroup:commerce-platform",
        "pipeline:dbt-cloud-prod": "urn:li:corpGroup:analytics-engineering",
      },
      blastRadius: blast(
        "urn:li:dataset:(urn:li:dataPlatform:snowflake,prod.orders,PROD)",
        [
          ["urn:li:dataset:(urn:li:dataPlatform:dbt,marts.daily_revenue,PROD)", 1],
          ["urn:li:dataset:(urn:li:dataPlatform:spark,features.order_velocity,PROD)", 1],
          ["urn:li:dashboard:(looker,revenue-pulse)", 2],
          ["urn:li:dashboard:(tableau,regional-sales)", 2],
          ["urn:li:mlModel:(vertex,fraud-risk-v4,PROD)", 2],
          ["urn:li:mlModelDeployment:(vertex,fraud-risk-v4-online,PROD)", 3],
        ],
        "high",
      ),
      provenance: [
        {
          source: "pipeline:snowflake-prod",
          runId: "snowflake-20260723-0918",
          observedAt: "2026-07-23T09:18:05.000Z",
          actor: "urn:li:corpuser:platform-ingestion",
          value: "commerce-platform",
          status: "trusted",
        },
        {
          source: "pipeline:dbt-cloud-prod",
          runId: "dbt-20260723-0927",
          observedAt: "2026-07-23T09:27:41.000Z",
          actor: "urn:li:corpuser:dbt-cloud",
          value: "analytics-engineering",
          status: "conflicting",
        },
      ],
      dossier: {
        dossierId: "dossier-a271aa9c7863",
        digest: "sha256:a271aa9c78634017c138a23e7ec0807261e59dd0447195ed8b453f4d357beb95",
        policyDigest: "sha256:10f7946113825248ab7d8b914d0968c0b47264042903fd7573c482362dc62b85",
        generatedAt,
        evidenceCount: 11,
      },
    },
  },
  {
    type: "lineage_gap",
    severity: "medium",
    subject: "urn:li:dataset:(urn:li:dataPlatform:dbt,marts.daily_revenue,PROD)",
    summary: "An upstream payment_events edge resolves to no catalogued entity.",
    recommendation: "Restore the missing ingestion source or remove the stale lineage edge.",
    detail: {
      missingRef: "urn:li:dataset:(urn:li:dataPlatform:kafka,payment_events,PROD)",
      blastRadius: blast(
        "urn:li:dataset:(urn:li:dataPlatform:dbt,marts.daily_revenue,PROD)",
        [
          ["urn:li:dashboard:(looker,revenue-pulse)", 1],
          ["urn:li:dashboard:(tableau,regional-sales)", 1],
        ],
        "low",
      ),
      provenance: [
        {
          source: "pipeline:dbt-cloud-prod",
          runId: "dbt-20260723-0927",
          observedAt: "2026-07-23T09:27:41.000Z",
          actor: "urn:li:corpuser:dbt-cloud",
          value: "upstream=payment_events",
          status: "observed",
        },
      ],
      dossier: {
        dossierId: "dossier-320d5ca0c317",
        digest: "sha256:320d5ca0c3171f26995480bdc34a79512f70bfdb2544f94daeb34fe07dd5a4fc",
        policyDigest: "sha256:10f7946113825248ab7d8b914d0968c0b47264042903fd7573c482362dc62b85",
        generatedAt,
        evidenceCount: 4,
      },
    },
  },
  {
    type: "governance_violation",
    severity: "medium",
    subject: "urn:li:dataset:(urn:li:dataPlatform:s3,raw/support_tickets,PROD)",
    summary: "Production asset has no accountable owner.",
    recommendation: "Assign the Customer Operations data steward.",
    detail: {
      ruleId: "G1",
      rule: "Every production asset has an accountable owner",
      blastRadius: blast(
        "urn:li:dataset:(urn:li:dataPlatform:s3,raw/support_tickets,PROD)",
        [["urn:li:dataset:(urn:li:dataPlatform:snowflake,staging.support_tickets,PROD)", 1]],
        "low",
      ),
      provenance: [
        {
          source: "pipeline:s3-prod",
          runId: "s3-20260723-0901",
          observedAt: "2026-07-23T09:01:12.000Z",
          actor: "urn:li:corpuser:s3-ingestion",
          value: "owners=[]",
          status: "trusted",
        },
      ],
      dossier: {
        dossierId: "dossier-9aa56210a350",
        digest: "sha256:9aa56210a350183d0698716d06561438064613e9104125562e7013bff3dd2fb9",
        policyDigest: "sha256:10f7946113825248ab7d8b914d0968c0b47264042903fd7573c482362dc62b85",
        generatedAt,
        evidenceCount: 3,
      },
    },
  },
  {
    type: "governance_violation",
    severity: "low",
    subject: "urn:li:dataset:(urn:li:dataPlatform:postgres,ops.shipment_status,PROD)",
    summary: "Production dataset is outside an approved DataHub domain.",
    recommendation: "Classify the asset under the Operations domain.",
    detail: {
      ruleId: "G2",
      rule: "Every production asset belongs to a governed domain",
      blastRadius: blast(
        "urn:li:dataset:(urn:li:dataPlatform:postgres,ops.shipment_status,PROD)",
        [],
        "none",
      ),
      provenance: [
        {
          source: "pipeline:postgres-ops",
          runId: "postgres-20260723-0830",
          observedAt: "2026-07-23T08:30:00.000Z",
          actor: "urn:li:corpuser:postgres-ingestion",
          value: "domain=null",
          status: "trusted",
        },
      ],
      dossier: {
        dossierId: "dossier-91cbceac3e32",
        digest: "sha256:91cbceac3e32d3d18c5f8087cbcc5944139f58dc367b71894d69ab308323db7a",
        policyDigest: "sha256:10f7946113825248ab7d8b914d0968c0b47264042903fd7573c482362dc62b85",
        generatedAt,
        evidenceCount: 2,
      },
    },
  },
];

export const previewAudit: AuditEnvelope = {
  requestId: "preview-request-0001",
  releaseSha: "showcase-fixture",
  report: {
    scanId: "archon-showcase-20260723T094218Z",
    classification: {
      totalEntities: 1049,
      withLineage: 682,
      sensitiveEntities: 74,
      domains: {
        Commerce: 386,
        Customer: 272,
        Operations: 213,
        "(none)": 178,
      },
      platforms: {
        snowflake: 464,
        dbt: 238,
        s3: 133,
        looker: 94,
        powerbi: 63,
        other: 57,
      },
    },
    findings,
    narrative:
      "Archon inspected the DataHub Context Graph and surfaced five integrity risks. Two high-severity findings affect governed ownership and PII classification; downstream impact reaches analytics, dashboards, and an ML deployment. All proposed actions remain human-gated.",
    trace: [
      { agent: "classifier", produced: "1,049 entities classified" },
      {
        agent: "lineage-analyzer",
        produced: "2 provenance and lineage findings; 1 recovered from aspect history",
      },
      { agent: "governance-auditor", produced: "3 G1–G6 policy findings" },
      { agent: "narrator", produced: "grounded executive summary" },
    ],
  },
};
