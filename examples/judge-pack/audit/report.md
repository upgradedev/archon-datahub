# Archon DataHub audit

- Scan: `scan-2026-07-01`
- Findings: 7
- Entities: 3
- Runtime: deterministic-fixture
- Model call: no
- Provider: fixture
- Requested model: archon-deterministic-fixture-narrator-v1
- Returned model: not applicable
- Provider response ID: not applicable
- Token usage: not available
- Latency: not applicable

## Findings

| Severity | Type | Subject | Finding | Downstream |
|---|---|---|---|---:|
| high | contradiction | `urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)#amount` | Sources disagree on 'fieldType' for urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)#amount: "number" (snowflake-ingest) vs "string" (dbt-ingest). | 0 |
| high | governance_violation | `urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)` | G1: No owner assigned — ungoverned asset (ownership aspect empty). | 0 |
| high | governance_violation | `urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)` | G6: 1 sensitive field lacks an accepted classification tag/term: email. | 0 |
| medium | contradiction | `urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)` | Sources disagree on 'owner' for urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD): "urn:li:corpGroup:team-finance" (snowflake-ingest) vs "urn:li:corpGroup:team-ops" (dbt-ingest). | 0 |
| medium | governance_violation | `urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)` | G2: No domain assigned (domains aspect empty). | 0 |
| medium | governance_violation | `urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)` | G3: No description — undocumented asset. | 0 |
| medium | lineage_gap | `urn:li:dataset:(urn:li:dataPlatform:external,external_feed,PROD)` | Declared upstream urn:li:dataset:(urn:li:dataPlatform:external,external_feed,PROD) is not catalogued — a dangling lineage edge (schema-break risk to 1 downstream consumer). | 2 |

## Executive summary

Metadata governance summary: the self-audit surfaced 7 findings for steward review — 2 cross-source contradictions, 1 lineage gap, and 4 governance-policy violations. Contradictions indicate two metadata sources disagree on the same entity and should be reconciled at the system of record; lineage gaps are declared upstreams that are not catalogued and risk silent schema breaks downstream; governance violations are ungoverned or unclassified assets. All findings are read-only recommendations — a steward decides.
