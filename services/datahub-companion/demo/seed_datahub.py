"""Regenerate the portable SQLite demo and seed matching DataHub metadata."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any

SOURCE_URN = (
    "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
)
DOWNSTREAM_URN = (
    "urn:li:dataset:(urn:li:dataPlatform:sqlite,"
    "archon_demo.customer_segment_revenue,PROD)"
)
QUESTION = (
    "Which customer segment generated the highest net revenue in Q2 2026, "
    "and is customers.customer_email governed as PII?"
)
COLUMN = "customer_email"
OWNER_URN = "urn:li:corpuser:archon-demo-owner"
PII_TAG_URN = "urn:li:tag:PII"
DOMAIN_URN = "urn:li:domain:customer-analytics"
TERM_URN = "urn:li:glossaryTerm:net-revenue"
QUERY_URN = "urn:li:query:archon-q2-segment-net-revenue"
SQL_PATH = Path(__file__).with_name("archon_demo.sql")
AUDIT_TIME_MS = 1775001600000


def create_database(database: Path) -> None:
    if database.exists():
        if database.is_symlink() or not database.is_file():
            raise RuntimeError("demo database target is not one regular file")
        database.unlink()
    database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    script = SQL_PATH.read_text(encoding="utf-8")
    connection = sqlite3.connect(database)
    try:
        connection.executescript(script)
        connection.execute("PRAGMA foreign_keys = ON")
        row = connection.execute(
            "SELECT segment, net_revenue_cents "
            "FROM customer_segment_revenue "
            "ORDER BY net_revenue_cents DESC, segment LIMIT 1"
        ).fetchone()
        if row != ("enterprise", 1850000):
            raise RuntimeError("portable demo result drifted")
        connection.commit()
    finally:
        connection.close()
    database.chmod(0o600)


def metadata_plan() -> dict[str, Any]:
    return {
        "schemaVersion": "archon.datahub-core-demo-seed/v2",
        "platform": "sqlite",
        "environment": "PROD",
        "question": QUESTION,
        "owner": {
            "urn": OWNER_URN,
            "displayName": "Archon Demo Data Owner",
            "email": "archon-demo-owner@example.invalid",
        },
        "tag": {
            "urn": PII_TAG_URN,
            "name": "Personally Identifiable Information",
        },
        "domain": {
            "urn": DOMAIN_URN,
            "name": "Customer Analytics",
            "datasets": [SOURCE_URN, DOWNSTREAM_URN],
        },
        "glossaryTerm": {
            "urn": TERM_URN,
            "name": "Net Revenue",
            "definition": (
                "Gross recognized revenue minus refunds for events on or after "
                "2026-04-01 and before 2026-07-01 (Q2 2026 UTC boundary)."
            ),
            "datasets": [DOWNSTREAM_URN],
        },
        "query": {
            "urn": QUERY_URN,
            "subjects": [SOURCE_URN, DOWNSTREAM_URN],
            "statement": (
                "SELECT segment, customer_count, net_revenue_cents "
                "FROM customer_segment_revenue "
                "ORDER BY net_revenue_cents DESC, segment LIMIT 1"
            ),
        },
        "source": {
            "urn": SOURCE_URN,
            "name": "archon_demo.customers",
            "owner": OWNER_URN,
            "quality": {
                "schemaAssertion": "required-columns",
                "q2RevenueReconciled": True,
            },
            "fields": [
                ("customer_id", "INTEGER", "number"),
                (COLUMN, "TEXT", "string"),
                ("segment", "TEXT", "string"),
                ("country_code", "TEXT", "string"),
                ("consent_status", "TEXT", "string"),
            ],
            "customerEmailTags": [],
        },
        "downstream": {
            "urn": DOWNSTREAM_URN,
            "name": "archon_demo.customer_segment_revenue",
            "owner": OWNER_URN,
            "upstreams": [SOURCE_URN],
            "fields": [
                ("segment", "TEXT", "string"),
                ("customer_count", "INTEGER", "number"),
                ("net_revenue_cents", "INTEGER", "number"),
            ],
        },
    }

def _token(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise RuntimeError("credential file must be regular and mode 0600")
        with os.fdopen(os.dup(descriptor), encoding="utf-8") as stream:
            document = json.load(stream)
    finally:
        os.close(descriptor)
    if set(document) != {"readToken", "writeToken"}:
        raise RuntimeError("credential file schema is invalid")
    token = document["writeToken"]
    if not isinstance(token, str) or not token or len(token) > 8192:
        raise RuntimeError("write credential is invalid")
    return token


def _schema(name: str, fields: list[tuple[str, str, str]]) -> Any:
    from datahub.emitter.mce_builder import make_data_platform_urn
    from datahub.metadata.schema_classes import (
        AuditStampClass,
        NumberTypeClass,
        OtherSchemaClass,
        SchemaFieldClass,
        SchemaFieldDataTypeClass,
        SchemaMetadataClass,
        StringTypeClass,
    )

    audit = AuditStampClass(
        time=AUDIT_TIME_MS, actor="urn:li:corpuser:archon-demo-owner"
    )
    schema_fields = []
    for field, native, kind in fields:
        logical = NumberTypeClass() if kind == "number" else StringTypeClass()
        schema_fields.append(
            SchemaFieldClass(
                fieldPath=field,
                type=SchemaFieldDataTypeClass(type=logical),
                nativeDataType=native,
                description=(
                    "Governed demo field; its intentionally missing PII tag is "
                    "added only after a digest-bound human approval."
                    if field == COLUMN
                    else "Deterministic, synthetic judge-demo field."
                ),
                lastModified=audit,
            )
        )
    return SchemaMetadataClass(
        schemaName=name,
        platform=make_data_platform_urn("sqlite"),
        version=0,
        created=audit,
        lastModified=audit,
        fields=schema_fields,
        hash="",
        platformSchema=OtherSchemaClass(rawSchema=SQL_PATH.read_text("utf-8")),
    )


def emit_metadata(gms_url: str, credential_file: Path) -> int:
    if gms_url != "http://127.0.0.1:18080":
        raise RuntimeError("Core seeder may target only the loopback GMS")
    from datahub.emitter.mce_builder import datahub_guid, make_assertion_urn
    from datahub.emitter.mcp import MetadataChangeProposalWrapper
    from datahub.emitter.rest_emitter import DatahubRestEmitter
    from datahub.metadata.schema_classes import (
        AssertionInfoClass,
        AssertionTypeClass,
        AuditStampClass,
        CorpUserInfoClass,
        DatasetLineageTypeClass,
        DatasetPropertiesClass,
        DomainPropertiesClass,
        DomainsClass,
        GlossaryTermAssociationClass,
        GlossaryTermInfoClass,
        GlossaryTermsClass,
        OwnerClass,
        OwnershipClass,
        OwnershipTypeClass,
        QueryLanguageClass,
        QueryPropertiesClass,
        QuerySourceClass,
        QueryStatementClass,
        QuerySubjectClass,
        QuerySubjectsClass,
        SchemaAssertionCompatibilityClass,
        SchemaAssertionInfoClass,
        TagPropertiesClass,
        UpstreamClass,
        UpstreamLineageClass,
    )

    plan = metadata_plan()
    token = _token(credential_file)
    emitter = DatahubRestEmitter(gms_server=gms_url, token=token)
    audit = AuditStampClass(
        time=AUDIT_TIME_MS, actor="urn:li:corpuser:archon-demo-owner"
    )
    owner = OwnershipClass(
        owners=[
            OwnerClass(
                owner="urn:li:corpuser:archon-demo-owner",
                type=OwnershipTypeClass.DATAOWNER,
            )
        ],
        lastModified=audit,
    )
    source_schema = _schema(plan["source"]["name"], plan["source"]["fields"])
    downstream_schema = _schema(
        plan["downstream"]["name"], plan["downstream"]["fields"]
    )
    proposals = [
        MetadataChangeProposalWrapper(
            entityUrn=OWNER_URN,
            aspect=CorpUserInfoClass(
                active=True,
                displayName=plan["owner"]["displayName"],
                fullName=plan["owner"]["displayName"],
                email=plan["owner"]["email"],
            ),
        ),
        MetadataChangeProposalWrapper(
            entityUrn=PII_TAG_URN,
            aspect=TagPropertiesClass(
                name=plan["tag"]["name"],
                description=(
                    "Personally identifiable data. The tag entity is seeded, but "
                    "customers.customer_email intentionally starts untagged."
                ),
                colorHex="#B42318",
            ),
        ),
        MetadataChangeProposalWrapper(
            entityUrn=DOMAIN_URN,
            aspect=DomainPropertiesClass(
                name=plan["domain"]["name"],
                description="Canonical synthetic customer analytics assets.",
            ),
        ),
        MetadataChangeProposalWrapper(
            entityUrn=TERM_URN,
            aspect=GlossaryTermInfoClass(
                definition=plan["glossaryTerm"]["definition"],
                termSource="INTERNAL",
                name=plan["glossaryTerm"]["name"],
                customProperties={
                    "calculation": "gross recognized revenue minus refunds",
                    "period.startInclusive": "2026-04-01T00:00:00Z",
                    "period.endExclusive": "2026-07-01T00:00:00Z",
                },
            ),
        ),
        MetadataChangeProposalWrapper(
            entityUrn=SOURCE_URN,
            aspect=DatasetPropertiesClass(
                name="Archon demo customers",
                description="Synthetic customer dimensions for the portable Q2 2026 demo.",
                customProperties={
                    "quality.q2RevenueReconciled": "true",
                    "governance.customer_email.pii": "missing-intentionally",
                    "analytics.queryUrn": QUERY_URN,
                    "fixture.schema": "archon.datahub-core-demo-seed/v2",
                },
            ),
        ),
        MetadataChangeProposalWrapper(entityUrn=SOURCE_URN, aspect=source_schema),
        MetadataChangeProposalWrapper(entityUrn=SOURCE_URN, aspect=owner),
        MetadataChangeProposalWrapper(
            entityUrn=SOURCE_URN, aspect=DomainsClass(domains=[DOMAIN_URN])
        ),
        MetadataChangeProposalWrapper(
            entityUrn=DOWNSTREAM_URN,
            aspect=DatasetPropertiesClass(
                name="Q2 2026 customer segment net revenue",
                description=(
                    "Deterministic aggregate for Q2 2026: gross recognized revenue "
                    "minus refunds; field tags do not propagate automatically in Core."
                ),
                customProperties={
                    "quality.expectedTopSegment": "enterprise",
                    "quality.expectedNetRevenueCents": "1850000",
                    "metric.netRevenue": "gross recognized revenue minus refunds",
                    "period.startInclusive": "2026-04-01T00:00:00Z",
                    "period.endExclusive": "2026-07-01T00:00:00Z",
                    "fixture.schema": "archon.datahub-core-demo-seed/v2",
                },
            ),
        ),
        MetadataChangeProposalWrapper(entityUrn=DOWNSTREAM_URN, aspect=downstream_schema),
        MetadataChangeProposalWrapper(entityUrn=DOWNSTREAM_URN, aspect=owner),
        MetadataChangeProposalWrapper(
            entityUrn=DOWNSTREAM_URN, aspect=DomainsClass(domains=[DOMAIN_URN])
        ),
        MetadataChangeProposalWrapper(
            entityUrn=DOWNSTREAM_URN,
            aspect=GlossaryTermsClass(
                terms=[GlossaryTermAssociationClass(urn=TERM_URN)],
                auditStamp=audit,
            ),
        ),
        MetadataChangeProposalWrapper(
            entityUrn=DOWNSTREAM_URN,
            aspect=UpstreamLineageClass(
                upstreams=[
                    UpstreamClass(
                        dataset=SOURCE_URN,
                        type=DatasetLineageTypeClass.TRANSFORMED,
                        auditStamp=audit,
                    )
                ]
            ),
        ),
        MetadataChangeProposalWrapper(
            entityUrn=QUERY_URN,
            aspect=QueryPropertiesClass(
                statement=QueryStatementClass(
                    value=plan["query"]["statement"],
                    language=QueryLanguageClass.SQL,
                ),
                source=QuerySourceClass.MANUAL,
                name="Top customer segment by Q2 2026 net revenue",
                description=(
                    "Canonical deterministic query used by the Analytics Agent demo."
                ),
                created=audit,
                lastModified=audit,
            ),
        ),
        MetadataChangeProposalWrapper(
            entityUrn=QUERY_URN,
            aspect=QuerySubjectsClass(
                subjects=[
                    QuerySubjectClass(entity=SOURCE_URN),
                    QuerySubjectClass(entity=DOWNSTREAM_URN),
                ]
            ),
        ),
    ]
    assertion_urn = make_assertion_urn(
        datahub_guid({"entity": SOURCE_URN, "type": "required-columns"})
    )
    proposals.append(
        MetadataChangeProposalWrapper(
            entityUrn=assertion_urn,
            aspect=AssertionInfoClass(
                type=AssertionTypeClass.DATA_SCHEMA,
                schemaAssertion=SchemaAssertionInfoClass(
                    entity=SOURCE_URN,
                    schema=source_schema,
                    compatibility=SchemaAssertionCompatibilityClass.SUPERSET,
                ),
                description=(
                    "The synthetic customers dataset must retain its required schema."
                ),
            ),
        )
    )
    for proposal in proposals:
        emitter.emit_mcp(proposal)
    return len(proposals)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--gms-url", default="")
    parser.add_argument("--credential-file", type=Path)
    arguments = parser.parse_args()
    create_database(arguments.database)
    if bool(arguments.gms_url) != bool(arguments.credential_file):
        raise RuntimeError("GMS URL and credential file must be supplied together")
    if arguments.gms_url:
        emit_metadata(arguments.gms_url, arguments.credential_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())