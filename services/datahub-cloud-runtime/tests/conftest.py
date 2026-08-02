from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

RUNTIME = Path(__file__).resolve().parents[1]
COMPANION = RUNTIME.parent / "datahub-companion"
for location in (str(RUNTIME), str(COMPANION)):
    if location not in sys.path:
        sys.path.insert(0, location)

import contracts


@pytest.fixture
def runtime_job() -> contracts.RuntimeJob:
    return contracts.RuntimeJob(
        event_id="evt-1",
        pk="SESSION#rs_" + "A" * 43,
        sk="JOB#job_" + "B" * 22,
        job_id="job_" + "B" * 22,
        audit_id="c" * 64,
        runtime_evidence_digest="sha256:" + "d" * 64,
        session_id="rs_" + "A" * 43,
        generation="cloud-v2",
        capability_digest="sha256:" + "e" * 64,
        operation="READ_TAGS",
        request={
            "schemaVersion": "archon.core-tag-read/v1",
            "auditId": "c" * 64,
            "runtimeEvidenceDigest": "sha256:" + "d" * 64,
            "entityUrn": contracts.DATASET_URN,
            "columnPath": contracts.COLUMN_PATH,
        },
        submitted_at="2026-08-02T12:00:00.000Z",
        expires_at=1785675600,
    )


@pytest.fixture
def lambda_context() -> SimpleNamespace:
    return SimpleNamespace(aws_request_id="00000000-0000-4000-8000-000000000001")
