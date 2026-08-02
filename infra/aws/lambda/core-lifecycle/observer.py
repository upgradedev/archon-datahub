"""Redacted CloudWatch projection for Core lease and readiness transitions."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

import boto3

STAGE = os.environ["CORE_STAGE"]
NAMESPACE = os.environ["CORE_METRIC_NAMESPACE"]
if STAGE not in {"staging", "production"} or NAMESPACE != "Archon/DataHubCore":
    raise RuntimeError("observer environment is invalid")

_CLOUDWATCH = boto3.client("cloudwatch")
ALLOWED_KEYS = {"CORE#LEASE", "RUNTIME#core"}
ALLOWED_STATES = {
    "STARTING",
    "ACTIVE",
    "UNHEALTHY",
    "STOPPING",
    "STOPPED",
    "EXPIRED",
    "FAILED",
    "READY",
}


def _scalar(value: Any) -> Any:
    if not isinstance(value, dict) or len(value) != 1:
        return None
    kind, raw = next(iter(value.items()))
    if kind == "S" and isinstance(raw, str):
        return raw
    if kind == "N" and isinstance(raw, str):
        try:
            return int(raw)
        except ValueError:
            return None
    return None


def _image(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {}
    image = record.get("dynamodb", {}).get("NewImage", {})
    if not isinstance(image, dict):
        return {}
    return {key: _scalar(value) for key, value in image.items()}


def handler(event: Any, _context: Any) -> dict[str, int]:
    records = event.get("Records", []) if isinstance(event, dict) else []
    metrics: list[dict[str, Any]] = []
    observed = 0
    for record in records:
        image = _image(record)
        pk = image.get("pk")
        if pk not in ALLOWED_KEYS:
            continue
        state = image.get("state") if pk == "CORE#LEASE" else image.get("status")
        if state not in ALLOWED_STATES:
            state = "UNKNOWN"
        session = image.get("sessionId")
        session_ref = (
            hashlib.sha256(session.encode("utf-8")).hexdigest()[:16]
            if isinstance(session, str)
            else "none"
        )
        transition = {
            "schema": "archon.core-runtime-observation/v1",
            "stage": STAGE,
            "record": "lease" if pk == "CORE#LEASE" else "health",
            "state": state,
            "revision": image.get("revision"),
            "checkedAt": image.get("checkedAt"),
            "sessionRef": session_ref,
        }
        print(json.dumps(transition, sort_keys=True, separators=(",", ":")))
        metrics.append(
            {
                "MetricName": "RuntimeTransition",
                "Dimensions": [
                    {"Name": "Stage", "Value": STAGE},
                    {"Name": "State", "Value": str(state)},
                ],
                "Value": 1,
                "Unit": "Count",
            }
        )
        observed += 1
    for start in range(0, len(metrics), 20):
        _CLOUDWATCH.put_metric_data(
            Namespace=NAMESPACE, MetricData=metrics[start : start + 20]
        )
    return {"observed": observed}
