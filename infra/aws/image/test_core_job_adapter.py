from __future__ import annotations

import importlib.util
import pathlib
import sys
import types
from unittest import TestCase, main, mock

SESSION = "rs_" + "A" * 43
JOB = "job_" + "B" * 22
DIGEST = "sha256:" + "a" * 64
AUDIT = "b" * 64
DATASET = "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"


class FakeClientError(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code}}


class FakeKey:
    def __init__(self, value):
        self.value = value

    def eq(self, value):
        return ("eq", self.value, value)

    def begins_with(self, value):
        return ("begins", self.value, value)

    def __and__(self, other):
        return ("and", self, other)


class FakeTable:
    def __init__(self) -> None:
        self.updates = []
        self.items = []

    def update_item(self, **kwargs):
        self.updates.append(kwargs)
        return {}

    def query(self, **_kwargs):
        return {"Items": list(self.items)}


TABLE = FakeTable()
fake_boto3 = types.ModuleType("boto3")
fake_boto3.resource = lambda _name: types.SimpleNamespace(Table=lambda _table: TABLE)
fake_conditions = types.ModuleType("boto3.dynamodb.conditions")
fake_conditions.Key = FakeKey
fake_exceptions = types.ModuleType("botocore.exceptions")
fake_exceptions.ClientError = FakeClientError
sys.modules.setdefault("boto3", fake_boto3)
sys.modules.setdefault("boto3.dynamodb", types.ModuleType("boto3.dynamodb"))
sys.modules.setdefault("boto3.dynamodb.conditions", fake_conditions)
sys.modules.setdefault("botocore", types.ModuleType("botocore"))
sys.modules.setdefault("botocore.exceptions", fake_exceptions)

path = pathlib.Path(__file__).with_name("core_job_adapter.py")
spec = importlib.util.spec_from_file_location("core_job_adapter", path)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def state(tags: list[str]) -> dict:
    value = {
        "entityUrn": DATASET,
        "columnPath": "customer_email",
        "tagUrns": tags,
    }
    return {**value, "stateDigest": module._digest(value)}


def governed_request() -> dict:
    approval = {
        "approvalId": "approval-1",
        "decision": "APPROVE",
        "approverDigest": DIGEST,
        "decidedAt": "2026-08-02T08:00:00.000Z",
        "digest": DIGEST,
    }
    value = {
        "schemaVersion": "archon.core-governed-tag-mutation/v1",
        "auditId": AUDIT,
        "runtimeEvidenceDigest": DIGEST,
        "auditEvidenceDigest": DIGEST,
        "planDigest": DIGEST,
        "policyDigest": DIGEST,
        "approval": approval,
        "action": "ADD_TAGS",
        "arguments": {
            "tagUrns": ["urn:li:tag:PII"],
            "entityUrns": [DATASET],
            "columnPaths": ["customer_email"],
        },
        "expectedBeforeDigest": state([])["stateDigest"],
        "expectedAfterDigest": state(["urn:li:tag:PII"])["stateDigest"],
        "authorization": {
            "envelope": {"signed": True},
            "signature": {
                "keyArn": "arn:aws:kms:eu-west-1:123456789012:key/example",
                "algorithm": "ECDSA_SHA_256",
                "canonicalization": "archon.sorted-json-utf8/v1",
                "envelopeDigest": DIGEST,
                "signatureBase64": "opaque",
            },
        },
    }
    return {**value, "requestDigest": module._digest(value)}


def post_request(operation: str) -> dict:
    expected = state(["urn:li:tag:PII"])
    if operation == "POST_READ_TAGS":
        schema = "archon.core-post-mutation-tag-read/v1"
        original = {
            "schemaVersion": "archon.core-tag-read/v1",
            "auditId": AUDIT,
            "runtimeEvidenceDigest": DIGEST,
            "entityUrn": DATASET,
            "columnPath": "customer_email",
        }
    else:
        schema = "archon.datahub-post-mutation-analysis/v1"
        original = {
            "schemaVersion": "archon.demo-analysis/v1",
            "question": "Re-run with the verified PII context.",
        }
    return {
        "schemaVersion": schema,
        "originalRequest": original,
        "sourceMutationAuditId": AUDIT,
        "sourceMutationReceiptDigest": DIGEST,
        "postMutationExpectedTagState": expected,
    }


def runtime_job(*, profile_id: str = "core", schema: str = "archon.runtime-bound-job/v2") -> dict:
    return {
        "pk": f"SESSION#{SESSION}",
        "sk": f"JOB#{JOB}",
        "schema": schema,
        "profileId": profile_id,
        "sessionId": SESSION,
        "generation": "core-generation",
        "capabilityDigest": DIGEST,
        "jobId": JOB,
        "operation": "POST_READ_TAGS",
        "state": "QUEUED",
        "request": post_request("POST_READ_TAGS"),
    }


class CoreJobAdapterTests(TestCase):
    def setUp(self) -> None:
        TABLE.updates.clear()
        TABLE.items.clear()
        self.adapter = module.CoreJobAdapter(
            table_name="core-table",
            session_id=SESSION,
            generation="core-generation",
            capability_digest=DIGEST,
        )

    def test_governed_request_requires_policy_and_asymmetric_authorization(self):
        value = governed_request()
        self.assertTrue(module._valid_governed_request(value))
        for key in ("policyDigest", "authorization"):
            invalid = dict(value)
            invalid.pop(key)
            self.assertFalse(module._valid_governed_request(invalid))
        tampered = governed_request()
        tampered["arguments"]["columnPaths"] = ["other"]
        self.assertFalse(module._valid_governed_request(tampered))

    def test_read_mcp_cannot_route_mutation_and_gateway_cannot_route_reads(self):
        with self.assertRaises(RuntimeError):
            self.adapter._mcp_call(
                self.adapter._read_mcp_url,
                "execute_governed_mutation",
                {"job_id": JOB},
            )
        with self.assertRaises(RuntimeError):
            self.adapter._mcp_call(
                self.adapter._governed_mcp_url,
                "get_entities",
                {"urns": [DATASET]},
            )

    def test_governed_mutation_uses_one_gateway_execution_and_seals_evidence(self):
        request = governed_request()
        gateway_unsigned = {
            "schemaVersion": "archon.core-governed-gateway-result/v2",
            "success": True,
            "action": "ADD_TAGS",
            "requestDigest": request["requestDigest"],
            "policyDigest": DIGEST,
            "approvalDigest": DIGEST,
            "beforeDigest": request["expectedBeforeDigest"],
            "afterDigest": request["expectedAfterDigest"],
            "changed": True,
            "verified": True,
            "mutationExecutor": "official-datahub-mcp",
            "officialMcpMutation": {
                "tool": "add_tags",
                "policyDigest": DIGEST,
                "approvalDigest": DIGEST,
                "requestDigest": request["requestDigest"],
                "responseDigest": DIGEST,
            },
            "authorizationEvidence": {
                "keyArn": "arn:aws:kms:eu-west-1:123456789012:key/example",
                "algorithm": "ECDSA_SHA_256",
                "canonicalization": "archon.sorted-json-utf8/v1",
                "envelopeDigest": DIGEST,
                "signatureDigest": DIGEST,
                "consumedAt": "2026-08-02T08:00:00.000Z",
            },
        }
        gateway_result = {
            **gateway_unsigned,
            "receiptDigest": module._digest(gateway_unsigned),
        }
        item = {"jobId": JOB, "request": request}
        with mock.patch.object(
            self.adapter, "_mcp_call", return_value=gateway_result
        ) as call:
            result = self.adapter._governed_mutation(item)
        call.assert_called_once_with(
            self.adapter._governed_mcp_url,
            "execute_governed_mutation",
            {"job_id": JOB, "request": request},
        )
        self.assertEqual(result["mutationExecutor"], "official-datahub-mcp")
        self.assertEqual(result["officialMcpMutation"]["tool"], "add_tags")
        self.assertEqual(
            result["authorizationEvidence"]["canonicalization"],
            "archon.sorted-json-utf8/v1",
        )
        self.assertEqual(
            result["responseDigest"],
            module._digest({k: v for k, v in result.items() if k != "responseDigest"}),
        )

    def test_post_analysis_rechecks_live_tags_then_reruns_companion(self):
        request = post_request("POST_ANALYZE")
        with (
            mock.patch.object(
                self.adapter, "_read_tags", return_value=state(["urn:li:tag:PII"])
            ),
            mock.patch.object(
                self.adapter,
                "_companion",
                return_value={"answer": "PII is now verified."},
            ) as companion,
        ):
            result = self.adapter._post_mutation("POST_ANALYZE", request)
        companion.assert_called_once_with("/v2/analyze", request["originalRequest"])
        self.assertEqual(
            result["schemaVersion"],
            "archon.datahub-post-mutation-analysis-result/v1",
        )
        self.assertEqual(result["sourceMutationAuditId"], AUDIT)
        self.assertEqual(
            result["postMutationResultDigest"],
            module._digest(result["postMutationResult"]),
        )

    def test_post_tag_read_rejects_live_state_drift(self):
        request = post_request("POST_READ_TAGS")
        with mock.patch.object(self.adapter, "_read_tags", return_value=state([])):
            with self.assertRaises(RuntimeError):
                self.adapter._post_mutation("POST_READ_TAGS", request)

    def test_core_consumer_ignores_cloud_mismatch_and_legacy_jobs(self):
        cloud = runtime_job(profile_id="cloud")
        generation_mismatch = runtime_job()
        generation_mismatch["generation"] = "other-generation"
        capability_mismatch = runtime_job()
        capability_mismatch["capabilityDigest"] = "sha256:" + "c" * 64
        legacy = runtime_job(schema="archon.core-runtime-job/v1")
        TABLE.items.extend([cloud, generation_mismatch, capability_mismatch, legacy])
        with mock.patch.object(self.adapter, "_execute") as execute:
            self.assertEqual(self.adapter.process_once(), 0)
        execute.assert_not_called()
        self.assertEqual(TABLE.updates, [])
        self.assertFalse(self.adapter._valid(cloud, f"SESSION#{SESSION}"))
        self.assertFalse(self.adapter._valid(generation_mismatch, f"SESSION#{SESSION}"))
        self.assertFalse(self.adapter._valid(capability_mismatch, f"SESSION#{SESSION}"))
        self.assertFalse(self.adapter._valid(legacy, f"SESSION#{SESSION}"))

    def test_terminal_receipt_preserves_immutable_request_and_runtime_binding(self):
        item = runtime_job()
        item["state"] = "RUNNING"
        original_request = item["request"]
        self.assertTrue(
            self.adapter._complete(
                item, "f" * 32, "SUCCEEDED", result={"ok": True}
            )
        )
        update = TABLE.updates[-1]
        self.assertNotIn("request", update["UpdateExpression"])
        self.assertIs(item["request"], original_request)
        receipt = update["ExpressionAttributeValues"][":receipt"]
        self.assertEqual(receipt["schema"], "archon.runtime-bound-job-receipt/v2")
        self.assertEqual(receipt["profileId"], "core")
        self.assertIn("#schema=:schema", update["ConditionExpression"])
        self.assertIn("profileId=:profile", update["ConditionExpression"])

    def test_post_operations_are_session_only_and_adapter_never_enqueues(self):
        item = runtime_job()
        self.assertTrue(self.adapter._valid(item, f"SESSION#{SESSION}"))
        self.assertFalse(self.adapter._valid(item, f"MUTATION#{SESSION}"))
        source = path.read_text(encoding="utf-8")
        self.assertNotIn(".put_item(", source)
        self.assertNotIn("authorization_digest", source)
        self.assertNotIn("_governed_gateway_key", source)


if __name__ == "__main__":
    main()