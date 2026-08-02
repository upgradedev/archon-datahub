from __future__ import annotations

import decimal
import importlib.util
import pathlib
import sys
import time
import types
from unittest import TestCase, main, mock

SESSION = "rs_" + "A" * 43
JOB = "job_" + "B" * 22
GENERATION = "core-20260802-1"
DIGEST = "sha256:" + "a" * 64
DATASET = (
    "urn:li:dataset:(urn:li:dataPlatform:snowflake,"
    "archon.public.customers,PROD)"
)


class FakeClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeKey:
    def __init__(self, _name: str) -> None:
        pass

    def eq(self, _value):
        return self

    def begins_with(self, _value):
        return self

    def __and__(self, _other):
        return self


class FakeTable:
    def __init__(self) -> None:
        self.pages: list[list[dict]] = []
        self.queries: list[dict] = []
        self.updates: list[dict] = []
        self.fail_update = ""

    def query(self, **kwargs):
        self.queries.append(kwargs)
        index = len(self.queries) - 1
        items = self.pages[index] if index < len(self.pages) else []
        result = {"Items": items}
        if index + 1 < len(self.pages):
            result["LastEvaluatedKey"] = {
                "pk": f"cursor-{index}",
                "sk": f"cursor-{index}",
            }
        return result

    def update_item(self, **kwargs):
        self.updates.append(kwargs)
        if self.fail_update:
            code = self.fail_update
            self.fail_update = ""
            raise FakeClientError(code)
        return {}


TABLE = FakeTable()
fake_boto3 = types.ModuleType("boto3")
fake_boto3.resource = lambda _name: types.SimpleNamespace(Table=lambda _name: TABLE)
fake_dynamodb = types.ModuleType("boto3.dynamodb")
fake_conditions = types.ModuleType("boto3.dynamodb.conditions")
fake_conditions.Key = FakeKey
fake_exceptions = types.ModuleType("botocore.exceptions")
fake_exceptions.ClientError = FakeClientError
sys.modules.setdefault("boto3", fake_boto3)
sys.modules.setdefault("boto3.dynamodb", fake_dynamodb)
sys.modules.setdefault("boto3.dynamodb.conditions", fake_conditions)
sys.modules.setdefault("botocore", types.ModuleType("botocore"))
sys.modules.setdefault("botocore.exceptions", fake_exceptions)

path = pathlib.Path(__file__).with_name("core_job_adapter.py")
spec = importlib.util.spec_from_file_location("core_job_adapter", path)
assert spec is not None and spec.loader is not None
adapter_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter_module)


def job(
    *,
    state: str = "QUEUED",
    operation: str = "ANALYZE",
    request=None,
    partition: str | None = None,
) -> dict:
    return {
        "pk": partition or f"SESSION#{SESSION}",
        "sk": f"JOB#{JOB}",
        "schema": "archon.core-runtime-job/v1",
        "sessionId": SESSION,
        "generation": GENERATION,
        "capabilityDigest": DIGEST,
        "state": state,
        "operation": operation,
        "jobId": JOB,
        "request": {} if request is None else request,
    }


def governed_request() -> dict:
    before_state = {
        "entityUrn": DATASET,
        "columnPath": "email",
        "tagUrns": [],
    }
    after_state = {
        "entityUrn": DATASET,
        "columnPath": "email",
        "tagUrns": ["urn:li:tag:PII"],
    }
    request = {
        "schemaVersion": "archon.core-governed-tag-mutation/v1",
        "auditId": "b" * 64,
        "runtimeEvidenceDigest": "sha256:" + "c" * 64,
        "auditEvidenceDigest": "sha256:" + "d" * 64,
        "planDigest": "sha256:" + "e" * 64,
        "approval": {
            "approvalId": "approval-123",
            "decision": "APPROVE",
            "approverDigest": "sha256:" + "f" * 64,
            "decidedAt": "2026-08-02T12:00:00.000Z",
            "digest": "sha256:" + "1" * 64,
        },
        "action": "ADD_TAGS",
        "arguments": {
            "tagUrns": ["urn:li:tag:PII"],
            "entityUrns": [DATASET],
            "columnPaths": ["email"],
        },
        "expectedBeforeDigest": adapter_module._digest(before_state),
        "expectedAfterDigest": adapter_module._digest(after_state),
    }
    return {**request, "requestDigest": adapter_module._digest(request)}


class CoreJobAdapterTests(TestCase):
    def setUp(self) -> None:
        TABLE.pages = []
        TABLE.queries.clear()
        TABLE.updates.clear()
        TABLE.fail_update = ""
        self.adapter = adapter_module.CoreJobAdapter(
            table_name="CoreLease",
            session_id=SESSION,
            generation=GENERATION,
            capability_digest=DIGEST,
        )

    def test_pagination_reaches_job_after_more_than_twenty_terminal_items(self):
        terminal = [
            job(state="SUCCEEDED")
            for _index in range(20)
        ]
        queued = job()
        TABLE.pages = [terminal, terminal, terminal, [queued]]
        executed: list[str] = []
        with (
            mock.patch.object(self.adapter, "_claim", return_value="a" * 32),
            mock.patch.object(
                self.adapter,
                "_execute",
                side_effect=lambda item, _attempt: executed.append(item["jobId"]),
            ),
        ):
            processed = self.adapter._process_partition(f"SESSION#{SESSION}")
        self.assertEqual(processed, 1)
        self.assertEqual(executed, [JOB])
        self.assertEqual(len(TABLE.queries), 4)
        self.assertIn("ExclusiveStartKey", TABLE.queries[-1])

    def test_stale_attempt_cannot_complete(self):
        TABLE.fail_update = "ConditionalCheckFailedException"
        completed = self.adapter._complete(
            job(state="RUNNING"),
            "a" * 32,
            "SUCCEEDED",
            result={"ok": True},
        )
        self.assertFalse(completed)
        condition = TABLE.updates[-1]["ConditionExpression"]
        self.assertIn("attemptId=:attempt", condition)

    def test_expired_attempt_is_requeued_for_crash_recovery(self):
        running = job(state="RUNNING")
        running.update(
            {
                "attemptId": "a" * 32,
                "attemptDeadlineEpoch": int(time.time()) - 1,
                "attemptCount": 1,
            }
        )
        self.assertTrue(self.adapter._recover_expired(running))
        update = TABLE.updates[-1]
        self.assertIn("SET #state=:queued", update["UpdateExpression"])
        self.assertIn("REMOVE attemptId", update["UpdateExpression"])

    def test_malformed_job_is_rejected_and_next_job_continues(self):
        malformed = job(request={"decimal": decimal.Decimal("1.2")})
        valid = job()
        valid["jobId"] = "job_" + "C" * 22
        valid["sk"] = "JOB#" + valid["jobId"]
        TABLE.pages = [[malformed, valid]]
        executed: list[str] = []
        with mock.patch.object(
            self.adapter,
            "_execute",
            side_effect=lambda item, _attempt: executed.append(item["jobId"]),
        ):
            processed = self.adapter._process_partition(f"SESSION#{SESSION}")
        self.assertEqual(processed, 1)
        self.assertEqual(executed, [valid["jobId"]])
        self.assertEqual(
            TABLE.updates[0]["ExpressionAttributeValues"][":receipt"]["error"][
                "code"
            ],
            "INVALID_CORE_JOB",
        )

    def test_unapproved_forged_or_multi_target_mutations_fail_closed(self):
        valid = governed_request()
        self.assertTrue(adapter_module._valid_governed_request(valid))

        unapproved = {**valid, "approval": {**valid["approval"], "decision": "DENY"}}
        self.assertFalse(adapter_module._valid_governed_request(unapproved))

        forged = {**valid, "planDigest": "sha256:" + "9" * 64}
        self.assertFalse(adapter_module._valid_governed_request(forged))

        wrong_tag = {
            **valid,
            "arguments": {
                **valid["arguments"],
                "tagUrns": ["urn:li:tag:Sensitive"],
            },
        }
        wrong_tag["requestDigest"] = adapter_module._digest(
            {key: value for key, value in wrong_tag.items() if key != "requestDigest"}
        )
        self.assertFalse(adapter_module._valid_governed_request(wrong_tag))

        multi = {
            **valid,
            "arguments": {
                **valid["arguments"],
                "entityUrns": [DATASET, DATASET],
                "columnPaths": ["email", "phone"],
            },
        }
        multi["requestDigest"] = adapter_module._digest(
            {key: value for key, value in multi.items() if key != "requestDigest"}
        )
        self.assertFalse(adapter_module._valid_governed_request(multi))

    def test_mutation_job_requires_separate_partition(self):
        request = governed_request()
        direct = job(
            operation="GOVERNED_TAG_MUTATION",
            request=request,
            partition=f"SESSION#{SESSION}",
        )
        isolated = {
            **direct,
            "pk": f"MUTATION#{SESSION}",
        }
        self.assertFalse(
            self.adapter._valid(direct, f"SESSION#{SESSION}")
        )
        self.assertTrue(
            self.adapter._valid(isolated, f"MUTATION#{SESSION}")
        )

    def test_governed_write_verifies_before_and_after(self):
        request = governed_request()
        before = [{"schemaMetadata": {"fields": [{"fieldPath": "email", "tags": []}]}}]
        after = [
            {
                "schemaMetadata": {
                    "fields": [
                        {
                            "fieldPath": "email",
                            "tags": [{"tag": {"urn": "urn:li:tag:PII"}}],
                        }
                    ]
                }
            }
        ]
        calls = [before, {"success": True}, after]
        with mock.patch.object(
            self.adapter, "_mcp_call", side_effect=calls
        ) as mcp:
            result = self.adapter._governed_mutation(request)
        self.assertTrue(result["verified"])
        self.assertEqual(result["requestDigest"], request["requestDigest"])
        self.assertRegex(result["responseDigest"], r"^sha256:[a-f0-9]{64}$")
        self.assertEqual(
            [call.args[0] for call in mcp.call_args_list],
            ["get_entities", "add_tags", "get_entities"],
        )

    def test_receipt_bound_prevents_dynamodb_item_overflow(self):
        self.adapter._complete(
            job(state="RUNNING"),
            "a" * 32,
            "SUCCEEDED",
            result={"payload": "x" * (adapter_module.MAX_RECEIPT_BYTES + 1)},
        )
        receipt = TABLE.updates[-1]["ExpressionAttributeValues"][":receipt"]
        self.assertEqual(receipt["state"], "FAILED")
        self.assertEqual(receipt["error"]["code"], "CORE_JOB_RECEIPT_TOO_LARGE")


if __name__ == "__main__":
    main()