from __future__ import annotations

import dataclasses

import pytest

import analytics_runtime
import contracts
from managed_mcp import ManagedCredential


def _credential():
    return ManagedCredential(
        gms_url="https://demo.acryl.io",
        endpoint="https://demo.acryl.io/integrations/ai/mcp",
        token="reader-token-" + "x" * 24,
        run_handle_key="A" * 43 + "=",
        oauth_master_key="B" * 43 + "=",
    )


def test_analytics_config_uses_env_token_reference_not_plaintext(tmp_path):
    config = analytics_runtime._analytics_config(
        _credential().endpoint,
        tmp_path / "demo.sqlite",
    )
    assert "${DATAHUB_GMS_TOKEN}" in config
    assert _credential().token not in config
    assert "127.0.0.1" not in config


def test_session_forces_bedrock_regional_sts_and_role_binding(
    runtime_job, monkeypatch
):
    monkeypatch.setenv("ARCHON_BEDROCK_MODEL", "anthropic.claude-v3")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    monkeypatch.setenv(
        "ARCHON_EXPECTED_ANALYTICS_ROLE_ARN",
        "arn:aws:iam::123456789012:role/archon-cloud-reader",
    )
    session = analytics_runtime.AnalyticsSession(
        runtime_job, _credential(), object()
    )
    env = session.environment
    assert env["LLM_PROVIDER"] == "bedrock"
    assert env["AWS_STS_REGIONAL_ENDPOINTS"] == "regional"
    assert env["ARCHON_EXPECTED_ANALYTICS_ROLE_ARN"].endswith(
        "role/archon-cloud-reader"
    )
    assert "AWS_ACCESS_KEY_ID" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "AWS_SESSION_TOKEN" not in env
    assert env["ARCHON_CLOUD_MCP_ENDPOINT"] == _credential().endpoint


def test_post_analysis_contract_is_exact_and_pii_verified(runtime_job):
    state = {
        "entityUrn": contracts.DATASET_URN,
        "columnPath": contracts.COLUMN_PATH,
        "tagUrns": [contracts.PII_TAG],
    }
    expected = {
        "schemaVersion": "archon.core-tag-read-result/v1",
        **state,
        "stateDigest": contracts.digest(state),
    }
    request = {
        "schemaVersion": "archon.datahub-post-mutation-analysis/v1",
        "originalRequest": {"query": "canonical"},
        "sourceMutationAuditId": runtime_job.audit_id,
        "sourceMutationReceiptDigest": "sha256:" + "1" * 64,
        "postMutationExpectedTagState": expected,
    }
    original, metadata = analytics_runtime.validate_post_analysis(
        request, runtime_job
    )
    assert original == {"query": "canonical"}
    assert metadata["postMutationExpectedTagState"] == expected
    request["postMutationExpectedTagState"]["tagUrns"] = []
    with pytest.raises(contracts.ContractError, match="post_analysis_request_invalid"):
        analytics_runtime.validate_post_analysis(request, runtime_job)


def test_post_analysis_result_wraps_exact_original_execution(
    runtime_job, monkeypatch
):
    state = {
        "entityUrn": contracts.DATASET_URN,
        "columnPath": contracts.COLUMN_PATH,
        "tagUrns": [contracts.PII_TAG],
    }
    expected = {
        "schemaVersion": "archon.core-tag-read-result/v1",
        **state,
        "stateDigest": contracts.digest(state),
    }
    request = {
        "schemaVersion": "archon.datahub-post-mutation-analysis/v1",
        "originalRequest": {"query": "canonical"},
        "sourceMutationAuditId": runtime_job.audit_id,
        "sourceMutationReceiptDigest": "sha256:" + "1" * 64,
        "postMutationExpectedTagState": expected,
    }
    job = dataclasses.replace(
        runtime_job, operation="POST_ANALYZE", request=request
    )
    raw = {
        "schemaVersion": "archon.datahub-agent-stack-result/v2",
        "digest": "sha256:" + "2" * 64,
    }

    class Session:
        checkpoint_receipt = None

        def __init__(self, *_args):
            self.environment = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            proof = {
                "schemaVersion": "archon.analytics-checkpoint-receipt/v1",
                "providerPayloadStored": False,
            }
            self.checkpoint_receipt = {
                **proof, "digest": contracts.digest(proof)
            }

    async def analyze(value):
        assert value == {"query": "canonical"}
        return raw

    monkeypatch.setattr(analytics_runtime, "AnalyticsSession", Session)
    monkeypatch.setattr(analytics_runtime, "_analyze", analyze)
    result, evidence = analytics_runtime.execute_analytics_operation(
        job, _credential(), object()
    )
    assert result["schemaVersion"] == (
        "archon.datahub-post-mutation-analysis-result/v1"
    )
    assert result["postMutationResult"] == raw
    assert result["postMutationResultDigest"] == contracts.digest(raw)
    assert evidence["providerPayloadStored"] is False


def test_regular_file_reader_rejects_symlink_and_cleans_fixture(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"safe")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(OSError):
        analytics_runtime._regular_bytes(link, 32)
    link.unlink()
    target.unlink()
