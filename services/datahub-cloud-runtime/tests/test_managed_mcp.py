from __future__ import annotations

import asyncio
import base64

import pytest
from cryptography.fernet import Fernet

import contracts
import managed_mcp


def _writer():
    return managed_mcp.ManagedCredential(
        gms_url="https://demo.acryl.io",
        endpoint="https://demo.acryl.io/integrations/ai/mcp",
        token="t" * 32,
    )


def test_endpoint_is_exact_https_single_acryl_tenant():
    assert managed_mcp.derive_endpoint("https://demo.acryl.io/gms") == (
        "https://demo.acryl.io/integrations/ai/mcp"
    )
    for value in (
        "http://demo.acryl.io",
        "https://demo.acryl.io.evil.example",
        "https://nested.demo.acryl.io",
        "https://demo.acryl.io:444",
        "https://user@demo.acryl.io",
        "https://demo.acryl.io/gms?token=x",
        "https://127.0.0.1",
    ):
        with pytest.raises(contracts.ContractError):
            managed_mcp.derive_endpoint(value)


def test_reader_and_writer_secrets_are_non_interchangeable():
    key1 = Fernet.generate_key().decode("ascii")
    key2 = Fernet.generate_key().decode("ascii")
    reader = {
        "schemaVersion": "archon.datahub-cloud-reader-secret/v1",
        "gmsUrl": "https://demo.acryl.io",
        "token": "r" * 32,
        "runHandleFernetKey": key1,
        "oauthMasterKey": key2,
    }
    parsed = managed_mcp.parse_managed_secret(reader, purpose="reader")
    assert parsed.run_handle_key == key1
    assert parsed.oauth_master_key == key2
    with pytest.raises(contracts.ContractError, match="cloud_secret_invalid"):
        managed_mcp.parse_managed_secret(reader, purpose="writer")

    writer = {
        "schemaVersion": "archon.datahub-cloud-writer-secret/v1",
        "gmsUrl": "https://demo.acryl.io",
        "token": "w" * 32,
    }
    assert managed_mcp.parse_managed_secret(
        writer, purpose="writer"
    ).run_handle_key is None
    with pytest.raises(contracts.ContractError, match="cloud_secret_invalid"):
        managed_mcp.parse_managed_secret(writer, purpose="reader")


def test_column_tag_extraction_does_not_leak_sibling_field_tags():
    result = {
        "content": [
            {
                "type": "text",
                "text": contracts.canonical_json(
                    {
                        "fields": [
                            {
                                "fieldPath": contracts.COLUMN_PATH,
                                "globalTags": {
                                    "tags": [{"tag": contracts.PII_TAG}]
                                },
                            },
                            {
                                "fieldPath": "unrelated",
                                "globalTags": {
                                    "tags": [{"tag": "urn:li:tag:SECRET"}]
                                },
                            },
                        ]
                    }
                ).decode(),
            }
        ]
    }
    assert managed_mcp.extract_column_tags(result) == [contracts.PII_TAG]


def test_official_mcp_read_and_mutation_use_exact_arguments(monkeypatch):
    calls = []

    class FakeClient:
        def __init__(self, credential):
            assert credential == _writer()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def call(self, tool, arguments):
            calls.append((tool, arguments))
            if tool == "list_schema_fields":
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": contracts.canonical_json(
                                {
                                    "fieldPath": contracts.COLUMN_PATH,
                                    "tags": [contracts.PII_TAG],
                                }
                            ).decode(),
                        }
                    ]
                }
            return {
                "content": [
                    {
                        "type": "text",
                        "text": contracts.canonical_json({"ok": True}).decode(),
                    }
                ]
            }

    monkeypatch.setattr(managed_mcp, "ManagedMcpClient", FakeClient)
    read = asyncio.run(managed_mcp.read_column_tags(_writer()))
    assert read["tagUrns"] == [contracts.PII_TAG]
    assert calls[:2] == [
        ("get_entities", {"urns": [contracts.DATASET_URN]}),
        (
            "list_schema_fields",
            {
                "urn": contracts.DATASET_URN,
                "keywords": [contracts.COLUMN_PATH],
                "limit": 50,
                "offset": 0,
            },
        ),
    ]
    calls.clear()
    mutation = asyncio.run(
        managed_mcp.mutate_tags(_writer(), tool="add_tags")
    )
    assert calls == [
        (
            "add_tags",
            {
                "tag_urns": [contracts.PII_TAG],
                "entity_urns": [contracts.DATASET_URN],
                "column_paths": [contracts.COLUMN_PATH],
            },
        )
    ]
    assert mutation["tool"] == "add_tags"
    assert mutation["providerPayloadStored"] is False
    assert mutation["digest"] == contracts.digest(
        contracts.without(mutation, "digest")
    )


def test_rpc_decoder_rejects_mismatched_ids_errors_and_unbounded_shapes():
    good = contracts.canonical_json(
        {"jsonrpc": "2.0", "id": 7, "result": {"tools": []}}
    )
    assert managed_mcp._decode_response(good, "application/json", 7) == {
        "tools": []
    }
    for payload in (
        {"jsonrpc": "2.0", "id": 8, "result": {}},
        {"jsonrpc": "2.0", "id": 7, "error": {"code": -1}},
        {"id": 7, "result": {}},
    ):
        with pytest.raises(contracts.ContractError):
            managed_mcp._decode_response(
                contracts.canonical_json(payload), "application/json", 7
            )
