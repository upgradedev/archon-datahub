from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import httpx
import pytest

import archon_companion as companion


DATASET = "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
QUESTION = (
    "Which customer segment generated the highest net revenue in Q2 2026, "
    "and is customers.customer_email governed as PII?"
)
DOWNSTREAM_DATASET = "archon_demo.customer_segment_revenue"
GOVERNED_COLUMN = "customer_email"


def configure_runtime(monkeypatch, profile: str) -> None:
    monkeypatch.setenv("ARCHON_RUNTIME_PROFILE_ID", profile)
    monkeypatch.setenv("ARCHON_RUNTIME_GENERATION", "generation-1")
    monkeypatch.setenv(
        "ARCHON_RUNTIME_CAPABILITY_DIGEST", "sha256:" + "a" * 64,
    )


def client_factory(
    base_url: str,
    transport: httpx.MockTransport,
):
    def factory(timeout: httpx.Timeout) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout,
            transport=transport,
            trust_env=False,
            follow_redirects=False,
        )

    return factory


def test_sanitized_is_bounded_and_removes_secret_shaped_keys():
    nested: object = "leaf"
    for _ in range(10):
        nested = {"next": nested}
    value = {
        "authorization": "Bearer secret",
        "tokenValue": "secret",
        "safe": [float("nan"), float("inf"), ("ok", object())],
        "deep": nested,
    }
    result = companion.sanitized(value)
    assert "authorization" not in result
    assert "tokenValue" not in result
    assert result["safe"][0:2] == ["[non-finite]", "[non-finite]"]
    assert result["safe"][2][1] == "[unsupported]"
    assert "[depth-limit]" in json.dumps(result)
    assert math.isfinite(1.0)


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {"searchResults": "not-a-list"},
        {"searchResults": [None, {"entity": "bad"}]},
    ],
)
def test_dataset_selection_rejects_unstructured_results(value):
    assert companion.dataset_urns(value) == []


def test_datahub_client_accepts_bounded_server_owned_https(monkeypatch):
    captured = {}

    def factory(**kwargs):
        captured.update(kwargs)
        return object()

    configure_runtime(monkeypatch, "cloud")
    monkeypatch.setattr(companion, "DataHubClient", factory)
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://datahub.example/gms")
    monkeypatch.setenv("DATAHUB_GMS_TOKEN", "runtime-secret")
    companion.datahub_client()
    assert captured == {
        "server": "https://datahub.example/gms",
        "token": "runtime-secret",
    }


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_datahub_client_accepts_only_exact_core_loopback_http(
    monkeypatch,
    host,
):
    captured = {}

    def factory(**kwargs):
        captured.update(kwargs)
        return object()

    configure_runtime(monkeypatch, "core")
    monkeypatch.setattr(companion, "DataHubClient", factory)
    monkeypatch.setenv("DATAHUB_GMS_URL", f"http://{host}:18080")
    monkeypatch.setenv("DATAHUB_GMS_TOKEN", "runtime-secret")
    companion.datahub_client()
    assert captured == {
        "server": f"http://{host}:18080",
        "token": "runtime-secret",
    }


@pytest.mark.parametrize(
    "profile,url",
    [
        ("cloud", "http://127.0.0.1:18080"),
        ("cloud", "http://localhost:18080"),
        ("core", "http://datahub.example:18080"),
        ("core", "http://169.254.169.254:18080"),
        ("core", "http://[::1]:18080"),
        ("core", "http://127.0.0.1:8080"),
        ("core", "http://127.0.0.1:not-a-port"),
        ("core", "http://127.0.0.1:18080/gms"),
        ("core", "http://user:datahub@127.0.0.1:18080"),
        ("core", "http://127.0.0.1:18080?next=http://169.254.169.254"),
        ("core", "http://127.0.0.1:18080#fragment"),
        ("core", "https://datahub.example:8080/gms"),
        ("core", "https://datahub.example/unsafe"),
    ],
)
def test_datahub_client_rejects_every_other_http_or_url_drift(
    monkeypatch,
    profile,
    url,
):
    configure_runtime(monkeypatch, profile)
    monkeypatch.setenv("DATAHUB_GMS_URL", url)
    monkeypatch.setenv("DATAHUB_GMS_TOKEN", "runtime-secret")
    with pytest.raises(RuntimeError, match="server policy"):
        companion.datahub_client()


@pytest.mark.parametrize("token", ["", "x" * 8193])
def test_datahub_client_rejects_missing_or_oversized_token(
    monkeypatch,
    token,
):
    configure_runtime(monkeypatch, "cloud")
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://datahub.example/gms")
    monkeypatch.setenv("DATAHUB_GMS_TOKEN", token)
    with pytest.raises(RuntimeError, match="bounded"):
        companion.datahub_client()


def test_datahub_connection_receipt_is_non_secret(monkeypatch):
    class Graph:
        def test_connection(self):
            return True

    class Client:
        _graph = Graph()

    configure_runtime(monkeypatch, "core")
    monkeypatch.setenv("DATAHUB_GMS_URL", "http://127.0.0.1:18080")
    monkeypatch.setattr(companion, "datahub_client", lambda: Client())
    receipt = companion.test_datahub_connection()
    assert receipt["status"] == "verified"
    assert receipt["transport"] == "isolated-loopback-http"
    assert receipt["endpointClass"] == "isolated-core-loopback"
    assert receipt["mutationsEnabled"] is False
    assert "url" not in json.dumps(receipt).lower()


def test_datahub_connection_false_is_not_ready(monkeypatch):
    class Graph:
        def test_connection(self):
            return False

    class Client:
        _graph = Graph()

    monkeypatch.setattr(companion, "datahub_client", lambda: Client())
    with pytest.raises(RuntimeError, match="connection check"):
        companion.test_datahub_connection()


class FakeContext:
    def __init__(self, client):
        self.client = client

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_ack_context_preserves_unknown_when_search_resolves_nothing(
    monkeypatch,
):
    monkeypatch.setattr(companion, "DataHubContext", FakeContext)
    monkeypatch.setattr(companion, "datahub_client", lambda: object())
    monkeypatch.setattr(
        companion,
        "search",
        lambda **_: {"searchResults": []},
    )
    context = companion.collect_ack_context(DATASET)
    assert context["entityUrns"] == []
    assert context["unknownPreserved"] is True
    assert len(context["receipts"]) == 6
    assert context["receipts"][0]["tool"] == "search"
    assert all(
        item["status"] == "unknown"
        for item in context["receipts"][1:]
    )


def test_ack_context_executes_exact_read_only_dataset_workflow(
    monkeypatch,
):
    calls = []

    def record(name, result):
        def operation(**kwargs):
            calls.append((name, kwargs))
            if name == "assertions":
                raise RuntimeError("upstream internal")
            return result

        return operation

    monkeypatch.setattr(companion, "DataHubContext", FakeContext)
    monkeypatch.setattr(companion, "datahub_client", lambda: object())
    monkeypatch.setattr(
        companion,
        "search",
        lambda **kwargs: {
            "searchResults": [{
                "entity": {"type": "DATASET", "urn": DATASET},
            }],
        },
    )
    monkeypatch.setattr(
        companion,
        "get_entities",
        record("entities", {"entities": [{"urn": DATASET}]}),
    )
    monkeypatch.setattr(
        companion,
        "list_schema_fields",
        record("schema", {"fields": [{"fieldPath": GOVERNED_COLUMN}]}),
    )
    monkeypatch.setattr(
        companion,
        "get_lineage",
        record("lineage", {"relationships": [{"entity": DOWNSTREAM_DATASET}]}),
    )
    monkeypatch.setattr(
        companion,
        "get_dataset_assertions",
        record("assertions", {}),
    )

    context = companion.collect_ack_context(DATASET)
    assert context["entityUrns"] == [DATASET]
    assert [item["tool"] for item in context["receipts"]] == [
        "search",
        "get_entities",
        "list_schema_fields",
        "get_lineage_upstream",
        "get_lineage_downstream",
        "get_dataset_assertions",
    ]
    assert context["receipts"][-1]["status"] == "unknown"
    assert context["receipts"][-1]["result"] == {
        "reason": "tool unavailable",
    }
    assert calls[1][1] == {"urn": DATASET, "limit": 50, "offset": 0}
    assert calls[2][1]["upstream"] is True
    assert calls[3][1]["upstream"] is False


def lock_entry(data: bytes) -> dict:
    return {
        "gitBlob": companion.git_blob(data),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def test_regular_file_and_locked_file_fail_closed_on_drift(tmp_path):
    path = tmp_path / "skill.md"
    path.write_bytes(b"reviewed")
    receipt = companion.verify_locked_file(
        path,
        lock_entry(b"reviewed"),
    )
    assert receipt["bytes"] == 8
    with pytest.raises(RuntimeError, match="Skill drift"):
        companion.verify_locked_file(path, lock_entry(b"different"))
    with pytest.raises(RuntimeError, match="regular file"):
        companion.read_regular(tmp_path)


def mcp_locks(tmp_path: Path) -> tuple[Path, Path]:
    delegated_path = tmp_path / "datahub-mcp-v0.6.0.json"
    delegated = {
        "schemaVersion": "archon.datahub-mcp-lock/v5",
        "package": {
            "name": companion.MCP_PACKAGE,
            "version": companion.MCP_VERSION,
            "wheel": {"sha256": "1" * 64},
        },
        "resolution": {"sourceBuilds": "deny"},
        "source": {"commit": companion.MCP_SOURCE_COMMIT},
    }
    data = json.dumps(delegated, sort_keys=True).encode()
    delegated_path.write_bytes(data)
    stack_path = tmp_path / "datahub-agent-stack.json"
    stack_path.write_text(json.dumps({
        "schemaVersion": "archon.datahub-agent-stack-lock/v1",
        "components": {
            "mcpServer": {
                "name": companion.MCP_PACKAGE,
                "version": companion.MCP_VERSION,
                "delegatedLock": {
                    "path": ".github/locks/datahub-mcp-v0.6.0.json",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                },
            },
        },
    }))
    return stack_path, delegated_path


def test_mcp_provenance_binds_delegated_lock_and_tool_surface(
    tmp_path,
    monkeypatch,
):
    stack, delegated = mcp_locks(tmp_path)
    monkeypatch.setenv("ARCHON_AGENT_STACK_LOCK", str(stack))
    monkeypatch.setenv("ARCHON_DATAHUB_MCP_LOCK", str(delegated))
    receipt = companion.load_mcp_provenance()
    assert receipt["package"] == "mcp-server-datahub"
    assert receipt["version"] == "0.6.0"
    assert receipt["sourceCommit"] == companion.MCP_SOURCE_COMMIT
    assert receipt["toolSurfaceDigest"] == companion.digest(
        list(companion.MCP_TOOLS),
    )
    delegated.write_text("{}")
    with pytest.raises(RuntimeError, match="delegated lock drift"):
        companion.load_mcp_provenance()


@pytest.mark.parametrize(
    "variable,value,match",
    [
        (
            "ARCHON_ANALYTICS_AGENT_URL",
            "http://analytics-agent:8100/extra",
            "Analytics Agent URL",
        ),
        (
            "ARCHON_ANALYTICS_AGENT_URL",
            "http://169.254.169.254:8100",
            "Analytics Agent URL",
        ),
        (
            "ARCHON_DATAHUB_MCP_URL",
            "http://datahub-mcp:8000/mcp?target=internal",
            "DataHub MCP URL",
        ),
        (
            "ARCHON_DATAHUB_MCP_URL",
            "http://attacker:8000/mcp",
            "DataHub MCP URL",
        ),
    ],
)
def test_private_service_allowlists_are_exact(
    monkeypatch,
    variable,
    value,
    match,
):
    monkeypatch.setenv(variable, value)
    operation = (
        companion.analytics_url
        if variable == "ARCHON_ANALYTICS_AGENT_URL"
        else companion.mcp_endpoint
    )
    with pytest.raises(RuntimeError, match=match):
        operation()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["status", "media", "large", "malformed"])
async def test_bounded_json_rejects_untrusted_response_shapes(mode):
    def handler(_: httpx.Request) -> httpx.Response:
        if mode == "status":
            return httpx.Response(503, json={"error": "secret detail"})
        if mode == "media":
            return httpx.Response(200, text="ok")
        if mode == "large":
            return httpx.Response(
                200,
                content=b"x" * (companion.MAX_JSON_BYTES + 1),
                headers={"content-type": "application/json"},
            )
        return httpx.Response(
            200,
            content=b"{",
            headers={"content-type": "application/json"},
        )

    async with httpx.AsyncClient(
        base_url="http://analytics-agent:8100",
        transport=httpx.MockTransport(handler),
        trust_env=False,
    ) as client:
        with pytest.raises(Exception) as raised:
            await companion.bounded_json(client, "GET", "/health")
    assert "secret detail" not in str(raised.value)


@pytest.mark.asyncio
async def test_mcp_preflight_binds_live_health_to_provenance(
    monkeypatch,
):
    provenance = {
        "digest": "sha256:" + "a" * 64,
        "package": companion.MCP_PACKAGE,
        "version": companion.MCP_VERSION,
        "sourceCommit": companion.MCP_SOURCE_COMMIT,
        "toolSurfaceDigest": companion.digest(list(companion.MCP_TOOLS)),
    }
    monkeypatch.setattr(
        companion,
        "load_mcp_provenance",
        lambda: provenance,
    )
    def healthy_response(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok"})

    transport = httpx.MockTransport(healthy_response)
    monkeypatch.setattr(
        companion,
        "mcp_client",
        client_factory("http://datahub-mcp:8000", transport),
    )
    receipt = await companion.mcp_preflight()
    assert receipt["status"] == "verified"
    assert receipt["mutationsEnabled"] is False
    assert receipt["toolSurface"] == list(companion.MCP_TOOLS)


@pytest.mark.asyncio
async def test_mcp_preflight_rejects_process_only_health_drift(
    monkeypatch,
):
    monkeypatch.setattr(
        companion,
        "load_mcp_provenance",
        lambda: {
            "digest": "sha256:" + "a" * 64,
            "package": companion.MCP_PACKAGE,
            "version": companion.MCP_VERSION,
            "sourceCommit": companion.MCP_SOURCE_COMMIT,
            "toolSurfaceDigest": companion.digest(list(companion.MCP_TOOLS)),
        },
    )
    def starting_response(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "starting"})

    transport = httpx.MockTransport(starting_response)
    monkeypatch.setattr(
        companion,
        "mcp_client",
        client_factory("http://datahub-mcp:8000", transport),
    )
    with pytest.raises(RuntimeError, match="health contract"):
        await companion.mcp_preflight()


def connection_inventory(
    *,
    tools: list[dict] | None = None,
    endpoint: str = "http://datahub-mcp:8000/mcp",
    mcp_name: str = "archon-datahub-mcp",
    active: bool = True,
) -> list[dict]:
    return [
        {
            "name": mcp_name,
            "type": "datahub-mcp",
            "status": "connected" if active else "error",
            "disabled": False,
            "fields": [{"key": "url", "value": endpoint}],
            "tools": tools if tools is not None else [
                {"name": name, "enabled": True}
                for name in companion.MCP_TOOLS
            ],
        },
        {
            "name": "archon-judge",
            "type": "duckdb",
            "status": "connected",
            "disabled": False,
            "tools": [],
        },
    ]


def test_connection_policy_requires_exact_live_mcp_surface(
    monkeypatch,
):
    monkeypatch.setenv(
        "ARCHON_DATAHUB_MCP_CONNECTION",
        "archon-datahub-mcp",
    )
    result = companion.validate_connections(
        connection_inventory(),
        "archon-judge",
    )
    assert result["mcpConnectionName"] == "archon-datahub-mcp"
    assert result["mutationTools"] == {
        "publish_analysis": False,
        "save_correction": False,
    }


@pytest.mark.parametrize("drift", ["missing", "write", "endpoint", "name", "inactive"])
def test_connection_policy_rejects_mcp_drift(monkeypatch, drift):
    monkeypatch.setenv(
        "ARCHON_DATAHUB_MCP_CONNECTION",
        "archon-datahub-mcp",
    )
    kwargs = {}
    if drift == "missing":
        kwargs["tools"] = [
            {"name": name, "enabled": True}
            for name in companion.MCP_TOOLS
            if name != "search"
        ]
    elif drift == "write":
        kwargs["tools"] = [
            *[
                {"name": name, "enabled": True}
                for name in companion.MCP_TOOLS
            ],
            {"name": "publish_analysis", "enabled": False},
        ]
    elif drift == "endpoint":
        kwargs["endpoint"] = "http://localhost:8000/mcp"
    elif drift == "name":
        kwargs["mcp_name"] = "unreviewed"
    else:
        kwargs["active"] = False
    with pytest.raises(RuntimeError):
        companion.validate_connections(
            connection_inventory(**kwargs),
            "archon-judge",
        )


def test_native_datahub_connection_must_keep_mutations_observably_off(
    monkeypatch,
):
    monkeypatch.setenv(
        "ARCHON_DATAHUB_MCP_CONNECTION",
        "archon-datahub-mcp",
    )
    inventory = connection_inventory()
    native = {
        "name": "native-readonly",
        "type": "datahub",
        "status": "connected",
        "disabled": False,
        "tools": [
            {"name": "search", "enabled": True},
            {"name": "publish_analysis", "enabled": False},
            {"name": "save_correction", "enabled": False},
        ],
    }
    inventory.insert(1, native)
    result = companion.validate_connections(inventory, "archon-judge")
    assert result["activeDataHubConnections"] == [
        "archon-datahub-mcp",
        "native-readonly",
    ]
    native["tools"][1]["enabled"] = True
    with pytest.raises(RuntimeError, match="mutation tools"):
        companion.validate_connections(inventory, "archon-judge")


@pytest.mark.asyncio
async def test_analytics_contract_requires_configured_engine(monkeypatch):
    monkeypatch.delenv("ARCHON_ANALYTICS_ENGINE", raising=False)
    with pytest.raises(RuntimeError, match="engine is not configured"):
        await companion.analytics_contract_preflight()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["health", "inventory", "missing-engine"])
async def test_analytics_contract_rejects_process_and_engine_drift(
    monkeypatch,
    mode,
):
    monkeypatch.setenv("ARCHON_ANALYTICS_ENGINE", "archon-judge")
    monkeypatch.setenv(
        "ARCHON_DATAHUB_MCP_CONNECTION",
        "archon-datahub-mcp",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            payload = {"status": "starting"} if mode == "health" else {
                "status": "ok",
            }
            return httpx.Response(200, json=payload)
        if request.url.path == "/api/engines":
            if mode == "inventory":
                return httpx.Response(200, json="bad")
            name = "other" if mode == "missing-engine" else "archon-judge"
            return httpx.Response(200, json=[{
                "name": name,
                "type": "duckdb",
            }])
        if request.url.path == "/api/settings/connections":
            return httpx.Response(200, json=connection_inventory())
        raise AssertionError(request.url.path)

    monkeypatch.setattr(
        companion,
        "analytics_client",
        client_factory(
            "http://analytics-agent:8100",
            httpx.MockTransport(handler),
        ),
    )
    with pytest.raises(RuntimeError):
        await companion.analytics_contract_preflight()
