from __future__ import annotations

import json

import httpx
import pytest

import archon_companion as companion


CAPABILITY = "sha256:" + "a" * 64
SESSION = "managed-session_1"
TOKEN = "reader-service-account-token"
TENANT = "https://judge.acryl.io"
PROVIDER_SECRET = "provider-internal-secret"


def configure_runtime(monkeypatch, profile: str = "cloud") -> None:
    monkeypatch.setenv("ARCHON_RUNTIME_PROFILE_ID", profile)
    monkeypatch.setenv("ARCHON_RUNTIME_GENERATION", "generation-1")
    monkeypatch.setenv("ARCHON_RUNTIME_CAPABILITY_DIGEST", CAPABILITY)
    monkeypatch.setenv("ARCHON_DEMO_QUERY", companion.CANONICAL_DATASET_URN)
    monkeypatch.delenv("ARCHON_DATAHUB_MCP_URL", raising=False)
    if profile == "cloud":
        monkeypatch.setenv("DATAHUB_GMS_URL", TENANT + "/gms")
        monkeypatch.setenv("DATAHUB_GMS_TOKEN", TOKEN)
    else:
        monkeypatch.setenv("DATAHUB_GMS_URL", "http://archon-gms:8080")
        monkeypatch.setenv("DATAHUB_GMS_TOKEN", "core-reader-token")
        monkeypatch.setenv(
            "ARCHON_DATAHUB_MCP_URL",
            "http://archon-read-mcp:8000/mcp",
        )


def managed_client_factory(transport: httpx.MockTransport):
    def factory(timeout: httpx.Timeout) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=TENANT,
            headers={"Authorization": f"Bearer {TOKEN}"},
            timeout=timeout,
            transport=transport,
            trust_env=False,
            follow_redirects=False,
        )

    return factory


def core_client_factory(transport: httpx.MockTransport):
    def factory(timeout: httpx.Timeout) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url="http://archon-read-mcp:8000",
            timeout=timeout,
            transport=transport,
            trust_env=False,
            follow_redirects=False,
        )

    return factory


def tool(name: str, *, read_only: bool = True, destructive: bool = False) -> dict:
    return {
        "name": name,
        "description": "provider text is never retained",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": True,
        },
    }


def initialize_result(request_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "protocolVersion": companion.MCP_PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "DataHub MCP", "version": "1"},
        },
    }


def tool_call_result(
    request_id: int,
    name: str,
    *,
    resolves_search: bool = True,
) -> dict:
    provider_result = {
        "tool": name,
        "providerSecret": PROVIDER_SECRET,
        "endpoint": "https://provider.internal/private",
    }
    if name == "search":
        provider_result["searchResults"] = [{
            "entity": {
                "urn": (
                    companion.CANONICAL_DATASET_URN
                    if resolves_search
                    else "prefix-" + companion.CANONICAL_DATASET_URN + "-suffix"
                ),
            },
        }]
    if name == "get_dataset_queries":
        provider_result["queries"] = []
    provider_payload = json.dumps(provider_result)
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": provider_payload}],
            "isError": False,
        },
    }


def assert_cloud_headers(request: httpx.Request) -> None:
    assert request.url.host == "judge.acryl.io"
    assert request.url.path == companion.CLOUD_MCP_PATH
    assert request.url.query == b""
    assert request.headers["authorization"] == f"Bearer {TOKEN}"
    assert request.headers["accept"] == "application/json, text/event-stream"


def cloud_protocol_handler(
    inventory: list[dict],
    *,
    tool_mode: str = "json",
    changed_session: bool = False,
    empty_search: bool = False,
    calls: list[httpx.Request] | None = None,
):
    observed = calls if calls is not None else []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        assert_cloud_headers(request)
        if request.method == "DELETE":
            assert request.headers["mcp-session-id"] == SESSION
            assert request.headers["mcp-protocol-version"] == (
                companion.MCP_PROTOCOL_VERSION
            )
            return httpx.Response(204)
        body = json.loads(request.content)
        method = body.get("method")
        if method == "initialize":
            assert "mcp-session-id" not in request.headers
            assert "mcp-protocol-version" not in request.headers
            return httpx.Response(
                200,
                json=initialize_result(),
                headers={"Mcp-Session-Id": SESSION},
            )
        assert request.headers["mcp-session-id"] == SESSION
        assert request.headers["mcp-protocol-version"] == (
            companion.MCP_PROTOCOL_VERSION
        )
        if method == "notifications/initialized":
            assert set(body) == {"jsonrpc", "method"}
            return httpx.Response(202)
        if method == "tools/list":
            response_headers = {}
            if changed_session:
                response_headers["Mcp-Session-Id"] = "different-session"
            if tool_mode == "large":
                return httpx.Response(
                    200,
                    content=b"x" * (companion.MAX_JSON_BYTES + 1),
                    headers={"content-type": "application/json"},
                )
            if tool_mode == "invalid-sse":
                return httpx.Response(
                    200,
                    content=b"event: message\ndata: {\n",
                    headers={"content-type": "text/event-stream"},
                )
            payload = {
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"tools": inventory},
            }
            if tool_mode == "sse":
                return httpx.Response(
                    200,
                    text="event: message\ndata: " + json.dumps(payload) + "\n\n",
                    headers={
                        "content-type": "text/event-stream",
                        **response_headers,
                    },
                )
            return httpx.Response(200, json=payload, headers=response_headers)
        if method == "tools/call":
            name = body["params"]["name"]
            return httpx.Response(200, json=tool_call_result(
                body["id"],
                name,
                resolves_search=not empty_search,
            ))
        raise AssertionError(method)

    return handler


def test_cloud_client_derives_tenant_origin_and_header_without_proxy(
    monkeypatch,
):
    configure_runtime(monkeypatch)
    captured = {}

    def factory(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(companion.httpx, "AsyncClient", factory)
    companion.mcp_client(httpx.Timeout(5.0))
    assert companion.mcp_endpoint() == TENANT + companion.CLOUD_MCP_PATH
    assert captured["base_url"] == TENANT
    assert captured["headers"] == {
        "Authorization": f"Bearer {TOKEN}",
    }
    assert captured["trust_env"] is False
    assert captured["follow_redirects"] is False
    assert TOKEN not in captured["base_url"]


def test_analytics_endpoint_is_profile_exact(monkeypatch):
    configure_runtime(monkeypatch, "cloud")
    monkeypatch.delenv("ARCHON_ANALYTICS_AGENT_URL", raising=False)
    assert companion.analytics_url() == "http://127.0.0.1:8100"
    for invalid in (
        "http://localhost:8100",
        "http://archon-analytics:8100",
        "http://127.0.0.1:8100/extra",
        "http://127.0.0.1:8101",
    ):
        monkeypatch.setenv("ARCHON_ANALYTICS_AGENT_URL", invalid)
        with pytest.raises(RuntimeError, match="private allowlist"):
            companion.analytics_url()

    configure_runtime(monkeypatch, "core")
    monkeypatch.delenv("ARCHON_ANALYTICS_AGENT_URL", raising=False)
    assert companion.analytics_url() == "http://archon-analytics:8100"
    monkeypatch.setenv(
        "ARCHON_ANALYTICS_AGENT_URL",
        "http://127.0.0.1:8100",
    )
    with pytest.raises(RuntimeError, match="private allowlist"):
        companion.analytics_url()


@pytest.mark.asyncio
async def test_managed_preflight_reads_canonical_sequence_with_session(
    monkeypatch,
):
    configure_runtime(monkeypatch)
    calls: list[httpx.Request] = []
    selected = [tool(name) for name in companion.MCP_TOOLS]
    first_page = selected[:3]
    second_page = [*selected[3:], tool("add_tags", read_only=False)]
    read_plan = list(companion.canonical_mcp_read_plan())

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert_cloud_headers(request)
        if request.method == "DELETE":
            assert request.headers["mcp-session-id"] == SESSION
            return httpx.Response(204)
        body = json.loads(request.content)
        method = body.get("method")
        if method == "initialize":
            assert body["params"]["protocolVersion"] == (
                companion.MCP_PROTOCOL_VERSION
            )
            return httpx.Response(
                200,
                json=initialize_result(),
                headers={"Mcp-Session-Id": SESSION},
            )
        assert request.headers["mcp-session-id"] == SESSION
        assert request.headers["mcp-protocol-version"] == (
            companion.MCP_PROTOCOL_VERSION
        )
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/list":
            if body["id"] == 2:
                assert body["params"] == {}
                return httpx.Response(200, json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {"tools": first_page, "nextCursor": "page-2"},
                })
            assert body["id"] == 3
            assert body["params"] == {"cursor": "page-2"}
            wire = {
                "jsonrpc": "2.0",
                "id": 3,
                "result": {"tools": second_page},
            }
            return httpx.Response(
                200,
                text="event: message\ndata: " + json.dumps(wire) + "\n\n",
                headers={"content-type": "text/event-stream"},
            )
        assert method == "tools/call"
        plan_index = body["id"] - 4
        expected_name, expected_arguments = read_plan[plan_index]
        assert body["params"] == {
            "name": expected_name,
            "arguments": expected_arguments,
        }
        return httpx.Response(
            200,
            json=tool_call_result(body["id"], expected_name),
        )

    monkeypatch.setattr(
        companion,
        "mcp_client",
        managed_client_factory(httpx.MockTransport(handler)),
    )
    receipt = await companion.mcp_preflight()
    assert receipt["deployment"] == "managed-datahub-cloud"
    assert receipt["sessionMode"] == "server-assigned"
    assert receipt["selectedToolSurface"] == list(companion.MCP_TOOLS)
    assert receipt["serverInfo"] == {"name": "DataHub MCP", "version": "1"}
    assert receipt["serverInfoSource"] == "server-reported"
    assert receipt["serverIdentity"]["reportingMode"] == (
        "server-reported-unpinned-managed-service"
    )
    assert receipt["serverIdentity"]["serverInfo"] == receipt["serverInfo"]
    assert receipt["serverInventory"]["count"] == 7
    assert receipt["serverInventory"]["matchesSelectedSurface"] is False
    assert receipt["serverInventory"]["additionalToolsAdvertised"] == [
        "add_tags",
    ]
    reads = receipt["officialMcpReadReceipts"]
    assert reads["sequence"] == list(companion.MCP_CANONICAL_READ_TOOLS)
    assert [item["tool"] for item in reads["receipts"]] == list(
        companion.MCP_CANONICAL_READ_TOOLS
    )
    assert all(item["status"] == "verified" for item in reads["receipts"])
    assert all(item["providerPayloadStored"] is False for item in reads["receipts"])
    search_receipt = next(
        item for item in reads["receipts"] if item["tool"] == "search"
    )
    assert search_receipt["canonicalDatasetResolved"] is True
    assert search_receipt["canonicalDatasetUrnDigest"] == companion.digest(
        companion.CANONICAL_DATASET_URN
    )
    query_receipt = next(
        item
        for item in reads["receipts"]
        if item["tool"] == "get_dataset_queries"
    )
    assert query_receipt["status"] == "verified"
    assert receipt["selectedMutationsEnabled"] is False
    encoded = json.dumps(receipt)
    assert TOKEN not in encoded
    assert TENANT not in encoded
    assert SESSION not in encoded
    assert PROVIDER_SECRET not in encoded
    assert "provider.internal" not in encoded
    methods = [
        json.loads(request.content).get("method")
        for request in calls
        if request.method == "POST"
    ]
    assert methods == [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "tools/list",
        *["tools/call"] * len(companion.MCP_CANONICAL_READ_TOOLS),
    ]
    invoked = [
        json.loads(request.content)["params"]["name"]
        for request in calls
        if request.method == "POST"
        and json.loads(request.content).get("method") == "tools/call"
    ]
    assert invoked == list(companion.MCP_CANONICAL_READ_TOOLS)
    assert not set(invoked) & companion.MUTATION_TOOLS


@pytest.mark.asyncio
async def test_managed_preflight_requires_exact_canonical_search_result(
    monkeypatch,
):
    configure_runtime(monkeypatch)
    inventory = [tool(name) for name in companion.MCP_TOOLS]
    monkeypatch.setattr(
        companion,
        "mcp_client",
        managed_client_factory(httpx.MockTransport(cloud_protocol_handler(
            inventory,
            empty_search=True,
        ))),
    )
    with pytest.raises(RuntimeError, match="did not resolve canonical dataset"):
        await companion.mcp_preflight()


@pytest.mark.parametrize(
    "server_info",
    [
        {"name": "DataHub\nMCP", "version": "1"},
        {"name": "DataHub MCP", "version": "v" * 129},
    ],
)
def test_initialize_rejects_unsafe_server_identity(server_info):
    initialized = initialize_result()["result"]
    initialized["serverInfo"] = server_info
    with pytest.raises(RuntimeError, match="initialize contract"):
        companion.validate_mcp_initialize(initialized)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutate",
    [
        "missing-required",
        "missing-annotations",
        "read-write",
        "destructive",
        "missing-destructive",
    ],
)
async def test_managed_preflight_fails_closed_on_required_tool_annotations(
    monkeypatch,
    mutate,
):
    configure_runtime(monkeypatch)
    inventory = [tool(name) for name in companion.MCP_TOOLS]
    if mutate == "missing-required":
        inventory = [item for item in inventory if item["name"] != "search"]
    else:
        target = next(item for item in inventory if item["name"] == "search")
        if mutate == "missing-annotations":
            target.pop("annotations")
        elif mutate == "read-write":
            target["annotations"]["readOnlyHint"] = False
        elif mutate == "destructive":
            target["annotations"]["destructiveHint"] = True
        else:
            target["annotations"].pop("destructiveHint")
    monkeypatch.setattr(
        companion,
        "mcp_client",
        managed_client_factory(httpx.MockTransport(cloud_protocol_handler(
            inventory,
        ))),
    )
    with pytest.raises(RuntimeError, match="tool"):
        await companion.mcp_preflight()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["large", "invalid-sse"])
async def test_managed_preflight_rejects_oversized_or_invalid_wire(
    monkeypatch,
    mode,
):
    configure_runtime(monkeypatch)
    inventory = [tool(name) for name in companion.MCP_TOOLS]
    monkeypatch.setattr(
        companion,
        "mcp_client",
        managed_client_factory(httpx.MockTransport(cloud_protocol_handler(
            inventory,
            tool_mode=mode,
        ))),
    )
    with pytest.raises(RuntimeError) as raised:
        await companion.mcp_preflight()
    assert TOKEN not in str(raised.value)
    assert TENANT not in str(raised.value)


@pytest.mark.asyncio
async def test_managed_preflight_rejects_redirect_without_auth_leak(
    monkeypatch,
):
    configure_runtime(monkeypatch)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            307,
            json={"error": PROVIDER_SECRET},
            headers={"location": "https://attacker.example/steal?token=secret"},
        )

    monkeypatch.setattr(
        companion,
        "mcp_client",
        managed_client_factory(httpx.MockTransport(handler)),
    )
    with pytest.raises(RuntimeError) as raised:
        await companion.mcp_preflight()
    assert len(calls) == 1
    assert calls[0].url.host == "judge.acryl.io"
    assert PROVIDER_SECRET not in str(raised.value)
    assert TOKEN not in str(raised.value)


@pytest.mark.asyncio
async def test_managed_preflight_rejects_changed_session_binding(monkeypatch):
    configure_runtime(monkeypatch)
    inventory = [tool(name) for name in companion.MCP_TOOLS]
    monkeypatch.setattr(
        companion,
        "mcp_client",
        managed_client_factory(httpx.MockTransport(cloud_protocol_handler(
            inventory,
            changed_session=True,
        ))),
    )
    with pytest.raises(RuntimeError, match="session binding"):
        await companion.mcp_preflight()


@pytest.mark.parametrize(
    "gms_url",
    [
        "http://judge.acryl.io",
        "https://example.com",
        "https://datahub.example.com",
        "https://localhost",
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://[::1]",
        "https://a.b.acryl.io",
        "https://-judge.acryl.io",
        "https://judge.acryl.io:9443",
        "https://user:password@judge.acryl.io",
        "https://judge.acryl.io/other",
        "https://judge.acryl.io/gms?next=https://attacker.example",
        "https://judge.acryl.io/gms#fragment",
    ],
)
def test_cloud_endpoint_rejects_non_tenant_or_ambiguous_gms(
    monkeypatch,
    gms_url,
):
    configure_runtime(monkeypatch)
    monkeypatch.setenv("DATAHUB_GMS_URL", gms_url)
    with pytest.raises(RuntimeError, match="endpoint policy"):
        companion.mcp_endpoint()


def test_cloud_endpoint_rejects_independent_mcp_override(monkeypatch):
    configure_runtime(monkeypatch)
    monkeypatch.setenv(
        "ARCHON_DATAHUB_MCP_URL",
        "https://judge.acryl.io/integrations/ai/mcp",
    )
    with pytest.raises(RuntimeError, match="must be derived"):
        companion.mcp_endpoint()


@pytest.mark.parametrize("token", ["", "line\nbreak", "x" * 8193])
def test_cloud_mcp_token_is_bounded_header_safe(monkeypatch, token):
    configure_runtime(monkeypatch)
    monkeypatch.setenv("DATAHUB_GMS_TOKEN", token)
    with pytest.raises(RuntimeError, match="credential policy") as raised:
        companion.cloud_mcp_token()
    if token:
        assert token not in str(raised.value)


def analytics_connections(extra_enabled: bool) -> list[dict]:
    return [
        {
            "name": "archon-datahub-mcp",
            "type": "datahub-mcp",
            "status": "connected",
            "disabled": False,
            "fields": [{
                "key": "url",
                "value": TENANT + companion.CLOUD_MCP_PATH,
            }],
            "tools": [
                *[
                    {"name": name, "enabled": True}
                    for name in companion.MCP_TOOLS
                ],
                {"name": "add_tags", "enabled": extra_enabled},
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


def test_cloud_analytics_selects_six_and_disables_extra_inventory(monkeypatch):
    configure_runtime(monkeypatch)
    monkeypatch.setenv(
        "ARCHON_DATAHUB_MCP_CONNECTION",
        "archon-datahub-mcp",
    )
    result = companion.validate_connections(
        analytics_connections(False),
        "archon-judge",
    )
    assert result["mcpToolSurfaceDigest"] == companion.digest(
        list(companion.MCP_TOOLS)
    )
    with pytest.raises(RuntimeError, match="tool surface"):
        companion.validate_connections(
            analytics_connections(True),
            "archon-judge",
        )


@pytest.mark.asyncio
async def test_core_preflight_runs_same_substantive_read_sequence(monkeypatch):
    configure_runtime(monkeypatch, "core")
    provenance = {
        "digest": "sha256:" + "b" * 64,
        "package": companion.MCP_PACKAGE,
        "version": companion.MCP_VERSION,
        "sourceCommit": companion.MCP_SOURCE_COMMIT,
        "toolSurfaceDigest": companion.digest(list(companion.MCP_TOOLS)),
    }
    monkeypatch.setattr(companion, "load_mcp_provenance", lambda: provenance)
    calls: list[httpx.Request] = []
    inventory = [tool(name) for name in companion.MCP_TOOLS]
    read_plan = list(companion.canonical_mcp_read_plan())

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.url.host == "archon-read-mcp"
        assert "authorization" not in request.headers
        if request.method == "GET":
            assert request.url.path == "/health"
            return httpx.Response(200, json={"status": "ok"})
        assert request.url.path == "/mcp"
        if request.method == "DELETE":
            assert request.headers["mcp-session-id"] == SESSION
            return httpx.Response(204)
        body = json.loads(request.content)
        method = body["method"]
        if method == "initialize":
            return httpx.Response(
                200,
                json=initialize_result(),
                headers={"Mcp-Session-Id": SESSION},
            )
        assert request.headers["mcp-session-id"] == SESSION
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/list":
            return httpx.Response(200, json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"tools": inventory},
            })
        assert method == "tools/call"
        name, arguments = read_plan[body["id"] - 3]
        assert body["params"] == {"name": name, "arguments": arguments}
        return httpx.Response(200, json=tool_call_result(body["id"], name))

    monkeypatch.setattr(
        companion,
        "mcp_client",
        core_client_factory(httpx.MockTransport(handler)),
    )
    receipt = await companion.mcp_preflight()
    assert receipt["schemaVersion"] == "archon.datahub-mcp-preflight/v2"
    assert receipt["package"] == companion.MCP_PACKAGE
    assert receipt["serverIdentity"]["reportingMode"] == (
        "server-reported-cross-bound-to-pinned-artifact"
    )
    assert receipt["serverIdentity"]["serverInfo"] == {
        "name": "DataHub MCP",
        "version": "1",
    }
    assert receipt["serverIdentity"]["pinnedArtifact"] == {
        "package": companion.MCP_PACKAGE,
        "version": companion.MCP_VERSION,
        "sourceCommit": companion.MCP_SOURCE_COMMIT,
        "provenanceDigest": provenance["digest"],
    }
    assert receipt["serverInventory"]["matchesSelectedSurface"] is True
    assert receipt["officialMcpReadReceipts"]["sequence"] == list(
        companion.MCP_CANONICAL_READ_TOOLS
    )
    invoked = [
        json.loads(request.content)["params"]["name"]
        for request in calls
        if request.method == "POST"
        and json.loads(request.content).get("method") == "tools/call"
    ]
    assert invoked == list(companion.MCP_CANONICAL_READ_TOOLS)
    assert PROVIDER_SECRET not in json.dumps(receipt)
