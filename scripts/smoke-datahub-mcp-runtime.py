#!/usr/bin/env python3
"""Credentialless MCP stdio startup proof.

This harness is intentionally executed only by GitHub Actions against the
wheel-only virtual environment materialized by the repository pipeline.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import http.server
import importlib.metadata
import json
import os
import pathlib
import sys
import tempfile
import threading
import urllib.parse
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


EXPECTED_TOOLS = sorted(
    {
        "get_dataset_queries",
        "get_entities",
        "get_lineage",
        "get_lineage_paths_between",
        "list_schema_fields",
        "search",
    }
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=45)
    return parser.parse_args()


def server_version(result: Any) -> str:
    info = getattr(result, "serverInfo", None)
    if info is None:
        info = getattr(result, "server_info", None)
    value = getattr(info, "version", None)
    require(isinstance(value, str) and value, "MCP server version is missing")
    return value


def config_handler(state: dict[str, Any]) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def respond(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def record(self) -> str:
            path = urllib.parse.urlsplit(self.path).path
            state["authorizationHeaders"] += int("Authorization" in self.headers)
            state["requests"].append({"method": self.command, "path": path})
            return path

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            path = self.record()
            if path != "/config":
                state["unexpectedHttpRequests"] += 1
                self.respond(404, {"error": "not-found"})
                return
            state["configRequests"] += 1
            self.respond(
                200,
                {
                    "datahub": {
                        "serverEnv": "core",
                        "serverType": "ci-loopback-stub",
                    },
                    "noCode": "true",
                    "telemetry": {"enabledCli": False},
                    "versions": {
                        "acryldata/datahub": {
                            "commit": "0000000000000000000000000000000000000000",
                            "version": "1.6.0",
                        }
                    },
                },
            )

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            self.record()
            state["unexpectedHttpRequests"] += 1
            self.respond(405, {"error": "method-not-allowed"})

    return Handler


async def exercise(
    server: pathlib.Path,
    child_env: dict[str, str],
    stderr_handle: Any,
) -> tuple[str, list[str], bool]:
    parameters = StdioServerParameters(
        command=str(server),
        args=["--transport", "stdio"],
        env=child_env,
    )
    async with stdio_client(parameters, errlog=stderr_handle) as streams:
        read_stream, write_stream = streams
        async with ClientSession(read_stream, write_stream) as session:
            initialized = await session.initialize()
            await session.send_ping()
            tools = await session.list_tools()
            names = sorted(tool.name for tool in tools.tools)
            read_only_hints = []
            for tool in tools.tools:
                annotations = getattr(tool, "annotations", None)
                hint = getattr(annotations, "readOnlyHint", None)
                if hint is None:
                    hint = getattr(annotations, "read_only_hint", None)
                read_only_hints.append(hint is True)
            return server_version(initialized), names, all(read_only_hints)


def main() -> int:
    args = parse_args()
    require(sys.platform.startswith("linux"), "runtime smoke requires Linux")
    require(1 <= args.timeout_seconds <= 60, "invalid smoke timeout")

    server = pathlib.Path(args.server)
    output = pathlib.Path(args.output)
    require(server.is_absolute(), "server path must be absolute")
    require(server.is_file() and not server.is_symlink(), "server must be one regular file")
    require(output.is_absolute(), "output path must be absolute")
    require(not output.exists(), "runtime smoke output already exists")

    package_version = importlib.metadata.version("mcp-server-datahub")
    fastmcp_version = importlib.metadata.version("fastmcp")
    require(package_version == "0.6.0", "installed MCP package version changed")

    state: dict[str, Any] = {
        "authorizationHeaders": 0,
        "configRequests": 0,
        "requests": [],
        "unexpectedHttpRequests": 0,
    }
    stub = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0),
        config_handler(state),
    )
    stub.daemon_threads = True
    stub_thread = threading.Thread(
        target=stub.serve_forever,
        name="archon-datahub-config-stub",
        daemon=True,
    )
    stub_thread.start()
    try:
        stub_host, stub_port = stub.server_address
        child_env = {
            "DATAHUB_GMS_URL": f"http://{stub_host}:{stub_port}",
            "DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED": "true",
            "DATAHUB_SKIP_CONFIG": "true",
            "DATAHUB_TELEMETRY_ENABLED": "false",
            "DATA_QUALITY_TOOLS_ENABLED": "false",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_PROXY": "127.0.0.1,localhost",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONNOUSERSITE": "1",
            "PYTHONUNBUFFERED": "1",
            "SAVE_DOCUMENT_TOOL_ENABLED": "false",
            "SEMANTIC_SEARCH_ENABLED": "false",
            "TOOLS_IS_MUTATION_ENABLED": "false",
            "TOOLS_IS_USER_ENABLED": "false",
        }
        require("DATAHUB_GMS_TOKEN" not in child_env, "credential leaked into smoke")
        with tempfile.TemporaryFile(mode="w+b") as stderr_handle:
            observed_server_version, tools, read_only_hints = asyncio.run(
                asyncio.wait_for(
                    exercise(server, child_env, stderr_handle),
                    timeout=args.timeout_seconds,
                )
            )
            stderr_handle.seek(0)
            stderr_bytes = stderr_handle.read()
    finally:
        stub.shutdown()
        stub.server_close()
        stub_thread.join(timeout=5)

    require(
        observed_server_version == fastmcp_version,
        "MCP serverInfo version differs from the installed FastMCP runtime",
    )
    require(tools == EXPECTED_TOOLS, "MCP read-only tool surface changed")
    require(read_only_hints, "MCP tool lost its read-only annotation")
    require(state["configRequests"] == 1, "unexpected DataHub config request count")
    require(state["unexpectedHttpRequests"] == 0, "unexpected DataHub HTTP request")
    require(state["authorizationHeaders"] == 0, "credential header reached the stub")
    require(b"Traceback (most recent call last)" not in stderr_bytes, "server traceback")
    require(b"ImportError" not in stderr_bytes, "server import failed")
    require(b"ModuleNotFoundError" not in stderr_bytes, "server module missing")

    receipt = {
        "credentialsUsed": False,
        "fastMcpVersion": fastmcp_version,
        "initialized": True,
        "loopbackConfigRequests": state["configRequests"],
        "networkToolCalls": 0,
        "packageVersion": package_version,
        "pinged": True,
        "protocol": "mcp-stdio",
        "readOnlyHints": True,
        "schemaVersion": "archon.datahub-mcp-runtime-smoke/v1",
        "serverInfoVersion": observed_server_version,
        "stderrBytes": len(stderr_bytes),
        "stderrSha256": hashlib.sha256(stderr_bytes).hexdigest(),
        "tools": tools,
        "unexpectedHttpRequests": state["unexpectedHttpRequests"],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
