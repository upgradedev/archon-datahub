# Archon DataHub Companion

This private runtime makes the Agent Context Kit and the official Analytics Agent
substantive parts of the same governed Archon journey.

- The official DataHub MCP Server is pinned to source and wheel provenance, runs with
  an exact six-tool read-only surface, and contributes live health evidence.
- Agent Context Kit tools are loaded read-only and produce bounded provenance receipts.
- Official DataHub Skills are materialized from the commit pinned in
  `.github/locks/datahub-agent-stack.json`.
- Analytics Agent answers the allowlisted synthetic judge question and returns SQL,
  results, chart, tool trace, and context-quality evidence; readiness separately proves
  process health and live Bedrock model connectivity.
- Upstream mutation tools are disabled. Every write remains owned by Archon's isolated
  remediation worker and requires a fresh digest-bound DataSteward approval.
- The runtime accepts only a server-resolved `cloud` or `core` binding. It never accepts
  an endpoint or credential from the browser and never changes profile mid-execution.

The frozen `uv.lock`, SBOM, vulnerability audit, imports, API contracts, and source
provenance are generated and verified only in GitHub Actions. Do not build this service
on a contributor workstation.

## Immutable runtime contract

The CI-built OCI candidate is the only deployable form. Its default process is:

```text
/opt/archon/companion/.venv/bin/python -m uvicorn archon_companion:app --host 0.0.0.0 --port 8080 --no-access-log
```

The image has no entrypoint and therefore supports explicit immutable process
commands while retaining the full companion command above as its default `CMD`.
It contains two isolated virtual environments because their reviewed DataHub SDK
closures differ:

- Analytics Agent:
  `/opt/archon/companion/.venv/bin/python -m uvicorn analytics_agent.main:app --host 0.0.0.0 --port 8100`.
- Official read-only MCP:
  `/opt/archon/mcp/.venv/bin/mcp-server-datahub --transport http`, with mutations,
  user tools, data-quality extras, document tools, and semantic search disabled so its
  live protocol inventory is exactly the six tools pinned by the companion. The
  image bakes only the non-secret fail-closed flags
  `TOOLS_IS_MUTATION_ENABLED=false`, `TOOLS_IS_USER_ENABLED=false`,
  `DATA_QUALITY_TOOLS_ENABLED=false`,
  `DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED=true`, and
  `SEMANTIC_SEARCH_ENABLED=false`. FastMCP is also pinned to port 8000 with
  strict input validation, masked tool errors, disabled update checks, and no rich
  payload logging.

The OCI build runs the existing wheel-only MCP materializer, verifies PyPI provenance
and the sealed resolved lock, and exercises initialize, ping, annotations, and exact
tool inventory without DataHub credentials or network tool calls. The image contains
no governed mutation gateway and no write credential. Core owns that separately as an
explicitly branded Archon service, separate venv/unit, credential, listener, and
approval-bound channel.

`GET /livez` is process liveness only; the orchestrator must never interpret it as
dependency readiness. The companion publishes
readiness only when `GET /healthz` returns 200. Its evidence distinguishes MCP process/provenance,
Analytics process health, and live Bedrock model connectivity; 503 means the runtime
must not be advertised.

Companion configuration is entirely server-owned:

- Identity: `ARCHON_RUNTIME_PROFILE_ID`, `ARCHON_RUNTIME_GENERATION`,
  `ARCHON_RUNTIME_CAPABILITY_DIGEST`.
- Demo scope: `ARCHON_DEMO_QUERY`, `ARCHON_ANALYTICS_QUESTION`,
  `ARCHON_ANALYTICS_ENGINE`. The canonical seeded scope is dataset/query
  `urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)`,
  question “Which customer segment generated the highest net revenue in Q2 2026,
  and is customers.customer_email governed as PII?”, governed column
  `customer_email`, and downstream dataset
  `archon_demo.customer_segment_revenue`.
- Private peers: `ARCHON_ANALYTICS_AGENT_URL`,
  `ARCHON_DATAHUB_MCP_URL`, `ARCHON_DATAHUB_MCP_CONNECTION`, and
  `DATAHUB_GMS_URL`.
- Bedrock proof: `ARCHON_ANALYTICS_LLM_PROVIDER=bedrock`,
  `ARCHON_ANALYTICS_LLM_MODEL`, and `ARCHON_ANALYTICS_AWS_REGION`.
  The non-mutating, one-token connectivity probe is response-size/time bounded,
  retains no provider message, uses the task/instance role (never static AWS keys),
  and reports an explicit generation-bound cache age.
- Secrets: generation-scoped `ARCHON_RUN_HANDLE_FERNET_KEY` and read-only
  `DATAHUB_GMS_TOKEN`.
- Provenance mounts: `ARCHON_AGENT_STACK_LOCK`,
  `ARCHON_DATAHUB_MCP_LOCK`, `ARCHON_DATAHUB_SKILLS_DIR`, and
  `ARCHON_CUSTOM_SKILLS_DIR`.

Never mount a DataHub write token into the companion, Analytics, or read-only MCP
containers. Expose only companion port 8080 to the private control plane; keep
Analytics port 8100 and MCP port 8000 on loopback or service-to-service networking.
The separately isolated `archon-remediation-worker` is the only write authority;
its governed-write adapter uses the separately allowlisted MCP listener on port 8001
and a distinct mutation partition, and must bind the plan, approval, runtime, and
before/after digests. Run as UID/GID 65532, with a read-only root filesystem,
all Linux capabilities dropped, `no-new-privileges`, and bounded `noexec,nosuid`
tmpfs storage only where Analytics Agent needs transient state.

Both profiles use these exact bytes. Core starts the three supervised read-only
processes from the ephemeral AMI and reaches GMS only at the exact loopback endpoint
`http://127.0.0.1:18080` (or `localhost` on the same port). HTTP is rejected for
every other profile, host, port, credential form, path, query, or fragment. Cloud uses
a server-owned HTTPS GMS endpoint on port 443 or 9443. Neither profile becomes
selectable until the companion readiness proof succeeds. The OSS story makes no claim
that PII tags automatically propagate downstream; the agent reports only lineage and
evidence actually returned by the pinned read-only tools.
