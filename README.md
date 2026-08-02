# Archon DataHub Companion

This private runtime makes all four DataHub challenge pillars substantive in one governed journey:

- the official **DataHub MCP Server** supplies live, read-only metadata evidence;
- **Agent Context Kit** supplies a separate bounded context receipt;
- pinned official **DataHub Skills** ground analysis without adding write authority;
- the official **Analytics Agent** must emit a matched MCP `TOOL_CALL` / `TOOL_RESULT` trace before an answer is accepted.

The browser never supplies an endpoint, credential, profile, or tool policy. A server-resolved immutable runtime binding selects `cloud` or `core` for the whole operation.

## Dual DataHub runtime

| Property | Cloud trial / paid | Reproducible Core |
| --- | --- | --- |
| DataHub control plane | Managed DataHub Cloud tenant | Ephemeral self-hosted DataHub Core |
| Official MCP | Managed Streamable HTTP endpoint | Pinned `mcp-server-datahub==0.6.0` image |
| Identity evidence | Server-reported, explicitly unpinned managed-service identity | Server-reported identity cross-bound to pinned package, source commit, and wheel provenance |
| Advertised inventory | May contain additional managed tools | Must be exactly the selected six |
| Selected inventory | Exactly six read tools; all extras disabled | Exactly six read tools |
| Lifecycle | Existing trial or paid tenant | On-demand runtime with automated teardown |
| Write authority | None in companion/MCP/Analytics | None in companion/MCP/Analytics |

The selected read surface is exactly:

```text
get_dataset_queries
get_entities
get_lineage
get_lineage_paths_between
list_schema_fields
search
```

Every selected tool must advertise `readOnlyHint=true` and `destructiveHint=false`. Discovery fails closed if a selected tool or annotation is missing. Cloud may advertise extra tools, but Analytics must expose all extras as disabled. Core rejects any extra server tool.

## Managed Cloud MCP contract

For `profileId=cloud`, the companion derives the only accepted MCP endpoint from the server-owned GMS tenant:

```text
DATAHUB_GMS_URL=https://<tenant>.acryl.io[/gms]
MCP endpoint=https://<tenant>.acryl.io/integrations/ai/mcp
Authorization: Bearer <DATAHUB_GMS_TOKEN>
```

`<tenant>` is exactly one DNS label. HTTPS port 443 is mandatory. Userinfo, redirects, proxies, alternate ports, IP literals, localhost/private hosts, query strings, fragments, arbitrary paths, and an independent `ARCHON_DATAHUB_MCP_URL` are rejected. The token is a bounded, header-safe, server-owned DataHub service-account token with Reader-level access; it is never placed in a URL or receipt.

The adapter performs the MCP `2025-06-18` Streamable HTTP sequence:

1. `initialize`, retaining only a bounded server-reported `{name, version}` projection and digest.
2. `notifications/initialized`, echoing the server session binding when supplied.
3. Paginated `tools/list`, enforcing the selected read policy.
4. Substantive `tools/call` requests against the canonical demo scope.
5. Session `DELETE` when the server issued a session identifier.

The canonical proof calls are:

```text
search("/q archon_demo+customers", entity_type=dataset)
get_entities(canonical dataset URN)
list_schema_fields(canonical dataset URN, keyword=customer_email)
get_lineage(canonical dataset URN, downstream, max_hops=2)
get_dataset_queries(canonical dataset URN)
```

The `search` response must structurally contain the exact canonical URN:

```text
urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)
```

A substring or merely successful response is insufficient. A successful empty `get_dataset_queries` result is valid evidence. Receipts retain arguments/result digests, bounded response shape, and byte counts only; provider payloads, raw endpoints, sessions, credentials, and provider errors are not retained.

Reader mutation denial is demonstrated by a separate live bootstrap check and is not performed during health/readiness. Health never invokes a mutation.

## Reproducible Core contract

Core runs the pinned official MCP artifact built and verified by CI. Its internal network contract is exact:

```text
DATAHUB_GMS_URL=http://archon-gms:8080
ARCHON_DATAHUB_MCP_URL=http://archon-read-mcp:8000/mcp
ARCHON_ANALYTICS_AGENT_URL=http://archon-analytics:8100
```

The read bridge may reach only the read-only GMS alias. The writer alias `archon-writer-gms`, host networking, host gateways, loopback shortcuts, arbitrary RFC1918 addresses, and direct dependency endpoints are rejected. Core live initialize identity is evidence, not an asserted package identity; the receipt cross-binds it to pinned package/version/source-commit provenance.

The CI-built OCI candidate contains isolated companion, Analytics Agent, and MCP environments. Mutation, user, data-quality, document, and semantic-search tools are disabled so the Core live inventory is the exact six-tool surface. The image contains no mutation gateway and no write credential.

## Distinct evidence chains

Agent Context Kit and official MCP receipts remain separate. Every pinned `SKILL.md` is bound to a reviewed execution plan (`phase`, exact `requiredCalls`, and mode) by its locked artifact digest. Grounding fails closed unless every required ACK and official MCP call has a verified digest. Per-skill v2 execution receipts mark search, lineage, quality, audit, and `using-datahub` as `executed`; enrich is `previewed` and never performs a write. The prompt receives these execution fields, not the untrusted Markdown. ACK and MCP digests remain distinct and are never relabeled.

Analytics readiness separately proves process health, the selected MCP connection, the exact enabled tool surface, and live model connectivity. A completed answer must contain ordered, cardinality-matched selected-tool pairs; failed, duplicate-result, unmatched, and out-of-order traces are rejected. Pinned Analytics v0.4.0 has no call ID in these payloads, so matching is intentionally sequence-based. Trace receipts retain event digests only (`tracePayloadStored=false`, `rawProviderPayloadStored=false`) and link to the official MCP preflight receipt.

Unknown or missing evidence remains unknown. Upstream mutation tools are disabled. Every governed write remains owned by the isolated remediation worker and requires fresh digest-bound DataSteward approval.

## Server-owned configuration

- Runtime identity: `ARCHON_RUNTIME_PROFILE_ID`, `ARCHON_RUNTIME_GENERATION`, `ARCHON_RUNTIME_CAPABILITY_DIGEST`.
- Canonical demo: `ARCHON_DEMO_QUERY`, `ARCHON_ANALYTICS_QUESTION`, `ARCHON_ANALYTICS_ENGINE`.
- Connections: `DATAHUB_GMS_URL`, `DATAHUB_GMS_TOKEN`, `ARCHON_DATAHUB_MCP_CONNECTION`, `ARCHON_ANALYTICS_AGENT_URL`. Analytics is profile-exact: Cloud uses only `http://127.0.0.1:8100` inside its Lambda container; Core uses only `http://archon-analytics:8100`.
- Core only: `ARCHON_DATAHUB_MCP_URL`.
- Model proof: `ARCHON_ANALYTICS_LLM_PROVIDER=bedrock`, `ARCHON_ANALYTICS_LLM_MODEL`, `ARCHON_ANALYTICS_AWS_REGION`.
- Continuation: generation-scoped `ARCHON_RUN_HANDLE_FERNET_KEY`.
- Provenance: `ARCHON_AGENT_STACK_LOCK`, `ARCHON_DATAHUB_MCP_LOCK`, `ARCHON_DATAHUB_SKILLS_DIR`, `ARCHON_CUSTOM_SKILLS_DIR`.

Never mount a DataHub write token into the companion, Analytics Agent, or read-only MCP process.

## Cloud worker reuse contract

A `profileId=cloud` stream worker can reuse the companion in-process without accepting request-supplied configuration. Its Analytics Agent child process is reachable only on exact loopback `http://127.0.0.1:8100`; redirects and environment proxies remain disabled. For an ANALYZE job it constructs `AnalyzeRequest`, runs `exact_public_input`, and invokes the same sequence as `/v2/analyze`:

```text
collect_ack_context
load_skill_receipt
analytics_preflight
ground_skills
run_analytics
```

Blocking SDK/context functions run in worker threads; preflight and Analytics functions are async. The worker creates one job-scoped `_ModelProbeState` and passes it as `analytics_preflight(..., model_probe_state=state)`, so warm Lambda reuse does not mutate the companion default cache. The worker preserves the `archon.datahub-agent-stack-result/v2` projection and digest links. IMPROVE_CONTEXT reuses `resolve_run_handle`, `analytics_preflight`, `analytics_turn`, and `context_quality` with the same generation/profile binding. There is no Core fallback for a Cloud-bound job.

Reuse the managed MCP adapter, model/health, Analytics boundary, runtime/skills, and API contract tests under `tests/` for the worker.

## CI-only verification

The frozen lock, OCI build, tests, SBOM, vulnerability audit, secret scanning, provenance, and deployment verification run in GitHub Actions. Do not build this service on a contributor workstation and do not leave local build artifacts.

`GET /livez` proves process liveness only. `GET /healthz` returns 200 only after the active profile DataHub, MCP, Agent Context Kit, Skills, Analytics process, and live model evidence all verify; otherwise it returns 503 and the runtime must not be advertised.
