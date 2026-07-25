# `get_aspect_history` for the official DataHub MCP server

This folder stages one focused, upstream-ready contribution for
[`acryldata/mcp-server-datahub`](https://github.com/acryldata/mcp-server-datahub):
a read-only MCP tool that retrieves the current value and a bounded page of retained
history for one governance aspect, including narrowly projected ingestion and audit
provenance.

It is the primary open-source bonus candidate in this repository. It does not duplicate
the broader `datahub-audit` Skill draft: this contribution adds a missing server
capability that such an audit can consume.

## Exact upstream target

- Repository: [`acryldata/mcp-server-datahub`](https://github.com/acryldata/mcp-server-datahub)
- Branch inspected: `main`
- Exact base commit:
  [`9a6946daa7d30eb481c82dd8ee5e15ae6526a3c9`](https://github.com/acryldata/mcp-server-datahub/commit/9a6946daa7d30eb481c82dd8ee5e15ae6526a3c9)
- Base commit timestamp: `2026-05-15T17:48:28Z`
- License: Apache-2.0

Read-only GitHub inspection was repeated on `2026-07-25`. Searches of current code,
open and closed pull requests, and open issues for `get_aspect_history`, `aspect history`,
and `versioned aspect` found no matching implementation or overlapping proposal. This is
evidence of uniqueness at the inspection time, not a promise that upstream cannot change
after this pinned snapshot.

## Staged artifacts

| Staged artifact | Intended upstream destination |
|---|---|
| `upstream/src/mcp_server_datahub/tools/aspect_history.py` | `src/mcp_server_datahub/tools/aspect_history.py` |
| `upstream/tests/test_mcp/test_get_aspect_history.py` | `tests/test_mcp/test_get_aspect_history.py` |
| `integration.patch` | Registers and exports the tool in `tools/__init__.py` and `mcp_server.py` |
| `manifest.json` | Machine-readable target, copy map, inspection evidence, and honest validation status |

The source and test are exact files rather than illustrative snippets. Against the pinned
commit, a maintainer can copy the two files to their destinations and apply
`integration.patch`. The top of upstream `mcp_server.py` says that file is synchronized
with a second repository; upstream maintainers must mirror the small import/registration
change there as part of their normal sync process.

## Tool contract

```text
get_aspect_history(
  urn,
  aspect_name,
  start_version=1,
  limit=10,
  include_current=true
)
```

DataHub reserves version `0` for the current aspect. Positive versions are retained
history ordered oldest to newest, as documented by the official
`DataHubGraph.get_aspect` SDK contract. The tool therefore returns current separately and
paginates only positive history:

```json
{
  "urn": "urn:li:dataset:(...)",
  "aspectName": "ownership",
  "current": {
    "version": 0,
    "value": {},
    "systemMetadata": {
      "runId": "...",
      "pipelineName": "...",
      "lastObserved": 1700000000000
    },
    "auditStamp": {
      "time": 1700000000000,
      "actor": "urn:li:corpuser:datahub"
    }
  },
  "history": [
    {
      "version": 1,
      "value": {}
    }
  ],
  "page": {
    "startVersion": 1,
    "requestedLimit": 10,
    "returned": 1,
    "hasMore": false,
    "nextStartVersion": null,
    "truncatedByResponseBudget": false
  }
}
```

There is no invented total count. One bounded look-ahead request determines whether
`nextStartVersion` is real. A missing version is represented by the official endpoint's
empty batch response. HTTP, authorization, JSON-shape, and entity-mismatch failures remain
errors and are never reclassified as “end of history.”

## Official API basis

The implementation uses DataHub's authorized OpenAPI v3 batch-get endpoint:

```text
POST /openapi/v3/entity/{entityName}/batchGet?systemMetadata=true
```

Each request contains one validated URN and one allowlisted aspect with:

```json
{
  "headers": {
    "If-Version-Match": "1"
  }
}
```

This is not a guessed private wire format:

- The official
  [`EntityController`](https://github.com/datahub-project/datahub/blob/c4f58917bd9f9fead40c63412fcc6715e267317d/metadata-service/openapi-servlet/src/main/java/io/datahubproject/openapi/v3/controller/EntityController.java)
  parses `If-Version-Match` as the requested aspect version and supports
  `systemMetadata=true`.
- The official
  [`GenericEntityV3`](https://github.com/datahub-project/datahub/blob/c4f58917bd9f9fead40c63412fcc6715e267317d/metadata-service/openapi-servlet/models/src/main/java/io/datahubproject/openapi/v3/models/GenericEntityV3.java)
  response contains `value`, `systemMetadata`, and `auditStamp`.
- The existing minimum dependency, `acryl-datahub>=1.3.1.7`, already ships
  `DataHubGraph.get_entities_v3` using the same batch-get route and authenticated graph
  session.
- Version-header support landed before the DataHub OSS `v0.14.0` release. The patch does
  not guess a DataHub Cloud version gate: an unavailable endpoint fails explicitly with a
  capability error instead of hiding the tool incorrectly or returning provenance-free
  data.

## Security and hard bounds

The tool is designed for autonomous agent use but treats catalog content as untrusted:

| Control | Enforced behavior |
|---|---|
| Read-only declaration | `@read_only` becomes MCP `readOnlyHint=true` through the upstream registrar |
| Network destination | Always the already configured DataHub GMS origin; callers cannot supply a URL |
| Path construction | URN is parsed by the official SDK; entity type must match a strict alphanumeric pattern |
| Aspect exposure | Static governance allowlist; arbitrary raw aspects and timeseries aspects are inaccessible |
| Request fan-out | `limit` is `1..20`; at most 1 current + 21 historical reads, plus the existing entity check |
| Cursor bound | `start_version` is `1..1,000,000`; booleans are rejected as ambiguous integers |
| Input size | URN is capped at 2,048 characters |
| Single value output | Values over 12,000 serialized characters become an explicitly marked preview |
| Whole response output | Aspect entries are capped at 60,000 serialized characters; pagination remains resumable |
| Provenance output | Strings are capped at 512 characters; arbitrary `systemMetadata.properties` and audit messages are not exposed |
| Authorization | Existing authenticated DataHub session and server-side entity READ authorization are preserved |
| Failure mode | 403/5xx, missing capability, malformed JSON shape, and mismatched URNs fail closed |
| Prompt-injection boundary | Response explicitly labels aspect values as untrusted catalog data, not instructions |

The governance allowlist is:

`datasetProperties`, `deprecation`, `domains`, `editableDatasetProperties`,
`editableSchemaMetadata`, `globalTags`, `glossaryTerms`, `ownership`,
`schemaMetadata`, `status`, `structuredProperties`, and `upstreamLineage`.

Expanding it should be a deliberate maintainer security decision because some raw DataHub
aspects can contain operational configuration that the current `get_entities` tool does
not normally expose.

## Provenance contract

Only fields useful for explaining where and when a value came from are projected:

- `systemMetadata`: `lastObserved`, `runId`, `lastRunId`, `pipelineName`,
  `registryName`, `registryVersion`, `version`, `schemaVersion`, and sanitized
  `aspectCreated` / `aspectModified`;
- `auditStamp`: `time`, `actor`, and `impersonator`;
- request provenance: entity type, endpoint family, version selector, and exact version
  semantics.

Free-form system-metadata properties and audit messages are intentionally omitted. This
keeps provenance useful for contradiction and governance audits without widening the
agent-visible data surface unnecessarily.

## Tests supplied for upstream CI

The exact test file covers:

- read-only annotation;
- current/history ordering and pagination;
- exact `If-Version-Match` requests;
- provenance whitelisting;
- governance allowlist and URN/path constraints;
- request, cursor, per-value, and total-response bounds;
- resumable response-budget truncation;
- distinct entity-not-found behavior;
- authorization/HTTP propagation;
- explicit unsupported-endpoint error;
- fail-closed malformed and mismatched success responses.

Required upstream CI commands are recorded in `manifest.json`. At minimum:

```text
ruff check src/mcp_server_datahub/tools/aspect_history.py tests/test_mcp/test_get_aspect_history.py
pytest tests/test_mcp/test_get_aspect_history.py
pytest tests/test_mcp/test_read_only.py
```

The upstream repository's type checks and full suite should also run. Security validation
belongs in that CI/CD pipeline; this contribution does not depend on Codex Security.

## Honest status

**Staged, not submitted.** No pull request was opened, the patch was not applied to
upstream, and no local build, test suite, or security scan was run. Those facts are also
machine-readable in `manifest.json`. The artifacts are prepared for review and CI
validation against the pinned commit; they are not represented as merged or as
upstream-CI-passing evidence.
