# Live DataHub proof

The `Live DataHub proof` workflow is a credentialed, read-only proof gate. It is not a
connectivity check and it does not accept workstation evidence.

## Required dispatch inputs

- `release_sha`: the full lowercase SHA that is currently deployed.
- `deployment_run_id`: a successful `Deploy immutable AWS release` run for that SHA.
- `query`: a trimmed 1–256 character dataset query. Control characters and wildcard
  operators are rejected.

The workflow runs only from the current `master` head. The dispatch SHA and release SHA
must be identical. Before credentials are used, the workflow requires the latest
same-repository `push` runs of CI, CodeQL, and Workflow security for that exact SHA to be
successful and seals their canonical receipt. It downloads the exact production deployment
evidence artifact, verifies its GitHub artifact digest and inner evidence, and requires the
deployed query digest to match the dispatch query. Immediately before the DataHub secrets
enter a step, it revalidates the current ref plus that exact receipt. After the credentialed
proof finishes, it runs the same whole-snapshot verifier again with the original receipt
digest, rejects any branch or latest-run change, and proves that the enriched live-proof
receipt is semantically identical to the exact enforced receipt. After constructing the
evidence bundle, it performs one final same-digest verification and byte-compares the current
exact receipt with the attestation subject immediately before signing.

The protected `datahub-demo` environment supplies a read-only `DATAHUB_GMS_URL` and
`DATAHUB_GMS_TOKEN`. The proof deliberately starts the hash-locked official MCP server
over stdio; it does not fall back to an unverified hosted or `uvx` transport.

## Immutable MCP runtime

The proof does not execute `uvx`. The repository-owned
`.github/locks/datahub-mcp-v0.6.0.json` contract selects the signed upstream v0.6.0 commit,
tree, `pyproject.toml`, and `uv.lock` by Git object IDs, SHA-256, and byte size.
`scripts/materialize-datahub-mcp-lock.sh` fetches only that commit, verifies every binding,
and retains those byte-exact upstream documents as provenance. The authenticated upstream
lock is not the runtime lock: its historical wheel-less dependency and related hashes stay
in the contract only to explain the upstream graph.

CI derives the runtime lock with `uv==0.11.31`, the PyPI registry, highest-version
resolution, a full upgrade, and the fixed `2026-07-23T03:00:00Z` upload cutoff. The
contract applies both `acryl-datahub==1.6.0.15` and `setuptools==81.0.0`. These pins
prevent resolver backtracking while honoring DataHub's required `setuptools<82`
compatibility boundary. Both resolved nodes must match the contract's exact official
wheel URL, SHA-256, and byte size. Before resolution, the already verified project
metadata receives a canonical evidence-recorded overlay that renames the virtual root to
`archon-datahub-mcp-runtime`, makes its version static, adds
`mcp-server-datahub==0.6.0` as an exact registry dependency, sets
`tool.uv.package = false`, and records both constraints. This prevents the upstream
setuptools backend from executing while ensuring `uv audit` includes the official MCP
package instead of excluding it as the local project root. Resolution and sync use
`--no-build` and `--no-cache`. Every registry node, including the MCP package, must come
from the exact PyPI registry and contain hash- and size-bound
`files.pythonhosted.org` wheels. A wheel-less, path, Git, URL, or alternate-registry node
fails the gate.

Setuptools 81 is reported for CVE-2026-59890 (GHSA-h35f-9h28-mq5c /
PYSEC-2026-3447), whose affected path creates source distributions on macOS APFS/HFS+.
Archon does not suppress or ignore that result. CI retains the raw `uv audit` SARIF and
applies a committed, hash-bound OpenVEX v0.2 statement scoped to the Archon MCP runtime
and its exact setuptools wheel. The exception is valid for at most 30 days and only for
Linux, hash-bound wheel installation, denied source builds, forbidden source-distribution
creation. These are the complete CVE-relevant applicability conditions: the affected
macOS source-distribution path is independent of DataHub authentication and cannot execute
in this Linux wheel-only runtime. The separate uncredentialed loopback smoke proves
least-privilege startup and the exact read-only MCP tool surface. The gate
requires the two expected scanner records and their precise aliases, package, version,
fix version, fingerprint, and scanner version. An expired or unused VEX statement,
malformed result, different version, or any additional finding fails closed. Only the
derived actionable SARIF is uploaded to code scanning; the unmodified raw SARIF, VEX
document, and application receipt remain in the retained evidence.
If any downstream lock, SBOM, receipt, or evidence binding fails, an `always()` projection
step replaces the upload candidate with the raw SARIF. Therefore only a completely sealed
gate can publish the zero-result projection and close the corresponding code-scanning
alerts.

The contract binds the derived `uv.lock` by SHA-256. Default materialization is sealed and
fails immediately on a placeholder or digest mismatch, before provenance downloads, sync,
or installation. Only the uncredentialed exploratory CI job may temporarily continue to
observe the first digest; even then, its final evidence-binding step fails closed while
still publishing the observed digest, audit SARIF, SBOM, inventory, and evidence artifact.
After the digest is sealed, runtime installation uses the exact Python version from the
contract and installs the official v0.6.0 PyPI wheel with the committed SHA-256,
`--require-hashes`, `--no-deps`, and `--no-build`. The gate also matches PyPI's
trusted-publisher DSSE statement, signature, Fulcio certificate, Rekor entry, GitHub
publisher identity, and exact wheel subject before execution uses `uv run --frozen
--no-sync`. Before any credentialed proof, CI starts the absolute installed executable
against a loopback-only `/config` stub, with no token, telemetry and every
mutation/user/document/data-quality/semantic capability disabled. A real MCP stdio
client must initialize, ping, and enumerate exactly the six approved read-only tools;
the stub rejects every other HTTP request and any authorization header.

Ordinary CI audits the resolved Python/Linux runtime closure with `uv audit`, exports a
CycloneDX SBOM that must contain exact `mcp-server-datahub`, `acryl-datahub`, and
`setuptools` versions, plus an exact installed-package inventory. It retains the contract,
byte-exact upstream project and lock, derived virtual project and lock, overlay receipt,
sealed lock binding, wheel-only graph (including the exact MCP wheel), trusted-publisher
provenance, raw and actionable SARIF, OpenVEX statement, VEX application receipt,
sanitized runtime-smoke receipt, and inventory for 90 days.
The signed CI release predicate includes both the gate result and exact evidence-artifact
digest. The credentialed live proof defaults to sealed mode and includes those exact
upstream and derived runtime subjects in its checksum manifest. Its v3 predicate binds the
resolved lock SHA-256 plus the contract, lock-binding receipt, wheel graph, project overlay,
PyPI provenance, OpenVEX, and runtime-smoke digests. The live workflow rechecks the VEX
expiry during materialization and again immediately before signing, so an old green CI run
cannot authorize a proof after the exception expires.

## Proof and retention

Search must resolve exactly one dataset. The proof additionally requires retained aspect
history, at least two stable source identities, and a recovered cross-source
contradiction. Raw query text, credentials, entity metadata, and the dataset URN are not
written to the proof bundle or job summary; the query and URN are represented there only
by SHA-256 digests. GitHub still retains the query as protected workflow-dispatch metadata
under the repository's normal Actions retention policy.

The workflow emits a canonical JSON proof, both the exact enforced
`control-plane-security-gates.json` receipt and its enriched MCP-evidence receipt, an exact
deployment binding, the MCP lock contract, exact upstream and resolved locks, virtual
project overlay, resolved-lock binding, wheel-only graph, trusted-publisher provenance,
OpenVEX statement, runtime-smoke receipt, and a SHA-256 manifest. Both control-plane
receipts and all MCP runtime evidence are
independent attestation subjects and their digests are recorded in the predicate. It signs
the proof manifest with a GitHub artifact attestation and retains the sanitized bundle for
90 days.
