# Live DataHub proof

The `Live DataHub proof` workflow is a credentialed, read-only proof gate. It is not a
connectivity check and it does not accept workstation evidence.

## Required dispatch inputs

- `release_sha`: the full lowercase SHA that is currently deployed.
- `deployment_run_id`: a successful `Deploy immutable AWS release` run for that SHA.
- `query`: the exact target URN from `contracts/datahub-demo-state-v1.json`. The ordinary
  narrow-query safety checks also reject whitespace aliases, control characters, and
  wildcard operators.

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

## Sealed demo-state and deployed semantics

The selected production deployment must contain the exact
`archon.datahub-demo-receipt-binding/v1` projection and the complete six-file
`sealed-datahub-demo-receipt` directory. The live workflow re-fetches the original
`.github/workflows/datahub-demo-state.yml` run at its exact attempt, re-fetches the
artifact by ID, compares its exact name/digest, runs the shared canonical receipt
verifier, byte-compares the regenerated sanitized binding, and verifies the original
`datahub-demo-state/v1` attestation. It also verifies the production deployment evidence
attestation (`production-deployment/v1`) and its strict root checksum inventory.

Before a credentialed read, `validate-config` normalizes the protected
`DATAHUB_GMS_URL`, emits only its SHA-256 fingerprint, and requires equality with the
seed receipt. The direct proof must then return the exact target-URN digest, one retained
history, two stable sources, one recovered contradiction, and one contradiction
attribute. Counts greater than the planted contract are drift and fail.

Separately, the workflow calls the deployed production `/api/audits` endpoint again and
requires exactly the promoted semantic projection: one G6 `email` gap, one dangling
upstream whose blast radius reaches the target consumer at one hop, and one retained
`owner` contradiction with the two expected source/run identities. The projection stores
booleans, counts, field path, statuses, and digests—not raw DataHub URLs, tokens, dataset
URNs, or provider responses.

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

### OpenVEX renewal runbook

Normal CI and an independent daily supply-chain maintenance job run the materializer's
local, read-only maintenance mode and fail when fewer than 14 days remain. The exact
release rescan repeats that gate against its checked-out source. Maintenance mode performs
no network access or runtime materialization; the existing expiry checks still cap every
statement at 30 days.

On failure, first re-evaluate every advisory alias against the exact wheel-only runtime,
platform, and execution-path conditions. If the runtime is affected or the disposition is
uncertain, upgrade the dependency or remove the disposition; do not renew it. Only when
`not_affected` remains demonstrably true, issue a new canonical statement whose
`issuedAt <= now < expiresAt` and whose validity is at most 30 days. Recompute its SHA-256
and update the OpenVEX document, `.github/locks/datahub-mcp-v0.6.0.json`, and the reviewed
constants or fixtures in `scripts/materialize-datahub-mcp-lock.sh`,
`scripts/validate-datahub-mcp-audit.py`, and their contract tests. Submit those changes as
one pull request and rely on CI to validate them; after merge, the daily rescan and live
proof consume the renewed evidence.

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
upstream and derived runtime subjects in its checksum manifest. Its v4 predicate binds the
resolved lock SHA-256 plus the contract, lock-binding receipt, wheel graph, project overlay,
PyPI provenance, OpenVEX, runtime-smoke, sealed demo receipt, endpoint fingerprint,
deployment evidence, and deployed semantic-proof digests. The live workflow rechecks the VEX
expiry during materialization and again immediately before signing, so an old green CI run
cannot authorize a proof after the exception expires.

## Proof and retention

Search must resolve the exact contract dataset. The proof additionally requires exactly
one retained history, two stable source identities, one recovered cross-source
contradiction, and the matching deployed G6/dangling-lineage projection. The sanitized
proof and semantic projections represent the query and target URN only by SHA-256
digests. The checksum-bound source receipt intentionally retains the reviewed public
contract URNs needed to reproduce the state binding. No DataHub endpoint, token, raw
provider response, or arbitrary entity metadata is retained in the proof bundle or job
summary. GitHub also retains the dispatch query under the repository's normal Actions
retention policy.

The workflow emits a canonical JSON proof, both the exact enforced
`control-plane-security-gates.json` receipt and its enriched MCP-evidence receipt, an exact
deployment binding and deployment evidence, the sanitized demo-state and endpoint
bindings, the complete sealed receipt, the current deployed semantic proof, the MCP lock
contract, exact upstream and resolved locks, virtual project overlay, resolved-lock
binding, wheel-only graph, trusted-publisher provenance, OpenVEX statement, runtime-smoke
receipt, and a strict SHA-256 manifest. Both control-plane receipts and all MCP runtime evidence are
independent attestation subjects and their digests are recorded in the predicate. It signs
the proof manifest with a GitHub artifact attestation and retains the sanitized bundle for
90 days. The artifact is
`live-datahub-proof-<release-sha>-<live-run-attempt>` and its predicate type is
`https://github.com/upgradedev/archon-datahub/attestations/live-datahub-proof/v4`; these
are the exact source selectors for a protected submission-readiness aggregator.
