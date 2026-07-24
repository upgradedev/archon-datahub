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
resolution, a full upgrade, and the fixed `2026-07-23T03:00:00Z` upload cutoff. Before
resolution, the already verified project metadata receives a canonical evidence-recorded
overlay that makes the project version static and sets `tool.uv.package = false`. This
prevents the upstream setuptools backend from executing; the official MCP wheel is
installed separately. Resolution and sync use `--no-build` and `--no-cache`. Every
non-project node must come from the exact PyPI registry and contain hash- and size-bound
`files.pythonhosted.org` wheels. A wheel-less, path, Git, URL, or alternate-registry node
fails the gate.

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
--no-sync`.

Ordinary CI audits the resolved Python/Linux runtime closure with `uv audit`, exports a
CycloneDX SBOM and exact installed-package inventory, and retains the contract, byte-exact
upstream project and lock, derived virtual project and lock, overlay receipt, sealed lock
binding, wheel-only graph, trusted-publisher provenance, SARIF, and inventory for 90 days.
The signed CI release predicate includes both the gate result and exact evidence-artifact
digest. The credentialed live proof defaults to sealed mode and includes those exact
upstream and derived runtime subjects in its checksum manifest. Its v2 predicate binds the
resolved lock SHA-256 plus the contract, lock-binding receipt, wheel graph, project overlay,
and PyPI provenance digests.

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
and a SHA-256 manifest. Both control-plane receipts and all MCP runtime evidence are
independent attestation subjects and their digests are recorded in the predicate. It signs
the proof manifest with a GitHub artifact attestation and retains the sanitized bundle for
90 days.
