# Live DataHub proof

The `Live DataHub proof` workflow is a credentialed, read-only proof gate. It is not a
connectivity check and it does not accept workstation evidence.

## Required dispatch inputs

- `release_sha`: the full lowercase SHA that is currently deployed.
- `deployment_run_id`: a successful `Deploy immutable AWS release` run for that SHA.
- `query`: a trimmed 1–256 character dataset query. Control characters and wildcard
  operators are rejected.

The workflow runs only from `master`. The dispatch SHA and release SHA must be identical.
Before credentials are used, the workflow requires successful same-repository `push` runs
of CI, CodeQL, and Workflow security for that exact SHA. It then downloads the exact
production deployment evidence artifact, verifies its GitHub artifact digest and inner
evidence, and requires the deployed query digest to match the dispatch query.

The protected `datahub-demo` environment supplies a read-only `DATAHUB_GMS_URL` and
`DATAHUB_GMS_TOKEN`. The proof deliberately starts the hash-locked official MCP server
over stdio; it does not fall back to an unverified hosted or `uvx` transport.

## Immutable MCP runtime

The proof does not execute `uvx`. The repository-owned
`.github/locks/datahub-mcp-v0.6.0.json` contract selects the signed upstream v0.6.0 commit,
tree, `pyproject.toml`, and `uv.lock` by Git object IDs, SHA-256, and byte size.
`scripts/materialize-datahub-mcp-lock.sh` fetches only that commit, verifies every binding,
and requires `uv lock --check`. It synchronizes the transitive closure with
`--no-install-project --no-build`, preventing an unbounded PEP 517 build environment, then
installs the official v0.6.0 PyPI wheel with the committed SHA-256, `--require-hashes`,
`--no-deps`, and `--no-build`. Runtime installation uses the exact Python and uv versions
from the contract. The gate also requires PyPI's trusted-publisher record and matches its
DSSE statement, signature, Fulcio certificate, Rekor entry, GitHub publisher identity,
and exact wheel subject to the committed contract before execution uses `uv run --locked
--no-sync`.

Ordinary CI independently audits that same frozen dependency closure with `uv audit`,
exports a CycloneDX SBOM plus the exact installed-package inventory, validates the
machine-readable documents (including the v0.6.0 wheel), retains them for 90 days, and
includes both the gate result and exact evidence-artifact digest in the signed CI release
predicate.

## Proof and retention

Search must resolve exactly one dataset. The proof additionally requires retained aspect
history, at least two stable source identities, and a recovered cross-source
contradiction. Raw query text, credentials, entity metadata, and the dataset URN are not
written to the proof bundle or job summary; the query and URN are represented there only
by SHA-256 digests. GitHub still retains the query as protected workflow-dispatch metadata
under the repository's normal Actions retention policy.

The workflow emits a canonical JSON proof, an exact control-plane/deployment binding, the
MCP lock contract, and a SHA-256 manifest. It signs the proof manifest with a GitHub
artifact attestation and retains the sanitized bundle for 90 days.
