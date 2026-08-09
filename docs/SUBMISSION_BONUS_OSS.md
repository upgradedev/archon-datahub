# BONUS-OSS upstream contribution evidence

## Current state

The BONUS-OSS producer is source-complete and intentionally fail-closed until
upstream acceptance. Public pull request
[`acryldata/mcp-server-datahub#183`](https://github.com/acryldata/mcp-server-datahub/pull/183)
contains the exact five-path `get_aspect_history` candidate. A maintainer gave
strong positive feedback and requested the batch/OpenAPI-seam refinements now
present at head `75e5cf25a1b3d4decb8717c8b962a1bc277ed603`; the pull request is still
open, so no accepted-contribution bonus is claimed.

`contrib/mcp-get-aspect-history/manifest.json` therefore records
`public-pull-request-open`, PR #183, its exact head SHA, `pullRequestOpened: true`,
`appliedToUpstream: false`, and all three local execution flags as `false`.
An open pull request is not sufficient evidence. The bonus is emitted
only after an independent upstream maintainer has merged the exact candidate.

## External activation sequence

1. Keep public pull request #183 based on
   `9a6946daa7d30eb481c82dd8ee5e15ae6526a3c9` limited to these five paths:
   `src/mcp_server_datahub/mcp_server.py`,
   `src/mcp_server_datahub/openapi_client.py`,
   `src/mcp_server_datahub/tools/__init__.py`,
   `src/mcp_server_datahub/tools/aspect_history.py`, and
   `tests/test_mcp/test_get_aspect_history.py`.
2. Obtain merge acceptance from an upstream identity different from the pull
   request author during the official submission period. A draft, open,
   closed-unmerged, self-merged, private, renamed-path, or extra-path pull
   request remains ineligible.
3. In a normal repository change after the merge, replace the manifest status
   with the exact `merged-upstream` variant:
   `state`, `pullRequestOpened`, `appliedToUpstream`, `pullRequestNumber`,
   `url`, `headSha`, `mergeCommitSha`, `mergedAt`, `localBuildRun`,
   `localTestsRun`, and `localSecurityScanRun`. The three local flags must
   remain `false`. In the same change, replace the contribution README's
   `Honest status` paragraph with the exact concrete values rendered as:

   ```text
   **Merged upstream.** Pull request [#<number>](<canonical-url>) was merged by an independent upstream maintainer at `<mergedAt>`. Head commit: `<headSha>`. Merge commit: `<mergeCommitSha>`. No local build, test suite, or security scan was run; all validation and security evidence was produced by CI/CD.
   ```

   Remove the staged/no-pull-request wording. The phase-aware verifier rejects
   a merged manifest paired with a stale staged README, or the reverse.
4. Let the ordinary `master` CI pipeline validate the merged-status release
   and produce the signed OSS validation receipt. Do not substitute a local
   build, local test result, local security scan, workstation JSON, or
   caller-supplied artifact.
5. Dispatch `.github/workflows/submission-bonus-oss.yml` with exactly
   `release_sha`, `ci_run_id`, and `upstream_pull_request_number`.

If upstream `main` advances in a way that prevents the exact pinned candidate
from being accepted, update the staged contribution, pinned base, integration
patch, and their source contracts through the normal CI-reviewed repository
flow before opening or updating the upstream pull request. Do not reinterpret a
different upstream tree as the current candidate.

## What the workflow proves

The read-only producer resolves the latest successful current-release CI push,
the exact successful contribution and Lambda producer jobs, their
job-window-owned immutable artifacts, and the current-attempt signed CI release
predicate. It safely extracts the CI receipt, verifies every checksum and
manifest byte, and reconstructs the candidate twice from the pinned public base:
first from the CI `applied.diff`, then from the staged source files plus
`integration.patch`.

Public upstream observations are credentialless and reject redirects. The
collector requires the canonical public Apache-2.0 repository, base branch
`main`, a merged non-draft pull request, an independent author and merger, and
the exact five changed paths. Credentialless Git then proves:

- the receipt diff reconstructs one exact candidate tree;
- the staged files and integration patch reconstruct the same diff and tree;
- the public pull-request head has that complete tree, with no unrelated
  commits or files hidden outside the five-path API inventory; and
- the merged commit contains identical modes and bytes for all five paths.

The canonical candidate manifest binds the pinned base commit, applied-diff
digest, reconstructed tree, and each path's mode, Git blob ID, and SHA-256
digest. Its digest is computed over sorted-key, compact, newline-terminated
UTF-8 JSON. The retained facts also bind the exact CI receipt artifact ID,
digest, producer attempt, receipt digest, verified CI predicate digest, and
attested Lambda subject.

The producer has read-only permissions and cannot sign. A separate attester
independently discovers the latest retained producer artifact by immutable ID,
repeats the complete CI and upstream reconstruction twice, validates the
standard four-subject inventory, and alone receives `attestations: write` and
`id-token: write`. Both jobs use GitHub-hosted `ubuntu-24.04` runners and run
the repository control-plane checks. All security and integrity enforcement is
inside CI/CD; this flow does not use Codex Security.

After signing, the attester validates the generated single-document Sigstore
bundle and then verifies the persisted GitHub attestation online for each of
the four subjects. Every verification must resolve exactly one result matching
that exact bundle, complete subject set, predicate bytes, repository, signer
workflow, release digest, and `refs/heads/master`; self-hosted provenance is
rejected. The exact numeric attestation ID must also reproduce the canonical
GitHub attestation URL.

## Retained subjects

The attempt-scoped artifact
`submission-bonus-oss-{releaseSha}-{runAttempt}` retains exactly:

- `attestation-predicate.json`
- `proofs/BONUS-OSS.json`
- `support/BONUS-OSS/upstream-pr.json`
- `support/BONUS-OSS/ci-validation.json`

`SHA256SUMS` covers those four subjects, and the independent attester signs that
exact checksum inventory with the custom BONUS-OSS predicate type. BONUS-OSS is
optional and never changes the required submission-readiness decision.
