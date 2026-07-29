# Submission content review

The final Devpost copy, public demo video, prior-work disclosures, repository
history, and cross-medium consistency are sealed by CI/CD. Local review output
and workstation security scans are not accepted as submission evidence.

The workflow is intentionally installed before the final media exists. It fails
closed until all three external prerequisites are real:

1. `docs/SUBMISSION_CONTENT.json` exists at the exact release and has
   `status: "final"`;
2. the supplied URL is one exact canonical HTTPS YouTube, Vimeo, or Youku URL
   with no userinfo or explicit port, and the target video's own provider
   object proves logged-out access and a duration from 1 through 179 seconds;
   and
3. the GitHub `submission-content-review` environment has the explicit
   `upgradedev` solo-owner reviewer.

The editable starting point is
[`SUBMISSION_CONTENT.example.json`](SUBMISSION_CONTENT.example.json). Copy it to
`docs/SUBMISSION_CONTENT.json` only when the submission copy and video are
final. Replace every deferred value, preserve the exact schema, sort all
`builtWith`, claim-ID, proof-ID, and video-claim lists, and change `status` to
`final`. Sort both disclosure inventories by their unique `name` values. The
workflow rejects `TODO`, `TBD`, `PLACEHOLDER`, `example.com`, the known
placeholder application name, missing disclosures, incomplete English
accessibility, and claims not bound to registered proof IDs.

## Protected environment

Create one GitHub environment named `submission-content-review` with all of the
following controls:

- exactly one custom deployment-branch policy named `master`;
- exactly one required reviewer, configured as the individual GitHub `User`
  `upgradedev`, not a team;
- `prevent_self_review` disabled so the owner may approve; and
- a reviewer whose numeric user ID equals both the workflow actor and
  triggering actor.

The prepare job prints a candidate-specific approval sentence in the workflow
summary. The reviewer must inspect the immutable candidate artifact and approve
the environment with that exact sentence. A generic approval, changed
whitespace, a second matching approval, a non-owner approval, a team approval,
or an approval for another attempt is rejected.

The approval receipt binds the repository, release, workflow path/ref, run and
review-producer attempt, actor IDs, environment ID, reviewer ID/login, exact
comment, candidate producer attempt, candidate artifact ID/digest, candidate
JSON digest, and project-access run. It also binds the exact content digest,
video-observation digest, and project-access binding digest explicitly rather
than relying only on transitive artifact provenance.
`approvalCommentDigest` is `sha256:` plus SHA-256 of the exact UTF-8 approval
comment bytes with no trailing newline. `candidateDigest` is SHA-256 of the
canonical immutable `candidate.json` bytes.

On a partial retry, the candidate can legitimately come from an earlier
successful `prepare` attempt. The Actions run title exposes the current attempt.
In the approval sentence copied from the prepare summary, change only
`run_attempt` to that current attempt; preserve `candidate_run_attempt` and
every candidate ID/digest binding. The workflow obtains candidate actor
provenance from the candidate attempt endpoint and reviewer/producer actor
provenance from the review-producer attempt endpoint. An approval sentence from
an older review attempt therefore cannot match the current review.

## Run contract

The only dispatch inputs are:

- `release_sha` — the 40-character SHA that must equal current `master`;
- `project_access_run_id` — an exact successful, attested
  `submission-project-access` run for that release; and
- `video_url` — the exact final public provider URL.

There are no inputs for facts, JSON, paths, reviewer identity, application URL,
approval bypasses, or arbitrary evidence. Those values come from the reviewed
release, GitHub APIs, the protected approval, the registered upstream
attestation, and credentialless observations.

An operator can dispatch the final review from the repository:

```bash
gh workflow run submission-content-review.yml \
  --ref master \
  -f release_sha=THE_EXACT_CURRENT_MASTER_SHA \
  -f project_access_run_id=THE_SUCCESSFUL_PROJECT_ACCESS_RUN_ID \
  -f video_url=THE_EXACT_FINAL_PUBLIC_VIDEO_URL
```

The workflow never writes submission evidence into the checkout. Ephemeral
candidate and reconstruction files live below `RUNNER_TEMP`; only
checksum-sealed GitHub Actions artifacts are retained.

Before every provider request, the shared validator parses and accepts only the
exact canonical URL/provider/video-ID tuple; `curl` receives that validated URL,
uses strict TLS, follows no redirects, and sends no credentials. The returned
HTML is not searched for an unrelated global duration. Instead, the validator
requires exactly one provider metadata object bound directly to the requested
video ID and reads the duration from that object. Zero, duplicate, conflicting,
private, unavailable, credential-gated, zero-second, or 180-second-and-longer
targets fail closed.

## Pipeline phases

`prepare` is read-only. It verifies current `master`, the full attested
project-access subject set, canonical final content, the exact public
application origin, strict provider URL/video ID/duration metadata, `NOTICE.md`,
`docs/JUDGE_TESTING.md`, and every commit reachable from the release. It uploads
a 90-day immutable candidate and publishes the exact approval request.

`review` runs behind the protected environment. It independently:

- resolves and attestation-verifies project-access again;
- downloads the exact candidate by numeric artifact ID and metadata digest;
- reproduces every content digest from reviewed bytes;
- reproduces the complete Git commit inventory from a full-history checkout;
- repeats the logged-out, no-redirect, strict-TLS video observation;
- proves one exact solo-owner environment approval; and
- assembles the registered SQ6, SQ7, and SQ8 standard-v1 subjects.

Provider pages are dynamic, so prepare and review each retain the SHA-256 digest
of the exact response bytes they observed, while revalidation compares only the
strictly typed stable tuple: canonical URL, provider, target video ID, duration,
public/logged-out flags, HTTP 200, and zero redirects. The independently
observed response digests are both signed in SQ7; equality between dynamic page
bodies is neither assumed nor fabricated.

The final artifact is
`submission-content-review-{releaseSha}-{producerAttempt}`, retained for 90
days. Its predicate type is
`https://archon.datahub.dev/attestations/submission-content-review/v1`.
`SHA256SUMS` covers exactly 16 attested subjects:

- the attestation predicate;
- proof envelopes for SQ6, SQ7, and SQ8;
- three SQ6 support subjects;
- five SQ7 support subjects; and
- four SQ8 support subjects.

`attest` has no protected environment or production credentials. It discovers
the latest retained eligible producer attempt from GitHub rather than trusting
job outputs for artifact selection. It then reads the signed candidate attempt,
numeric artifact ID, and artifact digest from SQ8 and resolves that exact
candidate independently. It validates the exact standard-v1 inventory,
re-verifies project-access, reproduces content, history, public video metadata,
approval receipt, and every fact, then signs all 16 checksummed subjects with
GitHub OIDC. It finally verifies the persisted GitHub attestation online against
the exact predicate and complete subject set.

Retries are fail-closed: the attester selects the latest retained complete
review-producer attempt, but resolves the candidate from the exact
`candidateRunAttempt`, `candidateArtifactId`, and `candidateArtifactDigest`
signed by that producer. The candidate attempt must not be later than the
review-producer attempt. A future, ambiguous, expired, wrong-run, wrong-release,
wrong-attempt, or digest-changed artifact is rejected.

## Evidence and current blockers

SQ6 proves complete English written fields, exact judge instructions, and
submission-claim digests. SQ7 proves logged-out public access, provider identity,
the under-three-minute duration, functioning footage, English accessibility,
media rights, application-origin consistency, and video claims. SQ8 proves the
official rules window, complete repository chronology, prior-work and
third-party inventories, `NOTICE.md`, cross-medium consistency, and the
explicit solo-owner approval provenance.

All three proofs use one identical `reviewedAt`. Every opaque digest is derived
from exact observed or reviewed bytes. SQ7 separately binds the prepare and
review provider-response digests. SQ8 additionally binds the workflow path, run
ID, review-producer attempt, environment ID, actor/reviewer IDs, exact candidate
attempt/artifact provenance, candidate digest, exact approval-comment digest,
and full approval-receipt digest.

Until the final `docs/SUBMISSION_CONTENT.json`, public video, and protected
environment/reviewer exist, a successful content-review artifact cannot be
produced. That is an explicit external prerequisite, not a green or deployed
claim. Workflow syntax, permissions, action pinning, artifact selection,
mutation resistance, and the approval boundary are enforced by the remote CI
contract test in
`tests/pipeline/submission_content_review_contracts_test.py`.
