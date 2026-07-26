# Devpost submission confirmation (SQ11)

This is the post-submit evidence procedure for the DataHub Agent
Hackathon. It does not submit the project to Devpost. It turns a real,
privately verified Devpost submission into a privacy-safe, independently
reviewed, six-subject GitHub attestation.

The required order is:

1. Produce the pre-submit aggregate without `SQ11`.
2. Seal that aggregate with
   `.github/workflows/submission-readiness.yml`.
3. Submit the real project in Devpost.
4. Run
   `.github/workflows/submission-devpost-confirmation.yml`.
5. Produce a new reporting aggregate that may consume the attested
   `SQ11` source.

Do not regenerate the pre-submit readiness seal from an aggregate that
already contains `SQ11`. That would make the submission confirmation
depend on itself.

## What this evidence proves

The workflow binds all of the following to one exact current `master`
release:

- the successful pre-submit readiness seal and its five signed subjects;
- the exact public Devpost project URL;
- the authoritative private submission time supplied by the operator;
- a salted commitment to the private Devpost confirmation;
- the independently reviewed final description and submission claims;
- fresh logged-out observations of the Devpost entry, application,
  repository, and video;
- one independent protected-environment approval with an exact,
  digest-bound comment; and
- the final `SQ11` predicate, proof, and four support subjects.

The evidence deliberately does not claim that a public Devpost page can
prove the authoritative submission time or every private required field.
Those facts require the authenticated confirmation and are checked out of
band by the independent reviewer. GitHub's approvals API does not expose
an authoritative approval timestamp, so the receipt records the protected
review job start as a conservative time bound.

An HTTP `200` response is only logged-out reachability evidence. Product
functionality, authentication posture, release identity, and operational
availability remain covered by the existing `SQ3`, `SQ4`, and `SQ10`
evidence.

## One-time GitHub configuration

Create the GitHub Actions environment
`submission-devpost-confirmation` with all of these controls:

- at least one named individual `User` reviewer;
- prevent self-review enabled;
- custom deployment branch policies enabled;
- exactly one allowed branch policy, `master`; and
- no team-only or wildcard reviewer substitution.

The workflow checks this posture in the prepare, protected-review, and
final signing phases. The reviewer must be different from both the
workflow actor and triggering actor.

The repository's normal GitHub-hosted runner and artifact-attestation
configuration must also remain enabled. No Devpost secret belongs in the
environment.

## Prepare the private confirmation commitment

Keep the authenticated Devpost confirmation, confirmation identifier,
screenshots, cookies, credentials, entrant details, and salt outside the
repository and outside GitHub Actions.

Generate at least 32 random bytes of salt. Build this canonical JSON value,
using the actual private confirmation text or identifier:

```json
{
  "confirmation": "<private Devpost confirmation>",
  "devpostProjectUrl": "https://devpost.com/software/<slug>",
  "releaseSha": "<40 lowercase hexadecimal characters>",
  "repository": "upgradedev/archon-datahub",
  "salt": "<64 or more lowercase hexadecimal characters>",
  "submittedAt": "YYYY-MM-DDTHH:MM:SSZ",
  "version": "archon.salted-private-devpost-confirmation/v1"
}
```

Serialize it as UTF-8 canonical JSON with keys sorted, no insignificant
whitespace, and exactly one trailing line feed. Compute SHA-256 and pass
only `sha256:<64 lowercase hexadecimal characters>` as
`confirmation_digest`.

The digest is a salted privacy-preserving commitment, not a Devpost
signature and not independent proof by itself. Give the reviewer the
private preimage and salt through an approved channel outside GitHub so
they can recompute it. Never put either value in an issue, approval
comment, workflow input, artifact, log, or step summary.

## Dispatch inputs

Freeze `master` at the release being submitted. The workflow fails closed
if the selected release is no longer the current `master`.

Supply these exact values:

| Input | Source |
| --- | --- |
| `release_sha` | The exact 40-character current `master` SHA submitted to Devpost |
| `readiness_run_id` | The successful pre-submit readiness workflow run ID |
| `readiness_run_attempt` | The exact successful readiness run attempt |
| `readiness_artifact_id` | Artifact ID for `submission-readiness-<release_sha>` |
| `readiness_artifact_digest` | GitHub artifact digest, including the `sha256:` prefix |
| `readiness_predicate_digest` | SHA-256 of the sealed `readiness-evidence.json`, including the prefix |
| `devpost_project_url` | Exact public URL matching `https://devpost.com/software/<slug>` |
| `submitted_at` | Authenticated Devpost confirmation time normalized to canonical UTC seconds |
| `confirmation_digest` | The salted private confirmation commitment described above |

All identifiers and digests must refer to the same release. The readiness
artifact must have been created by the successful seal job before
`submitted_at`, within the official submission period. Its GitHub artifact
`created_at` value is retained as the conservative `sealedAt` bound; it is
not represented as a Devpost timestamp.

The official submission period encoded by the workflow is
`2026-07-06T13:00:00Z` through `2026-08-10T21:00:00Z`. The workflow also
checks the essential submission requirements against the current
[official rules](https://datahub.devpost.com/rules).

## Protected review

The prepare job validates the exact readiness source, independently
verifies all five readiness attestation subjects, revalidates the nested
pre-submit aggregate, re-fetches the independently reviewed content
candidate, and probes all four public judging URLs without redirects. It
then uploads an immutable, privacy-safe candidate artifact and prints one
exact approval comment in the job summary.

The protected reviewer must:

1. Open the authenticated Devpost submission outside GitHub Actions.
2. Confirm that its project URL, submitted state, authoritative UTC time,
   required fields, description, application URL, repository URL, video
   URL, and release match the prepared candidate.
3. Recompute the salted commitment from the privately supplied preimage.
4. Check that no submission field is still draft or missing.
5. Approve the `submission-devpost-confirmation` environment using the
   exact comment printed by the prepare job, with no edits.

Do not approve based only on the public project page.

The review job independently downloads and revalidates the candidate,
readiness artifact, readiness attestations, nested aggregate, reviewed
content artifact, official rules, and all public URLs before producing
the standard `SQ11` source artifact.

The attestation job repeats the source-complete checks after review,
reconstructs the approval receipt from the protected GitHub records,
reprobes the rules and public URLs, and applies a final branch, artifact,
approval, inventory, and semantic TOCTOU gate immediately before signing.

## Retained result

The producer artifact is named:

```text
submission-devpost-confirmation-<release_sha>-<review_run_attempt>
```

It is retained for 90 days and contains exactly:

```text
SHA256SUMS
attestation-predicate.json
proofs/SQ11.json
support/SQ11/devpost-submission-confirmation.json
support/SQ11/logged-out-url-probes.json
support/SQ11/pre-submit-readiness-seal.json
support/SQ11/public-devpost-entry.json
```

`SHA256SUMS` is the complete inventory, not a seventh signed subject.
`actions/attest` signs the six inventoried subjects as one exact subject
set. The final workflow step first verifies each of the six exact files
offline against the single bundle returned by `actions/attest`. It then
waits for persistence and calls `gh attestation verify` again, without the
bundle, for every one of the six files. Both passes require the same
bundle identity, predicate bytes, predicate type, signer workflow, release
provenance, and complete sorted six-subject set. Temporary verification
responses are removed by an exit trap.

No raw rules response, URL response, Devpost confirmation, approval
preimage, salt, credential, cookie, screenshot, or private Devpost entrant
data is retained in the producer artifact. The signed `SQ11` proof retains
the workflow actor, triggering actor, and reviewer as public GitHub numeric
account IDs solely to prove reviewer independence. It retains no GitHub
login names.

## Failure and retry policy

Every phase is fail closed. Do not weaken an input, digest, URL, branch,
reviewer, timestamp, inventory, or attestation check to make a run pass.

- If a public URL is unavailable or redirects, repair the public
  deployment or hosting configuration and dispatch again.
- If `master` moved, create evidence for the new release; do not relabel an
  old seal.
- If the protected approval comment is wrong, reject that run and dispatch
  a new one. Do not edit or approximate the comment.
- If an artifact is expired, missing, or has a different digest, reproduce
  the appropriate upstream evidence through its workflow.
- If attestation persistence is briefly delayed, the final verifier
  retries. A run that still fails must be rerun; a summary alone is not
  evidence.
- If the official rules semantics change, stop and reconcile the source
  contract before continuing.

Dynamic response bodies and headers may legitimately change between
phases. The workflow compares stable URL and rules semantics while keeping
each raw response digest phase-local. It never treats differing dynamic
response bytes as proof of tampering.

## Remaining external blockers

This source is complete before submission, but `SQ11` cannot exist until
all external actions below have happened:

- the final public application, repository, and under-three-minute public
  video are available;
- the pre-submit readiness seal is successful;
- the real Devpost entry is submitted rather than saved as a draft;
- the operator supplies the exact private confirmation inputs;
- the independent protected reviewer approves the exact binding; and
- the workflow completes with persisted verification of all six subjects.

Only after that successful run may the reporting aggregate include
`SQ11`. Video production, any optional public post, and the actual Devpost
form remain end-of-process operator actions.
