# Most Valuable Feedback evidence

`BONUS-FEEDBACK` is optional and independent of Project eligibility. Its evidence
workflow is source-complete, but it must remain blocked until the eligible
solo owner has actually submitted the feedback form and privately verified the
authenticated confirmation.

The official rules define a Feedback Submission as an online form for a
registered entrant. It must be submitted between **2026-07-06 09:00 EDT
(13:00 UTC)** and **2026-08-10 17:00 EDT (21:00 UTC)**. There is one Feedback
Submission per Entrant. Eligible feedback must be complete and actionable, and
is evaluated for completeness, viability, and potential impact.

The challenge overview says to opt in and complete the feedback section during
submission. The rules separately define “Feedback Submission” and “Submission”,
and state that feedback prizes are awarded to individuals rather than Projects.
The public overview therefore describes the action as completing a feedback
section during submission. This is public wording, not an authenticated-UI
observation; the repository does not invent a separate form URL or attest a
specific private-page layout.

Authoritative sources:

- <https://datahub.devpost.com/>
- <https://datahub.devpost.com/rules>

## Privacy boundary

The workflow never receives or stores:

- feedback answers or excerpts;
- an entrant’s name, email, Devpost username, or private identifier;
- Devpost credentials, cookies, session state, tokens, or authenticated URLs;
- screenshots, page exports, receipt identifiers, or private confirmation
  bytes.

Only two domain-separated, salted SHA-256 commitments enter the public
repository:

- `entrant.bindingDigest` binds the privately reviewed individual entrant; and
- `confirmation.digest` binds a sanitized private confirmation/reference.

The private preimages must each include a fresh 256-bit random nonce. The
confirmation preimage may describe only the challenge, authenticated submitted
state, authoritative submitted timestamp, and an opaque confirmation reference.
It must not contain the feedback answers. The preimages stay outside the
repository, GitHub Actions, workflow inputs, logs, artifacts, comments, and
attestations. They are shown to the configured reviewer through a private
channel so the reviewer can recompute both commitments.

For deterministic review, each private preimage is UTF-8 compact JSON with
lexicographically sorted keys, no insignificant whitespace, and one final LF.
The entrant preimage has exactly:

```json
{"challengeUrl":"https://datahub.devpost.com/","devpostEntrantPrivateId":"<authenticated stable private ID>","nonce":"<64 lowercase hexadecimal characters>","schemaVersion":"archon.private-feedback-entrant-binding/v1"}
```

The confirmation preimage has exactly:

```json
{"challengeUrl":"https://datahub.devpost.com/","confirmationReference":"<opaque authoritative reference>","nonce":"<different 64 lowercase hexadecimal characters>","schemaVersion":"archon.private-feedback-reference/v1","status":"submitted","submittedAt":"<canonical Devpost UTC timestamp>"}
```

The public value is `sha256:` followed by the lowercase SHA-256 of the exact
preimage bytes. The two nonces must differ. If Devpost exposes no stable private
entrant identifier or authoritative confirmation reference, do not invent one;
leave the bonus blocked.

The entrant commitment is deliberately pseudonymous rather than described as
“not personal data.” The signed support also retains the solo owner’s
public GitHub numeric ID as approval provenance. It does not retain raw entrant
identifiers, the entrant’s Devpost identity, or any private-form identity field.

A salted digest is not a Devpost signature. It prevents the public evidence from
disclosing or cheaply guessing the private reference; the protected GitHub
environment approval supplies the attributable human attestation. Devpost
offers no credentialless public confirmation endpoint for this private form, so
the pipeline cannot independently prove the form directly.

The approval is a point-in-time observation. Because the pipeline cannot see the
authenticated form, it also cannot prevent a later edit or second entry. The
entrant must not alter or resubmit the feedback after approval; if the private
state becomes uncertain, the evidence must not be used.

## Deferred canonical evidence

Do not create
`docs/SUBMISSION_FEEDBACK_CONFIRMATION.json` before the real feedback
submission. A placeholder, synthetic timestamp, self-signed claim, local
fixture, or hash without private reviewer-verifiable preimage is invalid.

After submission, add exactly one canonical UTF-8 JSON file, at most 4 KiB,
using sorted keys, two-space indentation, and one final newline:

```json
{
  "assertions": {
    "actionable": true,
    "complete": true,
    "distinctFeedbackSubmissionUnderRules": true,
    "individualNotProjectPrize": true,
    "oneEntryPerEntrant": true,
    "potentialImpact": true,
    "registeredEntrant": true,
    "viable": true
  },
  "challengeUrl": "https://datahub.devpost.com/",
  "confirmation": {
    "digest": "sha256:<64 lowercase hexadecimal characters>",
    "scheme": "archon.salted-private-feedback-reference/v1"
  },
  "entrant": {
    "bindingDigest": "sha256:<64 lowercase hexadecimal characters>",
    "bindingScheme": "archon.salted-devpost-entrant-binding/v1",
    "kind": "individual"
  },
  "officialRulesUrl": "https://datahub.devpost.com/rules",
  "privacy": {
    "devpostCredentialsIncluded": false,
    "pseudonymousEntrantCommitmentIncluded": true,
    "rawEntrantPersonalDataIncluded": false,
    "rawFeedbackIncluded": false
  },
  "schemaVersion": "archon.submission-feedback-confirmation/v1",
  "status": "submitted",
  "submittedAt": "<authoritative UTC Devpost timestamp>"
}
```

`submittedAt` must be the timestamp shown by the authenticated Devpost
confirmation or another authoritative confirmation generated by Devpost. Do
not infer or backdate it. If Devpost provides no authoritative timestamp or
confirmation/reference that the solo owner can verify, leave the
bonus blocked.

The file deliberately records both:

- `individualNotProjectPrize: true`, matching the rules’ prize scope; and
- `distinctFeedbackSubmissionUnderRules: true`, matching the separately
  defined rules term without falsely claiming a separate public URL or page.

## Protected review

Configure a GitHub environment named `submission-bonus-feedback` with:

- exactly one required individual reviewer, `upgradedev`;
- `prevent_self_review` disabled so the owner may approve;
- one custom deployment policy of type `branch` allowing only `master`; and
- no secrets.

The reviewer must equal both the workflow actor and triggering actor. The solo
owner privately verifies all of the following before approving:

1. the individual is registered for the DataHub hackathon;
2. the authenticated UI shows the feedback as submitted;
3. its authoritative timestamp matches `submittedAt` and is within the
   Feedback Period;
4. this is the entrant’s only Feedback Submission;
5. the feedback is complete, actionable, viable, and potentially impactful;
6. the private entrant and confirmation preimages reproduce the two public
   digests; and
7. the public canonical file contains no raw feedback, raw entrant personal
   data, or Devpost credentials, and explicitly discloses the pseudonymous
   entrant commitment.

GitHub’s review-history response does not expose an authoritative approval
timestamp. The evidence therefore records
`authoritativeApprovalTimestampAvailable: false` and the protected review job’s
`reviewJobStartedAt`. Because an environment-protected job can start only after
approval, that value is a conservative “approval observed no later than” bound;
it is not presented as the time the reviewer clicked Approve.

The `prepare` job publishes the one exact approval comment. It binds the
release, workflow run and attempt, candidate artifact ID and digest, candidate
digest, canonical evidence digest, confirmation digest, entrant binding digest,
and submitted timestamp. Any altered or reused approval is rejected.

## Pipeline trust chain

`.github/workflows/submission-bonus-feedback.yml` accepts only `release_sha`.
All URLs, rules, schemas, artifact names, dates, paths, and predicate types are
workflow and registry constants.

1. `prepare` checks current `master`, validates the canonical file, fetches both
   official pages without credentials or redirects, creates an immutable
   checksum-sealed candidate, and retains it for 90 days.
2. `review` runs behind the protected environment. It verifies the exact
   solo-owner approval through the GitHub API, redownloads and revalidates the
   candidate, repeats the official-rules observation, assembles the registered
   three-subject standard source, and retains it for 90 days.
3. `attest` independently resolves the retained artifacts under the retry
   policy, rechecks the canonical release, candidate, public rules, environment
   posture, reviewer identity, approval comment, approval receipt, facts, and
   checksum inventory, then signs exactly the registered subjects.
4. After signing, the attester verifies the persisted GitHub attestation
   against the exact repository, workflow, release digest, `master` ref,
   predicate, and complete three-subject set while denying self-hosted
   provenance.

All security and integrity checks in this flow execute in CI/CD. No local
build, local test, workstation scan, copied report, or Codex Security result is
accepted as evidence.

Signed subjects are exactly:

```text
attestation-predicate.json
proofs/BONUS-FEEDBACK.json
support/BONUS-FEEDBACK/feedback-confirmation.json
```

`SHA256SUMS` contains exactly those three entries and is retained alongside
them; it is not a fourth signed subject.

## External blockers

The workflow must stay red or undispatched until all of these are true:

- an eligible individual has joined the hackathon;
- the real feedback has been submitted exactly once during the official
  Feedback Period;
- the authenticated confirmation and authoritative timestamp exist;
- privacy-preserving commitments and the canonical file have been created in a
  subsequent exact `master` release;
- `submission-bonus-feedback` is correctly protected; and
- the configured solo owner can privately verify the form,
  confirmation/reference, uniqueness, and quality assertions.

The workflow does not submit, edit, or read the form. If the solo owner cannot
privately verify it, do not claim `BONUS-FEEDBACK`.
