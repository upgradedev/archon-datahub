# Sealed AWS staging IAM incident recovery

Status: **recovered; `DeleteStack` executed once; deletion and cleanup proofs successful**.
Cleanup-only run `30571619440` first proved canonical temporary-policy absence.
Recovery runs `30571830902` and `30576390064` then failed closed before
`PutRolePolicy`; authorization-readback run `30579644527` reached the temporary
policy but stopped before deletion and completed mandatory revocation. After the
canonical byte-domain fix passed exact-master gates, recovery run `30582684638`
validated the sealed incident, proved the installed policy by canonical readback,
issued exactly one `STANDARD` `DeleteStack`, proved the original stack ID reached
`DELETE_COMPLETE` with no active stack of the sealed name, revoked the temporary
policy, and proved canonical absence. Its GitHub attestation is `38051531`.
The machine-readable status is `recovered-delete-complete-cleanup-proven`.

This runbook covers one historical CloudFormation incident only. It is not a
general rollback or stack-deletion facility, and it does not change the normal
foundation reconciler's observational-only failure behavior.

## Immutable incident binding

| Coordinate | Sealed value |
| --- | --- |
| Foundation workflow run | `30546241677`, attempt `1` |
| Incident commit | `aea65845e3a9456403a7fb6e9f338e4c14c0b781` |
| Artifact ID | `8760846578` |
| Artifact digest | `sha256:7aa20586b970ac938fba9299e0c3c2538482b92086db811ea583f84bd3b02e24` |
| Artifact size | `697` bytes |
| Exact inventory | `SHA256SUMS`, `cfn-failure.json` |
| Failure payload SHA-256 | `187d4cf683a61a778feec2051f1ef5c99b60cc58344edbf1a7d0189f28c67442` |
| Checksum-manifest SHA-256 | `9ecfdff27c6de11ab7403ad75780a7fae3339efe05684c6b3ec3185be6a52703` |
| Target label and region | `staging-iam`, `eu-west-1` |
| Source-template semantic SHA-256 | `80a2b02326bbaa3ae145d0fff52cc1c20f3a330d4ef5c7fa2d816182f7c2b825` |

The workflow re-reads the historical run and artifact through GitHub, downloads
only the exact artifact ID, and rejects any inventory, link, byte, checksum,
canonical-JSON, diagnostic, run, attempt, head, size, or digest difference. The
full CloudFormation stack ID is never an input, output, artifact, summary, or
cross-job value. It remains runner-private; only its SHA-256 crosses jobs.


## Executed cleanup and recovery receipts

| Receipt | Sealed result |
| --- | --- |
| Cleanup run | `30571619440`, attempt `1`, commit `dd9b6f8c4c23bed290871c89a505ec12422d8caa`, success |
| Cleanup artifact | `8771042311`, `aws-incident-recovery-cleanup-30571619440-1` |
| Cleanup artifact ZIP SHA-256 | `sha256:df4a796511f3afd850b5c7819b4562735fdec33e5f1fa1c2a286a5556a4739e0` |
| Canonical `cleanup.json` SHA-256 | `8cb752c3418f8587b5fb2a48fc19048babdb45db1570df5b9022831d774495d2` |
| Cleanup attestation | [GitHub attestation `38026442`](https://github.com/upgradedev/archon-datahub/attestations/38026442) |
| Prior recovery run | `30571830902`, attempt `1`, commit `dd9b6f8c4c23bed290871c89a505ec12422d8caa`, prepare failed |
| Prior recovery diagnostic | Historical `AWS_RECOVERY_INCIDENT_RECORD_MISMATCH`; `PutRolePolicy` not reached; `DeleteStack` skipped |
| Prior recovery artifact | `8771158101`, `aws-incident-recovery-30571830902-1` |
| Prior recovery artifact ZIP SHA-256 | `sha256:f21cb3207f1ea91320ce732aa0592bfb014b5fd649bf907fd54f51cfb4003878` |
| Classified recovery run | `30576390064`, attempt `1`, commit `9b9ed35e4c5a5bf0bfed4aa0b049ff654ad2d0b9`, prepare failed closed |
| Classified diagnostic | `AWS_RECOVERY_INCIDENT_DELETE_COMPLETE_NO_PHYSICAL_ID`; `PutRolePolicy` not reached; `DeleteStack` skipped |
| Classified recovery artifact | `8773039467`, `aws-incident-recovery-30576390064-1` |
| Classified artifact ZIP SHA-256 | `sha256:5fea23ffcd4e0d4d323b129644320cc8569746dd417c56fe472e5ef3d580f20e` |
| Authorization-readback run | `30579644527`, attempt `1`, commit `bce219b0a03a5d3a7e162edf81866d00848aaac9`, prepare failed closed |
| Authorization result | Validator success; `PutRolePolicy` request succeeded; canonical readback not proven; `DeleteStack` skipped |
| Authorization artifact | `8774187155`, `aws-incident-recovery-30579644527-1`, `930` bytes, expires `2026-10-28T20:32:58Z` |
| Authorization artifact ZIP SHA-256 | `sha256:f2ab1912324c75a2e1e04ea2ce4c8726905521eef38825cb656631667a2884a8` |
| Authorization evidence scope | Cleanup-only; `3` files uploaded; no GitHub attestation created |
| Authorization finalization | Mandatory revocation succeeded; canonical absence proved |
| Successful recovery run | `30582684638`, attempt `1`, commit `8b7451da65d1bf1ed14b17e0c1f0cc5d43d6cf40`, success |
| Exact-master preflight gates | CI `30582157198`; CodeQL `30582157151`; Workflow Security `30582157207`; Production Supply Chain `30582494521`; all success |
| Successful authorization | Validator, `PutRolePolicy`, and canonical policy readback succeeded |
| Successful delete | Exactly one `STANDARD` `DeleteStack`; original stack ID `DELETE_COMPLETE`; no active sealed stack name |
| Successful recovery artifact | `8775321544`, `aws-incident-recovery-30582684638-1`, `2085` bytes, `6` files, expires `2026-10-28T21:15:52Z` |
| Successful artifact ZIP SHA-256 | `sha256:dddf3d887781c18d2b1578c8083e450c41ba120753206b5f2f80b50031eee155` |
| Canonical `recovery.json` SHA-256 | `44f15d0c362cd16f7fa11a111956bceffa0afc7c6fd2cd5c0aca8747a0dc97ef` |
| Successful recovery attestation | [GitHub attestation `38051531`](https://github.com/upgradedev/archon-datahub/attestations/38051531) |
| Successful finalization | Mandatory revocation succeeded; canonical policy absence proved |
| Automatic cleanup follower | Run `30582939537` skipped on successful source recovery; no extra approval or mutation |

## Operator interface

The public entry workflow `.github/workflows/aws-incident-recovery.yml` accepts
exactly:

```text
expected_head_sha=<exact current lowercase 40-character master SHA>
confirmation=DELETE SEALED STAGING IAM INCIDENT
```

There are no account, artifact, region, role, stack-name, stack-ID, or target
inputs. The one sealed operation completed in run `30582684638`; do not dispatch
it again. The workflow remains immutable audit evidence for this incident, and
the now-absent target must make any accidental rerun fail before authorization.

Cleanup-only retry uses `.github/workflows/aws-incident-recovery-cleanup.yml`:

```text
expected_head_sha=<exact current lowercase 40-character master SHA>
confirmation=REVOKE SEALED INCIDENT POLICY
```

It also follows an incomplete recovery only for exact `action_required`,
`cancelled`, `failure`, `stale`, or `timed_out` conclusions. It excludes
`success`, `neutral`, and `skipped`, and has no recurring schedule. Success already includes mandatory final cleanup. Follower run `30582939537`
therefore completed as `skipped` and did not enqueue another approval.


## Current-state classification and narrow terminal acceptance

The recovery validator reads live `StackResourceSummary` values. AWS defines
[`ResourceStatus` as the resource's current status](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_StackResourceSummary.html)
and makes `PhysicalResourceId` optional. AWS also defines
[`ROLLBACK_COMPLETE`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/view-stack-events.html)
as successful cleanup after a failed stack creation: resources created during
that operation are deleted and only deletion of the stack is then allowed.
Resources deliberately retained during stack deletion use
[`DELETE_SKIPPED`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-delete-stack.html),
which this validator rejects. The immutable historical `CREATE_FAILED` event
therefore remains true even when the live current state is `DELETE_COMPLETE`.

Classified run `30576390064` proved the incident summary is the unique exact
logical ID and `AWS::IAM::ManagedPolicy` type, has current status
`DELETE_COMPLETE`, and omits `PhysicalResourceId`. The reviewed acceptance now
allows only that conjunction, in addition to exact `CREATE_FAILED` without an
ID. Missing `PhysicalResourceId` alone is never treated as proof. The root
`ROLLBACK_COMPLETE` stack identity, no service role, disabled termination
protection, exact tags, exact source template, globally constrained resource
statuses, and unique incident record remain mandatory.

Current rejected classes still fail before authorization with sanitized codes:

- `AWS_RECOVERY_INCIDENT_DELETE_COMPLETE_WITH_PHYSICAL_ID`
- `AWS_RECOVERY_INCIDENT_RESOURCE_TYPE_MISMATCH`
- `AWS_RECOVERY_RESOURCE_STATE_PAGINATED`
- `AWS_RECOVERY_RESOURCE_SUMMARY_SHAPE_INVALID`

`AWS_RECOVERY_INCIDENT_DELETE_COMPLETE_NO_PHYSICAL_ID` remains in the immutable
run receipt but is retired from the current failure-code allowlist. This change
does not alter the workflow, IAM policy, one-shot `DeleteStack` implementation,
or separate `governed-canary-recovery` approval.

## Recovery flow

1. The outer workflow holds non-cancelling `archon-aws-control-plane`; the
   reusable driver then holds non-cancelling
   `archon-governed-canary-mutation-recovery`.
2. `aws-foundation` verifies current master, repository owner, exact historical
   evidence, reviewed role source/render/deployment identity, exact recovery
   role trust and tags, its single baseline inline policy, and zero attached
   managed policies.
3. It accepts only the exact root `ROLLBACK_COMPLETE` target with no service
   role, no termination protection, exact tags and source identity. Every
   resource must be `DELETE_COMPLETE` or exact `CREATE_FAILED` without a
   physical ID. Any remaining `NextToken` fails before private outputs or
   authorization. The incident record must occur once, keep the exact logical ID
   and type, and be either `CREATE_FAILED` or `DELETE_COMPLETE` without an ID.
4. It seals a private plan and exact two-statement temporary policy.
   `PutRolePolicy` is followed by bounded canonical readback.
5. Separately approved `governed-canary-recovery` OIDC re-reads only the exact
   full stack ARN, rederives the same plan, and issues the repository's one
   `DeleteStack` request: full stack ID, deterministic token, `STANDARD` mode,
   no retain list, role override, deployment override, or force mode.
6. `aws-foundation` lists inline policies before mutation. Exact baseline-only
   inventory causes zero delete calls. If the exact temporary policy is present,
   it issues one delete request for that name; unexpected inventory without it
   fails without mutation. The opaque request response is never treated as proof.
7. Three new consecutive canonical baseline-only inventories are the sole
   revocation proof. Persistent temporary or unrelated policy drift and failed
   reads fail closed; temporary-plus-unrelated inventory is privilege-reduced
   before its canonical proof can fail.
8. Postverification requires the original stack-ID digest to reach
   `DELETE_COMPLETE` and a successful `ListStacks` result to show no active
   stack with the sealed name. Failed AWS reads never prove absence.
9. A final `if: always()` cleanup runs even after earlier failure.

## Canonical policy digest domain

The validator hashes recursively sorted, compact UTF-8 JSON bytes without a
trailing newline. Run `30579644527` exposed that the shell readback previously
piped jq's newline-terminated output directly to `sha256sum`, placing expected
and observed values in different byte domains even when their JSON could be
equivalent. The driver now captures object-only `jq -ceS` output and hashes it
with `printf '%s'`, so both sides use the exact no-newline domain.

CI compares bytes produced by the validator's exported `canonicalJson` function
with a deliberately key-reordered AWS-shaped readback. Exact equivalence must
pass on the first read. Modified, malformed, non-object, and newline-domain
values exhaust the bounded retries and fail closed without exposing raw AWS
values. This correction changes no workflow permission, IAM grant, delete
shape, approval gate, or cleanup requirement.

## Authority, IAM limitations, and consistency

The unchanged baseline recovery role is read-only. The temporary policy grants
exactly `cloudformation:DescribeStacks` and `cloudformation:DeleteStack` on the
sealed full stack ARN. Both require exact region, four exact resource tags, and
a short `aws:CurrentTime` expiry. Delete also requires a null
`cloudformation:RoleArn`. Configured TTL is 20 minutes; validation caps it at
30 minutes.

AWS IAM cannot use condition keys on `iam:PutRolePolicy` to constrain the
submitted policy name or document. Compensating controls are the exact role
resource, owner-only protected environment, zero attached managed policies,
canonical readback equality, short TTL, separate delete approval, and mandatory
exact cleanup. CloudFormation IAM conditions likewise cannot constrain
`DeletionMode`, retained resources, or client token. The reviewed driver and
sealed plan enforce those fields, and CI requires exactly one literal
`delete-stack --deletion-mode STANDARD` call.

IAM changes are eventually consistent. Put-to-readback, recovery
`DescribeStacks` authorization, and delete-to-absence therefore use bounded
retries; absence requires repeated successful inventories, never an API error.
See AWS documentation for
[IAM eventual consistency](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot.html#troubleshoot_general_eventual-consistency),
[`PutRolePolicy`](https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutRolePolicy.html),
and
[CloudFormation authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awscloudformation.html).

No repository or organization secret is forwarded to the reusable workflow.
AWS access uses environment-bound GitHub OIDC. TTL makes delayed cleanup
non-privileged, but cleanup remains mandatory for a valid receipt.

## Lock order

All paths preserve one order and no reverse edge:

```text
archon-aws-control-plane
  -> archon-governed-canary-mutation-recovery
```

Foundation holds outer and its reconciliation job also holds inner while it may
update governed-canary roles. Incident recovery and cleanup also hold outer then
inner. Deploy holds outer while synchronously dispatching the governed canary;
fixture, live canary, and compensation workflows hold inner only. Giving those
children the outer lock would deadlock their parent.

## Sanitized evidence and CI proof

Successful recovery or cleanup steps produce canonical JSON, SHA-256 manifests,
and attestation predicates retained for 90 days. Upload runs only when at least
one evidence-producing step succeeds; a failed cleanup with no receipt does not
trigger a misleading missing-artifact failure. Evidence may contain safe
coordinates and digests, but never raw account IDs, role ARNs, stack IDs/ARNs,
plans, AWS errors, credentials, tokens, paths, or secrets. Validator failures
expose only the explicit allowlisted machine code for the failed invariant.

Successful run `30582684638` uploaded six explicit recovery-and-cleanup files.
GitHub attestation `38051531` binds only canonical `recovery.json` at SHA-256
`44f15d0c362cd16f7fa11a111956bceffa0afc7c6fd2cd5c0aca8747a0dc97ef`;
the artifact's cleanup files are retained evidence, not separately attested.

`contracts/aws-incident-recovery-v1.json` is machine-readable authority. CI
syntax-checks both scripts, checks the validator, runs validator unit tests,
runs mocked fail-closed driver tests, and enforces workflow permissions, exact
action pins, triggers, lock scope/order, artifact identity, and deletion shape.
The normal foundation contract keeps `autoRecovery: forbidden` and explicitly
links this one exception.
