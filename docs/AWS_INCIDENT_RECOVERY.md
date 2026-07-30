# Sealed AWS staging IAM incident recovery

Status: **implemented, not executed**. This path is CI-only. It has not called
AWS, dispatched recovery, or deleted a stack.

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

## Operator interface

The public entry workflow `.github/workflows/aws-incident-recovery.yml` accepts
exactly:

```text
expected_head_sha=<exact current lowercase 40-character master SHA>
confirmation=DELETE SEALED STAGING IAM INCIDENT
```

There are no account, artifact, region, role, stack-name, stack-ID, or target
inputs. Run only the version merged to current `master`, after its CI,
workflow-security, and CodeQL receipts are successful. The present branch is
implementation evidence only; this document does not authorize dispatch.

Cleanup-only retry uses `.github/workflows/aws-incident-recovery-cleanup.yml`:

```text
expected_head_sha=<exact current lowercase 40-character master SHA>
confirmation=REVOKE SEALED INCIDENT POLICY
```

It also follows an incomplete recovery only for exact `action_required`,
`cancelled`, `failure`, `stale`, or `timed_out` conclusions. It excludes
`success`, `neutral`, and `skipped`, and has no recurring schedule. Success
already includes mandatory final cleanup and does not enqueue another approval.

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
   physical ID; the incident resource record must occur once.
4. It seals a private plan and exact two-statement temporary policy.
   `PutRolePolicy` is followed by bounded canonical readback.
5. Separately approved `governed-canary-recovery` OIDC re-reads only the exact
   full stack ARN, rederives the same plan, and issues the repository's one
   `DeleteStack` request: full stack ID, deterministic token, `STANDARD` mode,
   no retain list, role override, deployment override, or force mode.
6. `aws-foundation` unconditionally attempts deletion of the exact temporary
   policy before evaluating unrelated role drift. It accepts success or the
   exact AWS `NoSuchEntity` code for `DeleteRolePolicy`; every other error fails
   closed. Raw errors remain private runner-temporary files and are removed.
7. Three consecutive canonical baseline-only policy inventories prove
   revocation. Unexpected policies fail the receipt after the known temporary
   privilege has been removed.
8. Postverification requires the original stack-ID digest to reach
   `DELETE_COMPLETE` and a successful `ListStacks` result to show no active
   stack with the sealed name. Failed AWS reads never prove absence.
9. A final `if: always()` cleanup runs even after earlier failure.

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

Recovery and cleanup produce canonical JSON, SHA-256 manifests, and attestation
predicates retained for 90 days. They may contain safe coordinates and digests,
but never raw account IDs, role ARNs, stack IDs/ARNs, plans, AWS errors,
credentials, tokens, or secrets.

`contracts/aws-incident-recovery-v1.json` is machine-readable authority. CI
syntax-checks both scripts, checks the validator, runs validator unit tests,
runs mocked fail-closed driver tests, and enforces workflow permissions, exact
action pins, triggers, lock scope/order, artifact identity, and deletion shape.
The normal foundation contract keeps `autoRecovery: forbidden` and explicitly
links this one exception.