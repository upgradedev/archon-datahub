# Production paging delivery proof

`.github/workflows/production-paging-test.yml` is the scheduled and manually dispatchable,
protected, fail-closed proof that Amazon SNS delivered one release-bound test notification
to the configured external HTTPS paging integration and that the integration returned
HTTP 2xx. It is an operations evidence workflow, not a deployment path: it neither creates
a subscription nor changes the alarm topic. Its twice-weekly monitor runs at
`17 3 * * 1,4` (Monday and Thursday at 03:17 UTC), leaving operational margin inside
SQ10's seven-day paging-proof freshness limit.

The result is intentionally narrower than “a person was paged.” SNS delivery-status logs
prove acceptance by the external HTTPS endpoint. They do not prove downstream provider
routing, a device notification, an on-call response, or human acknowledgement.

## Prerequisites

The current `Archon-production` stack must expose:

- `ArchonAlarmTopicArn`;
- `ArchonAlarmTopicKmsKeyArn`;
- `ArchonAlarmDeliveryFeedbackRoleArn`;
- `ArchonAlarmDeliveryLogGroupName`;
- `ArchonReleaseSha`;
- `ArchonDeploymentWorkflowRunId`; and
- `ArchonDeploymentWorkflowRunAttempt`.

The stack creates one KMS-encrypted, 365-day retained delivery-status log group.
SNS writes both successful and failed HTTP/S delivery records to protocol streams in
this group:

```text
sns/<region>/<account>/archon-production-alarms
```

The alarm topic configures the same SNS-assumable feedback role for success and failure
logging, uses the CloudFormation `http/s` delivery-status protocol, and samples 100% of
successful HTTP/S deliveries. CI's project-owned CloudFormation Guard policy rejects a
missing or cross-stage retained log group, partial success sampling, a different protocol,
or a missing, split, unretained, non-SNS-trusted, or cross-stage feedback role.

Create one confirmed SNS subscription whose protocol is exactly `https`, whose topic is
the production `ArchonAlarmTopicArn`, and whose endpoint is owned by the external paging
provider. The endpoint must return a 2xx response only after it has accepted the
notification. Do not use an email, SMS, SQS, Lambda, pending-confirmation, or application
callback subscription as this proof source.

## Protected GitHub environment

Create a protected environment named `production-paging-test`. Restrict deployment
branches to `master`, prevent administrator bypass where supported, and place no
long-lived AWS access keys in it. Configure:

| Variable | Contract |
| --- | --- |
| `AWS_ACCOUNT_ID` | Exact 12-digit production AWS account. |
| `AWS_REGION` | Workload region containing `Archon-production`. |
| `AWS_PAGING_TEST_ROLE_ARN` | Exact dedicated GitHub-OIDC role ARN ending in `role/archon-production-paging-test`. |
| `ALARM_SUBSCRIPTION_ARN` | Exact confirmed external HTTPS subscription on the production alarm topic. |

The AWS foundation creates the exact `archon-production-paging-test` role and
returns its ARN for this environment. No hand-managed paging or deploy-role
fallback is permitted.

The workflow accepts no dispatch inputs, secrets, URLs, endpoints, payloads, topic ARNs,
role ARNs, log-group names, or arbitrary JSON. Its unprivileged `control-plane` job derives
its workflow source and required repository gates from the exact current `master` SHA.
The protected `exercise` job derives the deployed release plus deployment run and attempt
only from the exact `Archon-production` outputs; callers cannot select or relabel them.

Each `exercise` producer run sends a real test notification. Do not configure a required
human reviewer if the scheduled proof must run unattended; the selected provider
integration must instead be explicitly test-safe. If organizational policy requires a
reviewer, keep self-review disabled and recognize that scheduled runs will wait for that
approval. Attester-only retries reuse the one retained producer artifact and do not
publish another notification. If a runner fails only after the immutable final artifact
has uploaded, rerun the complete workflow; this creates a new producer attempt and avoids
overwriting trusted evidence.

## OIDC and least-privilege IAM

The `archon-production-paging-test` role trust policy should accept only this repository, the
`repo:upgradedev/archon-datahub:environment:production-paging-test` subject, and the
`sts.amazonaws.com` GitHub OIDC audience. It must not be a deploy, posture, or runtime
observer role.

A representative identity policy is below. Replace every uppercase placeholder with the
exact protected-environment value and use the topic and log-group outputs from the
deployed stack.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DescribeExactProductionStack",
      "Effect": "Allow",
      "Action": "cloudformation:DescribeStacks",
      "Resource": "arn:aws:cloudformation:WORKLOAD_REGION:ACCOUNT_ID:stack/Archon-production/*"
    },
    {
      "Sid": "ReadExactPagingSubscription",
      "Effect": "Allow",
      "Action": "sns:GetSubscriptionAttributes",
      "Resource": "ARCHON_ALARM_TOPIC_ARN"
    },
    {
      "Sid": "ReadAndPublishOnlyArchonProductionAlarmTest",
      "Effect": "Allow",
      "Action": [
        "sns:GetTopicAttributes",
        "sns:Publish"
      ],
      "Resource": "ARCHON_ALARM_TOPIC_ARN"
    },
    {
      "Sid": "ReadOnlyExactAlarmDeliveryLogs",
      "Effect": "Allow",
      "Action": "logs:FilterLogEvents",
      "Resource": "arn:aws:logs:WORKLOAD_REGION:ACCOUNT_ID:log-group:sns/WORKLOAD_REGION/ACCOUNT_ID/archon-production-alarms:*"
    },
    {
      "Sid": "UseExactKeyForEncryptedAlarmPublish",
      "Effect": "Allow",
      "Action": [
        "kms:GenerateDataKey*",
        "kms:Decrypt"
      ],
      "Resource": "ARCHON_ALARM_TOPIC_KMS_KEY_ARN",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "sns.WORKLOAD_REGION.amazonaws.com",
          "kms:EncryptionContext:aws:sns:topicArn": "ARCHON_ALARM_TOPIC_ARN"
        }
      }
    },
    {
      "Sid": "UseExactKeyOnlyToReadCloudWatchDeliveryLogs",
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:ReEncrypt*",
        "kms:Decrypt",
        "kms:GenerateDataKey*",
        "kms:Describe*"
      ],
      "Resource": "ARCHON_ALARM_TOPIC_KMS_KEY_ARN",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "logs.WORKLOAD_REGION.amazonaws.com"
        }
      }
    }
  ]
}
```

`sts:GetCallerIdentity` needs no identity-policy grant. The workflow validates that the
OIDC session belongs to `AWS_ACCOUNT_ID`, resolves all mutable AWS identities from the
exact stack and subscription, and fails if a configured value disagrees. Do not add
subscription mutation, CloudWatch write, CloudFormation mutation, broad SNS publish, or
deployment permissions.
SNS authorizes `GetSubscriptionAttributes` against the owning topic resource even though
the API request names the exact subscription ARN.

## Delivery contract

One producer run:

1. binds the scheduled or manual event to the current default-branch release and its
   required successful repository gates;
2. enters `production-paging-test`, revalidates the control-plane receipt, and assumes the
   dedicated AWS role;
3. reads the exact production stack outputs, topic attributes, and confirmed subscription;
4. requires the subscription owner and topic to match `AWS_ACCOUNT_ID` and
   `ArchonAlarmTopicArn`, the protocol to be exactly `https`, and
   `PendingConfirmation` to be false;
5. publishes one bounded nonce-bound test notification with automatic retries disabled
   (an ambiguous non-idempotent publish fails closed) and records the returned SNS
   `MessageId`;
6. polls the exact delivery-status log group across all protocol streams for a bounded
   interval; and
7. counts every record with that exact `MessageId` and destination before checking
   content or status, accepts only one success record with a 2xx status and the SNS
   message-body MD5 equal to the exact published payload bytes, then repeats the complete
   paginated lookup after a stabilization delay to reject a late contradictory record.

No “publish succeeded” result is accepted as delivery proof. Absence, timeout, duplicate
or contradictory records, a failure record, a non-2xx response, endpoint drift, topic or
subscription drift, or a control-plane change fails the run. The workflow clears AWS
credentials before artifact upload and provenance signing.

The endpoint, notification body, provider response, raw CloudWatch event, account ID,
topic ARN, subscription ARN, role ARN, and log-group name are never uploaded. The retained
projection carries only the minimum timestamps, status/protocol facts, release/run
identity, and cryptographic hashes needed to bind it to the separately attested production
posture.

## Evidence

A successful producer run retains:

```text
production-paging-delivery-<release-sha>-<run-attempt>
```

for 90 days with this exact five-file inventory:

```text
SHA256SUMS
attestation-predicate.json
manifest.json
paging-delivery.json
paging-subject.sha256
```

`SHA256SUMS` inventories the other four files, and `paging-subject.sha256` names exactly
`paging-delivery.json` and `manifest.json`. The isolated `attest` job signs those two
subjects with:

```text
https://archon.datahub.dev/attestations/production-paging-delivery/v1
```

The attester resolves the immutable producer artifact independently through the GitHub
API, downloads it by numeric ID, verifies its name, ID, digest, run, run attempt, release,
exact file inventory, checksums, predicate, subjects, canonical timestamps and bounded
delivery interval, and repeats the control-plane checks before signing. It then verifies
both subjects back from GitHub's attestation service against the exact signer workflow,
source SHA/ref, predicate type, predicate bytes, and two-subject set before retaining the
artifact.
The SQ10 operations producer must additionally require fresh paging evidence and exact
topic/subscription-hash equality with the selected production-posture evidence.

This workflow definition is not proof that an endpoint is configured or that a test has
passed. The claim becomes active only after the protected environment, OIDC role,
confirmed provider subscription, deployed delivery logging, and successful retained
workflow artifact all exist.
