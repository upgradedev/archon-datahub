# Production posture verification

`.github/workflows/production-posture.yml` is the scheduled and manual, fail-closed
production posture gate. It does not deploy or repair resources. It observes the current
AWS deployment, starts CloudFormation drift detection, and retains a sanitized signed
statement only when all checks pass.

The workflow deliberately separates trust acquisition:

1. The unprivileged `control-plane` job verifies that its commit is still the exact
   `master` default-branch head.
2. It requires the latest exact-SHA `CI`, `CodeQL`, and `Workflow security` push runs to
   be completed successfully.
3. After protected-environment entry, `observe` checks out that exact commit and immediately
   re-queries the current `master` ref plus the latest exact-SHA gate attempts. Their
   canonical run-ID/run-attempt receipts must equal the sealed unprivileged receipts.
4. Only then may `observe` request short-lived AWS credentials through GitHub OIDC.
5. AWS credentials are cleared before the pinned official attestation and artifact actions
   run.

## GitHub environment

Create a protected environment named `production-observer`. Restrict deployment branches
to `master`, prevent administrator bypass where supported, and do not put long-lived AWS
keys in the repository or environment. Do not configure a required human reviewer on this
observer environment: both production posture and supply-chain rescans are scheduled and
must fail or complete without waiting for an approval. Human approval remains mandatory
on the separate `production` deployment environment.

Configure these environment variables:

| Variable | Contract |
|---|---|
| `AWS_ACCOUNT_ID` | Exact 12-digit production AWS account. |
| `AWS_REGION` | Workload region containing `Archon-Registry` and `Archon-production`. |
| `AWS_READ_ROLE_ARN` | Dedicated GitHub-OIDC posture/drift observer role in `AWS_ACCOUNT_ID`. It must not be a deployment role. |
| `AWS_RUNTIME_READ_ROLE_ARN` | Separate GitHub-OIDC runtime-byte observer role used only by `Production Supply Chain`. |
| `ALARM_SUBSCRIPTION_ARN` | Exact confirmed subscription attached to the `ArchonAlarmTopicArn` output of `Archon-production`. |

The AWS foundation creates both exact observer roles:
`archon-production-posture-observer` and
`archon-production-runtime-read`. Map their outputs to the two role variables
above; do not reuse the production deploy role.

`Archon-production-Edge` is always checked in `us-east-1`; it is not inferred from
`AWS_REGION`. The subscription must be owned by `AWS_ACCOUNT_ID`, must have
`PendingConfirmation=false`, and must expose a concrete SNS protocol. The workflow never
copies or uploads the subscription endpoint.

This posture check proves that the configured subscription exists and remains confirmed;
it does not publish a notification or claim successful delivery. The separate
[production paging delivery proof](PRODUCTION_PAGING_TEST.md) reuses the exact
`ALARM_SUBSCRIPTION_ARN`, requires its protocol to be `https`, and correlates one real
publish with a unique 2xx SNS delivery-status record.

## OIDC and IAM

Both observer-role trust policies should accept only this repository, the
`production-observer` environment subject
`repo:upgradedev/archon-datahub:environment:production-observer`, and the
`sts.amazonaws.com` GitHub OIDC audience. Keep the session read-only except for the
CloudFormation drift-detection request itself.

At minimum, the role needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DescribeAndDetectExactStacks",
      "Effect": "Allow",
      "Action": [
        "cloudformation:DescribeStacks",
        "cloudformation:DetectStackDrift",
        "cloudformation:DetectStackResourceDrift"
      ],
      "Resource": [
        "arn:aws:cloudformation:WORKLOAD_REGION:ACCOUNT_ID:stack/Archon-Registry/*",
        "arn:aws:cloudformation:WORKLOAD_REGION:ACCOUNT_ID:stack/Archon-production/*",
        "arn:aws:cloudformation:us-east-1:ACCOUNT_ID:stack/Archon-production-Edge/*"
      ]
    },
    {
      "Sid": "ListExactProductionStackResources",
      "Effect": "Allow",
      "Action": "cloudformation:ListStackResources",
      "Resource": "arn:aws:cloudformation:WORKLOAD_REGION:ACCOUNT_ID:stack/Archon-production/*"
    },
    {
      "Sid": "PollBoundedDriftOperations",
      "Effect": "Allow",
      "Action": [
        "cloudformation:BatchDescribeTypeConfigurations",
        "cloudformation:DescribeStackDriftDetectionStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DescribeOnlyOperationalAlarmPrefixes",
      "Effect": "Allow",
      "Action": "cloudwatch:DescribeAlarms",
      "Resource": [
        "arn:aws:cloudwatch:WORKLOAD_REGION:ACCOUNT_ID:alarm:Archon-production-Api5xxAlarm*",
        "arn:aws:cloudwatch:WORKLOAD_REGION:ACCOUNT_ID:alarm:Archon-production-ApiLatencyAlarm*",
        "arn:aws:cloudwatch:WORKLOAD_REGION:ACCOUNT_ID:alarm:Archon-production-ApiCpuAlarm*",
        "arn:aws:cloudwatch:WORKLOAD_REGION:ACCOUNT_ID:alarm:Archon-production-AuditDlqAlarm*",
        "arn:aws:cloudwatch:WORKLOAD_REGION:ACCOUNT_ID:alarm:Archon-production-ApprovalDlqAlarm*",
        "arn:aws:cloudwatch:WORKLOAD_REGION:ACCOUNT_ID:alarm:Archon-production-RemediationDlqAlarm*",
        "arn:aws:cloudwatch:WORKLOAD_REGION:ACCOUNT_ID:alarm:Archon-production-StateMachineFailuresAlarm*",
        "arn:aws:cloudwatch:WORKLOAD_REGION:ACCOUNT_ID:alarm:Archon-production-ApprovalLambdaErrorsAlarm*",
        "arn:aws:cloudwatch:WORKLOAD_REGION:ACCOUNT_ID:alarm:Archon-production-ApprovalHandoffLambdaErrorsAlarm*",
        "arn:aws:cloudwatch:WORKLOAD_REGION:ACCOUNT_ID:alarm:Archon-production-ControlLambdaErrorsAlarm*"
      ]
    },
    {
      "Sid": "ReadExactAlarmSubscription",
      "Effect": "Allow",
      "Action": "sns:GetSubscriptionAttributes",
      "Resource": "ARCHON_ALARM_TOPIC_ARN"
    }
  ]
}
```

Replace every uppercase placeholder with the protected environment's exact value.
`sts:GetCallerIdentity` does not require an identity-policy grant.
`cloudformation:DetectStackDrift` also invokes
`cloudformation:DetectStackResourceDrift` for the exact stack resources, so both actions
remain stack-ARN scoped. `cloudformation:BatchDescribeTypeConfigurations` and
`cloudformation:DescribeStackDriftDetectionStatus` do not support resource-level IAM
permissions; their read-only statement therefore uses `Resource: "*"`. These calls can
only resolve registered type configuration and poll the opaque drift-operation IDs created
by this run.
`cloudformation:ListStackResources` is scoped to the exact production stack ARN. The
workflow uses this paginated API instead of `DescribeStackResources`, whose response is
limited to the first 100 resources. `cloudwatch:DescribeAlarms` supports alarm-resource
permissions for named metric alarms. The request pins `AlarmTypes=["MetricAlarm"]`, so the
example limits it to the ten CDK-generated operational-alarm prefixes rather than the four
step-scaling alarms or the account-wide `Resource: "*"` needed to return composite alarms.
Do not broaden either read to account-wide access.
SNS authorizes `GetSubscriptionAttributes` against the owning topic resource even though
the API request itself names the exact subscription ARN.

CloudFormation must also be able to read the deployed resource types during drift
detection. Prefer an existing, dedicated CloudFormation service role on each stack with
only the read calls required by that stack's resource types. If a stack has no service
role, add only the resource-specific read actions reported by CloudFormation to the
observer role; do not grant wildcard write access or reuse the deploy role.

The same protected environment contains a separate `AWS_RUNTIME_READ_ROLE_ARN` used by
the scheduled production supply-chain workflow to prove that the retained CI subjects are
the bytes currently served by ECS, Lambda, and S3. Do not add these byte-read grants to
the posture role: keeping the two roles separate prevents the runtime observer from
requesting drift operations and prevents the posture observer from reading application
bytes. Give the runtime role `cloudformation:DescribeStacks` only for
`Archon-production`, plus these read-only statements using the exact stack outputs:

```json
[
  {
    "Sid": "DescribeExactRuntimeStack",
    "Effect": "Allow",
    "Action": "cloudformation:DescribeStacks",
    "Resource": "arn:aws:cloudformation:WORKLOAD_REGION:ACCOUNT_ID:stack/Archon-production/*"
  },
  {
    "Sid": "DescribeExactArchonServices",
    "Effect": "Allow",
    "Action": "ecs:DescribeServices",
    "Resource": [
      "arn:aws:ecs:WORKLOAD_REGION:ACCOUNT_ID:service/ECS_CLUSTER/API_SERVICE",
      "arn:aws:ecs:WORKLOAD_REGION:ACCOUNT_ID:service/ECS_CLUSTER/AUDIT_WORKER_SERVICE",
      "arn:aws:ecs:WORKLOAD_REGION:ACCOUNT_ID:service/ECS_CLUSTER/REMEDIATION_WORKER_SERVICE"
    ]
  },
  {
    "Sid": "ListOnlyArchonServiceTasks",
    "Effect": "Allow",
    "Action": "ecs:ListTasks",
    "Resource": "*",
    "Condition": {
      "ArnEquals": {
        "ecs:cluster": "arn:aws:ecs:WORKLOAD_REGION:ACCOUNT_ID:cluster/ECS_CLUSTER"
      }
    }
  },
  {
    "Sid": "DescribeOnlyArchonRunningTasks",
    "Effect": "Allow",
    "Action": "ecs:DescribeTasks",
    "Resource": "arn:aws:ecs:WORKLOAD_REGION:ACCOUNT_ID:task/ECS_CLUSTER/*"
  },
  {
    "Sid": "DescribeImmutableTaskDefinitions",
    "Effect": "Allow",
    "Action": "ecs:DescribeTaskDefinition",
    "Resource": "*"
  },
  {
    "Sid": "ReadExactArchonLambdaCodeAndConfiguration",
    "Effect": "Allow",
    "Action": [
      "lambda:GetFunction",
      "lambda:GetFunctionConfiguration"
    ],
    "Resource": [
      "arn:aws:lambda:WORKLOAD_REGION:ACCOUNT_ID:function:archon-production-approval",
      "arn:aws:lambda:WORKLOAD_REGION:ACCOUNT_ID:function:archon-production-approval-handoff",
      "arn:aws:lambda:WORKLOAD_REGION:ACCOUNT_ID:function:archon-production-control"
    ]
  },
  {
    "Sid": "ReadExactVersionedSpaInventory",
    "Effect": "Allow",
    "Action": [
      "s3:GetBucketVersioning",
      "s3:GetEncryptionConfiguration",
      "s3:ListBucketVersions"
    ],
    "Resource": "arn:aws:s3:::SPA_BUCKET"
  },
  {
    "Sid": "ReadExactVersionedSpaBytes",
    "Effect": "Allow",
    "Action": "s3:GetObjectVersion",
    "Resource": "arn:aws:s3:::SPA_BUCKET/*"
  },
  {
    "Sid": "DecryptSpaBytesOnlyThroughS3",
    "Effect": "Allow",
    "Action": "kms:Decrypt",
    "Resource": "SPA_KEY_ARN",
    "Condition": {
      "StringEquals": {
        "kms:CallerAccount": "ACCOUNT_ID",
        "kms:ViaService": "s3.WORKLOAD_REGION.amazonaws.com"
      },
      "StringLike": {
        "kms:EncryptionContext:aws:s3:arn": [
          "arn:aws:s3:::SPA_BUCKET",
          "arn:aws:s3:::SPA_BUCKET/*"
        ]
      }
    }
  }
]
```

`ECS_CLUSTER`, the three service names, `SPA_BUCKET`, and `SPA_KEY_ARN` come from
`ArchonEcsClusterName`, the three `Archon*ServiceName` outputs,
`ArchonSpaBucketName`, and `ArchonSpaKeyArn`. `ecs:ListTasks` and
`ecs:DescribeTaskDefinition` require `Resource: "*"` in the AWS authorization model;
the former is constrained to the exact cluster, while the latter remains read-only. The
SPA KMS key policy must also admit this observer role under the same S3-only conditions.
Lambda code is downloaded through the short-lived URL returned by `GetFunction`; it
does not require an additional S3 permission.

## Enforced runtime contract

All three stacks must already exist, be in an explicitly allowed stable non-deleting
status, and have `EnableTerminationProtection=true`:

- `Archon-Registry` in `AWS_REGION`
- `Archon-production` in `AWS_REGION`
- `Archon-production-Edge` in `us-east-1`

The workflow launches all three drift detections before polling them, then permits at most
90 ten-second polling rounds. Every result must be `DETECTION_COMPLETE` and `IN_SYNC`.
It re-reads each stack and requires its identity, status, termination-protection flag,
timestamps, and canonical output-set digest to be unchanged.

For `Archon-production`, both the initial and final observations paginate
`ListStackResources` against the immutable stack ID, derive every direct
`AWS::CloudWatch::Alarm` physical resource, and require the exact current topology:
fourteen unique, stable stack alarm resources, comprising ten explicit operational alarms
and four upper/lower alarms generated by the two worker step-scaling policies. The ten
operational resources are selected by the exact CDK logical-ID-prefix allowlist, not by
their current actions; boundary tests cross-check that allowlist against the IaC source and
the synthesized fourteen-alarm contract. Each selected physical alarm name must start with
`Archon-production-<full-logical-ID>`, which also binds the runtime selection to the ten
IAM alarm-ARN prefixes above.

One exact-name `DescribeAlarms` request must return those same ten operational metric
alarms with no missing, substituted, composite, or log alarms and no continuation token.
Every operational alarm must have `ActionsEnabled=true`, `AlarmActions` exactly equal to
the one-element
`[ArchonAlarmTopicArn]` array, `OKActions` exactly equal to that same array, and
`InsufficientDataActions` exactly empty. The canonical resource/action inventory must be
byte-for-byte identical in the late observation; it includes all fourteen CloudFormation
alarm identities and the exact action projection of the ten operational alarms. The
workflow also re-reads the exact SNS subscription and requires its sanitized
owner/protocol/confirmation projection to be unchanged. Any absence, drift, unstable
status, timeout, pagination anomaly, inventory or action mismatch, or mid-run change fails
the job.

## Evidence

A successful run uploads `production-posture-<control-plane-sha>-<run-attempt>` for
90 days and signs `production-posture.json` with this exact predicate type:

`https://github.com/upgradedev/archon-datahub/attestations/production-posture/v1`

The artifact includes the exact workflow gate receipts, sanitized posture JSON, a manifest,
the attestation predicate, and strict SHA-256 checksums. It records hashes of the observer
role, stack drift-detection identifiers, alarm topic ARN, and subscription ARN instead of
the original values. The raw alarm names, logical IDs, ARNs, and action arrays remain only
in the runner's temporary observation workspace. Evidence exposes their canonical
SHA-256 inventory digest, observation timestamp, exact operational count of ten, and four
fail-closed action conclusions. The same timestamp, inventory digest, topic hash, and
subscription hash are copied into the checksum-sealed manifest and signed attestation
predicate. It records the SNS owner and protocol needed to prove that the subscription is
concrete, but never stores its endpoint or message-delivery data. SQ10 accepts
external-paging status only when separately attested paging evidence has the same
topic/subscription hashes; a posture boolean or successful SNS publish is insufficient.

The workflow is evidence, not remediation. A failure must be investigated and corrected
through the normal reviewed infrastructure/deployment pipeline before rerunning it.

The daily `Production Supply Chain` workflow adds byte-level proof beyond CloudFormation
drift. It downloads the exact retained deployment artifact by numeric artifact ID and
GitHub SHA-256 digest, verifies its canonical live-runtime manifest against a fresh
read-only AWS observation, scans the exact retained CI container/SPA/Lambda subjects, and
then repeats the AWS observation before signing. The manifest covers immutable ECS task
definitions and running image digests, Lambda ZIP/content/configuration digests, and every
current versioned KMS-encrypted SPA object. Each observation re-reads the bucket's
versioning and default KMS-encryption projection after reading the objects. Its final
evidence bundle contains the sealed deployment manifest, the post-scan observation, the
resolver's exact-equality binding, the deployed runtime configuration, the deployment and
observer control-plane gate receipts, and strict checksums. The observer whole-snapshot
receipt is revalidated after checkout before each OIDC trust boundary and once more against
the sealed receipt immediately before provenance signing. The workflow then independently
reads the latest CodeQL and workflow-security runs for the exact deployed historical source
SHA twice and requires both snapshots to equal its sealed source-gate receipt; that source
SHA need not still be current `master`. Any mid-scan branch, gate, or runtime change fails
closed.

Each ECS observation permits at most three whole-snapshot attempts with five- and
ten-second backoffs. A failed attempt's service, task-definition, and task receipts are
deleted together and never reused; only one complete canonical snapshot can proceed to the
initial/final semantic comparison.
