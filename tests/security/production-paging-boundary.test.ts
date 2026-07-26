import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const workflow = readFileSync(
  new URL(
    "../../.github/workflows/production-paging-test.yml",
    import.meta.url
  ),
  "utf8"
);
const controlPlaneVerifier = readFileSync(
  new URL("../../scripts/verify-github-control-plane.sh", import.meta.url),
  "utf8"
);

const expectedVariables = [
  "ALARM_SUBSCRIPTION_ARN",
  "AWS_ACCOUNT_ID",
  "AWS_PAGING_TEST_ROLE_ARN",
  "AWS_REGION"
];

type PagingJobs = {
  controlPlane: string;
  exercise: string;
  attest: string;
};

function count(source: string, expression: RegExp): number {
  const flags = expression.flags.includes("g")
    ? expression.flags
    : `${expression.flags}g`;
  return [...source.matchAll(new RegExp(expression.source, flags))].length;
}

function jobsOf(source: string): PagingJobs {
  const jobsStart = source.indexOf("\njobs:\n");
  assert.ok(jobsStart > 0, "workflow must have a jobs mapping");
  const jobsSource = source.slice(jobsStart + 1);
  const jobNames = [
    ...jobsSource.matchAll(/^  ([a-z][a-z0-9-]*):\s*$/gmu)
  ].map((match) => match[1]!);
  assert.deepEqual(jobNames, ["control-plane", "exercise", "attest"]);

  const controlPlaneStart = source.indexOf("\n  control-plane:", jobsStart);
  const exerciseStart = source.indexOf("\n  exercise:", controlPlaneStart);
  const attestStart = source.indexOf("\n  attest:", exerciseStart);
  assert.ok(controlPlaneStart > jobsStart);
  assert.ok(exerciseStart > controlPlaneStart);
  assert.ok(attestStart > exerciseStart);

  return {
    controlPlane: source.slice(controlPlaneStart, exerciseStart),
    exercise: source.slice(exerciseStart, attestStart),
    attest: source.slice(attestStart)
  };
}

function assertOrdered(source: string, markers: readonly string[]): void {
  let cursor = -1;
  for (const marker of markers) {
    const next = source.indexOf(marker, cursor + 1);
    assert.ok(next > cursor, `missing or out-of-order marker: ${marker}`);
    cursor = next;
  }
}

function replaceRequired(
  source: string,
  original: string,
  replacement: string
): string {
  assert.equal(
    source.split(original).length - 1,
    1,
    `mutation anchor must occur exactly once: ${original}`
  );
  return source.replace(original, replacement);
}

function replaceFirstRequired(
  source: string,
  original: string,
  replacement: string
): string {
  assert.ok(source.includes(original), `missing mutation anchor: ${original}`);
  return source.replace(original, replacement);
}

function removeRequired(source: string, original: string): string {
  return replaceRequired(source, original, "");
}

function escapeRegExp(source: string): string {
  return source.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function exactStringArray(values: readonly string[]): RegExp {
  const entries = values
    .map((value) => `"${escapeRegExp(value)}"`)
    .join(",\\s*");
  return new RegExp(`\\[\\s*${entries}\\s*\\]`, "u");
}

function sliceRequired(
  source: string,
  startMarker: string,
  endMarker: string
): string {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(start >= 0, `missing slice start: ${startMarker}`);
  assert.ok(end > start, `missing slice end: ${endMarker}`);
  return source.slice(start, end);
}

function assertWorkflowEnvelope(source: string): void {
  assert.match(source, /^name: Production paging delivery$/mu);
  assert.match(source, /^on:\n  schedule:/mu);
  assert.match(source, /^\s{4}- cron: "17 3 \* \* 1,4"$/mu);
  assert.match(source, /^\s{2}workflow_dispatch:\s*$/mu);
  assert.doesNotMatch(
    source,
    /^\s{2}(?:push|pull_request|workflow_run|repository_dispatch):/mu
  );
  assert.doesNotMatch(source, /^\s{4}inputs:/mu);
  assert.doesNotMatch(source, /\$\{\{\s*inputs\./u);
  assert.doesNotMatch(source, /\$\{\{\s*secrets\./u);
  assert.doesNotMatch(source, /\b(?:curl|wget)\b|--endpoint-url/u);
  assert.doesNotMatch(source, /\b(?:PAGING|TARGET|WEBHOOK)_URL\b/u);
  assert.match(source, /^permissions: \{\}$/mu);
  assert.equal(count(source, /^permissions: \{\}$/mu), 1);
  assert.match(
    source,
    /^concurrency:\n  group: archon-production-paging-delivery\n  cancel-in-progress: false$/mu
  );
  assert.match(
    source,
    /^  PREDICATE_TYPE: https:\/\/archon\.datahub\.dev\/attestations\/production-paging-delivery\/v1$/mu
  );

  const jobs = jobsOf(source);
  assert.match(
    jobs.controlPlane,
    /permissions:\n      actions: read\n      contents: read\n/u
  );
  assert.match(
    jobs.exercise,
    /permissions:\n      actions: read\n      contents: read\n      id-token: write\n/u
  );
  assert.match(
    jobs.attest,
    /permissions:\n      actions: read\n      attestations: write\n      contents: read\n      id-token: write\n/u
  );
  assert.doesNotMatch(jobs.controlPlane, /id-token:\s+write/u);
  assert.doesNotMatch(
    jobs.controlPlane,
    /configure-aws-credentials|\baws\s+(?:cloudformation|logs|sns|sts)\b/u
  );
  assert.match(jobs.exercise, /needs: control-plane/u);
  assert.match(jobs.exercise, /^\s{4}environment: production-paging-test$/mu);
  assert.match(jobs.exercise, /id-token:\s+write/u);
  assert.match(jobs.attest, /needs: exercise/u);
  assert.match(jobs.attest, /attestations:\s+write/u);
  assert.match(jobs.attest, /id-token:\s+write/u);
  assert.doesNotMatch(jobs.attest, /^\s{4}environment:/mu);
  assert.doesNotMatch(
    jobs.attest,
    /configure-aws-credentials|\baws\s+(?:cloudformation|logs|sns|sts)\b/u
  );

  assert.equal(count(source, /^\s{4}environment:/mu), 1);
  assert.doesNotMatch(
    source,
    /AWS_(?:DEPLOY|READ|POSTURE)_ROLE_ARN|production-(?:deploy|observer|posture)/u
  );

  const variables = [
    ...source.matchAll(/\$\{\{\s*vars\.([A-Z][A-Z0-9_]*)\s*\}\}/gu)
  ].map((match) => match[1]!);
  assert.deepEqual([...new Set(variables)].sort(), expectedVariables);
  assert.match(
    jobs.exercise,
    /role-to-assume: \$\{\{ vars\.AWS_PAGING_TEST_ROLE_ARN \}\}/u
  );
  assert.equal(count(source, /^\s+role-to-assume:/mu), 1);
}

function assertControlPlaneBoundary(source: string): void {
  const jobs = jobsOf(source);

  assert.match(
    controlPlaneVerifier,
    /EXPECTED_BRANCH="\$\{EXPECTED_BRANCH:-master\}"/u
  );
  assert.match(
    controlPlaneVerifier,
    /test "\$\(read_current_branch_sha\)" = "\$\{CONTROL_PLANE_SHA\}"/u
  );
  assert.match(controlPlaneVerifier, /^ci\.yml\|CI$/mu);
  assert.match(controlPlaneVerifier, /^codeql\.yml\|CodeQL$/mu);
  assert.match(controlPlaneVerifier, /^workflow-security\.yml\|Workflow security$/mu);
  assert.match(
    controlPlaneVerifier,
    /sort_by\(\.id, \.run_attempt\)\s+\|\s+last/u
  );
  assert.doesNotMatch(controlPlaneVerifier, /max_by\(\.id\)/u);

  assert.match(jobs.controlPlane, /verify-github-control-plane\.sh/u);
  assert.match(jobs.controlPlane, /gate_receipt_sha256/u);
  assert.match(jobs.controlPlane, /base64 --wrap=0/u);
  assert.match(jobs.exercise, /verify-github-control-plane\.sh/u);
  assert.match(jobs.exercise, /EXPECTED_GATE_SHA256:/u);
  assert.match(jobs.exercise, /CONTROL_PLANE_SHA:/u);
  assert.match(
    jobs.exercise,
    /test "\$\(git rev-parse HEAD\)" = "\$\{CONTROL_PLANE_SHA\}"/u
  );
  assert.match(jobs.exercise, /ref: \$\{\{ github\.sha \}\}/u);
  assert.match(jobs.exercise, /persist-credentials: false/u);
  assert.match(jobs.exercise, /VERIFICATION_MODE: sealed/u);
  assert.match(jobs.exercise, /SEALED_GATE_PATH:/u);
  assert.match(jobs.exercise, /cmp --silent "\$\{OUTPUT_PATH\}" "\$\{SEALED_GATE_PATH\}"/u);

  const protectedConfiguration = jobs.exercise.indexOf(
    "Validate protected paging configuration"
  );
  const checkout = jobs.exercise.indexOf(
    "Check out the exact protected paging control plane"
  );
  const gate = jobs.exercise.indexOf(
    "Revalidate exact control plane before AWS trust"
  );
  const oidc = jobs.exercise.indexOf(
    "Acquire short-lived dedicated paging credentials"
  );
  assert.ok(protectedConfiguration >= 0);
  assert.ok(checkout > protectedConfiguration);
  assert.ok(gate > checkout);
  assert.ok(oidc > gate);
  assert.match(
    jobs.exercise.slice(gate, oidc),
    /bash scripts\/verify-github-control-plane\.sh/u
  );
}

function assertAwsBindings(source: string): void {
  const { exercise } = jobsOf(source);

  assert.match(
    exercise,
    /uses: aws-actions\/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c/u
  );
  assert.match(exercise, /role-duration-seconds: 900/u);
  assert.match(
    exercise,
    /allowed-account-ids: \$\{\{ vars\.AWS_ACCOUNT_ID \}\}/u
  );
  assert.match(exercise, /aws-region: \$\{\{ vars\.AWS_REGION \}\}/u);
  assert.match(exercise, /mask-aws-account-id: true/u);
  assert.match(exercise, /unset-current-credentials: true/u);
  assert.match(
    exercise,
    /expected_paging_role_arn="arn:\$\{partition\}:iam::\$\{EXPECTED_ACCOUNT_ID\}:role\/archon-production-paging-test"/u
  );
  assert.match(
    exercise,
    /test "\$\{PAGING_ROLE_ARN\}" =\s+\\\s+"\$\{expected_paging_role_arn\}"/u
  );
  assert.match(
    exercise,
    /role-session-name: archon-production-paging-\$\{\{ github\.run_id \}\}/u
  );
  assert.match(
    exercise,
    /test -z "\$\{AWS_ACCESS_KEY_ID:-\}"[\s\S]+Acquire short-lived dedicated paging credentials/u
  );
  assert.match(exercise, /aws sts get-caller-identity/u);
  assert.match(exercise, /\.Account == \$account/u);
  assert.match(
    exercise,
    /expected_caller_arn="arn:\$\{partition\}:sts::\$\{EXPECTED_ACCOUNT_ID\}:assumed-role\/archon-production-paging-test\/archon-production-paging-\$\{GITHUB_RUN_ID\}"/u
  );
  assert.match(exercise, /\.Arn == \$callerArn/u);
  assert.match(exercise, /endswith\(":" \+ \$sessionName\)/u);
  assert.doesNotMatch(
    exercise,
    /\baws\s+(?:cloudformation\s+(?:create|delete|update)|sns\s+(?:subscribe|unsubscribe|set-subscription-attributes|set-topic-attributes))\b/u
  );

  assert.match(exercise, /Archon-production/u);
  assert.match(exercise, /aws cloudformation describe-stacks/u);
  for (const outputName of [
    "ArchonAlarmTopicArn",
    "ArchonAlarmDeliveryFeedbackRoleArn",
    "ArchonAlarmTopicKmsKeyArn",
    "ArchonAlarmDeliveryLogGroupName",
    "ArchonReleaseSha",
    "ArchonDeploymentWorkflowRunId",
    "ArchonDeploymentWorkflowRunAttempt"
  ]) {
    assert.match(exercise, new RegExp(outputName, "u"));
  }
  assert.match(exercise, /aws sns get-subscription-attributes/u);
  assert.match(exercise, /aws sns get-topic-attributes/u);
  assert.match(exercise, /\.Attributes\.TopicArn == \$topic/u);
  assert.match(exercise, /\.Attributes\.Protocol == "https"/u);
  assert.match(exercise, /\.Attributes\.PendingConfirmation == "false"/u);
  assert.match(exercise, /\.Attributes\.Owner == \$account/u);
  assert.match(
    exercise,
    /\(\(\.Attributes\.FilterPolicy \/\/ "\{\}"\) \| fromjson\) ==\s+\{\}/u
  );
  assert.match(
    exercise,
    /\.Attributes\.HTTPSuccessFeedbackRoleArn ==\s+\$feedbackRole/u
  );
  assert.match(
    exercise,
    /\.Attributes\.HTTPFailureFeedbackRoleArn ==\s+\$feedbackRole/u
  );
  assert.match(
    exercise,
    /\.Attributes\.HTTPSuccessFeedbackSampleRate == "100"/u
  );
  assert.match(
    exercise,
    /\.Attributes\.KmsMasterKeyId == \$topicKmsKeyArn/u
  );
  assertOrdered(exercise, [
    'endpoint="$(',
    'escaped_endpoint="${endpoint//%/%25}"',
    "escaped_endpoint=\"${escaped_endpoint//$'\\r'/%0D}\"",
    "escaped_endpoint=\"${escaped_endpoint//$'\\n'/%0A}\"",
    "printf '::add-mask::%s\\n' \"${escaped_endpoint}\""
  ]);
  assert.doesNotMatch(exercise, /::add-mask::\$\{endpoint\}/u);
}

function assertDeliveryProof(source: string): void {
  const { exercise } = jobsOf(source);

  assert.equal(count(exercise, /\baws sns publish\b/u), 1);
  assert.match(exercise, /nonce/u);
  assert.match(exercise, /message_id/u);
  assert.match(exercise, /--topic-arn/u);
  assert.equal(count(exercise, /AWS_MAX_ATTEMPTS=1/u), 1);
  assert.match(
    exercise,
    /AWS_MAX_ATTEMPTS=1\s+\\\s+AWS_RETRY_MODE=standard\s+\\\s+aws sns publish/u
  );
  assert.match(
    exercise,
    /published_at="\$\(date --utc \+'%Y-%m-%dT%H:%M:%SZ'\)"[\s\S]+published_epoch="\$\(\s+date --utc --date="\$\{published_at\}" \+%s\s+\)"\s+start_time_ms="\$\(\(published_epoch \* 1000 - 300000\)\)"/u
  );
  assert.match(exercise, /--message "file:\/\/\$\{payload_path\}"/u);
  assert.match(
    exercise,
    /--subject "Archon synthetic paging delivery test"/u
  );
  const payloadStart = exercise.indexOf(
    'payload_path="${work_dir}/synthetic-paging-message.json"'
  );
  const publish = exercise.indexOf('publish_result="$(', payloadStart);
  assert.ok(payloadStart > 0);
  assert.ok(publish > payloadStart);
  const payloadConstruction = exercise.slice(payloadStart, publish);
  assert.match(
    payloadConstruction,
    /archon\.synthetic-paging-delivery-test\/v1/u
  );
  assert.match(payloadConstruction, /severity: "test"/u);
  assert.match(payloadConstruction, /no action required/u);
  assert.match(payloadConstruction, /nonce: \$nonce/u);
  assert.doesNotMatch(
    payloadConstruction,
    /endpoint|subscription|topicArn|feedbackRole|logGroup|accountId/iu
  );
  assert.match(exercise, /md5sum "\$\{payload_path\}"/u);
  assert.match(
    exercise,
    /\[\[ "\$\{payload_md5\}" =~ \^\[0-9a-f\]\{32\}\$ \]\]/u
  );

  const publishCommand = exercise.indexOf("aws sns publish", publish);
  const poll = exercise.indexOf("logs filter-log-events", publishCommand);
  assert.ok(publishCommand > publish);
  assert.ok(publish > 0);
  assert.ok(poll > publishCommand);
  assert.match(exercise.slice(publishCommand), /for page in \{1\.\.100\}/u);
  assert.match(
    exercise.slice(publishCommand),
    /limit: 100,[\s\S]+logGroupName: \$logGroupName,[\s\S]+startTime: \(\$startTime \| tonumber\)/u
  );
  assert.match(
    exercise.slice(publishCommand),
    /else \{nextToken: \$nextToken\}/u
  );
  assert.match(
    exercise.slice(publishCommand),
    /--cli-input-json "file:\/\/\$\{request_file\}"/u
  );
  assert.match(exercise.slice(publishCommand), /--no-paginate/u);
  assert.doesNotMatch(exercise.slice(publishCommand), /^\s+--next-token /mu);
  assert.doesNotMatch(exercise.slice(publishCommand), /^\s+--limit /mu);
  assert.match(
    exercise.slice(publishCommand),
    /test "\$\{next_token\}" != "\$\{previous_token\}"/u
  );
  assert.match(
    exercise.slice(publishCommand),
    /jq -r '\.nextToken \/\/ empty'/u
  );
  assert.match(
    exercise.slice(publishCommand),
    /if \(\( page == 100 \)\); then/u
  );
  assert.match(exercise.slice(publishCommand), /for poll_attempt in \{1\.\.36\}/u);
  assert.doesNotMatch(exercise, /\/Failure|failure_delivery_log_group/u);
  assert.equal(
    count(exercise.slice(publishCommand), /collect_matching_delivery_events\s+\\/u),
    2
  );
  assert.match(exercise.slice(publishCommand), /sleep 10/u);
  assert.equal(count(exercise.slice(publishCommand), /sleep 30/u), 1);
  assert.doesNotMatch(exercise.slice(publishCommand), /while true/u);

  assert.match(exercise.slice(poll), /MessageId|messageId/u);
  assert.match(
    exercise.slice(poll),
    /\$message\.notification\.messageId ==\s+\$messageId/u
  );
  assert.match(
    exercise.slice(poll),
    /\$message\.delivery\.destination ==\s+\$destination/u
  );
  assert.match(
    exercise.slice(poll),
    /messageMD5Sum:\s+\$message\.notification\.messageMD5Sum/u
  );
  const exactMatchStart = exercise.indexOf("select(", poll);
  const exactMatchEnd = exercise.indexOf(
    ") |\n                  {",
    exactMatchStart
  );
  assert.ok(exactMatchStart >= poll);
  assert.ok(exactMatchEnd > exactMatchStart);
  const exactMatchSelection = exercise.slice(
    exactMatchStart,
    exactMatchEnd
  );
  assert.doesNotMatch(
    exactMatchSelection,
    /messageMD5Sum|\.status|statusCode|SUCCESS|FAILURE/u
  );
  assert.equal(
    count(
      exercise.slice(poll),
      /\.\[0\]\.messageMD5Sum == \$payloadMd5/u
    ),
    2
  );
  assert.match(exercise.slice(poll), /SUCCESS/u);
  assert.match(exercise.slice(poll), /statusCode/u);
  assert.match(exercise.slice(poll), />= 200/u);
  assert.match(exercise.slice(poll), /<= 299/u);
  assert.match(exercise.slice(poll), /destination/u);
  assert.match(exercise.slice(poll), /length == 1/u);
  assert.match(exercise.slice(poll), /unique_by\(\.eventId\)/u);
  assertOrdered(exercise.slice(poll), [
    "if (( match_count > 1 )); then",
    "if (( match_count == 1 )); then",
    'test "${delivery_found}" = "true"',
    "length == 1 and",
    ".[0].messageMD5Sum == $payloadMd5",
    '.[0].status == "SUCCESS"',
    ".[0].statusCode >= 200",
    ".[0].statusCode <= 299",
    "sleep 30",
    "collect_matching_delivery_events \\",
    "length == 1 and",
    ".[0].messageMD5Sum == $payloadMd5",
    '.[0].status == "SUCCESS"',
    ".[0].statusCode >= 200",
    ".[0].statusCode <= 299"
  ]);
}

function assertEvidenceBoundary(source: string): void {
  const jobs = jobsOf(source);
  const { exercise, attest } = jobs;
  const producerValidation = sliceRequired(
    exercise,
    "Revalidate canonical package without AWS credentials",
    "Retain unsigned exact paging candidate"
  );
  const independentValidation = sliceRequired(
    attest,
    "Independently validate exact paging bytes and semantics",
    "Recheck artifact and control plane before attestation"
  );

  const predicateKeys = [
    "controlPlaneGateReceiptSha256",
    "releaseSha",
    "repository",
    "schemaVersion",
    "subjects",
    "verificationResult",
    "workflow"
  ];
  const manifestKeys = [
    "controlPlaneGateReceiptSha256",
    "files",
    "releaseSha",
    "repository",
    "schemaVersion",
    "subjectCount",
    "subjects",
    "workflow"
  ];
  const pagingKeys = [
    "controlPlane",
    "delivery",
    "deployment",
    "releaseSha",
    "repository",
    "schemaVersion",
    "target",
    "verification",
    "workflow"
  ];
  const deploymentKeys = [
    "stackOutputSetSha256",
    "workflowRunAttempt",
    "workflowRunId"
  ];
  const controlPlaneKeys = ["gateReceiptSha256", "gates", "sourceSha"];
  const workflowKeys = ["path", "producerAttempt", "runId"];
  const targetKeys = [
    "awsAccountIdSha256",
    "endpointSha256",
    "feedbackRoleArnSha256",
    "logGroupNameSha256",
    "protocol",
    "region",
    "subscriptionArnSha256",
    "successFeedbackSampleRate",
    "topicArnSha256",
    "topicKmsEncrypted",
    "topicKmsKeyArnSha256"
  ];
  const deliveryKeys = [
    "deliveredAt",
    "deliveryEventTimestamp",
    "destinationMatched",
    "dwellTimeMs",
    "exactMessageIdMatched",
    "externalHttpsAccepted",
    "messageIdSha256",
    "nonceSha256",
    "observedAt",
    "payloadSha256",
    "publishedAt",
    "status",
    "statusCode",
    "syntheticTest",
    "uniqueDestinationMatch"
  ];
  const verificationKeys = [
    "boundedPoll",
    "completePagination",
    "stackUnchanged",
    "subscriptionUnchanged",
    "topicUnchanged"
  ];
  for (const validator of [producerValidation, independentValidation]) {
    for (const [keys, expectedCount] of [
      [predicateKeys, 1],
      [manifestKeys, 1],
      [pagingKeys, 1],
      [deploymentKeys, 1],
      [controlPlaneKeys, 1],
      [workflowKeys, 3],
      [targetKeys, 1],
      [deliveryKeys, 1],
      [verificationKeys, 1]
    ] as const) {
      assert.equal(count(validator, exactStringArray(keys)), expectedCount);
    }
    assert.match(
      validator,
      /\.schemaVersion ==\s+"archon\.production-paging-delivery-attestation\/v1"/u
    );
    assert.match(
      validator,
      /\.schemaVersion ==\s+"archon\.production-paging-delivery-manifest\/v1"/u
    );
    assert.match(
      validator,
      /\.schemaVersion ==\s+"archon\.production-paging-delivery\/v1"/u
    );
    assert.equal(
      count(validator, /\.repository == "upgradedev\/archon-datahub"/u),
      3
    );
    assert.equal(
      count(
        validator,
        /\.workflow\.path ==\s+"\.github\/workflows\/production-paging-test\.yml"/u
      ),
      3
    );
    assert.match(
      validator,
      /\.subjects == \{\s+"manifest\.json": \$manifestSha,\s+"paging-delivery\.json": \$pagingSha\s+\}/u
    );
    assert.match(
      validator,
      /\.files == \{\s+"paging-delivery\.json": \$pagingSha\s+\}/u
    );
    assert.match(
      validator,
      new RegExp(
        `\\.subjects ==\\s*${exactStringArray([
          "manifest.json",
          "paging-delivery.json"
        ]).source}`,
        "u"
      )
    );
    assert.match(validator, /\.subjectCount == 2/u);
    assert.match(validator, /\.target\.protocol == "https"/u);
    assert.match(
      validator,
      /\.target\.region \|\s+type == "string" and\s+test\("\^\[a-z\]\{2\}\(-gov\)\?-\[a-z\]\+-\[0-9\]\+\$"\)/u
    );
    assert.match(
      validator,
      /\.target\.successFeedbackSampleRate == 100/u
    );
    assert.match(validator, /\.target\.topicKmsEncrypted == true/u);
    assert.match(validator, /\.delivery\.syntheticTest == true/u);
    assert.match(validator, /\.delivery\.externalHttpsAccepted == true/u);
    assert.match(validator, /\.delivery\.destinationMatched == true/u);
    assert.match(validator, /\.delivery\.exactMessageIdMatched == true/u);
    assert.match(validator, /\.delivery\.uniqueDestinationMatch == true/u);
    assert.match(validator, /\.delivery\.status == "SUCCESS"/u);
    assert.match(validator, /\.verification\.completePagination == true/u);
    assert.match(validator, /\.verification\.boundedPoll == true/u);
    assert.match(validator, /\.verification\.stackUnchanged == true/u);
    assert.match(validator, /\.verification\.topicUnchanged == true/u);
    assert.match(
      validator,
      /\.verification\.subscriptionUnchanged == true/u
    );
    assert.match(validator, /canonical_utc_timestamp\(\)/u);
    assert.ok(
      validator.includes(
        '[[ "${value}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]'
      )
    );
    assert.match(
      validator,
      /date --utc\s+\\\s+--date="\$\{value\}"\s+\\\s+\+'%Y-%m-%dT%H:%M:%SZ'/u
    );
    for (const timestamp of ["published_at", "delivered_at", "observed_at"]) {
      assert.match(
        validator,
        new RegExp(
          `canonical_utc_timestamp "\\$\\{${timestamp}\\}"`,
          "u"
        )
      );
    }
    assert.match(
      validator,
      /\(\( delivered_epoch == delivery_event_timestamp \/ 1000 \)\)/u
    );
    assert.match(
      validator,
      /\(\( delivered_epoch >= published_epoch - 300 \)\)/u
    );
    assert.match(
      validator,
      /\(\( delivered_epoch <= published_epoch \+ 420 \)\)/u
    );
    assert.match(
      validator,
      /\(\( delivered_epoch <= observed_epoch \+ 300 \)\)/u
    );
    assert.match(
      validator,
      /\(\( observed_epoch <= delivered_epoch \+ 900 \)\)/u
    );
    assert.match(validator, /\(\( observed_epoch <= now_epoch \+ 300 \)\)/u);
    assert.match(validator, /\(\( now_epoch - observed_epoch <= 7200 \)\)/u);
    assert.equal(count(validator, /jq -se '/u), 1);
    assert.match(validator, /\.\. \|\s+objects \|\s+keys\[\]/u);
    assert.match(
      validator,
      /"\$\{(?:EVIDENCE_DIR|evidence_dir)\}"\/\*\.json/u
    );
  }

  for (const sanitizedDigest of [
    "awsAccountIdSha256",
    "topicArnSha256",
    "subscriptionArnSha256",
    "endpointSha256",
    "feedbackRoleArnSha256",
    "logGroupNameSha256",
    "topicKmsKeyArnSha256",
    "payloadSha256",
    "nonceSha256",
    "messageIdSha256"
  ]) {
    assert.match(exercise, new RegExp(sanitizedDigest, "u"));
  }
  assert.match(exercise, /topicArnSha256/u);
  assert.match(exercise, /subscriptionArnSha256/u);
  assert.match(exercise, /externalHttpsAccepted: true/u);
  assert.match(exercise, /destinationMatched: true/u);
  assert.match(exercise, /exactMessageIdMatched: true/u);
  assert.match(exercise, /uniqueDestinationMatch: true/u);
  assert.match(exercise, /status: "SUCCESS"/u);
  assert.match(exercise, /statusCode:/u);
  assert.match(exercise, /observedAt/u);
  assert.match(exercise, /sha256sum --check --strict SHA256SUMS/u);
  for (const retainedPath of [
    "SHA256SUMS",
    "attestation-predicate.json",
    "manifest.json",
    "paging-delivery.json",
    "paging-subject.sha256"
  ]) {
    assert.match(exercise, new RegExp(retainedPath.replace(".", "\\."), "u"));
  }
  assert.match(
    exercise,
    /test "\$\(wc -l <SHA256SUMS\)" = "4"/u
  );
  assert.match(
    exercise,
    /attestation-predicate\.json manifest\.json paging-delivery\.json paging-subject\.sha256/u
  );
  assert.match(
    exercise,
    /test "\$\(wc -l <paging-subject\.sha256\)" = "2"/u
  );
  assert.match(
    exercise,
    /\)\" = "paging-delivery\.json manifest\.json"/u
  );
  const retainedProjectionStart = exercise.indexOf("--slurpfile gates");
  const retainedProjectionEnd = exercise.indexOf(
    ' >"${EVIDENCE_DIR}/paging-delivery.json"',
    retainedProjectionStart
  );
  assert.ok(retainedProjectionStart > 0);
  assert.ok(retainedProjectionEnd > retainedProjectionStart);
  const retainedProjection = exercise.slice(
    retainedProjectionStart,
    retainedProjectionEnd
  );
  assert.doesNotMatch(
    retainedProjection,
    /\b(?:awsAccountId|endpoint|failureFeedbackRoleArn|feedbackRoleArn|logGroupName|messageId|nonce|payload|providerResponse|rawLog|subscriptionArn|topicArn|topicKmsKeyArn):/u
  );
  for (const forbiddenKey of [
    "awsAccountId",
    "endpoint",
    "failureFeedbackRoleArn",
    "feedbackRoleArn",
    "logGroupName",
    "messageId",
    "nonce",
    "payload",
    "providerResponse",
    "rawLog",
    "subscriptionArn",
    "topicArn",
    "topicKmsKeyArn"
  ]) {
    assert.match(
      exercise,
      new RegExp(`\\. != "${forbiddenKey}"`, "u")
    );
    assert.match(attest, new RegExp(`\\. != "${forbiddenKey}"`, "u"));
  }
  assert.equal(count(exercise, /jq -se '/u), 1);
  assert.equal(count(attest, /jq -se '/u), 1);

  assertOrdered(exercise, [
    "Publish one nonce-bound test and prove exact delivery",
    "Remove AWS credentials before evidence publication",
    "Revalidate canonical package without AWS credentials",
    "Retain unsigned exact paging candidate"
  ]);
  assertOrdered(exercise, [
    'raw_stack="$(',
    'publish_result="$(',
    "collect_matching_delivery_events()",
    "for poll_attempt in {1..36}",
    'test "${delivery_found}" = "true"',
    'final_stack="$(',
    'test "${final_stack}" = "${initial_stack}"',
    'final_topic_attributes="$(',
    'final_subscription_attributes="$(',
    '--slurpfile gates'
  ]);
  const credentialRemoval = exercise.indexOf(
    "Remove AWS credentials before evidence publication"
  );
  const upload = exercise.indexOf("Retain unsigned exact paging candidate");
  assert.ok(credentialRemoval > 0);
  assert.ok(upload > credentialRemoval);
  const publicationBoundary = exercise.slice(credentialRemoval, upload);
  assert.match(publicationBoundary, /AWS_ACCESS_KEY_ID=/u);
  assert.match(publicationBoundary, /AWS_SECRET_ACCESS_KEY=/u);
  assert.match(publicationBoundary, /AWS_SESSION_TOKEN=/u);
  assert.match(publicationBoundary, /test -z "\$\{AWS_ACCESS_KEY_ID:-\}"/u);
  assert.match(publicationBoundary, /verify-github-control-plane\.sh/u);
  assert.doesNotMatch(
    publicationBoundary,
    /\baws\s+(?:cloudformation|logs|sns|sts)\b/u
  );

  assert.match(
    exercise,
    /name: production-paging-delivery-candidate-\$\{\{ steps\.delivery\.outputs\.release_sha \}\}-\$\{\{ steps\.delivery\.outputs\.producer_attempt \}\}/u
  );
  assert.match(exercise, /retention-days: 1/u);
  assert.match(exercise, /if-no-files-found: error/u);

  assert.doesNotMatch(attest, /needs\.exercise\.outputs/u);
  assert.doesNotMatch(attest, /\$\{\{\s*vars\./u);
  assert.match(attest, /GITHUB_RUN_ID/u);
  assert.match(attest, /GITHUB_RUN_ATTEMPT/u);
  assert.match(attest, /actions\/runs\/\$\{GITHUB_RUN_ID\}\/artifacts/u);
  assert.equal(count(attest, /--paginate/u), 2);
  assert.equal(
    count(
      attest,
      /actions\/runs\/\$\{GITHUB_RUN_ID\}\/artifacts\?per_page=100/u
    ),
    2
  );
  assert.match(attest, /\.workflow_run\.id == \$runId/u);
  assert.match(attest, /\.workflow_run\.head_sha == \$sha/u);
  assert.match(attest, /\.expired == false/u);
  assert.match(attest, /\.digest == \$digest/u);
  assert.equal(
    count(attest, /\^production-paging-delivery-candidate-/u),
    2
  );
  assert.equal(
    count(attest, /\(\?<attempt>\[1-9\]\[0-9\]\*\)\$/u),
    2
  );
  assert.equal(
    count(
      attest,
      /select\(\$attempt <= \(\$currentAttempt \| tonumber\)\)/u
    ),
    2
  );
  assert.equal(count(attest, /group_by\(\.producerAttempt\)/u), 2);
  assert.equal(count(attest, /select\(length != 1\)/u), 2);
  assert.equal(count(attest, /map\(\.\[0\]\)/u), 2);
  assert.equal(count(attest, /sort_by\(\.producerAttempt\)\s+\|\s+last/u), 2);
  assert.match(attest, /\(\( producer_attempt <= GITHUB_RUN_ATTEMPT \)\)/u);
  assert.match(attest, /\(\( candidate_size <= 1048576 \)\)/u);
  assert.doesNotMatch(attest, /\b[0-9]+_[0-9_]+\b/u);
  assert.match(
    attest,
    /\.producerAttempt == \$producerAttempt and\s+\.artifact\.id == \$id and\s+\.artifact\.name == \$name and\s+\.artifact\.digest == \$digest and\s+\.artifact\.size_in_bytes == \$size/u
  );
  assert.match(attest, /actions\/artifacts\/\$\{candidate_id\}/u);
  assert.match(attest, /actions\/artifacts\/\$\{ARTIFACT_ID\}/u);
  const downloadStep = sliceRequired(
    attest,
    "Download the exact immutable paging candidate",
    "Independently validate exact paging bytes and semantics"
  );
  assert.match(
    downloadStep,
    /artifact-ids: \$\{\{ steps\.candidate\.outputs\.artifact_id \}\}/u
  );
  assert.match(downloadStep, /digest-mismatch: error/u);
  assert.match(downloadStep, /run-id: \$\{\{ github\.run_id \}\}/u);
  assert.doesNotMatch(downloadStep, /^\s+name:/mu);
  assert.match(attest, /sha256sum --check --strict SHA256SUMS/u);
  assert.match(
    attest,
    /\.schemaVersion ==\s+"archon\.production-paging-delivery-attestation\/v1"/u
  );
  assert.match(
    attest,
    /\.schemaVersion ==\s+"archon\.production-paging-delivery-manifest\/v1"/u
  );
  assert.match(
    attest,
    /\.controlPlaneGateReceiptSha256 ==\s+\$gateReceiptSha/u
  );
  assert.match(
    attest,
    /\.subjects == \{\s+"manifest\.json": \$manifestSha,\s+"paging-delivery\.json": \$pagingSha\s+\}/u
  );
  for (const retainedPath of [
    "SHA256SUMS",
    "attestation-predicate.json",
    "manifest.json",
    "paging-delivery.json",
    "paging-subject.sha256"
  ]) {
    assert.match(attest, new RegExp(retainedPath.replace(".", "\\."), "u"));
  }
  assert.match(
    attest,
    /test "\$\(wc -l <SHA256SUMS\)" = "4"/u
  );
  assert.match(
    attest,
    /attestation-predicate\.json manifest\.json paging-delivery\.json paging-subject\.sha256/u
  );
  assert.match(
    attest,
    /test "\$\(wc -l <paging-subject\.sha256\)" = "2"/u
  );
  assert.match(
    attest,
    /\)\" = "paging-delivery\.json manifest\.json"/u
  );
  assert.match(
    attest,
    /production-paging-delivery-\$\{\{ steps\.candidate\.outputs\.release_sha \}\}-\$\{\{ steps\.candidate\.outputs\.producer_attempt \}\}/u
  );
  assert.match(attest, /retention-days: 90/u);
  assert.match(attest, /topicArnSha256/u);
  assert.match(attest, /subscriptionArnSha256/u);
  assert.match(attest, /endpointSha256/u);
  assert.match(attest, /messageIdSha256/u);
  assert.match(attest, /def digest:/u);
  assert.match(attest, /def positive_integer:/u);
  assert.match(attest, /def nonnegative_integer:/u);
  assert.match(
    attest,
    /\(keys \| sort\) == \[\s+"controlPlane",\s+"delivery",\s+"deployment",\s+"releaseSha",\s+"repository",\s+"schemaVersion",\s+"target",\s+"verification",\s+"workflow"/u
  );
  assert.match(attest, /\.deployment\.stackOutputSetSha256 \| digest/u);
  for (const targetDigest of [
    "awsAccountIdSha256",
    "endpointSha256",
    "feedbackRoleArnSha256",
    "logGroupNameSha256",
    "subscriptionArnSha256",
    "topicArnSha256",
    "topicKmsKeyArnSha256"
  ]) {
    assert.match(
      attest,
      new RegExp(`\\.target\\.${targetDigest} \\| digest`, "u")
    );
  }
  for (const deliveryDigest of [
    "messageIdSha256",
    "nonceSha256",
    "payloadSha256"
  ]) {
    assert.match(
      attest,
      new RegExp(`\\.delivery\\.${deliveryDigest} \\| digest`, "u")
    );
  }
  assert.match(attest, /\.delivery\.dwellTimeMs \|\s+nonnegative_integer/u);
  assert.match(
    attest,
    /\.delivery\.deliveryEventTimestamp \|\s+positive_integer/u
  );
  assert.match(
    attest,
    /\.workflow\.path ==\s+"\.github\/workflows\/production-paging-test\.yml"/u
  );
  assert.match(
    attest,
    /\(\( delivered_epoch == delivery_event_timestamp \/ 1000 \)\)/u
  );
  assert.match(attest, /\(\( delivered_epoch >= published_epoch - 300 \)\)/u);
  assert.match(attest, /\(\( delivered_epoch <= observed_epoch \+ 300 \)\)/u);
  assert.match(attest, /now_epoch - observed_epoch <= 7200/u);

  assertOrdered(attest, [
    "Bind attester to the exact current workflow run",
    "Check out the exact unprivileged attester",
    "Verify attester control plane before repository validation",
    "Resolve one immutable paging producer artifact",
    "Download the exact immutable paging candidate",
    "Independently validate exact paging bytes and semantics",
    "Recheck artifact and control plane before attestation",
    "Attest the two exact paging subjects",
    "Verify the persisted signed paging attestation",
    "Confirm exact attested bytes before retention",
    "Retain exact attested paging evidence"
  ]);
  assert.match(
    attest,
    /predicate-type: https:\/\/archon\.datahub\.dev\/attestations\/production-paging-delivery\/v1/u
  );
  assert.match(attest, /subject-checksums:/u);
  const persistedAttestation = sliceRequired(
    attest,
    "Verify the persisted signed paging attestation",
    "Confirm exact attested bytes before retention"
  );
  assert.match(
    persistedAttestation,
    /ATTESTATION_BUNDLE_PATH: \$\{\{ steps\.attest\.outputs\.bundle-path \}\}/u
  );
  assert.match(
    persistedAttestation,
    /ATTESTATION_ID: \$\{\{ steps\.attest\.outputs\.attestation-id \}\}/u
  );
  assert.match(
    persistedAttestation,
    /ATTESTATION_URL: \$\{\{ steps\.attest\.outputs\.attestation-url \}\}/u
  );
  assert.match(
    persistedAttestation,
    /https:\/\/github\.com\/\$\{GITHUB_REPOSITORY\}\/attestations\/\$\{ATTESTATION_ID\}/u
  );
  assert.match(persistedAttestation, /test -f "\$\{ATTESTATION_BUNDLE_PATH\}"/u);
  assert.match(
    persistedAttestation,
    /test ! -L "\$\{ATTESTATION_BUNDLE_PATH\}"/u
  );
  assert.match(
    persistedAttestation,
    /\(\( bundle_size >= 1 && bundle_size <= 16777216 \)\)/u
  );
  assert.match(persistedAttestation, /for attempt in \{1\.\.12\}/u);
  assert.match(persistedAttestation, /gh attestation verify/u);
  assert.match(
    persistedAttestation,
    /--predicate-type "\$\{PREDICATE_TYPE\}"/u
  );
  assert.match(
    persistedAttestation,
    /--signer-workflow\s+\\\s+"\$\{GITHUB_REPOSITORY\}\/\.github\/workflows\/production-paging-test\.yml"/u
  );
  assert.match(
    persistedAttestation,
    /--source-digest "\$\{GITHUB_SHA\}"/u
  );
  assert.match(persistedAttestation, /--source-ref "\$\{GITHUB_REF\}"/u);
  assert.match(persistedAttestation, /--deny-self-hosted-runners/u);
  assert.match(persistedAttestation, /--format json/u);
  assert.match(
    persistedAttestation,
    /\.verificationResult\.statement\.predicateType ==\s+\$predicateType/u
  );
  assert.match(
    persistedAttestation,
    /\.verificationResult\.statement\.predicate ==\s+\$predicate\[0\]/u
  );
  assert.match(
    persistedAttestation,
    /name: "manifest\.json",\s+digest: \{\s+sha256: \$manifestSha\s+\}/u
  );
  assert.match(
    persistedAttestation,
    /name: "paging-delivery\.json",\s+digest: \{\s+sha256: \$pagingSha\s+\}/u
  );
  assert.equal(
    count(persistedAttestation, /verify_subject\s+\\/u),
    2
  );
  assert.match(
    persistedAttestation,
    /"\$\{EVIDENCE_DIR\}\/paging-delivery\.json"/u
  );
  assert.match(
    persistedAttestation,
    /"\$\{EVIDENCE_DIR\}\/manifest\.json"/u
  );
  assert.match(
    attest,
    /Confirm exact attested bytes before retention[\s\S]+retained_receipt_sha256[\s\S]+test "\$\{retained_receipt_sha256\}" =\s+\\\s+"\$\{PACKAGE_RECEIPT_SHA256\}"/u
  );
  assertOrdered(attest, [
    'package_receipt_sha256="$(',
    'echo "PACKAGE_RECEIPT_SHA256=${package_receipt_sha256}"',
    "Recheck artifact and control plane before attestation",
    'expected_package_receipt_sha256="${PACKAGE_RECEIPT_SHA256}"',
    'final_package_receipt_sha256="$(',
    'test "${final_package_receipt_sha256}" =',
    "Attest the two exact paging subjects",
    "Verify the persisted signed paging attestation",
    "Confirm exact attested bytes before retention",
    'retained_receipt_sha256="$(',
    'test "${retained_receipt_sha256}" ='
  ]);
  assert.equal(
    count(
      attest,
      /sha256sum\s+\\\s+SHA256SUMS\s+\\\s+attestation-predicate\.json\s+\\\s+manifest\.json\s+\\\s+paging-delivery\.json\s+\\\s+paging-subject\.sha256\s+\|\s+sha256sum/u
    ),
    3
  );
  const finalRecheck = attest.indexOf(
    "Recheck artifact and control plane before attestation"
  );
  const signing = attest.indexOf(
    "Attest the two exact paging subjects",
    finalRecheck
  );
  assert.ok(finalRecheck > 0);
  assert.ok(signing > finalRecheck);
  assertOrdered(attest.slice(finalRecheck, signing), [
    'artifacts="$(',
    'reselected="$(',
    'direct="$(',
    "bash scripts/verify-github-control-plane.sh",
    'test "${final_gates}" = "${embedded_gates}"'
  ]);
}

function assertPinnedActions(source: string): void {
  const actionReferences = [
    ...source.matchAll(/^\s+uses:\s+([^\s#]+)(?:\s+#.*)?$/gmu)
  ].map((match) => match[1]!);
  assert.ok(actionReferences.length > 0);
  for (const reference of actionReferences) {
    assert.match(
      reference,
      /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}$/u
    );
  }

  for (const pinnedReference of [
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
    "aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c"
  ]) {
    assert.ok(actionReferences.includes(pinnedReference), pinnedReference);
  }
  assert.deepEqual(
    [...actionReferences].sort(),
    [
      "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
      "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
      "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
      "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
      "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
      "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
      "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
      "aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c"
    ].sort()
  );
}

function assertPagingContract(source: string): void {
  assertWorkflowEnvelope(source);
  assertControlPlaneBoundary(source);
  assertAwsBindings(source);
  assertDeliveryProof(source);
  assertEvidenceBoundary(source);
  assertPinnedActions(source);
}

test("paging delivery has one exact protected AWS boundary and a separate attester", () => {
  assertWorkflowEnvelope(workflow);
  assertControlPlaneBoundary(workflow);
});

test("paging delivery binds the exact production SNS and delivery-log controls", () => {
  assertAwsBindings(workflow);
});

test("paging delivery proves one bounded, paginated, unique external HTTPS success", () => {
  assertDeliveryProof(workflow);
});

test("paging evidence is sanitized, late-revalidated, independently checked, and attested", () => {
  assertEvidenceBoundary(workflow);
  assertPinnedActions(workflow);
});

test("the complete paging contract accepts the authoritative workflow", () => {
  assertPagingContract(workflow);
});

test("paging contract rejects permission, role, and environment widening", () => {
  const weeklyWithoutFreshnessSlack = replaceRequired(
    workflow,
    'cron: "17 3 * * 1,4"',
    'cron: "17 3 * * 1"'
  );
  assert.throws(() => assertPagingContract(weeklyWithoutFreshnessSlack));

  const permissionsWidened = replaceRequired(
    workflow,
    "permissions: {}",
    "permissions:\n  contents: write"
  );
  assert.throws(() => assertPagingContract(permissionsWidened));

  const roleWidened = replaceRequired(
    workflow,
    "role-to-assume: ${{ vars.AWS_PAGING_TEST_ROLE_ARN }}",
    "role-to-assume: ${{ vars.AWS_DEPLOY_ROLE_ARN }}"
  );
  assert.throws(() => assertPagingContract(roleWidened));

  const environmentWidened = replaceRequired(
    workflow,
    "environment: production-paging-test",
    "environment: production-observer"
  );
  assert.throws(() => assertPagingContract(environmentWidened));

  const roleNameWidened = replaceRequired(
    workflow,
    'role/archon-production-paging-test"',
    'role/archon-production-deploy"'
  );
  assert.throws(() => assertPagingContract(roleNameWidened));

  const sessionNameWidened = replaceRequired(
    workflow,
    "role-session-name: archon-production-paging-${{ github.run_id }}",
    "role-session-name: archon-${{ github.run_id }}"
  );
  assert.throws(() => assertPagingContract(sessionNameWidened));

  const callerBindingRemoved = removeRequired(
    workflow,
    ".Arn == $callerArn and"
  );
  assert.throws(() => assertPagingContract(callerBindingRemoved));
});

test("paging contract rejects protocol, filter, or sampling weakening", () => {
  const protocolWeakened = replaceRequired(
    workflow,
    '.Attributes.Protocol == "https"',
    '.Attributes.Protocol == "http"'
  );
  assert.throws(() => assertPagingContract(protocolWeakened));

  const filterWeakened = removeRequired(
    workflow,
    '((.Attributes.FilterPolicy // "{}") | fromjson) ==\n                {}'
  );
  assert.throws(() => assertPagingContract(filterWeakened));

  const samplingWeakened = replaceRequired(workflow, '== "100"', '== "10"');
  assert.throws(() => assertPagingContract(samplingWeakened));
});

test("paging contract rejects unsafe endpoint masking", () => {
  const rawEndpointMask = replaceRequired(
    workflow,
    "printf '::add-mask::%s\\n' \"${escaped_endpoint}\"",
    "printf '::add-mask::%s\\n' \"${endpoint}\""
  );
  assert.throws(() => assertPagingContract(rawEndpointMask));

  const missingPercentEscape = removeRequired(
    workflow,
    'escaped_endpoint="${endpoint//%/%25}"'
  );
  assert.throws(() => assertPagingContract(missingPercentEscape));
});

test("paging contract rejects raw evidence leakage", () => {
  const rawEndpointLeak = replaceRequired(
    workflow,
    "endpointSha256:",
    "endpointSha256:\n                  endpoint:"
  );
  assert.throws(() => assertPagingContract(rawEndpointLeak));

  const rawLogLeak = replaceRequired(
    workflow,
    "messageIdSha256:",
    "messageIdSha256:\n                rawLog:"
  );
  assert.throws(() => assertPagingContract(rawLogLeak));

  const rawAccountLeak = replaceRequired(
    workflow,
    "awsAccountIdSha256:",
    "awsAccountIdSha256:\n                  awsAccountId:"
  );
  assert.throws(() => assertPagingContract(rawAccountLeak));

  assert.ok(workflow.includes("jq -se '"));
  const nonSlurpedBlacklist = workflow.replace("jq -se '", "jq -e '");
  assert.throws(() => assertPagingContract(nonSlurpedBlacklist));

  const nonRecursiveBlacklist = replaceFirstRequired(
    workflow,
    ".. |\n              objects |",
    ". |\n              objects |"
  );
  assert.throws(() => assertPagingContract(nonRecursiveBlacklist));
});

test("paging contract rejects exact evidence-schema validator weakening", () => {
  const predicateKeysWeakened = replaceFirstRequired(
    workflow,
    '"verificationResult",\n                "workflow"',
    '"workflow"'
  );
  assert.throws(() => assertPagingContract(predicateKeysWeakened));

  const manifestKeysWeakened = replaceFirstRequired(
    workflow,
    '"subjectCount",\n                "subjects",',
    '"subjects",'
  );
  assert.throws(() => assertPagingContract(manifestKeysWeakened));

  const targetKeysWeakened = replaceFirstRequired(
    workflow,
    '"protocol",\n                "region",',
    '"protocol",'
  );
  assert.throws(() => assertPagingContract(targetKeysWeakened));

  const regionSemanticsWeakened = replaceFirstRequired(
    workflow,
    'test("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$")',
    "true"
  );
  assert.throws(() => assertPagingContract(regionSemanticsWeakened));

  assert.equal(
    count(
      workflow,
      /\(\( delivered_epoch <= published_epoch \+ 420 \)\)/u
    ),
    3
  );
  const upperDeliveryBoundRemoved = workflow.replaceAll(
    "(( delivered_epoch <= published_epoch + 420 ))",
    ""
  );
  assert.throws(() => assertPagingContract(upperDeliveryBoundRemoved));

  const canonicalTimestampCheckRemoved = workflow.replaceAll(
    '[[ "${value}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]',
    ""
  );
  assert.throws(() => assertPagingContract(canonicalTimestampCheckRemoved));
});

test("paging contract rejects destination, pagination, and polling-bound removal", () => {
  const destinationEqualityRemoved = removeRequired(
    workflow,
    "$message.delivery.destination ==\n                      $destination"
  );
  assert.throws(() => assertPagingContract(destinationEqualityRemoved));

  const md5PreCountFilter = replaceRequired(
    workflow,
    "$message.delivery.destination ==\n                      $destination",
    "$message.delivery.destination ==\n                      $destination and\n                    $message.notification.messageMD5Sum ==\n                      $payloadMd5"
  );
  assert.throws(() => assertPagingContract(md5PreCountFilter));

  const soleRecordMd5Removed = replaceFirstRequired(
    workflow,
    ".[0].messageMD5Sum == $payloadMd5 and",
    ""
  );
  assert.throws(() => assertPagingContract(soleRecordMd5Removed));

  const paginationRemoved = removeRequired(
    workflow,
    "else {nextToken: $nextToken}"
  );
  assert.throws(() => assertPagingContract(paginationRemoved));

  const unsupportedDirectToken = replaceRequired(
    workflow,
    "                --no-paginate \\",
    '                --next-token "${next_token}" \\\n                --no-paginate \\'
  );
  assert.throws(() => assertPagingContract(unsupportedDirectToken));

  const boundRemoved = replaceRequired(
    workflow,
    "for poll_attempt in {1..36}",
    "while true"
  );
  assert.throws(() => assertPagingContract(boundRemoved));

  const stabilizationRemoved = removeRequired(workflow, "sleep 30");
  assert.throws(() => assertPagingContract(stabilizationRemoved));

  const invalidNumericSeparator = replaceRequired(
    workflow,
    "candidate_size <= 1048576",
    "candidate_size <= 1_048_576"
  );
  assert.throws(() => assertPagingContract(invalidNumericSeparator));
});

test("paging contract rejects first-candidate retry selection", () => {
  const latestSelection =
    "sort_by(.producerAttempt) |\n                    last";
  assert.ok(workflow.includes(latestSelection));
  const oldestCandidate = workflow.replace(
    latestSelection,
    "sort_by(.producerAttempt) |\n                    first"
  );
  assert.throws(() => assertPagingContract(oldestCandidate));

  const futureAttemptEligible = replaceFirstRequired(
    workflow,
    "select($attempt <= ($currentAttempt | tonumber))",
    "select($attempt >= ($currentAttempt | tonumber))"
  );
  assert.throws(() => assertPagingContract(futureAttemptEligible));

  const duplicateAttemptAccepted = replaceFirstRequired(
    workflow,
    "select(length != 1)",
    "select(length > 1)"
  );
  assert.throws(() => assertPagingContract(duplicateAttemptAccepted));
});

test("paging contract rejects name-based or digest-tolerant candidate download", () => {
  const nameBasedDownload = replaceRequired(
    workflow,
    "artifact-ids: ${{ steps.candidate.outputs.artifact_id }}",
    "name: ${{ steps.candidate.outputs.artifact_name }}"
  );
  assert.throws(() => assertPagingContract(nameBasedDownload));

  const digestMismatchTolerated = replaceRequired(
    workflow,
    "digest-mismatch: error",
    "digest-mismatch: warn"
  );
  assert.throws(() => assertPagingContract(digestMismatchTolerated));
});

test("paging contract rejects publish-only evidence and attester trust inheritance", () => {
  const publishOnly = removeRequired(workflow, "logs filter-log-events");
  assert.throws(() => assertPagingContract(publishOnly));

  const retryablePublish = replaceRequired(
    workflow,
    "AWS_MAX_ATTEMPTS=1",
    "AWS_MAX_ATTEMPTS=3"
  );
  assert.throws(() => assertPagingContract(retryablePublish));

  const oneSecondLookback = replaceRequired(
    workflow,
    "* 1000 - 300000",
    "* 1000 - 1000"
  );
  assert.throws(() => assertPagingContract(oneSecondLookback));

  const trustingAttester = replaceRequired(
    workflow,
    "    needs: exercise",
    "    needs: exercise\n    env:\n      TRUSTED_RUN_ID: ${{ needs.exercise.outputs.run_id }}"
  );
  assert.throws(() => assertPagingContract(trustingAttester));
});

test("paging contract rejects late-check ordering drift", () => {
  const first = 'test "${delivery_found}" = "true"';
  const second = 'final_stack="$(';
  let orderDrift = replaceRequired(
    workflow,
    first,
    "__ARCHON_ORDER_FIRST__"
  );
  orderDrift = replaceRequired(orderDrift, second, first);
  orderDrift = replaceRequired(
    orderDrift,
    "__ARCHON_ORDER_FIRST__",
    second
  );
  assert.throws(() => assertPagingContract(orderDrift));
});

test("paging contract rejects pre- or post-attestation byte-receipt removal", () => {
  const lateReceiptRemoved = removeRequired(
    workflow,
    'test "${final_package_receipt_sha256}" = \\\n            "${expected_package_receipt_sha256}"'
  );
  assert.throws(() => assertPagingContract(lateReceiptRemoved));

  const postAttestationReceiptRemoved = removeRequired(
    workflow,
    'test "${retained_receipt_sha256}" = \\\n            "${PACKAGE_RECEIPT_SHA256}"'
  );
  assert.throws(() => assertPagingContract(postAttestationReceiptRemoved));
});

test("paging contract rejects unverifiable or partial persisted attestation proof", () => {
  const remoteVerificationRemoved = removeRequired(
    workflow,
    "gh attestation verify"
  );
  assert.throws(() => assertPagingContract(remoteVerificationRemoved));

  const predicateEqualityRemoved = removeRequired(
    workflow,
    ".verificationResult.statement.predicate ==\n                    $predicate[0] and"
  );
  assert.throws(() => assertPagingContract(predicateEqualityRemoved));

  const oneSubjectOnly = removeRequired(
    workflow,
    'verify_subject \\\n            "${EVIDENCE_DIR}/manifest.json" \\\n            "${verification_dir}/manifest.json"'
  );
  assert.throws(() => assertPagingContract(oneSubjectOnly));

  const sourceBindingRemoved = removeRequired(
    workflow,
    '--source-digest "${GITHUB_SHA}" \\'
  );
  assert.throws(() => assertPagingContract(sourceBindingRemoved));
});
