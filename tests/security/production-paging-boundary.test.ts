import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { resolve } from "node:path";

const workflow = readFileSync(
  resolve(".github/workflows/production-paging-test.yml"),
  "utf8"
);

test("paging proof is exact, encrypted, end-to-end, and self-cleaning", () => {
  assert.match(workflow, /^permissions:\s*\{\}/m);
  assert.match(workflow, /environment: production-paging-test/);
  assert.match(workflow, /archon-production-paging-test/);
  assert.match(workflow, /set-alarm-state/);
  assert.match(workflow, /ArchonAlarmProofQueueUrl/);
  assert.match(workflow, /ArchonAlarmTopicArn/);
  assert.match(workflow, /KmsMasterKeyId/);
  assert.match(workflow, /aws:SourceArn/);
  assert.match(workflow, /NewStateValue == "ALARM"/);
  assert.match(workflow, /trap cleanup EXIT/);
  assert.match(workflow, /CloudWatch->SNS\(KMS\)->SQS\(KMS\)/);
  assert.match(workflow, /actions\/attest@[0-9a-f]{40}/);
  assert.doesNotMatch(workflow, /ALARM_SUBSCRIPTION_ARN|https.*webhook|codex.security/i);
});
