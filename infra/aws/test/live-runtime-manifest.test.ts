import { readFileSync } from "node:fs";
import { resolve } from "node:path";

describe("lean live-runtime observer", () => {
  const source = readFileSync(
    resolve(__dirname, "../../../scripts/observe-aws-live-runtime.sh"),
    "utf8"
  );

  test("observes the exact three-stack serverless and zero-idle topology", () => {
    for (const required of [
      "Archon-${ARCHON_STAGE}-Edge",
      "Archon-${ARCHON_STAGE}-Core",
      "Archon-${ARCHON_STAGE}-Judge",
      "ArchonCoreAutoScalingGroupName",
      "DesiredCapacity == 0",
      "ArchonRuntimeSessionTableName",
      "ArchonCloudCheckpointBucketName",
      "archon-${ARCHON_STAGE}-cloud-read",
      "archon-${ARCHON_STAGE}-cloud-mutation",
      "archon-${ARCHON_STAGE}-cloud-reset",
      "ArchonRegionalWebAclArn",
      "ArchonAlarmProofQueueUrl",
      "archon.lean-runtime-observation/v1",
      "rawIdentifiersProjected:false"
    ]) {
      expect(source).toContain(required);
    }
  });

  test("never performs a mutation and never expects the retired runtime", () => {
    expect(source).not.toMatch(/\b(create|update|put|delete|start|stop)-/);
    expect(source).not.toMatch(/describe-services|ECS_CLUSTER|NLB|VpcLink/i);
    expect(source).toContain('[[ "${ARCHON_OBSERVATION_OUTPUT}" == "${RUNNER_TEMP}/"* ]]');
  });
});
