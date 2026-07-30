import assert from "node:assert/strict";
import test from "node:test";

import {
  assertNoWildcardIamResourceArnServices,
  inspectIamPolicyResourceArns
} from "../../scripts/verify-iam-policy-resource-arns.mjs";

function templateWithResource(resource) {
  return {
    Resources: {
      ArchonCdkGuardPolicy: {
        Type: "AWS::IAM::ManagedPolicy",
        Properties: {
          PolicyDocument: {
            Version: "2012-10-17",
            Statement: [{ Sid: "Fixture", Effect: "Deny", Action: "*", Resource: resource }]
          }
        }
      }
    }
  };
}

test("accepts exact service segments and resource-name wildcards", () => {
  const result = assertNoWildcardIamResourceArnServices(
    templateWithResource([
      "*",
      "arn:aws:s3:::archon-production-*",
      { "Fn::Sub": "arn:${AWS::Partition}:s3:::archon-production-*/*" },
      { "Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/Archon-*" }
    ])
  );
  assert.equal(result.policyDocumentCount, 1);
  assert.equal(result.resourceArnCount, 3);
  assert.deepEqual(result.violations, []);
});

test("rejects a wildcard service segment in a direct Resource ARN", () => {
  assert.throws(
    () => assertNoWildcardIamResourceArnServices(templateWithResource("arn:aws:*:*:123456789012:*Archon-production*")),
    /ArchonCdkGuardPolicy\/Fixture:direct:service=\*/
  );
});

test("rejects a wildcard service segment in an intrinsic-sub Resource ARN", () => {
  assert.throws(
    () => assertNoWildcardIamResourceArnServices(templateWithResource({ "Fn::Sub": "arn:${AWS::Partition}:*:*:${AWS::AccountId}:*archon-staging*" })),
    /ArchonCdkGuardPolicy\/Fixture:intrinsic-sub:service=\*/
  );
});

test("walks conditional policy statements in IAM resources only", () => {
  const template = templateWithResource({
    "Fn::If": [
      "IsStaging",
      { "Fn::Sub": "arn:${AWS::Partition}:s3:::archon-production-*" },
      { "Fn::Sub": "arn:${AWS::Partition}:s3:::archon-staging-*" }
    ]
  });
  template.Resources.NonIamPolicy = {
    Type: "AWS::S3::BucketPolicy",
    Properties: { PolicyDocument: { Statement: [{ Resource: "arn:aws:*:*:123456789012:ignored" }] } }
  };
  const result = inspectIamPolicyResourceArns(template);
  assert.equal(result.policyDocumentCount, 1);
  assert.equal(result.resourceArnCount, 2);
  assert.deepEqual(result.violations, []);
});
