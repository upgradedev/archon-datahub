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

test("accepts exact AWS partitions, exact services, and resource-name wildcards", () => {
  const result = assertNoWildcardIamResourceArnServices(
    templateWithResource([
      "arn:aws:s3:::archon-production-*",
      "arn:aws-us-gov:iam::123456789012:role/Archon-*",
      { "Fn::Sub": "arn:${AWS::Partition}:s3:::archon-production-*/*" },
      {
        "Fn::Sub": [
          "arn:${Partition}:iam::${AWS::AccountId}:role/Archon-*",
          { Partition: { Ref: "AWS::Partition" } }
        ]
      }
    ])
  );
  assert.equal(result.policyDocumentCount, 1);
  assert.equal(result.resourceArnCount, 4);
  assert.deepEqual(result.violations, []);
});

test("rejects wildcard and nonliteral service segments without substitution-map bypass", () => {
  const fixtures = [
    "arn:aws:*:*:123456789012:*Archon-production*",
    "arn:aws:s?:*:123456789012:*Archon-production*",
    { "Fn::Sub": "arn:${AWS::Partition}:*:*:${AWS::AccountId}:*archon-staging*" },
    {
      "Fn::Sub": [
        "arn:${AWS::Partition}:${Service}:eu-west-1:${AWS::AccountId}:resource/*",
        { Service: "*" }
      ]
    }
  ];
  for (const fixture of fixtures) {
    const result = inspectIamPolicyResourceArns(templateWithResource(fixture));
    assert.equal(result.violations.length, 1);
    assert.throws(() => assertNoWildcardIamResourceArnServices(templateWithResource(fixture)));
  }
  assert.equal(
    inspectIamPolicyResourceArns(templateWithResource(fixtures[3])).violations[0].reason,
    "nonliteral-service"
  );
});

test("fails closed for malformed, incomplete, empty, and unresolved ARN shapes", () => {
  const fixtures = [
    ["arn:${AWS::Partition:s3:::archon-*", "unclosed-placeholder"],
    ["arn:aws:s3", "incomplete-arn"],
    ["arn:aws:s3:::", "missing-resource"],
    ["arn:${AWS::Partition}:s3:::archon-*", "invalid-partition"],
    [
      { "Fn::Sub": "arn:${Partition}:s3:::archon-*" },
      "invalid-partition"
    ],
    [
      {
        "Fn::Sub": ["arn:${Partition}:s3:::archon-*", { Partition: "aws" }]
      },
      "invalid-partition"
    ]
  ];
  for (const [fixture, reason] of fixtures) {
    const result = inspectIamPolicyResourceArns(templateWithResource(fixture));
    assert.equal(result.violations.length, 1);
    assert.equal(result.violations[0].reason, reason);
    assert.throws(() => assertNoWildcardIamResourceArnServices(templateWithResource(fixture)));
  }
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
