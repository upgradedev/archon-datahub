import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  dirname,
  join,
  resolve
} from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  validateSarif
} from "../../scripts/validate-trivy-iac-sarif.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const contractPath = resolve(
  here,
  "../../contracts/aws-iac-trivy-exceptions-v1.json"
);
const NOW = new Date("2026-08-02T12:00:00Z");

function ids(stage) {
  return {
    sink: "AccessLogBucketABCDEF12",
    logsKey: "LogsKeyABCDEF12",
    cloudFrontLogs: "CloudFrontLogBucketABCDEF12",
    spa: "SpaBucketABCDEF12",
    checkpoint: "CloudCheckpointBucketABCDEF12",
    policy: "ApiNoCachePolicyABCDEF12",
    apiStage:
      "JudgeApiDeploymentStage" + stage + "ABCDEF12",
    distribution: "JudgeDistributionABCDEF12"
  };
}

function template(stage) {
  const id = ids(stage);
  const stack = "Archon-" + stage + "-Judge";
  return {
    Parameters: {
      CloudFrontWebAclArn: {
        Type: "String",
        AllowedPattern:
          "^arn:aws:wafv2:us-east-1:[0-9]{12}:global/webacl/[A-Za-z0-9_-]{1,128}/[0-9a-fA-F-]{36}$"
      }
    },
    Resources: {
      [id.sink]: {
        Type: "AWS::S3::Bucket",
        Properties: {
          AccessControl: "LogDeliveryWrite",
          BucketEncryption: {
            ServerSideEncryptionConfiguration: [
              {
                ServerSideEncryptionByDefault: {
                  SSEAlgorithm: "AES256"
                }
              }
            ]
          },
          LifecycleConfiguration: {
            Rules: [
              {
                Id: "BoundedTerminalAccessLogs",
                Status: "Enabled",
                AbortIncompleteMultipartUpload: {
                  DaysAfterInitiation: 1
                },
                ExpirationInDays:
                  stage === "production" ? 180 : 30,
                NoncurrentVersionExpiration: {
                  NoncurrentDays:
                    stage === "production" ? 30 : 7
                }
              }
            ]
          },
          OwnershipControls: {
            Rules: [{ ObjectOwnership: "ObjectWriter" }]
          },
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: true,
            BlockPublicPolicy: true,
            IgnorePublicAcls: true,
            RestrictPublicBuckets: true
          },
          Tags: [
            {
              Key: "SecurityProfile",
              Value: "terminal-access-log-sink"
            }
          ],
          VersioningConfiguration: { Status: "Enabled" }
        },
        Metadata: {
          "aws:cdk:path":
            stack + "/AccessLogBucket/Resource"
        }
      },
      [id.logsKey]: {
        Type: "AWS::KMS::Key",
        Properties: {
          KeyPolicy: {
            Statement: [
              {
                Sid:
                  "AllowExactCloudFrontStandardLogDelivery",
                Effect: "Allow",
                Principal: {
                  Service:
                    "delivery.logs.amazonaws.com"
                },
                Action: [
                  "kms:GenerateDataKey*",
                  "kms:Decrypt"
                ],
                Resource: "*"
              }
            ]
          }
        },
        Metadata: {
          "aws:cdk:path": stack + "/LogsKey/Resource"
        }
      },
      [id.cloudFrontLogs]: {
        Type: "AWS::S3::Bucket",
        Properties: {
          BucketEncryption: {
            ServerSideEncryptionConfiguration: [
              {
                BucketKeyEnabled: true,
                ServerSideEncryptionByDefault: {
                  KMSMasterKeyID: {
                    "Fn::GetAtt": [id.logsKey, "Arn"]
                  },
                  SSEAlgorithm: "aws:kms"
                }
              }
            ]
          },
          LifecycleConfiguration: {
            Rules: [
              {
                Id: "BoundedCloudFrontStandardLogs",
                Status: "Enabled",
                AbortIncompleteMultipartUpload: {
                  DaysAfterInitiation: 1
                },
                ExpirationInDays:
                  stage === "production" ? 180 : 30,
                NoncurrentVersionExpiration: {
                  NoncurrentDays:
                    stage === "production" ? 30 : 7
                }
              }
            ]
          },
          LoggingConfiguration: {
            DestinationBucketName: { Ref: id.sink },
            LogFilePrefix:
              stage + "/s3/cloudfront-log-bucket/"
          },
          OwnershipControls: {
            Rules: [{ ObjectOwnership: "ObjectWriter" }]
          },
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: true,
            BlockPublicPolicy: true,
            IgnorePublicAcls: true,
            RestrictPublicBuckets: true
          },
          Tags: [
            {
              Key: "SecurityProfile",
              Value: "cloudfront-access-log-bucket"
            }
          ],
          VersioningConfiguration: { Status: "Enabled" }
        },
        Metadata: {
          "aws:cdk:path":
            stack + "/CloudFrontLogBucket/Resource"
        }
      },
      [id.spa]: {
        Type: "AWS::S3::Bucket",
        Properties: {
          LoggingConfiguration: {
            DestinationBucketName: { Ref: id.sink },
            LogFilePrefix: stage + "/s3/spa/"
          }
        },
        Metadata: {
          "aws:cdk:path": stack + "/SpaBucket/Resource"
        }
      },
      [id.checkpoint]: {
        Type: "AWS::S3::Bucket",
        Properties: {
          LoggingConfiguration: {
            DestinationBucketName: { Ref: id.sink },
            LogFilePrefix:
              stage + "/s3/cloud-checkpoints/"
          }
        },
        Metadata: {
          "aws:cdk:path":
            stack + "/CloudCheckpointBucket/Resource"
        }
      },
      [id.policy]: {
        Type: "AWS::CloudFront::CachePolicy",
        Properties: {
          CachePolicyConfig: {
            Name: "archon-" + stage + "-api-no-cache",
            DefaultTTL: 0,
            MinTTL: 0,
            MaxTTL: 0,
            ParametersInCacheKeyAndForwardedToOrigin: {
              CookiesConfig: { CookieBehavior: "none" },
              HeadersConfig: {
                HeaderBehavior: "whitelist",
                Headers: ["authorization"]
              },
              QueryStringsConfig: {
                QueryStringBehavior: "none"
              }
            }
          }
        },
        Metadata: {
          "aws:cdk:path":
            stack + "/ApiNoCachePolicy/Resource"
        }
      },
      [id.apiStage]: {
        Type: "AWS::ApiGateway::Stage",
        Properties: {
          AccessLogSetting: {
            DestinationArn: {
              "Fn::GetAtt": ["ApiAccessLogsABCDEF12", "Arn"]
            }
          },
          CacheClusterEnabled: false,
          MethodSettings: [
            {
              DataTraceEnabled: false,
              HttpMethod: "*",
              LoggingLevel: "ERROR",
              MetricsEnabled: true,
              ResourcePath: "/*"
            }
          ],
          StageName: stage,
          TracingEnabled: true
        },
        Metadata: {
          "aws:cdk:path":
            stack + "/JudgeApi/DeploymentStage." +
            stage + "/Resource"
        }
      },
      [id.distribution]: {
        Type: "AWS::CloudFront::Distribution",
        Properties: {
          DistributionConfig: {
            CacheBehaviors: [
              {
                PathPattern: "api/*",
                CachePolicyId: { Ref: id.policy },
                ViewerProtocolPolicy: "https-only"
              }
            ],
            Logging: {
              Bucket: {
                "Fn::GetAtt": [
                  id.cloudFrontLogs,
                  "RegionalDomainName"
                ]
              },
              IncludeCookies: false,
              Prefix: stage + "/cloudfront/"
            },
            WebACLId: { Ref: "CloudFrontWebAclArn" }
          }
        },
        Metadata: {
          "aws:cdk:path":
            stack + "/JudgeDistribution/Resource"
        }
      }
    }
  };
}

function render(value) {
  return JSON.stringify(value, null, 1) + "\n";
}

function resourceId(exception) {
  const id = ids(exception.stage);
  if (exception.ruleId === "AWS-0011") {
    return id.distribution;
  }
  if (exception.ruleId === "AWS-0190") {
    return id.apiStage;
  }
  return id.sink;
}

function resultFor(exception, templateText) {
  const logicalId = resourceId(exception);
  const lines = templateText.split("\n");
  const startLine = lines.findIndex((line) =>
    line.includes('"' + logicalId + '": {')
  ) + 1;
  assert.ok(startLine > 0);
  const uri = exception.template;
  return {
    ruleId: exception.ruleId,
    level: exception.sarifLevel,
    message: {
      text:
        "Artifact: " + uri + "\n" +
        "Type: cloudformation\n" +
        "Vulnerability " + exception.ruleId + "\n" +
        "Severity: " + exception.severity + "\n" +
        "Message: reviewed fixture\n" +
        "Link: [" + exception.ruleId + "]" +
        "(https://avd.aquasec.com/misconfig/" +
        exception.ruleId.toLowerCase() + ")"
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          region: { startLine }
        }
      }
    ]
  };
}

async function fixture() {
  const root = await mkdtemp(
    join(tmpdir(), "archon-trivy-contract-")
  );
  const contract = JSON.parse(
    await readFile(contractPath, "utf8")
  );
  const texts = new Map();
  for (const stage of ["staging", "production"]) {
    const directory = join(root, stage);
    await mkdir(directory, { recursive: true });
    const text = render(template(stage));
    const relative =
      stage + "/Archon-" + stage +
      "-Judge.template.json";
    texts.set(relative, text);
    await writeFile(join(root, relative), text, "utf8");
  }
  const sarif = {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Trivy",
            version: "0.72.0"
          }
        },
        results: contract.exceptions.map((exception) =>
          resultFor(exception, texts.get(exception.template))
        )
      }
    ]
  };
  const sarifPath = join(root, "trivy-iac.sarif");
  await writeFile(
    sarifPath,
    JSON.stringify(sarif),
    "utf8"
  );
  return { contract, root, sarif, sarifPath };
}

async function withFixture(callback) {
  const value = await fixture();
  try {
    await callback(value);
  } finally {
    await rm(value.root, {
      recursive: true,
      force: true
    });
  }
}

async function validate(value) {
  return validateSarif({
    sarifPath: value.sarifPath,
    templateRoot: value.root,
    contractPath,
    now: NOW
  });
}

async function rewriteSarif(value) {
  await writeFile(
    value.sarifPath,
    JSON.stringify(value.sarif),
    "utf8"
  );
}

async function mutateTemplate(value, stage, mutate) {
  const path = join(
    value.root,
    stage,
    "Archon-" + stage + "-Judge.template.json"
  );
  const document = JSON.parse(
    await readFile(path, "utf8")
  );
  mutate(document, ids(stage));
  await writeFile(path, render(document), "utf8");
}

test("accepts only the six exact evidence-bound findings", async () => {
  await withFixture(async (value) => {
    const summary = await validate(value);
    assert.deepEqual(summary, {
      scanner: "Trivy 0.72.0",
      reviewedExceptions: 6,
      stages: ["staging", "production"]
    });
  });
});

test("rejects every unreviewed additional finding", async () => {
  await withFixture(async (value) => {
    value.sarif.runs[0].results.push({
      ...structuredClone(value.sarif.runs[0].results[0]),
      ruleId: "AWS-0178"
    });
    await rewriteSarif(value);
    await assert.rejects(
      validate(value),
      /result count differs/u
    );
  });
});

test("rejects a missing expected review receipt", async () => {
  await withFixture(async (value) => {
    value.sarif.runs[0].results.pop();
    await rewriteSarif(value);
    await assert.rejects(
      validate(value),
      /result count differs/u
    );
  });
});

test("rejects cross-stack WAF evidence drift", async () => {
  await withFixture(async (value) => {
    await mutateTemplate(
      value,
      "staging",
      (document, id) => {
        document.Resources[id.distribution]
          .Properties.DistributionConfig.WebACLId = {
            Ref: "UnreviewedWebAcl"
          };
      }
    );
    await assert.rejects(
      validate(value),
      /exact WAF parameter Ref/u
    );
  });
});

test("rejects cache or Authorization boundary drift", async () => {
  await withFixture(async (value) => {
    await mutateTemplate(
      value,
      "production",
      (document, id) => {
        document.Resources[id.apiStage]
          .Properties.CacheClusterEnabled = true;
      }
    );
    await assert.rejects(
      validate(value),
      /caching disabled/u
    );
  });
});

test("rejects recursive logging on the terminal sink", async () => {
  await withFixture(async (value) => {
    await mutateTemplate(
      value,
      "staging",
      (document, id) => {
        document.Resources[id.sink]
          .Properties.LoggingConfiguration = {
            DestinationBucketName: { Ref: id.sink },
            LogFilePrefix: "recursive/"
          };
      }
    );
    await assert.rejects(
      validate(value),
      /must not recursively log itself/u
    );
  });
});

test("publishes only a revalidated actionable SARIF projection", async () => {
  const workflow = await readFile(
    resolve(here, "../../.github/workflows/ci.yml"),
    "utf8"
  );
  const start = workflow.indexOf("  publish-infra-sarif:");
  const end = workflow.indexOf("\n  readiness:", start);
  assert.ok(start >= 0 && end > start);
  const publishJob = workflow.slice(start, end);

  assert.match(
    publishJob,
    /ref: \$\{\{ github\.sha \}\}/u
  );
  assert.match(
    publishJob,
    /node scripts\/validate-trivy-iac-sarif\.mjs \\\n\s+"\$\{raw_sarif\}" \\\n\s+"\$\{synth_root\}" \\\n\s+contracts\/aws-iac-trivy-exceptions-v1\.json/u
  );
  assert.match(
    publishJob,
    /jq '\(\.runs\[\] \| \.results\) = \[\]' \\\n\s+"\$\{raw_sarif\}" >"\$\{projection\}"/u
  );
  assert.match(
    publishJob,
    /sarif_file: \$\{\{ runner\.temp \}\}\/trusted-actionable-trivy-iac\.sarif/u
  );
  assert.doesNotMatch(
    publishJob,
    /sarif_file: .*infra-evidence\/trivy-iac\.sarif/u
  );
  assert.doesNotMatch(
    publishJob,
    /Revalidate zero-finding SARIF/u
  );
  const validation = publishJob.indexOf(
    "node scripts/validate-trivy-iac-sarif.mjs"
  );
  const projection = publishJob.indexOf(
    "jq '(.runs[] | .results) = []'"
  );
  const upload = publishJob.indexOf(
    "Upload trusted actionable IaC SARIF projection"
  );
  assert.ok(
    validation >= 0 &&
      projection > validation &&
      upload > projection
  );
});
