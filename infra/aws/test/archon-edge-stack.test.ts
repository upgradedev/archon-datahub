import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { ArchonEdgeStack } from "../lib/archon-edge-stack";

const P256_CERTIFICATE_ALGORITHM = ["EC", "prime256v1"].join("_");

function edgeTemplate(
  stage = "staging"
): { stack: ArchonEdgeStack; template: Template } {
  const app = new App();
  const stack = new ArchonEdgeStack(app, `TestEdge-${stage}`, {
    env: { account: "111111111111", region: "us-east-1" },
    stage
  });
  return { stack, template: Template.fromStack(stack) };
}

function webAclRules(template: Template): any[] {
  const webAcl = Object.values(
    template.findResources("AWS::WAFv2::WebACL")
  )[0] as any;
  expect(webAcl).toBeDefined();
  return webAcl.Properties.Rules;
}

describe("Archon CloudFront edge stack", () => {
  test("is fixed to us-east-1 and requires bounded deployment parameters", () => {
    const { stack, template } = edgeTemplate();
    expect(stack.region).toBe("us-east-1");

    const parameters = template.toJSON().Parameters;
    expect(parameters.CloudFrontDomainName).toEqual(
      expect.objectContaining({
        MinLength: 4,
        MaxLength: 253,
        AllowedPattern:
          "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
      })
    );
    expect(parameters.CloudFrontDomainName.Default).toBeUndefined();
    expect(parameters.CloudFrontHostedZoneId).toEqual(
      expect.objectContaining({
        AllowedPattern: "^Z[A-Z0-9]{1,31}$"
      })
    );
    expect(parameters.CloudFrontHostedZoneId.Default).toBeUndefined();

    const implicitRegionStack = new ArchonEdgeStack(
      new App(),
      "ImplicitRegionEdge",
      { stage: "staging" }
    );
    expect(implicitRegionStack.region).toBe("us-east-1");
    expect(
      () =>
        new ArchonEdgeStack(new App(), "WrongRegionEdge", {
          env: { account: "111111111111", region: "eu-west-1" },
          stage: "staging"
        })
    ).toThrow("ArchonEdgeStack must be deployed in us-east-1");
    expect(
      () =>
        new ArchonEdgeStack(new App(), "InvalidStageEdge", {
          stage: "Production"
        })
    ).toThrow("ArchonEdgeStack stage must match");
  });

  test("issues a retained DNS-validated ECDSA CloudFront certificate", () => {
    const { template } = edgeTemplate();
    template.hasResourceProperties("AWS::CertificateManager::Certificate", {
      DomainName: { Ref: "CloudFrontDomainName" },
      DomainValidationOptions: [
        {
          DomainName: { Ref: "CloudFrontDomainName" },
          HostedZoneId: { Ref: "CloudFrontHostedZoneId" }
        }
      ],
      CertificateExport: "DISABLED",
      CertificateTransparencyLoggingPreference: "ENABLED",
      KeyAlgorithm: P256_CERTIFICATE_ALGORITHM,
      ValidationMethod: "DNS"
    });
    template.hasResource("AWS::CertificateManager::Certificate", {
      DeletionPolicy: "Retain",
      UpdateReplacePolicy: "Retain"
    });

    const certificateLogicalId = Object.keys(
      template.findResources("AWS::CertificateManager::Certificate")
    )[0]!;
    template.hasOutput("ArchonCloudFrontCertificateArn", {
      Value: { Ref: certificateLogicalId }
    });
  });

  test("uses the three managed protections and an environment-aware IP rate limit", () => {
    const { template } = edgeTemplate();
    template.hasResourceProperties("AWS::WAFv2::WebACL", {
      Scope: "CLOUDFRONT",
      DefaultAction: { Allow: {} },
      DataProtectionConfig: {
        DataProtections: [
          {
            Action: "SUBSTITUTION",
            ExcludeRateBasedDetails: false,
            ExcludeRuleMatchDetails: false,
            Field: {
              FieldType: "SINGLE_HEADER",
              FieldKeys: ["authorization"]
            }
          },
          {
            Action: "SUBSTITUTION",
            ExcludeRateBasedDetails: false,
            ExcludeRuleMatchDetails: false,
            Field: {
              FieldType: "SINGLE_HEADER",
              FieldKeys: ["cookie"]
            }
          },
          {
            Action: "SUBSTITUTION",
            ExcludeRateBasedDetails: false,
            ExcludeRuleMatchDetails: false,
            Field: {
              FieldType: "SINGLE_HEADER",
              FieldKeys: ["x-api-key"]
            }
          }
        ]
      },
      VisibilityConfig: {
        CloudWatchMetricsEnabled: true,
        MetricName: "archon-staging-cloudfront-waf",
        SampledRequestsEnabled: true
      }
    });

    const rules = webAclRules(template);
    expect(
      rules.map((rule) => ({ name: rule.Name, priority: rule.Priority }))
    ).toEqual([
      { name: "AWSManagedRulesAmazonIpReputationList", priority: 0 },
      { name: "AWSManagedRulesCommonRuleSet", priority: 10 },
      { name: "AWSManagedRulesKnownBadInputsRuleSet", priority: 20 },
      { name: "PerIpRateLimit", priority: 30 }
    ]);
    for (const name of [
      "AWSManagedRulesAmazonIpReputationList",
      "AWSManagedRulesCommonRuleSet",
      "AWSManagedRulesKnownBadInputsRuleSet"
    ]) {
      const rule = rules.find((candidate) => candidate.Name === name);
      expect(rule.OverrideAction).toEqual({ None: {} });
      expect(rule.Statement.ManagedRuleGroupStatement).toEqual({
        Name: name,
        VendorName: "AWS"
      });
    }
    const stagingRateRule = rules.find(
      (rule) => rule.Name === "PerIpRateLimit"
    );
    expect(stagingRateRule.Action).toEqual({ Block: {} });
    expect(stagingRateRule.Statement.RateBasedStatement).toEqual({
      AggregateKeyType: "IP",
      EvaluationWindowSec: 300,
      Limit: 300
    });

    const productionRateRule = webAclRules(
      edgeTemplate("production").template
    ).find((rule) => rule.Name === "PerIpRateLimit");
    expect(productionRateRule.Statement.RateBasedStatement).toEqual({
      AggregateKeyType: "IP",
      EvaluationWindowSec: 300,
      Limit: 1_000
    });
  });

  test("retains encrypted WAF logs and records only redacted block/count events", () => {
    const { template } = edgeTemplate();
    template.hasResourceProperties("AWS::KMS::Key", {
      Description: "KMS key for retained Archon CloudFront WAF logs",
      EnableKeyRotation: true
    });
    template.hasResource("AWS::KMS::Key", {
      DeletionPolicy: "Retain",
      UpdateReplacePolicy: "Retain"
    });
    template.hasResourceProperties("AWS::Logs::LogGroup", {
      LogGroupName: "aws-waf-logs-archon-staging-cloudfront",
      KmsKeyId: Match.anyValue(),
      RetentionInDays: 365
    });
    template.hasResource("AWS::Logs::LogGroup", {
      DeletionPolicy: "Retain",
      UpdateReplacePolicy: "Retain"
    });
    template.hasResourceProperties("AWS::WAFv2::LoggingConfiguration", {
      LogDestinationConfigs: [Match.anyValue()],
      LoggingFilter: {
        DefaultBehavior: "DROP",
        Filters: [
          {
            Behavior: "KEEP",
            Conditions: [
              { ActionCondition: { Action: "BLOCK" } },
              { ActionCondition: { Action: "COUNT" } }
            ],
            Requirement: "MEETS_ANY"
          }
        ]
      },
      RedactedFields: [
        { SingleHeader: { Name: "authorization" } },
        { SingleHeader: { Name: "cookie" } },
        { SingleHeader: { Name: "x-api-key" } }
      ],
      ResourceArn: Match.anyValue()
    });
    const loggingConfiguration = Object.values(
      template.findResources("AWS::WAFv2::LoggingConfiguration")
    )[0] as any;
    expect(
      JSON.stringify(loggingConfiguration.Properties.LogDestinationConfigs)
    ).toContain("aws-waf-logs-archon-staging-cloudfront");
    expect(
      JSON.stringify(loggingConfiguration.Properties.LogDestinationConfigs)
    ).not.toContain(":*");
    const key = Object.values(
      template.findResources("AWS::KMS::Key")
    )[0] as any;
    const statements = key.Properties.KeyPolicy.Statement;
    const cloudWatchLogsStatement = statements.find(
      (statement: any) => statement.Sid === "AllowCloudWatchLogsEncryption"
    );
    expect(cloudWatchLogsStatement).toBeDefined();
    expect(cloudWatchLogsStatement.Action).toEqual([
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]);
    expect(JSON.stringify(cloudWatchLogsStatement.Principal)).toContain(
      "logs.us-east-1."
    );
    expect(JSON.stringify(cloudWatchLogsStatement.Condition)).toContain(
      "kms:EncryptionContext:aws:logs:arn"
    );
    expect(JSON.stringify(cloudWatchLogsStatement.Condition)).toContain(
      "aws-waf-logs-archon-staging-cloudfront"
    );
    expect(JSON.stringify(cloudWatchLogsStatement.Condition)).not.toContain(
      "kms:ViaService"
    );

    const webAclLogicalId = Object.keys(
      template.findResources("AWS::WAFv2::WebACL")
    )[0]!;
    template.hasOutput("ArchonCloudFrontWebAclArn", {
      Value: { "Fn::GetAtt": [webAclLogicalId, "Arn"] }
    });
    template.hasOutput("ArchonCloudFrontWafLogKeyArn", {
      Value: Match.anyValue()
    });
  });
});
