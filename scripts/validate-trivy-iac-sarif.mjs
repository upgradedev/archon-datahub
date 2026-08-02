#!/usr/bin/env node
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  open,
  realpath
} from "node:fs/promises";
import {
  isAbsolute,
  relative,
  resolve,
  sep
} from "node:path";
import { pathToFileURL } from "node:url";

const MAX_CONTRACT_BYTES = 64 * 1024;
const MAX_SARIF_BYTES = 8 * 1024 * 1024;
const MAX_TEMPLATE_BYTES = 12 * 1024 * 1024;
const WAF_ARN_PATTERN =
  "^arn:aws:wafv2:us-east-1:[0-9]{12}:global/webacl/[A-Za-z0-9_-]{1,128}/[0-9a-fA-F-]{36}$";

const REVIEWED_RULES = Object.freeze({
  "AWS-0011": {
    evidenceKind: "cross-stack-waf-reference",
    resourceType: "AWS::CloudFront::Distribution",
    sarifLevel: "error",
    severity: "HIGH"
  },
  "AWS-0190": {
    evidenceKind: "authenticated-zero-ttl-control-api",
    resourceType: "AWS::ApiGateway::Stage",
    sarifLevel: "note",
    severity: "LOW"
  },
  "AWS-0089": {
    evidenceKind: "terminal-nonrecursive-log-sink",
    resourceType: "AWS::S3::Bucket",
    sarifLevel: "note",
    severity: "LOW"
  }
});

function invariant(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function isObject(value) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value);
}

function exactRef(value, logicalId) {
  return isObject(value) &&
    Object.keys(value).length === 1 &&
    value.Ref === logicalId;
}

function exactGetAtt(value, logicalId, attributes) {
  if (!isObject(value)) return false;
  const getAtt = value["Fn::GetAtt"];
  return Array.isArray(getAtt) &&
    getAtt.length === 2 &&
    getAtt[0] === logicalId &&
    attributes.includes(getAtt[1]);
}

async function readRegularJson(filePath, maxBytes, label) {
  const handle = await open(
    filePath,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW
  );
  try {
    const before = await handle.stat();
    invariant(before.isFile(),
      label + " must be a regular, non-symlink file");
    invariant(before.size > 0 && before.size <= maxBytes,
      label + " size is outside the reviewed boundary");
    const text = await handle.readFile("utf8");
    const after = await handle.stat();
    invariant(
      after.isFile() &&
        after.size === before.size &&
        after.mtimeMs === before.mtimeMs &&
        Buffer.byteLength(text, "utf8") === before.size,
      label + " changed while it was being read"
    );
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error(label + " is not valid JSON");
    }
    return { parsed, text };
  } finally {
    await handle.close();
  }
}

function validateContract(contract, now) {
  invariant(isObject(contract),
    "exception contract must be an object");
  invariant(
    contract.schemaVersion ===
      "archon.aws.iac-trivy-exceptions.v1",
    "unexpected exception-contract schema"
  );
  invariant(
    isObject(contract.scanner) &&
      contract.scanner.name === "Trivy" &&
      contract.scanner.version === "0.72.0",
    "exception contract must pin Trivy 0.72.0"
  );
  invariant(/^\d{4}-\d{2}-\d{2}$/u.test(contract.reviewBy),
    "reviewBy must be an ISO date");
  const reviewDeadline =
    new Date(contract.reviewBy + "T23:59:59.999Z");
  invariant(Number.isFinite(reviewDeadline.getTime()),
    "reviewBy is invalid");
  invariant(now.getTime() <= reviewDeadline.getTime(),
    "Trivy exceptions passed reviewBy and require re-review");
  invariant(Array.isArray(contract.exceptions) &&
    contract.exceptions.length === 6,
  "the reviewed exception set must contain exactly six entries");

  const seen = new Set();
  const stageRules = new Set();
  for (const exception of contract.exceptions) {
    invariant(isObject(exception),
      "every exception must be an object");
    const reviewed = REVIEWED_RULES[exception.ruleId];
    invariant(reviewed,
      "contract contains an unreviewed Trivy rule");
    invariant(
      ["staging", "production"].includes(exception.stage),
      "exception stage is not reviewed"
    );
    invariant(
      exception.template ===
        exception.stage + "/Archon-" + exception.stage +
          "-Judge.template.json",
      "exception template is not the exact Judge template"
    );
    invariant(
      exception.sarifLevel === reviewed.sarifLevel &&
      exception.severity === reviewed.severity &&
      exception.resourceType === reviewed.resourceType &&
      exception.evidenceKind === reviewed.evidenceKind,
      "exception severity or evidence classification drifted"
    );
    invariant(
      typeof exception.rationale === "string" &&
        exception.rationale.length >= 80,
      "exception rationale is missing or too short"
    );
    invariant(
      typeof exception.resourceLogicalIdPattern === "string" &&
        exception.resourceLogicalIdPattern.startsWith("^") &&
        exception.resourceLogicalIdPattern.endsWith("$"),
      "logical-ID pattern must be anchored"
    );
    new RegExp(exception.resourceLogicalIdPattern, "u");
    invariant(
      exception.resourcePath ===
        expectedResourcePath(exception.stage, exception.ruleId),
      "CDK resource path drifted in exception contract"
    );
    const key = exception.stage + "|" + exception.ruleId;
    invariant(!stageRules.has(key),
      "duplicate stage/rule exception");
    stageRules.add(key);
    const exactKey = key + "|" + exception.template + "|" +
      exception.resourceLogicalIdPattern;
    invariant(!seen.has(exactKey),
      "duplicate exception");
    seen.add(exactKey);
  }
  for (const stage of ["staging", "production"]) {
    for (const ruleId of Object.keys(REVIEWED_RULES)) {
      invariant(stageRules.has(stage + "|" + ruleId),
        "missing reviewed " + stage + " " + ruleId + " exception");
    }
  }
}

function expectedResourcePath(stage, ruleId) {
  if (ruleId === "AWS-0011") {
    return "Archon-" + stage +
      "-Judge/JudgeDistribution/Resource";
  }
  if (ruleId === "AWS-0190") {
    return "Archon-" + stage +
      "-Judge/JudgeApi/DeploymentStage." + stage + "/Resource";
  }
  return "Archon-" + stage +
    "-Judge/AccessLogBucket/Resource";
}

async function resolveTemplate(rootReal, uri) {
  invariant(
    typeof uri === "string" &&
      /^(?:staging|production)\/Archon-(?:staging|production)-Judge\.template\.json$/u
        .test(uri),
    "SARIF template URI is outside the reviewed shape"
  );
  const candidate = resolve(rootReal, uri);
  const lexical = relative(rootReal, candidate);
  invariant(
    lexical !== ".." &&
      !lexical.startsWith(".." + sep) &&
      !isAbsolute(lexical),
    "SARIF template URI escapes the synth root"
  );
  const candidateReal = await realpath(candidate);
  const resolvedRelative = relative(rootReal, candidateReal);
  invariant(
    resolvedRelative !== ".." &&
      !resolvedRelative.startsWith(".." + sep) &&
      !isAbsolute(resolvedRelative),
    "SARIF template resolves outside the synth root"
  );
  return candidateReal;
}

function locateResource(template, text, startLine) {
  const lines = text.split(/\r?\n/u);
  invariant(Number.isInteger(startLine) &&
    startLine >= 1 && startLine <= lines.length,
  "SARIF startLine is outside the template");
  const resources = template.Resources;
  invariant(isObject(resources),
    "synthesized template has no Resources object");
  for (let index = startLine - 1; index >= 0; index -= 1) {
    const match = lines[index].match(
      /^\s+"([^"]+)": \{$/u
    );
    if (match && Object.hasOwn(resources, match[1])) {
      return {
        logicalId: match[1],
        resource: resources[match[1]],
        resourceStartLine: index + 1
      };
    }
  }
  throw new Error("unable to bind SARIF location to a resource");
}

function resourceByPath(template, resourcePath) {
  const matches = Object.entries(template.Resources ?? {})
    .filter(([, resource]) =>
      resource?.Metadata?.["aws:cdk:path"] === resourcePath
    );
  invariant(matches.length === 1,
    "expected exactly one synthesized resource at " + resourcePath);
  return { logicalId: matches[0][0], resource: matches[0][1] };
}

function verifyWafReference(template, resource) {
  invariant(
    exactRef(
      resource?.Properties?.DistributionConfig?.WebACLId,
      "CloudFrontWebAclArn"
    ),
    "AWS-0011 exception requires the exact WAF parameter Ref"
  );
  const parameter = template.Parameters?.CloudFrontWebAclArn;
  invariant(
    parameter?.Type === "String" &&
      parameter.AllowedPattern === WAF_ARN_PATTERN,
    "CloudFrontWebAclArn is not constrained to the exact global WAF ARN"
  );
}

function verifyDynamicNoCache(template, resource, stage) {
  const properties = resource?.Properties;
  invariant(properties?.CacheClusterEnabled === false,
    "AWS-0190 exception requires API Gateway caching disabled");
  invariant(properties.StageName === stage,
    "API stage does not match the exception stage");
  invariant(properties.TracingEnabled === true,
    "dynamic control API must retain X-Ray tracing");
  invariant(isObject(properties.AccessLogSetting) &&
    properties.AccessLogSetting.DestinationArn,
  "dynamic control API must retain access logging");
  invariant(
    Array.isArray(properties.MethodSettings) &&
      properties.MethodSettings.length > 0 &&
      properties.MethodSettings.every((setting) =>
        setting.DataTraceEnabled === false &&
        setting.HttpMethod === "*" &&
        setting.ResourcePath === "/*" &&
        setting.LoggingLevel === "ERROR" &&
        setting.MetricsEnabled === true
      ),
    "dynamic control API method observability boundary drifted"
  );

  const policies = Object.entries(template.Resources)
    .filter(([, candidate]) =>
      candidate.Type === "AWS::CloudFront::CachePolicy" &&
      candidate.Properties?.CachePolicyConfig?.Name ===
        "archon-" + stage + "-api-no-cache"
    );
  invariant(policies.length === 1,
    "exact zero-TTL API cache policy is missing");
  const [policyLogicalId, policy] = policies[0];
  const config = policy.Properties.CachePolicyConfig;
  invariant(
    config.DefaultTTL === 0 &&
      config.MinTTL === 0 &&
      config.MaxTTL === 0,
    "API cache policy is no longer zero-TTL"
  );
  const forwarded =
    config.ParametersInCacheKeyAndForwardedToOrigin;
  const headers = forwarded?.HeadersConfig;
  invariant(
    headers?.HeaderBehavior === "whitelist" &&
      Array.isArray(headers.Headers) &&
      headers.Headers.length === 1 &&
      headers.Headers[0].toLowerCase() === "authorization" &&
      forwarded.CookiesConfig?.CookieBehavior === "none" &&
      forwarded.QueryStringsConfig?.QueryStringBehavior === "none",
    "zero-TTL policy no longer forwards only Authorization"
  );
  const distribution = resourceByPath(
    template,
    "Archon-" + stage +
      "-Judge/JudgeDistribution/Resource"
  ).resource;
  const apiBehaviors =
    distribution.Properties?.DistributionConfig?.CacheBehaviors
      ?.filter((behavior) => behavior.PathPattern === "api/*");
  invariant(
    Array.isArray(apiBehaviors) &&
      apiBehaviors.length === 1 &&
      exactRef(apiBehaviors[0].CachePolicyId, policyLogicalId) &&
      apiBehaviors[0].ViewerProtocolPolicy === "https-only",
    "CloudFront API behavior is not bound to the zero-TTL policy"
  );
}

function verifyTerminalSink(
  template,
  resource,
  logicalId,
  stage
) {
  const properties = resource?.Properties;
  invariant(properties?.AccessControl === "LogDeliveryWrite",
    "terminal sink must use the exact log-delivery ACL");
  invariant(!Object.hasOwn(properties, "LoggingConfiguration"),
    "terminal access-log sink must not recursively log itself");
  invariant(
    properties?.OwnershipControls?.Rules?.length === 1 &&
      properties.OwnershipControls.Rules[0].ObjectOwnership ===
        "ObjectWriter",
    "terminal sink ACL ownership boundary drifted"
  );
  const encryption =
    properties?.BucketEncryption
      ?.ServerSideEncryptionConfiguration;
  invariant(
    Array.isArray(encryption) &&
      encryption.length === 1 &&
      !Object.hasOwn(encryption[0], "BucketKeyEnabled") &&
      encryption[0].ServerSideEncryptionByDefault
        ?.SSEAlgorithm === "AES256" &&
      !Object.hasOwn(
        encryption[0].ServerSideEncryptionByDefault,
        "KMSMasterKeyID"
      ),
    "terminal S3 log sink must use delivery-compatible SSE-S3"
  );
  invariant(
    properties?.VersioningConfiguration?.Status === "Enabled",
    "terminal sink must remain versioned"
  );
  const publicBlock =
    properties?.PublicAccessBlockConfiguration;
  invariant(
    publicBlock?.BlockPublicAcls === true &&
      publicBlock.BlockPublicPolicy === true &&
      publicBlock.IgnorePublicAcls === true &&
      publicBlock.RestrictPublicBuckets === true,
    "terminal sink public-access block drifted"
  );
  invariant(
    properties?.Tags?.some((tag) =>
      tag.Key === "SecurityProfile" &&
      tag.Value === "terminal-access-log-sink"
    ),
    "terminal sink security-profile tag is missing"
  );
  const lifecycle =
    properties?.LifecycleConfiguration?.Rules?.find((rule) =>
      rule.Id === "BoundedTerminalAccessLogs" &&
      rule.Status === "Enabled"
    );
  invariant(
    lifecycle &&
      lifecycle.AbortIncompleteMultipartUpload
        ?.DaysAfterInitiation > 0 &&
      lifecycle.AbortIncompleteMultipartUpload
        .DaysAfterInitiation <= 1 &&
      lifecycle.ExpirationInDays > 0 &&
      lifecycle.ExpirationInDays <= 180 &&
      lifecycle.NoncurrentVersionExpiration
        ?.NoncurrentDays > 0 &&
      lifecycle.NoncurrentVersionExpiration
        .NoncurrentDays <= 30,
    "terminal sink lifecycle is missing or unbounded"
  );

  const sources = [
    ["SpaBucket", stage + "/s3/spa/"],
    [
      "CloudCheckpointBucket",
      stage + "/s3/cloud-checkpoints/"
    ]
  ];
  for (const [constructId, prefix] of sources) {
    const source = resourceByPath(
      template,
      "Archon-" + stage + "-Judge/" +
        constructId + "/Resource"
    ).resource;
    const logging = source.Properties?.LoggingConfiguration;
    invariant(
      exactRef(logging?.DestinationBucketName, logicalId) &&
        logging.LogFilePrefix === prefix,
      constructId + " is not logging to the exact terminal sink prefix"
    );
  }

  const cloudFrontLogs = resourceByPath(
    template,
    "Archon-" + stage +
      "-Judge/CloudFrontLogBucket/Resource"
  );
  const cloudFrontProperties =
    cloudFrontLogs.resource.Properties;
  invariant(
    cloudFrontProperties?.OwnershipControls?.Rules?.length === 1 &&
      cloudFrontProperties.OwnershipControls.Rules[0]
        .ObjectOwnership === "ObjectWriter" &&
      !Object.hasOwn(cloudFrontProperties, "AccessControl"),
    "CloudFront log bucket must enable only ObjectWriter ACLs"
  );
  const cloudFrontEncryption =
    cloudFrontProperties?.BucketEncryption
      ?.ServerSideEncryptionConfiguration;
  invariant(
    Array.isArray(cloudFrontEncryption) &&
      cloudFrontEncryption.length === 1 &&
      cloudFrontEncryption[0].BucketKeyEnabled === true &&
      cloudFrontEncryption[0].ServerSideEncryptionByDefault
        ?.SSEAlgorithm === "aws:kms",
    "CloudFront standard logs must remain KMS encrypted with a bucket key"
  );
  const keyReference =
    cloudFrontEncryption[0].ServerSideEncryptionByDefault
      .KMSMasterKeyID;
  invariant(
    isObject(keyReference) &&
      Array.isArray(keyReference["Fn::GetAtt"]) &&
      keyReference["Fn::GetAtt"].length === 2 &&
      keyReference["Fn::GetAtt"][1] === "Arn",
    "CloudFront log bucket must reference an in-stack CMK ARN"
  );
  const logsKeyLogicalId = keyReference["Fn::GetAtt"][0];
  const logsKey = template.Resources[logsKeyLogicalId];
  invariant(logsKey?.Type === "AWS::KMS::Key",
    "CloudFront log bucket CMK resource is missing");
  const deliveryStatements =
    logsKey.Properties?.KeyPolicy?.Statement?.filter((statement) =>
      statement.Sid ===
        "AllowExactCloudFrontStandardLogDelivery"
    );
  invariant(
    Array.isArray(deliveryStatements) &&
      deliveryStatements.length === 1,
    "exact CloudFront KMS delivery statement is missing"
  );
  const delivery = deliveryStatements[0];
  invariant(
    delivery.Effect === "Allow" &&
      delivery.Resource === "*" &&
      isObject(delivery.Principal) &&
      Object.keys(delivery.Principal).length === 1 &&
      delivery.Principal.Service ===
        "delivery.logs.amazonaws.com" &&
      Array.isArray(delivery.Action) &&
      delivery.Action.length === 2 &&
      [...delivery.Action].sort().join("|") ===
        "kms:Decrypt|kms:GenerateDataKey*" &&
      !Object.hasOwn(delivery, "Condition"),
    "CloudFront KMS delivery principal/actions drifted"
  );
  const cloudFrontServerLogging =
    cloudFrontProperties.LoggingConfiguration;
  invariant(
    exactRef(
      cloudFrontServerLogging?.DestinationBucketName,
      logicalId
    ) &&
      cloudFrontServerLogging.LogFilePrefix ===
        stage + "/s3/cloudfront-log-bucket/",
    "CloudFront log bucket does not forward access logs to the terminal sink"
  );
  invariant(
    cloudFrontProperties?.Tags?.some((tag) =>
      tag.Key === "SecurityProfile" &&
      tag.Value === "cloudfront-access-log-bucket"
    ),
    "CloudFront log bucket security-profile tag is missing"
  );
  const cloudFrontLifecycle =
    cloudFrontProperties?.LifecycleConfiguration?.Rules?.find(
      (rule) =>
        rule.Id === "BoundedCloudFrontStandardLogs" &&
        rule.Status === "Enabled"
    );
  invariant(
    cloudFrontLifecycle &&
      cloudFrontLifecycle.AbortIncompleteMultipartUpload
        ?.DaysAfterInitiation > 0 &&
      cloudFrontLifecycle.AbortIncompleteMultipartUpload
        .DaysAfterInitiation <= 1 &&
      cloudFrontLifecycle.ExpirationInDays > 0 &&
      cloudFrontLifecycle.ExpirationInDays <= 180 &&
      cloudFrontLifecycle.NoncurrentVersionExpiration
        ?.NoncurrentDays > 0 &&
      cloudFrontLifecycle.NoncurrentVersionExpiration
        .NoncurrentDays <= 30,
    "CloudFront log bucket lifecycle is missing or unbounded"
  );

  const distribution = resourceByPath(
    template,
    "Archon-" + stage +
      "-Judge/JudgeDistribution/Resource"
  ).resource;
  const logging =
    distribution.Properties?.DistributionConfig?.Logging;
  invariant(
    logging?.IncludeCookies === false &&
      logging.Prefix === stage + "/cloudfront/" &&
      exactGetAtt(
        logging.Bucket,
        cloudFrontLogs.logicalId,
        ["DomainName", "RegionalDomainName"]
      ),
    "CloudFront is not logging to the exact KMS log bucket"
  );
}

function verifyEvidence(
  exception,
  template,
  resource,
  logicalId
) {
  if (exception.ruleId === "AWS-0011") {
    verifyWafReference(template, resource);
    return;
  }
  if (exception.ruleId === "AWS-0190") {
    verifyDynamicNoCache(
      template,
      resource,
      exception.stage
    );
    return;
  }
  verifyTerminalSink(
    template,
    resource,
    logicalId,
    exception.stage
  );
}

function verifyResultMessage(result, exception, uri) {
  invariant(typeof result.message?.text === "string",
    "SARIF result message is missing");
  const expectedLines = [
    "Artifact: " + uri,
    "Type: cloudformation",
    "Vulnerability " + exception.ruleId,
    "Severity: " + exception.severity,
    "Link: [" + exception.ruleId + "]" +
      "(https://avd.aquasec.com/misconfig/" +
      exception.ruleId.toLowerCase() + ")"
  ];
  for (const expected of expectedLines) {
    invariant(result.message.text.includes(expected),
      "SARIF result message drifted: " + expected);
  }
}

export async function validateSarif({
  sarifPath,
  templateRoot,
  contractPath,
  now = new Date()
}) {
  invariant(typeof sarifPath === "string" &&
    typeof templateRoot === "string" &&
    typeof contractPath === "string",
  "validator paths are required");
  const rootStat = await lstat(templateRoot);
  invariant(rootStat.isDirectory() && !rootStat.isSymbolicLink(),
    "synth root must be a non-symlink directory");
  const rootReal = await realpath(templateRoot);
  const { parsed: contract } = await readRegularJson(
    contractPath,
    MAX_CONTRACT_BYTES,
    "exception contract"
  );
  validateContract(contract, now);
  const { parsed: sarif } = await readRegularJson(
    sarifPath,
    MAX_SARIF_BYTES,
    "Trivy SARIF"
  );
  invariant(sarif.version === "2.1.0",
    "unexpected SARIF version");
  invariant(Array.isArray(sarif.runs) &&
    sarif.runs.length === 1,
  "Trivy SARIF must contain exactly one run");
  const run = sarif.runs[0];
  invariant(
    run?.tool?.driver?.name === contract.scanner.name &&
      run.tool.driver.version === contract.scanner.version,
    "SARIF scanner identity/version drifted"
  );
  invariant(Array.isArray(run.results),
    "SARIF results must be an array");
  invariant(
    run.results.length === contract.exceptions.length,
    "SARIF result count differs from the exact reviewed set"
  );

  const matched = new Set();
  const templateCache = new Map();
  for (const result of run.results) {
    invariant(
      typeof result.ruleId === "string" &&
        typeof result.level === "string",
      "SARIF result identity is malformed"
    );
    invariant(
      !Array.isArray(result.suppressions) ||
        result.suppressions.length === 0,
      "scanner-side SARIF suppressions are not accepted"
    );
    invariant(Array.isArray(result.locations) &&
      result.locations.length === 1,
    "every SARIF result must have one physical location");
    const physical =
      result.locations[0]?.physicalLocation;
    const uri = physical?.artifactLocation?.uri;
    const startLine = physical?.region?.startLine;
    const templatePath = await resolveTemplate(rootReal, uri);
    let cached = templateCache.get(templatePath);
    if (!cached) {
      cached = await readRegularJson(
        templatePath,
        MAX_TEMPLATE_BYTES,
        "synthesized template"
      );
      templateCache.set(templatePath, cached);
    }
    const located = locateResource(
      cached.parsed,
      cached.text,
      startLine
    );
    const candidates = contract.exceptions.filter((exception) =>
      exception.ruleId === result.ruleId &&
      exception.template === uri &&
      new RegExp(
        exception.resourceLogicalIdPattern,
        "u"
      ).test(located.logicalId)
    );
    invariant(candidates.length === 1,
      "SARIF finding is not in the exact reviewed allowlist: " +
        result.ruleId + " " + uri + " " + located.logicalId);
    const exception = candidates[0];
    const key = exception.stage + "|" + exception.ruleId;
    invariant(!matched.has(key),
      "duplicate SARIF finding for " + key);
    invariant(result.level === exception.sarifLevel,
      "SARIF level drifted for " + key);
    invariant(
      located.resource?.Type === exception.resourceType &&
      located.resource?.Metadata?.["aws:cdk:path"] ===
        exception.resourcePath,
      "synthesized resource type/path drifted for " + key
    );
    verifyResultMessage(result, exception, uri);
    verifyEvidence(
      exception,
      cached.parsed,
      located.resource,
      located.logicalId
    );
    matched.add(key);
  }

  for (const exception of contract.exceptions) {
    const key = exception.stage + "|" + exception.ruleId;
    invariant(matched.has(key),
      "expected reviewed SARIF finding is missing: " + key);
  }
  return {
    scanner: contract.scanner.name + " " +
      contract.scanner.version,
    reviewedExceptions: matched.size,
    stages: ["staging", "production"]
  };
}

async function main() {
  invariant(process.argv.length === 5,
    "usage: validate-trivy-iac-sarif.mjs " +
      "<sarif> <cdk-root> <exception-contract>");
  const summary = await validateSarif({
    sarifPath: process.argv[2],
    templateRoot: process.argv[3],
    contractPath: process.argv[4]
  });
  process.stdout.write(JSON.stringify(summary) + "\n");
}

if (
  process.argv[1] &&
  import.meta.url ===
    pathToFileURL(resolve(process.argv[1])).href
) {
  main().catch((error) => {
    process.stderr.write(
      "Trivy IaC evidence validation failed: " +
      error.message + "\n"
    );
    process.exitCode = 1;
  });
}
