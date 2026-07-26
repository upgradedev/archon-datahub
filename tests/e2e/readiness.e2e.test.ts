// End-to-end assertion of the READINESS PROJECTION (scripts/readiness.ts).
//
// This imports the SAME pure computeReadiness() the CLI + CI job use, runs the full
// evidence-gathering offline (pipeline, ReAct loop, MCP round-trip, live contradiction
// recovery, static tool-surface + docs/NOTICE checks), and asserts the offline capability
// surface clears the 95% CI regression gate. It also asserts that this CI result cannot be
// mistaken for final readiness: the five official criteria are equal-weighted, external
// deliverables remain explicit blockers, and the differentiator check (I1) genuinely passes
// on version-history-shaped data.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  applyReadinessEvidence,
  computeReadiness,
  createBonusChecks,
  createEngineeringCapabilityChecks,
  evaluateSubmission,
  EXTERNAL_PROOFS,
  READINESS_EVIDENCE_ENVIRONMENT,
  READINESS_EVIDENCE_PREDICATE_TYPE,
  READINESS_EVIDENCE_SEAL_PREDICATE_TYPE,
  READINESS_EVIDENCE_SCHEMA_VERSION,
  READINESS_EVIDENCE_SOURCE_WORKFLOW_PATH,
  READINESS_EVIDENCE_WORKFLOW_PATH,
  READINESS_REPOSITORY,
  REQUIRED_EXTERNAL_PROOFS,
  validateReadinessEvidenceManifest,
  type CapabilityCheck,
  type Check,
  type ReadinessEvidenceBinding,
  type ReadinessEvidenceInput,
} from "../../scripts/readiness.js";

let reportPromise: ReturnType<typeof computeReadiness> | undefined;
const report = (): ReturnType<typeof computeReadiness> =>
  (reportPromise ??= computeReadiness());

const SHA_A = `sha256:${"a".repeat(64)}`;
const SHA_B = `sha256:${"b".repeat(64)}`;
const RELEASE_SHA = "c".repeat(40);

const evidenceBinding = (): ReadinessEvidenceBinding => ({
  repository: READINESS_REPOSITORY,
  releaseSha: RELEASE_SHA,
  source: {
    workflowPath: READINESS_EVIDENCE_SOURCE_WORKFLOW_PATH,
    runId: 123456,
    producerRunAttempt: 1,
    attestationRunAttempt: 2,
  },
  artifact: {
    name: `submission-evidence-${RELEASE_SHA}-1`,
    id: 789012,
    digest: SHA_A,
  },
  predicate: {
    type: READINESS_EVIDENCE_PREDICATE_TYPE,
    digest: SHA_B,
  },
  approval: {
    environment: READINESS_EVIDENCE_ENVIRONMENT,
    workflowPath: READINESS_EVIDENCE_WORKFLOW_PATH,
    workflowRef:
      `${READINESS_REPOSITORY}/${READINESS_EVIDENCE_WORKFLOW_PATH}` +
      "@refs/heads/master",
    runId: 345678,
    runAttempt: 1,
    environmentId: 456789,
    reviewerId: 567890,
    receiptDigest: `sha256:${"f".repeat(64)}`,
  },
});

const evidenceInput = (
  proofIds: string[],
  bonusIds: Array<"BONUS-OSS" | "BONUS-FEEDBACK"> = []
): ReadinessEvidenceInput => {
  const binding = evidenceBinding();
  return {
    expectedBinding: binding,
    manifest: {
      schemaVersion: READINESS_EVIDENCE_SCHEMA_VERSION,
      binding: structuredClone(binding),
      proofs: proofIds.map((id, index) => {
        const registry = EXTERNAL_PROOFS.find((proof) => proof.id === id);
        assert.ok(registry, `unknown fixture proof ID ${id}`);
        return {
          id,
          criterion: registry.criterion,
          status: "verified",
          evidence: `${id} contract fixture; not live evidence`,
          receipt: {
            name: `receipts/${id.toLowerCase()}.json`,
            digest: `sha256:${(index + 1).toString(16).padStart(64, "0")}`,
          },
        };
      }),
      bonuses: bonusIds.map((id, index) => ({
        id,
        status: "verified",
        evidence: `${id} contract fixture; not live evidence`,
        receipt: {
          name: `receipts/${id.toLowerCase()}.json`,
          digest: `sha256:${(index + 20).toString(16).padStart(64, "0")}`,
        },
      })),
    },
  };
};

const completeOfficialChecks = (): Check[] => [
  {
    id: "D4",
    criterion: "use-of-datahub",
    weight: 1,
    status: "pass",
    title: "Live DataHub proof",
    evidence: "present",
  },
  {
    id: "T-example",
    criterion: "technical-execution",
    weight: 1,
    status: "pass",
    title: "Technical evidence",
    evidence: "present",
  },
  {
    id: "I-example",
    criterion: "originality",
    weight: 1,
    status: "pass",
    title: "Originality evidence",
    evidence: "present",
  },
  {
    id: "U3",
    criterion: "real-world-usefulness",
    weight: 1,
    status: "pass",
    title: "Live usefulness proof",
    evidence: "present",
  },
  ...[
    "SQ3",
    "SQ4",
    "SQ5",
    "SQ6",
    "SQ7",
    "SQ8",
    "SQ9",
    "SQ10",
    "SQ11",
  ].map(
    (id): Check => ({
      id,
      criterion: "submission-quality",
      weight: 1,
      status: "pass",
      title: `Submission proof ${id}`,
      evidence: "present",
    })
  ),
];

const completeCapabilityChecks = (): CapabilityCheck[] => [
  {
    id: "ENG-example",
    axis: "engineering",
    weight: 1,
    status: "pass",
    title: "Engineering evidence",
    evidence: "present",
  },
  {
    id: "SEC-example",
    axis: "security",
    weight: 1,
    status: "pass",
    title: "Security evidence",
    evidence: "present",
  },
];

test("readiness: offline capability evidence clears the 95% CI regression gate", async () => {
  const r = await report();
  assert.ok(
    r.capabilityEvidence.offlineCapabilityPercent >= 95,
    `offlineCapabilityPercent=${r.capabilityEvidence.offlineCapabilityPercent}% (< 95). Failing checks: ${r.capabilityEvidence.checks
      .filter((c) => c.status === "fail")
      .map((c) => `${c.id}:${c.evidence}`)
      .join(" | ")}`
  );
  assert.equal(r.capabilityEvidence.gate.passed, true);
  assert.equal(r.capabilityEvidence.gate.metric, "offlineCapabilityPercent");
});

test("readiness: official projection has exactly five equally weighted criteria", async () => {
  const r = await report();
  assert.deepEqual(
    r.officialCriteria.map((criterion) => criterion.id),
    [
      "use-of-datahub",
      "technical-execution",
      "originality",
      "real-world-usefulness",
      "submission-quality",
    ]
  );
  assert.deepEqual(
    r.officialCriteria.map((criterion) => criterion.weight),
    [20, 20, 20, 20, 20]
  );
  assert.deepEqual(
    r.officialCriteria.map((criterion) => criterion.title),
    [
      "Use of DataHub",
      "Technical Execution",
      "Originality",
      "Real-World Usefulness",
      "Submission Quality",
    ]
  );
  assert.equal(
    r.officialCriteria.reduce((sum, criterion) => sum + criterion.weight, 0),
    100
  );
  const equalWeightProjection =
    Math.round(
      (r.officialCriteria.reduce(
        (sum, criterion) => sum + criterion.evidenceCompletenessPercent,
        0
      ) /
        r.officialCriteria.length) *
        10
    ) / 10;
  assert.equal(r.judgingEvidencePercent, equalWeightProjection);
  assert.equal(r.projectionKind, "evidence-coverage-not-judge-score");
});

test("readiness: external-proof IDs retain exact criterion and readiness roles", () => {
  assert.deepEqual(EXTERNAL_PROOFS, [
    { id: "D4", criterion: "use-of-datahub", role: "eligibility" },
    { id: "U3", criterion: "real-world-usefulness", role: "eligibility" },
    { id: "SQ3", criterion: "submission-quality", role: "eligibility" },
    { id: "SQ4", criterion: "submission-quality", role: "eligibility" },
    { id: "SQ5", criterion: "submission-quality", role: "eligibility" },
    { id: "SQ6", criterion: "submission-quality", role: "eligibility" },
    { id: "SQ7", criterion: "submission-quality", role: "eligibility" },
    { id: "SQ8", criterion: "submission-quality", role: "eligibility" },
    { id: "SQ9", criterion: "submission-quality", role: "recommended" },
    {
      id: "SQ10",
      criterion: "submission-quality",
      role: "operational-monitor",
    },
    { id: "SQ11", criterion: "submission-quality", role: "post-submit" },
  ]);
  assert.deepEqual(REQUIRED_EXTERNAL_PROOFS, [
    { id: "D4", criterion: "use-of-datahub", role: "eligibility" },
    { id: "U3", criterion: "real-world-usefulness", role: "eligibility" },
    { id: "SQ3", criterion: "submission-quality", role: "eligibility" },
    { id: "SQ4", criterion: "submission-quality", role: "eligibility" },
    { id: "SQ5", criterion: "submission-quality", role: "eligibility" },
    { id: "SQ6", criterion: "submission-quality", role: "eligibility" },
    { id: "SQ7", criterion: "submission-quality", role: "eligibility" },
    { id: "SQ8", criterion: "submission-quality", role: "eligibility" },
    {
      id: "SQ10",
      criterion: "submission-quality",
      role: "operational-monitor",
    },
  ]);
});

test("readiness: external proofs never leak into offline capability gating", () => {
  const officialChecks = completeOfficialChecks().map((check) =>
    check.id === "SQ9" || check.id === "SQ11"
      ? { ...check, status: "fail" as const }
      : check
  );
  const engineeringChecks = createEngineeringCapabilityChecks(officialChecks);
  assert.deepEqual(
    engineeringChecks
      .filter((check) =>
        EXTERNAL_PROOFS.some((proof) => check.id === `ENG-${proof.id}`)
      )
      .map((check) => check.id),
    []
  );
  const securityCheck = completeCapabilityChecks().find(
    (check) => check.axis === "security"
  )!;
  const submission = evaluateSubmission(officialChecks, [
    ...engineeringChecks,
    securityCheck,
  ]);
  assert.equal(submission.evidenceCompleteForSealing, true);
  assert.deepEqual(submission.internalBlockers, []);
  assert.deepEqual(
    submission.recommendedEvidenceOutstanding.map((blocker) => blocker.id),
    ["SQ9"]
  );
  assert.deepEqual(
    submission.postSubmitBlockers.map((blocker) => blocker.id),
    ["SQ11"]
  );
  assert.equal(submission.readyToSubmit, false);
});

test("readiness: the differentiator (I1) fires on version-history data", async () => {
  const r = await report();
  const i1 = r.checks.find((c) => c.id === "I1")!;
  assert.equal(i1.status, "pass", `I1 evidence: ${i1.evidence}`);
});

test("readiness: no offline capability check is failing", async () => {
  const r = await report();
  const failing = r.capabilityEvidence.checks.filter((c) => c.status === "fail");
  assert.deepEqual(failing.map((c) => c.id), [], `unexpected failures: ${JSON.stringify(failing)}`);
});

test("readiness: engineering and security stay separate offline capability axes", async () => {
  const r = await report();
  assert.deepEqual(
    r.capabilityEvidence.axes.map((axis) => axis.id),
    ["engineering", "security"]
  );
  const automatedOfficialIds = r.checks
    .filter((check) => check.status !== "user-gated")
    .map((check) => check.id);
  assert.deepEqual(
    r.capabilityEvidence.checks
      .filter((check) => check.axis === "engineering")
      .map((check) => check.id),
    automatedOfficialIds.map((id) => `ENG-${id}`)
  );
  assert.deepEqual(
    r.capabilityEvidence.checks
      .filter((check) => check.axis === "security")
      .map((check) => check.id),
    ["SEC-1", "SEC-2", "SEC-3"]
  );
});

test("readiness: no manifest keeps eligibility proof user-gated and fails closed", async () => {
  const r = await report();
  assert.ok(
    r.judgingEvidencePercent < 100,
    "official evidence coverage must include outstanding external proof"
  );
  assert.equal(r.submission.status, "blocked");
  assert.equal(r.submission.ready, false);
  assert.equal(r.submission.readyToSubmit, false);
  assert.equal(r.submission.submitted, false);
  assert.equal(r.submission.evidenceCompleteForSealing, false);
  assert.equal(r.submission.postSubmitEvidenceComplete, false);
  assert.deepEqual(r.projectionTrust, {
    status: "unsigned-projection",
    readyClaimAllowed: false,
    requiredSignerWorkflow:
      `github.com/${READINESS_REPOSITORY}/${READINESS_EVIDENCE_WORKFLOW_PATH}`,
    requiredPredicateType: READINESS_EVIDENCE_SEAL_PREDICATE_TYPE,
  });
  assert.deepEqual(r.submission.internalBlockers, []);
  assert.deepEqual(
    r.submission.externalBlockers.map((blocker) => blocker.id),
    [
      "D4",
      "U3",
      "SQ3",
      "SQ4",
      "SQ5",
      "SQ6",
      "SQ7",
      "SQ8",
      "SQ10",
    ]
  );
  assert.deepEqual(
    [
      ...r.submission.externalBlockers.map((blocker) => blocker.id),
      ...r.submission.recommendedEvidenceOutstanding.map(
        (blocker) => blocker.id
      ),
      ...r.submission.postSubmitBlockers.map((blocker) => blocker.id),
    ].sort(),
    r.userGated.map((check) => check.id).sort(),
    "every user-gated proof must remain visible in its exact readiness role"
  );
  assert.deepEqual(
    r.submission.recommendedEvidenceOutstanding.map((blocker) => blocker.id),
    ["SQ9"]
  );
  assert.deepEqual(
    r.submission.postSubmitBlockers.map((blocker) => blocker.id),
    ["SQ11"]
  );
  assert.equal(r.externalEvidence.status, "not-provided");
  assert.deepEqual(r.externalEvidence.acceptedProofIds, []);
  assert.equal(r.bonus.allBonusesReady, false);
  assert.deepEqual(
    r.bonus.outstanding.map((blocker) => blocker.id),
    ["BONUS-OSS", "BONUS-FEEDBACK"]
  );
  assert.ok(
    r.userGated.length >= 11,
    "live proof, public deliverables, retained samples, judging access, and final entry remain user-gated"
  );
});

test("readiness: ordinary CLI has no workstation evidence override", () => {
  const source = readFileSync(
    new URL("../../scripts/readiness.ts", import.meta.url),
    "utf8"
  );
  assert.doesNotMatch(
    source,
    /process\.env\.[A-Z0-9_]*READINESS/,
    "regular CI must not ingest an arbitrary JSON path or value from the environment"
  );
  assert.match(
    source,
    /if \(isMain\) \{\s*computeReadiness\(\)/,
    "the ordinary CLI must invoke readiness without external evidence"
  );
});

test("readiness: protected pipeline independently verifies and seals remote evidence", () => {
  const workflow = readFileSync(
    new URL("../../.github/workflows/submission-readiness.yml", import.meta.url),
    "utf8"
  );
  const sourceVerifier = readFileSync(
    new URL(
      "../../scripts/verify-submission-readiness-source.sh",
      import.meta.url
    ),
    "utf8"
  );
  assert.match(workflow, /^\s{2}collect:\s*$/m);
  assert.match(workflow, /^\s{2}review:\s*$/m);
  assert.match(workflow, /^\s{2}seal:\s*$/m);
  assert.match(workflow, /^\s{4}environment: submission-readiness\s*$/m);
  const sealStart = workflow.indexOf("\n  seal:\n");
  assert.notEqual(sealStart, -1, "seal job must exist");
  const sealJob = workflow.slice(sealStart);
  assert.match(
    sealJob,
    /permissions:\n      actions: read\n      attestations: write\n      contents: read\n      id-token: write/
  );
  const downloadStepStart = sealJob.indexOf(
    "\n      - name: Download exact reviewed artifact\n"
  );
  assert.notEqual(
    downloadStepStart,
    -1,
    "exact reviewed-artifact download step must exist"
  );
  const metadataStepStart = sealJob.indexOf(
    "\n      - name: Validate exact reviewed artifact metadata before download\n"
  );
  assert.notEqual(
    metadataStepStart,
    -1,
    "reviewed-artifact metadata must be checked before download"
  );
  assert.ok(
    metadataStepStart < downloadStepStart,
    "OIDC-capable seal job must validate artifact metadata before reading bytes"
  );
  const downloadStepEnd = sealJob.indexOf(
    "\n      - name:",
    downloadStepStart + 1
  );
  assert.notEqual(
    downloadStepEnd,
    -1,
    "reviewed-artifact download step must have a bounded body"
  );
  const downloadStep = sealJob.slice(downloadStepStart, downloadStepEnd);
  assert.equal(
    (downloadStep.match(/^\s+artifact-ids:/gm) ?? []).length,
    1,
    "reviewed-artifact download must have exactly one artifact selector"
  );
  assert.match(
    downloadStep,
    /^\s+artifact-ids: \$\{\{ needs\.review\.outputs\.artifact_id \}\}$/m
  );
  assert.match(
    sealJob,
    /\/actions\/artifacts\/\$\{REVIEW_ARTIFACT_ID\}/
  );
  assert.match(
    sealJob,
    /\.id == \$artifactId and[\s\S]*\.digest == \$digest and[\s\S]*\.size_in_bytes > 0 and[\s\S]*\.size_in_bytes <= 536870912 and[\s\S]*\.workflow_run\.id == \$runId and[\s\S]*\.workflow_run\.head_sha == \$sha/
  );
  const reviewStart = workflow.indexOf("\n  review:\n");
  assert.notEqual(reviewStart, -1, "review job must exist");
  const reviewJob = workflow.slice(reviewStart, sealStart);
  const collectedMetadata = reviewJob.indexOf(
    "\n      - name: Validate exact collected artifact metadata before download\n"
  );
  const collectedDownload = reviewJob.indexOf(
    "\n      - name: Download exact collected receipt\n"
  );
  assert.ok(
    collectedMetadata !== -1 &&
      collectedDownload !== -1 &&
      collectedMetadata < collectedDownload,
    "protected review must validate the exact collected artifact before download"
  );
  assert.match(
    reviewJob,
    /producer_run_attempt: \$\{\{ steps\.bundle\.outputs\.producer_run_attempt \}\}/
  );
  assert.match(
    sealJob,
    /REVIEW_RUN_ATTEMPT: \$\{\{ needs\.review\.outputs\.producer_run_attempt \}\}/
  );
  assert.match(
    sealJob,
    /\(\( REVIEW_RUN_ATTEMPT <= GITHUB_RUN_ATTEMPT \)\)/
  );
  assert.match(
    sealJob,
    /--argjson runAttempt "\$\{REVIEW_RUN_ATTEMPT\}"/
  );
  assert.match(
    sealJob,
    /\.submission\.evidenceCompleteForSealing == true and[\s\S]*\.submission\.ready == false and[\s\S]*\.submission\.readyToSubmit == false and[\s\S]*\.submission\.submitted == false/
  );
  assert.match(
    sealJob,
    /\.projectionTrust == \{[\s\S]*status: "unsigned-projection",[\s\S]*readyClaimAllowed: false,[\s\S]*requiredSignerWorkflow:[\s\S]*"github\.com\/upgradedev\/archon-datahub\/\.github\/workflows\/submission-readiness\.yml",[\s\S]*requiredPredicateType:[\s\S]*"https:\/\/archon\.datahub\.dev\/attestations\/submission-readiness-seal\/v1"[\s\S]*\}/
  );
  const attestStepStart = sealJob.indexOf(
    "\n      - name: Attest canonical readiness subjects\n"
  );
  assert.notEqual(attestStepStart, -1, "canonical attestation step must exist");
  const attestStepEnd = sealJob.indexOf(
    "\n      - name:",
    attestStepStart + 1
  );
  assert.notEqual(
    attestStepEnd,
    -1,
    "canonical attestation step must have a bounded body"
  );
  const attestStep = sealJob.slice(attestStepStart, attestStepEnd);
  assert.equal(
    (
      attestStep.match(
        /actions\/attest@59d89421af93a897026c735860bf21b6eb4f7b26/g
      ) ?? []
    ).length,
    1,
    "seal must contain exactly one pinned attestation action"
  );
  const subjectBlock = /          subject-path: \|\n((?:            .+\n)+)/.exec(
    attestStep
  );
  assert.ok(subjectBlock, "canonical attestation must declare a subject block");
  assert.deepEqual(
    subjectBlock[1]!
      .trimEnd()
      .split("\n")
      .map((line) => line.trim()),
    [
      "${{ runner.temp }}/submission-readiness-seal/SHA256SUMS",
      "${{ runner.temp }}/submission-readiness-seal/approval-receipt.json",
      "${{ runner.temp }}/submission-readiness-seal/readiness-evidence.json",
      "${{ runner.temp }}/submission-readiness-seal/readiness.json",
      "${{ runner.temp }}/submission-readiness-seal/source-binding.json",
    ],
    "sealed subject set must be exact"
  );
  assert.equal(
    (
      attestStep.match(
        /^\s+predicate-type: https:\/\/archon\.datahub\.dev\/attestations\/submission-readiness-seal\/v1$/gm
      ) ?? []
    ).length,
    1
  );
  assert.equal(
    (
      attestStep.match(
        /^\s+predicate-path: \$\{\{ runner\.temp \}\}\/submission-readiness-seal\/readiness-evidence\.json$/gm
      ) ?? []
    ).length,
    1
  );
  assert.equal(
    (
      workflow.match(
        /bash scripts\/verify-submission-readiness-source\.sh/g
      ) ?? []
    ).length,
    2,
    "collection and protected review must independently execute the verifier"
  );
  assert.match(
    workflow,
    /computeReadiness\(\{\s*externalEvidence: \{ manifest, expectedBinding \}/
  );
  assert.match(
    workflow,
    /report\.submission\.evidenceCompleteForSealing/
  );
  assert.match(
    workflow,
    /report\.projectionTrust\.status !== "unsigned-projection"/
  );
  assert.doesNotMatch(
    workflow,
    /\.submission\.(?:ready|readyToSubmit|submitted) == true|!report\.submission\.(?:ready|readyToSubmit|submitted)/
  );
  assert.match(
    workflow,
    /actions\/attest@59d89421af93a897026c735860bf21b6eb4f7b26/
  );
  assert.doesNotMatch(
    workflow,
    /^\s{6}(?:manifest|claims|evidence)(?:_json|_path):|^\s{6}source_workflow_path:/m,
    "workflow_dispatch must not accept local JSON or choose the producer identity"
  );
  assert.match(
    workflow,
    /SOURCE_WORKFLOW_PATH: \.github\/workflows\/submission-evidence\.yml/
  );
  assert.doesNotMatch(
    workflow,
    /SOURCE_WORKFLOW_PATH: \$\{\{ inputs\./
  );
  assert.match(sourceVerifier, /actions\/artifacts\/\$\{SOURCE_ARTIFACT_ID\}\/zip/);
  assert.match(sourceVerifier, /actual_archive_digest=/);
  assert.match(sourceVerifier, /sha256sum --check --strict SHA256SUMS/);
  assert.match(sourceVerifier, /gh attestation verify/);
  assert.match(sourceVerifier, /--deny-self-hosted-runners/);
  assert.match(
    sourceVerifier,
    /SOURCE_WORKFLOW_PATH}" == "\.github\/workflows\/submission-evidence\.yml"/
  );
  assert.match(
    sourceVerifier,
    /SOURCE_ARTIFACT_NAME}" ==[\s\\\r\n]*"submission-evidence-\$\{RELEASE_SHA\}-\$\{SOURCE_PRODUCER_RUN_ATTEMPT\}"/
  );
  assert.match(
    sourceVerifier,
    /\(\( SOURCE_PRODUCER_RUN_ATTEMPT <= SOURCE_RUN_ATTEMPT \)\)/
  );
  assert.match(
    sourceVerifier,
    /"D4", "U3", "SQ3", "SQ4", "SQ5", "SQ6", "SQ7", "SQ8", "SQ10"/
  );
});

test("readiness: valid evidence is complete but cannot make an unsigned ready claim", async () => {
  const input = evidenceInput(
    REQUIRED_EXTERNAL_PROOFS.map((proof) => proof.id)
  );
  const validated = validateReadinessEvidenceManifest(input);
  assert.equal(validated.ok, true);

  const r = await computeReadiness({ externalEvidence: input });
  assert.equal(r.externalEvidence.status, "accepted");
  assert.deepEqual(
    r.externalEvidence.acceptedProofIds,
    REQUIRED_EXTERNAL_PROOFS.map((proof) => proof.id)
  );
  assert.equal(r.submission.ready, false);
  assert.equal(r.submission.readyToSubmit, false);
  assert.equal(r.submission.submitted, false);
  assert.equal(r.submission.evidenceCompleteForSealing, true);
  assert.equal(r.submission.postSubmitEvidenceComplete, false);
  assert.equal(r.submission.status, "evidence-complete-awaiting-seal");
  assert.equal(r.projectionTrust.status, "unsigned-projection");
  assert.equal(r.projectionTrust.readyClaimAllowed, false);
  assert.deepEqual(r.submission.internalBlockers, []);
  assert.deepEqual(r.submission.externalBlockers, []);
  assert.deepEqual(
    r.submission.recommendedEvidenceOutstanding.map((blocker) => blocker.id),
    ["SQ9"],
    "recommended sample outputs stay visible without blocking eligibility"
  );
  assert.deepEqual(
    r.submission.postSubmitBlockers.map((blocker) => blocker.id),
    ["SQ11"],
    "post-submit confirmation cannot be required before submission"
  );
});

test("readiness: accepted external evidence cannot change the offline capability metric", async () => {
  const baseline = await report();
  const accepted = await computeReadiness({
    externalEvidence: evidenceInput(
      REQUIRED_EXTERNAL_PROOFS.map((proof) => proof.id)
    ),
  });
  assert.equal(
    accepted.capabilityEvidence.offlineCapabilityPercent,
    baseline.capabilityEvidence.offlineCapabilityPercent
  );
  assert.deepEqual(
    accepted.capabilityEvidence.gate,
    baseline.capabilityEvidence.gate
  );
  assert.deepEqual(
    accepted.capabilityEvidence.checks.map((check) => check.id),
    baseline.capabilityEvidence.checks.map((check) => check.id)
  );
});

test("readiness: post-submit and bonus evidence use independent state axes", async () => {
  const input = evidenceInput(
    [
      ...REQUIRED_EXTERNAL_PROOFS.map((proof) => proof.id),
      "SQ11",
    ],
    ["BONUS-OSS", "BONUS-FEEDBACK"]
  );
  const r = await computeReadiness({ externalEvidence: input });
  assert.equal(r.submission.readyToSubmit, false);
  assert.equal(r.submission.submitted, false);
  assert.equal(r.submission.evidenceCompleteForSealing, true);
  assert.equal(r.submission.postSubmitEvidenceComplete, true);
  assert.equal(r.submission.status, "evidence-complete-awaiting-seal");
  assert.deepEqual(r.submission.postSubmitBlockers, []);
  assert.equal(r.bonus.allBonusesReady, true);
  assert.deepEqual(r.bonus.outstanding, []);
  assert.deepEqual(r.externalEvidence.acceptedBonusIds, [
    "BONUS-OSS",
    "BONUS-FEEDBACK",
  ]);
  assert.deepEqual(
    r.submission.recommendedEvidenceOutstanding.map((blocker) => blocker.id),
    ["SQ9"],
    "a seal-eligible post-submit projection can still report recommended evidence as outstanding"
  );
});

interface MutableEvidenceManifest {
  [key: string]: unknown;
  binding: {
    repository: string;
    releaseSha: string;
    source: {
      workflowPath: string;
      runId: number;
      producerRunAttempt: number;
      attestationRunAttempt: number;
    };
    artifact: { name: string; id: number; digest: string };
    predicate: { type: string; digest: string };
    approval: {
      environment: string;
      workflowPath: string;
      workflowRef: string;
      runId: number;
      runAttempt: number;
      environmentId: number;
      reviewerId: number;
      receiptDigest: string;
    };
  };
  proofs: Array<{
    id: string;
    criterion: string;
    status: string;
    evidence: string;
    receipt: { name: string; digest: string };
  }>;
}

test("readiness: malformed, unknown, duplicate, and tampered evidence fails closed", async () => {
  const mutations: Array<
    [string, (manifest: MutableEvidenceManifest) => void]
  > = [
    ["unknown top-level field", (manifest) => {
      manifest.unexpected = true;
    }],
    ["unknown proof", (manifest) => {
      manifest.proofs.push({
        id: "UNKNOWN",
        criterion: "submission-quality",
        status: "verified",
        evidence: "not registered",
        receipt: { name: "receipts/unknown.json", digest: SHA_A },
      });
    }],
    ["duplicate proof", (manifest) => {
      manifest.proofs.push(structuredClone(manifest.proofs[0]!));
    }],
    ["criterion mismatch", (manifest) => {
      manifest.proofs[0]!.criterion = "submission-quality";
    }],
    ["repository mismatch", (manifest) => {
      manifest.binding.repository = "attacker/repository";
    }],
    ["release mismatch", (manifest) => {
      manifest.binding.releaseSha = "d".repeat(40);
    }],
    ["source workflow mismatch", (manifest) => {
      manifest.binding.source.workflowPath =
        ".github/workflows/live-datahub-proof.yml";
    }],
    ["source run mismatch", (manifest) => {
      manifest.binding.source.runId += 1;
    }],
    ["source attempt order mismatch", (manifest) => {
      manifest.binding.source.producerRunAttempt =
        manifest.binding.source.attestationRunAttempt + 1;
    }],
    ["artifact id mismatch", (manifest) => {
      manifest.binding.artifact.id += 1;
    }],
    ["artifact name mismatch", (manifest) => {
      manifest.binding.artifact.name = "other-evidence";
    }],
    ["artifact digest mismatch", (manifest) => {
      manifest.binding.artifact.digest = `sha256:${"d".repeat(64)}`;
    }],
    ["predicate type mismatch", (manifest) => {
      manifest.binding.predicate.type = "https://attacker.invalid/predicate";
    }],
    ["predicate digest mismatch", (manifest) => {
      manifest.binding.predicate.digest = `sha256:${"e".repeat(64)}`;
    }],
    ["approval environment mismatch", (manifest) => {
      manifest.binding.approval.environment = "unprotected";
    }],
    ["approval workflow mismatch", (manifest) => {
      manifest.binding.approval.workflowRef =
        `${READINESS_REPOSITORY}/${READINESS_EVIDENCE_WORKFLOW_PATH}` +
        "@refs/heads/feature";
    }],
    ["approval run mismatch", (manifest) => {
      manifest.binding.approval.runAttempt += 1;
    }],
    ["approval environment id mismatch", (manifest) => {
      manifest.binding.approval.environmentId += 1;
    }],
    ["approval reviewer mismatch", (manifest) => {
      manifest.binding.approval.reviewerId += 1;
    }],
    ["approval receipt mismatch", (manifest) => {
      manifest.binding.approval.receiptDigest =
        `sha256:${"1".repeat(64)}`;
    }],
  ];

  const base = evidenceInput(
    REQUIRED_EXTERNAL_PROOFS.map((proof) => proof.id)
  );
  for (const [label, mutate] of mutations) {
    const candidate = structuredClone(base);
    const manifest = candidate.manifest as MutableEvidenceManifest;
    mutate(manifest);
    const result = validateReadinessEvidenceManifest(candidate);
    assert.equal(result.ok, false, `${label} must be rejected`);
  }

  const rejected = structuredClone(base);
  (rejected.manifest as MutableEvidenceManifest).binding.releaseSha =
    "f".repeat(40);
  const baseline = await report();
  const projection = applyReadinessEvidence(
    baseline.checks,
    createBonusChecks(),
    rejected
  );
  assert.equal(projection.status, "rejected");
  assert.ok(projection.errors.length > 0);
  assert.deepEqual(projection.acceptedProofIds, []);
  assert.deepEqual(
    projection.checks
      .filter((candidate) => REQUIRED_EXTERNAL_PROOFS.some(
        (proof) => proof.id === candidate.id
      ))
      .map((candidate) => candidate.status),
    REQUIRED_EXTERNAL_PROOFS.map(() => "user-gated"),
    "a rejected manifest must not partially transition any proof"
  );

  const rejectedReport = await computeReadiness({
    externalEvidence: rejected,
  });
  assert.equal(rejectedReport.externalEvidence.status, "rejected");
  assert.equal(rejectedReport.submission.readyToSubmit, false);
  assert.ok(
    rejectedReport.submission.internalBlockers.some(
      (blocker) => blocker.id === "EVIDENCE:manifest"
    )
  );

  const wrongTarget = applyReadinessEvidence(
    baseline.checks.map((candidate) =>
      candidate.id === "D4"
        ? { ...candidate, status: "pass" as const }
        : candidate
    ),
    createBonusChecks(),
    base
  );
  assert.equal(wrongTarget.status, "rejected");
  assert.match(wrongTarget.errors[0]!, /must target exactly one user-gated check/);
});

test("readiness: the tolerant CI threshold can never hide a final capability failure", () => {
  const officialChecks = completeOfficialChecks();
  const capabilityChecks = completeCapabilityChecks().map((check) =>
    check.axis === "security" ? { ...check, status: "fail" as const } : check
  );

  const submission = evaluateSubmission(officialChecks, capabilityChecks);
  assert.equal(submission.ready, false);
  assert.equal(submission.status, "blocked");
  assert.deepEqual(
    submission.internalBlockers.map((blocker) => blocker.id),
    ["SEC-example"]
  );
  assert.deepEqual(submission.externalBlockers, []);
});

test("readiness: missing criterion, capability axis, or external-proof check fails closed", () => {
  const withoutCriterion = evaluateSubmission(
    completeOfficialChecks().filter(
      (check) => check.criterion !== "originality"
    ),
    completeCapabilityChecks()
  );
  assert.ok(
    withoutCriterion.internalBlockers.some(
      (blocker) => blocker.id === "STRUCTURE:criterion:originality"
    )
  );
  assert.equal(withoutCriterion.ready, false);

  const withoutSecurityAxis = evaluateSubmission(
    completeOfficialChecks(),
    completeCapabilityChecks().filter((check) => check.axis !== "security")
  );
  assert.ok(
    withoutSecurityAxis.internalBlockers.some(
      (blocker) => blocker.id === "STRUCTURE:capability-axis:security"
    )
  );
  assert.equal(withoutSecurityAxis.ready, false);

  const withoutDisclosureProof = evaluateSubmission(
    completeOfficialChecks().filter((check) => check.id !== "SQ8"),
    completeCapabilityChecks()
  );
  assert.ok(
    withoutDisclosureProof.internalBlockers.some(
      (blocker) => blocker.id === "STRUCTURE:external-proof:SQ8"
    )
  );
  assert.equal(withoutDisclosureProof.ready, false);
});

test("readiness: duplicate and cross-registry check IDs fail closed", () => {
  const official = completeOfficialChecks();
  const capabilities = completeCapabilityChecks();
  const duplicateOfficial = evaluateSubmission(
    [...official, { ...official[0]! }],
    capabilities
  );
  assert.ok(
    duplicateOfficial.internalBlockers.some(
      (blocker) => blocker.id === "STRUCTURE:duplicate-check-id:D4"
    )
  );

  const duplicateCapability = evaluateSubmission(official, [
    ...capabilities,
    { ...capabilities[0]! },
  ]);
  assert.ok(
    duplicateCapability.internalBlockers.some(
      (blocker) =>
        blocker.id === "STRUCTURE:duplicate-capability-id:ENG-example"
    )
  );

  const crossRegistry = evaluateSubmission(official, [
    ...capabilities,
    { ...capabilities[0]!, id: "D4" },
  ]);
  assert.ok(
    crossRegistry.internalBlockers.some(
      (blocker) => blocker.id === "STRUCTURE:cross-registry-id:D4"
    )
  );
});

test("readiness: invalid weights and external-proof mappings fail closed", () => {
  const invalidOfficialWeight = completeOfficialChecks().map((check) =>
    check.id === "D4" ? { ...check, weight: 0 } : check
  );
  const invalidCapabilityWeight = completeCapabilityChecks().map((check) =>
    check.id === "SEC-example" ? { ...check, weight: Number.NaN } : check
  );
  const invalidWeights = evaluateSubmission(
    invalidOfficialWeight,
    invalidCapabilityWeight
  );
  assert.ok(
    invalidWeights.internalBlockers.some(
      (blocker) => blocker.id === "STRUCTURE:check-weight:D4"
    )
  );
  assert.ok(
    invalidWeights.internalBlockers.some(
      (blocker) => blocker.id === "STRUCTURE:capability-weight:SEC-example"
    )
  );

  const wrongCriterion = completeOfficialChecks().map((check) =>
    check.id === "SQ7"
      ? { ...check, criterion: "originality" as const }
      : check
  );
  const invalidMapping = evaluateSubmission(
    wrongCriterion,
    completeCapabilityChecks()
  );
  assert.ok(
    invalidMapping.internalBlockers.some(
      (blocker) =>
        blocker.id === "STRUCTURE:external-proof-mapping:SQ7"
    )
  );
  assert.equal(invalidMapping.ready, false);
});
