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
import {
  computeReadiness,
  evaluateSubmission,
  REQUIRED_EXTERNAL_PROOFS,
  type CapabilityCheck,
  type Check,
} from "../../scripts/readiness.js";

let reportPromise: ReturnType<typeof computeReadiness> | undefined;
const report = (): ReturnType<typeof computeReadiness> =>
  (reportPromise ??= computeReadiness());

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

test("readiness: external-proof IDs retain their exact official criterion mapping", () => {
  assert.deepEqual(REQUIRED_EXTERNAL_PROOFS, [
    { id: "D4", criterion: "use-of-datahub" },
    { id: "U3", criterion: "real-world-usefulness" },
    { id: "SQ3", criterion: "submission-quality" },
    { id: "SQ4", criterion: "submission-quality" },
    { id: "SQ5", criterion: "submission-quality" },
    { id: "SQ6", criterion: "submission-quality" },
    { id: "SQ7", criterion: "submission-quality" },
    { id: "SQ8", criterion: "submission-quality" },
    { id: "SQ9", criterion: "submission-quality" },
    { id: "SQ10", criterion: "submission-quality" },
    { id: "SQ11", criterion: "submission-quality" },
  ]);
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

test("readiness: required public deliverables keep final submission blocked", async () => {
  const r = await report();
  assert.ok(
    r.judgingEvidencePercent < 100,
    "official evidence coverage must include outstanding external proof"
  );
  assert.equal(r.submission.status, "blocked");
  assert.equal(r.submission.ready, false);
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
      "SQ9",
      "SQ10",
      "SQ11",
    ]
  );
  assert.deepEqual(
    r.submission.externalBlockers.map((blocker) => blocker.id),
    r.userGated.map((check) => check.id),
    "every future user-gated official check must fail closed as a submission blocker"
  );
  assert.ok(
    r.userGated.length >= 11,
    "live proof, public deliverables, retained samples, judging access, and final entry remain user-gated"
  );
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
