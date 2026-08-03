#!/usr/bin/env python3
"""Remote-CI contract tests for the submission evidence trust boundary."""

from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import json
import tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts" / "validate-submission-proof-receipts.py"
REGISTRY_PATH = ROOT / "scripts" / "submission-evidence-registry.json"
NOTICE_PATH = ROOT / "NOTICE.md"
RELEASE = "a" * 40
DIGEST = "sha256:" + ("b" * 64)
ALT_DIGEST = "sha256:" + ("c" * 64)
THIRD_DIGEST = "sha256:" + ("d" * 64)
NOW = (
    dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
).replace(microsecond=0)
BONUS_EVENT = min(
    NOW,
    dt.datetime(2026, 8, 9, 12, 0, 0, tzinfo=dt.timezone.utc),
)
if BONUS_EVENT < dt.datetime(2026, 7, 6, 13, 0, 0, tzinfo=dt.timezone.utc):
    BONUS_EVENT = dt.datetime(2026, 7, 6, 13, 0, 0, tzinfo=dt.timezone.utc)


def iso(value: dt.datetime = NOW) -> str:
    return value.isoformat().replace("+00:00", "Z")


def load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "submission_evidence_validator", VALIDATOR_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("validator module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load_validator()
registry, sources = validator.load_registry(REGISTRY_PATH)
TESTING_DIGEST = validator.sha256_file(ROOT / "docs" / "JUDGE_TESTING.md")


def expect_rejected(callable_value, message: str) -> None:
    try:
        callable_value()
    except validator.ContractError:
        return
    raise AssertionError(message)


def valid_facts() -> dict[str, dict]:
    application = "https://www.datahub.com"
    application_digest = validator.sha256_text(application)
    application_origin_sha256 = application_digest.removeprefix("sha256:")
    availability_observed_at = iso(NOW - dt.timedelta(minutes=30))
    feedback_rules_observed_at = BONUS_EVENT + dt.timedelta(seconds=10)
    feedback_review_job_started_at = BONUS_EVENT + dt.timedelta(seconds=20)
    bonus_oss_paths = [
        "src/mcp_server_datahub/mcp_server.py",
        "src/mcp_server_datahub/tools/__init__.py",
        "src/mcp_server_datahub/tools/aspect_history.py",
        "tests/test_mcp/test_get_aspect_history.py",
    ]
    bonus_oss_base_sha = "1" * 40
    bonus_oss_head_sha = "2" * 40
    bonus_oss_head_tree_sha = "3" * 40
    bonus_oss_merge_sha = "4" * 40
    bonus_oss_merge_tree_sha = "5" * 40
    bonus_oss_files = [
        {
            "path": path,
            "mode": "100644",
            "gitBlobSha": f"{index + 6:x}" * 40,
            "sha256": DIGEST,
        }
        for index, path in enumerate(bonus_oss_paths)
    ]
    bonus_oss_applied_diff_digest = ALT_DIGEST
    bonus_oss_candidate_digest = validator.canonical_json_digest(
        {
            "schemaVersion": "archon.oss-candidate-binding/v1",
            "upstreamRepository": "acryldata/mcp-server-datahub",
            "baseCommit": bonus_oss_base_sha,
            "appliedDiffDigest": bonus_oss_applied_diff_digest,
            "reconstructedTreeSha": bonus_oss_head_tree_sha,
            "files": bonus_oss_files,
        }
    )
    deployment = {
        "workflowPath": ".github/workflows/deploy.yml",
        "runId": 201,
        "runAttempt": 2,
        "artifactId": 202,
        "artifactName": f"deployment-evidence-production-{RELEASE}-201",
        "artifactDigest": DIGEST,
        "predicateType": (
            "https://github.com/upgradedev/archon-datahub/"
            "attestations/aws-deployment/v2"
        ),
        "predicateDigest": DIGEST,
    }
    identity_digest = DIGEST
    cognito_subject_digest = ALT_DIGEST
    lifecycle_operations = []
    for index, (operation, result, receipt_character) in enumerate(
        (
            ("provision", "provisioned-and-readback-verified", "d"),
            ("rotate", "rotated-and-readback-verified", "e"),
            ("deactivate", "deactivated-and-readback-verified", "f"),
            ("reactivate", "reactivated-and-readback-verified", "1"),
        )
    ):
        receipt_digest = "sha256:" + (receipt_character * 64)
        attempt = index + 1
        lifecycle_operations.append(
            {
                "operation": operation,
                "workflowPath": ".github/workflows/judge-user.yml",
                "stage": "production",
                "runId": 210 + index,
                "runAttempt": attempt,
                "artifactId": 220 + index,
                "artifactName": (
                    f"judge-user-operation-{operation}-{RELEASE}-{attempt}"
                ),
                "artifactDigest": DIGEST,
                "predicateType": (
                    "https://github.com/upgradedev/archon-datahub/"
                    "attestations/judge-user-operation/v1"
                ),
                "predicateDigest": DIGEST,
                "verificationDigest": DIGEST,
                "releaseSha": RELEASE,
                "identityDigest": identity_digest,
                "cognitoSubjectDigest": cognito_subject_digest,
                "applicationOriginSha256": application_origin_sha256,
                "operationReceiptDigest": receipt_digest,
                "performedAt": iso(NOW - dt.timedelta(hours=4 - index)),
                "result": result,
                "sanitized": True,
                "secretMaterialRetained": False,
            }
        )
    history_digest = DIGEST
    notice_digest = validator.sha256_file(NOTICE_PATH)
    disclosure_set_digest = validator.canonical_json_digest(
        {
            "noticeDigest": notice_digest,
            "preExistingWorkInventoryDigest": DIGEST,
            "thirdPartyInventoryDigest": DIGEST,
        }
    )
    rules = {
        "officialRulesUrl": "https://datahub.devpost.com/rules",
        "snapshotDigest": DIGEST,
        "submissionStart": "2026-07-06T13:00:00Z",
        "submissionEnd": "2026-08-10T21:00:00Z",
    }
    facts = {
        "D4": {
            "applicationUrl": application,
            "evidenceClass": "LIVE_DEPLOYED_DATAHUB",
            "liveDataHubRead": True,
            "retainedHistoryRead": True,
            "stableSourceCount": 2,
            "recoveredContradictions": 1,
            "governedWrite": {
                "workflowRunId": 101,
                "result": "write-verified-and-rollback-proven",
                "rollbackSubjectDigest": DIGEST,
                "rollbackEvidenceDigest": DIGEST,
                "attestationPredicateDigest": DIGEST,
                "attestationVerificationDigest": DIGEST,
            },
            "provenAt": iso(),
        },
        "U3": {
            "evidenceClass": "LIVE_DEPLOYED_DATAHUB",
            "datasetUrnDigest": DIGEST,
            "classification": {
                "totalEntities": 1,
                "withLineage": 1,
                "sensitiveEntities": 1,
            },
            "findings": {
                "totalCount": 3,
                "g6": {
                    "exactTarget": True,
                    "fieldPath": "email",
                    "classificationAbsent": True,
                    "blastRootBound": True,
                    "downstreamCount": 0,
                    "maxHops": 3,
                    "truncated": False,
                    "impact": "none",
                },
                "danglingLineage": {
                    "exactUpstream": True,
                    "upstreamAbsent": True,
                    "blastRootBound": True,
                    "targetConsumerMinHops": 1,
                    "downstreamCount": 1,
                    "maxHops": 3,
                    "truncated": False,
                    "impact": "low",
                },
                "retainedHistory": {
                    "exactTarget": True,
                    "attribute": "owner",
                    "provenanceCount": 2,
                    "stableSourceCount": 2,
                    "statuses": ["conflicting", "trusted"],
                    "retainedOwnershipHistorySha256": "c" * 64,
                },
            },
            "provenAt": iso(),
        },
        "SQ3": {
            "applicationUrl": application,
            "applicationOriginDigest": application_digest,
            "deployment": copy.deepcopy(deployment),
            "observation": {
                "observedAt": iso(),
                "availabilityObservedAt": availability_observed_at,
                "loggedOutAccessible": True,
                "httpStatus": 200,
                "redirectsObserved": 0,
                "strictTls": True,
                "releaseMatched": True,
                "availabilityRunId": 203,
                "availabilityRunAttempt": 3,
                "availabilityArtifactId": 204,
                "availabilityArtifactName": (
                    f"production-availability-{RELEASE}-203"
                ),
                "availabilityArtifactDigest": DIGEST,
                "availabilityPredicateType": (
                    "https://github.com/upgradedev/archon-datahub/"
                    "attestations/production-availability/v2"
                ),
                "availabilityPredicateDigest": DIGEST,
            },
        },
        "SQ4": {
            "applicationUrl": application,
            "authenticationRequired": True,
            "accessMode": "pipeline-managed-confirmed",
            "deployment": copy.deepcopy(deployment),
            "judgeUserLifecycle": {
                "releaseSha": RELEASE,
                "stage": "production",
                "identityDigest": identity_digest,
                "cognitoSubjectDigest": cognito_subject_digest,
                "applicationOriginSha256": application_origin_sha256,
                "chainDigest": validator.canonical_json_digest(
                    lifecycle_operations
                ),
                "operations": lifecycle_operations,
                "sanitized": True,
                "secretMaterialRetained": False,
            },
            "freshJudgeJourney": {
                "workflowPath": ".github/workflows/submission-judge-journey.yml",
                "stage": "production",
                "runId": 230,
                "runAttempt": 1,
                "artifactId": 231,
                "artifactName": f"submission-judge-journey-{RELEASE}-1",
                "artifactDigest": DIGEST,
                "predicateType": (
                    "https://archon.datahub.dev/attestations/"
                    "submission-judge-journey/v1"
                ),
                "predicateDigest": DIGEST,
                "verificationDigest": DIGEST,
                "releaseSha": RELEASE,
                "identityDigest": identity_digest,
                "cognitoSubjectDigest": cognito_subject_digest,
                "applicationOriginSha256": application_origin_sha256,
                "journeyStartedAt": iso(NOW - dt.timedelta(minutes=30)),
                "journeyCompletedAt": iso(NOW - dt.timedelta(minutes=10)),
                "identityIsFresh": True,
                "loginSucceeded": True,
                "startSucceeded": True,
                "statusPollingSucceeded": True,
                "terminalReceiptVerified": True,
                "logoutIsolationVerified": True,
                "terminalReceiptDigest": DIGEST,
                "sanitized": True,
                "secretMaterialRetained": False,
            },
            "testingInstructionsPath": "docs/JUDGE_TESTING.md",
            "testingInstructionsDigest": TESTING_DIGEST,
            "credentialRotation": {
                "pipelineManagedConfirmed": True,
                "secretMaterialRetained": False,
                "rotationTested": True,
                "recoveryTested": True,
            },
            "freeAccess": True,
            "accessValidThrough": "2026-08-31T21:00:00Z",
            "observedAt": iso(),
        },
        "SQ5": {
            "repositoryUrl": "https://github.com/upgradedev/archon-datahub",
            "releaseUrl": (
                f"https://github.com/upgradedev/archon-datahub/tree/{RELEASE}"
            ),
            "licenseUrl": (
                f"https://github.com/upgradedev/archon-datahub/blob/"
                f"{RELEASE}/LICENSE"
            ),
            "defaultBranch": "master",
            "releaseVisible": True,
            "loggedOutAccessible": True,
            "completeSource": True,
            "licenseSpdx": "Apache-2.0",
            "hostingUiDetectedLicense": True,
            "observedAt": iso(),
        },
        "SQ6": {
            "allWrittenFieldsComplete": True,
            "submissionLanguage": "en",
            "testingInstructionsLanguage": "en",
            "completeEnglishTranslation": True,
            "submissionFieldsDigest": DIGEST,
            "testingInstructionsPath": "docs/JUDGE_TESTING.md",
            "testingInstructionsDigest": TESTING_DIGEST,
            "claimsDigest": DIGEST,
            "reviewedAt": iso(),
        },
        "SQ7": {
            "videoUrl": "https://www.youtube.com/watch?v=ArchonDemo1",
            "publiclyAccessible": True,
            "loggedOutAccessible": True,
            "durationSeconds": 179,
            "providerResponseDigests": {
                "preparedResponseDigest": DIGEST,
                "reviewResponseDigest": ALT_DIGEST,
            },
            "spokenLanguage": "en",
            "subtitlesLanguage": "none",
            "completeEnglishTranslation": True,
            "functioningProjectShown": True,
            "thirdPartyMarksAndMusicAuthorized": True,
            "allThirdPartyMaterialAuthorized": True,
            "mediaReviewDigest": DIGEST,
            "shownApplicationUrl": application,
            "claimsDigest": DIGEST,
            "reviewedAt": iso(),
        },
        "SQ8": {
            "rules": copy.deepcopy(rules),
            "projectHistory": {
                "projectStartedAt": "2026-07-06T20:26:56Z",
                "repositoryCreatedAt": "2026-07-06T20:31:38Z",
                "rootCommitSha": "2" * 40,
                "rootCommitAuthoredAt": "2026-07-06T20:26:56Z",
                "rootCommitCommittedAt": "2026-07-06T20:26:56Z",
                "rootCommitParentCount": 0,
                "releaseCommitSha": RELEASE,
                "releaseCommitCommittedAt": iso(NOW - dt.timedelta(minutes=5)),
                "reachableCommitCount": 12,
                "allReachableCommitsWithinSubmissionPeriod": True,
                "historyDigest": history_digest,
            },
            "reviewedSurfaces": [
                "NOTICE.md",
                "repository-history",
                "submission-fields",
                "testing-instructions",
                "video",
            ],
            "noticeDigest": notice_digest,
            "repositoryHistoryDigest": history_digest,
            "submissionFieldsDigest": DIGEST,
            "testingInstructionsDigest": TESTING_DIGEST,
            "submissionClaimsDigest": DIGEST,
            "videoClaimsDigest": DIGEST,
            "preExistingWorkInventoryDigest": DIGEST,
            "thirdPartyInventoryDigest": DIGEST,
            "disclosureSetDigest": disclosure_set_digest,
            "allNonStandardPreExistingWorkDisclosed": True,
            "workDescribedAndSubmittedBuiltDuringPeriod": True,
            "standardToolsOnlyExcludedFromDisclosure": True,
            "thirdPartyIntegrationsAuthorized": True,
            "originalWorkOwnershipReviewed": True,
            "crossMediumConsistent": True,
            "reviewApproval": {
                "approvalMode": "solo-owner",
                "environment": "submission-content-review",
                "workflowPath": ".github/workflows/submission-content-review.yml",
                "runId": 903,
                "runAttempt": 1,
                "environmentId": 604,
                "workflowActorId": 601,
                "triggeringActorId": 601,
                "reviewerId": 601,
                "candidateRunAttempt": 1,
                "candidateArtifactId": 2003,
                "candidateArtifactDigest": ALT_DIGEST,
                "candidateDigest": DIGEST,
                "approvalCommentDigest": ALT_DIGEST,
                "approvalReceiptDigest": DIGEST,
            },
            "finalizedAt": iso(NOW - dt.timedelta(minutes=1)),
            "reviewedAt": iso(),
        },
        "SQ9": {
            "evidenceClass": "SYNTHETIC_OFFLINE_FIXTURE",
            "ci": {
                "workflowPath": ".github/workflows/ci.yml",
                "runId": 301,
                "runAttempt": 1,
                "predicateType": (
                    "https://github.com/upgradedev/archon-datahub/"
                    "attestations/ci-release/v1"
                ),
                "predicateDigest": DIGEST,
            },
            "artifact": {
                "id": 302,
                "name": f"judge-evidence-{RELEASE}-1",
                "digest": DIGEST,
                "producerAttempt": 1,
            },
            "manifestDigest": DIGEST,
            "formats": [
                "approval",
                "dossier",
                "json",
                "markdown",
                "plan",
                "receipt",
                "rollback",
                "sarif",
            ],
            "sanitized": True,
            "notLiveProof": True,
        },
        "SQ10": {
            "applicationUrl": application,
            "availability": {
                "workflowPath": ".github/workflows/availability.yml",
                "runId": 203,
                "runAttempt": 3,
                "artifactId": 204,
                "artifactName": f"production-availability-{RELEASE}-203",
                "artifactDigest": DIGEST,
                "predicateType": (
                    "https://github.com/upgradedev/archon-datahub/"
                    "attestations/production-availability/v2"
                ),
                "predicateDigest": DIGEST,
                "observedAt": availability_observed_at,
                "result": "passed",
                "profileResponseDigest": DIGEST,
                "observationDigest": DIGEST,
            },
            "posture": {
                "workflowPath": ".github/workflows/production-posture.yml",
                "runId": 403,
                "runAttempt": 5,
                "artifactId": 404,
                "artifactName": f"production-posture-{RELEASE}-403",
                "artifactDigest": DIGEST,
                "predicateType": (
                    "https://github.com/upgradedev/archon-datahub/"
                    "attestations/production-posture/v2"
                ),
                "predicateDigest": DIGEST,
                "observedAt": iso(),
                "result": "passed",
                "checks": {
                    "leanRuntimeControls": True,
                    "zeroIdleCore": True,
                    "cloudFormationDrift": "IN_SYNC",
                    "alarmsNotFiring": True,
                    "legacyAlwaysOnRuntimeAbsent": True,
                },
                "observationDigest": DIGEST,
                "driftEvidenceDigest": ALT_DIGEST,
                "alarmNames": [
                    "archon-production-control-plane-errors",
                    "archon-production-runtime-failure-queue-visible",
                ],
            },
            "alerting": {
                "alarmsActive": True,
                "encryptedRouteBound": True,
                "externalPagingDeliveryTested": True,
                "lastPagingTestAt": iso(),
                "pagingDelivery": {
                    "workflowPath": (
                        ".github/workflows/production-paging-test.yml"
                    ),
                    "runId": 405,
                    "runAttempt": 6,
                    "artifactId": 406,
                    "artifactName": (
                        f"production-alarm-delivery-{RELEASE}-405"
                    ),
                    "artifactDigest": DIGEST,
                    "predicateType": (
                        "https://github.com/upgradedev/archon-datahub/"
                        "attestations/production-alarm-delivery/v2"
                    ),
                    "predicateDigest": DIGEST,
                    "provedAt": iso(),
                    "route": "CloudWatch->SNS(KMS)->SQS(KMS)",
                    "checks": {
                        "exactAlarm": True,
                        "alarmTransition": True,
                        "topicBinding": True,
                        "encryptedProofQueue": True,
                        "endToEndDelivery": True,
                        "cleanupRegistered": True,
                    },
                    "deliveryDigest": DIGEST,
                },
            },
            "recovery": {
                "rollbackPathTested": True,
                "credentialRotationTested": True,
                "lastRollbackTestAt": iso(),
                "lastCredentialRotationTestAt": (
                    lifecycle_operations[1]["performedAt"]
                ),
                "governedCanary": {
                    "workflowPath": ".github/workflows/governed-canary.yml",
                    "runId": 101,
                    "runAttempt": 1,
                    "artifactId": 408,
                    "artifactName": "governed-canary-rollback-101-1",
                    "artifactDigest": DIGEST,
                    "predicateType": (
                        "https://github.com/upgradedev/archon-datahub/"
                        "attestations/governed-canary-cloud-v2"
                    ),
                    "predicateDigest": DIGEST,
                    "verifiedAt": iso(),
                    "subjectDigest": DIGEST,
                    "rollbackEvidenceDigest": DIGEST,
                    "attestationVerificationDigest": DIGEST,
                },
            },
            "access": {
                "freeJudgeAccess": True,
                "confirmedCredentialOrPublicNoAuth": True,
                "validThrough": "2026-08-31T21:00:00Z",
                "projectAccess": {
                    "workflowPath": (
                        ".github/workflows/submission-project-access.yml"
                    ),
                    "runId": 903,
                    "runAttempt": 1,
                    "artifactId": 1003,
                    "artifactName": (
                        f"submission-project-access-{RELEASE}-1"
                    ),
                    "artifactDigest": DIGEST,
                    "predicateType": (
                        "https://archon.datahub.dev/attestations/"
                        "submission-project-access/v1"
                    ),
                    "predicateDigest": DIGEST,
                    "observedAt": iso(),
                    "credentialRotationPerformedAt": (
                        lifecycle_operations[1]["performedAt"]
                    ),
                },
            },
            "monitoringWindow": {
                "schedule": "*/30 * * * *",
                "maximumExpectedGapMinutes": 90,
                "active": True,
                "through": "2026-08-31T21:00:00Z",
            },
        },
        "SQ11": {
            "rules": {
                **copy.deepcopy(rules),
                "judgingStart": "2026-08-17T14:00:00Z",
                "judgingEnd": "2026-08-31T21:00:00Z",
            },
            "challengeUrl": "https://datahub.devpost.com/",
            "devpostProjectUrl": "https://devpost.com/software/archon-datahub",
            "submissionStatus": "submitted",
            "submittedAt": iso(NOW - dt.timedelta(seconds=30)),
            "confirmationDigest": DIGEST,
            "allRequiredFieldsSubmitted": True,
            "challengeEntryVisible": True,
            "descriptionDigest": DIGEST,
            "submissionFieldsDigest": DIGEST,
            "testingInstructionsDigest": TESTING_DIGEST,
            "submissionClaimsDigest": DIGEST,
            "videoClaimsDigest": DIGEST,
            "applicationUrl": application,
            "applicationAuthenticationRequired": True,
            "repositoryUrl": "https://github.com/upgradedev/archon-datahub",
            "videoUrl": "https://www.youtube.com/watch?v=ArchonDemo1",
            "loggedOutVerification": {
                "observedAt": iso(),
                "devpostEntry": {
                    "url": "https://devpost.com/software/archon-datahub",
                    "httpStatus": 200,
                    "loggedOutAccessible": True,
                    "redirectsObserved": 0,
                    "loginRequired": False,
                },
                "application": {
                    "url": application,
                    "httpStatus": 200,
                    "loggedOutAccessible": True,
                    "redirectsObserved": 0,
                    "loginRequired": True,
                },
                "repository": {
                    "url": "https://github.com/upgradedev/archon-datahub",
                    "httpStatus": 200,
                    "loggedOutAccessible": True,
                    "redirectsObserved": 0,
                    "loginRequired": False,
                },
                "video": {
                    "url": "https://www.youtube.com/watch?v=ArchonDemo1",
                    "httpStatus": 200,
                    "loggedOutAccessible": True,
                    "redirectsObserved": 0,
                    "loginRequired": False,
                },
            },
            "preSubmitSeal": {
                "workflowPath": ".github/workflows/submission-readiness.yml",
                "runId": 701,
                "runAttempt": 1,
                "artifactId": 702,
                "artifactName": f"submission-readiness-{RELEASE}",
                "artifactDigest": DIGEST,
                "inventoryDigest": DIGEST,
                "subjectSetDigest": DIGEST,
                "predicateType": (
                    "https://archon.datahub.dev/attestations/"
                    "submission-readiness-seal/v1"
                ),
                "predicateDigest": DIGEST,
                "readinessEvidenceDigest": DIGEST,
                "readinessDigest": DIGEST,
                "sourceBindingDigest": DIGEST,
                "approvalReceiptDigest": DIGEST,
                "sealedAt": iso(NOW - dt.timedelta(minutes=1)),
            },
            "reviewApproval": {
                "approvalMode": "solo-owner",
                "environment": "submission-devpost-confirmation",
                "workflowActorId": 703,
                "triggeringActorId": 703,
                "reviewerId": 703,
                "approvalReceiptDigest": ALT_DIGEST,
            },
        },
        "BONUS-OSS": {
            "upstreamRepositoryUrl": "https://github.com/acryldata/mcp-server-datahub",
            "pullRequestUrl": "https://github.com/acryldata/mcp-server-datahub/pull/12345",
            "state": "merged",
            "publiclyAccessible": True,
            "acceptedByMaintainer": True,
            "acceptedAt": iso(BONUS_EVENT),
            "patchDigest": DIGEST,
            "validatedCandidateDigest": bonus_oss_candidate_digest,
            "upstreamPullRequest": {
                "number": 12345,
                "baseRef": "main",
                "baseSha": bonus_oss_base_sha,
                "headSha": bonus_oss_head_sha,
                "headTreeSha": bonus_oss_head_tree_sha,
                "mergeCommitSha": bonus_oss_merge_sha,
                "mergeTreeSha": bonus_oss_merge_tree_sha,
                "changedPaths": bonus_oss_paths,
                "authorId": 601,
                "authorLogin": "archon-contributor",
                "mergedById": 602,
                "mergedByLogin": "datahub-maintainer",
                "mergedAt": iso(BONUS_EVENT),
            },
            "candidateBinding": {
                "baseCommit": bonus_oss_base_sha,
                "appliedDiffDigest": bonus_oss_applied_diff_digest,
                "reconstructedTreeSha": bonus_oss_head_tree_sha,
                "canonicalFileManifestDigest": bonus_oss_candidate_digest,
                "files": bonus_oss_files,
                "exactHeadTreeMatch": True,
                "exactMergedPathBytesMatch": True,
            },
            "ciValidation": {
                "workflowPath": ".github/workflows/ci.yml",
                "runId": 501,
                "runAttempt": 1,
                "artifactId": 502,
                "artifactName": f"oss-validation-receipt-{RELEASE}",
                "artifactDigest": DIGEST,
                "artifactProducerAttempt": 1,
                "receiptDigest": ALT_DIGEST,
                "predicateType": (
                    "https://github.com/upgradedev/archon-datahub/"
                    "attestations/ci-release/v1"
                ),
                "predicateDigest": THIRD_DIGEST,
                "attestedSubjectName": "archon-lambdas.tar.gz",
                "attestedSubjectDigest": DIGEST,
            },
        },
        "BONUS-FEEDBACK": {
            "challengeUrl": "https://datahub.devpost.com/",
            "officialRulesUrl": "https://datahub.devpost.com/rules",
            "status": "submitted",
            "submittedAt": iso(BONUS_EVENT),
            "canonicalEvidenceDigest": DIGEST,
            "confirmationDigest": ALT_DIGEST,
            "entrantBindingDigest": THIRD_DIGEST,
            "entrantKind": "individual",
            "registeredEntrant": True,
            "oneEntryPerEntrant": True,
            "individualNotProjectPrize": True,
            "distinctFeedbackSubmissionUnderRules": True,
            "feedbackQuality": {
                "complete": True,
                "actionable": True,
                "viable": True,
                "potentialImpact": True,
            },
            "privacyDisclosure": {
                "rawFeedbackIncluded": False,
                "rawEntrantPersonalDataIncluded": False,
                "devpostCredentialsIncluded": False,
                "privateConfirmationBytesIncluded": False,
                "pseudonymousEntrantCommitmentIncluded": True,
                "publicReviewerNumericIdentifierIncluded": True,
            },
            "rulesObservation": {
                "observedAt": iso(feedback_rules_observed_at),
                "feedbackStart": "2026-07-06T13:00:00Z",
                "feedbackDeadline": "2026-08-10T21:00:00Z",
                "semanticDigest": DIGEST,
                "authenticatedUiObserved": False,
                "publicOverviewInstruction": (
                    "complete-feedback-section-during-submission"
                ),
            },
            "approvalTiming": {
                "authoritativeApprovalTimestampAvailable": False,
                "reviewJobStartedAt": iso(feedback_review_job_started_at),
            },
            "reviewApproval": {
                "approvalMode": "solo-owner",
                "environment": "submission-bonus-feedback",
                "workflowPath": (
                    ".github/workflows/submission-bonus-feedback.yml"
                ),
                "runId": 991,
                "runAttempt": 1,
                "environmentId": 802,
                "workflowActorId": 803,
                "triggeringActorId": 803,
                "reviewerId": 803,
                "candidateRunAttempt": 1,
                "candidateArtifactId": 806,
                "candidateArtifactDigest": DIGEST,
                "candidateDigest": ALT_DIGEST,
                "canonicalEvidenceDigest": DIGEST,
                "confirmationDigest": ALT_DIGEST,
                "approvalCommentDigest": THIRD_DIGEST,
                "approvalReceiptDigest": DIGEST,
            },
        },
    }
    return facts


def make_receipt(proof_id: str, facts: dict) -> dict:
    source = validator.source_for_proof(proof_id, sources)
    attempt = 1
    return {
        "schemaVersion": validator.RECEIPT_SCHEMA,
        "id": proof_id,
        "criterion": validator.PROOF_CRITERIA[proof_id],
        "repository": validator.REPOSITORY,
        "releaseSha": RELEASE,
        "source": {
            "workflowPath": source["workflowPath"],
            "runId": 900 + len(proof_id),
            "runAttempt": attempt,
            "artifact": {
                "id": 1000 + len(proof_id),
                "name": validator.artifact_name(source, RELEASE, attempt),
                "digest": DIGEST,
            },
            "attestation": {
                "predicateType": source["predicateType"],
                "predicateDigest": DIGEST,
                "subjectSetDigest": DIGEST,
                "verificationSetDigest": DIGEST,
                "subjects": [
                    {
                        "role": subject["role"],
                        "name": subject["name"],
                        "digest": DIGEST,
                    }
                    for subject in validator.expected_receipt_subject_names(
                        source,
                        proof_id,
                    )
                ],
            },
        },
        "facts": facts,
    }


facts_by_id = valid_facts()
for registered_id, facts in facts_by_id.items():
    validator.validate_facts(
        registered_id,
        facts,
        RELEASE,
        notice_path=NOTICE_PATH,
    )
    validator.validate_receipt(
        make_receipt(registered_id, facts),
        sources,
        validator.REPOSITORY,
        RELEASE,
        notice_path=NOTICE_PATH,
    )
    expect_rejected(
        lambda proof_id=registered_id: validator.validate_facts(
            proof_id, {}, RELEASE, notice_path=NOTICE_PATH
        ),
        f"{registered_id} accepted an empty literal-only receipt",
    )

sq9_partial_attester_retry = copy.deepcopy(facts_by_id["SQ9"])
sq9_partial_attester_retry["ci"]["runAttempt"] = 2
validator.validate_facts(
    "SQ9",
    sq9_partial_attester_retry,
    RELEASE,
    notice_path=NOTICE_PATH,
)

feedback_partial_attester_retry = copy.deepcopy(
    facts_by_id["BONUS-FEEDBACK"]
)
feedback_partial_attester_retry["reviewApproval"]["runAttempt"] = 2
validator.validate_facts(
    "BONUS-FEEDBACK",
    feedback_partial_attester_retry,
    RELEASE,
    notice_path=NOTICE_PATH,
)

sq3_availability_support = validator.expected_support_bindings(
    "SQ3",
    "availability-verification",
    facts_by_id["SQ3"],
)
assert (
    sq3_availability_support["observation"]["availabilityObservedAt"]
    == facts_by_id["SQ10"]["availability"]["observedAt"]
)
assert (
    sq3_availability_support["observation"]["availabilityObservedAt"]
    != sq3_availability_support["observation"]["observedAt"]
)
sq4_lifecycle_support = validator.expected_support_bindings(
    "SQ4",
    "fresh-identity-lifecycle",
    facts_by_id["SQ4"],
)
assert (
    sq4_lifecycle_support["judgeUserLifecycle"]["cognitoSubjectDigest"]
    == ALT_DIGEST
)
assert all(
    operation["cognitoSubjectDigest"] == ALT_DIGEST
    for operation in sq4_lifecycle_support["judgeUserLifecycle"]["operations"]
)
assert (
    sq4_lifecycle_support["freshJudgeJourney"]["cognitoSubjectDigest"]
    == ALT_DIGEST
)
sq4_journey_support = validator.expected_support_bindings(
    "SQ4",
    "fresh-judge-journey",
    facts_by_id["SQ4"],
)
assert (
    sq4_journey_support["freshJudgeJourney"]["cognitoSubjectDigest"]
    == ALT_DIGEST
)
sq4_rotation_support = validator.expected_support_bindings(
    "SQ4",
    "credential-rotation-recovery",
    facts_by_id["SQ4"],
)
assert (
    sq4_rotation_support["judgeUserLifecycle"]["cognitoSubjectDigest"]
    == ALT_DIGEST
)
sq10_paging_support = validator.expected_support_bindings(
    "SQ10",
    "paging-delivery",
    facts_by_id["SQ10"],
)
assert (
    sq10_paging_support["alerting"]["pagingDelivery"]["workflowPath"]
    == ".github/workflows/production-paging-test.yml"
)
sq10_rollback_support = validator.expected_support_bindings(
    "SQ10",
    "rollback-recovery",
    facts_by_id["SQ10"],
)
assert (
    sq10_rollback_support["recovery"]["governedCanary"]["workflowPath"]
    == ".github/workflows/governed-canary.yml"
)
sq10_rotation_support = validator.expected_support_bindings(
    "SQ10",
    "credential-rotation",
    facts_by_id["SQ10"],
)
assert set(sq10_rotation_support) == {"access", "recovery"}
assert (
    sq10_rotation_support["access"]["projectAccess"]["workflowPath"]
    == ".github/workflows/submission-project-access.yml"
)
bonus_oss_upstream_support = validator.expected_support_bindings(
    "BONUS-OSS",
    "upstream-pr",
    facts_by_id["BONUS-OSS"],
)
assert (
    bonus_oss_upstream_support["upstreamPullRequest"]["number"] == 12345
)
assert (
    bonus_oss_upstream_support["acceptedAt"]
    == bonus_oss_upstream_support["upstreamPullRequest"]["mergedAt"]
)
bonus_oss_ci_support = validator.expected_support_bindings(
    "BONUS-OSS",
    "ci-validation",
    facts_by_id["BONUS-OSS"],
)
assert (
    bonus_oss_ci_support["validatedCandidateDigest"]
    == bonus_oss_ci_support["candidateBinding"][
        "canonicalFileManifestDigest"
    ]
)
assert (
    bonus_oss_ci_support["ciValidation"]["artifactProducerAttempt"]
    <= bonus_oss_ci_support["ciValidation"]["runAttempt"]
)
validator.cross_validate(
    {
        "D4": make_receipt("D4", facts_by_id["D4"]),
        "SQ3": make_receipt("SQ3", facts_by_id["SQ3"]),
        "SQ4": make_receipt("SQ4", facts_by_id["SQ4"]),
        "SQ10": make_receipt("SQ10", facts_by_id["SQ10"]),
    }
)


def rejects_mutation(
    proof_id: str, mutate, description: str
) -> None:
    changed = copy.deepcopy(facts_by_id[proof_id])
    mutate(changed)
    expect_rejected(
        lambda: validator.validate_facts(
            proof_id, changed, RELEASE, notice_path=NOTICE_PATH
        ),
        description,
    )


def rejects_sq10_cross_mutation(mutate, description: str) -> None:
    changed = copy.deepcopy(facts_by_id["SQ10"])
    mutate(changed)
    validator.validate_facts(
        "SQ10",
        changed,
        RELEASE,
        notice_path=NOTICE_PATH,
    )
    expect_rejected(
        lambda: validator.cross_validate(
            {
                "D4": make_receipt("D4", facts_by_id["D4"]),
                "SQ3": make_receipt("SQ3", facts_by_id["SQ3"]),
                "SQ4": make_receipt("SQ4", facts_by_id["SQ4"]),
                "SQ10": make_receipt("SQ10", changed),
            }
        ),
        description,
    )


def rejects_content_cross_mutation(
    proof_id: str, mutate, description: str
) -> None:
    changed = copy.deepcopy(facts_by_id[proof_id])
    mutate(changed)
    validator.validate_facts(
        proof_id,
        changed,
        RELEASE,
        notice_path=NOTICE_PATH,
    )
    receipts = {
        content_id: make_receipt(
            content_id,
            changed if content_id == proof_id else facts_by_id[content_id],
        )
        for content_id in ("SQ6", "SQ7", "SQ8")
    }
    expect_rejected(
        lambda: validator.cross_validate(receipts),
        description,
    )


def mutate_sq4_lifecycle_stage(value: dict, stage: str) -> None:
    lifecycle = value["judgeUserLifecycle"]
    lifecycle["stage"] = stage
    for operation in lifecycle["operations"]:
        operation["stage"] = stage
    lifecycle["chainDigest"] = validator.canonical_json_digest(
        lifecycle["operations"]
    )
    value["freshJudgeJourney"]["stage"] = stage


def mutate_sq4_application_origin(value: dict, digest: str) -> None:
    lifecycle = value["judgeUserLifecycle"]
    lifecycle["applicationOriginSha256"] = digest
    for operation in lifecycle["operations"]:
        operation["applicationOriginSha256"] = digest
    lifecycle["chainDigest"] = validator.canonical_json_digest(
        lifecycle["operations"]
    )
    value["freshJudgeJourney"]["applicationOriginSha256"] = digest


def mutate_sq4_operation_subject(value: dict, digest: str) -> None:
    lifecycle = value["judgeUserLifecycle"]
    lifecycle["operations"][2]["cognitoSubjectDigest"] = digest
    lifecycle["chainDigest"] = validator.canonical_json_digest(
        lifecycle["operations"]
    )


rejects_mutation(
    "SQ3",
    lambda value: value.update(applicationUrl="http://wrong.example"),
    "SQ3 accepted a non-HTTPS or origin-mismatched URL",
)
rejects_mutation(
    "SQ3",
    lambda value: value["observation"].update(
        availabilityObservedAt=iso(NOW + dt.timedelta(minutes=1))
    ),
    "SQ3 accepted availability evidence observed after its public probe",
)
rejects_mutation(
    "SQ4",
    lambda value: value["freshJudgeJourney"].update(terminalReceiptVerified=False),
    "SQ4 accepted an incomplete fresh-judge journey",
)
rejects_mutation(
    "SQ4",
    lambda value: mutate_sq4_lifecycle_stage(value, "staging"),
    "SQ4 accepted lifecycle and journey receipts from staging",
)
rejects_mutation(
    "SQ4",
    lambda value: mutate_sq4_application_origin(value, "a" * 64),
    "SQ4 accepted lifecycle and journey receipts for another application origin",
)
rejects_mutation(
    "SQ4",
    lambda value: mutate_sq4_operation_subject(value, DIGEST),
    "SQ4 accepted a lifecycle operation for another Cognito subject",
)
rejects_mutation(
    "SQ4",
    lambda value: value["judgeUserLifecycle"].update(
        cognitoSubjectDigest="c" * 64
    ),
    "SQ4 accepted a non-prefixed Cognito subject digest",
)
rejects_mutation(
    "SQ4",
    lambda value: value["freshJudgeJourney"].update(
        cognitoSubjectDigest=DIGEST
    ),
    "SQ4 accepted a browser journey for another Cognito subject",
)
rejects_mutation(
    "SQ4",
    lambda value: value["judgeUserLifecycle"]["operations"].pop(2),
    "SQ4 accepted a lifecycle without all four exact operation receipts",
)
rejects_mutation(
    "SQ4",
    lambda value: value["judgeUserLifecycle"]["operations"][3].update(
        operationReceiptDigest=DIGEST
    ),
    "SQ4 accepted an operation list that differs from its aggregate chain",
)
rejects_mutation(
    "SQ5",
    lambda value: value.update(licenseSpdx="MIT"),
    "SQ5 accepted the wrong detected license",
)
rejects_mutation(
    "SQ6",
    lambda value: value.update(submissionLanguage="el"),
    "SQ6 accepted non-English final fields",
)
rejects_mutation(
    "SQ7",
    lambda value: value.update(durationSeconds=180),
    "SQ7 accepted a three-minute video",
)
rejects_mutation(
    "SQ7",
    lambda value: value.update(spokenLanguage="el", subtitlesLanguage="none"),
    "SQ7 accepted a video without English accessibility",
)
rejects_mutation(
    "SQ7",
    lambda value: value.update(videoUrl="https://www.youtube.com/"),
    "SQ7 accepted a provider homepage without an exact video ID",
)
rejects_mutation(
    "SQ7",
    lambda value: value.update(videoUrl="https://evil.youtube.com/watch?v=ArchonDemo1"),
    "SQ7 accepted an unapproved video-provider subdomain",
)
rejects_mutation(
    "SQ7",
    lambda value: value.update(
        videoUrl="https://youtube.com/watch?v=ArchonDemo1"
    ),
    "SQ7 accepted a redirecting bare YouTube alias",
)
rejects_mutation(
    "SQ7",
    lambda value: value.update(videoUrl="https://youtu.be/ArchonDemo1"),
    "SQ7 accepted a redirecting shortened YouTube alias",
)
rejects_mutation(
    "SQ7",
    lambda value: value.update(videoUrl="https://www.vimeo.com/12345"),
    "SQ7 accepted a redirecting Vimeo alias",
)
rejects_mutation(
    "SQ7",
    lambda value: value.update(allThirdPartyMaterialAuthorized=False),
    "SQ7 accepted unreviewed third-party material",
)
rejects_mutation(
    "SQ8",
    lambda value: value.update(crossMediumConsistent=False),
    "SQ8 accepted an inconsistent disclosure review",
)
rejects_mutation(
    "SQ8",
    lambda value: value["projectHistory"].update(
        projectStartedAt="2026-07-06T12:59:59Z",
        rootCommitAuthoredAt="2026-07-06T12:59:59Z",
    ),
    "SQ8 accepted a project started before the New Projects Only period",
)
rejects_mutation(
    "SQ8",
    lambda value: value["rules"].update(
        officialRulesUrl="https://datahub.devpost.com/"
    ),
    "SQ8 accepted a non-rules source for New Projects Only",
)
rejects_mutation(
    "SQ8",
    lambda value: value["projectHistory"].update(
        releaseCommitCommittedAt=iso(NOW + dt.timedelta(days=1))
    ),
    "SQ8 accepted future repository history",
)
rejects_mutation(
    "SQ8",
    lambda value: value["projectHistory"].update(
        allReachableCommitsWithinSubmissionPeriod=False
    ),
    "SQ8 accepted out-of-period reachable history",
)
rejects_mutation(
    "SQ8",
    lambda value: value["projectHistory"].update(
        releaseCommitCommittedAt="2026-07-06T20:25:00Z"
    ),
    "SQ8 accepted impossible repository/release chronology",
)
rejects_mutation(
    "SQ8",
    lambda value: value.update(preExistingWorkInventoryDigest=ALT_DIGEST),
    "SQ8 accepted a disclosure inventory no longer bound to NOTICE",
)
rejects_mutation(
    "SQ9",
    lambda value: value["artifact"].pop("producerAttempt"),
    "SQ9 accepted an artifact without its producer attempt",
)
rejects_mutation(
    "SQ9",
    lambda value: value["artifact"].update(producerAttempt=2),
    "SQ9 accepted an artifact produced after its attesting CI attempt",
)
rejects_mutation(
    "SQ9",
    lambda value: value["artifact"].update(
        name=f"judge-evidence-{RELEASE}"
    ),
    "SQ9 accepted a judge artifact name detached from its producer attempt",
)
rejects_mutation(
    "SQ10",
    lambda value: value["alerting"].update(
        externalPagingDeliveryTested=False
    ),
    "SQ10 accepted untested external paging",
)
rejects_mutation(
    "SQ10",
    lambda value: value["alerting"].update(encryptedRouteBound=False),
    "SQ10 accepted an unbound encrypted alarm route",
)
rejects_mutation(
    "SQ10",
    lambda value: value["alerting"]["pagingDelivery"].update(
        workflowPath=".github/workflows/production-posture.yml"
    ),
    "SQ10 accepted paging provenance from the posture workflow",
)
rejects_mutation(
    "SQ10",
    lambda value: value["alerting"]["pagingDelivery"].pop(
        "predicateDigest"
    ),
    "SQ10 accepted paging provenance without an exact predicate digest",
)
rejects_mutation(
    "SQ10",
    lambda value: value["alerting"]["pagingDelivery"].update(
        artifactName=f"production-alarm-delivery-{RELEASE}-404"
    ),
    "SQ10 accepted paging provenance for a different run ID",
)
rejects_mutation(
    "SQ10",
    lambda value: value["alerting"].update(
        lastPagingTestAt=iso(NOW - dt.timedelta(hours=1))
    ),
    "SQ10 accepted a paging timestamp not bound to paging evidence",
)
rejects_mutation(
    "SQ10",
    lambda value: value["alerting"]["pagingDelivery"].update(
        route="CloudWatch->SNS"
    ),
    "SQ10 accepted a truncated alarm-delivery route",
)
rejects_mutation(
    "SQ10",
    lambda value: value["alerting"]["pagingDelivery"]["checks"].update(
        encryptedProofQueue=False
    ),
    "SQ10 accepted an unencrypted alarm proof queue",
)
rejects_mutation(
    "SQ10",
    lambda value: value["posture"]["checks"].update(
        alarmsNotFiring=False
    ),
    "SQ10 accepted firing production alarms",
)
rejects_mutation(
    "SQ10",
    lambda value: value["posture"].update(
        alarmNames=["archon-production-control-plane-errors"]
    ),
    "SQ10 accepted an incomplete lean alarm inventory",
)
rejects_mutation(
    "SQ10",
    lambda value: value["availability"].update(
        profileResponseDigest="sha256:not-a-digest"
    ),
    "SQ10 accepted an invalid runtime-profile response digest",
)
rejects_mutation(
    "SQ10",
    lambda value: value["availability"].update(
        observationDigest="sha256:not-a-digest"
    ),
    "SQ10 accepted an invalid availability observation digest",
)
rejects_mutation(
    "SQ10",
    lambda value: value["posture"].update(
        observationDigest="sha256:not-a-digest"
    ),
    "SQ10 accepted an invalid posture observation digest",
)
rejects_mutation(
    "SQ10",
    lambda value: value["posture"].update(
        driftEvidenceDigest="sha256:not-a-digest"
    ),
    "SQ10 accepted an invalid drift evidence digest",
)
rejects_mutation(
    "SQ10",
    lambda value: value["recovery"]["governedCanary"].update(
        artifactName=f"governed-canary-rollback-{RELEASE}-1"
    ),
    "SQ10 accepted a governed-canary artifact not bound to its run ID",
)
rejects_mutation(
    "SQ10",
    lambda value: value["recovery"]["governedCanary"].update(
        predicateType=(
            "https://github.com/upgradedev/archon-datahub/"
            "attestations/governed-canary-recovery/v1"
        )
    ),
    "SQ10 accepted the independent-recovery predicate as governed-canary proof",
)
rejects_mutation(
    "SQ10",
    lambda value: value["recovery"].update(
        lastRollbackTestAt=iso(NOW - dt.timedelta(hours=1))
    ),
    "SQ10 accepted rollback freshness not bound to canary evidence",
)
rejects_mutation(
    "SQ10",
    lambda value: value["recovery"].update(
        lastCredentialRotationTestAt=iso(NOW - dt.timedelta(hours=1))
    ),
    "SQ10 accepted rotation freshness not bound to project-access evidence",
)
rejects_mutation(
    "SQ10",
    lambda value: value["access"]["projectAccess"].update(
        artifactName=f"submission-project-access-{RELEASE}-2"
    ),
    "SQ10 accepted project-access evidence for a different producer attempt",
)
rejects_mutation(
    "SQ10",
    lambda value: value["access"]["projectAccess"].update(
        artifactId=value["access"]["projectAccess"]["runId"]
    ),
    "SQ10 accepted aliased project-access run and artifact IDs",
)
rejects_mutation(
    "SQ10",
    lambda value: value["availability"].update(
        observedAt=iso(NOW - dt.timedelta(hours=2))
    ),
    "SQ10 accepted a stale availability observation",
)
rejects_mutation(
    "SQ10",
    lambda value: value["monitoringWindow"].update(
        schedule="17 */6 * * *"
    ),
    "SQ10 accepted a legacy availability cadence",
)
rejects_mutation(
    "SQ10",
    lambda value: value["monitoringWindow"].update(
        maximumExpectedGapMinutes=420
    ),
    "SQ10 accepted a widened availability gap",
)
rejects_sq10_cross_mutation(
    lambda value: value["recovery"]["governedCanary"].update(
        runId=102,
        artifactName="governed-canary-rollback-102-1",
    ),
    "SQ10 accepted a governed-canary run different from its D4 evidence",
)
rejects_sq10_cross_mutation(
    lambda value: value["recovery"]["governedCanary"].update(
        predicateDigest=ALT_DIGEST
    ),
    "SQ10 accepted a governed-canary predicate different from its D4 evidence",
)
rejects_sq10_cross_mutation(
    lambda value: value["recovery"]["governedCanary"].update(
        subjectDigest=ALT_DIGEST
    ),
    "SQ10 accepted a governed-canary subject different from its D4 evidence",
)
rejects_sq10_cross_mutation(
    lambda value: value["availability"].update(
        runId=205,
        artifactName=f"production-availability-{RELEASE}-205",
    ),
    "SQ10 accepted availability evidence different from SQ3",
)
rejects_sq10_cross_mutation(
    lambda value: value["availability"].update(
        observedAt=facts_by_id["SQ3"]["observation"]["observedAt"]
    ),
    "SQ10 accepted the later SQ3 public-probe time as availability evidence",
)
rejects_sq10_cross_mutation(
    lambda value: value["access"]["projectAccess"].update(
        predicateDigest=ALT_DIGEST
    ),
    "SQ10 accepted a project-access source different from its SQ4 receipt",
)
rejects_sq10_cross_mutation(
    lambda value: (
        value["access"]["projectAccess"].update(
            credentialRotationPerformedAt=iso(
                NOW - dt.timedelta(hours=2)
            )
        ),
        value["recovery"].update(
            lastCredentialRotationTestAt=iso(
                NOW - dt.timedelta(hours=2)
            )
        ),
    ),
    "SQ10 accepted a rotation time different from its SQ4 lifecycle",
)
rejects_sq10_cross_mutation(
    lambda value: value["access"].update(
        validThrough="2026-09-01T21:00:00Z"
    ),
    "SQ10 accepted judge-access validity different from its SQ4 evidence",
)
rejects_content_cross_mutation(
    "SQ7",
    lambda value: value.update(
        reviewedAt=iso(NOW - dt.timedelta(minutes=1))
    ),
    "SQ6/SQ7/SQ8 accepted different review timestamps",
)
rejects_content_cross_mutation(
    "SQ8",
    lambda value: value["reviewApproval"].update(runId=904),
    "SQ8 accepted approval provenance from a different workflow run",
)
rejects_mutation(
    "SQ8",
    lambda value: value["reviewApproval"].update(
        workflowPath=".github/workflows/submission-readiness.yml"
    ),
    "SQ8 accepted approval provenance from a different workflow",
)
rejects_mutation(
    "SQ7",
    lambda value: value["providerResponseDigests"].update(
        preparedResponseDigest="sha256:invalid"
    ),
    "SQ7 accepted an invalid prepared provider-response digest",
)
rejects_mutation(
    "SQ7",
    lambda value: value["providerResponseDigests"].pop(
        "reviewResponseDigest"
    ),
    "SQ7 accepted a missing independent review-response digest",
)
rejects_mutation(
    "SQ8",
    lambda value: value["reviewApproval"].update(candidateRunAttempt=2),
    "SQ8 accepted a candidate produced after the reviewed artifact",
)
rejects_content_cross_mutation(
    "SQ8",
    lambda value: value["reviewApproval"].update(candidateArtifactId=1003),
    "SQ8 accepted one artifact as both candidate and reviewed evidence",
)
rejects_mutation(
    "SQ8",
    lambda value: value["reviewApproval"].update(
        candidateArtifactDigest="sha256:invalid"
    ),
    "SQ8 accepted an invalid candidate artifact digest",
)
rejects_mutation(
    "SQ11",
    lambda value: value.update(devpostProjectUrl="https://devpost.com/software/"),
    "SQ11 accepted a Devpost listing without a project slug",
)
rejects_mutation(
    "SQ11",
    lambda value: value["loggedOutVerification"]["devpostEntry"].update(
        loginRequired=True
    ),
    "SQ11 accepted a login-gated Devpost entry",
)
rejects_mutation(
    "SQ11",
    lambda value: value["preSubmitSeal"].update(
        readinessEvidenceDigest=ALT_DIGEST
    ),
    "SQ11 accepted a pre-submit seal predicate mismatch",
)
rejects_mutation(
    "SQ11",
    lambda value: value["rules"].update(
        judgingStart="2026-08-18T14:00:00Z"
    ),
    "SQ11 accepted altered official judging dates",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value.update(
        upstreamRepositoryUrl="https://github.com/attacker/mcp-server-datahub"
    ),
    "BONUS-OSS accepted the wrong upstream repository",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value.update(state="accepted"),
    "BONUS-OSS accepted a non-merged upstream state",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value.update(acceptedAt="2026-07-06T12:59:59Z"),
    "BONUS-OSS accepted maintainer evidence before the submission period",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value["upstreamPullRequest"].update(number=12346),
    "BONUS-OSS accepted a pull-request number detached from its URL",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value["upstreamPullRequest"]["changedPaths"].append(
        "src/mcp_server_datahub/unrelated.py"
    ),
    "BONUS-OSS accepted an extra upstream path",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value["upstreamPullRequest"].update(mergedById=601),
    "BONUS-OSS accepted a self-merged upstream pull request",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value["candidateBinding"].update(baseCommit="f" * 40),
    "BONUS-OSS accepted a candidate detached from the upstream base",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value["candidateBinding"].update(
        reconstructedTreeSha="e" * 40
    ),
    "BONUS-OSS accepted a candidate detached from the pull-request head tree",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value["candidateBinding"]["files"][0].update(mode="100755"),
    "BONUS-OSS accepted an executable-mode candidate path",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value.update(validatedCandidateDigest=DIGEST),
    "BONUS-OSS accepted a detached canonical candidate digest",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value["candidateBinding"].update(exactHeadTreeMatch=False),
    "BONUS-OSS accepted a failed exact head-tree match",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value["ciValidation"].update(artifactProducerAttempt=2),
    "BONUS-OSS accepted a future CI artifact producer attempt",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value["ciValidation"].update(artifactId=501),
    "BONUS-OSS accepted an artifact ID equal to its CI run ID",
)
rejects_mutation(
    "BONUS-OSS",
    lambda value: value["ciValidation"].update(
        predicateType="https://attacker.example/ci-release/v1"
    ),
    "BONUS-OSS accepted the wrong signed CI predicate type",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value.update(submittedAt="2026-07-06T12:59:59Z"),
    "BONUS-FEEDBACK accepted a pre-period confirmation",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value["rulesObservation"].update(
        authenticatedUiObserved=True
    ),
    "BONUS-FEEDBACK relabeled public wording as authenticated UI evidence",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value["privacyDisclosure"].update(
        pseudonymousEntrantCommitmentIncluded=False
    ),
    "BONUS-FEEDBACK hid its pseudonymous entrant commitment",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value["privacyDisclosure"].update(
        rawEntrantPersonalDataIncluded=True
    ),
    "BONUS-FEEDBACK accepted raw entrant personal data",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value["privacyDisclosure"].update(
        publicReviewerNumericIdentifierIncluded=False
    ),
    "BONUS-FEEDBACK hid the retained public reviewer identifier",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value["feedbackQuality"].update(actionable=False),
    "BONUS-FEEDBACK accepted incomplete quality assertions",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value["reviewApproval"].update(reviewerId=805),
    "BONUS-FEEDBACK accepted review detached from the workflow owner",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value["approvalTiming"].update(
        authoritativeApprovalTimestampAvailable=True
    ),
    "BONUS-FEEDBACK invented an authoritative approval timestamp",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value["approvalTiming"].update(
        reviewJobStartedAt="2026-07-06T12:59:59Z"
    ),
    "BONUS-FEEDBACK accepted an approval bound before submission",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value["rulesObservation"].update(
        publicOverviewInstruction="authenticated-feedback-form-observed"
    ),
    "BONUS-FEEDBACK accepted altered public overview semantics",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value["reviewApproval"].update(
        confirmationDigest=THIRD_DIGEST
    ),
    "BONUS-FEEDBACK accepted an unbound confirmation digest",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value["reviewApproval"].update(candidateRunAttempt=3),
    "BONUS-FEEDBACK accepted a future candidate attempt",
)
rejects_mutation(
    "BONUS-FEEDBACK",
    lambda value: value.update(distinctFeedbackSubmissionUnderRules=False),
    "BONUS-FEEDBACK accepted a non-distinct rules submission",
)

expect_rejected(
    lambda: validator.public_https_url(
        "https://www.datahub.com:70000",
        "invalidPort",
    ),
    "public HTTPS validation accepted an invalid port",
)
expect_rejected(
    lambda: validator.public_https_url(
        "https://archon.example",
        "reservedHost",
    ),
    "public HTTPS validation accepted a reserved DNS suffix",
)

wrong_source = make_receipt("SQ5", facts_by_id["SQ5"])
wrong_source["source"]["workflowPath"] = ".github/workflows/ci.yml"
expect_rejected(
    lambda: validator.validate_receipt(
        wrong_source,
        sources,
        validator.REPOSITORY,
        RELEASE,
        notice_path=NOTICE_PATH,
    ),
    "receipt accepted the wrong registered source workflow",
)
wrong_release = make_receipt("SQ5", facts_by_id["SQ5"])
wrong_release["releaseSha"] = "d" * 40
expect_rejected(
    lambda: validator.validate_receipt(
        wrong_release,
        sources,
        validator.REPOSITORY,
        RELEASE,
        notice_path=NOTICE_PATH,
    ),
    "receipt accepted the wrong release",
)
wrong_repository = make_receipt("SQ5", facts_by_id["SQ5"])
wrong_repository["repository"] = "attacker/repository"
expect_rejected(
    lambda: validator.validate_receipt(
        wrong_repository,
        sources,
        validator.REPOSITORY,
        RELEASE,
        notice_path=NOTICE_PATH,
    ),
    "receipt accepted the wrong repository",
)

def write_support_subject(
    path: Path,
    proof_id: str,
    role: str,
    facts: dict,
) -> None:
    captured_at = iso()
    bindings = validator.expected_support_bindings(proof_id, role, facts)
    data = [
        {
            "schemaVersion": validator.SUPPORT_RECORD_SCHEMA,
            "recordType": role,
            "observedAt": captured_at,
            "evidence": bindings,
        }
    ]
    capture_bytes = validator.canonical_json_text(data).encode("utf-8")
    validator.write_json(
        path,
        {
            "schemaVersion": validator.SUPPORT_SCHEMA,
            "proofId": proof_id,
            "role": role,
            "repository": validator.REPOSITORY,
            "releaseSha": RELEASE,
            "factsDigest": validator.canonical_json_digest(facts),
            "capture": {
                "schemaVersion": validator.SUPPORT_CAPTURE_SCHEMA,
                "capturedAt": captured_at,
                "digest": validator.sha256_bytes(capture_bytes),
                "sizeBytes": len(capture_bytes),
                "recordCount": 1,
                "data": data,
            },
            "sanitized": True,
            "bindings": bindings,
        },
    )


def materialize_standard_source(
    aggregate_root: Path,
    source_key: str,
    source_facts: dict[str, dict],
) -> tuple[Path, dict[str, dict], dict]:
    source = sources[source_key]
    subject_root = aggregate_root / "upstream-subjects" / source_key
    verification_root = aggregate_root / "upstream-verification" / source_key
    receipt_dir = aggregate_root / "receipts"
    subject_root.mkdir(parents=True)
    verification_root.mkdir(parents=True)
    receipt_dir.mkdir(parents=True, exist_ok=True)
    envelopes: dict[str, tuple[dict, Path, list[dict]]] = {}
    for proof_id in source["proofIds"]:
        facts = source_facts[proof_id]
        support_rows = []
        for configured in validator.configured_support_rows(source, proof_id):
            support_path = subject_root / configured["name"]
            write_support_subject(
                support_path,
                proof_id,
                configured["role"],
                facts,
            )
            support_rows.append(
                {
                    "role": configured["role"],
                    "name": configured["name"],
                    "digest": validator.sha256_file(support_path),
                }
            )
        envelope_path = subject_root / "proofs" / f"{proof_id}.json"
        envelope = {
            "schemaVersion": validator.UPSTREAM_SCHEMA,
            "id": proof_id,
            "repository": validator.REPOSITORY,
            "releaseSha": RELEASE,
            "facts": facts,
            "supportSubjects": support_rows,
        }
        validator.write_json(envelope_path, envelope)
        envelopes[proof_id] = (envelope, envelope_path, support_rows)
    predicate = {
        "schemaVersion": validator.UPSTREAM_PREDICATE_SCHEMA,
        "repository": validator.REPOSITORY,
        "releaseSha": RELEASE,
        "source": {
            "workflowPath": source["workflowPath"],
            "runId": 991,
            "runAttempt": 1,
        },
        "proofs": [
            {
                "id": proof_id,
                "subjects": [
                    {
                        "role": "proof-envelope",
                        "name": f"proofs/{proof_id}.json",
                        "digest": validator.sha256_file(envelope_path),
                    },
                    *support_rows,
                ],
            }
            for proof_id, (
                _,
                envelope_path,
                support_rows,
            ) in sorted(envelopes.items())
        ],
        "result": "verified",
    }
    predicate_path = subject_root / source["predicateFile"]
    validator.write_json(predicate_path, predicate)
    predicate_digest = validator.sha256_file(predicate_path)
    inventory_path = subject_root / source["subjectInventory"]
    inventory_subjects = {
        path.relative_to(subject_root).as_posix(): validator.sha256_file(path)
        for path in subject_root.rglob("*")
        if path.is_file() and path != inventory_path
    }
    inventory_path.write_text(
        "".join(
            f"{digest.removeprefix('sha256:')}  {name}\n"
            for name, digest in sorted(inventory_subjects.items())
        ),
        encoding="utf-8",
    )
    subject_set_digest = validator.checksum_subject_set_digest(
        inventory_subjects
    )
    verification_names: set[str] = set()
    for proof in predicate["proofs"]:
        for subject in proof["subjects"]:
            name = f"{proof['id']}--{subject['role']}.json"
            verification_names.add(name)
            validator.write_json(
                verification_root / name,
                {
                    "schemaVersion": (
                        "archon.upstream-attestation-verification/v1"
                    ),
                    "repository": validator.REPOSITORY,
                    "releaseSha": RELEASE,
                    "proofId": proof["id"],
                    "role": subject["role"],
                    "subject": {
                        "name": subject["name"],
                        "digest": subject["digest"],
                    },
                    "predicate": {
                        "type": source["predicateType"],
                        "digest": predicate_digest,
                    },
                    "statement": {
                        "predicateType": source["predicateType"],
                        "predicate": predicate,
                        "subject": validator.attestation_subjects(
                            inventory_subjects
                        ),
                    },
                },
            )
    verification_set_digest = validator.retained_file_set_digest(
        verification_root,
        verification_names,
    )
    receipts = validator.derive_standard(
        subject_root,
        source,
        validator.REPOSITORY,
        RELEASE,
        991,
        1,
        992,
        validator.artifact_name(source, RELEASE, 1),
        DIGEST,
        predicate_digest,
        subject_set_digest,
        verification_set_digest,
        NOTICE_PATH,
    )
    for receipt in receipts:
        validator.write_json(
            receipt_dir / f"{receipt['id']}.json",
            receipt,
        )
    validator.write_json(
        verification_root / "binding.json",
        {
            "schemaVersion": validator.UPSTREAM_BINDING_SCHEMA,
            "repository": validator.REPOSITORY,
            "releaseSha": RELEASE,
            "sourceKey": source_key,
            "source": {
                "workflowPath": source["workflowPath"],
                "runId": 991,
                "runAttempt": 1,
            },
            "artifact": {
                "id": 992,
                "name": validator.artifact_name(source, RELEASE, 1),
                "digest": DIGEST,
            },
            "attestation": {
                "predicateType": source["predicateType"],
                "predicateDigest": predicate_digest,
                "verificationSetDigest": verification_set_digest,
                "subjectSetDigest": subject_set_digest,
            },
            "proofIds": source["proofIds"],
        },
    )
    return (
        receipt_dir,
        {receipt["id"]: receipt for receipt in receipts},
        predicate,
    )


STANDARD_SOURCE_SUBJECT_COUNTS = {
    "project-access": 15,
    "content-review": 16,
    "operations": 9,
    "judge-pack": 4,
    "bonus-oss": 4,
    "bonus-feedback": 3,
    "devpost-confirmation": 6,
}


def write_standard_facts_directory(
    root: Path,
    source_key: str,
    *,
    facts_override: dict[str, dict] | None = None,
) -> Path:
    facts_dir = root / f"{source_key}-facts"
    facts_dir.mkdir()
    selected = facts_override or {
        proof_id: facts_by_id[proof_id]
        for proof_id in sources[source_key]["proofIds"]
    }
    for proof_id, facts in selected.items():
        validator.write_json(
            facts_dir / f"{proof_id}.json",
            copy.deepcopy(facts),
        )
    return facts_dir


def assemble_standard_fixture(
    root: Path,
    source_key: str,
    name: str,
    *,
    captured_at: str | None = None,
) -> tuple[Path, dict]:
    facts_dir = write_standard_facts_directory(
        root,
        source_key,
    )
    output_dir = root / name
    output_dir.mkdir()
    validated = validator.assemble_standard_source(
        output_dir,
        facts_dir,
        sources[source_key],
        validator.REPOSITORY,
        RELEASE,
        991,
        1,
        NOTICE_PATH,
        captured_at=captured_at or iso(),
    )
    return output_dir, validated


def reseal_standard_inventory(root: Path, source_key: str) -> None:
    source = sources[source_key]
    inventory = {
        name: validator.sha256_file(root / name)
        for name in validator.standard_subject_names(source)
    }
    (root / source["subjectInventory"]).write_bytes(
        validator.checksum_inventory_text(inventory).encode("utf-8")
    )


def rebind_feedback_source_facts(output: Path, mutate) -> None:
    source = sources["bonus-feedback"]
    proof_path = output / "proofs" / "BONUS-FEEDBACK.json"
    support_name = (
        "support/BONUS-FEEDBACK/feedback-confirmation.json"
    )
    support_path = output / support_name
    predicate_path = output / source["predicateFile"]
    envelope = validator.load_json(
        proof_path,
        "BONUS-FEEDBACK envelope",
    )
    mutate(envelope["facts"])
    retained_support = validator.load_json(
        support_path,
        "BONUS-FEEDBACK support",
    )
    support_value = validator.standard_support_subject_value(
        "BONUS-FEEDBACK",
        "feedback-confirmation",
        envelope["facts"],
        validator.REPOSITORY,
        RELEASE,
        retained_support["capture"]["capturedAt"],
    )
    support_path.write_text(
        validator.canonical_json_text(support_value),
        encoding="utf-8",
        newline="\n",
    )
    support_subject = {
        "role": "feedback-confirmation",
        "name": support_name,
        "digest": validator.sha256_file(support_path),
    }
    envelope["supportSubjects"] = [support_subject]
    proof_path.write_text(
        validator.canonical_json_text(envelope),
        encoding="utf-8",
        newline="\n",
    )
    predicate = validator.load_json(
        predicate_path,
        "BONUS-FEEDBACK predicate",
    )
    proof = next(
        item
        for item in predicate["proofs"]
        if item["id"] == "BONUS-FEEDBACK"
    )
    proof["subjects"] = [
        {
            "role": "proof-envelope",
            "name": "proofs/BONUS-FEEDBACK.json",
            "digest": validator.sha256_file(proof_path),
        },
        support_subject,
    ]
    predicate_path.write_text(
        validator.canonical_json_text(predicate),
        encoding="utf-8",
        newline="\n",
    )
    reseal_standard_inventory(output, "bonus-feedback")


with tempfile.TemporaryDirectory(
    prefix="submission-standard-assembler-"
) as raw:
    temporary = Path(raw)
    for index, (
        source_key,
        expected_subject_count,
    ) in enumerate(STANDARD_SOURCE_SUBJECT_COUNTS.items()):
        source_root = temporary / f"source-{index}"
        source_root.mkdir()
        output_dir, validated = assemble_standard_fixture(
            source_root,
            source_key,
            "assembled",
        )
        source = sources[source_key]
        expected_subjects = validator.standard_subject_names(source)
        expected_files = expected_subjects | {source["subjectInventory"]}
        assert len(expected_subjects) == expected_subject_count
        validator.exact_retained_tree(
            output_dir,
            expected_files,
            f"{source_key} assembled source",
        )
        inventory = validator.load_checksum_inventory(
            output_dir / source["subjectInventory"],
            source["subjectInventory"],
            f"{source_key} assembled inventory",
        )
        assert set(inventory) == expected_subjects
        assert (
            output_dir / source["subjectInventory"]
        ).read_bytes() == validator.checksum_inventory_text(
            inventory
        ).encode("utf-8")
        assert validated["subjectCount"] == expected_subject_count
        assert (
            validated["subjectSetDigest"]
            == validator.checksum_subject_set_digest(inventory)
        )
        assert (
            validated["predicateDigest"]
            == validator.sha256_file(
                output_dir / source["predicateFile"]
            )
        )
        projection = validator.standard_source_projection(
            source_key,
            source,
            validator.REPOSITORY,
            RELEASE,
            1,
            validated,
        )
        assert projection == {
            "schemaVersion": (
                "archon.submission-standard-source-validation/v1"
            ),
            "repository": validator.REPOSITORY,
            "releaseSha": RELEASE,
            "sourceKey": source_key,
            "workflowPath": source["workflowPath"],
            "artifactName": validator.artifact_name(
                source,
                RELEASE,
                1,
            ),
            "predicateType": source["predicateType"],
            "predicateDigest": validated["predicateDigest"],
            "subjectSetDigest": validated["subjectSetDigest"],
            "subjectCount": expected_subject_count,
            "proofIds": sorted(source["proofIds"]),
            "result": "verified",
        }
        receipts = validator.derive_standard(
            output_dir,
            source,
            validator.REPOSITORY,
            RELEASE,
            991,
            1,
            992,
            validator.artifact_name(source, RELEASE, 1),
            DIGEST,
            validated["predicateDigest"],
            validated["subjectSetDigest"],
            DIGEST,
            NOTICE_PATH,
        )
        assert {receipt["id"] for receipt in receipts} == set(
            source["proofIds"]
        )


with tempfile.TemporaryDirectory(
    prefix="submission-standard-determinism-"
) as raw:
    temporary = Path(raw)
    first_root = temporary / "first"
    second_root = temporary / "second"
    first_root.mkdir()
    second_root.mkdir()
    deterministic_timestamp = iso()
    first, _ = assemble_standard_fixture(
        first_root,
        "bonus-feedback",
        "assembled",
        captured_at=deterministic_timestamp,
    )
    second, _ = assemble_standard_fixture(
        second_root,
        "bonus-feedback",
        "assembled",
        captured_at=deterministic_timestamp,
    )
    deterministic_files = (
        validator.standard_subject_names(sources["bonus-feedback"])
        | {sources["bonus-feedback"]["subjectInventory"]}
    )
    assert {
        name: (first / name).read_bytes()
        for name in deterministic_files
    } == {
        name: (second / name).read_bytes()
        for name in deterministic_files
    }


with tempfile.TemporaryDirectory(
    prefix="submission-standard-tamper-"
) as raw:
    temporary = Path(raw)

    support_root = temporary / "support"
    support_root.mkdir()
    support_output, _ = assemble_standard_fixture(
        support_root,
        "bonus-feedback",
        "assembled",
    )
    support_path = (
        support_output
        / "support"
        / "BONUS-FEEDBACK"
        / "feedback-confirmation.json"
    )
    support = validator.load_json(support_path, "assembled support")
    support["bindings"]["oneEntryPerEntrant"] = False
    support_path.write_text(
        validator.canonical_json_text(support),
        encoding="utf-8",
        newline="\n",
    )
    reseal_standard_inventory(support_output, "bonus-feedback")
    expect_rejected(
        lambda: validator.validate_standard_source(
            support_output,
            sources["bonus-feedback"],
            validator.REPOSITORY,
            RELEASE,
            991,
            1,
            NOTICE_PATH,
        ),
        "standard source accepted a resealed false support binding",
    )

    oss_support_root = temporary / "oss-support"
    oss_support_root.mkdir()
    oss_support_output, _ = assemble_standard_fixture(
        oss_support_root,
        "bonus-oss",
        "assembled",
    )
    oss_support_path = (
        oss_support_output
        / "support"
        / "BONUS-OSS"
        / "ci-validation.json"
    )
    oss_support = validator.load_json(
        oss_support_path,
        "assembled BONUS-OSS support",
    )
    oss_support["bindings"]["candidateBinding"][
        "exactHeadTreeMatch"
    ] = False
    oss_support_path.write_text(
        validator.canonical_json_text(oss_support),
        encoding="utf-8",
        newline="\n",
    )
    reseal_standard_inventory(oss_support_output, "bonus-oss")
    expect_rejected(
        lambda: validator.validate_standard_source(
            oss_support_output,
            sources["bonus-oss"],
            validator.REPOSITORY,
            RELEASE,
            991,
            1,
            NOTICE_PATH,
        ),
        "standard source accepted a resealed false OSS tree binding",
    )

    predicate_root = temporary / "predicate"
    predicate_root.mkdir()
    predicate_output, _ = assemble_standard_fixture(
        predicate_root,
        "bonus-feedback",
        "assembled",
    )
    predicate_path = predicate_output / "attestation-predicate.json"
    predicate = validator.load_json(
        predicate_path,
        "assembled predicate",
    )
    predicate["source"]["runAttempt"] = 2
    predicate_path.write_text(
        validator.canonical_json_text(predicate),
        encoding="utf-8",
        newline="\n",
    )
    reseal_standard_inventory(predicate_output, "bonus-feedback")
    expect_rejected(
        lambda: validator.validate_standard_source(
            predicate_output,
            sources["bonus-feedback"],
            validator.REPOSITORY,
            RELEASE,
            991,
            1,
            NOTICE_PATH,
        ),
        "standard source accepted a resealed wrong predicate run attempt",
    )

    detached_run_root = temporary / "detached-run"
    detached_run_root.mkdir()
    detached_run_output, _ = assemble_standard_fixture(
        detached_run_root,
        "bonus-feedback",
        "assembled",
    )
    rebind_feedback_source_facts(
        detached_run_output,
        lambda value: value["reviewApproval"].update(runId=992),
    )
    expect_rejected(
        lambda: validator.validate_standard_source(
            detached_run_output,
            sources["bonus-feedback"],
            validator.REPOSITORY,
            RELEASE,
            991,
            1,
            NOTICE_PATH,
        ),
        "standard source accepted feedback approval from another run",
    )

    detached_attempt_root = temporary / "detached-attempt"
    detached_attempt_root.mkdir()
    detached_attempt_output, _ = assemble_standard_fixture(
        detached_attempt_root,
        "bonus-feedback",
        "assembled",
    )
    rebind_feedback_source_facts(
        detached_attempt_output,
        lambda value: value["reviewApproval"].update(runAttempt=2),
    )
    expect_rejected(
        lambda: validator.validate_standard_source(
            detached_attempt_output,
            sources["bonus-feedback"],
            validator.REPOSITORY,
            RELEASE,
            991,
            1,
            NOTICE_PATH,
        ),
        "standard source accepted feedback approval from another attempt",
    )

    inventory_root = temporary / "inventory"
    inventory_root.mkdir()
    inventory_output, _ = assemble_standard_fixture(
        inventory_root,
        "bonus-feedback",
        "assembled",
    )
    inventory_path = inventory_output / "SHA256SUMS"
    rows = inventory_path.read_text(encoding="utf-8").splitlines()
    inventory_path.write_text(
        "\n".join(reversed(rows)) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    expect_rejected(
        lambda: validator.validate_standard_source(
            inventory_output,
            sources["bonus-feedback"],
            validator.REPOSITORY,
            RELEASE,
            991,
            1,
            NOTICE_PATH,
        ),
        "standard source accepted a noncanonical inventory order",
    )

    extra_root = temporary / "extra"
    extra_root.mkdir()
    extra_output, _ = assemble_standard_fixture(
        extra_root,
        "bonus-feedback",
        "assembled",
    )
    (extra_output / "unexpected.json").write_text(
        "{}\n",
        encoding="utf-8",
        newline="\n",
    )
    expect_rejected(
        lambda: validator.validate_standard_source(
            extra_output,
            sources["bonus-feedback"],
            validator.REPOSITORY,
            RELEASE,
            991,
            1,
            NOTICE_PATH,
        ),
        "standard source ignored an extra artifact file",
    )


with tempfile.TemporaryDirectory(
    prefix="submission-standard-failure-"
) as raw:
    temporary = Path(raw)
    invalid_facts = copy.deepcopy(facts_by_id["BONUS-FEEDBACK"])
    invalid_facts["oneEntryPerEntrant"] = False
    invalid_root = temporary / "invalid"
    invalid_root.mkdir()
    facts_dir = write_standard_facts_directory(
        invalid_root,
        "bonus-feedback",
        facts_override={"BONUS-FEEDBACK": invalid_facts},
    )
    output_dir = temporary / "must-not-appear"
    expect_rejected(
        lambda: validator.assemble_standard_command(
            SimpleNamespace(
                registry=REGISTRY_PATH,
                source_key="bonus-feedback",
                facts_dir=facts_dir,
                output_dir=output_dir,
                repository=validator.REPOSITORY,
                release_sha=RELEASE,
                run_id=991,
                run_attempt=1,
                notice=NOTICE_PATH,
            )
        ),
        "assembler accepted invalid facts",
    )
    assert not output_dir.exists()
    assert not list(
        temporary.glob(".must-not-appear.assembling-*")
    ), "failed assembly leaked a staging directory"

    extra_facts_root = temporary / "extra-facts"
    extra_facts_root.mkdir()
    extra_facts_dir = write_standard_facts_directory(
        extra_facts_root,
        "bonus-feedback",
    )
    validator.write_json(
        extra_facts_dir / "EXTRA.json",
        {"unregistered": True},
    )
    empty_output = temporary / "empty-output"
    empty_output.mkdir()
    expect_rejected(
        lambda: validator.assemble_standard_source(
            empty_output,
            extra_facts_dir,
            sources["bonus-feedback"],
            validator.REPOSITORY,
            RELEASE,
            991,
            1,
            NOTICE_PATH,
            captured_at=iso(),
        ),
        "assembler accepted an extra facts file",
    )
    assert not list(empty_output.iterdir())

    symlink_root = temporary / "symlink-facts"
    symlink_root.mkdir()
    symlink_target = symlink_root / "outside.json"
    validator.write_json(
        symlink_target,
        facts_by_id["BONUS-FEEDBACK"],
    )
    symlink_facts = symlink_root / "facts"
    symlink_facts.mkdir()
    (
        symlink_facts / "BONUS-FEEDBACK.json"
    ).symlink_to(symlink_target)
    symlink_output = temporary / "symlink-output"
    symlink_output.mkdir()
    expect_rejected(
        lambda: validator.assemble_standard_source(
            symlink_output,
            symlink_facts,
            sources["bonus-feedback"],
            validator.REPOSITORY,
            RELEASE,
            991,
            1,
            NOTICE_PATH,
            captured_at=iso(),
        ),
        "assembler accepted a symlinked facts file",
    )
    assert not list(symlink_output.iterdir())

    native_output = temporary / "native-output"
    native_output.mkdir()
    expect_rejected(
        lambda: validator.assemble_standard_source(
            native_output,
            extra_facts_dir,
            sources["live-datahub"],
            validator.REPOSITORY,
            RELEASE,
            991,
            1,
            NOTICE_PATH,
            captured_at=iso(),
        ),
        "standard assembler accepted a native-live source",
    )
    assert not list(native_output.iterdir())


assemble_args = validator.parser().parse_args(
    [
        "assemble-standard",
        "--registry",
        str(REGISTRY_PATH),
        "--source-key",
        "bonus-feedback",
        "--facts-dir",
        "facts",
        "--output-dir",
        "output",
        "--repository",
        validator.REPOSITORY,
        "--release-sha",
        RELEASE,
        "--run-id",
        "991",
        "--run-attempt",
        "1",
        "--notice",
        str(NOTICE_PATH),
    ]
)
assert assemble_args.handler is validator.assemble_standard_command
validate_standard_args = validator.parser().parse_args(
    [
        "validate-standard-source",
        "--registry",
        str(REGISTRY_PATH),
        "--source-key",
        "bonus-feedback",
        "--source-dir",
        "source",
        "--repository",
        validator.REPOSITORY,
        "--release-sha",
        RELEASE,
        "--run-id",
        "991",
        "--run-attempt",
        "1",
        "--notice",
        str(NOTICE_PATH),
    ]
)
assert (
    validate_standard_args.handler
    is validator.validate_standard_source_command
)


with tempfile.TemporaryDirectory(prefix="submission-evidence-contracts-") as raw:
    temporary = Path(raw)
    receipt_dir, retained_receipts, retained_predicate = (
        materialize_standard_source(
            temporary,
            "bonus-feedback",
            {"BONUS-FEEDBACK": facts_by_id["BONUS-FEEDBACK"]},
        )
    )
    loaded = validator.load_receipt_directory(
        receipt_dir,
        sources,
        validator.REPOSITORY,
        RELEASE,
        NOTICE_PATH,
    )
    validator.revalidate_retained_sources(
        receipt_dir,
        loaded,
        sources,
        validator.REPOSITORY,
        RELEASE,
        NOTICE_PATH,
    )
    support_path = (
        temporary
        / "upstream-subjects"
        / "bonus-feedback"
        / "support"
        / "BONUS-FEEDBACK"
        / "feedback-confirmation.json"
    )
    retained_inventory_subjects = validator.load_checksum_inventory(
        temporary
        / "upstream-subjects"
        / "bonus-feedback"
        / "SHA256SUMS",
        "SHA256SUMS",
        "retained fixture inventory",
    )
    expected_statement_subjects = validator.attestation_subjects(
        retained_inventory_subjects
    )
    feedback_receipt = retained_receipts["BONUS-FEEDBACK"]
    feedback_attestation = feedback_receipt["source"]["attestation"]
    feedback_subject = next(
        subject
        for subject in feedback_attestation["subjects"]
        if subject["role"] == "feedback-confirmation"
    )
    verification_projection = {
        "schemaVersion": "archon.upstream-attestation-verification/v1",
        "repository": validator.REPOSITORY,
        "releaseSha": RELEASE,
        "proofId": "BONUS-FEEDBACK",
        "role": "feedback-confirmation",
        "subject": {
            "name": feedback_subject["name"],
            "digest": feedback_subject["digest"],
        },
        "predicate": {
            "type": sources["bonus-feedback"]["predicateType"],
            "digest": feedback_attestation["predicateDigest"],
        },
    }
    tampered_support = validator.load_json(support_path, "support fixture")
    tampered_support["capture"]["data"][0]["evidence"][
        "oneEntryPerEntrant"
    ] = False
    tampered_path = temporary / "tampered-support.json"
    validator.write_json(tampered_path, tampered_support)
    expect_rejected(
        lambda: validator.validate_support_subject(
            tampered_path,
            "BONUS-FEEDBACK",
            "feedback-confirmation",
            validator.REPOSITORY,
            RELEASE,
            facts_by_id["BONUS-FEEDBACK"],
        ),
        "support validation accepted capture bytes that differ from the binding",
    )
    forged_verification = temporary / "forged-verification.json"
    validator.write_json(
        forged_verification,
        {
            **verification_projection,
            "statement": {
                "predicateType": sources["bonus-feedback"]["predicateType"],
                "predicate": {"forged": True},
                "subject": expected_statement_subjects,
            },
        },
    )
    expect_rejected(
        lambda: validator.validate_gh_verification(
            forged_verification,
            validator.REPOSITORY,
            RELEASE,
            "BONUS-FEEDBACK",
            "feedback-confirmation",
            sources["bonus-feedback"]["predicateType"],
            feedback_attestation["predicateDigest"],
            retained_predicate,
            feedback_subject["name"],
            feedback_subject["digest"],
            expected_statement_subjects,
            "forged verification",
        ),
        "protected validation accepted a forged upstream predicate statement",
    )
    extra_subject_verification = temporary / "extra-subject-verification.json"
    validator.write_json(
        extra_subject_verification,
        {
            **verification_projection,
            "statement": {
                "predicateType": sources["bonus-feedback"]["predicateType"],
                "predicate": retained_predicate,
                "subject": [
                    *expected_statement_subjects,
                    {
                        "name": "unregistered.json",
                        "digest": {"sha256": "c" * 64},
                    },
                ],
            },
        },
    )
    expect_rejected(
        lambda: validator.validate_gh_verification(
            extra_subject_verification,
            validator.REPOSITORY,
            RELEASE,
            "BONUS-FEEDBACK",
            "feedback-confirmation",
            sources["bonus-feedback"]["predicateType"],
            feedback_attestation["predicateDigest"],
            retained_predicate,
            feedback_subject["name"],
            feedback_subject["digest"],
            expected_statement_subjects,
            "extra-subject verification",
        ),
        "upstream verification accepted a subject outside the exact inventory",
    )
    wrong_subject_set_receipts = copy.deepcopy(retained_receipts)
    wrong_subject_set_receipts["BONUS-FEEDBACK"]["source"]["attestation"][
        "subjectSetDigest"
    ] = ALT_DIGEST
    expect_rejected(
        lambda: validator.revalidate_retained_sources(
            receipt_dir,
            wrong_subject_set_receipts,
            sources,
            validator.REPOSITORY,
            RELEASE,
            NOTICE_PATH,
        ),
        "protected validation accepted a receipt bound to the wrong full subject set",
    )
    extra_subject = (
        temporary / "upstream-subjects" / "bonus-feedback" / "extra.json"
    )
    extra_subject.write_text("{}\n", encoding="utf-8")
    expect_rejected(
        lambda: validator.revalidate_retained_sources(
            receipt_dir,
            retained_receipts,
            sources,
            validator.REPOSITORY,
            RELEASE,
            NOTICE_PATH,
        ),
        "retained source validation ignored an extra file",
    )
    (receipt_dir / "ignored.txt").write_text(
        "must be rejected\n",
        encoding="utf-8",
    )
    expect_rejected(
        lambda: validator.load_receipt_directory(
            receipt_dir,
            sources,
            validator.REPOSITORY,
            RELEASE,
            NOTICE_PATH,
        ),
        "receipt inventory ignored an extra non-JSON file",
    )

derive_live_source = VALIDATOR_PATH.read_text(encoding="utf-8").split(
    "def derive_live(", maxsplit=1
)[1].split("def standard_subject_names(", maxsplit=1)[0]
assert "archon.aws-deployment-evidence/v2" in derive_live_source
assert 'proof["governedWrite"]' in derive_live_source
assert "preProductionGovernedCanary" not in derive_live_source
assert "pipelineSecurity" not in derive_live_source
assert "fixtureBinding" not in derive_live_source

with tempfile.TemporaryDirectory(prefix="native-live-v3-derive-") as raw:
    native_root = Path(raw)
    live_source = sources["live-datahub"]
    runtime_binding = {
        "profileId": "cloud",
        "availability": "READY",
        "generation": "cloud-release-v1",
        "capabilityDigest": DIGEST,
        "bindingDigest": ALT_DIGEST,
    }
    proof = {
        "schemaVersion": "archon.live-datahub-proof/v3",
        "ok": True,
        "result": "retained-history-contradiction-proven",
        "querySha256": "c" * 64,
        "datasetUrnSha256": "b" * 64,
        "datasetsDiscovered": 1,
        "aspectHistories": 1,
        "retainedHistories": 1,
        "stableSourceCount": 2,
        "recoveredContradictions": 1,
        "contradictionAttributeCount": 1,
        "runtimeBinding": runtime_binding,
        "governedWrite": copy.deepcopy(
            facts_by_id["D4"]["governedWrite"]
        ),
    }
    semantic = {
        "schemaVersion": "archon.deployed-datahub-semantic-proof/v2",
        "evidenceClass": "credentialed-live-cloud",
        "classification": copy.deepcopy(
            facts_by_id["U3"]["classification"]
        ),
        "findings": copy.deepcopy(facts_by_id["U3"]["findings"]),
    }
    deployment = {
        "schemaVersion": "archon.aws-deployment-evidence/v2",
        "stage": "production",
        "releaseSha": RELEASE,
        "ciRunId": 701,
        "deploymentRunId": 702,
        "applicationUrl": facts_by_id["D4"]["applicationUrl"],
        "promotion": {
            "policy": "build-once-promote-exact-artifacts",
            "webArtifactDigest": DIGEST,
            "lambdaArtifactDigest": ALT_DIGEST,
            "cloudRuntimeReleaseDigest": THIRD_DIGEST,
            "coreCapabilityDigest": DIGEST,
            "coreImageManifestDigest": ALT_DIGEST,
        },
        "verification": {
            "result": "passed",
            "zeroIdleCore": True,
            "httpBoundary": True,
            "securityHeaders": True,
            "directApiRejected": True,
            "canonicalHostEnforced": True,
            "observationSha256": "e" * 64,
        },
        "secretsProjected": False,
        "generatedAt": iso(),
    }
    proof_path = native_root / "proof.json"
    semantic_path = (
        native_root / "deployed-datahub-semantic-proof.json"
    )
    deployment_path = native_root / "deployment-evidence.json"
    validator.write_json(proof_path, proof)
    validator.write_json(semantic_path, semantic)
    validator.write_json(deployment_path, deployment)
    predicate = {
        "schemaVersion": live_source["predicateSchemaVersion"],
        "repository": validator.REPOSITORY,
        "workflow": {"runId": "703", "runAttempt": "1"},
        "releaseSha": RELEASE,
        "deploymentRunId": "702",
        "governedCanaryRunId": str(
            proof["governedWrite"]["workflowRunId"]
        ),
        "provenAt": iso(),
        "querySha256": proof["querySha256"],
        "runtimeBinding": runtime_binding,
        "evidence": {
            "proofSha256": validator.sha256_file(
                proof_path
            ).removeprefix("sha256:"),
            "deploymentEvidenceSha256": validator.sha256_file(
                deployment_path
            ).removeprefix("sha256:"),
            "deployedDataHubSemanticProofSha256":
                validator.sha256_file(semantic_path).removeprefix(
                    "sha256:"
                ),
        },
        "result": proof["result"],
        "datasetUrnSha256": proof["datasetUrnSha256"],
    }
    predicate_path = native_root / "attestation-predicate.json"
    validator.write_json(predicate_path, predicate)
    inventory = {
        name: validator.sha256_file(native_root / name)
        for name in (
            "deployment-evidence.json",
            "deployed-datahub-semantic-proof.json",
            "proof.json",
        )
    }
    inventory_path = native_root / "proof-subject.sha256"
    inventory_path.write_text(
        validator.checksum_inventory_text(inventory),
        encoding="utf-8",
    )
    derived = validator.derive_live(
        native_root,
        live_source,
        validator.REPOSITORY,
        RELEASE,
        703,
        1,
        704,
        f"live-datahub-proof-{RELEASE}-1",
        THIRD_DIGEST,
        validator.sha256_file(predicate_path),
        validator.checksum_subject_set_digest(inventory),
        ALT_DIGEST,
    )
    derived_by_id = {receipt["id"]: receipt for receipt in derived}
    assert derived_by_id["D4"]["facts"] == facts_by_id["D4"]
    assert derived_by_id["U3"]["facts"] == facts_by_id["U3"]

    legacy_deployment = copy.deepcopy(deployment)
    legacy_deployment["pipelineSecurity"] = {
        "preProductionGovernedCanary": {}
    }
    deployment_path.unlink()
    validator.write_json(deployment_path, legacy_deployment)
    predicate["evidence"]["deploymentEvidenceSha256"] = (
        validator.sha256_file(deployment_path).removeprefix("sha256:")
    )
    predicate_path.unlink()
    validator.write_json(predicate_path, predicate)
    inventory["deployment-evidence.json"] = validator.sha256_file(
        deployment_path
    )
    inventory_path.write_text(
        validator.checksum_inventory_text(inventory),
        encoding="utf-8",
    )
    expect_rejected(
        lambda: validator.derive_live(
            native_root,
            live_source,
            validator.REPOSITORY,
            RELEASE,
            703,
            1,
            704,
            f"live-datahub-proof-{RELEASE}-1",
            THIRD_DIGEST,
            validator.sha256_file(predicate_path),
            validator.checksum_subject_set_digest(inventory),
            ALT_DIGEST,
        ),
        "native D4 accepted legacy deploy.pipelineSecurity canary facts",
    )

with tempfile.TemporaryDirectory(prefix="native-live-subject-set-") as raw:
    native_root = Path(raw) / "upstream-subjects" / "live-datahub"
    native_root.mkdir(parents=True)
    for name, value in {
        "proof.json": {"kind": "live-proof"},
        "deployment-evidence.json": {"kind": "deployment"},
        "deployed-datahub-semantic-proof.json": {"kind": "semantic"},
        "sealed-extra.json": {"kind": "additional-attested-evidence"},
    }.items():
        validator.write_json(native_root / name, value)
    native_predicate = {
        "schemaVersion": "archon.live-datahub-proof-attestation/v4",
        "result": "verified",
    }
    native_predicate_path = native_root / "attestation-predicate.json"
    validator.write_json(native_predicate_path, native_predicate)
    native_inventory_rows = [
        "proof.json",
        "sealed-extra.json",
        "deployment-evidence.json",
        "deployed-datahub-semantic-proof.json",
    ]
    native_inventory_path = native_root / "proof-subject.sha256"
    native_inventory_path.write_text(
        "".join(
            f"{validator.sha256_file(native_root / name).removeprefix('sha256:')}"
            f"  {name}\n"
            for name in native_inventory_rows
        ),
        encoding="utf-8",
    )
    native_inventory = validator.load_checksum_inventory(
        native_inventory_path,
        "proof-subject.sha256",
        "native fixture inventory",
    )
    assert "attestation-predicate.json" not in native_inventory
    validator.exact_retained_tree(
        native_root,
        {
            *native_inventory,
            "proof-subject.sha256",
            "attestation-predicate.json",
        },
        "native fixture retained tree",
    )
    native_source = sources["live-datahub"]
    native_predicate_digest = validator.sha256_file(native_predicate_path)
    native_subject_digest = validator.sha256_file(
        native_root / "deployment-evidence.json"
    )
    native_projection = {
        "schemaVersion": "archon.upstream-attestation-verification/v1",
        "repository": validator.REPOSITORY,
        "releaseSha": RELEASE,
        "proofId": "D4",
        "role": "deployment-evidence",
        "subject": {
            "name": "deployment-evidence.json",
            "digest": native_subject_digest,
        },
        "predicate": {
            "type": native_source["predicateType"],
            "digest": native_predicate_digest,
        },
        "statement": {
            "predicateType": native_source["predicateType"],
            "predicate": native_predicate,
            "subject": validator.attestation_subjects(native_inventory),
        },
    }
    native_verification = Path(raw) / "D4--deployment-evidence.json"
    validator.write_json(native_verification, native_projection)
    validator.validate_gh_verification(
        native_verification,
        validator.REPOSITORY,
        RELEASE,
        "D4",
        "deployment-evidence",
        native_source["predicateType"],
        native_predicate_digest,
        native_predicate,
        "deployment-evidence.json",
        native_subject_digest,
        validator.attestation_subjects(native_inventory),
        "native multi-subject verification",
    )
    native_with_predicate = copy.deepcopy(native_projection)
    native_with_predicate["statement"]["subject"].append(
        {
            "name": "attestation-predicate.json",
            "digest": {
                "sha256": native_predicate_digest.removeprefix("sha256:")
            },
        }
    )
    native_bad_verification = Path(raw) / "native-extra-subject.json"
    validator.write_json(native_bad_verification, native_with_predicate)
    expect_rejected(
        lambda: validator.validate_gh_verification(
            native_bad_verification,
            validator.REPOSITORY,
            RELEASE,
            "D4",
            "deployment-evidence",
            native_source["predicateType"],
            native_predicate_digest,
            native_predicate,
            "deployment-evidence.json",
            native_subject_digest,
            validator.attestation_subjects(native_inventory),
            "native predicate-outside-inventory verification",
        ),
        "native verification accepted the predicate outside its exact subject inventory",
    )

with tempfile.TemporaryDirectory(prefix="submission-registry-contracts-") as raw:
    weakened_registry = copy.deepcopy(registry)
    project_access = next(
        item
        for item in weakened_registry["sources"]
        if item["key"] == "project-access"
    )
    project_access["supportSubjects"]["SQ4"].pop()
    weakened_registry_path = Path(raw) / "weakened-registry.json"
    validator.write_json(weakened_registry_path, weakened_registry)
    expect_rejected(
        lambda: validator.load_registry(weakened_registry_path),
        "registry accepted a missing required proof-support role",
    )
    operations = next(
        item
        for item in registry["sources"]
        if item["key"] == "operations"
    )
    assert {
        subject["role"]
        for subject in operations["supportSubjects"]["SQ10"]
    } == {
        "availability-attestation",
        "posture-attestation",
        "paging-delivery",
        "rollback-recovery",
        "credential-rotation",
        "judge-access-validity",
        "monitor-configuration",
    }


def artifact_fixture(
    attempt: int,
    *,
    artifact_id: int | None = None,
    expired: bool = False,
    digest: str = DIGEST,
    size: int = 1024,
    run_id: int = 901,
    release: str = RELEASE,
) -> dict:
    return {
        "id": artifact_id if artifact_id is not None else 1000 + attempt,
        "name": f"submission-project-access-{RELEASE}-{attempt}",
        "expired": expired,
        "digest": digest,
        "size_in_bytes": size,
        "workflow_run": {
            "id": run_id,
            "head_sha": release,
        },
    }


def select_artifact(
    artifacts: list[dict],
    *,
    policy: str,
    maximum_attempt: int,
) -> dict:
    return validator.select_run_artifact(
        [{"total_count": len(artifacts), "artifacts": artifacts}],
        policy=policy,
        artifact_prefix=f"submission-project-access-{RELEASE}-",
        run_id=901,
        release_sha=RELEASE,
        maximum_attempt=maximum_attempt,
    )


exact_current = select_artifact(
    [artifact_fixture(2)],
    policy="exact-current",
    maximum_attempt=2,
)
assert exact_current["producerAttempt"] == 2

failed_attester_retry = select_artifact(
    [artifact_fixture(2)],
    policy="latest-retained",
    maximum_attempt=3,
)
assert failed_attester_retry["producerAttempt"] == 2

full_rerun = [artifact_fixture(1), artifact_fixture(2)]
assert (
    select_artifact(
        full_rerun,
        policy="latest-retained",
        maximum_attempt=2,
    )["producerAttempt"]
    == 2
)
assert (
    select_artifact(
        full_rerun,
        policy="exact-current",
        maximum_attempt=2,
    )["producerAttempt"]
    == 2
)
expect_rejected(
    lambda: select_artifact(
        full_rerun,
        policy="single-retained",
        maximum_attempt=2,
    ),
    "single-retained policy accepted a producer rerun",
)
assert (
    select_artifact(
        [artifact_fixture(1)],
        policy="single-retained",
        maximum_attempt=2,
    )["producerAttempt"]
    == 1
)

artifact_rejections = (
    (
        [artifact_fixture(2), artifact_fixture(2, artifact_id=2002)],
        "latest-retained",
        3,
        "duplicate selected producer attempt",
    ),
    (
        [artifact_fixture(4)],
        "latest-retained",
        3,
        "future producer attempt",
    ),
    (
        [artifact_fixture(2, expired=True)],
        "latest-retained",
        3,
        "expired artifact",
    ),
    (
        [artifact_fixture(2, run_id=902)],
        "latest-retained",
        3,
        "wrong workflow-run owner",
    ),
    (
        [artifact_fixture(2, release="c" * 40)],
        "latest-retained",
        3,
        "wrong release",
    ),
    (
        [artifact_fixture(2, digest="sha256:not-a-digest")],
        "latest-retained",
        3,
        "invalid digest",
    ),
    (
        [artifact_fixture(2, size=0)],
        "latest-retained",
        3,
        "zero-sized artifact",
    ),
    (
        [artifact_fixture(2, size=52_428_801)],
        "latest-retained",
        3,
        "oversized artifact",
    ),
)
for rejected_artifacts, rejected_policy, rejected_maximum, rejected_label in (
    artifact_rejections
):
    expect_rejected(
        lambda artifacts=rejected_artifacts,
        policy=rejected_policy,
        maximum=rejected_maximum: select_artifact(
            artifacts,
            policy=policy,
            maximum_attempt=maximum,
        ),
        f"artifact selection accepted {rejected_label}",
    )

expect_rejected(
    lambda: validator.select_run_artifact(
        [{"total_count": 2, "artifacts": [artifact_fixture(2)]}],
        policy="latest-retained",
        artifact_prefix=f"submission-project-access-{RELEASE}-",
        run_id=901,
        release_sha=RELEASE,
        maximum_attempt=3,
    ),
    "artifact selection accepted an incomplete paginated response",
)
expect_rejected(
    lambda: validator.select_run_artifact(
        [
            {"total_count": 2, "artifacts": [artifact_fixture(1)]},
            {"total_count": 3, "artifacts": [artifact_fixture(2)]},
        ],
        policy="latest-retained",
        artifact_prefix=f"submission-project-access-{RELEASE}-",
        run_id=901,
        release_sha=RELEASE,
        maximum_attempt=3,
    ),
    "artifact selection accepted pagination total-count drift",
)
expect_rejected(
    lambda: validator.select_run_artifact(
        [
            {"total_count": 2, "artifacts": [artifact_fixture(1)]},
            {"total_count": 2, "artifacts": [artifact_fixture(1)]},
        ],
        policy="latest-retained",
        artifact_prefix=f"submission-project-access-{RELEASE}-",
        run_id=901,
        release_sha=RELEASE,
        maximum_attempt=3,
    ),
    "artifact selection accepted a duplicate artifact across pages",
)
expect_rejected(
    lambda: validator.parse_json_text('{"value":1e999}', "overflow fixture"),
    "strict JSON parser accepted numeric overflow",
)

producer = (ROOT / ".github/workflows/submission-evidence.yml").read_text(
    encoding="utf-8"
)
collector = (ROOT / "scripts/collect-submission-evidence-source.sh").read_text(
    encoding="utf-8"
)
consumer = (ROOT / "scripts/verify-submission-readiness-source.sh").read_text(
    encoding="utf-8"
)
availability = (ROOT / ".github/workflows/availability.yml").read_text(
    encoding="utf-8"
)


def assert_availability_contract(workflow: str) -> None:
    assert workflow.startswith("name: Lean production availability\n")
    assert '    - cron: "*/30 * * * *"' in workflow
    assert "  workflow_dispatch:\n" in workflow
    assert "permissions: {}\n" in workflow
    assert "  group: archon-production-availability\n" in workflow
    assert "  cancel-in-progress: false\n" in workflow
    assert workflow.count("\n  probe:\n") == 1
    assert "\n  attest:\n" not in workflow
    for required in (
        "environment: production-observer",
        "actions: read",
        "attestations: write",
        "contents: read",
        "id-token: write",
        "aws-actions/configure-aws-credentials@",
        "scripts/verify-github-control-plane.sh",
        "scripts/observe-aws-live-runtime.sh",
        "EXPECT_CORE_IDLE: \"true\"",
        "archon.runtime-profiles/v1",
        '([.profiles[].profileId] | sort) == ["cloud","core"]',
        '.autoSelection == "cloud"',
        'select(.profileId == "cloud")',
        '== ["READY"]',
        'select(.profileId == "core")',
        '== ["LAUNCHABLE"]',
        "all(.capabilities[]; . == true)",
        'test("^sha256:[0-9a-f]{64}$")',
        "agentContextKit",
        "analyticsAgent",
        "dataHubSkills",
        "mcpGovernedWrite",
        "mcpRead",
        "archon.production-availability/v2",
        "publicSpa:true",
        "runtimeProfiles:true",
        "securityHeaders:true",
        "leanAwsControls:true",
        "coreIdle:true",
        "rawIdentifiersRetained:false",
        "actions/attest@",
        "attestations/production-availability/v2",
        "subject-path: ${{ steps.probe.outputs.evidence }}",
        "predicate-path: ${{ steps.probe.outputs.evidence }}",
        "name: production-availability-${{ github.sha }}-${{ github.run_id }}",
        "path: |\n"
        "            ${{ runner.temp }}/availability/evidence.json\n"
        "            ${{ runner.temp }}/availability/observation.json",
        "retention-days: 90",
        "Remove runner-only evidence",
    ):
        assert required in workflow, f"availability lost lean-v2 contract {required}"
    for forbidden in (
        "producer_run_attempt",
        "PRODUCER_RUN_ATTEMPT",
        "availability-subject.sha256",
        "attestation-predicate.json",
        "archon.production-availability-attestation/v1",
        "attestations/production-availability/v1",
        "live-runtime-manifest",
        'IN("READY","LAUNCHABLE","STARTING","BUSY","UNAVAILABLE")',
    ):
        assert forbidden not in workflow, f"availability retained legacy contract {forbidden}"
    assert "secrets." not in workflow


def expect_availability_contract_rejected(
    tampered_workflow: str, message: str
) -> None:
    try:
        assert_availability_contract(tampered_workflow)
    except AssertionError:
        return
    raise AssertionError(message)


assert_availability_contract(availability)
availability_tamper_cases = (
    (
        availability.replace(
            "archon.production-availability/v2",
            "archon.production-availability/v1",
            1,
        ),
        "availability accepted a legacy evidence schema",
    ),
    (
        availability.replace(
            "attestations/production-availability/v2",
            "attestations/production-availability/v1",
            1,
        ),
        "availability accepted a legacy predicate type",
    ),
    (
        availability.replace("coreIdle:true", "coreIdle:false", 1),
        "availability accepted a non-idle Core observation",
    ),
    (
        availability.replace(
            '.autoSelection == "cloud"',
            '.autoSelection == "core"',
            1,
        ),
        "availability accepted Core as the default judge runtime",
    ),
    (
        availability.replace('== ["READY"]', '== ["UNAVAILABLE"]', 1),
        "availability accepted an unavailable Cloud runtime",
    ),
    (
        availability.replace('== ["LAUNCHABLE"]', '== ["UNAVAILABLE"]', 1),
        "availability accepted an unavailable optional Core runtime",
    ),
    (
        availability.replace(
            "all(.capabilities[]; . == true)",
            'all(.capabilities[]; type == "boolean")',
            1,
        ),
        "availability accepted a missing required DataHub capability",
    ),
    (
        availability.replace(
            "            ${{ runner.temp }}/availability/observation.json\n",
            "            ${{ runner.temp }}/availability/index.html\n",
            1,
        ),
        "availability dropped the sanitized topology observation",
    ),
    (
        availability.replace(
            "name: production-availability-${{ github.sha }}-${{ github.run_id }}",
            "name: production-availability-${{ github.sha }}-${{ github.run_attempt }}",
            1,
        ),
        "availability artifact identity became retry-attempt based",
    ),
    (
        availability.replace(
            "  workflow_dispatch:\n",
            "  workflow_call:\n",
            1,
        ),
        "availability lost explicit operational dispatch",
    ),
)
for tampered_availability, tamper_message in availability_tamper_cases:
    assert tampered_availability != availability, (
        f"availability mutation was a no-op: {tamper_message}"
    )
    expect_availability_contract_rejected(
        tampered_availability,
        tamper_message,
    )

for forbidden_input in (
    "claims_json:",
    "evidence_json:",
    "artifact_path:",
    "source_workflow:",
    "application_url:",
    "video_url:",
):
    assert forbidden_input not in producer, (
        f"producer exposed arbitrary input {forbidden_input}"
    )
for required_binding in (
    "SOURCE_RUN_ID",
    ".workflow_run.id == $runId",
    ".workflow_run.head_sha == $release",
    "actual_artifact_digest",
    "zipfile.ZipFile",
    "duplicate canonical ZIP path",
    "extracted_bytes",
    "67108864",
    "--signer-workflow",
    "--signer-digest",
    "--predicate-type",
    "length == 1",
    "registered-subjects.tsv",
    "upstream-subjects",
    "--verification-set-digest",
    "subjectSetDigest",
    "attestation_run_attempt",
    'selection_policy="exact-current"',
    'selection_policy="latest-retained"',
    "select-run-artifact",
    '--maximum-attempt "${attestation_run_attempt}"',
    '--run-attempt "${producer_run_attempt}"',
    '--argjson runAttempt "${producer_run_attempt}"',
    ".run_attempt == $runAttempt",
    "source run changed during evidence collection",
    "master changed during",
    "artifact selection changed during collection",
    "artifact changed during evidence collection",
    "unique_by(.statement)",
):
    assert required_binding in collector, (
        f"collector lost exact binding {required_binding}"
    )
assert '--run-attempt "${attestation_run_attempt}"' not in collector
assert collector.count('python3 "${validator}" select-run-artifact') == 2
assert (
    'semantic_validator="scripts/validate-submission-proof-receipts.py"'
    in consumer
)
assert 'python3 "${semantic_validator}" validate-bundle' in consumer
assert 'test "${#archive_entries[@]}" -le 1024' in consumer
assert 'test "${extracted_bytes}" -le 67108864' in consumer
assert "zipfile.ZipFile" in consumer
assert "duplicate canonical ZIP path" in consumer
assert "fresh-upstream-attestation-verification/v1" in consumer
assert "upstreamVerificationSetDigest" in consumer
assert "SOURCE_PRODUCER_RUN_ATTEMPT" in consumer
assert "(( SOURCE_PRODUCER_RUN_ATTEMPT <= SOURCE_RUN_ATTEMPT ))" in consumer
assert '--argjson attempt "${SOURCE_RUN_ATTEMPT}"' in consumer
assert '--argjson runAttempt "${SOURCE_PRODUCER_RUN_ATTEMPT}"' in consumer
assert consumer.count('gh attestation verify "${upstream_subject}"') == 1
assert "exactly one fresh upstream statement must match" in consumer
assert consumer.count("bash scripts/verify-submission-readiness-source.sh") == 0
assert "\n  attest:\n" in producer
produce_job, attest_job = producer.split("\n  attest:\n", maxsplit=1)
assert "attestations: read" in produce_job
assert "attestations: write" not in produce_job
assert "id-token: write" not in produce_job
assert "attestations: write" in attest_job
assert "id-token: write" in attest_job
assert producer.count("attestations: write") == 1
assert producer.count("id-token: write") == 1
assert (
    "artifact-ids: ${{ needs.produce.outputs.artifact_id }}" in attest_job
)
assert ".id == $artifactId" in attest_job
assert ".digest == $digest" in attest_job
assert ".workflow_run.id == $runId" in attest_job
assert ".workflow_run.head_sha == $sha" in attest_job
assert attest_job.index("/actions/artifacts/${ARTIFACT_ID}") < attest_job.index(
    "actions/download-artifact@"
)
assert (
    "PRODUCER_RUN_ATTEMPT: "
    "${{ needs.produce.outputs.producer_run_attempt }}" in attest_job
)
assert "${GITHUB_RUN_ATTEMPT}" not in attest_job
assert (
    '"submission-evidence-${RELEASE_SHA}-${PRODUCER_RUN_ATTEMPT}"'
    in attest_job
)
assert (
    registry["aggregate"]["artifactNameTemplate"]
    == "submission-evidence-{releaseSha}-{runAttempt}"
)
assert producer.count(
    "scripts/validate-submission-proof-receipts.py build-bundle"
) == 2
assert "submission-evidence-derived" in attest_job
assert (
    'cmp --silent "${derived}/claims.json" "${output}/claims.json"'
    in attest_job
)
assert (
    'cmp --silent "${derived}/predicate.json" "${output}/predicate.json"'
    in attest_job
)
assert (
    "subject-checksums: "
    "${{ runner.temp }}/submission-evidence-subjects.sha256" in attest_job
)
for required_availability_contract in (
    "attestations: write",
    "id-token: write",
    "archon.production-availability/v2",
    "observation.json",
    "attestations/production-availability/v2",
    "actions/attest@",
):
    assert required_availability_contract in availability, (
        "availability lost custom attestation contract "
        f"{required_availability_contract}"
    )

expected_sources = {
    "D4": "live-datahub",
    "U3": "live-datahub",
    "SQ3": "project-access",
    "SQ4": "project-access",
    "SQ5": "project-access",
    "SQ6": "content-review",
    "SQ7": "content-review",
    "SQ8": "content-review",
    "SQ9": "judge-pack",
    "SQ10": "operations",
    "SQ11": "devpost-confirmation",
    "BONUS-OSS": "bonus-oss",
    "BONUS-FEEDBACK": "bonus-feedback",
}
for proof_id, source_key in expected_sources.items():
    assert proof_id in sources[source_key]["proofIds"]
assert {source["key"] for source in registry["sources"] if source["required"]} == {
    "live-datahub",
    "project-access",
    "content-review",
    "operations",
}
assert "post_submit_run_id:" in producer
assert (
    ROOT / ".github" / "workflows" / "submission-devpost-confirmation.yml"
).is_file(), "SQ11 Devpost-confirmation producer is missing"
assert (
    ROOT
    / "tests"
    / "pipeline"
    / "submission_devpost_confirmation_contracts_test.py"
).is_file(), "SQ11 dedicated contract is missing"
assert (
    ROOT / ".github" / "workflows" / "submission-bonus-oss.yml"
).is_file(), "BONUS-OSS producer is missing"
assert (
    ROOT / "tests" / "pipeline" / "submission_bonus_oss_contracts_test.py"
).is_file(), "BONUS-OSS dedicated contract is missing"
assert (
    ROOT / ".github" / "workflows" / "submission-bonus-feedback.yml"
).is_file(), "BONUS-FEEDBACK producer is missing"
assert (
    ROOT / "tests" / "pipeline" / "submission_bonus_feedback_contracts_test.py"
).is_file(), "BONUS-FEEDBACK dedicated contract is missing"

print(
    json.dumps(
        {
            "schemaVersion": "archon.submission-evidence-contract-test/v1",
            "validatedProofIds": sorted(facts_by_id),
            "result": "passed",
        },
        separators=(",", ":"),
        sort_keys=True,
    )
)
