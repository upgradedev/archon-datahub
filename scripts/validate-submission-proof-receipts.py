#!/usr/bin/env python3
"""Strict CI-only contracts for submission evidence.

The producer uses ``derive`` to turn an exact, attested upstream artifact into
one canonical receipt per proof.  The readiness source verifier uses
``validate-bundle`` again after independently fetching and attestation-checking
the aggregate artifact.  No command accepts claims, URLs, or facts on the
command line; semantic facts must come from a hard-registered artifact.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import math
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import parse_qs, urlsplit


REPOSITORY = "upgradedev/archon-datahub"
RECEIPT_SCHEMA = "archon.submission-proof-receipt/v1"
UPSTREAM_SCHEMA = "archon.submission-upstream-proof/v1"
UPSTREAM_PREDICATE_SCHEMA = "archon.submission-upstream-attestation/v1"
SUPPORT_SCHEMA = "archon.submission-support-subject/v1"
SUPPORT_CAPTURE_SCHEMA = "archon.submission-support-capture/v1"
SUPPORT_RECORD_SCHEMA = "archon.submission-support-record/v1"
UPSTREAM_BINDING_SCHEMA = "archon.submission-upstream-binding/v1"
CLAIMS_SCHEMA = "archon.submission-readiness-claims/v1"
PREDICATE_SCHEMA = "archon.submission-readiness-predicate/v1"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RAW_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_RE = re.compile(r"^[0-9a-f]{40}$")
LANGUAGE_RE = re.compile(r"^[a-z]{2}(?:-[A-Z]{2})?$")
JUDGING_END = dt.datetime(2026, 8, 31, 21, 0, 0, tzinfo=dt.timezone.utc)
JUDGING_START = dt.datetime(2026, 8, 17, 14, 0, 0, tzinfo=dt.timezone.utc)
SUBMISSION_START = dt.datetime(2026, 7, 6, 13, 0, 0, tzinfo=dt.timezone.utc)
SUBMISSION_DEADLINE = dt.datetime(
    2026, 8, 10, 21, 0, 0, tzinfo=dt.timezone.utc
)
FEEDBACK_START = SUBMISSION_START

PROOF_CRITERIA = {
    "D4": "use-of-datahub",
    "U3": "real-world-usefulness",
    "SQ3": "submission-quality",
    "SQ4": "submission-quality",
    "SQ5": "submission-quality",
    "SQ6": "submission-quality",
    "SQ7": "submission-quality",
    "SQ8": "submission-quality",
    "SQ9": "submission-quality",
    "SQ10": "submission-quality",
    "SQ11": "submission-quality",
    "BONUS-OSS": "bonus",
    "BONUS-FEEDBACK": "bonus",
}
REQUIRED_PROOFS = {
    "D4",
    "U3",
    "SQ3",
    "SQ4",
    "SQ5",
    "SQ6",
    "SQ7",
    "SQ8",
    "SQ10",
}
OPTIONAL_PROOFS = {"SQ9", "SQ11", "BONUS-OSS", "BONUS-FEEDBACK"}
BONUS_PROOFS = {"BONUS-OSS", "BONUS-FEEDBACK"}

EVIDENCE_SUMMARIES = {
    "D4": (
        "Attested live DataHub retained-history reads and the governed "
        "write/read-back/rollback canary were verified."
    ),
    "U3": (
        "Attested deployed DataHub semantics reproduced the exact G6, lineage, "
        "and retained-provenance findings."
    ),
    "SQ3": (
        "A fresh logged-out probe verified the exact release at its attested "
        "public HTTPS application origin."
    ),
    "SQ4": (
        "A fresh judge identity completed the tested free-access journey and "
        "verified its terminal receipt."
    ),
    "SQ5": (
        "A logged-out visitor verified the complete exact release and "
        "hosting-provider Apache-2.0 detection."
    ),
    "SQ6": (
        "All final written submission fields and testing instructions passed "
        "the digest-bound English review."
    ),
    "SQ7": (
        "The final public demo video is logged-out accessible, English "
        "accessible, claim-bound, and shorter than 180 seconds."
    ),
    "SQ8": (
        "An independent digest-bound review reconciled NOTICE, history, final "
        "copy, instructions, and video disclosures."
    ),
    "SQ9": (
        "The exact CI judge pack is retained as sanitized synthetic fixture "
        "evidence and is explicitly not live proof."
    ),
    "SQ10": (
        "Fresh attested availability and posture evidence, tested paging, "
        "recovery, credential rotation, and free judging access are active."
    ),
    "SQ11": (
        "Post-submit confirmation binds the public Devpost entry and every "
        "logged-out judging URL to the independently verified pre-submit seal."
    ),
    "BONUS-OSS": (
        "The CI-validated candidate is bound to a public upstream contribution "
        "with maintainer acceptance."
    ),
    "BONUS-FEEDBACK": (
        "A rules-defined, one-per-entrant feedback submission was privately "
        "reviewed and retained through privacy-preserving bindings."
    ),
}

SUPPORT_BINDING_FIELDS: dict[tuple[str, str], tuple[str, ...]] = {
    ("SQ3", "deployment-verification"): ("applicationUrl", "deployment"),
    ("SQ3", "availability-verification"): ("applicationUrl", "observation"),
    (
        "SQ3",
        "public-probe",
    ): ("applicationUrl", "applicationOriginDigest", "observation"),
    ("SQ4", "deployment-verification"): (
        "applicationUrl",
        "deployment",
        "observedAt",
    ),
    ("SQ4", "fresh-identity-lifecycle"): (
        "applicationUrl",
        "authenticationRequired",
        "accessMode",
        "judgeUserLifecycle",
        "freshJudgeJourney",
        "observedAt",
    ),
    ("SQ4", "fresh-judge-journey"): (
        "applicationUrl",
        "freshJudgeJourney",
        "freeAccess",
        "observedAt",
    ),
    ("SQ4", "credential-rotation-recovery"): (
        "authenticationRequired",
        "judgeUserLifecycle",
        "credentialRotation",
        "accessValidThrough",
        "observedAt",
    ),
    ("SQ4", "testing-instructions"): (
        "testingInstructionsPath",
        "testingInstructionsDigest",
        "accessMode",
        "freeAccess",
    ),
    ("SQ5", "logged-out-repository-probe"): (
        "repositoryUrl",
        "releaseUrl",
        "licenseUrl",
        "loggedOutAccessible",
        "observedAt",
    ),
    ("SQ5", "release-tree-inventory"): (
        "repositoryUrl",
        "releaseUrl",
        "defaultBranch",
        "releaseVisible",
        "completeSource",
        "observedAt",
    ),
    ("SQ5", "license-detection"): (
        "licenseUrl",
        "licenseSpdx",
        "hostingUiDetectedLicense",
        "observedAt",
    ),
    ("SQ6", "submission-fields"): (
        "allWrittenFieldsComplete",
        "submissionLanguage",
        "submissionFieldsDigest",
        "claimsDigest",
        "reviewedAt",
    ),
    ("SQ6", "testing-instructions"): (
        "testingInstructionsPath",
        "testingInstructionsLanguage",
        "testingInstructionsDigest",
        "reviewedAt",
    ),
    ("SQ6", "english-review"): (
        "submissionLanguage",
        "testingInstructionsLanguage",
        "completeEnglishTranslation",
        "reviewedAt",
    ),
    ("SQ7", "provider-metadata"): (
        "videoUrl",
        "durationSeconds",
        "providerResponseDigests",
        "spokenLanguage",
        "subtitlesLanguage",
        "reviewedAt",
    ),
    ("SQ7", "logged-out-video-probe"): (
        "videoUrl",
        "publiclyAccessible",
        "loggedOutAccessible",
        "providerResponseDigests",
        "reviewedAt",
    ),
    ("SQ7", "functioning-footage-review"): (
        "videoUrl",
        "functioningProjectShown",
        "shownApplicationUrl",
        "claimsDigest",
        "reviewedAt",
    ),
    ("SQ7", "english-accessibility"): (
        "spokenLanguage",
        "subtitlesLanguage",
        "completeEnglishTranslation",
        "reviewedAt",
    ),
    ("SQ7", "media-rights"): (
        "thirdPartyMarksAndMusicAuthorized",
        "allThirdPartyMaterialAuthorized",
        "mediaReviewDigest",
        "reviewedAt",
    ),
    ("SQ8", "repository-history"): (
        "rules",
        "projectHistory",
        "repositoryHistoryDigest",
        "finalizedAt",
        "reviewedAt",
    ),
    ("SQ8", "preexisting-work-inventory"): (
        "noticeDigest",
        "disclosureSetDigest",
        "preExistingWorkInventoryDigest",
        "thirdPartyInventoryDigest",
        "allNonStandardPreExistingWorkDisclosed",
        "workDescribedAndSubmittedBuiltDuringPeriod",
        "standardToolsOnlyExcludedFromDisclosure",
        "thirdPartyIntegrationsAuthorized",
        "originalWorkOwnershipReviewed",
    ),
    ("SQ8", "cross-medium-review"): (
        "reviewedSurfaces",
        "submissionFieldsDigest",
        "testingInstructionsDigest",
        "submissionClaimsDigest",
        "videoClaimsDigest",
        "crossMediumConsistent",
        "finalizedAt",
        "reviewedAt",
    ),
    ("SQ8", "solo-owner-approval"): ("reviewApproval", "reviewedAt"),
    ("SQ9", "ci-attestation"): ("evidenceClass", "ci"),
    ("SQ9", "judge-pack-manifest"): (
        "artifact",
        "manifestDigest",
        "formats",
        "sanitized",
        "notLiveProof",
    ),
    ("SQ10", "availability-attestation"): (
        "applicationUrl",
        "availability",
        "monitoringWindow",
    ),
    ("SQ10", "posture-attestation"): ("applicationUrl", "posture"),
    ("SQ10", "paging-delivery"): ("alerting",),
    ("SQ10", "rollback-recovery"): ("recovery",),
    ("SQ10", "credential-rotation"): ("recovery", "access"),
    ("SQ10", "judge-access-validity"): ("access", "monitoringWindow"),
    ("SQ10", "monitor-configuration"): (
        "applicationUrl",
        "monitoringWindow",
    ),
    ("BONUS-OSS", "upstream-pr"): (
        "upstreamRepositoryUrl",
        "pullRequestUrl",
        "state",
        "publiclyAccessible",
        "acceptedByMaintainer",
        "acceptedAt",
        "patchDigest",
        "upstreamPullRequest",
    ),
    ("BONUS-OSS", "ci-validation"): (
        "validatedCandidateDigest",
        "candidateBinding",
        "ciValidation",
    ),
    ("BONUS-FEEDBACK", "feedback-confirmation"): (
        "challengeUrl",
        "officialRulesUrl",
        "status",
        "submittedAt",
        "canonicalEvidenceDigest",
        "confirmationDigest",
        "entrantBindingDigest",
        "entrantKind",
        "registeredEntrant",
        "oneEntryPerEntrant",
        "individualNotProjectPrize",
        "distinctFeedbackSubmissionUnderRules",
        "feedbackQuality",
        "privacyDisclosure",
        "rulesObservation",
        "approvalTiming",
        "reviewApproval",
    ),
    ("SQ11", "pre-submit-readiness-seal"): ("preSubmitSeal",),
    ("SQ11", "devpost-submission-confirmation"): (
        "rules",
        "challengeUrl",
        "devpostProjectUrl",
        "submissionStatus",
        "submittedAt",
        "confirmationDigest",
        "allRequiredFieldsSubmitted",
        "challengeEntryVisible",
        "reviewApproval",
    ),
    ("SQ11", "public-devpost-entry"): (
        "devpostProjectUrl",
        "applicationUrl",
        "applicationAuthenticationRequired",
        "repositoryUrl",
        "videoUrl",
        "descriptionDigest",
        "submissionFieldsDigest",
        "testingInstructionsDigest",
        "submissionClaimsDigest",
        "videoClaimsDigest",
    ),
    ("SQ11", "logged-out-url-probes"): ("loggedOutVerification",),
}


class ContractError(ValueError):
    pass


def fail(message: str) -> NoReturn:
    raise ContractError(message)


def parse_json_text(raw: str, label: str) -> Any:
    def reject_duplicate_pairs(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                fail(f"{label} contains duplicate object key {key!r}")
            result[key] = item
        return result

    def reject_non_finite(value: str) -> NoReturn:
        fail(f"{label} contains non-finite JSON number {value}")

    def parse_finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            fail(f"{label} contains non-finite JSON number {value}")
        return parsed

    try:
        return json.loads(
            raw,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_non_finite,
            parse_float=parse_finite_float,
        )
    except json.JSONDecodeError as error:
        fail(f"{label} is not strict JSON: {error}")


def load_json(path: Path, label: str) -> Any:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular file")
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        fail(f"{label} is not strict UTF-8 JSON: {error}")
    return parse_json_text(raw, label)


def select_run_artifact(
    value: Any,
    *,
    policy: str,
    artifact_prefix: str,
    run_id: int,
    release_sha: str,
    maximum_attempt: int,
) -> dict[str, Any]:
    """Select one immutable GitHub Actions artifact by reviewed retry policy."""

    if not isinstance(policy, str) or policy not in {
        "exact-current",
        "exact-run-id",
        "single-retained",
        "latest-retained",
    }:
        fail("artifact selection policy is not registered")
    if not isinstance(artifact_prefix, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,170}", artifact_prefix
    ):
        fail("artifact prefix is not safe")
    if type(run_id) is not int or run_id <= 0:
        fail("artifact run ID must be a positive integer")
    if not isinstance(release_sha, str) or not RELEASE_RE.fullmatch(release_sha):
        fail("artifact release SHA must be exact")
    if type(maximum_attempt) is not int or maximum_attempt <= 0:
        fail("maximum run attempt must be a positive integer")

    pages = value if isinstance(value, list) else [value]
    if not pages:
        fail("artifact response must contain at least one page")
    candidates: list[tuple[int, dict[str, Any]]] = []
    expected_total_count: int | None = None
    collected_count = 0
    observed_artifact_ids: set[int] = set()
    for page_index, page in enumerate(pages):
        if not isinstance(page, dict) or not isinstance(page.get("artifacts"), list):
            fail(f"artifact response page {page_index} is malformed")
        total_count = page.get("total_count")
        if type(total_count) is not int or total_count < 0:
            fail(f"artifact response page {page_index} has an invalid total count")
        if expected_total_count is None:
            expected_total_count = total_count
        elif total_count != expected_total_count:
            fail("artifact response total count changed during pagination")
        collected_count += len(page["artifacts"])
        for artifact_index, artifact in enumerate(page["artifacts"]):
            if not isinstance(artifact, dict):
                fail(
                    f"artifact response page {page_index} item "
                    f"{artifact_index} is malformed"
                )
            observed_id = artifact.get("id")
            if type(observed_id) is not int or observed_id <= 0:
                fail("artifact response contains an invalid artifact ID")
            if observed_id in observed_artifact_ids:
                fail("artifact response contains a duplicate artifact ID")
            observed_artifact_ids.add(observed_id)
            name = artifact.get("name")
            if not isinstance(name, str) or not name.startswith(artifact_prefix):
                continue
            if len(name) > 181:
                fail("registered artifact name exceeds the reviewed limit")
            suffix = name.removeprefix(artifact_prefix)
            if not re.fullmatch(r"[1-9][0-9]*", suffix):
                fail("registered artifact prefix has a malformed attempt suffix")
            attempt = int(suffix)
            if policy != "exact-run-id" and attempt > maximum_attempt:
                fail("registered artifact has a future producer attempt")
            candidates.append((attempt, artifact))
    if expected_total_count != collected_count:
        fail("artifact response is incomplete")

    if policy == "exact-current":
        selected = [
            (attempt, artifact)
            for attempt, artifact in candidates
            if attempt == maximum_attempt
        ]
        if len(selected) != 1:
            fail("exact-current policy requires one current-attempt artifact")
    elif policy == "exact-run-id":
        selected = [
            (attempt, artifact)
            for attempt, artifact in candidates
            if attempt == run_id
        ]
        if len(selected) != 1:
            fail("exact-run-id policy requires one run-ID-bound artifact")
    elif policy == "single-retained":
        selected = candidates
        if len(selected) != 1:
            fail("single-retained policy requires exactly one retained artifact")
    else:
        if not candidates:
            fail("latest-retained policy found no eligible artifact")
        latest_attempt = max(attempt for attempt, _artifact in candidates)
        selected = [
            (attempt, artifact)
            for attempt, artifact in candidates
            if attempt == latest_attempt
        ]
        if len(selected) != 1:
            fail("latest-retained producer attempt is ambiguous")

    producer_attempt, metadata = selected[0]
    if policy == "exact-run-id":
        producer_attempt = maximum_attempt
    artifact_id = metadata.get("id")
    artifact_digest = metadata.get("digest")
    artifact_size = metadata.get("size_in_bytes")
    workflow_run = metadata.get("workflow_run")
    if type(artifact_id) is not int or artifact_id <= 0:
        fail("selected artifact ID is invalid")
    if metadata.get("expired") is not False:
        fail("selected artifact is expired")
    if not isinstance(artifact_digest, str) or not SHA256_RE.fullmatch(
        artifact_digest
    ):
        fail("selected artifact digest is invalid")
    if (
        type(artifact_size) is not int
        or artifact_size <= 0
        or artifact_size > 52_428_800
    ):
        fail("selected artifact size is invalid")
    if not isinstance(workflow_run, dict):
        fail("selected artifact workflow ownership is missing")
    if (
        type(workflow_run.get("id")) is not int
        or workflow_run.get("id") != run_id
    ):
        fail("selected artifact belongs to a different workflow run")
    if (
        not isinstance(workflow_run.get("head_sha"), str)
        or workflow_run.get("head_sha") != release_sha
    ):
        fail("selected artifact belongs to a different release")

    return {"metadata": metadata, "producerAttempt": producer_attempt}


def select_run_artifact_command(args: argparse.Namespace) -> None:
    raw = sys.stdin.buffer.read(16_777_217)
    if len(raw) > 16_777_216:
        fail("artifact response exceeds the 16 MiB input limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"artifact response is not strict UTF-8 JSON: {error}")
    selected = select_run_artifact(
        parse_json_text(text, "artifact response"),
        policy=args.policy,
        artifact_prefix=args.artifact_prefix,
        run_id=args.run_id,
        release_sha=args.release_sha,
        maximum_attempt=args.maximum_attempt,
    )
    print(
        json.dumps(
            selected,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        fail(f"refusing to overwrite {path}")
    path.write_text(
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n",
        encoding="utf-8",
    )


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        fail(f"{path} must be a regular file")
    return sha256_bytes(path.read_bytes())


def testing_instructions_digest(notice_path: Path) -> str:
    return sha256_file(notice_path.parent / "docs" / "JUDGE_TESTING.md")


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def canonical_json_text(value: Any) -> str:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def canonical_json_digest(value: Any) -> str:
    return sha256_text(canonical_json_text(value))


def record(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    candidate = record(value, label)
    actual = set(candidate)
    if actual != expected:
        fail(
            f"{label} keys differ: missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )
    return candidate


def exact(value: Any, expected: Any, label: str) -> None:
    if value != expected or type(value) is not type(expected):
        fail(f"{label} must equal {expected!r}")


def nonempty(value: Any, label: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        fail(f"{label} must be a non-empty string of at most {maximum} chars")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        fail(f"{label} contains a control character")
    return value


def positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        fail(f"{label} must be a positive integer")
    return value


def bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        fail(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def sha256_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} must be a lowercase sha256:<64-hex> digest")
    return value


def raw_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or RAW_SHA256_RE.fullmatch(value) is None:
        fail(f"{label} must be a lowercase 64-hex SHA-256")
    return value


def release_sha(value: Any, label: str = "releaseSha") -> str:
    if not isinstance(value, str) or RELEASE_RE.fullmatch(value) is None:
        fail(f"{label} must be a lowercase 40-hex commit")
    return value


def timestamp(value: Any, label: str) -> dt.datetime:
    text = nonempty(value, label, 40)
    if not text.endswith("Z"):
        fail(f"{label} must be canonical UTC with a Z suffix")
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        fail(f"{label} is not an ISO-8601 timestamp: {error}")
    if parsed.tzinfo != dt.timezone.utc:
        fail(f"{label} must be UTC")
    return parsed


def fresh(value: Any, label: str, maximum_age: dt.timedelta) -> dt.datetime:
    observed = timestamp(value, label)
    now = dt.datetime.now(dt.timezone.utc)
    if observed > now + dt.timedelta(minutes=5):
        fail(f"{label} is in the future")
    if now - observed > maximum_age:
        fail(f"{label} is stale (maximum age {maximum_age})")
    return observed


def not_future(value: Any, label: str) -> dt.datetime:
    observed = timestamp(value, label)
    if observed > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        fail(f"{label} is in the future")
    return observed


def public_https_url(
    value: Any, label: str, *, origin_only: bool = False
) -> str:
    text = nonempty(value, label)
    if text != text.strip() or any(character.isspace() for character in text):
        fail(f"{label} must not contain leading, trailing, or embedded whitespace")
    parsed = urlsplit(text)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        fail(f"{label} must be a credential-free HTTPS URL")
    try:
        port = parsed.port
    except ValueError as error:
        fail(f"{label} has an invalid port: {error}")
    if port not in (None, 443):
        fail(f"{label} must use the default HTTPS port")
    if parsed.fragment:
        fail(f"{label} must not contain a fragment")
    if origin_only and (parsed.path not in ("", "/") or parsed.query):
        fail(f"{label} must be an exact HTTPS origin")
    host = parsed.hostname
    if host is None or host.lower() == "localhost" or "." not in host:
        fail(f"{label} must use a public DNS host")
    lower_host = host.lower()
    if host != lower_host or host.endswith(".") or "%" in parsed.netloc:
        fail(f"{label} must use a canonical lowercase DNS host")
    labels = lower_host.split(".")
    if any(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", item) is None
        for item in labels
    ):
        fail(f"{label} contains an invalid DNS label")
    if lower_host.endswith((".example", ".invalid", ".localhost", ".test")):
        fail(f"{label} must not use a reserved test DNS suffix")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        fail(f"{label} must not use a private or non-global IP")
    return text


def canonical_origin(value: str) -> str:
    parsed = urlsplit(value)
    port = f":{parsed.port}" if parsed.port and parsed.port != 443 else ""
    return f"https://{parsed.hostname}{port}"


def safe_relative_name(value: Any, label: str) -> str:
    name = nonempty(value, label, 220)
    if (
        name.startswith("/")
        or "\\" in name
        or "//" in name
        or any(part in ("", ".", "..") for part in name.split("/"))
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", name) is None
    ):
        fail(f"{label} must be a safe canonical relative file name")
    return name


def canonical_workflow_path(value: Any, label: str) -> str:
    path = nonempty(value, label, 220)
    if re.fullmatch(r"\.github/workflows/[a-z0-9][a-z0-9-]*\.yml", path) is None:
        fail(f"{label} must be a canonical GitHub workflow path")
    return path


def strict_video_url(value: Any, label: str) -> str:
    text = public_https_url(value, label)
    parsed = urlsplit(text)
    host = parsed.hostname
    if host == "www.youtube.com":
        if parsed.path != "/watch":
            fail(f"{label} must be an exact YouTube watch URL")
        try:
            query = parse_qs(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
            )
        except ValueError as error:
            fail(f"{label} has an invalid YouTube query: {error}")
        if set(query) != {"v"} or len(query["v"]) != 1:
            fail(f"{label} must contain only one YouTube video ID")
        if re.fullmatch(r"[A-Za-z0-9_-]{11}", query["v"][0]) is None:
            fail(f"{label} contains an invalid YouTube video ID")
    elif host == "vimeo.com":
        if re.fullmatch(r"/[1-9][0-9]{4,14}", parsed.path) is None or parsed.query:
            fail(f"{label} must be an exact Vimeo video URL")
    elif host == "v.youku.com":
        if (
            re.fullmatch(r"/v_show/id_[A-Za-z0-9=_-]{6,96}\.html", parsed.path)
            is None
            or parsed.query
        ):
            fail(f"{label} must be an exact Youku video URL")
    else:
        fail(f"{label} must be hosted on YouTube, Vimeo, or Youku")
    return text


def load_registry(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    registry = exact_keys(
        load_json(path, "registry"),
        {
            "schemaVersion",
            "repository",
            "aggregate",
            "upstreamSchemaVersion",
            "upstreamPredicateSchemaVersion",
            "receiptSchemaVersion",
            "sources",
        },
        "registry",
    )
    exact(registry["schemaVersion"], "archon.submission-evidence-registry/v1", "registry.schemaVersion")
    exact(registry["repository"], REPOSITORY, "registry.repository")
    exact(registry["upstreamSchemaVersion"], UPSTREAM_SCHEMA, "registry.upstreamSchemaVersion")
    exact(
        registry["upstreamPredicateSchemaVersion"],
        UPSTREAM_PREDICATE_SCHEMA,
        "registry.upstreamPredicateSchemaVersion",
    )
    exact(registry["receiptSchemaVersion"], RECEIPT_SCHEMA, "registry.receiptSchemaVersion")
    exact_keys(
        registry["aggregate"],
        {
            "workflowPath",
            "artifactNameTemplate",
            "predicateType",
            "predicateSchemaVersion",
        },
        "registry.aggregate",
    )
    canonical_workflow_path(
        registry["aggregate"]["workflowPath"],
        "registry.aggregate.workflowPath",
    )
    if not isinstance(registry["sources"], list) or not registry["sources"]:
        fail("registry.sources must be a non-empty array")
    sources: dict[str, dict[str, Any]] = {}
    registered_ids: set[str] = set()
    for index, raw_source in enumerate(registry["sources"]):
        label = f"registry.sources[{index}]"
        source = exact_keys(
            raw_source,
            {
                "key",
                "required",
                "mode",
                "workflowPath",
                "artifactNameTemplate",
                "predicateType",
                "predicateSchemaVersion",
                "predicateFile",
                "subjectInventory",
                "proofIds",
                "supportSubjects",
            },
            label,
        )
        key = nonempty(source["key"], f"{label}.key", 64)
        if key in sources:
            fail(f"duplicate source key {key}")
        if type(source["required"]) is not bool:
            fail(f"{label}.required must be boolean")
        if source["mode"] not in {"native-live-v4", "standard-v1"}:
            fail(f"{label}.mode is not registered")
        exact(
            source["predicateSchemaVersion"],
            (
                "archon.live-datahub-proof-attestation/v4"
                if source["mode"] == "native-live-v4"
                else UPSTREAM_PREDICATE_SCHEMA
            ),
            f"{label}.predicateSchemaVersion",
        )
        canonical_workflow_path(source["workflowPath"], f"{label}.workflowPath")
        nonempty(source["artifactNameTemplate"], f"{label}.artifactNameTemplate", 180)
        nonempty(source["predicateType"], f"{label}.predicateType", 240)
        safe_relative_name(source["predicateFile"], f"{label}.predicateFile")
        safe_relative_name(source["subjectInventory"], f"{label}.subjectInventory")
        if not isinstance(source["proofIds"], list) or not source["proofIds"]:
            fail(f"{label}.proofIds must be a non-empty array")
        support_by_proof = record(
            source["supportSubjects"],
            f"{label}.supportSubjects",
        )
        if set(support_by_proof) != set(source["proofIds"]):
            fail(f"{label}.supportSubjects must map every source proof exactly once")
        for proof_id in source["proofIds"]:
            if proof_id not in PROOF_CRITERIA or proof_id in registered_ids:
                fail(f"{label}.proofIds contains unknown or duplicate {proof_id!r}")
            registered_ids.add(proof_id)
            raw_subjects = support_by_proof[proof_id]
            if not isinstance(raw_subjects, list) or not raw_subjects:
                fail(f"{label}.supportSubjects.{proof_id} must be a non-empty array")
            roles: set[str] = set()
            names: set[str] = set()
            for subject_index, raw_subject in enumerate(raw_subjects):
                subject_label = (
                    f"{label}.supportSubjects.{proof_id}[{subject_index}]"
                )
                subject = exact_keys(
                    raw_subject,
                    {"role", "name"},
                    subject_label,
                )
                role = nonempty(subject["role"], f"{subject_label}.role", 64)
                if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", role) is None:
                    fail(f"{subject_label}.role is not canonical")
                name = safe_relative_name(
                    subject["name"],
                    f"{subject_label}.name",
                )
                if role in roles or name in names:
                    fail(f"{subject_label} duplicates a role or file name")
                roles.add(role)
                names.add(name)
                if source["mode"] == "standard-v1":
                    exact(
                        name,
                        f"support/{proof_id}/{role}.json",
                        f"{subject_label}.name",
                    )
                    if (proof_id, role) not in SUPPORT_BINDING_FIELDS:
                        fail(f"{subject_label}.role has no semantic binding contract")
            if source["mode"] == "standard-v1":
                exact(
                    roles,
                    {
                        registered_role
                        for registered_id, registered_role in SUPPORT_BINDING_FIELDS
                        if registered_id == proof_id
                    },
                    f"{label}.supportSubjects.{proof_id} roles",
                )
            if source["mode"] == "native-live-v4":
                expected_native = {
                    "D4": {
                        ("live-proof", "proof.json"),
                        ("deployment-evidence", "deployment-evidence.json"),
                    },
                    "U3": {
                        ("live-proof", "proof.json"),
                        (
                            "deployed-semantic-proof",
                            "deployed-datahub-semantic-proof.json",
                        ),
                    },
                }
                exact(
                    {(item["role"], item["name"]) for item in raw_subjects},
                    expected_native[proof_id],
                    f"{label}.supportSubjects.{proof_id}",
                )
        exact(
            source["required"],
            any(proof_id in REQUIRED_PROOFS for proof_id in source["proofIds"]),
            f"{label}.required",
        )
        sources[key] = source
    if registered_ids != set(PROOF_CRITERIA):
        fail("registry must map every and only registered proof ID exactly once")
    return registry, sources


def source_for_proof(
    proof_id: str, sources: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    matches = [source for source in sources.values() if proof_id in source["proofIds"]]
    if len(matches) != 1:
        fail(f"{proof_id} must map to exactly one source")
    return matches[0]


def artifact_name(source: dict[str, Any], release: str, attempt: int) -> str:
    template = nonempty(source["artifactNameTemplate"], "artifactNameTemplate", 180)
    name = template.replace("{releaseSha}", release).replace(
        "{runAttempt}", str(attempt)
    )
    if "{" in name or "}" in name:
        fail("artifactNameTemplate contains an unsupported token")
    return name


def validate_deployment_binding(value: Any, label: str, release: str) -> None:
    deployment = exact_keys(
        value,
        {
            "workflowPath",
            "runId",
            "runAttempt",
            "artifactId",
            "artifactName",
            "artifactDigest",
            "predicateType",
            "predicateDigest",
        },
        label,
    )
    exact(deployment["workflowPath"], ".github/workflows/deploy.yml", f"{label}.workflowPath")
    run_id = positive_int(deployment["runId"], f"{label}.runId")
    attempt = positive_int(deployment["runAttempt"], f"{label}.runAttempt")
    positive_int(deployment["artifactId"], f"{label}.artifactId")
    exact(
        deployment["artifactName"],
        f"deployment-evidence-production-{release}-{run_id}",
        f"{label}.artifactName",
    )
    sha256_digest(deployment["artifactDigest"], f"{label}.artifactDigest")
    exact(
        deployment["predicateType"],
        "https://github.com/upgradedev/archon-datahub/attestations/aws-deployment/v2",
        f"{label}.predicateType",
    )
    sha256_digest(deployment["predicateDigest"], f"{label}.predicateDigest")
    if run_id == deployment["artifactId"]:
        fail(f"{label} run and artifact IDs must be independently bound values")


def validate_exact_provenance_binding(
    value: Any,
    label: str,
    release: str,
    *,
    workflow_path: str,
    artifact_name_template: str,
    predicate_type: str,
    extra_fields: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    binding = exact_keys(
        value,
        {
            "workflowPath",
            "runId",
            "runAttempt",
            "artifactId",
            "artifactName",
            "artifactDigest",
            "predicateType",
            "predicateDigest",
        }
        | extra_fields,
        label,
    )
    exact(binding["workflowPath"], workflow_path, f"{label}.workflowPath")
    run_id = positive_int(binding["runId"], f"{label}.runId")
    run_attempt = positive_int(binding["runAttempt"], f"{label}.runAttempt")
    artifact_id = positive_int(binding["artifactId"], f"{label}.artifactId")
    exact(
        binding["artifactName"],
        artifact_name_template.format(
            releaseSha=release,
            runId=run_id,
            runAttempt=run_attempt,
        ),
        f"{label}.artifactName",
    )
    sha256_digest(binding["artifactDigest"], f"{label}.artifactDigest")
    exact(binding["predicateType"], predicate_type, f"{label}.predicateType")
    sha256_digest(binding["predicateDigest"], f"{label}.predicateDigest")
    if run_id == artifact_id:
        fail(f"{label} run and artifact IDs must be independently bound values")
    return binding


def validate_facts(
    proof_id: str,
    value: Any,
    release: str,
    *,
    notice_path: Path | None = None,
) -> None:
    label = f"{proof_id}.facts"
    facts = record(value, label)

    if proof_id == "D4":
        exact_keys(
            facts,
            {
                "applicationUrl",
                "evidenceClass",
                "liveDataHubRead",
                "retainedHistoryRead",
                "stableSourceCount",
                "recoveredContradictions",
                "governedWrite",
                "provenAt",
            },
            label,
        )
        public_https_url(
            facts["applicationUrl"],
            f"{label}.applicationUrl",
            origin_only=True,
        )
        exact(facts["evidenceClass"], "LIVE_DEPLOYED_DATAHUB", f"{label}.evidenceClass")
        exact(facts["liveDataHubRead"], True, f"{label}.liveDataHubRead")
        exact(facts["retainedHistoryRead"], True, f"{label}.retainedHistoryRead")
        if positive_int(facts["stableSourceCount"], f"{label}.stableSourceCount") < 2:
            fail(f"{label}.stableSourceCount must be at least two")
        positive_int(facts["recoveredContradictions"], f"{label}.recoveredContradictions")
        governed = exact_keys(
            facts["governedWrite"],
            {
                "workflowRunId",
                "result",
                "rollbackSubjectDigest",
                "rollbackEvidenceDigest",
                "attestationPredicateDigest",
                "attestationVerificationDigest",
            },
            f"{label}.governedWrite",
        )
        positive_int(governed["workflowRunId"], f"{label}.governedWrite.workflowRunId")
        exact(
            governed["result"],
            "write-verified-and-rollback-proven",
            f"{label}.governedWrite.result",
        )
        for key in (
            "rollbackSubjectDigest",
            "rollbackEvidenceDigest",
            "attestationPredicateDigest",
            "attestationVerificationDigest",
        ):
            sha256_digest(governed[key], f"{label}.governedWrite.{key}")
        fresh(facts["provenAt"], f"{label}.provenAt", dt.timedelta(days=7))
        return

    if proof_id == "U3":
        exact_keys(
            facts,
            {
                "evidenceClass",
                "datasetUrnDigest",
                "classification",
                "findings",
                "provenAt",
            },
            label,
        )
        exact(facts["evidenceClass"], "LIVE_DEPLOYED_DATAHUB", f"{label}.evidenceClass")
        sha256_digest(facts["datasetUrnDigest"], f"{label}.datasetUrnDigest")
        classification = exact_keys(
            facts["classification"],
            {"totalEntities", "withLineage", "sensitiveEntities"},
            f"{label}.classification",
        )
        exact(classification, {"totalEntities": 1, "withLineage": 1, "sensitiveEntities": 1}, f"{label}.classification")
        findings = exact_keys(
            facts["findings"],
            {"totalCount", "g6", "danglingLineage", "retainedHistory"},
            f"{label}.findings",
        )
        exact(findings["totalCount"], 3, f"{label}.findings.totalCount")
        g6 = exact_keys(
            findings["g6"],
            {
                "exactTarget",
                "fieldPath",
                "classificationAbsent",
                "blastRootBound",
                "downstreamCount",
                "maxHops",
                "truncated",
                "impact",
            },
            f"{label}.findings.g6",
        )
        exact(g6["exactTarget"], True, f"{label}.findings.g6.exactTarget")
        exact(g6["fieldPath"], "email", f"{label}.findings.g6.fieldPath")
        exact(g6["classificationAbsent"], True, f"{label}.findings.g6.classificationAbsent")
        exact(g6["blastRootBound"], True, f"{label}.findings.g6.blastRootBound")
        exact(g6["downstreamCount"], 0, f"{label}.findings.g6.downstreamCount")
        exact(g6["maxHops"], 3, f"{label}.findings.g6.maxHops")
        exact(g6["truncated"], False, f"{label}.findings.g6.truncated")
        exact(g6["impact"], "none", f"{label}.findings.g6.impact")
        gap = exact_keys(
            findings["danglingLineage"],
            {
                "exactUpstream",
                "upstreamAbsent",
                "blastRootBound",
                "targetConsumerMinHops",
                "downstreamCount",
                "maxHops",
                "truncated",
                "impact",
            },
            f"{label}.findings.danglingLineage",
        )
        exact(gap["exactUpstream"], True, f"{label}.findings.danglingLineage.exactUpstream")
        exact(gap["upstreamAbsent"], True, f"{label}.findings.danglingLineage.upstreamAbsent")
        exact(gap["blastRootBound"], True, f"{label}.findings.danglingLineage.blastRootBound")
        exact(gap["targetConsumerMinHops"], 1, f"{label}.findings.danglingLineage.targetConsumerMinHops")
        exact(gap["downstreamCount"], 1, f"{label}.findings.danglingLineage.downstreamCount")
        exact(gap["maxHops"], 3, f"{label}.findings.danglingLineage.maxHops")
        exact(gap["truncated"], False, f"{label}.findings.danglingLineage.truncated")
        exact(gap["impact"], "low", f"{label}.findings.danglingLineage.impact")
        retained = exact_keys(
            findings["retainedHistory"],
            {
                "exactTarget",
                "attribute",
                "provenanceCount",
                "stableSourceCount",
                "statuses",
                "retainedOwnershipHistorySha256",
            },
            f"{label}.findings.retainedHistory",
        )
        exact(retained["exactTarget"], True, f"{label}.findings.retainedHistory.exactTarget")
        exact(retained["attribute"], "owner", f"{label}.findings.retainedHistory.attribute")
        exact(retained["provenanceCount"], 2, f"{label}.findings.retainedHistory.provenanceCount")
        exact(retained["stableSourceCount"], 2, f"{label}.findings.retainedHistory.stableSourceCount")
        exact(retained["statuses"], ["conflicting", "trusted"], f"{label}.findings.retainedHistory.statuses")
        raw_sha256(
            retained["retainedOwnershipHistorySha256"],
            f"{label}.findings.retainedHistory.retainedOwnershipHistorySha256",
        )
        fresh(facts["provenAt"], f"{label}.provenAt", dt.timedelta(days=7))
        return

    if proof_id == "SQ3":
        exact_keys(
            facts,
            {
                "applicationUrl",
                "applicationOriginDigest",
                "deployment",
                "observation",
            },
            label,
        )
        application_url = public_https_url(
            facts["applicationUrl"], f"{label}.applicationUrl", origin_only=True
        )
        exact(
            facts["applicationOriginDigest"],
            sha256_text(canonical_origin(application_url)),
            f"{label}.applicationOriginDigest",
        )
        validate_deployment_binding(facts["deployment"], f"{label}.deployment", release)
        observation = exact_keys(
            facts["observation"],
            {
                "observedAt",
                "availabilityObservedAt",
                "loggedOutAccessible",
                "httpStatus",
                "redirectsObserved",
                "strictTls",
                "releaseMatched",
                "availabilityRunId",
                "availabilityRunAttempt",
                "availabilityArtifactId",
                "availabilityArtifactName",
                "availabilityArtifactDigest",
                "availabilityPredicateType",
                "availabilityPredicateDigest",
            },
            f"{label}.observation",
        )
        public_observed_at = fresh(
            observation["observedAt"],
            f"{label}.observation.observedAt",
            dt.timedelta(hours=7),
        )
        availability_observed_at = fresh(
            observation["availabilityObservedAt"],
            f"{label}.observation.availabilityObservedAt",
            dt.timedelta(hours=7),
        )
        if availability_observed_at > public_observed_at:
            fail(
                f"{label}.observation.availabilityObservedAt must not "
                "follow the public probe"
            )
        exact(observation["loggedOutAccessible"], True, f"{label}.observation.loggedOutAccessible")
        exact(observation["httpStatus"], 200, f"{label}.observation.httpStatus")
        exact(observation["redirectsObserved"], 0, f"{label}.observation.redirectsObserved")
        exact(observation["strictTls"], True, f"{label}.observation.strictTls")
        exact(observation["releaseMatched"], True, f"{label}.observation.releaseMatched")
        positive_int(observation["availabilityRunId"], f"{label}.observation.availabilityRunId")
        availability_attempt = positive_int(
            observation["availabilityRunAttempt"],
            f"{label}.observation.availabilityRunAttempt",
        )
        positive_int(
            observation["availabilityArtifactId"],
            f"{label}.observation.availabilityArtifactId",
        )
        exact(
            observation["availabilityArtifactName"],
            f"production-availability-{release}-{observation['availabilityRunId']}",
            f"{label}.observation.availabilityArtifactName",
        )
        sha256_digest(
            observation["availabilityArtifactDigest"],
            f"{label}.observation.availabilityArtifactDigest",
        )
        exact(
            observation["availabilityPredicateType"],
            "https://github.com/upgradedev/archon-datahub/attestations/production-availability/v2",
            f"{label}.observation.availabilityPredicateType",
        )
        sha256_digest(
            observation["availabilityPredicateDigest"],
            f"{label}.observation.availabilityPredicateDigest",
        )
        return

    if proof_id == "SQ4":
        exact_keys(
            facts,
            {
                "applicationUrl",
                "authenticationRequired",
                "accessMode",
                "deployment",
                "judgeUserLifecycle",
                "freshJudgeJourney",
                "testingInstructionsPath",
                "testingInstructionsDigest",
                "credentialRotation",
                "freeAccess",
                "accessValidThrough",
                "observedAt",
            },
            label,
        )
        application_url = public_https_url(
            facts["applicationUrl"],
            f"{label}.applicationUrl",
            origin_only=True,
        )
        application_origin_sha256 = sha256_text(
            canonical_origin(application_url)
        ).removeprefix("sha256:")
        if type(facts["authenticationRequired"]) is not bool:
            fail(f"{label}.authenticationRequired must be boolean")
        auth_required = facts["authenticationRequired"]
        exact(
            facts["accessMode"],
            "pipeline-managed-confirmed" if auth_required else "public-no-authentication",
            f"{label}.accessMode",
        )
        validate_deployment_binding(facts["deployment"], f"{label}.deployment", release)
        lifecycle = exact_keys(
            facts["judgeUserLifecycle"],
            {
                "releaseSha",
                "stage",
                "identityDigest",
                "cognitoSubjectDigest",
                "applicationOriginSha256",
                "chainDigest",
                "operations",
                "sanitized",
                "secretMaterialRetained",
            },
            f"{label}.judgeUserLifecycle",
        )
        exact(
            lifecycle["releaseSha"],
            release,
            f"{label}.judgeUserLifecycle.releaseSha",
        )
        exact(
            lifecycle["stage"],
            "production",
            f"{label}.judgeUserLifecycle.stage",
        )
        identity_digest = sha256_digest(
            lifecycle["identityDigest"],
            f"{label}.judgeUserLifecycle.identityDigest",
        )
        cognito_subject_digest = sha256_digest(
            lifecycle["cognitoSubjectDigest"],
            f"{label}.judgeUserLifecycle.cognitoSubjectDigest",
        )
        exact(
            raw_sha256(
                lifecycle["applicationOriginSha256"],
                f"{label}.judgeUserLifecycle.applicationOriginSha256",
            ),
            application_origin_sha256,
            f"{label}.judgeUserLifecycle.applicationOriginSha256",
        )
        chain_digest = sha256_digest(
            lifecycle["chainDigest"],
            f"{label}.judgeUserLifecycle.chainDigest",
        )
        if not isinstance(lifecycle["operations"], list):
            fail(f"{label}.judgeUserLifecycle.operations must be an array")
        exact(
            len(lifecycle["operations"]),
            4,
            f"{label}.judgeUserLifecycle.operations length",
        )
        expected_operations = (
            ("provision", "provisioned-and-readback-verified"),
            ("rotate", "rotated-and-readback-verified"),
            ("deactivate", "deactivated-and-readback-verified"),
            ("reactivate", "reactivated-and-readback-verified"),
        )
        previous_time: dt.datetime | None = None
        run_ids: set[int] = set()
        artifact_ids: set[int] = set()
        for index, ((operation, result), raw_operation) in enumerate(
            zip(expected_operations, lifecycle["operations"], strict=True)
        ):
            operation_label = (
                f"{label}.judgeUserLifecycle.operations[{index}]"
            )
            operation_receipt = exact_keys(
                raw_operation,
                {
                    "operation",
                    "workflowPath",
                    "stage",
                    "runId",
                    "runAttempt",
                    "artifactId",
                    "artifactName",
                    "artifactDigest",
                    "predicateType",
                    "predicateDigest",
                    "verificationDigest",
                    "releaseSha",
                    "identityDigest",
                    "cognitoSubjectDigest",
                    "applicationOriginSha256",
                    "operationReceiptDigest",
                    "performedAt",
                    "result",
                    "sanitized",
                    "secretMaterialRetained",
                },
                operation_label,
            )
            exact(
                operation_receipt["operation"],
                operation,
                f"{operation_label}.operation",
            )
            exact(
                operation_receipt["workflowPath"],
                ".github/workflows/judge-user.yml",
                f"{operation_label}.workflowPath",
            )
            exact(
                operation_receipt["stage"],
                lifecycle["stage"],
                f"{operation_label}.stage",
            )
            run_id = positive_int(
                operation_receipt["runId"],
                f"{operation_label}.runId",
            )
            run_attempt = positive_int(
                operation_receipt["runAttempt"],
                f"{operation_label}.runAttempt",
            )
            artifact_id = positive_int(
                operation_receipt["artifactId"],
                f"{operation_label}.artifactId",
            )
            if run_id in run_ids or artifact_id in artifact_ids:
                fail(f"{operation_label} must bind unique run and artifact IDs")
            run_ids.add(run_id)
            artifact_ids.add(artifact_id)
            exact(
                operation_receipt["artifactName"],
                f"judge-user-operation-{operation}-{release}-{run_attempt}",
                f"{operation_label}.artifactName",
            )
            for key in (
                "artifactDigest",
                "predicateDigest",
                "verificationDigest",
                "operationReceiptDigest",
            ):
                sha256_digest(
                    operation_receipt[key],
                    f"{operation_label}.{key}",
                )
            exact(
                operation_receipt["predicateType"],
                "https://github.com/upgradedev/archon-datahub/attestations/judge-user-operation/v1",
                f"{operation_label}.predicateType",
            )
            exact(
                operation_receipt["releaseSha"],
                release,
                f"{operation_label}.releaseSha",
            )
            exact(
                operation_receipt["identityDigest"],
                identity_digest,
                f"{operation_label}.identityDigest",
            )
            exact(
                operation_receipt["cognitoSubjectDigest"],
                cognito_subject_digest,
                f"{operation_label}.cognitoSubjectDigest",
            )
            exact(
                raw_sha256(
                    operation_receipt["applicationOriginSha256"],
                    f"{operation_label}.applicationOriginSha256",
                ),
                lifecycle["applicationOriginSha256"],
                f"{operation_label}.applicationOriginSha256",
            )
            performed_at = fresh(
                operation_receipt["performedAt"],
                f"{operation_label}.performedAt",
                dt.timedelta(days=7),
            )
            if previous_time is not None and performed_at <= previous_time:
                fail(f"{operation_label}.performedAt must be strictly ordered")
            previous_time = performed_at
            exact(
                operation_receipt["result"],
                result,
                f"{operation_label}.result",
            )
            exact(
                operation_receipt["sanitized"],
                True,
                f"{operation_label}.sanitized",
            )
            exact(
                operation_receipt["secretMaterialRetained"],
                False,
                f"{operation_label}.secretMaterialRetained",
            )
        exact(
            chain_digest,
            canonical_json_digest(lifecycle["operations"]),
            f"{label}.judgeUserLifecycle.chainDigest",
        )
        exact(
            lifecycle["sanitized"],
            True,
            f"{label}.judgeUserLifecycle.sanitized",
        )
        exact(
            lifecycle["secretMaterialRetained"],
            False,
            f"{label}.judgeUserLifecycle.secretMaterialRetained",
        )
        journey = exact_keys(
            facts["freshJudgeJourney"],
            {
                "workflowPath",
                "stage",
                "runId",
                "runAttempt",
                "artifactId",
                "artifactName",
                "artifactDigest",
                "predicateType",
                "predicateDigest",
                "verificationDigest",
                "releaseSha",
                "identityDigest",
                "cognitoSubjectDigest",
                "applicationOriginSha256",
                "journeyStartedAt",
                "journeyCompletedAt",
                "identityIsFresh",
                "loginSucceeded",
                "startSucceeded",
                "statusPollingSucceeded",
                "terminalReceiptVerified",
                "logoutIsolationVerified",
                "terminalReceiptDigest",
                "sanitized",
                "secretMaterialRetained",
            },
            f"{label}.freshJudgeJourney",
        )
        exact(
            journey["workflowPath"],
            ".github/workflows/submission-judge-journey.yml",
            f"{label}.freshJudgeJourney.workflowPath",
        )
        exact(
            journey["stage"],
            lifecycle["stage"],
            f"{label}.freshJudgeJourney.stage",
        )
        positive_int(journey["runId"], f"{label}.freshJudgeJourney.runId")
        journey_attempt = positive_int(
            journey["runAttempt"],
            f"{label}.freshJudgeJourney.runAttempt",
        )
        positive_int(
            journey["artifactId"],
            f"{label}.freshJudgeJourney.artifactId",
        )
        exact(
            journey["artifactName"],
            f"submission-judge-journey-{release}-{journey_attempt}",
            f"{label}.freshJudgeJourney.artifactName",
        )
        for key in (
            "artifactDigest",
            "predicateDigest",
            "verificationDigest",
            "terminalReceiptDigest",
        ):
            sha256_digest(journey[key], f"{label}.freshJudgeJourney.{key}")
        exact(
            journey["predicateType"],
            "https://archon.datahub.dev/attestations/submission-judge-journey/v1",
            f"{label}.freshJudgeJourney.predicateType",
        )
        exact(
            journey["releaseSha"],
            release,
            f"{label}.freshJudgeJourney.releaseSha",
        )
        exact(
            journey["identityDigest"],
            identity_digest,
            f"{label}.freshJudgeJourney.identityDigest",
        )
        exact(
            journey["cognitoSubjectDigest"],
            cognito_subject_digest,
            f"{label}.freshJudgeJourney.cognitoSubjectDigest",
        )
        exact(
            raw_sha256(
                journey["applicationOriginSha256"],
                f"{label}.freshJudgeJourney.applicationOriginSha256",
            ),
            lifecycle["applicationOriginSha256"],
            f"{label}.freshJudgeJourney.applicationOriginSha256",
        )
        journey_started = fresh(
            journey["journeyStartedAt"],
            f"{label}.freshJudgeJourney.journeyStartedAt",
            dt.timedelta(hours=24),
        )
        journey_completed = fresh(
            journey["journeyCompletedAt"],
            f"{label}.freshJudgeJourney.journeyCompletedAt",
            dt.timedelta(hours=24),
        )
        if previous_time is not None and journey_started <= previous_time:
            fail(f"{label}.freshJudgeJourney must start after reactivation")
        if journey_completed < journey_started:
            fail(f"{label}.freshJudgeJourney completion precedes its start")
        for key, expected in {
            "identityIsFresh": True,
            "loginSucceeded": True,
            "startSucceeded": True,
            "statusPollingSucceeded": True,
            "terminalReceiptVerified": True,
            "logoutIsolationVerified": True,
        }.items():
            exact(journey[key], expected, f"{label}.freshJudgeJourney.{key}")
        exact(
            journey["sanitized"],
            True,
            f"{label}.freshJudgeJourney.sanitized",
        )
        exact(
            journey["secretMaterialRetained"],
            False,
            f"{label}.freshJudgeJourney.secretMaterialRetained",
        )
        exact(
            facts["testingInstructionsPath"],
            "docs/JUDGE_TESTING.md",
            f"{label}.testingInstructionsPath",
        )
        sha256_digest(facts["testingInstructionsDigest"], f"{label}.testingInstructionsDigest")
        if notice_path is not None:
            exact(
                facts["testingInstructionsDigest"],
                testing_instructions_digest(notice_path),
                f"{label}.testingInstructionsDigest",
            )
        rotation = exact_keys(
            facts["credentialRotation"],
            {
                "pipelineManagedConfirmed",
                "secretMaterialRetained",
                "rotationTested",
                "recoveryTested",
            },
            f"{label}.credentialRotation",
        )
        exact(
            rotation["pipelineManagedConfirmed"],
            auth_required,
            f"{label}.credentialRotation.pipelineManagedConfirmed",
        )
        exact(rotation["secretMaterialRetained"], False, f"{label}.credentialRotation.secretMaterialRetained")
        exact(rotation["rotationTested"], auth_required, f"{label}.credentialRotation.rotationTested")
        exact(rotation["recoveryTested"], True, f"{label}.credentialRotation.recoveryTested")
        exact(facts["freeAccess"], True, f"{label}.freeAccess")
        if timestamp(facts["accessValidThrough"], f"{label}.accessValidThrough") < JUDGING_END:
            fail(f"{label}.accessValidThrough ends before the judging window")
        observed_at = fresh(
            facts["observedAt"],
            f"{label}.observedAt",
            dt.timedelta(hours=24),
        )
        if observed_at < journey_completed:
            fail(f"{label}.observedAt must follow the fresh journey receipt")
        return

    if proof_id == "SQ5":
        exact_keys(
            facts,
            {
                "repositoryUrl",
                "releaseUrl",
                "licenseUrl",
                "defaultBranch",
                "releaseVisible",
                "loggedOutAccessible",
                "completeSource",
                "licenseSpdx",
                "hostingUiDetectedLicense",
                "observedAt",
            },
            label,
        )
        exact(
            facts["repositoryUrl"],
            "https://github.com/upgradedev/archon-datahub",
            f"{label}.repositoryUrl",
        )
        exact(
            facts["releaseUrl"],
            f"https://github.com/upgradedev/archon-datahub/tree/{release}",
            f"{label}.releaseUrl",
        )
        exact(
            facts["licenseUrl"],
            f"https://github.com/upgradedev/archon-datahub/blob/{release}/LICENSE",
            f"{label}.licenseUrl",
        )
        exact(facts["defaultBranch"], "master", f"{label}.defaultBranch")
        for key in (
            "releaseVisible",
            "loggedOutAccessible",
            "completeSource",
            "hostingUiDetectedLicense",
        ):
            exact(facts[key], True, f"{label}.{key}")
        exact(facts["licenseSpdx"], "Apache-2.0", f"{label}.licenseSpdx")
        fresh(facts["observedAt"], f"{label}.observedAt", dt.timedelta(hours=24))
        return

    if proof_id == "SQ6":
        exact_keys(
            facts,
            {
                "allWrittenFieldsComplete",
                "submissionLanguage",
                "testingInstructionsLanguage",
                "completeEnglishTranslation",
                "submissionFieldsDigest",
                "testingInstructionsPath",
                "testingInstructionsDigest",
                "claimsDigest",
                "reviewedAt",
            },
            label,
        )
        exact(facts["allWrittenFieldsComplete"], True, f"{label}.allWrittenFieldsComplete")
        exact(facts["submissionLanguage"], "en", f"{label}.submissionLanguage")
        exact(facts["testingInstructionsLanguage"], "en", f"{label}.testingInstructionsLanguage")
        exact(facts["completeEnglishTranslation"], True, f"{label}.completeEnglishTranslation")
        exact(
            facts["testingInstructionsPath"],
            "docs/JUDGE_TESTING.md",
            f"{label}.testingInstructionsPath",
        )
        for key in ("submissionFieldsDigest", "testingInstructionsDigest", "claimsDigest"):
            sha256_digest(facts[key], f"{label}.{key}")
        if notice_path is not None:
            exact(
                facts["testingInstructionsDigest"],
                testing_instructions_digest(notice_path),
                f"{label}.testingInstructionsDigest",
            )
        fresh(facts["reviewedAt"], f"{label}.reviewedAt", dt.timedelta(days=7))
        return

    if proof_id == "SQ7":
        exact_keys(
            facts,
            {
                "videoUrl",
                "publiclyAccessible",
                "loggedOutAccessible",
                "durationSeconds",
                "providerResponseDigests",
                "spokenLanguage",
                "subtitlesLanguage",
                "completeEnglishTranslation",
                "functioningProjectShown",
                "thirdPartyMarksAndMusicAuthorized",
                "allThirdPartyMaterialAuthorized",
                "mediaReviewDigest",
                "shownApplicationUrl",
                "claimsDigest",
                "reviewedAt",
            },
            label,
        )
        strict_video_url(facts["videoUrl"], f"{label}.videoUrl")
        exact(facts["publiclyAccessible"], True, f"{label}.publiclyAccessible")
        exact(facts["loggedOutAccessible"], True, f"{label}.loggedOutAccessible")
        bounded_int(facts["durationSeconds"], f"{label}.durationSeconds", 1, 179)
        response_digests = exact_keys(
            facts["providerResponseDigests"],
            {"preparedResponseDigest", "reviewResponseDigest"},
            f"{label}.providerResponseDigests",
        )
        sha256_digest(
            response_digests["preparedResponseDigest"],
            f"{label}.providerResponseDigests.preparedResponseDigest",
        )
        sha256_digest(
            response_digests["reviewResponseDigest"],
            f"{label}.providerResponseDigests.reviewResponseDigest",
        )
        spoken = nonempty(facts["spokenLanguage"], f"{label}.spokenLanguage", 12)
        subtitles = nonempty(facts["subtitlesLanguage"], f"{label}.subtitlesLanguage", 12)
        if spoken != "none" and LANGUAGE_RE.fullmatch(spoken) is None:
            fail(f"{label}.spokenLanguage is invalid")
        if subtitles != "none" and LANGUAGE_RE.fullmatch(subtitles) is None:
            fail(f"{label}.subtitlesLanguage is invalid")
        exact(facts["completeEnglishTranslation"], True, f"{label}.completeEnglishTranslation")
        if spoken != "en" and subtitles != "en":
            fail(f"{label} must provide English narration or subtitles")
        exact(facts["functioningProjectShown"], True, f"{label}.functioningProjectShown")
        exact(
            facts["thirdPartyMarksAndMusicAuthorized"],
            True,
            f"{label}.thirdPartyMarksAndMusicAuthorized",
        )
        exact(
            facts["allThirdPartyMaterialAuthorized"],
            True,
            f"{label}.allThirdPartyMaterialAuthorized",
        )
        sha256_digest(facts["mediaReviewDigest"], f"{label}.mediaReviewDigest")
        public_https_url(
            facts["shownApplicationUrl"],
            f"{label}.shownApplicationUrl",
            origin_only=True,
        )
        sha256_digest(facts["claimsDigest"], f"{label}.claimsDigest")
        fresh(facts["reviewedAt"], f"{label}.reviewedAt", dt.timedelta(days=7))
        return

    if proof_id == "SQ8":
        exact_keys(
            facts,
            {
                "rules",
                "projectHistory",
                "reviewedSurfaces",
                "noticeDigest",
                "repositoryHistoryDigest",
                "submissionFieldsDigest",
                "testingInstructionsDigest",
                "submissionClaimsDigest",
                "videoClaimsDigest",
                "preExistingWorkInventoryDigest",
                "thirdPartyInventoryDigest",
                "disclosureSetDigest",
                "allNonStandardPreExistingWorkDisclosed",
                "workDescribedAndSubmittedBuiltDuringPeriod",
                "standardToolsOnlyExcludedFromDisclosure",
                "thirdPartyIntegrationsAuthorized",
                "originalWorkOwnershipReviewed",
                "crossMediumConsistent",
                "reviewApproval",
                "finalizedAt",
                "reviewedAt",
            },
            label,
        )
        rules = exact_keys(
            facts["rules"],
            {
                "officialRulesUrl",
                "snapshotDigest",
                "submissionStart",
                "submissionEnd",
            },
            f"{label}.rules",
        )
        exact(
            rules["officialRulesUrl"],
            "https://datahub.devpost.com/rules",
            f"{label}.rules.officialRulesUrl",
        )
        sha256_digest(rules["snapshotDigest"], f"{label}.rules.snapshotDigest")
        exact(
            rules["submissionStart"],
            "2026-07-06T13:00:00Z",
            f"{label}.rules.submissionStart",
        )
        exact(
            rules["submissionEnd"],
            "2026-08-10T21:00:00Z",
            f"{label}.rules.submissionEnd",
        )
        history = exact_keys(
            facts["projectHistory"],
            {
                "projectStartedAt",
                "repositoryCreatedAt",
                "rootCommitSha",
                "rootCommitAuthoredAt",
                "rootCommitCommittedAt",
                "rootCommitParentCount",
                "releaseCommitSha",
                "releaseCommitCommittedAt",
                "reachableCommitCount",
                "allReachableCommitsWithinSubmissionPeriod",
                "historyDigest",
            },
            f"{label}.projectHistory",
        )
        project_started = timestamp(
            history["projectStartedAt"],
            f"{label}.projectHistory.projectStartedAt",
        )
        repository_created = timestamp(
            history["repositoryCreatedAt"],
            f"{label}.projectHistory.repositoryCreatedAt",
        )
        root_authored = timestamp(
            history["rootCommitAuthoredAt"],
            f"{label}.projectHistory.rootCommitAuthoredAt",
        )
        root_committed = timestamp(
            history["rootCommitCommittedAt"],
            f"{label}.projectHistory.rootCommitCommittedAt",
        )
        release_committed = timestamp(
            history["releaseCommitCommittedAt"],
            f"{label}.projectHistory.releaseCommitCommittedAt",
        )
        for time_label, observed in {
            "projectStartedAt": project_started,
            "repositoryCreatedAt": repository_created,
            "rootCommitAuthoredAt": root_authored,
            "rootCommitCommittedAt": root_committed,
            "releaseCommitCommittedAt": release_committed,
        }.items():
            if not SUBMISSION_START <= observed <= SUBMISSION_DEADLINE:
                fail(
                    f"{label}.projectHistory.{time_label} is outside the "
                    "official submission period"
                )
            if observed > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
                fail(f"{label}.projectHistory.{time_label} is in the future")
        exact(
            history["projectStartedAt"],
            history["rootCommitAuthoredAt"],
            f"{label}.projectHistory.projectStartedAt",
        )
        release_sha(history["rootCommitSha"], f"{label}.projectHistory.rootCommitSha")
        exact(
            history["rootCommitParentCount"],
            0,
            f"{label}.projectHistory.rootCommitParentCount",
        )
        exact(
            history["releaseCommitSha"],
            release,
            f"{label}.projectHistory.releaseCommitSha",
        )
        positive_int(
            history["reachableCommitCount"],
            f"{label}.projectHistory.reachableCommitCount",
        )
        exact(
            history["allReachableCommitsWithinSubmissionPeriod"],
            True,
            f"{label}.projectHistory.allReachableCommitsWithinSubmissionPeriod",
        )
        history_digest = sha256_digest(
            history["historyDigest"],
            f"{label}.projectHistory.historyDigest",
        )
        exact(
            facts["reviewedSurfaces"],
            [
                "NOTICE.md",
                "repository-history",
                "submission-fields",
                "testing-instructions",
                "video",
            ],
            f"{label}.reviewedSurfaces",
        )
        for key in (
            "noticeDigest",
            "repositoryHistoryDigest",
            "submissionFieldsDigest",
            "testingInstructionsDigest",
            "submissionClaimsDigest",
            "videoClaimsDigest",
            "preExistingWorkInventoryDigest",
            "thirdPartyInventoryDigest",
            "disclosureSetDigest",
        ):
            sha256_digest(facts[key], f"{label}.{key}")
        exact(
            facts["repositoryHistoryDigest"],
            history_digest,
            f"{label}.repositoryHistoryDigest",
        )
        if notice_path is not None:
            exact(
                facts["noticeDigest"],
                sha256_file(notice_path),
                f"{label}.noticeDigest",
            )
            exact(
                facts["testingInstructionsDigest"],
                testing_instructions_digest(notice_path),
                f"{label}.testingInstructionsDigest",
            )
        exact(
            facts["disclosureSetDigest"],
            canonical_json_digest(
                {
                    "noticeDigest": facts["noticeDigest"],
                    "preExistingWorkInventoryDigest": facts[
                        "preExistingWorkInventoryDigest"
                    ],
                    "thirdPartyInventoryDigest": facts["thirdPartyInventoryDigest"],
                }
            ),
            f"{label}.disclosureSetDigest",
        )
        for key in (
            "allNonStandardPreExistingWorkDisclosed",
            "workDescribedAndSubmittedBuiltDuringPeriod",
            "standardToolsOnlyExcludedFromDisclosure",
            "thirdPartyIntegrationsAuthorized",
            "originalWorkOwnershipReviewed",
            "crossMediumConsistent",
        ):
            exact(facts[key], True, f"{label}.{key}")
        approval = exact_keys(
            facts["reviewApproval"],
            {
                "approvalMode",
                "environment",
                "workflowPath",
                "runId",
                "runAttempt",
                "environmentId",
                "workflowActorId",
                "triggeringActorId",
                "reviewerId",
                "candidateRunAttempt",
                "candidateArtifactId",
                "candidateArtifactDigest",
                "candidateDigest",
                "approvalCommentDigest",
                "approvalReceiptDigest",
            },
            f"{label}.reviewApproval",
        )
        exact(
            approval["approvalMode"],
            "solo-owner",
            f"{label}.reviewApproval.approvalMode",
        )
        exact(
            approval["environment"],
            "submission-content-review",
            f"{label}.reviewApproval.environment",
        )
        exact(
            approval["workflowPath"],
            ".github/workflows/submission-content-review.yml",
            f"{label}.reviewApproval.workflowPath",
        )
        positive_int(
            approval["runId"],
            f"{label}.reviewApproval.runId",
        )
        review_attempt = positive_int(
            approval["runAttempt"],
            f"{label}.reviewApproval.runAttempt",
        )
        positive_int(
            approval["environmentId"],
            f"{label}.reviewApproval.environmentId",
        )
        actor_id = positive_int(
            approval["workflowActorId"],
            f"{label}.reviewApproval.workflowActorId",
        )
        triggering_id = positive_int(
            approval["triggeringActorId"],
            f"{label}.reviewApproval.triggeringActorId",
        )
        reviewer_id = positive_int(
            approval["reviewerId"],
            f"{label}.reviewApproval.reviewerId",
        )
        if reviewer_id != actor_id or reviewer_id != triggering_id:
            fail(f"{label}.reviewApproval reviewer must be the workflow owner")
        candidate_attempt = positive_int(
            approval["candidateRunAttempt"],
            f"{label}.reviewApproval.candidateRunAttempt",
        )
        if candidate_attempt > review_attempt:
            fail(
                f"{label}.reviewApproval.candidateRunAttempt exceeds "
                "the reviewed producer attempt"
            )
        positive_int(
            approval["candidateArtifactId"],
            f"{label}.reviewApproval.candidateArtifactId",
        )
        sha256_digest(
            approval["candidateArtifactDigest"],
            f"{label}.reviewApproval.candidateArtifactDigest",
        )
        sha256_digest(
            approval["candidateDigest"],
            f"{label}.reviewApproval.candidateDigest",
        )
        sha256_digest(
            approval["approvalCommentDigest"],
            f"{label}.reviewApproval.approvalCommentDigest",
        )
        sha256_digest(
            approval["approvalReceiptDigest"],
            f"{label}.reviewApproval.approvalReceiptDigest",
        )
        finalized_at = not_future(facts["finalizedAt"], f"{label}.finalizedAt")
        reviewed_at = fresh(
            facts["reviewedAt"],
            f"{label}.reviewedAt",
            dt.timedelta(days=7),
        )
        if not SUBMISSION_START <= finalized_at <= SUBMISSION_DEADLINE:
            fail(f"{label}.finalizedAt is outside the official submission period")
        if reviewed_at < finalized_at or reviewed_at > SUBMISSION_DEADLINE:
            fail(f"{label}.reviewedAt must follow finalization before the deadline")
        if not (
            project_started == root_authored
            and root_authored <= root_committed
            and max(root_committed, repository_created)
            <= release_committed
            <= finalized_at
            <= reviewed_at
        ):
            fail(f"{label} repository/release/final-review chronology is invalid")
        return

    if proof_id == "SQ9":
        exact_keys(
            facts,
            {
                "evidenceClass",
                "ci",
                "artifact",
                "manifestDigest",
                "formats",
                "sanitized",
                "notLiveProof",
            },
            label,
        )
        exact(facts["evidenceClass"], "SYNTHETIC_OFFLINE_FIXTURE", f"{label}.evidenceClass")
        ci = exact_keys(
            facts["ci"],
            {
                "workflowPath",
                "runId",
                "runAttempt",
                "predicateType",
                "predicateDigest",
            },
            f"{label}.ci",
        )
        exact(ci["workflowPath"], ".github/workflows/ci.yml", f"{label}.ci.workflowPath")
        positive_int(ci["runId"], f"{label}.ci.runId")
        positive_int(ci["runAttempt"], f"{label}.ci.runAttempt")
        exact(
            ci["predicateType"],
            "https://github.com/upgradedev/archon-datahub/attestations/ci-release/v1",
            f"{label}.ci.predicateType",
        )
        sha256_digest(ci["predicateDigest"], f"{label}.ci.predicateDigest")
        artifact = exact_keys(
            facts["artifact"],
            {"id", "name", "digest", "producerAttempt"},
            f"{label}.artifact",
        )
        positive_int(artifact["id"], f"{label}.artifact.id")
        producer_attempt = positive_int(
            artifact["producerAttempt"], f"{label}.artifact.producerAttempt"
        )
        if producer_attempt > ci["runAttempt"]:
            fail(f"{label}.artifact.producerAttempt exceeds the CI run attempt")
        exact(
            artifact["name"],
            f"judge-evidence-{release}-{producer_attempt}",
            f"{label}.artifact.name",
        )
        sha256_digest(artifact["digest"], f"{label}.artifact.digest")
        sha256_digest(facts["manifestDigest"], f"{label}.manifestDigest")
        exact(
            facts["formats"],
            ["approval", "dossier", "json", "markdown", "plan", "receipt", "rollback", "sarif"],
            f"{label}.formats",
        )
        exact(facts["sanitized"], True, f"{label}.sanitized")
        exact(facts["notLiveProof"], True, f"{label}.notLiveProof")
        return

    if proof_id == "SQ10":
        exact_keys(
            facts,
            {
                "applicationUrl",
                "availability",
                "posture",
                "alerting",
                "recovery",
                "access",
                "monitoringWindow",
            },
            label,
        )
        public_https_url(facts["applicationUrl"], f"{label}.applicationUrl", origin_only=True)
        availability = exact_keys(
            facts["availability"],
            {
                "workflowPath",
                "runId",
                "runAttempt",
                "artifactId",
                "artifactName",
                "artifactDigest",
                "predicateType",
                "predicateDigest",
                "observedAt",
                "result",
            },
            f"{label}.availability",
        )
        exact(
            availability["workflowPath"],
            ".github/workflows/availability.yml",
            f"{label}.availability.workflowPath",
        )
        availability_run_id = positive_int(
            availability["runId"],
            f"{label}.availability.runId",
        )
        availability_attempt = positive_int(
            availability["runAttempt"], f"{label}.availability.runAttempt"
        )
        availability_artifact_id = positive_int(
            availability["artifactId"],
            f"{label}.availability.artifactId",
        )
        if availability_run_id == availability_artifact_id:
            fail(
                f"{label}.availability run and artifact IDs must be "
                "independently bound values"
            )
        exact(
            availability["artifactName"],
            f"production-availability-{release}-{availability_run_id}",
            f"{label}.availability.artifactName",
        )
        sha256_digest(availability["artifactDigest"], f"{label}.availability.artifactDigest")
        exact(
            availability["predicateType"],
            "https://github.com/upgradedev/archon-datahub/attestations/production-availability/v2",
            f"{label}.availability.predicateType",
        )
        sha256_digest(availability["predicateDigest"], f"{label}.availability.predicateDigest")
        fresh(
            availability["observedAt"],
            f"{label}.availability.observedAt",
            dt.timedelta(hours=7),
        )
        exact(availability["result"], "passed", f"{label}.availability.result")
        posture = exact_keys(
            facts["posture"],
            {
                "workflowPath",
                "runId",
                "runAttempt",
                "artifactId",
                "artifactName",
                "artifactDigest",
                "predicateType",
                "predicateDigest",
                "observedAt",
                "result",
                "topicArnSha256",
                "subscriptionArnSha256",
                "alarmInventory",
            },
            f"{label}.posture",
        )
        exact(
            posture["workflowPath"],
            ".github/workflows/production-posture.yml",
            f"{label}.posture.workflowPath",
        )
        posture_run_id = positive_int(
            posture["runId"],
            f"{label}.posture.runId",
        )
        posture_attempt = positive_int(posture["runAttempt"], f"{label}.posture.runAttempt")
        posture_artifact_id = positive_int(
            posture["artifactId"],
            f"{label}.posture.artifactId",
        )
        if posture_run_id == posture_artifact_id:
            fail(
                f"{label}.posture run and artifact IDs must be "
                "independently bound values"
            )
        exact(
            posture["artifactName"],
            f"production-posture-{release}-{posture_attempt}",
            f"{label}.posture.artifactName",
        )
        sha256_digest(posture["artifactDigest"], f"{label}.posture.artifactDigest")
        exact(
            posture["predicateType"],
            "https://github.com/upgradedev/archon-datahub/attestations/production-posture/v1",
            f"{label}.posture.predicateType",
        )
        sha256_digest(posture["predicateDigest"], f"{label}.posture.predicateDigest")
        fresh(posture["observedAt"], f"{label}.posture.observedAt", dt.timedelta(hours=30))
        exact(posture["result"], "passed", f"{label}.posture.result")
        sha256_digest(
            posture["topicArnSha256"],
            f"{label}.posture.topicArnSha256",
        )
        sha256_digest(
            posture["subscriptionArnSha256"],
            f"{label}.posture.subscriptionArnSha256",
        )
        alarm_inventory = exact_keys(
            posture["alarmInventory"],
            {
                "observedAt",
                "alarmCount",
                "allActionsEnabled",
                "alarmActionsBoundToTopic",
                "okActionsBoundToTopic",
                "insufficientDataActionsEmpty",
                "inventoryDigest",
            },
            f"{label}.posture.alarmInventory",
        )
        exact(
            alarm_inventory["observedAt"],
            posture["observedAt"],
            f"{label}.posture.alarmInventory.observedAt",
        )
        exact(
            alarm_inventory["alarmCount"],
            10,
            f"{label}.posture.alarmInventory.alarmCount",
        )
        for key in (
            "allActionsEnabled",
            "alarmActionsBoundToTopic",
            "okActionsBoundToTopic",
            "insufficientDataActionsEmpty",
        ):
            exact(
                alarm_inventory[key],
                True,
                f"{label}.posture.alarmInventory.{key}",
            )
        sha256_digest(
            alarm_inventory["inventoryDigest"],
            f"{label}.posture.alarmInventory.inventoryDigest",
        )
        alerting = exact_keys(
            facts["alerting"],
            {
                "alarmsActive",
                "snsSubscriptionConfirmed",
                "externalPagingDeliveryTested",
                "lastPagingTestAt",
                "pagingDelivery",
            },
            f"{label}.alerting",
        )
        for key in ("alarmsActive", "snsSubscriptionConfirmed", "externalPagingDeliveryTested"):
            exact(alerting[key], True, f"{label}.alerting.{key}")
        paging_delivery = validate_exact_provenance_binding(
            alerting["pagingDelivery"],
            f"{label}.alerting.pagingDelivery",
            release,
            workflow_path=".github/workflows/production-paging-test.yml",
            artifact_name_template=(
                "production-paging-delivery-{releaseSha}-{runAttempt}"
            ),
            predicate_type=(
                "https://archon.datahub.dev/attestations/"
                "production-paging-delivery/v1"
            ),
            extra_fields=frozenset(
                {
                    "observedAt",
                    "topicArnSha256",
                    "subscriptionArnSha256",
                }
            ),
        )
        fresh(
            paging_delivery["observedAt"],
            f"{label}.alerting.pagingDelivery.observedAt",
            dt.timedelta(days=7),
        )
        exact(
            alerting["lastPagingTestAt"],
            paging_delivery["observedAt"],
            f"{label}.alerting.lastPagingTestAt",
        )
        exact(
            paging_delivery["topicArnSha256"],
            posture["topicArnSha256"],
            f"{label}.alerting.pagingDelivery.topicArnSha256",
        )
        exact(
            paging_delivery["subscriptionArnSha256"],
            posture["subscriptionArnSha256"],
            f"{label}.alerting.pagingDelivery.subscriptionArnSha256",
        )
        for key in ("topicArnSha256", "subscriptionArnSha256"):
            sha256_digest(
                paging_delivery[key],
                f"{label}.alerting.pagingDelivery.{key}",
            )
        recovery = exact_keys(
            facts["recovery"],
            {
                "rollbackPathTested",
                "credentialRotationTested",
                "lastRollbackTestAt",
                "lastCredentialRotationTestAt",
                "governedCanary",
            },
            f"{label}.recovery",
        )
        exact(recovery["rollbackPathTested"], True, f"{label}.recovery.rollbackPathTested")
        exact(
            recovery["credentialRotationTested"],
            True,
            f"{label}.recovery.credentialRotationTested",
        )
        governed_canary = validate_exact_provenance_binding(
            recovery["governedCanary"],
            f"{label}.recovery.governedCanary",
            release,
            workflow_path=".github/workflows/governed-canary.yml",
            artifact_name_template=(
                "governed-canary-rollback-{runId}-{runAttempt}"
            ),
            predicate_type=(
                "https://github.com/upgradedev/archon-datahub/"
                "attestations/governed-canary/v1"
            ),
            extra_fields=frozenset(
                {
                    "verifiedAt",
                    "subjectDigest",
                    "rollbackEvidenceDigest",
                    "attestationVerificationDigest",
                }
            ),
        )
        fresh(
            governed_canary["verifiedAt"],
            f"{label}.recovery.governedCanary.verifiedAt",
            dt.timedelta(days=7),
        )
        exact(
            recovery["lastRollbackTestAt"],
            governed_canary["verifiedAt"],
            f"{label}.recovery.lastRollbackTestAt",
        )
        for key in (
            "subjectDigest",
            "rollbackEvidenceDigest",
            "attestationVerificationDigest",
        ):
            sha256_digest(
                governed_canary[key],
                f"{label}.recovery.governedCanary.{key}",
            )
        access = exact_keys(
            facts["access"],
            {
                "freeJudgeAccess",
                "confirmedCredentialOrPublicNoAuth",
                "validThrough",
                "projectAccess",
            },
            f"{label}.access",
        )
        exact(access["freeJudgeAccess"], True, f"{label}.access.freeJudgeAccess")
        exact(
            access["confirmedCredentialOrPublicNoAuth"],
            True,
            f"{label}.access.confirmedCredentialOrPublicNoAuth",
        )
        if timestamp(access["validThrough"], f"{label}.access.validThrough") < JUDGING_END:
            fail(f"{label}.access.validThrough ends before the judging window")
        project_access = validate_exact_provenance_binding(
            access["projectAccess"],
            f"{label}.access.projectAccess",
            release,
            workflow_path=".github/workflows/submission-project-access.yml",
            artifact_name_template=(
                "submission-project-access-{releaseSha}-{runAttempt}"
            ),
            predicate_type=(
                "https://archon.datahub.dev/attestations/"
                "submission-project-access/v1"
            ),
            extra_fields=frozenset(
                {
                    "observedAt",
                    "credentialRotationPerformedAt",
                }
            ),
        )
        fresh(
            project_access["observedAt"],
            f"{label}.access.projectAccess.observedAt",
            dt.timedelta(hours=24),
        )
        fresh(
            project_access["credentialRotationPerformedAt"],
            f"{label}.access.projectAccess.credentialRotationPerformedAt",
            dt.timedelta(days=7),
        )
        exact(
            recovery["lastCredentialRotationTestAt"],
            project_access["credentialRotationPerformedAt"],
            f"{label}.recovery.lastCredentialRotationTestAt",
        )
        window = exact_keys(
            facts["monitoringWindow"],
            {"schedule", "active", "through"},
            f"{label}.monitoringWindow",
        )
        exact(window["schedule"], "17 */6 * * *", f"{label}.monitoringWindow.schedule")
        exact(window["active"], True, f"{label}.monitoringWindow.active")
        if timestamp(window["through"], f"{label}.monitoringWindow.through") < JUDGING_END:
            fail(f"{label}.monitoringWindow.through ends before the judging window")
        return

    if proof_id == "SQ11":
        exact_keys(
            facts,
            {
                "rules",
                "challengeUrl",
                "devpostProjectUrl",
                "submissionStatus",
                "submittedAt",
                "confirmationDigest",
                "allRequiredFieldsSubmitted",
                "challengeEntryVisible",
                "descriptionDigest",
                "submissionFieldsDigest",
                "testingInstructionsDigest",
                "submissionClaimsDigest",
                "videoClaimsDigest",
                "applicationUrl",
                "applicationAuthenticationRequired",
                "repositoryUrl",
                "videoUrl",
                "loggedOutVerification",
                "preSubmitSeal",
                "reviewApproval",
            },
            label,
        )
        rules = exact_keys(
            facts["rules"],
            {
                "officialRulesUrl",
                "snapshotDigest",
                "submissionStart",
                "submissionEnd",
                "judgingStart",
                "judgingEnd",
            },
            f"{label}.rules",
        )
        exact(
            rules["officialRulesUrl"],
            "https://datahub.devpost.com/rules",
            f"{label}.rules.officialRulesUrl",
        )
        sha256_digest(rules["snapshotDigest"], f"{label}.rules.snapshotDigest")
        for key, expected in {
            "submissionStart": "2026-07-06T13:00:00Z",
            "submissionEnd": "2026-08-10T21:00:00Z",
            "judgingStart": "2026-08-17T14:00:00Z",
            "judgingEnd": "2026-08-31T21:00:00Z",
        }.items():
            exact(rules[key], expected, f"{label}.rules.{key}")
        exact(
            facts["challengeUrl"],
            "https://datahub.devpost.com/",
            f"{label}.challengeUrl",
        )
        devpost_url = public_https_url(
            facts["devpostProjectUrl"],
            f"{label}.devpostProjectUrl",
        )
        if (
            re.fullmatch(
                r"https://devpost\.com/software/[a-z0-9]+(?:-[a-z0-9]+)*",
                devpost_url,
            )
            is None
        ):
            fail(f"{label}.devpostProjectUrl must be an exact public Devpost project URL")
        exact(facts["submissionStatus"], "submitted", f"{label}.submissionStatus")
        submitted_at = not_future(facts["submittedAt"], f"{label}.submittedAt")
        if not SUBMISSION_START <= submitted_at <= SUBMISSION_DEADLINE:
            fail(f"{label}.submittedAt is outside the official submission period")
        sha256_digest(facts["confirmationDigest"], f"{label}.confirmationDigest")
        exact(
            facts["allRequiredFieldsSubmitted"],
            True,
            f"{label}.allRequiredFieldsSubmitted",
        )
        exact(
            facts["challengeEntryVisible"],
            True,
            f"{label}.challengeEntryVisible",
        )
        for key in (
            "descriptionDigest",
            "submissionFieldsDigest",
            "testingInstructionsDigest",
            "submissionClaimsDigest",
            "videoClaimsDigest",
        ):
            sha256_digest(facts[key], f"{label}.{key}")
        if notice_path is not None:
            exact(
                facts["testingInstructionsDigest"],
                testing_instructions_digest(notice_path),
                f"{label}.testingInstructionsDigest",
            )
        application_url = public_https_url(
            facts["applicationUrl"],
            f"{label}.applicationUrl",
            origin_only=True,
        )
        if type(facts["applicationAuthenticationRequired"]) is not bool:
            fail(f"{label}.applicationAuthenticationRequired must be boolean")
        exact(
            facts["repositoryUrl"],
            "https://github.com/upgradedev/archon-datahub",
            f"{label}.repositoryUrl",
        )
        repository_url = public_https_url(
            facts["repositoryUrl"],
            f"{label}.repositoryUrl",
        )
        video_url = strict_video_url(facts["videoUrl"], f"{label}.videoUrl")
        logged_out = exact_keys(
            facts["loggedOutVerification"],
            {"observedAt", "devpostEntry", "application", "repository", "video"},
            f"{label}.loggedOutVerification",
        )
        observed_at = fresh(
            logged_out["observedAt"],
            f"{label}.loggedOutVerification.observedAt",
            dt.timedelta(hours=24),
        )
        if observed_at < submitted_at:
            fail(f"{label}.loggedOutVerification must follow submission")
        for key, expected_url in {
            "devpostEntry": devpost_url,
            "application": application_url,
            "repository": repository_url,
            "video": video_url,
        }.items():
            probe = exact_keys(
                logged_out[key],
                {
                    "url",
                    "httpStatus",
                    "loggedOutAccessible",
                    "redirectsObserved",
                    "loginRequired",
                },
                f"{label}.loggedOutVerification.{key}",
            )
            exact(
                probe["url"],
                expected_url,
                f"{label}.loggedOutVerification.{key}.url",
            )
            exact(
                probe["httpStatus"],
                200,
                f"{label}.loggedOutVerification.{key}.httpStatus",
            )
            exact(
                probe["loggedOutAccessible"],
                True,
                f"{label}.loggedOutVerification.{key}.loggedOutAccessible",
            )
            exact(
                probe["redirectsObserved"],
                0,
                f"{label}.loggedOutVerification.{key}.redirectsObserved",
            )
            exact(
                probe["loginRequired"],
                (
                    facts["applicationAuthenticationRequired"]
                    if key == "application"
                    else False
                ),
                f"{label}.loggedOutVerification.{key}.loginRequired",
            )
        seal = exact_keys(
            facts["preSubmitSeal"],
            {
                "workflowPath",
                "runId",
                "runAttempt",
                "artifactId",
                "artifactName",
                "artifactDigest",
                "inventoryDigest",
                "subjectSetDigest",
                "predicateType",
                "predicateDigest",
                "readinessEvidenceDigest",
                "readinessDigest",
                "sourceBindingDigest",
                "approvalReceiptDigest",
                "sealedAt",
            },
            f"{label}.preSubmitSeal",
        )
        exact(
            seal["workflowPath"],
            ".github/workflows/submission-readiness.yml",
            f"{label}.preSubmitSeal.workflowPath",
        )
        positive_int(seal["runId"], f"{label}.preSubmitSeal.runId")
        positive_int(seal["runAttempt"], f"{label}.preSubmitSeal.runAttempt")
        positive_int(seal["artifactId"], f"{label}.preSubmitSeal.artifactId")
        exact(
            seal["artifactName"],
            f"submission-readiness-{release}",
            f"{label}.preSubmitSeal.artifactName",
        )
        for key in (
            "artifactDigest",
            "inventoryDigest",
            "subjectSetDigest",
            "predicateDigest",
            "readinessEvidenceDigest",
            "readinessDigest",
            "sourceBindingDigest",
            "approvalReceiptDigest",
        ):
            sha256_digest(seal[key], f"{label}.preSubmitSeal.{key}")
        exact(
            seal["predicateType"],
            "https://archon.datahub.dev/attestations/submission-readiness-seal/v1",
            f"{label}.preSubmitSeal.predicateType",
        )
        exact(
            seal["predicateDigest"],
            seal["readinessEvidenceDigest"],
            f"{label}.preSubmitSeal predicate/readiness evidence digest",
        )
        sealed_at = not_future(
            seal["sealedAt"],
            f"{label}.preSubmitSeal.sealedAt",
        )
        if (
            not SUBMISSION_START <= sealed_at <= SUBMISSION_DEADLINE
            or sealed_at >= submitted_at
        ):
            fail(f"{label}.preSubmitSeal must predate submission within the period")
        approval = exact_keys(
            facts["reviewApproval"],
            {
                "approvalMode",
                "environment",
                "workflowActorId",
                "triggeringActorId",
                "reviewerId",
                "approvalReceiptDigest",
            },
            f"{label}.reviewApproval",
        )
        exact(
            approval["approvalMode"],
            "solo-owner",
            f"{label}.reviewApproval.approvalMode",
        )
        exact(
            approval["environment"],
            "submission-devpost-confirmation",
            f"{label}.reviewApproval.environment",
        )
        actor_id = positive_int(
            approval["workflowActorId"],
            f"{label}.reviewApproval.workflowActorId",
        )
        triggering_id = positive_int(
            approval["triggeringActorId"],
            f"{label}.reviewApproval.triggeringActorId",
        )
        reviewer_id = positive_int(
            approval["reviewerId"],
            f"{label}.reviewApproval.reviewerId",
        )
        if reviewer_id != actor_id or reviewer_id != triggering_id:
            fail(f"{label}.reviewApproval reviewer must be the workflow owner")
        approval_digest = sha256_digest(
            approval["approvalReceiptDigest"],
            f"{label}.reviewApproval.approvalReceiptDigest",
        )
        if approval_digest == seal["approvalReceiptDigest"]:
            fail(f"{label} must retain a distinct post-submit approval receipt")
        return

    if proof_id == "BONUS-OSS":
        expected_paths = [
            "src/mcp_server_datahub/mcp_server.py",
            "src/mcp_server_datahub/tools/__init__.py",
            "src/mcp_server_datahub/tools/aspect_history.py",
            "tests/test_mcp/test_get_aspect_history.py",
        ]
        facts = exact_keys(
            facts,
            {
                "upstreamRepositoryUrl",
                "pullRequestUrl",
                "state",
                "publiclyAccessible",
                "acceptedByMaintainer",
                "acceptedAt",
                "patchDigest",
                "validatedCandidateDigest",
                "upstreamPullRequest",
                "candidateBinding",
                "ciValidation",
            },
            label,
        )
        upstream = public_https_url(
            facts["upstreamRepositoryUrl"],
            f"{label}.upstreamRepositoryUrl",
        )
        pull_request = public_https_url(
            facts["pullRequestUrl"],
            f"{label}.pullRequestUrl",
        )
        exact(
            upstream,
            "https://github.com/acryldata/mcp-server-datahub",
            f"{label}.upstreamRepositoryUrl",
        )
        exact(facts["state"], "merged", f"{label}.state")
        exact(facts["publiclyAccessible"], True, f"{label}.publiclyAccessible")
        exact(facts["acceptedByMaintainer"], True, f"{label}.acceptedByMaintainer")
        accepted_at = not_future(facts["acceptedAt"], f"{label}.acceptedAt")
        exact(
            facts["acceptedAt"],
            accepted_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            f"{label}.acceptedAt",
        )
        if not SUBMISSION_START <= accepted_at <= SUBMISSION_DEADLINE:
            fail(f"{label}.acceptedAt is outside the official submission period")
        sha256_digest(facts["patchDigest"], f"{label}.patchDigest")

        pull = exact_keys(
            facts["upstreamPullRequest"],
            {
                "number",
                "baseRef",
                "baseSha",
                "headSha",
                "headTreeSha",
                "mergeCommitSha",
                "mergeTreeSha",
                "changedPaths",
                "authorId",
                "authorLogin",
                "mergedById",
                "mergedByLogin",
                "mergedAt",
            },
            f"{label}.upstreamPullRequest",
        )
        pull_number = positive_int(
            pull["number"],
            f"{label}.upstreamPullRequest.number",
        )
        exact(
            pull_request,
            f"{upstream}/pull/{pull_number}",
            f"{label}.pullRequestUrl",
        )
        exact(
            pull["baseRef"],
            "main",
            f"{label}.upstreamPullRequest.baseRef",
        )
        for key in (
            "baseSha",
            "headSha",
            "headTreeSha",
            "mergeCommitSha",
            "mergeTreeSha",
        ):
            release_sha(
                pull[key],
                f"{label}.upstreamPullRequest.{key}",
            )
        exact(
            pull["changedPaths"],
            expected_paths,
            f"{label}.upstreamPullRequest.changedPaths",
        )
        author_id = positive_int(
            pull["authorId"],
            f"{label}.upstreamPullRequest.authorId",
        )
        merger_id = positive_int(
            pull["mergedById"],
            f"{label}.upstreamPullRequest.mergedById",
        )
        if author_id == merger_id:
            fail(f"{label}.upstreamPullRequest merger must be independent")
        nonempty(
            pull["authorLogin"],
            f"{label}.upstreamPullRequest.authorLogin",
            100,
        )
        nonempty(
            pull["mergedByLogin"],
            f"{label}.upstreamPullRequest.mergedByLogin",
            100,
        )
        merged_at = not_future(
            pull["mergedAt"],
            f"{label}.upstreamPullRequest.mergedAt",
        )
        exact(
            pull["mergedAt"],
            merged_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            f"{label}.upstreamPullRequest.mergedAt",
        )
        if not SUBMISSION_START <= merged_at <= SUBMISSION_DEADLINE:
            fail(
                f"{label}.upstreamPullRequest.mergedAt is outside the "
                "official submission period"
            )
        exact(
            facts["acceptedAt"],
            pull["mergedAt"],
            f"{label}.acceptedAt",
        )

        binding = exact_keys(
            facts["candidateBinding"],
            {
                "baseCommit",
                "appliedDiffDigest",
                "reconstructedTreeSha",
                "canonicalFileManifestDigest",
                "files",
                "exactHeadTreeMatch",
                "exactMergedPathBytesMatch",
            },
            f"{label}.candidateBinding",
        )
        release_sha(
            binding["baseCommit"],
            f"{label}.candidateBinding.baseCommit",
        )
        exact(
            binding["baseCommit"],
            pull["baseSha"],
            f"{label}.candidateBinding.baseCommit",
        )
        sha256_digest(
            binding["appliedDiffDigest"],
            f"{label}.candidateBinding.appliedDiffDigest",
        )
        release_sha(
            binding["reconstructedTreeSha"],
            f"{label}.candidateBinding.reconstructedTreeSha",
        )
        exact(
            binding["reconstructedTreeSha"],
            pull["headTreeSha"],
            f"{label}.candidateBinding.reconstructedTreeSha",
        )
        exact(
            binding["exactHeadTreeMatch"],
            True,
            f"{label}.candidateBinding.exactHeadTreeMatch",
        )
        exact(
            binding["exactMergedPathBytesMatch"],
            True,
            f"{label}.candidateBinding.exactMergedPathBytesMatch",
        )
        files = binding["files"]
        if not isinstance(files, list) or len(files) != len(expected_paths):
            fail(f"{label}.candidateBinding.files inventory is not exact")
        for index, expected_path in enumerate(expected_paths):
            entry = exact_keys(
                files[index],
                {"path", "mode", "gitBlobSha", "sha256"},
                f"{label}.candidateBinding.files[{index}]",
            )
            exact(
                entry["path"],
                expected_path,
                f"{label}.candidateBinding.files[{index}].path",
            )
            exact(
                entry["mode"],
                "100644",
                f"{label}.candidateBinding.files[{index}].mode",
            )
            release_sha(
                entry["gitBlobSha"],
                f"{label}.candidateBinding.files[{index}].gitBlobSha",
            )
            sha256_digest(
                entry["sha256"],
                f"{label}.candidateBinding.files[{index}].sha256",
            )
        candidate_manifest = {
            "schemaVersion": "archon.oss-candidate-binding/v1",
            "upstreamRepository": "acryldata/mcp-server-datahub",
            "baseCommit": binding["baseCommit"],
            "appliedDiffDigest": binding["appliedDiffDigest"],
            "reconstructedTreeSha": binding["reconstructedTreeSha"],
            "files": files,
        }
        candidate_digest = canonical_json_digest(candidate_manifest)
        exact(
            binding["canonicalFileManifestDigest"],
            candidate_digest,
            f"{label}.candidateBinding.canonicalFileManifestDigest",
        )
        exact(
            facts["validatedCandidateDigest"],
            candidate_digest,
            f"{label}.validatedCandidateDigest",
        )

        ci = exact_keys(
            facts["ciValidation"],
            {
                "workflowPath",
                "runId",
                "runAttempt",
                "artifactId",
                "artifactName",
                "artifactDigest",
                "artifactProducerAttempt",
                "receiptDigest",
                "predicateType",
                "predicateDigest",
                "attestedSubjectName",
                "attestedSubjectDigest",
            },
            f"{label}.ciValidation",
        )
        exact(
            ci["workflowPath"],
            ".github/workflows/ci.yml",
            f"{label}.ciValidation.workflowPath",
        )
        ci_run_id = positive_int(
            ci["runId"],
            f"{label}.ciValidation.runId",
        )
        run_attempt = positive_int(
            ci["runAttempt"],
            f"{label}.ciValidation.runAttempt",
        )
        if run_attempt > 20:
            fail(f"{label}.ciValidation.runAttempt exceeds the bounded history")
        artifact_id = positive_int(
            ci["artifactId"],
            f"{label}.ciValidation.artifactId",
        )
        if ci_run_id == artifact_id:
            fail(f"{label}.ciValidation run and artifact IDs must be distinct")
        exact(
            ci["artifactName"],
            f"oss-validation-receipt-{release}",
            f"{label}.ciValidation.artifactName",
        )
        sha256_digest(
            ci["artifactDigest"],
            f"{label}.ciValidation.artifactDigest",
        )
        producer_attempt = positive_int(
            ci["artifactProducerAttempt"],
            f"{label}.ciValidation.artifactProducerAttempt",
        )
        if producer_attempt > run_attempt:
            fail(
                f"{label}.ciValidation artifact producer attempt exceeds "
                "the signed CI attempt"
            )
        sha256_digest(
            ci["receiptDigest"],
            f"{label}.ciValidation.receiptDigest",
        )
        exact(
            ci["predicateType"],
            (
                "https://github.com/upgradedev/archon-datahub/"
                "attestations/ci-release/v1"
            ),
            f"{label}.ciValidation.predicateType",
        )
        sha256_digest(
            ci["predicateDigest"],
            f"{label}.ciValidation.predicateDigest",
        )
        exact(
            ci["attestedSubjectName"],
            "archon-lambdas.tar.gz",
            f"{label}.ciValidation.attestedSubjectName",
        )
        sha256_digest(
            ci["attestedSubjectDigest"],
            f"{label}.ciValidation.attestedSubjectDigest",
        )
        return

    if proof_id == "BONUS-FEEDBACK":
        exact_keys(
            facts,
            {
                "challengeUrl",
                "officialRulesUrl",
                "status",
                "submittedAt",
                "canonicalEvidenceDigest",
                "confirmationDigest",
                "entrantBindingDigest",
                "entrantKind",
                "registeredEntrant",
                "oneEntryPerEntrant",
                "individualNotProjectPrize",
                "distinctFeedbackSubmissionUnderRules",
                "feedbackQuality",
                "privacyDisclosure",
                "rulesObservation",
                "approvalTiming",
                "reviewApproval",
            },
            label,
        )
        exact(
            facts["challengeUrl"],
            "https://datahub.devpost.com/",
            f"{label}.challengeUrl",
        )
        exact(
            facts["officialRulesUrl"],
            "https://datahub.devpost.com/rules",
            f"{label}.officialRulesUrl",
        )
        exact(facts["status"], "submitted", f"{label}.status")
        submitted_at = not_future(facts["submittedAt"], f"{label}.submittedAt")
        if not FEEDBACK_START <= submitted_at <= SUBMISSION_DEADLINE:
            fail(f"{label}.submittedAt is outside the official feedback period")
        canonical_digest = sha256_digest(
            facts["canonicalEvidenceDigest"],
            f"{label}.canonicalEvidenceDigest",
        )
        confirmation_digest = sha256_digest(
            facts["confirmationDigest"],
            f"{label}.confirmationDigest",
        )
        entrant_digest = sha256_digest(
            facts["entrantBindingDigest"],
            f"{label}.entrantBindingDigest",
        )
        if len({canonical_digest, confirmation_digest, entrant_digest}) != 3:
            fail(
                f"{label} canonical, confirmation, and entrant-binding "
                "digests must be distinct"
            )
        exact(facts["entrantKind"], "individual", f"{label}.entrantKind")
        exact(facts["registeredEntrant"], True, f"{label}.registeredEntrant")
        exact(facts["oneEntryPerEntrant"], True, f"{label}.oneEntryPerEntrant")
        exact(
            facts["individualNotProjectPrize"],
            True,
            f"{label}.individualNotProjectPrize",
        )
        exact(
            facts["distinctFeedbackSubmissionUnderRules"],
            True,
            f"{label}.distinctFeedbackSubmissionUnderRules",
        )

        quality = exact_keys(
            facts["feedbackQuality"],
            {"complete", "actionable", "viable", "potentialImpact"},
            f"{label}.feedbackQuality",
        )
        for key in ("complete", "actionable", "viable", "potentialImpact"):
            exact(quality[key], True, f"{label}.feedbackQuality.{key}")

        privacy = exact_keys(
            facts["privacyDisclosure"],
            {
                "rawFeedbackIncluded",
                "rawEntrantPersonalDataIncluded",
                "devpostCredentialsIncluded",
                "privateConfirmationBytesIncluded",
                "pseudonymousEntrantCommitmentIncluded",
                "publicReviewerNumericIdentifierIncluded",
            },
            f"{label}.privacyDisclosure",
        )
        for key in (
            "rawFeedbackIncluded",
            "rawEntrantPersonalDataIncluded",
            "devpostCredentialsIncluded",
            "privateConfirmationBytesIncluded",
        ):
            exact(privacy[key], False, f"{label}.privacyDisclosure.{key}")
        for key in (
            "pseudonymousEntrantCommitmentIncluded",
            "publicReviewerNumericIdentifierIncluded",
        ):
            exact(privacy[key], True, f"{label}.privacyDisclosure.{key}")

        observation = exact_keys(
            facts["rulesObservation"],
            {
                "observedAt",
                "feedbackStart",
                "feedbackDeadline",
                "semanticDigest",
                "authenticatedUiObserved",
                "publicOverviewInstruction",
            },
            f"{label}.rulesObservation",
        )
        observed_at = not_future(
            observation["observedAt"],
            f"{label}.rulesObservation.observedAt",
        )
        exact(
            observation["feedbackStart"],
            "2026-07-06T13:00:00Z",
            f"{label}.rulesObservation.feedbackStart",
        )
        exact(
            observation["feedbackDeadline"],
            "2026-08-10T21:00:00Z",
            f"{label}.rulesObservation.feedbackDeadline",
        )
        sha256_digest(
            observation["semanticDigest"],
            f"{label}.rulesObservation.semanticDigest",
        )
        exact(
            observation["authenticatedUiObserved"],
            False,
            f"{label}.rulesObservation.authenticatedUiObserved",
        )
        exact(
            observation["publicOverviewInstruction"],
            "complete-feedback-section-during-submission",
            f"{label}.rulesObservation.publicOverviewInstruction",
        )

        approval_timing = exact_keys(
            facts["approvalTiming"],
            {
                "authoritativeApprovalTimestampAvailable",
                "reviewJobStartedAt",
            },
            f"{label}.approvalTiming",
        )
        exact(
            approval_timing["authoritativeApprovalTimestampAvailable"],
            False,
            f"{label}.approvalTiming.authoritativeApprovalTimestampAvailable",
        )
        review_job_started_at = not_future(
            approval_timing["reviewJobStartedAt"],
            f"{label}.approvalTiming.reviewJobStartedAt",
        )
        if not (
            submitted_at
            <= observed_at
            <= review_job_started_at
            <= SUBMISSION_DEADLINE
        ):
            fail(
                f"{label} must order submission, rules observation, and the "
                "conservative review-job approval bound within the feedback period"
            )

        approval = exact_keys(
            facts["reviewApproval"],
            {
                "approvalMode",
                "environment",
                "workflowPath",
                "runId",
                "runAttempt",
                "environmentId",
                "workflowActorId",
                "triggeringActorId",
                "reviewerId",
                "candidateRunAttempt",
                "candidateArtifactId",
                "candidateArtifactDigest",
                "candidateDigest",
                "canonicalEvidenceDigest",
                "confirmationDigest",
                "approvalCommentDigest",
                "approvalReceiptDigest",
            },
            f"{label}.reviewApproval",
        )
        exact(
            approval["approvalMode"],
            "solo-owner",
            f"{label}.reviewApproval.approvalMode",
        )
        exact(
            approval["environment"],
            "submission-bonus-feedback",
            f"{label}.reviewApproval.environment",
        )
        exact(
            approval["workflowPath"],
            ".github/workflows/submission-bonus-feedback.yml",
            f"{label}.reviewApproval.workflowPath",
        )
        positive_int(approval["runId"], f"{label}.reviewApproval.runId")
        run_attempt = positive_int(
            approval["runAttempt"],
            f"{label}.reviewApproval.runAttempt",
        )
        positive_int(
            approval["environmentId"],
            f"{label}.reviewApproval.environmentId",
        )
        actor_id = positive_int(
            approval["workflowActorId"],
            f"{label}.reviewApproval.workflowActorId",
        )
        triggering_id = positive_int(
            approval["triggeringActorId"],
            f"{label}.reviewApproval.triggeringActorId",
        )
        reviewer_id = positive_int(
            approval["reviewerId"],
            f"{label}.reviewApproval.reviewerId",
        )
        if reviewer_id != actor_id or reviewer_id != triggering_id:
            fail(f"{label}.reviewApproval reviewer must be the workflow owner")
        candidate_attempt = positive_int(
            approval["candidateRunAttempt"],
            f"{label}.reviewApproval.candidateRunAttempt",
        )
        if candidate_attempt > run_attempt:
            fail(
                f"{label}.reviewApproval candidate attempt exceeds the "
                "retained producer attempt"
            )
        positive_int(
            approval["candidateArtifactId"],
            f"{label}.reviewApproval.candidateArtifactId",
        )
        for key in (
            "candidateArtifactDigest",
            "candidateDigest",
            "approvalCommentDigest",
            "approvalReceiptDigest",
        ):
            sha256_digest(
                approval[key],
                f"{label}.reviewApproval.{key}",
            )
        exact(
            approval["canonicalEvidenceDigest"],
            canonical_digest,
            f"{label}.reviewApproval.canonicalEvidenceDigest",
        )
        exact(
            approval["confirmationDigest"],
            confirmation_digest,
            f"{label}.reviewApproval.confirmationDigest",
        )
        return

    fail(f"no semantic validator is registered for {proof_id}")


def expected_support_bindings(
    proof_id: str,
    role: str,
    facts: dict[str, Any],
) -> dict[str, Any]:
    fields = SUPPORT_BINDING_FIELDS.get((proof_id, role))
    if fields is None:
        fail(f"{proof_id}/{role} has no support binding contract")
    missing = set(fields) - set(facts)
    if missing:
        fail(f"{proof_id}/{role} facts are missing support fields {sorted(missing)}")
    return {field: facts[field] for field in fields}


def validate_support_subject(
    path: Path,
    proof_id: str,
    role: str,
    repository: str,
    release: str,
    facts: dict[str, Any],
) -> None:
    label = f"support subject {proof_id}/{role}"
    support = exact_keys(
        load_json(path, label),
        {
            "schemaVersion",
            "proofId",
            "role",
            "repository",
            "releaseSha",
            "factsDigest",
            "capture",
            "sanitized",
            "bindings",
        },
        label,
    )
    exact(support["schemaVersion"], SUPPORT_SCHEMA, f"{label}.schemaVersion")
    exact(support["proofId"], proof_id, f"{label}.proofId")
    exact(support["role"], role, f"{label}.role")
    exact(support["repository"], repository, f"{label}.repository")
    exact(support["releaseSha"], release, f"{label}.releaseSha")
    exact(
        support["factsDigest"],
        canonical_json_digest(facts),
        f"{label}.factsDigest",
    )
    capture = exact_keys(
        support["capture"],
        {
            "schemaVersion",
            "capturedAt",
            "digest",
            "sizeBytes",
            "recordCount",
            "data",
        },
        f"{label}.capture",
    )
    exact(
        capture["schemaVersion"],
        SUPPORT_CAPTURE_SCHEMA,
        f"{label}.capture.schemaVersion",
    )
    fresh(
        capture["capturedAt"],
        f"{label}.capture.capturedAt",
        dt.timedelta(days=7),
    )
    expected_bindings = expected_support_bindings(proof_id, role, facts)
    expected_data = [
        {
            "schemaVersion": SUPPORT_RECORD_SCHEMA,
            "recordType": role,
            "observedAt": capture["capturedAt"],
            "evidence": expected_bindings,
        }
    ]
    exact(capture["data"], expected_data, f"{label}.capture.data")
    capture_bytes = canonical_json_text(capture["data"]).encode("utf-8")
    if not 1 <= len(capture_bytes) <= 10 * 1024 * 1024:
        fail(f"{label}.capture.data must be 1 byte..10 MiB")
    exact(
        capture["digest"],
        sha256_bytes(capture_bytes),
        f"{label}.capture.digest",
    )
    exact(
        capture["sizeBytes"],
        len(capture_bytes),
        f"{label}.capture.sizeBytes",
    )
    exact(
        capture["recordCount"],
        1,
        f"{label}.capture.recordCount",
    )
    exact(support["sanitized"], True, f"{label}.sanitized")
    exact(
        support["bindings"],
        expected_bindings,
        f"{label}.bindings",
    )


def configured_support_rows(
    source_registry: dict[str, Any],
    proof_id: str,
) -> list[dict[str, str]]:
    return sorted(
        source_registry["supportSubjects"][proof_id],
        key=lambda item: item["role"],
    )


def resolved_support_subjects(
    source_dir: Path,
    source_registry: dict[str, Any],
    proof_id: str,
    repository: str,
    release: str,
    facts: dict[str, Any] | None,
) -> list[dict[str, str]]:
    subjects: list[dict[str, str]] = []
    for configured in configured_support_rows(source_registry, proof_id):
        role = configured["role"]
        name = configured["name"]
        path = source_dir / name
        if source_registry["mode"] == "standard-v1":
            if facts is None:
                fail(f"{proof_id}/{role} requires facts for support validation")
            validate_support_subject(
                path,
                proof_id,
                role,
                repository,
                release,
                facts,
            )
        elif not path.is_file() or path.is_symlink():
            fail(f"native support subject {proof_id}/{role} must be a regular file")
        subjects.append(
            {
                "role": role,
                "name": name,
                "digest": sha256_file(path),
            }
        )
    return subjects


def expected_receipt_subject_names(
    source_registry: dict[str, Any],
    proof_id: str,
) -> list[dict[str, str]]:
    support = [
        {"role": item["role"], "name": item["name"]}
        for item in configured_support_rows(source_registry, proof_id)
    ]
    if source_registry["mode"] == "standard-v1":
        return [
            {
                "role": "proof-envelope",
                "name": f"proofs/{proof_id}.json",
            },
            *support,
        ]
    return support


def validate_common_source(
    value: Any,
    label: str,
    source_registry: dict[str, Any],
    proof_id: str,
    repository: str,
    release: str,
) -> None:
    source = exact_keys(
        value,
        {"workflowPath", "runId", "runAttempt", "artifact", "attestation"},
        label,
    )
    exact(source["workflowPath"], source_registry["workflowPath"], f"{label}.workflowPath")
    positive_int(source["runId"], f"{label}.runId")
    attempt = positive_int(source["runAttempt"], f"{label}.runAttempt")
    artifact = exact_keys(
        source["artifact"],
        {"id", "name", "digest"},
        f"{label}.artifact",
    )
    positive_int(artifact["id"], f"{label}.artifact.id")
    exact(
        artifact["name"],
        artifact_name(source_registry, release, attempt),
        f"{label}.artifact.name",
    )
    sha256_digest(artifact["digest"], f"{label}.artifact.digest")
    attestation = exact_keys(
        source["attestation"],
        {
            "predicateType",
            "predicateDigest",
            "subjectSetDigest",
            "verificationSetDigest",
            "subjects",
        },
        f"{label}.attestation",
    )
    exact(
        attestation["predicateType"],
        source_registry["predicateType"],
        f"{label}.attestation.predicateType",
    )
    sha256_digest(attestation["predicateDigest"], f"{label}.attestation.predicateDigest")
    sha256_digest(
        attestation["subjectSetDigest"],
        f"{label}.attestation.subjectSetDigest",
    )
    sha256_digest(
        attestation["verificationSetDigest"],
        f"{label}.attestation.verificationSetDigest",
    )
    if not isinstance(attestation["subjects"], list):
        fail(f"{label}.attestation.subjects must be an array")
    subjects: list[dict[str, str]] = []
    for index, raw_subject in enumerate(attestation["subjects"]):
        subject_label = f"{label}.attestation.subjects[{index}]"
        subject = exact_keys(
            raw_subject,
            {"role", "name", "digest"},
            subject_label,
        )
        role = nonempty(subject["role"], f"{subject_label}.role", 64)
        if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", role) is None:
            fail(f"{subject_label}.role is not canonical")
        subjects.append(
            {
                "role": role,
                "name": safe_relative_name(
                    subject["name"],
                    f"{subject_label}.name",
                ),
                "digest": sha256_digest(
                    subject["digest"],
                    f"{subject_label}.digest",
                ),
            }
        )
    expected_names = expected_receipt_subject_names(source_registry, proof_id)
    exact(
        [
            {"role": subject["role"], "name": subject["name"]}
            for subject in subjects
        ],
        expected_names,
        f"{label}.attestation subject roles and names",
    )
    exact(repository, REPOSITORY, "repository")


def validate_receipt(
    value: Any,
    sources: dict[str, dict[str, Any]],
    repository: str,
    release: str,
    *,
    notice_path: Path | None,
) -> dict[str, Any]:
    receipt = exact_keys(
        value,
        {
            "schemaVersion",
            "id",
            "criterion",
            "repository",
            "releaseSha",
            "source",
            "facts",
        },
        "receipt",
    )
    exact(receipt["schemaVersion"], RECEIPT_SCHEMA, "receipt.schemaVersion")
    proof_id = nonempty(receipt["id"], "receipt.id", 32)
    if proof_id not in PROOF_CRITERIA:
        fail(f"receipt.id {proof_id!r} is not registered")
    exact(receipt["criterion"], PROOF_CRITERIA[proof_id], "receipt.criterion")
    exact(receipt["repository"], repository, "receipt.repository")
    exact(receipt["releaseSha"], release, "receipt.releaseSha")
    source_registry = source_for_proof(proof_id, sources)
    validate_common_source(
        receipt["source"],
        "receipt.source",
        source_registry,
        proof_id,
        repository,
        release,
    )
    validate_facts(proof_id, receipt["facts"], release, notice_path=notice_path)
    return receipt


def cross_validate(receipts: dict[str, dict[str, Any]]) -> None:
    if "D4" in receipts and "SQ3" in receipts:
        exact(
            receipts["D4"]["facts"]["applicationUrl"],
            receipts["SQ3"]["facts"]["applicationUrl"],
            "D4/SQ3 applicationUrl",
        )
    if "D4" in receipts and "SQ10" in receipts:
        governed_write = receipts["D4"]["facts"]["governedWrite"]
        governed_canary = receipts["SQ10"]["facts"]["recovery"][
            "governedCanary"
        ]
        exact(
            governed_canary["runId"],
            governed_write["workflowRunId"],
            "D4/SQ10 governed-canary run ID",
        )
        exact(
            governed_canary["predicateDigest"],
            governed_write["attestationPredicateDigest"],
            "D4/SQ10 governed-canary predicate digest",
        )
        exact(
            governed_canary["subjectDigest"],
            governed_write["rollbackSubjectDigest"],
            "D4/SQ10 governed-canary subject digest",
        )
        exact(
            governed_canary["rollbackEvidenceDigest"],
            governed_write["rollbackEvidenceDigest"],
            "D4/SQ10 governed-canary rollback evidence digest",
        )
        exact(
            governed_canary["attestationVerificationDigest"],
            governed_write["attestationVerificationDigest"],
            "D4/SQ10 governed-canary verification digest",
        )
        if timestamp(
            governed_canary["verifiedAt"],
            "D4/SQ10 governed-canary verifiedAt",
        ) > timestamp(
            receipts["D4"]["facts"]["provenAt"],
            "D4/SQ10 live proof provenAt",
        ):
            fail("D4/SQ10 live proof predates governed-canary rollback verification")
    if "SQ3" in receipts and "SQ4" in receipts:
        exact(
            receipts["SQ4"]["facts"]["applicationUrl"],
            receipts["SQ3"]["facts"]["applicationUrl"],
            "SQ3/SQ4 applicationUrl",
        )
        exact(
            receipts["SQ4"]["facts"]["deployment"],
            receipts["SQ3"]["facts"]["deployment"],
            "SQ3/SQ4 deployment binding",
        )
        exact(
            receipts["SQ4"]["facts"]["testingInstructionsDigest"],
            receipts["SQ6"]["facts"]["testingInstructionsDigest"]
            if "SQ6" in receipts
            else receipts["SQ4"]["facts"]["testingInstructionsDigest"],
            "SQ4/SQ6 testingInstructionsDigest",
        )
    if "SQ3" in receipts and "SQ7" in receipts:
        exact(
            receipts["SQ7"]["facts"]["shownApplicationUrl"],
            receipts["SQ3"]["facts"]["applicationUrl"],
            "SQ3/SQ7 applicationUrl",
        )
    if "SQ3" in receipts and "SQ10" in receipts:
        exact(
            receipts["SQ10"]["facts"]["applicationUrl"],
            receipts["SQ3"]["facts"]["applicationUrl"],
            "SQ3/SQ10 applicationUrl",
        )
        sq3_observation = receipts["SQ3"]["facts"]["observation"]
        sq10_availability = receipts["SQ10"]["facts"]["availability"]
        exact(
            sq10_availability,
            {
                "workflowPath": ".github/workflows/availability.yml",
                "runId": sq3_observation["availabilityRunId"],
                "runAttempt": sq3_observation["availabilityRunAttempt"],
                "artifactId": sq3_observation["availabilityArtifactId"],
                "artifactName": sq3_observation["availabilityArtifactName"],
                "artifactDigest": sq3_observation[
                    "availabilityArtifactDigest"
                ],
                "predicateType": sq3_observation[
                    "availabilityPredicateType"
                ],
                "predicateDigest": sq3_observation[
                    "availabilityPredicateDigest"
                ],
                "observedAt": sq3_observation["availabilityObservedAt"],
                "result": "passed",
            },
            "SQ3/SQ10 availability source binding",
        )
    if "SQ4" in receipts and "SQ10" in receipts:
        sq4 = receipts["SQ4"]
        sq10 = receipts["SQ10"]["facts"]
        sq4_source = sq4["source"]
        rotations = [
            operation
            for operation in sq4["facts"]["judgeUserLifecycle"]["operations"]
            if operation["operation"] == "rotate"
        ]
        if len(rotations) != 1:
            fail("SQ4/SQ10 requires exactly one credential-rotation operation")
        rotation = rotations[0]
        exact(
            sq10["access"]["projectAccess"],
            {
                "workflowPath": sq4_source["workflowPath"],
                "runId": sq4_source["runId"],
                "runAttempt": sq4_source["runAttempt"],
                "artifactId": sq4_source["artifact"]["id"],
                "artifactName": sq4_source["artifact"]["name"],
                "artifactDigest": sq4_source["artifact"]["digest"],
                "predicateType": sq4_source["attestation"]["predicateType"],
                "predicateDigest": sq4_source["attestation"]["predicateDigest"],
                "observedAt": sq4["facts"]["observedAt"],
                "credentialRotationPerformedAt": rotation["performedAt"],
            },
            "SQ4/SQ10 project-access source binding",
        )
        exact(
            sq10["access"]["freeJudgeAccess"],
            sq4["facts"]["freeAccess"],
            "SQ4/SQ10 free judge access",
        )
        exact(
            sq10["access"]["validThrough"],
            sq4["facts"]["accessValidThrough"],
            "SQ4/SQ10 judge access validity",
        )
        exact(
            sq10["recovery"]["credentialRotationTested"],
            sq4["facts"]["credentialRotation"]["rotationTested"],
            "SQ4/SQ10 credential rotation",
        )
        exact(
            sq10["recovery"]["lastCredentialRotationTestAt"],
            rotation["performedAt"],
            "SQ4/SQ10 credential-rotation timestamp",
        )
    if {"SQ6", "SQ7", "SQ8"}.issubset(receipts):
        sq8_approval = receipts["SQ8"]["facts"]["reviewApproval"]
        sq8_source = receipts["SQ8"]["source"]
        exact(
            sq8_approval["workflowPath"],
            sq8_source["workflowPath"],
            "SQ8 approval/source workflow path",
        )
        exact(
            sq8_approval["runId"],
            sq8_source["runId"],
            "SQ8 approval/source run ID",
        )
        exact(
            sq8_approval["runAttempt"],
            sq8_source["runAttempt"],
            "SQ8 approval/source run attempt",
        )
        if sq8_approval["candidateArtifactId"] == sq8_source["artifact"]["id"]:
            fail("SQ8 candidate and reviewed artifacts must be distinct")
        exact(
            receipts["SQ7"]["facts"]["reviewedAt"],
            receipts["SQ6"]["facts"]["reviewedAt"],
            "SQ6/SQ7 common review timestamp",
        )
        exact(
            receipts["SQ8"]["facts"]["reviewedAt"],
            receipts["SQ6"]["facts"]["reviewedAt"],
            "SQ6/SQ8 common review timestamp",
        )
        exact(
            receipts["SQ8"]["facts"]["submissionFieldsDigest"],
            receipts["SQ6"]["facts"]["submissionFieldsDigest"],
            "SQ6/SQ8 submission fields digest",
        )
        exact(
            receipts["SQ8"]["facts"]["testingInstructionsDigest"],
            receipts["SQ6"]["facts"]["testingInstructionsDigest"],
            "SQ6/SQ8 testing instructions digest",
        )
        exact(
            receipts["SQ8"]["facts"]["submissionClaimsDigest"],
            receipts["SQ6"]["facts"]["claimsDigest"],
            "SQ6/SQ8 submission claims digest",
        )
        exact(
            receipts["SQ8"]["facts"]["videoClaimsDigest"],
            receipts["SQ7"]["facts"]["claimsDigest"],
            "SQ7/SQ8 video claims digest",
        )
    if "SQ11" in receipts:
        sq11 = receipts["SQ11"]["facts"]
        if "SQ3" in receipts:
            exact(
                sq11["applicationUrl"],
                receipts["SQ3"]["facts"]["applicationUrl"],
                "SQ3/SQ11 application URL",
            )
        if "SQ4" in receipts:
            exact(
                sq11["applicationAuthenticationRequired"],
                receipts["SQ4"]["facts"]["authenticationRequired"],
                "SQ4/SQ11 application authentication mode",
            )
        if "SQ5" in receipts:
            exact(
                sq11["repositoryUrl"],
                receipts["SQ5"]["facts"]["repositoryUrl"],
                "SQ5/SQ11 repository URL",
            )
        if "SQ6" in receipts:
            for sq11_key, sq6_key in {
                "submissionFieldsDigest": "submissionFieldsDigest",
                "testingInstructionsDigest": "testingInstructionsDigest",
                "submissionClaimsDigest": "claimsDigest",
            }.items():
                exact(
                    sq11[sq11_key],
                    receipts["SQ6"]["facts"][sq6_key],
                    f"SQ6/SQ11 {sq11_key}",
                )
        if "SQ7" in receipts:
            exact(
                sq11["videoUrl"],
                receipts["SQ7"]["facts"]["videoUrl"],
                "SQ7/SQ11 video URL",
            )
            exact(
                sq11["videoClaimsDigest"],
                receipts["SQ7"]["facts"]["claimsDigest"],
                "SQ7/SQ11 video claims digest",
            )
        if "SQ8" in receipts:
            exact(
                sq11["submissionClaimsDigest"],
                receipts["SQ8"]["facts"]["submissionClaimsDigest"],
                "SQ8/SQ11 submission claims digest",
            )
            exact(
                {
                    key: sq11["rules"][key]
                    for key in (
                        "officialRulesUrl",
                        "snapshotDigest",
                        "submissionStart",
                        "submissionEnd",
                    )
                },
                receipts["SQ8"]["facts"]["rules"],
                "SQ8/SQ11 official rules binding",
            )


def upstream_envelope(
    source_dir: Path, proof_id: str, repository: str, release: str
) -> tuple[dict[str, Any], Path]:
    path = source_dir / "proofs" / f"{proof_id}.json"
    envelope = exact_keys(
        load_json(path, f"upstream {proof_id}"),
        {
            "schemaVersion",
            "id",
            "repository",
            "releaseSha",
            "facts",
            "supportSubjects",
        },
        f"upstream {proof_id}",
    )
    exact(envelope["schemaVersion"], UPSTREAM_SCHEMA, f"upstream {proof_id}.schemaVersion")
    exact(envelope["id"], proof_id, f"upstream {proof_id}.id")
    exact(envelope["repository"], repository, f"upstream {proof_id}.repository")
    exact(envelope["releaseSha"], release, f"upstream {proof_id}.releaseSha")
    return envelope, path


def common_receipt(
    proof_id: str,
    facts: dict[str, Any],
    source_registry: dict[str, Any],
    repository: str,
    release: str,
    run_id: int,
    run_attempt: int,
    artifact_id: int,
    artifact_name_value: str,
    artifact_digest: str,
    predicate_digest: str,
    subject_set_digest: str,
    verification_set_digest: str,
    subjects: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "schemaVersion": RECEIPT_SCHEMA,
        "id": proof_id,
        "criterion": PROOF_CRITERIA[proof_id],
        "repository": repository,
        "releaseSha": release,
        "source": {
            "workflowPath": source_registry["workflowPath"],
            "runId": run_id,
            "runAttempt": run_attempt,
            "artifact": {
                "id": artifact_id,
                "name": artifact_name_value,
                "digest": artifact_digest,
            },
            "attestation": {
                "predicateType": source_registry["predicateType"],
                "predicateDigest": predicate_digest,
                "subjectSetDigest": subject_set_digest,
                "verificationSetDigest": verification_set_digest,
                "subjects": subjects,
            },
        },
        "facts": facts,
    }


def prefixed(value: Any, label: str) -> str:
    return "sha256:" + raw_sha256(value, label)


def derive_live(
    source_dir: Path,
    source_registry: dict[str, Any],
    repository: str,
    release: str,
    run_id: int,
    run_attempt: int,
    artifact_id: int,
    artifact_name_value: str,
    artifact_digest: str,
    predicate_digest: str,
    subject_set_digest: str,
    verification_set_digest: str,
) -> list[dict[str, Any]]:
    source_inventory = load_checksum_inventory(
        source_dir / source_registry["subjectInventory"],
        source_registry["subjectInventory"],
        "live subject inventory",
    )
    exact(
        subject_set_digest,
        checksum_subject_set_digest(source_inventory),
        "live subjectSetDigest",
    )
    proof_path = source_dir / "proof.json"
    semantic_path = source_dir / "deployed-datahub-semantic-proof.json"
    deployment_path = source_dir / "deployment-evidence.json"
    predicate_path = source_dir / "attestation-predicate.json"

    proof = exact_keys(
        load_json(proof_path, "live proof"),
        {
            "schemaVersion",
            "ok",
            "result",
            "querySha256",
            "datasetUrnSha256",
            "datasetsDiscovered",
            "aspectHistories",
            "retainedHistories",
            "stableSourceCount",
            "recoveredContradictions",
            "contradictionAttributeCount",
            "runtimeBinding",
            "governedWrite",
        },
        "live proof",
    )
    exact(
        proof["schemaVersion"],
        "archon.live-datahub-proof/v3",
        "live proof.schemaVersion",
    )
    exact(proof["ok"], True, "live proof.ok")
    exact(
        proof["result"],
        "retained-history-contradiction-proven",
        "live proof.result",
    )
    raw_sha256(proof["querySha256"], "live proof.querySha256")
    dataset_digest = prefixed(
        proof["datasetUrnSha256"],
        "live proof.datasetUrnSha256",
    )
    exact(proof["datasetsDiscovered"], 1, "live proof.datasetsDiscovered")
    positive_int(proof["aspectHistories"], "live proof.aspectHistories")
    exact(proof["retainedHistories"], 1, "live proof.retainedHistories")
    exact(proof["stableSourceCount"], 2, "live proof.stableSourceCount")
    exact(
        proof["recoveredContradictions"],
        1,
        "live proof.recoveredContradictions",
    )
    exact(
        proof["contradictionAttributeCount"],
        1,
        "live proof.contradictionAttributeCount",
    )
    runtime_binding = exact_keys(
        proof["runtimeBinding"],
        {
            "profileId",
            "availability",
            "generation",
            "capabilityDigest",
            "bindingDigest",
        },
        "live proof.runtimeBinding",
    )
    exact(
        runtime_binding["profileId"],
        "cloud",
        "live proof.runtimeBinding.profileId",
    )
    exact(
        runtime_binding["availability"],
        "READY",
        "live proof.runtimeBinding.availability",
    )
    nonempty(
        runtime_binding["generation"],
        "live proof.runtimeBinding.generation",
        128,
    )
    sha256_digest(
        runtime_binding["capabilityDigest"],
        "live proof.runtimeBinding.capabilityDigest",
    )
    sha256_digest(
        runtime_binding["bindingDigest"],
        "live proof.runtimeBinding.bindingDigest",
    )
    governed_write = exact_keys(
        proof["governedWrite"],
        {
            "workflowRunId",
            "result",
            "rollbackSubjectDigest",
            "rollbackEvidenceDigest",
            "attestationPredicateDigest",
            "attestationVerificationDigest",
        },
        "live proof.governedWrite",
    )
    positive_int(
        governed_write["workflowRunId"],
        "live proof.governedWrite.workflowRunId",
    )
    exact(
        governed_write["result"],
        "write-verified-and-rollback-proven",
        "live proof.governedWrite.result",
    )
    for key in (
        "rollbackSubjectDigest",
        "rollbackEvidenceDigest",
        "attestationPredicateDigest",
        "attestationVerificationDigest",
    ):
        sha256_digest(
            governed_write[key],
            f"live proof.governedWrite.{key}",
        )

    semantic = exact_keys(
        load_json(semantic_path, "deployed semantic proof"),
        {
            "schemaVersion",
            "evidenceClass",
            "classification",
            "findings",
        },
        "deployed semantic proof",
    )
    exact(
        semantic["schemaVersion"],
        "archon.deployed-datahub-semantic-proof/v2",
        "deployed semantic proof.schemaVersion",
    )
    exact(
        semantic["evidenceClass"],
        "credentialed-live-cloud",
        "deployed semantic proof.evidenceClass",
    )

    deployment = exact_keys(
        load_json(deployment_path, "deployment evidence"),
        {
            "schemaVersion",
            "stage",
            "releaseSha",
            "ciRunId",
            "deploymentRunId",
            "applicationUrl",
            "promotion",
            "verification",
            "secretsProjected",
            "generatedAt",
        },
        "deployment evidence",
    )
    exact(
        deployment["schemaVersion"],
        "archon.aws-deployment-evidence/v2",
        "deployment evidence.schemaVersion",
    )
    exact(deployment["stage"], "production", "deployment evidence.stage")
    exact(
        deployment["releaseSha"],
        release,
        "deployment evidence.releaseSha",
    )
    positive_int(deployment["ciRunId"], "deployment evidence.ciRunId")
    deployment_run = positive_int(
        deployment["deploymentRunId"],
        "deployment evidence.deploymentRunId",
    )
    application_url = public_https_url(
        deployment["applicationUrl"],
        "deployment evidence.applicationUrl",
        origin_only=True,
    )
    promotion = exact_keys(
        deployment["promotion"],
        {
            "policy",
            "webArtifactDigest",
            "lambdaArtifactDigest",
            "cloudRuntimeReleaseDigest",
            "coreCapabilityDigest",
            "coreImageManifestDigest",
        },
        "deployment evidence.promotion",
    )
    exact(
        promotion["policy"],
        "build-once-promote-exact-artifacts",
        "deployment evidence.promotion.policy",
    )
    for key in (
        "webArtifactDigest",
        "lambdaArtifactDigest",
        "cloudRuntimeReleaseDigest",
        "coreCapabilityDigest",
        "coreImageManifestDigest",
    ):
        sha256_digest(
            promotion[key],
            f"deployment evidence.promotion.{key}",
        )
    verification = exact_keys(
        deployment["verification"],
        {
            "result",
            "zeroIdleCore",
            "httpBoundary",
            "securityHeaders",
            "directApiRejected",
            "canonicalHostEnforced",
            "observationSha256",
        },
        "deployment evidence.verification",
    )
    exact(
        verification["result"],
        "passed",
        "deployment evidence.verification.result",
    )
    for key in (
        "zeroIdleCore",
        "httpBoundary",
        "securityHeaders",
        "directApiRejected",
        "canonicalHostEnforced",
    ):
        exact(
            verification[key],
            True,
            f"deployment evidence.verification.{key}",
        )
    raw_sha256(
        verification["observationSha256"],
        "deployment evidence.verification.observationSha256",
    )
    exact(
        deployment["secretsProjected"],
        False,
        "deployment evidence.secretsProjected",
    )
    fresh(
        deployment["generatedAt"],
        "deployment evidence.generatedAt",
        dt.timedelta(days=7),
    )

    predicate = exact_keys(
        load_json(predicate_path, "live predicate"),
        {
            "schemaVersion",
            "repository",
            "workflow",
            "releaseSha",
            "deploymentRunId",
            "governedCanaryRunId",
            "provenAt",
            "querySha256",
            "runtimeBinding",
            "evidence",
            "result",
            "datasetUrnSha256",
        },
        "live predicate",
    )
    exact(
        predicate["schemaVersion"],
        source_registry["predicateSchemaVersion"],
        "live predicate.schemaVersion",
    )
    exact(predicate["repository"], repository, "live predicate.repository")
    exact(
        predicate["workflow"],
        {"runId": str(run_id), "runAttempt": str(run_attempt)},
        "live predicate.workflow",
    )
    exact(predicate["releaseSha"], release, "live predicate.releaseSha")
    exact(
        predicate["deploymentRunId"],
        str(deployment_run),
        "live predicate.deploymentRunId",
    )
    exact(
        predicate["governedCanaryRunId"],
        str(governed_write["workflowRunId"]),
        "live predicate.governedCanaryRunId",
    )
    proven_at = nonempty(predicate["provenAt"], "live predicate.provenAt", 40)
    fresh(proven_at, "live predicate.provenAt", dt.timedelta(days=7))
    exact(
        predicate["querySha256"],
        proof["querySha256"],
        "live predicate.querySha256",
    )
    exact(
        predicate["runtimeBinding"],
        runtime_binding,
        "live predicate.runtimeBinding",
    )
    exact(predicate["result"], proof["result"], "live predicate.result")
    exact(
        predicate["datasetUrnSha256"],
        proof["datasetUrnSha256"],
        "live predicate.datasetUrnSha256",
    )
    evidence = exact_keys(
        predicate["evidence"],
        {
            "proofSha256",
            "deploymentEvidenceSha256",
            "deployedDataHubSemanticProofSha256",
        },
        "live predicate.evidence",
    )
    for key, path in {
        "proofSha256": proof_path,
        "deploymentEvidenceSha256": deployment_path,
        "deployedDataHubSemanticProofSha256": semantic_path,
    }.items():
        exact(
            evidence[key],
            sha256_file(path).removeprefix("sha256:"),
            f"live predicate.evidence.{key}",
        )
    exact(
        predicate_digest,
        sha256_file(predicate_path),
        "live predicate digest",
    )

    d4_facts = {
        "applicationUrl": application_url,
        "evidenceClass": "LIVE_DEPLOYED_DATAHUB",
        "liveDataHubRead": True,
        "retainedHistoryRead": True,
        "stableSourceCount": proof["stableSourceCount"],
        "recoveredContradictions": proof["recoveredContradictions"],
        "governedWrite": governed_write,
        "provenAt": proven_at,
    }
    u3_facts = {
        "evidenceClass": "LIVE_DEPLOYED_DATAHUB",
        "datasetUrnDigest": dataset_digest,
        "classification": semantic["classification"],
        "findings": semantic["findings"],
        "provenAt": proven_at,
    }
    validate_facts("D4", d4_facts, release)
    validate_facts("U3", u3_facts, release)
    d4_subjects = resolved_support_subjects(
        source_dir,
        source_registry,
        "D4",
        repository,
        release,
        None,
    )
    u3_subjects = resolved_support_subjects(
        source_dir,
        source_registry,
        "U3",
        repository,
        release,
        None,
    )
    return [
        common_receipt(
            "D4",
            d4_facts,
            source_registry,
            repository,
            release,
            run_id,
            run_attempt,
            artifact_id,
            artifact_name_value,
            artifact_digest,
            predicate_digest,
            subject_set_digest,
            verification_set_digest,
            d4_subjects,
        ),
        common_receipt(
            "U3",
            u3_facts,
            source_registry,
            repository,
            release,
            run_id,
            run_attempt,
            artifact_id,
            artifact_name_value,
            artifact_digest,
            predicate_digest,
            subject_set_digest,
            verification_set_digest,
            u3_subjects,
        ),
    ]

def standard_subject_names(
    source_registry: dict[str, Any],
) -> set[str]:
    exact(
        source_registry["mode"],
        "standard-v1",
        "standard source mode",
    )
    names = [source_registry["predicateFile"]]
    for proof_id in sorted(source_registry["proofIds"]):
        names.append(f"proofs/{proof_id}.json")
        names.extend(
            configured["name"]
            for configured in configured_support_rows(
                source_registry,
                proof_id,
            )
        )
    if (
        len(names) != len(set(names))
        or source_registry["subjectInventory"] in names
    ):
        fail("standard source registry contains colliding artifact paths")
    return set(names)


def validate_standard_source(
    source_dir: Path,
    source_registry: dict[str, Any],
    repository: str,
    release: str,
    run_id: int,
    run_attempt: int,
    notice_path: Path,
) -> dict[str, Any]:
    """Validate one complete standard producer artifact before attestation."""

    exact(source_registry["mode"], "standard-v1", "standard source mode")
    exact(repository, REPOSITORY, "standard source repository")
    release_sha(release)
    positive_int(run_id, "standard source runId")
    positive_int(run_attempt, "standard source runAttempt")
    if (
        not source_dir.is_dir()
        or source_dir.is_symlink()
        or not notice_path.is_file()
        or notice_path.is_symlink()
        or notice_path.name != "NOTICE.md"
    ):
        fail("standard source and NOTICE must be regular canonical paths")

    inventory_name = source_registry["subjectInventory"]
    expected_subject_names = standard_subject_names(source_registry)
    expected_files = expected_subject_names | {inventory_name}
    exact_retained_tree(source_dir, expected_files, "standard source")
    source_inventory = load_checksum_inventory(
        source_dir / inventory_name,
        inventory_name,
        "standard subject inventory",
    )
    exact(
        set(source_inventory),
        expected_subject_names,
        "standard subject inventory names",
    )
    actual_inventory_text = (
        source_dir / inventory_name
    ).read_text(encoding="utf-8")
    exact(
        actual_inventory_text,
        checksum_inventory_text(source_inventory),
        "standard subject inventory canonical order",
    )
    for name, expected_digest in source_inventory.items():
        exact(
            sha256_file(source_dir / name),
            expected_digest,
            f"standard subject inventory digest for {name}",
        )

    envelopes: dict[
        str,
        tuple[dict[str, Any], Path, list[dict[str, str]]],
    ] = {}
    for proof_id in sorted(source_registry["proofIds"]):
        envelope, path = upstream_envelope(
            source_dir,
            proof_id,
            repository,
            release,
        )
        validate_facts(
            proof_id,
            envelope["facts"],
            release,
            notice_path=notice_path,
        )
        if proof_id == "BONUS-FEEDBACK":
            approval = record(
                envelope["facts"]["reviewApproval"],
                "BONUS-FEEDBACK.facts.reviewApproval",
            )
            exact(
                approval["runId"],
                run_id,
                "BONUS-FEEDBACK.facts.reviewApproval.runId",
            )
            exact(
                approval["runAttempt"],
                run_attempt,
                "BONUS-FEEDBACK.facts.reviewApproval.runAttempt",
            )
        support_subjects = resolved_support_subjects(
            source_dir,
            source_registry,
            proof_id,
            repository,
            release,
            envelope["facts"],
        )
        exact(
            envelope["supportSubjects"],
            support_subjects,
            f"upstream {proof_id}.supportSubjects",
        )
        envelopes[proof_id] = (envelope, path, support_subjects)

    predicate_path = source_dir / source_registry["predicateFile"]
    predicate = exact_keys(
        load_json(predicate_path, "upstream predicate"),
        {
            "schemaVersion",
            "repository",
            "releaseSha",
            "source",
            "proofs",
            "result",
        },
        "upstream predicate",
    )
    exact(
        predicate["schemaVersion"],
        UPSTREAM_PREDICATE_SCHEMA,
        "upstream predicate.schemaVersion",
    )
    exact(predicate["repository"], repository, "upstream predicate.repository")
    exact(predicate["releaseSha"], release, "upstream predicate.releaseSha")
    exact(
        predicate["source"],
        {
            "workflowPath": source_registry["workflowPath"],
            "runId": run_id,
            "runAttempt": run_attempt,
        },
        "upstream predicate.source",
    )
    expected_proofs = [
        {
            "id": proof_id,
            "subjects": [
                {
                    "role": "proof-envelope",
                    "name": f"proofs/{proof_id}.json",
                    "digest": sha256_file(path),
                },
                *support_subjects,
            ],
        }
        for proof_id, (_, path, support_subjects) in sorted(envelopes.items())
    ]
    exact(predicate["proofs"], expected_proofs, "upstream predicate.proofs")
    exact(predicate["result"], "verified", "upstream predicate.result")

    return {
        "envelopes": envelopes,
        "predicate": predicate,
        "predicateDigest": sha256_file(predicate_path),
        "subjectSetDigest": checksum_subject_set_digest(source_inventory),
        "subjectCount": len(source_inventory),
    }


def derive_standard(
    source_dir: Path,
    source_registry: dict[str, Any],
    repository: str,
    release: str,
    run_id: int,
    run_attempt: int,
    artifact_id: int,
    artifact_name_value: str,
    artifact_digest: str,
    predicate_digest: str,
    subject_set_digest: str,
    verification_set_digest: str,
    notice_path: Path | None,
) -> list[dict[str, Any]]:
    if notice_path is None:
        fail("standard sources require the exact NOTICE path")
    validated = validate_standard_source(
        source_dir,
        source_registry,
        repository,
        release,
        run_id,
        run_attempt,
        notice_path,
    )
    exact(
        subject_set_digest,
        validated["subjectSetDigest"],
        "standard subjectSetDigest",
    )
    exact(
        predicate_digest,
        validated["predicateDigest"],
        "upstream predicate digest",
    )
    envelopes = validated["envelopes"]

    receipts = []
    for proof_id, (envelope, path, support_subjects) in sorted(envelopes.items()):
        receipts.append(
            common_receipt(
                proof_id,
                envelope["facts"],
                source_registry,
                repository,
                release,
                run_id,
                run_attempt,
                artifact_id,
                artifact_name_value,
                artifact_digest,
                predicate_digest,
                subject_set_digest,
                verification_set_digest,
                [
                    {
                        "role": "proof-envelope",
                        "name": f"proofs/{proof_id}.json",
                        "digest": sha256_file(path),
                    },
                    *support_subjects,
                ],
            )
        )
    return receipts


def derive_command(args: argparse.Namespace) -> None:
    registry, sources = load_registry(args.registry)
    if args.source_key not in sources:
        fail(f"source key {args.source_key!r} is not registered")
    source = sources[args.source_key]
    repository = nonempty(args.repository, "repository", 180)
    exact(repository, registry["repository"], "repository")
    release = release_sha(args.release_sha)
    run_id = positive_int(args.run_id, "runId")
    run_attempt = positive_int(args.run_attempt, "runAttempt")
    artifact_id = positive_int(args.artifact_id, "artifactId")
    expected_artifact_name = artifact_name(source, release, run_attempt)
    exact(args.artifact_name, expected_artifact_name, "artifactName")
    artifact_digest = sha256_digest(args.artifact_digest, "artifactDigest")
    predicate_digest = sha256_digest(args.predicate_digest, "predicateDigest")
    subject_set_digest = sha256_digest(
        args.subject_set_digest,
        "subjectSetDigest",
    )
    verification_set_digest = sha256_digest(
        args.verification_set_digest,
        "verificationSetDigest",
    )
    source_dir = args.source_dir.resolve(strict=True)
    receipt_dir = args.receipt_dir.resolve()
    if receipt_dir.exists() and not receipt_dir.is_dir():
        fail("receipt-dir must be a directory")
    receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    notice_path = args.notice.resolve(strict=True) if args.notice else None
    if source["mode"] == "native-live-v4":
        receipts = derive_live(
            source_dir,
            source,
            repository,
            release,
            run_id,
            run_attempt,
            artifact_id,
            args.artifact_name,
            artifact_digest,
            predicate_digest,
            subject_set_digest,
            verification_set_digest,
        )
    else:
        receipts = derive_standard(
            source_dir,
            source,
            repository,
            release,
            run_id,
            run_attempt,
            artifact_id,
            args.artifact_name,
            artifact_digest,
            predicate_digest,
            subject_set_digest,
            verification_set_digest,
            notice_path,
        )
    for receipt in receipts:
        validate_receipt(
            receipt,
            sources,
            repository,
            release,
            notice_path=notice_path,
        )
        write_json(receipt_dir / f"{receipt['id']}.json", receipt)


def load_receipt_directory(
    receipt_dir: Path,
    sources: dict[str, dict[str, Any]],
    repository: str,
    release: str,
    notice_path: Path | None,
) -> dict[str, dict[str, Any]]:
    if not receipt_dir.is_dir() or receipt_dir.is_symlink():
        fail("receipt directory must be a regular directory")
    entries = sorted(receipt_dir.iterdir(), key=lambda candidate: candidate.name)
    expected_names = {f"{proof_id}.json" for proof_id in PROOF_CRITERIA}
    for entry in entries:
        if (
            entry.name not in expected_names
            or not entry.is_file()
            or entry.is_symlink()
        ):
            fail(
                "receipt directory may contain only regular registered "
                f"<proof-id>.json files; rejected {entry.name!r}"
            )
    paths = entries
    if not paths:
        fail("receipt directory is empty")
    receipts: dict[str, dict[str, Any]] = {}
    for path in paths:
        receipt = validate_receipt(
            load_json(path, f"receipt {path.name}"),
            sources,
            repository,
            release,
            notice_path=notice_path,
        )
        proof_id = receipt["id"]
        if path.name != f"{proof_id}.json":
            fail(f"receipt filename {path.name} does not match ID {proof_id}")
        if proof_id in receipts:
            fail(f"duplicate receipt {proof_id}")
        receipts[proof_id] = receipt
    unknown = set(receipts) - set(PROOF_CRITERIA)
    if unknown:
        fail(f"unknown receipts: {sorted(unknown)}")
    cross_validate(receipts)
    return receipts


def load_checksum_inventory(
    path: Path,
    inventory_name: str,
    label: str,
) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular file")
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        fail(f"{label} must be strict UTF-8: {error}")
    if not raw.endswith("\n") or "\r" in raw:
        fail(f"{label} must be newline-terminated canonical text")
    lines = raw.splitlines()
    if not 1 <= len(lines) <= 512:
        fail(f"{label} must contain 1..512 subjects")
    subjects: dict[str, str] = {}
    for index, line in enumerate(lines):
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)",
            line,
        )
        if match is None:
            fail(f"{label}[{index}] is not a canonical checksum row")
        name = safe_relative_name(match.group(2), f"{label}[{index}].name")
        if name == inventory_name or name in subjects:
            fail(f"{label}[{index}] is self-referential or duplicated")
        subjects[name] = "sha256:" + match.group(1)
    return subjects


def checksum_inventory_text(subjects: dict[str, str]) -> str:
    rows: list[str] = []
    for name, digest in sorted(subjects.items()):
        safe_relative_name(name, "checksum inventory subject name")
        sha256_digest(digest, f"checksum inventory digest for {name}")
        rows.append(f"{digest.removeprefix('sha256:')}  {name}\n")
    if not 1 <= len(rows) <= 512:
        fail("checksum inventory must contain 1..512 subjects")
    return "".join(rows)


def checksum_subject_set_digest(subjects: dict[str, str]) -> str:
    return sha256_text(checksum_inventory_text(subjects))


def attestation_subjects(subjects: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "digest": {"sha256": digest.removeprefix("sha256:")},
        }
        for name, digest in sorted(subjects.items())
    ]


def exact_retained_tree(
    root: Path,
    expected_files: set[str],
    label: str,
) -> None:
    if not root.is_dir() or root.is_symlink():
        fail(f"{label} must be a regular directory")
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for entry in root.rglob("*"):
        relative = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            fail(f"{label} contains symlink {relative!r}")
        if entry.is_dir():
            actual_directories.add(relative)
        elif entry.is_file():
            actual_files.add(relative)
        else:
            fail(f"{label} contains non-regular entry {relative!r}")
    expected_directories: set[str] = set()
    for name in expected_files:
        parts = name.split("/")[:-1]
        for count in range(1, len(parts) + 1):
            expected_directories.add("/".join(parts[:count]))
    exact(actual_files, expected_files, f"{label} file inventory")
    exact(actual_directories, expected_directories, f"{label} directory inventory")


def retained_file_set_digest(root: Path, names: set[str]) -> str:
    projection = "".join(
        f"{sha256_file(root / name).removeprefix('sha256:')}  {name}\n"
        for name in sorted(names)
    )
    return sha256_text(projection)


def canonical_capture_timestamp(value: str | None = None) -> str:
    if value is None:
        value = (
            dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    observed = fresh(value, "standard capture timestamp", dt.timedelta(days=7))
    exact(
        value,
        observed.replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "standard capture timestamp",
    )
    return value


def load_standard_facts(
    facts_dir: Path,
    source_registry: dict[str, Any],
    release: str,
    notice_path: Path,
) -> dict[str, dict[str, Any]]:
    if not facts_dir.is_dir() or facts_dir.is_symlink():
        fail("standard facts directory must be a regular directory")
    expected_files = {
        f"{proof_id}.json" for proof_id in source_registry["proofIds"]
    }
    exact_retained_tree(facts_dir, expected_files, "standard facts directory")
    facts_by_id: dict[str, dict[str, Any]] = {}
    for proof_id in sorted(source_registry["proofIds"]):
        facts = record(
            load_json(facts_dir / f"{proof_id}.json", f"{proof_id} facts"),
            f"{proof_id} facts",
        )
        validate_facts(
            proof_id,
            facts,
            release,
            notice_path=notice_path,
        )
        facts_by_id[proof_id] = facts
    return facts_by_id


def standard_support_subject_value(
    proof_id: str,
    role: str,
    facts: dict[str, Any],
    repository: str,
    release: str,
    captured_at: str,
) -> dict[str, Any]:
    bindings = expected_support_bindings(proof_id, role, facts)
    data = [
        {
            "schemaVersion": SUPPORT_RECORD_SCHEMA,
            "recordType": role,
            "observedAt": captured_at,
            "evidence": bindings,
        }
    ]
    capture_bytes = canonical_json_text(data).encode("utf-8")
    return {
        "schemaVersion": SUPPORT_SCHEMA,
        "proofId": proof_id,
        "role": role,
        "repository": repository,
        "releaseSha": release,
        "factsDigest": canonical_json_digest(facts),
        "capture": {
            "schemaVersion": SUPPORT_CAPTURE_SCHEMA,
            "capturedAt": captured_at,
            "digest": sha256_bytes(capture_bytes),
            "sizeBytes": len(capture_bytes),
            "recordCount": 1,
            "data": data,
        },
        "sanitized": True,
        "bindings": bindings,
    }


def assemble_standard_source(
    output_dir: Path,
    facts_dir: Path,
    source_registry: dict[str, Any],
    repository: str,
    release: str,
    run_id: int,
    run_attempt: int,
    notice_path: Path,
    *,
    captured_at: str | None = None,
) -> dict[str, Any]:
    exact(source_registry["mode"], "standard-v1", "standard source mode")
    exact(repository, REPOSITORY, "standard source repository")
    release_sha(release)
    positive_int(run_id, "standard source runId")
    positive_int(run_attempt, "standard source runAttempt")
    if (
        not notice_path.is_file()
        or notice_path.is_symlink()
        or notice_path.name != "NOTICE.md"
    ):
        fail("standard source NOTICE must be a regular canonical path")
    if (
        not output_dir.is_dir()
        or output_dir.is_symlink()
        or any(output_dir.iterdir())
    ):
        fail("standard output directory must be a new empty regular directory")
    captured_at = canonical_capture_timestamp(captured_at)
    facts_by_id = load_standard_facts(
        facts_dir,
        source_registry,
        release,
        notice_path,
    )
    if "BONUS-FEEDBACK" in facts_by_id:
        approval = record(
            facts_by_id["BONUS-FEEDBACK"]["reviewApproval"],
            "BONUS-FEEDBACK facts.reviewApproval",
        )
        exact(
            approval["runId"],
            run_id,
            "BONUS-FEEDBACK facts.reviewApproval.runId",
        )
        exact(
            approval["runAttempt"],
            run_attempt,
            "BONUS-FEEDBACK facts.reviewApproval.runAttempt",
        )

    envelopes: dict[
        str,
        tuple[dict[str, Any], Path, list[dict[str, str]]],
    ] = {}
    for proof_id in sorted(source_registry["proofIds"]):
        facts = facts_by_id[proof_id]
        support_subjects: list[dict[str, str]] = []
        for configured in configured_support_rows(source_registry, proof_id):
            role = configured["role"]
            name = configured["name"]
            support_path = output_dir / name
            write_json(
                support_path,
                standard_support_subject_value(
                    proof_id,
                    role,
                    facts,
                    repository,
                    release,
                    captured_at,
                ),
            )
            support_subjects.append(
                {
                    "role": role,
                    "name": name,
                    "digest": sha256_file(support_path),
                }
            )

        envelope_path = output_dir / "proofs" / f"{proof_id}.json"
        envelope = {
            "schemaVersion": UPSTREAM_SCHEMA,
            "id": proof_id,
            "repository": repository,
            "releaseSha": release,
            "facts": facts,
            "supportSubjects": support_subjects,
        }
        write_json(envelope_path, envelope)
        envelopes[proof_id] = (
            envelope,
            envelope_path,
            support_subjects,
        )

    predicate = {
        "schemaVersion": UPSTREAM_PREDICATE_SCHEMA,
        "repository": repository,
        "releaseSha": release,
        "source": {
            "workflowPath": source_registry["workflowPath"],
            "runId": run_id,
            "runAttempt": run_attempt,
        },
        "proofs": [
            {
                "id": proof_id,
                "subjects": [
                    {
                        "role": "proof-envelope",
                        "name": f"proofs/{proof_id}.json",
                        "digest": sha256_file(envelope_path),
                    },
                    *support_subjects,
                ],
            }
            for proof_id, (
                _,
                envelope_path,
                support_subjects,
            ) in sorted(envelopes.items())
        ],
        "result": "verified",
    }
    write_json(output_dir / source_registry["predicateFile"], predicate)

    subject_names = standard_subject_names(source_registry)
    exact_retained_tree(
        output_dir,
        subject_names,
        "assembled standard subjects",
    )
    inventory = {
        name: sha256_file(output_dir / name)
        for name in subject_names
    }
    inventory_path = output_dir / source_registry["subjectInventory"]
    if inventory_path.exists() or inventory_path.is_symlink():
        fail("refusing to overwrite standard subject inventory")
    inventory_path.write_bytes(
        checksum_inventory_text(inventory).encode("utf-8")
    )
    return validate_standard_source(
        output_dir,
        source_registry,
        repository,
        release,
        run_id,
        run_attempt,
        notice_path,
    )


def standard_source_projection(
    source_key: str,
    source_registry: dict[str, Any],
    repository: str,
    release: str,
    run_attempt: int,
    validated: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schemaVersion": "archon.submission-standard-source-validation/v1",
        "repository": repository,
        "releaseSha": release,
        "sourceKey": source_key,
        "workflowPath": source_registry["workflowPath"],
        "artifactName": artifact_name(
            source_registry,
            release,
            run_attempt,
        ),
        "predicateType": source_registry["predicateType"],
        "predicateDigest": validated["predicateDigest"],
        "subjectSetDigest": validated["subjectSetDigest"],
        "subjectCount": validated["subjectCount"],
        "proofIds": sorted(source_registry["proofIds"]),
        "result": "verified",
    }


def resolve_regular_path(
    path: Path,
    label: str,
    *,
    directory: bool,
) -> Path:
    if path.is_symlink():
        fail(f"{label} must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"{label} cannot be resolved: {error}")
    if (
        (directory and not resolved.is_dir())
        or (not directory and not resolved.is_file())
        or resolved.is_symlink()
    ):
        fail(f"{label} must be a regular {'directory' if directory else 'file'}")
    return resolved


def standard_command_context(
    args: argparse.Namespace,
) -> tuple[
    dict[str, Any],
    str,
    str,
    int,
    int,
    Path,
]:
    registry, sources = load_registry(args.registry)
    source_key = nonempty(args.source_key, "sourceKey", 64)
    if source_key not in sources:
        fail(f"source key {source_key!r} is not registered")
    source = sources[source_key]
    exact(source["mode"], "standard-v1", "standard source mode")
    repository = nonempty(args.repository, "repository", 180)
    exact(repository, registry["repository"], "repository")
    release = release_sha(args.release_sha)
    run_id = positive_int(args.run_id, "runId")
    run_attempt = positive_int(args.run_attempt, "runAttempt")
    notice_path = resolve_regular_path(
        args.notice,
        "NOTICE",
        directory=False,
    )
    exact(notice_path.name, "NOTICE.md", "NOTICE filename")
    return (
        source,
        repository,
        release,
        run_id,
        run_attempt,
        notice_path,
    )


def print_standard_source_projection(value: dict[str, Any]) -> None:
    print(json.dumps(value, separators=(",", ":"), sort_keys=True))


def assemble_standard_command(args: argparse.Namespace) -> None:
    (
        source,
        repository,
        release,
        run_id,
        run_attempt,
        notice_path,
    ) = standard_command_context(args)
    facts_dir = resolve_regular_path(
        args.facts_dir,
        "facts directory",
        directory=True,
    )
    output_name = nonempty(args.output_dir.name, "output directory name", 180)
    output_parent = resolve_regular_path(
        args.output_dir.parent,
        "output parent",
        directory=True,
    )
    output_dir = output_parent / output_name
    if output_dir.exists() or output_dir.is_symlink():
        fail("output directory must not already exist")

    staging_dir = Path(
        tempfile.mkdtemp(
            prefix=f".{output_name}.assembling-",
            dir=output_parent,
        )
    )
    published = False
    try:
        validated = assemble_standard_source(
            staging_dir,
            facts_dir,
            source,
            repository,
            release,
            run_id,
            run_attempt,
            notice_path,
        )
        if output_dir.exists() or output_dir.is_symlink():
            fail("output directory appeared during assembly")
        try:
            staging_dir.rename(output_dir)
        except OSError as error:
            fail(f"standard source could not be published atomically: {error}")
        published = True
    finally:
        if not published and staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)

    print_standard_source_projection(
        standard_source_projection(
            args.source_key,
            source,
            repository,
            release,
            run_attempt,
            validated,
        )
    )


def validate_standard_source_command(args: argparse.Namespace) -> None:
    (
        source,
        repository,
        release,
        run_id,
        run_attempt,
        notice_path,
    ) = standard_command_context(args)
    source_dir = resolve_regular_path(
        args.source_dir,
        "standard source directory",
        directory=True,
    )
    validated = validate_standard_source(
        source_dir,
        source,
        repository,
        release,
        run_id,
        run_attempt,
        notice_path,
    )
    print_standard_source_projection(
        standard_source_projection(
            args.source_key,
            source,
            repository,
            release,
            run_attempt,
            validated,
        )
    )


def validate_gh_verification(
    path: Path,
    repository: str,
    release: str,
    proof_id: str,
    role: str,
    predicate_type: str,
    predicate_digest: str,
    predicate: dict[str, Any],
    subject_name: str,
    subject_digest: str,
    expected_subjects: list[dict[str, Any]],
    label: str,
) -> None:
    verification = exact_keys(
        load_json(path, label),
        {
            "schemaVersion",
            "repository",
            "releaseSha",
            "proofId",
            "role",
            "subject",
            "predicate",
            "statement",
        },
        label,
    )
    exact(
        verification["schemaVersion"],
        "archon.upstream-attestation-verification/v1",
        f"{label}.schemaVersion",
    )
    exact(verification["repository"], repository, f"{label}.repository")
    exact(verification["releaseSha"], release, f"{label}.releaseSha")
    exact(verification["proofId"], proof_id, f"{label}.proofId")
    exact(verification["role"], role, f"{label}.role")
    exact(
        verification["subject"],
        {"name": subject_name, "digest": subject_digest},
        f"{label}.subject",
    )
    exact(
        verification["predicate"],
        {"type": predicate_type, "digest": predicate_digest},
        f"{label}.predicate",
    )
    statement = record(verification["statement"], f"{label}.statement")
    exact(
        statement.get("predicateType"),
        predicate_type,
        f"{label}.statement.predicateType",
    )
    exact(
        statement.get("predicate"),
        predicate,
        f"{label}.statement.predicate",
    )
    raw_subjects = statement.get("subject")
    if not isinstance(raw_subjects, list):
        fail(f"{label}.statement.subject must be an array")
    normalized_subjects: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, raw_subject in enumerate(raw_subjects):
        item = exact_keys(
            raw_subject,
            {"name", "digest"},
            f"{label}.statement.subject[{index}]",
        )
        name = safe_relative_name(
            item["name"],
            f"{label}.statement.subject[{index}].name",
        )
        if name in names:
            fail(f"{label}.statement.subject contains duplicate {name!r}")
        names.add(name)
        digest = exact_keys(
            item["digest"],
            {"sha256"},
            f"{label}.statement.subject[{index}].digest",
        )
        normalized_subjects.append(
            {
                "name": name,
                "digest": {
                    "sha256": raw_sha256(
                        digest["sha256"],
                        f"{label}.statement.subject[{index}].digest.sha256",
                    )
                },
            }
        )
    exact(
        sorted(normalized_subjects, key=lambda subject: subject["name"]),
        expected_subjects,
        f"{label}.statement.subject exact inventory",
    )


def revalidate_retained_sources(
    receipt_dir: Path,
    receipts: dict[str, dict[str, Any]],
    sources: dict[str, dict[str, Any]],
    repository: str,
    release: str,
    notice_path: Path | None,
) -> None:
    aggregate_root = receipt_dir.parent
    receipts_by_source: dict[str, dict[str, dict[str, Any]]] = {}
    for proof_id, receipt in receipts.items():
        source_registry = source_for_proof(proof_id, sources)
        source_key = source_registry["key"]
        receipts_by_source.setdefault(source_key, {})[proof_id] = receipt

    for source_key, source_receipts in sorted(receipts_by_source.items()):
        source_registry = sources[source_key]
        exact(
            set(source_receipts),
            set(source_registry["proofIds"]),
            f"{source_key} retained receipt inventory",
        )
        first_receipt = source_receipts[source_registry["proofIds"][0]]
        common_source = first_receipt["source"]
        expected_common = {
            "workflowPath": common_source["workflowPath"],
            "runId": common_source["runId"],
            "runAttempt": common_source["runAttempt"],
            "artifact": common_source["artifact"],
            "predicateType": common_source["attestation"]["predicateType"],
            "predicateDigest": common_source["attestation"]["predicateDigest"],
            "subjectSetDigest": common_source["attestation"][
                "subjectSetDigest"
            ],
            "verificationSetDigest": common_source["attestation"][
                "verificationSetDigest"
            ],
        }
        for proof_id, receipt in source_receipts.items():
            receipt_source = receipt["source"]
            exact(
                {
                    "workflowPath": receipt_source["workflowPath"],
                    "runId": receipt_source["runId"],
                    "runAttempt": receipt_source["runAttempt"],
                    "artifact": receipt_source["artifact"],
                    "predicateType": receipt_source["attestation"]["predicateType"],
                    "predicateDigest": receipt_source["attestation"][
                        "predicateDigest"
                    ],
                    "subjectSetDigest": receipt_source["attestation"][
                        "subjectSetDigest"
                    ],
                    "verificationSetDigest": receipt_source["attestation"][
                        "verificationSetDigest"
                    ],
                },
                expected_common,
                f"{source_key}/{proof_id} common source binding",
            )

        subject_root = aggregate_root / "upstream-subjects" / source_key
        verification_root = aggregate_root / "upstream-verification" / source_key
        subjects_by_name: dict[str, str] = {}
        expected_verification_files: set[str] = set()
        for proof_id, receipt in source_receipts.items():
            for subject in receipt["source"]["attestation"]["subjects"]:
                name = subject["name"]
                digest = subject["digest"]
                if name in subjects_by_name and subjects_by_name[name] != digest:
                    fail(f"{source_key} has conflicting digests for retained {name}")
                subjects_by_name[name] = digest
                expected_verification_files.add(
                    f"{proof_id}--{subject['role']}.json"
                )
        predicate_name = source_registry["predicateFile"]
        inventory_name = source_registry["subjectInventory"]
        inventory_subjects = load_checksum_inventory(
            subject_root / inventory_name,
            inventory_name,
            f"{source_key} retained subject inventory",
        )
        subject_set_digest = checksum_subject_set_digest(inventory_subjects)
        exact(
            subject_set_digest,
            expected_common["subjectSetDigest"],
            f"{source_key} subjectSetDigest",
        )
        exact_retained_tree(
            subject_root,
            {*inventory_subjects, predicate_name, inventory_name},
            f"{source_key} retained subjects",
        )
        exact_retained_tree(
            verification_root,
            {*expected_verification_files, "binding.json"},
            f"{source_key} retained verifications",
        )
        for name, digest in inventory_subjects.items():
            exact(
                sha256_file(subject_root / name),
                digest,
                f"{source_key} inventoried subject {name} digest",
            )
        for name, digest in subjects_by_name.items():
            exact(
                inventory_subjects.get(name),
                digest,
                f"{source_key} registered subject {name} inventory binding",
            )
        predicate_path = subject_root / predicate_name
        exact(
            sha256_file(predicate_path),
            expected_common["predicateDigest"],
            f"{source_key} retained predicate digest",
        )
        predicate = record(
            load_json(predicate_path, f"{source_key} retained predicate"),
            f"{source_key} retained predicate",
        )
        verification_set_digest = retained_file_set_digest(
            verification_root,
            expected_verification_files,
        )
        exact(
            verification_set_digest,
            expected_common["verificationSetDigest"],
            f"{source_key} verificationSetDigest",
        )
        for proof_id, receipt in source_receipts.items():
            exact(
                receipt["source"]["attestation"]["subjectSetDigest"],
                subject_set_digest,
                f"{source_key}/{proof_id} receipt subjectSetDigest",
            )
            exact(
                receipt["source"]["attestation"]["verificationSetDigest"],
                verification_set_digest,
                f"{source_key}/{proof_id} receipt verificationSetDigest",
            )
            for subject in receipt["source"]["attestation"]["subjects"]:
                validate_gh_verification(
                    verification_root
                    / f"{proof_id}--{subject['role']}.json",
                    repository,
                    release,
                    proof_id,
                    subject["role"],
                    expected_common["predicateType"],
                    expected_common["predicateDigest"],
                    predicate,
                    subject["name"],
                    subject["digest"],
                    attestation_subjects(inventory_subjects),
                    f"{source_key}/{proof_id}/{subject['role']} verification",
                )

        binding = load_json(
            verification_root / "binding.json",
            f"{source_key} retained binding",
        )
        exact(
            binding,
            {
                "schemaVersion": UPSTREAM_BINDING_SCHEMA,
                "repository": repository,
                "releaseSha": release,
                "sourceKey": source_key,
                "source": {
                    "workflowPath": expected_common["workflowPath"],
                    "runId": expected_common["runId"],
                    "runAttempt": expected_common["runAttempt"],
                },
                "artifact": expected_common["artifact"],
                "attestation": {
                    "predicateType": expected_common["predicateType"],
                    "predicateDigest": expected_common["predicateDigest"],
                    "verificationSetDigest": verification_set_digest,
                    "subjectSetDigest": subject_set_digest,
                },
                "proofIds": source_registry["proofIds"],
            },
            f"{source_key} retained binding",
        )

        derivation_args = (
            subject_root,
            source_registry,
            repository,
            release,
            expected_common["runId"],
            expected_common["runAttempt"],
            expected_common["artifact"]["id"],
            expected_common["artifact"]["name"],
            expected_common["artifact"]["digest"],
            expected_common["predicateDigest"],
            subject_set_digest,
            verification_set_digest,
        )
        if source_registry["mode"] == "native-live-v4":
            derived = derive_live(*derivation_args)
        else:
            derived = derive_standard(*derivation_args, notice_path)
        exact(
            {receipt["id"]: receipt for receipt in derived},
            source_receipts,
            f"{source_key} receipts rederived from retained subjects",
        )


def build_command(args: argparse.Namespace) -> None:
    registry, sources = load_registry(args.registry)
    repository = nonempty(args.repository, "repository", 180)
    exact(repository, registry["repository"], "repository")
    release = release_sha(args.release_sha)
    run_id = positive_int(args.run_id, "runId")
    run_attempt = positive_int(args.run_attempt, "runAttempt")
    notice_path = args.notice.resolve(strict=True)
    receipt_dir = args.receipt_dir.resolve(strict=True)
    receipts = load_receipt_directory(
        receipt_dir,
        sources,
        repository,
        release,
        notice_path,
    )
    revalidate_retained_sources(
        receipt_dir,
        receipts,
        sources,
        repository,
        release,
        notice_path,
    )
    missing = REQUIRED_PROOFS - set(receipts)
    if missing:
        fail(f"required receipts are absent: {sorted(missing)}")
    unknown_optional = set(receipts) - REQUIRED_PROOFS - OPTIONAL_PROOFS
    if unknown_optional:
        fail(f"unregistered optional receipts: {sorted(unknown_optional)}")

    proofs = []
    bonuses = []
    for proof_id, receipt in sorted(receipts.items()):
        claim = {
            "id": proof_id,
            "status": "verified",
            "evidence": EVIDENCE_SUMMARIES[proof_id],
            "receipt": {
                "name": f"receipts/{proof_id}.json",
                "digest": sha256_file(receipt_dir / f"{proof_id}.json"),
            },
        }
        if proof_id in BONUS_PROOFS:
            bonuses.append(claim)
        else:
            claim["criterion"] = PROOF_CRITERIA[proof_id]
            proofs.append(claim)

    claims = {
        "schemaVersion": CLAIMS_SCHEMA,
        "repository": repository,
        "releaseSha": release,
        "proofs": proofs,
        "bonuses": bonuses,
    }
    write_json(args.claims, claims)
    receipt_projection = [
        {"id": item["id"], "receipt": item["receipt"]}
        for item in sorted(proofs + bonuses, key=lambda item: item["id"])
    ]
    canonical_projection = (
        json.dumps(
            receipt_projection,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    predicate = {
        "schemaVersion": PREDICATE_SCHEMA,
        "repository": repository,
        "releaseSha": release,
        "source": {
            "workflowPath": registry["aggregate"]["workflowPath"],
            "runId": run_id,
            "runAttempt": run_attempt,
        },
        "artifactName": registry["aggregate"]["artifactNameTemplate"]
        .replace("{releaseSha}", release)
        .replace("{runAttempt}", str(run_attempt)),
        "claimsDigest": sha256_file(args.claims),
        "receiptSetDigest": sha256_text(canonical_projection),
    }
    write_json(args.predicate, predicate)


def validate_bundle_command(args: argparse.Namespace) -> None:
    registry, sources = load_registry(args.registry)
    repository = nonempty(args.repository, "repository", 180)
    exact(repository, registry["repository"], "repository")
    release = release_sha(args.release_sha)
    notice_path = args.notice.resolve(strict=True)
    claims = exact_keys(
        load_json(args.claims, "claims"),
        {"schemaVersion", "repository", "releaseSha", "proofs", "bonuses"},
        "claims",
    )
    exact(claims["schemaVersion"], CLAIMS_SCHEMA, "claims.schemaVersion")
    exact(claims["repository"], repository, "claims.repository")
    exact(claims["releaseSha"], release, "claims.releaseSha")
    if not isinstance(claims["proofs"], list) or not isinstance(claims["bonuses"], list):
        fail("claims proofs and bonuses must be arrays")
    receipt_dir = args.receipt_dir.resolve(strict=True)
    receipts = load_receipt_directory(
        receipt_dir,
        sources,
        repository,
        release,
        notice_path,
    )
    revalidate_retained_sources(
        receipt_dir,
        receipts,
        sources,
        repository,
        release,
        notice_path,
    )
    missing = REQUIRED_PROOFS - set(receipts)
    if missing:
        fail(f"required receipts are absent: {sorted(missing)}")
    claim_ids: set[str] = set()
    for collection_name, collection, bonus in (
        ("proofs", claims["proofs"], False),
        ("bonuses", claims["bonuses"], True),
    ):
        for index, raw_claim in enumerate(collection):
            label = f"claims.{collection_name}[{index}]"
            expected_keys = {"id", "status", "evidence", "receipt"}
            if not bonus:
                expected_keys.add("criterion")
            claim = exact_keys(raw_claim, expected_keys, label)
            proof_id = nonempty(claim["id"], f"{label}.id", 32)
            if proof_id not in receipts or proof_id in claim_ids:
                fail(f"{label}.id is absent from receipts or duplicated")
            if (proof_id in BONUS_PROOFS) is not bonus:
                fail(f"{label}.id is on the wrong claims axis")
            claim_ids.add(proof_id)
            exact(claim["status"], "verified", f"{label}.status")
            exact(claim["evidence"], EVIDENCE_SUMMARIES[proof_id], f"{label}.evidence")
            if not bonus:
                exact(claim["criterion"], PROOF_CRITERIA[proof_id], f"{label}.criterion")
            receipt_ref = exact_keys(
                claim["receipt"], {"name", "digest"}, f"{label}.receipt"
            )
            exact(
                receipt_ref["name"],
                f"receipts/{proof_id}.json",
                f"{label}.receipt.name",
            )
            exact(
                receipt_ref["digest"],
                sha256_file(receipt_dir / f"{proof_id}.json"),
                f"{label}.receipt.digest",
            )
    if claim_ids != set(receipts):
        fail("claims and receipt inventory differ")
    print(
        json.dumps(
            {
                "schemaVersion": "archon.submission-proof-validation/v1",
                "repository": repository,
                "releaseSha": release,
                "validatedProofIds": sorted(receipts),
                "result": "verified",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def validate_registry_command(args: argparse.Namespace) -> None:
    registry, sources = load_registry(args.registry)
    print(
        json.dumps(
            {
                "schemaVersion": "archon.submission-evidence-registry-validation/v1",
                "repository": registry["repository"],
                "sourceKeys": sorted(sources),
                "result": "verified",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    validate_registry = commands.add_parser("validate-registry")
    validate_registry.add_argument("--registry", type=Path, required=True)
    validate_registry.set_defaults(handler=validate_registry_command)

    select_artifact = commands.add_parser("select-run-artifact")
    select_artifact.add_argument(
        "--policy",
        choices=(
            "exact-current",
            "exact-run-id",
            "single-retained",
            "latest-retained",
        ),
        required=True,
    )
    select_artifact.add_argument("--artifact-prefix", required=True)
    select_artifact.add_argument("--run-id", type=int, required=True)
    select_artifact.add_argument("--release-sha", required=True)
    select_artifact.add_argument("--maximum-attempt", type=int, required=True)
    select_artifact.set_defaults(handler=select_run_artifact_command)

    assemble_standard = commands.add_parser("assemble-standard")
    assemble_standard.add_argument("--registry", type=Path, required=True)
    assemble_standard.add_argument("--source-key", required=True)
    assemble_standard.add_argument("--facts-dir", type=Path, required=True)
    assemble_standard.add_argument("--output-dir", type=Path, required=True)
    assemble_standard.add_argument("--repository", required=True)
    assemble_standard.add_argument("--release-sha", required=True)
    assemble_standard.add_argument("--run-id", type=int, required=True)
    assemble_standard.add_argument("--run-attempt", type=int, required=True)
    assemble_standard.add_argument("--notice", type=Path, required=True)
    assemble_standard.set_defaults(handler=assemble_standard_command)

    validate_standard = commands.add_parser("validate-standard-source")
    validate_standard.add_argument("--registry", type=Path, required=True)
    validate_standard.add_argument("--source-key", required=True)
    validate_standard.add_argument("--source-dir", type=Path, required=True)
    validate_standard.add_argument("--repository", required=True)
    validate_standard.add_argument("--release-sha", required=True)
    validate_standard.add_argument("--run-id", type=int, required=True)
    validate_standard.add_argument("--run-attempt", type=int, required=True)
    validate_standard.add_argument("--notice", type=Path, required=True)
    validate_standard.set_defaults(handler=validate_standard_source_command)

    derive = commands.add_parser("derive")
    derive.add_argument("--registry", type=Path, required=True)
    derive.add_argument("--source-key", required=True)
    derive.add_argument("--source-dir", type=Path, required=True)
    derive.add_argument("--receipt-dir", type=Path, required=True)
    derive.add_argument("--repository", required=True)
    derive.add_argument("--release-sha", required=True)
    derive.add_argument("--run-id", type=int, required=True)
    derive.add_argument("--run-attempt", type=int, required=True)
    derive.add_argument("--artifact-id", type=int, required=True)
    derive.add_argument("--artifact-name", required=True)
    derive.add_argument("--artifact-digest", required=True)
    derive.add_argument("--predicate-digest", required=True)
    derive.add_argument("--subject-set-digest", required=True)
    derive.add_argument("--verification-set-digest", required=True)
    derive.add_argument("--notice", type=Path)
    derive.set_defaults(handler=derive_command)

    build = commands.add_parser("build-bundle")
    build.add_argument("--registry", type=Path, required=True)
    build.add_argument("--receipt-dir", type=Path, required=True)
    build.add_argument("--claims", type=Path, required=True)
    build.add_argument("--predicate", type=Path, required=True)
    build.add_argument("--notice", type=Path, required=True)
    build.add_argument("--repository", required=True)
    build.add_argument("--release-sha", required=True)
    build.add_argument("--run-id", type=int, required=True)
    build.add_argument("--run-attempt", type=int, required=True)
    build.set_defaults(handler=build_command)

    validate = commands.add_parser("validate-bundle")
    validate.add_argument("--registry", type=Path, required=True)
    validate.add_argument("--receipt-dir", type=Path, required=True)
    validate.add_argument("--claims", type=Path, required=True)
    validate.add_argument("--notice", type=Path, required=True)
    validate.add_argument("--repository", required=True)
    validate.add_argument("--release-sha", required=True)
    validate.set_defaults(handler=validate_bundle_command)
    return root


def main() -> int:
    try:
        args = parser().parse_args()
        args.handler(args)
        return 0
    except ContractError as error:
        print(f"submission evidence rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
