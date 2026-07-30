#!/usr/bin/env python3
"""Validate a public submission-video URL and target-bound provider metadata."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from decimal import Decimal, InvalidOperation
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit


MAX_BODY_BYTES = 10 * 1024 * 1024
OBSERVATION_KEYS = {
    "schemaVersion",
    "url",
    "provider",
    "videoId",
    "durationSeconds",
    "publiclyAccessible",
    "loggedOutAccessible",
    "httpStatus",
    "redirectsObserved",
    "responseDigest",
}
STABLE_OBSERVATION_KEYS = OBSERVATION_KEYS - {"responseDigest"}


class ValidationError(ValueError):
    """Raised when public-video evidence is not exact and target-bound."""


class ScriptCollector(HTMLParser):
    """Collect script bodies without interpreting provider JavaScript."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._current: list[str] | None = None
        self.scripts: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        del attrs
        if tag.lower() == "script" and self._current is None:
            self._current = []

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._current.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._current is not None:
            self.scripts.append("".join(self._current))
            self._current = None


def fail(message: str) -> None:
    raise ValidationError(message)


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    path.write_bytes(canonical_bytes(value))


def reject_duplicate_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def exact_video_url(url: str) -> dict[str, str]:
    if (
        not isinstance(url, str)
        or not 1 <= len(url) <= 2048
        or url != url.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in url)
    ):
        fail("video URL is empty, oversized, or contains whitespace/control bytes")
    try:
        parsed = urlsplit(url)
        explicit_port = parsed.port
    except ValueError as error:
        fail(f"video URL authority is invalid: {error}")
    if (
        parsed.scheme != "https"
        or not url.startswith("https://")
        or parsed.username is not None
        or parsed.password is not None
        or explicit_port is not None
        or parsed.hostname is None
        or parsed.netloc != parsed.hostname
    ):
        fail(
            "video URL must use canonical HTTPS with no credentials or explicit port"
        )

    host = parsed.hostname
    video_id: str
    if host == "www.youtube.com":
        match = re.fullmatch(r"/watch\?v=([A-Za-z0-9_-]{11})", parsed.path + (
            f"?{parsed.query}" if parsed.query else ""
        ))
        if match is None or parsed.fragment:
            fail("YouTube URL must be https://www.youtube.com/watch?v=<exact-id>")
        video_id = match.group(1)
        canonical_url = f"https://www.youtube.com/watch?v={video_id}"
    elif host == "vimeo.com":
        match = re.fullmatch(r"/([1-9][0-9]{4,14})", parsed.path)
        if match is None or parsed.query or parsed.fragment:
            fail("Vimeo URL must be https://vimeo.com/<exact-id>")
        video_id = match.group(1)
        canonical_url = f"https://vimeo.com/{video_id}"
    elif host == "v.youku.com":
        match = re.fullmatch(
            r"/v_show/id_([A-Za-z0-9=_-]{6,96})\.html",
            parsed.path,
        )
        if match is None or parsed.query or parsed.fragment:
            fail("Youku URL must be https://v.youku.com/v_show/id_<exact-id>.html")
        video_id = match.group(1)
        canonical_url = f"https://v.youku.com/v_show/id_{video_id}.html"
    else:
        fail("video URL host is not an exact supported provider")
    if url != canonical_url:
        fail("video URL is not the exact canonical provider URL")
    return {
        "schemaVersion": "archon.submission-video-preflight/v1",
        "url": canonical_url,
        "provider": host,
        "videoId": video_id,
    }


def decoded_json_roots(body: str) -> Iterator[Any]:
    collector = ScriptCollector()
    collector.feed(body)
    collector.close()
    stripped_body = body.strip()
    sources = list(collector.scripts)
    if stripped_body.startswith(("{", "[")):
        sources.append(stripped_body)
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicate_pairs)
    decode_attempts = 0
    for raw_source in sources:
        source = html.unescape(raw_source)
        cursor = 0
        while cursor < len(source):
            object_at = source.find("{", cursor)
            array_at = source.find("[", cursor)
            starts = [offset for offset in (object_at, array_at) if offset >= 0]
            if not starts:
                break
            start = min(starts)
            decode_attempts += 1
            if decode_attempts > 8192:
                fail("provider page contains an excessive ambiguous JSON surface")
            try:
                value, end = decoder.raw_decode(source, start)
            except json.JSONDecodeError:
                cursor = start + 1
                continue
            yield value
            cursor = max(end, start + 1)


def nested_objects(value: Any, depth: int = 0) -> Iterator[dict[str, Any]]:
    if depth > 128:
        fail("provider JSON exceeds the maximum nesting depth")
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from nested_objects(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            yield from nested_objects(child, depth + 1)
    elif isinstance(value, str):
        candidate = html.unescape(value).strip()
        if candidate.startswith(("{", "[")) and len(candidate) <= MAX_BODY_BYTES:
            try:
                decoded = json.loads(
                    candidate,
                    object_pairs_hook=reject_duplicate_pairs,
                )
            except json.JSONDecodeError:
                return
            yield from nested_objects(decoded, depth + 1)


def exact_seconds(value: Any) -> int:
    if isinstance(value, bool):
        fail("provider duration must not be boolean")
    if isinstance(value, int):
        result = value
    elif isinstance(value, float):
        if not value.is_integer():
            fail("provider duration must be an exact whole second")
        result = int(value)
    elif isinstance(value, str):
        stripped = value.strip()
        iso = re.fullmatch(
            r"PT(?:(?P<hours>[0-9]+)H)?"
            r"(?:(?P<minutes>[0-9]+)M)?"
            r"(?:(?P<seconds>[0-9]+)S)?",
            stripped,
        )
        if iso is not None and any(iso.groupdict().values()):
            result = (
                int(iso.group("hours") or 0) * 3600
                + int(iso.group("minutes") or 0) * 60
                + int(iso.group("seconds") or 0)
            )
        else:
            try:
                decimal = Decimal(stripped)
            except InvalidOperation:
                fail("provider duration is not numeric")
            if not decimal.is_finite() or decimal != decimal.to_integral_value():
                fail("provider duration must be an exact whole second")
            result = int(decimal)
    else:
        fail("provider duration has an unsupported type")
    if not 1 <= result <= 179:
        fail("target video duration must be from 1 through 179 seconds")
    return result


def direct_id_matches(node: dict[str, Any], provider: str, video_id: str) -> bool:
    if provider == "www.youtube.com":
        return node.get("videoId") == video_id
    if provider == "vimeo.com":
        id_keys = ("video_id", "clip_id", "id", "identifier")
        url_patterns = (
            rf"https://vimeo\.com/{re.escape(video_id)}",
            rf"https://player\.vimeo\.com/video/{re.escape(video_id)}",
        )
    else:
        id_keys = ("videoId", "video_id", "vid", "id")
        url_patterns = (
            rf"https://v\.youku\.com/v_show/id_{re.escape(video_id)}\.html",
        )
    if any(
        key in node
        and not isinstance(node[key], bool)
        and str(node[key]) == video_id
        for key in id_keys
    ):
        return True
    for key in ("url", "videoUrl", "video_url", "embedUrl", "embed_url"):
        value = node.get(key)
        if isinstance(value, str) and any(
            re.fullmatch(pattern, value) is not None for pattern in url_patterns
        ):
            return True
    return False


def target_duration(preflight: dict[str, str], body: str) -> int:
    provider = preflight["provider"]
    video_id = preflight["videoId"]
    objects = [
        node
        for root in decoded_json_roots(body)
        for node in nested_objects(root)
    ]
    if provider == "www.youtube.com":
        candidates = [
            node
            for node in objects
            if isinstance(node.get("videoDetails"), dict)
            and isinstance(node.get("playabilityStatus"), dict)
            and direct_id_matches(node["videoDetails"], provider, video_id)
            and "lengthSeconds" in node["videoDetails"]
        ]
        if len(candidates) != 1:
            fail("YouTube must expose one unambiguous target player-response object")
        candidate = candidates[0]
        if candidate["playabilityStatus"].get("status") != "OK":
            fail("YouTube target is not publicly playable")
        return exact_seconds(candidate["videoDetails"]["lengthSeconds"])

    duration_keys = (
        ("duration", "durationSeconds", "duration_seconds")
        if provider == "vimeo.com"
        else ("duration", "seconds", "durationSeconds", "duration_seconds")
    )
    candidates = [
        node
        for node in objects
        if direct_id_matches(node, provider, video_id)
        and any(key in node for key in duration_keys)
    ]
    if len(candidates) != 1:
        fail(f"{provider} must expose one unambiguous target metadata object")
    candidate = candidates[0]
    values = [
        exact_seconds(candidate[key])
        for key in duration_keys
        if key in candidate
    ]
    if len(set(values)) != 1:
        fail("target metadata object contains conflicting duration values")
    for key in ("private", "isPrivate", "is_private"):
        if candidate.get(key) is True:
            fail("target video metadata reports private media")
    for key in ("status", "availability", "state"):
        value = candidate.get(key)
        if isinstance(value, str) and value.lower() in {
            "blocked",
            "disabled",
            "private",
            "unavailable",
        }:
            fail("target video metadata reports unavailable media")
    if candidate.get("isAccessibleForFree") is False:
        fail("target video metadata reports credential-gated media")
    return values[0]


def observe(url: str, body_path: Path) -> dict[str, Any]:
    preflight = exact_video_url(url)
    raw = body_path.read_bytes()
    if not 1 <= len(raw) <= MAX_BODY_BYTES:
        fail("video response must contain from 1 byte through 10 MiB")
    try:
        body = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"video response is not strict UTF-8: {error}")
    return {
        "schemaVersion": "archon.submission-video-observation/v1",
        "url": preflight["url"],
        "provider": preflight["provider"],
        "videoId": preflight["videoId"],
        "durationSeconds": target_duration(preflight, body),
        "publiclyAccessible": True,
        "loggedOutAccessible": True,
        "httpStatus": 200,
        "redirectsObserved": 0,
        "responseDigest": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }


def load_observation(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if not 1 <= len(raw) <= 16384:
        fail("prepared video observation has an invalid byte length")
    value = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=reject_duplicate_pairs,
    )
    if not isinstance(value, dict) or set(value) != OBSERVATION_KEYS:
        fail("prepared video observation has missing or unknown fields")
    if canonical_bytes(value) != raw:
        fail("prepared video observation is not canonical JSON")
    preflight = exact_video_url(value["url"])
    if (
        value["schemaVersion"]
        != "archon.submission-video-observation/v1"
        or value["provider"] != preflight["provider"]
        or value["videoId"] != preflight["videoId"]
        or type(value["durationSeconds"]) is not int
        or not 1 <= value["durationSeconds"] <= 179
        or type(value["publiclyAccessible"]) is not bool
        or value["publiclyAccessible"] is not True
        or type(value["loggedOutAccessible"]) is not bool
        or value["loggedOutAccessible"] is not True
        or type(value["httpStatus"]) is not int
        or value["httpStatus"] != 200
        or type(value["redirectsObserved"]) is not int
        or value["redirectsObserved"] != 0
    ):
        fail("prepared video observation has invalid typed stable fields")
    if (
        not isinstance(value["responseDigest"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value["responseDigest"]) is None
    ):
        fail("prepared video response digest is invalid")
    return value


def command_preflight(args: argparse.Namespace) -> None:
    write_json(args.output, exact_video_url(args.url))


def command_observe(args: argparse.Namespace) -> None:
    write_json(args.output, observe(args.url, args.body))


def command_revalidate(args: argparse.Namespace) -> None:
    prepared = load_observation(args.prepared)
    current = observe(args.url, args.body)
    if any(prepared[key] != current[key] for key in STABLE_OBSERVATION_KEYS):
        fail("fresh provider metadata differs from the prepared observation")
    write_json(args.output, current)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--url", required=True)
    preflight.add_argument("--output", required=True, type=Path)
    preflight.set_defaults(handler=command_preflight)
    observe_parser = commands.add_parser("observe")
    observe_parser.add_argument("--url", required=True)
    observe_parser.add_argument("--body", required=True, type=Path)
    observe_parser.add_argument("--output", required=True, type=Path)
    observe_parser.set_defaults(handler=command_observe)
    revalidate = commands.add_parser("revalidate")
    revalidate.add_argument("--url", required=True)
    revalidate.add_argument("--body", required=True, type=Path)
    revalidate.add_argument("--prepared", required=True, type=Path)
    revalidate.add_argument("--output", required=True, type=Path)
    revalidate.set_defaults(handler=command_revalidate)
    return root


def main() -> None:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (OSError, json.JSONDecodeError, ValidationError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
