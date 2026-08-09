#!/usr/bin/env python3
"""Generate short, measured Google Cloud TTS scenes and aligned captions in CI."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import subprocess
import urllib.error
import urllib.request


ROOT = pathlib.Path(os.environ["ARCHON_VIDEO_ROOT"])
SPEC = pathlib.Path(__file__).with_name("narration.json")
OUT = ROOT / "narration"
TAIL_SECONDS = 0.65


def run(args: list[str]) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def duration(path: pathlib.Path) -> float:
    return float(
        run(
            [
                os.environ["FFPROBE"],
                "-v",
                "error",
                "-show_entries",
                "format=duration",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
                str(path),
            ]
        )
    )


def timestamp(value: float) -> str:
    millis = round(max(0.0, value) * 1000)
    hours, millis = divmod(millis, 3_600_000)
    minutes, millis = divmod(millis, 60_000)
    seconds, millis = divmod(millis, 1_000)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d},{millis:03d}"


def wrapped(text: str, width: int = 66) -> str:
    words = text.split()
    lines: list[str] = []
    line = ""
    for word in words:
        candidate = f"{line} {word}".strip()
        if line and len(candidate) > width:
            lines.append(line)
            line = word
        else:
            line = candidate
    if line:
        lines.append(line)
    if len(lines) <= 2:
        return "\n".join(lines)
    midpoint = max(1, len(words) // 2)
    return " ".join(words[:midpoint]) + "\n" + " ".join(words[midpoint:])


def synthesize(text: str, spec: dict[str, object], token: str) -> bytes:
    body = json.dumps(
        {
            "input": {"text": text},
            "voice": {
                "languageCode": spec["languageCode"],
                "name": spec["voice"],
            },
            "audioConfig": {
                "audioEncoding": "MP3",
                "speakingRate": spec["speakingRate"],
                "pitch": -1.0,
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        "https://texttospeech.googleapis.com/v1/text:synthesize",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        raise SystemExit(f"Cloud TTS failed with HTTP {error.code}") from error
    encoded = payload.get("audioContent")
    if not isinstance(encoded, str) or len(encoded) < 32:
        raise SystemExit("Cloud TTS returned no bounded audio payload")
    return base64.b64decode(encoded, validate=True)


def main() -> None:
    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    segments = spec.get("segments")
    if spec.get("schemaVersion") != "archon.submission-video/v1" or not isinstance(segments, list):
        raise SystemExit("narration contract is invalid")
    token = run(["gcloud", "auth", "print-access-token"])
    if not token or len(token) > 4096:
        raise SystemExit("bounded Google access token is unavailable")
    OUT.mkdir(parents=True, exist_ok=False)
    timing: list[dict[str, object]] = []
    cues: list[tuple[float, float, str]] = []
    offset = 0.0
    for index, segment in enumerate(segments, start=1):
        identifier = segment.get("id")
        speech = segment.get("speechText")
        caption = segment.get("captionText")
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z][a-z-]{1,24}", identifier):
            raise SystemExit("scene identifier is invalid")
        if not all(isinstance(value, str) and 20 <= len(value) <= 800 for value in (speech, caption)):
            raise SystemExit(f"scene text is invalid: {identifier}")
        audio = OUT / f"{index:02d}-{identifier}.mp3"
        audio.write_bytes(synthesize(speech, spec, token))
        seconds = duration(audio)
        if seconds < 3 or seconds > 40:
            raise SystemExit(f"scene audio duration is unsafe: {identifier}")
        hold = seconds + TAIL_SECONDS
        sentences = [part.strip() for part in re.split(r"(?<=[.!?])\s+", caption) if part.strip()]
        weight = sum(len(part) for part in sentences) or 1
        cursor = 0.0
        for sentence in sentences:
            share = seconds * len(sentence) / weight
            cues.append((offset + cursor, offset + cursor + share, wrapped(sentence)))
            cursor += share
        timing.append(
            {
                "id": identifier,
                "audio": audio.name,
                "durationSeconds": round(seconds, 3),
                "holdSeconds": round(hold, 3),
                "startSeconds": round(offset, 3),
            }
        )
        offset += hold
    if not 90 <= offset < 175:
        raise SystemExit(f"narration must be 90-174 seconds, observed {offset:.3f}")
    (OUT / "timing.json").write_text(
        json.dumps(
            {
                "schemaVersion": "archon.submission-video-timing/v1",
                "totalSeconds": round(offset, 3),
                "scenes": timing,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    srt: list[str] = []
    for number, (start, end, text) in enumerate(cues, start=1):
        srt.extend([str(number), f"{timestamp(start)} --> {timestamp(end)}", text, ""])
    (OUT / "captions.en.srt").write_text("\n".join(srt), encoding="utf-8")
    token = ""
    print(f"Generated {len(timing)} scenes across {offset:.3f} seconds")


if __name__ == "__main__":
    main()
