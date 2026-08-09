import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class SubmissionVideoContracts(unittest.TestCase):
    def test_ci_only_video_is_release_bound_and_ephemeral(self) -> None:
        workflow = (ROOT / ".github/workflows/submission-video.yml").read_text(
            encoding="utf-8"
        )
        for required in (
            "release_sha:",
            "hosted_run_id:",
            "governed_run_id:",
            "GCP_VIDEO_SERVICE_ACCOUNT",
            "id-token: write",
            ".github/workflows/hosted-demo.yml",
            ".github/workflows/live-governed-proof.yml",
            "durationSeconds < 179",
            'rm -rf -- "${ARCHON_VIDEO_ROOT}"',
            'case "${GOOGLE_GHA_CREDS_PATH:-}" in',
            '"${GITHUB_WORKSPACE}"/gha-creds-*.json)',
            'test -z "$(git status --porcelain)"',
        ):
            self.assertIn(required, workflow)
        self.assertNotIn("ELEVENLABS_API_KEY", workflow)
        self.assertNotIn("pull_request", workflow)

    def test_narration_and_capture_share_one_exact_scene_order(self) -> None:
        narration = json.loads((ROOT / "video/narration.json").read_text("utf-8"))
        identifiers = [segment["id"] for segment in narration["segments"]]
        self.assertEqual(
            identifiers,
            [
                "hook",
                "live",
                "findings",
                "stack",
                "governance",
                "evidence",
                "oss",
                "close",
            ],
        )
        capture = (ROOT / "web/video/capture-production.mjs").read_text("utf-8")
        for identifier in identifiers:
            self.assertIn(f'holdScene("{identifier}"', capture)
        self.assertIn("Live DataHub", capture)
        self.assertIn("mcp-server-datahub/pull/183", capture)

    def test_media_never_enters_the_repository(self) -> None:
        tracked_media = [
            path
            for path in ROOT.rglob("*")
            if path.is_file() and path.suffix.lower() in {".mp3", ".mp4", ".wav", ".webm"}
        ]
        self.assertEqual(tracked_media, [])


if __name__ == "__main__":
    unittest.main()
