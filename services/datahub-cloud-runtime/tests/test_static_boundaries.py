from __future__ import annotations

from pathlib import Path

ROOT = Path("/var/task") if Path("/var/task").is_dir() else Path(__file__).resolve().parents[1]


def _source(name):
    return (ROOT / name).read_text(encoding="utf-8")


def test_writer_path_has_no_bedrock_or_reader_secret_authority():
    mutation = _source("mutation_runtime.py")
    handlers = _source("handlers.py")
    assert "bedrock" not in mutation.lower()
    assert "ARCHON_BEDROCK_MODEL" not in mutation
    assert "DATAHUB_CLOUD_READER_SECRET_ARN" not in mutation
    assert 'purpose="writer"' in handlers
    assert "MUTATION_OPERATIONS" in handlers


def test_fixture_reset_has_only_canonical_remove_tag_surface():
    source = _source("fixture_reset.py")
    assert 'tool="remove_tags"' in source
    assert "add_tags" not in source
    assert "APPROVE" not in source
    assert "humanApprovalUsed" in source
    assert "system-lifecycle-only" in source


def test_no_runtime_module_logs_provider_or_secret_payloads():
    for path in ROOT.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "print(" not in source
        assert "logging." not in source
        assert "SecretString)" not in source
        assert "sys.stdout" not in source
        assert "sys.stderr" not in source


def test_lambda_handlers_are_exactly_three_public_entrypoints():
    source = _source("handlers.py")
    assert source.count("def read_handler(") == 1
    assert source.count("def mutation_handler(") == 1
    assert source.count("def fixture_reset_handler(") == 1
