from __future__ import annotations

import json

import pytest

import archon_companion as companion


ACCOUNT = "123456789012"
ROLE = "archon-analytics"
EXPECTED = f"arn:aws:iam::{ACCOUNT}:role/{ROLE}"
SESSION = "lambda-session"


class FakeSts:
    def __init__(self, response):
        self.response = response

    def get_caller_identity(self):
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def assumed_role_response(role: str = ROLE) -> dict:
    return {
        "Account": ACCOUNT,
        "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{SESSION}",
        "UserId": f"AROAEXAMPLEIDENTIFIER:{SESSION}",
        "ResponseMetadata": {"RequestId": "private-provider-request"},
    }


@pytest.fixture
def temporary_role(monkeypatch):
    for name in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ASIA" + "A" * 16)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "s" * 40)
    monkeypatch.setenv("AWS_SESSION_TOKEN", "t" * 64)
    monkeypatch.setenv("AWS_STS_REGIONAL_ENDPOINTS", "regional")
    monkeypatch.setenv("ARCHON_EXPECTED_ANALYTICS_ROLE_ARN", EXPECTED)
    monkeypatch.setenv("ARCHON_ANALYTICS_LLM_PROVIDER", "bedrock")
    monkeypatch.setenv(
        "ARCHON_ANALYTICS_LLM_MODEL",
        "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
    )
    monkeypatch.setenv("ARCHON_ANALYTICS_AWS_REGION", "eu-west-1")
    calls = []

    def client(service, **kwargs):
        calls.append((service, kwargs))
        return FakeSts(assumed_role_response())

    monkeypatch.setattr(companion.boto3, "client", client)
    return calls


def test_temporary_role_identity_is_bounded_and_sanitized(temporary_role):
    receipt = companion.temporary_aws_role_identity("eu-west-1")
    encoded = json.dumps(receipt, sort_keys=True)
    assert receipt["schemaVersion"] == (
        "archon.analytics-temporary-role-identity/v1"
    )
    assert receipt["usesTemporaryRoleCredentials"] is True
    assert receipt["usesStaticAwsKeys"] is False
    assert receipt["providerPayloadStored"] is False
    assert receipt["digest"].startswith("sha256:")
    assert len(temporary_role) == 1
    service, kwargs = temporary_role[0]
    assert service == "sts"
    assert kwargs["region_name"] == "eu-west-1"
    assert kwargs["config"].proxies == {}
    for secret in (ACCOUNT, ROLE, SESSION, "private-provider-request"):
        assert secret not in encoded


def test_analytics_model_identity_binds_temporary_role(temporary_role):
    identity = companion.analytics_model_identity()
    assert identity["usesIamRoleCredentials"] is True
    assert identity["usesTemporaryRoleCredentials"] is True
    assert identity["usesStaticAwsKeys"] is False
    assert identity["roleIdentityDigest"].startswith("sha256:")
    assert identity["credentialModeDigest"].startswith("sha256:")


@pytest.mark.parametrize(
    "name,value",
    [
        ("AWS_ACCESS_KEY_ID", "AKIA" + "A" * 16),
        ("AWS_ACCESS_KEY_ID", "ASIAshort"),
        ("AWS_SECRET_ACCESS_KEY", "short"),
        ("AWS_SESSION_TOKEN", ""),
        ("AWS_STS_REGIONAL_ENDPOINTS", "legacy"),
    ],
)
def test_static_incomplete_or_nonregional_credentials_are_rejected(
    temporary_role,
    monkeypatch,
    name,
    value,
):
    monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError):
        companion.temporary_aws_role_identity("eu-west-1")
    assert temporary_role == []


@pytest.mark.parametrize(
    "caller",
    [
        {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:root", "UserId": ACCOUNT},
        {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/operator",
            "UserId": "AIDAEXAMPLE",
        },
        {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:federated-user/operator",
            "UserId": "AIDAEXAMPLE:operator",
        },
        assumed_role_response("unexpected-role"),
    ],
)
def test_root_user_federated_and_unexpected_roles_are_rejected(
    temporary_role,
    monkeypatch,
    caller,
):
    monkeypatch.setattr(
        companion.boto3,
        "client",
        lambda *args, **kwargs: FakeSts(caller),
    )
    with pytest.raises(RuntimeError):
        companion.temporary_aws_role_identity("eu-west-1")


def test_proxy_and_unavailable_sts_fail_closed_without_provider_details(
    temporary_role,
    monkeypatch,
):
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid:8080")
    with pytest.raises(RuntimeError, match="proxy policy"):
        companion.temporary_aws_role_identity("eu-west-1")
    monkeypatch.delenv("HTTPS_PROXY")
    monkeypatch.setattr(
        companion.boto3,
        "client",
        lambda *args, **kwargs: FakeSts(
            RuntimeError("private credential provider trace"),
        ),
    )
    with pytest.raises(RuntimeError) as raised:
        companion.temporary_aws_role_identity("eu-west-1")
    assert "private credential provider trace" not in str(raised.value)


def test_changed_expected_role_fails_closed(temporary_role, monkeypatch):
    monkeypatch.setenv(
        "ARCHON_EXPECTED_ANALYTICS_ROLE_ARN",
        f"arn:aws:iam::{ACCOUNT}:role/other-analytics",
    )
    with pytest.raises(RuntimeError, match="does not match"):
        companion.temporary_aws_role_identity("eu-west-1")
