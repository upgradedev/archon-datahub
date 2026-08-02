"""Exact GraphQL reconciliation for stage-scoped DataHub Cloud trial identities."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any

from datahub_cloud_trial_clients import GraphQLClient, TrialError

CANONICAL_DATASET_URN = (
    "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
)
PII_TAG_URN = "urn:li:tag:PII"
COLUMN = "customer_email"
PRIVILEGE = "EDIT_DATASET_COL_TAGS"
SOURCE_COMMIT = "53064c2d9b41f77a141736ad6eb037966174329b"
DESCRIPTION_MARKER = "Managed by upgradedev/archon-datahub DataHub Cloud trial v1."

LIST_SERVICE_ACCOUNTS = """
query listServiceAccounts($input: ListServiceAccountsInput!) {
  listServiceAccounts(input: $input) {
    start count total
    serviceAccounts {
      urn type name displayName description createdBy createdAt
    }
  }
}
"""
CREATE_SERVICE_ACCOUNT = """
mutation createServiceAccount($input: CreateServiceAccountInput!) {
  createServiceAccount(input: $input) {
    urn type name displayName description createdBy createdAt
  }
}
"""
DELETE_SERVICE_ACCOUNT = """
mutation deleteServiceAccount($urn: String!) {
  deleteServiceAccount(urn: $urn)
}
"""
LIST_ROLES = """
query listRoles($input: ListRolesInput!) {
  listRoles(input: $input) {
    start count total
    roles { urn type name description }
  }
}
"""
BATCH_ASSIGN_ROLE = """
mutation batchAssignRole($input: BatchAssignRoleInput!) {
  batchAssignRole(input: $input)
}
"""
LIST_POLICIES = """
query listPolicies($input: ListPoliciesInput!) {
  listPolicies(input: $input) {
    start count total
    policies {
      urn type name description state privileges
      resources {
        filter {
          criteria { field condition values { value } }
        }
        privilegeConstraints {
          criteria { field condition values { value } }
        }
      }
      actors {
        users groups roles resourceOwners resourceOwnersTypes allUsers allGroups
      }
    }
  }
}
"""
CREATE_POLICY = """
mutation createPolicy($input: PolicyUpdateInput!) {
  createPolicy(input: $input)
}
"""
UPDATE_POLICY = """
mutation updatePolicy($urn: String!, $input: PolicyUpdateInput!) {
  updatePolicy(urn: $urn, input: $input)
}
"""
DELETE_POLICY = """
mutation deletePolicy($urn: String!) {
  deletePolicy(urn: $urn)
}
"""
LIST_ACCESS_TOKENS = """
query listAccessTokens($input: ListAccessTokenInput!) {
  listAccessTokens(input: $input) {
    start count total
    tokens { id name actorUrn createdAt expiresAt }
  }
}
"""
CREATE_ACCESS_TOKEN = """
mutation createAccessToken($input: CreateAccessTokenInput!) {
  createAccessToken(input: $input) {
    accessToken
    metadata { id name actorUrn createdAt expiresAt }
  }
}
"""
REVOKE_ACCESS_TOKEN = """
mutation revokeAccessToken($tokenId: String!) {
  revokeAccessToken(tokenId: $tokenId)
}
"""


@dataclass(frozen=True)
class GeneratedToken:
    token_id: str
    raw: str
    name: str
    actor_urn: str
    expires_at: int


def service_account_spec(stage: str, role: str) -> dict[str, str]:
    if stage not in {"staging", "production"} or role not in {"reader", "writer"}:
        raise TrialError("service account scope failed")
    return {
        "displayName": f"Archon {stage} DataHub {role}",
        "description": (
            f"{DESCRIPTION_MARKER} Stage={stage}; authority={role}; "
            "raw credentials are held only by AWS Secrets Manager."
        ),
    }


def policy_name(stage: str) -> str:
    if stage not in {"staging", "production"}:
        raise TrialError("policy stage failed")
    return f"Archon {stage} exact PII column writer"


def expected_policy_input(stage: str, writer_urn: str) -> dict[str, Any]:
    if not writer_urn.startswith("urn:li:corpuser:"):
        raise TrialError("writer service account URN failed")
    return {
        "type": "METADATA",
        "name": policy_name(stage),
        "state": "ACTIVE",
        "description": (
            f"{DESCRIPTION_MARKER} Grants only {PRIVILEGE} on the canonical "
            "dataset and only for urn:li:tag:PII."
        ),
        "resources": {
            "filter": {
                "criteria": [
                    {
                        "field": "URN",
                        "condition": "EQUALS",
                        "values": [CANONICAL_DATASET_URN],
                    }
                ]
            },
            "privilegeConstraints": {
                "criteria": [
                    {
                        "field": "URN",
                        "condition": "EQUALS",
                        "values": [PII_TAG_URN],
                    }
                ]
            },
        },
        "privileges": [PRIVILEGE],
        "actors": {
            "users": [writer_urn],
            "groups": [],
            "resourceOwners": False,
            "resourceOwnersTypes": [],
            "allUsers": False,
            "allGroups": False,
        },
    }


def token_name(stage: str, role: str, run_id: str, run_attempt: str) -> str:
    if (
        stage not in {"staging", "production"}
        or role not in {"reader", "writer"}
        or re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is None
        or re.fullmatch(r"[1-9][0-9]{0,9}", run_attempt) is None
    ):
        raise TrialError("token name binding failed")
    return f"archon-{stage}-{role}-runtime-{run_id}-{run_attempt}"


def token_prefix(stage: str, role: str) -> str:
    return f"archon-{stage}-{role}-runtime-"


class TrialControlPlane:
    def __init__(self, client: GraphQLClient, stage: str) -> None:
        if stage not in {"staging", "production"}:
            raise TrialError("DataHub stage failed")
        self.client = client
        self.stage = stage

    def _pages(
        self,
        operation: str,
        document: str,
        root: str,
        collection: str,
        *,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        start = 0
        records: list[dict[str, Any]] = []
        for _ in range(100):
            input_value: dict[str, Any] = {"start": start, "count": 100}
            if query is not None:
                input_value["query"] = query
            data = self.client.execute(
                operation,
                document,
                {"input": input_value},
            )
            page = data.get(root)
            if not isinstance(page, dict):
                raise TrialError(f"{operation} page contract failed")
            items = page.get(collection)
            total = page.get("total")
            count = page.get("count")
            if (
                not isinstance(items, list)
                or not isinstance(total, int)
                or not isinstance(count, int)
                or total < 0
                or count < 0
            ):
                raise TrialError(f"{operation} pagination contract failed")
            if any(not isinstance(item, dict) for item in items):
                raise TrialError(f"{operation} item contract failed")
            records.extend(items)
            if len(records) >= total:
                if len(records) != total:
                    raise TrialError(f"{operation} total contract failed")
                return records
            if not items:
                raise TrialError(f"{operation} pagination stalled")
            start += len(items)
        raise TrialError(f"{operation} pagination exceeded policy")

    def service_accounts(self) -> list[dict[str, Any]]:
        return self._pages(
            "listServiceAccounts",
            LIST_SERVICE_ACCOUNTS,
            "listServiceAccounts",
            "serviceAccounts",
        )

    def roles(self) -> list[dict[str, Any]]:
        return self._pages("listRoles", LIST_ROLES, "listRoles", "roles")

    def policies(self) -> list[dict[str, Any]]:
        return self._pages(
            "listPolicies",
            LIST_POLICIES,
            "listPolicies",
            "policies",
        )

    def tokens(self) -> list[dict[str, Any]]:
        return self._pages(
            "listAccessTokens",
            LIST_ACCESS_TOKENS,
            "listAccessTokens",
            "tokens",
        )

    def find_service_account(self, role: str) -> dict[str, Any] | None:
        spec = service_account_spec(self.stage, role)
        matches = [
            account
            for account in self.service_accounts()
            if account.get("displayName") == spec["displayName"]
        ]
        if len(matches) > 1:
            raise TrialError(f"duplicate {role} service account failed")
        if not matches:
            return None
        account = matches[0]
        if (
            account.get("description") != spec["description"]
            or not isinstance(account.get("urn"), str)
            or not account["urn"].startswith("urn:li:corpuser:")
        ):
            raise TrialError(f"{role} service account ownership drift")
        return account

    def ensure_service_account(self, role: str) -> dict[str, Any]:
        existing = self.find_service_account(role)
        if existing is not None:
            return existing
        result = self.client.execute(
            "createServiceAccount",
            CREATE_SERVICE_ACCOUNT,
            {"input": service_account_spec(self.stage, role)},
        )
        account = result.get("createServiceAccount")
        if not isinstance(account, dict):
            raise TrialError(f"{role} service account creation failed")
        expected = service_account_spec(self.stage, role)
        if (
            account.get("displayName") != expected["displayName"]
            or account.get("description") != expected["description"]
            or not isinstance(account.get("urn"), str)
            or not account["urn"].startswith("urn:li:corpuser:")
        ):
            raise TrialError(f"{role} service account response drift")
        return account

    def reader_role(self) -> dict[str, Any]:
        matches = [role for role in self.roles() if role.get("name") == "Reader"]
        if len(matches) != 1 or not isinstance(matches[0].get("urn"), str):
            raise TrialError("exact Reader role was not uniquely resolved")
        return matches[0]

    def assign_reader_role(self, actors: list[str]) -> None:
        if len(actors) != 2 or len(set(actors)) != 2:
            raise TrialError("Reader role actor set failed")
        result = self.client.execute(
            "batchAssignRole",
            BATCH_ASSIGN_ROLE,
            {
                "input": {
                    "roleUrn": self.reader_role()["urn"],
                    "actors": sorted(actors),
                }
            },
        )
        if result.get("batchAssignRole") is not True:
            raise TrialError("Reader role assignment failed")

    @staticmethod
    def _criterion(criteria: Any) -> list[dict[str, Any]]:
        if not isinstance(criteria, list):
            return []
        normalized = []
        for item in criteria:
            if not isinstance(item, dict) or not isinstance(item.get("values"), list):
                raise TrialError("policy criterion response failed")
            values = []
            for value in item["values"]:
                if not isinstance(value, dict) or not isinstance(value.get("value"), str):
                    raise TrialError("policy criterion value failed")
                values.append(value["value"])
            normalized.append(
                {
                    "field": item.get("field"),
                    "condition": item.get("condition"),
                    "values": values,
                }
            )
        return normalized

    def normalize_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        resources = policy.get("resources")
        actors = policy.get("actors")
        if not isinstance(resources, dict) or not isinstance(actors, dict):
            raise TrialError("policy response shape failed")
        resource_filter = resources.get("filter")
        constraints = resources.get("privilegeConstraints")
        if not isinstance(resource_filter, dict) or not isinstance(constraints, dict):
            raise TrialError("policy resource filter failed")
        return {
            "type": policy.get("type"),
            "name": policy.get("name"),
            "state": policy.get("state"),
            "description": policy.get("description"),
            "resources": {
                "filter": {
                    "criteria": self._criterion(resource_filter.get("criteria"))
                },
                "privilegeConstraints": {
                    "criteria": self._criterion(constraints.get("criteria"))
                },
            },
            "privileges": policy.get("privileges"),
            "actors": {
                "users": actors.get("users") or [],
                "groups": actors.get("groups") or [],
                "resourceOwners": actors.get("resourceOwners"),
                "resourceOwnersTypes": actors.get("resourceOwnersTypes") or [],
                "allUsers": actors.get("allUsers"),
                "allGroups": actors.get("allGroups"),
            },
        }

    def exact_policy(self) -> dict[str, Any] | None:
        matches = [
            policy
            for policy in self.policies()
            if policy.get("name") == policy_name(self.stage)
        ]
        if len(matches) > 1:
            raise TrialError("duplicate exact writer policy failed")
        return matches[0] if matches else None

    def ensure_policy(self, writer_urn: str) -> dict[str, Any]:
        expected = expected_policy_input(self.stage, writer_urn)
        existing = self.exact_policy()
        if existing is None:
            result = self.client.execute(
                "createPolicy",
                CREATE_POLICY,
                {"input": expected},
            )
            if not isinstance(result.get("createPolicy"), str):
                raise TrialError("exact writer policy creation failed")
        elif self.normalize_policy(existing) != expected:
            urn = existing.get("urn")
            if not isinstance(urn, str) or DESCRIPTION_MARKER not in str(
                existing.get("description", "")
            ):
                raise TrialError("unowned exact-name writer policy drift")
            result = self.client.execute(
                "updatePolicy",
                UPDATE_POLICY,
                {"urn": urn, "input": expected},
            )
            if result.get("updatePolicy") != urn:
                raise TrialError("exact writer policy update failed")
        verified = self.exact_policy()
        if verified is None or self.normalize_policy(verified) != expected:
            raise TrialError("exact writer policy verification failed")
        self.assert_no_effective_write_expansion(writer_urn, verified["urn"])
        return verified

    def assert_no_effective_write_expansion(
        self, writer_urn: str, exact_policy_urn: str
    ) -> None:
        mutation_prefixes = (
            "EDIT_",
            "MANAGE_",
            "DELETE_",
            "CREATE_",
            "ADD_",
            "REMOVE_",
            "PUBLISH_",
        )
        reader_role_urn = self.reader_role()["urn"]
        for policy in self.policies():
            if policy.get("urn") == exact_policy_urn:
                continue
            actors = policy.get("actors")
            privileges = policy.get("privileges")
            if not isinstance(actors, dict) or not isinstance(privileges, list):
                raise TrialError("policy expansion review failed")
            users = actors.get("users") or []
            roles = actors.get("roles") or []
            all_users = actors.get("allUsers")
            if (
                not isinstance(users, list)
                or not isinstance(roles, list)
                or not isinstance(all_users, bool)
            ):
                raise TrialError("policy actor expansion review failed")
            applies_to_writer = (
                writer_urn in users
                or reader_role_urn in roles
                or all_users
            )
            if not applies_to_writer:
                continue
            if any(
                isinstance(privilege, str)
                and privilege.startswith(mutation_prefixes)
                for privilege in privileges
            ):
                raise TrialError("writer has an unreviewed effective mutation policy")

    def scoped_tokens(self, role: str, actor_urn: str) -> list[dict[str, Any]]:
        prefix = token_prefix(self.stage, role)
        return [
            token
            for token in self.tokens()
            if token.get("actorUrn") == actor_urn
            and isinstance(token.get("name"), str)
            and token["name"].startswith(prefix)
        ]

    def create_token(
        self,
        role: str,
        actor_urn: str,
        run_id: str,
        run_attempt: str,
    ) -> GeneratedToken:
        name = token_name(self.stage, role, run_id, run_attempt)
        result = self.client.execute(
            "createAccessToken",
            CREATE_ACCESS_TOKEN,
            {
                "input": {
                    "type": "SERVICE_ACCOUNT",
                    "actorUrn": actor_urn,
                    "duration": "ONE_MONTH",
                    "name": name,
                    "description": (
                        f"{DESCRIPTION_MARKER} ONE_MONTH {self.stage} {role} "
                        f"runtime credential; workflow run {run_id}/{run_attempt}."
                    ),
                }
            },
        )
        created = result.get("createAccessToken")
        if not isinstance(created, dict):
            raise TrialError(f"{role} access token creation failed")
        raw = created.get("accessToken")
        metadata = created.get("metadata")
        if (
            not isinstance(raw, str)
            or not isinstance(metadata, dict)
            or not isinstance(metadata.get("id"), str)
            or metadata.get("name") != name
            or metadata.get("actorUrn") != actor_urn
            or not isinstance(metadata.get("expiresAt"), int)
        ):
            raise TrialError(f"{role} access token response failed")
        remaining = metadata["expiresAt"] - int(time.time() * 1000)
        if not 27 * 86_400_000 <= remaining <= 32 * 86_400_000:
            raise TrialError(f"{role} ONE_MONTH expiry contract failed")
        return GeneratedToken(
            token_id=metadata["id"],
            raw=raw,
            name=name,
            actor_urn=actor_urn,
            expires_at=metadata["expiresAt"],
        )

    def revoke(self, token_id: str) -> None:
        if not isinstance(token_id, str) or not token_id:
            raise TrialError("token revocation identifier failed")
        result = self.client.execute(
            "revokeAccessToken",
            REVOKE_ACCESS_TOKEN,
            {"tokenId": token_id},
        )
        if result.get("revokeAccessToken") is not True:
            raise TrialError("token revocation failed")

    def delete_owned(
        self,
        reader: dict[str, Any] | None,
        writer: dict[str, Any] | None,
    ) -> dict[str, int]:
        accounts = [
            (role, account)
            for role, account in (("reader", reader), ("writer", writer))
            if account is not None
        ]
        for _role, account in accounts:
            if (
                DESCRIPTION_MARKER not in str(account.get("description", ""))
                or not isinstance(account.get("urn"), str)
            ):
                raise TrialError("cleanup refused an unowned service account")

        revoked_ids: set[str] = set()
        for role, account in accounts:
            remaining: list[dict[str, Any]] = []
            for attempt in range(1, 6):
                remaining = self.scoped_tokens(role, account["urn"])
                if not remaining:
                    break
                for token in remaining:
                    token_id = token.get("id")
                    if not isinstance(token_id, str) or not token_id:
                        raise TrialError("cleanup token inventory failed")
                    revoked_ids.add(token_id)
                    try:
                        self.revoke(token_id)
                    except Exception:
                        pass
                if attempt < 5:
                    time.sleep(1)
            if remaining:
                raise TrialError("cleanup token revocation did not verify")

        policy = self.exact_policy()
        deleted_policies = 0
        if policy is not None:
            if DESCRIPTION_MARKER not in str(policy.get("description", "")):
                raise TrialError("cleanup refused an unowned exact-name policy")
            result = self.client.execute(
                "deletePolicy",
                DELETE_POLICY,
                {"urn": policy["urn"]},
            )
            if result.get("deletePolicy") != policy["urn"]:
                raise TrialError("writer policy cleanup failed")
            deleted_policies = 1

        actors = sorted(account["urn"] for _role, account in accounts)
        if actors:
            result = self.client.execute(
                "batchAssignRole",
                BATCH_ASSIGN_ROLE,
                {"input": {"roleUrn": None, "actors": actors}},
            )
            if result.get("batchAssignRole") is not True:
                raise TrialError("Reader role cleanup failed")

        deleted_accounts = 0
        for _role, account in accounts:
            result = self.client.execute(
                "deleteServiceAccount",
                DELETE_SERVICE_ACCOUNT,
                {"urn": account["urn"]},
            )
            if result.get("deleteServiceAccount") is not True:
                raise TrialError("service account cleanup failed")
            deleted_accounts += 1

        for attempt in range(1, 6):
            if (
                self.find_service_account("reader") is None
                and self.find_service_account("writer") is None
                and self.exact_policy() is None
            ):
                return {
                    "revokedTokens": len(revoked_ids),
                    "deletedPolicies": deleted_policies,
                    "deletedServiceAccounts": deleted_accounts,
                }
            if attempt < 5:
                time.sleep(1)
        raise TrialError("cleanup final absence did not verify")
