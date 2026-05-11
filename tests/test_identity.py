"""Tests for identity/access auditing."""

from datetime import datetime, timedelta, timezone

import pytest
import responses

from pipeaudit.github_client import GitHubClient, GITHUB_API
from pipeaudit.identity import audit_identity, _highest_permission


class TestHighestPermission:
    def test_admin(self):
        assert _highest_permission({"admin": True, "push": True, "pull": True}) == "admin"

    def test_write(self):
        assert _highest_permission({"admin": False, "push": True, "pull": True}) == "write"

    def test_read(self):
        assert _highest_permission({"admin": False, "push": False, "pull": True}) == "read"

    def test_maintain(self):
        assert _highest_permission({"admin": False, "maintain": True, "push": True, "pull": True}) == "maintain"

    def test_none(self):
        assert _highest_permission({}) == "none"


def _setup_org_responses(org="testorg", admin_count=5):
    """Set up common API responses for identity audit tests."""

    # All members (admins + regular)
    admin_users = [{"login": f"admin-{i}", "avatar_url": ""} for i in range(admin_count)]
    regular_users = [
        {"login": "member-0", "avatar_url": ""},
        {"login": "member-1", "avatar_url": ""},
    ]
    responses.add(
        responses.GET,
        f"{GITHUB_API}/orgs/{org}/members",
        json=admin_users + regular_users,
        match=[responses.matchers.query_param_matcher({"per_page": "100", "role": "all"}, strict_match=False)],
    )

    # Per-user membership endpoint (admins get role=admin, members get role=member)
    for i in range(admin_count):
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/{org}/memberships/admin-{i}",
            json={"role": "admin", "state": "active"},
        )
    for login in ("member-0", "member-1"):
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/{org}/memberships/{login}",
            json={"role": "member", "state": "active"},
        )

    # Outside collaborators
    responses.add(
        responses.GET,
        f"{GITHUB_API}/orgs/{org}/outside_collaborators",
        json=[
            {"login": "external-user", "avatar_url": ""},
        ],
    )

    # Pending invitations
    responses.add(
        responses.GET,
        f"{GITHUB_API}/orgs/{org}/invitations",
        json=[
            {
                "login": "pending-user",
                "role": "member",
                "created_at": "2026-01-01T00:00:00Z",
                "inviter": {"login": "alice"},
            },
        ],
    )

    # Teams
    responses.add(
        responses.GET,
        f"{GITHUB_API}/orgs/{org}/teams",
        json=[
            {"name": "Core", "slug": "core", "privacy": "closed", "permission": "push"},
        ],
    )

    # Team members
    responses.add(
        responses.GET,
        f"{GITHUB_API}/orgs/{org}/teams/core/members",
        json=[
            {"login": "admin-0"},
            {"login": "member-0"},
        ],
    )

    # Team repos
    responses.add(
        responses.GET,
        f"{GITHUB_API}/orgs/{org}/teams/core/repos",
        json=[
            {
                "full_name": f"{org}/repo-a",
                "permissions": {"admin": True, "push": True, "pull": True},
            },
        ],
    )

    # Search commits — all members show as active (committed recently) by default
    recent_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    all_users = [u["login"] for u in admin_users + regular_users]
    for login in all_users:
        responses.add(
            responses.GET,
            f"{GITHUB_API}/search/commits",
            json={
                "total_count": 1,
                "items": [{
                    "commit": {
                        "committer": {"date": recent_date},
                        "author": {"date": recent_date},
                    },
                }],
            },
        )


class TestAuditIdentity:
    @responses.activate
    def test_detects_too_many_admins(self):
        org = "testorg"
        _setup_org_responses(org, admin_count=5)

        # Repo collaborators
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/repo-a/collaborators",
            json=[
                {"login": "admin-0", "permissions": {"admin": True, "push": True, "pull": True}},
            ],
        )

        client = GitHubClient("test-token")
        repos = [{"full_name": f"{org}/repo-a", "private": False}]
        result = audit_identity(client, org, repos)

        # 5 admins (>3) should trigger IAM001
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "IAM001" in rule_ids

        assert result["org_owner_count"] == 5
        assert len(result["org_owners"]) == 5

    @responses.activate
    def test_detects_outside_collaborators(self):
        org = "testorg"
        _setup_org_responses(org)

        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/repo-a/collaborators",
            json=[],
        )

        client = GitHubClient("test-token")
        repos = [{"full_name": f"{org}/repo-a", "private": False}]
        result = audit_identity(client, org, repos)

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "IAM003" in rule_ids
        assert len(result["outside_collaborators"]) == 1

    @responses.activate
    def test_detects_pending_invitations(self):
        org = "testorg"
        _setup_org_responses(org)

        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/repo-a/collaborators",
            json=[],
        )

        client = GitHubClient("test-token")
        repos = [{"full_name": f"{org}/repo-a", "private": False}]
        result = audit_identity(client, org, repos)

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "IAM004" in rule_ids
        assert len(result["pending_invitations"]) == 1

    @responses.activate
    def test_detects_team_admin_access(self):
        org = "testorg"
        _setup_org_responses(org)

        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/repo-a/collaborators",
            json=[],
        )

        client = GitHubClient("test-token")
        repos = [{"full_name": f"{org}/repo-a", "private": False}]
        result = audit_identity(client, org, repos)

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "IAM005" in rule_ids

    @responses.activate
    def test_detects_outside_collab_with_write_on_repo(self):
        org = "testorg"
        _setup_org_responses(org)

        # external-user has write access to repo
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/repo-a/collaborators",
            json=[
                {"login": "external-user", "permissions": {"admin": False, "push": True, "pull": True}},
            ],
        )

        client = GitHubClient("test-token")
        repos = [{"full_name": f"{org}/repo-a", "private": False}]
        result = audit_identity(client, org, repos)

        iam006 = [f for f in result["findings"] if f["rule_id"] == "IAM006"]
        assert len(iam006) >= 1
        assert iam006[0]["user"] == "external-user"

    @responses.activate
    def test_org_member_not_flagged_as_outside_collaborator(self):
        """Org members appearing in repo collaborators must NOT be flagged as outside collaborators.

        Regression test: previously used `login not in all_logins` which would flag
        everyone if list_org_members returned empty (e.g. due to a silent 403).
        Now uses the authoritative outside_collaborators endpoint instead.
        """
        org = "testorg"
        _setup_org_responses(org, admin_count=2)

        # member-0 is an org member who also appears as a direct repo collaborator
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/repo-a/collaborators",
            json=[
                {"login": "member-0", "permissions": {"admin": False, "push": True, "pull": True}},
            ],
        )

        client = GitHubClient("test-token")
        repos = [{"full_name": f"{org}/repo-a", "private": False}]
        result = audit_identity(client, org, repos)

        # member-0 is NOT an outside collaborator
        repo_collabs = result["repo_access"][0]["collaborators"]
        member0 = next(c for c in repo_collabs if c["login"] == "member-0")
        assert member0["is_org_member"] is True
        assert member0["is_outside_collaborator"] is False

        # No IAM006 for member-0 (they are an org member, not an outside collaborator)
        iam006_users = [f["user"] for f in result["findings"] if f["rule_id"] == "IAM006"]
        assert "member-0" not in iam006_users

    @responses.activate
    def test_report_structure(self):
        org = "testorg"
        _setup_org_responses(org)

        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/repo-a/collaborators",
            json=[],
        )

        client = GitHubClient("test-token")
        repos = [{"full_name": f"{org}/repo-a", "private": False}]
        result = audit_identity(client, org, repos)

        # Verify all expected keys
        assert "org_members" in result
        assert "org_owners" in result
        assert "org_member_count" in result
        assert "org_owner_count" in result
        assert "inactive_members" in result
        assert "outside_collaborators" in result
        assert "pending_invitations" in result
        assert "teams" in result
        assert "repo_access" in result
        assert "findings" in result

        # Teams should have structure
        assert len(result["teams"]) == 1
        assert result["teams"][0]["name"] == "Core"
        assert "admin-0" in result["teams"][0]["members"]

    @responses.activate
    def test_enumerates_org_owners(self):
        org = "testorg"
        _setup_org_responses(org, admin_count=2)

        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/repo-a/collaborators",
            json=[],
        )

        client = GitHubClient("test-token")
        repos = [{"full_name": f"{org}/repo-a", "private": False}]
        result = audit_identity(client, org, repos)

        iam008 = [f for f in result["findings"] if f["rule_id"] == "IAM008"]
        assert len(iam008) == 1
        assert iam008[0]["severity"] == "info"
        assert sorted(iam008[0]["users"]) == ["admin-0", "admin-1"]
        assert "Organization owners" in iam008[0]["title"]


class TestInactiveMembers:
    """Tests for inactive member detection (IAM009, IAM010, IAM011)."""

    def _setup_minimal_org(self, org, members):
        """Set up org with given members, no teams/collabs/invites."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/{org}/members",
            json=[{"login": m, "avatar_url": ""} for m in members],
            match=[responses.matchers.query_param_matcher(
                {"per_page": "100", "role": "all"}, strict_match=False,
            )],
        )
        for m in members:
            responses.add(
                responses.GET,
                f"{GITHUB_API}/orgs/{org}/memberships/{m}",
                json={"role": "member", "state": "active"},
            )
        # Empty outside collaborators, invitations, teams
        responses.add(responses.GET, f"{GITHUB_API}/orgs/{org}/outside_collaborators", json=[])
        responses.add(responses.GET, f"{GITHUB_API}/orgs/{org}/invitations", json=[])
        responses.add(responses.GET, f"{GITHUB_API}/orgs/{org}/teams", json=[])

    @responses.activate
    def test_detects_6_month_inactive(self):
        org = "testorg"
        self._setup_minimal_org(org, ["active-user", "stale-user"])

        now = datetime.now(timezone.utc)
        recent = (now - timedelta(days=1)).isoformat()

        # active-user: committed yesterday
        responses.add(
            responses.GET,
            f"{GITHUB_API}/search/commits",
            json={"total_count": 1, "items": [{"commit": {"committer": {"date": recent}}}]},
        )
        # stale-user: no commits in 6 months
        responses.add(
            responses.GET,
            f"{GITHUB_API}/search/commits",
            json={"total_count": 0, "items": []},
        )

        client = GitHubClient("test-token")
        result = audit_identity(client, org, [])

        iam009 = [f for f in result["findings"] if f["rule_id"] == "IAM009"]
        assert len(iam009) == 1
        assert iam009[0]["severity"] == "high"
        assert "stale-user" in iam009[0]["users"]
        assert "active-user" not in iam009[0]["users"]

        # Report should include inactive_members section
        assert "stale-user" in result["inactive_members"]["no_contributions_6_months"]

    @responses.activate
    def test_detects_3_month_inactive(self):
        org = "testorg"
        self._setup_minimal_org(org, ["user-3m"])

        # user-3m: last commit 4 months ago (within 6m but outside 3m)
        old_date = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
        responses.add(
            responses.GET,
            f"{GITHUB_API}/search/commits",
            json={"total_count": 1, "items": [{"commit": {"committer": {"date": old_date}}}]},
        )

        client = GitHubClient("test-token")
        result = audit_identity(client, org, [])

        iam010 = [f for f in result["findings"] if f["rule_id"] == "IAM010"]
        assert len(iam010) == 1
        assert iam010[0]["severity"] == "medium"
        assert "user-3m" in iam010[0]["users"]
        assert "user-3m" in result["inactive_members"]["no_contributions_3_months"]

    @responses.activate
    def test_detects_1_month_inactive(self):
        org = "testorg"
        self._setup_minimal_org(org, ["user-1m"])

        # user-1m: last commit 45 days ago (within 3m but outside 1m)
        old_date = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        responses.add(
            responses.GET,
            f"{GITHUB_API}/search/commits",
            json={"total_count": 1, "items": [{"commit": {"committer": {"date": old_date}}}]},
        )

        client = GitHubClient("test-token")
        result = audit_identity(client, org, [])

        iam011 = [f for f in result["findings"] if f["rule_id"] == "IAM011"]
        assert len(iam011) == 1
        assert iam011[0]["severity"] == "info"
        assert "user-1m" in iam011[0]["users"]
        assert "user-1m" in result["inactive_members"]["no_contributions_1_month"]

    @responses.activate
    def test_active_user_no_findings(self):
        org = "testorg"
        self._setup_minimal_org(org, ["active-user"])

        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        responses.add(
            responses.GET,
            f"{GITHUB_API}/search/commits",
            json={"total_count": 10, "items": [{"commit": {"committer": {"date": recent}}}]},
        )

        client = GitHubClient("test-token")
        result = audit_identity(client, org, [])

        inactive_ids = {"IAM009", "IAM010", "IAM011"}
        found_ids = {f["rule_id"] for f in result["findings"]}
        assert not (found_ids & inactive_ids)

    @responses.activate
    def test_skips_on_search_api_error(self):
        """Users with search API failures are skipped, not flagged."""
        org = "testorg"
        self._setup_minimal_org(org, ["error-user"])

        responses.add(
            responses.GET,
            f"{GITHUB_API}/search/commits",
            status=403,
            json={"message": "rate limited"},
        )

        client = GitHubClient("test-token")
        result = audit_identity(client, org, [])

        inactive_ids = {"IAM009", "IAM010", "IAM011"}
        found_ids = {f["rule_id"] for f in result["findings"]}
        assert not (found_ids & inactive_ids)
