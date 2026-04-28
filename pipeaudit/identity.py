"""Identity and access audit for GitHub organizations.

Enumerates users, roles, and permissions across the org and its repos,
producing findings about overly-broad access and risky configurations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone

from .github_client import GitHubClient

logger = logging.getLogger(__name__)

# Permission levels ordered by privilege (highest first)
PERMISSION_RANK = {"admin": 0, "maintain": 1, "write": 2, "triage": 3, "read": 4}


def audit_identity(
    client: GitHubClient,
    org: str,
    repos: list[dict],
    on_status: callable = None,
) -> dict:
    """Run the full identity/access audit for an org.

    Returns a dict with:
        - org_members: list of members with roles
        - org_owners: list of org-level owners
        - outside_collaborators: list of non-member collaborators
        - teams: list of teams with members and repo permissions
        - repo_access: per-repo collaborator breakdown
        - pending_invitations: pending org invitations
        - findings: identity-related findings (IAM001-IAM00x)
    """
    def _status(msg: str):
        if on_status:
            on_status(msg)

    findings = []

    # 1. Org members — fetch all, then verify each member's actual org role
    #    via the membership endpoint. The /orgs/{org}/members?role=admin filter
    #    silently returns ALL members when the token user isn't an org owner,
    #    so we cannot rely on it alone.
    _status("Fetching org members...")
    all_members = client.list_org_members(org, role="all")

    owner_logins: set[str] = set()
    member_logins: set[str] = set()
    org_members_report = []

    for m in all_members:
        login = m["login"]
        _status(f"  Verifying role: {login}...")
        membership = client.get_org_membership(org, login)
        if membership and membership.get("role") == "admin":
            role = "owner"
            owner_logins.add(login)
        else:
            role = "member"
            member_logins.add(login)
        org_members_report.append({
            "login": login,
            "role": role,
            "avatar_url": m.get("avatar_url", ""),
        })

    admin_logins = owner_logins
    all_logins = owner_logins | member_logins

    # Finding: enumerate org owners (always reported for audit trail)
    if admin_logins:
        findings.append({
            "rule_id": "IAM008",
            "severity": "info",
            "title": f"Organization owners: {', '.join(sorted(admin_logins))}",
            "description": (
                f"The following {len(admin_logins)} user(s) are organization owners: "
                f"{', '.join(sorted(admin_logins))}. "
                f"Organization owners have unrestricted access including billing, "
                f"repository deletion, membership management, and all org settings. "
                f"Ensure each owner account has 2FA enabled and access is reviewed regularly."
            ),
            "users": sorted(admin_logins),
        })

    # Finding: too many org owners
    if len(admin_logins) > 3:
        findings.append({
            "rule_id": "IAM001",
            "severity": "high",
            "title": f"Organization has {len(admin_logins)} owners",
            "description": (
                f"The organization has {len(admin_logins)} owners: "
                f"{', '.join(sorted(admin_logins))}. "
                f"Limit org-level owner access to a small number of trusted individuals. "
                f"Org owners can change billing, delete repos, manage all settings, and "
                f"access all repositories."
            ),
            "users": sorted(admin_logins),
        })
    elif len(admin_logins) == 1:
        findings.append({
            "rule_id": "IAM002",
            "severity": "medium",
            "title": "Organization has only 1 owner (single point of failure)",
            "description": (
                f"Only '{next(iter(admin_logins))}' has owner access. "
                f"If this account is compromised or loses access, the org cannot be managed. "
                f"Consider adding at least one additional trusted owner."
            ),
            "users": sorted(admin_logins),
        })

    # 2. Inactive member detection
    #    Check each member's last commit in the org to identify stale accounts.
    _status("Checking member activity (commit history)...")
    inactive_6m, inactive_3m, inactive_1m = _find_inactive_members(
        client, org, all_logins, _status,
    )

    if inactive_6m:
        findings.append({
            "rule_id": "IAM009",
            "severity": "high",
            "title": f"{len(inactive_6m)} member(s) with no contributions in the last 6 months",
            "description": (
                f"The following member(s) have not committed to any repository in the "
                f"organization for over 6 months: {', '.join(sorted(inactive_6m))}. "
                f"Stale accounts with org access are a security risk. Review whether "
                f"these users still need membership and consider removing inactive accounts."
            ),
            "users": sorted(inactive_6m),
        })

    if inactive_3m:
        findings.append({
            "rule_id": "IAM010",
            "severity": "medium",
            "title": f"{len(inactive_3m)} member(s) with no contributions in the last 3 months",
            "description": (
                f"The following member(s) have not committed to any repository in the "
                f"organization for 3-6 months: {', '.join(sorted(inactive_3m))}. "
                f"Consider verifying whether these users are still actively working "
                f"on projects in this organization."
            ),
            "users": sorted(inactive_3m),
        })

    if inactive_1m:
        findings.append({
            "rule_id": "IAM011",
            "severity": "info",
            "title": f"{len(inactive_1m)} member(s) with no contributions in the last month",
            "description": (
                f"The following member(s) have not committed to any repository in the "
                f"organization for 1-3 months: {', '.join(sorted(inactive_1m))}. "
                f"This may be normal (e.g., PTO, non-coding roles) but is noted for "
                f"awareness during access reviews."
            ),
            "users": sorted(inactive_1m),
        })

    # 3. Outside collaborators
    _status("Fetching outside collaborators...")
    outside_collabs = client.list_outside_collaborators(org)
    outside_collab_logins: set[str] = {c["login"] for c in outside_collabs}
    outside_report = []
    for c in outside_collabs:
        outside_report.append({
            "login": c["login"],
            "avatar_url": c.get("avatar_url", ""),
        })

    if outside_collabs:
        findings.append({
            "rule_id": "IAM003",
            "severity": "medium",
            "title": f"{len(outside_collabs)} outside collaborator(s) have repo access",
            "description": (
                f"Outside collaborators are not org members but have direct access "
                f"to one or more repos: {', '.join(c['login'] for c in outside_collabs)}. "
                f"Review whether these external users still need access."
            ),
            "users": [c["login"] for c in outside_collabs],
        })

    # 3. Pending invitations
    _status("Checking pending invitations...")
    invitations = client.list_pending_invitations(org)
    invitations_report = []
    for inv in invitations:
        invitations_report.append({
            "login": inv.get("login") or inv.get("email", "unknown"),
            "role": inv.get("role", "unknown"),
            "created_at": inv.get("created_at", ""),
            "inviter": (inv.get("inviter") or {}).get("login", "unknown"),
        })

    if invitations:
        findings.append({
            "rule_id": "IAM004",
            "severity": "low",
            "title": f"{len(invitations)} pending org invitation(s)",
            "description": (
                f"There are {len(invitations)} pending invitations. "
                f"Stale invitations should be revoked to reduce the attack surface. "
                f"An invitation link could be used by an unintended recipient."
            ),
        })

    # 4. Teams
    _status("Fetching teams...")
    teams = client.list_org_teams(org)
    teams_report = []

    for team in teams:
        slug = team["slug"]
        _status(f"  Auditing team: {team['name']}...")

        team_members = client.list_team_members(org, slug)
        team_repos = client.list_team_repos(org, slug)

        team_entry = {
            "name": team["name"],
            "slug": slug,
            "privacy": team.get("privacy", "unknown"),
            "permission": team.get("permission", "unknown"),
            "members": [m["login"] for m in team_members],
            "member_count": len(team_members),
            "repos": [],
        }

        for repo in team_repos:
            perms = repo.get("permissions", {})
            effective = _highest_permission(perms)
            team_entry["repos"].append({
                "repo": repo["full_name"],
                "permission": effective,
            })

            # Finding: team has admin on a repo
            if effective == "admin":
                findings.append({
                    "rule_id": "IAM005",
                    "severity": "high",
                    "title": f"Team '{team['name']}' has admin access to {repo['full_name']}",
                    "description": (
                        f"Team '{team['name']}' ({len(team_members)} members) has admin "
                        f"permission on {repo['full_name']}. Admin access grants ability "
                        f"to delete the repo, change settings, and manage access. "
                        f"Consider reducing to 'maintain' or 'write' if full admin is not required."
                    ),
                    "team": team["name"],
                    "repo": repo["full_name"],
                    "members": [m["login"] for m in team_members],
                })

        teams_report.append(team_entry)

    # 5. Per-repo collaborator access
    _status("Auditing repo-level access...")
    repo_access_report = []

    for repo_meta in repos:
        full_name = repo_meta["full_name"]
        owner, repo_name = full_name.split("/", 1)
        is_public = not repo_meta.get("private", True)

        _status(f"  Checking access: {full_name}...")
        try:
            collaborators = client.list_repo_collaborators(owner, repo_name)
        except Exception as e:
            logger.debug("Could not list collaborators for %s: %s", full_name, e)
            continue

        repo_collabs = []
        admin_users = []
        write_users = []

        for collab in collaborators:
            login = collab["login"]
            perms = collab.get("permissions", {})
            effective = _highest_permission(perms)
            role_via = collab.get("role_name", effective)

            repo_collabs.append({
                "login": login,
                "permission": effective,
                "is_org_member": login in all_logins,
                "is_outside_collaborator": login in outside_collab_logins,
            })

            if effective == "admin":
                admin_users.append(login)
            elif effective in ("write", "maintain"):
                write_users.append(login)

            # Outside collaborator with write/admin on a repo
            if login in outside_collab_logins and effective in ("admin", "write", "maintain"):
                sev = "critical" if effective == "admin" and is_public else "high"
                findings.append({
                    "rule_id": "IAM006",
                    "severity": sev,
                    "title": f"Outside collaborator '{login}' has {effective} access to {full_name}",
                    "description": (
                        f"User '{login}' is not an org member but has '{effective}' permission "
                        f"on {'public' if is_public else 'private'} repo {full_name}. "
                        f"External users with write/admin access can push code, modify settings, "
                        f"or delete resources. Verify this access is intentional and still needed."
                    ),
                    "user": login,
                    "repo": full_name,
                    "permission": effective,
                })

        if repo_collabs:
            repo_access_report.append({
                "repo": full_name,
                "visibility": "public" if is_public else "private",
                "collaborators": repo_collabs,
                "admin_count": len(admin_users),
                "write_count": len(write_users),
            })

        # Too many admins on a single repo
        if len(admin_users) > 5:
            findings.append({
                "rule_id": "IAM007",
                "severity": "medium",
                "title": f"Repo {full_name} has {len(admin_users)} admin users",
                "description": (
                    f"Repository {full_name} has {len(admin_users)} users with admin "
                    f"access: {', '.join(sorted(admin_users))}. "
                    f"Consider reducing admin access and using 'maintain' or 'write' roles."
                ),
                "repo": full_name,
                "users": sorted(admin_users),
            })

    # Sort findings by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 99))

    return {
        "org_members": org_members_report,
        "org_owners": sorted(admin_logins),
        "org_member_count": len(all_logins),
        "org_owner_count": len(admin_logins),
        "inactive_members": {
            "no_contributions_6_months": sorted(inactive_6m),
            "no_contributions_3_months": sorted(inactive_3m),
            "no_contributions_1_month": sorted(inactive_1m),
        },
        "outside_collaborators": outside_report,
        "pending_invitations": invitations_report,
        "teams": teams_report,
        "repo_access": repo_access_report,
        "findings": findings,
    }


def _find_inactive_members(
    client: GitHubClient,
    org: str,
    all_logins: set[str],
    _status: callable,
) -> tuple[set[str], set[str], set[str]]:
    """Identify org members who have not contributed recently.

    For each member, searches for commits in the org within the last 6 months.
    Returns three sets (mutually exclusive buckets):
        - inactive_6m: no commits in 6+ months (or ever)
        - inactive_3m: last commit was 3-6 months ago
        - inactive_1m: last commit was 1-3 months ago
    """
    now = datetime.now(timezone.utc)
    date_6m = (now - timedelta(days=180)).strftime("%Y-%m-%d")
    date_3m = (now - timedelta(days=90)).strftime("%Y-%m-%d")
    date_1m = (now - timedelta(days=30)).strftime("%Y-%m-%d")

    inactive_6m: set[str] = set()
    inactive_3m: set[str] = set()
    inactive_1m: set[str] = set()

    for login in sorted(all_logins):
        _status(f"  Checking activity: {login}...")

        # Single query: search for commits in the last 6 months
        result = client.search_user_commits_in_org(org, login, date_6m)

        if result["total_count"] == -1:
            # API error (rate limit etc.) — skip this user
            logger.warning("Could not check activity for %s, skipping", login)
            continue

        if result["total_count"] == 0:
            # No commits in last 6 months
            inactive_6m.add(login)
            continue

        # Has commits in last 6 months — check when the most recent one was
        last_commit_date = _extract_commit_date(result)

        if last_commit_date is None:
            # Couldn't parse date, but they have commits — assume active
            continue

        if last_commit_date < (now - timedelta(days=90)):
            # Last commit was 3-6 months ago
            inactive_3m.add(login)
        elif last_commit_date < (now - timedelta(days=30)):
            # Last commit was 1-3 months ago
            inactive_1m.add(login)
        # else: active within last month — no finding

    return inactive_6m, inactive_3m, inactive_1m


def _extract_commit_date(search_result: dict) -> datetime | None:
    """Extract the most recent commit date from a search result."""
    items = search_result.get("items", [])
    if not items:
        return None

    commit_info = items[0].get("commit", {})
    # Try committer date first, fall back to author date
    date_str = (
        commit_info.get("committer", {}).get("date")
        or commit_info.get("author", {}).get("date")
    )
    if not date_str:
        return None

    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _highest_permission(perms: dict) -> str:
    """Given a permissions dict like {admin: true, push: true, pull: true}, return the highest."""
    # GitHub API returns: admin, maintain, push (=write), triage, pull (=read)
    if perms.get("admin"):
        return "admin"
    if perms.get("maintain"):
        return "maintain"
    if perms.get("push"):
        return "write"
    if perms.get("triage"):
        return "triage"
    if perms.get("pull"):
        return "read"
    return "none"
