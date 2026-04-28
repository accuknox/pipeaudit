"""Security rules for auditing GitHub Actions workflow files.

Each rule function receives:
    workflow_name: str - the filename of the workflow
    workflow: dict - parsed YAML of the workflow
    repo_meta: dict - repository metadata (visibility, name, etc.)

Each returns a list of Finding dicts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    description: str
    workflow_file: str
    job: str = ""
    step: str = ""
    line_hint: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_public(repo_meta: dict) -> bool:
    return repo_meta.get("visibility") == "public" or not repo_meta.get("private", True)


def _get_triggers(workflow: dict) -> set[str]:
    on = workflow.get("on") or workflow.get(True)  # YAML parses 'on' as True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on.keys())
    return set()


def _get_jobs(workflow: dict) -> dict:
    return workflow.get("jobs") or {}


def _expression_in_run(text: str) -> list[str]:
    """Find GitHub expression interpolations in run: blocks."""
    if not isinstance(text, str):
        return []
    return re.findall(r"\$\{\{.*?\}\}", text, re.DOTALL)


_UNTRUSTED_CONTEXTS = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.commits.*.author.email",
    "github.event.commits.*.author.name",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.head_ref",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
]

# Pre-compile patterns for untrusted context matching
_UNTRUSTED_PATTERNS = []
for ctx in _UNTRUSTED_CONTEXTS:
    pattern = ctx.replace(".", r"\.").replace("*", r"[^}]+")
    _UNTRUSTED_PATTERNS.append(re.compile(pattern))


def _contains_untrusted_context(expr: str) -> list[str]:
    """Check if an expression contains references to untrusted input contexts."""
    matches = []
    for i, pattern in enumerate(_UNTRUSTED_PATTERNS):
        if pattern.search(expr):
            matches.append(_UNTRUSTED_CONTEXTS[i])
    return matches


# ---------------------------------------------------------------------------
# Rule: pull_request_target usage
# ---------------------------------------------------------------------------

def check_pull_request_target(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []
    triggers = _get_triggers(workflow)

    if "pull_request_target" not in triggers:
        return findings

    severity = Severity.CRITICAL if _is_public(repo_meta) else Severity.HIGH

    finding = Finding(
        rule_id="GHA001",
        severity=severity.value,
        title="pull_request_target trigger detected",
        description=(
            "The 'pull_request_target' trigger runs in the context of the base "
            "branch with access to secrets. In public repos, an attacker can submit "
            "a PR that modifies workflow code, which then executes with secret access. "
            "Avoid checking out PR code or passing PR-controlled data to run: steps."
        ),
        workflow_file=workflow_name,
    )
    findings.append(finding)

    # Extra: check if it checks out the PR head ref (extremely dangerous)
    for job_id, job in _get_jobs(workflow).items():
        for i, step in enumerate(job.get("steps") or []):
            uses = step.get("uses", "")
            with_ref = (step.get("with") or {}).get("ref", "")
            if "actions/checkout" in uses and (
                "github.event.pull_request.head" in with_ref
                or "${{ github.event.pull_request.head.sha }}" in with_ref
                or "github.head_ref" in with_ref
            ):
                findings.append(Finding(
                    rule_id="GHA001a",
                    severity=Severity.CRITICAL.value,
                    title="pull_request_target checks out PR head code",
                    description=(
                        "This workflow uses pull_request_target AND checks out "
                        "the pull request's head ref. This is extremely dangerous: "
                        "an attacker's PR code runs with base branch secrets. "
                        "This is the #1 GitHub Actions vulnerability pattern."
                    ),
                    workflow_file=workflow_name,
                    job=job_id,
                    step=step.get("name") or step.get("id") or f"step-{i}",
                ))

    return findings


# ---------------------------------------------------------------------------
# Rule: Script injection via expression interpolation
# ---------------------------------------------------------------------------

def check_script_injection(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []

    for job_id, job in _get_jobs(workflow).items():
        for i, step in enumerate(job.get("steps") or []):
            run_block = step.get("run")
            if not run_block:
                continue

            expressions = _expression_in_run(run_block)
            for expr in expressions:
                untrusted = _contains_untrusted_context(expr)
                if untrusted:
                    findings.append(Finding(
                        rule_id="GHA002",
                        severity=Severity.HIGH.value,
                        title="Potential script injection via expression interpolation",
                        description=(
                            f"The run: block interpolates untrusted input "
                            f"({', '.join(untrusted)}) directly into a shell command. "
                            f"An attacker can craft input to execute arbitrary commands. "
                            f"Use an environment variable instead: set the value via "
                            f"env: and reference $ENV_VAR in the script."
                        ),
                        workflow_file=workflow_name,
                        job=job_id,
                        step=step.get("name") or step.get("id") or f"step-{i}",
                        line_hint=expr,
                    ))

    return findings


# ---------------------------------------------------------------------------
# Rule: Unpinned third-party actions
# ---------------------------------------------------------------------------

_TRUSTED_OWNERS = {"actions", "github", "azure"}

# Version-tag pattern: starts with an optional 'v' followed by a digit (e.g. v1, v2.3.0, 1.0.0).
# Anything else that isn't a SHA is treated as a branch-like ref (e.g. master, main, latest).
_VERSION_TAG_RE = re.compile(r"^v?\d")


def check_unpinned_actions(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []

    # Own-org actions are not an external supply chain threat — treat them as trusted.
    org = repo_meta.get("full_name", "/").split("/")[0].lower()
    trusted_owners = _TRUSTED_OWNERS | {org}

    for job_id, job in _get_jobs(workflow).items():
        for i, step in enumerate(job.get("steps") or []):
            uses = step.get("uses", "")
            if not uses or uses.startswith("./"):
                continue  # local action, skip

            # Parse owner/repo@ref
            if "@" not in uses:
                findings.append(Finding(
                    rule_id="GHA003",
                    severity=Severity.MEDIUM.value,
                    title="Action reference without version pin",
                    description=(
                        f"Action '{uses}' is used without any version pin. "
                        f"Always pin actions to a full commit SHA."
                    ),
                    workflow_file=workflow_name,
                    job=job_id,
                    step=step.get("name") or step.get("id") or f"step-{i}",
                ))
                continue

            action_path, ref = uses.rsplit("@", 1)
            owner = action_path.split("/")[0] if "/" in action_path else ""

            # SHA pins are 40-char hex
            is_sha_pinned = bool(re.fullmatch(r"[0-9a-f]{40}", ref))

            if not is_sha_pinned:
                is_version_tag = bool(_VERSION_TAG_RE.match(ref))

                if not is_version_tag:
                    # Branch-like ref (master, main, latest, …) — highest risk:
                    # branches are continuously moving and can be updated at any time.
                    severity = Severity.HIGH
                    ref_context = (
                        f"'{ref}' is a branch, not a version tag. Branches are "
                        f"continuously updated and can introduce malicious code at any push. "
                    )
                elif owner.lower() not in trusted_owners:
                    # Third-party version tag — still mutable but lower immediate risk.
                    severity = Severity.HIGH
                    ref_context = (
                        f"'{ref}' is a mutable version tag from a third-party owner. "
                        f"Tags can be force-pushed to point at a different commit. "
                    )
                else:
                    # Trusted/own-org version tag — flag for awareness but lower risk.
                    severity = Severity.MEDIUM
                    ref_context = (
                        f"'{ref}' is a mutable version tag. Tags can be force-pushed "
                        f"to point at a different commit. "
                    )

                findings.append(Finding(
                    rule_id="GHA003",
                    severity=severity.value,
                    title="Action not pinned to a full commit SHA",
                    description=(
                        f"Action '{uses}' is not pinned to a full commit SHA. "
                        f"{ref_context}"
                        f"Pin to a specific commit SHA to prevent supply chain attacks."
                    ),
                    workflow_file=workflow_name,
                    job=job_id,
                    step=step.get("name") or step.get("id") or f"step-{i}",
                ))

    return findings


# ---------------------------------------------------------------------------
# Rule: Overly permissive permissions
# ---------------------------------------------------------------------------

def check_permissions(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []

    # Check top-level permissions
    top_perms = workflow.get("permissions")
    if top_perms is None:
        findings.append(Finding(
            rule_id="GHA004",
            severity=Severity.MEDIUM.value,
            title="No top-level permissions declared",
            description=(
                "Workflow does not declare top-level permissions. The default "
                "depends on org/repo settings and may grant broad read-write "
                "access. Explicitly declare 'permissions' to follow least-privilege."
            ),
            workflow_file=workflow_name,
        ))
    elif top_perms == "write-all" or top_perms == {"write-all": True}:
        findings.append(Finding(
            rule_id="GHA004",
            severity=Severity.HIGH.value,
            title="Workflow uses write-all permissions",
            description=(
                "Workflow grants 'write-all' permissions, providing write access "
                "to all scopes. Use fine-grained per-scope permissions instead."
            ),
            workflow_file=workflow_name,
        ))
    elif isinstance(top_perms, dict):
        _check_permission_scope(findings, top_perms, workflow_name, "top-level")

    # Check per-job permissions
    for job_id, job in _get_jobs(workflow).items():
        job_perms = job.get("permissions")
        if isinstance(job_perms, str) and job_perms == "write-all":
            findings.append(Finding(
                rule_id="GHA004",
                severity=Severity.HIGH.value,
                title="Job uses write-all permissions",
                description=(
                    f"Job '{job_id}' grants 'write-all' permissions. "
                    f"Use fine-grained per-scope permissions instead."
                ),
                workflow_file=workflow_name,
                job=job_id,
            ))
        elif isinstance(job_perms, dict):
            _check_permission_scope(findings, job_perms, workflow_name, job_id)

    return findings


_SENSITIVE_WRITE_PERMS = {
    "contents": "write",
    "packages": "write",
    "actions": "write",
    "security-events": "write",
    "id-token": "write",
}


def _check_permission_scope(
    findings: list, perms: dict, workflow_name: str, context: str
):
    for scope, level in perms.items():
        if scope in _SENSITIVE_WRITE_PERMS and level == "write":
            findings.append(Finding(
                rule_id="GHA004a",
                severity=Severity.LOW.value,
                title=f"Write permission on '{scope}' scope",
                description=(
                    f"In {context}: '{scope}: write' is granted. Verify this is "
                    f"necessary. Prefer read-only access where possible."
                ),
                workflow_file=workflow_name,
            ))


# ---------------------------------------------------------------------------
# Rule: Self-hosted runners on public repos
# ---------------------------------------------------------------------------

def check_self_hosted_runners(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []

    if not _is_public(repo_meta):
        return findings

    for job_id, job in _get_jobs(workflow).items():
        runs_on = job.get("runs-on", "")
        is_self_hosted = False

        if isinstance(runs_on, str) and "self-hosted" in runs_on:
            is_self_hosted = True
        elif isinstance(runs_on, list) and "self-hosted" in runs_on:
            is_self_hosted = True
        elif isinstance(runs_on, dict):
            labels = runs_on.get("labels") or runs_on.get("group", "")
            if isinstance(labels, list) and "self-hosted" in labels:
                is_self_hosted = True
            elif isinstance(labels, str) and "self-hosted" in labels:
                is_self_hosted = True

        if is_self_hosted:
            findings.append(Finding(
                rule_id="GHA005",
                severity=Severity.CRITICAL.value,
                title="Self-hosted runner used in public repository",
                description=(
                    "Public repo workflows using self-hosted runners allow any "
                    "forked PR to execute code on your infrastructure. Attackers "
                    "can gain persistent access to the runner machine, access "
                    "network resources, and steal secrets. Use GitHub-hosted "
                    "runners for public repos, or strictly limit with "
                    "environment protections."
                ),
                workflow_file=workflow_name,
                job=job_id,
            ))

    return findings


# ---------------------------------------------------------------------------
# Rule: workflow_run trigger risks
# ---------------------------------------------------------------------------

def check_workflow_run(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []
    triggers = _get_triggers(workflow)

    if "workflow_run" not in triggers:
        return findings

    findings.append(Finding(
        rule_id="GHA006",
        severity=Severity.MEDIUM.value,
        title="workflow_run trigger detected",
        description=(
            "The 'workflow_run' trigger runs in the context of the default branch "
            "with access to secrets, even when triggered by a fork PR. Be cautious "
            "about using artifacts or data from the triggering workflow, as they "
            "may be attacker-controlled."
        ),
        workflow_file=workflow_name,
    ))

    return findings


# ---------------------------------------------------------------------------
# Rule: Dangerous environment variable usage
# ---------------------------------------------------------------------------

def check_env_secrets_exposure(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []

    triggers = _get_triggers(workflow)
    pr_triggers = triggers & {"pull_request_target", "pull_request"}

    if not pr_triggers:
        return findings

    # Check for secrets usage in workflows triggered by PRs
    workflow_str = str(workflow)
    if "secrets." not in workflow_str and "secrets[" not in workflow_str:
        return findings

    # Only flag for pull_request_target (pull_request from forks won't have secrets)
    if "pull_request_target" in pr_triggers:
        findings.append(Finding(
            rule_id="GHA007",
            severity=Severity.HIGH.value,
            title="Secrets used in pull_request_target workflow",
            description=(
                "This pull_request_target workflow references secrets. Since "
                "pull_request_target runs with base branch context, secrets are "
                "available. If any PR-controlled data influences what code runs, "
                "an attacker can exfiltrate secrets."
            ),
            workflow_file=workflow_name,
        ))

    return findings


# ---------------------------------------------------------------------------
# Rule: Unsafe artifact usage
# ---------------------------------------------------------------------------

def check_unsafe_artifacts(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []

    triggers = _get_triggers(workflow)
    if "workflow_run" not in triggers:
        return findings

    for job_id, job in _get_jobs(workflow).items():
        for i, step in enumerate(job.get("steps") or []):
            uses = step.get("uses", "")
            if "download-artifact" in uses:
                findings.append(Finding(
                    rule_id="GHA008",
                    severity=Severity.HIGH.value,
                    title="Artifact download in workflow_run context",
                    description=(
                        "Downloading artifacts in a workflow_run workflow is dangerous. "
                        "The artifact may have been produced by an untrusted fork PR. "
                        "Never execute or eval downloaded artifact content without "
                        "validation. Treat artifact data as untrusted input."
                    ),
                    workflow_file=workflow_name,
                    job=job_id,
                    step=step.get("name") or step.get("id") or f"step-{i}",
                ))

    return findings


# ---------------------------------------------------------------------------
# Rule: persist-credentials not disabled on checkout
# ---------------------------------------------------------------------------

def check_persist_credentials(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []

    for job_id, job in _get_jobs(workflow).items():
        for i, step in enumerate(job.get("steps") or []):
            uses = step.get("uses", "")
            if "actions/checkout" not in uses:
                continue
            with_block = step.get("with") or {}
            # persist-credentials defaults to true
            persist = with_block.get("persist-credentials")
            if persist is None or persist is True or str(persist).lower() == "true":
                findings.append(Finding(
                    rule_id="GHA009",
                    severity=Severity.LOW.value,
                    title="actions/checkout persists credentials by default",
                    description=(
                        "actions/checkout persists the token in the git config by "
                        "default. Any subsequent step can use this token. Set "
                        "'persist-credentials: false' to limit token exposure, "
                        "especially in workflows that run untrusted code."
                    ),
                    workflow_file=workflow_name,
                    job=job_id,
                    step=step.get("name") or step.get("id") or f"step-{i}",
                ))

    return findings


# ---------------------------------------------------------------------------
# Rule: Use of deprecated/known-vulnerable actions
# ---------------------------------------------------------------------------

_KNOWN_VULNERABLE_ACTIONS = {
    "actions/cache@v1": "actions/cache v1 has known cache poisoning vulnerabilities",
    "actions/checkout@v1": "actions/checkout v1 has known credential-leak issues",
    "actions/upload-artifact@v1": "v1 is deprecated and has known issues",
    "actions/download-artifact@v1": "v1 is deprecated and has known issues",
}


def check_vulnerable_actions(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []

    for job_id, job in _get_jobs(workflow).items():
        for i, step in enumerate(job.get("steps") or []):
            uses = step.get("uses", "")
            for vuln_action, reason in _KNOWN_VULNERABLE_ACTIONS.items():
                if uses.startswith(vuln_action):
                    findings.append(Finding(
                        rule_id="GHA010",
                        severity=Severity.MEDIUM.value,
                        title=f"Known vulnerable action: {vuln_action}",
                        description=f"Action '{uses}' is outdated. {reason}. Upgrade to the latest version.",
                        workflow_file=workflow_name,
                        job=job_id,
                        step=step.get("name") or step.get("id") or f"step-{i}",
                    ))

    return findings


# ---------------------------------------------------------------------------
# Rule: ACTIONS_ALLOW_UNSECURE_COMMANDS
# ---------------------------------------------------------------------------

def check_unsecure_commands(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []

    # Check top-level env
    top_env = workflow.get("env") or {}
    if top_env.get("ACTIONS_ALLOW_UNSECURE_COMMANDS") in ("true", True):
        findings.append(Finding(
            rule_id="GHA011",
            severity=Severity.HIGH.value,
            title="ACTIONS_ALLOW_UNSECURE_COMMANDS enabled",
            description=(
                "Enabling ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables deprecated "
                "set-env and add-path commands, which are vulnerable to injection. "
                "Use $GITHUB_ENV and $GITHUB_PATH files instead."
            ),
            workflow_file=workflow_name,
        ))

    for job_id, job in _get_jobs(workflow).items():
        job_env = job.get("env") or {}
        if job_env.get("ACTIONS_ALLOW_UNSECURE_COMMANDS") in ("true", True):
            findings.append(Finding(
                rule_id="GHA011",
                severity=Severity.HIGH.value,
                title="ACTIONS_ALLOW_UNSECURE_COMMANDS enabled at job level",
                description=(
                    "Enabling ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables deprecated "
                    "set-env and add-path commands, which are vulnerable to injection."
                ),
                workflow_file=workflow_name,
                job=job_id,
            ))

        for i, step in enumerate(job.get("steps") or []):
            step_env = step.get("env") or {}
            if step_env.get("ACTIONS_ALLOW_UNSECURE_COMMANDS") in ("true", True):
                findings.append(Finding(
                    rule_id="GHA011",
                    severity=Severity.HIGH.value,
                    title="ACTIONS_ALLOW_UNSECURE_COMMANDS enabled at step level",
                    description=(
                        "Enabling ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables "
                        "deprecated set-env and add-path commands."
                    ),
                    workflow_file=workflow_name,
                    job=job_id,
                    step=step.get("name") or step.get("id") or f"step-{i}",
                ))

    return findings


# ---------------------------------------------------------------------------
# Rule: Dangerous default branch triggers with no branch filter
# ---------------------------------------------------------------------------

def check_unfiltered_triggers(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []

    on = workflow.get("on") or workflow.get(True)
    if not isinstance(on, dict):
        return findings

    # Check if push trigger has no branch filter (runs on all branches)
    push_config = on.get("push")
    if isinstance(push_config, dict):
        if not push_config.get("branches") and not push_config.get("tags"):
            findings.append(Finding(
                rule_id="GHA012",
                severity=Severity.LOW.value,
                title="Push trigger with no branch filter",
                description=(
                    "The push trigger has no branch filter, meaning it runs on "
                    "pushes to any branch. Consider restricting to specific branches "
                    "to reduce unnecessary workflow runs and potential abuse."
                ),
                workflow_file=workflow_name,
            ))
    elif push_config is None or push_config == {}:
        pass  # push trigger not present

    return findings


# ---------------------------------------------------------------------------
# Rule: Third-party actions from potentially risky sources
# ---------------------------------------------------------------------------

def check_third_party_actions(
    workflow_name: str, workflow: dict, repo_meta: dict
) -> list[Finding]:
    findings = []

    well_known_owners = {
        "actions", "github", "azure", "docker", "aws-actions",
        "google-github-actions", "hashicorp", "gradle", "ruby",
        "pypa", "codecov", "dorny", "peter-evans", "softprops",
    }

    for job_id, job in _get_jobs(workflow).items():
        for i, step in enumerate(job.get("steps") or []):
            uses = step.get("uses", "")
            if not uses or uses.startswith("./") or uses.startswith("docker://"):
                continue

            action_ref = uses.split("@")[0] if "@" in uses else uses
            owner = action_ref.split("/")[0] if "/" in action_ref else ""

            if owner.lower() not in well_known_owners:
                findings.append(Finding(
                    rule_id="GHA013",
                    severity=Severity.INFO.value,
                    title=f"Third-party action from '{owner}'",
                    description=(
                        f"Action '{uses}' is from '{owner}', which is not in the "
                        f"list of well-known action publishers. Review this action "
                        f"for trustworthiness and pin to a commit SHA."
                    ),
                    workflow_file=workflow_name,
                    job=job_id,
                    step=step.get("name") or step.get("id") or f"step-{i}",
                ))

    return findings


# ---------------------------------------------------------------------------
# Registry of all rules
# ---------------------------------------------------------------------------

ALL_RULES = [
    check_pull_request_target,
    check_script_injection,
    check_unpinned_actions,
    check_permissions,
    check_self_hosted_runners,
    check_workflow_run,
    check_env_secrets_exposure,
    check_unsafe_artifacts,
    check_persist_credentials,
    check_vulnerable_actions,
    check_unsecure_commands,
    check_unfiltered_triggers,
    check_third_party_actions,
]
