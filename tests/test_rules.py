"""Tests for the security rules."""

import pytest

from pipeaudit.rules import (
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
)


def _public_repo():
    return {"full_name": "org/repo", "private": False, "visibility": "public"}


def _private_repo():
    return {"full_name": "org/repo", "private": True, "visibility": "private"}


# ---------------------------------------------------------------------------
# GHA001: pull_request_target
# ---------------------------------------------------------------------------

class TestPullRequestTarget:
    def test_detects_prt_in_public_repo(self):
        wf = {"on": {"pull_request_target": {}}, "jobs": {}}
        findings = check_pull_request_target("ci.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].rule_id == "GHA001"
        assert findings[0].severity == "critical"

    def test_detects_prt_in_private_repo_as_high(self):
        wf = {"on": {"pull_request_target": {}}, "jobs": {}}
        findings = check_pull_request_target("ci.yml", wf, _private_repo())
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_no_finding_without_prt(self):
        wf = {"on": {"push": {}}, "jobs": {}}
        findings = check_pull_request_target("ci.yml", wf, _public_repo())
        assert len(findings) == 0

    def test_detects_checkout_of_pr_head(self):
        wf = {
            "on": {"pull_request_target": {}},
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "uses": "actions/checkout@v4",
                            "with": {"ref": "${{ github.event.pull_request.head.sha }}"},
                        }
                    ]
                }
            },
        }
        findings = check_pull_request_target("ci.yml", wf, _public_repo())
        assert any(f.rule_id == "GHA001a" for f in findings)


# ---------------------------------------------------------------------------
# GHA002: Script injection
# ---------------------------------------------------------------------------

class TestScriptInjection:
    def test_detects_untrusted_input_in_run(self):
        wf = {
            "on": "push",
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "name": "Echo title",
                            "run": 'echo "${{ github.event.issue.title }}"',
                        }
                    ]
                }
            },
        }
        findings = check_script_injection("ci.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].rule_id == "GHA002"

    def test_safe_expression_no_finding(self):
        wf = {
            "on": "push",
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "name": "Echo SHA",
                            "run": 'echo "${{ github.sha }}"',
                        }
                    ]
                }
            },
        }
        findings = check_script_injection("ci.yml", wf, _public_repo())
        assert len(findings) == 0

    def test_detects_pr_body_injection(self):
        wf = {
            "on": "pull_request",
            "jobs": {
                "check": {
                    "steps": [
                        {
                            "run": 'echo "${{ github.event.pull_request.body }}"',
                        }
                    ]
                }
            },
        }
        findings = check_script_injection("ci.yml", wf, _public_repo())
        assert len(findings) == 1

    def test_detects_head_ref_injection(self):
        wf = {
            "on": "pull_request",
            "jobs": {
                "check": {
                    "steps": [
                        {"run": "git checkout ${{ github.head_ref }}"}
                    ]
                }
            },
        }
        findings = check_script_injection("ci.yml", wf, _public_repo())
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# GHA003: Unpinned actions
# ---------------------------------------------------------------------------

class TestUnpinnedActions:
    def test_trusted_owner_tag_ref_is_medium(self):
        wf = {
            "on": "push",
            "jobs": {"build": {"steps": [{"uses": "actions/checkout@v4"}]}},
        }
        findings = check_unpinned_actions("ci.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].rule_id == "GHA003"
        assert findings[0].severity == "medium"

    def test_sha_pinned_no_finding(self):
        wf = {
            "on": "push",
            "jobs": {
                "build": {
                    "steps": [{"uses": "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29"}]
                }
            },
        }
        findings = check_unpinned_actions("ci.yml", wf, _public_repo())
        assert len(findings) == 0

    def test_third_party_branch_ref_is_high(self):
        wf = {
            "on": "push",
            "jobs": {"build": {"steps": [{"uses": "unknown-owner/action@main"}]}},
        }
        findings = check_unpinned_actions("ci.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_third_party_version_tag_is_high(self):
        wf = {
            "on": "push",
            "jobs": {"build": {"steps": [{"uses": "unknown-owner/action@v2"}]}},
        }
        findings = check_unpinned_actions("ci.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_branch_ref_is_high_even_for_trusted_owner(self):
        # Branches are continuously moving — always HIGH regardless of owner trust.
        wf = {
            "on": "push",
            "jobs": {"build": {"steps": [{"uses": "actions/checkout@master"}]}},
        }
        findings = check_unpinned_actions("ci.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_own_org_version_tag_is_medium(self):
        # Own-org actions are not an external supply chain risk.
        wf = {
            "on": "push",
            "jobs": {"build": {"steps": [{"uses": "org/some-action@v1"}]}},
        }
        # _public_repo() has full_name "org/repo", so "org" is the current org.
        findings = check_unpinned_actions("ci.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_own_org_branch_ref_is_high(self):
        # Even own-org actions on a branch are HIGH — branches are mutable.
        wf = {
            "on": "push",
            "jobs": {"build": {"steps": [{"uses": "org/some-action@main"}]}},
        }
        findings = check_unpinned_actions("ci.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_local_action_no_finding(self):
        wf = {
            "on": "push",
            "jobs": {"build": {"steps": [{"uses": "./.github/actions/my-action"}]}},
        }
        findings = check_unpinned_actions("ci.yml", wf, _public_repo())
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# GHA004: Permissions
# ---------------------------------------------------------------------------

class TestPermissions:
    def test_no_permissions_declared(self):
        wf = {"on": "push", "jobs": {"build": {"steps": []}}}
        findings = check_permissions("ci.yml", wf, _public_repo())
        assert any(f.rule_id == "GHA004" for f in findings)

    def test_write_all_detected(self):
        wf = {"on": "push", "permissions": "write-all", "jobs": {}}
        findings = check_permissions("ci.yml", wf, _public_repo())
        assert any(f.severity == "high" for f in findings)

    def test_read_all_no_high_finding(self):
        wf = {"on": "push", "permissions": "read-all", "jobs": {}}
        findings = check_permissions("ci.yml", wf, _public_repo())
        assert not any(f.severity == "high" for f in findings)

    def test_fine_grained_permissions_ok(self):
        wf = {
            "on": "push",
            "permissions": {"contents": "read"},
            "jobs": {},
        }
        findings = check_permissions("ci.yml", wf, _public_repo())
        # No high/critical findings expected
        assert not any(f.severity in ("high", "critical") for f in findings)


# ---------------------------------------------------------------------------
# GHA005: Self-hosted runners in public repos
# ---------------------------------------------------------------------------

class TestSelfHostedRunners:
    def test_detects_self_hosted_in_public(self):
        wf = {
            "on": "push",
            "jobs": {"build": {"runs-on": "self-hosted", "steps": []}},
        }
        findings = check_self_hosted_runners("ci.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_no_finding_in_private(self):
        wf = {
            "on": "push",
            "jobs": {"build": {"runs-on": "self-hosted", "steps": []}},
        }
        findings = check_self_hosted_runners("ci.yml", wf, _private_repo())
        assert len(findings) == 0

    def test_github_hosted_no_finding(self):
        wf = {
            "on": "push",
            "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": []}},
        }
        findings = check_self_hosted_runners("ci.yml", wf, _public_repo())
        assert len(findings) == 0

    def test_list_format_self_hosted(self):
        wf = {
            "on": "push",
            "jobs": {"build": {"runs-on": ["self-hosted", "linux"], "steps": []}},
        }
        findings = check_self_hosted_runners("ci.yml", wf, _public_repo())
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# GHA006: workflow_run
# ---------------------------------------------------------------------------

class TestWorkflowRun:
    def test_detects_workflow_run(self):
        wf = {"on": {"workflow_run": {"workflows": ["CI"]}}, "jobs": {}}
        findings = check_workflow_run("deploy.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].rule_id == "GHA006"

    def test_no_finding_without_workflow_run(self):
        wf = {"on": "push", "jobs": {}}
        findings = check_workflow_run("ci.yml", wf, _public_repo())
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# GHA007: Secrets in pull_request_target
# ---------------------------------------------------------------------------

class TestSecretsExposure:
    def test_detects_secrets_in_prt(self):
        wf = {
            "on": {"pull_request_target": {}},
            "jobs": {
                "build": {
                    "steps": [
                        {"run": "echo ${{ secrets.MY_TOKEN }}"}
                    ]
                }
            },
        }
        findings = check_env_secrets_exposure("ci.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].rule_id == "GHA007"


# ---------------------------------------------------------------------------
# GHA008: Unsafe artifacts
# ---------------------------------------------------------------------------

class TestUnsafeArtifacts:
    def test_detects_download_in_workflow_run(self):
        wf = {
            "on": {"workflow_run": {"workflows": ["CI"]}},
            "jobs": {
                "deploy": {
                    "steps": [
                        {"uses": "actions/download-artifact@v4"}
                    ]
                }
            },
        }
        findings = check_unsafe_artifacts("deploy.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].rule_id == "GHA008"


# ---------------------------------------------------------------------------
# GHA009: persist-credentials
# ---------------------------------------------------------------------------

class TestPersistCredentials:
    def test_default_persist_credentials(self):
        wf = {
            "on": "push",
            "jobs": {
                "build": {
                    "steps": [{"uses": "actions/checkout@v4"}]
                }
            },
        }
        findings = check_persist_credentials("ci.yml", wf, _public_repo())
        assert len(findings) == 1

    def test_persist_false_no_finding(self):
        wf = {
            "on": "push",
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "uses": "actions/checkout@v4",
                            "with": {"persist-credentials": False},
                        }
                    ]
                }
            },
        }
        findings = check_persist_credentials("ci.yml", wf, _public_repo())
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# GHA010: Vulnerable actions
# ---------------------------------------------------------------------------

class TestVulnerableActions:
    def test_detects_old_checkout(self):
        wf = {
            "on": "push",
            "jobs": {
                "build": {
                    "steps": [{"uses": "actions/checkout@v1"}]
                }
            },
        }
        findings = check_vulnerable_actions("ci.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].rule_id == "GHA010"


# ---------------------------------------------------------------------------
# GHA011: ACTIONS_ALLOW_UNSECURE_COMMANDS
# ---------------------------------------------------------------------------

class TestUnsecureCommands:
    def test_detects_at_top_level(self):
        wf = {
            "on": "push",
            "env": {"ACTIONS_ALLOW_UNSECURE_COMMANDS": "true"},
            "jobs": {},
        }
        findings = check_unsecure_commands("ci.yml", wf, _public_repo())
        assert len(findings) == 1

    def test_detects_at_job_level(self):
        wf = {
            "on": "push",
            "jobs": {
                "build": {
                    "env": {"ACTIONS_ALLOW_UNSECURE_COMMANDS": "true"},
                    "steps": [],
                }
            },
        }
        findings = check_unsecure_commands("ci.yml", wf, _public_repo())
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# GHA012: Unfiltered triggers
# ---------------------------------------------------------------------------

class TestUnfilteredTriggers:
    def test_push_without_branch_filter(self):
        wf = {"on": {"push": {"paths": ["src/**"]}}, "jobs": {}}
        findings = check_unfiltered_triggers("ci.yml", wf, _public_repo())
        assert len(findings) == 1

    def test_push_with_branch_filter_no_finding(self):
        wf = {"on": {"push": {"branches": ["main"]}}, "jobs": {}}
        findings = check_unfiltered_triggers("ci.yml", wf, _public_repo())
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# GHA013: Third-party actions
# ---------------------------------------------------------------------------

class TestThirdPartyActions:
    def test_detects_unknown_publisher(self):
        wf = {
            "on": "push",
            "jobs": {
                "build": {
                    "steps": [{"uses": "random-person/action@v1"}]
                }
            },
        }
        findings = check_third_party_actions("ci.yml", wf, _public_repo())
        assert len(findings) == 1
        assert findings[0].severity == "info"

    def test_well_known_no_finding(self):
        wf = {
            "on": "push",
            "jobs": {
                "build": {
                    "steps": [{"uses": "actions/setup-node@v4"}]
                }
            },
        }
        findings = check_third_party_actions("ci.yml", wf, _public_repo())
        assert len(findings) == 0
