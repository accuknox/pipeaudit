# Dev Pipeline Auditor

Audit workflows, branch protection, repository security features, and organization settings across an entire GitHub organization — or Azure DevOps projects.

![demo](res/demo.gif)

## Features

### GitHub

- **Workflow Security** (GHA001-GHA013) — pull_request_target misuse, script injection, unpinned actions, overly permissive permissions, self-hosted runner risks, and more
- **Branch Protection** (BPR001-BPR010) — required reviews, push restrictions, status checks, signed commits, code owner reviews, linear history
- **Repository Security** (SEC001-SEC005) — secret scanning, push protection, Dependabot, CODEOWNERS, SECURITY.md
- **Organization Settings** (ORG001-ORG005) — 2FA requirement, default permissions, allowed actions, GITHUB_TOKEN defaults
- **Identity & Access** (IAM001-IAM011) — org admins, outside collaborators, team permissions, inactive members
- **Apps & Tokens** (APP001-APP005, PAT001-PAT005) — inactive app installations, overly permissive apps, stale PATs, non-expiring tokens, broad repo access

### Azure DevOps

- **Pipeline Security** (AZP001-AZP008) — persist credentials, unpinned templates, service connection misuse, script injection, self-hosted agents, approval gates, variable group exposure
- **Branch Policies** (ABP001-ABP007) — minimum reviewers, required reviewers, self-approval, build validation, comment resolution, merge strategy
- **Repository Security** (ASC001-ASC004) — credential scanning, dependency scanning, fork restrictions, security policy
- **Project Settings** (AOG001-AOG005) — guest access, public projects, third-party apps, SSH policy, project permissions
- **Identity & Access** (AIM001-AIM005) — excessive admins, inactive users, guest privileges, service account expiry, direct permissions

Reports are generated in JSON, HTML, and SARIF formats.

## Installation

### One-line install (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/accuknox/gh-audit/main/install.sh | sh
```

This downloads the latest pre-built binary for your platform and installs it to `/usr/local/bin` (or `~/.local/bin` if not writable). You can control the install directory and version:

```bash
VERSION=0.1.0 INSTALL_DIR=~/bin curl -fsSL https://raw.githubusercontent.com/accuknox/gh-audit/main/install.sh | sh
```

### Pre-built binaries

Download the latest binary for your platform from the [Releases](https://github.com/accuknox/gh-audit/releases) page.

### From source

```bash
git clone https://github.com/accuknox/gh-audit.git
cd gh-audit
pip install .
```

### For development

```bash
pip install -e ".[dev]"
```

## Setup

### GitHub

Create a **fine-grained Personal Access Token** (classic PATs are not supported):

1. Go to https://github.com/settings/personal-access-tokens/new
2. Under **Resource owner**, select your organization
3. Under **Repository access**, choose **All repositories**
4. Set these **Repository permissions** to **Read-only**:
   - Administration
   - Contents
   - Metadata (auto-granted)
5. Set these **Organization permissions** to **Read-only**:
   - Members
   - Administration _(optional — needed for Apps & Tokens audit; the audit degrades gracefully without it)_
6. Leave all other permissions as **No access**

Export the token:

```bash
export GH_AUDIT_TOKEN=github_pat_...
```

### Azure DevOps

Create a **Personal Access Token** with the following scopes:

1. Go to `https://dev.azure.com/{your-org}/_usersSettings/tokens`
2. Create a new token with these scopes:
   - **Code**: Read
   - **Build**: Read
   - **Graph**: Read
   - **Project and Team**: Read
   - **Security**: Manage (for identity/access audits)
3. Set an appropriate expiration

Export the token:

```bash
export ADO_AUDIT_TOKEN=...
```


### GITLAB — PERSONAL ACCESS TOKEN SETUP:
  Create a Personal Access Token (PAT) with read_api scope.

  1. Go to: https://gitlab.com/-/user_settings/personal_access_tokens

  2. Create a token with these scopes:
       read_api ......... Read       (needed to read groups, projects,
                                      pipelines, and settings)

  3. Set an appropriate expiration (30-90 days recommended).

  4. Click 'Create personal access token' and export it:
       export GL_AUDIT_TOKEN=glpat-...

  5. Run the audit:
       pipeaudit --platform gitlab --org my-group --output report.json
     
## Usage

### GitHub

#### With a config file

```bash
pipeaudit --config audit-config.yaml
```

#### With CLI arguments

```bash
pipeaudit --org my-org --output report.json --html report.html --sarif report.sarif
```

#### Audit specific repos

```bash
pipeaudit --org my-org --repos my-org/frontend my-org/backend:develop
```

#### Skip optional audits

```bash
pipeaudit --config audit-config.yaml --skip-identity
```

### Azure DevOps

```bash
pipeaudit --platform azure --org my-ado-org --output report.json --html report.html
```

#### Audit specific Azure DevOps projects

```bash
pipeaudit --platform azure --org my-ado-org --projects MyProject BackendProject
```

## Configuration

### GitHub config

Create an `audit-config.yaml`:

```yaml
org: my-org
output: report.json
html_output: report.html
sarif_output: report.sarif
include_archived: false
include_forks: false
skip_identity: false
skip_repo_security: false
skip_org_settings: false
skip_apps_and_tokens: false
updated_within_months: 3
```

### Azure DevOps config

```yaml
platform: azure
org: my-ado-org
projects:
  - MyProject
  - BackendProject
output: report.json
html_output: report.html
sarif_output: report.sarif
skip_identity: false
skip_project_settings: false
skip_pipeline_security: false
include_disabled_repos: false
updated_within_months: 3
```

## Risk Scoring

Every audit produces a **0-100 risk score** and a letter grade for the organization and each individual repository.

### How it works

Each unique rule violation deducts points from a perfect score of 100. The penalty uses **diminishing returns** — the first instance of a rule costs the full severity weight, but additional instances of the same rule add only +1 point each, capped at 2x the base weight. This means 50 unpinned-action findings are penalized similarly to 5, because they reflect the same underlying practice gap.

| Severity | Base Weight | Max per Rule (2x) |
|----------|-----------|-------------------|
| Critical | 10 | 20 |
| High | 7 | 14 |
| Medium | 4 | 8 |
| Low | 2 | 4 |
| Info | 0.5 | 1 |

**Example:** A rule with severity `high` (base=7):
- 1 instance → penalty = 7
- 3 instances → penalty = 7 + 2 = 9
- 50 instances → penalty = 7 + 7 = 14 (capped)

**Repository score** = `max(0, 100 - sum of per-rule penalties)`

The score reflects how many *different* security issues a repo has, not just the raw count of findings.

**Organization score** = `repo_average - org_penalties - identity_penalties - apps_tokens_penalties`

The org score starts as the average of all repo scores, then deducts penalties for org-level findings (ORG001-ORG005), identity/access findings (IAM001-IAM011), and apps & tokens findings (APP001-APP005, PAT001-PAT005). Each category is **capped at 15 points** to prevent any single category from dominating the score (max total org deduction = 45 points).

### Grade scale

| Grade | Score Range | Interpretation |
|-------|-----------|----------------|
| A+ | 97-100 | Excellent — minimal or no findings |
| A | 93-96 | Strong security posture |
| A- | 90-92 | Good, with minor improvements possible |
| B+/B/B- | 80-89 | Adequate, some findings need attention |
| C+/C/C- | 70-79 | Needs improvement — multiple medium+ findings |
| D | 60-69 | Poor — significant security gaps |
| F | <60 | Critical — immediate remediation required |

### Where scores appear

- **JSON report**: `audit_metadata.org_score` and per-repo `score` fields
- **HTML report**: Org grade card at the top, per-repo score badges in repository headers
- **SARIF report**: `invocations[0].properties.riskScore`

## License

MIT
