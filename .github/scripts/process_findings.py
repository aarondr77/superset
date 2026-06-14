import json
import os
import subprocess
import sys
import time

import requests

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
DEVIN_API_KEY = os.environ["DEVIN_API_KEY"]
PR_NUMBER = os.environ["PR_NUMBER"]
REPO = os.environ["REPO"]
BRANCH = os.environ["BRANCH"]

DEVIN_API_BASE = "https://api.devin.ai/v1"
DEVIN_POLL_INTERVAL_SECONDS = int(os.environ.get("DEVIN_POLL_INTERVAL_SECONDS", "30"))
DEVIN_SESSION_TIMEOUT_SECONDS = int(os.environ.get("DEVIN_SESSION_TIMEOUT_SECONDS", "3600"))
DEVIN_TERMINAL_STATUSES = {"blocked", "finished"}
REMEDIATION_MARKER = "<!-- security-scan-devin-attempted -->"

# Your 5 injected findings — filter to these for the demo
TARGET_FINDINGS = [
    {"file": "superset/key_value/utils.py", "test_id": "B324"},
    {"file": "superset/views/core.py", "test_id": "B608"},
    {"file": "superset/config.py", "test_id": "B105", "line_min": 1183, "line_max": 1188},
    {"file": "superset/views/core.py", "test_id": "B310"},
    {"file": "superset/utils/core.py", "test_id": "B602"},
]

SEVERITY_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}


def load_findings():
    with open("bandit_results.json") as f:
        data = json.load(f)
    results = []
    for r in data.get("results", []):
        rel_path = r["filename"].replace("./", "")
        for target in TARGET_FINDINGS:
            if target["file"] in rel_path and r["test_id"] == target["test_id"]:
                if "line_min" in target:
                    if target["line_min"] <= r["line_number"] <= target["line_max"]:
                        results.append(r)
                else:
                    results.append(r)
    return results


def finding_key(finding):
    return (
        finding["test_id"],
        finding["filename"].replace("./", ""),
        finding["line_number"],
    )


def get_git_blame(filepath, line_number):
    try:
        result = subprocess.run(
            ["git", "blame", "-L", f"{line_number},{line_number}", "--porcelain", filepath],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in result.stdout.splitlines():
            if line.startswith("author "):
                return line.replace("author ", "").strip()
    except Exception:
        pass
    return "Unknown"


def run_bandit():
    subprocess.run(
        ["bandit", "-r", "superset/", "-f", "json", "-o", "bandit_results.json"],
        check=False,
    )


def sync_pr_branch():
    subprocess.run(["git", "fetch", "origin", BRANCH], check=True)
    subprocess.run(["git", "checkout", "-B", BRANCH, f"origin/{BRANCH}"], check=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    sha = head.stdout.strip()
    print(f"Synced to origin/{BRANCH} at {sha}")
    return sha


def gh_headers():
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }


def remediation_already_attempted():
    response = requests.get(
        f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments",
        headers=gh_headers(),
        timeout=30,
    )
    response.raise_for_status()
    return any(REMEDIATION_MARKER in (c.get("body") or "") for c in response.json())


def mark_remediation_attempted():
    requests.post(
        f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments",
        headers=gh_headers(),
        json={"body": f"{REMEDIATION_MARKER}\n_Automatic remediation was attempted on this PR._"},
        timeout=30,
    ).raise_for_status()


def format_findings_table(findings):
    rows = []
    for f in findings:
        filepath = f["filename"].replace("./", "")
        author = get_git_blame(filepath, f["line_number"])
        emoji = SEVERITY_EMOJI.get(f["issue_severity"], "⚪")
        rows.append(
            f"| {emoji} {f['issue_severity']} | `{f['test_id']}` | "
            f"`{filepath}:{f['line_number']}` | {f['issue_text'][:60]} | {author} |"
        )
    return "\n".join(rows)


def post_pr_review(body, event):
    response = requests.post(
        f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}/reviews",
        headers=gh_headers(),
        json={"body": body, "event": event},
        timeout=30,
    )
    response.raise_for_status()
    print(f"Posted PR review: {event}")


def post_issue_comment(body):
    response = requests.post(
        f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments",
        headers=gh_headers(),
        json={"body": body},
        timeout=30,
    )
    response.raise_for_status()


def sha_note(sha):
    return f"\n\n_Scanned commit: `{sha[:7]}`_" if sha else ""


def post_initial_review(findings, sha):
    table = format_findings_table(findings)
    body = f"""## 🔒 Security Scan — {len(findings)} Finding(s) Detected

| Severity | Rule | Location | Description | Introduced By |
|----------|------|----------|-------------|---------------|
{table}

**Devin will remediate each finding once, sequentially.** Do not merge until the security scan passes.{sha_note(sha)}
"""
    post_pr_review(body, "REQUEST_CHANGES")


def post_pass_review(sha):
    body = f"## ✅ Security Scan Passed\n\nNo target security findings detected.{sha_note(sha)}"
    post_pr_review(body, "APPROVE")


def post_remediation_failed_review(original_keys, remaining, sha):
    table = format_findings_table(remaining)
    persisted = [k for k in map(finding_key, remaining) if k in original_keys]
    persisted_rules = ", ".join(sorted({k[0] for k in persisted})) or "n/a"

    body = f"""## ⚠️ Security Scan — Remediation Incomplete

Devin attempted to fix the findings below, but a follow-up Bandit scan still reports **{len(remaining)}** issue(s).

| Severity | Rule | Location | Description | Introduced By |
|----------|------|----------|-------------|---------------|
{table}

**No further automatic remediation will be run on this PR.** Rules still failing include: {persisted_rules}.

Please fix the remaining issues manually, then tag `@devin-error-detector` again to re-run the scan only.{sha_note(sha)}
"""
    post_pr_review(body, "REQUEST_CHANGES")


def post_skip_remediation_comment(findings, sha):
    table = format_findings_table(findings)
    post_issue_comment(
        f"""## ⚠️ Security Scan — Automatic Remediation Skipped

Findings were detected, but automatic remediation **already ran once** on this PR and will not be retried.

| Severity | Rule | Location | Description | Introduced By |
|----------|------|----------|-------------|---------------|
{table}

Fix the remaining issues manually, then tag `@devin-error-detector` to re-run the scan.{sha_note(sha)}
"""
    )


def trigger_devin_session(finding, index, total):
    filepath = finding["filename"].replace("./", "")
    code_snippet = finding.get("code", "").strip()

    prompt = f"""You are working on a pull request in a fork of Apache Superset.

## Your Task
Fix a security vulnerability that was detected by an automated scan on this PR.
Commit your fix directly to the branch `{BRANCH}` in the repository `https://github.com/{REPO}`.

This is remediation **{index} of {total}** in a sequential batch. Earlier fixes may already be on the branch — always sync before editing.

## Vulnerability Details
- **Rule:** {finding["test_id"]}
- **Severity:** {finding["issue_severity"]}
- **File:** `{filepath}`
- **Line:** {finding["line_number"]}
- **Description:** {finding["issue_text"]}

## Vulnerable Code
```python
{code_snippet}
```

## Instructions
1. Clone or update the repo and run `git pull origin {BRANCH}` before making changes
2. Navigate to `{filepath}` at line {finding["line_number"]}
3. Fix the vulnerability described above
4. Verify that running `bandit -r {filepath}` no longer reports {finding["test_id"]} on this code
5. Commit the fix to branch `{BRANCH}` with message: `fix: remediate {finding["test_id"]} in {filepath}`
6. Push to `{BRANCH}` and do not open a new PR

## Acceptance Criteria
- [ ] Branch is up to date with `origin/{BRANCH}` before edits
- [ ] {finding["test_id"]} no longer fires on the fixed code
- [ ] Function signatures and behavior are unchanged
- [ ] Fix is committed and pushed to branch `{BRANCH}`
"""

    response = requests.post(
        f"{DEVIN_API_BASE}/sessions",
        headers={
            "Authorization": f"Bearer {DEVIN_API_KEY}",
            "Content-Type": "application/json",
        },
        json={"prompt": prompt},
        timeout=30,
    )
    response.raise_for_status()

    session_id = response.json().get("session_id")
    print(f"Devin session started for {finding['test_id']}: {session_id}")
    return session_id


def wait_for_devin_session(session_id, test_id):
    headers = {"Authorization": f"Bearer {DEVIN_API_KEY}"}
    deadline = time.monotonic() + DEVIN_SESSION_TIMEOUT_SECONDS

    while time.monotonic() < deadline:
        response = requests.get(
            f"{DEVIN_API_BASE}/sessions/{session_id}",
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        status_enum = response.json().get("status_enum", "unknown")
        print(f"Devin session {session_id} ({test_id}) status: {status_enum}")

        if status_enum in DEVIN_TERMINAL_STATUSES:
            if status_enum == "blocked":
                raise RuntimeError(
                    f"Devin session {session_id} for {test_id} is blocked and needs attention"
                )
            return

        time.sleep(DEVIN_POLL_INTERVAL_SECONDS)

    raise TimeoutError(
        f"Devin session {session_id} for {test_id} did not finish within "
        f"{DEVIN_SESSION_TIMEOUT_SECONDS} seconds"
    )


def main():
    initial_sha = os.environ.get("SCANNED_SHA", "")
    findings = load_findings()
    print(f"Found {len(findings)} target findings")

    if not findings:
        post_pass_review(initial_sha)
        return

    if remediation_already_attempted():
        print("Remediation already attempted on this PR — skipping Devin.")
        post_skip_remediation_comment(findings, initial_sha)
        sys.exit(1)

    original_keys = {finding_key(f) for f in findings}
    post_initial_review(findings, initial_sha)

    total = len(findings)
    for index, finding in enumerate(findings, start=1):
        session_id = trigger_devin_session(finding, index, total)
        if not session_id:
            raise RuntimeError(f"Devin did not return a session_id for {finding['test_id']}")
        wait_for_devin_session(session_id, finding["test_id"])
        print(f"Completed remediation {index}/{total} for {finding['test_id']}")

    mark_remediation_attempted()

    print("Devin remediation complete — re-scanning latest branch...")
    final_sha = sync_pr_branch()
    run_bandit()
    remaining = load_findings()
    print(f"Remaining findings after remediation: {len(remaining)}")

    if remaining:
        post_remediation_failed_review(original_keys, remaining, final_sha)
        sys.exit(1)

    post_pass_review(final_sha)
    print("Security scan passed.")


if __name__ == "__main__":
    main()
