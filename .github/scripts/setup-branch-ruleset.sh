#!/usr/bin/env bash
# Require security-scan before merging to master, without blocking pushes to demo branches.
set -euo pipefail

REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
RULESET_NAME="devin-vulnerability-agent"

RULESET_PAYLOAD=$(cat <<'EOF'
{
  "name": "devin-vulnerability-agent",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/master"],
      "exclude": []
    }
  },
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          {"context": "security-scan", "integration_id": 15368}
        ]
      }
    }
  ]
}
EOF
)

existing_id=$(gh api "repos/${REPO}/rulesets" --jq ".[] | select(.name == \"${RULESET_NAME}\") | .id" | head -1)

if [[ -n "${existing_id}" ]]; then
  gh api --method PUT "repos/${REPO}/rulesets/${existing_id}" --input - <<< "${RULESET_PAYLOAD}"
  echo "Updated ruleset ${RULESET_NAME} on ${REPO}"
else
  gh api --method POST "repos/${REPO}/rulesets" --input - <<< "${RULESET_PAYLOAD}"
  echo "Created ruleset ${RULESET_NAME} on ${REPO}"
fi

echo "Done. security-scan is required to merge into master only; demo-* branch pushes are allowed."
