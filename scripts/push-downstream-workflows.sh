#!/usr/bin/env bash
# push-downstream-workflows.sh
#
# Creates PRs in downstream repos to add the bump-nono.yml workflow.
# Requires: gh CLI authenticated with repo scope for nolabs-ai org.
#
# Usage: ./scripts/push-downstream-workflows.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKFLOW_DIR="${SCRIPT_DIR}/downstream-workflows"

declare -A REPOS=(
  ["nono-py"]="bump-nono-py.yml"
  ["nono-ts"]="bump-nono-ts.yml"
  ["nono-go"]="bump-nono-go.yml"
  ["nono-registry"]="bump-nono-registry.yml"
  ["nono-docs"]="bump-nono-docs.yml"
)

BRANCH="add-bump-nono-workflow"
COMMIT_MSG="ci: add automated nono version bump workflow

Adds a workflow that receives repository_dispatch events from the
nono release pipeline and creates a PR to bump the nono dependency.

Signed-off-by: nono-release-automation <noreply@nono.sh>"

for repo in "${!REPOS[@]}"; do
  workflow_file="${REPOS[$repo]}"
  full_repo="nolabs-ai/${repo}"

  echo "==> Processing ${full_repo}..."

  # Check if PR already exists
  existing=$(gh pr list -R "${full_repo}" --search "add automated nono version bump workflow" --state open --json number --jq '.[0].number' 2>/dev/null || true)
  if [ -n "$existing" ]; then
    echo "    PR #${existing} already exists, skipping"
    continue
  fi

  # Clone, branch, add workflow, push, PR
  tmpdir=$(mktemp -d)
  gh repo clone "${full_repo}" "${tmpdir}" -- --depth 1

  cd "${tmpdir}"
  git checkout -b "${BRANCH}"

  mkdir -p .github/workflows
  cp "${WORKFLOW_DIR}/${workflow_file}" .github/workflows/bump-nono.yml

  git add .github/workflows/bump-nono.yml
  git commit -m "${COMMIT_MSG}"
  git push origin "${BRANCH}"

  gh pr create \
    --repo "${full_repo}" \
    --title "ci: add automated nono version bump workflow" \
    --body "$(cat <<'EOF'
## Summary

Adds `.github/workflows/bump-nono.yml` — an automated workflow that:

1. **Listens** for `repository_dispatch` events (type: `nono-release`) from the nono release pipeline
2. **Creates a PR** to bump the nono dependency to the new version
3. Can also be triggered manually via `workflow_dispatch`

This is part of the [nono release automation](https://github.com/nolabs-ai/nono) that keeps all downstream SDKs and services in sync when a new nono version is released.

### Flow
```
nono tag v0.X.0
  → nono release.yml builds + publishes
  → dispatches nono-release event to this repo
  → bump-nono.yml creates a PR with the version bump
  → maintainer reviews + merges
  → existing release/deploy workflow runs
```

### Required setup
- A `DOWNSTREAM_PAT` secret must be configured in the nono repo with `repo` scope for the `nolabs-ai` org

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"

  echo "    PR created for ${full_repo}"
  cd -
  rm -rf "${tmpdir}"
done

echo ""
echo "Done! Remember to add the DOWNSTREAM_PAT secret to nolabs-ai/nono."
