#!/bin/bash
# Upstream Drift Check Tests
# Verifies the bash + PowerShell twin scripts produce identical JSON for known
# ranges, tag auto-detection picks v0.X tags (not fork v2.X), missing upstream
# remote exits 1 with actionable hint, --format table emits category-grouped
# output, and the read-only invariant holds (git status clean post-invocation).
#
# This suite does NOT require the nono binary. It tests
# scripts/check-upstream-drift.{sh,ps1}. It is NOT in tests/run_integration_tests.sh
# SUITES array (which builds nono via cargo first). Run standalone:
#   bash tests/integration/test_upstream_drift.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../lib/test_helpers.sh"
# test_helpers.sh sets `set -euo pipefail`; restore the looser mode so failed
# assertions don't abort the whole suite (we want to keep running through all
# checks and report a final summary).
set +e

echo ""
echo -e "${BLUE}=== Upstream Drift Tests ===${NC}"

FIXTURES="$SCRIPT_DIR/fixtures/upstream-drift"
SCRIPT_SH="$REPO_ROOT/scripts/check-upstream-drift.sh"
SCRIPT_PS1="$REPO_ROOT/scripts/check-upstream-drift.ps1"

# Local pass/fail helpers (test_helpers.sh's expect_* helpers focus on the nono
# binary; the drift test does plain shell assertions and benefits from compact
# pass/fail rendering).
pass() {
    echo -e "  ${GREEN}PASS${NC}: $1"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
}
fail() {
    echo -e "  ${RED}FAIL${NC}: $1"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

# ===========================================================================
# Test 1: Golden-fixture diff (bash) for 3 ranges
# ===========================================================================
echo ""
echo "Golden-fixture diff (bash):"
for range in "v0.37.1__v0.40.1" "v0.39.0__v0.40.0" "v0.40.0__v0.40.1"; do
    from="${range%__*}"
    to="${range#*__}"
    expected="$FIXTURES/${range}.json"
    if [[ ! -f "$expected" ]]; then
        fail "fixture missing: $expected"
        continue
    fi
    actual=$(bash "$SCRIPT_SH" --from "$from" --to "$to" --format json 2>/dev/null)
    if diff <(echo "$actual") "$expected" >/dev/null 2>&1; then
        pass "bash fixture diff: $range"
    else
        fail "bash fixture diff: $range (run: bash $SCRIPT_SH --from $from --to $to --format json | diff - $expected)"
    fi
done

# ===========================================================================
# Test 2: Twin-parity diff (skip if no PS interpreter)
# ===========================================================================
echo ""
echo "Twin-parity diff (bash vs PowerShell):"
PS_RUNNER=""
if command -v pwsh >/dev/null 2>&1; then
    PS_RUNNER="pwsh"
elif command -v powershell.exe >/dev/null 2>&1; then
    PS_RUNNER="powershell.exe"
fi
if [[ -n "$PS_RUNNER" ]]; then
    for range in "v0.37.1__v0.40.1" "v0.39.0__v0.40.0" "v0.40.0__v0.40.1"; do
        from="${range%__*}"
        to="${range#*__}"
        expected="$FIXTURES/${range}.json"
        actual_ps=$("$PS_RUNNER" -NoProfile -File "$SCRIPT_PS1" -From "$from" -To "$to" -Format json 2>/dev/null)
        if diff <(echo "$actual_ps") "$expected" >/dev/null 2>&1; then
            pass "ps fixture diff ($PS_RUNNER): $range"
        else
            fail "ps fixture diff ($PS_RUNNER): $range"
        fi
    done
else
    echo "  SKIP: no PowerShell runner on PATH (pwsh / powershell.exe both absent)"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
fi

# ===========================================================================
# Test 3: Tag auto-detect picks v0.X (not fork v1.X / v2.X)
# ===========================================================================
echo ""
echo "Tag auto-detect:"
auto_output=$(bash "$SCRIPT_SH" --format json 2>/dev/null)
if [[ -n "$auto_output" ]] \
   && echo "$auto_output" \
       | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); sys.exit(0 if d['from'].startswith('v0.') else 1)" 2>/dev/null; then
    pass "auto-detected from-tag matches ^v0\\. (not fork v1./v2.)"
else
    fail "auto-detect failed or returned a non-v0.X from-tag (output prefix: ${auto_output:0:200})"
fi

# ===========================================================================
# Test 4: Missing upstream remote -> exit 1 + hint
# ===========================================================================
echo ""
echo "Missing upstream remote:"
TMP_REPO=$(mktemp -d)
TMP_REPO_TRAP_SET=1
cleanup_tmp_repo() {
    if [[ "${TMP_REPO_TRAP_SET:-0}" -eq 1 && -n "${TMP_REPO:-}" && -d "$TMP_REPO" ]]; then
        rm -rf "$TMP_REPO"
    fi
}
trap cleanup_tmp_repo EXIT

(
    set +e
    cd "$TMP_REPO"
    git init -q
    git config user.email "test@example.invalid"
    git config user.name "Test"
    git commit --allow-empty -q -m init
    cp "$SCRIPT_SH" check-upstream-drift.sh
    chmod +x check-upstream-drift.sh
    bash check-upstream-drift.sh --from v0.40.0 --to v0.40.1 --format json 2>err.log
    rc=$?
    if [[ $rc -ne 0 ]] && grep -F 'git remote add upstream' err.log >/dev/null 2>&1; then
        echo "OK"
        exit 0
    else
        echo "BAD rc=$rc err=$(cat err.log 2>/dev/null | tr -d '\r' | head -c 200)"
        exit 1
    fi
)
remote_test_rc=$?
if [[ $remote_test_rc -eq 0 ]]; then
    pass "missing-upstream exits non-zero with actionable hint"
else
    fail "missing-upstream test failed"
fi

# ===========================================================================
# Test 5: --format table produces grouped output
# ===========================================================================
echo ""
echo "Table format:"
table_out=$(bash "$SCRIPT_SH" --from v0.37.1 --to v0.40.1 --format table 2>/dev/null)
if echo "$table_out" | head -1 | grep -qE '^Upstream drift: v0\.37\.1\.\.v0\.40\.1$'; then
    pass "table header line"
else
    fail "table header line missing (got: $(echo "$table_out" | head -1))"
fi
if echo "$table_out" | head -2 | tail -1 | grep -qE '^Total: [0-9]+ unique commits$'; then
    pass "table Total line"
else
    fail "table Total line missing"
fi
if echo "$table_out" | grep -qE '^## (profile|policy|package|proxy|audit|other) \([0-9]+ commits\)$'; then
    pass "table category section header present"
else
    fail "no table category section header found"
fi

# ===========================================================================
# Test 6: Read-only invariant (T-24-02)
# ===========================================================================
echo ""
echo "Read-only invariant:"
status_before=$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)
bash "$SCRIPT_SH" --from v0.40.0 --to v0.40.1 --format json > /dev/null 2>&1
status_after=$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)
if [[ "$status_before" == "$status_after" ]]; then
    pass "git status unchanged after script invocation"
else
    fail "git status diverged after invocation (script wrote something - security violation)"
fi

# ===========================================================================
# Test 7: Ref injection rejection (T-24-01)
# ===========================================================================
echo ""
echo "Ref injection rejection:"
if bash "$SCRIPT_SH" --from "v0.40.0; touch /tmp/nono-drift-pwn-$$" --to v0.40.1 >/dev/null 2>&1; then
    fail "injected ref accepted (security regression)"
else
    pass "injected ref rejected (T-24-01 mitigation)"
fi
# Defense-in-depth: even if injection somehow ran, the touched file should not
# exist; clean up just in case.
rm -f "/tmp/nono-drift-pwn-$$" 2>/dev/null || true

# ===========================================================================
# Test 8: Template file presence + D-19 trailer block (DRIFT-02)
# ===========================================================================
echo ""
echo "Template file presence + D-19 trailer block:"
TEMPLATE=".planning/templates/upstream-sync-quick.md"
TEMPLATE_PATH="$REPO_ROOT/$TEMPLATE"

if [[ -f "$TEMPLATE_PATH" ]]; then
    pass "template file exists at $TEMPLATE"
else
    fail "template file missing at $TEMPLATE"
fi

# 6-line D-19 trailer block, verified per-line.
if grep -qE '^Upstream-commit: \{[a-z_]+\}' "$TEMPLATE_PATH"; then
    pass "trailer line 1 (Upstream-commit) present"
else
    fail "trailer line 1 (Upstream-commit) missing or wrong placeholder shape"
fi

if grep -qE '^Upstream-tag: \{[a-z_]+\}' "$TEMPLATE_PATH"; then
    pass "trailer line 2 (Upstream-tag) present"
else
    fail "trailer line 2 (Upstream-tag) missing"
fi

# Lowercase 'a' in Upstream-author — D-19 LOCKED
if grep -qE '^Upstream-author: \{[a-z_]+\}' "$TEMPLATE_PATH"; then
    pass "trailer line 3 (Upstream-author, lowercase 'a') present"
else
    fail "trailer line 3 (Upstream-author) missing or capitalized 'Upstream-Author' (D-19 violation)"
fi

if grep -qE '^Upstream-Author' "$TEMPLATE_PATH"; then
    fail "FORBIDDEN capitalized 'Upstream-Author' present (D-19: must be lowercase 'a')"
else
    pass "no FORBIDDEN 'Upstream-Author' (capital A) present"
fi

if grep -qE '^Co-Authored-By: \{[a-z_]+\}' "$TEMPLATE_PATH"; then
    pass "trailer line 4 (Co-Authored-By) present"
else
    fail "trailer line 4 (Co-Authored-By) missing"
fi

# TWO Signed-off-by lines (DCO + GitHub attribution)
sob_count=$(grep -c '^Signed-off-by: ' "$TEMPLATE_PATH" || true)
if [[ "$sob_count" -eq 2 ]]; then
    pass "exactly 2 Signed-off-by lines (DCO + GitHub attribution)"
else
    fail "expected 2 Signed-off-by lines, got $sob_count (D-19 violation)"
fi

# ===========================================================================
# Test 9: Fork-divergence catalog explicit entries (DRIFT-02)
# ===========================================================================
echo ""
echo "Fork-divergence catalog explicit entries:"
for entry in 'validate_path_within' 'load_production_trusted_root' 'hooks.rs' '#[cfg(target_os = "windows")]'; do  # intentional fork: Phase 32 D-32-01
    if grep -qF "$entry" "$TEMPLATE_PATH"; then
        pass "fork-divergence catalog mentions: $entry"
    else
        fail "fork-divergence catalog missing: $entry"
    fi
done

# Deferred enum variants — accept either ArtifactType::Plugin OR generic phrase
if grep -qE '(ArtifactType::Plugin|deferred enum variants?)' "$TEMPLATE_PATH"; then
    pass "fork-divergence catalog mentions deferred enum variants"
else
    fail "fork-divergence catalog missing deferred-enum-variants entry"
fi

# ===========================================================================
# Test 10: Placeholder smoke test (T-24-05 mitigation)
# ===========================================================================
echo ""
echo "Placeholder smoke test (T-24-05):"
SMOKE_TMPDIR=$(mktemp -d)
cleanup_smoke_tmpdir() {
    if [[ -n "${SMOKE_TMPDIR:-}" && -d "$SMOKE_TMPDIR" ]]; then
        rm -rf "$SMOKE_TMPDIR"
    fi
}
# Chain to existing EXIT trap for tmp_repo cleanup; both must run.
trap 'cleanup_tmp_repo; cleanup_smoke_tmpdir' EXIT

# Substitute every {name} placeholder with sample values for a hypothetical v0.41.0 sync.
# Use a stable file rewrite via temp file rather than `sed -i` to avoid macOS BSD vs GNU
# divergence.
sed \
    -e 's|{quick_slug}|260501-upr-sync-v041|g' \
    -e 's|{date}|2026-05-01|g' \
    -e 's|{from_tag}|v0.40.1|g' \
    -e 's|{to_tag}|v0.41.0|g' \
    -e 's|{commit_count}|18|g' \
    -e 's|{insertions}|3|g' \
    -e 's|{deletions}|0|g' \
    -e 's|{n_profile}|3|g' \
    -e 's|{n_policy}|2|g' \
    -e 's|{n_package}|4|g' \
    -e 's|{n_proxy}|1|g' \
    -e 's|{n_audit}|6|g' \
    -e 's|{n_other}|2|g' \
    -e 's|{upstream_sha_abbrev}|abc12345|g' \
    -e 's|{upstream_sha_full}|abc12345abc12345abc12345abc12345abc12345|g' \
    -e 's|{upstream_tag}|v0.41.0|g' \
    -e 's|{upstream_author_name}|Upstream Author|g' \
    -e 's|{upstream_author_email}|upstream@example.com|g' \
    -e 's|{fork_author_name}|Fork Author|g' \
    -e 's|{fork_author_email}|fork@example.com|g' \
    -e 's|{fork_author_handle}|fork-handle|g' \
    -e 's|{fork_branch}|windows-squash|g' \
    "$TEMPLATE_PATH" > "$SMOKE_TMPDIR/PLAN.md"

# Assert no remaining {placeholder} markers.
# Strip HTML comment blocks before scanning. The template's leading and section
# comments contain illustrative placeholder syntax (e.g., `{placeholder}` in the
# smoke-check instruction and `{sha} {subject} ({adds}/{dels})` in the example
# commit-list format) — these are maintainer guidance, not unfilled fields, and
# they survive sed substitution by design. The maintainer's own smoke-check
# (per the leading comment block) operates on the user-visible content with the
# same comment-stripping semantics, so the test mirrors that contract.
stripped=$(awk '
    /<!--/{in_comment=1}
    !in_comment{print}
    /-->/{in_comment=0}
' "$SMOKE_TMPDIR/PLAN.md")
remaining=$(echo "$stripped" | grep -oE '\{[a-z_]+\}' || true)
remaining_count=0
if [[ -n "$remaining" ]]; then
    remaining_count=$(echo "$remaining" | grep -c '^' || true)
fi
if [[ "$remaining_count" -eq 0 ]]; then
    pass "all {placeholder} markers substituted cleanly (HTML comments excluded)"
else
    fail "unfilled placeholders remain in rendered template (outside HTML comments): $remaining"
fi

# Assert frontmatter delimiter is present.
# The template has a leading HTML comment block, so the first --- frontmatter line is
# not literally line 1. Use grep to assert it appears in the file.
if grep -qE '^---$' "$SMOKE_TMPDIR/PLAN.md"; then
    pass "rendered PLAN.md has frontmatter delimiter"
else
    fail "rendered PLAN.md missing frontmatter ---"
fi

if grep -qE '^slug: 260501-upr-sync-v041$' "$SMOKE_TMPDIR/PLAN.md"; then
    pass "rendered slug field substituted correctly"
else
    fail "rendered slug field missing or incorrect"
fi

if grep -qE '^range: v0\.40\.1\.\.v0\.41\.0$' "$SMOKE_TMPDIR/PLAN.md"; then
    pass "rendered range field substituted correctly"
else
    fail "rendered range field missing or incorrect"
fi

# Assert D-19 trailer block has expected structure post-substitution
if grep -qE '^Upstream-commit: abc12345$' "$SMOKE_TMPDIR/PLAN.md"; then
    pass "rendered D-19 trailer Upstream-commit substituted"
else
    fail "rendered D-19 trailer Upstream-commit missing"
fi

rendered_sob=$(grep -c '^Signed-off-by: ' "$SMOKE_TMPDIR/PLAN.md" || true)
if [[ "$rendered_sob" -eq 2 ]]; then
    pass "rendered D-19 trailer has 2 Signed-off-by lines"
else
    fail "rendered D-19 trailer Signed-off-by count wrong (got $rendered_sob)"
fi

# ===========================================================================
# Test 11: Documentation cross-links (DRIFT-02)
# ===========================================================================
echo ""
echo "Documentation cross-links:"
PROJECT_MD="$REPO_ROOT/.planning/PROJECT.md"
DOCS_MDX="$REPO_ROOT/docs/cli/development/upstream-drift.mdx"

# .mdx file exists (D-16: NOT .md)
if [[ -f "$DOCS_MDX" ]]; then
    pass "docs file exists at docs/cli/development/upstream-drift.mdx (D-16 .mdx convention)"
else
    fail "docs file missing at docs/cli/development/upstream-drift.mdx"
fi

# .md form does NOT exist (D-16 acceptance: enforces .mdx convention)
if [[ ! -f "$REPO_ROOT/docs/cli/development/upstream-drift.md" ]]; then
    pass "no stray .md form (D-16 .mdx convention upheld)"
else
    fail "FORBIDDEN docs/cli/development/upstream-drift.md exists (must be .mdx per D-16)"
fi

# .mdx Mintlify frontmatter present
if grep -qE '^title: Upstream Drift Check$' "$DOCS_MDX"; then
    pass "docs has Mintlify title frontmatter"
else
    fail "docs missing Mintlify title frontmatter"
fi

if grep -qE '^description: ' "$DOCS_MDX"; then
    pass "docs has Mintlify description frontmatter"
else
    fail "docs missing Mintlify description frontmatter"
fi

# .mdx cross-references to script + template + Upstream-author shape
for ref in 'make check-upstream-drift' 'upstream-sync-quick.md' 'Upstream-author'; do
    if grep -qF "$ref" "$DOCS_MDX"; then
        pass "docs references: $ref"
    else
        fail "docs missing reference to: $ref"
    fi
done

# PROJECT.md has new section + cross-links
if grep -qE '^## Upstream Parity Process$' "$PROJECT_MD"; then
    pass "PROJECT.md has '## Upstream Parity Process' H2 section"
else
    fail "PROJECT.md missing '## Upstream Parity Process' H2 section"
fi

for ref in '.planning/templates/upstream-sync-quick.md' 'docs/cli/development/upstream-drift' 'make check-upstream-drift'; do
    if grep -qF "$ref" "$PROJECT_MD"; then
        pass "PROJECT.md references: $ref"
    else
        fail "PROJECT.md missing reference to: $ref"
    fi
done

# PROJECT.md ordering: Upstream Parity Process must come BEFORE Evolution
if awk '/^## Upstream Parity Process$/{p=NR} /^## Evolution$/{e=NR} END{exit !(p && e && p < e)}' "$PROJECT_MD"; then
    pass "PROJECT.md section ordering: Upstream Parity Process precedes Evolution"
else
    fail "PROJECT.md section ordering wrong"
fi

# ===========================================================================
# Summary
# ===========================================================================
echo ""
print_summary
