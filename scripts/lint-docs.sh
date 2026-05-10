#!/usr/bin/env bash
#
# lint-docs.sh — grep for forbidden legacy schema tokens in docs and source.
#
# Issue #594 Phase 2 restructured the profile JSON schema, removing the
# `policy.*` namespace and collapsing `security.groups` /
# `security.allowed_commands` into top-level `groups` / `commands`. This
# script is the enforcement gate that stops new documentation or rustdoc
# from reintroducing the old keys.
#
# Forbidden tokens (dotted prose form):
#   policy\.add_              — policy.add_allow_*, policy.add_deny_*
#   policy\.override_deny     — renamed to filesystem.bypass_protection
#   policy\.exclude_groups    — renamed to groups.exclude
#   security\.groups          — renamed to top-level groups.include
#   security\.allowed_commands — renamed to top-level commands.allow
#   --override-deny           — renamed CLI flag --bypass-protection
#
# Forbidden tokens (JSON-quoted form — legacy-only key names that don't
# appear in the canonical schema, so the bare quoted name is a reliable
# signal that an example is teaching the deprecated schema):
#   "add_allow_read", "add_allow_write", "add_allow_readwrite"
#   "add_deny_access", "add_deny_commands"
#   "override_deny", "exclude_groups", "allowed_commands"
#
# Allowlist (files where the tokens are legitimately retained):
#   - deprecated_schema.rs / deprecated_policy.rs
#     (the modules that deserialize and warn about the legacy keys)
#   - tests/fixtures/legacy_profiles/
#     (legacy JSON fixtures exercising the deprecation path)
#   - docs/plans/
#     (design docs referencing the old schema by name)
#   - CHANGELOG.md
#     (release notes calling out the rename)
#
# Exits 0 on clean, 1 on any forbidden hit outside the allowlist.

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

forbidden='policy\.add_|policy\.override_deny|policy\.exclude_groups|security\.groups|security\.allowed_commands|--override-deny|"add_allow_read"|"add_allow_write"|"add_allow_readwrite"|"add_deny_access"|"add_deny_commands"|"override_deny"|"exclude_groups"|"allowed_commands"'

# Permanent allowlist entries — these files legitimately document, test, or
# deserialize the legacy keys and must always be allowed to mention them.
permanent_allow=(
  'crates/nono-cli/src/deprecated_schema\.rs'
  'crates/nono-cli/src/deprecated_policy\.rs'
  'crates/nono-cli/tests/deprecated_schema\.rs'
  'crates/nono-cli/tests/deprecated_policy\.rs'
  'crates/nono-cli/tests/fixtures/legacy_profiles/'
  # Lint script tests legitimately mention forbidden tokens — they
  # describe what the scripts forbid and assert that violations are
  # caught (negative-path proofs for both the alias inventory and the
  # docs-token scanner).
  'crates/nono-cli/tests/lint_docs\.rs'
  'crates/nono-cli/tests/lint_scripts_negative_paths\.rs'
  # schema_shape.rs has NEGATIVE assertions ("…still present; canonical
  # location is …") that must mention the old key names to verify they're
  # absent from the regenerated JSON schema.
  'crates/nono-cli/tests/schema_shape\.rs'
  # command_blocking_deprecation.rs intentionally exercises the legacy
  # security.allowed_commands / policy.add_deny_commands JSON shapes in its
  # tests to verify deprecation warnings fire on those fields.
  'crates/nono-cli/src/command_blocking_deprecation\.rs'
  # The capability manifest is a SEPARATE schema (consumed by nono-ffi)
  # whose `allowed_commands` field is canonical for that schema and
  # unrelated to the profile-schema migration in #594.
  'crates/nono/schema/capability-manifest\.schema\.json'
  'crates/nono/tests/manifest_types\.rs'
  'crates/nono/tests/capability_manifest_schema\.rs'
  'docs/cli/internals/capability-manifest\.mdx'
  'docs/plans/'
  'CHANGELOG\.md'
)

# TEMPORARY allowlist entries — REMOVE in later Part G subtasks of issue #594
# Phase 2 (or at v1.0.0 for the clap alias). See the plan at
# docs/plans/2026-04-24-issue-594-phase-2-schema-plan.md.
temporary_allow=(
  # TODO(v1.0.0): REMOVE when the --override-deny clap alias is dropped
  # (see /// ALIAS markers at crates/nono-cli/src/cli.rs ~lines 872 and 1135,
  # both with remove_by="v1.0.0"). cli.rs carries the alias declaration and
  # a parser test that locks it in; main.rs wires the deprecation warning.
  'crates/nono-cli/src/cli\.rs'
  'crates/nono-cli/src/main\.rs'

  # TODO(v1.0.0): REMOVE the "Migration from previous schema" section (and
  # this allowlist entry) when the deprecated keys are dropped. Until then the
  # embedded authoring guide is the canonical migration-mapping location and
  # deliberately lists every legacy → canonical mapping.
  'crates/nono-cli/data/profile-authoring-guide\.md'
)

# Build a single alternation regex from both allowlists. Entries are already
# regex-escaped where literal dots matter.
allow_pattern=$(IFS='|'; echo "${permanent_allow[*]}|${temporary_allow[*]}")

hits=$(
  grep -RnE "$forbidden" crates/ docs/ tests/ qa-profiles/ README.md 2>/dev/null \
    | grep -vE "$allow_pattern" \
    || true
)

if [ -n "$hits" ]; then
  echo "lint-docs: forbidden legacy tokens found outside the allowlist:" >&2
  echo "$hits" >&2
  echo "" >&2
  echo "See docs/plans/2026-04-24-issue-594-phase-2-schema-plan.md Task F4" >&2
  echo "for the forbidden-token list and allowlist rationale." >&2
  exit 1
fi

echo "lint-docs: ok"
