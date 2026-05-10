#!/usr/bin/env bash
#
# test-list-aliases.sh — enforce the /// ALIAS marker convention.
#
# Every `#[serde(..., alias = ...)]`, `#[serde(rename = ..., alias = ...)]`,
# and `#[arg(..., alias = ...)]` attribute in crates/ must be preceded
# (within 3 lines above the start of the attribute) by a
# `/// ALIAS(canonical="...", introduced="...", remove_by="...", issue="...")`
# rustdoc comment bearing all four fields.
#
# Only approved callers may `use crate::deprecated_schema` or
# `use crate::deprecated_policy`: main.rs, app_runtime.rs, profile/mod.rs,
# cli.rs. Any other importer is a policy violation.
#
# Prints an inventory grouped by remove_by, nearest first. Exits 0 on pass,
# 1 on any violation. POSIX-ish bash; relies on grep, sed, awk, sort, uniq.

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

fail=0

# --------------------------------------------------------------------------
# Step 1: locate every `alias = "..."` line in crates/
#
# Skip rustdoc and line-comment lines (they reference aliases in prose
# rather than declaring them).
# --------------------------------------------------------------------------

alias_lines=$(
  grep -RnE 'alias = "' crates/ 2>/dev/null \
    | grep -vE ':[[:space:]]*(//|#!)' \
    | grep -vE 'crates/nono-cli/tests/lint_scripts_negative_paths\.rs:' \
    || true
)

# --------------------------------------------------------------------------
# Step 2: for each alias line, walk backward to the attribute opener
# (`#[serde(` or `#[arg(`), then check that a `/// ALIAS(` marker sits on
# one of the 3 lines directly above that opener.
# --------------------------------------------------------------------------

while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  file=${hit%%:*}
  rest=${hit#*:}
  lineno=${rest%%:*}

  # Walk backward up to 10 lines to find the attribute opener. This covers
  # multi-line `#[serde(...)]` and `#[arg(...)]` blocks.
  start=$lineno
  found_opener=0
  i=0
  while [ $i -lt 10 ]; do
    probe=$((lineno - i))
    [ $probe -lt 1 ] && break
    if sed -n "${probe}p" "$file" | grep -qE '#\[(serde|arg)\('; then
      start=$probe
      found_opener=1
      break
    fi
    i=$((i + 1))
  done

  if [ $found_opener -eq 0 ]; then
    # Not inside a serde/arg attribute (maybe a #[command(alias = ...)] for
    # subcommand renames, or a raw string literal). Skip; out of scope.
    continue
  fi

  # Check the 3 lines directly above the opener for `/// ALIAS(`.
  marker_found=0
  j=1
  while [ $j -le 3 ]; do
    probe=$((start - j))
    [ $probe -lt 1 ] && break
    if sed -n "${probe}p" "$file" | grep -qE '^[[:space:]]*///[[:space:]]*ALIAS\('; then
      marker_found=1
      break
    fi
    j=$((j + 1))
  done

  if [ $marker_found -eq 0 ]; then
    # Extract the alias value for a clearer error message.
    alias_val=$(sed -n "${lineno}p" "$file" | sed -E 's/.*alias = "([^"]+)".*/\1/')
    echo "MISSING /// ALIAS marker for alias \"$alias_val\" at $file:$lineno (attribute opens at line $start)"
    fail=1
  fi
done <<< "$alias_lines"

# --------------------------------------------------------------------------
# Step 3: validate every `/// ALIAS(...)` marker has all four fields.
# Allow literals "indefinite" and "N/A" for remove_by / issue (legacy aliases
# kept for user-facing back-compat with no scheduled removal).
# --------------------------------------------------------------------------

markers=$(grep -RnE '^[[:space:]]*///[[:space:]]*ALIAS\(' crates/ 2>/dev/null \
  | grep -vE 'crates/nono-cli/tests/lint_scripts_negative_paths\.rs:' \
  || true)

while IFS= read -r m; do
  [ -z "$m" ] && continue
  for field in canonical introduced remove_by issue; do
    if ! printf '%s\n' "$m" | grep -qE "${field}=\"[^\"]+\""; then
      echo "MARKER missing or malformed '$field' field: $m"
      fail=1
    fi
  done
done <<< "$markers"

# --------------------------------------------------------------------------
# Step 4: only approved callers may reach into deprecated_* modules. Both
# `use crate::deprecated_schema::...` and fully-qualified path expressions
# like `crate::deprecated_schema::Foo::bar()` are checked — the latter
# pattern was previously how `profile_cmd.rs` quietly bypassed this gate.
# --------------------------------------------------------------------------

approved='(main\.rs|app_runtime\.rs|profile/mod\.rs|cli\.rs)'
# Match both `use crate::deprecated_(schema|policy)` and any other
# `crate::deprecated_(schema|policy)::...` access that isn't behind a
# `use`. Strip self-refs inside the deprecated modules themselves.
unapproved=$(
  grep -RnE 'crate::deprecated_(schema|policy)::' crates/ 2>/dev/null \
    | grep -vE ":[[:space:]]*//" \
    | grep -vE "deprecated_(schema|policy)\.rs:" \
    | grep -vE 'crates/nono-cli/tests/lint_scripts_negative_paths\.rs:' \
    | grep -vE "${approved}:" \
    || true
)

if [ -n "$unapproved" ]; then
  echo "UNAPPROVED reach into deprecated_schema / deprecated_policy:"
  echo "(allowed callers: ${approved}; if a new caller is needed, justify"
  echo " in the design note and add it to this script's approved list)"
  echo "$unapproved"
  fail=1
fi

# --------------------------------------------------------------------------
# Step 5: print inventory grouped by remove_by (nearest first).
# --------------------------------------------------------------------------

echo "----------------------------------------------------------------"
echo "  Alias inventory (sorted by remove_by, nearest first)"
echo "----------------------------------------------------------------"

# Extract "remove_by<TAB>canonical<TAB>file:line" per marker, then sort.
#
# "indefinite" and "N/A" sort to the end (they start with letters that come
# after "v" in ASCII — not true, "i" < "v" — so sort explicitly: prepend a
# sort key: versioned values get priority 0, "indefinite"/"N/A" get 1.
#
# Using awk to emit the sort key.
printf '%s\n' "$markers" \
  | awk -F: '
      NF >= 3 {
        file = $1
        line = $2
        rest = ""
        for (i = 3; i <= NF; i++) {
          rest = rest (i == 3 ? "" : ":") $i
        }
        canonical = rest; sub(/.*canonical="/, "", canonical); sub(/".*/, "", canonical)
        rb        = rest; sub(/.*remove_by="/, "", rb);        sub(/".*/, "", rb)
        introduced = rest; sub(/.*introduced="/, "", introduced); sub(/".*/, "", introduced)
        issue     = rest; sub(/.*issue="/, "", issue);          sub(/".*/, "", issue)
        key = (rb == "indefinite" || rb == "N/A") ? "1" rb : "0" rb
        printf "%s\t%s\t%s\t%s\t%s:%s\n", key, rb, canonical, issue, file, line
      }
    ' \
  | sort -t $'\t' -k1,1 \
  | awk -F'\t' '
      BEGIN { last_rb = "" }
      {
        rb = $2; can = $3; iss = $4; loc = $5
        if (rb != last_rb) {
          printf "\nremove_by = %s\n", rb
          last_rb = rb
        }
        printf "  %-40s  %-10s  %s\n", can, iss, loc
      }
    '

echo
echo "----------------------------------------------------------------"
if [ $fail -eq 0 ]; then
  total=$(printf '%s\n' "$markers" | grep -c '/// ALIAS(' || true)
  echo "  OK — $total alias markers, all fields present, approved imports only"
else
  echo "  FAIL — fix the violations above"
fi
echo "----------------------------------------------------------------"

exit $fail
