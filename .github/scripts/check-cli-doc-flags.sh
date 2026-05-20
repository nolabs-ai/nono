#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CLI_RS="${ROOT_DIR}/crates/nono-cli/src/cli.rs"
FLAGS_DOC="${ROOT_DIR}/docs/cli/usage/flags.mdx"

if [[ ! -f "${CLI_RS}" ]]; then
  echo "Missing CLI source: ${CLI_RS}" >&2
  exit 1
fi

if [[ ! -f "${FLAGS_DOC}" ]]; then
  echo "Missing flags doc: ${FLAGS_DOC}" >&2
  exit 1
fi

RUN_FLAGS_RAW="$(
  awk '
    /pub struct (RunArgs|SandboxArgs|ProfileResolverArgs) \{/ { in_struct = 1; next }
    in_struct && /^\}/ { in_struct = 0 }
    in_struct { print }
  ' "${CLI_RS}" | awk '
    # Phase 44 WR-01 P37: accumulate multi-line #[arg(...)] blocks until
    # the closing )]. The pre-44 parser only matched #[arg(...)] when the
    # `long` keyword landed on the SAME source line as `#[arg(`, silently
    # exempting every multi-line attribute (~30 flags including
    # SandboxArgs::allow and ProfileResolverArgs::no_auto_pull) from
    # doc-parity validation. The accumulator captures the full attribute
    # spec across however many source lines clap-fmt wraps it across.
    /#\[arg\(/ {
      attr = $0
      if (attr ~ /\)\]/) {
        in_arg = 0
      } else {
        in_arg = 1
      }
      next
    }

    in_arg {
      attr = attr " " $0
      if ($0 ~ /\)\]/) {
        in_arg = 0
      }
      next
    }

    /^[[:space:]]*pub[[:space:]]+[a-zA-Z0-9_]+:/ {
      if (attr == "") {
        next
      }

      # Phase 44 WR-10 P37: skip fields whose #[arg(...)] sets hide = true.
      # Hidden flags (e.g. --dangerous-force-wfp-ready) are intentionally
      # excluded from the public CLI surface; the doc-parity script must
      # not flag them as "missing" — they are missing by design.
      if (attr ~ /hide[[:space:]]*=[[:space:]]*true/) {
        attr = ""
        next
      }

      # Skip fields whose accumulated attr does not declare a long flag
      # (clap allows #[arg(short = ...)] only, or #[arg()] for positional
      # arguments). The pre-44 guard was implicit in the single-line
      # /long/ pattern; the accumulator now matches every #[arg(...)],
      # so re-introduce the guard explicitly here.
      if (attr !~ /long/) {
        attr = ""
        next
      }

      field = $2
      sub(/:$/, "", field)

      if (match(attr, /long[[:space:]]*=[[:space:]]*"[^"]+"/)) {
        long_spec = substr(attr, RSTART, RLENGTH)
        sub(/^.*"/, "", long_spec)
        sub(/".*$/, "", long_spec)
        print long_spec
      } else {
        gsub(/_/, "-", field)
        print field
      }

      attr = ""
      next
    }

    {
      if ($0 !~ /^#[[:space:]]*\[/) {
        attr = ""
      }
    }
  ' | sort -u
)"

if [[ -z "${RUN_FLAGS_RAW}" ]]; then
  echo "No RunArgs long flags found; parser likely broke." >&2
  exit 1
fi

missing=()
while IFS= read -r flag; do
  [[ -z "${flag}" ]] && continue
  if ! grep -Fq -- "--${flag}" "${FLAGS_DOC}"; then
    missing+=("--${flag}")
  fi
done <<< "${RUN_FLAGS_RAW}"

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "Missing RunArgs flags in docs/cli/usage/flags.mdx:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  exit 1
fi

echo "RunArgs flag documentation parity check passed."
