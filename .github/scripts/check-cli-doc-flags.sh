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
    /#\[arg\(/ && /long/ { attr = $0; next }

    /^[[:space:]]*pub[[:space:]]+[a-zA-Z0-9_]+:/ {
      if (attr == "") {
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
