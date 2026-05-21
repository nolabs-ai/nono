---
phase: 50
slug: corp-network-tuf-refresh-via-os-root-store-replace-or-wrap-t
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-21
---

# Phase 50 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Source: 50-RESEARCH.md `## Validation Architecture` section.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust built-in) + `cargo clippy` cross-target lanes |
| **Config file** | none — workspace test runner |
| **Quick run command** | `cargo test -p nono-cli trust_refresh::tests` |
| **Full suite command** | `make ci` (workspace clippy + fmt + tests on host triple) |
| **Cross-target command** | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` AND `--target x86_64-apple-darwin` |
| **Estimated runtime** | ~30s for quick, ~3min for full CI, +~2min for cross-target lanes |

---

## Sampling Rate

- **After every task commit:** Run `cargo build -p nono-cli` (compile-only smoke)
- **After tests are added (Wave 2+):** Run `cargo test -p nono-cli trust_refresh::tests`
- **Before `/gsd-verify-work`:** `make ci` green on host triple + cross-target clippy green on the two non-host Unix triples per CLAUDE.md MUST/NEVER
- **Max feedback latency:** ~30 seconds for unit tests; ~5 minutes for full cross-target verify

---

## Per-Task Verification Map

> Filled in during planning. Below is the SPEC-requirement → validation-method coverage map derived from 50-RESEARCH.md.

| SPEC Req | Description | Test Type | Automated Command | Status |
|----------|-------------|-----------|-------------------|--------|
| Req 1 | nono-local TUF walk replaces upstream call | grep guard + compile | `grep -rn 'TrustedRoot::production()' crates/nono-cli/src/` returns 0 | ⬜ pending |
| Req 2 | HTTP client consults Windows cert store | code review + compile | `grep -rn 'ureq::Agent' crates/nono-cli/src/trust_refresh.rs` returns ≥1; no `reqwest::Client::builder()` in trust_refresh.rs | ⬜ pending |
| Req 3 | TUF verification correctness via `tough` | unit (negative test) | `cargo test -p nono-cli trust_refresh::tests::bad_signature_rejected` | ⬜ pending |
| Req 4 | Byte-identical cache output | unit (snapshot test) | `cargo test -p nono-cli trust_refresh::tests::cache_bytes_match_baseline` | ⬜ pending |
| Req 5 | ≥4 hermetic unit tests, CI green on all OS | unit | `cargo test -p nono-cli trust_refresh::tests` (≥4 fns; PASS on Win/Linux/macOS CI lanes) | ⬜ pending |
| Req 6 | HUMAN-UAT corp-network scenario | manual | One run on Windows corp-network host → pass entry in 50-VERIFICATION.md | ⬜ pending |
| D-21 | Linux/macOS source-file invariance | cross-target clippy | Both non-host triples PASS `-D warnings -D clippy::unwrap_used` | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

> Per-task rows (`{50}-{plan}-{task}` IDs) will be populated by the planner during PLAN.md generation.

---

## Wave 0 Requirements

- [ ] `crates/nono-cli/Cargo.toml` — add `tough = "0.22"` to `[dependencies]` (promotion from transitive)
- [ ] Verify workspace MSRV vs `ureq 3.3.0` rust-version = 1.85 (RESEARCH.md Open Question 4)
- [ ] `crates/nono-cli/src/trust_refresh.rs` — new module skeleton (empty `pub fn refresh_production_trusted_root` returning `Err(NonoError::Setup("not yet implemented"))` so the call site compiles before the implementation lands)
- [ ] `crates/nono-cli/src/main.rs` (or `lib.rs`) — `mod trust_refresh;` declaration
- [ ] Test fixture decision (RESEARCH.md Open Question 3): pre-generated checked-in `tests/fixtures/tuf/14.root.json`, `15.root.json`, `targets.json`, `snapshot.json`, `timestamp.json`, `trusted_root.json` (planner picks pre-gen via `tuftool` over runtime `tough::editor` per researcher recommendation)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `nono setup --refresh-trust-root` succeeds on Windows host behind TLS-inspecting corporate proxy with enterprise CA only in Windows root store | SPEC Req 6 | Requires real corp-network host with MITM proxy + GPO-deployed enterprise CA; CI cannot replicate (round-2 user lock rejected live MITM in CI) | (1) Run nono setup --refresh-trust-root on a corp-network Windows host; (2) Confirm `[3/5] Refresh trust root` exits 0; (3) Confirm `<nono_home>/.nono/trust-root/trusted_root.json` exists and is non-empty; (4) Confirm stderr has zero `error sending request for url` errors; (5) Record pass in 50-VERIFICATION.md |

---

## Validation Sign-Off

- [ ] All 6 SPEC requirements have an automated command OR a documented manual UAT (Req 6 is manual-only by design)
- [ ] Sampling continuity: every plan has at least one `cargo test` or `cargo clippy` automated verify
- [ ] Wave 0 covers Cargo.toml dep add + module skeleton + fixture generation
- [ ] No watch-mode flags (Rust tests are single-shot)
- [ ] Feedback latency < 5 minutes for full cross-target verify
- [ ] Cross-target clippy lanes documented per CLAUDE.md MUST/NEVER
- [ ] `nyquist_compliant: true` set in frontmatter after planner fills per-task rows

**Approval:** pending
