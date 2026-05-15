# Phase 41: CI cleanup + v24 broker code-review closure - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-15
**Phase:** 41-ci-cleanup-v24-broker-code-review-closure
**Areas discussed:** Sub-plan structure & ordering, Dead-code disposition policy, CR-01 FFI mapping (BrokerNotFound), CR-04 Job-object test skip policy

---

## Sub-plan structure & ordering

### Q1 — Which lane should land FIRST in Phase 41?

| Option | Description | Selected |
|--------|-------------|----------|
| API migration sub-plan first | Land the 14-site `CapabilityRequest::path` → `HandleTarget::FilePath` migration first so Phase 37 can rebase ASAP. Research pass first to validate with single call site. | ✓ |
| Simple-Unix sub-plan first (CR-A pattern) | Land the ~17 trivial fixes first as warm-up — mirrors PR #2's CR-A discipline. Phase 37 waits longer for rebase target. | |
| Windows fixes first | Tackle Windows CI failures first (Windows host = fastest iteration). Risk: Phase 37 stays blocked longer on API migration. | |

**Rationale:** Phase 37 parallel-execution dependency on the API migration commit (ROADMAP § Sequencing Rationale).

### Q2 — How granular should the sub-plans be?

| Option | Description | Selected |
|--------|-------------|----------|
| Tracker shape: ~6-7 plans, one per error class | Plan 41-01 API migration → 41-02 Unix simple → 41-03 Win MSI → 41-04 Win block-net → 41-05 env_vars flake → 41-06 broker CR-01/02/03 → 41-07 broker CR-04 + baseline reset. | ✓ |
| Coarser: 3-4 plans grouped by host | Fewer plans, less overhead, bigger blast radius per plan. | |
| Finer: split simple-Unix further, total ~8-9 plans | Maximum atomicity for dead-code investigation. | |

### Q3 — Where do the 4 broker CR todos live?

| Option | Description | Selected |
|--------|-------------|----------|
| Two plans: 41-06 (CR-01/02/03 broker hygiene) + 41-07 (CR-04 + baseline reset close gate) | CR-01/02/03 share bindings/c + broker code area. CR-04 pairs with baseline reset per REQ-CI-03 SC#3. | ✓ |
| One plan: 41-06 all four CRs, then 41-07 baseline reset | Simpler mental model. Risk: bigger plan blast radius. | |
| Slot each CR todo into the matching CI plan | Co-locate by code area. Harder to trace 'all broker CR work' if reviewer wants to see together. | |

### Q4 — Should 41-02 (API migration) and 41-04 (block-net probe) get explicit research passes?

| Option | Description | Selected |
|--------|-------------|----------|
| Research pass on both before planning | API migration: single-site spike before bulk. Block-net probe: read fixture code path + reproduce locally to find root cause. | ✓ |
| Research only on API migration; block-net probe goes in-plan | Fold block-net triage into Plan 41-04 task-1. | |
| No separate research — let gsd-phase-researcher handle it via /gsd-plan-phase | Trust the phase-researcher agent. | |

---

## Dead-code disposition policy

### Q1 — Default disposition policy for ~14 orphans?

| Option | Description | Selected |
|--------|-------------|----------|
| Investigate first, default to wire-up if Windows-callsite exists | Per-function callsite grep including exec_strategy_windows + Windows-gated tests; fix cfg gating OR add cfg(target_os="windows"). | ✓ |
| Delete-bias, recover from git if needed | Delete first, recover if downstream breaks. Risk: Windows CI is ALSO red so can't trust regression detection. | |
| Mixed by file: audit_ledger.rs investigate, all others delete-bias | Investigate the highest-stakes file; delete-bias for smaller orphans. | |

**Rationale:** audit_ledger.rs's 17 functions look like load-bearing audit infrastructure (compute_session_digest, verify_session_in_ledger, etc.). Investigation is the conservative default.

### Q2 — Verification standard before deleting?

| Option | Description | Selected |
|--------|-------------|----------|
| Cross-target grep + Linux cross-target clippy + macOS-target clippy | Grep + `cargo clippy --target x86_64-unknown-linux-gnu` + `cargo clippy --target x86_64-apple-darwin` from Windows host. Belt-and-suspenders. | ✓ |
| Grep + Linux cross-target clippy only | Rely on CI macOS Clippy runner for macOS-only breakage. | |
| Grep only, trust CI for verification | Symbol grep + CI catches misses. Forces CI-driven rework loop. | |

**Rationale:** Memory `feedback_clippy_cross_target` (Phase 25 CR-A regression lesson).

### Q3 — Commit-body granularity for dispositions?

| Option | Description | Selected |
|--------|-------------|----------|
| One commit per disposition class with table in body | 3 commits: 'delete' / 'wire-up' / 'preserve-Windows-only'. Each commit body has table listing function + grep evidence + change. | ✓ |
| One commit per function | audit_ledger.rs alone = 17 commits. Max atomicity, max git-log noise. | |
| One commit per file | Per-file is natural review unit; mixed disposition in body. | |

### Q4 — `test_env.rs` disallowed-methods Drop self-reference fix?

| Option | Description | Selected |
|--------|-------------|----------|
| Per-file #[allow] with rationale comment | Add #[allow(clippy::disallowed_methods)] at Drop impl block. EnvVarGuard IS the abstraction. Mirrors unsafe fencing. | ✓ |
| Restructure Drop to call a private helper | Extract env_set_raw / env_remove_raw private fns with per-fn #[allow]. More verbose, same outcome. | |
| Defer to planner/researcher — not a real philosophy choice | Below user-decision threshold. | |

---

## CR-01 FFI mapping (BrokerNotFound)

### Q1 — Remap target for BrokerNotFound?

| Option | Description | Selected |
|--------|-------------|----------|
| Remap to existing ErrSandboxInit (-6) | Lowest blast radius — no enum addition, no nono-py / nono-ts changes needed. Update nono.h doc-comment to clarify reuse. | ✓ |
| Add new ErrBrokerMissing variant | Additive C-ABI change. Cleaner semantics. Cascades to nono.h doc + possibly nono-py / nono-ts error-class mapping. | |
| Defer to existing + follow-up todo to evaluate | Remap now (low-risk), evaluate dedicated variant later. | |

### Q2 — Downstream language-binding repo coordination?

| Option | Description | Selected |
|--------|-------------|----------|
| Update doc-comment only in this phase; file follow-up if downstream needs change | Plan 41-06 includes manual verification check on nono-py / nono-ts; file follow-up if either maps by value. | ✓ |
| Block Phase 41 close on coordinated downstream update | Don't ship remap until nono-py + nono-ts have matching PRs queued. Tighter coupling. | |
| Skip — nono-py / nono-ts don't map by code value | If both stringify nono_last_error(), remap is invisible. Add verification check to plan. | |

### Q3 — CR-03 empty-list disposition?

| Option | Description | Selected |
|--------|-------------|----------|
| (c) Reject empty list in argv parser | Mirrors CR-02 pattern — broker parser becomes consistent enforcement boundary. Plan 31-02 SUMMARY claim becomes correct-by-construction-rejected. | ✓ |
| (a) Doc-only — update Plan 31-02 SUMMARY | Cheapest. Production unreachable per Verifier. Risk: future code change could make path reachable. | |
| (b) Add guard in broker (skip STARTUPINFOEXW for empty list) | "Default-inherit" semantics are the OPPOSITE of "most-restrictive". Avoid unless intentional. | |

### Q4 — Plan 41-06 test coverage plan?

| Option | Description | Selected |
|--------|-------------|----------|
| Plan 41-06 owns 3 new tests + downstream verification check | (1) `--inherit-handle 0x0` → SandboxInit error. (2) No --inherit-handle flags → SandboxInit error. (3) BrokerNotFound → ErrSandboxInit. (4) Manual check on nono-py / nono-ts. | ✓ |
| Tests in 41-06 + cross-repo verification deferred to follow-up todo | Same 3 tests; defer cross-repo check. | |
| Tests only in 41-06; trust the doc-comment as the spec | Skip downstream verification. Risk: silent breakage if downstream maps by value. | |

---

## CR-04 Job-object test skip policy

### Q1 — SKIP policy for broker_launch_assigns_child_to_job_object?

| Option | Description | Selected |
|--------|-------------|----------|
| (c) Convert SKIP to FAIL when artifact missing | panic! with clear message. Highest signal quality. Forces pre-build everywhere. | ✓ |
| (b) Add #[ignore] back; CI uses cargo test -- --ignored | Test shows as 'ignored' not 'passed' when missing. CI scripts need update. | |
| (a) Accept SKIP-as-PASS + CI wrapper builds broker first | Status quo. Risk: CI config drift could silently pass. | |

### Q2 — Pre-build mechanism for the broker artifact?

| Option | Description | Selected |
|--------|-------------|----------|
| build.rs that compiles broker as a test artifact | Add/extend build.rs to trigger `cargo build -p nono-shell-broker --release` on target_os = "windows". Automatic. | ✓ |
| Test helper that builds broker on-demand if missing | Self-healing. Anti-pattern of mixing build with test logic. | |
| Document the pre-build in CONTRIBUTING / Makefile target only | Relies on developer reading docs. FAIL message guides them if they don't. | |

### Q3 — REQ-CI-03 baseline reset placement?

| Option | Description | Selected |
|--------|-------------|----------|
| Plan 41-07 final task: baseline reset commit + SUMMARY conventions doc | Three commits: baseline SHA update / SUMMARY frontmatter conventions / STATE.md Deferred Items cleanup. | ✓ |
| Plan 41-07 single combined commit for baseline reset | All three changes in one commit. Simpler log; bigger blast radius. | |
| Defer baseline reset to a Phase 41 close-out separate from any sub-plan | Risk of being missed during phase-close workflow. | |

### Q4 — Phase close gate verification approach?

| Option | Description | Selected |
|--------|-------------|----------|
| Draft PR opened early, kept up to date; CI green on the head before phase close | Plan 41-01 lands → draft PR → subsequent plans push to branch. CI on every push. Standard Windows-host workflow. | ✓ |
| Per-plan branches, each PR merged after its CI is green | 7 merge commits to main. Main goes through transient red states. | |
| Single squash PR at phase close | Big PR diff for review. No incremental signal during execution. | |

---

## Claude's Discretion

- Mechanical implementation details within each plan's task list (commit ordering within 41-02 dead-code dispositions, greppable test asserts vs structured match patterns).
- CR-02 implementation specifics (null-handle reject in same match arm vs separate post-parse validation).
- Exact `build.rs` invocation shape (cargo subprocess vs Cargo `xtask` vs `[dev-dependencies]` workaround).

## Deferred Ideas

- nono-py / nono-ts downstream FFI mapping coordination — file follow-up todo if either repo maps by integer value.
- `ErrBrokerMissing` dedicated FFI variant — considered, rejected in favor of `ErrSandboxInit` reuse. Future-phase candidate if FFI scheme is refactored to "one variant per distinct error class".
