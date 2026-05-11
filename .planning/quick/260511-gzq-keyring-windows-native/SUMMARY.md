---
slug: keyring-windows-native
quick_id: 260511-gzq
created: 2026-05-11
completed: 2026-05-11
type: bug-fix
status: complete
---

# Summary: keyring v3 Windows-native backend enabled — Credential Manager actually used now

## What broke (severity: HIGH — silent since v2.1)

POC user's keyed sign+verify roundtrip:

```powershell
nono trust keygen --id poc-key     # → "Stored in: Windows Credential Manager"
nono trust sign instruction.md --key poc-key
# → ERROR Secret not found in keystore: signing key 'poc-key' not found
```

Same process tree, same Credential Manager, ms-apart. Keygen wrote successfully; sign
couldn't find what keygen wrote.

## Root cause

`keyring v3.6.3` requires the **`windows-native`** feature flag to use the Windows
Credential Manager (`wincred`) backend. Without it, the crate silently falls back to a
**platform-independent in-memory mock store** (per
[docs.rs/keyring/3.6.3](https://docs.rs/keyring/3.6.3/keyring/) "if no credential store
features apply to a given platform, the crate uses the (platform-independent) _mock_
credential store").

The mock store works *within* a single process but is wiped on process exit — exactly the
symptom shape (keygen write succeeds → sign in next process finds nothing).

The Cargo.toml gap that caused this:

| Crate | Linux features | macOS features | Windows features |
|-------|----------------|----------------|------------------|
| `crates/nono/Cargo.toml` | `sync-secret-service` ✓ | `apple-native` ✓ | **MISSING — was using mock** |
| `crates/nono-cli/Cargo.toml` | `sync-secret-service` ✓ | `apple-native` ✓ | **MISSING — was using mock** |

The `system_keystore_label()` helper at `crates/nono-cli/src/trust_keystore.rs:311-326`
hardcodes `"Windows Credential Manager"` as the platform label without checking the
actual active backend — that's why keygen's "Stored in: Windows Credential Manager"
display was misleading (it has been since the keyring v3 adoption).

## Blast radius (silently broken paths now fixed)

Every keyring-backed flow on Windows has been hitting the in-memory mock:

- **`nono trust keygen` / `sign` / `verify`** keyed-mode roundtrip (the POC user's failure)
- **`nono trust sign-policy`** (uses same `load_signing_key` path)
- **`keyring://service/account` URI scheme** in profile credentials (Phase 20 UPST-03,
  `crates/nono/src/keystore.rs`) — sandbox-injected credentials from Credential Manager
  have been failing silently on Windows
- **`audit-attestation.bundle` signing via `keyring://nono/audit`** (Phase 22 AUD-02 / Plan
  22-05a) — Authenticated audit ledger signing would have hit empty mock on Windows

Every Windows keyring unit test passed because tests do the write and read in a single
process — the mock works fine there. No cross-process integration tests exist for the
keystore path, which is why this slipped through all of v2.1–v2.3 review.

## Fix

Added the Windows-target keyring entry matching the Linux/macOS pattern:

**`crates/nono/Cargo.toml`** (+1 line in the Windows target block):
```toml
[target.'cfg(target_os = "windows")'.dependencies]
windows-sys = { version = "0.59", features = ["Win32_Foundation", ...] }
keyring = { version = "3", features = ["windows-native"] }  # NEW
```

**`crates/nono-cli/Cargo.toml`** (+1 line in the Windows target block, same shape).

The base `keyring = "3"` line at the top of each crate's `[dependencies]` stays — the
target override just adds the `windows-native` feature for Windows builds, which is how
the Linux and macOS blocks add their respective backend flags.

Not touched: `crates/nono-proxy/Cargo.toml` has `keyring = "3"` declared but no
`use keyring` in `src/` (unused dep at source level). Adding a feature flag to an unused
dep is noise. Truly-unused dep deletion is a separate cleanup task.

## End-to-end verification on Windows

Real keyed sign+verify roundtrip with `target/debug/nono.exe`:

```
=== Step 1: keygen ===
Signing key generated successfully.
  Key ID: repro-260511
  Stored in: Windows Credential Manager (service: nono-trust)

=== Step 2: sign (the failure point pre-fix) ===
  SIGNED \\?\C:\...\instruction.md -> instruction.md.bundle
  Signed 1 file(s) successfully.

=== Step 3: verify ===
  FAILED: signer 'repro-260511 (keyed)' not in trusted publishers
```

**Step 2 succeeds post-fix** — that's the keystore round-trip working. Step 3's "not in
trusted publishers" is a *different* gate (trust policy doesn't list this freshly-generated
key as a publisher; fail-closed-by-design — `nono trust init` + manually adding the public
key would close this loop, but it's not the keystore bug).

**Confirmed via Windows Credential Manager directly:**
```
cmdkey /list | Select-String "nono-trust"
  Target: LegacyGeneric:target=repro-260511.nono-trust-pub
  Target: LegacyGeneric:target=repro-260511.nono-trust
```

Pre-fix, the mock backend wouldn't have produced ANY `LegacyGeneric:` entries because it
was in-memory only. Post-fix, both the private key (`nono-trust`) and public key
(`nono-trust-pub`) services persist real credentials to Windows Credential Manager.

Cleanup of test credentials: `cmdkey /delete:LegacyGeneric:target=repro-260511.nono-trust*`
ran clean.

## Quality gates

| Check | Result |
|-------|--------|
| `cargo build --workspace` (Windows host) | ✅ Finished `dev` in 29.05s — `keyring v3.6.3` recompiled with new feature flag |
| `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` (Windows host) | ✅ clean |
| `cargo fmt --all -- --check` | ✅ clean (no diff) |
| `cargo test -p nono-cli --bin nono trust_keystore::` | ✅ 1 passed (existing `backend_description_mentions_windows_credential_manager` test) |
| `cargo build --release -p nono-cli --bin nono` | ✅ Finished `release` in 2m 12s |
| New `target/release/nono.exe` sha256 | `06c1156eac757bf55e0a4a847f7466c63385723d0e09b6f2b259e28509d96d68` (was `8742260...`) |
| Manual keyed sign roundtrip on Windows | ✅ keygen + sign both succeed; produces `.bundle`; persists to Credential Manager |
| Cross-target Linux clippy | ⚠️ skipped — host missing `x86_64-linux-gnu-gcc`; patch is a Cargo.toml feature-flag add only, no source code changes, no `#[cfg(target_os = ...)]` regions touched, Phase 25 CR-A regression class does not apply |

## POC user retry after rebuild

After the new `target/release/nono.exe` is on the POC test box (replace
`C:\tools\bin\nono.exe`):

```powershell
cd C:\temp
"hello from nono POC" | Out-File -Encoding utf8 instruction.md
nono trust keygen --id poc-key
nono trust sign instruction.md --key poc-key   # now produces instruction.md.bundle
```

To get past the "signer not in trusted publishers" gate on the subsequent verify, the
POC user needs to register the public key in a trust policy. The keygen output already
prints the public key in base64 DER format for exactly this purpose — paste it into a
trust policy:

```powershell
nono trust init                                                          # creates a default trust-policy.json
# Then edit trust-policy.json to add the public key from `keygen` output
# under publishers[].keys, OR use the nono trust list / nono trust verify --all flow
nono trust verify instruction.md
```

The trust-policy authoring step is its own UX surface beyond the keystore bug. For
"does the keystore work end-to-end on Windows" POC question, the keygen + sign halves
of the roundtrip are sufficient evidence.

## Files touched

- `crates/nono/Cargo.toml` (+1 line — Windows target keyring entry)
- `crates/nono-cli/Cargo.toml` (+1 line — same)
- `.planning/quick/260511-gzq-keyring-windows-native/PLAN.md` (new)
- `.planning/quick/260511-gzq-keyring-windows-native/SUMMARY.md` (this file)
- `.planning/STATE.md` (Last activity)
- `Cargo.lock` (recompile-locked feature resolution; keyring 3.6.3 itself unchanged)

## Acceptance — all checked

- [x] Windows target blocks include `keyring = { version = "3", features = ["windows-native"] }`
- [x] `cargo build --workspace` clean on Windows
- [x] `cargo clippy` clean on Windows host
- [x] `cargo fmt --check` clean
- [x] Manual keygen+sign roundtrip works (Credential Manager persists across processes)
- [x] Release binary rebuilt (`06c1156e...`)
- [x] Ready for push to origin/main so POC user can fetch rebuilt binary

## Open follow-ups (out of scope)

- **`system_keystore_label()` should report actual active backend**, not the platform-default
  label. Otherwise the "Stored in: Windows Credential Manager" message remains a foot-gun
  if anyone reintroduces the feature-flag gap. Future quick task: make the label dynamic
  based on whether `windows-native` is compiled in (compile-time `cfg!()` check) or query
  the actual `keyring::Entry` backend at runtime.
- **`crates/nono-proxy/Cargo.toml` cleanup** — `keyring = "3"` declared but unused at source
  level (no `use keyring` anywhere in `src/`). Either delete the dep or document why it
  stays. Separate task.
- **Add a cross-process keystore integration test** — the unit-test gap that hid this bug
  for 6+ months should not recur. Future quick task: add a `#[test]` that spawns a child
  `nono trust keygen` then a separate child `nono trust sign` against the same key ID
  and asserts success. (Has to be `#[ignore]`d or env-var-gated to avoid polluting CI
  Credential Manager state.)
- **Audit `nono::keystore::keyring_credential()` path** for whether `keyring://service/account`
  URI consumers (sandbox profile credential injection) have any silent failure paths now
  that the backend actually works. May surface new behavior on existing tests.
