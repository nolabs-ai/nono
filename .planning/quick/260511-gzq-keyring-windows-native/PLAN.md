---
slug: keyring-windows-native
quick_id: 260511-gzq
created: 2026-05-11
type: bug-fix
status: in-progress
---

# Quick task: Enable `keyring v3` Windows-native backend — fix Credential Manager bypass

## Problem

POC user ran the keyed sign+verify roundtrip:

```powershell
nono trust keygen --id poc-key       # reports: Stored in: Windows Credential Manager
nono trust sign instruction.md --key poc-key
```

keygen reported success ("Stored in: Windows Credential Manager (service: nono-trust)").
sign immediately failed:

```
ERROR Secret not found in keystore: signing key 'poc-key' not found in keystore
  (run 'nono trust keygen' first)
```

Same process tree, same user, same Credential Manager. Keygen wrote, sign couldn't read.

## Root cause

`keyring v3` (3.6.3 per `Cargo.lock`) on Windows requires the **`windows-native`**
feature flag to use the Windows Credential Manager `wincred` backend. Without that flag,
keyring v3 falls back to a **platform-independent mock credential store** (in-memory,
per-process, does NOT persist across invocations — verified against keyring docs at
`docs.rs/keyring/3.6.3`).

Inspection of the workspace Cargo.toml files shows the gap:

| Crate | Linux target | macOS target | Windows target |
|-------|--------------|--------------|----------------|
| `crates/nono/Cargo.toml` | `features = ["sync-secret-service"]` ✓ | `features = ["apple-native"]` ✓ | **MISSING** |
| `crates/nono-cli/Cargo.toml` | `features = ["sync-secret-service"]` ✓ | `features = ["apple-native"]` ✓ | **MISSING** |
| `crates/nono-proxy/Cargo.toml` | (none — base `keyring = "3"` only) | (none) | (none — unused dep, no `use keyring` anywhere in `src/`) |

So on Windows, every keyring operation has been silently using the mock backend ever since
the keyring v3 adoption. The string `system_keystore_label()` (at
`crates/nono-cli/src/trust_keystore.rs:311-326`) hardcodes "Windows Credential Manager" as
the label without verifying the actual active backend, which is why keygen's
"Stored in: Windows Credential Manager" message was misleading.

## Blast radius — what's silently been broken

Anything that round-trips a secret through keyring on Windows:

- **`nono trust keygen` → `nono trust sign`** (the POC user's failure shape)
- **`nono trust keygen` → `nono trust verify`** (keyed verify path)
- **`keyring://service/account` URI scheme in profile credentials** (Phase 20 UPST-03,
  `crates/nono/src/keystore.rs`) — sandbox profile credential injection that was supposed
  to read from Windows Credential Manager has been hitting an empty mock instead.
- **`audit-attestation.bundle` signing key reads from `keyring://nono/audit`** (Phase 22
  AUD-02) — silently failed on Windows if anyone tried it.

Every Windows keyring test passed because both the write and the read in a single test
process hit the same in-memory mock; cross-process tests would have caught this but none
exist.

## Fix shape

Add `keyring` to the Windows target block in both `crates/nono/Cargo.toml` and
`crates/nono-cli/Cargo.toml`, matching the Linux/macOS pattern:

```toml
[target.'cfg(target_os = "windows")'.dependencies]
keyring = { version = "3", features = ["windows-native"] }
# ... existing Windows deps below
```

The base `keyring = "3"` line in each crate's top-level `[dependencies]` can stay; the
target override adds the feature flag for Windows builds, which is how Linux and macOS
add their respective backend flags.

**Not touching:**
- `crates/nono-proxy/Cargo.toml` — unused dep at source level (grep finds no `use keyring`
  in `src/`). Adding feature flags to an unused dep is noise. If it's truly unused, it
  should be deleted in a separate cleanup task; this task doesn't make that call.

## Verification plan

1. `cargo build --workspace` clean on Windows.
2. `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` clean.
3. `cargo fmt --all -- --check` clean.
4. **Manual roundtrip on Windows** (the real proof):
   ```powershell
   cd $env:TEMP
   "test" | Out-File instruction.md
   .\target\release\nono.exe trust keygen --id repro-test
   .\target\release\nono.exe trust sign instruction.md --key repro-test
   .\target\release\nono.exe trust verify instruction.md
   ```
   Expected: keygen reports success, sign produces `instruction.md.bundle`, verify returns
   green. (Pre-fix: sign fails with "key not found".)
5. Clean up: `Remove-ItemProperty` the test credential from Credential Manager
   (`nono-trust/repro-test`).

## Out of scope

- **No `system_keystore_label()` fix** — the misleading label string is a small polish
  issue but separate from the actual backend wiring. Future quick task could make the
  label dynamic ("Windows Credential Manager (windows-native)" vs "Mock (in-memory)").
- **No `crates/nono-proxy/Cargo.toml` cleanup** — separate task to either delete the
  unused `keyring = "3"` dep or document why it stays.
- **No keyring v3 → v4 upgrade** — staying at the workspace-pinned 3.6.3.
- **No reproduction of how this slipped through Phase 20 / 22 / 27.2 review** — that's
  forensics; the gap is in the diff and the fix is clear.

## Acceptance

- [ ] `crates/nono-cli/Cargo.toml` Windows target block includes
      `keyring = { version = "3", features = ["windows-native"] }`
- [ ] `crates/nono/Cargo.toml` Windows target block includes the same
- [ ] `cargo build --workspace` clean on Windows host
- [ ] `cargo clippy --workspace --target x86_64-unknown-linux-gnu` (where runnable) clean
- [ ] `cargo fmt --all -- --check` clean
- [ ] Manual roundtrip on Windows passes (keygen → sign → verify)
- [ ] New release binary at `target/release/nono.exe` ready for POC user reinstall
- [ ] Push to origin/main so POC user can fetch the rebuilt binary

## POC user retry

After this lands and the rebuilt binary is on the POC test box, the sequence:

```powershell
cd C:\temp
"hello from nono POC" | Out-File -Encoding utf8 instruction.md
nono trust keygen --id poc-key
nono trust sign instruction.md --key poc-key
nono trust verify instruction.md
```

…should produce `instruction.md.bundle` after step 3 and verify-green on step 4.
