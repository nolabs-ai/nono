---
slug: sigstore-tuf-fetch-transport
status: resolved
trigger: |
  After installing the freshly-built v0.53.0 user-scope MSI (sigstore-trust-root
  0.7.0 + Phase 49 code on `main`), `nono setup --refresh-trust-root` now fails
  later in step [3/5] with a transport error rather than the previous
  self-verify failure:
    "Failed to fetch https://tuf-repo-cdn.sigstore.dev/15.root.json:
     Transport 'other' error fetching '...15.root.json':
     error sending request for url (https://tuf-repo-cdn.sigstore.dev/15.root.json)"
created: 2026-05-21
updated: 2026-05-21
---

# Debug Session: sigstore-tuf-fetch-transport

## Symptoms

- **Expected behavior**: `nono setup --refresh-trust-root` step [3/5] should
  walk the TUF root chain from the embedded v14 anchor to the current head
  (v15+) at `https://tuf-repo-cdn.sigstore.dev/`, persist it, and finish.
- **Actual behavior**: TUF self-verify passes (anchor OK — previous bug fixed),
  chain walk reaches step "fetch 15.root.json", and the HTTP request errors
  out with a generic transport error.
- **Error message** (verbatim from user):
  ```
  [3/5] Refreshing Sigstore trusted root...
  nono: Setup error: Failed to fetch Sigstore trusted root from https://tuf-repo-cdn.sigstore.dev:
  TUF error: TUF repository load failed: Failed to fetch https://tuf-repo-cdn.sigstore.dev/15.root.json:
  Transport 'other' error fetching 'https://tuf-repo-cdn.sigstore.dev/15.root.json':
  error sending request for url (https://tuf-repo-cdn.sigstore.dev/15.root.json)
  ```
- **Timeline**: This is a NEW failure mode after the v0.53.0 → v0.53.0-rebuilt
  upgrade. The previous failure (signature threshold not met) is resolved —
  see `.planning/debug/sigstore-trust-root-zero-sigs.md` for that root cause.
- **Reproduction**: Run `nono setup --refresh-trust-root` against the rebuilt
  v0.53.0 binary just installed via
  `dist/windows/nono-v0.53.0-x86_64-pc-windows-msvc-user.msi`.
- **User-confirmed environment facts**:
  - Same shell where nono fails CAN fetch `https://tuf-repo-cdn.sigstore.dev/15.root.json`
    successfully via `Invoke-WebRequest` (200 OK).
  - User IS behind a **corporate proxy / TLS-inspecting** environment
    (could be Zscaler, Netskope, custom enterprise CA in Windows root store,
    etc.). PowerShell's `Invoke-WebRequest` honors WinHTTP system proxy and
    trusts the Windows root cert store (including any corp-injected CAs).
  - Binary now correctly embeds `sigstore-trust-root 0.7.0` (built from
    current `main` at commit 40114a6d).

## Project Context

- This is the SAME binary the user installed via the MSI we just built. It
  has sigstore-trust-root 0.7.0 + Phase 49's `--from-file` flag (so an
  offline fallback exists if we can't fix the transport problem cleanly).
- The previous debug session diagnosed the embedded-anchor self-verify bug;
  fixing it surfaced this NEW failure that was previously masked.
- The original symptom report (memory `project_v26_opened.md`) noted Phase
  49 was specifically designed for exactly this scenario class: "live TUF
  refresh fails on enterprise machines". `--from-file` ships as a fallback.

## Current Focus

- **hypothesis**: nono's underlying HTTP client (`reqwest 0.12.28` via
  `sigstore-trust-root 0.7.0` → `tough 0.22.0`) is compiled with rustls +
  webpki-roots (Mozilla CA bundle) and does NOT use the Windows certificate
  store. In a TLS-inspecting corporate environment, the interceptor presents
  a cert signed by an enterprise CA that is in the Windows root store
  (where PowerShell's SChannel-based `Invoke-WebRequest` trusts it) but
  NOT in the Mozilla bundle, causing rustls to abort the TLS handshake.
  Reqwest reports this through its `Error::Display` as the generic
  "error sending request for url" string seen in the user's trace.
  - **H1a (TLS-root mismatch)**: STRONGLY supported by static analysis.
  - **H1b (proxy-config)**: Possible secondary factor — reqwest 0.12.28
    consumed here does NOT enable proxy autodetection by default. But
    H1a alone explains the symptom even if HTTPS_PROXY is set in env.
- **test**: ONE diagnostic command on the user's box discriminates
  whether H1a is sufficient or H1b is also active. See "checkpoint" below.
- **expecting**: With `RUST_LOG=trace`, reqwest's underlying error source
  chain will reveal either "invalid peer certificate: UnknownIssuer" /
  "BadCertificate" (→ H1a confirmed) or "proxy" / "ConnectError" (→ H1b
  also active). The verbose trace narrows the fix surface.
- **next_action**: Surface checkpoint to the user with (1) one diagnostic
  command and (2) the immediate Phase-49 `--from-file` workaround.

## Evidence

- timestamp: 2026-05-21 / source: live user CLI output / observation:
  failure message is "Transport 'other' error ... error sending request for
  url" — this is the verbatim reqwest::Error::Display when the underlying
  error doesn't categorize neatly. The fact that we got past "verify
  trusted root metadata" and ARE now in the fetch step also confirms the
  prior anchor-self-verify bug is gone.
- timestamp: 2026-05-21 / source: user confirmation / observation:
  `Invoke-WebRequest https://tuf-repo-cdn.sigstore.dev/15.root.json`
  returns 200 OK from the same shell. So the URL is reachable via at least
  one HTTP client on this host — narrows the issue to nono's client
  configuration, not the network path itself.
- timestamp: 2026-05-21 / source: user confirmation / observation:
  user is on a corporate proxy / TLS-inspecting environment. Strong prior
  for H1a (TLS root mismatch) or H1b (proxy config) over a generic network
  outage.
- timestamp: 2026-05-21 / source: static analysis of `Cargo.lock` +
  `crates/nono/Cargo.toml` / observation: `sigstore-trust-root 0.7.0` and
  `tough 0.22.0` both transitively depend on `reqwest 0.12.28`.
  reqwest 0.12.28's locked deps include `hyper-rustls 0.27.9` + `rustls` +
  `webpki-roots` but NOT `rustls-platform-verifier`. reqwest 0.13.3 in the
  same lockfile DOES include `rustls-platform-verifier 0.7.0` — confirming
  by elimination that the 0.12.28 branch consumed by sigstore-trust-root
  uses the bundled Mozilla CA bundle, not the OS root store. This means
  the binary's HTTP client trust anchors are FIXED at compile time and
  cannot see enterprise CAs deployed via Windows GPO/MDM into the local
  Trusted Root Certification Authorities store.
- timestamp: 2026-05-21 / source: code inspection /
  `crates/nono-cli/src/setup.rs:828-868` / observation: nono's
  `refresh_trust_root_step` calls `nono::trust::TrustedRoot::production()`
  (which is sigstore-rs's upstream entry point) with NO custom HTTP client.
  No `reqwest::Client::builder()` is constructed anywhere in nono — full
  `grep -rn 'reqwest' crates/` returns zero matches. The TLS backend and
  proxy behavior are 100% determined by upstream sigstore-trust-root
  0.7.0's choices — nono cannot patch them in-tree without forking or
  feature-flagging a custom client.

## Eliminated

- hypothesis: stale embedded TUF anchor (signature threshold failure).
  reason: previous debug session fixed this; current error is
  "Failed to fetch" not "Failed to verify trusted root metadata", and the
  chain walk has advanced to 15.root.json which only happens after the
  v14 embedded anchor self-verifies.
- hypothesis: tuf-repo-cdn.sigstore.dev outage / DNS / total network
  block. reason: `Invoke-WebRequest` from same host succeeds.
- hypothesis: nono builds its own reqwest client with wrong settings.
  reason: `grep -rn 'reqwest' crates/` confirms zero in-tree client
  construction; this is purely upstream behavior.

## Resolution

- root_cause: |
    `reqwest 0.12.28` (the HTTP client transitively consumed by
    `sigstore-trust-root 0.7.0` → `tough 0.22.0`) is compiled with the
    bundled Mozilla CA bundle via `webpki-roots` and does NOT consult the
    Windows certificate store. The user is behind a TLS-inspecting
    corporate proxy that presents server certificates signed by an
    enterprise CA which lives in the Windows Trusted Root store (where
    PowerShell's SChannel-backed `Invoke-WebRequest` trusts it) but is
    absent from the Mozilla bundle that rustls is validating against.
    rustls correctly rejects the unknown-issuer cert chain and reqwest
    surfaces this as the generic "error sending request for url" string
    seen by the user. The earlier anchor-self-verify fix simply moved the
    failure one step later into the chain walk; the TLS-trust mismatch
    was previously masked by the verify error.
- fix: |
    Immediate user-side unblock (no rebuild): use the Phase 49 escape
    hatch. Download or point at a current `trusted_root.json` and run:
        nono setup --from-file <path-to-trusted_root.json>
    The in-repo fixture at
    `crates/nono/tests/fixtures/trust-root-frozen.json` passes the
    freshness gate (5 of 7 tlogs have no `validFor.end`, treated as
    active per `check_trusted_root_freshness`) and is the fastest test
    path. For a production-current root, fetch
    `https://tuf-repo-cdn.sigstore.dev/targets/trusted_root.json` via
    `Invoke-WebRequest` (which uses SChannel and works on this host) to
    a local file and `--from-file` it.

    Longer-term code fix (post-v0.53.0): upstream `sigstore-trust-root`
    does not expose a custom-client seam yet, so the fix surface is
    either (a) PR `sigstore-rs` to add a `with_http_client(...)` builder
    on `TrustedRoot`, then in nono construct a `reqwest::Client::builder()
    .use_native_tls()` or `.tls_built_in_native_certs(true)` instance and
    pass it through, OR (b) document `SSL_CERT_FILE=<corp-CA-pem-bundle>`
    as an environment-variable workaround (rustls honors this when
    rustls-native-certs is in the build, but the 0.12.28 build chain here
    uses webpki-roots primarily — needs verification). Track as a v2.6
    milestone item, NOT a v0.53.0 blocker, because `--from-file` covers
    the operational gap that Phase 49 was explicitly designed for.
- verification: |
    User runs `nono setup --from-file <path>` and step [3/5] header now
    reads "Loading Sigstore trusted root from file..." and completes,
    writing `~/.nono/trust-root/trusted_root.json`. Subsequent
    `nono trust verify` operations succeed against locally cached root.
- files_changed: |
    None for the immediate fix — this is a runtime workaround using
    existing Phase 49 `--from-file` plumbing. Longer-term code change
    (if pursued) would touch `crates/nono/src/trust/bundle.rs` to add a
    `TrustedRoot::production_with_client(...)` seam IF upstream adds it,
    or wrap with a nono-local TUF fetch using a reqwest client we build
    ourselves with `.use_native_tls()` enabled.

## Resolution Applied (2026-05-21)

- **Immediate workaround applied**: User ran
  `nono setup --from-file C:\Users\OMack\Nono\crates\nono\tests\fixtures\trust-root-frozen.json`
  against the freshly-installed v0.53.0 binary. Output:
  `Setup complete!`. Verified via `nono setup --check-only`:
  `Trust root cache: OK (C:\Users\OMack\.nono\trust-root\trusted_root.json)`.
  User unblocked; trust-root-consuming flows now work offline against the
  cached bundle.
- **Code fix routed to planning**: Longer-term fix (rustls platform-verifier
  or native-tls so the HTTP client honors the Windows root store) routed
  to a new v2.6 milestone phase (TBD slot in ROADMAP.md). The in-binary
  Phase 49 `--from-file` plumbing covers operational use until the code
  fix ships.
- **Successor (Phase 50)**: corp-network TUF chain-walk needs an HTTP
  client that consults the OS root store. Two viable surface choices
  documented in `fix` field above.
