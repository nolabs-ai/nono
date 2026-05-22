---
phase: 50
slug: corp-network-tuf-refresh-via-os-root-store-replace-or-wrap-t
created: 2026-05-21
status: pending
scenarios: 1
---

# Phase 50 — Human-UAT Scenarios

> **Source:** 50-SPEC.md Req 6 (locked).
> One scenario, dispositive for SPEC Req 6. Per D-50-09, this UAT is the
> ONLY real TLS-stack check for Phase 50 — hermetic unit tests in
> `trust_refresh::tests` cover the chain-walk + cache-contract paths but
> deliberately do NOT exercise a real TLS handshake. Pass here is the
> proof that `ureq + platform-verifier` consults the Windows certificate
> store as advertised.

## Scenario 1: TLS-inspecting corporate proxy refresh succeeds natively

**Requirement:** SPEC Req 6
**Owner:** Original POC user (the one who hit the failure traced in
`.planning/debug/resolved/sigstore-tuf-fetch-transport.md`) OR any
contributor with access to a Windows host behind a TLS-inspecting
enterprise proxy whose interceptor CA is deployed via GPO/MDM into the
Windows root certificate store.

### Pre-conditions

- Windows 10 or Windows 11 host
- Host is connected to a network that uses a TLS-inspecting corporate
  proxy (e.g., Zscaler, Netskope, custom enterprise MITM appliance)
- The proxy's enterprise CA is present in `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT`
  (verify in PowerShell with: `Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -match '<your-corp-CA-name>'`)
- The Phase 50 nono build is installed (v0.53.x+ user-MSI or built from
  Phase 50 close SHA)
- No `<nono_home>/.nono/trust-root/trusted_root.json` exists yet
  (or it can be deleted before the run to force a fresh refresh)

### Steps

1. Open a PowerShell prompt on the corp-network Windows host.
2. (Optional sanity) Confirm Path B (Phase 49 `--from-file` workaround)
   is no longer the only path that works on this host: skip this and
   go straight to step 3 — if Phase 50 worked, you'll never need
   `--from-file` again on this corp-network.
3. Delete any cached trust root from a prior run:
   ```powershell
   Remove-Item -Force "$env:USERPROFILE\.nono\trust-root\trusted_root.json" -ErrorAction SilentlyContinue
   ```
4. Run the refresh:
   ```powershell
   nono setup --refresh-trust-root
   ```

### Expected output

- Step `[3/5] Refreshing Sigstore trusted root...` (or whatever
  index the step lands at — `[X/N]` formatting) exits 0.
- A new file `$env:USERPROFILE\.nono\trust-root\trusted_root.json`
  exists and is non-empty:
  ```powershell
  Test-Path "$env:USERPROFILE\.nono\trust-root\trusted_root.json"
  # Expected: True
  (Get-Item "$env:USERPROFILE\.nono\trust-root\trusted_root.json").Length
  # Expected: > 0
  ```
- Stderr contains ZERO `error sending request for url` errors (this
  was the corp-network failure signature traced in
  `.planning/debug/resolved/sigstore-tuf-fetch-transport.md`).
- Optionally, the new TUF datastore directory `$env:USERPROFILE\.nono\trust-root\tuf-cache\`
  exists and contains tough's local state (`latest_known_time.json`,
  intermediate root.json files, etc.).

### Failure modes to watch for

- If the run prints `Failed to fetch Sigstore trusted root from https://tuf-repo-cdn.sigstore.dev: ...`,
  capture the full error chain and check whether the trailing `: {e}`
  message contains:
  - `error sending request for url` — corp-network failure NOT
    fixed. Verify the build is post-Phase-50 close SHA. If yes, this
    is a regression — file a debug session.
  - `signature` / `threshold` / `expired` — TUF spec-layer failure
    unrelated to corp-network; consult Phase 49 `--from-file`
    fallback (`docs/cli/development/windows-poc-handoff.mdx`).
  - `not found` / `FileNotFound` — see Residual Risks section below
    re: 403 -> FileNotFound diagnostic obscurity.
- If `[3/5]` exits 0 but no cache file appears: investigate
  `nono_home_dir()` resolution under the running shell's `HOME` /
  `USERPROFILE`.

### Residual risks (Codex R-50-06 + R-50-10)

Phase 50 fixes ONE specific failure mode: **transparent TLS interception
by a corporate proxy whose CA is in the Windows root store**. The
following are explicitly NOT fixed by this phase and may still cause
`nono setup --refresh-trust-root` to fail on certain corp networks:

1. **Explicit proxy discovery (PAC files, WPAD, manual proxy settings).**
   nono / ureq does not consult Internet Explorer / Edge / Windows
   `WinHTTP` proxy settings, PAC files, or WPAD discovery. If the
   corp network REQUIRES traffic to flow through a forward proxy (not
   transparent TLS interception), this phase's fix is insufficient.
   Symptom: connection timeouts to `tuf-repo-cdn.sigstore.dev` even
   though browsers on the same host succeed.
   **Workaround:** Use Phase 49 `--from-file` with a trusted_root.json
   downloaded from the release page or another host that has direct
   internet access.

2. **Proxy authentication (Basic / NTLM / Kerberos).**
   Even if the corp proxy is reachable, it may require client
   authentication that nono does not provide. Browsers handle this
   transparently via SSO; nono does not.
   **Workaround:** Same as (1) — Phase 49 `--from-file`.

3. **403 -> FileNotFound diagnostic obscurity (R-50-10).**
   Tough's HTTP transport (and nono's `UreqTransport`) normalize HTTP
   403 responses into TUF "FileNotFound" errors so the chain walk can
   terminate cleanly when the next `N+1.root.json` doesn't exist on the
   server. CORP PROXIES THAT RETURN 403 FOR POLICY-DENY REASONS will
   appear to nono as if a TUF root file is missing.
   Symptom: error message like
   `Sigstore target not found in TUF repo: trusted_root.json` or
   `read trusted_root target: ...not found...` when in fact the proxy
   denied access to the URL.
   **Diagnostic:** Check the corp proxy's access logs for 403s on
   `tuf-repo-cdn.sigstore.dev` paths at the time of the failure. If
   confirmed, escalate to the proxy admin to allow-list those paths
   OR use Phase 49 `--from-file` as a workaround.

4. **CA missing from Windows root store entirely.**
   If the corp-proxy's interceptor CA is not yet deployed via GPO/MDM,
   nono will (correctly) reject the chain as untrusted. This is
   fail-secure behavior; remediation is to ensure the CA is properly
   deployed before testing this scenario.

### Recording the result

After running, append to `.planning/phases/50-corp-network-tuf-refresh-via-os-root-store-replace-or-wrap-t/50-VERIFICATION.md`:

```markdown
## Scenario 1 — TLS-inspecting corporate proxy refresh

- **Host:** {Windows 10|11} build {YYYY.MM}
- **Corp proxy:** {Zscaler|Netskope|other; CA subject snippet OK}
- **nono build SHA:** {git rev-parse HEAD}
- **Result:** pass | fail
- **Cache file size:** {bytes}
- **Stderr excerpt:** {none / or paste failure trail}
- **Date:** {YYYY-MM-DD}
- **Tester:** {handle}
- **If failed, which Residual Risk category applied?** {1-4 or n/a}
```

### Disposition gate

- `pass` -> Phase 50 SPEC Req 6 satisfied; Phase 50 can close.
- `fail` -> investigate the Residual Risk category first; if none match,
  file a debug session; do NOT close Phase 50.
- `not_run` (no corp-network host available within phase window) ->
  document the deferral in 50-VERIFICATION.md with a clear path to
  re-run when a host becomes available; SPEC Req 6 acceptance gate
  remains open.
