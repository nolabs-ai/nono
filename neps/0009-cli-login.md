---
nep: 0009
title: OAuth 2.0 login and device enrollment from the CLI (`nono login`)
authors:
  - lukehinds
status: draft
created: 2026-10-31
breaking: false
superseded-by:
---

# NEP-0009: OAuth 2.0 login and device enrollment from the CLI (`nono login`)

## Summary

Add `nono login`, which signs a developer in to a nono platform through a
standard OAuth 2.0 flow and, on first use, enrolls the machine in the same
round trip. The CLI acts as an OAuth 2.0 public native client. It opens the
platform's login page in the browser and receives the result on a loopback
redirect (authorization code + PKCE, [RFC 8252]). Its tokens are bound to the
CLI's device key with DPoP ([RFC 9449]). When no local browser is available,
such as over SSH or in a container, it falls back to the device authorization
grant ([RFC 8628]). When login finishes, the browser is sent to a landing page
the tenant has declared, for example an onboarding guide or internal docs.
Without one, it goes to the platform default.

Token-based `nono platform enroll --token` stays as the path for workloads,
CI, and fleet provisioning.

## Motivation

Today a developer machine gets connected in three steps:

1. A human signs in to the console and mints a short-lived, single-use
   enrollment token.
2. They paste it into `nono platform enroll --url … --token "$TOKEN"`, which
   generates a P-256 device key, exchanges the token for an audit-only
   `device` subject, and writes `platform.json`
   (`crates/nono-cli/src/platform_client.rs`).
3. On first `nono connect` / `nono ps --remote`, the CLI runs a second,
   bespoke device-code flow (`/api/v1/auth/device/*`, specified in
   [remote-attach-v1](../docs/protocols/remote-attach-v1.md)) to bind a human
   to that device.

The problems with this:

- **Not OAuth.** The human-authorization flow looks like RFC 8628 but is a
  private protocol: custom endpoints, an opaque credential, and a custom
  access-token exchange. Tenants that federate to an IdP (Okta, Entra ID,
  Google Workspace) expect a native CLI to be a normal OAuth client. That
  means standard discovery, consent, and token lifetimes, and revocation the
  IdP and platform admins already understand.
- **Friction.** It takes two browser trips and a manual token copy before the
  machine is useful. Developers expect `nono login`, as with `gh auth login` or
  `gcloud auth login`.
- **Token handling.** Bearer enrollment tokens pass through clipboards, chat,
  and shell history.
- **No onboarding hand-off.** Once enrolled, the developer is left at a
  terminal prompt. Tenants want to send new users somewhere specific: setup
  instructions, policy acknowledgement, a team-specific getting-started page.
  That page differs per organization.

### Goals

- `nono login` takes an unenrolled developer machine to "enrolled device +
  signed-in human" with one browser sign-in.
- Use standard OAuth 2.0 throughout:
  - authorization server metadata discovery ([RFC 8414]);
  - authorization code + PKCE on a loopback redirect ([RFC 8252], [RFC 7636]);
  - device authorization grant as a fallback ([RFC 8628]);
  - the `iss` response parameter ([RFC 9207]);
  - DPoP-bound tokens ([RFC 9449]);
  - token revocation ([RFC 7009]).
- Bind every token, and the enrollment itself, to the CLI-generated device
  key, so that intercepted codes or tokens are useless without the key.
- Let a tenant admin declare where the browser lands after a successful
  login, without letting the CLI, a link, or an attacker choose that
  destination.
- Make `nono login` idempotent. On an enrolled machine it only refreshes the
  human session.
- Add `nono logout` to revoke the human tokens without removing the device
  enrollment.

### Non-Goals

- Workload, CI, or headless-service enrollment. These keep
  `nono platform enroll --workload --token`.
- Any change to sandbox enforcement, capabilities, profiles, Landlock, or
  Seatbelt, or to the `nono` library and C bindings.
- Integrating the CLI directly with the tenant's IdP. The platform is the only
  OAuth authorization server the CLI talks to, and it federates to the IdP.
- Re-enrollment, key rotation, or moving a device between tenants.
- Hardware-attested device keys. See Open Questions.

## Proposal

### Roles

| OAuth role | nono component |
|---|---|
| Authorization server | nono platform (federates sign-in to the tenant IdP or local accounts) |
| Client | `nono` CLI: public native client, `client_id=nono-cli`, no client secret |
| Resource servers | platform APIs (audit delivery, connect/attach), nono-console |
| Resource owner | the developer signing in |

### CLI surface (`nono-cli` only)

```text
nono login  [--url <origin>] [--name <label>] [--keyref <ref>]
            [--browser | --device-code] [--no-open]
nono logout
```

- `--url`: platform origin, validated exactly as `platform enroll --url`
  (`validate_platform_url`). It is required on first login unless
  `NONO_PLATFORM_URL` is set. Once enrolled, it must equal the enrolled origin
  or be omitted.
- `--name`: device label, defaulting to the hostname. It is shown on the
  consent screen and treated as untrusted.
- `--keyref`: same semantics and default (`keystore://platform-device`) as
  `platform enroll`.
- `--browser` / `--device-code`: force a flow. By default the CLI uses the
  device code when `SSH_CONNECTION`/`SSH_TTY` is set or there is no usable
  display, and the loopback flow otherwise. If the loopback listener cannot
  bind, the CLI falls back to the device code and says so.
- `--no-open`: print the URL instead of opening a browser.

`nono platform enroll --url <origin>` without `--token` runs `nono login`.
`--workload` without `--token` is rejected.

### Local state machine

| Local state | `nono login` does |
|---|---|
| No `platform.json` | Enroll + sign in (scope includes `nono:device.enroll`) |
| Enrolled device, valid refresh token | Print identity, exit 0 |
| Enrolled device, no/expired/revoked refresh token | Sign in only (no enroll scope) |
| Enrolled, different origin | Error: run `nono platform unenroll` first |
| Enrolled as `workload` | Error: workloads cannot hold human sessions |

### Discovery

The CLI fetches `{origin}/.well-known/oauth-authorization-server`
([RFC 8414]) and requires all of the following:

- `issuer` exactly equals the origin, with the path prefix preserved;
- every endpoint it uses (authorization, token, device authorization,
  revocation) is `https` on the same origin, or `http` loopback in
  development;
- `code_challenge_methods_supported` includes `S256`;
- `dpop_signing_alg_values_supported` includes `ES256`;
- `authorization_response_iss_parameter_supported` is `true`.

Anything else fails closed. The CLI never follows endpoints on other origins.

### Flow A: authorization code + PKCE on a loopback redirect (default)

1. **Prepare.** Load or generate the P-256 device key, using the same code
   path as `platform_client::enroll`, and compute its JWK thumbprint `jkt`
   ([RFC 7638]). Generate a PKCE `code_verifier` (S256) and a random `state`.
   Bind a one-shot HTTP listener on `127.0.0.1`, on an ephemeral port chosen by
   the OS. Nothing is written to `platform.json` yet.

2. **Authorize.** Open the browser at:

   ```text
   {authorization_endpoint}?response_type=code&client_id=nono-cli
     &redirect_uri=http://127.0.0.1:{port}/callback
     &scope=openid nono:device.enroll nono:connect
     &code_challenge={S256}&code_challenge_method=S256
     &state={state}&dpop_jkt={jkt}
     &device_name={label}
   ```

   `dpop_jkt` ([RFC 9449 §10]) binds the authorization code to the device key
   before the user signs in. When the request is large, the platform should
   also accept it through Pushed Authorization Requests ([RFC 9126]), which
   keeps parameters out of the browser history.

3. **Sign in and consent (platform).** The platform shows its login page and
   federates to the tenant IdP as configured. It resolves user and tenant from
   that sign-in, never from CLI-supplied parameters. When the scope includes
   `nono:device.enroll`, it then shows a consent screen. The screen includes:
   - the device label;
   - a short key fingerprint, which the CLI also prints in the terminal;
   - the claimed OS and version, labelled *unverified*;
   - the requested scopes.

   Enrollment requires both:
   - the user's role permits device self-enrollment, and
   - the tenant's self-enrollment policy is not `disabled`.

   If the policy is `admin_approval`, the platform records a pending enrollment
   and the token request returns `authorization_pending`, in the same way as
   the device flow (see Open Questions).

4. **Callback.** The platform redirects to
   `http://127.0.0.1:{port}/callback?code=…&state=…&iss=…`. The listener
   accepts exactly one `GET /callback` and checks `state` (constant-time) and
   `iss`. It then holds the browser response open while it completes step 5,
   so the page the user sees reflects the real outcome.

5. **Token request.**

   ```text
   POST {token_endpoint}
   DPoP: <proof JWT signed by the device key>
   grant_type=authorization_code&code=…&code_verifier=…
     &redirect_uri=http://127.0.0.1:{port}/callback&client_id=nono-cli
   ```

   The platform checks that the proof's key matches the `dpop_jkt` bound at
   authorization. It returns a standard token response with
   `token_type: "DPoP"`, a short-lived access token, a DPoP-bound refresh
   token, and an ID token. When the scope included `nono:device.enroll`, the
   response also carries the enrollment as an extension member:

   ```json
   {"access_token":"…","token_type":"DPoP","expires_in":300,
    "refresh_token":"…","id_token":"…","scope":"…",
    "nono_enrollment":{"protocol_version":"1","tenant_id":"…","subject_id":"…",
                       "subject_kind":"device","management_mode":"audit_only",
                       "enrolled_at":"…"}}
   ```

   The CLI validates `nono_enrollment` exactly as `platform_client::enroll`
   does. It writes `platform.json`, then stores the refresh token in the
   keystore and discards the access token.

6. **Hand-off to the landing page.** The CLI answers the held callback request
   with a `302` to a fixed path on its own platform origin:

   ```text
   {origin}/platform/cli/complete?result=success
   {origin}/platform/cli/complete?result=error&error={oauth error code}
   ```

   The CLI puts no codes, tokens, or identifiers in that URL, and never
   redirects anywhere except its enrolled origin. The platform, which still has
   the user's browser session, then redirects to the tenant's declared landing
   page (see below). The CLI closes the listener and prints the tenant,
   subject, and signed-in user.

### Flow B: device authorization grant (fallback)

For SSH sessions, containers, and remote dev boxes, the CLI uses the standard
RFC 8628 endpoints from discovery, with the same `client_id`, scopes, and
device key:

1. `POST {device_authorization_endpoint}` with `client_id`, `scope`,
   `device_name`, and a `DPoP` proof. The platform records the proof's `jkt`
   on the pending request. This is an extension, because RFC 9449 does not
   define DPoP at this endpoint.
2. The CLI prints `verification_uri` and `user_code`, plus the key
   fingerprint. It does **not** display `verification_uri_complete`: the user
   types the code.
3. The user signs in on any browser and sees the same consent screen as in
   Flow A. After approving, the platform redirects that browser to the
   tenant's landing page directly.
4. The CLI polls `{token_endpoint}` with
   `grant_type=urn:ietf:params:oauth:grant-type:device_code` and a DPoP proof.
   The platform rejects any poll whose proof key differs from the recorded
   `jkt`. It handles `authorization_pending`, `slow_down`, `access_denied`, and
   `expired_token` per the RFC. The success response is the same as in Flow A.

The CLI enforces the existing bounds: code lifetime ≤ 15 min, interval
≤ 30 s, honouring `slow_down`.

### Tenant-declared landing page

Tenant admins configure the post-login destination in platform settings:

```yaml
cli_login:
  landing_url: https://wiki.example.com/eng/nono-getting-started
  # optional: different destinations for first enrollment vs re-sign-in
  reauth_landing_url: https://nono.example.com/platform/cli/signed-in
```

Rules:

- Only a tenant admin can set it, in the platform. The CLI, query parameters,
  the `state` value, and profiles cannot set or override it. Accepting a
  destination from the request would make `/platform/cli/complete` an open
  redirect.
- It must be an absolute `https` URL with no userinfo or fragment. It may be on
  any origin, so a tenant's wiki or intranet works. The platform validates it
  when saved and again when redirecting.
- If none is configured, the platform shows its default "you're signed in,
  you can close this tab" page. First enrollment and re-sign-in may use
  different pages.
- The redirect carries no tokens, codes, or device identifiers. A landing page
  that needs to personalise content does so through its own sign-in.
- Failed logins never go to the tenant page. They go to the platform's error
  page with the OAuth error code.

### Using the tokens

- `nono connect`, `nono ps --remote`, and audit delivery for login-enrolled
  devices obtain access tokens with the `refresh_token` grant plus DPoP. Each
  API call presents `Authorization: DPoP <token>` with a fresh proof. A copied
  refresh token is useless without the device key.
- Device-level operations that need no human, such as audit delivery and
  console discovery, keep the existing enrolled-request signatures, so
  delivery continues after the human session expires.
- `nono logout` calls the revocation endpoint ([RFC 7009]) for the refresh
  token, then deletes it locally. If revocation fails, the CLI still deletes
  the token, then reports the failure and exits non-zero. Device enrollment is
  untouched.

### Relationship to remote-attach-v1

The bespoke `/api/v1/auth/device/*` flow and its opaque credential are
superseded for login-enrolled devices. Token-enrolled devices keep working
unchanged. Moving them to the OAuth endpoints and deprecating the bespoke
flow is a follow-up, tracked in Open Questions.

### Protocol specification

The flow is specified in `docs/protocols/cli-login-v1.md`, which covers:

- the discovery requirements;
- the scopes;
- the `dpop_jkt` / device-authorization DPoP extension;
- the `nono_enrollment` token response member;
- the `/platform/cli/complete` contract;
- the landing-page rules.

Fixtures go in `tests/fixtures/`. The server lives in the platform repo, and
the protocol document is normative for both sides.

### Platform differences and compatibility

- No enforcement code changes. The differences between platforms are the
  existing keystore backends and browser-opening code.
- Additive: `platform enroll --token`, `connect`, and `ps --remote` keep
  working for existing enrollments.

## Security Considerations

This NEP changes no sandbox capability and no library API. The risk is in
issuing identity and tokens.

- **Authorization code interception.** Defended by PKCE S256, by binding the
  code to the device key through `dpop_jkt`, by single-use `state`, and by
  `iss` validation (mix-up defence, [RFC 9207]). Any one of these alone stops
  a stolen code from being redeemed.
- **Local processes on the loopback port.** Any local process, including a
  sandboxed agent with localhost network access, can connect to the listener.
  That gives it nothing:
  - the listener serves a single `GET /callback` and returns nothing
    sensitive;
  - a forged callback fails `state`;
  - an injected code fails PKCE or DPoP;
  - the listener binds `127.0.0.1` only, accepts one request, and times out
    when the authorization does.
- **Phishing.**
  - Loopback flow: an attacker who sends a victim a crafted authorization link
    cannot receive the code, because it goes to the victim's own loopback,
    where `state` fails.
  - Device-code flow: this remains the higher-risk path ([RFC 8628 §5.4]).
    Mitigations:
    - the user must type the code; `verification_uri_complete` is never shown;
    - the fingerprint and source IP/location appear on the consent screen;
    - the resulting device is audit-only;
    - tenant self-enrollment can be set to `admin_approval` or `disabled`;
    - every enrollment is audit-logged and admins are notified.
- **Open redirect.** The CLI redirects only to its enrolled origin's fixed
  completion path. The landing destination is admin-declared server-side,
  validated, and never taken from request input. Success and failure states
  cannot be confused into sending a failed login to a tenant page.
- **Brute force and the unauthenticated endpoints.** User codes have at least
  ~40 bits of entropy and approval attempts are rate-limited. Pending
  authorization and device requests are short-lived and capped globally and
  per source. Error responses do not reveal tenants.
- **Fail-secure.** Any discovery, `state`, `iss`, PKCE, DPoP, or contract
  mismatch aborts with an error and writes no `platform.json`. The only partial
  state is a generated key, which `platform enroll` already leaves behind and
  reuses. If the refresh token cannot be stored after enrollment, the result
  is an enrolled device without a human session, which the next `nono login`
  fixes.
- **Credential secrecy.** The refresh and access tokens, `code_verifier`,
  `device_code`, and private key are held in `Zeroizing` types. They never
  appear in `Debug`/`Display`, logs, errors, audit output, or child
  environments. The refresh token is stored in the keystore, not a plain file.
  Tokens are DPoP-bound, so a copied token is useless without the device key.
- **Sandboxed agents.** A sandboxed agent must not be able to run `nono login`
  against the host identity, read the platform state, or read the keystore
  entries. Implementation must confirm these are outside every default and
  profile grant, and test that a nested `nono login` fails closed. The
  loopback listener runs in the unsandboxed CLI process.
- **Path handling.** No new path logic.
- **Library/CLI boundary.** Everything stays in `nono-cli`. No change to
  `crates/nono` or `bindings/c`.

## Alternatives Considered

- **Device code only** (this NEP's first draft). It works everywhere, but has
  the weakest phishing resistance and a worse desktop experience. Device code
  is kept as the fallback.
- **Extend the bespoke remote-attach device flow.** This avoids new server
  work but keeps nono outside standard OAuth tooling, IdP policy, and
  revocation. Rejected.
- **Bearer tokens without DPoP.** Simpler, but a leaked token from logs,
  backups, or a copied home directory would be replayable. The device key
  already exists, so binding costs little.
- **mTLS-bound tokens ([RFC 8705]).** Equivalent binding, but it is awkward
  through corporate TLS-inspecting proxies and the CLI's HTTP stack. DPoP works
  at the application layer.
- **CLI chooses the landing page** (flag, profile, or `state`). Rejected as an
  open redirect that lets anyone send a freshly signed-in user to an
  arbitrary site.
- **Private-use URI scheme redirect (`nono://callback`).** Requires OS
  handler registration, is spoofable by other apps on some platforms, and
  gains nothing over loopback for a CLI.

## Open Questions

- Should there be a default hosted platform origin, or must
  `--url`/`NONO_PLATFORM_URL` always be explicit?
- What should the default tenant self-enrollment policy be (`allowed`,
  `admin_approval`, `disabled`)? With `admin_approval` in the loopback flow,
  should the CLI hold the browser open, or should it close the listener and
  poll a pending enrollment?
- Should the landing page be selectable per IdP group or role (for example
  one page per team) in addition to per tenant?
- Users in several tenants: does the tenant picker live on the platform login
  page, or does the CLI pass a `login_hint`-style tenant hint that the platform
  must match?
- What lifetimes should the refresh tokens have, should they rotate, and does
  tenant IdP session policy cap them?
- Should token-enrolled devices migrate from the remote-attach-v1 credential
  to OAuth refresh tokens, and on what deprecation timeline?
- Should hardware-backed keys (Secure Enclave, TPM) and attestation be
  surfaced on the consent screen in a follow-up NEP?

[RFC 7009]: https://www.rfc-editor.org/rfc/rfc7009
[RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636
[RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638
[RFC 8252]: https://www.rfc-editor.org/rfc/rfc8252
[RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
[RFC 8628]: https://www.rfc-editor.org/rfc/rfc8628
[RFC 8628 §5.4]: https://www.rfc-editor.org/rfc/rfc8628#section-5.4
[RFC 8705]: https://www.rfc-editor.org/rfc/rfc8705
[RFC 9126]: https://www.rfc-editor.org/rfc/rfc9126
[RFC 9207]: https://www.rfc-editor.org/rfc/rfc9207
[RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449
[RFC 9449 §10]: https://www.rfc-editor.org/rfc/rfc9449#section-10
