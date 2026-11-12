---
nep: 0009
title: Account sign-in from the CLI (`nono platform login`)
authors:
  - lukehinds
status: draft
created: 2026-10-31
breaking: true
superseded-by:
---

# NEP-0009: Account sign-in from the CLI (`nono platform login`)

## Summary

Add `nono platform login`, which signs a person in to a nono platform from the
terminal. The browser opens the platform's sign-in page, the person signs in
with GitHub or Google, and a first sign-in creates their account through the
platform's normal onboarding. The CLI then holds a revocable session that lets
it use the platform on that person's behalf: launch remote runs
(`nono remote run`), list remote sessions (`nono remote list`) and attach to
them (`nono remote connect`), in their personal account or in any organization they
belong to.

`nono platform login` signs in a person and automatically enrolls a separate device
identity unless `--no-enroll` is supplied. The coordinated extension is described
in [login-enrollment-v1](../docs/protocols/login-enrollment-v1.md). Manual enrollment
remains available through `nono platform enroll`.

New device registrations select an authorized enrollment group with the shared
terminal picker or `--group <name|id>`. Existing registrations retain their
groups; enrollment opt-outs skip group selection. `nono platform group` lists
and changes explicit memberships without rotating the device identity. Group
placement feeds [signed local policy delivery](../docs/protocols/local-policy-v1.md)
for subsequent runs; explicit local profiles still take precedence.

The CLI is a standard OAuth 2.0 public native client: authorization code with
PKCE on a loopback redirect ([RFC 8252], [RFC 7636]), with the device
authorization grant ([RFC 8628]) as the fallback when no local browser is
available. Tokens are bound to a key the CLI generates for the session, using
DPoP ([RFC 9449]).

## Implementation status

Implemented in `nono-cli` by PR #2250, pending acceptance of this NEP:
`nono platform login` (browser and device-code flows, `--tenant`), `nono platform logout`, session
use by `nono remote run`, `nono remote list` and `nono remote connect`, the
`cli-login-v1` protocol document and conformance fixtures. Open questions
below remain open.

## Motivation

Today a person who wants to use a hosted nono platform from the terminal must:

1. sign in to the platform in a browser;
2. mint a Run API personal access token and export it as `NONO_RUN_TOKEN` for
   `nono remote run`;
3. enroll the machine with a single-use enrollment token
   (`nono platform enroll --url … --token …`), because `nono remote connect` and
   `nono remote list` find the console through a request signed by an enrolled
   device;
4. complete a second, bespoke browser approval (remote-attach-v1) the first
   time they connect.

That is three credentials and two browser trips before anything works, and it
ties remote use to device enrollment, which exists for audit delivery. People
expect `nono platform login`, as with `gh auth login` or `gcloud auth login`: sign in
once, and the CLI can act as them.

### Goals

- `nono platform login` takes a person with no account to "signed in, account created"
  in one browser sign-in, using the platform's existing GitHub and Google
  sign-in and onboarding.
- After `nono platform login`, `nono remote run`, `nono remote list` and
  `nono remote connect` work with no other credential, token file or enrollment.
- A signed-in person can work in their personal account or any organization
  they are a member of, including ones they join later by invitation, and
  switch between them from the CLI.
- Standard OAuth 2.0 throughout, so the session is revocable and understood by
  platform administrators.
- No dependency on the operating-system keyring: sign-in works over SSH and in
  containers.
- `nono platform logout` revokes the session.

### Non-Goals

- Mandatory auditing and full terminal recording. Enrollment enables automatic
  audit delivery but leaves existing audit opt-outs intact.
- Signing in to an identity provider other than through the platform. The
  platform is the only OAuth authorization server the CLI talks to.
- Any change to sandbox enforcement, capabilities, profiles, Landlock or
  Seatbelt, or to the `nono` library and C bindings.
- Workload and CI authentication. These keep personal access tokens or
  workload enrollment.

## Proposal

### CLI surface (`nono-cli` only)

```text
nono platform login   [--url <origin>] [--tenant <name>] [--no-enroll] [--browser | --device-code] [--no-open]
nono platform logout
nono platform tenant list [--json]
nono platform tenant use <tenant> [--no-enroll]
nono platform re-enroll [--tenant <tenant>]
nono remote run --agent <agent> [--workspace <workspace>] [--tenant <tenant>] [--detached] [prompt]
nono remote list [--tenant <tenant>] [--all] [--json]
nono remote connect [session] [--tenant <tenant>]\```

The CLI groups sign-in, tenant selection and enrollment under `platform`, and
remote session operations under `remote`. Tenant administration remains in the web console: organizations, members, invitations and workspaces are
managed in the platform's web console.

- `--url` is the platform origin, validated like `platform enroll --url`. It
  defaults to `NONO_PLATFORM_URL`, then to the platform last signed in to, then
  to the hosted platform `https://app.nolabs.ai`; self-hosted platforms pass
  their own origin. It must match the signed-in platform while a session
  exists.
- Over SSH (`SSH_CONNECTION`/`SSH_TTY`), with no display, or when the loopback
  listener cannot bind, the CLI uses the device-code flow.
- After authentication, the CLI selects the only accessible tenant or displays
  a terminal picker shared with `nono remote connect`. `--tenant personal` selects the
  personal tenant.
  `nono platform tenant use <name>` makes another one active; on a signed-in machine it
  does so without a browser, after the platform confirms membership.
- `nono platform login` on a signed-in machine confirms the saved context and ensures
  device enrollment unless `--no-enroll` or `NONO_NO_ENROLL=true` is set.
  The summary uses **User**, **Current tenant**, and **Enrollment** separately.
- Remote commands (`nono remote run`, `nono remote list`, `nono remote connect`)
  resolve `--tenant` before `NONO_TENANT`, then the saved tenant. Overrides last
  one command, do not change local audit enrollment, and cannot change the scope
  of explicitly supplied API tokens. An unfinished default selection uses the
  shared tenant picker and persists the choice without creating an enrollment.
- A remote launch pins one resolved tenant and access token through workspace
  selection, submission, polling and attachment. The human CLI context owns
  remote selection; enrolled-device discovery remains a legacy fallback only.

See [platform identity and tenant context](../docs/platform-context.md) for
terminology, workflows, opt-outs and status semantics.

### Sign-in

1. The CLI generates a P-256 key for the session and stores it, with the rest
   of the session, in nono's protected state directory (see Security
   Considerations). It computes the key's thumbprint `jkt` ([RFC 7638]).
2. Discovery: `{origin}/.well-known/oauth-authorization-server` ([RFC 8414]).
   The CLI requires the issuer to equal the origin, every endpoint to be on
   the origin, PKCE `S256`, DPoP `ES256`, and the `iss` authorization response
   parameter ([RFC 9207]).
3. Authorization: the browser opens the authorization endpoint with
   `client_id=nono-cli`, a loopback `redirect_uri`, `scope=openid nono:connect
   nono:runs`, PKCE, `state` and `dpop_jkt`.
4. The platform shows its sign-in page. A person without an account signs in
   with GitHub or Google; the platform creates the account and personal
   organization and runs its onboarding, then returns to the request. The
   consent screen names the client, the scopes and the organization that will
   be active, and lets a member of several organizations choose.
5. The platform redirects to the loopback listener with `code`, `state` and
   `iss`. The CLI redeems the code with a DPoP proof. The response carries a
   short-lived access token, a refresh token, an ID token, and:

   ```json
   {
     "nono_session": {
       "tenant_id": "…",
       "console_url": "https://console.example.com",
       "organizations": [
         {"tenant_id": "…", "slug": "alice", "display_name": "Alice", "kind": "personal"},
         {"tenant_id": "…", "slug": "acme", "display_name": "Acme", "kind": "organization"}
       ]
     }
   }
   ```

6. The browser lands on the platform's completion page, which forwards to the
   organization's configured landing page or the platform default.

The device-code flow differs only in steps 3 and 5, as in [RFC 8628], with the
DPoP key recorded when the device authorization starts.

### Using the session

- The refresh token represents the person's CLI session. It belongs to the
  person, not to an organization, and is bound to the session key.
- Each access token is for one organization. The CLI asks for one with the
  refresh grant and a `nono_tenant` parameter naming the active organization.
  The platform checks membership every time, so an organization joined by
  invitation is usable immediately, and a removed membership stops working at
  the next refresh. The response carries a fresh `nono_session` member, which
  keeps the CLI's organization list current.
- The access token is accepted by nono-console (`nono remote connect`,
  `nono remote list`) and by the platform Runs API (`nono remote run`).
  Requests present it as `Authorization: DPoP <token>` with a proof.
  Permissions are the person's role permissions in that organization, as for
  their browser session.
- Access tokens live five minutes and are never stored. Refresh tokens rotate
  on every use; reuse of a rotated one revokes the session.
- `nono platform logout` revokes the refresh token ([RFC 7009]) and deletes the local
  session even if revocation fails.

### Relationship to existing credentials

- Explicit credentials keep precedence: `NONO_RUN_TOKEN`, `--run-token-file`,
  `NONO_CONNECT_TOKEN` and `--token-file` behave as today.
- A device-enrolled machine without a `nono platform login` session keeps using
  remote-attach-v1 for `nono remote connect`. Deprecating that flow is a follow-up.
- Manual token enrollment is retained. Login enrollment and fixed audit provenance
  are specified in `login-enrollment-v1`.

### Protocol specification

The wire contract is `docs/protocols/cli-login-v1.md`, normative for both the
CLI and the platform, with fixtures in `tests/fixtures/`.

## Security Considerations

This NEP changes no sandbox capability and no library API. The risk is in
issuing and holding human credentials.

- **Code interception.** PKCE S256, `state`, `iss` validation and binding the
  code to the session key through `dpop_jkt` each stop a stolen code from
  being redeemed.
- **Local processes and the loopback port.** The listener binds `127.0.0.1`,
  answers only `GET /callback` with the right `state`, and ignores everything
  else; a forged callback fails `state`, and an injected code fails PKCE and
  DPoP.
- **Phishing.** The loopback flow cannot deliver a code to an attacker. The
  device-code flow is the higher-risk path ([RFC 8628 §5.4]): the user must
  type the code, `verification_uri_complete` is never shown, the consent
  screen shows the key fingerprint the CLI printed, and failed code entry is
  rate-limited.
- **Credential storage.** The session key and refresh token live in nono's
  state directory (`$XDG_STATE_HOME/nono`), owner-only (0600 files in a 0700
  directory). That directory is a protected root: no sandbox capability can
  grant it, so an agent running under nono cannot read the session. A process
  running as the user outside nono can read both, the same exposure as
  `gh` or `gcloud` file storage; DPoP still prevents replay of a token
  captured in transit, in logs, or by a server. Secrets are held in
  `Zeroizing` types and never logged.
- **Sandboxed agents.** `nono platform login` (including `--tenant`) and `nono platform logout`
  refuse to run inside a nono sandbox. Remote commands launched by an agent
  inside a sandbox cannot use the session, because they cannot read it.
- **Organization scoping.** The organization comes from the person's
  memberships, checked on every token. A `nono_tenant` value the person is
  not a member of is refused; the CLI never chooses an organization the
  platform has not listed.
- **Open redirect.** The CLI redirects the browser only to the platform's
  fixed completion path; landing pages are configured by organization owners
  and validated by the platform.
- **Fail-secure.** Any discovery, `state`, `iss`, PKCE, DPoP or contract
  mismatch aborts without writing a session.
- **Library/CLI boundary.** Everything stays in `nono-cli`.

## Alternatives Considered

- **Sign in by enrolling the device** (this NEP's earlier draft). It tied a
  person's remote access to the machine's audit identity, needed the device
  key (and so the OS keyring) before sign-in, and could not express "a person
  in several organizations". Rejected.
- **Mint a personal access token at login.** Works with the Runs API
  unchanged, but leaves a long-lived secret per organization on disk and in
  the token list. Short-lived session tokens are revocable as one sign-in.
- **Bearer tokens.** Simpler, but a token leaked from a log or proxy would be
  replayable. DPoP costs little.
- **Store the session in the OS keyring.** Stronger against other local
  processes, but unavailable or locked over SSH and in containers, which are
  where the CLI is often used. A keyring backend can be added later as an
  option.
- **Fix the organization at login.** Simpler, but members of several
  organizations would sign in repeatedly. `nono platform tenant use` keeps the
  organization a sign-in setting while switching through a token refresh
  instead of a new sign-in.
- **A `nono org list` / `nono org switch` command group.** Rejected to keep
  the CLI from growing platform-administration commands; `nono platform login` reports
  the current context and `--tenant` switches.
- **Organization-free tokens.** A token covering every organization, with
  the platform inferring the organization from each request, would remove the
  concept from the CLI entirely. Rejected: the console and its row-level
  security are scoped to one organization, `remote list` would need a listing
  that spans organizations, a workspace name can exist in several
  organizations, and membership would be checked per request instead of per
  token.

## Open Questions

- Should the platform list and let people revoke their CLI sessions in its
  security settings?
- What lifetime should a CLI session have, and should an organization's
  policy (for example required MFA) cap it?



[RFC 7009]: https://www.rfc-editor.org/rfc/rfc7009
[RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636
[RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638
[RFC 8252]: https://www.rfc-editor.org/rfc/rfc8252
[RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
[RFC 8628]: https://www.rfc-editor.org/rfc/rfc8628
[RFC 8628 §5.4]: https://www.rfc-editor.org/rfc/rfc8628#section-5.4
[RFC 9207]: https://www.rfc-editor.org/rfc/rfc9207
[RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449
