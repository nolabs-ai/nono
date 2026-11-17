# CLI login protocol v1

This document specifies the OAuth 2.0 contract between `nono platform login` and a nono
platform acting as the authorization server ([NEP-0009]). It is normative for
both the CLI and the platform. It does not define how the platform signs people
in (GitHub, Google, or other providers), how it onboards new accounts, or any
sandbox behaviour.

`nono platform login` signs in a person and, by default, registers a separate device
identity through the optional [login enrollment extension](login-enrollment-v1.md).
`--no-enroll` or `NONO_NO_ENROLL=true` requests sign-in only. Manual token enrollment and audit delivery
remain specified in [audit-delivery-v1](audit-delivery-v1.md).

The CLI is an OAuth 2.0 public native client:

| Parameter | Value |
|---|---|
| `client_id` | `nono-cli` (no client secret) |
| Redirect URI | `http://127.0.0.1:{port}/callback`, any port ([RFC 8252] §7.3) |
| PKCE | `S256` only ([RFC 7636]) |
| Token binding | DPoP with `ES256` ([RFC 9449]) |
| Grants | `authorization_code`, `urn:ietf:params:oauth:grant-type:device_code`, `refresh_token` |

The DPoP key is a P-256 key the CLI generates for the sign-in session. It is
unrelated to any device enrollment key.

## Scopes

| Scope | Meaning |
|---|---|
| `openid` | Issue an ID token identifying the person. |
| `nono:connect` | Access tokens accepted by nono-console: list sessions and attach to them. |
| `nono:runs` | Access tokens accepted by the platform Runs API: launch and read runs; and by nono-console to list the workspaces a run can target. |

The CLI requests all three. With automatic enrollment enabled and the extension
advertised, it also requests `nono:enroll`. That scope authorizes the dedicated
enrollment endpoint; it does not expand console or Runs API access.

A console accepts these tokens only for `GET /api/v1/sessions`,
`GET /api/v1/sessions/{id}/terminal` and `GET /api/v1/workspaces`, and still
applies the person's own permissions. Every other console operation refuses
them with 403. A resource server records each accepted proof's `jti` (scoped
to the key) in storage shared by all its replicas and kept across restarts.

## Discovery

For platform URL `P` (normalized as for `nono platform enroll --url`: no
query, no fragment, no trailing slash), the CLI fetches the [RFC 8414]
metadata. The well-known segment goes between the host and any path (RFC 8414
§3.1):

| Platform URL | Metadata URL |
|---|---|
| `https://nono.example.com` | `https://nono.example.com/.well-known/oauth-authorization-server` |
| `https://example.com/platform` | `https://example.com/.well-known/oauth-authorization-server/platform` |

The CLI does not follow redirects. It requires all of the following, and
otherwise fails without writing any state:

- `issuer` is exactly `P`;
- `token_endpoint` is present;
- every endpoint present has the same origin (scheme, host, port) as `P` and
  no userinfo, query or fragment. `P` is already restricted to `https`, or
  `http` on a loopback host for development;
- `code_challenge_methods_supported` contains `S256`;
- `dpop_signing_alg_values_supported` contains `ES256`;
- `authorization_response_iss_parameter_supported` is `true`.

`authorization_endpoint` is required for the loopback flow,
`device_authorization_endpoint` for the device flow, and `revocation_endpoint`
for `nono platform logout`. Deployments that front the platform with a reverse proxy
must route the metadata path to the platform.

## DPoP

Every request to the token, device authorization and revocation endpoints
carries a `DPoP` header holding a proof JWT as defined in RFC 9449 §4:

- header: `typ` `dpop+jwt`, `alg` `ES256`, and `jwk` holding the public key
  (`kty` `EC`, `crv` `P-256`, `x`, `y`);
- claims: `jti` (unique random), `htm`, `htu` (the request URI without query or
  fragment), `iat`, plus `nonce` when the server has supplied one.

The platform accepts a proof whose `iat` is at most 300 seconds old and at most
60 seconds in the future, and accepts each `jti` once.

If the server answers `400` with `error=use_dpop_nonce` and a new `DPoP-Nonce`
header, the CLI retries the request once with that nonce, and sends the most
recent nonce on later requests to the same server. Nonces must use the RFC 9449
NQCHAR alphabet and be at most 1024 bytes.

The key's JWK thumbprint `jkt` is computed as in [RFC 7638]: base64url
SHA-256 of `{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}`.

### Key fingerprint

The CLI prints a short fingerprint, and the consent screen shows the same value
so the person can compare them: the first 16 characters of `jkt`, in four
groups of four separated by `:`. For the RFC 9449 example key
(`jkt` `0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I`) the fingerprint is
`0ZcO:CORZ:NYy-:DWpq`. See `tests/fixtures/cli-login-v1.json`.

### Resource requests

An access token is presented to nono-console and to the platform Runs API as
`Authorization: DPoP <access token>` with a fresh proof that also carries
`ath` (base64url SHA-256 of the access token). For a WebSocket attach, the
proof's `htm` is `GET` and its `htu` is the HTTP form of the WebSocket URI
(`wss://` becomes `https://`, `ws://` becomes `http://`), without query or
fragment. That is the URI of the HTTP request that opens the WebSocket.

Resource servers must reject a DPoP-bound access token presented as `Bearer`.

## Flow A: authorization code on a loopback redirect

1. The CLI binds a listener on `127.0.0.1` with an ephemeral port, then opens
   the browser at the authorization endpoint with:

   | Parameter | Value |
   |---|---|
   | `response_type` | `code` |
   | `client_id` | `nono-cli` |
   | `redirect_uri` | `http://127.0.0.1:{port}/callback` |
   | `scope` | `openid nono:connect nono:runs` |
   | `code_challenge`, `code_challenge_method` | S256 PKCE, `S256` |
   | `state` | 32 random bytes, base64url |
   | `dpop_jkt` | the session key's `jkt` (RFC 9449 §10) |
   | `device_name` | optional: untrusted label for the consent screen, at most 64 characters, no control characters |

   The platform must accept any port on the `127.0.0.1` loopback redirect URI
   for `nono-cli` and bind the authorization code to `dpop_jkt`.

2. The platform signs the person in. Someone without an account signs in with
   one of the platform's providers, and the platform creates the account and
   runs its onboarding before returning to this request. The consent screen
   shows the client, the scopes and the key fingerprint. After sign-in the CLI
   selects the sole accessible tenant, or presents a terminal picker. `--tenant`
   explicitly selects a tenant by slug, ID, display name, or `personal`.

3. The platform redirects to the redirect URI with `code`, `state` and `iss`
   (RFC 9207), or with `error`, `state` and `iss`.

4. The CLI's listener answers `GET /callback` only. A request with a missing or
   wrong `state`, a repeated parameter, another path or another method is
   rejected and ignored; after 64 rejected requests the CLI aborts. A request
   with the correct `state` but a missing or wrong `iss`, or both or neither of
   `code` and `error`, aborts the login. The CLI holds the accepted request open
   until it has redeemed the code.

5. Token request:

   ```http
   POST {token_endpoint}
   Content-Type: application/x-www-form-urlencoded
   DPoP: <proof>

   grant_type=authorization_code&code=…&code_verifier=…
     &redirect_uri=http://127.0.0.1:{port}/callback&client_id=nono-cli
   ```

   The platform verifies that the proof key's `jkt` equals the `dpop_jkt`
   bound to the code. A code is single-use: it is consumed by the first
   redemption attempt, successful or not.

6. The CLI answers the held browser request with a `302` to the fixed
   completion page on `P`:

   ```text
   {P}/platform/cli/complete?result=success
   {P}/platform/cli/complete?result=error&error={code}
   ```

   `{code}` is an OAuth error code from the authorization or token response,
   or `client_error` when the CLI failed locally. The URL never carries codes,
   tokens or identifiers.

## Flow B: device authorization

The CLI uses this flow when `--device-code` is given, when `SSH_CONNECTION`
or `SSH_TTY` is set, when Linux has neither `DISPLAY` nor `WAYLAND_DISPLAY`,
when the platform offers no authorization endpoint, or when the loopback
listener cannot bind.

1. Device authorization ([RFC 8628]) with a DPoP proof:

   ```http
   POST {device_authorization_endpoint}
   DPoP: <proof>

   client_id=nono-cli&scope=openid nono:connect nono:runs&device_name=…
   ```

   This is an extension: RFC 9449 does not define DPoP at this endpoint. The
   platform records the proof key's `jkt` on the pending request.

2. The response must have `device_code`, a `user_code` of at most 32
   characters from `A-Z a-z 0-9 -`, a `verification_uri` on the platform
   origin, `expires_in` between 1 and 900 seconds, and an `interval` between 1
   and 30 seconds (5 if omitted). The CLI never shows
   `verification_uri_complete`; the person types the code.

3. The CLI polls the token endpoint with
   `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`,
   `client_id` and a DPoP proof. The platform answers a poll whose proof key
   differs from the recorded `jkt` exactly as it answers an unknown device code
   (`invalid_grant`). The CLI handles `authorization_pending`, adds 5 seconds to
   the interval on each `slow_down` (up to 60), and stops on `access_denied`,
   `expired_token` or any other error.

4. After approval, the platform sends the approving browser to the completion
   page directly.

## Token response

```json
{
  "access_token": "…",
  "token_type": "DPoP",
  "expires_in": 300,
  "refresh_token": "…",
  "id_token": "…",
  "scope": "openid nono:connect nono:runs",
  "nono_session": {
    "tenant_id": "0198f357-7c22-75e6-a64d-7dcb16ad5c91",
    "console_url": "https://console.example.com",
    "organizations": [
      {
        "tenant_id": "0198f357-7c22-75e6-a64d-7dcb16ad5c91",
        "slug": "alice",
        "display_name": "Alice",
        "kind": "personal"
      }
    ]
  }
}
```

The CLI requires:

- `token_type` is `DPoP` (case-insensitive). A `Bearer` token is refused;
- `expires_in` is present and between 1 and 3600;
- each token is 1 to 65536 visible ASCII characters;
- `refresh_token` is present on every response; refresh tokens rotate;
- for a sign-in (flows A and B): `id_token` is present;
- `nono_session` is present on every response, with:
  - `tenant_id`: the organization the access token is for, which must appear
    in `organizations`;
  - `console_url`: the nono-console origin for remote sessions, or `null` if
    the platform has none. When present it must be an absolute `https` URL, or
    `http` on a loopback host, with no userinfo, query or fragment;
  - `organizations`: every organization the person is an active member of,
    at most 1000. `slug` and `tenant_id` use the characters `A-Z a-z 0-9 . _ -`
    and are at most 200 characters; `kind` is `personal` or `organization`;
    `display_name` is display text the CLI sanitizes before printing.

The CLI reads the ID token claims without checking the signature. That is
permitted because the token came straight from the token endpoint over TLS
(OpenID Connect Core §3.1.3.7). It requires `iss` = issuer, `aud` containing
`nono-cli`, and `exp` not more than 5 minutes in the past. It uses `email`,
`preferred_username`, `name` or `sub` only to show who signed in.

### Choosing the organization

A sign-in's access token is for the organization selected on the consent
screen. Afterwards the CLI asks for a token for another organization with the
refresh grant:

```http
POST {token_endpoint}
DPoP: <proof>

grant_type=refresh_token&refresh_token=…&client_id=nono-cli&nono_tenant=<tenant id>
```

Without `nono_tenant` the platform uses the organization of the previous
token. The platform checks active membership on every refresh. A
`nono_tenant` the person is not a member of fails with `invalid_target` and
does not consume the refresh token. The CLI MUST check that
`nono_session.tenant_id` equals the `nono_tenant` it sent; on a mismatch it
stores the rotated refresh token, discards the access token and fails.

Refresh tokens belong to the person, not an organization, and are bound to the
session key. The refresh grant verifies the proof key. If a response carries a
new `refresh_token`, the CLI replaces the stored one before it uses the new
access token. A rotated refresh token presented again revokes the whole
session, so the CLI holds an exclusive lock on `platform-login.lock` while it
reads, refreshes, writes or deletes the session; concurrent nono commands
refresh one at a time.

### Access token claims

The access token is a platform-signed JWT (audience `nono-console`, scope
`console:access:dpop`) carrying the person's permissions in the organization
and `cnf.jkt` naming the session key. nono-console and the platform Runs API
both accept it, and only with a matching DPoP proof.

## Errors

Token endpoint errors use RFC 6749 §5.2 JSON with status 400 or 401. The CLI
accepts error codes of at most 64 characters from `a-z 0-9 _`. It treats
`invalid_grant` on refresh as a revoked or expired session and deletes it.

## Revocation

`nono platform logout` sends:

```http
POST {revocation_endpoint}
DPoP: <proof>

token=<refresh token>&token_type_hint=refresh_token&client_id=nono-cli
```

The platform revokes the session only when the proof key matches the token's
key, and answers 200 either way. Any status other than 200 is reported as a
failure. The CLI deletes its local session whatever the result. When it could
not send the request (credentials missing, unreadable, corrupt or with loose
permissions, or no record naming the platform), it still deletes the local
session but exits with an error saying the sign-in was not revoked.

## Completion page and landing page

`{P}/platform/cli/complete` is served by the platform using the person's
browser session.

- `result=success`: redirect to the active organization's admin-configured
  landing page, or show the platform's "signed in, you can close this tab"
  page.
- `result=error`: always show the platform's own error page.

The landing URL is configured only by an organization owner, in the platform.
It must be an absolute `https` URL with no userinfo or fragment, and is
validated when saved and again on redirect. It is never taken from query
parameters, `state`, the CLI or profiles.

## Local state

All of it lives in nono's state directory (`$XDG_STATE_HOME/nono`, created
0700), which no sandbox capability can grant:

| File | Contents |
|---|---|
| `platform-login.json` | Platform URL, issuer, signed-in user, current tenant, tenant memberships, console URL, session key thumbprint. No secrets. |
| `platform-login-key` | The session's P-256 private key (PKCS#8, base64), mode 0600. |
| `platform-login-refresh-token` | The current refresh token, mode 0600. |
| `platform-login.lock` | Empty; serializes session access between nono processes (`flock`), mode 0600. |

The CLI never stores access tokens. `nono remote connect`, `nono remote list` and
`nono remote run` use the refresh grant to get one on demand. Explicit
credentials (`NONO_RUN_TOKEN`, `--run-token-file`, `NONO_CONNECT_TOKEN`,
`--token-file`) take precedence over the session and cannot be combined with a
tenant override. Remote commands resolve `--tenant` before `NONO_TENANT`, then
the saved tenant, and verify the issued token matches that tenant. Command
overrides do not change the saved default or audit enrollment. See
[platform identity and tenant context](../platform-context.md) for user-facing
terminology and workflows.

[NEP-0009]: ../../neps/0009-cli-login.md
[RFC 7009]: https://www.rfc-editor.org/rfc/rfc7009
[RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636
[RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638
[RFC 8252]: https://www.rfc-editor.org/rfc/rfc8252
[RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
[RFC 8628]: https://www.rfc-editor.org/rfc/rfc8628
[RFC 9207]: https://www.rfc-editor.org/rfc/rfc9207
[RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449
