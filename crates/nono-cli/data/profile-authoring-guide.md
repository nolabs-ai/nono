# nono Profile Authoring Guide

This guide is designed for LLM agents helping users create custom nono profiles. It covers the full profile schema, common patterns, and validation workflow.

## 1. Profile File Location

User profiles live at **`~/.config/nono/profiles/<name>.json`** by default. If
`XDG_CONFIG_HOME` is set, nono uses **`$XDG_CONFIG_HOME/nono/profiles/<name>.json`**
instead. In profile JSON path grants, prefer `$XDG_CONFIG_HOME`, `$NONO_CONFIG`, or
`$NONO_PACKAGES` over hardcoded `$HOME/.config/...`.

Profile names must be alphanumeric with hyphens only. No leading or trailing hyphens.

Valid: `my-agent`, `ci-build`, `dev2`
Invalid: `-leading`, `trailing-`, `has spaces`, `special_chars!`

User profiles take precedence over built-in profiles of the same name.

## 2. Minimal Profile Example

```json
{
  "meta": {
    "name": "my-agent",
    "description": "Profile for my agent"
  },
  "groups": {
    "include": []
  },
  "workdir": {
    "access": "readwrite"
  }
}
```

## 3. Section Reference

### meta

| Field         | Type   | Required | Description              |
|---------------|--------|----------|--------------------------|
| `name`        | string | yes      | Profile name             |
| `version`     | string | no       | Semver version string    |
| `description` | string | no       | Human-readable summary   |
| `author`      | string | no       | Author name              |

### extends

Inherit from another profile by name:

```json
{
  "extends": "default"
}
```

- Inheritance chain max depth: 10.
- The CLI `--extends <PROFILE>` flag composes a selected `--profile` for one
  invocation. It is repeatable and prepends its bases to the profile JSON's
  `extends` list, preserving left-to-right merge order while keeping the
  selected profile as the final override layer. Inherited grants can widen
  sandbox permissions.
- Scalar fields: child overrides base.
- Array fields (`groups.include`, `groups.exclude`, `commands.allow`, `commands.deny`, `filesystem.*`, `allow_domain`, `deny_domain`, `open_port`, `listen_port`, `rollback.*`, `upstream_bypass`): child values are appended to base values and deduplicated. To remove inherited entries, use `groups.exclude` for groups; there is no mechanism to remove inherited filesystem paths. For `allow_domain` entries with endpoint rules, rules for the same domain are merged (appended) rather than replaced. `deny_domain` entries are additive — child profiles can only add more denies, never remove inherited ones.
- Map fields (`env_credentials`, `hooks`, `custom_credentials`): child entries are merged into base; child keys override matching base keys.
- `network_profile` supports three-state inheritance via `InheritableValue`: absent = inherit base value, `null` = explicitly clear, string = override. This is the only field that supports null-clearing.
- `open_urls`: if the child provides the field (even as `{}`), it replaces the base entirely. If absent, the base value is inherited. Setting to `null` in JSON is equivalent to omitting it (both inherit the base).
- `workdir`: child overrides base unless child is `"none"` (which inherits the base value instead).

### platform_overrides

Apply per-OS patches to the profile after `extends` resolution. Only the block matching the current platform is merged in; the others are ignored.

```json
{
  "meta": { "name": "myprofile" },
  "filesystem": {
    "read": ["/tmp"]
  },
  "platform_overrides": {
    "macos": {
      "security": { "process_info_mode": "allow_all" },
      "filesystem": { "read": ["/opt/homebrew", "~/Library/Caches"] }
    },
    "linux": {
      "security": { "signal_mode": "isolated", "process_info_mode": "allow_same_sandbox" },
      "filesystem": { "read": ["/usr/lib", "~/.cache"] }
    }
  }
}
```

Merge semantics are identical to `extends`: array fields are dedup-appended, scalar fields are child-wins, deny-lists union. The override can only add or tighten — it cannot remove inherited paths or relax inherited deny rules.

Valid platform keys are `macos`, `linux`, and `windows`. Unrecognised keys are a parse error.

`extends` and `platform_overrides` are not allowed inside an override block. Nesting either is a parse error.

Use `platform_overrides` when a single profile needs different paths or security modes per OS. Use group-level `when` predicates for package-level platform differences that are already handled by built-in groups.

### groups

Controls which policy groups apply to the profile. Group definitions live in `policy.json`; list available groups with `nono profile groups`.

| Field     | Type            | Default | Description |
|-----------|-----------------|---------|-------------|
| `include` | array of string | `[]`    | Policy group names to apply. |
| `exclude` | array of string | `[]`    | Group names to remove from the resolved group set, including inherited defaults. |

### commands

Controls startup-time command gating. These checks run only at launch time and are not enforced on child processes — prefer path-based controls in `filesystem` for strong enforcement.

| Field   | Type            | Default | Description |
|---------|-----------------|---------|-------------|
| `allow` | array of string | `[]`    | Startup-only command allowlist. Deprecated in v0.33.0; retained for existing profiles. |
| `deny`  | array of string | `[]`    | Startup-only command denylist extension. Deprecated in v0.33.0; prefer `filesystem.deny` and narrower grants instead. |

### command_policies

tool-sandbox policies live under `command_policies`. Use `commands.<name>.executable` to bind a command name to one exact executable file instead of the first PATH match. By default, tool-sandbox rejects pinned executables and direct parent directories that are writable through the outer sandbox capability set. If a low-assurance profile intentionally grants write access overlapping a pinned executable, `commands.<name>.allow_writable_executable` is available as a per-command trust downgrade. It is valid only with an absolute `executable` path; relative paths and bare command names fail validation. For local demos, `command_policies.allow_writable_executables` disables the writable executable and parent-directory trust check across policy, deny-only, and outer executable allow-list paths. The agent still invokes the command name through the tool-sandbox shim. On macOS, tool-sandbox verifies the file before sandboxing but must still exec by path, so sandbox-writable pinned executables are not suitable for high-assurance policies.

Command sandbox path lists (`fs_read`, `fs_write`, `fs_read_file`, `fs_write_file`) may use dynamic provider tokens. `@git:config-files` expands to trusted global/system Git config files, Git file settings (attributes, excludes, commit templates), and the declared target of every `include.path` and `includeIf.*.path` directive — including conditional includes that do not currently fire. `@git:hooks-path` expands to trusted global/system `core.hooksPath` directories. `@git:common-dir` expands to the git common directory (`.git` in a regular repo, or the absolute path to the main repo's `.git` in a worktree). `@git:worktree` expands to the main worktree root (empty in a regular repo). `@git:toplevel` expands to the current checkout root. `@git:toplevel-parent` expands to the parent of the current checkout root. These tokens are opt-in per profile and ignore repo-local/worktree Git config so a checkout cannot grant itself extra host filesystem access.

```json
{
  "command_policies": {
    "entrypoint": "demonator",
    "commands": {
      "demonator": {
        "executable": "/opt/homebrew/bin/demonator",
        "sandbox": {
          "fs_write": ["/opt/homebrew/bin"]
        },
        "allow_writable_executable": true
      }
    }
  }
}
```

#### Tool Sandbox  command-policy denials

Tool Sandbox denials are not filesystem denials. A message like:

```text
nono: tool-sandbox denied gh: Command 'gh' is blocked: agents may read issues but not comment on them
```

means the tool-sandbox command policy blocked the resolved command invocation. `nono why --path ...` only explains filesystem grants and denials, and `nono why --host ...` only explains network/proxy reachability. For command-policy denials, query the command edge directly:

```sh
nono why --profile <profile> --command gh -- issue comment 1052
nono profile show <profile>
nono profile validate <profile>
```

Look under `command_policies.commands.<command>.from.<caller>.invocation_policy` for argv or environment rules. For commands started directly by the sandboxed session, the caller is usually `session`; for a child tool launched by another controlled tool, the caller is the parent command name.

`invocation_policy` evaluates in this order: `deny`, then `approve`, then `allow`, then `default`. The `argv` matcher compares against the command arguments after the command name, so `gh issue comment 1052` matches `{"argv": {"prefix": ["issue", "comment"]}}`.

```json
{
  "command_policies": {
    "commands": {
      "gh": {
        "from": {
          "session": {
            "sandbox": {
              "fs_read": ["."],
              "network": {
                "allow_domain": ["api.github.com"]
              }
            },
            "invocation_policy": {
              "default": "deny",
              "deny": [
                {
                  "argv": { "prefix": ["issue", "comment"] },
                  "reason": "agents may read issues but not comment on them"
                }
              ],
              "allow": [
                {
                  "argv": { "prefix": ["issue", "list"] },
                  "reason": "agents may list GitHub issues"
                },
                {
                  "argv": { "prefix": ["issue", "view"] },
                  "reason": "agents may view GitHub issues"
                }
              ]
            }
          }
        }
      }
    }
  }
}
```

To allow a previously denied subcommand, remove or narrow the matching `deny` rule and add a matching `allow` rule, or change `default` if that is the intended policy. Adding a child-profile `allow` does not override an inherited `deny`. When profiles are merged, command policy permissions widen monotonically in most places, and an inherited `invocation_policy` on the same command edge is retained rather than replaced. If the resolved profile already contains the deny you want to remove, edit the profile that owns that rule or extend a base profile that does not include it.

#### Proxy credential endpoint policy

Some Tool Sandbox  policies intentionally use two layers:

1. `invocation_policy` blocks obvious high-level CLI mutations before the child process runs.
2. `sandbox.credentials[].endpoint_policy` blocks the underlying HTTP method and path even if the CLI uses a broad subcommand such as `gh api`.

If a command uses a proxy credential, both layers must allow the operation. For example, permitting `gh issue comment` at the argv layer is not enough if the GitHub API proxy still denies `POST /repos/<owner>/<repo>/issues/**`.

```json
{
  "command_policies": {
    "credentials": {
      "github-api": {
        "type": "proxy",
        "upstream": "https://api.github.com",
        "credential_key": "keyring://gh:github.com/example?decode=go-keyring",
        "env_var": "GH_TOKEN",
        "inject_header": "Authorization",
        "credential_format": "Bearer {}"
      }
    },
    "commands": {
      "gh": {
        "from": {
          "session": {
            "sandbox": {
              "credentials": [
                {
                  "name": "github-api",
                  "endpoint_policy": {
                    "default": "deny",
                    "allow": [
                      { "method": "GET", "path": "/repos/nolabs-ai/nono/issues" },
                      { "method": "GET", "path": "/repos/nolabs-ai/nono/issues/*" },
                      { "method": "POST", "path": "/repos/nolabs-ai/nono/issues/*/comments" }
                    ],
                    "deny": [
                      {
                        "method": "DELETE",
                        "path": "/**",
                        "reason": "destructive GitHub API calls are denied"
                      }
                    ]
                  }
                }
              ]
            },
            "invocation_policy": {
              "default": "deny",
              "allow": [
                { "argv": { "prefix": ["issue", "list"] } },
                { "argv": { "prefix": ["issue", "view"] } },
                { "argv": { "prefix": ["issue", "comment"] } },
                {
                  "argv": { "prefix": ["api"] },
                  "reason": "gh api is constrained by endpoint_policy"
                }
              ]
            }
          }
        }
      }
    }
  }
}
```

Endpoint policy uses the same decision order as invocation policy: `deny`, then `approve`, then `allow`, then `default`. A broad `deny` such as `{"method": "POST", "path": "/repos/nolabs-ai/nono/issues/**"}` will still win over a later `allow` for issue comments. Remove or narrow the deny when the mutation is intentionally allowed.

### security

| Field                 | Type            | Default      | Description |
|-----------------------|-----------------|--------------|-------------|
| `signal_mode`         | string          | `"isolated"` | One of: `"isolated"`, `"allow_same_sandbox"`, `"allow_all"`. |
| `process_info_mode`   | string          | `"isolated"` | One of: `"isolated"`, `"allow_same_sandbox"`, `"allow_all"`. |
| `ipc_mode`            | string          | `"shared_memory_only"` | One of: `"shared_memory_only"`, `"full"`. Use `"full"` for multiprocessing (enables POSIX semaphores). macOS only. |
| `capability_elevation`| boolean         | `false`      | Enable runtime capability elevation via seccomp-notify. Linux only. |
| `wsl2_proxy_policy`  | string          | `"error"`    | WSL2 only. Controls behavior when proxy-only network mode cannot be kernel-enforced. `"error"`: refuse to run (fail-secure). `"insecure_proxy"`: allow degraded execution where credential proxy runs but child is not prevented from bypassing it. See [WSL2 docs](https://nono.sh/docs/cli/internals/wsl2). |

### filesystem

All filesystem grants, denials, and deny-rule exemptions live under this single section.

| Field               | Type            | Description |
|---------------------|-----------------|-------------|
| `allow`             | array of string | Directories with read+write access. |
| `read`              | array of string | Directories with read-only access. |
| `write`             | array of string | Directories with write-only access. |
| `allow_file`        | array of string | Single files with read+write access. |
| `read_file`         | array of string | Single files with read-only access. |
| `write_file`        | array of string | Single files with write-only access. |
| `deny`              | array of string | Paths denied filesystem access. |
| `bypass_protection` | array of string | Paths exempted from deny groups. **This flag does not implicitly grant access** — `bypass_protection` only removes the deny rule; each path must also appear in `filesystem.allow`, `filesystem.read`, or `filesystem.write` (or the matching `*_file` variant) to become accessible. |
| `ignore`            | array of string | Paths whose runtime denials should not be offered in save-profile prompts. Does not grant access or hide diagnostics. |

All path fields support variable expansion (see Section 6).

### workdir

| Field    | Type   | Default  | Description |
|----------|--------|----------|-------------|
| `access` | string | `"none"` | One of: `"none"`, `"read"`, `"write"`, `"readwrite"`. Controls automatic CWD sharing with the sandboxed process. |

### network

| Field                   | Type                              | Default  | Description |
|-------------------------|-----------------------------------|----------|-------------|
| `block`                 | boolean                           | `false`  | Block all network access. |
| `allow_http2`           | boolean                           | `false`  | Allow HTTP/2 to upstream servers via ALPN negotiation. Default is HTTP/1.1 with keep-alive. Equivalent to `--allow-http2`. |
| `network_profile`       | string or null                    | inherit  | Name from `network-policy.json` for proxy filtering. Set to `null` to clear inherited value. |
| `allow_domain`          | array of string or object         | `[]`     | Additional domains to allow through the proxy. Entries can be plain strings (CONNECT tunnel) or objects with endpoint rules (TLS-intercepted L7 filtering). Aliases: `proxy_allow`, `allow_proxy`. |
| `deny_domain`           | array of string                   | `[]`     | Domains to block through the proxy regardless of the allowlist. Evaluated before `allow_domain`. Supports wildcard subdomains (`*.ads.example.com`). Equivalent to `--deny-domain`. |
| `credentials`           | array of string                   | `[]`     | Credential services to enable via reverse proxy. Alias: `proxy_credentials`. |
| `open_port`             | array of integer                  | `[]`     | Localhost TCP IPC. Aliases: `port_allow`, `allow_port`. Port **0**: macOS only (`localhost:*` outbound); Linux: explicit ports. |
| `listen_port`           | array of integer                  | `[]`     | TCP ports the sandboxed child may listen on. |
| `custom_credentials`    | map of string to credential def   | `{}`     | Custom credential route definitions (see below). Defines the route only — the proxy does not activate unless the service name also appears in `credentials`. |
| `upstream_proxy`        | string                            | `null`   | Enterprise proxy address (`host:port`). Alias: `external_proxy`. |
| `upstream_bypass`       | array of string                   | `[]`     | Hosts to bypass the upstream proxy. Supports `*.` wildcard suffixes. Alias: `external_proxy_bypass`. |

#### allow_domain with endpoint restrictions

When an `allow_domain` entry is an object with `endpoints`, the proxy performs TLS interception to enforce method+path restrictions (default-deny). This is useful for restricting access to specific API endpoints without credential injection:

```json
{
  "network": {
    "allow_domain": [
      "api.openai.com",
      {
        "domain": "api.github.com",
        "endpoints": [
          { "method": "GET", "path": "/repos/my-org/**" },
          { "method": "POST", "path": "/repos/my-org/*/issues" }
        ]
      }
    ]
  }
}
```

| Field       | Type   | Required | Description |
|-------------|--------|----------|-------------|
| `domain`    | string | yes      | Domain hostname (e.g., `"api.github.com"`). |
| `endpoints` | array  | yes      | L7 method+path rules. Only requests matching at least one rule are allowed. |

Each endpoint rule has `method` (HTTP method or `"*"` for any) and `path` (glob pattern: `*` = one segment, `**` = zero or more segments).

When profiles extend each other, endpoint rules for the same domain are **appended** (merged), not replaced. Proxy mode is automatically enabled when endpoint rules are present.

#### custom_credentials entry

Define a custom reverse proxy credential route for services not in `network-policy.json`.

> **Important:** `custom_credentials` defines the route configuration but does not activate the proxy on its own. The service name must also appear in `credentials` to start the proxy and inject the phantom token. For example:
>
> ```json
> {
>   "network": {
>     "credentials": ["myservice"],
>     "custom_credentials": {
>       "myservice": {
>         "upstream": "https://api.myservice.com",
>         "credential_key": "myservice_api_key",
>         "inject_header": "Authorization",
>         "credential_format": "Bearer {}"
>       }
>     }
>   }
> }
> ```

An individual entry in the `custom_credentials` map is configured as follows:

```json
{
  "upstream": "https://api.example.com",
  "credential_key": "example_api_key",
  "inject_mode": "header",
  "inject_header": "Authorization",
  "credential_format": "Bearer {}",
  "proxy": {
    "inject_mode": "query_param",
    "query_param_name": "api_key"
  }
}
```

| Field               | Type            | Required    | Description |
|---------------------|-----------------|-------------|-------------|
| `upstream`          | string          | yes         | Upstream URL. Must be HTTPS (HTTP only for loopback). |
| `credential_key`    | string          | yes         | Keystore account name, `op://` URI, `bw://` URI, `apple-password://` URI, `file://` URI, `env://` URI, or `cmd://` URI referencing `credential_capture`. |
| `inject_mode`       | string          | no          | One of: `"header"` (default), `"url_path"`, `"query_param"`, `"basic_auth"`. |
| `inject_header`     | string          | header mode | HTTP header name. Default: `"Authorization"`. |
| `credential_format` | string          | header mode | Format string with `{}` placeholder. Default: `"Bearer {}"`. |
| `path_pattern`      | string          | url_path    | Pattern to match in URL path. Use `{}` for placeholder. |
| `path_replacement`  | string          | url_path    | Replacement pattern. Defaults to `path_pattern`. |
| `query_param_name`  | string          | query_param | Query parameter name for credential injection. |
| `proxy`             | object          | no          | Optional proxy-side overrides for phantom token parsing. Omitted fields inherit from top-level values. |
| `env_var`           | string          | URI keys    | Environment variable name for SDK API key. Required when `credential_key` is `op://`, `bw://`, `apple-password://`, `file://`, or `cmd://`. Optional for `env://`. |
| `endpoint_rules`    | array           | no          | L7 allow-list of `{"method": "GET", "path": "/**"}` rules. When non-empty, only matching requests are forwarded (default-deny). |
| `tls_ca`            | string (path)   | no          | Path to a PEM-encoded CA certificate. Use for upstreams with self-signed or private CA certs (e.g. a Kubernetes API server). |
| `tls_client_cert`   | string (path)   | no          | Path to a PEM-encoded client certificate for mutual TLS (mTLS). Must be set together with `tls_client_key`. |
| `tls_client_key`    | string (path)   | no          | Path to the PEM-encoded private key matching `tls_client_cert`. |

`proxy` overrides apply only to how the local proxy validates incoming phantom tokens from the sandboxed process. Outbound upstream credential injection continues to use top-level fields.

### credential_capture

Defines supervisor-side commands and provider subprocesses that produce credentials for `cmd://` custom credential routes. Capture runs lazily when the proxy first needs the credential; only the proxy receives captured material, and the sandboxed child never sees the command output, provider output, or real credential.

```json
{
  "network": {
    "credentials": ["github"],
    "custom_credentials": {
      "github": {
        "upstream": "https://api.github.com",
        "credential_key": "cmd://github",
        "env_var": "GH_TOKEN",
        "credential_format": "token {}"
      }
    }
  },
  "credential_capture": {
    "github": {
      "command": ["gh", "auth", "token"],
      "timeout_secs": 5,
      "cache_ttl_secs": 900,
      "cache_path_regex": "^/(?:repos/|orgs/)?([^/]+)"
    }
  }
}
```

Provider-backed captures use a typed JSON protocol. The provider receives request metadata and provider-specific config on stdin and returns credential material on stdout. The provider does not route requests or inject credentials; `nono` still validates the phantom token, applies endpoint policy, validates provider output, and injects only on matching upstream requests.

```json
{
  "network": {
    "credentials": ["acme_mcp"],
    "custom_credentials": {
      "acme_mcp": {
        "upstream": "https://mcp.acme.com",
        "credential_key": "cmd://acme_mcp",
        "env_var": "ACME_MCP_TOKEN",
        "credential_format": "Bearer {}",
        "endpoint_rules": [{ "method": "*", "path": "/mcp/**" }]
      }
    }
  },
  "credential_capture": {
    "acme_mcp": {
      "provider": {
        "command": ["acme-nono-provider"],
        "config": {
          "issuer": "https://auth.acme.com",
          "client_id": "abc123"
        }
      },
      "timeout_secs": 30,
      "cache_ttl_secs": 240
    }
  }
}
```

Provider stdout must be JSON:

```json
{
  "material": {
    "type": "secret",
    "value": "real-access-token"
  }
}
```

For multi-header output, configure `output.allow_headers` and return:

```json
{
  "material": {
    "type": "headers",
    "headers": {
      "Authorization": "Bearer real-access-token"
    }
  }
}
```

| Field              | Type            | Required | Default | Description |
|--------------------|-----------------|----------|---------|-------------|
| `command`          | array of string | yes      | —       | Command and arguments. No shell interpolation is used. |
| `timeout_secs`     | integer         | no       | `5`     | Maximum runtime, 1–300 seconds. |
| `cache_ttl_secs`   | integer         | no       | `900`   | In-memory cache TTL, 0–3600 seconds. `0` disables caching. |
| `ttl_secs`         | integer         | no       | `900`   | Older alias for `cache_ttl_secs`. Do not set both fields. |
| `cache_path_regex` | string          | no       | host    | Regex evaluated against the request path. Capture group 1 becomes the cache scope; otherwise the full match is used. |
| `stdin`            | string          | no       | `null`  | `null` closes stdin (unless `interaction.stdin` is `true`); `request_json` writes request metadata JSON to stdin. |
| `output`           | string/object   | no       | `text`  | `text` captures stdout as one credential. `{"format":"json","allow_headers":[...]}` captures multiple headers. |
| `interaction`      | object          | no       | none    | Explicit opt-in for capture commands that need inherited stderr, inherited stdin, or browser opening. |

Capture commands run with `NONO_SESSION_ID`, `NONO_REQUEST_HOST`, `NONO_REQUEST_PATH`, `NONO_REQUEST_METHOD`, `NONO_CACHE_SCOPE`, `NONO_CAPTURE_CREDENTIAL`, and `NONO_CAPTURE_ROUTE` set. Proxy environment variables are removed to avoid recursively using the same proxy route while capturing the credential.

`stdin: "request_json"` sends this shape to the command:

```json
{
  "session_id": "c0ffee1234567890",
  "credential_name": "github",
  "route_id": "github",
  "request_host": "api.github.com",
  "request_path": "/repos/nolabs-ai/nono/issues/787",
  "request_method": "GET",
  "cache_scope": "nolabs-ai"
}
```

For multi-header injection, use object-form output and allow every header name explicitly:

```json
{
  "credential_capture": {
    "gateway": {
      "command": ["internal-auth", "headers"],
      "output": {
        "format": "json",
        "allow_headers": ["Authorization", "X-Gateway-Key"]
      }
    }
  }
}
```

The command must print JSON like `{"headers":{"Authorization":"Bearer ...","X-Gateway-Key":"..."}}`. The proxy rejects empty output, unlisted headers, hop-by-hop headers, invalid header names, non-string values, and values containing CR or LF. Audit records include the route, command path, redacted argv, duration, exit status, cache state, cache scope, output format, header names, stdin mode, interaction flag, stdout byte count, and redacted stderr for failures; credential values are never logged.

Browser auth is command-scoped. Add `interaction.open_urls` to a specific capture entry when that command may open a browser:

```json
{
  "credential_capture": {
    "github": {
      "command": ["gh", "auth", "login"],
      "interaction": {
        "stdio": true,
        "open_urls": {
          "allow_origins": ["https://github.com"],
          "allow_localhost": true
        },
        "allow_launch_services": true
      }
    }
  }
}
```

When `open_urls` is configured, nono gives the capture command a temporary `BROWSER` helper and URL-opening socket. On macOS it also prepends an `open` shim to `PATH`. URL requests through those helpers are validated against that capture entry's `interaction.open_urls`, not the child sandbox's top-level `open_urls`. Non-URL `open` fallback through the shim is available only when `allow_launch_services` is true.

### credential_providers and credential_routes

`credential_providers` declare profile-driven OAuth providers for sandboxed `/login` flows where the agent may drive the CLI, but token endpoint responses are captured and rewritten before real token material reaches the sandbox. The sandbox receives phantom `nono_<64hex>` tokens; the proxy resolves those phantoms to real tokens only for declared `api_hosts` and route endpoint policy.

`credential_routes` bind a provider to the sandbox-visible environment variables and optional API endpoint policy. Provider declarations are data, so local profiles and packs can define providers without adding Rust enum variants or merging provider-specific code.

OAuth capture currently forces HTTP/1.1 for declared token hosts so the proxy can buffer and rewrite token responses before releasing them to the sandbox. HTTP/2 token response rewriting must be implemented before capture hosts can safely negotiate h2.

When a client has its own CA-bundle environment variable, add it with
`network.tls_intercept.ca_env_vars`. nono still sets the standard CA variables;
profile entries add client-specific names that should point at the same
generated trust bundle.

```json
{
  "network": {
    "tls_intercept": {
      "ca_env_vars": ["CODEX_CA_CERTIFICATE"]
    }
  },
  "credential_providers": {
    "claude_code": {
      "type": "oauth_capture",
      "token_endpoints": [
        {
          "host": "https://platform.claude.com",
          "path": "/v1/oauth/token",
          "response_fields": [
            { "path": "access_token", "kind": "opaque" },
            { "path": "refresh_token", "kind": "opaque" },
            { "path": "id_token", "kind": "jwt" }
          ],
          "request_body": "auto",
          "request_nonce_fields": ["access_token", "refresh_token"]
        }
      ],
      "api_hosts": ["https://api.anthropic.com"],
      "credential_store": {
        "type": "keychain_json",
        "service": "Claude Code-credentials",
        "account_candidates": ["unknown", "$USER", "claude-code-user"],
        "phantom_fields": [
          "claudeAiOauth.accessToken",
          "claudeAiOauth.refreshToken"
        ]
      },
      "helpers": {
        "status": ["claude", "auth", "status", "--json"],
        "login": ["claude", "auth", "login"],
        "logout": ["claude", "auth", "logout"]
      }
    }
  },
  "credential_routes": [
    {
      "name": "anthropic_oauth",
      "provider": "claude_code",
      "env_var": "ANTHROPIC_AUTH_TOKEN",
      "base_url_env_var": "ANTHROPIC_BASE_URL",
      "endpoint_policy": {
        "default": { "decision": "deny" },
        "allow": [{ "method": "POST", "path": "/v1/messages" }]
      }
    }
  ]
}
```

| Provider field       | Type            | Required | Description |
|----------------------|-----------------|----------|-------------|
| `type`               | string          | yes      | Currently `oauth_capture`. |
| `token_endpoints`    | array           | yes      | HTTPS OAuth token origins and exact paths whose JSON responses are captured and rewritten to phantom tokens. Configure every token-bearing path the client may use. |
| `api_hosts`          | array           | yes      | HTTPS API URL origins where this provider's phantom tokens may be resolved on egress. |
| `response_fields`    | array           | yes      | Token response fields to rewrite. Each entry declares a `path` and a visible phantom `kind` of `opaque` or `jwt`; use `jwt` only for locally parsed fields, not bearer tokens resent upstream. |
| `request_body`       | string          | no       | Token request body format for refresh/exchange rewriting: `auto`, `json`, or `form`. |
| `credential_store`   | object          | no       | Optional session/logout detection, such as a keychain JSON record or file JSON record with fields expected to contain phantoms. |
| `helpers`            | object          | no       | Optional status, login, and logout commands for humans or CLI workflows. Commands are arrays and are not run through a shell. |

The OAuth capture store lives under nono's state directory with owner-only
permissions. It retains real token material for phantom resolution for up to 90
days, capped at 4096 phantoms.

Unmatched capture-host responses are inspected for common OAuth token field
names as a fail-closed backstop. Providers that use unusual token field names
still need exact `token_endpoints` and exhaustive `response_fields`; the backstop
is not the primary capture policy.

| Route field          | Type            | Required | Description |
|----------------------|-----------------|----------|-------------|
| `name`               | string          | yes      | Route name used in generated proxy routes and audit. |
| `provider`           | string          | yes      | Provider key from `credential_providers`. |
| `env_var`            | string          | no       | Optional environment variable for clients that can start from a sandbox-visible phantom. Many OAuth CLI clients instead receive phantoms by writing their captured credential store during login. |
| `base_url_env_var`   | string          | no       | Environment variable that points SDKs or CLIs at the mediated proxy base URL. |
| `endpoint_policy`    | object          | no       | Method/path policy for provider API egress. |

### env_credentials (alias: secrets)

Maps keystore account names to environment variable names. Secrets are loaded from the system keystore (macOS Keychain / Linux Secret Service) under the service name "nono".

```json
{
  "env_credentials": {
    "openai_api_key": "OPENAI_API_KEY",
    "op://vault/item/field": "ANTHROPIC_API_KEY"
  }
}
```

Supported key formats:
- Bare keystore account name: `"openai_api_key"`
- 1Password URI: `"op://vault/item/field"`
- Apple Passwords URI: `"apple-password://account/name"`
- Environment reference: `"env://EXISTING_VAR"`

### environment

Controls which environment variables are passed to the sandboxed process. When `allow_vars` is set, only the listed variables (and nono-injected credentials) are passed through. `set_vars` injects explicit values regardless of filtering.

```json
{
  "environment": {
    "allow_vars": ["PATH", "HOME", "TERM", "AWS_*"],
    "deny_vars": ["GH_TOKEN"],
    "set_vars": { "RUST_LOG": "debug", "XDG_CONFIG_HOME": "$HOME/.config" }
  }
}
```

| Field         | Type            | Default | Description |
|---------------|-----------------|---------|-------------|
| `allow_vars`  | array of string | absent  | Allow-list of environment variable names. Supports exact names (`"PATH"`) and prefix patterns ending with `*` (`"AWS_*"` matches `AWS_REGION`, `AWS_SECRET_ACCESS_KEY`, etc.). The `*` wildcard is only valid as a trailing suffix. When omitted (or when the `environment` section is absent entirely), all variables pass through. When explicitly set to `[]`, no inherited variables are passed (only nono-injected credentials). When non-empty, only matching variables pass. Nono-injected credentials always bypass this list. |
| `deny_vars`   | array of string | `[]`    | Deny-list of environment variable names stripped from the child. Same pattern syntax as `allow_vars` (exact names and trailing `*`). Denied vars are stripped even if they also match `allow_vars`. |
| `set_vars`    | object (string→string) | `{}` | Static environment variables injected after allow/deny filtering and before credential injection (injected credentials win on conflict). Values support the same expansion as profile paths (`$HOME`, `~`, `$WORKDIR`, `$TMPDIR`, `$XDG_*`, `$NONO_CONFIG`, `$NONO_PACKAGES`); keys are not expanded. `PATH` and any `NONO_*` key are reserved and rejected at load time. Unlike inherited host vars, keys here are NOT subject to the dangerous-variable blocklist (`LD_PRELOAD`, `NODE_OPTIONS`, …) — setting one is an explicit operator decision. |

Inheritance: child `allow_vars` and `deny_vars` are appended to base values and deduplicated; `set_vars` merges as a map, with the child's value winning on key conflict.

### hooks

Map of application name to hook configuration:

```json
{
  "hooks": {
    "claude-code": {
      "event": "PostToolUseFailure",
      "matcher": "Read|Write|Edit|Bash",
      "script": "nono-hook.sh"
    }
  }
}
```

| Field     | Type   | Description |
|-----------|--------|-------------|
| `event`   | string | Trigger event name. |
| `matcher` | string | Regex for tool name matching. |
| `script`  | string | Script filename from embedded hooks. |

### rollback (alias: undo)

| Field              | Type            | Description |
|--------------------|-----------------|-------------|
| `exclude_patterns` | array of string | Path component patterns to exclude from snapshots. |
| `exclude_globs`    | array of string | Glob patterns for filename exclusion. |

### open_urls

Controls supervisor-delegated URL opening (e.g., OAuth2 login flows).

| Field             | Type            | Default | Description |
|-------------------|-----------------|---------|-------------|
| `allow_origins`   | array of string | `[]`    | Allowed URL origins (scheme + host, e.g., `"https://console.anthropic.com"`). |
| `allow_localhost`  | boolean         | `false` | Allow `http://localhost` and `http://127.0.0.1` URLs. |

To replace inherited URL-opening permissions, provide `open_urls` with an explicit empty object: `"open_urls": { "allow_origins": [], "allow_localhost": false }`. Omitting `open_urls` inherits the base profile's configuration.

## 4. Common Patterns

### Developer profile (extending default)

```json
{
  "extends": "default",
  "meta": {
    "name": "developer",
    "description": "General development"
  },
  "workdir": {
    "access": "readwrite"
  },
  "filesystem": {
    "read": ["$HOME/.config"]
  }
}
```

### CI profile (locked down)

```json
{
  "meta": {
    "name": "ci-build",
    "description": "CI build environment"
  },
  "groups": {
    "include": ["deny_credentials", "deny_ssh_keys"]
  },
  "workdir": {
    "access": "readwrite"
  },
  "network": {
    "block": true
  }
}
```

### Agent with API access

```json
{
  "extends": "default",
  "meta": {
    "name": "api-agent",
    "description": "Agent with API access"
  },
  "workdir": {
    "access": "readwrite"
  },
  "env_credentials": {
    "openai_api_key": "OPENAI_API_KEY"
  },
  "network": {
    "network_profile": "standard"
  }
}
```

### Linux host compatibility

On Linux, the built-in `default` profile keeps host runtime, sysfs, and shared temp reads out of the base policy. If your tool needs access to paths like `/run`, `/var/run`, `/sys`, or `/tmp`, extend the built-in compatibility preset:

```json
{
  "extends": "linux-host-compat",
  "meta": {
    "name": "linux-desktop-agent",
    "description": "Agent with Linux host runtime compatibility"
  },
  "workdir": {
    "access": "readwrite"
  }
}
```

### Profile with deny overrides

When a deny group blocks a path you need access to, use `filesystem.bypass_protection` together with an explicit grant. Remember: `bypass_protection` only removes the deny rule — it does not grant access on its own.

```json
{
  "extends": "default",
  "meta": {
    "name": "shell-config-reader",
    "description": "Needs to read shell configs"
  },
  "workdir": {
    "access": "readwrite"
  },
  "filesystem": {
    "read_file": ["$HOME/.bashrc", "$HOME/.zshrc"],
    "bypass_protection": ["$HOME/.bashrc", "$HOME/.zshrc"]
  }
}
```

### Suppress repeated save suggestions

Use `filesystem.suppress_save_prompt` for paths you intentionally do not want
to grant, but also do not want offered in the save-profile prompt every run:

```json
{
  "extends": "default",
  "meta": {
    "name": "copilot-local",
    "description": "Local prompt-suppression choices"
  },
  "filesystem": {
    "suppress_save_prompt": ["$HOME/.copilot/settings.json"]
  }
}
```

The sandbox still denies these paths. `filesystem.suppress_save_prompt` only
filters the save-profile suggestion. `filesystem.ignore` is accepted as an
alias, but new profiles should use the explicit suppress name so it is not
mistaken for an access grant.

### Denying specific project files

Block access to a file in the working directory while keeping the rest accessible. Use `$WORKDIR` to reference the current working directory — relative paths like `./` are not expanded:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "no-dotenv",
    "description": "Claude Code without .env access"
  },
  "filesystem": {
    "deny": ["$WORKDIR/.env"]
  }
}
```

**macOS**: This works directly. Seatbelt can deny a specific file within an allowed directory.

**Linux**: Landlock is strictly allow-list and cannot deny a child of an allowed parent. Use supervised mode instead, which intercepts file opens via seccomp-notify and checks them against the deny list before granting access:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "no-dotenv",
    "description": "Claude Code without .env access"
  },
  "security": {
    "capability_elevation": true
  },
  "filesystem": {
    "deny": ["$WORKDIR/.env"]
  }
}
```

With `capability_elevation` enabled, nono runs in supervised mode where every file access outside the initial grant set is trapped and evaluated. The deny list is checked before the supervisor prompts for approval, so denied paths are blocked regardless of platform.

### Blocking container access (Docker, Podman, kubectl)

Socket access enforcement is platform-specific because macOS (Seatbelt) and Linux (Landlock + seccomp) have different capabilities.

#### macOS

Use `filesystem.deny` on the socket path. Seatbelt treats `connect(2)` as a network operation, so nono also emits a `network-outbound` deny for the path — the socket is blocked at both the filesystem and network layers:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "no-docker",
    "description": "Claude Code without Docker access"
  },
  "filesystem": {
    "deny": ["/var/run/docker.sock"]
  }
}
```

#### Linux

Landlock cannot express deny-within-allow, so `filesystem.deny` is a no-op on Linux. Instead, enable `linux.af_unix_mediation` to switch to a default-deny seccomp supervisor for AF_UNIX pathname sockets, then add back only the sockets the agent needs via `filesystem.unix_socket`:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "no-docker",
    "description": "Claude Code without Docker access"
  },
  "linux": {
    "af_unix_mediation": "pathname"
  }
}
```

With no `filesystem.unix_socket` entries, every AF_UNIX pathname connect and bind is blocked — including `/run/docker.sock`. To allow specific sockets back (e.g. tmux, D-Bus), add them explicitly:

```json
{
  "linux": { "af_unix_mediation": "pathname" },
  "filesystem": {
    "unix_socket": ["/run/user/1000/bus"]
  }
}
```

#### Deprecation note

`commands.deny` is deprecated startup-only gating — it blocks the command from launching but does not enforce socket access and should not be relied on as enforcement. It remains visible in `nono profile show` under the commands section for compatibility.

### Allowing parent-of-protected-root grants (macOS only)

By default, granting a parent directory of `~/.nono` (e.g. `--allow ~`) is rejected because it would expose nono's internal state. On macOS, Seatbelt can express deny-within-allow rules, so this restriction can be relaxed when the profile opts in with `allow_parent_of_protected`:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "home-access",
    "description": "Claude Code with full home directory access"
  },
  "allow_parent_of_protected": true
}
```

When `allow_parent_of_protected` is `true` and the platform is macOS, nono permits the parent grant and emits Seatbelt deny rules that protect `~/.nono` from reads and writes. On Linux this field is ignored — Landlock cannot deny a child of an allowed parent, so the pre-flight check always rejects parent-of-protected grants.

### Profile with group exclusion

Remove an inherited deny group that is too restrictive for your use case:

```json
{
  "extends": "default",
  "meta": {
    "name": "browser-tool",
    "description": "Needs browser data access"
  },
  "workdir": {
    "access": "readwrite"
  },
  "groups": {
    "exclude": ["deny_browser_data_macos", "deny_browser_data_linux"]
  }
}
```

### Profile with custom credential routing

```json
{
  "extends": "default",
  "meta": {
    "name": "telegram-bot",
    "description": "Telegram bot with credential injection"
  },
  "workdir": {
    "access": "readwrite"
  },
  "network": {
    "custom_credentials": {
      "telegram": {
        "upstream": "https://api.telegram.org",
        "credential_key": "telegram_bot_token",
        "inject_mode": "url_path",
        "path_pattern": "/bot{}/",
        "path_replacement": "/bot{}/"
      }
    },
    "credentials": ["telegram"]
  }
}
```

## 5. Validation

Run these commands to verify a profile:

```
nono profile validate <path>      # Check a profile file for errors
nono profile show <name>          # Show the fully resolved profile (after inheritance)
nono profile groups               # List available security groups
nono profile diff <a> <b>         # Compare two profiles
```

## 6. Variable Expansion

The following variables are expanded in all path fields (`filesystem.*`, including `filesystem.allow`, `filesystem.read`, `filesystem.write`, `filesystem.deny`, `filesystem.bypass_protection`, and `filesystem.suppress_save_prompt`), in `command_args`, and in the values of `environment.set_vars`.

| Variable           | Expands to |
|--------------------|------------|
| `$HOME`            | User's home directory |
| `$WORKDIR`         | Working directory (from `--workdir` flag or cwd) |
| `$REPO_ROOT`       | Git repository root (`--repo-root`, `NONO_REPO_ROOT`, or auto-detected via `git rev-parse`). Left unexpanded when not in a git repo — path is then silently skipped. |
| `$TMPDIR`          | System temporary directory |
| `$UID`             | Current user ID |
| `$XDG_CONFIG_HOME` | XDG config directory (default: `$HOME/.config`) |
| `$XDG_DATA_HOME`   | XDG data directory (default: `$HOME/.local/share`) |
| `$XDG_STATE_HOME`  | XDG state directory (default: `$HOME/.local/state`) |
| `$XDG_CACHE_HOME`  | XDG cache directory (default: `$HOME/.cache`) |
| `$XDG_RUNTIME_DIR` | XDG runtime directory (no default; left unexpanded when unset) |

Always use these variables instead of hardcoded absolute paths to keep profiles portable across machines and users.

### Monorepo example

When running from a nested package directory, use `$REPO_ROOT` to reference
files at the repository root without hardcoding `../` levels:

```json
{
  "filesystem": {
    "read_file": [
      "$REPO_ROOT/AGENTS.md",
      "$REPO_ROOT/.cursor/rules/AGENTS.md"
    ]
  }
}
```

Override the detected root with `--repo-root /path/to/repo` or by setting
`NONO_REPO_ROOT=/path/to/repo` in your environment.

## 7. Platform Predicates

Profile entries that list paths, group names, URL origins, or env credentials can be unconditional strings or conditional objects with `when`.

```json
{
  "groups": {
    "include": [
      "agent_common",
      { "name": "agent_linux", "when": "linux" },
      { "name": "agent_macos", "when": "macos" }
    ]
  },
  "filesystem": {
    "read": [
      "$HOME/.agent",
      { "path": "$HOME/Library/Application Support/Agent", "when": "macos" },
      { "path": "$XDG_CONFIG_HOME/agent", "when": "linux" }
    ]
  },
  "env_credentials": {
    "agent_key": { "env_var": "AGENT_API_KEY", "when": ["linux", "macos:>=15"] }
  }
}
```

Supported predicate forms include `linux`, `macos`, `linux:fedora`, `linux:rhel-like`, `linux:ubuntu:>=24.04`, `macos:>=15`, negation such as `!linux:nixos`, and arrays for any-of matching.

## 8. Key Rules

- A profile with no `groups.include` has no deny rules. Always include appropriate deny groups for untrusted workloads.
- `filesystem.bypass_protection` only removes the deny rule. It does not grant access. You must also add the path via `filesystem.allow`, `filesystem.read`, or `filesystem.write` (or the matching `*_file` variant).
- `filesystem.suppress_save_prompt` only suppresses save-profile suggestions. It does not grant access, remove deny rules, or hide diagnostics.
- `groups.exclude` removes groups from the resolved set. This weakens the sandbox. Use it only when you understand which protections you are removing.
- `extends` chains resolve recursively up to depth 10. Circular inheritance is an error.
- `platform_overrides` is applied after all `extends` inheritance is resolved. The override for the current platform is merged as a child, so its values win over inherited ones. Override blocks cannot themselves use `extends` or `platform_overrides`.
- Prefer `when` predicates for package-specific platform differences. Put shared OS baseline paths in built-in policy groups instead.
- `network.block: true` blocks all network access. It cannot be combined with proxy settings.
- `custom_credentials` upstream URLs must use HTTPS. HTTP is only accepted for loopback addresses (localhost, 127.0.0.1, ::1).

## 9. Migration from previous schema

Issue [#594](https://github.com/nolabs-ai/nono/issues/594) restructured the profile JSON schema. The old `policy.*` namespace has been dissolved into `filesystem`, `groups`, and `commands`; `security.groups` and `security.allowed_commands` have moved to top-level `groups.include` and `commands.allow`.

Legacy keys still deserialize — profiles using the old names continue to load and emit a single deprecation warning — but they are scheduled for removal in **v1.0.0**. New profiles and edits should use the canonical keys below.

| OLD                          | NEW                             |
|------------------------------|---------------------------------|
| `security.groups`            | `groups.include`                |
| `security.allowed_commands`  | `commands.allow`                |
| `policy.add_allow_read`      | `filesystem.read`               |
| `policy.add_allow_write`     | `filesystem.write`              |
| `policy.add_allow_readwrite` | `filesystem.allow`              |
| `policy.add_deny_access`     | `filesystem.deny`               |
| `policy.add_deny_commands`   | `commands.deny`                 |
| `policy.override_deny`       | `filesystem.bypass_protection`  |
| `policy.exclude_groups`      | `groups.exclude`                |
| `--override-deny` (CLI)      | `--bypass-protection` (CLI)     |

Notes:
- The old `policy` key is no longer recognized as a top-level section. Its former fields now live directly under `filesystem`, `groups`, or `commands` as shown above.
- The CLI flag renamed from `--override-deny` to `--bypass-protection` for the same reason the JSON key was renamed: to make the "does not grant access" semantics explicit. The old flag remains as a deprecated alias until v1.0.0.
- When mechanically migrating a profile, move each `policy.*` entry up one level and rename per the table. Array values are preserved unchanged.
