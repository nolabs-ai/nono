# nono Profile Authoring Guide

This guide is designed for LLM agents helping users create custom nono profiles. It covers the full profile schema, common patterns, and validation workflow.

## 1. Profile File Location

User profiles live at `~/.config/nono/profiles/<name>.json`.

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
- Scalar fields: child overrides base.
- Array fields (`groups.include`, `groups.exclude`, `commands.allow`, `commands.deny`, `filesystem.*`, `allow_domain`, `open_port`, `listen_port`, `rollback.*`, `upstream_bypass`): child values are appended to base values and deduplicated. To remove inherited entries, use `groups.exclude` for groups; there is no mechanism to remove inherited filesystem paths.
- Map fields (`env_credentials`, `hooks`, `custom_credentials`): child entries are merged into base; child keys override matching base keys.
- `network_profile` supports three-state inheritance via `InheritableValue`: absent = inherit base value, `null` = explicitly clear, string = override. This is the only field that supports null-clearing.
- `open_urls`: if the child provides the field (even as `{}`), it replaces the base entirely. If absent, the base value is inherited. Setting to `null` in JSON is equivalent to omitting it (both inherit the base).
- `workdir`: child overrides base unless child is `"none"` (which inherits the base value instead).

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

All path fields support variable expansion (see Section 6).

### workdir

| Field    | Type   | Default  | Description |
|----------|--------|----------|-------------|
| `access` | string | `"none"` | One of: `"none"`, `"read"`, `"write"`, `"readwrite"`. Controls automatic CWD sharing with the sandboxed process. |

### network

| Field                   | Type                              | Default  | Description |
|-------------------------|-----------------------------------|----------|-------------|
| `block`                 | boolean                           | `false`  | Block all network access. |
| `network_profile`       | string or null                    | inherit  | Name from `network-policy.json` for proxy filtering. Set to `null` to clear inherited value. |
| `allow_domain`          | array of string                   | `[]`     | Additional domains to allow through the proxy. Aliases: `proxy_allow`, `allow_proxy`. |
| `credentials`           | array of string                   | `[]`     | Credential services to enable via reverse proxy. Alias: `proxy_credentials`. |
| `open_port`             | array of integer                  | `[]`     | Localhost TCP ports for bidirectional IPC. Aliases: `port_allow`, `allow_port`. |
| `listen_port`           | array of integer                  | `[]`     | TCP ports the sandboxed child may listen on. |
| `custom_credentials`    | map of string to credential def   | `{}`     | Custom credential route definitions (see below). |
| `upstream_proxy`        | string                            | `null`   | Enterprise proxy address (`host:port`). Alias: `external_proxy`. |
| `upstream_bypass`       | array of string                   | `[]`     | Hosts to bypass the upstream proxy. Supports `*.` wildcard suffixes. Alias: `external_proxy_bypass`. |

#### custom_credentials entry

Define a custom reverse proxy credential route for services not in `network-policy.json`:

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
| `credential_key`    | string          | yes         | Keystore account name, `op://` URI, `apple-password://` URI, or `file://` URI. |
| `inject_mode`       | string          | no          | One of: `"header"` (default), `"url_path"`, `"query_param"`, `"basic_auth"`. |
| `inject_header`     | string          | header mode | HTTP header name. Default: `"Authorization"`. |
| `credential_format` | string          | header mode | Format string with `{}` placeholder. Default: `"Bearer {}"`. |
| `path_pattern`      | string          | url_path    | Pattern to match in URL path. Use `{}` for placeholder. |
| `path_replacement`  | string          | url_path    | Replacement pattern. Defaults to `path_pattern`. |
| `query_param_name`  | string          | query_param | Query parameter name for credential injection. |
| `proxy`             | object          | no          | Optional proxy-side overrides for phantom token parsing. Omitted fields inherit from top-level values. |
| `env_var`           | string          | URI keys    | Environment variable name for SDK API key. Required when `credential_key` is a URI. |
| `endpoint_rules`    | array           | no          | L7 allow-list of `{"method": "GET", "path": "/**"}` rules. When non-empty, only matching requests are forwarded (default-deny). |
| `tls_ca`            | string (path)   | no          | Path to a PEM-encoded CA certificate. Use for upstreams with self-signed or private CA certs (e.g. a Kubernetes API server). |
| `tls_client_cert`   | string (path)   | no          | Path to a PEM-encoded client certificate for mutual TLS (mTLS). Must be set together with `tls_client_key`. |
| `tls_client_key`    | string (path)   | no          | Path to the PEM-encoded private key matching `tls_client_cert`. |

`proxy` overrides apply only to how the local proxy validates incoming phantom tokens from the sandboxed process. Outbound upstream credential injection continues to use top-level fields.

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

Controls which environment variables are passed to the sandboxed process. When `allow_vars` is set, only the listed variables (and nono-injected credentials) are passed through.

```json
{
  "environment": {
    "allow_vars": ["PATH", "HOME", "TERM", "AWS_*"]
  }
}
```

| Field         | Type            | Default | Description |
|---------------|-----------------|---------|-------------|
| `allow_vars`  | array of string | `[]`    | Allow-list of environment variable names. Supports exact names (`"PATH"`) and prefix patterns ending with `*` (`"AWS_*"` matches `AWS_REGION`, `AWS_SECRET_ACCESS_KEY`, etc.). The `*` wildcard is only valid as a trailing suffix. When the `environment` section is omitted entirely, all variables are allowed. When present with an empty array, no inherited variables are passed (only nono-injected credentials). Nono-injected credentials always bypass this list. |

Inheritance: child `allow_vars` are appended to base values and deduplicated.

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

Use `filesystem.deny` to prevent an agent from reaching the Docker daemon or similar container runtimes. `commands.deny` is deprecated startup-only gating and should not be relied on as enforcement:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "no-docker",
    "description": "Claude Code without Docker access"
  },
  "filesystem": {
    "deny": ["/var/run/docker.sock"]
  },
  "commands": {
    "deny": ["docker", "docker-compose", "podman", "kubectl"]
  }
}
```

On macOS, `filesystem.deny` on a socket path also emits a Seatbelt `network-outbound` deny — Seatbelt treats `connect(2)` as a network operation so a file deny alone won't block it. Prefer path- and network-based controls; `commands.deny` remains as deprecated startup-only compatibility behavior and is visible in `nono profile show` under the commands section.

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

The following variables are expanded in all path fields (`filesystem.*`, including `filesystem.allow`, `filesystem.read`, `filesystem.write`, `filesystem.deny`, and `filesystem.bypass_protection`).

| Variable           | Expands to |
|--------------------|------------|
| `$HOME`            | User's home directory |
| `$WORKDIR`         | Working directory (from `--workdir` flag or cwd) |
| `$TMPDIR`          | System temporary directory |
| `$UID`             | Current user ID |
| `$XDG_CONFIG_HOME` | XDG config directory (default: `$HOME/.config`) |
| `$XDG_DATA_HOME`   | XDG data directory (default: `$HOME/.local/share`) |
| `$XDG_STATE_HOME`  | XDG state directory (default: `$HOME/.local/state`) |
| `$XDG_CACHE_HOME`  | XDG cache directory (default: `$HOME/.cache`) |
| `$XDG_RUNTIME_DIR` | XDG runtime directory (no default; left unexpanded when unset) |

Always use these variables instead of hardcoded absolute paths to keep profiles portable across machines and users.

## 7. Key Rules

- A profile with no `groups.include` has no deny rules. Always include appropriate deny groups for untrusted workloads.
- `filesystem.bypass_protection` only removes the deny rule. It does not grant access. You must also add the path via `filesystem.allow`, `filesystem.read`, or `filesystem.write` (or the matching `*_file` variant).
- `groups.exclude` removes groups from the resolved set. This weakens the sandbox. Use it only when you understand which protections you are removing.
- `extends` chains resolve recursively up to depth 10. Circular inheritance is an error.
- Platform-specific groups (suffix `_macos` or `_linux`) are filtered at resolution time. Include both variants for cross-platform profiles.
- `network.block: true` blocks all network access. It cannot be combined with proxy settings.
- `custom_credentials` upstream URLs must use HTTPS. HTTP is only accepted for loopback addresses (localhost, 127.0.0.1, ::1).

## 8. Migration from previous schema

Issue [#594](https://github.com/always-further/nono/issues/594) restructured the profile JSON schema. The old `policy.*` namespace has been dissolved into `filesystem`, `groups`, and `commands`; `security.groups` and `security.allowed_commands` have moved to top-level `groups.include` and `commands.allow`.

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
