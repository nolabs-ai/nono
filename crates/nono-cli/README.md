# nono-cli

CLI for capability-based sandboxing using Landlock (Linux) and Seatbelt (macOS).

## Installation

### Homebrew (macOS/Linux)

```bash
brew install nono
```

### Cargo

```bash
cargo install nono-cli
```

### From Source

```bash
git clone https://github.com/nolabs-ai/nono
cd nono
cargo build --release
```

## Usage

```bash
# Allow read+write to current directory
nono run --allow . -- command

# Separate read and write permissions
nono run --read ./src --write ./output -- cargo build

# Multiple paths
nono run --allow ./project-a --allow ./project-b -- command

# Block network access
nono run --allow-cwd --block-net -- command

# Use a pack profile (requires: nono pull always-further/claude)
nono run --profile always-further/claude -- claude

# Use a built-in profile
nono run --profile always-further/opencode -- opencode

# Keep a profile but temporarily allow unrestricted network
nono run --profile always-further/claude --allow-net -- claude

# Start an interactive shell inside the sandbox
nono shell --allow .

# Check why a path would be blocked
nono why --path ~/.ssh/id_rsa --op read

# Dry run (show what would be sandboxed)
nono run --allow-cwd --dry-run -- command
```

## Themes

The CLI supports named output themes for banners, summaries, warnings, and status text.

Available themes: `mocha`, `latte`, `frappe`, `macchiato`, `tokyo-night`, `minimal`

```bash
# Per invocation
nono --theme tokyo-night run --allow-cwd -- claude

# Environment variable
export NONO_THEME=latte

# Config file
# ~/.config/nono/config.toml
# [ui]
# theme = "frappe"
```

Precedence is: CLI flag, then `NONO_THEME`, then config file, then the default `mocha`.

## Profiles

### Pack profiles (install via `nono pull`)

| Profile | Install | Command |
|---------|---------|---------|
| Claude Code | `nono pull always-further/claude` | `nono run --profile always-further/claude -- claude` |
| Codex | `nono pull always-further/codex` | `nono run --profile always-further/codex -- codex` |

### Built-in profiles

| Profile | Command |
|---------|---------|
| OpenCode | `nono run --profile always-further/opencode -- opencode` |
| OpenClaw | `nono run --profile openclaw -- openclaw gateway` |
| Swival | `nono run --profile swival -- swival` |

## Profile Inheritance

User profiles can extend built-in, pack, or other user profiles with the `extends` field. The child inherits all settings from the base and only declares additions or overrides.

```json
{
  "extends": "claude-code",
  "meta": { "name": "my-claude" },
  "filesystem": {
    "allow": ["/opt/my-tools"],
    "read": ["/etc/my-app"]
  }
}
```

You can also extend multiple profiles at once. Bases are merged left-to-right, then the child overrides:

```json
{
  "extends": ["claude-code", "node-dev"],
  "meta": { "name": "my-fullstack" },
  "filesystem": { "allow": ["/opt/extra"] }
}
```

Save to `~/.config/nono/profiles/my-claude.json`, then:

```bash
nono run --profile my-claude -- claude
```

### Merge semantics

- **Lists** (filesystem paths, security groups, rollback patterns): appended and deduplicated
- **HashMaps** (credentials, hooks): merged, child wins on same key
- **Booleans** (`network.block`, `interactive`): OR — either activates
- **Scalars** (`meta`): child overrides
- **Nullable scalars** (`network_profile`): absent inherits, `null` clears, string overrides

When extending multiple bases, they are merged left-to-right using the same rules. The child then overrides the accumulated base.

### Chaining

Profiles can form chains (up to 10 levels deep). Circular dependencies are detected and rejected. Shared transitive bases are deduplicated.

```
my-dev.json → team-base.json → claude-code (pack)
```

## Network Modes

nono has three network modes. You pick one per run; they cannot be combined.

| Mode | CLI flag | Profile field | What it does |
|------|----------|---------------|--------------|
| **Unrestricted** | *(default)* | — | Child has full network access |
| **Blocked** | `--block-net` | `"network": { "block": true }` | All outbound connections denied |
| **Proxy-only** | `--allow-domain <host>` | `"network": { "allow_domain": [...] }` | Child may only reach the nono proxy; proxy enforces an allowlist |

### Localhost IPC ports

`open_port` and `open_port_range` punch loopback exceptions into an otherwise restricted network. They have no effect in unrestricted (AllowAll) mode.

**Single port — CLI or profile:**
```bash
nono run --allow-cwd --block-net --open-port 3000 -- my-agent
```
```json
{ "network": { "block": true, "open_port": [3000, 3001] } }
```

**Port range — profile only:**
```json
{ "network": { "block": true, "open_port_range": [[3000, 3100]] } }
```

Multiple ranges are supported: `[[3000, 3100], [49152, 49200]]`.

#### Platform behaviour

|  | macOS | Linux |
|--|-------|-------|
| **`open_port`** | One `(remote tcp "localhost:N")` Seatbelt rule per port. Bind/inbound become a blanket allow (Seatbelt cannot filter by port). | Block-net: individual Landlock rules per port. Proxy mode: seccomp supervisor enforces loopback-only for connect. |
| **`open_port = [0]`** (wildcard) | `(remote tcp "localhost:*")` — any loopback port. | Proxy mode only. Errors at startup in block-net mode. |
| **`open_port_range`** | Ranges ≤ 256 ports expand to individual rules. Ranges > 256 ports collapse to `localhost:*` with a warning. Bind/inbound become a blanket allow. | Expanded to individual Landlock rules. Works in both block-net and proxy mode. In proxy mode, connect is additionally loopback-only; bind is per-port (no blanket allow). |

### Proxy-only mode (`--allow-domain`)

Proxy mode starts a local nono proxy and restricts the child to that proxy only. The proxy enforces domain allowlists, injects credentials, and optionally inspects endpoints.

```bash
# Allow one external domain
nono run --allow-cwd --allow-domain api.openai.com -- my-agent
```

```json
{
  "network": {
    "allow_domain": ["api.openai.com", "registry.npmjs.org"],
    "open_port_range": [[3000, 3002]]
  }
}
```

When proxy mode is active, `open_port` and `open_port_range` add **localhost IPC exceptions** on top — the proxy itself is always reachable and the listed ports are additionally allowed for loopback communication.

For tools that bind to an OS-assigned ephemeral port (Testcontainers, Maven Surefire, etc.), use the wildcard:

```json
{
  "network": {
    "allow_domain": ["api.example.com"],
    "open_port": [0]
  }
}
```

`open_port: [0]` allows any loopback connect or bind without knowing the port in advance. External traffic is still restricted to the domain allowlist.

On Linux, proxy-only mode always uses seccomp-notify to mediate `connect()` and `bind()` calls, even on kernels with Landlock V4+ network support. This is intentional: Landlock TCP rules match by destination port only and cannot enforce the loopback-only invariant that proxy mode requires.

### Blocking external network while allowing localhost IPC

```json
{
  "network": {
    "block": true,
    "open_port": [6379, 6380]
  }
}
```

Works on both macOS and Linux, including port ranges:

```json
{
  "network": {
    "block": true,
    "open_port": [6379],
    "open_port_range": [[49152, 49200]]
  }
}
```

## Deprecated Command Blocking

Command blocking is deprecated in `v0.33.0`. It is only checked against the
directly-invoked startup command, not enforced for child processes, and should
not be treated as a sandbox security boundary.

Dangerous commands are still startup-blocked by default in `v0.33.x`:

| Category | Commands |
|----------|----------|
| File destruction | `rm`, `rmdir`, `shred`, `srm` |
| Disk operations | `dd`, `mkfs`, `fdisk`, `parted` |
| Permission changes | `chmod`, `chown`, `chgrp` |
| Privilege escalation | `sudo`, `su`, `doas` |

Compatibility overrides still exist temporarily:

```bash
# Per invocation
nono run --allow-cwd --allow-command rm -- rm ./temp-file.txt

# Via profile
cat > ~/.config/nono/profiles/my-profile.json << 'EOF'
{
  "meta": { "name": "my-profile" },
  "filesystem": { "allow": ["/tmp"] },
  "commands": { "allow": ["rm"] }
}
EOF
nono run --profile my-profile -- rm /tmp/old-file.txt
```

Prefer resource-based controls instead: narrower filesystem grants,
`filesystem.deny`, `unlink_protection`, and network policy.

## Documentation

- [Full Documentation](https://docs.nono.sh)
- [Client Guides](https://docs.nono.sh/cli/clients/quickstart)

## License

Apache-2.0
