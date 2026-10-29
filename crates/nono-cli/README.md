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

# Use a pack profile (requires: nono pull nolabs-ai/pi)
nono run --profile nolabs-ai/pi -- pi

# Run OpenCode 2 with its server in the sandbox
nono run --profile nolabs-ai/opencode -- opencode --standalone

# Keep a profile but temporarily allow unrestricted network
nono run --profile nolabs-ai/claude --allow-net -- claude

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
| Pi | `nono pull nolabs-ai/pi` | `nono run --profile nolabs-ai/pi -- pi` |
| Claude Code | `nono pull nolabs-ai/claude` | `nono run --profile nolabs-ai/claude -- claude` |
| Codex | `nono pull nolabs-ai/codex` | `nono run --profile nolabs-ai/codex -- codex --no-daemon --sandbox danger-full-access --ask-for-approval on-request` |
| OpenCode 2 | `nono pull nolabs-ai/opencode` | `nono run --profile nolabs-ai/opencode -- opencode --standalone` |
| OpenCode 1 | `nono pull nolabs-ai/opencode-v1` | `nono run --profile nolabs-ai/opencode-v1 -- opencode` |

### Pack profiles (continued)

| Profile | Command |
|---------|---------|
| OpenClaw | `nono run --profile nolabs-ai/openclaw -- openclaw gateway` |
| Swival | `nono run --profile jedisct1/swival -- swival` (officially maintained by Swival's creator) |

## Profile Inheritance

User profiles can extend built-in, pack, or other user profiles with the `extends` field. The child inherits all settings from the base and only declares additions or overrides.

```json
{
  "extends": "nolabs-ai/claude",
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
  "extends": ["nolabs-ai/claude", "node-dev"],
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
- **Booleans** (`network.block`): OR — either activates
- **Scalars** (`meta`): child overrides
- **Nullable scalars** (`network_profile`): absent inherits, `null` clears, string overrides

When extending multiple bases, they are merged left-to-right using the same rules. The child then overrides the accumulated base.

### Chaining

Profiles can form chains (up to 10 levels deep). Circular dependencies are detected and rejected. Shared transitive bases are deduplicated.

```
my-dev.json → team-base.json → nolabs-ai/claude (package)
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

Prefer filesystem, network, and command policies instead: narrower filesystem
grants, `filesystem.deny`, `unlink_protection`, and network policy.

## Documentation

- [Full Documentation](https://docs.nono.sh)
- [Client Guides](https://docs.nono.sh/cli/clients/quickstart)

## License

Apache-2.0
