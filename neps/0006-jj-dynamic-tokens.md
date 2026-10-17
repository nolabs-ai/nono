---
nep: 0006
title: "`@jj:*` dynamic tokens for Jujutsu workspaces"
authors:
  - Romain Marcadier
status: draft
created: 2026-10-16
superseded-by:
---

# NEP-0006: `@jj:*` dynamic tokens for Jujutsu workspaces

## Summary

Add a `@jj:*` dynamic-token provider to `nono-cli`, next to the existing
`@git:*` provider. The tokens resolve the paths that the
[Jujutsu (`jj`)](https://docs.jj-vcs.dev/latest/) version control system
needs outside the current workspace: the shared repository directory, the
Git backend directory, and the configuration directories.

Each token resolves with filesystem reads only (nono never starts `jj`).
Each pointer that the resolver follows is untrusted. The resolver grants a
path only after a structural or backlink check, and grants write access only
if the agent can already write the workspace that the check authenticated.
If a check fails, the token expands to no paths.

Tracking issue: [#2076](https://github.com/nolabs-ai/nono/issues/2076).

## Motivation

Jujutsu is a Git-compatible version control system. It is often used with
AI coding agents, because its
[workspaces](https://docs.jj-vcs.dev/latest/working-copy/#workspaces)
(similar to `git worktree`) let several agents work on one repository at the
same time, each agent in its own working copy.

A sandboxed agent that starts in a non-default jj workspace cannot use `jj`
correctly today:

- **The repository data is outside the workspace.** In a non-default
  workspace, `<workspace>/.jj/repo` is a *file*. It contains the path of the
  repository directory of the default workspace (for example
  `../../main/.jj/repo`). All jj operations (`jj describe`, `jj new`,
  `jj git fetch`, ...) write to that directory, which is outside `$WORKDIR`.
- **The Git backend is outside the workspace.** In a
  [colocated repository](https://docs.jj-vcs.dev/latest/git-compatibility/#colocated-jujutsugit-repos),
  `<repo>/store/git_target` points to the `.git` directory of the default
  workspace. `jj git fetch` and `jj git push` start a `git` subprocess that
  needs that directory.
- **Repository and workspace configuration is outside the repository.**
  Since jj v0.38, jj keeps this configuration out of the repository for
  security reasons (see
  [Secure config](https://docs.jj-vcs.dev/latest/design/secure-config/)).
  It is in `<jj config dir>/repos/<config-id>/` and
  `<jj config dir>/workspaces/<config-id>/`. The `<config-id>` values come
  from `<repo>/config-id` and `<workspace>/.jj/workspace-config-id`.

The `@git:*` tokens do not cover these paths. A non-default workspace that
is not also a Git worktree has no `.git` entry. This is true for all
workspaces before jj v0.46, and for non-colocated workspaces since then.
In these workspaces, `@git:common-dir` and the related tokens resolve to
nothing, or to an unrelated Git repository in a parent directory.

The only workaround today is to put absolute paths in a user profile, for
each repository and for each workspace. That is not portable, and a shipped
profile cannot use it.

A maintainer asked for a NEP
([comment on #2076](https://github.com/nolabs-ai/nono/issues/2076#issuecomment-6059921805)).
A NEP is necessary because the proposal changes enforcement semantics: it
widens filesystem grants from pointers that the agent controls.

### Goals

- Let a profile or a command sandbox policy give `jj` the access that it
  needs in default and non-default workspaces, without absolute paths.
- Use the tokens in profile `filesystem.*` grant lists and in command
  sandbox `fs_*` lists, the same as the `@git:*` tokens.
- Never start `jj` (or any other process) to resolve a token.
- Never give write access to a path only because an agent-writable file
  names it.
- Never give a mediated `jj` command write access to a repository when the
  agent itself cannot write the authenticated workspace.
- The `@jj:*` tokens never add write access to jj secure configuration.
- Give the same results when a jj workspace is also a Git worktree
  (jj v0.46 `jj workspace add --colocate`).
- Fail closed: in a grant list, a token that cannot be resolved safely
  expands to no paths. In a list where an empty expansion is not safe
  (for example a deny list), the token is a profile error.

### Non-Goals

- No new policy in the `nono` library. The library can need one small
  mechanism (an identity check when a rule is installed, see
  [TOCTOU](#path-handling-symbolic-links-and-toctou)); the policy that
  uses it stays in `nono-cli`.
- No change to the `@git:*` tokens. Changes to them are open questions (see
  [Open Questions](#open-questions)); they are not part of this proposal.
- No support for a Git backend that is outside the default workspace (a
  repository made with `jj git init --git-repo=<path>`), or for a `.git`
  that is a symbolic link (for example the `repo` tool). These setups must
  use a literal path in the profile.
- No support for non-Git jj backends beyond `@jj:repo-dir` (for example the
  test backends, or Google's internal backend).
- No grant for the Watchman socket (`fsmonitor.backend = "watchman"`). This
  can be a separate token later.
- No change to a shipped profile in the first version. A shipped `jj`
  command policy can be a follow-up after the tokens are available.
- No Windows support. The tool sandbox and the `@git:*` tokens are Linux and
  macOS only today.

## Proposal

### Token set

| Token | Allowed list kinds | Resolves to |
|---|---|---|
| `@jj:workspace-root` | read, write | The current workspace root `W`. See [`@jj:workspace-root`](#jjworkspace-root). |
| `@jj:workspace-root-parent` | read, write | The parent directory of `W`. Necessary for `jj workspace add ../sibling`. |
| `@jj:repo-dir` | read, write | The repository directory `R`. See [`@jj:repo-dir`](#jjrepo-dir). **This is the main token.** |
| `@jj:git-dir` | read, write | The Git backend directory `G`. See [`@jj:git-dir`](#jjgit-dir). Empty for a non-Git backend. |
| `@jj:default-workspace` | read | The root of the default workspace (the workspace that physically contains `R`). Unlike `@git:worktree`, it is not empty in the default workspace: there it is `W`. |
| `@jj:config-files` | read-file | jj system and user configuration files. See [Configuration tokens](#configuration-tokens). |
| `@jj:config-dirs` | read | jj system and user configuration directories (`conf.d`, and directory entries of `$JJ_CONFIG`). |
| `@jj:repo-config` | read | `<C>/repos/<config-id>/` of the current repository. |
| `@jj:workspace-config` | read | `<C>/workspaces/<config-id>/` of the current workspace. |

The list kinds are:

- **read:** `filesystem.read` and `fs_read`.
- **read-file:** `filesystem.read_file` and `fs_read_file`.
- **write:** `filesystem.allow`, `filesystem.write`, `fs_write`, and their
  `*_file` variants.

See [List kinds](#list-kinds) for the lists where no `@jj:*` token is
allowed.

Example command sandbox policy:

```json
{
  "command_policies": {
    "commands": {
      "jj": {
        "sandbox": {
          "fs_read_file": ["@jj:config-files"],
          "fs_read": [
            "@jj:config-dirs",
            "@jj:repo-config",
            "@jj:workspace-config"
          ],
          "fs_write": ["$WORKDIR", "@jj:repo-dir", "@jj:git-dir"]
        }
      }
    }
  }
}
```

### Delivery phases

1. **Phase 1:** `@jj:workspace-root`, `@jj:workspace-root-parent`,
   `@jj:repo-dir`, `@jj:git-dir`, `@jj:default-workspace`, the list-kind
   checks, the write non-escalation rule, and the TOCTOU checks. These are
   enough for `jj` operations in a non-default workspace, when the user also
   grants the configuration paths with literal paths.
2. **Phase 2:** `@jj:config-files`, `@jj:config-dirs`, `@jj:repo-config`,
   `@jj:workspace-config`. These need the `secure_config` metadata check.

Each phase is one PR with code, tests, and documentation.

### Where the code goes

All resolution code is in `nono-cli`:

- A new `jj` module in
  `crates/nono-cli/src/tool-sandbox/dynamic_providers.rs` (or a sibling
  file), next to the `git` module.
- A new `"jj"` arm in `dispatch_token`. An unknown `@jj:<query>` is a
  `NonoError::ProfileParse` error, the same as an unknown `@git:<query>`.

`expand_dynamic_tokens` already runs for these lists, so the tokens are
seen everywhere the `@git:*` tokens are seen:

- the profile lists `filesystem.allow`, `read`, `write`, `allow_file`,
  `read_file`, `write_file`, `deny`, and `bypass_protection`
  (`capability_ext.rs`); and
- the command sandbox lists `fs_read`, `fs_read_file`, `fs_write`,
  `fs_write_file`, `unix_socket_bind`, and `exec_paths`
  (`tool-sandbox/platform/linux.rs` and `macos.rs`).

The call sites change: each one passes the kind of its list to
`expand_dynamic_tokens` (see [List kinds](#list-kinds)). The command sandbox
`write_access` rule in `add_policy_fs` also changes (see
[Write non-escalation](#write-non-escalation)).

### Typed expansion output

Today `expand_dynamic_tokens` returns `Vec<String>`, and token outputs are
mixed with literal entries. With that type, the call sites cannot apply the
rules of this NEP: they cannot know which paths come from a `@jj:*` token,
which workspace authenticated them, or which identity the resolver checked.
They also apply `$VAR`, `~`, and glob expansion to all entries.

The return type changes to a typed entry, for example:

```rust
enum ExpandedEntry {
    /// A literal profile entry. Expanded as today.
    Literal(String),
    /// A canonical path from a dynamic token. Never expanded again.
    Resolved {
        path: PathBuf,
        /// The workspace that the backlink check authenticated, if any.
        authenticated_root: Option<PathBuf>,
        /// (device, inode) at check time.
        identity: (u64, u64),
    },
}
```

`resolve_policy_path`, the `write_access` closures in
`tool-sandbox/platform/{linux,macos}.rs`, and `add_fs_paths` in
`capability_ext.rs` use this type. `@git:*` tokens can keep the current
behavior with `Literal`, until Open Question 2 is decided.

On a target that is not Linux or macOS, the `capability_ext.rs` fallback
returns the entries without expansion. A `@jj:*` entry then becomes a
literal path that does not exist, so it grants nothing. This is the same
as for `@git:*` today. The documentation must say this.

### List kinds

`expand_dynamic_tokens` gets a new argument, for example:

```rust
enum TokenList { Read, ReadFile, Write, WriteFile, Deny, Bypass, Exec, Socket }
```

Each `@jj:*` token has a fixed set of allowed list kinds (the table in
[Token set](#token-set)). A token in a list kind that is not allowed is a
`NonoError::ProfileParse` error. In particular:

- **All `@jj:*` tokens are rejected in `Deny`.** An empty expansion in a
  deny list removes a denial. That is fail-open.
- **All `@jj:*` tokens are rejected in `Bypass`, `Exec`, and `Socket`.** An
  agent-influenced path in these lists gives more than filesystem access
  (protection bypass, execute permission on agent-writable files, socket
  `bind`). No use case needs them.
- **The configuration tokens are rejected in `Write` and `WriteFile`.**

The `@git:*` tokens keep their current behavior. Whether they must get
list-kind checks too is an open question.

### Resolution rules for all tokens

These rules apply to every step below:

1. **No process.** The resolver uses only filesystem calls and the
   environment of the nono supervisor process. It never uses the
   environment of the calling agent.
2. **Safe reads.** Each file that the resolver reads is opened with
   `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`. The resolver checks with `fstat`
   that it is a regular file, and reads at most a fixed limit (for example
   4 KiB for a pointer file, 1 MiB for the workspace store). If the file is
   a symbolic link, a FIFO, a device, larger than the limit, or not valid,
   the check fails. This prevents a hang of the supervisor, and reads of
   arbitrary host files through a symbolic link.
3. **No canonicalization of agent-writable anchors.** The resolver never
   compares a candidate against the canonical path of a directory that the
   agent can change (for example `R/store`). It canonicalizes a trusted
   anchor once, then joins fixed names to it, and checks each joined
   component with `symlink_metadata` (it must be a real directory, not a
   symbolic link).
4. **Component comparison.** All path comparisons use `Path` component
   comparison, never string prefixes.
5. **Literal output.** The resolver returns canonical absolute paths. The
   call sites use these paths as literal paths: no `$VAR`, `~`, or glob
   expansion on the output. A directory name that the agent created (for
   example one that contains `*` or `$`) is thus not read as a template.
6. **Non-UTF-8.** A path that is not valid UTF-8 (for example a `bytes`
   path from a protobuf) expands to no paths.
7. **Final checks.** After the full capability set is assembled (in the
   same pass as the [configuration check](#configuration-tokens)), each
   output is checked against the resolved deny paths and the protected
   roots. An output that is equal to, or under, a deny path or a protected
   root is dropped (no error, no grant). The check runs on the final set
   because the profile `filesystem.deny` list is expanded after the grant
   lists. A deny path *inside* an output (for example inside `R`) cannot be
   enforced on Linux (Landlock is allow-list only).

### Resolution algorithm

#### `@jj:workspace-root`

1. Start at `workdir` (or the live command cwd).
2. Walk up to the first ancestor (inclusive) that contains a `.jj` entry
   that is a real directory (by `symlink_metadata`). A `.jj` symbolic link
   does not mark a workspace root. This is a deliberate difference from
   `jj`, which follows the link. Such setups must use a literal path.
3. Canonicalize the ancestor to get `W`.
4. Expand to no paths if `W` is a sensitive root (`/`, `$HOME`, or the
   other paths that `is_sensitive_root` rejects). For example, a jj
   repository for dotfiles in `$HOME` must not make `@jj:workspace-root`
   equal `$HOME`.
5. In the command sandbox, also expand to no paths if the agent cannot
   access `W` by the same rule as `admit_command_cwd`: `W` is not under a
   deny path, and `W` is under `policy_root` or
   `caps_grant(outer_caps, W, Read)` is true. `W` can be above the starting
   directory, and thus outside the agent's granted filesystem.

#### `@jj:repo-dir`

Let `P` = `W/.jj/repo`.

1. **Default workspace.** If `P` is a real directory (by
   `symlink_metadata`), `R` = `P`. Because `W` is canonical and `.jj` and
   `repo` are real directories, `R` is inside `W`. Also check that `R` and
   `W` are on the same device (`st_dev`), so that a mount point cannot
   replace it.
2. **Non-default workspace.** If `P` is a regular file, read it with the
   safe-read rule. The content is a path. If it is relative, join it to
   `W/.jj`. Canonicalize it to get the candidate `R`.
3. **Store type.** Read `R/workspace_store/type`. The content must be
   exactly `simple_workspace_store` (no trim, the same as jj). A missing
   file expands to no paths. jj ≥ v0.38 writes it on the next host-side
   `jj` command.
4. **Backlink check.** Read `R/workspace_store/index` (a
   [`simple_workspace_store.Workspaces`](https://github.com/jj-vcs/jj/blob/main/lib/src/protos/simple_workspace_store.proto)
   protobuf). Limit the number of entries (for example 1024). For each
   entry:
   - Compute the path the same way as jj: `normalize_path(R.join(path))`
     (lexical normalization).
   - The entry matches only if this lexical path is equal to `W`, **and**
     no component of it is a symbolic link, **and** its canonical path is
     also `W`.

   Accept `R` only if at least one entry matches.
5. In all other cases (no `.jj/repo`, a symbolic link, a read or decode
   error, no matching entry), expand to no paths.

Without step 4, an agent can write any path (for example `~/.ssh`) into
`.jj/repo`, and get write access to it the next time the token resolves.
With step 4, the target directory must list the workspace. The lexical and
"no symbolic link" rules stop an entry that goes through an
agent-controlled symbolic link from matching any `W`.

#### Write non-escalation

The backlink check proves that `R` belongs to `W`. It does not prove that
the agent is allowed to change `R`. In the command sandbox, the agent can
`cd` into any directory that it can *read*, and start `jj` there. Today,
`add_policy_fs` downgrades a write grant to read only for paths *under the
cwd*. `R` and `G` are outside the cwd in a non-default workspace, so they
stay writable. Without a new rule, an agent with read-only access to a
different project can get write access to that project's `.jj/repo` and
`.git` (and its hooks).

The new rule:

- In the command sandbox, a `@jj:*` output in a write list gets write
  access only if `agent_can_write(W, policy_root, outer_caps, deny_paths)`
  is true. Otherwise, it is downgraded to read.
- For `@jj:workspace-root-parent`, the check is on the parent itself:
  `agent_can_write(parent of W, ...)`. Otherwise an agent that can write
  `W` gets write access to every sibling directory of `W`, and to the
  `.jj/repo` and `.git` of each sibling repository.
- For a profile `filesystem.*` list, the starting directory is the
  `--workdir` that the user selected, and the agent is not running yet. The
  rule is the same as for `@git:*` today: the user's choice of workdir
  selects the workspace.

A usability limit: if `$WORKDIR` is a subdirectory of `W`, and the agent
can write only `$WORKDIR`, then `agent_can_write(W)` is false and
`@jj:repo-dir` is read-only. The user must grant write access to `W`.

A mediated `jj` runs code that the agent selects (for example
`jj util exec`, or `jj --config ui.diff-formatter=[...]`). Thus, each grant
to the `jj` command sandbox is a grant to the agent. The rule above is
necessary for this reason.

#### `@jj:default-workspace`

Derived from `R` by structure, not by the content of the workspace store:

- If the canonical `R` has the shape `<D>/.jj/repo` (the file name is
  `repo` and the parent file name is `.jj`), return `<D>`.
- Otherwise, expand to no paths.

The workspace store also records a `default` entry, but the agent can write
that file (it is in `R`). The resolver does not use it.

#### `@jj:git-dir`

1. Resolve `R` as for `@jj:repo-dir`. If that fails, expand to no paths.
2. Let `S` = `R.join("store")`. `S` must be a real directory (by
   `symlink_metadata`) on the same device as `R`. Do **not** canonicalize
   `S`: the agent can write `R`, and can replace `store` with a symbolic
   link to the store of a different repository.
3. Read `S/type` (safe read). If the content is not `git`, expand to no
   paths.
4. Read `S/git_target` (safe read). If the path is relative, join it to `S`.
   Canonicalize it to get `G`.
5. Accept `G` only if one of these is true:
   - **Internal Git backend:** `G` is a descendant of `S` by component
     comparison, and each component between `S` and `G` is a real
     directory (no symbolic link).
   - **Colocated repository:** `R` has the shape `<D>/.jj/repo`, and
     `<D>/.git` is a real directory (by `symlink_metadata`) on the same
     device as `<D>`, and `G` is equal to `<D>/.git`.
6. In all other cases, expand to no paths.

The check is by **structure**, not by content. The resolver does not accept
a directory only because it "looks like a Git repository". If it did, an
agent with write access to `R` could point `git_target` at an unrelated
repository on the host, and get write access to it.

A `<D>/.git` symbolic link is rejected. If the agent can write `<D>` (for
example, when `$WORKDIR` is the default workspace), it could replace `.git`
with a symbolic link to an unrelated repository.

This is stricter than the first draft in
[#2076](https://github.com/nolabs-ai/nono/issues/2076). That draft took the
default workspace root from the workspace store, which the agent can write.
This NEP takes it from the shape of `R`.

#### `@jj:workspace-root-parent`

The parent directory of `W`, the same as `@git:toplevel-parent`. Empty if
`W` has no parent, or if the parent is a sensitive root. The write
non-escalation rule applies.

#### Configuration tokens

jj finds its configuration directory with the
[`etcetera`](https://crates.io/crates/etcetera) XDG strategy, on Linux and
on macOS: an absolute `$XDG_CONFIG_HOME`, or else `~/.config`. An empty or
relative `$XDG_CONFIG_HOME` is ignored. Let `C` be `<that directory>/jj`.
`$JJ_CONFIG` does not change `C`. nono uses the same rule, with the
environment of the supervisor process.

The jj child process can get a different `$XDG_CONFIG_HOME` or `$JJ_CONFIG`
from the agent environment. Then the grants can be wrong for the child.
This is a usability limit, not a security problem: the grants are read-only
and come from the supervisor environment.

- **`@jj:config-files` and `@jj:config-dirs`:**
  - System configuration (Unix, if `$JJ_CONFIG` is not set):
    `/etc/jj/config.toml` and `/etc/jj/conf.d`, if they exist.
  - User configuration: if `$JJ_CONFIG` is set, its entries (split like
    `PATH`, empty entries removed). Otherwise `~/.jjconfig.toml` if it
    exists, `C/config.toml`, and `C/conf.d` if it exists.
  - Files go to `@jj:config-files`, directories to `@jj:config-dirs`. The
    split is the same as for `@git:config-files` and `@git:hooks-path`:
    `fs_read` needs directories, and `fs_read_file` needs files.
- **`@jj:repo-config`:**
  1. Read `R/config-id` (safe read). It must be exactly 20 hexadecimal
     characters (the jj format, `CONFIG_ID_BYTES = 10`).
  2. Let `K` = `C/repos/<config-id>`. `C/repos` and `K` must be real
     directories.
  3. Read `K/metadata.binpb` (safe read), a
     [`secure_config.ConfigMetadata`](https://github.com/jj-vcs/jj/blob/main/lib/src/protos/secure_config.proto)
     protobuf.
  4. Return `K` only if its `path` field is byte-for-byte equal to `R`. jj
     compares the stored value with its own canonical path, so nono does
     not canonicalize the stored value.
- **`@jj:workspace-config`:** the same, with `W/.jj/workspace-config-id`,
  `C/workspaces/<config-id>`, and a `path` equal to `W/.jj`.

The agent can write `config-id` (it is in `R`) and `workspace-config-id`
(it is in the workspace). The `metadata.binpb` check stops the agent from
selecting the configuration of a different repository.

The `metadata.binpb` check is useful only if the agent cannot write
`metadata.binpb`. Thus, after the full capability set is assembled, a
validation pass checks the profile set, or, in the command sandbox, both
the agent's `outer_caps` and the final command set (the agent can forge
the file from outside the `jj` sandbox). It checks `C`, `C/repos`, `C/workspaces`, `K`, and
`K/metadata.binpb`. If one of them is writable, the configuration token
paths are removed and nono shows a warning. The check runs on the final set
because the profile lists are processed in order (`allow`, `read`, `write`,
then the `*_file` lists, then CLI flags), so a check during expansion can
miss a later grant.

### First run and setup

The jj source (`lib/src/secure_config.rs`) shows how jj behaves with
read-only access to `C`:

- If there is no `config-id` and no legacy configuration, jj loads no
  repository configuration and writes nothing. This works.
- jj writes to `C` in these cases:
  1. migration of a legacy `<repo>/config.toml`;
  2. `config-id` exists but `metadata.binpb` does not;
  3. the metadata path is different (the repository was moved or copied);
  4. commands that edit repository configuration (`jj config set --repo`,
     `jj config edit --repo`, `jj git init` or `jj git clone` with
     presets).

  With read-only access, these fail with an error.

The documentation tells users to run `jj config path --repo` and
`jj config path --workspace` once on the host, outside the sandbox, for
cases 2 and 3.

### Protobuf decoding

The two messages contain only `string`, `bytes`, `optional bytes`, and
`repeated` message fields. Two implementation choices are possible:

- Use `prost`. `prost` 0.14 and `prost-derive` are already in the
  `nono-cli` dependency graph (through `nono-proxy` → `spiffe`), so a
  direct dependency adds no new crate. The message types are written by
  hand with `#[derive(Message)]`, so no build-time `protoc` step is
  necessary.
- Write a small decoder for the wire format (varint tags, length-delimited
  fields only).

Both must reject malformed input, oversized fields, and duplicate singular
fields (with `prost`, the last value wins, so this needs a custom check),
enforce
the size and entry limits, ignore unknown fields, and decode `bytes` paths
with `OsStr::from_bytes`. The implementation PR makes this choice.

### Platform behavior

The token resolver is the same code on Linux and macOS. It produces
canonical paths. The existing tool sandbox code turns them into
capabilities:

- **Linux (Landlock):** each path becomes an allow-list rule. Landlock
  cannot deny a path inside an allowed path. This NEP does not depend on a
  deny-within-allow rule. Thus, any file inside `R` or `G` is writable when
  the token is in a write list and the write non-escalation rule allows it.
  See [Residual exposure](#residual-exposure).
- **macOS (Seatbelt):** each path becomes a rule on its canonical path.
  Seatbelt can express deny-within-allow, but this NEP does not add a jj
  specific deny rule. Thus the two platforms give the same access.

### Backward compatibility

The tokens are new and opt-in. A profile that does not use a `@jj:*` token
is not affected. Today, `@jj:<anything>` is an "unknown dynamic-token
provider" error on Linux and macOS, so no existing valid profile can change
meaning.

An older nono that reads a profile with a `@jj:*` token fails with that same
error. This fails closed.

The `write_access` change in `add_policy_fs` applies only to `@jj:*`
outputs, so existing `@git:*` and literal grants do not change.

### Documentation

The implementation PRs update:

- `docs/cli/features/tool-sandbox.mdx` (token table, resolution notes,
  first-run setup);
- `crates/nono-cli/data/profile-authoring-guide.md`;
- `docs/cli/internals/security-model.mdx`, with the residual exposure given
  below; and
- `CHANGELOG.md`.

### Tests

Unit tests in `dynamic_providers.rs`, and tool sandbox tests in
`platform/linux.rs` and `platform/macos.rs`, run on Linux and on macOS:

- default workspace, and a subdirectory of a workspace;
- non-default workspace with a relative and with an absolute `.jj/repo`
  pointer;
- colocated and non-colocated Git store, and a non-Git store type;
- a jj v0.46 workspace that is also a Git worktree, with `@jj:*` and `@git:*`
  tokens that resolve to the same directories;
- forged pointers: `.jj/repo` to an unrelated directory, a `git_target` to
  an unrelated Git repository, `R/store` replaced by a symbolic link to a
  different store, a `config-id` of a different repository, a `config-id`
  with path characters, a forged `default` workspace store entry, and a
  workspace store entry that goes through a symbolic link;
- `.jj`, `.jj/repo`, and `<D>/.git` as symbolic links;
- pointer files that are FIFOs, symbolic links, or larger than the limit;
- a workspace that is not in the workspace store, and a missing
  `workspace_store/type`;
- truncated, oversized, malformed, and non-UTF-8 protobuf content;
- each `@jj:*` token in each list kind (allowed or rejected);
- an agent-writable `C` or `metadata.binpb`, also when the write grant comes
  later in the profile or from a CLI flag (configuration paths removed);
- write non-escalation: the agent `cd`s into a workspace that it can only
  read, and `@jj:repo-dir` and `@jj:git-dir` are downgraded to read; and
  an agent that can write `W` but not its parent gets
  `@jj:workspace-root-parent` as read-only;
- token outputs that contain `*`, `$`, or `~` are not expanded again;
- `W` equal to `$HOME`, and `W` outside the agent's read grants;
- a deny path that covers `@jj:default-workspace` (dropped);
- a path component replaced between the check and the `FsCapability`
  creation (grant dropped);
- a check that no `jj` process starts during resolution (the same
  "spawn sentinel" pattern that the `@git:*` tests use).

## Security Considerations

### Least privilege

The tokens let a sandboxed process write outside `$WORKDIR`, but only to:

- the repository directory of the current workspace, after a backlink
  check;
- the Git backend directory of that repository, after a structural check;
  and
- the parent of the current workspace root, when the profile asks for
  `@jj:workspace-root-parent`.

In the command sandbox, these write grants apply only if the agent can
already write the authenticated workspace `W` (or, for
`@jj:workspace-root-parent`, the parent itself). Otherwise they are
read-only.

Write access to the parent of `W` is broad: it includes every sibling
directory, and the `.jj/repo` and `.git` of each sibling repository. In a
profile `filesystem.*` list (where no agent-write check applies), the
profile author grants this on purpose. `@git:toplevel-parent` has the same
exposure today.

The configuration tokens give read access only, and only to the
configuration that jj itself associates with the repository or the
workspace.

All outputs are checked against deny paths and protected roots. The tokens
are opt-in: a profile author must add each token to a list.

### Trust in pointer files

The workspace directory is under the agent's control. After a first grant,
the repository directory is also under the agent's control. The resolver
thus treats these files as untrusted:

| File | Who can write it | How the resolver uses it |
|---|---|---|
| `<workspace>/.jj/repo` | agent | Candidate path only. Needs the backlink check. |
| `<repo>/workspace_store/{type,index}` | agent, after a grant | Backlink check only. Never a source of a new path to grant. |
| `<repo>/store` (the directory itself) | agent, after a grant | Fixed anchor. Must be a real directory. Never canonicalized. |
| `<repo>/store/type`, `<repo>/store/git_target` | agent, after a grant | Candidate path only. Needs the structural check. |
| `<repo>/config-id`, `<workspace>/.jj/workspace-config-id` | agent | Candidate name only. Needs the format check and the `metadata.binpb` check. |
| `<C>/repos/*/metadata.binpb`, `<C>/workspaces/*/metadata.binpb` | not the agent (checked on the final set) | Backlink check for the configuration tokens. |

The workspace store can be used for the backlink check, although the agent
can write it. To get a grant on a target directory `T`, the agent must make
`T/workspace_store/index` list the workspace. That needs write access to
`T`, either now or in an earlier session (see
[Residual exposure](#residual-exposure)).

### Never start `jj`

The resolver never starts `jj`, `git`, or any other process. A
repository's jj configuration can contain commands (`ui.pager`,
`ui.editor`, `fix.tools`, aliases, signing backends). Starting `jj`
host-side, unsandboxed, from an agent-controlled workspace is code
execution. It also adds the `PATH` planting problem given in
[PATH Sanitization for Host-Side Brokers](../docs/cli/internals/security-model.mdx#path-sanitization-for-host-side-brokers).
A pure filesystem walk avoids both.

### Secure configuration

jj keeps repository and workspace configuration out of the repository
*because* it can contain commands that an unsandboxed `jj` runs later. Write
access to it is a sandbox escape. This NEP:

- gives only read access to it, and rejects the configuration tokens in
  write lists; and
- removes the configuration token paths if the final capability set can
  write the configuration directory, and shows a warning.

Other grants (for example a profile that grants write access to
`~/.config`) can still give write access to secure configuration. This NEP
does not change that. The warning makes it visible.

### Fail-secure behavior

- In a grant list, a pointer that cannot be read, decoded, canonicalized,
  or checked expands to no paths. There is no fallback to a broader
  directory.
- In a deny, bypass, exec, or socket list, a `@jj:*` token is a profile
  error, so an empty expansion can never remove a denial.
- An unknown `@jj:` query is a profile error.
- A configuration token in a write list is a profile error.
- A non-regular file, a file larger than its limit, or too many entries is
  a check failure (no paths), not a hang.
- An older nono rejects the tokens as an unknown provider.

### Path handling, symbolic links, and TOCTOU

- The resolver canonicalizes trusted anchors once and compares by
  component.
- It never canonicalizes an agent-writable anchor (for example `R/store`).
  It checks fixed components with `symlink_metadata` instead.
- `.jj`, `.jj/repo`, `R/store`, and `<D>/.git` must be real directories. A
  device check stops a mount point from replacing them.
- The resolver returns the canonical path that it checked, never the raw
  pointer content, and the call site does not expand variables or globs in
  it.

There are two time windows between the check and the moment the rule is in
force. In the command sandbox, the agent is running while tokens resolve, so
both windows are real:

1. **CLI window (Linux and macOS).** The CLI turns each path into an
   `FsCapability`, which canonicalizes the path again. If the agent replaces
   a component of the checked path in that window (for example a directory
   that it created inside `$WORKDIR`), `cap.resolved` can name a different
   directory. **Requirement:** after the CLI creates the `FsCapability`, it
   checks that `cap.resolved` is equal to the checked path, and that the
   device and inode are the same as at the check. Otherwise it drops the
   grant. On macOS, Seatbelt matches rules by path at access time, so this
   closes the window there.
2. **Library window (Linux only).** Landlock attaches a rule to a file
   descriptor that `nono` opens from `cap.resolved` (`open_path_rule` in
   `crates/nono/src/sandbox/linux.rs`, with `O_PATH | O_CLOEXEC`), and that
   open follows symbolic links. A check in the CLI can make this window
   smaller, but cannot remove it. **Requirement:** `FsCapability` gets an
   optional expected identity (device and inode). `open_path_rule` already
   reads the metadata from the opened descriptor; if an expected identity
   is present and is different, it fails closed. The CLI supplies the
   expected identity. This is a mechanism, not policy, so the library/CLI
   boundary stays the same. The execute-restriction ruleset (which uses
   `PathFd::new`) is not affected, because `@jj:*` tokens are rejected in
   `exec_paths`.

NEP-0002 proposes a similar device and inode re-check for approved
filesystem paths, and also says that it only reduces the window. The
existing `@git:common-dir` backlink check has the same two windows. Whether
this NEP's implementation also fixes `@git:*` is an open question.

### Residual exposure

These risks stay after this NEP. The documentation must describe them.

1. **Full control of the repository.** Write access to `@jj:repo-dir`
   (operation log, operation heads, commit store) lets the agent rewrite
   commits and operations for **all** workspaces of the repository. The
   next host-side `jj` command in a different workspace (for example the
   user's default workspace) then writes files that the agent selected
   (for example `.envrc`, `.vscode/settings.json`, `Makefile`), and can
   export them to Git. This can give code execution outside the sandbox
   without hooks or configuration. Write access to `@jj:repo-dir` is thus
   equivalent to full control of the repository history and of the files
   that jj writes in every workspace.
2. **Git hooks and configuration.** Write access to `@jj:git-dir` includes
   `.git/config` and `.git/hooks`. An agent can change them to run code when
   the user later runs `jj git fetch` or `git` outside the sandbox. The
   `@git:common-dir` token has the same exposure today.
3. **Legacy jj configuration migration.** jj v0.38 to v0.46 (the current
   release) migrate a legacy `<repo>/config.toml` into secure configuration
   when `<repo>/config-id` does not exist (see `maybe_migrate_legacy_config`
   in `lib/src/secure_config.rs`). An agent with write access to
   `@jj:repo-dir` can remove `config-id` and write a legacy `config.toml`.
   The next unsandboxed `jj` command then copies it into secure
   configuration, and can run commands from it. The same applies to
   `<workspace>/.jj/workspace-config.toml` and `$WORKDIR`. This exposure
   exists today for any agent with write access to a default workspace
   (where `.jj/repo` is inside `$WORKDIR`). A `TODO` comment in the jj
   source says that v0.49 can stop the automatic migration. This NEP does
   not depend on that.
4. **Adoption of a different configuration.** If the agent sets
   `config-id` to the id of a different configuration directory, host-side
   `jj` compares the stored path with the repository path. If the stored
   path does not exist, jj adopts that configuration ("the repository was
   moved"); if it exists, jj copies it. Thus an agent can make a later
   host-side `jj` use the configuration of a different repository. This
   exists today for any agent with write access to `.jj/repo`.
5. **Agent-writable workspace paths.** If a path in a legitimate
   `workspace_store/index` is in a directory that the agent can write (for
   example a stale workspace in `/tmp` that was deleted without
   `jj workspace forget`), the agent can create a workspace there and
   claim the repository. The write non-escalation rule limits this to
   workspaces that the agent can write. The documentation recommends
   `jj workspace forget` for stale workspaces.
6. **Forgery from an earlier session.** A `workspace_store/index` that an
   agent forged during an earlier session with broader grants stays on
   disk, and stays valid in a later, stricter session. `@git:common-dir`
   has the same limit.
7. **Parent of the workspace.** A profile `filesystem.*` list with
   `@jj:workspace-root-parent` in a write list gives write access to all
   sibling directories of `W`, including other repositories, their
   `.jj/repo`, and their `.git/hooks`. In the command sandbox, the
   agent-write check on the parent limits this.
8. **Landlock cannot deny inside an allow.** On Linux, nono cannot protect
   the files of items 1 to 4 while it grants their parent directory.

### Library/CLI boundary

All policy and resolution logic stays in `nono-cli`. The `nono` library
receives the final, canonical paths in the `CapabilitySet`. The only
library change is the identity check at rule installation (see
[TOCTOU](#path-handling-symbolic-links-and-toctou)). It is a mechanism: the
CLI decides which identity to expect.

### Credential and secret secrecy

The tokens do not read, store, or forward credentials. jj configuration can
contain credential-related settings (for example signing keys), but the
resolver does not read the content of the configuration files. It reads
only pointer files, the workspace store, and `metadata.binpb`, which
contain paths and identifiers. Diagnostic messages show paths only, never
file content.

## Alternatives Considered

### Literal paths in a user profile

This is the workaround today. It is not portable: it must change for each
repository and for each workspace, and a shipped profile cannot use it.

### Start `jj` to resolve the paths

`jj workspace root` and `jj config path --repo` give the correct values. But
nono must not start `jj` host-side from an agent-controlled workspace (see
[Never start `jj`](#never-start-jj)). Rejected.

### Grant the parent of all workspaces

A broad grant (for example, the directory that contains all workspaces of a
project) is simple. But it gives write access to unrelated directories, and
it does not cover the configuration directories. Rejected for least
privilege.

### Extend `@git:*` to understand jj

The `@git:*` tokens could follow `.jj/repo` pointers. But the jj layout is
different (workspace store, `git_target`, secure configuration), and the
`@git:*` names would have a different meaning in a jj repository. A
separate provider is easier to review and to document.

### Trust a directory that looks like a Git repository for `@jj:git-dir`

Accept a `git_target` if the target contains `HEAD`, `objects/`, and
`refs/`. This lets an agent point `git_target` at any repository on the
host. Rejected in favor of the structural check.

### Take the default workspace from the workspace store

The workspace store records the `default` workspace path. But the agent can
write the workspace store after the first grant of `@jj:repo-dir`. Rejected
in favor of the `<D>/.jj/repo` shape check.

### Accept `.jj/repo` targets that the agent can read

For workspaces without a workspace store entry, accept the target if it is
the `<D>/.jj/repo` of a directory that the agent can read. Read access is
often broad (for example all of `$HOME`), so the agent could point
`.jj/repo` at any repository that it can read, and get write access to it.
Rejected.

### One `@jj:user-config` token for files and directories

The `fs_read` list needs directories and `fs_read_file` needs files. One
token cannot go to both lists. Rejected in favor of `@jj:config-files` and
`@jj:config-dirs`, the same split as `@git:config-files` and
`@git:hooks-path`.

## Open Questions

1. **Older workspaces.** A non-default workspace made before jj v0.38 has no
   entry in the workspace store, so the backlink check fails. jj ≥ v0.38
   creates an empty index for such repositories, but it does not add the old
   workspaces. The proposal: expand to no paths, and document that the user
   must add the workspace again (`jj workspace forget` and
   `jj workspace add`) or use a literal path. Is that acceptable?
2. **Fix `@git:*` at the same time?** The write non-escalation gap, the two
   TOCTOU windows, list-kind checks, and literal output also apply to
   `@git:common-dir`, `@git:worktree`, and `@git:toplevel-parent`. Must the
   implementation PRs fix them for `@git:*` too, or is that a separate
   change?
3. **Should `@git:*` stop at a `.jj` directory?** In a non-default jj
   workspace that is not a Git worktree, `@git:*` can walk up to an
   unrelated `.git` in a parent directory. Must the Git provider stop its
   walk at a workspace root that has `.jj` but no `.git`?
4. **Residual exposure mitigation on macOS.** Seatbelt can deny writes to
   `<repo>/config.toml`, `<repo>/config-id`, `.git/config`, and
   `.git/hooks` inside a granted directory. Linux cannot. Is a macOS-only
   mitigation useful, or does the difference between platforms make it
   misleading?
5. **Library identity API.** Is a new library API (expected device and inode
   per filesystem rule) acceptable in the scope of this NEP, or must it be a
   separate NEP that this one depends on?
6. **Watchman.** Is a separate `@watchman:socket` token useful for
   `fsmonitor.backend = "watchman"`, or is it out of scope?
7. **Shipped policy.** After both phases, must nono ship a default `jj`
   command policy, or only document an example?
