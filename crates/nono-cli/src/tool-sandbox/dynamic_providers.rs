//! Dynamic token expansion for per-command sandbox path lists.
//!
//! Profile authors can place a sentinel like `@<provider>:<query>` in any
//! per-command sandbox path list (`fs_read`, `fs_read_file`, `fs_write`,
//! `fs_write_file`). At launch time, the token is replaced with one or more
//! concrete paths produced by the named provider — letting profiles cover
//! user-specific state (e.g. paths referenced by the user's git config)
//! without enumerating every per-user dotfile location in the shipped profile.
//!
//! Token format: `@<provider>:<query>`.
//! - `<provider>` is a lowercase alphanumeric identifier (no `:` or spaces).
//! - `<query>` is provider-specific and may contain hyphens, slashes, etc.
//! - Anything not starting with `@` is left untouched.
//! - `@` strings without a `:` are passed through as literal paths.
//!
//! Adapted from the kipz/nono `develop` branch `profile::dynamic_providers`.

use nono::{NonoError, Result};

/// Parse a profile path entry as a dynamic-provider token.
///
/// Returns `Some((provider, query))` for strings of the shape
/// `@<provider>:<query>`. Returns `None` for everything else, including
/// `@` strings that lack a `:` (treated as literal paths).
fn parse_token(s: &str) -> Option<(&str, &str)> {
    let rest = s.strip_prefix('@')?;
    let (provider, query) = rest.split_once(':')?;
    Some((provider, query))
}

pub(super) mod git {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use nono::{NonoError, Result};

    /// Paths extracted from `git config --list --show-origin --show-scope`,
    /// split by filesystem type so the consumer (a profile) can route each
    /// kind to the right capability list — `files` into `fs_read_file`
    /// and `dirs` into `fs_read`.
    ///
    /// `core.hooksPath` is the only directory-typed expansion today;
    /// every other path-valued knob points at a single file.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub(super) struct GitConfigPaths {
        pub files: Vec<String>,
        pub dirs: Vec<String>,
    }

    /// Run `git rev-parse --show-toplevel` and return the repo root, or `None`
    /// when the process is not inside a git repository (or git is absent).
    fn git_toplevel() -> Option<PathBuf> {
        let output = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let s = std::str::from_utf8(&output.stdout).ok()?.trim();
        if s.is_empty() {
            return None;
        }
        Some(PathBuf::from(s))
    }

    /// Invoke `git config --list --show-origin --show-scope` and return
    /// the file-typed paths the git binary needs to read at startup.
    ///
    /// See [`read_hooks_path`] for directory-typed paths.
    ///
    /// Returns an empty list if `git` is absent or exits non-zero.
    pub(crate) fn read_files() -> Result<Vec<String>> {
        let cwd = git_toplevel();
        Ok(run(cwd.as_deref(), None)?.files)
    }

    /// Invoke `git config --list --show-origin --show-scope` and return
    /// the directory-typed paths the git binary needs to read (today: just
    /// `core.hooksPath` if set in the `global` or `system` scope).
    ///
    /// Returned paths are intended for `fs_read` lists.
    pub(crate) fn read_hooks_path() -> Result<Vec<String>> {
        let cwd = git_toplevel();
        Ok(run(cwd.as_deref(), None)?.dirs)
    }

    /// Return the path to the git common directory (`.git` or the main repo's
    /// `.git` when running inside a worktree).
    ///
    /// In a regular repo this is `.git` (relative). In a worktree it is an
    /// absolute path pointing to the main repo's `.git`. Either form is
    /// suitable for `fs_write`/`fs_read` path lists — relative paths are
    /// resolved against `$WORKDIR` by `resolve_policy_path`.
    ///
    /// Returns an empty list when git is absent, the command fails, or the
    /// process is not inside a git repository.
    pub(crate) fn read_common_dir() -> Result<Vec<String>> {
        run_common_dir(git_toplevel().as_deref())
    }

    fn run_common_dir(cwd: Option<&Path>) -> Result<Vec<String>> {
        let mut cmd = Command::new("git");
        cmd.args(["rev-parse", "--git-common-dir"]);
        if let Some(d) = cwd {
            cmd.current_dir(d);
        }
        let output = match cmd.output() {
            Ok(o) if o.status.success() => o,
            _ => return Ok(vec![]),
        };
        let path = std::str::from_utf8(&output.stdout)
            .unwrap_or("")
            .trim()
            .to_string();
        if path.is_empty() {
            return Ok(vec![]);
        }
        Ok(vec![path])
    }

    /// Test seam: run the common-dir provider from a specific directory.
    #[cfg(test)]
    pub(super) fn read_common_dir_in(cwd: &Path) -> Result<Vec<String>> {
        run_common_dir(Some(cwd))
    }

    /// Test seam: parse a known-fixture global config and return the
    /// files+dirs split.
    #[cfg(test)]
    pub(super) fn read_paths_with_global(global_config: &Path) -> Result<GitConfigPaths> {
        run(None, Some(global_config))
    }

    /// Test seam: run the provider with both a specific cwd and a fixed
    /// global config path.
    #[cfg(test)]
    pub(super) fn read_paths_in(
        cwd: &Path,
        global_config: Option<&Path>,
    ) -> Result<GitConfigPaths> {
        run(Some(cwd), global_config)
    }

    fn run(cwd: Option<&Path>, global_config_override: Option<&Path>) -> Result<GitConfigPaths> {
        let mut cmd = Command::new("git");
        cmd.args(["config", "--list", "--show-origin", "--show-scope"]);
        if let Some(d) = cwd {
            cmd.current_dir(d);
        }
        if let Some(path) = global_config_override {
            cmd.env("GIT_CONFIG_GLOBAL", path);
            cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
        }
        let output = match cmd.output() {
            Ok(o) => o,
            Err(_) => return Ok(GitConfigPaths::default()),
        };
        if !output.status.success() {
            return Ok(GitConfigPaths::default());
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| NonoError::ProfileParse(format!("git config produced non-UTF-8: {e}")))?;
        Ok(parse_paths_from_stdout(&stdout))
    }

    /// Parse the stdout of `git config --list --show-origin --show-scope`
    /// into a [`GitConfigPaths`] split by capability type.
    ///
    /// Only `global` and `system` scopes are kept; `local` and `worktree`
    /// are dropped (attacker-controlled per-repo `.git/config` threat model).
    pub(super) fn parse_paths_from_stdout(stdout: &str) -> GitConfigPaths {
        use std::collections::BTreeSet;

        const FILE_PATH_KEYS: &[&str] = &[
            "core.attributesfile",
            "core.excludesfile",
            "commit.template",
        ];
        const DIR_PATH_KEYS: &[&str] = &["core.hookspath"];
        const TRUSTED_SCOPES: &[&str] = &["global", "system"];

        let mut files_seen = BTreeSet::new();
        let mut dirs_seen = BTreeSet::new();
        let mut out = GitConfigPaths::default();

        for line in stdout.lines() {
            let Some((scope, after_scope)) = line.split_once('\t') else {
                continue;
            };
            if !TRUSTED_SCOPES.contains(&scope) {
                continue;
            }
            let Some((origin, rest)) = after_scope.split_once('\t') else {
                continue;
            };
            if let Some(path) = origin.strip_prefix("file:")
                && !path.is_empty()
                && files_seen.insert(path.to_string())
            {
                out.files.push(path.to_string());
            }

            let Some((key, value)) = rest.split_once('=') else {
                continue;
            };
            let key_lower = key.to_lowercase();
            if value.is_empty() {
                continue;
            }
            if FILE_PATH_KEYS.contains(&key_lower.as_str()) && files_seen.insert(value.to_string())
            {
                out.files.push(value.to_string());
            } else if DIR_PATH_KEYS.contains(&key_lower.as_str())
                && dirs_seen.insert(value.to_string())
            {
                out.dirs.push(value.to_string());
            }
        }
        out
    }
}

/// Built-in dispatcher: route `(provider, query)` to the appropriate
/// provider implementation. Returns an error for unknown providers so
/// typos and stale profile entries surface at launch rather than silently
/// producing no paths.
fn dispatch_token(provider: &str, query: &str) -> Result<Vec<String>> {
    match provider {
        "git" => match query {
            "config-files" => git::read_files(),
            "hooks-path" => git::read_hooks_path(),
            "common-dir" => git::read_common_dir(),
            other => Err(NonoError::ProfileParse(format!(
                "unknown git provider query '{other}'"
            ))),
        },
        other => Err(NonoError::ProfileParse(format!(
            "unknown dynamic-token provider '{other}'"
        ))),
    }
}

/// Expand every dynamic-provider token in a path list in place, returning
/// the expanded list. Literal paths pass through unchanged.
pub(super) fn expand_dynamic_tokens(entries: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        match parse_token(entry) {
            Some((provider, query)) => out.extend(dispatch_token(provider, query)?),
            None => out.push(entry.clone()),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_token_recognises_at_provider_colon_query() {
        assert_eq!(
            parse_token("@git:config-files"),
            Some(("git", "config-files"))
        );
        assert_eq!(parse_token("@git:hooks-path"), Some(("git", "hooks-path")));
        assert_eq!(parse_token("@git:common-dir"), Some(("git", "common-dir")));
    }

    #[test]
    fn parse_token_returns_none_for_literal_paths() {
        assert_eq!(parse_token("~/.gitconfig"), None);
        assert_eq!(parse_token("/etc/passwd"), None);
        assert_eq!(parse_token("$HOME/.gitconfig"), None);
    }

    #[test]
    fn parse_token_returns_none_for_at_without_colon() {
        assert_eq!(parse_token("@something"), None);
    }

    #[test]
    fn parse_token_returns_none_for_empty_string() {
        assert_eq!(parse_token(""), None);
    }

    #[test]
    fn expand_dynamic_tokens_passes_literal_paths_through_unchanged() {
        let input = vec!["~/.gitconfig".to_string(), "/etc/static".to_string()];
        let out = expand_dynamic_tokens(&input).expect("literal pass-through");
        assert_eq!(out, vec!["~/.gitconfig", "/etc/static"]);
    }

    #[test]
    fn expand_dynamic_tokens_errors_on_unknown_provider() {
        let input = vec!["@unknown:query".to_string()];
        let err = expand_dynamic_tokens(&input).expect_err("unknown provider");
        assert!(format!("{err}").contains("unknown"));
    }

    #[test]
    fn expand_dynamic_tokens_errors_on_unknown_git_query() {
        let input = vec!["@git:nonsense".to_string()];
        let err = expand_dynamic_tokens(&input).expect_err("unknown git query");
        assert!(format!("{err}").contains("nonsense"));
    }

    #[test]
    fn parse_paths_from_stdout_extracts_config_file_paths_into_files() {
        let stdout = "\
global\tfile:/home/u/.gitconfig\tuser.name=Alice
global\tfile:/home/u/.gitconfig\tuser.email=alice@example.com
global\tfile:/home/u/.gitconfig-work\tcommit.template=/tmp/template
command\tcmdline:\tcore.editor=vim
global\tfile:/home/u/.gitconfig\tinclude.path=~/.gitconfig-work
";
        let out = git::parse_paths_from_stdout(stdout);
        assert!(out.files.contains(&"/home/u/.gitconfig".to_string()));
        assert!(out.files.contains(&"/home/u/.gitconfig-work".to_string()));
        assert!(out.dirs.is_empty(), "dirs should be empty: {:?}", out.dirs);
    }

    #[test]
    fn parse_paths_from_stdout_dedupes_repeated_file_origins() {
        let stdout = "\
global\tfile:/home/u/.gitconfig\tuser.name=Alice
global\tfile:/home/u/.gitconfig\tuser.email=alice@example.com
global\tfile:/home/u/.gitconfig\tcore.editor=vim
";
        let out = git::parse_paths_from_stdout(stdout);
        let count = out
            .files
            .iter()
            .filter(|p| *p == "/home/u/.gitconfig")
            .count();
        assert_eq!(count, 1, "got {:?}", out.files);
    }

    #[test]
    fn parse_paths_from_stdout_ignores_non_file_origins() {
        let stdout = "\
command\tcmdline:\tcore.editor=vim
local\tblob:HEAD:.gitmodules\tsubmodule.foo.url=x
global\tstandard input:\tuser.name=Alice
";
        let out = git::parse_paths_from_stdout(stdout);
        assert!(out.files.is_empty(), "got files {:?}", out.files);
        assert!(out.dirs.is_empty(), "got dirs {:?}", out.dirs);
    }

    #[test]
    fn parse_paths_from_stdout_drops_local_and_worktree_scopes() {
        let stdout = "\
global\tfile:/home/u/.gitconfig\tcore.attributesFile=/home/u/.gitattributes
local\tfile:/repo/.git/config\tcore.attributesFile=/etc/passwd
worktree\tfile:/repo/.git/config.worktree\tcore.hooksPath=/etc/sudoers.d
system\tfile:/etc/gitconfig\tcommit.template=/etc/git-template
";
        let out = git::parse_paths_from_stdout(stdout);
        assert!(out.files.contains(&"/home/u/.gitattributes".to_string()));
        assert!(out.files.contains(&"/etc/git-template".to_string()));
        assert!(out.files.contains(&"/home/u/.gitconfig".to_string()));
        assert!(out.files.contains(&"/etc/gitconfig".to_string()));
        for leaked in ["/etc/passwd", "/etc/sudoers.d", "/repo/.git/config"] {
            assert!(
                !out.files.iter().any(|p| p == leaked) && !out.dirs.iter().any(|p| p == leaked),
                "untrusted-scope path leaked: {leaked} in {out:?}",
            );
        }
    }

    #[test]
    fn parse_paths_from_stdout_routes_hooks_path_to_dirs() {
        let stdout = "\
global\tfile:/home/u/.gitconfig\tcore.hooksPath=/home/u/.githooks
global\tfile:/home/u/.gitconfig\tcore.attributesFile=/home/u/.gitattributes
";
        let out = git::parse_paths_from_stdout(stdout);
        assert_eq!(out.dirs, vec!["/home/u/.githooks".to_string()]);
        assert!(out.files.contains(&"/home/u/.gitattributes".to_string()));
        assert!(
            !out.files.iter().any(|p| p == "/home/u/.githooks"),
            "hooksPath leaked into files: {:?}",
            out.files
        );
    }

    #[test]
    fn git_read_paths_with_global_returns_config_file_and_path_values() {
        use std::io::Write;
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = tmp.path().join("gitconfig");
        {
            let mut f = std::fs::File::create(&cfg).expect("create gitconfig");
            writeln!(f, "[user]\n\tname = Test").expect("write user");
            writeln!(f, "[core]\n\tattributesFile = ~/.gitattributes-test")
                .expect("write attributesFile");
        }

        let paths = git::read_paths_with_global(&cfg).expect("git config");

        let cfg_str = cfg.to_str().expect("utf8 tempdir");
        assert!(
            paths.files.iter().any(|p| p == cfg_str),
            "expected gitconfig path {cfg_str} in files, got {:?}",
            paths.files
        );
        assert!(
            paths.files.iter().any(|p| p == "~/.gitattributes-test"),
            "expected attributesFile value in files, got {:?}",
            paths.files
        );
    }

    #[test]
    fn git_read_paths_excludes_per_repo_local_config_overrides() {
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("tempdir");
        let global_cfg = tmp.path().join("global-gitconfig");
        let global_attrs = "/tmp/global-attributes-trusted";
        let evil_attrs = "/etc/passwd";

        {
            let mut f = std::fs::File::create(&global_cfg).expect("create global");
            writeln!(f, "[user]\n\tname = Test").expect("write user");
            writeln!(f, "[core]\n\tattributesFile = {global_attrs}").expect("write attrs");
        }

        let repo = tmp.path().join("hostile-repo");
        std::fs::create_dir(&repo).expect("mkdir repo");
        let status = Command::new("git")
            .arg("init")
            .arg("--quiet")
            .current_dir(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init failed");
        let status = Command::new("git")
            .args(["config", "core.attributesFile", evil_attrs])
            .current_dir(&repo)
            .status()
            .expect("git config local");
        assert!(status.success(), "git config local failed");

        let paths = git::read_paths_in(&repo, Some(&global_cfg)).expect("git config provider");

        assert!(
            paths.files.iter().any(|p| p == global_attrs),
            "global attributesFile missing, got {:?}",
            paths.files
        );
        assert!(
            !paths.files.iter().any(|p| p == evil_attrs)
                && !paths.dirs.iter().any(|p| p == evil_attrs),
            "per-repo attributesFile leaked into provider output (sandbox bypass), got {paths:?}"
        );
    }

    #[test]
    fn git_read_paths_with_global_walks_include_chain() {
        use std::io::Write;
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = tmp.path().join("gitconfig");
        let work = tmp.path().join("gitconfig-work");
        {
            let mut f = std::fs::File::create(&work).expect("create work");
            writeln!(f, "[user]\n\temail = work@example.com").expect("write work");
        }
        {
            let mut f = std::fs::File::create(&cfg).expect("create main");
            writeln!(f, "[user]\n\tname = Test").expect("write user");
            writeln!(f, "[include]\n\tpath = {}", work.display()).expect("write include");
        }

        let paths = git::read_paths_with_global(&cfg).expect("git config");

        let cfg_str = cfg.to_str().expect("utf8");
        let work_str = work.to_str().expect("utf8");
        assert!(
            paths.files.iter().any(|p| p == cfg_str),
            "main gitconfig missing, got {:?}",
            paths.files
        );
        assert!(
            paths.files.iter().any(|p| p == work_str),
            "included gitconfig-work missing, got {:?}",
            paths.files
        );
    }

    #[test]
    fn git_read_paths_includeif_hasconfig_matches_remote() {
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("tempdir");

        // A file included only when a ddoghq remote is present.
        let included = tmp.path().join("gitconfig-ddoghq");
        {
            let mut f = std::fs::File::create(&included).expect("create included");
            writeln!(f, "[user]\n\temail = work@ddoghq.example.com").expect("write included");
        }

        // Global config with a hasconfig:remote.*.url includeIf.
        let global_cfg = tmp.path().join("gitconfig");
        {
            let mut f = std::fs::File::create(&global_cfg).expect("create global");
            writeln!(f, "[user]\n\tname = Test").expect("write user");
            writeln!(
                f,
                "[includeIf \"hasconfig:remote.*.url:git@github.com:ddoghq/**\"]\n\tpath = {}",
                included.display()
            )
            .expect("write includeIf");
        }

        // A repo with a matching remote so hasconfig: fires.
        let repo = tmp.path().join("repo");
        std::fs::create_dir(&repo).expect("mkdir repo");
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&repo)
            .status()
            .expect("git init");
        Command::new("git")
            .args(["remote", "add", "origin", "git@github.com:ddoghq/some-repo"])
            .current_dir(&repo)
            .status()
            .expect("git remote add");

        let paths =
            git::read_paths_in(&repo, Some(&global_cfg)).expect("git config with hasconfig");

        let included_str = included.to_str().expect("utf8");
        assert!(
            paths.files.iter().any(|p| p == included_str),
            "hasconfig:remote includeIf target missing from files; got {:?}",
            paths.files
        );
    }

    #[test]
    fn parse_paths_from_stdout_extracts_path_valued_keys() {
        let stdout = "\
global\tfile:/home/u/.gitconfig\tcore.attributesFile=~/.gitattributes
global\tfile:/home/u/.gitconfig\tcore.excludesFile=~/.gitexcludes
global\tfile:/home/u/.gitconfig\tcore.hooksPath=~/.githooks
global\tfile:/home/u/.gitconfig\tcommit.template=~/.gitmessage
global\tfile:/home/u/.gitconfig\tuser.name=Alice
";
        let out = git::parse_paths_from_stdout(stdout);
        assert!(out.files.contains(&"~/.gitattributes".to_string()));
        assert!(out.files.contains(&"~/.gitexcludes".to_string()));
        assert!(out.files.contains(&"~/.gitmessage".to_string()));
        assert_eq!(out.dirs, vec!["~/.githooks".to_string()]);
    }

    #[test]
    fn git_read_common_dir_returns_dot_git_in_regular_repo() {
        use std::process::Command;
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path().join("repo");
        std::fs::create_dir(&repo).expect("mkdir repo");
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&repo)
            .status()
            .expect("git init");

        let result = git::read_common_dir_in(&repo).expect("read_common_dir");
        assert_eq!(result, vec![".git".to_string()]);
    }

    #[test]
    fn git_read_common_dir_returns_absolute_path_in_worktree() {
        use std::process::Command;
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path().join("repo");
        std::fs::create_dir(&repo).expect("mkdir repo");
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&repo)
            .status()
            .expect("git init");
        Command::new("git")
            .args([
                "-c",
                "user.email=t@t.com",
                "-c",
                "user.name=T",
                "commit",
                "--allow-empty",
                "-m",
                "init",
            ])
            .current_dir(&repo)
            .status()
            .expect("git commit");

        let wt = tmp.path().join("worktree");
        Command::new("git")
            .args(["worktree", "add", wt.to_str().expect("utf8")])
            .current_dir(&repo)
            .status()
            .expect("git worktree add");

        let result = git::read_common_dir_in(&wt).expect("read_common_dir in worktree");
        assert_eq!(result.len(), 1, "expected one entry, got {:?}", result);
        let common = std::path::Path::new(&result[0]);
        assert!(
            common.is_absolute(),
            "expected absolute path in worktree, got {:?}",
            result
        );
        assert_eq!(
            common,
            repo.join(".git").canonicalize().expect("canonicalize"),
        );
    }

    #[test]
    fn git_read_common_dir_returns_empty_outside_git_repo() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = git::read_common_dir_in(tmp.path()).expect("read_common_dir");
        assert!(
            result.is_empty(),
            "expected empty outside repo, got {:?}",
            result
        );
    }
}
