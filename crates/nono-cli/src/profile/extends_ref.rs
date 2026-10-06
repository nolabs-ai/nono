//! Classification and resolution of `extends` entries.
//!
//! An entry is a built-in/user profile name, a registry pack reference, or a
//! relative `./`/`../` path to a profile file.

use super::{is_registry_ref, is_under_user_profile_draft_dir, is_valid_profile_name};
use nono::{NonoError, Result};
use std::path::{Path, PathBuf};

const ERR_ABSOLUTE_PATH: &str =
    "absolute and `~/` paths are not supported in `extends`; use a relative path";
const ERR_PACK_STORE_TARGET: &str = "extend a pack by name (`org/pack`), not by path";
const ERR_NOT_JSON: &str = "path entries in `extends` must end in `.json` or `.jsonc`";
const ERR_PATH_IN_PACK_PROFILE: &str = "path entries in `extends` are not allowed in pack profiles";
const ERR_PATH_IN_DRAFT: &str = "path entries in `extends` are not allowed in profile drafts";
const ERR_PATH_IN_BUILTIN: &str = "path entries in `extends` are not allowed in built-in profiles";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExtendsRef {
    Name(String),
    Registry(String),
    /// Canonical path to the base profile file.
    Path(PathBuf),
}

/// Where an `extends` entry was written.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ExtendsOrigin<'a> {
    /// Entry written in the profile file at this path (canonical when loaded;
    /// may not exist yet for `profile init`).
    File(&'a Path),
    /// Entry from `--extends`; paths resolve against this directory.
    #[allow(dead_code)] // constructed by CLI `--extends` handling in a later change
    Cli(&'a Path),
    Builtin,
}

impl ExtendsRef {
    /// Key identifying this base in cycle detection: the name, or the
    /// canonical path.
    pub(crate) fn visited_key(&self) -> String {
        match self {
            Self::Name(s) | Self::Registry(s) => s.clone(),
            Self::Path(p) => p.display().to_string(),
        }
    }
}

fn inheritance_error(msg: String) -> NonoError {
    NonoError::ProfileInheritance(msg)
}

pub(crate) fn classify_extends_entry(raw: &str, origin: ExtendsOrigin<'_>) -> Result<ExtendsRef> {
    if raw.starts_with("./") || raw.starts_with("../") {
        return resolve_path_entry(raw, origin).map(ExtendsRef::Path);
    }
    if raw.starts_with('/') || raw.starts_with('~') {
        return Err(inheritance_error(format!("'{raw}': {ERR_ABSOLUTE_PATH}")));
    }
    if is_registry_ref(raw) {
        return Ok(ExtendsRef::Registry(raw.to_string()));
    }
    if is_valid_profile_name(raw) {
        return Ok(ExtendsRef::Name(raw.to_string()));
    }
    Err(inheritance_error(format!(
        "invalid base profile name '{raw}'"
    )))
}

fn resolve_path_entry(raw: &str, origin: ExtendsOrigin<'_>) -> Result<PathBuf> {
    let base_dir = match origin {
        ExtendsOrigin::Cli(dir) => dir.to_path_buf(),
        ExtendsOrigin::Builtin => {
            return Err(inheritance_error(format!("'{raw}': {ERR_PATH_IN_BUILTIN}")));
        }
        ExtendsOrigin::File(file) => {
            // The rejection checks compare canonical prefixes; a non-canonical
            // spelling of a store or draft path would otherwise slip past them.
            let file = &nono::try_canonicalize(file);
            if is_under_pack_store(file) {
                return Err(inheritance_error(format!(
                    "'{raw}': {ERR_PATH_IN_PACK_PROFILE}"
                )));
            }
            if is_under_user_profile_draft_dir(file) {
                return Err(inheritance_error(format!("'{raw}': {ERR_PATH_IN_DRAFT}")));
            }
            let parent = file.parent().ok_or_else(|| {
                inheritance_error(format!(
                    "'{raw}': profile file {} has no parent directory",
                    file.display()
                ))
            })?;
            parent.to_path_buf()
        }
    };

    if !(raw.ends_with(".json") || raw.ends_with(".jsonc")) {
        return Err(inheritance_error(format!("'{raw}': {ERR_NOT_JSON}")));
    }

    let joined = base_dir.join(raw);
    let target = joined.canonicalize().map_err(|e| {
        inheritance_error(format!(
            "extends '{raw}' resolves to {}, which cannot be read: {e}",
            joined.display()
        ))
    })?;
    if is_under_pack_store(&target) {
        return Err(inheritance_error(format!(
            "'{raw}': {ERR_PACK_STORE_TARGET}"
        )));
    }
    Ok(target)
}

/// True when `path` is inside the installed pack store. A missing store
/// contains nothing.
pub(crate) fn is_under_pack_store(path: &Path) -> bool {
    let Ok(store) = crate::package::package_store_dir() else {
        return false;
    };
    let Ok(store_canon) = store.canonicalize() else {
        return false;
    };
    path.starts_with(&store_canon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::with_isolated_config_home;
    use std::fs;

    fn origin_file(p: &Path) -> ExtendsOrigin<'_> {
        ExtendsOrigin::File(p)
    }

    fn err_text(r: Result<ExtendsRef>) -> String {
        r.expect_err("expected error").to_string()
    }

    #[test]
    fn bare_name_is_name() {
        let r = classify_extends_entry("default", ExtendsOrigin::Builtin).expect("classify");
        assert_eq!(r, ExtendsRef::Name("default".into()));
    }

    #[test]
    fn registry_ref_is_registry() {
        let r = classify_extends_entry("nolabs-ai/claude", ExtendsOrigin::Builtin).expect("ok");
        assert_eq!(r, ExtendsRef::Registry("nolabs-ai/claude".into()));
    }

    #[test]
    fn dot_slash_resolves_against_declaring_file_dir() {
        with_isolated_config_home(|_| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let d = tmp.path().canonicalize().expect("canon");
            fs::write(d.join("base.json"), "{}").expect("write");
            let child = d.join("child.json");
            let r = classify_extends_entry("./base.json", origin_file(&child)).expect("classify");
            assert_eq!(r, ExtendsRef::Path(d.join("base.json")));
        });
    }

    #[test]
    fn dot_dot_resolves_to_parent() {
        with_isolated_config_home(|_| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let d = tmp.path().canonicalize().expect("canon");
            fs::create_dir(d.join("sub")).expect("mkdir");
            fs::write(d.join("base.json"), "{}").expect("write");
            let child = d.join("sub").join("child.json");
            let r = classify_extends_entry("../base.json", origin_file(&child)).expect("classify");
            assert_eq!(r, ExtendsRef::Path(d.join("base.json")));
        });
    }

    #[test]
    fn cli_origin_resolves_against_given_dir() {
        with_isolated_config_home(|_| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let d = tmp.path().canonicalize().expect("canon");
            fs::write(d.join("x.json"), "{}").expect("write");
            let r = classify_extends_entry("./x.json", ExtendsOrigin::Cli(&d)).expect("classify");
            assert_eq!(r, ExtendsRef::Path(d.join("x.json")));
        });
    }

    #[test]
    fn missing_path_errors_with_resolved_path() {
        with_isolated_config_home(|_| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let d = tmp.path().canonicalize().expect("canon");
            let msg = err_text(classify_extends_entry(
                "./nope.json",
                ExtendsOrigin::Cli(&d),
            ));
            assert!(msg.contains("./nope.json"), "{msg}");
            assert!(
                msg.contains(&d.join("./nope.json").display().to_string()),
                "{msg}"
            );
        });
    }

    #[test]
    fn path_without_json_extension_errors() {
        with_isolated_config_home(|_| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let d = tmp.path().canonicalize().expect("canon");
            fs::write(d.join("base"), "{}").expect("write");
            let msg = err_text(classify_extends_entry("./base", ExtendsOrigin::Cli(&d)));
            assert!(msg.contains(ERR_NOT_JSON), "{msg}");
        });
    }

    #[test]
    fn jsonc_extension_is_accepted() {
        with_isolated_config_home(|_| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let d = tmp.path().canonicalize().expect("canon");
            fs::write(d.join("base.jsonc"), "{}").expect("write");
            let r = classify_extends_entry("./base.jsonc", ExtendsOrigin::Cli(&d)).expect("ok");
            assert_eq!(r, ExtendsRef::Path(d.join("base.jsonc")));
        });
    }

    #[test]
    fn absolute_and_tilde_rejected() {
        for raw in ["/x.json", "~/x.json"] {
            let msg = err_text(classify_extends_entry(raw, ExtendsOrigin::Builtin));
            assert!(msg.contains(ERR_ABSOLUTE_PATH), "{raw}: {msg}");
        }
    }

    #[test]
    fn path_into_pack_store_rejected() {
        with_isolated_config_home(|cfg| {
            let pack = cfg.join("nono/packages/ns/p/profiles");
            fs::create_dir_all(&pack).expect("mkdir");
            fs::write(pack.join("x.json"), "{}").expect("write");
            let msg = err_text(classify_extends_entry(
                "./x.json",
                ExtendsOrigin::Cli(&pack),
            ));
            assert!(msg.contains(ERR_PACK_STORE_TARGET), "{msg}");
        });
    }

    #[test]
    fn path_entry_in_pack_store_profile_rejected() {
        with_isolated_config_home(|cfg| {
            let pack = cfg.join("nono/packages/ns/p/profiles");
            fs::create_dir_all(&pack).expect("mkdir");
            let file = pack.join("x.json");
            let msg = err_text(classify_extends_entry("./y.json", origin_file(&file)));
            assert!(msg.contains(ERR_PATH_IN_PACK_PROFILE), "{msg}");
        });
    }

    #[test]
    fn path_entry_in_draft_rejected() {
        with_isolated_config_home(|cfg| {
            let drafts = cfg.join("nono/profile-drafts");
            fs::create_dir_all(&drafts).expect("mkdir");
            let file = drafts.join("x.json");
            let msg = err_text(classify_extends_entry("./y.json", origin_file(&file)));
            assert!(msg.contains(ERR_PATH_IN_DRAFT), "{msg}");
        });
    }

    #[test]
    fn path_entry_in_draft_rejected_via_non_canonical_spelling() {
        with_isolated_config_home(|cfg| {
            let drafts = cfg.join("nono/profile-drafts");
            fs::create_dir_all(&drafts).expect("mkdir");
            fs::write(drafts.join("y.json"), "{}").expect("write");
            let file = cfg.join("nono/../nono/profile-drafts/x.json");
            let msg = err_text(classify_extends_entry("./y.json", origin_file(&file)));
            assert!(msg.contains(ERR_PATH_IN_DRAFT), "{msg}");
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlink_outside_store_into_pack_store_rejected() {
        with_isolated_config_home(|cfg| {
            let pack = cfg.join("nono/packages/ns/p/profiles");
            fs::create_dir_all(&pack).expect("mkdir");
            fs::write(pack.join("x.json"), "{}").expect("write");
            let tmp = tempfile::tempdir().expect("tempdir");
            let d = tmp.path().canonicalize().expect("canon");
            std::os::unix::fs::symlink(pack.join("x.json"), d.join("link.json")).expect("link");
            let child = d.join("child.json");
            let msg = err_text(classify_extends_entry("./link.json", origin_file(&child)));
            assert!(msg.contains(ERR_PACK_STORE_TARGET), "{msg}");
        });
    }

    #[test]
    fn path_entry_in_builtin_rejected() {
        let msg = err_text(classify_extends_entry("./y.json", ExtendsOrigin::Builtin));
        assert!(msg.contains(ERR_PATH_IN_BUILTIN), "{msg}");
    }

    #[test]
    fn cli_origin_skips_file_rules() {
        with_isolated_config_home(|cfg| {
            let drafts = cfg.join("nono/profile-drafts");
            fs::create_dir_all(&drafts).expect("mkdir");
            fs::write(drafts.join("x.json"), "{}").expect("write");
            let r = classify_extends_entry("./x.json", ExtendsOrigin::Cli(&drafts)).expect("ok");
            assert_eq!(r, ExtendsRef::Path(drafts.join("x.json")));
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_target_returns_canonical() {
        with_isolated_config_home(|_| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let root = tmp.path().canonicalize().expect("canon");
            let (d, e) = (root.join("d"), root.join("e"));
            fs::create_dir(&d).expect("mkdir");
            fs::create_dir(&e).expect("mkdir");
            fs::write(e.join("real.json"), "{}").expect("write");
            std::os::unix::fs::symlink(e.join("real.json"), d.join("base.json")).expect("link");
            let child = d.join("child.json");
            let r = classify_extends_entry("./base.json", origin_file(&child)).expect("ok");
            assert_eq!(r, ExtendsRef::Path(e.join("real.json")));
        });
    }

    #[test]
    fn shared_slash_json_is_still_invalid() {
        let msg = err_text(classify_extends_entry(
            "shared/base.json",
            ExtendsOrigin::Builtin,
        ));
        assert!(msg.contains("invalid base profile name"), "{msg}");
    }

    #[test]
    fn visited_key_is_name_or_canonical_path() {
        assert_eq!(ExtendsRef::Name("a".into()).visited_key(), "a");
        assert_eq!(
            ExtendsRef::Path(PathBuf::from("/x/y.json")).visited_key(),
            "/x/y.json"
        );
    }
}
