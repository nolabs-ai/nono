//! Portable policy data. Imports remain raw until the enforcing device loads them.
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    path::{Path, PathBuf},
    rc::Rc,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bundle {
    pub format_version: String,
    pub entry: String,
    pub profiles: BTreeMap<String, Value>,
    pub policy: Value,
    pub network: Value,
}

#[derive(Clone)]
struct Definitions {
    policy: crate::policy::Policy,
    network: crate::network_policy::NetworkPolicy,
    directory: PathBuf,
    ids: BTreeSet<String>,
}
thread_local! { static CURRENT: RefCell<Option<Definitions>> = const { RefCell::new(None) }; }

pub(crate) struct Scope {
    previous: Option<Definitions>,
    _thread: PhantomData<Rc<()>>,
}
impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.with(|slot| {
            slot.replace(self.previous.take());
        });
    }
}

pub(crate) fn current_policy() -> Option<crate::policy::Policy> {
    CURRENT.with(|slot| slot.borrow().as_ref().map(|d| d.policy.clone()))
}
pub(crate) fn current_network() -> Option<crate::network_policy::NetworkPolicy> {
    CURRENT.with(|slot| slot.borrow().as_ref().map(|d| d.network.clone()))
}

pub(crate) fn bundled_base(name: &str, context: Option<&Path>) -> Option<Result<PathBuf>> {
    CURRENT.with(|slot| {
        let slot = slot.borrow();
        let definitions = slot.as_ref()?;
        if context != Some(definitions.directory.as_path()) || !definitions.ids.contains(name) {
            return None;
        }
        let path = definitions.directory.join(format!("{name}.json"));
        Some(if path.is_file() {
            Ok(path)
        } else {
            Err(invalid("a bundled dependency is missing"))
        })
    })
}

fn invalid(message: impl Into<String>) -> NonoError {
    NonoError::ProfileParse(format!("policy bundle: {}", message.into()))
}
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn bases(document: &Value) -> Result<Vec<String>> {
    match document.get("extends") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(name)) => Ok(vec![name.clone()]),
        Some(Value::Array(names)) => names
            .iter()
            .map(|n| {
                n.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("extends must contain names"))
            })
            .collect(),
        _ => Err(invalid("invalid extends")),
    }
}

fn data_only(value: &Value) -> Result<()> {
    match value {
        Value::String(value) if value.contains("$PACK_DIR") => {
            return Err(invalid(
                "runtime pack assets are not policy data; use a local profile for executable pack features",
            ));
        }
        Value::Object(object) => {
            if object
                .get("packs")
                .and_then(Value::as_array)
                .is_some_and(|packs| !packs.is_empty())
            {
                return Err(invalid("runtime packs cannot be embedded as policy data"));
            }
            if object
                .get("session_hooks")
                .and_then(Value::as_object)
                .is_some_and(|hooks| hooks.values().any(|v| !v.is_null()))
            {
                return Err(invalid("host session hooks are not permitted"));
            }
            for child in object.values() {
                data_only(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                data_only(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

impl Bundle {
    pub(crate) fn validate(&self) -> Result<()> {
        if serde_json::to_vec(self)
            .map_err(|e| invalid(e.to_string()))?
            .len()
            > 2 * 1024 * 1024
        {
            return Err(invalid("document exceeds size limit"));
        }
        if self.format_version != "1"
            || self.profiles.is_empty()
            || self.profiles.len() > 64
            || !self.profiles.contains_key(&self.entry)
            || !self.policy.is_object()
            || !self.network.is_object()
        {
            return Err(invalid("unsupported or incomplete document"));
        }
        for (id, document) in &self.profiles {
            if !valid_id(id) || !document.is_object() {
                return Err(invalid("invalid profile entry"));
            }
            for base in bases(document)? {
                if !self.profiles.contains_key(&base) {
                    return Err(invalid("external or missing profile dependency"));
                }
            }
            data_only(document)?;
        }
        let mut heights = BTreeMap::new();
        for id in self.profiles.keys() {
            self.check_graph(id, &mut BTreeSet::new(), &mut heights)?;
        }
        data_only(&self.policy)?;
        data_only(&self.network)
    }

    fn check_graph(
        &self,
        id: &str,
        visiting: &mut BTreeSet<String>,
        heights: &mut BTreeMap<String, usize>,
    ) -> Result<usize> {
        if let Some(height) = heights.get(id) {
            return Ok(*height);
        }
        if visiting.len() > crate::profile::MAX_INHERITANCE_DEPTH || !visiting.insert(id.into()) {
            return Err(invalid("cyclic or excessively deep inheritance"));
        }
        let mut height = 0;
        for base in bases(&self.profiles[id])? {
            height = height.max(1 + self.check_graph(&base, visiting, heights)?);
        }
        if height > crate::profile::MAX_INHERITANCE_DEPTH {
            return Err(invalid("inheritance depth exceeded"));
        }
        visiting.remove(id);
        heights.insert(id.into(), height);
        Ok(height)
    }

    pub(crate) fn activate(&self, directory: &Path) -> Result<Scope> {
        self.validate()?;
        let definitions = Definitions {
            policy: crate::policy::load_policy(&self.policy.to_string())?,
            network: crate::network_policy::load_network_policy(&self.network.to_string())?,
            directory: directory
                .canonicalize()
                .map_err(|_| invalid("bundle directory is unavailable"))?,
            ids: self.profiles.keys().cloned().collect(),
        };
        let previous = CURRENT.with(|slot| slot.replace(Some(definitions)));
        Ok(Scope {
            previous,
            _thread: PhantomData,
        })
    }

    pub(crate) fn materialize(&self, directory: &Path) -> Result<PathBuf> {
        self.validate()?;
        for (id, document) in &self.profiles {
            let path = directory.join(format!("{id}.json"));
            let expected =
                serde_json::to_vec_pretty(document).map_err(|e| invalid(e.to_string()))?;
            let unchanged = std::fs::symlink_metadata(&path)
                .ok()
                .filter(|metadata| metadata.file_type().is_file())
                .and_then(|_| std::fs::File::open(&path).ok())
                .and_then(|file| {
                    use std::io::Read;
                    let mut contents = Vec::new();
                    file.take(expected.len() as u64 + 1)
                        .read_to_end(&mut contents)
                        .ok()?;
                    Some(contents == expected)
                })
                .unwrap_or(false);
            if !unchanged {
                crate::platform_client::write_json_secure(&path, document)?;
            }
        }
        Ok(directory.join(format!("{}.json", self.entry)))
    }
}

struct Collector {
    bundle: Bundle,
    seen: BTreeMap<String, String>,
    packages: BTreeSet<String>,
}
impl Collector {
    fn collect(
        &mut self,
        source: crate::profile::BaseProfileSource,
        depth: usize,
    ) -> Result<String> {
        if depth > crate::profile::MAX_INHERITANCE_DEPTH {
            return Err(invalid("inheritance depth exceeded"));
        }
        let (identity, document, source_file, package) = match source {
            crate::profile::BaseProfileSource::File { path, package } => {
                let path = path
                    .canonicalize()
                    .map_err(|source| NonoError::ProfileRead {
                        path: path.clone(),
                        source,
                    })?;
                let text =
                    std::fs::read_to_string(&path).map_err(|source| NonoError::ProfileRead {
                        path: path.clone(),
                        source,
                    })?;
                if text.len() > 1024 * 1024 {
                    return Err(invalid("profile exceeds size limit"));
                }
                let document: Value = crate::jsonc::parse(&text).map_err(invalid)?;
                (
                    format!("file:{}", path.display()),
                    document,
                    Some(path),
                    package,
                )
            }
            crate::profile::BaseProfileSource::Embedded(name) => {
                let document = self.bundle.policy["profiles"]
                    .get(&name)
                    .cloned()
                    .ok_or_else(|| invalid("missing built-in base"))?;
                (format!("builtin:{name}"), document, None, None)
            }
        };
        if let Some(package) = package {
            self.packages.insert(package);
        }
        if let Some(id) = self.seen.get(&identity) {
            return Ok(id.clone());
        }
        if self.seen.len() >= 64 {
            return Err(invalid("too many imported profiles"));
        }
        let id = format!("p{}", self.seen.len());
        self.seen.insert(identity, id.clone());
        let mut document = document;
        let mut imports = Vec::new();
        for name in bases(&document)? {
            let source = crate::profile::base_profile_source(
                &name,
                source_file
                    .as_deref()
                    .filter(|path| !crate::profile::is_under_user_profile_draft_dir(path))
                    .and_then(Path::parent),
                source_file.as_deref(),
            )?;
            imports.push(self.collect(source, depth + 1)?);
        }
        if let Some(object) = document.as_object_mut() {
            object.remove("extends");
            if !imports.is_empty() {
                object.insert(
                    "extends".into(),
                    serde_json::to_value(imports).map_err(|e| invalid(e.to_string()))?,
                );
            }
        } else {
            return Err(invalid("profile must be an object"));
        }
        self.bundle.profiles.insert(id.clone(), document);
        Ok(id)
    }
}

pub(crate) fn export(name: &str) -> Result<Bundle> {
    let policy: Value = serde_json::from_str(crate::config::embedded::embedded_policy_json())
        .map_err(|e| invalid(e.to_string()))?;
    let network: Value =
        serde_json::from_str(crate::config::embedded::embedded_network_policy_json())
            .map_err(|e| invalid(e.to_string()))?;
    let mut collector = Collector {
        bundle: Bundle {
            format_version: "1".into(),
            entry: String::new(),
            profiles: BTreeMap::new(),
            policy,
            network,
        },
        seen: BTreeMap::new(),
        packages: BTreeSet::new(),
    };
    let source = if crate::profile::is_file_path_ref(name) {
        crate::profile::BaseProfileSource::File {
            path: PathBuf::from(name),
            package: None,
        }
    } else {
        crate::profile::base_profile_source(name, None, None)?
    };
    collector.bundle.entry = collector.collect(source, 0)?;
    let packages: Vec<String> = collector.packages.into_iter().collect();
    crate::profile_runtime::verify_profile_packs(&packages, &crate::profile::Profile::default())?;
    for package in packages {
        let (namespace, name) = package
            .split_once('/')
            .ok_or_else(|| invalid("invalid package identity"))?;
        let path = crate::package::package_groups_path(namespace, name)?;
        if path.exists() {
            let groups: BTreeMap<String, Value> =
                serde_json::from_str(&std::fs::read_to_string(&path).map_err(|source| {
                    NonoError::ProfileRead {
                        path: path.clone(),
                        source,
                    }
                })?)
                .map_err(|e| invalid(e.to_string()))?;
            let target = collector.bundle.policy["groups"]
                .as_object_mut()
                .ok_or_else(|| invalid("invalid group definitions"))?;
            for (name, group) in groups {
                if target.insert(name.clone(), group).is_some() {
                    return Err(invalid(format!(
                        "package group '{name}' collides with a policy group"
                    )));
                }
            }
        }
    }
    let default = collector.bundle.policy["profiles"]["default"].clone();
    collector.bundle.policy["profiles"] = serde_json::json!({"default":default});
    collector.bundle.validate()?;
    Ok(collector.bundle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};

    fn fixture() -> Bundle {
        let policy: Value =
            serde_json::from_str(crate::config::embedded::embedded_policy_json()).unwrap();
        let network: Value =
            serde_json::from_str(crate::config::embedded::embedded_network_policy_json()).unwrap();
        Bundle {
            format_version: "1".into(),
            entry: "p0".into(),
            profiles: BTreeMap::from([
                (
                    "p0".into(),
                    serde_json::json!({"extends":["p1"],"meta":{"name":"child"}}),
                ),
                (
                    "p1".into(),
                    serde_json::json!({"meta":{"name":"base"},"filesystem":{"read":["$HOME/from-base"]}}),
                ),
            ]),
            policy,
            network,
        }
    }

    #[test]
    fn closed_graph_rejects_external_paths_cycles_and_host_assets() {
        let original = fixture();
        original.validate().unwrap();
        for base in ["../escape", "nolabs-ai/codex", "p0"] {
            let mut bundle = original.clone();
            bundle.profiles.get_mut("p0").unwrap()["extends"] = serde_json::json!([base]);
            assert!(bundle.validate().is_err(), "{base}");
        }
        let mut oversized = original.clone();
        oversized.policy["padding"] = "x".repeat(2 * 1024 * 1024).into();
        assert!(oversized.validate().is_err());
        let mut deep = original.clone();
        for id in 1..=12 {
            deep.profiles.insert(
                format!("p{id}"),
                serde_json::json!({"extends": [format!("p{}", id + 1)]}),
            );
        }
        deep.profiles.insert("p13".into(), serde_json::json!({}));
        assert!(deep.validate().is_err());
        let mut bundle = original.clone();
        bundle
            .profiles
            .insert("../outside".into(), serde_json::json!({}));
        assert!(bundle.validate().is_err());
        for extra in [
            serde_json::json!({"packs":["acme/executable"]}),
            serde_json::json!({"session_hooks":{"before":{"script":"/host"}}}),
            serde_json::json!({"filesystem":{"read":["$PACK_DIR/data"]}}),
        ] {
            let mut bundle = original.clone();
            bundle.profiles.insert("p1".into(), extra);
            assert!(bundle.validate().is_err());
        }
    }

    #[test]
    fn imported_rules_and_custom_groups_work_without_any_local_pack_store() {
        let _guard = ENV_LOCK.lock().unwrap();
        let config = tempfile::tempdir().unwrap();
        let _env = EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", config.path().to_str().unwrap())]);
        let mut bundle = fixture();
        bundle.profiles.get_mut("p1").unwrap()["groups"] =
            serde_json::json!({"include":["remote-only"]});
        bundle.profiles.get_mut("p1").unwrap()["filesystem"] = serde_json::json!({"read":[{"path":"$HOME/mac","when":"macos"},{"path":"$HOME/linux","when":"linux"}]});
        bundle.policy["groups"]["remote-only"] = serde_json::json!({"description":"Bundled group","allow":{"read":["$HOME/remote-only"]}});
        let directory = config.path().join("snapshot");
        let entry = bundle.materialize(&directory).unwrap();
        {
            let _scope = bundle.activate(&directory).unwrap();
            let loaded = crate::profile::load_profile_no_migrate(entry.to_str().unwrap()).unwrap();
            assert!(loaded.packs.is_empty());
            assert!(loaded.extends.is_none());
            assert!(loaded.groups.include.contains(&"remote-only".to_string()));
            assert!(
                crate::policy::load_embedded_policy()
                    .unwrap()
                    .groups
                    .contains_key("remote-only")
            );
            let expected = if cfg!(target_os = "macos") {
                "$HOME/mac"
            } else {
                "$HOME/linux"
            };
            assert!(loaded.filesystem.read.contains(&expected.to_string()));
            assert!(
                bundle.profiles["p1"]["filesystem"]["read"]
                    .as_array()
                    .unwrap()
                    .len()
                    == 2
            );
            assert!(!crate::package::package_store_dir().unwrap().exists());
            std::fs::remove_file(directory.join("p1.json")).unwrap();
            assert!(crate::profile::load_profile_no_migrate(entry.to_str().unwrap()).is_err());
        }
        assert!(current_policy().is_none());
    }

    #[test]
    fn unchanged_snapshots_are_reused_and_modified_files_are_repaired() {
        let home = tempfile::tempdir().unwrap();
        let bundle = fixture();
        let entry = bundle.materialize(home.path()).unwrap();
        let original = std::fs::metadata(&entry).unwrap();
        bundle.materialize(home.path()).unwrap();
        let reused = std::fs::metadata(&entry).unwrap();
        assert_eq!(original.modified().unwrap(), reused.modified().unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(original.ino(), reused.ino());
        }
        std::fs::write(&entry, "{}").unwrap();
        bundle.materialize(home.path()).unwrap();
        let restored: Value = serde_json::from_slice(&std::fs::read(&entry).unwrap()).unwrap();
        assert_eq!(restored, bundle.profiles["p0"]);
        #[cfg(unix)]
        {
            let external = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(external.path(), std::fs::read(&entry).unwrap()).unwrap();
            std::fs::remove_file(&entry).unwrap();
            std::os::unix::fs::symlink(external.path(), &entry).unwrap();
            bundle.materialize(home.path()).unwrap();
            assert!(
                !std::fs::symlink_metadata(&entry)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
    }

    #[test]
    fn collector_captures_raw_registry_inheritance_and_sibling_profiles() {
        let _guard = ENV_LOCK.lock().unwrap();
        let config = tempfile::tempdir().unwrap();
        let _env = EnvVarGuard::set_all(&[
            ("XDG_CONFIG_HOME", config.path().to_str().unwrap()),
            ("NONO_NO_MIGRATE", "1"),
        ]);
        let pack = crate::test_env::write_fake_pack(
            config.path(),
            "acme",
            "base",
            "base",
            r#"{"extends":"sibling","filesystem":{"read":[{"path":"$HOME/mac","when":"macos"},{"path":"$HOME/linux","when":"linux"}]}}"#,
            &[],
            None,
        );
        std::fs::write(
            pack.join("profiles/sibling.json"),
            r#"{"network":{"block":true}}"#,
        )
        .unwrap();
        let root = config.path().join("root.json");
        std::fs::write(&root, r#"{"extends":"acme/base"}"#).unwrap();
        let mut collector = Collector {
            bundle: fixture(),
            seen: BTreeMap::new(),
            packages: BTreeSet::new(),
        };
        collector.bundle.profiles.clear();
        collector.bundle.entry = collector
            .collect(
                crate::profile::BaseProfileSource::File {
                    path: root,
                    package: None,
                },
                0,
            )
            .unwrap();
        assert_eq!(collector.bundle.profiles.len(), 3);
        assert_eq!(
            collector.bundle.profiles["p1"]["filesystem"]["read"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(collector.packages, BTreeSet::from(["acme/base".into()]));
        collector.bundle.validate().unwrap();
    }
}
