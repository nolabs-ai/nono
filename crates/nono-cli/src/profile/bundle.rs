//! Preserve source predicates until the requesting device resolves its policy.
use super::{
    MAX_INHERITANCE_DEPTH, Profile, ResolvedBase, load_base_profile_raw, parse_profile_bytes,
    resolve_extends_with,
};
use nono::{NonoError, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(crate) mod files;

#[derive(Debug, Clone)]
pub(crate) struct ManagedProfile {
    pub profile: Profile,
    pub policy: crate::policy::Policy,
}

impl ManagedProfile {
    pub(crate) fn from_sources(sources: &PolicySources) -> Result<Self> {
        let (profile, policy) = parse_sources(sources)?;
        let profile = super::finalize_profile_with_policy(profile, &policy)?;
        Ok(Self { profile, policy })
    }
}

pub(crate) struct PolicySources {
    root: serde_json::Value,
    profiles: BTreeMap<String, serde_json::Value>,
    groups: BTreeMap<String, serde_json::Value>,
}

#[derive(Default)]
struct Collector {
    profiles: BTreeMap<String, serde_json::Value>,
    sources: BTreeMap<String, String>,
    stack: Vec<String>,
    packs: BTreeSet<String>,
    files: BTreeMap<String, Vec<u8>>,
}

fn read_document(path: &Path) -> Result<serde_json::Value> {
    let text = std::fs::read_to_string(path).map_err(|source| NonoError::ProfileRead {
        path: path.to_path_buf(),
        source,
    })?;
    crate::jsonc::parse(&text).map_err(NonoError::ProfileParse)
}

fn parse_profile(value: &serde_json::Value) -> Result<Profile> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| NonoError::ProfileParse(error.to_string()))?;
    parse_profile_bytes(&bytes)
}

impl Collector {
    fn include_declared_packs(&mut self, profile: &Profile) -> Result<()> {
        for pack in &profile.packs {
            self.include_pack(pack)?;
        }
        if let Some(overrides) = &profile.platform_overrides {
            for profile in [&overrides.macos, &overrides.linux, &overrides.windows]
                .into_iter()
                .flatten()
            {
                self.include_declared_packs(&profile.0)?;
            }
        }
        Ok(())
    }

    fn include_pack(&mut self, name: &str) -> Result<()> {
        let package = crate::package::parse_package_ref(name)?;
        if package.version.is_some() {
            return Err(NonoError::ProfileParse(format!(
                "versioned pack references are not supported: {name:?}"
            )));
        }
        if self.packs.insert(package.key()) {
            files::collect_pack(&package, &mut self.files)?;
        }
        Ok(())
    }

    fn collect(
        &mut self,
        mut document: serde_json::Value,
        source: Option<&Path>,
    ) -> Result<serde_json::Value> {
        let raw = parse_profile(&document)?;
        self.include_declared_packs(&raw)?;
        if self.stack.len() >= MAX_INHERITANCE_DEPTH {
            return Err(NonoError::ProfileInheritance(
                "delivered inheritance is too deep".into(),
            ));
        }
        let mut references = Vec::new();
        for name in raw.extends.unwrap_or_default() {
            let (base, base_path, identity) =
                match load_base_profile_raw(&name, source.and_then(Path::parent), source)? {
                    ResolvedBase::Sibling(_, path) => {
                        if super::is_registry_ref(&name) {
                            self.include_pack(&name)?;
                        }
                        let document = read_document(&path)?;
                        let identity = path.to_string_lossy().into_owned();
                        (document, Some(path), identity)
                    }
                    ResolvedBase::Global(_) => {
                        let embedded: serde_json::Value =
                            crate::jsonc::parse(crate::config::embedded::embedded_policy_json())
                                .map_err(NonoError::ProfileParse)?;
                        let base = embedded["profiles"]
                            .get(&name)
                            .cloned()
                            .ok_or_else(|| NonoError::ProfileNotFound(name.clone()))?;
                        (base, None, format!("builtin:{name}"))
                    }
                };
            if self.stack.contains(&identity) {
                return Err(NonoError::ProfileInheritance(
                    "circular delivered inheritance".into(),
                ));
            }
            let reference = if let Some(reference) = self.sources.get(&identity) {
                reference.clone()
            } else {
                let reference = format!("profile-{}", self.sources.len());
                self.sources.insert(identity.clone(), reference.clone());
                self.stack.push(identity);
                let base = self.collect(base, base_path.as_deref())?;
                self.stack.pop();
                self.profiles.insert(reference.clone(), base);
                reference
            };
            references.push(reference);
        }
        let object = document
            .as_object_mut()
            .ok_or_else(|| NonoError::ProfileParse("profile must be an object".into()))?;
        object.remove("packs");
        if let Some(overrides) = object
            .get_mut("platform_overrides")
            .and_then(serde_json::Value::as_object_mut)
        {
            for profile in overrides
                .values_mut()
                .filter_map(serde_json::Value::as_object_mut)
            {
                profile.remove("packs");
            }
        }
        if references.is_empty() {
            object.remove("extends");
        } else {
            object.insert("extends".into(), serde_json::json!(references));
        }
        Ok(document)
    }
}

fn collect_group_names(value: &serde_json::Value, names: &mut std::collections::BTreeSet<String>) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(groups) = object.get("groups").and_then(serde_json::Value::as_object) {
                for key in ["include", "exclude"] {
                    if let Some(items) = groups.get(key).and_then(serde_json::Value::as_array) {
                        for item in items {
                            if let Some(name) = item
                                .as_str()
                                .or_else(|| item.get("name").and_then(serde_json::Value::as_str))
                            {
                                names.insert(name.to_string());
                            }
                        }
                    }
                }
            }
            for item in object.values() {
                collect_group_names(item, names);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_group_names(item, names);
            }
        }
        _ => {}
    }
}

fn collect_sources(path: &Path) -> Result<(PolicySources, BTreeMap<String, Vec<u8>>)> {
    let source = path
        .canonicalize()
        .map_err(|error| NonoError::ProfileParse(error.to_string()))?;
    let mut collector = Collector::default();
    let root = collector.collect(read_document(&source)?, Some(&source))?;
    let mut names = std::collections::BTreeSet::new();
    collect_group_names(&root, &mut names);
    for profile in collector.profiles.values() {
        collect_group_names(profile, &mut names);
    }
    let groups = crate::policy::package_group_documents()?
        .into_iter()
        .filter(|(name, _)| names.contains(name))
        .collect();
    let bundle = PolicySources {
        root,
        profiles: collector.profiles,
        groups,
    };
    // Check references using the same resolver the device uses, without finalizing its OS policy.
    resolve(&bundle)?;
    Ok((bundle, collector.files))
}

fn resolve(bundle: &PolicySources) -> Result<Profile> {
    let root = parse_profile(&bundle.root)?;
    let mut loader = |name: &str, _: Option<&Path>, _: Option<&Path>| {
        let document = bundle.profiles.get(name).ok_or_else(|| {
            NonoError::ProfileInheritance(format!("missing delivered base '{name}'"))
        })?;
        parse_profile(document).map(ResolvedBase::Global)
    };
    let mut profile = resolve_extends_with(root, &mut Vec::new(), 0, None, None, &mut loader)?;
    if !profile.packs.is_empty() {
        return Err(NonoError::ProfileParse(
            "delivered policy contains runtime package dependencies".into(),
        ));
    }
    disable_hooks(&mut profile);
    Ok(profile)
}

/// Delivered hook declarations and files are retained as authenticated content.
/// Keep them out of the runtime profile until managed hook execution and wiring
/// have their own activation contract. This never changes the signed sources.
fn disable_hooks(profile: &mut Profile) {
    profile.hooks = Default::default();
    profile.session_hooks = Default::default();
    if let Some(overrides) = &mut profile.platform_overrides {
        for item in [
            &mut overrides.macos,
            &mut overrides.linux,
            &mut overrides.windows,
        ]
        .into_iter()
        .flatten()
        {
            disable_hooks(&mut item.0);
        }
    }
}

pub(crate) fn parse_sources(sources: &PolicySources) -> Result<(Profile, crate::policy::Policy)> {
    let profile = resolve(sources)?;
    let policy = crate::policy::delivered_policy(&sources.groups)?;
    Ok((profile, policy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_ext::CapabilitySetExt;
    use serde_json::json;

    fn sources(value: serde_json::Value) -> PolicySources {
        PolicySources {
            root: value["root"].clone(),
            profiles: serde_json::from_value(value["profiles"].clone()).expect("profiles"),
            groups: serde_json::from_value(value["groups"].clone()).expect("groups"),
        }
    }

    #[test]
    fn delivered_hooks_are_retained_in_sources_but_disabled_for_managed_launches() {
        let _lock = crate::test_env::ENV_LOCK.lock().expect("environment lock");
        let hooks = json!({"claude":{"event":"PreToolUse","matcher":"Bash","script":"hook.sh"}});
        let session_hooks = json!({
            "before":{"script":"$PACK_DIR/bin/before.sh"},
            "after":{"script":"$PACK_DIR/bin/after.sh"}
        });
        for inherited in [false, true] {
            let fragment = json!({"hooks":hooks,"session_hooks":session_hooks});
            let mut document = fragment.clone();
            document["platform_overrides"] = json!({
                "linux":fragment,"macos":fragment,"windows":fragment
            });
            let bundle = sources(if inherited {
                json!({"root":{"extends":"base"},"profiles":{"base":document},"groups":{}})
            } else {
                json!({"root":document,"profiles":{},"groups":{}})
            });
            let source = if inherited {
                &bundle.profiles["base"]
            } else {
                &bundle.root
            };
            let original = source.clone();
            let local = parse_profile(source).expect("local profile retains hooks");
            assert!(!local.hooks.hooks.is_empty());
            assert!(local.session_hooks.before.is_some());
            assert!(local.session_hooks.after.is_some());

            let (profile, _) = parse_sources(&bundle).expect("inert delivered profile");
            let assert_disabled = |profile: &Profile| {
                assert!(profile.hooks.hooks.is_empty());
                assert!(profile.session_hooks.before.is_none());
                assert!(profile.session_hooks.after.is_none());
            };
            assert_disabled(&profile);
            let overrides = profile.platform_overrides.as_ref().expect("OS overrides");
            for item in [&overrides.linux, &overrides.macos, &overrides.windows] {
                assert_disabled(&item.as_ref().expect("OS profile").0);
            }
            let managed = ManagedProfile::from_sources(&bundle).expect("managed runtime profile");
            assert_disabled(&managed.profile);
            assert_eq!(
                *source, original,
                "signed hook declarations must stay intact"
            );
        }
    }

    #[test]
    fn delivered_groups_are_isolated_between_launches_and_local_policy() {
        let _lock = crate::test_env::ENV_LOCK.lock().expect("environment lock");
        // Linux's default groups grant /tmp, so deny targets must live elsewhere.
        let root = tempfile::Builder::new()
            .prefix("managed-groups-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("root");
        let first = root.path().join("first");
        let second = root.path().join("second");
        std::fs::write(&first, "first").expect("first");
        std::fs::write(&second, "second").expect("second");
        let prepare = |path: &Path| {
            ManagedProfile::from_sources(&sources(json!({
                "root": {"meta":{"name":"managed"}, "groups":{"include":["launch-scope"]}},
                "profiles": {},
                "groups": {"launch-scope":{"description":"launch-specific deny", "deny":{"access":[path]}}}
            }))).expect("managed profile")
        };
        let first_profile = prepare(&first);
        let second_profile = prepare(&second);
        for (managed, denied, other) in [
            (&first_profile, &first, &second),
            (&second_profile, &second, &first),
            (&first_profile, &first, &second),
        ] {
            let args = crate::cli::SandboxArgs {
                managed_profile: Some(managed.clone()),
                ..Default::default()
            };
            let prepared = nono::CapabilitySet::from_profile(&managed.profile, root.path(), &args)
                .expect("capabilities");
            assert!(prepared.deny_paths.contains(denied));
            assert!(!prepared.deny_paths.contains(other));
            assert!(
                !crate::policy::load_embedded_policy()
                    .expect("local policy")
                    .groups
                    .contains_key("launch-scope")
            );
        }
    }

    #[test]
    fn delivered_required_groups_cannot_be_excluded() {
        let text = json!({
            "root": {"meta":{"name":"managed"}, "groups":{"exclude":["tenant-required"]}},
            "profiles": {},
            "groups": {"tenant-required":{"description":"required", "required":true}}
        })
        .to_string();
        assert!(
            ManagedProfile::from_sources(&sources(serde_json::from_str(&text).expect("source")))
                .expect_err("required group")
                .to_string()
                .contains("tenant-required")
        );
    }

    #[test]
    fn delivered_sources_evaluate_predicates_only_on_the_device() {
        let text = json!({
            "root": {"meta":{"name":"root"}, "extends":"base", "groups":{"include":["delivered-test"]}},
            "profiles": {"base":{"meta":{"name":"base"},"filesystem":{"read":[
                {"path":"$HOME/linux-only","when":"linux"},
                {"path":"$HOME/mac-only","when":"macos"}
            ]}}},
            "groups": {"delivered-test":{"description":"fixture", "allow":{"read":["$HOME/shared"]}}}
        }).to_string();
        let (profile, groups) =
            parse_sources(&sources(serde_json::from_str(&text).expect("source")))
                .expect("delivered source");
        if cfg!(target_os = "linux") {
            assert_eq!(profile.filesystem.read, ["$HOME/linux-only"]);
        }
        if cfg!(target_os = "macos") {
            assert_eq!(profile.filesystem.read, ["$HOME/mac-only"]);
        }
        assert_eq!(
            groups.groups["delivered-test"]
                .allow
                .as_ref()
                .expect("allow")
                .read,
            ["$HOME/shared"]
        );
    }

    #[test]
    fn missing_or_cyclic_bases_never_fall_back_to_builtin_profiles() {
        let mut bundle = json!({"root":{"extends":"default"},"profiles":{},"groups":{}});
        assert!(parse_sources(&sources(bundle.clone())).is_err());
        bundle["profiles"]["default"] = json!({"extends":"default"});
        assert!(parse_sources(&sources(bundle.clone())).is_err());
    }

    #[test]
    fn delivered_groups_cannot_replace_builtin_protections() {
        let embedded: serde_json::Value =
            serde_json::from_str(crate::config::embedded::embedded_policy_json())
                .expect("embedded");
        let name = embedded["groups"]
            .as_object()
            .expect("groups")
            .keys()
            .next()
            .expect("built-in");
        let mut groups = serde_json::Map::new();
        groups.insert(name.clone(), json!({"description":"replacement"}));
        let bundle = json!({"root":{"meta":{"name":"fixture"}},"profiles":{},"groups":groups});
        assert!(parse_sources(&sources(bundle.clone())).is_err());
    }
}
