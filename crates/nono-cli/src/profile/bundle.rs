//! Preserve source predicates until the requesting device resolves its policy.
use super::{
    MAX_INHERITANCE_DEPTH, Profile, ResolvedBase, load_base_profile_raw, parse_profile_bytes,
    resolve_extends_with, validate_delivered_profile,
};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileBundle {
    root: serde_json::Value,
    profiles: BTreeMap<String, serde_json::Value>,
    groups: BTreeMap<String, serde_json::Value>,
}

#[derive(Default)]
struct Collector {
    profiles: BTreeMap<String, serde_json::Value>,
    sources: BTreeMap<String, String>,
    stack: Vec<String>,
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
    fn collect(
        &mut self,
        mut document: serde_json::Value,
        source: Option<&Path>,
    ) -> Result<serde_json::Value> {
        let raw = parse_profile(&document)?;
        validate_delivered_profile(&raw)?;
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

pub(crate) fn export(path: &Path) -> Result<ProfileBundle> {
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
    let bundle = ProfileBundle {
        root,
        profiles: collector.profiles,
        groups,
    };
    // Check references using the same resolver the device uses, without finalizing its OS policy.
    resolve(&bundle)?;
    Ok(bundle)
}

fn resolve(bundle: &ProfileBundle) -> Result<Profile> {
    let root = parse_profile(&bundle.root)?;
    let mut loader = |name: &str, _: Option<&Path>, _: Option<&Path>| {
        let document = bundle.profiles.get(name).ok_or_else(|| {
            NonoError::ProfileInheritance(format!("missing delivered base '{name}'"))
        })?;
        parse_profile(document).map(ResolvedBase::Global)
    };
    let profile = resolve_extends_with(root, &mut Vec::new(), 0, None, None, &mut loader)?;
    if !profile.packs.is_empty() {
        return Err(NonoError::ProfileParse(
            "delivered policy contains runtime package dependencies".into(),
        ));
    }
    validate_delivered_profile(&profile)?;
    Ok(profile)
}

pub(crate) fn parse_delivered(
    text: &str,
) -> Result<(Profile, BTreeMap<String, serde_json::Value>)> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|error| NonoError::ProfileParse(error.to_string()))?;
    let bundle = if value.get("root").is_some() {
        serde_json::from_value::<ProfileBundle>(value)
            .map_err(|error| NonoError::ProfileParse(error.to_string()))?
    } else {
        ProfileBundle {
            root: value,
            profiles: BTreeMap::new(),
            groups: BTreeMap::new(),
        }
    };
    let profile = resolve(&bundle)?;
    crate::policy::validate_delivered_groups(&bundle.groups)?;
    Ok((profile, bundle.groups))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        let (profile, groups) = parse_delivered(&text).expect("delivered source");
        if cfg!(target_os = "linux") {
            assert_eq!(profile.filesystem.read, ["$HOME/linux-only"]);
        }
        if cfg!(target_os = "macos") {
            assert_eq!(profile.filesystem.read, ["$HOME/mac-only"]);
        }
        assert_eq!(groups["delivered-test"]["allow"]["read"][0], "$HOME/shared");
    }

    #[test]
    fn missing_or_cyclic_bases_never_fall_back_to_builtin_profiles() {
        let mut bundle = json!({"root":{"extends":"default"},"profiles":{},"groups":{}});
        assert!(parse_delivered(&bundle.to_string()).is_err());
        bundle["profiles"]["default"] = json!({"extends":"default"});
        assert!(parse_delivered(&bundle.to_string()).is_err());
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
        assert!(parse_delivered(&bundle.to_string()).is_err());
    }
}
