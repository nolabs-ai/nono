//! Comment-preserving edits to profile files on disk.
//!
//! The save prompt updates an existing profile by appending grants. Editing
//! the concrete syntax tree keeps the user's comments and formatting, which a
//! `serde_json` round trip would discard.

use crate::profile;
use jsonc_parser::ParseOptions;
use jsonc_parser::cst::{CstInputValue, CstObject, CstRootNode};
use nono::{NonoError, Result};
use std::collections::HashSet;

type PatchValues = fn(&profile::Profile) -> &[String];

/// The string lists `merge_profile_patch` dedup-appends, as
/// (parent object key or `None` for the root, array key, patch accessor).
/// `open_urls.allow_localhost` is a bool and is handled separately.
const PATCHED_LISTS: &[(Option<&str>, &str, PatchValues)] = &[
    (Some("filesystem"), "allow", |p| &p.filesystem.allow),
    (Some("filesystem"), "read", |p| &p.filesystem.read),
    (Some("filesystem"), "write", |p| &p.filesystem.write),
    (Some("filesystem"), "allow_file", |p| {
        &p.filesystem.allow_file
    }),
    (Some("filesystem"), "read_file", |p| &p.filesystem.read_file),
    (Some("filesystem"), "write_file", |p| {
        &p.filesystem.write_file
    }),
    (Some("filesystem"), "bypass_protection", |p| {
        &p.filesystem.bypass_protection
    }),
    (Some("filesystem"), "suppress_save_prompt", |p| {
        &p.filesystem.suppress_save_prompt
    }),
    (None, "unsafe_macos_seatbelt_rules", |p| {
        &p.unsafe_macos_seatbelt_rules
    }),
    (Some("open_urls"), "allow_origins", |p| {
        p.open_urls.as_ref().map_or(&[], |urls| &urls.allow_origins)
    }),
];

/// Append the grants in `patch` to the profile source `text`, keeping
/// comments and formatting. Mirrors `merge_profile_patch`: list values not
/// already present are appended, and `allow_localhost` only flips to `true`.
pub(crate) fn apply_patch_to_profile_text(text: &str, patch: &profile::Profile) -> Result<String> {
    let root = CstRootNode::parse(text, &ParseOptions::default())
        .map_err(|e| NonoError::LearnError(format!("Failed to parse profile: {e}")))?;
    let root_object = root
        .object_value_or_create()
        .ok_or_else(|| NonoError::LearnError("Profile root is not an object".to_string()))?;

    for (section, key, patch_values) in PATCHED_LISTS {
        let values = patch_values(patch);
        if values.is_empty() {
            continue;
        }
        let parent = match section {
            Some(section) => section_object(&root_object, section)?,
            None => root_object.clone(),
        };
        let array = parent.array_value_or_create(key).ok_or_else(|| {
            let path = section.map_or(key.to_string(), |s| format!("{s}.{key}"));
            NonoError::LearnError(format!("Profile field `{path}` is not an array"))
        })?;
        let mut present: HashSet<String> = array
            .elements()
            .iter()
            .filter_map(|node| node.as_string_lit()?.decoded_value().ok())
            .collect();
        for value in values {
            if present.insert(value.clone()) {
                array.append(value.as_str().into());
            }
        }
    }

    if patch
        .open_urls
        .as_ref()
        .is_some_and(|urls| urls.allow_localhost)
    {
        let open_urls = section_object(&root_object, "open_urls")?;
        match open_urls.get("allow_localhost") {
            Some(prop) => prop.set_value(CstInputValue::Bool(true)),
            None => {
                open_urls.append("allow_localhost", CstInputValue::Bool(true));
            }
        }
    }

    Ok(root.to_string())
}

fn section_object(root: &CstObject, section: &str) -> Result<CstObject> {
    root.object_value_or_create(section)
        .ok_or_else(|| NonoError::LearnError(format!("Profile field `{section}` is not an object")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_save_runtime::merge_profile_patch;

    fn parse(text: &str) -> profile::Profile {
        profile::parse_profile_bytes(text.as_bytes()).expect("parse profile")
    }

    fn patch_with_read(paths: &[&str]) -> profile::Profile {
        let mut patch = profile::Profile::default();
        patch.filesystem.read = paths.iter().map(|p| p.to_string()).collect();
        patch
    }

    fn localhost_patch(allow_localhost: bool) -> profile::Profile {
        profile::Profile {
            open_urls: Some(profile::OpenUrlConfig {
                allow_origins: Vec::new(),
                allow_localhost,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn keeps_comments_and_appends_new_entries() {
        let input = r#"{
  // keep me
  "meta": { "name": "x" },
  "filesystem": {
    // keep me too
    "read": ["/a"]
  }
}
"#;
        let output = apply_patch_to_profile_text(input, &patch_with_read(&["/a", "/b"]))
            .expect("apply patch");

        assert!(output.contains("// keep me\n"), "output: {output}");
        assert!(output.contains("// keep me too"), "output: {output}");
        assert_eq!(output.matches("\"/a\"").count(), 1, "output: {output}");
        assert_eq!(output.matches("\"/b\"").count(), 1, "output: {output}");
        assert_eq!(parse(&output).filesystem.read, vec!["/a", "/b"]);
    }

    #[test]
    fn creates_missing_sections() {
        let input = r#"{ "meta": { "name": "x" } }"#;
        let mut patch = profile::Profile::default();
        patch.filesystem.read_file = vec!["/f".to_string()];
        patch.open_urls = Some(profile::OpenUrlConfig {
            allow_origins: vec!["https://example.com".to_string()],
            allow_localhost: false,
        });

        let output = apply_patch_to_profile_text(input, &patch).expect("apply patch");
        let parsed = parse(&output);

        assert_eq!(parsed.filesystem.read_file, vec!["/f"]);
        assert_eq!(
            parsed.open_urls.expect("open_urls").allow_origins,
            vec!["https://example.com"]
        );
    }

    #[test]
    fn appends_to_empty_inline_array() {
        let input = r#"{ "meta": { "name": "x" }, "filesystem": { "read": [] } }"#;
        let output =
            apply_patch_to_profile_text(input, &patch_with_read(&["/a"])).expect("apply patch");

        assert_eq!(parse(&output).filesystem.read, vec!["/a"]);
    }

    #[test]
    fn allow_localhost_only_flips_to_true() {
        let input_false =
            r#"{ "meta": { "name": "x" }, "open_urls": { "allow_localhost": false } }"#;
        let output =
            apply_patch_to_profile_text(input_false, &localhost_patch(true)).expect("apply patch");
        assert!(parse(&output).open_urls.expect("open_urls").allow_localhost);

        let input_true = r#"{ "meta": { "name": "x" }, "open_urls": { "allow_localhost": true } }"#;
        let output =
            apply_patch_to_profile_text(input_true, &localhost_patch(false)).expect("apply patch");
        assert!(parse(&output).open_urls.expect("open_urls").allow_localhost);
    }

    #[test]
    fn matches_merge_profile_patch() {
        let input = r#"{
  // comment
  "meta": { "name": "x" },
  "filesystem": {
    "allow": ["/allow-old"],
    "read": ["/read-old"],
    "bypass_protection": ["/bp-old"]
  },
  "unsafe_macos_seatbelt_rules": ["(allow old)"],
  "open_urls": { "allow_origins": ["https://old.example.com"] }
}
"#;

        let mut filesystem_lists = profile::Profile::default();
        filesystem_lists.filesystem.allow =
            vec!["/allow-old".to_string(), "/allow-new".to_string()];
        filesystem_lists.filesystem.read = vec!["/read-new".to_string()];
        filesystem_lists.filesystem.write = vec!["/write-new".to_string()];
        filesystem_lists.filesystem.allow_file = vec!["/af".to_string()];
        filesystem_lists.filesystem.read_file = vec!["/rf".to_string()];
        filesystem_lists.filesystem.write_file = vec!["/wf".to_string()];
        filesystem_lists.filesystem.suppress_save_prompt = vec!["/quiet".to_string()];

        let mut bypass = profile::Profile::default();
        bypass.filesystem.bypass_protection = vec!["/bp-old".to_string(), "/bp-new".to_string()];

        let seatbelt = profile::Profile {
            unsafe_macos_seatbelt_rules: vec!["(allow old)".to_string(), "(allow new)".to_string()],
            ..Default::default()
        };

        let open_urls = profile::Profile {
            open_urls: Some(profile::OpenUrlConfig {
                allow_origins: vec![
                    "https://old.example.com".to_string(),
                    "https://new.example.com".to_string(),
                ],
                allow_localhost: true,
            }),
            ..Default::default()
        };

        for patch in [filesystem_lists, bypass, seatbelt, open_urls] {
            let output = apply_patch_to_profile_text(input, &patch).expect("apply patch");
            let mut expected = parse(input);
            merge_profile_patch(&mut expected, &patch);

            assert_eq!(
                serde_json::to_value(parse(&output)).expect("serialize output"),
                serde_json::to_value(expected).expect("serialize expected"),
                "output: {output}"
            );
        }
    }

    #[test]
    fn non_object_section_errors() {
        let input = r#"{ "meta": { "name": "x" }, "filesystem": [] }"#;
        let result = apply_patch_to_profile_text(input, &patch_with_read(&["/a"]));

        assert!(result.is_err(), "expected error, got {result:?}");
    }
}
