//! Profile subcommand implementations
//!
//! Handles `nono profile init|list|show|diff|validate|groups|schema|guide`:
//! creation, inspection, comparison, validation, and documentation of
//! nono profiles and the group-based policy rules they reference.

use crate::cli::{
    ProfileCmdArgs, ProfileCommands, ProfileDiffArgs, ProfileGroupsArgs, ProfileGuideArgs,
    ProfileInitArgs, ProfileListArgs, ProfilePromoteArgs, ProfileSchemaArgs, ProfileShowArgs,
    ProfileValidateArgs,
};
use crate::config::embedded;
use crate::policy::{self, AllowOps, DenyOps, Group};
use crate::profile::{self, Profile, WorkdirAccess};
use crate::theme;
use colored::Colorize;
use nono::{NonoError, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Serialize a value to pretty-printed JSON, propagating serialization errors.
fn to_json(val: &serde_json::Value) -> Result<String> {
    serde_json::to_string_pretty(val)
        .map_err(|e| NonoError::ProfileParse(format!("JSON serialization failed: {e}")))
}

/// Prefix used for all profile command output
fn prefix() -> colored::ColoredString {
    let t = theme::current();
    theme::fg("nono profile", t.brand).bold()
}

/// Dispatch to the appropriate profile subcommand.
pub fn run_profile(args: ProfileCmdArgs) -> Result<()> {
    match args.command {
        ProfileCommands::Init(args) => cmd_init(args),
        ProfileCommands::List(args) => cmd_list(args),
        ProfileCommands::Show(args) => cmd_show(args),
        ProfileCommands::Diff(args) => cmd_diff(args),
        ProfileCommands::Validate(args) => cmd_validate(args),
        ProfileCommands::Promote(args) => cmd_promote(args),
        ProfileCommands::Groups(args) => cmd_groups(args),
        ProfileCommands::Schema(args) => cmd_schema(args),
        ProfileCommands::Guide(args) => cmd_guide(args),
    }
}

// ---------------------------------------------------------------------------
// nono profile init
// ---------------------------------------------------------------------------

fn cmd_init(args: ProfileInitArgs) -> Result<()> {
    // If the name looks like an org/pack reference, check whether it matches
    // an installed pack before falling through to the generic name-validation
    // error — this gives the user actionable guidance.
    if profile::is_registry_ref(&args.name) {
        let short_name = args
            .name
            .split_once('/')
            .map_or(args.name.as_str(), |(_, n)| n);
        let suggested = format!("{}-local", short_name);
        let extends_target = args.extends.as_deref().unwrap_or(args.name.as_str());
        crate::output::print_warning(&format!(
            "'{}' is a pack reference, not a profile name. \
             Choose a plain name for your profile.",
            args.name
        ));
        let t = theme::current();
        eprintln!(
            "  {} nono profile init {} --extends {}",
            theme::fg("Try:", t.green).bold(),
            suggested,
            extends_target
        );
        return Err(NonoError::Cancelled(String::new()));
    }

    // Validate profile name
    if !profile::is_valid_profile_name(&args.name) {
        return Err(NonoError::ProfileParse(format!(
            "Invalid profile name '{}': must be alphanumeric with hyphens, no leading/trailing hyphens",
            args.name
        )));
    }

    // Determine output path
    let output_path = match &args.output {
        Some(path) => path.clone(),
        None => profile::get_user_profile_path(&args.name)?,
    };

    // Check for existing file
    if output_path.exists() && !args.force {
        return Err(NonoError::ProfileParse(format!(
            "Profile file already exists: {}\nUse --force to overwrite",
            output_path.display()
        )));
    }

    // Block names that match an embedded built-in profile. Pack profiles use
    // `org/name` keys (e.g. `always-further/hermes`), which are invalid as
    // profile names, so a short name like `hermes` cannot shadow a pack.
    {
        let pol = policy::load_embedded_policy()?;
        if pol.profiles.contains_key(args.name.as_str()) {
            crate::output::print_warning(&format!(
                "Cannot create profile '{}': it conflicts with the built-in '{}' profile.",
                args.name, args.name
            ));
            let t = theme::current();
            eprintln!(
                "  {} nono profile init {}-local --extends {}",
                theme::fg("Try:", t.green).bold(),
                args.name,
                args.name
            );
            return Err(NonoError::Cancelled(String::new()));
        }
    }

    // Validate --extends target exists in any of the three sources the
    // resolver knows about (user dir, pack store, built-in).
    if let Some(ref base) = args.extends
        && !profile_exists(base)
    {
        return Err(NonoError::ProfileParse(extends_target_not_found_message(
            base,
        )));
    }

    // Validate --groups against embedded policy
    if !args.groups.is_empty() {
        let pol = policy::load_embedded_policy()?;
        for group in &args.groups {
            if !pol.groups.contains_key(group.as_str()) {
                return Err(NonoError::ProfileParse(format!(
                    "Unknown security group '{}'. Use `nono profile groups` to list available groups",
                    group
                )));
            }
        }
    }

    // Build skeleton JSON
    let skeleton = build_skeleton(&args);

    // Ensure parent directory exists
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            NonoError::ProfileParse(format!(
                "Failed to create directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    // Write file
    let json = serde_json::to_string_pretty(&skeleton)
        .map_err(|e| NonoError::ProfileParse(format!("JSON serialization failed: {e}")))?;

    fs::write(&output_path, format!("{json}\n")).map_err(|e| {
        NonoError::ProfileParse(format!(
            "Failed to write profile to {}: {}",
            output_path.display(),
            e
        ))
    })?;

    eprintln!(
        "{} Created profile at {}",
        prefix(),
        output_path.display().to_string().bold()
    );
    eprintln!(
        "{} Validate with: nono profile validate {}",
        prefix(),
        profile_validate_target(&args, &output_path)
    );
    eprintln!(
        "{} For editor autocomplete: nono profile schema -o nono-profile.schema.json",
        prefix()
    );

    Ok(())
}

fn profile_validate_target(args: &ProfileInitArgs, output_path: &Path) -> String {
    match profile::get_user_profile_path(&args.name) {
        Ok(default_path) if default_path == output_path => args.name.clone(),
        _ => output_path.display().to_string(),
    }
}

/// Build a skeleton profile JSON value with controlled field ordering.
fn build_skeleton(args: &ProfileInitArgs) -> serde_json::Value {
    let mut root = serde_json::Map::new();

    if let Some(ref base) = args.extends {
        root.insert(
            "extends".to_string(),
            serde_json::Value::String(base.clone()),
        );
    }

    // meta
    let mut meta = serde_json::Map::new();
    meta.insert(
        "name".to_string(),
        serde_json::Value::String(args.name.clone()),
    );
    if let Some(ref desc) = args.description {
        meta.insert(
            "description".to_string(),
            serde_json::Value::String(desc.clone()),
        );
    }
    root.insert("meta".to_string(), serde_json::Value::Object(meta));

    // groups (canonical: top-level include/exclude pair)
    let mut groups = serde_json::Map::new();
    let include: Vec<serde_json::Value> = args
        .groups
        .iter()
        .map(|g| serde_json::Value::String(g.clone()))
        .collect();
    groups.insert("include".to_string(), serde_json::Value::Array(include));
    if args.full {
        groups.insert("exclude".to_string(), serde_json::Value::Array(vec![]));
    }
    root.insert("groups".to_string(), serde_json::Value::Object(groups));

    // commands (only included with --full; allow/deny are deprecated since
    // v0.33.0 but remain the canonical home for command gating until removed).
    if args.full {
        let mut commands = serde_json::Map::new();
        commands.insert("allow".to_string(), serde_json::Value::Array(vec![]));
        commands.insert("deny".to_string(), serde_json::Value::Array(vec![]));
        root.insert("commands".to_string(), serde_json::Value::Object(commands));
    }

    // workdir
    let mut workdir = serde_json::Map::new();
    workdir.insert(
        "access".to_string(),
        serde_json::Value::String("readwrite".to_string()),
    );
    root.insert("workdir".to_string(), serde_json::Value::Object(workdir));

    // filesystem (minimal has allow + read; full adds all fields, including
    // the canonical replacements for the legacy `policy` patch keys —
    // see deprecated_schema.rs for the migration mapping).
    let mut filesystem = serde_json::Map::new();
    filesystem.insert("allow".to_string(), serde_json::Value::Array(vec![]));
    filesystem.insert("read".to_string(), serde_json::Value::Array(vec![]));
    if args.full {
        filesystem.insert("write".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("allow_file".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("read_file".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("write_file".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("deny".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert(
            "bypass_protection".to_string(),
            serde_json::Value::Array(vec![]),
        );
        filesystem.insert(
            "suppress_save_prompt".to_string(),
            serde_json::Value::Array(vec![]),
        );
    }
    root.insert(
        "filesystem".to_string(),
        serde_json::Value::Object(filesystem),
    );

    // Full skeleton adds additional sections
    if args.full {
        // network
        // NOTE: network_profile is intentionally omitted. Emitting null would
        // clear an inherited proxy profile (e.g., "developer" from python-dev),
        // silently broadening network access. Absent = inherit from base.
        let mut network = serde_json::Map::new();
        network.insert("block".to_string(), serde_json::Value::Bool(false));
        network.insert("allow_domain".to_string(), serde_json::Value::Array(vec![]));
        network.insert("credentials".to_string(), serde_json::Value::Array(vec![]));
        network.insert("open_port".to_string(), serde_json::Value::Array(vec![]));
        network.insert("listen_port".to_string(), serde_json::Value::Array(vec![]));
        network.insert(
            "custom_credentials".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
        root.insert("network".to_string(), serde_json::Value::Object(network));

        // env_credentials
        root.insert(
            "env_credentials".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );

        // hooks
        root.insert(
            "hooks".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );

        // rollback
        let mut rollback = serde_json::Map::new();
        rollback.insert(
            "exclude_patterns".to_string(),
            serde_json::Value::Array(vec![]),
        );
        rollback.insert(
            "exclude_globs".to_string(),
            serde_json::Value::Array(vec![]),
        );
        root.insert("rollback".to_string(), serde_json::Value::Object(rollback));

        // NOTE: open_urls, allow_launch_services, and allow_gpu are intentionally
        // omitted. Emitting them would replace inherited values from base profiles like
        // claude-code (which grants OAuth2 origins, launch services, and GPU access).
        // Absent = inherit from base. Authors who need to override these
        // should add them explicitly.
    }

    serde_json::Value::Object(root)
}

/// Check if a profile exists (built-in, user, or pack-provided).
///
/// Mirrors the resolver in `profile::load_profile_inner`: user dir →
/// pack-store → built-in. Without the pack-store check, formerly-builtin
/// profiles that have moved to registry packs (claude-code, codex)
/// would falsely fail `nono profile init --extends <name>` validation
/// even when `nono profile show <name>` resolves them fine.
fn profile_exists(name: &str) -> bool {
    if profile::builtin::get_builtin(name).is_some() {
        return true;
    }
    if let Ok(path) = profile::resolve_user_profile_path(name)
        && path.exists()
    {
        return true;
    }
    profile::find_pack_store_profile(name).is_some()
}

/// Update the validation error so users know all three sources were
/// considered. Used by `cmd_init`'s `--extends` check.
fn extends_target_not_found_message(name: &str) -> String {
    format!(
        "Base profile '{name}' not found (built-in, user, or installed pack). \
         If it's provided by a registry pack, run `nono pull <namespace>/<pack>` first."
    )
}

// ---------------------------------------------------------------------------
// nono profile schema
// ---------------------------------------------------------------------------

fn cmd_schema(args: ProfileSchemaArgs) -> Result<()> {
    let schema = embedded::embedded_profile_schema();

    match args.output {
        Some(path) => {
            fs::write(&path, schema).map_err(|e| {
                NonoError::ProfileParse(format!(
                    "Failed to write schema to {}: {}",
                    path.display(),
                    e
                ))
            })?;
            eprintln!(
                "{} Schema written to {}",
                prefix(),
                path.display().to_string().bold()
            );
        }
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(schema.as_bytes())
                .map_err(|e| NonoError::ProfileParse(format!("Failed to write to stdout: {e}")))?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// nono profile guide
// ---------------------------------------------------------------------------

fn cmd_guide(_args: ProfileGuideArgs) -> Result<()> {
    let guide = embedded::embedded_profile_guide();
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle
        .write_all(guide.as_bytes())
        .map_err(|e| NonoError::ProfileParse(format!("Failed to write to stdout: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// nono profile groups
// ---------------------------------------------------------------------------

pub(crate) fn cmd_groups(args: ProfileGroupsArgs) -> Result<()> {
    let pol = policy::load_embedded_policy()?;

    match args.name {
        Some(name) => cmd_groups_detail(&pol, &name, args.json),
        None => cmd_groups_list(&pol, args.json, args.all_platforms),
    }
}

fn cmd_groups_list(pol: &policy::Policy, json: bool, all_platforms: bool) -> Result<()> {
    let mut groups: Vec<(&String, &Group)> = pol.groups.iter().collect();
    groups.sort_by_key(|(name, _)| name.as_str());

    if !all_platforms {
        groups.retain(|(_, g)| policy::group_matches_platform(g));
    }

    if json {
        let arr: Vec<serde_json::Value> = groups
            .iter()
            .map(|(name, g)| {
                serde_json::json!({
                    "name": name,
                    "description": g.description,
                    "platform": g.platform.as_deref().unwrap_or("cross-platform"),
                    "required": g.required,
                    "allow": count_allow(&g.allow),
                    "deny": count_deny(&g.deny),
                })
            })
            .collect();
        println!("{}", to_json(&serde_json::Value::Array(arr))?);
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: {} groups{}",
        prefix(),
        groups.len(),
        if all_platforms {
            " (all platforms)"
        } else {
            ""
        }
    );
    println!();

    for (name, group) in &groups {
        let platform = group.platform.as_deref().unwrap_or("cross-platform");
        let required = if group.required { "  required" } else { "" };
        println!(
            "  {:<36} {:<42} {}{}",
            theme::fg(name, t.text).bold(),
            theme::fg(&group.description, t.subtext),
            theme::fg(platform, t.overlay),
            theme::fg(required, t.yellow),
        );
    }

    Ok(())
}

fn cmd_groups_detail(pol: &policy::Policy, name: &str, json: bool) -> Result<()> {
    let group = pol.groups.get(name).ok_or_else(|| {
        NonoError::ProfileParse(format!(
            "group '{}' not found in policy.json. Use `nono profile groups` to list available groups",
            name
        ))
    })?;

    if json {
        let val = group_to_json(name, group);
        println!("{}", to_json(&val)?);
        return Ok(());
    }

    let t = theme::current();
    println!("{}: group '{}'", prefix(), theme::fg(name, t.text).bold());
    println!();
    println!(
        "  {}  {}",
        theme::fg("Description:", t.subtext),
        theme::fg(&group.description, t.text)
    );
    println!(
        "  {}     {}",
        theme::fg("Platform:", t.subtext),
        theme::fg(
            group.platform.as_deref().unwrap_or("cross-platform"),
            t.text
        )
    );
    println!(
        "  {}     {}",
        theme::fg("Required:", t.subtext),
        theme::fg(if group.required { "yes" } else { "no" }, t.text)
    );

    if let Some(ref allow) = group.allow {
        print_path_section("allow.read", &allow.read, t);
        print_path_section("allow.write", &allow.write, t);
        print_path_section("allow.readwrite", &allow.readwrite, t);
    }

    if let Some(ref deny) = group.deny {
        print_path_section("deny.access", &deny.access, t);
        if deny.unlink {
            println!();
            println!("  {}", theme::fg("deny.unlink:", t.red).bold());
            println!("    {}", theme::fg("enabled", t.red));
        }
        if !deny.commands.is_empty() {
            println!();
            println!("  {}", theme::fg("deny.commands:", t.red).bold());
            for cmd in &deny.commands {
                println!("    {}", theme::fg(cmd, t.text));
            }
        }
    }

    if let Some(ref pairs) = group.symlink_pairs
        && !pairs.is_empty()
    {
        println!();
        println!("  {}", theme::fg("symlink_pairs:", t.subtext).bold());
        let mut sorted: Vec<(&String, &String)> = pairs.iter().collect();
        sorted.sort_by_key(|(k, _)| k.as_str());
        for (from, to) in sorted {
            println!(
                "    {} -> {}",
                theme::fg(from, t.text),
                theme::fg(to, t.subtext)
            );
        }
    }

    Ok(())
}

fn print_path_section(label: &str, paths: &[String], t: &theme::Theme) {
    if paths.is_empty() {
        return;
    }
    let color = if label.starts_with("deny") {
        t.red
    } else {
        t.green
    };
    println!();
    println!("  {}", theme::fg(&format!("{label}:"), color).bold());
    for raw in paths {
        match policy::expand_path(raw) {
            Ok(expanded) => {
                let exp_str = expanded.display().to_string();
                if exp_str == *raw {
                    println!("    {}", theme::fg(raw, t.text));
                } else {
                    println!(
                        "    {:<36} -> {}",
                        theme::fg(raw, t.text),
                        theme::fg(&exp_str, t.subtext)
                    );
                }
            }
            Err(_) => {
                println!(
                    "    {:<36} -> {}",
                    theme::fg(raw, t.text),
                    theme::fg("<expansion failed>", t.red)
                );
            }
        }
    }
}

fn count_allow(allow: &Option<AllowOps>) -> serde_json::Value {
    match allow {
        Some(a) => serde_json::json!({
            "read": a.read.len(),
            "write": a.write.len(),
            "readwrite": a.readwrite.len(),
        }),
        None => serde_json::json!({}),
    }
}

fn count_deny(deny: &Option<DenyOps>) -> serde_json::Value {
    match deny {
        Some(d) => serde_json::json!({
            "access": d.access.len(),
            "commands": d.commands.len(),
            "unlink": d.unlink,
        }),
        None => serde_json::json!({}),
    }
}

fn group_to_json(name: &str, group: &Group) -> serde_json::Value {
    let mut val = serde_json::json!({
        "name": name,
        "description": group.description,
        "platform": group.platform.as_deref().unwrap_or("cross-platform"),
        "required": group.required,
    });

    if let Some(ref allow) = group.allow {
        let mut allow_val = serde_json::Map::new();
        if !allow.read.is_empty() {
            allow_val.insert("read".into(), expand_paths_json(&allow.read));
        }
        if !allow.write.is_empty() {
            allow_val.insert("write".into(), expand_paths_json(&allow.write));
        }
        if !allow.readwrite.is_empty() {
            allow_val.insert("readwrite".into(), expand_paths_json(&allow.readwrite));
        }
        val["allow"] = serde_json::Value::Object(allow_val);
    }

    if let Some(ref deny) = group.deny {
        let mut deny_val = serde_json::Map::new();
        if !deny.access.is_empty() {
            deny_val.insert("access".into(), expand_paths_json(&deny.access));
        }
        if !deny.commands.is_empty() {
            deny_val.insert("commands".into(), serde_json::json!(deny.commands));
        }
        if deny.unlink {
            deny_val.insert("unlink".into(), serde_json::json!(true));
        }
        val["deny"] = serde_json::Value::Object(deny_val);
    }

    if let Some(ref pairs) = group.symlink_pairs
        && !pairs.is_empty()
    {
        val["symlink_pairs"] = serde_json::json!(pairs);
    }

    val
}

fn expand_paths_json(paths: &[String]) -> serde_json::Value {
    let arr: Vec<serde_json::Value> = paths
        .iter()
        .map(|raw| {
            let expanded = policy::expand_path(raw)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<expansion failed>".to_string());
            serde_json::json!({
                "raw": raw,
                "expanded": expanded,
            })
        })
        .collect();
    serde_json::Value::Array(arr)
}

// ---------------------------------------------------------------------------
// nono profile list
// ---------------------------------------------------------------------------

/// Determine the actual source of a loaded profile.
///
/// Load precedence is user-first (profile/mod.rs), so a user file with a
/// built-in name shadows the built-in. We must check the filesystem to
/// report the real source accurately.
fn profile_source(name: &str) -> &'static str {
    let builtin_names = profile::builtin::list_builtin();
    let is_pack = profile::list_pack_store_profiles()
        .iter()
        .any(|(n, _)| n == name);
    if profile::is_user_override(name) {
        if is_pack {
            "user (overrides pack)"
        } else if builtin_names.contains(&name.to_string()) {
            "user (overrides built-in)"
        } else {
            "user"
        }
    } else if is_pack {
        "pack"
    } else if builtin_names.contains(&name.to_string()) {
        "built-in"
    } else {
        "user"
    }
}

pub(crate) fn cmd_list(args: ProfileListArgs) -> Result<()> {
    let builtin_names = profile::builtin::list_builtin();
    let all_names = profile::list_profiles();
    // (install_as -> pack ref) for the catalogue. Used to bucket pack
    // profiles under their own section and surface the providing pack.
    let pack_profiles: std::collections::HashMap<String, String> =
        profile::list_pack_store_profiles().into_iter().collect();

    let mut builtin_profiles: Vec<(String, Result<Profile>)> = Vec::new();
    let mut user_profiles: Vec<(String, Result<Profile>)> = Vec::new();
    let mut pack_entries: Vec<(String, String, Result<Profile>)> = Vec::new();

    for name in &all_names {
        // Use the no-migrate loader so listing never triggers an
        // install prompt for pack-provided profiles whose pack happens
        // to be installed via the resolver self-heal path.
        let p = profile::load_profile_no_migrate(name);
        // Categorize by actual source. Precedence: user override > pack
        // store > built-in. User overrides of either built-in or pack
        // names go under user section to make shadowing visible.
        if profile::is_user_override(name) {
            user_profiles.push((name.clone(), p));
        } else if let Some(pack_ref) = pack_profiles.get(name) {
            pack_entries.push((name.clone(), pack_ref.clone(), p));
        } else if builtin_names.contains(name) {
            builtin_profiles.push((name.clone(), p));
        } else {
            user_profiles.push((name.clone(), p));
        }
    }

    if args.json {
        let format_entry = |name: &str, result: &Result<Profile>| {
            let source = profile_source(name);
            let extends = profile::load_profile_extends(name).unwrap_or_default();
            let pack = pack_profiles.get(name).cloned();
            match result {
                Ok(p) => serde_json::json!({
                    "name": name,
                    "source": source,
                    "pack": pack,
                    "description": p.meta.description.as_deref().unwrap_or(""),
                    "extends": extends,
                }),
                Err(e) => serde_json::json!({
                    "name": name,
                    "source": source,
                    "pack": pack,
                    "error": format!("{}", e),
                }),
            }
        };

        let arr: Vec<serde_json::Value> = builtin_profiles
            .iter()
            .map(|(n, p)| format_entry(n, p))
            .chain(pack_entries.iter().map(|(n, _, p)| format_entry(n, p)))
            .chain(user_profiles.iter().map(|(n, p)| format_entry(n, p)))
            .collect();
        println!("{}", to_json(&serde_json::Value::Array(arr))?);
        return Ok(());
    }

    let t = theme::current();
    let total = builtin_profiles.len() + pack_entries.len() + user_profiles.len();
    println!("{}: {} profiles", prefix(), total);

    if !builtin_profiles.is_empty() {
        println!();
        println!("  {}", theme::fg("Built-in:", t.subtext).bold());
        for (name, result) in &builtin_profiles {
            print_profile_line(name, result, t);
        }
    }

    if !pack_entries.is_empty() {
        println!();
        println!("  {}", theme::fg("Packages:", t.subtext).bold());
        for (name, pack_ref, result) in &pack_entries {
            print_pack_profile_line(name, pack_ref, result, t);
        }
    }

    if !user_profiles.is_empty() {
        println!();
        println!(
            "  {}",
            theme::fg("User (~/.config/nono/profiles/):", t.subtext).bold()
        );
        for (name, result) in &user_profiles {
            print_profile_line(name, result, t);
        }
    }

    Ok(())
}

/// Like `print_profile_line` but appends the providing pack ref so the
/// user sees `claude-code  Anthropic Claude Code …  always-further/claude`.
fn print_pack_profile_line(name: &str, pack_ref: &str, result: &Result<Profile>, t: &theme::Theme) {
    match result {
        Ok(p) => {
            let desc = p.meta.description.as_deref().unwrap_or("").to_string();
            let pack_label = format!("from {pack_ref}");
            println!(
                "    {:<16} {:<42} {}",
                theme::fg(name, t.text).bold(),
                theme::fg(&desc, t.subtext),
                theme::fg(&pack_label, t.overlay),
            );
        }
        Err(e) => {
            println!(
                "    {:<16} {}",
                theme::fg(name, t.text).bold(),
                theme::fg(&format!("[error: {}]", e), t.red),
            );
        }
    }
}

fn print_profile_line(name: &str, result: &Result<Profile>, t: &theme::Theme) {
    match result {
        Ok(p) => {
            let desc = p.meta.description.as_deref().unwrap_or("").to_string();
            let extends = profile::load_profile_extends(name)
                .map(|v| format!("extends {}", v.join(", ")))
                .unwrap_or_default();
            println!(
                "    {:<16} {:<42} {}",
                theme::fg(name, t.text).bold(),
                theme::fg(&desc, t.subtext),
                theme::fg(&extends, t.overlay),
            );
        }
        Err(e) => {
            println!(
                "    {:<16} {}",
                theme::fg(name, t.text).bold(),
                theme::fg(&format!("[error: {}]", e), t.red),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// nono profile show
// ---------------------------------------------------------------------------

#[allow(deprecated)] // reads profile.commands.{allow,deny} (deprecated v0.33.0)
pub(crate) fn cmd_show(args: ProfileShowArgs) -> Result<()> {
    // Order matters: `load_profile_extends` opens an internal
    // `WarningSuppressionGuard` for its preview parse, so deprecation
    // warnings fire only on the subsequent real `load_profile` call —
    // exactly once per legacy key per file (the design's contract,
    // line 141). DO NOT swap or merge these two calls without
    // preserving that suppression scope, or warnings will double-emit.
    // See the regression test `legacy_all_keys_shows_byte_equal_canonical_equivalent`
    // in tests/deprecated_schema.rs which asserts the exact 9-warning
    // count on `legacy_all_keys.json`.
    let raw_extends = profile::load_profile_extends(&args.profile);
    let profile = profile::load_profile_no_migrate(&args.profile)?;

    if matches!(args.format, Some(crate::cli::ProfileShowFormat::Manifest)) {
        let workdir = std::env::current_dir().map_err(|e| {
            NonoError::ConfigParse(format!("cannot determine working directory: {e}"))
        })?;
        let manifest = resolve_to_manifest(&profile, &workdir)?;
        let json = manifest.to_json()?;
        println!("{json}");
        return Ok(());
    }

    if args.json {
        let val = profile_to_json(&args.profile, &profile, &raw_extends);
        println!("{}", to_json(&val)?);
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: profile '{}'",
        prefix(),
        theme::fg(&args.profile, t.text).bold()
    );

    // Meta
    if let Some(ref desc) = profile.meta.description {
        println!();
        println!(
            "  {}  {}",
            theme::fg("Description:", t.subtext),
            theme::fg(desc, t.text)
        );
    }
    if let Some(ref extends) = raw_extends {
        println!(
            "  {}      {}",
            theme::fg("Extends:", t.subtext),
            theme::fg(&extends.join(", "), t.text)
        );
    }

    // Security groups (resolved into `groups.include` by profile loading).
    if !profile.groups.include.is_empty() {
        println!();
        println!("  {}", theme::fg("Security groups:", t.subtext).bold());
        for g in &profile.groups.include {
            println!("    {}", theme::fg(g, t.text));
        }
    }
    if !profile.groups.exclude.is_empty() {
        println!();
        println!(
            "  {}",
            theme::fg("Excluded security groups:", t.subtext).bold()
        );
        for g in &profile.groups.exclude {
            println!("    {}", theme::fg(g, t.yellow));
        }
    }

    if !profile.commands.allow.is_empty() {
        println!();
        println!(
            "  {}",
            theme::fg("Allowed commands (deprecated, startup-only):", t.subtext).bold()
        );
        for cmd in &profile.commands.allow {
            println!("    {}", theme::fg(cmd, t.text));
        }
    }
    if !profile.commands.deny.is_empty() {
        println!();
        println!(
            "  {}",
            theme::fg("Denied commands (deprecated, startup-only):", t.subtext).bold()
        );
        for cmd in &profile.commands.deny {
            println!("    {}", theme::fg(cmd, t.yellow));
        }
    }

    if let Some(mode) = &profile.security.signal_mode {
        println!("  {}   {:?}", theme::fg("Signal mode:", t.subtext), mode);
    }

    if let Some(mode) = &profile.security.process_info_mode {
        println!("  {} {:?}", theme::fg("Process info:", t.subtext), mode);
    }

    if let Some(mode) = &profile.security.ipc_mode {
        println!("  {}     {:?}", theme::fg("IPC mode:", t.subtext), mode);
    }

    if let Some(elev) = profile.security.capability_elevation {
        println!(
            "  {} {}",
            theme::fg("Capability elevation:", t.subtext),
            theme::fg(if elev { "enabled" } else { "disabled" }, t.text)
        );
    }
    if let Some(policy) = profile.security.wsl2_proxy_policy {
        println!(
            "  {} {}",
            theme::fg("WSL2 proxy policy:", t.subtext),
            theme::fg(&format!("{policy:?}"), t.text)
        );
    }
    if let Some(mode) = profile.linux.af_unix_mediation {
        println!(
            "  {} {}",
            theme::fg("Linux AF_UNIX mediation:", t.subtext),
            theme::fg(&format!("{mode:?}"), t.text)
        );
    }

    // Filesystem
    let fs = &profile.filesystem;
    let has_fs = !fs.allow.is_empty()
        || !fs.read.is_empty()
        || !fs.write.is_empty()
        || !fs.allow_file.is_empty()
        || !fs.read_file.is_empty()
        || !fs.write_file.is_empty()
        || !fs.deny.is_empty()
        || !fs.bypass_protection.is_empty()
        || !fs.suppress_save_prompt.is_empty();

    if has_fs {
        println!();
        println!("  {}", theme::fg("Filesystem:", t.subtext).bold());
        print_fs_paths("allow (r+w)", &fs.allow, t, args.raw);
        print_fs_paths("read", &fs.read, t, args.raw);
        print_fs_paths("write", &fs.write, t, args.raw);
        print_fs_paths("allow_file (r+w)", &fs.allow_file, t, args.raw);
        print_fs_paths("read_file", &fs.read_file, t, args.raw);
        print_fs_paths("write_file", &fs.write_file, t, args.raw);
        print_fs_paths("deny", &fs.deny, t, args.raw);
        print_fs_paths(
            "suppress_save_prompt",
            &fs.suppress_save_prompt,
            t,
            args.raw,
        );
        if !fs.bypass_protection.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("bypass_protection", t.yellow),
                fs.bypass_protection.join(", ")
            );
        }
    }

    // Network
    let net = &profile.network;
    let has_net = net.block
        || net.resolved_network_profile().is_some()
        || !net.allow_domain.is_empty()
        || !net.resolved_credentials().is_empty()
        || !net.open_port.is_empty()
        || !net.listen_port.is_empty()
        || net.upstream_proxy.is_some()
        || !net.upstream_bypass.is_empty();

    if has_net {
        println!();
        println!("  {}", theme::fg("Network:", t.subtext).bold());
        if net.block {
            println!("    {}", theme::fg("network blocked", t.red));
        }
        if let Some(np) = net.resolved_network_profile() {
            println!(
                "    {}: {}",
                theme::fg("network_profile", t.subtext),
                theme::fg(np, t.text)
            );
        }
        if !net.allow_domain.is_empty() {
            let display: Vec<String> = net
                .allow_domain
                .iter()
                .map(|e| match e {
                    profile::AllowDomainEntry::Plain(s) => s.clone(),
                    profile::AllowDomainEntry::WithEndpoints { domain, endpoints } => {
                        format!("{} ({} endpoint rules)", domain, endpoints.len())
                    }
                })
                .collect();
            println!(
                "    {}: {}",
                theme::fg("allow_domain", t.subtext),
                display.join(", ")
            );
        }
        if !net.resolved_credentials().is_empty() {
            println!(
                "    {}: {}",
                theme::fg("credentials", t.subtext),
                net.resolved_credentials().join(", ")
            );
        }
        if !net.open_port.is_empty() {
            let ports: Vec<String> = net.open_port.iter().map(|p| p.to_string()).collect();
            println!(
                "    {}: {}",
                theme::fg("open_port", t.subtext),
                ports.join(", ")
            );
        }
        if !net.listen_port.is_empty() {
            let ports: Vec<String> = net.listen_port.iter().map(|p| p.to_string()).collect();
            println!(
                "    {}: {}",
                theme::fg("listen_port", t.subtext),
                ports.join(", ")
            );
        }
        if let Some(ref ep) = net.upstream_proxy {
            println!(
                "    {}: {}",
                theme::fg("upstream_proxy", t.subtext),
                theme::fg(ep, t.text)
            );
        }
        if !net.upstream_bypass.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("upstream_bypass", t.subtext),
                net.upstream_bypass.join(", ")
            );
        }
    }

    // Workdir
    if profile.workdir.access != WorkdirAccess::None {
        println!();
        println!(
            "  {}  {:?}",
            theme::fg("Workdir access:", t.subtext).bold(),
            profile.workdir.access
        );
    }

    // Rollback
    let rb = &profile.rollback;
    if !rb.exclude_patterns.is_empty() || !rb.exclude_globs.is_empty() {
        println!();
        println!("  {}", theme::fg("Rollback exclusions:", t.subtext).bold());
        for p in &rb.exclude_patterns {
            println!("    {}", theme::fg(p, t.text));
        }
        for g in &rb.exclude_globs {
            println!(
                "    {} {}",
                theme::fg("glob:", t.overlay),
                theme::fg(g, t.text)
            );
        }
    }

    // Open URLs
    if let Some(ref urls) = profile.open_urls {
        println!();
        println!("  {}", theme::fg("Open URLs:", t.subtext).bold());
        if urls.allow_localhost {
            println!("    {}", theme::fg("localhost allowed", t.text));
        }
        for origin in &urls.allow_origins {
            println!("    {}", theme::fg(origin, t.text));
        }
    }

    // Raw Seatbelt rules — surfaced prominently so it is obvious a profile uses them.
    // Shown on all platforms so cross-platform auditing is possible.
    if !profile.unsafe_macos_seatbelt_rules.is_empty() {
        println!();
        println!(
            "  {}",
            theme::fg(
                "Raw Seatbelt rules (unsafe_macos_seatbelt_rules):",
                t.yellow
            )
            .bold()
        );
        for rule in &profile.unsafe_macos_seatbelt_rules {
            println!("    {}", theme::fg(rule, t.text));
        }
    }

    Ok(())
}

fn print_fs_paths(label: &str, paths: &[String], t: &theme::Theme, raw: bool) {
    if paths.is_empty() {
        return;
    }
    println!("    {}:", theme::fg(label, t.subtext));
    for p in paths {
        if raw {
            println!("      {}", theme::fg(p, t.text));
        } else {
            match policy::expand_path(p) {
                Ok(expanded) => {
                    let exp_str = expanded.display().to_string();
                    if exp_str == *p {
                        println!("      {}", theme::fg(p, t.text));
                    } else {
                        println!(
                            "      {:<36} -> {}",
                            theme::fg(p, t.text),
                            theme::fg(&exp_str, t.subtext)
                        );
                    }
                }
                Err(_) => {
                    println!("      {}", theme::fg(p, t.text));
                }
            }
        }
    }
}

#[allow(deprecated)] // reads profile.commands.{allow,deny} (deprecated v0.33.0)
fn profile_to_json(
    _name: &str,
    profile: &Profile,
    raw_extends: &Option<Vec<String>>,
) -> serde_json::Value {
    // `name` is taken from `profile.meta.name` (resolved at load time) rather
    // than the invocation argument, so byte-equal comparison between two
    // fixtures at different paths with the same logical profile works.
    let mut val = serde_json::json!({
        "name": profile.meta.name,
        "description": profile.meta.description.as_deref().unwrap_or(""),
        "extends": raw_extends.as_ref().map(|v| serde_json::json!(v)).unwrap_or(serde_json::Value::Null),
    });

    // Security — narrow, process-level knobs only. Build via Map so that
    // Option<…> mode fields are *omitted* when None, matching the shape of
    // hand-authored profile files (e.g. those produced by users) and the
    // input schema accepted by `profile validate`. The enum types derive
    // Serialize with the right rename_all annotations, so values render as
    // snake_case (`isolated`, `allow_same_sandbox`, …).
    let mut security = serde_json::Map::new();
    if let Some(v) = profile.security.signal_mode {
        security.insert("signal_mode".into(), serde_json::json!(v));
    }
    if let Some(v) = profile.security.process_info_mode {
        security.insert("process_info_mode".into(), serde_json::json!(v));
    }
    if let Some(v) = profile.security.ipc_mode {
        security.insert("ipc_mode".into(), serde_json::json!(v));
    }
    security.insert(
        "capability_elevation".into(),
        serde_json::json!(profile.security.capability_elevation),
    );
    if let Some(v) = profile.security.wsl2_proxy_policy {
        security.insert("wsl2_proxy_policy".into(), serde_json::json!(v));
    }
    val["security"] = serde_json::Value::Object(security);
    if let Some(v) = profile.linux.af_unix_mediation {
        val["linux"] = serde_json::json!({ "af_unix_mediation": v });
    }

    // Filesystem (canonical schema — `allow`/`read`/`write`/`*_file`/`deny`/
    // `bypass_protection`). Legacy keys deserialize into these fields via
    // `deprecated_schema::LegacyPolicyPatch` before reaching `Profile`.
    val["filesystem"] = serde_json::json!({
        "allow": profile.filesystem.allow,
        "read": profile.filesystem.read,
        "write": profile.filesystem.write,
        "allow_file": profile.filesystem.allow_file,
        "read_file": profile.filesystem.read_file,
        "write_file": profile.filesystem.write_file,
        "deny": profile.filesystem.deny,
        "bypass_protection": profile.filesystem.bypass_protection,
        "suppress_save_prompt": profile.filesystem.suppress_save_prompt,
    });

    // Groups and commands are emitted only when populated, so default-empty
    // profiles don't carry noise. This matches the canonical input shape.
    if !profile.groups.include.is_empty() || !profile.groups.exclude.is_empty() {
        val["groups"] = serde_json::json!({
            "include": profile.groups.include,
            "exclude": profile.groups.exclude,
        });
    }
    if !profile.commands.allow.is_empty() || !profile.commands.deny.is_empty() {
        val["commands"] = serde_json::json!({
            "allow": profile.commands.allow,
            "deny": profile.commands.deny,
        });
    }

    // Network
    val["network"] = serde_json::json!({
        "block": profile.network.block,
        "network_profile": profile.network.resolved_network_profile(),
        "allow_domain": profile.network.allow_domain,
        "credentials": profile.network.resolved_credentials(),
        "open_port": profile.network.open_port,
        "listen_port": profile.network.listen_port,
        "upstream_proxy": profile.network.upstream_proxy,
        "upstream_bypass": profile.network.upstream_bypass,
    });

    // Workdir. Serde renders WorkdirAccess as lowercase via rename_all.
    val["workdir"] = serde_json::json!({
        "access": profile.workdir.access,
    });

    // Rollback
    val["rollback"] = serde_json::json!({
        "exclude_patterns": profile.rollback.exclude_patterns,
        "exclude_globs": profile.rollback.exclude_globs,
    });

    // Env credentials
    if !profile.env_credentials.mappings.is_empty() {
        val["env_credentials"] = serde_json::json!(profile.env_credentials.mappings);
    }

    // Hooks
    if !profile.hooks.hooks.is_empty() {
        let hooks: serde_json::Map<String, serde_json::Value> = profile
            .hooks
            .hooks
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    serde_json::json!({
                        "event": v.event,
                        "matcher": v.matcher,
                        "script": v.script,
                    }),
                )
            })
            .collect();
        val["hooks"] = serde_json::Value::Object(hooks);
    }

    // Open URLs
    if let Some(ref urls) = profile.open_urls {
        val["open_urls"] = serde_json::json!({
            "allow_origins": urls.allow_origins,
            "allow_localhost": urls.allow_localhost,
        });
    }

    // Allow launch services
    if let Some(als) = profile.allow_launch_services {
        val["allow_launch_services"] = serde_json::json!(als);
    }

    if let Some(ag) = profile.allow_gpu {
        val["allow_gpu"] = serde_json::json!(ag);
    }

    if !profile.unsafe_macos_seatbelt_rules.is_empty() {
        val["unsafe_macos_seatbelt_rules"] = serde_json::json!(profile.unsafe_macos_seatbelt_rules);
    }

    val
}

// ---------------------------------------------------------------------------
// nono profile diff
// ---------------------------------------------------------------------------

#[allow(deprecated)] // reads commands.{allow,deny} (deprecated v0.33.0)
pub(crate) fn cmd_diff(args: ProfileDiffArgs) -> Result<()> {
    let p1 = profile::load_profile_no_migrate(&args.profile1)?;
    let p2 = profile::load_profile_no_migrate(&args.profile2)?;

    if args.json {
        let val = diff_to_json(&args.profile1, &args.profile2, &p1, &p2);
        println!("{}", to_json(&val)?);
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: diff '{}' vs '{}'",
        prefix(),
        theme::fg(&args.profile1, t.text).bold(),
        theme::fg(&args.profile2, t.text).bold()
    );

    let mut any_diff = false;

    // Groups
    let g1: BTreeSet<&str> = p1.groups.include.iter().map(|s| s.as_str()).collect();
    let g2: BTreeSet<&str> = p2.groups.include.iter().map(|s| s.as_str()).collect();
    let added_groups: BTreeSet<&&str> = g2.difference(&g1).collect();
    let removed_groups: BTreeSet<&&str> = g1.difference(&g2).collect();

    if !added_groups.is_empty() || !removed_groups.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Groups", t.subtext).bold());
        for g in &removed_groups {
            println!("    {} {}", theme::fg("-", t.red), theme::fg(g, t.red));
        }
        for g in &added_groups {
            println!("    {} {}", theme::fg("+", t.green), theme::fg(g, t.green));
        }
    }

    // Filesystem
    let fs_diffs = diff_string_vecs(&[
        ("allow", &p1.filesystem.allow, &p2.filesystem.allow),
        ("read", &p1.filesystem.read, &p2.filesystem.read),
        ("write", &p1.filesystem.write, &p2.filesystem.write),
        (
            "allow_file",
            &p1.filesystem.allow_file,
            &p2.filesystem.allow_file,
        ),
        (
            "read_file",
            &p1.filesystem.read_file,
            &p2.filesystem.read_file,
        ),
        (
            "write_file",
            &p1.filesystem.write_file,
            &p2.filesystem.write_file,
        ),
    ]);

    if !fs_diffs.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Filesystem", t.subtext).bold());
        for (label, sign, path) in &fs_diffs {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(path, color)
            );
        }
    }

    // Additional filesystem, groups, and commands diffs (formerly grouped
    // under the legacy `policy.*` patches; now read from their canonical
    // sections).
    let pp_diffs = diff_string_vecs(&[
        ("groups.exclude", &p1.groups.exclude, &p2.groups.exclude),
        ("filesystem.deny", &p1.filesystem.deny, &p2.filesystem.deny),
        (
            "filesystem.bypass_protection",
            &p1.filesystem.bypass_protection,
            &p2.filesystem.bypass_protection,
        ),
        (
            "filesystem.suppress_save_prompt",
            &p1.filesystem.suppress_save_prompt,
            &p2.filesystem.suppress_save_prompt,
        ),
        ("commands.deny", &p1.commands.deny, &p2.commands.deny),
    ]);

    if !pp_diffs.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Composition", t.subtext).bold());
        for (label, sign, val) in &pp_diffs {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(val, color)
            );
        }
    }

    // Security scalar fields
    any_diff |= diff_scalar_option(
        "capability_elevation",
        &p1.security.capability_elevation.map(|v| format!("{v}")),
        &p2.security.capability_elevation.map(|v| format!("{v}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "wsl2_proxy_policy",
        &p1.security.wsl2_proxy_policy.map(|v| format!("{v:?}")),
        &p2.security.wsl2_proxy_policy.map(|v| format!("{v:?}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "linux.af_unix_mediation",
        &p1.linux.af_unix_mediation.map(|v| format!("{v:?}")),
        &p2.linux.af_unix_mediation.map(|v| format!("{v:?}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "signal_mode",
        &p1.security.signal_mode.map(|v| format!("{v:?}")),
        &p2.security.signal_mode.map(|v| format!("{v:?}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "process_info_mode",
        &p1.security.process_info_mode.map(|v| format!("{v:?}")),
        &p2.security.process_info_mode.map(|v| format!("{v:?}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "ipc_mode",
        &p1.security.ipc_mode.map(|v| format!("{v:?}")),
        &p2.security.ipc_mode.map(|v| format!("{v:?}")),
        t,
    );

    // Network
    let mut net_diffs: Vec<(String, String)> = Vec::new();
    if p1.network.block != p2.network.block {
        net_diffs.push((
            format!("- block: {}", p1.network.block),
            format!("+ block: {}", p2.network.block),
        ));
    }
    let np1 = p1.network.resolved_network_profile().unwrap_or("");
    let np2 = p2.network.resolved_network_profile().unwrap_or("");
    if np1 != np2 {
        if !np1.is_empty() {
            net_diffs.push((format!("- network_profile: {np1}"), String::new()));
        }
        if !np2.is_empty() {
            net_diffs.push((String::new(), format!("+ network_profile: {np2}")));
        }
    }

    let p1_allow_domain_strs: Vec<String> = p1
        .network
        .allow_domain
        .iter()
        .map(|e| e.domain().to_string())
        .collect();
    let p2_allow_domain_strs: Vec<String> = p2
        .network
        .allow_domain
        .iter()
        .map(|e| e.domain().to_string())
        .collect();
    let net_vec_diffs = diff_string_vecs(&[
        ("allow_domain", &p1_allow_domain_strs, &p2_allow_domain_strs),
        (
            "credentials",
            p1.network.resolved_credentials(),
            p2.network.resolved_credentials(),
        ),
        (
            "upstream_bypass",
            &p1.network.upstream_bypass,
            &p2.network.upstream_bypass,
        ),
    ]);

    let port1: Vec<String> = p1.network.open_port.iter().map(|p| p.to_string()).collect();
    let port2: Vec<String> = p2.network.open_port.iter().map(|p| p.to_string()).collect();
    let port_diffs = diff_string_vecs(&[("open_port", &port1, &port2)]);
    let listen1: Vec<String> = p1
        .network
        .listen_port
        .iter()
        .map(|p| p.to_string())
        .collect();
    let listen2: Vec<String> = p2
        .network
        .listen_port
        .iter()
        .map(|p| p.to_string())
        .collect();
    let listen_diffs = diff_string_vecs(&[("listen_port", &listen1, &listen2)]);

    if !net_diffs.is_empty()
        || !net_vec_diffs.is_empty()
        || !port_diffs.is_empty()
        || !listen_diffs.is_empty()
    {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Network", t.subtext).bold());
        for (rem, add) in &net_diffs {
            if !rem.is_empty() {
                println!("    {}", theme::fg(rem, t.red));
            }
            if !add.is_empty() {
                println!("    {}", theme::fg(add, t.green));
            }
        }
        for (label, sign, val) in net_vec_diffs
            .iter()
            .chain(port_diffs.iter())
            .chain(listen_diffs.iter())
        {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(val, color)
            );
        }
    }

    any_diff |= diff_scalar_option(
        "upstream_proxy",
        &p1.network.upstream_proxy,
        &p2.network.upstream_proxy,
        t,
    );

    // Workdir
    if p1.workdir.access != p2.workdir.access {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Workdir", t.subtext).bold());
        println!(
            "    {}",
            theme::fg(&format!("- access: {:?}", p1.workdir.access), t.red)
        );
        println!(
            "    {}",
            theme::fg(&format!("+ access: {:?}", p2.workdir.access), t.green)
        );
    }

    // Allowed commands
    let cmd1: BTreeSet<&str> = p1.commands.allow.iter().map(|s| s.as_str()).collect();
    let cmd2: BTreeSet<&str> = p2.commands.allow.iter().map(|s| s.as_str()).collect();
    let added_cmds: BTreeSet<&&str> = cmd2.difference(&cmd1).collect();
    let removed_cmds: BTreeSet<&&str> = cmd1.difference(&cmd2).collect();

    if !added_cmds.is_empty() || !removed_cmds.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Allowed commands", t.subtext).bold());
        for c in &removed_cmds {
            println!("    {} {}", theme::fg("-", t.red), theme::fg(c, t.red));
        }
        for c in &added_cmds {
            println!("    {} {}", theme::fg("+", t.green), theme::fg(c, t.green));
        }
    }

    // Rollback
    let rb_diffs = diff_string_vecs(&[
        (
            "exclude_patterns",
            &p1.rollback.exclude_patterns,
            &p2.rollback.exclude_patterns,
        ),
        (
            "exclude_globs",
            &p1.rollback.exclude_globs,
            &p2.rollback.exclude_globs,
        ),
    ]);
    if !rb_diffs.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Rollback", t.subtext).bold());
        for (label, sign, val) in &rb_diffs {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(val, color)
            );
        }
    }

    // Open URLs
    let ou1_origins: Vec<String> = p1
        .open_urls
        .as_ref()
        .map(|u| u.allow_origins.clone())
        .unwrap_or_default();
    let ou2_origins: Vec<String> = p2
        .open_urls
        .as_ref()
        .map(|u| u.allow_origins.clone())
        .unwrap_or_default();
    let ou_diffs = diff_string_vecs(&[("allow_origins", &ou1_origins, &ou2_origins)]);
    let ou1_localhost = p1.open_urls.as_ref().is_some_and(|u| u.allow_localhost);
    let ou2_localhost = p2.open_urls.as_ref().is_some_and(|u| u.allow_localhost);

    if !ou_diffs.is_empty() || ou1_localhost != ou2_localhost {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Open URLs", t.subtext).bold());
        for (label, sign, val) in &ou_diffs {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(val, color)
            );
        }
        if ou1_localhost != ou2_localhost {
            println!(
                "    {}",
                theme::fg(&format!("- allow_localhost: {ou1_localhost}"), t.red)
            );
            println!(
                "    {}",
                theme::fg(&format!("+ allow_localhost: {ou2_localhost}"), t.green)
            );
        }
    }

    // Allow launch services
    any_diff |= diff_scalar_option(
        "allow_launch_services",
        &p1.allow_launch_services.map(|v| format!("{v}")),
        &p2.allow_launch_services.map(|v| format!("{v}")),
        t,
    );

    any_diff |= diff_scalar_option(
        "allow_gpu",
        &p1.allow_gpu.map(|v| format!("{v}")),
        &p2.allow_gpu.map(|v| format!("{v}")),
        t,
    );

    // Env credentials
    let ec1: BTreeSet<(&String, &String)> = p1.env_credentials.mappings.iter().collect();
    let ec2: BTreeSet<(&String, &String)> = p2.env_credentials.mappings.iter().collect();
    let ec_added: BTreeSet<&(&String, &String)> = ec2.difference(&ec1).collect();
    let ec_removed: BTreeSet<&(&String, &String)> = ec1.difference(&ec2).collect();
    if !ec_added.is_empty() || !ec_removed.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Env credentials", t.subtext).bold());
        for (k, v) in &ec_removed {
            println!(
                "    {} {} -> {}",
                theme::fg("-", t.red),
                theme::fg(k, t.red),
                theme::fg(v, t.red)
            );
        }
        for (k, v) in &ec_added {
            println!(
                "    {} {} -> {}",
                theme::fg("+", t.green),
                theme::fg(k, t.green),
                theme::fg(v, t.green)
            );
        }
    }

    // Hooks
    let h1: BTreeSet<&String> = p1.hooks.hooks.keys().collect();
    let h2: BTreeSet<&String> = p2.hooks.hooks.keys().collect();
    let hooks_added: BTreeSet<&&String> = h2.difference(&h1).collect();
    let hooks_removed: BTreeSet<&&String> = h1.difference(&h2).collect();
    // Check for hooks present in both but with different config
    let hooks_changed: Vec<&String> = h1
        .intersection(&h2)
        .filter(|k| {
            let a = &p1.hooks.hooks[**k];
            let b = &p2.hooks.hooks[**k];
            a.event != b.event || a.matcher != b.matcher || a.script != b.script
        })
        .copied()
        .collect();
    if !hooks_added.is_empty() || !hooks_removed.is_empty() || !hooks_changed.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Hooks", t.subtext).bold());
        for h in &hooks_removed {
            println!("    {} {}", theme::fg("-", t.red), theme::fg(h, t.red));
        }
        for h in &hooks_added {
            println!("    {} {}", theme::fg("+", t.green), theme::fg(h, t.green));
        }
        for h in &hooks_changed {
            println!(
                "    {} {} (changed)",
                theme::fg("~", t.yellow),
                theme::fg(h, t.yellow)
            );
        }
    }

    // Custom credentials
    let cc1: BTreeSet<&String> = p1.network.custom_credentials.keys().collect();
    let cc2: BTreeSet<&String> = p2.network.custom_credentials.keys().collect();
    let cc_added: BTreeSet<&&String> = cc2.difference(&cc1).collect();
    let cc_removed: BTreeSet<&&String> = cc1.difference(&cc2).collect();
    let cc_changed: Vec<&String> = cc1
        .intersection(&cc2)
        .filter(|k| p1.network.custom_credentials[**k] != p2.network.custom_credentials[**k])
        .copied()
        .collect();
    if !cc_added.is_empty() || !cc_removed.is_empty() || !cc_changed.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Custom credentials", t.subtext).bold());
        for c in &cc_removed {
            println!("    {} {}", theme::fg("-", t.red), theme::fg(c, t.red));
        }
        for c in &cc_added {
            println!("    {} {}", theme::fg("+", t.green), theme::fg(c, t.green));
        }
        for c in &cc_changed {
            let old = &p1.network.custom_credentials[*c];
            let new = &p2.network.custom_credentials[*c];
            println!(
                "    {} {} (changed)",
                theme::fg("~", t.yellow),
                theme::fg(c, t.yellow)
            );
            if old.upstream != new.upstream {
                println!(
                    "      {} upstream: {}",
                    theme::fg("-", t.red),
                    theme::fg(&old.upstream, t.red)
                );
                println!(
                    "      {} upstream: {}",
                    theme::fg("+", t.green),
                    theme::fg(&new.upstream, t.green)
                );
            }
            if old.credential_key != new.credential_key {
                let old_key = old.credential_key.as_deref().unwrap_or("<none>");
                let new_key = new.credential_key.as_deref().unwrap_or("<none>");
                println!(
                    "      {} credential_key: {}",
                    theme::fg("-", t.red),
                    theme::fg(old_key, t.red)
                );
                println!(
                    "      {} credential_key: {}",
                    theme::fg("+", t.green),
                    theme::fg(new_key, t.green)
                );
            }
            if old.inject_mode != new.inject_mode {
                println!(
                    "      {} inject_mode: {:?}",
                    theme::fg("-", t.red),
                    old.inject_mode
                );
                println!(
                    "      {} inject_mode: {:?}",
                    theme::fg("+", t.green),
                    new.inject_mode
                );
            }
            if old.inject_header != new.inject_header {
                println!(
                    "      {} inject_header: {}",
                    theme::fg("-", t.red),
                    theme::fg(&old.inject_header, t.red)
                );
                println!(
                    "      {} inject_header: {}",
                    theme::fg("+", t.green),
                    theme::fg(&new.inject_header, t.green)
                );
            }
            if old.credential_format != new.credential_format {
                println!(
                    "      {} credential_format: {}",
                    theme::fg("-", t.red),
                    theme::fg(&credential_format_diff_label(&old.credential_format), t.red)
                );
                println!(
                    "      {} credential_format: {}",
                    theme::fg("+", t.green),
                    theme::fg(
                        &credential_format_diff_label(&new.credential_format),
                        t.green
                    )
                );
            }
            if old.path_pattern != new.path_pattern {
                println!(
                    "      {} path_pattern: {:?}",
                    theme::fg("-", t.red),
                    old.path_pattern
                );
                println!(
                    "      {} path_pattern: {:?}",
                    theme::fg("+", t.green),
                    new.path_pattern
                );
            }
            if old.path_replacement != new.path_replacement {
                println!(
                    "      {} path_replacement: {:?}",
                    theme::fg("-", t.red),
                    old.path_replacement
                );
                println!(
                    "      {} path_replacement: {:?}",
                    theme::fg("+", t.green),
                    new.path_replacement
                );
            }
            if old.query_param_name != new.query_param_name {
                println!(
                    "      {} query_param_name: {:?}",
                    theme::fg("-", t.red),
                    old.query_param_name
                );
                println!(
                    "      {} query_param_name: {:?}",
                    theme::fg("+", t.green),
                    new.query_param_name
                );
            }
            if old.env_var != new.env_var {
                println!("      {} env_var: {:?}", theme::fg("-", t.red), old.env_var);
                println!(
                    "      {} env_var: {:?}",
                    theme::fg("+", t.green),
                    new.env_var
                );
            }
        }
    }

    if !any_diff {
        println!();
        println!("  {}", theme::fg("(no differences)", t.subtext));
    }

    Ok(())
}

/// Human-readable label for optional credential_format in profile diffs.
fn credential_format_diff_label(f: &Option<String>) -> String {
    match f {
        None => "(default)".to_string(),
        Some(s) => s.clone(),
    }
}

/// Print a diff for an optional scalar field. Returns true if there was a difference.
fn diff_scalar_option(
    label: &str,
    v1: &Option<String>,
    v2: &Option<String>,
    t: &theme::Theme,
) -> bool {
    if v1 == v2 {
        return false;
    }
    println!();
    println!("  {}:", theme::fg(label, t.subtext).bold());
    if let Some(old) = v1 {
        println!("    {}", theme::fg(&format!("- {old}"), t.red));
    }
    if let Some(new) = v2 {
        println!("    {}", theme::fg(&format!("+ {new}"), t.green));
    }
    true
}

fn diff_string_vecs<'a>(
    pairs: &[(&'a str, &[String], &[String])],
) -> Vec<(&'a str, &'static str, String)> {
    let mut result = Vec::new();
    for (label, v1, v2) in pairs {
        let s1: BTreeSet<&str> = v1.iter().map(|s| s.as_str()).collect();
        let s2: BTreeSet<&str> = v2.iter().map(|s| s.as_str()).collect();
        for removed in s1.difference(&s2) {
            result.push((*label, "-", removed.to_string()));
        }
        for added in s2.difference(&s1) {
            result.push((*label, "+", added.to_string()));
        }
    }
    result
}

#[allow(deprecated)] // reads commands.{allow,deny} (deprecated v0.33.0)
fn diff_to_json(name1: &str, name2: &str, p1: &Profile, p2: &Profile) -> serde_json::Value {
    let g1: BTreeSet<&str> = p1.groups.include.iter().map(|s| s.as_str()).collect();
    let g2: BTreeSet<&str> = p2.groups.include.iter().map(|s| s.as_str()).collect();

    let groups_added: Vec<&str> = g2.difference(&g1).copied().collect();
    let groups_removed: Vec<&str> = g1.difference(&g2).copied().collect();

    let diff_vec = |v1: &[String], v2: &[String]| -> serde_json::Value {
        let s1: BTreeSet<&str> = v1.iter().map(|s| s.as_str()).collect();
        let s2: BTreeSet<&str> = v2.iter().map(|s| s.as_str()).collect();
        let added: Vec<&str> = s2.difference(&s1).copied().collect();
        let removed: Vec<&str> = s1.difference(&s2).copied().collect();
        serde_json::json!({ "added": added, "removed": removed })
    };

    let p1_allow_domain_strs: Vec<String> = p1
        .network
        .allow_domain
        .iter()
        .map(|e| e.domain().to_string())
        .collect();
    let p2_allow_domain_strs: Vec<String> = p2
        .network
        .allow_domain
        .iter()
        .map(|e| e.domain().to_string())
        .collect();

    let ou1 = p1.open_urls.as_ref();
    let ou2 = p2.open_urls.as_ref();

    serde_json::json!({
        "profile1": name1,
        "profile2": name2,
        "groups": {
            "added": groups_added,
            "removed": groups_removed,
        },
        "commands": {
            "allow": diff_vec(&p1.commands.allow, &p2.commands.allow),
            "deny": diff_vec(&p1.commands.deny, &p2.commands.deny),
        },
        "capability_elevation": {
            "profile1": p1.security.capability_elevation,
            "profile2": p2.security.capability_elevation,
            "changed": p1.security.capability_elevation != p2.security.capability_elevation,
        },
        "wsl2_proxy_policy": {
            "profile1": p1.security.wsl2_proxy_policy,
            "profile2": p2.security.wsl2_proxy_policy,
            "changed": p1.security.wsl2_proxy_policy != p2.security.wsl2_proxy_policy,
        },
        "linux": {
            "af_unix_mediation": {
                "profile1": p1.linux.af_unix_mediation,
                "profile2": p2.linux.af_unix_mediation,
                "changed": p1.linux.af_unix_mediation != p2.linux.af_unix_mediation,
            }
        },
        "filesystem": diff_fs_json(&p1.filesystem, &p2.filesystem),
        "workdir": {
            "profile1": p1.workdir.access,
            "profile2": p2.workdir.access,
            "changed": p1.workdir.access != p2.workdir.access,
        },
        "network": {
            "block": {
                "profile1": p1.network.block,
                "profile2": p2.network.block,
                "changed": p1.network.block != p2.network.block,
            },
            "network_profile": {
                "profile1": p1.network.resolved_network_profile(),
                "profile2": p2.network.resolved_network_profile(),
                "changed": p1.network.resolved_network_profile() != p2.network.resolved_network_profile(),
            },
            "allow_domain": diff_vec(&p1_allow_domain_strs, &p2_allow_domain_strs),
            "credentials": diff_vec(p1.network.resolved_credentials(), p2.network.resolved_credentials()),
            "open_port": {
                "profile1": p1.network.open_port,
                "profile2": p2.network.open_port,
                "changed": p1.network.open_port != p2.network.open_port,
            },
            "listen_port": {
                "profile1": p1.network.listen_port,
                "profile2": p2.network.listen_port,
                "changed": p1.network.listen_port != p2.network.listen_port,
            },
            "upstream_proxy": {
                "profile1": p1.network.upstream_proxy,
                "profile2": p2.network.upstream_proxy,
                "changed": p1.network.upstream_proxy != p2.network.upstream_proxy,
            },
            "upstream_bypass": diff_vec(
                &p1.network.upstream_bypass,
                &p2.network.upstream_bypass,
            ),
            "custom_credentials": diff_custom_credentials_json(
                &p1.network.custom_credentials,
                &p2.network.custom_credentials,
            ),
        },
        "env_credentials": {
            "profile1": p1.env_credentials.mappings,
            "profile2": p2.env_credentials.mappings,
            "changed": p1.env_credentials.mappings != p2.env_credentials.mappings,
        },
        "hooks": diff_hooks_json(&p1.hooks.hooks, &p2.hooks.hooks),
        "rollback": {
            "exclude_patterns": diff_vec(&p1.rollback.exclude_patterns, &p2.rollback.exclude_patterns),
            "exclude_globs": diff_vec(&p1.rollback.exclude_globs, &p2.rollback.exclude_globs),
        },
        "open_urls": {
            "allow_origins": diff_vec(
                &ou1.map(|u| u.allow_origins.clone()).unwrap_or_default(),
                &ou2.map(|u| u.allow_origins.clone()).unwrap_or_default(),
            ),
            "allow_localhost": {
                "profile1": ou1.is_some_and(|u| u.allow_localhost),
                "profile2": ou2.is_some_and(|u| u.allow_localhost),
                "changed": ou1.is_some_and(|u| u.allow_localhost) != ou2.is_some_and(|u| u.allow_localhost),
            },
        },
        "allow_launch_services": {
            "profile1": p1.allow_launch_services,
            "profile2": p2.allow_launch_services,
            "changed": p1.allow_launch_services != p2.allow_launch_services,
        },
        "allow_gpu": {
            "profile1": p1.allow_gpu,
            "profile2": p2.allow_gpu,
            "changed": p1.allow_gpu != p2.allow_gpu,
        },
    })
}

fn diff_fs_json(
    fs1: &profile::FilesystemConfig,
    fs2: &profile::FilesystemConfig,
) -> serde_json::Value {
    let diff_vec = |v1: &[String], v2: &[String]| -> serde_json::Value {
        let s1: BTreeSet<&str> = v1.iter().map(|s| s.as_str()).collect();
        let s2: BTreeSet<&str> = v2.iter().map(|s| s.as_str()).collect();
        let added: Vec<&str> = s2.difference(&s1).copied().collect();
        let removed: Vec<&str> = s1.difference(&s2).copied().collect();
        serde_json::json!({ "added": added, "removed": removed })
    };

    serde_json::json!({
        "allow": diff_vec(&fs1.allow, &fs2.allow),
        "read": diff_vec(&fs1.read, &fs2.read),
        "write": diff_vec(&fs1.write, &fs2.write),
        "allow_file": diff_vec(&fs1.allow_file, &fs2.allow_file),
        "read_file": diff_vec(&fs1.read_file, &fs2.read_file),
        "write_file": diff_vec(&fs1.write_file, &fs2.write_file),
        "suppress_save_prompt": diff_vec(
            &fs1.suppress_save_prompt,
            &fs2.suppress_save_prompt
        ),
    })
}

fn diff_hooks_json(
    h1: &std::collections::HashMap<String, profile::HookConfig>,
    h2: &std::collections::HashMap<String, profile::HookConfig>,
) -> serde_json::Value {
    let added: Vec<&String> = h2.keys().filter(|k| !h1.contains_key(*k)).collect();
    let removed: Vec<&String> = h1.keys().filter(|k| !h2.contains_key(*k)).collect();
    let changed: Vec<&String> = h1
        .keys()
        .filter(|k| {
            h2.get(*k).is_some_and(|v2| {
                let v1 = &h1[*k];
                v1.event != v2.event || v1.matcher != v2.matcher || v1.script != v2.script
            })
        })
        .collect();

    let mut changed_details = serde_json::Map::new();
    for k in &changed {
        let old = &h1[*k];
        let new = &h2[*k];
        let mut detail = serde_json::Map::new();
        if old.event != new.event {
            detail.insert(
                "event".into(),
                serde_json::json!({"profile1": old.event, "profile2": new.event}),
            );
        }
        if old.matcher != new.matcher {
            detail.insert(
                "matcher".into(),
                serde_json::json!({"profile1": old.matcher, "profile2": new.matcher}),
            );
        }
        if old.script != new.script {
            detail.insert(
                "script".into(),
                serde_json::json!({"profile1": old.script, "profile2": new.script}),
            );
        }
        changed_details.insert((*k).clone(), serde_json::Value::Object(detail));
    }

    serde_json::json!({
        "added": added,
        "removed": removed,
        "changed": changed_details,
    })
}

fn diff_custom_credentials_json(
    cc1: &std::collections::HashMap<String, profile::CustomCredentialDef>,
    cc2: &std::collections::HashMap<String, profile::CustomCredentialDef>,
) -> serde_json::Value {
    let added: Vec<&String> = cc2.keys().filter(|k| !cc1.contains_key(*k)).collect();
    let removed: Vec<&String> = cc1.keys().filter(|k| !cc2.contains_key(*k)).collect();
    let changed: Vec<&String> = cc1
        .keys()
        .filter(|k| cc2.get(*k).is_some_and(|v2| cc1[*k] != *v2))
        .collect();

    let mut changed_details = serde_json::Map::new();
    for k in &changed {
        let old = &cc1[*k];
        let new = &cc2[*k];
        let mut detail = serde_json::Map::new();
        if old.upstream != new.upstream {
            detail.insert(
                "upstream".into(),
                serde_json::json!({"profile1": old.upstream, "profile2": new.upstream}),
            );
        }
        if old.credential_key != new.credential_key {
            detail.insert(
                "credential_key".into(),
                serde_json::json!({"profile1": old.credential_key, "profile2": new.credential_key}),
            );
        }
        if old.inject_mode != new.inject_mode {
            detail.insert(
                "inject_mode".into(),
                serde_json::json!({"profile1": format!("{:?}", old.inject_mode), "profile2": format!("{:?}", new.inject_mode)}),
            );
        }
        if old.inject_header != new.inject_header {
            detail.insert(
                "inject_header".into(),
                serde_json::json!({"profile1": old.inject_header, "profile2": new.inject_header}),
            );
        }
        if old.credential_format != new.credential_format {
            detail.insert(
                "credential_format".into(),
                serde_json::json!({"profile1": old.credential_format, "profile2": new.credential_format}),
            );
        }
        if old.path_pattern != new.path_pattern {
            detail.insert(
                "path_pattern".into(),
                serde_json::json!({"profile1": old.path_pattern, "profile2": new.path_pattern}),
            );
        }
        if old.path_replacement != new.path_replacement {
            detail.insert(
                "path_replacement".into(),
                serde_json::json!({"profile1": old.path_replacement, "profile2": new.path_replacement}),
            );
        }
        if old.query_param_name != new.query_param_name {
            detail.insert(
                "query_param_name".into(),
                serde_json::json!({"profile1": old.query_param_name, "profile2": new.query_param_name}),
            );
        }
        if old.env_var != new.env_var {
            detail.insert(
                "env_var".into(),
                serde_json::json!({"profile1": old.env_var, "profile2": new.env_var}),
            );
        }
        changed_details.insert((*k).clone(), serde_json::Value::Object(detail));
    }

    serde_json::json!({
        "added": added,
        "removed": removed,
        "changed": changed_details,
    })
}

// ---------------------------------------------------------------------------
// nono profile validate
// ---------------------------------------------------------------------------

fn classify_profile_error(e: &NonoError) -> &'static str {
    match e {
        NonoError::ProfileParse(msg)
            if msg.starts_with("expected")
                || msg.contains("line ")
                || msg.contains("column ")
                || msg.contains("EOF") =>
        {
            "JSON syntax error"
        }
        NonoError::ProfileParse(_) => "Profile error",
        NonoError::ProfileRead { .. } => "File read error",
        NonoError::ProfileInheritance(_) => "Inheritance error",
        NonoError::ProfileNotFound(_) => "Profile not found",
        _ => "Error",
    }
}

/// Resolve a `nono profile validate` target into a filesystem path.
///
/// Clap parses the positional argument as a `PathBuf`, so a user who
/// types `nono profile validate claude-docs` arrives here with the bare
/// name. We mirror the same precedence as `--profile`: the literal path
/// wins if it exists, otherwise look up the user profile dir, then the
/// installed pack store, then the `.json` form of the bare name. If
/// nothing matches, return the original input so the existing
/// not-found error path produces a readable message.
fn resolve_validate_target(input: &std::path::Path) -> std::path::PathBuf {
    if input.exists() {
        return input.to_path_buf();
    }
    let Some(name) = input.to_str() else {
        return input.to_path_buf();
    };
    if profile::is_file_path_ref(name) {
        return input.to_path_buf();
    }
    if let Ok(p) = profile::resolve_user_profile_path(name)
        && p.exists()
    {
        return p;
    }
    if let Some((p, _)) = profile::find_pack_store_profile(name) {
        return p;
    }
    input.to_path_buf()
}

fn resolve_validate_draft_target(input: &std::path::Path) -> Result<std::path::PathBuf> {
    let name = input.to_str().ok_or_else(|| {
        NonoError::ProfileParse(format!("invalid draft profile name '{}'", input.display()))
    })?;
    if !profile::is_valid_profile_name(name) {
        return Err(NonoError::ProfileParse(format!(
            "invalid draft profile name '{}'",
            name
        )));
    }
    profile::get_user_profile_draft_path(name)
}

pub(crate) fn cmd_validate(args: ProfileValidateArgs) -> Result<()> {
    let pol = policy::load_embedded_policy()?;
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Resolve the input. Clap parses any bare token as a `PathBuf`, so a
    // user typing `nono profile validate claude-docs` lands here with
    // `args.file = PathBuf::from("claude-docs")`. If that doesn't exist as
    // a file, treat it as a profile name and look it up the same way
    // `--profile` does.
    let target_path = if args.draft {
        resolve_validate_draft_target(&args.file)?
    } else {
        resolve_validate_target(&args.file)
    };

    // Step 1: Load profile (parse JSON + resolve inheritance).
    //
    // Open a WarningCounterGuard scope around the single parse so each
    // `emit_deprecation_warning` call triggered inside the legacy drain is
    // counted. `cmd_validate` only parses once (unlike `cmd_show`, which
    // invokes `load_profile_extends` then `load_profile`), so the count
    // matches exactly the number of deprecation lines printed — no
    // dedupe or state walking required.
    let guard = crate::deprecation_warnings::WarningCounterGuard::begin();
    let profile = match profile::load_profile_from_path(&target_path) {
        Ok(p) => Some(p),
        Err(e) => {
            let label = classify_profile_error(&e);
            errors.push(format!("{}: {}", label, e));
            None
        }
    };
    let deprecation_count = guard.finish();

    if let Some(ref profile) = profile {
        // Step 2: Check group references
        for group_name in &profile.groups.include {
            if !pol.groups.contains_key(group_name) {
                errors.push(format!("Group '{}' not found in policy.json", group_name));
            }
        }

        // Step 3: Check exclude_groups
        for excl in &profile.groups.exclude {
            if let Some(group) = pol.groups.get(excl) {
                if group.required {
                    errors.push(format!("Cannot exclude required group '{}'", excl));
                }
            } else {
                warnings.push(format!(
                    "Excluded group '{}' not found in policy.json",
                    excl
                ));
            }
        }

        // Step 5: Check for empty paths
        let check_paths = |paths: &[String], label: &str, w: &mut Vec<String>| {
            for p in paths {
                if p.trim().is_empty() {
                    w.push(format!("Empty path in {}", label));
                }
            }
        };
        check_paths(&profile.filesystem.allow, "filesystem.allow", &mut warnings);
        check_paths(&profile.filesystem.read, "filesystem.read", &mut warnings);
        check_paths(&profile.filesystem.write, "filesystem.write", &mut warnings);
        check_paths(
            &profile.filesystem.suppress_save_prompt,
            "filesystem.suppress_save_prompt",
            &mut warnings,
        );
    }

    if args.json {
        let val = serde_json::json!({
            "file": target_path.display().to_string(),
            "valid": errors.is_empty(),
            "errors": errors,
            "warnings": warnings,
            "deprecated_keys": deprecation_count,
        });
        println!("{}", to_json(&val)?);
        emit_deprecation_summary(deprecation_count);
        if !errors.is_empty() {
            return Err(NonoError::ProfileParse("validation failed".into()));
        }
        if args.strict && deprecation_count > 0 {
            std::process::exit(2);
        }
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: validating {}",
        prefix(),
        theme::fg(&target_path.display().to_string(), t.text)
    );
    println!();

    if profile.is_some() {
        println!("  {}  JSON syntax valid", theme::fg("[ok]", t.green));
    }

    if let Some(ref profile) = profile {
        let valid_groups = profile
            .groups
            .include
            .iter()
            .filter(|g| pol.groups.contains_key(g.as_str()))
            .count();
        let total_groups = profile.groups.include.len();
        if valid_groups == total_groups && total_groups > 0 {
            println!(
                "  {}  All {} group references valid",
                theme::fg("[ok]", t.green),
                total_groups
            );
        }
    }

    for w in &warnings {
        println!(
            "  {} {}",
            theme::fg("[warn]", t.yellow),
            theme::fg(w, t.yellow)
        );
    }

    for e in &errors {
        println!("  {}  {}", theme::fg("[err]", t.red), theme::fg(e, t.red));
    }

    println!();
    if errors.is_empty() {
        let suffix = if warnings.is_empty() {
            String::new()
        } else {
            format!(
                " ({} warning{})",
                warnings.len(),
                if warnings.len() == 1 { "" } else { "s" }
            )
        };
        println!(
            "  Result: {}{}",
            theme::fg("valid", t.green).bold(),
            theme::fg(&suffix, t.yellow)
        );
        emit_deprecation_summary(deprecation_count);
        if args.strict && deprecation_count > 0 {
            std::process::exit(2);
        }
        Ok(())
    } else {
        println!(
            "  Result: {} ({} error{})",
            theme::fg("invalid", t.red).bold(),
            errors.len(),
            if errors.len() == 1 { "" } else { "s" }
        );
        emit_deprecation_summary(deprecation_count);
        Err(NonoError::ProfileParse("validation failed".into()))
    }
}

// ---------------------------------------------------------------------------
// nono profile promote
// ---------------------------------------------------------------------------

pub(crate) fn cmd_promote(args: ProfilePromoteArgs) -> Result<()> {
    if args.diff && args.yes {
        return Err(NonoError::ProfileParse(
            "`--diff` cannot be combined with `--yes`".to_string(),
        ));
    }
    if !profile::is_valid_profile_name(&args.name) {
        return Err(NonoError::ProfileParse(format!(
            "invalid draft profile name '{}'",
            args.name
        )));
    }

    let draft_path = profile::get_user_profile_draft_path(&args.name)?;
    let base_path = profile::get_user_profile_draft_base_path(&args.name)?;
    let target_path = profile::get_user_profile_path(&args.name)?;

    let draft_bytes = read_regular_file(&draft_path, "profile draft")?;
    let raw_profile = profile::parse_profile_bytes(&draft_bytes)?;
    if raw_profile.meta.name != args.name {
        return Err(NonoError::ProfileParse(format!(
            "draft meta.name '{}' does not match draft name '{}'",
            raw_profile.meta.name, args.name
        )));
    }
    let resolved_profile = profile::resolve_and_finalize_profile(raw_profile)?;
    validate_promote_profile(&resolved_profile)?;

    let target_exists = regular_file_exists(&target_path, "target profile")?;
    let current_bytes = if target_exists {
        Some(read_regular_file(&target_path, "target profile")?)
    } else {
        None
    };

    if current_bytes.is_none()
        && let Some(source) = reserved_profile_source(&args.name)?
    {
        return Err(NonoError::ProfileParse(format!(
            "refusing to promote '{}' because it would shadow a {source} profile. \
                 Draft a derived profile such as '{}-local' with \"extends\": \"{}\" instead.",
            args.name, args.name, args.name
        )));
    }

    if let Some(current) = current_bytes.as_deref() {
        verify_base_hash(&base_path, current)?;
    }

    print_promote_diff(&args.name, current_bytes.as_deref(), &draft_bytes);
    if args.diff {
        return Ok(());
    }

    if !args.yes && !crate::profile_save_runtime::confirm("Promote this draft? [y/N] ", false)? {
        eprintln!("{} promotion skipped", prefix());
        return Ok(());
    }

    atomic_write_file(&target_path, &draft_bytes)?;
    let _ = fs::remove_file(&draft_path);
    let _ = fs::remove_file(&base_path);

    eprintln!(
        "{} Promoted draft to {}",
        prefix(),
        target_path.display().to_string().bold()
    );
    Ok(())
}

fn validate_promote_profile(profile: &Profile) -> Result<()> {
    let pol = policy::load_embedded_policy()?;
    let mut errors = Vec::new();

    for group_name in &profile.groups.include {
        if !pol.groups.contains_key(group_name) {
            errors.push(format!("group '{}' not found in policy.json", group_name));
        }
    }

    for excluded in &profile.groups.exclude {
        match pol.groups.get(excluded) {
            Some(group) if group.required => {
                errors.push(format!("cannot exclude required group '{}'", excluded));
            }
            Some(_) | None => {}
        }
    }

    for (label, paths) in [
        ("filesystem.allow", &profile.filesystem.allow),
        ("filesystem.read", &profile.filesystem.read),
        ("filesystem.write", &profile.filesystem.write),
        ("filesystem.allow_file", &profile.filesystem.allow_file),
        ("filesystem.read_file", &profile.filesystem.read_file),
        ("filesystem.write_file", &profile.filesystem.write_file),
    ] {
        if paths.iter().any(|path| path.trim().is_empty()) {
            errors.push(format!("empty path in {label}"));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(NonoError::ProfileParse(format!(
            "draft profile failed validation: {}",
            errors.join("; ")
        )))
    }
}

fn reserved_profile_source(name: &str) -> Result<Option<&'static str>> {
    let pol = policy::load_embedded_policy()?;
    if pol.profiles.contains_key(name) {
        return Ok(Some("built-in"));
    }
    if profile::find_pack_store_profile(name).is_some() {
        return Ok(Some("installed pack"));
    }
    Ok(None)
}

fn verify_base_hash(base_path: &Path, current_bytes: &[u8]) -> Result<()> {
    let base_bytes = read_regular_file(base_path, "profile draft base hash")?;
    let provided = std::str::from_utf8(&base_bytes)
        .map_err(|e| NonoError::ProfileParse(format!("base hash is not UTF-8: {e}")))?
        .trim();
    if provided.len() != 64 || !provided.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(NonoError::ProfileParse(format!(
            "invalid base hash in {}",
            base_path.display()
        )));
    }

    let current = sha256_hex(current_bytes);
    if !provided.eq_ignore_ascii_case(&current) {
        return Err(NonoError::ProfileParse(
            "draft base hash does not match current profile. The profile changed after the draft was written; regenerate or review the draft before promoting."
                .to_string(),
        ));
    }
    Ok(())
}

fn read_regular_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|e| NonoError::ProfileRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    let metadata = file.metadata().map_err(|e| NonoError::ProfileRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    if !metadata.file_type().is_file() {
        return Err(NonoError::ProfileParse(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| NonoError::ProfileRead {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(bytes)
}

fn regular_file_exists(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(NonoError::ProfileParse(format!(
                    "{label} must not be a symlink: {}",
                    path.display()
                )));
            }
            if !metadata.file_type().is_file() {
                return Err(NonoError::ProfileParse(format!(
                    "{label} is not a regular file: {}",
                    path.display()
                )));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(NonoError::ProfileRead {
            path: path.to_path_buf(),
            source: error,
        }),
    }
}

fn atomic_write_file(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        NonoError::ProfileParse(format!("invalid profile path {}", path.display()))
    })?;
    fs::create_dir_all(parent).map_err(|e| NonoError::ProfileRead {
        path: parent.to_path_buf(),
        source: e,
    })?;

    let file_name = path.file_name().ok_or_else(|| {
        NonoError::ProfileParse(format!("invalid profile path {}", path.display()))
    })?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp_path = parent.join(tmp_name);

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(|e| NonoError::ProfileRead {
            path: tmp_path.clone(),
            source: e,
        })?;
    if let Err(error) = file.write_all(contents) {
        let _ = fs::remove_file(&tmp_path);
        return Err(NonoError::ProfileRead {
            path: tmp_path,
            source: error,
        });
    }
    if let Err(error) = file.sync_all() {
        let _ = fs::remove_file(&tmp_path);
        return Err(NonoError::ProfileRead {
            path: tmp_path,
            source: error,
        });
    }
    drop(file);

    if let Err(error) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(NonoError::ProfileRead {
            path: path.to_path_buf(),
            source: error,
        });
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn print_promote_diff(name: &str, current: Option<&[u8]>, draft: &[u8]) {
    use similar::{ChangeTag, TextDiff};

    let old_text = current
        .map(String::from_utf8_lossy)
        .unwrap_or_else(|| "".into());
    let new_text = String::from_utf8_lossy(draft);
    let t = theme::current();

    println!(
        "{}: promote draft '{}'",
        prefix(),
        theme::fg(name, t.text).bold()
    );
    println!();
    println!("  {}", theme::fg("Diff:", t.subtext).bold());
    println!("--- profiles/{name}.json");
    println!("+++ profile-drafts/{name}.json");

    let diff = TextDiff::from_lines(&old_text, &new_text);
    let mut changed = false;
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Delete => {
                changed = true;
                print!("{}", format!("-{change}").red());
            }
            ChangeTag::Insert => {
                changed = true;
                print!("{}", format!("+{change}").green());
            }
            ChangeTag::Equal => print!(" {change}"),
        }
    }
    if !changed {
        println!("  {}", theme::fg("(no differences)", t.subtext));
    }
    println!();
}

/// Print the deprecation summary line to stderr when any legacy keys were
/// encountered during `cmd_validate`'s parse. No-op when `count == 0` to
/// keep canonical profiles silent.
fn emit_deprecation_summary(count: usize) {
    if count == 0 {
        return;
    }
    let _ = writeln!(
        std::io::stderr(),
        "found {count} deprecated keys; run 'nono profile guide' for migration mapping"
    );
}

// ---------------------------------------------------------------------------
// Profile → Manifest compilation
// ---------------------------------------------------------------------------

/// Compile a resolved profile into a capability manifest.
///
/// This produces a fully-resolved, portable manifest with absolute paths.
/// Environment variables (`~`, `$HOME`, `$TMPDIR`, etc.) are expanded.
#[allow(deprecated)] // reads commands.{allow,deny} (deprecated v0.33.0)
fn resolve_to_manifest(
    prof: &Profile,
    workdir: &std::path::Path,
) -> Result<nono::manifest::CapabilityManifest> {
    use nono::manifest;

    // Helper: expand a path template and convert to string for the manifest
    let expand = |tmpl: &str| -> Result<String> {
        let expanded = profile::expand_vars(tmpl, workdir)?;
        Ok(expanded.to_string_lossy().into_owned())
    };

    // Filesystem
    let mut grants = Vec::new();
    let mut deny = Vec::new();

    let fs_sources: &[(&[String], manifest::AccessMode, bool)] = &[
        (
            &prof.filesystem.allow,
            manifest::AccessMode::Readwrite,
            false,
        ),
        (&prof.filesystem.read, manifest::AccessMode::Read, false),
        (&prof.filesystem.write, manifest::AccessMode::Write, false),
        (
            &prof.filesystem.allow_file,
            manifest::AccessMode::Readwrite,
            true,
        ),
        (&prof.filesystem.read_file, manifest::AccessMode::Read, true),
        (
            &prof.filesystem.write_file,
            manifest::AccessMode::Write,
            true,
        ),
    ];

    for (paths, access, is_file) in fs_sources {
        for p in *paths {
            grants.push(make_fs_grant(&expand(p)?, *access, *is_file)?);
        }
    }
    // Deny paths from canonical `filesystem.deny`
    for p in &prof.filesystem.deny {
        let expanded = expand(p)?;
        deny.push(manifest::FsDeny {
            path: expanded
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid deny path: {e}")))?,
        });
    }

    // Resolve groups.include → filesystem grants, deny paths, and blocked
    // commands. Groups are the primary source of system read paths, deny
    // rules, and dangerous command blocks. Without this, the exported
    // manifest is weaker than the profile.
    let loaded_policy = policy::load_embedded_policy()?;
    let mut scratch_caps = nono::CapabilitySet::new();
    let resolved_groups =
        policy::resolve_groups(&loaded_policy, &prof.groups.include, &mut scratch_caps)?;

    // Add filesystem grants from resolved groups
    for cap in scratch_caps.fs_capabilities() {
        let access = match cap.access {
            nono::AccessMode::Read => manifest::AccessMode::Read,
            nono::AccessMode::Write => manifest::AccessMode::Write,
            nono::AccessMode::ReadWrite => manifest::AccessMode::Readwrite,
        };
        let path_str = cap.resolved.to_string_lossy().into_owned();
        grants.push(make_fs_grant(&path_str, access, cap.is_file)?);
    }

    // Expand bypass_protection paths so we can filter them out of the deny
    // list. The manifest is the fully-resolved output — overridden denies
    // must not appear, otherwise the manifest re-applies restrictions the
    // profile relaxed.
    let bypass_protection_expanded: Vec<std::path::PathBuf> = prof
        .filesystem
        .bypass_protection
        .iter()
        .filter_map(|tmpl| profile::expand_vars(tmpl, workdir).ok())
        .map(|p| {
            if p.exists() {
                p.canonicalize().unwrap_or(p)
            } else {
                p
            }
        })
        .collect();

    // Add deny paths from resolved groups, filtering out overridden paths.
    for deny_path in resolved_groups.deny_paths.iter().filter(|dp| {
        !bypass_protection_expanded
            .iter()
            .any(|ovr| dp.starts_with(ovr))
    }) {
        let path_str = deny_path.to_string_lossy().into_owned();
        deny.push(manifest::FsDeny {
            path: path_str
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid deny path: {e}")))?,
        });
    }

    // Add blocked commands from resolved groups
    let group_blocked_commands: Vec<String> = scratch_caps.blocked_commands().to_vec();

    // Add workdir access as a filesystem grant
    let workdir_str = workdir.to_string_lossy().into_owned();
    match prof.workdir.access {
        WorkdirAccess::ReadWrite => {
            grants.push(make_fs_grant(
                &workdir_str,
                manifest::AccessMode::Readwrite,
                false,
            )?);
        }
        WorkdirAccess::Read => {
            grants.push(make_fs_grant(
                &workdir_str,
                manifest::AccessMode::Read,
                false,
            )?);
        }
        WorkdirAccess::Write => {
            grants.push(make_fs_grant(
                &workdir_str,
                manifest::AccessMode::Write,
                false,
            )?);
        }
        WorkdirAccess::None => {} // no grant
    }

    // Deduplicate grants: if the same path appears from both filesystem.allow
    // and workdir (or groups), keep the highest-access-mode entry.
    grants.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    grants.dedup_by(|a, b| {
        if a.path.as_str() == b.path.as_str() && a.type_ == b.type_ {
            // Keep the broader access mode in `b` (the survivor of dedup_by)
            b.access = wider_access(a.access, b.access);
            true
        } else {
            false
        }
    });

    // Deduplicate deny entries by path
    deny.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    deny.dedup_by(|a, b| a.path.as_str() == b.path.as_str());

    let filesystem = if grants.is_empty() && deny.is_empty() {
        None
    } else {
        Some(manifest::Filesystem { grants, deny })
    };

    // Network
    let network_mode = if prof.network.block {
        manifest::NetworkMode::Blocked
    } else if prof.network.resolved_network_profile().is_some()
        || !prof.network.allow_domain.is_empty()
        || !prof.network.resolved_credentials().is_empty()
        || !prof.network.custom_credentials.is_empty()
    {
        manifest::NetworkMode::Proxy
    } else {
        manifest::NetworkMode::Unrestricted
    };

    let manifest_endpoints: Vec<manifest::NetworkEndpoint> = prof
        .network
        .allow_domain
        .iter()
        .filter_map(|e| match e {
            profile::AllowDomainEntry::WithEndpoints { domain, endpoints }
                if !endpoints.is_empty() =>
            {
                let host: manifest::NetworkEndpointHost = domain.as_str().try_into().ok()?;
                let rules = endpoints
                    .iter()
                    .filter_map(|r| {
                        let method: manifest::EndpointRuleMethod =
                            r.method.as_str().try_into().ok()?;
                        let path: manifest::EndpointRulePath = r.path.as_str().try_into().ok()?;
                        Some(manifest::EndpointRule { method, path })
                    })
                    .collect();
                Some(manifest::NetworkEndpoint { host, rules })
            }
            _ => None,
        })
        .collect();

    let network = Some(manifest::Network {
        mode: network_mode,
        allow_domains: prof
            .network
            .allow_domain
            .iter()
            .map(|e| e.domain().to_string())
            .collect(),
        endpoints: manifest_endpoints,
        dns: true,
        ports: if prof.network.listen_port.is_empty() && prof.network.open_port.is_empty() {
            None
        } else {
            Some(manifest::PortConfig {
                connect: Vec::new(),
                bind: prof
                    .network
                    .listen_port
                    .iter()
                    .filter_map(|p| std::num::NonZeroU64::new(u64::from(*p)))
                    .collect(),
                localhost: prof
                    .network
                    .open_port
                    .iter()
                    .filter_map(|p| std::num::NonZeroU64::new(u64::from(*p)))
                    .collect(),
            })
        },
    });

    // Process
    let signal_mode = match prof.security.signal_mode {
        Some(profile::ProfileSignalMode::Isolated) | None => manifest::SignalMode::Isolated,
        Some(profile::ProfileSignalMode::AllowSameSandbox) => {
            manifest::SignalMode::AllowSameSandbox
        }
        Some(profile::ProfileSignalMode::AllowAll) => manifest::SignalMode::AllowAll,
    };
    let process_info_mode = match prof.security.process_info_mode {
        Some(profile::ProfileProcessInfoMode::Isolated) | None => {
            manifest::ProcessInfoMode::Isolated
        }
        Some(profile::ProfileProcessInfoMode::AllowSameSandbox) => {
            manifest::ProcessInfoMode::AllowSameSandbox
        }
        Some(profile::ProfileProcessInfoMode::AllowAll) => manifest::ProcessInfoMode::AllowAll,
    };
    let ipc_mode = match prof.security.ipc_mode {
        Some(profile::ProfileIpcMode::SharedMemoryOnly) | None => {
            manifest::IpcMode::SharedMemoryOnly
        }
        Some(profile::ProfileIpcMode::Full) => manifest::IpcMode::Full,
    };

    let process = Some(manifest::Process {
        allowed_commands: prof.commands.allow.clone(),
        blocked_commands: {
            let mut cmds = group_blocked_commands;
            cmds.extend(prof.commands.deny.clone());
            cmds.sort();
            cmds.dedup();
            cmds
        },
        exec_strategy: if !prof.rollback.exclude_patterns.is_empty()
            || !prof.rollback.exclude_globs.is_empty()
        {
            manifest::ExecStrategy::Supervised
        } else {
            manifest::ExecStrategy::Monitor
        },
        signal_mode,
        process_info_mode,
        ipc_mode,
    });

    // Rollback
    let rollback =
        if prof.rollback.exclude_patterns.is_empty() && prof.rollback.exclude_globs.is_empty() {
            None
        } else {
            Some(manifest::Rollback {
                enabled: false,
                exclude_patterns: prof.rollback.exclude_patterns.clone(),
                exclude_globs: prof.rollback.exclude_globs.clone(),
            })
        };

    // Credentials (custom_credentials from profile → manifest credentials)
    // OAuth2 credentials (auth field) are not yet representable in the manifest
    // schema, so only static-key credentials are exported.
    let mut credentials = Vec::new();
    for (name, cred) in &prof.network.custom_credentials {
        let inject_mode = match cred.inject_mode {
            profile::InjectMode::Header => manifest::InjectMode::Header,
            profile::InjectMode::UrlPath => manifest::InjectMode::UrlPath,
            profile::InjectMode::QueryParam => manifest::InjectMode::QueryParam,
            profile::InjectMode::BasicAuth => manifest::InjectMode::BasicAuth,
        };

        let endpoint_rules: Vec<manifest::EndpointRule> = cred
            .endpoint_rules
            .iter()
            .map(|r| {
                let method = r.method.parse().map_err(|e| {
                    NonoError::ConfigParse(format!(
                        "invalid endpoint rule method '{}': {e}",
                        r.method
                    ))
                })?;
                let path = r.path.parse().map_err(|e| {
                    NonoError::ConfigParse(format!("invalid endpoint rule path '{}': {e}", r.path))
                })?;
                Ok(manifest::EndpointRule { method, path })
            })
            .collect::<Result<Vec<_>>>()?;

        credentials.push(manifest::Credential {
            name: name
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid credential name: {e}")))?,
            upstream: cred
                .upstream
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid credential upstream: {e}")))?,
            source: match cred.credential_key.as_ref() {
                Some(key) => key.parse().map_err(|e| {
                    NonoError::ConfigParse(format!("invalid credential source: {e}"))
                })?,
                None => continue,
            },
            inject: Some(manifest::CredentialInject {
                mode: inject_mode,
                header: cred.inject_header.clone(),
                format: nono_proxy::config::resolved_credential_format(
                    &cred.inject_header,
                    cred.credential_format.as_deref(),
                ),
                path_pattern: cred.path_pattern.clone(),
                path_replacement: cred.path_replacement.clone(),
                query_param_name: cred.query_param_name.clone(),
            }),
            env_var: cred
                .env_var
                .as_ref()
                .map(|v| {
                    v.parse()
                        .map_err(|e| NonoError::ConfigParse(format!("invalid env_var: {e}")))
                })
                .transpose()?,
            endpoint_rules,
        });
    }

    let version = "0.1.0"
        .parse()
        .map_err(|e| NonoError::ConfigParse(format!("version parse error: {e}")))?;

    Ok(manifest::CapabilityManifest {
        version,
        schema: Some("https://nono.sh/schemas/capability-manifest.schema.json".to_string()),
        filesystem,
        network,
        process,
        rollback,
        credentials,
        // Profiles do not yet express resource limits (issue #1102); they are
        // set via CLI flags or a hand-written manifest for now.
        resources: None,
    })
}

/// Return the broader of two access modes (Read + Write → Readwrite).
fn wider_access(
    a: nono::manifest::AccessMode,
    b: nono::manifest::AccessMode,
) -> nono::manifest::AccessMode {
    use nono::manifest::AccessMode::{Read, Readwrite, Write};
    match (a, b) {
        (Readwrite, _) | (_, Readwrite) => Readwrite,
        (Read, Write) | (Write, Read) => Readwrite,
        (Read, Read) => Read,
        (Write, Write) => Write,
    }
}

/// Helper to construct an `FsGrant` from an expanded path string.
fn make_fs_grant(
    path: &str,
    access: nono::manifest::AccessMode,
    is_file: bool,
) -> Result<nono::manifest::FsGrant> {
    Ok(nono::manifest::FsGrant {
        path: path
            .parse()
            .map_err(|e| NonoError::ConfigParse(format!("invalid grant path: {e}")))?,
        access,
        type_: if is_file {
            nono::manifest::FsEntryType::File
        } else {
            nono::manifest::FsEntryType::Directory
        },
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use std::path::PathBuf;

    /// The profile authoring guide is compiled into the binary and surfaced
    /// via `nono profile guide`. It must not instruct users to run the
    /// deprecated `nono policy <sub>` commands.
    #[test]
    fn embedded_guide_contains_no_nono_policy_references() {
        let text = crate::config::embedded::embedded_profile_guide();
        assert!(
            !text.contains("nono policy "),
            "profile-authoring-guide.md references deprecated 'nono policy ' commands — update to 'nono profile '",
        );
    }

    #[test]
    fn test_minimal_skeleton_is_valid_profile() {
        let args = ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        let json = serde_json::to_string(&skeleton).expect("serialize");
        let profile: Profile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile.meta.name, "test-profile");
    }

    #[test]
    fn test_full_skeleton_is_valid_profile() {
        let args = ProfileInitArgs {
            name: "full-test".to_string(),
            extends: Some("default".to_string()),
            groups: vec![],
            description: Some("A full test profile".to_string()),
            full: true,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        let json = serde_json::to_string(&skeleton).expect("serialize");
        let profile: Profile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile.meta.name, "full-test");
        assert_eq!(profile.extends, Some(vec!["default".to_string()]));
        assert_eq!(
            profile.meta.description,
            Some("A full test profile".to_string())
        );
    }

    #[test]
    fn test_skeleton_with_groups() {
        let args = ProfileInitArgs {
            name: "grouped".to_string(),
            extends: None,
            groups: vec!["deny_credentials".to_string()],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        let groups = skeleton["groups"]["include"].as_array().expect("array");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], "deny_credentials");
    }

    #[test]
    fn test_skeleton_omits_schema_url() {
        let args = ProfileInitArgs {
            name: "schema-test".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        // $schema is not emitted because the URL is not hosted;
        // users export the schema locally via `nono profile schema`
        assert!(skeleton.get("$schema").is_none());
    }

    #[test]
    fn test_invalid_profile_name() {
        let result = cmd_init(ProfileInitArgs {
            name: "-bad-name-".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(PathBuf::from("/tmp/nono-test-bad.json")),
            force: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(err.to_string().contains("Invalid profile name"));
    }

    #[test]
    fn test_invalid_group_name() {
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec!["nonexistent_group_xyz".to_string()],
            description: None,
            full: false,
            output: Some(PathBuf::from("/tmp/nono-test-badgroup.json")),
            force: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(err.to_string().contains("Unknown security group"));
    }

    #[test]
    fn test_invalid_extends_target() {
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: Some("nonexistent-base-profile-xyz".to_string()),
            groups: vec![],
            description: None,
            full: false,
            output: Some(PathBuf::from("/tmp/nono-test-badextends.json")),
            force: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_init_blocked_when_shadowing_builtin() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let xdg = dir.path().join("config");
        std::fs::create_dir_all(&xdg).expect("create xdg");
        let xdg_str = xdg.to_str().expect("utf8 xdg");
        let _env = crate::test_env::EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", xdg_str)]);

        // `openclaw` is a known built-in profile; init to the default path must be blocked.
        let result = cmd_init(ProfileInitArgs {
            name: "openclaw".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(
            matches!(err, nono::NonoError::Cancelled(_)),
            "expected Cancelled (shadow block), got: {err}"
        );
    }

    #[test]
    fn test_init_blocked_with_custom_output_when_shadowing_builtin() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let xdg = dir.path().join("config");
        std::fs::create_dir_all(&xdg).expect("create xdg");
        let xdg_str = xdg.to_str().expect("utf8 xdg");
        let _env = crate::test_env::EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", xdg_str)]);

        let out = dir.path().join("openclaw-draft.json");
        // Shadow check applies even when --output points to a custom path.
        let result = cmd_init(ProfileInitArgs {
            name: "openclaw".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(out.clone()),
            force: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(
            matches!(err, nono::NonoError::Cancelled(_)),
            "expected Cancelled (shadow block), got: {err}"
        );
    }

    #[test]
    fn test_init_allowed_when_pack_has_same_short_name() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let xdg = dir.path().join("config");
        std::fs::create_dir_all(&xdg).expect("create xdg");
        let xdg_str = xdg.to_str().expect("utf8 xdg");
        let _env = crate::test_env::EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", xdg_str)]);

        // Set up a fake pack that provides a profile with install_as "my-agent".
        // Creating a user profile named "my-agent" must be allowed — packs are
        // referenced by their full `org/name` key, not by `install_as`.
        let pack_dir = xdg
            .join("nono")
            .join("packages")
            .join("test-ns")
            .join("test-pack");
        std::fs::create_dir_all(pack_dir.join("profiles")).expect("mkdir pack");
        let manifest = r#"{
            "schema_version": 1,
            "name": "test-pack",
            "artifacts": [
                {"type": "profile", "path": "profiles/my-agent.json", "install_as": "my-agent"}
            ]
        }"#;
        std::fs::write(pack_dir.join("package.json"), manifest).expect("write manifest");
        std::fs::write(
            pack_dir.join("profiles").join("my-agent.json"),
            "{\"meta\":{\"name\":\"my-agent\",\"version\":\"1.0.0\"}}\n",
        )
        .expect("write pack profile");

        let profiles_dir = xdg.join("nono").join("profiles");
        std::fs::create_dir_all(&profiles_dir).expect("mkdir profiles");

        let result = cmd_init(ProfileInitArgs {
            name: "my-agent".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        });
        assert!(result.is_ok(), "expected ok, got: {:?}", result.err());
    }

    #[test]
    fn profile_validate_target_prefers_name_for_default_user_profile_path() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let xdg = dir.path().join("config");
        std::fs::create_dir_all(&xdg).expect("create xdg");
        let xdg_str = xdg.to_str().expect("utf8 xdg");
        let _env = crate::test_env::EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", xdg_str)]);

        let args = ProfileInitArgs {
            name: "copilot".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let output_path = profile::get_user_profile_path("copilot").expect("profile path");

        assert_eq!(profile_validate_target(&args, &output_path), "copilot");
    }

    #[test]
    fn profile_validate_target_uses_path_for_custom_output() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let xdg = dir.path().join("config");
        std::fs::create_dir_all(&xdg).expect("create xdg");
        let xdg_str = xdg.to_str().expect("utf8 xdg");
        let _env = crate::test_env::EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", xdg_str)]);

        let output_path = dir.path().join("custom-copilot.json");
        let args = ProfileInitArgs {
            name: "copilot".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(output_path.clone()),
            force: false,
        };

        assert_eq!(
            profile_validate_target(&args, &output_path),
            output_path.display().to_string()
        );
    }

    #[test]
    fn test_force_overwrite() {
        use std::io::Write;

        let tmp = std::env::temp_dir().join("nono-test-force-overwrite.json");
        // Create existing file
        let mut f = fs::File::create(&tmp).expect("create");
        f.write_all(b"{}").expect("write");
        drop(f);

        // Without force: should fail
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(tmp.clone()),
            force: false,
        });
        assert!(result.is_err());

        // With force: should succeed
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(tmp.clone()),
            force: true,
        });
        assert!(result.is_ok());

        // Verify file was written with correct content
        let content = fs::read_to_string(&tmp).expect("read");
        let profile: Profile = serde_json::from_str(&content).expect("parse");
        assert_eq!(profile.meta.name, "test-profile");

        // Cleanup
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_full_vs_minimal_differences() {
        let minimal_args = ProfileInitArgs {
            name: "minimal".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let full_args = ProfileInitArgs {
            name: "full".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: true,
            output: None,
            force: false,
        };
        let minimal = build_skeleton(&minimal_args);
        let full = build_skeleton(&full_args);

        let minimal_obj = minimal.as_object().expect("object");
        let full_obj = full.as_object().expect("object");

        // Full has more keys than minimal
        assert!(full_obj.len() > minimal_obj.len());

        // Full has sections that minimal does not.
        // No top-level `policy` key: per #594 the legacy `policy.*` keys
        // (exclude_groups, add_allow_*, add_deny_*, override_deny) are gone
        // and their canonical homes are top-level `groups.exclude`,
        // `commands.deny`, and `filesystem.{deny,bypass_protection,read,write,allow}`.
        assert!(!full_obj.contains_key("policy"));
        assert!(full_obj.contains_key("commands"));
        assert!(full_obj.contains_key("network"));
        assert!(full_obj.contains_key("env_credentials"));
        assert!(full_obj.contains_key("hooks"));
        assert!(full_obj.contains_key("rollback"));

        // open_urls, allow_launch_services, and allow_gpu are intentionally
        // omitted to avoid silently overriding inherited values from base profiles
        assert!(!full_obj.contains_key("open_urls"));
        assert!(!full_obj.contains_key("allow_launch_services"));
        assert!(!full_obj.contains_key("allow_gpu"));

        assert!(!minimal_obj.contains_key("commands"));
        assert!(!minimal_obj.contains_key("network"));
        assert!(!minimal_obj.contains_key("hooks"));

        // Full filesystem has all canonical fields, including the new
        // `deny` and `bypass_protection` (canonical replacements for the
        // legacy `policy` patch — see deprecated_schema.rs).
        let full_fs = full_obj["filesystem"].as_object().expect("fs object");
        assert!(full_fs.contains_key("write"));
        assert!(full_fs.contains_key("allow_file"));
        assert!(full_fs.contains_key("read_file"));
        assert!(full_fs.contains_key("write_file"));
        assert!(full_fs.contains_key("deny"));
        assert!(full_fs.contains_key("bypass_protection"));
        assert!(full_fs.contains_key("suppress_save_prompt"));

        // Minimal filesystem has only allow + read; the canonical deny /
        // bypass_protection appear only with --full.
        let min_fs = minimal_obj["filesystem"].as_object().expect("fs object");
        assert!(!min_fs.contains_key("write"));
        assert!(!min_fs.contains_key("allow_file"));
        assert!(!min_fs.contains_key("deny"));
        assert!(!min_fs.contains_key("bypass_protection"));
        assert!(!min_fs.contains_key("suppress_save_prompt"));

        // Full groups has both include and exclude; minimal has only include.
        let full_groups = full_obj["groups"].as_object().expect("groups object");
        assert!(full_groups.contains_key("include"));
        assert!(full_groups.contains_key("exclude"));
        let min_groups = minimal_obj["groups"].as_object().expect("groups object");
        assert!(min_groups.contains_key("include"));
        assert!(!min_groups.contains_key("exclude"));

        // Full commands has both allow and deny.
        let full_cmds = full_obj["commands"].as_object().expect("commands object");
        assert!(full_cmds.contains_key("allow"));
        assert!(full_cmds.contains_key("deny"));

        // Full network has all fields
        let full_net = full_obj["network"].as_object().expect("network object");
        assert!(full_net.contains_key("allow_domain"));
        assert!(full_net.contains_key("credentials"));
        assert!(full_net.contains_key("open_port"));
        assert!(full_net.contains_key("listen_port"));
        assert!(full_net.contains_key("custom_credentials"));
    }

    #[test]
    fn test_full_skeleton_emits_zero_deprecation_warnings() {
        // The init skeleton is the canonical "how do I write a profile"
        // entrypoint. It must not teach any deprecated keys; loading it
        // through the normal Profile parse path must emit zero deprecation
        // warnings via WarningCounterGuard.
        use crate::deprecation_warnings::WarningCounterGuard;

        let args = ProfileInitArgs {
            name: "skeleton-zero-warn".to_string(),
            extends: Some("default".to_string()),
            groups: vec![],
            description: None,
            full: true,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        let json = serde_json::to_string(&skeleton).expect("serialize");

        let guard = WarningCounterGuard::begin();
        let _profile: Profile = serde_json::from_str(&json).expect("deserialize");
        let count = guard.finish();
        assert_eq!(
            count, 0,
            "build_skeleton --full produced {count} deprecation warning(s); skeleton must use canonical schema only"
        );
    }

    #[test]
    fn test_minimal_skeleton_emits_zero_deprecation_warnings() {
        use crate::deprecation_warnings::WarningCounterGuard;

        let args = ProfileInitArgs {
            name: "skeleton-min-zero-warn".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        let json = serde_json::to_string(&skeleton).expect("serialize");

        let guard = WarningCounterGuard::begin();
        let _profile: Profile = serde_json::from_str(&json).expect("deserialize");
        let count = guard.finish();
        assert_eq!(
            count, 0,
            "build_skeleton minimal produced {count} deprecation warning(s)"
        );
    }

    #[test]
    fn test_groups_lists_all() {
        let pol = policy::load_embedded_policy().expect("should load policy");
        assert!(
            pol.groups.len() > 10,
            "expected many groups, got {}",
            pol.groups.len()
        );
        assert!(
            pol.groups.contains_key("deny_credentials"),
            "expected deny_credentials group"
        );
    }

    #[test]
    fn test_groups_specific_known() {
        let pol = policy::load_embedded_policy().expect("should load policy");
        let group = pol
            .groups
            .get("deny_credentials")
            .expect("deny_credentials should exist");
        assert!(!group.description.is_empty());
        assert!(group.required);
        if let Some(ref deny) = group.deny {
            let all_paths = deny.access.join(" ");
            assert!(all_paths.contains(".ssh"), "expected .ssh in deny paths");
            assert!(all_paths.contains(".aws"), "expected .aws in deny paths");
        } else {
            panic!("deny_credentials should have deny rules");
        }
    }

    #[test]
    fn test_groups_unknown_errors() {
        let pol = policy::load_embedded_policy().expect("should load policy");
        let result = cmd_groups_detail(&pol, "nonexistent_group_xyz", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_profiles_includes_builtins() {
        let profiles = profile::list_profiles();
        assert!(
            profiles.contains(&"default".to_string()),
            "expected 'default' in profiles"
        );
        assert!(
            profiles.contains(&"openclaw".to_string()),
            "expected 'openclaw' in profiles"
        );
    }

    #[test]
    fn test_show_resolves_inheritance() {
        let profile = profile::load_profile("openclaw").expect("openclaw profile should load");
        assert!(
            !profile.groups.include.is_empty(),
            "openclaw should have groups"
        );
        // openclaw extends default, so it should have default's base groups
        let has_deny = profile.groups.include.iter().any(|g| g.contains("deny"));
        assert!(has_deny, "openclaw should inherit deny groups");
    }

    #[test]
    fn test_diff_shows_differences() {
        let p1 = profile::load_profile("default").expect("default should load");
        let p2 = profile::load_profile("openclaw").expect("openclaw should load");

        let g1: BTreeSet<&str> = p1.groups.include.iter().map(|s| s.as_str()).collect();
        let g2: BTreeSet<&str> = p2.groups.include.iter().map(|s| s.as_str()).collect();

        let added: BTreeSet<&&str> = g2.difference(&g1).collect();
        assert!(
            !added.is_empty(),
            "openclaw should have additional groups over default"
        );
    }

    #[test]
    fn test_validate_valid_profile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test-profile.json");
        std::fs::write(
            &path,
            r#"{
                "meta": { "name": "test", "description": "test profile" },
                "groups": { "include": ["deny_credentials"] },
                "workdir": { "access": "readwrite" }
            }"#,
        )
        .expect("write");

        let args = ProfileValidateArgs {
            file: path,
            draft: false,
            json: false,
            strict: false,
            help: None,
        };
        let result = cmd_validate(args);
        assert!(result.is_ok(), "valid profile should pass validation");
    }

    #[test]
    fn test_validate_invalid_group() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad-profile.json");
        std::fs::write(
            &path,
            r#"{
                "meta": { "name": "test" },
                "groups": { "include": ["nonexistent_group_xyz"] }
            }"#,
        )
        .expect("write");

        let args = ProfileValidateArgs {
            file: path,
            draft: false,
            json: false,
            strict: false,
            help: None,
        };
        let result = cmd_validate(args);
        assert!(result.is_err(), "invalid group should fail validation");
    }

    #[test]
    fn test_validate_exclude_required() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad-exclude.json");
        std::fs::write(
            &path,
            r#"{
                "meta": { "name": "test" },
                "groups": { "include": [], "exclude": ["deny_credentials"] }
            }"#,
        )
        .expect("write");

        let args = ProfileValidateArgs {
            file: path,
            draft: false,
            json: false,
            strict: false,
            help: None,
        };
        let result = cmd_validate(args);
        assert!(
            result.is_err(),
            "excluding required group should fail validation"
        );
    }

    #[test]
    fn promote_creates_new_profile_from_draft_and_removes_draft() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let xdg = dir.path().join("config");
        std::fs::create_dir_all(&xdg).expect("create xdg");
        let xdg_str = xdg.to_str().expect("utf8 xdg");
        let _env = crate::test_env::EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", xdg_str)]);

        let draft_dir = profile::user_profile_draft_dir().expect("draft dir");
        std::fs::create_dir_all(&draft_dir).expect("create drafts");
        let draft_path = profile::get_user_profile_draft_path("agent-local").expect("draft path");
        std::fs::write(
            &draft_path,
            r#"{
  "meta": { "name": "agent-local" },
  "filesystem": { "read": ["/tmp"] }
}
"#,
        )
        .expect("write draft");

        let result = cmd_promote(ProfilePromoteArgs {
            name: "agent-local".to_string(),
            diff: false,
            yes: true,
            help: None,
        });
        assert!(result.is_ok(), "promote should succeed: {result:?}");
        let target = profile::get_user_profile_path("agent-local").expect("target path");
        assert!(target.exists(), "target profile should exist");
        assert!(
            !draft_path.exists(),
            "draft should be removed after promote"
        );
    }

    #[test]
    fn promote_existing_profile_requires_matching_base_hash() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let xdg = dir.path().join("config");
        std::fs::create_dir_all(&xdg).expect("create xdg");
        let xdg_str = xdg.to_str().expect("utf8 xdg");
        let _env = crate::test_env::EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", xdg_str)]);

        let profiles_dir = profile::user_profile_dir().expect("profile dir");
        let draft_dir = profile::user_profile_draft_dir().expect("draft dir");
        std::fs::create_dir_all(&profiles_dir).expect("create profiles");
        std::fs::create_dir_all(&draft_dir).expect("create drafts");

        let target = profile::get_user_profile_path("agent-local").expect("target path");
        let old = b"{\n  \"meta\": { \"name\": \"agent-local\" },\n  \"filesystem\": { \"read\": [\"/tmp\"] }\n}\n";
        std::fs::write(&target, old).expect("write target");
        let draft = profile::get_user_profile_draft_path("agent-local").expect("draft path");
        std::fs::write(
            &draft,
            "{\n  \"meta\": { \"name\": \"agent-local\" },\n  \"filesystem\": { \"read\": [\"/var/tmp\"] }\n}\n",
        )
        .expect("write draft");

        let missing_base = cmd_promote(ProfilePromoteArgs {
            name: "agent-local".to_string(),
            diff: false,
            yes: true,
            help: None,
        });
        assert!(
            missing_base.is_err(),
            "existing profile promote must require .base"
        );

        let base = profile::get_user_profile_draft_base_path("agent-local").expect("base path");
        std::fs::write(&base, sha256_hex(old)).expect("write base");
        let result = cmd_promote(ProfilePromoteArgs {
            name: "agent-local".to_string(),
            diff: false,
            yes: true,
            help: None,
        });
        assert!(result.is_ok(), "promote should succeed: {result:?}");
        let promoted = std::fs::read_to_string(&target).expect("read promoted");
        assert!(promoted.contains("/var/tmp"));
    }

    #[test]
    fn promote_refuses_to_shadow_builtin_profile() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let xdg = dir.path().join("config");
        std::fs::create_dir_all(&xdg).expect("create xdg");
        let xdg_str = xdg.to_str().expect("utf8 xdg");
        let _env = crate::test_env::EnvVarGuard::set_all(&[("XDG_CONFIG_HOME", xdg_str)]);

        let draft_dir = profile::user_profile_draft_dir().expect("draft dir");
        std::fs::create_dir_all(&draft_dir).expect("create drafts");
        let draft_path = profile::get_user_profile_draft_path("default").expect("draft path");
        std::fs::write(
            &draft_path,
            r#"{
  "meta": { "name": "default" },
  "filesystem": { "read": ["/tmp"] }
}
"#,
        )
        .expect("write draft");

        let result = cmd_promote(ProfilePromoteArgs {
            name: "default".to_string(),
            diff: false,
            yes: true,
            help: None,
        });
        assert!(
            result.is_err(),
            "promote should refuse to shadow built-in profiles"
        );
    }
}
