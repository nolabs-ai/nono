//! Policy introspection subcommand implementations
//!
//! Handles `nono policy groups|profiles|show|diff|validate` for inspecting
//! the group-based policy system, profiles, and security rules.

use crate::cli::{
    PolicyArgs, PolicyCommands, PolicyDiffArgs, PolicyGroupsArgs, PolicyProfilesArgs,
    PolicyShowArgs, PolicyValidateArgs,
};
use crate::policy::{self, AllowOps, DenyOps, Group};
use crate::profile::{self, Profile, WorkdirAccess};
use crate::theme;
use colored::Colorize;
use nono::{NonoError, Result};
use std::collections::BTreeSet;

/// Serialize a value to pretty-printed JSON, propagating serialization errors.
fn to_json(val: &serde_json::Value) -> Result<String> {
    serde_json::to_string_pretty(val)
        .map_err(|e| NonoError::ProfileParse(format!("JSON serialization failed: {e}")))
}

/// Prefix used for all policy command output
fn prefix() -> colored::ColoredString {
    let t = theme::current();
    theme::fg("nono policy", t.brand).bold()
}

/// Dispatch to the appropriate policy subcommand.
pub fn run_policy(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommands::Groups(args) => cmd_groups(args),
        PolicyCommands::Profiles(args) => cmd_profiles(args),
        PolicyCommands::Show(args) => cmd_show(args),
        PolicyCommands::Diff(args) => cmd_diff(args),
        PolicyCommands::Validate(args) => cmd_validate(args),
    }
}

// ---------------------------------------------------------------------------
// nono policy groups
// ---------------------------------------------------------------------------

fn cmd_groups(args: PolicyGroupsArgs) -> Result<()> {
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
            "group '{}' not found in policy.json. Use 'nono policy groups' to list available groups",
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

    if let Some(ref pairs) = group.symlink_pairs {
        if !pairs.is_empty() {
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

    if let Some(ref pairs) = group.symlink_pairs {
        if !pairs.is_empty() {
            val["symlink_pairs"] = serde_json::json!(pairs);
        }
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
// nono policy profiles
// ---------------------------------------------------------------------------

/// Determine the actual source of a loaded profile.
///
/// Load precedence is user-first (profile/mod.rs), so a user file with a
/// built-in name shadows the built-in. We must check the filesystem to
/// report the real source accurately.
fn profile_source(name: &str) -> &'static str {
    let builtin_names = profile::builtin::list_builtin();
    if profile::is_user_override(name) {
        if builtin_names.contains(&name.to_string()) {
            "user (overrides built-in)"
        } else {
            "user"
        }
    } else if builtin_names.contains(&name.to_string()) {
        "built-in"
    } else {
        "user"
    }
}

fn cmd_profiles(args: PolicyProfilesArgs) -> Result<()> {
    let builtin_names = profile::builtin::list_builtin();
    let all_names = profile::list_profiles();

    let mut builtin_profiles: Vec<(String, Result<Profile>)> = Vec::new();
    let mut user_profiles: Vec<(String, Result<Profile>)> = Vec::new();

    for name in &all_names {
        let p = profile::load_profile(name);
        // Categorize by actual source: user overrides of built-in names
        // go under user section to make shadowing visible.
        if builtin_names.contains(name) && !profile::is_user_override(name) {
            builtin_profiles.push((name.clone(), p));
        } else {
            user_profiles.push((name.clone(), p));
        }
    }

    if args.json {
        let format_entry = |name: &str, result: &Result<Profile>| {
            let source = profile_source(name);
            let extends = profile::load_profile_extends(name).unwrap_or_default();
            match result {
                Ok(p) => serde_json::json!({
                    "name": name,
                    "source": source,
                    "description": p.meta.description.as_deref().unwrap_or(""),
                    "extends": extends,
                }),
                Err(e) => serde_json::json!({
                    "name": name,
                    "source": source,
                    "error": format!("{}", e),
                }),
            }
        };

        let arr: Vec<serde_json::Value> = builtin_profiles
            .iter()
            .map(|(n, p)| format_entry(n, p))
            .chain(user_profiles.iter().map(|(n, p)| format_entry(n, p)))
            .collect();
        println!("{}", to_json(&serde_json::Value::Array(arr))?);
        return Ok(());
    }

    let t = theme::current();
    let total = builtin_profiles.len() + user_profiles.len();
    println!("{}: {} profiles", prefix(), total);

    if !builtin_profiles.is_empty() {
        println!();
        println!("  {}", theme::fg("Built-in:", t.subtext).bold());
        for (name, result) in &builtin_profiles {
            print_profile_line(name, result, t);
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
// nono policy show
// ---------------------------------------------------------------------------

fn cmd_show(args: PolicyShowArgs) -> Result<()> {
    let raw_extends = profile::load_profile_extends(&args.profile);
    let profile = profile::load_profile(&args.profile)?;

    if matches!(args.format, Some(crate::cli::PolicyShowFormat::Manifest)) {
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

    // Security groups
    if !profile.security.groups.is_empty() {
        println!();
        println!("  {}", theme::fg("Security groups:", t.subtext).bold());
        for g in &profile.security.groups {
            println!("    {}", theme::fg(g, t.text));
        }
    }

    if !profile.security.allowed_commands.is_empty() {
        println!();
        println!(
            "  {}",
            theme::fg("Allowed commands (deprecated, startup-only):", t.subtext).bold()
        );
        for cmd in &profile.security.allowed_commands {
            println!("    {}", theme::fg(cmd, t.text));
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

    // Filesystem
    let fs = &profile.filesystem;
    let has_fs = !fs.allow.is_empty()
        || !fs.read.is_empty()
        || !fs.write.is_empty()
        || !fs.allow_file.is_empty()
        || !fs.read_file.is_empty()
        || !fs.write_file.is_empty();

    if has_fs {
        println!();
        println!("  {}", theme::fg("Filesystem:", t.subtext).bold());
        print_fs_paths("allow (r+w)", &fs.allow, t, args.raw);
        print_fs_paths("read", &fs.read, t, args.raw);
        print_fs_paths("write", &fs.write, t, args.raw);
        print_fs_paths("allow_file (r+w)", &fs.allow_file, t, args.raw);
        print_fs_paths("read_file", &fs.read_file, t, args.raw);
        print_fs_paths("write_file", &fs.write_file, t, args.raw);
    }

    // Policy patches
    let pp = &profile.policy;
    let has_policy = !pp.exclude_groups.is_empty()
        || !pp.add_allow_read.is_empty()
        || !pp.add_allow_write.is_empty()
        || !pp.add_allow_readwrite.is_empty()
        || !pp.add_deny_access.is_empty()
        || !pp.add_deny_commands.is_empty()
        || !pp.override_deny.is_empty();

    if has_policy {
        println!();
        println!("  {}", theme::fg("Policy patches:", t.subtext).bold());
        if !pp.exclude_groups.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("exclude_groups", t.yellow),
                pp.exclude_groups.join(", ")
            );
        }
        print_fs_paths("add_allow_read", &pp.add_allow_read, t, args.raw);
        print_fs_paths("add_allow_write", &pp.add_allow_write, t, args.raw);
        print_fs_paths("add_allow_readwrite", &pp.add_allow_readwrite, t, args.raw);
        print_fs_paths("add_deny_access", &pp.add_deny_access, t, args.raw);
        if !pp.add_deny_commands.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("add_deny_commands (deprecated, startup-only)", t.yellow),
                pp.add_deny_commands.join(", ")
            );
        }
        if !pp.override_deny.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("override_deny", t.yellow),
                pp.override_deny.join(", ")
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
            println!(
                "    {}: {}",
                theme::fg("allow_domain", t.subtext),
                net.allow_domain.join(", ")
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

fn profile_to_json(
    name: &str,
    profile: &Profile,
    raw_extends: &Option<Vec<String>>,
) -> serde_json::Value {
    let mut val = serde_json::json!({
        "name": name,
        "description": profile.meta.description.as_deref().unwrap_or(""),
        "extends": raw_extends.as_ref().map(|v| serde_json::json!(v)).unwrap_or(serde_json::Value::Null),
    });

    // Security
    val["security"] = serde_json::json!({
        "groups": profile.security.groups,
        "allowed_commands": profile.security.allowed_commands,
        "signal_mode": format!("{:?}", profile.security.signal_mode),
        "process_info_mode": format!("{:?}", profile.security.process_info_mode),
        "ipc_mode": format!("{:?}", profile.security.ipc_mode),
        "capability_elevation": profile.security.capability_elevation,
        "wsl2_proxy_policy": format!("{:?}", profile.security.wsl2_proxy_policy),
    });

    // Filesystem
    val["filesystem"] = serde_json::json!({
        "allow": profile.filesystem.allow,
        "read": profile.filesystem.read,
        "write": profile.filesystem.write,
        "allow_file": profile.filesystem.allow_file,
        "read_file": profile.filesystem.read_file,
        "write_file": profile.filesystem.write_file,
    });

    // Policy patches
    val["policy"] = serde_json::json!({
        "exclude_groups": profile.policy.exclude_groups,
        "add_allow_read": profile.policy.add_allow_read,
        "add_allow_write": profile.policy.add_allow_write,
        "add_allow_readwrite": profile.policy.add_allow_readwrite,
        "add_deny_access": profile.policy.add_deny_access,
        "add_deny_commands": profile.policy.add_deny_commands,
        "override_deny": profile.policy.override_deny,
    });

    // Network
    val["network"] = serde_json::json!({
        "block": profile.network.block,
        "network_profile": profile.network.resolved_network_profile(),
        "allow_domain": profile.network.allow_domain,
        "reject_domain": profile.network.reject_domain,
        "credentials": profile.network.resolved_credentials(),
        "open_port": profile.network.open_port,
        "listen_port": profile.network.listen_port,
        "upstream_proxy": profile.network.upstream_proxy,
        "upstream_bypass": profile.network.upstream_bypass,
    });

    // Workdir
    val["workdir"] = serde_json::json!({
        "access": format!("{:?}", profile.workdir.access),
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
// nono policy diff
// ---------------------------------------------------------------------------

fn cmd_diff(args: PolicyDiffArgs) -> Result<()> {
    let p1 = profile::load_profile(&args.profile1)?;
    let p2 = profile::load_profile(&args.profile2)?;

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
    let g1: BTreeSet<&str> = p1.security.groups.iter().map(|s| s.as_str()).collect();
    let g2: BTreeSet<&str> = p2.security.groups.iter().map(|s| s.as_str()).collect();
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

    // Policy patches
    let pp_diffs = diff_string_vecs(&[
        (
            "exclude_groups",
            &p1.policy.exclude_groups,
            &p2.policy.exclude_groups,
        ),
        (
            "add_allow_read",
            &p1.policy.add_allow_read,
            &p2.policy.add_allow_read,
        ),
        (
            "add_allow_write",
            &p1.policy.add_allow_write,
            &p2.policy.add_allow_write,
        ),
        (
            "add_allow_readwrite",
            &p1.policy.add_allow_readwrite,
            &p2.policy.add_allow_readwrite,
        ),
        (
            "add_deny_access",
            &p1.policy.add_deny_access,
            &p2.policy.add_deny_access,
        ),
        (
            "add_deny_commands",
            &p1.policy.add_deny_commands,
            &p2.policy.add_deny_commands,
        ),
        (
            "override_deny",
            &p1.policy.override_deny,
            &p2.policy.override_deny,
        ),
    ]);

    if !pp_diffs.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Policy patches", t.subtext).bold());
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

    let net_vec_diffs = diff_string_vecs(&[
        (
            "allow_domain",
            &p1.network.allow_domain,
            &p2.network.allow_domain,
        ),
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
    let cmd1: BTreeSet<&str> = p1
        .security
        .allowed_commands
        .iter()
        .map(|s| s.as_str())
        .collect();
    let cmd2: BTreeSet<&str> = p2
        .security
        .allowed_commands
        .iter()
        .map(|s| s.as_str())
        .collect();
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
                    theme::fg(&old.credential_format, t.red)
                );
                println!(
                    "      {} credential_format: {}",
                    theme::fg("+", t.green),
                    theme::fg(&new.credential_format, t.green)
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
    if let Some(ref old) = v1 {
        println!("    {}", theme::fg(&format!("- {old}"), t.red));
    }
    if let Some(ref new) = v2 {
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

fn diff_to_json(name1: &str, name2: &str, p1: &Profile, p2: &Profile) -> serde_json::Value {
    let g1: BTreeSet<&str> = p1.security.groups.iter().map(|s| s.as_str()).collect();
    let g2: BTreeSet<&str> = p2.security.groups.iter().map(|s| s.as_str()).collect();

    let groups_added: Vec<&str> = g2.difference(&g1).copied().collect();
    let groups_removed: Vec<&str> = g1.difference(&g2).copied().collect();

    let diff_vec = |v1: &[String], v2: &[String]| -> serde_json::Value {
        let s1: BTreeSet<&str> = v1.iter().map(|s| s.as_str()).collect();
        let s2: BTreeSet<&str> = v2.iter().map(|s| s.as_str()).collect();
        let added: Vec<&str> = s2.difference(&s1).copied().collect();
        let removed: Vec<&str> = s1.difference(&s2).copied().collect();
        serde_json::json!({ "added": added, "removed": removed })
    };

    let ou1 = p1.open_urls.as_ref();
    let ou2 = p2.open_urls.as_ref();

    serde_json::json!({
        "profile1": name1,
        "profile2": name2,
        "groups": {
            "added": groups_added,
            "removed": groups_removed,
        },
        "allowed_commands": diff_vec(
            &p1.security.allowed_commands,
            &p2.security.allowed_commands,
        ),
        "capability_elevation": {
            "profile1": p1.security.capability_elevation,
            "profile2": p2.security.capability_elevation,
            "changed": p1.security.capability_elevation != p2.security.capability_elevation,
        },
        "wsl2_proxy_policy": {
            "profile1": format!("{:?}", p1.security.wsl2_proxy_policy),
            "profile2": format!("{:?}", p2.security.wsl2_proxy_policy),
            "changed": p1.security.wsl2_proxy_policy != p2.security.wsl2_proxy_policy,
        },
        "filesystem": diff_fs_json(&p1.filesystem, &p2.filesystem),
        "workdir": {
            "profile1": format!("{:?}", p1.workdir.access),
            "profile2": format!("{:?}", p2.workdir.access),
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
            "allow_domain": diff_vec(&p1.network.allow_domain, &p2.network.allow_domain),
            "reject_domain": diff_vec(&p1.network.reject_domain, &p2.network.reject_domain),
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
// nono policy validate
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

fn cmd_validate(args: PolicyValidateArgs) -> Result<()> {
    let pol = policy::load_embedded_policy()?;
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Step 1: Load profile (parse JSON + resolve inheritance)
    let profile = match profile::load_profile_from_path(&args.file) {
        Ok(p) => Some(p),
        Err(e) => {
            let label = classify_profile_error(&e);
            errors.push(format!("{}: {}", label, e));
            None
        }
    };

    if let Some(ref profile) = profile {
        // Step 2: Check group references
        for group_name in &profile.security.groups {
            if !pol.groups.contains_key(group_name) {
                errors.push(format!("Group '{}' not found in policy.json", group_name));
            }
        }

        // Step 3: Check exclude_groups
        for excl in &profile.policy.exclude_groups {
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
    }

    if args.json {
        let val = serde_json::json!({
            "file": args.file.display().to_string(),
            "valid": errors.is_empty(),
            "errors": errors,
            "warnings": warnings,
        });
        println!("{}", to_json(&val)?);
        if !errors.is_empty() {
            return Err(NonoError::ProfileParse("validation failed".into()));
        }
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: validating {}",
        prefix(),
        theme::fg(&args.file.display().to_string(), t.text)
    );
    println!();

    if profile.is_some() {
        println!("  {}  JSON syntax valid", theme::fg("[ok]", t.green));
    }

    if let Some(ref profile) = profile {
        let valid_groups = profile
            .security
            .groups
            .iter()
            .filter(|g| pol.groups.contains_key(g.as_str()))
            .count();
        let total_groups = profile.security.groups.len();
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
        Ok(())
    } else {
        println!(
            "  Result: {} ({} error{})",
            theme::fg("invalid", t.red).bold(),
            errors.len(),
            if errors.len() == 1 { "" } else { "s" }
        );
        Err(NonoError::ProfileParse("validation failed".into()))
    }
}

// ---------------------------------------------------------------------------
// Profile → Manifest compilation
// ---------------------------------------------------------------------------

/// Compile a resolved profile into a capability manifest.
///
/// This produces a fully-resolved, portable manifest with absolute paths.
/// Environment variables (`~`, `$HOME`, `$TMPDIR`, etc.) are expanded.
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
        (
            &prof.policy.add_allow_read,
            manifest::AccessMode::Read,
            false,
        ),
        (
            &prof.policy.add_allow_write,
            manifest::AccessMode::Write,
            false,
        ),
        (
            &prof.policy.add_allow_readwrite,
            manifest::AccessMode::Readwrite,
            false,
        ),
    ];

    for (paths, access, is_file) in fs_sources {
        for p in *paths {
            grants.push(make_fs_grant(&expand(p)?, *access, *is_file)?);
        }
    }
    // Deny paths from policy patches
    for p in &prof.policy.add_deny_access {
        let expanded = expand(p)?;
        deny.push(manifest::FsDeny {
            path: expanded
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid deny path: {e}")))?,
        });
    }

    // Resolve security.groups → filesystem grants, deny paths, and blocked commands.
    // Groups are the primary source of system read paths, deny rules, and dangerous
    // command blocks. Without this, the exported manifest is weaker than the profile.
    let loaded_policy = policy::load_embedded_policy()?;
    let mut scratch_caps = nono::CapabilitySet::new();
    let resolved_groups =
        policy::resolve_groups(&loaded_policy, &prof.security.groups, &mut scratch_caps)?;

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

    // Expand override_deny paths so we can filter them out of the deny list.
    // The manifest is the fully-resolved output — overridden denies must not
    // appear, otherwise the manifest re-applies restrictions the profile relaxed.
    let override_deny_expanded: Vec<std::path::PathBuf> = prof
        .policy
        .override_deny
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
    for deny_path in resolved_groups
        .deny_paths
        .iter()
        .filter(|dp| !override_deny_expanded.iter().any(|ovr| dp.starts_with(ovr)))
    {
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

    let network = Some(manifest::Network {
        mode: network_mode,
        allow_domains: prof.network.allow_domain.clone(),
        endpoints: Vec::new(),
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
        allowed_commands: prof.security.allowed_commands.clone(),
        blocked_commands: {
            let mut cmds = group_blocked_commands;
            cmds.extend(prof.policy.add_deny_commands.clone());
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
                format: cred.credential_format.clone(),
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
        schema: Some("https://nono.dev/schemas/capability-manifest.schema.json".to_string()),
        filesystem,
        network,
        process,
        rollback,
        credentials,
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
            profiles.contains(&"claude-code".to_string()),
            "expected 'claude-code' in profiles"
        );
    }

    #[test]
    fn test_show_resolves_inheritance() {
        let profile =
            profile::load_profile("claude-code").expect("claude-code profile should load");
        assert!(
            !profile.security.groups.is_empty(),
            "claude-code should have security groups"
        );
        // claude-code extends default, so it should have default's base groups
        let has_deny = profile.security.groups.iter().any(|g| g.contains("deny"));
        assert!(has_deny, "claude-code should inherit deny groups");
    }

    #[test]
    fn test_diff_shows_differences() {
        let p1 = profile::load_profile("default").expect("default should load");
        let p2 = profile::load_profile("claude-code").expect("claude-code should load");

        let g1: BTreeSet<&str> = p1.security.groups.iter().map(|s| s.as_str()).collect();
        let g2: BTreeSet<&str> = p2.security.groups.iter().map(|s| s.as_str()).collect();

        let added: BTreeSet<&&str> = g2.difference(&g1).collect();
        assert!(
            !added.is_empty(),
            "claude-code should have additional groups over default"
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
                "security": { "groups": ["deny_credentials"] },
                "workdir": { "access": "readwrite" }
            }"#,
        )
        .expect("write");

        let args = PolicyValidateArgs {
            file: path,
            json: false,
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
                "security": { "groups": ["nonexistent_group_xyz"] }
            }"#,
        )
        .expect("write");

        let args = PolicyValidateArgs {
            file: path,
            json: false,
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
                "security": { "groups": [] },
                "policy": { "exclude_groups": ["deny_credentials"] }
            }"#,
        )
        .expect("write");

        let args = PolicyValidateArgs {
            file: path,
            json: false,
        };
        let result = cmd_validate(args);
        assert!(
            result.is_err(),
            "excluding required group should fail validation"
        );
    }
}
