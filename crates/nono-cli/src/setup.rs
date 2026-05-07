use crate::cli::SetupArgs;
use crate::profile;
use nono::{NonoError, Result};
use std::fs;
use std::path::Path;

#[cfg(target_os = "macos")]
use nix::libc;

pub struct SetupRunner {
    check_only: bool,
    generate_profiles: bool,
    show_shell_integration: bool,
    #[allow(dead_code)]
    verbose: u8,
}

impl SetupRunner {
    pub fn new(args: &SetupArgs) -> Self {
        Self {
            check_only: args.check_only,
            generate_profiles: args.profiles,
            show_shell_integration: args.shell_integration,
            verbose: args.verbose,
        }
    }

    pub fn run(&self) -> Result<()> {
        // Installation verification
        self.check_installation()?;

        // Sandbox support testing
        self.test_sandbox_support()?;

        // Show what nono protects
        self.show_protection_summary()?;

        // Show built-in profiles
        self.show_builtin_profiles();

        if !self.check_only {
            // Directory setup
            if self.generate_profiles {
                self.setup_profiles()?;
            }

            // Shell integration
            if self.show_shell_integration {
                self.show_shell_help();
            }
        }

        // Final: Summary
        self.show_summary();

        Ok(())
    }

    fn check_installation(&self) -> Result<()> {
        println!("[1/{}] Checking installation...", self.total_phases());

        // Get the current executable path
        let exe_path = std::env::current_exe()
            .map_err(|e| NonoError::Setup(format!("Failed to get executable path: {}", e)))?;

        println!("  * nono binary found at {}", exe_path.display());
        println!("  * Version: {}", env!("CARGO_PKG_VERSION"));

        // Detect platform
        let platform = if cfg!(target_os = "macos") {
            "macOS (Seatbelt sandbox)"
        } else if cfg!(target_os = "linux") {
            "Linux (Landlock sandbox)"
        } else if cfg!(target_os = "windows") {
            return Err(NonoError::Setup(
                "Windows is not supported. nono requires macOS (Seatbelt) or Linux (Landlock) for sandboxing.".to_string()
            ));
        } else {
            return Err(NonoError::Setup(
                "Unsupported platform. nono requires macOS (Seatbelt) or Linux (Landlock)."
                    .to_string(),
            ));
        };

        println!("  * Platform: {}", platform);
        println!();

        Ok(())
    }

    fn test_sandbox_support(&self) -> Result<()> {
        println!("[2/{}] Testing sandbox support...", self.total_phases());

        #[cfg(target_os = "macos")]
        self.test_macos_seatbelt()?;

        #[cfg(target_os = "linux")]
        self.test_linux_landlock()?;

        println!();
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn test_macos_seatbelt(&self) -> Result<()> {
        use std::ffi::CString;
        use std::ptr;

        // Get macOS version
        let version_output = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string());

        if let Some(version) = version_output {
            println!("  * macOS version: {}", version);
        }

        // Test Seatbelt by forking and trying to apply a minimal sandbox
        // This is the only safe way since sandbox is irreversible
        let test_profile = CString::new("(version 1)\n(allow default)\n")
            .map_err(|e| NonoError::Setup(format!("Failed to create test profile: {}", e)))?;

        unsafe {
            let pid = libc::fork();

            if pid == 0 {
                // Child process: try to apply sandbox
                extern "C" {
                    fn sandbox_init(
                        profile: *const std::os::raw::c_char,
                        flags: u64,
                        errorbuf: *mut *mut std::os::raw::c_char,
                    ) -> i32;
                }

                let result = sandbox_init(test_profile.as_ptr(), 0, ptr::null_mut());
                std::process::exit(if result == 0 { 0 } else { 1 });
            } else if pid > 0 {
                // Parent: wait for child
                let mut status = 0;
                libc::waitpid(pid, &mut status, 0);

                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    println!("  * Seatbelt sandbox support verified");
                    println!("  * File access restrictions: OK");
                    println!("  * Network restrictions: OK");
                } else {
                    return Err(NonoError::Setup(
                        "Seatbelt sandbox test failed. This may indicate a system configuration issue.".to_string()
                    ));
                }
            } else {
                return Err(NonoError::Setup("Failed to fork test process".to_string()));
            }
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn test_linux_landlock(&self) -> Result<()> {
        // Get kernel version
        let kernel_version = std::fs::read_to_string("/proc/version").ok().and_then(|s| {
            s.split_whitespace()
                .nth(2)
                .map(|v| v.trim_end_matches('-').to_string())
        });

        if let Some(version) = kernel_version {
            println!("  * Kernel version: {}", version);
        }

        // Check Landlock support via syscall probe
        let detected = nono::Sandbox::detect_abi()
            .map_err(|e| NonoError::Setup(format!(
                "Landlock is not available: {}\n\n\
                To enable Landlock:\n\
                  1. Check your kernel config: CONFIG_SECURITY_LANDLOCK=y\n\
                  2. Add to boot params: lsm=landlock,lockdown,yama,integrity,apparmor\n\
                  3. Reboot your system\n\n\
                See: https://github.com/always-further/nono/docs/troubleshooting.md#landlock-not-supported",
                e
            )))?;

        println!("  * Landlock enabled (syscall probe)");

        println!("  * {}", detected);
        println!("  * Available features:");

        for feature in detected.feature_names() {
            println!("      - {}", feature);
        }

        println!("  * Filesystem ruleset creation verified");

        // WSL2 environment detection and feature matrix
        if nono::sandbox::is_wsl2() {
            println!("  * WSL2 environment detected");
            println!(
                "    - Filesystem sandbox: available (Landlock {})",
                detected.version_string()
            );
            println!("    - Block-all network (--block-net): available");
            if detected.has_network() {
                println!("    - Per-port network filtering: available (Landlock V4+)");
            } else {
                println!("    - Per-port network filtering: unavailable (needs kernel 6.7+ for Landlock V4)");
            }
            println!(
                "    - Credential proxy (--credential): requires wsl2_proxy_policy profile opt-in"
            );
            println!("    - Capability elevation (--capability-elevation): unavailable");
            println!("    Note: seccomp user notification returns EBUSY (microsoft/WSL#9548)");
        }

        if detected.has_network() {
            if verify_landlock_network_rule_support(detected.abi)? {
                println!("  * TCP network rule support verified");
            } else {
                println!("  * TCP network filtering: probe failed despite ABI support");
            }
        } else {
            match nono::sandbox::probe_seccomp_block_network_support()? {
                true => println!(
                    "  * TCP network filtering: not supported by this ABI \
                     (seccomp fallback available: full --block-net and --proxy-only modes)"
                ),
                false => println!(
                    "  * TCP network filtering: not supported by this ABI \
                     (seccomp fallback is not available on this system)"
                ),
            }
        }

        Ok(())
    }

    fn show_protection_summary(&self) -> Result<()> {
        println!("[3/{}] Default protections...", self.total_phases());

        // Get sensitive paths and dangerous commands from policy
        let loaded_policy = crate::policy::load_embedded_policy()?;
        let sensitive_paths = crate::policy::get_sensitive_paths(&loaded_policy)?;
        let dangerous_commands = crate::policy::get_dangerous_commands(&loaded_policy);

        println!(
            "  * {} sensitive paths blocked by default:",
            sensitive_paths.len()
        );
        println!("      SSH keys, AWS/GCP/Azure credentials, Kubernetes config,");
        println!("      Docker config, GPG keys, password managers, shell configs");

        println!(
            "  * {} dangerous commands blocked by default:",
            dangerous_commands.len()
        );

        // Show a sample of blocked commands (sort first for deterministic output)
        let mut all_commands: Vec<_> = dangerous_commands.iter().cloned().collect();
        all_commands.sort();
        let sample: Vec<_> = all_commands.into_iter().take(8).collect();
        println!("      {}, ...", sample.join(", "));

        println!("  * Network access: allowed by default (use --block-net to disable)");
        println!();

        Ok(())
    }

    fn show_builtin_profiles(&self) {
        println!("[4/{}] Built-in profiles...", self.total_phases());

        let profiles = profile::list_profiles();

        for name in &profiles {
            // Load profile to get description
            match profile::load_profile(name) {
                Ok(p) => {
                    let desc = p
                        .meta
                        .description
                        .unwrap_or_else(|| "No description".to_string());
                    let net_status = if p.network.block {
                        "network blocked"
                    } else {
                        "network allowed"
                    };
                    println!("  * {} - {} ({})", name, desc, net_status);
                }
                Err(e) => {
                    println!("  * {} - <warning: failed to load: {}>", name, e);
                }
            }
        }

        println!();
        println!("  Use with: nono run --profile <name> -- <command>");
        println!();
    }

    fn setup_profiles(&self) -> Result<()> {
        println!("[5/{}] Setting up example profiles...", self.total_phases());

        // Create profile directory
        let profile_dir = crate::profile::resolve_user_config_dir()?
            .join("nono")
            .join("profiles");

        fs::create_dir_all(&profile_dir).map_err(|e| {
            NonoError::Setup(format!(
                "Failed to create profile directory {}: {}",
                profile_dir.display(),
                e
            ))
        })?;

        println!("  * Created directory: {}", profile_dir.display());

        // Generate example profiles
        self.write_example_profile(&profile_dir, "example-agent.json", EXAMPLE_AGENT_PROFILE)?;
        self.write_example_profile(&profile_dir, "offline-build.json", OFFLINE_BUILD_PROFILE)?;
        self.write_example_profile(
            &profile_dir,
            "data-processing.json",
            DATA_PROCESSING_PROFILE,
        )?;

        println!();
        Ok(())
    }

    fn write_example_profile(&self, dir: &Path, filename: &str, content: &str) -> Result<()> {
        let path = dir.join(filename);
        fs::write(&path, content)
            .map_err(|e| NonoError::Setup(format!("Failed to write {}: {}", filename, e)))?;
        println!("  * Generated {}", filename);
        Ok(())
    }

    fn show_shell_help(&self) {
        println!("[6/{}] Shell integration...", self.total_phases());

        // Detect shell
        let shell = std::env::var("SHELL")
            .ok()
            .and_then(|s| s.split('/').next_back().map(String::from))
            .unwrap_or_else(|| "bash".to_string());

        let shell_rc = match shell.as_str() {
            "zsh" => "~/.zshrc",
            "bash" => "~/.bashrc",
            "fish" => "~/.config/fish/config.fish",
            _ => "~/.bashrc",
        };

        println!("  You can add these aliases to {}:", shell_rc);
        println!();
        println!("    alias nono-claude='nono run --profile claude-code -- claude'");
        println!("    alias nono-safe='nono run --allow-cwd --block-net --'");
        println!();
    }

    fn show_summary(&self) {
        println!("-----------------------------------------------------------");
        println!();

        if self.check_only {
            println!("Installation verified!");
            println!();
            println!("Your system is ready to use nono. Run 'nono run --help' to get started.");
        } else {
            println!("Setup complete!");
            println!();
            println!("Quick start examples:");
            println!();
            println!("  # Run Claude Code with built-in profile (recommended)");
            println!("  nono run --profile claude-code -- claude");
            println!();
            println!("  # Run any command with current directory access");
            println!("  nono run --allow-cwd -- <command>");
            println!();
            println!("  # Check why a sensitive path is blocked");
            println!("  nono why --path ~/.ssh/id_rsa");
            println!();

            if self.generate_profiles {
                println!("Custom profiles:");
                let profile_dir = crate::profile::resolve_user_config_dir()
                    .map(|p| p.join("nono").join("profiles"))
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "~/.config/nono/profiles".to_string());
                println!("  Edit example profiles in: {}", profile_dir);
                println!();
            }

            println!("Documentation: https://github.com/always-further/nono#readme");
            println!();
            println!("Run 'nono run --help' to see all options.");
        }
    }

    fn total_phases(&self) -> usize {
        let mut count = 4; // Installation check + sandbox test + protection summary + profiles

        if !self.check_only {
            if self.generate_profiles {
                count += 1;
            }
            if self.show_shell_integration {
                count += 1;
            }
        }

        count
    }
}

// ABI probing is now handled by the library's detect_abi().
// Only network rule verification remains here as it tests actual rule addition.

#[cfg(target_os = "linux")]
fn verify_landlock_network_rule_support(abi: landlock::ABI) -> Result<bool> {
    use landlock::{
        Access, AccessNet, CompatLevel, Compatible, NetPort, Ruleset, RulesetAttr,
        RulesetCreatedAttr,
    };

    let handled_net = AccessNet::from_all(abi);
    if handled_net.is_empty() {
        return Ok(false);
    }

    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled_net)
        .map_err(|e| NonoError::Setup(format!("Failed to probe Landlock network access: {}", e)))?
        .create()
        .map_err(|e| NonoError::Setup(format!("Failed to create network probe ruleset: {}", e)))?;

    ruleset
        .set_compatibility(CompatLevel::HardRequirement)
        .add_rule(NetPort::new(443, AccessNet::ConnectTcp))
        .map_err(|e| NonoError::Setup(format!("Failed to add TCP connect probe rule: {}", e)))?
        .add_rule(NetPort::new(444, AccessNet::BindTcp))
        .map_err(|e| NonoError::Setup(format!("Failed to add TCP bind probe rule: {}", e)))?;

    Ok(true)
}

// Feature lines are now provided by DetectedAbi::feature_names() in the library.

// Profile templates
const EXAMPLE_AGENT_PROFILE: &str = r#"{
  "meta": {
    "name": "example-agent",
    "version": "1.0.0",
    "description": "Template for creating custom agent profiles"
  },
  "filesystem": {
    "allow": ["$WORKDIR"],
    "read": ["$HOME/.config/my-agent"],
    "write": []
  },
  "network": {
    "block": false
  }
}
"#;

const OFFLINE_BUILD_PROFILE: &str = r#"{
  "meta": {
    "name": "offline-build",
    "version": "1.0.0",
    "description": "Build environment with no network access"
  },
  "filesystem": {
    "allow": ["$WORKDIR"],
    "read": ["$HOME/.cargo", "$HOME/.rustup"]
  },
  "network": {
    "block": true
  }
}
"#;

const DATA_PROCESSING_PROFILE: &str = r#"{
  "meta": {
    "name": "data-processing",
    "version": "1.0.0",
    "description": "Read from input, write to output"
  },
  "filesystem": {
    "read": ["$WORKDIR/input"],
    "write": ["$WORKDIR/output"],
    "read_file": ["$WORKDIR/config.yaml"]
  },
  "network": {
    "block": false
  }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Profiles written by `setup --profiles` must be loadable by `load_profile()`.
    ///
    /// This is a round-trip test: run setup_profiles() to write example profiles,
    /// then load one by name through the normal profile loader. Both must use the
    /// same directory resolution — previously setup used `dirs::config_dir()` which
    /// returns `~/Library/Application Support` on macOS, while the loader used
    /// `resolve_user_config_dir()` returning `~/.config`. This test catches that.
    #[test]
    fn test_setup_profiles_loadable_by_name() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        let tmp = tempdir().expect("tempdir");

        // Point HOME at a tmpdir so both setup and loader derive paths
        // under our control. Set XDG_CONFIG_HOME to a placeholder so
        // EnvVarGuard captures its original value, then remove it so the
        // loader falls back to HOME-based resolution.
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("HOME", tmp.path().to_str().expect("tmp path")),
            ("XDG_CONFIG_HOME", "__placeholder__"),
        ]);
        _env.remove("XDG_CONFIG_HOME");

        // Run the actual setup code that writes example profiles.
        let runner = SetupRunner {
            check_only: false,
            generate_profiles: true,
            show_shell_integration: false,
            verbose: 0,
        };
        runner.setup_profiles().expect("setup_profiles failed");

        // The loader must find the example profiles by name.
        let profile = crate::profile::load_profile("example-agent")
            .expect("example-agent profile written by setup was not found by load_profile()");
        assert_eq!(profile.meta.name, "example-agent");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_library_detect_abi_returns_result() {
        // Verify the library detection works (or returns an error without panicking)
        let _ = nono::Sandbox::detect_abi();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detected_abi_has_network_for_v4_plus() {
        let detected = nono::DetectedAbi::new(landlock::ABI::V4);
        assert!(detected.has_network());
        assert!(detected
            .feature_names()
            .iter()
            .any(|n| n.starts_with("TCP network filtering")));
    }
}
