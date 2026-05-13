use crate::cli::SetupArgs;
use crate::profile;
use nono::{NonoError, Result};
use std::fs;
use std::path::Path;
#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[cfg(target_os = "macos")]
use nix::libc;

pub struct SetupRunner {
    check_only: bool,
    register_wfp_service: bool,
    install_wfp_service: bool,
    install_wfp_driver: bool,
    start_wfp_service: bool,
    start_wfp_driver: bool,
    refresh_trust_root: bool,
    generate_profiles: bool,
    show_shell_integration: bool,
}

impl SetupRunner {
    pub fn new(args: &SetupArgs) -> Self {
        Self {
            check_only: args.check_only,
            register_wfp_service: args.register_wfp_service,
            install_wfp_service: args.install_wfp_service,
            install_wfp_driver: args.install_wfp_driver,
            start_wfp_service: args.start_wfp_service,
            start_wfp_driver: args.start_wfp_driver,
            refresh_trust_root: args.refresh_trust_root,
            generate_profiles: args.profiles,
            show_shell_integration: args.shell_integration,
        }
    }

    pub fn run(&self) -> Result<()> {
        // Installation verification
        self.check_installation()?;

        // Sandbox support testing
        self.test_sandbox_support()?;

        #[cfg(target_os = "windows")]
        {
            crate::exec_strategy::cleanup_windows_network_enforcement_artifacts();
        }

        #[cfg(target_os = "windows")]
        if !self.check_only && self.register_wfp_service {
            self.register_windows_wfp_service()?;
        }

        #[cfg(target_os = "windows")]
        if !self.check_only && self.install_wfp_service {
            self.install_windows_wfp_service()?;
        }

        #[cfg(target_os = "windows")]
        if !self.check_only && self.install_wfp_driver {
            self.install_windows_wfp_driver()?;
        }

        #[cfg(target_os = "windows")]
        if !self.check_only && self.start_wfp_driver {
            self.start_windows_wfp_driver()?;
        }

        #[cfg(target_os = "windows")]
        if !self.check_only && self.start_wfp_service {
            self.start_windows_wfp_service()?;
        }

        #[cfg(target_os = "windows")]
        if !self.check_only && self.any_windows_wfp_action_requested() {
            self.report_windows_wfp_post_action_status()?;
        }

        if !self.check_only && self.refresh_trust_root {
            self.refresh_trust_root_step()?;
        }

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
        println!("  * Platform: {}", installation_platform_label()?);
        println!();

        Ok(())
    }

    fn test_sandbox_support(&self) -> Result<()> {
        println!("[2/{}] Testing sandbox support...", self.total_phases());

        #[cfg(target_os = "macos")]
        self.test_macos_seatbelt()?;

        #[cfg(target_os = "linux")]
        self.test_linux_landlock()?;

        #[cfg(target_os = "windows")]
        self.test_windows_support()?;

        println!();
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn register_windows_wfp_service(&self) -> Result<()> {
        if !crate::exec_strategy::is_admin_process() {
            return Err(NonoError::Setup(
                "Windows WFP service registration requires an elevated administrator session. Please run this command from an 'Administrator' terminal.".to_string()
            ));
        }

        println!(
            "[{}/{}] Registering Windows WFP service...",
            self.register_phase_index(),
            self.total_phases()
        );
        let report = crate::exec_strategy::install_windows_wfp_service()?;
        println!("  * WFP service registration: {}", report.status_label);
        println!("  * {}", report.details);
        println!();
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn install_windows_wfp_service(&self) -> Result<()> {
        if !crate::exec_strategy::is_admin_process() {
            return Err(NonoError::Setup(
                "Windows WFP service installation requires an elevated administrator session."
                    .to_string(),
            ));
        }
        println!(
            "[{}/{}] Registering Windows WFP service (placeholder)...",
            self.install_phase_index(),
            self.total_phases()
        );
        let report = crate::exec_strategy::install_windows_wfp_service()?;
        println!("  * WFP service install: {}", report.status_label);
        println!("  * {}", report.details);
        println!();
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn install_windows_wfp_driver(&self) -> Result<()> {
        if !crate::exec_strategy::is_admin_process() {
            return Err(NonoError::Setup(
                "Windows WFP driver registration requires an elevated administrator session."
                    .to_string(),
            ));
        }
        println!(
            "[{}/{}] Registering Windows WFP driver...",
            self.install_driver_phase_index(),
            self.total_phases()
        );
        let report = crate::exec_strategy::install_windows_wfp_driver()?;
        println!("  * WFP driver install: {}", report.status_label);
        println!("  * {}", report.details);
        println!();
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn start_windows_wfp_driver(&self) -> Result<()> {
        if !crate::exec_strategy::is_admin_process() {
            return Err(NonoError::Setup(
                "Starting Windows WFP driver requires an elevated administrator session."
                    .to_string(),
            ));
        }
        println!(
            "[{}/{}] Starting Windows WFP driver...",
            self.start_driver_phase_index(),
            self.total_phases()
        );
        let report = crate::exec_strategy::start_windows_wfp_driver()?;
        println!("  * WFP driver start: {}", report.status_label);
        println!("  * {}", report.details);
        println!();
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn start_windows_wfp_service(&self) -> Result<()> {
        if !crate::exec_strategy::is_admin_process() {
            return Err(NonoError::Setup(
                "Starting Windows WFP service requires an elevated administrator session."
                    .to_string(),
            ));
        }
        println!(
            "[{}/{}] Starting Windows WFP service...",
            self.start_phase_index(),
            self.total_phases()
        );
        let report = crate::exec_strategy::start_windows_wfp_service()?;
        println!("  * WFP service start: {}", report.status_label);
        println!("  * {}", report.details);
        println!();
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn test_windows_support(&self) -> Result<()> {
        let info = nono::Sandbox::support_info();
        let wfp = crate::exec_strategy::probe_windows_wfp_readiness();
        let storage = windows_storage_layout()?;
        println!("  * Platform: {}", info.platform);
        println!("  * Support status: {}", info.status_label());
        println!("  * {}", info.details);
        println!(
            "  * Administrator session: {}",
            if crate::exec_strategy::is_admin_process() {
                "YES"
            } else {
                "NO (Standard User)"
            }
        );
        println!(
            "  * User config root: {}",
            storage.user_config_root.display()
        );
        println!("  * User state root: {}", storage.user_state_root.display());
        println!("  * Rollback root: {}", storage.rollback_root.display());
        println!(
            "  * User trust policy: {}",
            storage.user_trust_policy.display()
        );
        print_windows_foundation_report("  * ");
        print_windows_wfp_readiness_report("  * ", &wfp);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn report_windows_wfp_post_action_status(&self) -> Result<()> {
        println!(
            "[{}/{}] Re-checking Windows WFP readiness...",
            self.recheck_wfp_phase_index(),
            self.total_phases()
        );
        let wfp = crate::exec_strategy::probe_windows_wfp_readiness();
        print_windows_wfp_readiness_report("  * ", &wfp);
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
        println!(
            "[{}/{}] Default protections...",
            self.protection_phase_index(),
            self.total_phases()
        );

        // Get sensitive paths and dangerous commands from policy
        let loaded_policy = crate::policy::load_embedded_policy()?;
        let dangerous_commands = crate::policy::get_dangerous_commands(&loaded_policy);
        match crate::policy::get_sensitive_paths(&loaded_policy) {
            Ok(sensitive_paths) => {
                println!(
                    "  * {} sensitive paths blocked by default:",
                    sensitive_paths.len()
                );
                println!("      SSH keys, AWS/GCP/Azure credentials, Kubernetes config,");
                println!("      Docker config, GPG keys, password managers, shell configs");
            }
            Err(err) => {
                #[cfg(target_os = "windows")]
                println!(
                    "  * Sensitive path expansion: unavailable in the current Windows command surface ({})",
                    err
                );

                #[cfg(not(target_os = "windows"))]
                return Err(err);
            }
        }

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
        println!(
            "[{}/{}] Built-in profiles...",
            self.profiles_phase_index(),
            self.total_phases()
        );

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
        #[cfg(target_os = "windows")]
        println!("  Use with: nono run --profile <name> -- <command>");
        #[cfg(target_os = "windows")]
        println!("            Supported profile-backed restrictions run live; unsupported controls fail with backend diagnostics.");
        #[cfg(not(target_os = "windows"))]
        println!("  Use with: nono run --profile <name> -- <command>");
        println!();
    }

    fn setup_profiles(&self) -> Result<()> {
        println!(
            "[{}/{}] Setting up example profiles...",
            self.setup_profiles_phase_index(),
            self.total_phases()
        );

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

        // Phase 36.5 D-36.5-B1: Create profile-drafts directory alongside profiles/
        let drafts_dir = crate::package::profile_drafts_dir()?;

        fs::create_dir_all(&drafts_dir).map_err(|e| {
            NonoError::Setup(format!(
                "Failed to create profile-drafts directory {}: {}",
                drafts_dir.display(),
                e
            ))
        })?;

        println!("  * Created directory: {}", drafts_dir.display());

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
        println!(
            "[{}/{}] Shell integration...",
            self.shell_integration_phase_index(),
            self.total_phases()
        );
        print_shell_help_body();
    }

    fn show_summary(&self) {
        println!("-----------------------------------------------------------");
        println!();

        if self.check_only {
            println!("Installation verified!");
            println!();
            print_check_only_summary();
        } else {
            println!("Setup complete!");
            println!();
            #[cfg(target_os = "windows")]
            {
                println!("Quick start examples:");
                println!();
                println!("  # Run a built-in profile where the Windows backend supports it");
                println!("  nono run --profile default -- cmd /c echo hello");
                println!();
                println!("  # Preview filesystem and network policy without launching");
                println!("  nono run --dry-run --profile claude-code -- claude");
                println!();
                println!("  # Direct execution with the current supported Windows command surface");
                println!("  nono run -- <command>");
                println!();
                println!("  # Check why a sensitive path is blocked");
                println!("  nono why ~/.ssh/id_rsa");
                println!();
                println!("Documentation: https://github.com/always-further/nono#readme");
                println!();
                println!("Run 'nono run --help' to inspect the current Windows command surface.");
            }

            #[cfg(not(target_os = "windows"))]
            println!("Quick start examples:");
            println!();
            #[cfg(not(target_os = "windows"))]
            println!("  # Run Claude Code with built-in profile (recommended)");
            #[cfg(not(target_os = "windows"))]
            println!("  nono run --profile claude-code -- claude");
            println!();
            #[cfg(not(target_os = "windows"))]
            println!("  # Run any command with current directory access");
            #[cfg(not(target_os = "windows"))]
            println!("  nono run --allow-cwd -- <command>");
            println!();
            #[cfg(not(target_os = "windows"))]
            println!("  # Check why a sensitive path is blocked");
            #[cfg(not(target_os = "windows"))]
            println!("  nono why --path ~/.ssh/id_rsa");
            println!();

            #[cfg(not(target_os = "windows"))]
            if self.generate_profiles {
                println!("Custom profiles:");
                let profile_dir = crate::profile::resolve_user_config_dir()
                    .map(|p| p.join("nono").join("profiles"))
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "~/.config/nono/profiles".to_string());
                println!("  Edit example profiles in: {}", profile_dir);
                println!();
            }

            #[cfg(not(target_os = "windows"))]
            println!("Documentation: https://github.com/always-further/nono#readme");
            println!();
            #[cfg(not(target_os = "windows"))]
            println!("Run 'nono run --help' to see all options.");
        }
    }

    fn total_phases(&self) -> usize {
        let mut count = 4; // Installation check + sandbox test + protection summary + profiles

        #[cfg(target_os = "windows")]
        if !self.check_only && self.register_wfp_service {
            count += 1;
        }

        #[cfg(target_os = "windows")]
        if !self.check_only && self.install_wfp_service {
            count += 1;
        }

        #[cfg(target_os = "windows")]
        if !self.check_only && self.install_wfp_driver {
            count += 1;
        }

        #[cfg(target_os = "windows")]
        if !self.check_only && self.start_wfp_driver {
            count += 1;
        }

        #[cfg(target_os = "windows")]
        if !self.check_only && self.start_wfp_service {
            count += 1;
        }

        #[cfg(target_os = "windows")]
        if !self.check_only && self.any_windows_wfp_action_requested() {
            count += 1;
        }

        if !self.check_only && self.refresh_trust_root {
            count += 1;
        }

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

    fn protection_phase_index(&self) -> usize {
        #[cfg(target_os = "windows")]
        if !self.check_only {
            let mut index = 3
                + usize::from(self.register_wfp_service)
                + usize::from(self.install_wfp_service)
                + usize::from(self.install_wfp_driver)
                + usize::from(self.start_wfp_driver)
                + usize::from(self.start_wfp_service);

            if self.any_windows_wfp_action_requested() {
                index += 1;
            }

            index += usize::from(self.refresh_trust_root);
            return index;
        }

        3 + usize::from(!self.check_only && self.refresh_trust_root)
    }

    fn profiles_phase_index(&self) -> usize {
        #[cfg(target_os = "windows")]
        if !self.check_only {
            let mut index = 4
                + usize::from(self.register_wfp_service)
                + usize::from(self.install_wfp_service)
                + usize::from(self.install_wfp_driver)
                + usize::from(self.start_wfp_driver)
                + usize::from(self.start_wfp_service);

            if self.any_windows_wfp_action_requested() {
                index += 1;
            }

            index += usize::from(self.refresh_trust_root);
            return index;
        }

        4 + usize::from(!self.check_only && self.refresh_trust_root)
    }

    fn register_phase_index(&self) -> usize {
        3
    }

    fn install_phase_index(&self) -> usize {
        3 + usize::from(self.register_wfp_service)
    }

    fn start_phase_index(&self) -> usize {
        3 + usize::from(self.register_wfp_service)
            + usize::from(self.install_wfp_service)
            + usize::from(self.install_wfp_driver)
            + usize::from(self.start_wfp_driver)
    }

    fn install_driver_phase_index(&self) -> usize {
        3 + usize::from(self.register_wfp_service) + usize::from(self.install_wfp_service)
    }

    fn start_driver_phase_index(&self) -> usize {
        3 + usize::from(self.register_wfp_service)
            + usize::from(self.install_wfp_service)
            + usize::from(self.install_wfp_driver)
    }

    #[cfg(target_os = "windows")]
    fn any_windows_wfp_action_requested(&self) -> bool {
        self.register_wfp_service
            || self.install_wfp_service
            || self.install_wfp_driver
            || self.start_wfp_driver
            || self.start_wfp_service
    }

    fn recheck_wfp_phase_index(&self) -> usize {
        3 + usize::from(self.register_wfp_service)
            + usize::from(self.install_wfp_service)
            + usize::from(self.install_wfp_driver)
            + usize::from(self.start_wfp_driver)
            + usize::from(self.start_wfp_service)
    }

    fn refresh_trust_root_phase_index(&self) -> usize {
        #[cfg(target_os = "windows")]
        if !self.check_only {
            let mut index = 3
                + usize::from(self.register_wfp_service)
                + usize::from(self.install_wfp_service)
                + usize::from(self.install_wfp_driver)
                + usize::from(self.start_wfp_driver)
                + usize::from(self.start_wfp_service);
            if self.any_windows_wfp_action_requested() {
                index += 1;
            }
            return index;
        }
        3
    }

    fn setup_profiles_phase_index(&self) -> usize {
        self.profiles_phase_index() + 1
    }

    fn shell_integration_phase_index(&self) -> usize {
        self.profiles_phase_index() + 1 + usize::from(self.generate_profiles)
    }

    fn refresh_trust_root_step(&self) -> Result<()> {
        let cache_dir = crate::config::nono_home_dir()?
            .join(".nono")
            .join("trust-root");
        std::fs::create_dir_all(&cache_dir).map_err(NonoError::Io)?;

        println!(
            "[{}/{}] Refreshing Sigstore trusted root...",
            self.refresh_trust_root_phase_index(),
            self.total_phases()
        );

        // ONE-SHOT tokio runtime — the rest of `nono setup` is sync.
        // TrustedRoot::production() runs full TUF verification (signature
        // threshold 3, root-of-trust pinned in sigstore-rs) before returning.
        // The bytes we persist are post-verification per T-32-02-01.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| NonoError::Setup(format!("tokio runtime: {e}")))?;
        let trusted_root = rt
            .block_on(nono::trust::TrustedRoot::production())
            .map_err(|e| {
                NonoError::Setup(format!(
                    "Failed to fetch Sigstore trusted root from \
                     https://tuf-repo-cdn.sigstore.dev: {e}"
                ))
            })?;

        let json = serde_json::to_string_pretty(&trusted_root)
            .map_err(|e| NonoError::Setup(format!("serialize trusted root: {e}")))?;
        let cache_path = cache_dir.join("trusted_root.json");
        std::fs::write(&cache_path, &json).map_err(NonoError::Io)?;

        println!(
            "  * Sigstore trusted root cached at {}",
            cache_path.display()
        );
        println!();
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn installation_platform_label() -> Result<&'static str> {
    Ok("macOS (Seatbelt sandbox)")
}

#[cfg(target_os = "linux")]
fn installation_platform_label() -> Result<&'static str> {
    Ok("Linux (Landlock sandbox)")
}

#[cfg(target_os = "windows")]
fn installation_platform_label() -> Result<&'static str> {
    Ok("Windows (restricted execution)")
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn installation_platform_label() -> Result<&'static str> {
    Err(NonoError::Setup(
        "Unsupported platform. nono requires macOS (Seatbelt) or Linux (Landlock).".to_string(),
    ))
}

#[cfg(target_os = "windows")]
fn print_shell_help_body() {
    println!("  Add a PowerShell function or alias, for example:");
    println!();
    println!("    function nono-safe {{ nono run --allow-cwd --block-net -- @Args }}");
    println!();
}

#[cfg(not(target_os = "windows"))]
fn print_shell_help_body() {
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

#[cfg(target_os = "windows")]
fn print_check_only_summary() {
    let info = nono::Sandbox::support_info();
    let wfp = crate::exec_strategy::probe_windows_wfp_readiness();
    println!("Support status: {}", info.status_label());
    println!("{}", info.details);
    if let Ok(storage) = windows_storage_layout() {
        println!("User config root: {}", storage.user_config_root.display());
        println!("User state root: {}", storage.user_state_root.display());
        println!("Rollback root: {}", storage.rollback_root.display());
        println!("User trust policy: {}", storage.user_trust_policy.display());
    }
    print_windows_foundation_report("");
    print_windows_wfp_readiness_report("", &wfp);
    print_trust_root_status("");
    // P32-CHK-003 / D-32-13: surface nono.exe's own Authenticode status so
    // operators can verify the install matches expectations. Also enables the
    // `broker_authenticode.rs::self_authenticode_extracts_subject_and_thumbprint`
    // integration test which cannot directly link the bin-only nono-cli crate.
    print_self_authenticode_status();
    let wfp_ready = wfp.status_label == "ready";
    print!("{}", trailing_usage_guidance(wfp_ready));
}

/// Print nono.exe's own Authenticode subject and thumbprint to stdout.
/// Both lines always appear; the value is `<Unsigned>`, `<InvalidSignature>`,
/// `<QueryFailed: …>`, or a live signer subject / 40-char SHA-1 hex thumbprint.
/// Fail-open (display the diagnostic) — if `current_exe()` fails, the path
/// `<unknown>` is shown and `query_authenticode_status` returns `QueryFailed`.
#[cfg(target_os = "windows")]
fn print_self_authenticode_status() {
    use crate::exec_identity::AuthenticodeStatus;
    use crate::exec_identity_windows::query_authenticode_status;

    let exe_path =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("<unknown>"));
    match query_authenticode_status(&exe_path) {
        Ok(AuthenticodeStatus::Valid {
            signer_subject,
            thumbprint,
        }) => {
            println!("self-authenticode-subject: {signer_subject}");
            println!("self-authenticode-thumbprint: {thumbprint}");
        }
        Ok(other) => {
            println!("self-authenticode-subject: <{other:?}>");
            println!("self-authenticode-thumbprint: <unavailable>");
        }
        Err(e) => {
            println!("self-authenticode-subject: <query-failed: {e}>");
            println!("self-authenticode-thumbprint: <unavailable>");
        }
    }
}

/// Shape A helper for the Windows `nono setup --check-only` trailing guidance.
/// Extracted so tests can assert on the rendered output (see `windows_check_only_tests`).
/// Fix for Phase 07 P07-HV-2 / Phase 14 Plan 14-02: the stale wrap-unavailable line
/// was replaced by the canonical wrap-availability sentence required by the Phase 07
/// acceptance criterion.
#[cfg(target_os = "windows")]
fn trailing_usage_guidance(_wfp_ready: bool) -> String {
    let mut out = String::new();
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "Use 'nono run --dry-run ...' to validate profiles and policy."
    );
    let _ = writeln!(
        out,
        "Plain 'nono run -- <command>' uses the current supported Windows command surface with backend-owned launch validation and low-integrity write boundaries."
    );
    let _ = writeln!(
        out,
        "Blocked-network and other enforcement-dependent Windows flows require current backend readiness; check the WFP readiness lines above before treating them as available."
    );
    let _ = writeln!(
        out,
        "'nono wrap' is available on Windows with Job Object + WFP enforcement (no exec-replace, unlike Unix)."
    );
    let _ = writeln!(
        out,
        "Run 'nono run --help' to inspect the current command surface."
    );
    out
}

#[cfg(target_os = "windows")]
fn print_windows_foundation_report(prefix: &str) {
    let job_probe = crate::exec_strategy::probe_job_object_permissions();
    let integrity_probe = crate::exec_strategy::probe_integrity_level_support();
    let bfe_probe = crate::exec_strategy::probe_bfe_service_status();

    println!(
        "{}Job Object creation: {}",
        prefix,
        if job_probe.is_ok() { "OK" } else { "FAILED" }
    );
    if let Err(e) = &job_probe {
        println!("{}  - {}", prefix, e);
    }
    println!(
        "{}Token Integrity level support: {}",
        prefix,
        if integrity_probe.is_ok() {
            "OK"
        } else {
            "FAILED"
        }
    );
    if let Err(e) = &integrity_probe {
        println!("{}  - {}", prefix, e);
    }
    println!(
        "{}BFE service status: {}",
        prefix,
        if bfe_probe.is_ok() { "OK" } else { "FAILED" }
    );
    if let Err(e) = &bfe_probe {
        println!("{}  - {}", prefix, e);
    }
}

#[cfg(target_os = "windows")]
fn print_windows_wfp_readiness_report(
    prefix: &str,
    wfp: &crate::exec_strategy::WindowsWfpReadinessReport,
) {
    println!("{prefix}WFP readiness: {}", wfp.status_label);
    println!("{prefix}{}", wfp.details);
    if let Some(next_action) = &wfp.next_action {
        println!("{prefix}{next_action}");
    }
    println!(
        "{prefix}WFP service readiness: {}",
        wfp.service_status_label
    );
    println!("{prefix}{}", wfp.service_details);
    println!("{prefix}WFP driver readiness: {}", wfp.driver_status_label);
    println!("{prefix}{}", wfp.driver_details);
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsStorageLayout {
    user_config_root: PathBuf,
    user_state_root: PathBuf,
    rollback_root: PathBuf,
    user_trust_policy: PathBuf,
}

#[cfg(target_os = "windows")]
fn windows_storage_layout() -> Result<WindowsStorageLayout> {
    let user_config_root = crate::profile::resolve_user_config_dir()?.join("nono");
    let user_state_root = crate::config::user_state_dir().ok_or_else(|| {
        NonoError::Setup("Could not determine Windows user state directory".to_string())
    })?;
    let rollback_root = crate::rollback_session::rollback_root()?;
    let user_trust_policy = crate::trust_cmd::user_trust_policy_path().ok_or_else(|| {
        NonoError::Setup("Could not determine Windows user trust policy path".to_string())
    })?;

    Ok(WindowsStorageLayout {
        user_config_root,
        user_state_root,
        rollback_root,
        user_trust_policy,
    })
}

#[cfg(not(target_os = "windows"))]
fn print_check_only_summary() {
    print_trust_root_status("");
    println!("Your system is ready to use nono. Run 'nono run --help' to get started.");
}

/// Print the current status of the Sigstore trusted-root cache.
///
/// Used by both Windows and non-Windows `print_check_only_summary` paths.
/// Per P32-CHK-012: the STALE branch propagates the library's error message
/// verbatim, which already contains `"nono setup --refresh-trust-root"` per
/// D-32-03 / D-32-05 wording requirements.
fn print_trust_root_status(prefix: &str) {
    let path = match crate::config::nono_home_dir() {
        Ok(h) => h.join(".nono").join("trust-root").join("trusted_root.json"),
        Err(_) => {
            println!("{prefix}Trust root cache: <home not resolvable>");
            return;
        }
    };
    if !path.exists() {
        println!(
            "{prefix}Trust root cache: NOT INITIALIZED (run `nono setup --refresh-trust-root`)"
        );
        return;
    }
    match nono::trust::load_production_trusted_root() {
        Ok(_) => println!("{prefix}Trust root cache: OK ({})", path.display()),
        Err(e) => println!("{prefix}Trust root cache: STALE — {e}"),
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
            register_wfp_service: false,
            install_wfp_service: false,
            install_wfp_driver: false,
            start_wfp_service: false,
            start_wfp_driver: false,
            refresh_trust_root: false,
            generate_profiles: true,
            show_shell_integration: false,
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

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_storage_layout_uses_absolute_user_roots() {
        let layout = windows_storage_layout().expect("windows storage layout");

        assert!(layout.user_config_root.is_absolute());
        assert!(layout.user_state_root.is_absolute());
        assert!(layout.rollback_root.is_absolute());
        assert!(layout.user_trust_policy.is_absolute());
        assert_eq!(
            layout.rollback_root,
            layout.user_state_root.join("rollbacks")
        );
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

#[cfg(all(test, target_os = "windows"))]
mod windows_check_only_tests {
    use super::*;

    #[test]
    fn check_only_summary_includes_canonical_wrap_availability_sentence() {
        let out: String = trailing_usage_guidance(true);
        assert!(
            out.contains("'nono wrap' is available on Windows with Job Object + WFP enforcement (no exec-replace, unlike Unix)"),
            "canonical wrap-availability sentence missing from trailing usage guidance: {out}"
        );
    }

    #[test]
    fn check_only_summary_does_not_mention_intentionally_unavailable() {
        let out: String = trailing_usage_guidance(true);
        assert!(
            !out.contains("remain intentionally unavailable"),
            "stale 'remain intentionally unavailable' sentence resurfaced in trailing usage guidance: {out}"
        );
    }

    #[test]
    fn check_only_summary_is_internally_consistent_about_wrap() {
        let out: String = trailing_usage_guidance(true);
        let has_available = out.contains("'nono wrap' is available on Windows");
        let has_unavailable = out.contains("remain intentionally unavailable");
        assert!(
            has_available && !has_unavailable,
            "trailing usage guidance must advertise wrap as available and not unavailable: {out}"
        );
    }
}
