use crate::deps::checker::{CheckResult, DependencyCheck, get_all_checks};
use crate::deps::platform::{command_exists, PackageManager, Platform};
use std::io::{self, Write};
use std::process::Command;
use std::time::Duration;
use std::thread;

/// ANSI color codes for terminal output
struct Colors;

impl Colors {
    const GREEN: &'static str = "\x1b[32m";
    const YELLOW: &'static str = "\x1b[33m";
    const RED: &'static str = "\x1b[31m";
    const BLUE: &'static str = "\x1b[34m";
    const BOLD: &'static str = "\x1b[1m";
    const RESET: &'static str = "\x1b[0m";
}

/// Installation options
#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// Dry run - show what would be installed without doing it
    pub dry_run: bool,
    /// Skip confirmation prompts
    pub yes: bool,
    /// Maximum retry attempts for transient failures
    pub max_retries: u32,
    /// Verbose output
    pub verbose: bool,
}

/// Result of an installation attempt
#[derive(Debug)]
pub enum InstallResult {
    Success,
    Skipped(String),
    Failed(String),
    DryRun(String),
}

/// Check if sudo is available and working
pub fn check_sudo_available() -> Result<(), String> {
    // First check if we're already root
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }

    // Check if sudo command exists
    if !command_exists("sudo") {
        return Err("sudo command not found. Please run as root or install sudo.".to_string());
    }

    // Check if sudo works (cached credentials or NOPASSWD)
    let status = Command::new("sudo")
        .args(["-n", "true"])
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        _ => {
            // Sudo exists but needs password - that's fine
            println!("{}Note:{} Some operations may require your password.",
                Colors::YELLOW, Colors::RESET);
            Ok(())
        }
    }
}

/// Check if package manager is locked (another process using it)
fn check_package_manager_lock(pm: &PackageManager) -> Result<(), String> {
    let lock_files = match pm {
        PackageManager::Apt => vec![
            "/var/lib/dpkg/lock",
            "/var/lib/dpkg/lock-frontend",
            "/var/lib/apt/lists/lock",
        ],
        PackageManager::Dnf | PackageManager::Yum => vec![
            "/var/run/yum.pid",
        ],
        PackageManager::Pacman => vec![
            "/var/lib/pacman/db.lck",
        ],
        PackageManager::Zypper => vec![
            "/var/run/zypp.pid",
        ],
        _ => vec![],
    };

    for lock_file in lock_files {
        if std::path::Path::new(lock_file).exists() {
            // Check if the lock is stale (process dead)
            if let Ok(content) = std::fs::read_to_string(lock_file) {
                if let Ok(pid) = content.trim().parse::<i32>() {
                    let proc_path = format!("/proc/{}", pid);
                    if std::path::Path::new(&proc_path).exists() {
                        return Err(format!(
                            "Package manager is locked by another process (PID {}). \
                            Please wait or terminate the other process.", pid
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Wait for package manager lock to be released
fn wait_for_package_manager(pm: &PackageManager, timeout_secs: u64) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    while start.elapsed() < timeout {
        match check_package_manager_lock(pm) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if start.elapsed() < timeout {
                    println!("{}Waiting:{} {}", Colors::YELLOW, Colors::RESET, e);
                    thread::sleep(Duration::from_secs(2));
                } else {
                    return Err(e);
                }
            }
        }
    }

    check_package_manager_lock(pm)
}

/// Update package manager cache if needed
fn update_package_cache(pm: &PackageManager, options: &InstallOptions) -> Result<(), String> {
    let update_cmd = match pm {
        PackageManager::Apt => Some("sudo apt-get update -qq"),
        PackageManager::Dnf => Some("sudo dnf check-update -q || true"),
        PackageManager::Yum => Some("sudo yum check-update -q || true"),
        PackageManager::Pacman => Some("sudo pacman -Sy --noconfirm"),
        PackageManager::Apk => Some("sudo apk update -q"),
        _ => None,
    };

    if let Some(cmd) = update_cmd {
        if options.dry_run {
            println!("{}[DRY RUN]{} Would run: {}", Colors::BLUE, Colors::RESET, cmd);
            return Ok(());
        }

        if options.verbose {
            println!("{}Updating package cache...{}", Colors::BLUE, Colors::RESET);
        }

        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let (prog, args) = if parts[0] == "sudo" {
            ("sudo", &parts[1..])
        } else {
            (parts[0], &parts[1..])
        };

        let status = Command::new(prog)
            .args(args)
            .status()
            .map_err(|e| format!("Failed to update package cache: {}", e))?;

        // Don't fail on update issues - we can still try to install
        if !status.success() && options.verbose {
            println!("{}Warning:{} Package cache update had issues, continuing anyway.",
                Colors::YELLOW, Colors::RESET);
        }
    }
    Ok(())
}

/// Execute an installation command with retry logic
fn execute_with_retry(
    install_cmd: &str,
    pm: &PackageManager,
    options: &InstallOptions,
) -> Result<(), String> {
    let mut last_error = String::new();
    let max_attempts = if options.max_retries > 0 { options.max_retries } else { 3 };

    for attempt in 1..=max_attempts {
        // Wait for package manager if locked
        wait_for_package_manager(pm, 30)?;

        match execute_install_inner(install_cmd) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_error = e.clone();

                // Check if error is retryable
                let retryable = e.contains("Could not get lock") ||
                    e.contains("temporarily unavailable") ||
                    e.contains("Connection") ||
                    e.contains("timeout");

                if retryable && attempt < max_attempts {
                    let wait_secs = 2_u64.pow(attempt);
                    println!("{}Retry:{} Attempt {}/{} failed, retrying in {}s...",
                        Colors::YELLOW, Colors::RESET, attempt, max_attempts, wait_secs);
                    thread::sleep(Duration::from_secs(wait_secs));
                } else if !retryable {
                    return Err(e);
                }
            }
        }
    }

    Err(last_error)
}

/// Inner function to execute installation command
fn execute_install_inner(install_cmd: &str) -> Result<(), String> {
    let parts: Vec<&str> = install_cmd.split_whitespace().collect();
    if parts.is_empty() {
        return Err("Empty install command".to_string());
    }

    let (cmd, args) = if parts[0] == "sudo" {
        if parts.len() < 2 {
            return Err("Invalid sudo command".to_string());
        }
        ("sudo", &parts[1..])
    } else {
        (parts[0], &parts[1..])
    };

    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Command failed: {}", stderr.trim()))
    }
}

/// Attempt to install a missing dependency
pub fn attempt_install(
    check: &DependencyCheck,
    platform: &Platform,
    options: &InstallOptions,
) -> InstallResult {
    let install_cmd = match check.get_install_command(&platform.package_manager) {
        Some(cmd) => cmd,
        None => return InstallResult::Skipped("No install command available".to_string()),
    };

    // Dry run mode
    if options.dry_run {
        return InstallResult::DryRun(format!("Would run: {}", install_cmd));
    }

    // Ask for confirmation unless --yes
    if !options.yes {
        print!("{}Install {}?{} [y/N] ", Colors::BOLD, check.name, Colors::RESET);
        io::stdout().flush().ok();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return InstallResult::Skipped("Could not read input".to_string());
        }

        if !input.trim().eq_ignore_ascii_case("y") {
            return InstallResult::Skipped("Skipped by user".to_string());
        }
    }

    println!("{}Installing:{} {}", Colors::BLUE, Colors::RESET, check.name);
    if options.verbose {
        println!("  Command: {}", install_cmd);
    }

    // Execute installation with retry
    match execute_with_retry(&install_cmd, &platform.package_manager, options) {
        Ok(()) => {
            // Post-install verification and fixes
            if let Err(e) = post_install_fixes(&platform.package_manager) {
                println!("{}Warning:{} Post-install fixes failed: {}",
                    Colors::YELLOW, Colors::RESET, e);
            }

            // Verify installation
            if verify_installation(check) {
                println!("{}Success:{} {} installed and verified",
                    Colors::GREEN, Colors::RESET, check.name);
                InstallResult::Success
            } else {
                println!("{}Warning:{} {} installed but verification failed",
                    Colors::YELLOW, Colors::RESET, check.name);
                InstallResult::Success // Still count as success since package was installed
            }
        }
        Err(e) => {
            println!("{}Failed:{} {}", Colors::RED, Colors::RESET, e);
            InstallResult::Failed(e)
        }
    }
}

/// Verify that an installation was successful by re-checking
fn verify_installation(check: &DependencyCheck) -> bool {
    // Simple verification: check if the command now exists
    let commands_to_check = match check.name {
        "runc" => vec!["runc"],
        "fuse-overlayfs" => vec!["fuse-overlayfs"],
        "pasta" => vec!["pasta"],
        "slirp4netns" => vec!["slirp4netns"],
        "nsenter" => vec!["nsenter"],
        "newuidmap" => vec!["newuidmap"],
        "fusermount3" => vec!["fusermount3", "fusermount"],
        _ => return true, // Can't verify, assume success
    };

    for cmd in commands_to_check {
        if command_exists(cmd) {
            return true;
        }
    }
    false
}

fn post_install_fixes(pm: &PackageManager) -> Result<(), String> {
    // After installing fuse packages, we may need to:
    // 1. Load the fuse module
    // 2. Set SUID bits on fusermount3

    // Try to load fuse module (ignore errors - might already be loaded)
    let _ = Command::new("sudo")
        .args(["modprobe", "fuse"])
        .status();

    // Check and fix fusermount3 SUID
    let fusermount_paths = [
        "/usr/bin/fusermount3",
        "/usr/bin/fusermount",
        "/bin/fusermount3",
        "/bin/fusermount",
    ];

    for path in &fusermount_paths {
        if std::path::Path::new(path).exists() {
            if let Ok(metadata) = std::fs::metadata(path) {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                if mode & 0o4000 == 0 {
                    // Missing SUID bit, try to set it
                    println!("Setting SUID bit on {}", path);
                    let _ = Command::new("sudo")
                        .args(["chmod", "u+s", path])
                        .status();
                }
            }
        }
    }

    // Check and fix newuidmap/newgidmap SUID
    let uidmap_paths = [
        "/usr/bin/newuidmap",
        "/usr/bin/newgidmap",
    ];

    for path in &uidmap_paths {
        if std::path::Path::new(path).exists() {
            if let Ok(metadata) = std::fs::metadata(path) {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                if mode & 0o4000 == 0 {
                    println!("Setting SUID bit on {}", path);
                    let _ = Command::new("sudo")
                        .args(["chmod", "u+s", path])
                        .status();
                }
            }
        }
    }

    // Apply fixes specific to package managers
    match pm {
        PackageManager::Apt => {
            // On Debian/Ubuntu, shadow package might need extra setup
        }
        PackageManager::Pacman => {
            // On Arch, newuidmap/newgidmap might not have SUID by default
        }
        _ => {}
    }

    Ok(())
}

/// Get all packages needed for a full Carrier installation
pub fn get_all_packages(pm: &PackageManager) -> Vec<&'static str> {
    match pm {
        PackageManager::Apt => vec![
            "runc",
            "fuse-overlayfs",
            "fuse3",
            "slirp4netns",
            "passt",
            "uidmap",
            "util-linux",
        ],
        PackageManager::Dnf | PackageManager::Yum => vec![
            "runc",
            "fuse-overlayfs",
            "fuse3",
            "slirp4netns",
            "passt",
            "shadow-utils",
            "util-linux",
        ],
        PackageManager::Pacman => vec![
            "runc",
            "fuse-overlayfs",
            "fuse3",
            "slirp4netns",
            "passt",
            "shadow",
            "util-linux",
        ],
        PackageManager::Zypper => vec![
            "runc",
            "fuse-overlayfs",
            "fuse3",
            "slirp4netns",
            "shadow",
            "util-linux",
        ],
        PackageManager::Apk => vec![
            "runc",
            "fuse-overlayfs",
            "fuse3",
            "slirp4netns",
            "shadow",
            "util-linux",
        ],
        PackageManager::Brew => vec![
            "lima",
            "passt",
            "util-linux",
        ],
        _ => vec![],
    }
}

/// Generate a single command to install all dependencies
pub fn get_full_install_command(pm: &PackageManager) -> Option<String> {
    let packages = get_all_packages(pm);
    if packages.is_empty() {
        return None;
    }

    let pkg_list = packages.join(" ");

    Some(match pm {
        PackageManager::Apt => format!("sudo apt-get install -y {}", pkg_list),
        PackageManager::Dnf => format!("sudo dnf install -y {}", pkg_list),
        PackageManager::Yum => format!("sudo yum install -y {}", pkg_list),
        PackageManager::Pacman => format!("sudo pacman -S --noconfirm {}", pkg_list),
        PackageManager::Zypper => format!("sudo zypper install -y {}", pkg_list),
        PackageManager::Apk => format!("sudo apk add {}", pkg_list),
        PackageManager::Brew => format!("brew install {}", pkg_list),
        _ => return None,
    })
}

/// Install all dependencies at once
pub fn install_all(platform: &Platform, options: &InstallOptions) -> Result<(), String> {
    // Check sudo availability first
    check_sudo_available()?;

    // Wait for package manager
    wait_for_package_manager(&platform.package_manager, 60)?;

    // Update cache
    update_package_cache(&platform.package_manager, options)?;

    let install_cmd = get_full_install_command(&platform.package_manager)
        .ok_or_else(|| "No package manager detected".to_string())?;

    println!("{}Installing all Carrier dependencies...{}", Colors::BOLD, Colors::RESET);
    println!("Command: {}", install_cmd);

    // Dry run mode
    if options.dry_run {
        println!("\n{}[DRY RUN]{} Would execute the above command.", Colors::BLUE, Colors::RESET);
        println!("{}[DRY RUN]{} Would setup subuid/subgid if needed.", Colors::BLUE, Colors::RESET);
        return Ok(());
    }

    // Ask for confirmation unless --yes
    if !options.yes {
        print!("Proceed? [y/N] ");
        io::stdout().flush().map_err(|e| e.to_string())?;

        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;

        if !input.trim().eq_ignore_ascii_case("y") {
            return Err("Cancelled by user".to_string());
        }
    }

    // Execute with retry
    execute_with_retry(&install_cmd, &platform.package_manager, options)?;

    // Post-install fixes
    post_install_fixes(&platform.package_manager)?;

    // Setup subuid/subgid if needed
    setup_subuid_subgid()?;

    println!("\n{}All dependencies installed successfully!{}", Colors::GREEN, Colors::RESET);
    println!("Run 'carrier doctor' to verify the installation.");

    Ok(())
}

/// Install only missing dependencies
pub fn install_missing(platform: &Platform, options: &InstallOptions) -> Result<(usize, usize), String> {
    // Check sudo availability first
    check_sudo_available()?;

    // Wait for package manager
    wait_for_package_manager(&platform.package_manager, 60)?;

    // Update cache first
    update_package_cache(&platform.package_manager, options)?;

    let checks = get_all_checks();
    let mut installed = 0;
    let mut failed = 0;

    println!("{}Checking dependencies...{}\n", Colors::BOLD, Colors::RESET);

    for (check, check_fn) in &checks {
        let result = check_fn(platform);

        // Only try to install if missing or misconfigured
        let needs_install = matches!(
            result,
            CheckResult::Missing { .. } | CheckResult::Misconfigured { .. }
        );

        if needs_install {
            match attempt_install(check, platform, options) {
                InstallResult::Success => installed += 1,
                InstallResult::DryRun(msg) => {
                    println!("  {}", msg);
                }
                InstallResult::Skipped(reason) => {
                    if options.verbose {
                        println!("  Skipped {}: {}", check.name, reason);
                    }
                }
                InstallResult::Failed(e) => {
                    println!("{}Failed:{} {}: {}", Colors::RED, Colors::RESET, check.name, e);
                    failed += 1;
                }
            }
        } else if options.verbose {
            match result {
                CheckResult::Ok { version } => {
                    let ver_str = version.map(|v| format!(" ({})", v)).unwrap_or_default();
                    println!("{}OK:{} {}{}", Colors::GREEN, Colors::RESET, check.name, ver_str);
                }
                CheckResult::Unavailable { alternative: Some(alt), .. } => {
                    println!("{}Skip:{} {} - using {}", Colors::YELLOW, Colors::RESET, check.name, alt);
                }
                _ => {}
            }
        }
    }

    // Setup subuid/subgid if needed
    if !options.dry_run {
        if let Err(e) = setup_subuid_subgid() {
            println!("{}Warning:{} Could not setup subuid/subgid: {}",
                Colors::YELLOW, Colors::RESET, e);
        }
    }

    println!("\n{}Summary:{} {} installed, {} failed",
        Colors::BOLD, Colors::RESET, installed, failed);

    Ok((installed, failed))
}

fn setup_subuid_subgid() -> Result<(), String> {
    let username = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    // Skip for root
    if username == "root" {
        return Ok(());
    }

    // Check if subuid is configured
    let subuid_configured = std::fs::read_to_string("/etc/subuid")
        .map(|c| c.contains(&format!("{}:", username)))
        .unwrap_or(false);

    if !subuid_configured {
        println!("Setting up subordinate UID ranges for {}...", username);
        let status = Command::new("sudo")
            .args(["usermod", "--add-subuids", "100000-165535", &username])
            .status()
            .map_err(|e| format!("Failed to setup subuid: {}", e))?;

        if !status.success() {
            // Try alternative method
            let entry = format!("{}:100000:65536", username);
            let _ = Command::new("sh")
                .args(["-c", &format!("echo '{}' | sudo tee -a /etc/subuid", entry)])
                .status();
        }
    }

    // Check if subgid is configured
    let subgid_configured = std::fs::read_to_string("/etc/subgid")
        .map(|c| c.contains(&format!("{}:", username)))
        .unwrap_or(false);

    if !subgid_configured {
        println!("Setting up subordinate GID ranges for {}...", username);
        let status = Command::new("sudo")
            .args(["usermod", "--add-subgids", "100000-165535", &username])
            .status()
            .map_err(|e| format!("Failed to setup subgid: {}", e))?;

        if !status.success() {
            let entry = format!("{}:100000:65536", username);
            let _ = Command::new("sh")
                .args(["-c", &format!("echo '{}' | sudo tee -a /etc/subgid", entry)])
                .status();
        }
    }

    Ok(())
}

/// Print a summary of what would be installed (for --dry-run with --all)
pub fn print_install_summary(platform: &Platform) {
    println!("{}Carrier Dependency Installation Summary{}", Colors::BOLD, Colors::RESET);
    println!("======================================\n");

    println!("Platform: {:?}", platform.os);
    println!("Package Manager: {}\n", platform.package_manager_name());

    let checks = get_all_checks();
    let mut missing = Vec::new();
    let mut misconfigured = Vec::new();

    for (check, check_fn) in &checks {
        let result = check_fn(platform);
        match result {
            CheckResult::Missing { .. } => {
                if let Some(cmd) = check.get_install_command(&platform.package_manager) {
                    missing.push((check.name, cmd));
                }
            }
            CheckResult::Misconfigured { fix, .. } => {
                misconfigured.push((check.name, fix));
            }
            _ => {}
        }
    }

    if missing.is_empty() && misconfigured.is_empty() {
        println!("{}All dependencies are already installed!{}", Colors::GREEN, Colors::RESET);
        return;
    }

    if !missing.is_empty() {
        println!("{}Missing packages to install:{}", Colors::YELLOW, Colors::RESET);
        for (name, cmd) in &missing {
            println!("  - {}: {}", name, cmd);
        }
        println!();
    }

    if !misconfigured.is_empty() {
        println!("{}Fixes to apply:{}", Colors::YELLOW, Colors::RESET);
        for (name, fix) in &misconfigured {
            println!("  - {}: {}", name, fix);
        }
        println!();
    }

    // Show batch command
    if let Some(cmd) = get_full_install_command(&platform.package_manager) {
        println!("{}Batch install command:{}", Colors::BLUE, Colors::RESET);
        println!("  {}\n", cmd);
    }
}
