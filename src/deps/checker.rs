use crate::deps::installer::{attempt_install, InstallOptions};
use crate::deps::platform::{command_exists, detect_platform, get_command_version, PackageManager, Platform};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum Category {
    Essential,
    Recommended,
    Optional,
}

#[derive(Debug, Clone)]
pub enum CheckResult {
    Ok {
        version: Option<String>,
    },
    Missing {
        suggestion: String,
    },
    Misconfigured {
        issue: String,
        fix: String,
    },
    Unavailable {
        reason: String,
        alternative: Option<String>,
    },
}

impl CheckResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, CheckResult::Ok { .. })
    }

    pub fn is_error(&self) -> bool {
        matches!(self, CheckResult::Missing { .. } | CheckResult::Unavailable { reason: _, alternative: None })
    }

    pub fn is_warning(&self) -> bool {
        matches!(self, CheckResult::Misconfigured { .. } | CheckResult::Unavailable { reason: _, alternative: Some(_) })
    }
}

pub struct DependencyCheck {
    pub name: &'static str,
    pub category: Category,
    pub purpose: &'static str,
    pub alternatives: Vec<&'static str>,
    pub install_packages: HashMap<PackageManager, Vec<&'static str>>,
}

impl DependencyCheck {
    pub fn get_install_command(&self, pm: &PackageManager) -> Option<String> {
        self.install_packages.get(pm).map(|packages| {
            let pkg_list = packages.join(" ");
            match pm {
                PackageManager::Apt => format!("sudo apt-get install -y {}", pkg_list),
                PackageManager::Dnf => format!("sudo dnf install -y {}", pkg_list),
                PackageManager::Yum => format!("sudo yum install -y {}", pkg_list),
                PackageManager::Pacman => format!("sudo pacman -S --noconfirm {}", pkg_list),
                PackageManager::Zypper => format!("sudo zypper install -y {}", pkg_list),
                PackageManager::Apk => format!("sudo apk add {}", pkg_list),
                PackageManager::Emerge => format!("sudo emerge {}", pkg_list),
                PackageManager::Xbps => format!("sudo xbps-install -y {}", pkg_list),
                PackageManager::NixEnv => format!("nix-env -iA nixpkgs.{}", pkg_list),
                PackageManager::Brew => format!("brew install {}", pkg_list),
                PackageManager::None => format!("# Install {} manually", pkg_list),
            }
        })
    }
}

fn create_install_map(entries: &[(&[PackageManager], &[&'static str])]) -> HashMap<PackageManager, Vec<&'static str>> {
    let mut map = HashMap::new();
    for (pms, packages) in entries {
        for pm in *pms {
            map.insert(pm.clone(), packages.to_vec());
        }
    }
    map
}

pub fn get_all_checks() -> Vec<(DependencyCheck, Box<dyn Fn(&Platform) -> CheckResult>)> {
    vec![
        // runc - Essential container runtime
        (
            DependencyCheck {
                name: "runc",
                category: Category::Essential,
                purpose: "OCI-compliant container runtime",
                alternatives: vec!["crun"],
                install_packages: create_install_map(&[
                    (&[PackageManager::Apt], &["runc"]),
                    (&[PackageManager::Dnf, PackageManager::Yum], &["runc"]),
                    (&[PackageManager::Pacman], &["runc"]),
                    (&[PackageManager::Zypper], &["runc"]),
                    (&[PackageManager::Apk], &["runc"]),
                    (&[PackageManager::Brew], &["lima"]),
                ]),
            },
            Box::new(|_platform| check_runc()),
        ),
        // fuse-overlayfs - Storage driver
        (
            DependencyCheck {
                name: "fuse-overlayfs",
                category: Category::Essential,
                purpose: "FUSE-based overlay filesystem for rootless containers",
                alternatives: vec!["native overlay (kernel 5.11+)", "VFS (slower)"],
                install_packages: create_install_map(&[
                    (&[PackageManager::Apt], &["fuse-overlayfs"]),
                    (&[PackageManager::Dnf, PackageManager::Yum], &["fuse-overlayfs"]),
                    (&[PackageManager::Pacman], &["fuse-overlayfs"]),
                    (&[PackageManager::Zypper], &["fuse-overlayfs"]),
                    (&[PackageManager::Apk], &["fuse-overlayfs"]),
                ]),
            },
            Box::new(|platform| check_fuse_overlayfs(platform)),
        ),
        // /dev/fuse device
        (
            DependencyCheck {
                name: "/dev/fuse",
                category: Category::Essential,
                purpose: "FUSE device for userspace filesystems",
                alternatives: vec!["VFS storage (no FUSE needed)"],
                install_packages: create_install_map(&[
                    (&[PackageManager::Apt], &["fuse3"]),
                    (&[PackageManager::Dnf, PackageManager::Yum], &["fuse3"]),
                    (&[PackageManager::Pacman], &["fuse3"]),
                    (&[PackageManager::Zypper], &["fuse3"]),
                    (&[PackageManager::Apk], &["fuse3"]),
                ]),
            },
            Box::new(|platform| check_dev_fuse(platform)),
        ),
        // fusermount3
        (
            DependencyCheck {
                name: "fusermount3",
                category: Category::Essential,
                purpose: "FUSE mount/unmount utility (requires SUID)",
                alternatives: vec![],
                install_packages: create_install_map(&[
                    (&[PackageManager::Apt], &["fuse3"]),
                    (&[PackageManager::Dnf, PackageManager::Yum], &["fuse3"]),
                    (&[PackageManager::Pacman], &["fuse3"]),
                    (&[PackageManager::Zypper], &["fuse3"]),
                    (&[PackageManager::Apk], &["fuse3"]),
                ]),
            },
            Box::new(|_platform| check_fusermount3()),
        ),
        // pasta (preferred networking)
        (
            DependencyCheck {
                name: "pasta",
                category: Category::Recommended,
                purpose: "High-performance userspace networking",
                alternatives: vec!["slirp4netns"],
                install_packages: create_install_map(&[
                    (&[PackageManager::Apt], &["passt"]),
                    (&[PackageManager::Dnf, PackageManager::Yum], &["passt"]),
                    (&[PackageManager::Pacman], &["passt"]),
                    (&[PackageManager::Brew], &["passt"]),
                ]),
            },
            Box::new(|_platform| check_pasta()),
        ),
        // slirp4netns (fallback networking)
        (
            DependencyCheck {
                name: "slirp4netns",
                category: Category::Recommended,
                purpose: "Userspace networking (fallback)",
                alternatives: vec!["pasta"],
                install_packages: create_install_map(&[
                    (&[PackageManager::Apt], &["slirp4netns"]),
                    (&[PackageManager::Dnf, PackageManager::Yum], &["slirp4netns"]),
                    (&[PackageManager::Pacman], &["slirp4netns"]),
                    (&[PackageManager::Zypper], &["slirp4netns"]),
                    (&[PackageManager::Apk], &["slirp4netns"]),
                    (&[PackageManager::Brew], &["slirp4netns"]),
                ]),
            },
            Box::new(|_platform| check_slirp4netns()),
        ),
        // nsenter
        (
            DependencyCheck {
                name: "nsenter",
                category: Category::Recommended,
                purpose: "Enter container namespaces (for shell/exec)",
                alternatives: vec![],
                install_packages: create_install_map(&[
                    (&[PackageManager::Apt], &["util-linux"]),
                    (&[PackageManager::Dnf, PackageManager::Yum], &["util-linux"]),
                    (&[PackageManager::Pacman], &["util-linux"]),
                    (&[PackageManager::Zypper], &["util-linux"]),
                    (&[PackageManager::Apk], &["util-linux"]),
                    (&[PackageManager::Brew], &["util-linux"]),
                ]),
            },
            Box::new(|_platform| check_nsenter()),
        ),
        // newuidmap
        (
            DependencyCheck {
                name: "newuidmap",
                category: Category::Recommended,
                purpose: "UID mapping for rootless containers",
                alternatives: vec!["single-UID mode (limited functionality)"],
                install_packages: create_install_map(&[
                    (&[PackageManager::Apt], &["uidmap"]),
                    (&[PackageManager::Dnf, PackageManager::Yum], &["shadow-utils"]),
                    (&[PackageManager::Pacman], &["shadow"]),
                    (&[PackageManager::Zypper], &["shadow"]),
                    (&[PackageManager::Apk], &["shadow"]),
                ]),
            },
            Box::new(|_platform| check_newuidmap()),
        ),
        // User namespaces
        (
            DependencyCheck {
                name: "user_namespaces",
                category: Category::Essential,
                purpose: "Kernel support for unprivileged user namespaces",
                alternatives: vec!["run as root (not recommended)"],
                install_packages: HashMap::new(),
            },
            Box::new(|_platform| check_user_namespaces()),
        ),
        // /etc/subuid
        (
            DependencyCheck {
                name: "/etc/subuid",
                category: Category::Recommended,
                purpose: "Subordinate UID ranges for user",
                alternatives: vec!["single-UID mode"],
                install_packages: HashMap::new(),
            },
            Box::new(|_platform| check_subuid()),
        ),
        // /etc/subgid
        (
            DependencyCheck {
                name: "/etc/subgid",
                category: Category::Recommended,
                purpose: "Subordinate GID ranges for user",
                alternatives: vec!["single-GID mode"],
                install_packages: HashMap::new(),
            },
            Box::new(|_platform| check_subgid()),
        ),
    ]
}

// Individual check functions

fn check_runc() -> CheckResult {
    if command_exists("runc") {
        let version = get_command_version("runc");
        CheckResult::Ok { version }
    } else if command_exists("crun") {
        CheckResult::Unavailable {
            reason: "runc not found".to_string(),
            alternative: Some("crun is available and can be used instead".to_string()),
        }
    } else {
        CheckResult::Missing {
            suggestion: "Install runc package".to_string(),
        }
    }
}

fn check_fuse_overlayfs(platform: &Platform) -> CheckResult {
    if platform.is_macos() {
        return CheckResult::Unavailable {
            reason: "FUSE-overlayfs not available on macOS".to_string(),
            alternative: Some("VFS storage driver will be used".to_string()),
        };
    }

    if command_exists("fuse-overlayfs") {
        let version = get_command_version("fuse-overlayfs");
        CheckResult::Ok { version }
    } else {
        // Check if native overlay might work
        if can_use_native_overlay() {
            CheckResult::Unavailable {
                reason: "fuse-overlayfs not installed".to_string(),
                alternative: Some("Native overlay support detected (kernel 5.11+)".to_string()),
            }
        } else {
            CheckResult::Missing {
                suggestion: "Install fuse-overlayfs package".to_string(),
            }
        }
    }
}

fn check_dev_fuse(platform: &Platform) -> CheckResult {
    if platform.is_macos() {
        return CheckResult::Unavailable {
            reason: "/dev/fuse not available on macOS".to_string(),
            alternative: Some("VFS storage driver will be used".to_string()),
        };
    }

    if Path::new("/dev/fuse").exists() {
        CheckResult::Ok { version: None }
    } else {
        // Check if fuse module can be loaded
        CheckResult::Misconfigured {
            issue: "/dev/fuse device not found".to_string(),
            fix: "sudo modprobe fuse".to_string(),
        }
    }
}

fn check_fusermount3() -> CheckResult {
    let paths = ["/usr/bin/fusermount3", "/usr/bin/fusermount", "/bin/fusermount3", "/bin/fusermount"];

    for path in &paths {
        if Path::new(path).exists() {
            // Check for SUID bit
            if let Ok(metadata) = std::fs::metadata(path) {
                let mode = metadata.permissions().mode();
                if mode & 0o4000 != 0 {
                    return CheckResult::Ok { version: None };
                } else {
                    return CheckResult::Misconfigured {
                        issue: format!("{} missing SUID bit", path),
                        fix: format!("sudo chmod u+s {}", path),
                    };
                }
            }
        }
    }

    if command_exists("fusermount3") || command_exists("fusermount") {
        // Found but couldn't check SUID
        CheckResult::Ok { version: None }
    } else {
        CheckResult::Missing {
            suggestion: "Install fuse3 package".to_string(),
        }
    }
}

fn check_pasta() -> CheckResult {
    if command_exists("pasta") {
        let version = get_command_version("pasta");
        CheckResult::Ok { version }
    } else {
        if command_exists("slirp4netns") {
            CheckResult::Unavailable {
                reason: "pasta not found".to_string(),
                alternative: Some("slirp4netns is available".to_string()),
            }
        } else {
            CheckResult::Missing {
                suggestion: "Install passt package for better networking performance".to_string(),
            }
        }
    }
}

fn check_slirp4netns() -> CheckResult {
    if command_exists("slirp4netns") {
        let version = get_command_version("slirp4netns");
        CheckResult::Ok { version }
    } else {
        if command_exists("pasta") {
            CheckResult::Unavailable {
                reason: "slirp4netns not found".to_string(),
                alternative: Some("pasta is available".to_string()),
            }
        } else {
            CheckResult::Missing {
                suggestion: "Install slirp4netns package".to_string(),
            }
        }
    }
}

fn check_nsenter() -> CheckResult {
    if command_exists("nsenter") {
        let version = get_command_version("nsenter");
        CheckResult::Ok { version }
    } else {
        CheckResult::Missing {
            suggestion: "Install util-linux package".to_string(),
        }
    }
}

fn check_newuidmap() -> CheckResult {
    let paths = ["/usr/bin/newuidmap", "/bin/newuidmap"];

    for path in &paths {
        if Path::new(path).exists() {
            // Check for SUID bit
            if let Ok(metadata) = std::fs::metadata(path) {
                let mode = metadata.permissions().mode();
                if mode & 0o4000 != 0 {
                    return CheckResult::Ok { version: None };
                } else {
                    return CheckResult::Misconfigured {
                        issue: format!("{} missing SUID bit", path),
                        fix: format!("sudo chmod u+s {}", path),
                    };
                }
            }
        }
    }

    if command_exists("newuidmap") {
        CheckResult::Ok { version: None }
    } else {
        CheckResult::Unavailable {
            reason: "newuidmap not found".to_string(),
            alternative: Some("Single-UID mode will be used".to_string()),
        }
    }
}

fn check_user_namespaces() -> CheckResult {
    // Check /proc/sys/kernel/unprivileged_userns_clone
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        if content.trim() == "1" {
            return CheckResult::Ok { version: None };
        } else {
            return CheckResult::Misconfigured {
                issue: "Unprivileged user namespaces disabled".to_string(),
                fix: "sudo sysctl -w kernel.unprivileged_userns_clone=1".to_string(),
            };
        }
    }

    // File doesn't exist - might be enabled by default (newer kernels)
    // Try to create a user namespace to verify
    match std::process::Command::new("unshare")
        .args(["--user", "--map-root-user", "true"])
        .output()
    {
        Ok(output) if output.status.success() => CheckResult::Ok { version: None },
        _ => CheckResult::Misconfigured {
            issue: "Cannot create user namespaces".to_string(),
            fix: "Enable CONFIG_USER_NS in kernel or sysctl kernel.unprivileged_userns_clone=1".to_string(),
        },
    }
}

fn check_subuid() -> CheckResult {
    let username = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    if let Ok(content) = std::fs::read_to_string("/etc/subuid") {
        for line in content.lines() {
            if line.starts_with(&format!("{}:", username)) {
                // Parse the range
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    if let Ok(count) = parts[2].parse::<u32>() {
                        if count >= 65536 {
                            return CheckResult::Ok { version: Some(format!("{} UIDs", count)) };
                        } else {
                            return CheckResult::Misconfigured {
                                issue: format!("Only {} subordinate UIDs configured (65536 recommended)", count),
                                fix: format!("sudo usermod --add-subuids 100000-165535 {}", username),
                            };
                        }
                    }
                }
            }
        }
        CheckResult::Misconfigured {
            issue: format!("No subordinate UIDs configured for user {}", username),
            fix: format!("sudo usermod --add-subuids 100000-165535 {}", username),
        }
    } else {
        CheckResult::Misconfigured {
            issue: "/etc/subuid does not exist".to_string(),
            fix: format!("echo '{}:100000:65536' | sudo tee -a /etc/subuid", username),
        }
    }
}

fn check_subgid() -> CheckResult {
    let username = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    if let Ok(content) = std::fs::read_to_string("/etc/subgid") {
        for line in content.lines() {
            if line.starts_with(&format!("{}:", username)) {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    if let Ok(count) = parts[2].parse::<u32>() {
                        if count >= 65536 {
                            return CheckResult::Ok { version: Some(format!("{} GIDs", count)) };
                        } else {
                            return CheckResult::Misconfigured {
                                issue: format!("Only {} subordinate GIDs configured (65536 recommended)", count),
                                fix: format!("sudo usermod --add-subgids 100000-165535 {}", username),
                            };
                        }
                    }
                }
            }
        }
        CheckResult::Misconfigured {
            issue: format!("No subordinate GIDs configured for user {}", username),
            fix: format!("sudo usermod --add-subgids 100000-165535 {}", username),
        }
    } else {
        CheckResult::Misconfigured {
            issue: "/etc/subgid does not exist".to_string(),
            fix: format!("echo '{}:100000:65536' | sudo tee -a /etc/subgid", username),
        }
    }
}

fn can_use_native_overlay() -> bool {
    // Check kernel version >= 5.11
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        let version = content.trim();
        if let Some((major, rest)) = version.split_once('.') {
            if let Ok(major_num) = major.parse::<u32>() {
                if major_num > 5 {
                    return true;
                }
                if major_num == 5 {
                    if let Some((minor, _)) = rest.split_once('.') {
                        if let Ok(minor_num) = minor.parse::<u32>() {
                            return minor_num >= 11;
                        }
                    }
                }
            }
        }
    }
    false
}

// Main doctor function

pub async fn run_doctor(fix: bool, json: bool) {
    let platform = detect_platform();
    let checks = get_all_checks();

    let mut results: Vec<(&str, Category, CheckResult, Option<String>)> = Vec::new();
    let mut passed = 0;
    let mut warnings = 0;
    let mut errors = 0;

    for (check, check_fn) in &checks {
        let result = check_fn(&platform);

        // Count results
        match &result {
            CheckResult::Ok { .. } => passed += 1,
            CheckResult::Misconfigured { .. } | CheckResult::Unavailable { alternative: Some(_), .. } => warnings += 1,
            CheckResult::Missing { .. } | CheckResult::Unavailable { alternative: None, .. } => errors += 1,
        }

        // Attempt fix if requested
        let fix_result = if fix && !result.is_ok() {
            let options = InstallOptions {
                dry_run: false,
                yes: false,
                max_retries: 3,
                verbose: false,
            };
            Some(format!("{:?}", attempt_install(check, &platform, &options)))
        } else {
            None
        };

        results.push((check.name, check.category.clone(), result, fix_result));
    }

    if json {
        print_json_report(&platform, &results, passed, warnings, errors);
    } else {
        print_human_report(&platform, &results, &checks, passed, warnings, errors);
    }
}

fn print_human_report(
    platform: &Platform,
    results: &[(&str, Category, CheckResult, Option<String>)],
    checks: &[(DependencyCheck, Box<dyn Fn(&Platform) -> CheckResult>)],
    passed: usize,
    warnings: usize,
    errors: usize,
) {
    println!("Carrier Dependency Check");
    println!("========================\n");

    // Platform info
    println!("Platform: {:?} ({:?})", platform.os, platform.distro);
    if let Some(ref v) = platform.kernel_version {
        println!("Kernel: {}", v);
    }
    println!("Package Manager: {}\n", platform.package_manager_name());

    // Results
    for (name, _category, result, fix_result) in results {
        let status = match result {
            CheckResult::Ok { version } => {
                let ver_str = version.as_ref().map(|v| format!(" ({})", v)).unwrap_or_default();
                format!("[OK] {}{}", name, ver_str)
            }
            CheckResult::Missing { suggestion } => {
                format!("[MISSING] {} - {}", name, suggestion)
            }
            CheckResult::Misconfigured { issue, fix } => {
                format!("[WARN] {} - {}\n       Fix: {}", name, issue, fix)
            }
            CheckResult::Unavailable { reason, alternative } => {
                let alt_str = alternative.as_ref()
                    .map(|a| format!("\n       Alternative: {}", a))
                    .unwrap_or_default();
                format!("[WARN] {} - {}{}", name, reason, alt_str)
            }
        };

        println!("{}", status);

        // Show install command if missing
        if matches!(result, CheckResult::Missing { .. }) {
            if let Some((check, _)) = checks.iter().find(|(c, _)| c.name == *name) {
                if let Some(cmd) = check.get_install_command(&platform.package_manager) {
                    println!("       To install: {}", cmd);
                }
            }
        }

        // Show fix result
        if let Some(fix_msg) = fix_result {
            println!("       Fix attempted: {}", fix_msg);
        }
    }

    // Summary
    println!("\n------------------------");
    println!("Summary: {} passed, {} warnings, {} errors", passed, warnings, errors);

    if errors > 0 || warnings > 0 {
        println!("\nRun 'carrier doctor --fix' to attempt automatic fixes.");
    }
}

fn print_json_report(
    platform: &Platform,
    results: &[(&str, Category, CheckResult, Option<String>)],
    passed: usize,
    warnings: usize,
    errors: usize,
) {
    let mut checks_json = Vec::new();

    for (name, category, result, _fix_result) in results {
        let (status, details) = match result {
            CheckResult::Ok { version } => ("ok", version.clone()),
            CheckResult::Missing { suggestion } => ("missing", Some(suggestion.clone())),
            CheckResult::Misconfigured { issue, .. } => ("misconfigured", Some(issue.clone())),
            CheckResult::Unavailable { reason, .. } => ("unavailable", Some(reason.clone())),
        };

        let category_str = match category {
            Category::Essential => "essential",
            Category::Recommended => "recommended",
            Category::Optional => "optional",
        };

        checks_json.push(serde_json::json!({
            "name": name,
            "category": category_str,
            "status": status,
            "details": details,
        }));
    }

    let report = serde_json::json!({
        "platform": {
            "os": format!("{:?}", platform.os).to_lowercase(),
            "distro": format!("{:?}", platform.distro).to_lowercase(),
            "version": platform.distro_version,
            "kernel": platform.kernel_version,
            "package_manager": platform.package_manager_name(),
        },
        "checks": checks_json,
        "summary": {
            "passed": passed,
            "warnings": warnings,
            "errors": errors,
        }
    });

    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
}
