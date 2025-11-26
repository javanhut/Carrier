use std::process::Command;

#[derive(Debug, Clone, PartialEq)]
pub enum Os {
    Linux,
    MacOS,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Distro {
    Debian,
    Ubuntu,
    Fedora,
    CentOS,
    RHEL,
    Arch,
    OpenSUSE,
    Alpine,
    Gentoo,
    Void,
    NixOS,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Pacman,
    Zypper,
    Apk,
    Emerge,
    Xbps,
    NixEnv,
    Brew,
    None,
}

#[derive(Debug, Clone)]
pub struct Platform {
    pub os: Os,
    pub distro: Distro,
    pub distro_version: Option<String>,
    pub package_manager: PackageManager,
    pub kernel_version: Option<String>,
}

impl Platform {
    pub fn is_linux(&self) -> bool {
        matches!(self.os, Os::Linux)
    }

    pub fn is_macos(&self) -> bool {
        matches!(self.os, Os::MacOS)
    }

    pub fn package_manager_name(&self) -> &'static str {
        match self.package_manager {
            PackageManager::Apt => "apt",
            PackageManager::Dnf => "dnf",
            PackageManager::Yum => "yum",
            PackageManager::Pacman => "pacman",
            PackageManager::Zypper => "zypper",
            PackageManager::Apk => "apk",
            PackageManager::Emerge => "emerge",
            PackageManager::Xbps => "xbps-install",
            PackageManager::NixEnv => "nix-env",
            PackageManager::Brew => "brew",
            PackageManager::None => "unknown",
        }
    }
}

pub fn detect_platform() -> Platform {
    let os = detect_os();
    let (distro, distro_version) = if os == Os::Linux {
        detect_linux_distro()
    } else {
        (Distro::Unknown, None)
    };
    let package_manager = detect_package_manager(&os, &distro);
    let kernel_version = detect_kernel_version();

    Platform {
        os,
        distro,
        distro_version,
        package_manager,
        kernel_version,
    }
}

fn detect_os() -> Os {
    #[cfg(target_os = "linux")]
    {
        Os::Linux
    }
    #[cfg(target_os = "macos")]
    {
        Os::MacOS
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Os::Unknown
    }
}

fn detect_linux_distro() -> (Distro, Option<String>) {
    // Try /etc/os-release first (standard on modern distros)
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        return parse_os_release(&content);
    }

    // Fallback to /etc/lsb-release
    if let Ok(content) = std::fs::read_to_string("/etc/lsb-release") {
        return parse_lsb_release(&content);
    }

    // Check for specific distro files
    if std::path::Path::new("/etc/debian_version").exists() {
        let version = std::fs::read_to_string("/etc/debian_version")
            .ok()
            .map(|v| v.trim().to_string());
        return (Distro::Debian, version);
    }

    if std::path::Path::new("/etc/arch-release").exists() {
        return (Distro::Arch, None);
    }

    if std::path::Path::new("/etc/alpine-release").exists() {
        let version = std::fs::read_to_string("/etc/alpine-release")
            .ok()
            .map(|v| v.trim().to_string());
        return (Distro::Alpine, version);
    }

    if std::path::Path::new("/etc/gentoo-release").exists() {
        return (Distro::Gentoo, None);
    }

    (Distro::Unknown, None)
}

fn parse_os_release(content: &str) -> (Distro, Option<String>) {
    let mut id = None;
    let mut version = None;

    for line in content.lines() {
        if let Some(value) = line.strip_prefix("ID=") {
            id = Some(value.trim_matches('"').to_lowercase());
        } else if let Some(value) = line.strip_prefix("VERSION_ID=") {
            version = Some(value.trim_matches('"').to_string());
        }
    }

    let distro = match id.as_deref() {
        Some("debian") => Distro::Debian,
        Some("ubuntu") => Distro::Ubuntu,
        Some("fedora") => Distro::Fedora,
        Some("centos") => Distro::CentOS,
        Some("rhel") | Some("redhat") => Distro::RHEL,
        Some("arch") | Some("archlinux") => Distro::Arch,
        Some("opensuse") | Some("opensuse-leap") | Some("opensuse-tumbleweed") => Distro::OpenSUSE,
        Some("alpine") => Distro::Alpine,
        Some("gentoo") => Distro::Gentoo,
        Some("void") => Distro::Void,
        Some("nixos") => Distro::NixOS,
        _ => Distro::Unknown,
    };

    (distro, version)
}

fn parse_lsb_release(content: &str) -> (Distro, Option<String>) {
    let mut id = None;
    let mut version = None;

    for line in content.lines() {
        if let Some(value) = line.strip_prefix("DISTRIB_ID=") {
            id = Some(value.trim_matches('"').to_lowercase());
        } else if let Some(value) = line.strip_prefix("DISTRIB_RELEASE=") {
            version = Some(value.trim_matches('"').to_string());
        }
    }

    let distro = match id.as_deref() {
        Some("ubuntu") => Distro::Ubuntu,
        Some("debian") => Distro::Debian,
        Some("arch") => Distro::Arch,
        _ => Distro::Unknown,
    };

    (distro, version)
}

fn detect_package_manager(os: &Os, distro: &Distro) -> PackageManager {
    match os {
        Os::MacOS => {
            // Check for Homebrew
            if command_exists("brew") {
                return PackageManager::Brew;
            }
            PackageManager::None
        }
        Os::Linux => {
            // First try by distro
            match distro {
                Distro::Debian | Distro::Ubuntu => PackageManager::Apt,
                Distro::Fedora => PackageManager::Dnf,
                Distro::CentOS | Distro::RHEL => {
                    // CentOS 8+ and RHEL 8+ use dnf
                    if command_exists("dnf") {
                        PackageManager::Dnf
                    } else {
                        PackageManager::Yum
                    }
                }
                Distro::Arch => PackageManager::Pacman,
                Distro::OpenSUSE => PackageManager::Zypper,
                Distro::Alpine => PackageManager::Apk,
                Distro::Gentoo => PackageManager::Emerge,
                Distro::Void => PackageManager::Xbps,
                Distro::NixOS => PackageManager::NixEnv,
                Distro::Unknown => detect_package_manager_by_binary(),
            }
        }
        Os::Unknown => PackageManager::None,
    }
}

fn detect_package_manager_by_binary() -> PackageManager {
    // Check for package managers by binary existence
    if command_exists("apt-get") {
        PackageManager::Apt
    } else if command_exists("dnf") {
        PackageManager::Dnf
    } else if command_exists("yum") {
        PackageManager::Yum
    } else if command_exists("pacman") {
        PackageManager::Pacman
    } else if command_exists("zypper") {
        PackageManager::Zypper
    } else if command_exists("apk") {
        PackageManager::Apk
    } else if command_exists("emerge") {
        PackageManager::Emerge
    } else if command_exists("xbps-install") {
        PackageManager::Xbps
    } else if command_exists("nix-env") {
        PackageManager::NixEnv
    } else if command_exists("brew") {
        PackageManager::Brew
    } else {
        PackageManager::None
    }
}

fn detect_kernel_version() -> Option<String> {
    // Try uname -r
    if let Ok(output) = Command::new("uname").arg("-r").output() {
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
    }

    // Fallback to /proc/sys/kernel/osrelease
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|v| v.trim().to_string())
}

pub fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn get_command_version(cmd: &str) -> Option<String> {
    // Try --version first
    if let Ok(output) = Command::new(cmd).arg("--version").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Extract first line and try to find version number
            if let Some(first_line) = stdout.lines().next() {
                return Some(first_line.to_string());
            }
        }
    }

    // Try -v
    if let Ok(output) = Command::new(cmd).arg("-v").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(first_line) = stdout.lines().next() {
                return Some(first_line.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_os() {
        let os = detect_os();
        #[cfg(target_os = "linux")]
        assert_eq!(os, Os::Linux);
        #[cfg(target_os = "macos")]
        assert_eq!(os, Os::MacOS);
    }

    #[test]
    fn test_parse_os_release_ubuntu() {
        let content = r#"
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
VERSION_ID="22.04"
"#;
        let (distro, version) = parse_os_release(content);
        assert_eq!(distro, Distro::Ubuntu);
        assert_eq!(version, Some("22.04".to_string()));
    }

    #[test]
    fn test_parse_os_release_arch() {
        let content = r#"
NAME="Arch Linux"
ID=arch
"#;
        let (distro, _version) = parse_os_release(content);
        assert_eq!(distro, Distro::Arch);
    }
}
