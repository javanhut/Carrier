use nix::mount::{MsFlags, mount};
use nix::sys::stat::{Mode, SFlag, major, makedev, minor, mknod};
use nix::unistd::mkfifo;
use std::env;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Ensure runtime directory exists and is configured.
/// Returns the runtime directory path and whether it was auto-detected or created as fallback.
fn ensure_runtime_dir() -> Result<(PathBuf, bool), Box<dyn std::error::Error>> {
    // First check if XDG_RUNTIME_DIR is already set
    if let Some(dir) = dirs::runtime_dir() {
        return Ok((dir, false));
    }

    // If not set, try to detect and set it
    let uid = nix::unistd::getuid().as_raw();
    let runtime_dir = PathBuf::from(format!("/run/user/{}", uid));

    // Check if the expected runtime dir exists
    if runtime_dir.exists() {
        // Set the environment variable for this process and children
        // SAFETY: This is safe as we're setting a valid path string
        unsafe {
            env::set_var("XDG_RUNTIME_DIR", &runtime_dir);
        }
        Ok((runtime_dir, true))
    } else {
        // Fallback to /tmp if /run/user/{uid} doesn't exist
        let fallback = PathBuf::from(format!("/tmp/runtime-{}", uid));
        fs::create_dir_all(&fallback)?;

        // Set permissions to 0700
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&fallback)?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&fallback, perms)?;

        // SAFETY: This is safe as we're setting a valid path string
        unsafe {
            env::set_var("XDG_RUNTIME_DIR", &fallback);
        }
        Ok((fallback, true))
    }
}

pub struct ContainerStorage {
    persistent_dir: PathBuf,
    runtime_dir: PathBuf,
    use_fuse_overlayfs: bool,
    forced_driver: Option<StorageDriver>,
    last_driver: Option<StorageDriver>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StorageDriver {
    OverlayFuse,
    OverlayNative,
    Vfs,
}

impl ContainerStorage {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Persistent base
        let persistent_dir = dirs::data_dir()
            .ok_or("Cannot determine data directory")?
            .join("carrier")
            .join("storage");
        fs::create_dir_all(&persistent_dir)?;

        // Use persistent storage for runtime dir to avoid filling tmpfs
        // This is especially important for VFS which copies entire rootfs
        let runtime_dir = persistent_dir.join("run");
        fs::create_dir_all(&runtime_dir)?;

        // Check if we can use native overlayfs or need fuse-overlayfs
        let use_fuse_overlayfs = !can_use_native_overlay();

        Ok(Self {
            persistent_dir,
            runtime_dir,
            use_fuse_overlayfs,
            forced_driver: None,
            last_driver: None,
        })
    }

    pub fn new_with_driver(forced: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        let mut s = Self::new()?;
        s.forced_driver = match forced.map(|v| v.to_lowercase()) {
            Some(ref v) if v == "overlay-fuse" => Some(StorageDriver::OverlayFuse),
            Some(ref v) if v == "overlay-native" => Some(StorageDriver::OverlayNative),
            Some(ref v) if v == "vfs" => Some(StorageDriver::Vfs),
            _ => None,
        };
        Ok(s)
    }

    pub fn create_container_filesystem(
        &mut self,
        container_id: &str,
        image_layers: Vec<PathBuf>,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        // Use overlay-containers to match StorageLayout paths used by commands
        let persist_container = self.persistent_dir.join("overlay-containers").join(container_id);
        let run_container = self.runtime_dir.join("overlay-containers").join(container_id);
        let upper_dir = persist_container.join("upper");
        let work_dir = persist_container.join("work");
        let merged_dir = run_container.join("merged");

        fs::create_dir_all(&upper_dir)?;
        fs::create_dir_all(&work_dir)?;
        fs::create_dir_all(&merged_dir)?;

        // Ensure upper and work dirs are writable by current user (for user namespace mapping)
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&upper_dir)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&upper_dir, perms)?;

        let mut work_perms = fs::metadata(&work_dir)?.permissions();
        work_perms.set_mode(0o755);
        fs::set_permissions(&work_dir, work_perms)?;

        if self.is_already_mounted(&merged_dir) {
            // Detect the actual driver from /proc/mounts
            self.last_driver = Some(self.detect_mount_driver(&merged_dir));
            return Ok(merged_dir);
        }

        let lower_dirs: Vec<String> = image_layers
            .iter()
            .rev()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        let lower_dirs_str = lower_dirs.join(":");

        let chosen = match self.forced_driver.clone() {
            Some(StorageDriver::OverlayFuse) => StorageDriver::OverlayFuse,
            Some(StorageDriver::OverlayNative) => StorageDriver::OverlayNative,
            Some(StorageDriver::Vfs) => StorageDriver::Vfs,
            None => StorageDriver::OverlayFuse,
        };

        let mut mounted = false;
        let mut actual_driver = chosen.clone();

        // Priority order: fuse-overlayfs -> native overlay -> vfs
        if matches!(chosen, StorageDriver::OverlayFuse) {
            match self.mount_fuse_overlayfs(&lower_dirs_str, &upper_dir, &work_dir, &merged_dir) {
                Ok(_) => {
                    mounted = true;
                    println!("Using fuse-overlayfs storage driver");
                }
                Err(e) => {
                    eprintln!("fuse-overlayfs mount failed: {}", e);
                    // Try native overlay as fallback if not forced to use fuse
                    if !matches!(self.forced_driver, Some(StorageDriver::OverlayFuse)) {
                        eprintln!("Attempting native overlay as fallback...");
                        if let Ok(_) = self.mount_native_overlayfs(
                            &lower_dirs_str,
                            &upper_dir,
                            &work_dir,
                            &merged_dir,
                        ) {
                            mounted = true;
                            actual_driver = StorageDriver::OverlayNative;
                            println!("Using native overlay storage driver");
                        }
                    }
                }
            }
        } else if matches!(chosen, StorageDriver::OverlayNative) {
            match self.mount_native_overlayfs(&lower_dirs_str, &upper_dir, &work_dir, &merged_dir) {
                Ok(_) => {
                    mounted = true;
                    println!("Using native overlay storage driver");
                }
                Err(e) => {
                    eprintln!("native overlay mount failed: {}", e);
                    // Try fuse-overlayfs as fallback if not forced to use native
                    if !matches!(self.forced_driver, Some(StorageDriver::OverlayNative)) {
                        eprintln!("Attempting fuse-overlayfs as fallback...");
                        if let Ok(_) = self.mount_fuse_overlayfs(
                            &lower_dirs_str,
                            &upper_dir,
                            &work_dir,
                            &merged_dir,
                        ) {
                            mounted = true;
                            actual_driver = StorageDriver::OverlayFuse;
                            println!("Using fuse-overlayfs storage driver");
                        }
                    }
                }
            }
        }

        // Final fallback to VFS if nothing else worked
        if !mounted {
            if !matches!(chosen, StorageDriver::Vfs) {
                eprintln!("All overlay mount attempts failed; using VFS fallback");
            }
            self.build_vfs_root_optimized(&lower_dirs, &merged_dir)?;
            actual_driver = StorageDriver::Vfs;
            println!("Using VFS storage driver");
        }

        self.last_driver = Some(actual_driver);
        Ok(merged_dir)
    }

    fn is_already_mounted(&self, path: &Path) -> bool {
        if !path.exists() {
            return false;
        }

        // Check /proc/mounts for actual mount status
        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            let path_str = path.to_string_lossy();
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[1] == path_str {
                    return true;
                }
            }
        }

        // Alternative: check if device ID differs from parent (indicates mount point)
        if let Some(parent) = path.parent() {
            if let (Ok(path_meta), Ok(parent_meta)) = (fs::metadata(path), fs::metadata(parent)) {
                use std::os::unix::fs::MetadataExt;
                if path_meta.dev() != parent_meta.dev() {
                    return true;
                }
            }
        }

        false
    }

    fn detect_mount_driver(&self, path: &Path) -> StorageDriver {
        // Check /proc/mounts for the filesystem type
        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            let path_str = path.to_string_lossy();
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[1] == path_str {
                    let fs_type = parts[2];
                    return match fs_type {
                        "fuse.fuse-overlayfs" => StorageDriver::OverlayFuse,
                        "overlay" => StorageDriver::OverlayNative,
                        _ => StorageDriver::Vfs,
                    };
                }
            }
        }
        // Default to VFS if we can't determine
        StorageDriver::Vfs
    }

    fn mount_fuse_overlayfs(
        &self,
        lower: &str,
        upper: &Path,
        work: &Path,
        merged: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Use squash_to_root so all files appear as root (UID 0) in the overlay.
        // The user namespace mapping then makes container root (UID 0) map to the host user,
        // allowing proper write permissions while maintaining correct ownership semantics.
        let output = Command::new("fuse-overlayfs")
            .arg("-o")
            .arg(format!(
                "lowerdir={},upperdir={},workdir={},squash_to_root",
                lower,
                upper.display(),
                work.display()
            ))
            .arg(merged)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("fuse-overlayfs failed: {}", stderr).into());
        }

        Ok(())
    }

    fn mount_native_overlayfs(
        &self,
        lower: &str,
        upper: &Path,
        work: &Path,
        merged: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Try native overlayfs (requires kernel support for unprivileged overlay)
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower,
            upper.display(),
            work.display()
        );

        // This will only work on newer kernels with unprivileged overlay support
        mount(
            Some("overlay"),
            merged,
            Some("overlay"),
            MsFlags::empty(),
            Some(options.as_str()),
        )?;

        Ok(())
    }

    pub fn last_driver(&self) -> StorageDriver {
        self.last_driver
            .clone()
            .unwrap_or(if self.use_fuse_overlayfs {
                StorageDriver::OverlayFuse
            } else {
                StorageDriver::OverlayNative
            })
    }
}

pub fn can_use_native_overlay() -> bool {
    // Allow on modern kernels with user namespaces enabled
    // Check if kernel supports unprivileged user namespaces
    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        if content.trim() != "1" {
            return false;
        }
    } else {
        return false;
    }

    // Check kernel version (5.11+ has better rootless overlay support)
    if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        if let Some(version) = parse_kernel_version(&release) {
            return version >= (5, 11, 0);
        }
    }

    // As a conservative default, enable attempt; if mount fails, we'll fallback
    true
}

fn parse_kernel_version(release: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = release.split('.').collect();
    if parts.len() >= 2 {
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = parts
            .get(2)
            .and_then(|p| p.split('-').next())
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        return Some((major, minor, patch));
    }
    None
}

impl ContainerStorage {
    fn build_vfs_root_optimized(
        &self,
        lower_dirs: &[String],
        merged: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::process::Command;

        if merged.exists() && fs::read_dir(merged)?.next().is_some() {
            return Ok(());
        }

        if merged.exists() {
            let _ = fs::remove_dir_all(merged);
        }
        fs::create_dir_all(merged)?;

        for lower in lower_dirs.iter() {
            let src = Path::new(lower);

            // Use "src/." to copy directory contents (not the directory itself)
            // This properly handles the copy without shell glob expansion
            let src_contents = format!("{}/.", src.display());
            let output = Command::new("cp")
                .arg("-a")
                .arg(&src_contents)
                .arg(merged)
                .output();

            if output.is_err() || !output.as_ref().map(|o| o.status.success()).unwrap_or(false) {
                self.copy_recursive(src, merged)?;
            }
        }

        // Note: We deliberately do NOT call fix_ownership_for_rootless here.
        // The files should keep their original ownership from the image layers.
        // With proper user namespace UID/GID mappings configured in the OCI config,
        // the kernel will handle the mapping correctly:
        // - Files owned by the current user on the host appear as root in the container
        // - Files owned by subuid range appear as other users in the container
        // This allows package managers to properly chown/chgrp files during installation.

        Ok(())
    }


    fn copy_recursive(&self, src: &Path, dst: &Path) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::copy;

        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let target = dst.join(&name);
            let path = entry.path();

            if ty.is_dir() {
                if dst.to_string_lossy().ends_with("merged")
                    && (name_str == "dev" || name_str == "proc" || name_str == "sys")
                {
                    fs::create_dir_all(&target)?;
                    continue;
                }
                fs::create_dir_all(&target)?;
                self.copy_recursive(&path, &target)?;
                continue;
            }

            if ty.is_symlink() {
                #[cfg(unix)]
                {
                    if target.exists() {
                        let _ = fs::remove_file(&target);
                    }
                    let link_target = fs::read_link(&path)?;
                    let _ = std::os::unix::fs::symlink(&link_target, &target);
                }
                continue;
            }

            #[cfg(unix)]
            {
                let metadata = fs::metadata(&path)?;
                let mode_bits = metadata.mode() & 0o7777;
                let perm = Mode::from_bits_truncate(mode_bits as u32);

                if ty.is_char_device() {
                    if target.exists() {
                        let _ = fs::remove_file(&target);
                    }
                    let dev = metadata.rdev();
                    let _ = mknod(
                        &target,
                        SFlag::S_IFCHR,
                        perm,
                        makedev(major(dev), minor(dev)),
                    );
                    continue;
                }

                if ty.is_block_device() {
                    if target.exists() {
                        let _ = fs::remove_file(&target);
                    }
                    let dev = metadata.rdev();
                    let _ = mknod(
                        &target,
                        SFlag::S_IFBLK,
                        perm,
                        makedev(major(dev), minor(dev)),
                    );
                    continue;
                }

                if ty.is_fifo() {
                    if target.exists() {
                        let _ = fs::remove_file(&target);
                    }
                    let _ = mkfifo(&target, perm);
                    continue;
                }

                if ty.is_socket() {
                    continue;
                }

                if ty.is_file() {
                    if target.exists() {
                        fs::remove_file(&target)?;
                    }

                    let mut src_file = fs::File::open(&path)?;
                    let mut dst_file = fs::File::create(&target)?;
                    copy(&mut src_file, &mut dst_file)?;
                    drop(dst_file);

                    fs::set_permissions(&target, metadata.permissions())?;
                    continue;
                }
            }

            if ty.is_file() {
                if target.exists() {
                    fs::remove_file(&target)?;
                }

                let mut src_file = fs::File::open(&path)?;
                let mut dst_file = fs::File::create(&target)?;
                copy(&mut src_file, &mut dst_file)?;
            }
        }
        Ok(())
    }
}

/// Check if a command exists in the system
fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Attempt to install fuse3 and fuse-overlayfs packages
fn try_install_fuse3() -> Result<(), Box<dyn std::error::Error>> {
    println!("Attempting to install fuse3 and fuse-overlayfs...");

    // Detect package manager and install
    if Path::new("/usr/bin/apt-get").exists() || Path::new("/usr/bin/apt").exists() {
        // Debian/Ubuntu
        let status = Command::new("sudo")
            .args(&["-n", "apt-get", "update", "-qq"])
            .status();

        if status.is_ok() && status.unwrap().success() {
            let install = Command::new("sudo")
                .args(&["-n", "apt-get", "install", "-y", "fuse3", "fuse-overlayfs"])
                .status();

            if install.is_ok() && install.unwrap().success() {
                println!("Successfully installed fuse3 and fuse-overlayfs");
                return Ok(());
            }
        }
    } else if Path::new("/usr/bin/dnf").exists() {
        // Fedora/RHEL
        let install = Command::new("sudo")
            .args(&["-n", "dnf", "install", "-y", "fuse3", "fuse-overlayfs"])
            .status();

        if install.is_ok() && install.unwrap().success() {
            println!("Successfully installed fuse3 and fuse-overlayfs");
            return Ok(());
        }
    } else if Path::new("/usr/bin/pacman").exists() {
        // Arch Linux
        let install = Command::new("sudo")
            .args(&["-n", "pacman", "-S", "--noconfirm", "fuse3", "fuse-overlayfs"])
            .status();

        if install.is_ok() && install.unwrap().success() {
            println!("Successfully installed fuse3 and fuse-overlayfs");
            return Ok(());
        }
    } else if Path::new("/usr/bin/zypper").exists() {
        // openSUSE
        let install = Command::new("sudo")
            .args(&["-n", "zypper", "install", "-y", "fuse3", "fuse-overlayfs"])
            .status();

        if install.is_ok() && install.unwrap().success() {
            println!("Successfully installed fuse3 and fuse-overlayfs");
            return Ok(());
        }
    }

    Err("Unable to install fuse3 automatically. Please install manually.".into())
}

// Preflight rootless environment checks with actionable hints
pub fn preflight_rootless_checks() {
    // XDG_RUNTIME_DIR with auto-detection
    match ensure_runtime_dir() {
        Ok((path, was_configured)) => {
            if !path.exists() {
                let _ = fs::create_dir_all(&path);
            }
            if was_configured {
                eprintln!("Note: Configured runtime dir: {}", path.display());
            }
        }
        Err(e) => eprintln!("Warning: Could not determine runtime directory: {}", e),
    }

    // Check for fuse-overlayfs first
    if !command_exists("fuse-overlayfs") {
        println!("fuse-overlayfs not found, attempting to install...");
        if let Err(e) = try_install_fuse3() {
            eprintln!("Warning: {}", e);
            eprintln!("Will fall back to VFS storage driver if needed.");
        }
    }

    // fusermount3 SUID check
    if let Ok(meta) = fs::metadata("/usr/bin/fusermount3") {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode();
        if mode & 0o4000 == 0 {
            eprintln!(
                "Warning: fusermount3 is not setuid. Rootless FUSE may fail."
            );
            eprintln!("Attempting to set setuid bit...");

            let status = Command::new("sudo")
                .args(&["-n", "chmod", "u+s", "/usr/bin/fusermount3"])
                .status();

            if status.is_ok() && status.unwrap().success() {
                println!("Successfully set setuid bit on fusermount3");
            } else {
                eprintln!("Try manually: sudo chmod u+s /usr/bin/fusermount3");
                eprintln!("Will fall back to VFS storage driver if needed.");
            }
        }
    } else if !command_exists("fusermount3") && !command_exists("fuse-overlayfs") {
        eprintln!("Warning: fusermount3 not found.");
        if let Err(e) = try_install_fuse3() {
            eprintln!("Warning: {}", e);
            eprintln!("Will fall back to VFS storage driver.");
        }
    }

    // /dev/fuse present
    if !Path::new("/dev/fuse").exists() {
        eprintln!("Warning: /dev/fuse not present. Attempting to load FUSE module...");

        let status = Command::new("sudo")
            .args(&["-n", "modprobe", "fuse"])
            .status();

        if status.is_ok() && status.unwrap().success() {
            println!("Successfully loaded FUSE module");
        } else {
            eprintln!("Try manually: sudo modprobe fuse");
            eprintln!("Will fall back to VFS storage driver if needed.");
        }
    }
}
