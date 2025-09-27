use nix::mount::{MsFlags, mount, umount};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct ContainerStorage {
    // Persistent data (upper/work) rooted under user data dir
    persistent_dir: PathBuf,
    // Runtime mounts (merged) under XDG_RUNTIME_DIR to mirror Podman behavior
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

        // Runtime base (XDG_RUNTIME_DIR)
        let runtime_dir = dirs::runtime_dir()
            .ok_or("Cannot determine runtime directory (XDG_RUNTIME_DIR) for rootless mounts")?
            .join("carrier");
        fs::create_dir_all(&runtime_dir)?;

        // Check if we can use native overlayfs or need fuse-overlayfs
        let use_fuse_overlayfs = !can_use_native_overlay();

        Ok(Self { persistent_dir, runtime_dir, use_fuse_overlayfs, forced_driver: None, last_driver: None })
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
        // Create container-specific directories
        let persist_container = self.persistent_dir.join("containers").join(container_id);
        let run_container = self.runtime_dir.join("containers").join(container_id);
        let upper_dir = persist_container.join("upper");
        let work_dir = persist_container.join("work");
        let merged_dir = run_container.join("merged");

        fs::create_dir_all(&upper_dir)?;
        fs::create_dir_all(&work_dir)?;
        fs::create_dir_all(&merged_dir)?;

        // Build lower dirs string (colon-separated, reverse order)
        let lower_dirs: Vec<String> = image_layers
            .iter()
            .rev()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        let lower_dirs_str = lower_dirs.join(":");

        // Decide driver
        let chosen = match self.forced_driver.clone() {
            Some(StorageDriver::OverlayFuse) => StorageDriver::OverlayFuse,
            Some(StorageDriver::OverlayNative) => StorageDriver::OverlayNative,
            Some(StorageDriver::Vfs) => StorageDriver::Vfs,
            None => if self.use_fuse_overlayfs { StorageDriver::OverlayFuse } else { StorageDriver::OverlayNative },
        };

        // Execute
        let mut mounted = false;
        if matches!(chosen, StorageDriver::OverlayNative) {
            if let Err(e) = self.mount_native_overlayfs(&lower_dirs_str, &upper_dir, &work_dir, &merged_dir) {
                eprintln!("native overlay mount failed: {}", e);
            } else {
                mounted = true;
            }
        } else if matches!(chosen, StorageDriver::OverlayFuse) {
            if let Err(e) = self.mount_fuse_overlayfs(&lower_dirs_str, &upper_dir, &work_dir, &merged_dir) {
                eprintln!("fuse-overlayfs mount failed: {}", e);
            } else {
                mounted = true;
            }
        }

        if !mounted {
            eprintln!("overlay mount failed; using vfs fallback");
            eprintln!("Falling back to vfs (copy) backend. This is slower but should work.");
            self.build_vfs_root(&lower_dirs, &upper_dir, &merged_dir)?;
            self.last_driver = Some(StorageDriver::Vfs);
        } else {
            self.last_driver = Some(chosen);
        }

        Ok(merged_dir)
    }

    fn mount_fuse_overlayfs(
        &self,
        lower: &str,
        upper: &Path,
        work: &Path,
        merged: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Use fuse-overlayfs for rootless containers
        let status = Command::new("fuse-overlayfs")
            .arg("-o")
            .arg(format!(
                "lowerdir={},upperdir={},workdir={}",
                lower,
                upper.display(),
                work.display()
            ))
            .arg(merged)
            .status()?;

        if !status.success() {
            return Err("Failed to mount with fuse-overlayfs".into());
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

    pub fn unmount_container(&self, container_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let merged_dir = self
            .runtime_dir
            .join("containers")
            .join(container_id)
            .join("merged");

        if self.use_fuse_overlayfs {
            Command::new("fusermount")
                .arg("-u")
                .arg(&merged_dir)
                .status()?;
        } else {
            umount(&merged_dir)?;
        }

        Ok(())
    }

    pub fn last_driver(&self) -> StorageDriver {
        self.last_driver.clone().unwrap_or(if self.use_fuse_overlayfs { StorageDriver::OverlayFuse } else { StorageDriver::OverlayNative })
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

// Example usage for complete rootless container creation
pub fn create_rootless_container(
    _image_name: &str,
    container_id: &str,
    layer_paths: Vec<PathBuf>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut storage = ContainerStorage::new()?;

    // Create container filesystem
    let rootfs = storage.create_container_filesystem(container_id, layer_paths)?;

    println!("Container filesystem ready at: {}", rootfs.display());

    Ok(rootfs)
}

// Helper to check fuse-overlayfs availability
pub fn ensure_fuse_overlayfs() -> Result<(), Box<dyn std::error::Error>> {
    match Command::new("fuse-overlayfs").arg("--version").output() {
        Ok(_) => Ok(()),
        Err(_) => {
            eprintln!("fuse-overlayfs not found. Install it for better rootless support:");
            eprintln!("  Ubuntu/Debian: sudo apt install fuse-overlayfs");
            eprintln!("  Fedora: sudo dnf install fuse-overlayfs");
            eprintln!("  Arch: sudo pacman -S fuse-overlayfs");
            Err("fuse-overlayfs required for rootless containers".into())
        }
    }
}

impl ContainerStorage {
    // Build a merged rootfs by copying files from lower layers (vfs fallback)
    fn build_vfs_root(
        &self,
        lower_dirs: &[String],
        _upper: &Path,
        merged: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Clear merged if any content exists
        if merged.exists() {
            // best-effort clean
            let _ = fs::remove_dir_all(merged);
            fs::create_dir_all(merged)?;
        }

        for lower in lower_dirs.iter() {
            let src = Path::new(lower);
            self.copy_recursive(src, merged)?;
        }
        Ok(())
    }

    fn copy_recursive(&self, src: &Path, dst: &Path) -> Result<(), Box<dyn std::error::Error>> {
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let name = entry.file_name();
            let target = dst.join(&name);
            let path = entry.path();
            if ty.is_dir() {
                fs::create_dir_all(&target)?;
                self.copy_recursive(&path, &target)?;
            } else if ty.is_file() {
                // If exists, overwrite
                let _ = fs::copy(&path, &target)?;
            } else if ty.is_symlink() {
                #[cfg(unix)]
                {
                    let link_target = fs::read_link(&path)?;
                    let _ = std::os::unix::fs::symlink(&link_target, &target);
                }
            }
        }
        Ok(())
    }
}

// Preflight rootless environment checks with actionable hints
pub fn preflight_rootless_checks() {
    // XDG_RUNTIME_DIR
    match dirs::runtime_dir() {
        Some(p) => {
            if !p.exists() { let _ = fs::create_dir_all(&p); }
            println!("Using runtime dir: {}", p.display());
        }
        None => eprintln!("Warning: XDG_RUNTIME_DIR not set. Rootless mounts may fail."),
    }

    // fusermount3 SUID
    if let Ok(meta) = fs::metadata("/usr/bin/fusermount3") {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode();
        if mode & 0o4000 == 0 {
            eprintln!("Warning: fusermount3 is not setuid. Rootless FUSE may fail. Try: sudo chmod u+s /usr/bin/fusermount3");
        }
    } else {
        eprintln!("Warning: fusermount3 not found. Install fuse3 package.");
    }

    // /dev/fuse present
    if !Path::new("/dev/fuse").exists() {
        eprintln!("Warning: /dev/fuse not present. Load FUSE module: sudo modprobe fuse");
    }
}
