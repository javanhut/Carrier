use nix::mount::{MsFlags, mount, umount};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct ContainerStorage {
    base_dir: PathBuf,
    use_fuse_overlayfs: bool,
}

impl ContainerStorage {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Use XDG standard for rootless storage
        let base_dir = dirs::data_dir()
            .ok_or("Cannot determine data directory")?
            .join("carrier")
            .join("storage");

        fs::create_dir_all(&base_dir)?;

        // Check if we can use native overlayfs or need fuse-overlayfs
        let use_fuse_overlayfs = !can_use_native_overlay();

        Ok(Self {
            base_dir,
            use_fuse_overlayfs,
        })
    }

    pub fn create_container_filesystem(
        &self,
        container_id: &str,
        image_layers: Vec<PathBuf>,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        // Create container-specific directories
        let container_dir = self.base_dir.join("containers").join(container_id);
        let upper_dir = container_dir.join("upper");
        let work_dir = container_dir.join("work");
        let merged_dir = container_dir.join("merged");

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

        if self.use_fuse_overlayfs {
            self.mount_fuse_overlayfs(&lower_dirs_str, &upper_dir, &work_dir, &merged_dir)?;
        } else {
            self.mount_native_overlayfs(&lower_dirs_str, &upper_dir, &work_dir, &merged_dir)?;
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
            .base_dir
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
}

pub fn can_use_native_overlay() -> bool {
    // For now, always use fuse-overlayfs for rootless containers
    // Native overlay support for rootless is still inconsistent across distros
    if !nix::unistd::Uid::effective().is_root() {
        return false;
    }
    
    // Check if kernel supports unprivileged overlay mounts
    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        if content.trim() != "1" {
            return false;
        }
    }

    // Check kernel version (5.11+ has better rootless support)
    if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        if let Some(version) = parse_kernel_version(&release) {
            return version >= (5, 11, 0);
        }
    }

    false
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
    let storage = ContainerStorage::new()?;

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
