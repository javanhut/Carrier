use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{setgid, sethostname, setuid, Gid, Pid, Uid};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Namespace configuration for container isolation
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub use_pid_ns: bool,
    pub use_net_ns: bool,
    pub use_ipc_ns: bool,
    pub use_uts_ns: bool,
    pub use_mount_ns: bool,
    pub use_user_ns: bool,
    pub use_cgroup_ns: bool,
    pub hostname: Option<String>,
    pub uid_mappings: Vec<UidMapping>,
    pub gid_mappings: Vec<GidMapping>,
}

#[derive(Debug, Clone)]
pub struct UidMapping {
    pub container_id: u32,
    pub host_id: u32,
    pub range: u32,
}

#[derive(Debug, Clone)]
pub struct GidMapping {
    pub container_id: u32,
    pub host_id: u32,
    pub range: u32,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();

        Self {
            use_pid_ns: true,
            use_net_ns: true,
            use_ipc_ns: true,
            use_uts_ns: true,
            use_mount_ns: true,
            use_user_ns: true,
            use_cgroup_ns: true,
            hostname: None,
            // Map root in container to current user outside
            uid_mappings: vec![
                UidMapping {
                    container_id: 0,
                    host_id: uid,
                    range: 1,
                },
                // Map higher UIDs if available
                UidMapping {
                    container_id: 1,
                    host_id: 100000,
                    range: 65536,
                },
            ],
            gid_mappings: vec![
                GidMapping {
                    container_id: 0,
                    host_id: gid,
                    range: 1,
                },
                // Map higher GIDs if available
                GidMapping {
                    container_id: 1,
                    host_id: 100000,
                    range: 65536,
                },
            ],
        }
    }
}

pub struct NamespaceManager {
    config: NamespaceConfig,
}

impl NamespaceManager {
    pub fn new(config: NamespaceConfig) -> Self {
        Self { config }
    }

    /// Enter new namespaces based on configuration
    pub fn enter_namespaces(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut flags = CloneFlags::empty();

        if self.config.use_pid_ns {
            flags.insert(CloneFlags::CLONE_NEWPID);
        }
        if self.config.use_net_ns {
            flags.insert(CloneFlags::CLONE_NEWNET);
        }
        if self.config.use_ipc_ns {
            flags.insert(CloneFlags::CLONE_NEWIPC);
        }
        if self.config.use_uts_ns {
            flags.insert(CloneFlags::CLONE_NEWUTS);
        }
        if self.config.use_mount_ns {
            flags.insert(CloneFlags::CLONE_NEWNS);
        }
        if self.config.use_user_ns {
            flags.insert(CloneFlags::CLONE_NEWUSER);
        }
        if self.config.use_cgroup_ns {
            flags.insert(CloneFlags::CLONE_NEWCGROUP);
        }

        // Unshare into new namespaces
        unshare(flags)?;

        // Set hostname if in UTS namespace
        if self.config.use_uts_ns {
            if let Some(ref hostname) = self.config.hostname {
                sethostname(hostname)?;
            }
        }

        Ok(())
    }

    /// Setup user namespace mappings
    pub fn setup_user_mappings(&self, pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
        // Write uid_map
        let uid_map_path = format!("/proc/{}/uid_map", pid);
        let mut uid_map_content = String::new();
        for mapping in &self.config.uid_mappings {
            uid_map_content.push_str(&format!(
                "{} {} {}\n",
                mapping.container_id, mapping.host_id, mapping.range
            ));
        }

        // Disable setgroups before writing gid_map (required for unprivileged user namespaces)
        let setgroups_path = format!("/proc/{}/setgroups", pid);
        fs::write(&setgroups_path, "deny")?;

        // Write gid_map
        let gid_map_path = format!("/proc/{}/gid_map", pid);
        let mut gid_map_content = String::new();
        for mapping in &self.config.gid_mappings {
            gid_map_content.push_str(&format!(
                "{} {} {}\n",
                mapping.container_id, mapping.host_id, mapping.range
            ));
        }

        fs::write(uid_map_path, uid_map_content)?;
        fs::write(gid_map_path, gid_map_content)?;

        Ok(())
    }

    /// Setup rootless user namespace with newuidmap/newgidmap
    pub fn setup_rootless_userns(&self, pid: i32) -> Result<(), Box<dyn std::error::Error>> {
        // Use newuidmap for setting up uid mappings
        let uid = nix::unistd::getuid().as_raw();
        let mut newuidmap_cmd = Command::new("newuidmap");
        newuidmap_cmd.arg(pid.to_string());
        newuidmap_cmd.arg("0").arg(uid.to_string()).arg("1");

        // Add subuid ranges if available
        if let Ok(subuid_content) = fs::read_to_string("/etc/subuid") {
            for line in subuid_content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() == 3 {
                    let username = parts[0];
                    if let Ok(current_user) = std::env::var("USER") {
                        if username == current_user {
                            let subuid_start = parts[1];
                            let subuid_count = parts[2];
                            newuidmap_cmd.arg("1").arg(subuid_start).arg(subuid_count);
                            break;
                        }
                    }
                }
            }
        }

        newuidmap_cmd.output()?;

        // Use newgidmap for setting up gid mappings
        let gid = nix::unistd::getgid().as_raw();
        let mut newgidmap_cmd = Command::new("newgidmap");
        newgidmap_cmd.arg(pid.to_string());
        newgidmap_cmd.arg("0").arg(gid.to_string()).arg("1");

        // Add subgid ranges if available
        if let Ok(subgid_content) = fs::read_to_string("/etc/subgid") {
            for line in subgid_content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() == 3 {
                    let username = parts[0];
                    if let Ok(current_user) = std::env::var("USER") {
                        if username == current_user {
                            let subgid_start = parts[1];
                            let subgid_count = parts[2];
                            newgidmap_cmd.arg("1").arg(subgid_start).arg(subgid_count);
                            break;
                        }
                    }
                }
            }
        }

        newgidmap_cmd.output()?;

        Ok(())
    }

    /// Setup basic container mounts
    pub fn setup_container_mounts(&self, rootfs: &Path) -> Result<(), Box<dyn std::error::Error>> {
        // Mount proc
        let proc_target = rootfs.join("proc");
        if !proc_target.exists() {
            fs::create_dir_all(&proc_target)?;
        }
        mount(
            Some("proc"),
            &proc_target,
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            None::<&str>,
        )?;

        // Mount sys
        let sys_target = rootfs.join("sys");
        if !sys_target.exists() {
            fs::create_dir_all(&sys_target)?;
        }
        mount(
            Some("sysfs"),
            &sys_target,
            Some("sysfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV | MsFlags::MS_RDONLY,
            None::<&str>,
        )?;

        // Mount /dev
        let dev_target = rootfs.join("dev");
        if !dev_target.exists() {
            fs::create_dir_all(&dev_target)?;
        }

        // Try to mount devtmpfs first
        let dev_mount_flags = MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME;
        let devtmpfs_mounted = mount(
            Some("devtmpfs"),
            &dev_target,
            Some("devtmpfs"),
            dev_mount_flags,
            Some("mode=755"),
        ).is_ok();

        if !devtmpfs_mounted {
            // Fall back to tmpfs when devtmpfs is not permitted (e.g. inside user namespaces)
            mount(
                Some("tmpfs"),
                &dev_target,
                Some("tmpfs"),
                dev_mount_flags,
                Some("mode=755,size=65536k"),
            )?;

            // When using tmpfs, we need to create all device nodes manually
            self.create_devices(&dev_target)?;
        } else {
            // devtmpfs provides most devices, but we still need to ensure essential ones exist
            self.create_devices(&dev_target)?;
        }

        // Mount /dev/pts
        let pts_target = dev_target.join("pts");
        if !pts_target.exists() {
            fs::create_dir_all(&pts_target)?;
        }
        mount(
            Some("devpts"),
            &pts_target,
            Some("devpts"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("newinstance,ptmxmode=0666,mode=0620"),
        )?;

        // Mount /dev/shm
        let shm_target = dev_target.join("shm");
        if !shm_target.exists() {
            fs::create_dir_all(&shm_target)?;
        }
        mount(
            Some("shm"),
            &shm_target,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            Some("mode=1777,size=65536k"),
        )?;

        Ok(())
    }

    /// Create essential device nodes
    fn create_devices(&self, dev_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        use nix::sys::stat::{mknod, Mode, SFlag};
        use std::os::unix::fs::{symlink, PermissionsExt};

        // Create /dev/null
        let null_path = dev_path.join("null");
        if !null_path.exists() {
            mknod(
                &null_path,
                SFlag::S_IFCHR,
                Mode::S_IRUSR
                    | Mode::S_IWUSR
                    | Mode::S_IRGRP
                    | Mode::S_IWGRP
                    | Mode::S_IROTH
                    | Mode::S_IWOTH,
                nix::sys::stat::makedev(1, 3),
            )?;
        }
        // Ensure correct permissions on /dev/null (mode 0666)
        fs::set_permissions(&null_path, fs::Permissions::from_mode(0o666))?;

        // Create /dev/zero
        let zero_path = dev_path.join("zero");
        if !zero_path.exists() {
            mknod(
                &zero_path,
                SFlag::S_IFCHR,
                Mode::S_IRUSR
                    | Mode::S_IWUSR
                    | Mode::S_IRGRP
                    | Mode::S_IWGRP
                    | Mode::S_IROTH
                    | Mode::S_IWOTH,
                nix::sys::stat::makedev(1, 5),
            )?;
        }
        // Ensure correct permissions on /dev/zero (mode 0666)
        fs::set_permissions(&zero_path, fs::Permissions::from_mode(0o666))?;

        // Create /dev/random
        let random_path = dev_path.join("random");
        if !random_path.exists() {
            mknod(
                &random_path,
                SFlag::S_IFCHR,
                Mode::S_IRUSR
                    | Mode::S_IWUSR
                    | Mode::S_IRGRP
                    | Mode::S_IWGRP
                    | Mode::S_IROTH
                    | Mode::S_IWOTH,
                nix::sys::stat::makedev(1, 8),
            )?;
        }
        // Ensure correct permissions on /dev/random (mode 0666)
        fs::set_permissions(&random_path, fs::Permissions::from_mode(0o666))?;

        // Create /dev/urandom
        let urandom_path = dev_path.join("urandom");
        if !urandom_path.exists() {
            mknod(
                &urandom_path,
                SFlag::S_IFCHR,
                Mode::S_IRUSR
                    | Mode::S_IWUSR
                    | Mode::S_IRGRP
                    | Mode::S_IWGRP
                    | Mode::S_IROTH
                    | Mode::S_IWOTH,
                nix::sys::stat::makedev(1, 9),
            )?;
        }
        // Ensure correct permissions on /dev/urandom (mode 0666)
        fs::set_permissions(&urandom_path, fs::Permissions::from_mode(0o666))?;

        // Create /dev/tty
        let tty_path = dev_path.join("tty");
        if !tty_path.exists() {
            mknod(
                &tty_path,
                SFlag::S_IFCHR,
                Mode::S_IRUSR
                    | Mode::S_IWUSR
                    | Mode::S_IRGRP
                    | Mode::S_IWGRP
                    | Mode::S_IROTH
                    | Mode::S_IWOTH,
                nix::sys::stat::makedev(5, 0),
            )?;
        }
        // Ensure correct permissions on /dev/tty (mode 0666)
        fs::set_permissions(&tty_path, fs::Permissions::from_mode(0o666))?;

        // Create /dev/console
        let console_path = dev_path.join("console");
        if !console_path.exists() {
            mknod(
                &console_path,
                SFlag::S_IFCHR,
                Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IWGRP,
                nix::sys::stat::makedev(5, 1),
            )?;
        }
        // Ensure correct permissions on /dev/console (mode 0620)
        fs::set_permissions(&console_path, fs::Permissions::from_mode(0o620))?;

        // Symlink /dev/ptmx to /dev/pts/ptmx
        let ptmx_path = dev_path.join("ptmx");
        if !ptmx_path.exists() {
            symlink("pts/ptmx", &ptmx_path)?;
        }

        // Symlink standard streams
        symlink("/proc/self/fd", &dev_path.join("fd"))?;
        symlink("/proc/self/fd/0", &dev_path.join("stdin"))?;
        symlink("/proc/self/fd/1", &dev_path.join("stdout"))?;
        symlink("/proc/self/fd/2", &dev_path.join("stderr"))?;

        Ok(())
    }
}
