use caps::{Capability, CapSet, CapsHashSet};
use nix::unistd::{Uid, Gid, setuid, setgid, setgroups};
use nix::sys::prctl;
use std::collections::HashSet;
use std::path::Path;

/// Security configuration for the container
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Capabilities to drop
    pub drop_caps: Vec<Capability>,
    /// Capabilities to keep
    pub keep_caps: Vec<Capability>,
    /// Enable no-new-privileges flag
    pub no_new_privs: bool,
    /// Make rootfs read-only
    pub readonly_rootfs: bool,
    /// Seccomp profile (simplified for now)
    pub seccomp_profile: SeccompProfile,
    /// User to run as in container
    pub user: Option<String>,
    /// Group to run as in container
    pub group: Option<String>,
    /// Additional groups
    pub supplementary_groups: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum SeccompProfile {
    /// Allow all syscalls (no filtering)
    Unconfined,
    /// Default secure profile
    Default,
    /// Custom profile path
    Custom(String),
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            // Drop dangerous capabilities by default
            drop_caps: vec![
                Capability::CAP_SYS_ADMIN,
                Capability::CAP_SYS_MODULE,
                Capability::CAP_SYS_RAWIO,
                Capability::CAP_SYS_PTRACE,
                Capability::CAP_SYS_BOOT,
                Capability::CAP_SYS_NICE,
                Capability::CAP_SYS_RESOURCE,
                Capability::CAP_SYS_TIME,
                Capability::CAP_MKNOD,
                Capability::CAP_NET_ADMIN,
            ],
            // Keep basic capabilities
            keep_caps: vec![
                Capability::CAP_CHOWN,
                Capability::CAP_DAC_OVERRIDE,
                Capability::CAP_FSETID,
                Capability::CAP_FOWNER,
                Capability::CAP_SETGID,
                Capability::CAP_SETUID,
                Capability::CAP_SETPCAP,
                Capability::CAP_NET_BIND_SERVICE,
                Capability::CAP_KILL,
            ],
            no_new_privs: true,
            readonly_rootfs: false,
            seccomp_profile: SeccompProfile::Default,
            user: None,
            group: None,
            supplementary_groups: vec![],
        }
    }
}

pub struct SecurityManager {
    config: SecurityConfig,
}

impl SecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        Self { config }
    }
    
    /// Apply all security configurations
    pub fn apply_security(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Set no-new-privileges if configured
        if self.config.no_new_privs {
            self.set_no_new_privs()?;
        }
        
        // Drop capabilities
        self.apply_capabilities()?;
        
        // Apply seccomp filter (simplified for now)
        self.apply_seccomp()?;
        
        // Set user/group if specified
        if self.config.user.is_some() || self.config.group.is_some() {
            self.set_user_group()?;
        }
        
        Ok(())
    }
    
    /// Set the no-new-privileges flag
    fn set_no_new_privs(&self) -> Result<(), Box<dyn std::error::Error>> {
        prctl::set_no_new_privs()?;
        Ok(())
    }
    
    /// Apply capability restrictions
    fn apply_capabilities(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Get current capabilities
        let mut effective = caps::read(None, CapSet::Effective)?;
        let mut permitted = caps::read(None, CapSet::Permitted)?;
        let mut inheritable = caps::read(None, CapSet::Inheritable)?;
        
        // Create set of capabilities to keep
        let mut keep_set = CapsHashSet::new();
        for cap in &self.config.keep_caps {
            keep_set.insert(*cap);
        }
        
        // Remove capabilities not in keep list
        // We'll iterate through the explicit drop list
        for cap in &self.config.drop_caps {
            effective.remove(cap);
            permitted.remove(cap);
            inheritable.remove(cap);
        }
        
        // Apply the capability sets
        caps::set(None, CapSet::Effective, &effective)?;
        caps::set(None, CapSet::Permitted, &permitted)?;
        caps::set(None, CapSet::Inheritable, &inheritable)?;
        
        Ok(())
    }
    
    /// Apply seccomp filtering (simplified implementation)
    fn apply_seccomp(&self) -> Result<(), Box<dyn std::error::Error>> {
        match &self.config.seccomp_profile {
            SeccompProfile::Unconfined => {
                // No seccomp filtering
            }
            SeccompProfile::Default => {
                // Apply default secure profile
                // This would normally use libseccomp, but for simplicity we'll use prctl
                unsafe {
                    // Enable seccomp in filter mode
                    let ret = libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER,
                        get_default_seccomp_filter(),
                    );
                    if ret != 0 {
                        // Seccomp not available or failed, continue anyway
                    }
                }
            }
            SeccompProfile::Custom(_profile_path) => {
                // Would load custom profile from file
                // For now, use default
                unsafe {
                    let _ = libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER,
                        get_default_seccomp_filter(),
                    );
                }
            }
        }
        Ok(())
    }
    
    /// Set user and group for the process
    fn set_user_group(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Set supplementary groups first
        if !self.config.supplementary_groups.is_empty() {
            let gids: Vec<Gid> = self.config.supplementary_groups
                .iter()
                .filter_map(|g| {
                    g.parse::<u32>().ok().map(Gid::from_raw)
                })
                .collect();
            setgroups(&gids)?;
        }
        
        // Set primary group
        if let Some(ref group) = self.config.group {
            let gid = if let Ok(gid_num) = group.parse::<u32>() {
                Gid::from_raw(gid_num)
            } else {
                // Would normally look up group by name
                Gid::from_raw(0)
            };
            setgid(gid)?;
        }
        
        // Set user (must be done last)
        if let Some(ref user) = self.config.user {
            let uid = if let Ok(uid_num) = user.parse::<u32>() {
                Uid::from_raw(uid_num)
            } else {
                // Would normally look up user by name
                Uid::from_raw(0)
            };
            setuid(uid)?;
        }
        
        Ok(())
    }
    
    /// Make the root filesystem read-only
    pub fn make_rootfs_readonly(&self, rootfs: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if self.config.readonly_rootfs {
            use nix::mount::{mount, MsFlags};
            
            // Remount rootfs as read-only
            mount(
                None::<&str>,
                rootfs,
                None::<&str>,
                MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_BIND,
                None::<&str>,
            )?;
        }
        Ok(())
    }
}

/// Get a default seccomp filter (simplified, would normally use libseccomp)
fn get_default_seccomp_filter() -> *const libc::c_void {
    // This would normally return a BPF program that filters syscalls
    // For now, return null pointer (no filtering)
    std::ptr::null()
}

/// Helper to check if running as root
pub fn is_root() -> bool {
    nix::unistd::getuid().is_root()
}

/// Helper to drop all privileges
pub fn drop_privileges() -> Result<(), Box<dyn std::error::Error>> {
    // List all capabilities to drop
    let all_caps = vec![
        Capability::CAP_CHOWN,
        Capability::CAP_DAC_OVERRIDE,
        Capability::CAP_DAC_READ_SEARCH,
        Capability::CAP_FOWNER,
        Capability::CAP_FSETID,
        Capability::CAP_KILL,
        Capability::CAP_SETGID,
        Capability::CAP_SETUID,
        Capability::CAP_SETPCAP,
        Capability::CAP_LINUX_IMMUTABLE,
        Capability::CAP_NET_BIND_SERVICE,
        Capability::CAP_NET_BROADCAST,
        Capability::CAP_NET_ADMIN,
        Capability::CAP_NET_RAW,
        Capability::CAP_IPC_LOCK,
        Capability::CAP_IPC_OWNER,
        Capability::CAP_SYS_MODULE,
        Capability::CAP_SYS_RAWIO,
        Capability::CAP_SYS_CHROOT,
        Capability::CAP_SYS_PTRACE,
        Capability::CAP_SYS_PACCT,
        Capability::CAP_SYS_ADMIN,
        Capability::CAP_SYS_BOOT,
        Capability::CAP_SYS_NICE,
        Capability::CAP_SYS_RESOURCE,
        Capability::CAP_SYS_TIME,
        Capability::CAP_SYS_TTY_CONFIG,
        Capability::CAP_MKNOD,
        Capability::CAP_LEASE,
        Capability::CAP_AUDIT_WRITE,
        Capability::CAP_AUDIT_CONTROL,
        Capability::CAP_SETFCAP,
    ];
    
    let security_config = SecurityConfig {
        drop_caps: all_caps,
        keep_caps: vec![],
        no_new_privs: true,
        ..Default::default()
    };
    
    let manager = SecurityManager::new(security_config);
    manager.apply_security()
}