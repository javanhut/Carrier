use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, execve, fork, setsid, ForkResult, Pid};
use std::ffi::{CStr, CString};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::runtime::cgroups::{CgroupConfig, CgroupManager};
use crate::runtime::namespaces::{NamespaceConfig, NamespaceManager};
use crate::runtime::security::{SecurityConfig, SecurityManager};

/// Container process configuration
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    /// Container ID
    pub container_id: String,
    /// Root filesystem path
    pub rootfs: PathBuf,
    /// Command to execute
    pub command: Vec<String>,
    /// Environment variables
    pub env: Vec<String>,
    /// Working directory
    pub cwd: String,
    /// Terminal attached
    pub terminal: bool,
    /// User to run as
    pub user: Option<String>,
    /// Namespace configuration
    pub namespace_config: NamespaceConfig,
    /// Cgroup configuration
    pub cgroup_config: CgroupConfig,
    /// Security configuration
    pub security_config: SecurityConfig,
    /// Init process (run as PID 1)
    pub init: bool,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            container_id: String::new(),
            rootfs: PathBuf::new(),
            command: vec!["/bin/sh".to_string()],
            env: vec![
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                "TERM=xterm".to_string(),
            ],
            cwd: "/".to_string(),
            terminal: false,
            user: None,
            namespace_config: NamespaceConfig::default(),
            cgroup_config: CgroupConfig::default(),
            security_config: SecurityConfig::default(),
            init: true,
        }
    }
}

pub struct ContainerProcess {
    config: ProcessConfig,
    pid: Option<Pid>,
    running: Arc<AtomicBool>,
}

impl ContainerProcess {
    pub fn new(config: ProcessConfig) -> Self {
        Self {
            config,
            pid: None,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the container process
    pub fn start(&mut self) -> Result<Pid, Box<dyn std::error::Error>> {
        // Use simpler synchronization without pipes for now
        // In a production system, we'd use proper IPC

        // Use fork for process creation
        let child_pid = match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                // Parent process

                // Give child a moment to set up
                std::thread::sleep(std::time::Duration::from_millis(100));

                // Setup user namespace mappings if needed
                if self.config.namespace_config.use_user_ns {
                    let ns_mgr = NamespaceManager::new(self.config.namespace_config.clone());
                    ns_mgr.setup_rootless_userns(child.as_raw())?;
                }

                // Setup cgroups
                let cgroup_mgr = CgroupManager::new(
                    self.config.container_id.clone(),
                    self.config.cgroup_config.clone(),
                )?;
                cgroup_mgr.setup_cgroup()?;
                cgroup_mgr.add_process(child.as_raw() as u32)?;

                child
            }
            ForkResult::Child => {
                // Child process

                // Setup namespaces
                let ns_mgr = NamespaceManager::new(self.config.namespace_config.clone());
                let _ = ns_mgr.enter_namespaces();

                // Wait a moment for parent to set things up
                std::thread::sleep(std::time::Duration::from_millis(200));

                // Run container
                if let Err(e) = self.run_container() {
                    eprintln!("Container failed: {}", e);
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
        };

        self.pid = Some(child_pid);
        self.running.store(true, Ordering::SeqCst);

        Ok(child_pid)
    }

    /// Run the container (executed in child process)
    fn run_container(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Setup container filesystem
        self.setup_container_fs()?;

        // Change to new root
        self.pivot_root()?;

        // Setup mounts
        let ns_mgr = NamespaceManager::new(self.config.namespace_config.clone());
        ns_mgr.setup_container_mounts(&PathBuf::from("/"))?;

        // Apply security policies
        let sec_mgr = SecurityManager::new(self.config.security_config.clone());
        sec_mgr.apply_security()?;

        // Set working directory
        chdir(Path::new(&self.config.cwd))?;

        // Set hostname if configured
        if let Some(ref hostname) = self.config.namespace_config.hostname {
            nix::unistd::sethostname(hostname)?;
        }

        // Create new session
        setsid()?;

        // Execute the command
        self.exec_command()
    }

    /// Setup container filesystem
    fn setup_container_fs(&self) -> Result<(), Box<dyn std::error::Error>> {
        use nix::mount::{mount, MsFlags};

        // Ensure rootfs exists
        if !self.config.rootfs.exists() {
            return Err(format!("Rootfs does not exist: {:?}", self.config.rootfs).into());
        }

        // Only bind mount for root containers
        // Rootless containers don't need this as they use chroot
        if nix::unistd::Uid::effective().is_root() {
            // Make rootfs a mount point
            mount(
                Some(&self.config.rootfs),
                &self.config.rootfs,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )?;
        }

        Ok(())
    }

    /// Pivot root to container filesystem
    fn pivot_root(&self) -> Result<(), Box<dyn std::error::Error>> {
        use nix::mount::{mount, umount2, MntFlags, MsFlags};
        use std::fs;

        // For rootless containers, we use chroot instead of pivot_root
        // as pivot_root requires CAP_SYS_ADMIN in the user namespace
        if !nix::unistd::Uid::effective().is_root() {
            // Use chroot for rootless containers
            nix::unistd::chroot(&self.config.rootfs)?;
            chdir(Path::new("/"))?;
        } else {
            // Use pivot_root for root containers
            let new_root = &self.config.rootfs;
            let put_old = new_root.join(".old_root");

            // Create directory for old root
            if !put_old.exists() {
                fs::create_dir(&put_old)?;
            }

            // Bind mount new root to itself to make it a mount point
            mount(
                Some(new_root),
                new_root,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )?;

            // Pivot root
            nix::unistd::pivot_root(new_root, &put_old)?;

            // Change to new root
            chdir(Path::new("/"))?;

            // Unmount old root
            umount2("/.old_root", MntFlags::MNT_DETACH)?;

            // Remove old root directory
            fs::remove_dir("/.old_root")?;
        }

        Ok(())
    }

    /// Execute the container command
    fn exec_command(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.config.command.is_empty() {
            return Err("No command specified".into());
        }

        // Prepare command and arguments
        let cmd = CString::new(self.config.command[0].as_bytes())?;
        let args: Vec<CString> = self
            .config
            .command
            .iter()
            .map(|s| CString::new(s.as_bytes()).unwrap())
            .collect();

        // Prepare environment
        let env: Vec<CString> = self
            .config
            .env
            .iter()
            .map(|s| CString::new(s.as_bytes()).unwrap())
            .collect();

        // Execute
        execve(&cmd, &args, &env)?;

        // Should never reach here
        Err("execve failed".into())
    }

    /// Wait for the container process to exit
    pub fn wait(&self) -> Result<WaitStatus, Box<dyn std::error::Error>> {
        if let Some(pid) = self.pid {
            let status = waitpid(pid, None)?;
            Ok(status)
        } else {
            Err("Container not started".into())
        }
    }

    /// Kill the container process
    pub fn kill(&self, signal: Signal) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(pid) = self.pid {
            kill(pid, signal)?;
            Ok(())
        } else {
            Err("Container not started".into())
        }
    }

    /// Check if container is running
    pub fn is_running(&self) -> bool {
        if let Some(pid) = self.pid {
            // Check if process exists
            match kill(pid, None) {
                Ok(_) => true,
                Err(_) => {
                    self.running.store(false, Ordering::SeqCst);
                    false
                }
            }
        } else {
            false
        }
    }

    /// Get container PID
    pub fn get_pid(&self) -> Option<Pid> {
        self.pid
    }

    /// Stop the container gracefully
    pub fn stop(&mut self, timeout: Duration) -> Result<(), Box<dyn std::error::Error>> {
        if !self.is_running() {
            return Ok(());
        }

        // Send SIGTERM
        self.kill(Signal::SIGTERM)?;

        // Wait for process to exit
        let start = std::time::Instant::now();
        while self.is_running() && start.elapsed() < timeout {
            thread::sleep(Duration::from_millis(100));
        }

        // Force kill if still running
        if self.is_running() {
            self.kill(Signal::SIGKILL)?;
            thread::sleep(Duration::from_millis(100));
        }

        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }
}

/// Container init process for reaping zombies
pub fn container_init(config: ProcessConfig) -> Result<(), Box<dyn std::error::Error>> {
    use nix::sys::wait::{waitpid, WaitPidFlag};

    // Fork to create the actual process
    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            // Init process - reap zombies
            loop {
                match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(pid, _)) if pid == child => {
                        // Main process exited
                        break;
                    }
                    Ok(WaitStatus::Signaled(pid, _, _)) if pid == child => {
                        // Main process killed
                        break;
                    }
                    Ok(_) => {
                        // Reaped a zombie
                        continue;
                    }
                    Err(_) => {
                        // No children to reap
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            Ok(())
        }
        ForkResult::Child => {
            // Execute the actual command
            let process = ContainerProcess::new(config);
            process.run_container()?;
            Ok(())
        }
    }
}
