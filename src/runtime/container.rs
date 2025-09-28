use nix::sys::signal::Signal;
use nix::unistd::Pid;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::runtime::cgroups::{CgroupConfig, CgroupManager};
use crate::runtime::namespaces::{NamespaceConfig, NamespaceManager};
use crate::runtime::network::{NetworkConfig, NetworkManager, NetworkMode};
use crate::runtime::process::{ContainerProcess, ProcessConfig};
use crate::runtime::security::{SecurityConfig, SecurityManager};

/// Complete container runtime configuration
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    pub id: String,
    pub name: Option<String>,
    pub image: String,
    pub rootfs: PathBuf,
    pub command: Vec<String>,
    pub env: Vec<(String, String)>,
    pub working_dir: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub readonly_rootfs: bool,
    pub network_config: NetworkConfig,
    pub cgroup_config: CgroupConfig,
    pub security_config: SecurityConfig,
    pub mounts: Vec<MountPoint>,
    pub labels: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct MountPoint {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub readonly: bool,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: None,
            image: String::new(),
            rootfs: PathBuf::new(),
            command: vec!["/bin/sh".to_string()],
            env: vec![
                (
                    "PATH".to_string(),
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                ),
                ("TERM".to_string(), "xterm".to_string()),
            ],
            working_dir: "/".to_string(),
            hostname: None,
            user: None,
            readonly_rootfs: false,
            network_config: NetworkConfig::default(),
            cgroup_config: CgroupConfig::default(),
            security_config: SecurityConfig::default(),
            mounts: vec![],
            labels: vec![],
        }
    }
}

pub struct Container {
    config: ContainerConfig,
    process: Option<ContainerProcess>,
    network: Option<NetworkManager>,
    cgroup: Option<CgroupManager>,
    pid: Option<Pid>,
    running: Arc<AtomicBool>,
    start_time: Option<std::time::Instant>,
}

impl Container {
    /// Create a new container
    pub fn new(config: ContainerConfig) -> Self {
        Self {
            config,
            process: None,
            network: None,
            cgroup: None,
            pid: None,
            running: Arc::new(AtomicBool::new(false)),
            start_time: None,
        }
    }

    /// Start the container
    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.running.load(Ordering::SeqCst) {
            return Err("Container is already running".into());
        }

        println!("Starting container {}...", self.config.id);

        // Validate configuration
        self.validate_config()?;

        // Setup network manager
        let mut network_mgr = NetworkManager::new(self.config.network_config.clone());

        // Setup cgroup manager
        let cgroup_mgr =
            CgroupManager::new(self.config.id.clone(), self.config.cgroup_config.clone())?;
        cgroup_mgr.setup_cgroup()?;

        // Prepare process configuration
        let mut namespace_config = NamespaceConfig::default();
        namespace_config.hostname = self.config.hostname.clone();

        // Disable network namespace if using host network
        if matches!(self.config.network_config.network_mode, NetworkMode::Host) {
            namespace_config.use_net_ns = false;
        }

        let process_config = ProcessConfig {
            container_id: self.config.id.clone(),
            rootfs: self.config.rootfs.clone(),
            command: self.config.command.clone(),
            env: self
                .config
                .env
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect(),
            cwd: self.config.working_dir.clone(),
            terminal: false,
            user: self.config.user.clone(),
            namespace_config,
            cgroup_config: self.config.cgroup_config.clone(),
            security_config: self.config.security_config.clone(),
            init: true,
        };

        // Setup DNS before starting container
        if self.config.network_config.enable_network {
            network_mgr.setup_dns(&self.config.rootfs)?;
        }

        // Start the container process
        let mut process = ContainerProcess::new(process_config);
        let pid = process.start()?;

        // Setup networking after process starts
        if self.config.network_config.enable_network {
            network_mgr.setup_network(pid)?;
        }

        // Add process to cgroup
        cgroup_mgr.add_process(pid.as_raw() as u32)?;

        // Store components
        self.process = Some(process);
        self.network = Some(network_mgr);
        self.cgroup = Some(cgroup_mgr);
        self.pid = Some(pid);
        self.running.store(true, Ordering::SeqCst);
        self.start_time = Some(std::time::Instant::now());

        println!("Container {} started with PID {}", self.config.id, pid);

        Ok(())
    }

    /// Stop the container
    pub fn stop(&mut self, timeout: std::time::Duration) -> Result<(), Box<dyn std::error::Error>> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        println!("Stopping container {}...", self.config.id);

        // Stop the process
        if let Some(ref mut process) = self.process {
            process.stop(timeout)?;
        }

        // Cleanup network
        if let Some(ref mut network) = self.network {
            network.cleanup()?;
        }

        // Cleanup cgroup
        if let Some(ref cgroup) = self.cgroup {
            cgroup.cleanup()?;
        }

        self.running.store(false, Ordering::SeqCst);
        println!("Container {} stopped", self.config.id);

        Ok(())
    }

    /// Kill the container
    pub fn kill(&self, signal: Signal) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref process) = self.process {
            process.kill(signal)?;
        }
        Ok(())
    }

    /// Wait for the container to exit
    pub fn wait(&self) -> Result<i32, Box<dyn std::error::Error>> {
        if let Some(ref process) = self.process {
            let status = process.wait()?;
            match status {
                nix::sys::wait::WaitStatus::Exited(_, code) => Ok(code),
                nix::sys::wait::WaitStatus::Signaled(_, signal, _) => Ok(128 + signal as i32),
                _ => Ok(-1),
            }
        } else {
            Err("Container not started".into())
        }
    }

    /// Get container status
    pub fn status(&self) -> ContainerStatus {
        if self.running.load(Ordering::SeqCst) {
            if let Some(ref process) = self.process {
                if process.is_running() {
                    return ContainerStatus::Running;
                }
            }
            self.running.store(false, Ordering::SeqCst);
        }
        ContainerStatus::Stopped
    }

    /// Get container stats
    pub fn stats(&self) -> Result<ContainerStats, Box<dyn std::error::Error>> {
        let mut stats = ContainerStats::default();

        // Get cgroup stats
        if let Some(ref cgroup) = self.cgroup {
            stats.memory_usage = cgroup.get_memory_usage()?;
            let cpu_stats = cgroup.get_cpu_stats()?;
            stats.cpu_usage = cpu_stats.usage_usec;
        }

        // Get runtime duration
        if let Some(start_time) = self.start_time {
            stats.runtime_seconds = start_time.elapsed().as_secs();
        }

        stats.pid = self.pid.map(|p| p.as_raw() as u32);

        Ok(stats)
    }

    /// Validate container configuration
    fn validate_config(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Check rootfs exists
        if !self.config.rootfs.exists() {
            return Err(format!("Rootfs does not exist: {:?}", self.config.rootfs).into());
        }

        // Check command is not empty
        if self.config.command.is_empty() {
            return Err("No command specified".into());
        }

        // Check for required binaries in rootfs
        let cmd_path = if self.config.command[0].starts_with('/') {
            self.config.rootfs.join(&self.config.command[0][1..])
        } else {
            // Would need to search PATH
            self.config.rootfs.join("bin").join(&self.config.command[0])
        };

        if !cmd_path.exists() {
            // Try common locations
            let locations = vec!["bin", "usr/bin", "sbin", "usr/sbin"];
            let mut found = false;
            for loc in locations {
                let path = self.config.rootfs.join(loc).join(&self.config.command[0]);
                if path.exists() {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(
                    format!("Command not found in rootfs: {}", self.config.command[0]).into(),
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContainerStatus {
    Created,
    Running,
    Paused,
    Stopped,
    Dead,
}

#[derive(Debug, Default)]
pub struct ContainerStats {
    pub memory_usage: u64,
    pub cpu_usage: u64,
    pub runtime_seconds: u64,
    pub pid: Option<u32>,
}

/// Run a container with the given configuration
pub fn run_container(config: ContainerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut container = Container::new(config);

    // Start the container
    container.start()?;

    // Wait for it to exit
    let exit_code = container.wait()?;

    // Cleanup
    container.stop(std::time::Duration::from_secs(10))?;

    if exit_code != 0 {
        return Err(format!("Container exited with code {}", exit_code).into());
    }

    Ok(())
}
