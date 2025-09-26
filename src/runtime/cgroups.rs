use std::fs;
use std::path::{Path, PathBuf};
use std::io::Write;

/// Cgroup v2 resource limits configuration
#[derive(Debug, Clone, Default)]
pub struct CgroupConfig {
    /// Memory limit in bytes
    pub memory_limit: Option<u64>,
    /// Memory swap limit in bytes
    pub memory_swap_limit: Option<u64>,
    /// CPU quota in microseconds per period
    pub cpu_quota: Option<u64>,
    /// CPU period in microseconds
    pub cpu_period: Option<u64>,
    /// CPU weight (1-10000, default 100)
    pub cpu_weight: Option<u32>,
    /// Maximum number of processes
    pub pids_limit: Option<u64>,
    /// IO weight (1-10000, default 100)
    pub io_weight: Option<u32>,
}

pub struct CgroupManager {
    config: CgroupConfig,
    container_id: String,
    cgroup_path: PathBuf,
    is_rootless: bool,
}

impl CgroupManager {
    pub fn new(container_id: String, config: CgroupConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let is_rootless = nix::unistd::getuid().as_raw() != 0;
        let cgroup_path = if is_rootless {
            Self::get_user_cgroup_path(&container_id)?
        } else {
            PathBuf::from(format!("/sys/fs/cgroup/carrier/{}", container_id))
        };
        
        Ok(Self {
            config,
            container_id,
            cgroup_path,
            is_rootless,
        })
    }
    
    /// Get the user's delegated cgroup path for rootless containers
    fn get_user_cgroup_path(container_id: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        // Try to find the user's delegated cgroup via systemd
        let uid = nix::unistd::getuid().as_raw();
        let user_slice = format!("user-{}.slice", uid);
        
        // Check common paths for user's cgroup delegation
        let possible_paths = vec![
            format!("/sys/fs/cgroup/user.slice/{}/user@{}.service", user_slice, uid),
            format!("/sys/fs/cgroup/user.slice/{}", user_slice),
            format!("/sys/fs/cgroup/user/{}", uid),
        ];
        
        for path in possible_paths {
            let cgroup_path = PathBuf::from(&path);
            if cgroup_path.exists() {
                // Create carrier subdirectory for our containers
                let carrier_path = cgroup_path.join("carrier.slice");
                if !carrier_path.exists() {
                    fs::create_dir_all(&carrier_path)?;
                }
                return Ok(carrier_path.join(container_id));
            }
        }
        
        // Fallback: try to use current process's cgroup
        let proc_cgroup = fs::read_to_string("/proc/self/cgroup")?;
        for line in proc_cgroup.lines() {
            if line.starts_with("0::") {
                let cgroup_path = line.trim_start_matches("0::");
                let base_path = PathBuf::from(format!("/sys/fs/cgroup{}", cgroup_path));
                if base_path.exists() {
                    let carrier_path = base_path.join("carrier");
                    if !carrier_path.exists() {
                        fs::create_dir_all(&carrier_path)?;
                    }
                    return Ok(carrier_path.join(container_id));
                }
            }
        }
        
        Err("Unable to find suitable cgroup path for rootless container".into())
    }
    
    /// Create and configure the cgroup for the container
    pub fn setup_cgroup(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create cgroup directory
        if !self.cgroup_path.exists() {
            fs::create_dir_all(&self.cgroup_path)?;
        }
        
        // Enable controllers if we have permission
        if !self.is_rootless {
            self.enable_controllers()?;
        }
        
        // Apply resource limits
        self.apply_limits()?;
        
        Ok(())
    }
    
    /// Enable necessary controllers in the parent cgroup
    fn enable_controllers(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = self.cgroup_path.parent() {
            let subtree_control = parent.join("cgroup.subtree_control");
            if subtree_control.exists() {
                // Try to enable controllers we need
                let controllers = "+memory +cpu +pids +io";
                let _ = fs::write(subtree_control, controllers);
            }
        }
        Ok(())
    }
    
    /// Apply configured resource limits
    pub fn apply_limits(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Memory limit
        if let Some(limit) = self.config.memory_limit {
            let memory_max = self.cgroup_path.join("memory.max");
            if memory_max.exists() {
                fs::write(memory_max, limit.to_string())?;
            }
        }
        
        // Memory + swap limit
        if let Some(limit) = self.config.memory_swap_limit {
            let swap_max = self.cgroup_path.join("memory.swap.max");
            if swap_max.exists() {
                fs::write(swap_max, limit.to_string())?;
            }
        }
        
        // CPU quota and period (converted to cpu.max format)
        if let Some(quota) = self.config.cpu_quota {
            let period = self.config.cpu_period.unwrap_or(100000);
            let cpu_max = self.cgroup_path.join("cpu.max");
            if cpu_max.exists() {
                fs::write(cpu_max, format!("{} {}", quota, period))?;
            }
        }
        
        // CPU weight
        if let Some(weight) = self.config.cpu_weight {
            let cpu_weight = self.cgroup_path.join("cpu.weight");
            if cpu_weight.exists() {
                fs::write(cpu_weight, weight.to_string())?;
            }
        }
        
        // PIDs limit
        if let Some(limit) = self.config.pids_limit {
            let pids_max = self.cgroup_path.join("pids.max");
            if pids_max.exists() {
                fs::write(pids_max, limit.to_string())?;
            }
        }
        
        // IO weight
        if let Some(weight) = self.config.io_weight {
            let io_weight = self.cgroup_path.join("io.weight");
            if io_weight.exists() {
                fs::write(io_weight, format!("default {}", weight))?;
            }
        }
        
        Ok(())
    }
    
    /// Add a process to the cgroup
    pub fn add_process(&self, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        let cgroup_procs = self.cgroup_path.join("cgroup.procs");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(cgroup_procs)?;
        writeln!(file, "{}", pid)?;
        Ok(())
    }
    
    /// Get current memory usage
    pub fn get_memory_usage(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let memory_current = self.cgroup_path.join("memory.current");
        if memory_current.exists() {
            let content = fs::read_to_string(memory_current)?;
            Ok(content.trim().parse()?)
        } else {
            Ok(0)
        }
    }
    
    /// Get current CPU usage statistics
    pub fn get_cpu_stats(&self) -> Result<CpuStats, Box<dyn std::error::Error>> {
        let cpu_stat = self.cgroup_path.join("cpu.stat");
        let mut stats = CpuStats::default();
        
        if cpu_stat.exists() {
            let content = fs::read_to_string(cpu_stat)?;
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() == 2 {
                    match parts[0] {
                        "usage_usec" => stats.usage_usec = parts[1].parse().unwrap_or(0),
                        "user_usec" => stats.user_usec = parts[1].parse().unwrap_or(0),
                        "system_usec" => stats.system_usec = parts[1].parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }
        }
        
        Ok(stats)
    }
    
    /// Cleanup the cgroup when container stops
    pub fn cleanup(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.cgroup_path.exists() {
            // Kill all processes in the cgroup
            let _ = self.kill_all_processes();
            
            // Remove the cgroup directory
            fs::remove_dir(&self.cgroup_path)?;
        }
        Ok(())
    }
    
    /// Kill all processes in the cgroup
    fn kill_all_processes(&self) -> Result<(), Box<dyn std::error::Error>> {
        let cgroup_kill = self.cgroup_path.join("cgroup.kill");
        if cgroup_kill.exists() {
            // cgroup v2 kill file (kernel 5.14+)
            fs::write(cgroup_kill, "1")?;
        } else {
            // Fallback: read PIDs and kill manually
            let cgroup_procs = self.cgroup_path.join("cgroup.procs");
            if cgroup_procs.exists() {
                let pids = fs::read_to_string(cgroup_procs)?;
                for pid_str in pids.lines() {
                    if let Ok(pid) = pid_str.parse::<i32>() {
                        unsafe {
                            libc::kill(pid, libc::SIGKILL);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct CpuStats {
    pub usage_usec: u64,
    pub user_usec: u64,
    pub system_usec: u64,
}

/// Helper to get available cgroup controllers
pub fn get_available_controllers() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let controllers_file = Path::new("/sys/fs/cgroup/cgroup.controllers");
    if controllers_file.exists() {
        let content = fs::read_to_string(controllers_file)?;
        Ok(content.split_whitespace().map(String::from).collect())
    } else {
        Ok(vec![])
    }
}

/// Check if running in cgroup v2
pub fn is_cgroup_v2() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}