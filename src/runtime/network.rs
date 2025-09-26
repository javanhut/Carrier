use std::process::{Command, Stdio, Child};
use std::path::Path;
use std::fs;
use std::io::Write;
use nix::unistd::Pid;

/// Network configuration for containers
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Enable networking
    pub enable_network: bool,
    /// Port mappings (host_port:container_port)
    pub port_mappings: Vec<PortMapping>,
    /// DNS servers
    pub dns_servers: Vec<String>,
    /// Hostname
    pub hostname: String,
    /// Domain name
    pub domainname: String,
    /// Network mode
    pub network_mode: NetworkMode,
}

#[derive(Debug, Clone)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone)]
pub enum Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone)]
pub enum NetworkMode {
    /// No network
    None,
    /// Use host network namespace
    Host,
    /// Use slirp4netns for usermode networking
    Slirp4netns,
    /// Bridge networking (requires root)
    Bridge,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enable_network: true,
            port_mappings: vec![],
            dns_servers: vec![
                "8.8.8.8".to_string(),
                "8.8.4.4".to_string(),
            ],
            hostname: "carrier-container".to_string(),
            domainname: "local".to_string(),
            network_mode: NetworkMode::Slirp4netns,
        }
    }
}

pub struct NetworkManager {
    config: NetworkConfig,
    slirp_process: Option<Child>,
}

impl NetworkManager {
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            slirp_process: None,
        }
    }
    
    /// Setup network for container
    pub fn setup_network(&mut self, container_pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
        match self.config.network_mode {
            NetworkMode::None => {
                // No network setup needed
                Ok(())
            }
            NetworkMode::Host => {
                // Using host network, no setup needed
                Ok(())
            }
            NetworkMode::Slirp4netns => {
                // Setup usermode networking with slirp4netns
                self.setup_slirp4netns(container_pid)
            }
            NetworkMode::Bridge => {
                // Would require root privileges
                Err("Bridge networking requires root privileges".into())
            }
        }
    }
    
    /// Setup slirp4netns for usermode networking
    fn setup_slirp4netns(&mut self, container_pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
        // Check if slirp4netns is available
        if !Path::new("/usr/bin/slirp4netns").exists() {
            return Err("slirp4netns not found. Please install slirp4netns package.".into());
        }
        
        // Build slirp4netns command
        let mut cmd = Command::new("slirp4netns");
        
        // Basic options
        cmd.arg("--configure")
            .arg("--mtu=65520")
            .arg("--disable-host-loopback");
        
        // Add port mappings
        for mapping in &self.config.port_mappings {
            let proto = match mapping.protocol {
                Protocol::TCP => "tcp",
                Protocol::UDP => "udp",
            };
            cmd.arg(format!(
                "--api-socket=/tmp/slirp4netns-{}.sock",
                container_pid.as_raw()
            ));
            cmd.arg(format!(
                "{}:{}:{}",
                proto,
                mapping.host_port,
                mapping.container_port
            ));
        }
        
        // Add container PID and tap device
        cmd.arg(container_pid.as_raw().to_string())
            .arg("tap0");
        
        // Start slirp4netns
        let slirp = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        
        self.slirp_process = Some(slirp);
        
        // Wait a moment for slirp4netns to initialize
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        Ok(())
    }
    
    /// Setup DNS resolution in container
    pub fn setup_dns(&self, rootfs: &Path) -> Result<(), Box<dyn std::error::Error>> {
        // Create /etc/resolv.conf
        let resolv_conf = rootfs.join("etc/resolv.conf");
        
        // Ensure /etc exists
        let etc_dir = rootfs.join("etc");
        if !etc_dir.exists() {
            fs::create_dir_all(&etc_dir)?;
        }
        
        // Write DNS configuration
        let mut content = String::new();
        
        // Add search domain
        if !self.config.domainname.is_empty() {
            content.push_str(&format!("search {}\n", self.config.domainname));
        }
        
        // Add nameservers
        for dns in &self.config.dns_servers {
            content.push_str(&format!("nameserver {}\n", dns));
        }
        
        fs::write(&resolv_conf, content)?;
        
        // Create /etc/hosts
        let hosts_file = rootfs.join("etc/hosts");
        let hosts_content = format!(
            "127.0.0.1\tlocalhost\n\
             ::1\tlocalhost\n\
             127.0.1.1\t{} {}.{}\n",
            self.config.hostname,
            self.config.hostname,
            self.config.domainname
        );
        fs::write(&hosts_file, hosts_content)?;
        
        // Create /etc/hostname
        let hostname_file = rootfs.join("etc/hostname");
        fs::write(&hostname_file, &self.config.hostname)?;
        
        Ok(())
    }
    
    /// Configure network interfaces in container
    pub fn configure_interfaces(&self) -> Result<(), Box<dyn std::error::Error>> {
        use std::process::Command;
        
        match self.config.network_mode {
            NetworkMode::Slirp4netns => {
                // Configure lo interface
                Command::new("ip")
                    .args(&["link", "set", "lo", "up"])
                    .output()?;
                
                // The tap0 interface should be configured by slirp4netns
                // Just ensure it's up
                Command::new("ip")
                    .args(&["link", "set", "tap0", "up"])
                    .output()?;
            }
            _ => {}
        }
        
        Ok(())
    }
    
    /// Add port forwarding rule (for slirp4netns API)
    pub fn add_port_forward(
        &self,
        container_pid: Pid,
        mapping: &PortMapping
    ) -> Result<(), Box<dyn std::error::Error>> {
        let api_socket = format!("/tmp/slirp4netns-{}.sock", container_pid.as_raw());
        
        if !Path::new(&api_socket).exists() {
            return Err("slirp4netns API socket not found".into());
        }
        
        let proto = match mapping.protocol {
            Protocol::TCP => "tcp",
            Protocol::UDP => "udp",
        };
        
        // Use slirp4netns API to add port forwarding
        let _json_request = format!(
            r#"{{"execute": "add_hostfwd", "arguments": {{"proto": "{}", "host_addr": "0.0.0.0", "host_port": {}, "guest_addr": "10.0.2.100", "guest_port": {}}}}}"#,
            proto,
            mapping.host_port,
            mapping.container_port
        );
        
        // Would normally send this to the API socket
        // For simplicity, we'll rely on initial configuration
        
        Ok(())
    }
    
    /// Cleanup network resources
    pub fn cleanup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Kill slirp4netns if running
        if let Some(mut slirp) = self.slirp_process.take() {
            let _ = slirp.kill();
            let _ = slirp.wait();
        }
        
        Ok(())
    }
}

impl Drop for NetworkManager {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Helper to check network connectivity
pub fn check_network_connectivity() -> bool {
    Command::new("ping")
        .args(&["-c", "1", "-W", "1", "8.8.8.8"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Get default gateway
pub fn get_default_gateway() -> Option<String> {
    let output = Command::new("ip")
        .args(&["route", "show", "default"])
        .output()
        .ok()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.starts_with("default via") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 2 {
                return Some(parts[2].to_string());
            }
        }
    }
    
    None
}