use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use std::io::{BufRead, BufReader};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OCISpec {
    pub oci_version: String,
    pub process: Process,
    pub root: Root,
    pub hostname: String,
    pub mounts: Vec<Mount>,
    pub linux: Linux,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Process {
    pub terminal: bool,
    pub user: User,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub capabilities: Option<Capabilities>,
    pub rlimits: Vec<Rlimit>,
    #[serde(rename = "noNewPrivileges")]
    pub no_new_privileges: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub bounding: Vec<String>,
    pub effective: Vec<String>,
    pub permitted: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Rlimit {
    #[serde(rename = "type")]
    pub typ: String,
    pub hard: u64,
    pub soft: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Root {
    pub path: String,
    pub readonly: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Mount {
    pub destination: String,
    #[serde(rename = "type")]
    pub typ: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Linux {
    #[serde(rename = "uidMappings")]
    pub uid_mappings: Vec<IDMapping>,
    #[serde(rename = "gidMappings")]
    pub gid_mappings: Vec<IDMapping>,
    pub namespaces: Vec<Namespace>,
    #[serde(rename = "maskedPaths")]
    pub masked_paths: Vec<String>,
    #[serde(rename = "readonlyPaths")]
    pub readonly_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IDMapping {
    #[serde(rename = "containerID")]
    pub container_id: u32,
    #[serde(rename = "hostID")]
    pub host_id: u32,
    pub size: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Namespace {
    #[serde(rename = "type")]
    pub typ: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Resources {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<Memory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<Cpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids: Option<Pids>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Memory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Cpu {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pids {
    pub limit: i64,
}

fn get_subid_range(username: &str, subid_file: &str) -> Result<(u32, u32), String> {
    let file = fs::File::open(subid_file)
        .map_err(|e| format!("Failed to open {}: {}", subid_file, e))?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 3 && parts[0] == username {
                let start = parts[1].parse::<u32>()
                    .map_err(|e| format!("Invalid start ID: {}", e))?;
                let count = parts[2].parse::<u32>()
                    .map_err(|e| format!("Invalid count: {}", e))?;
                return Ok((start, count));
            }
        }
    }
    
    Err(format!("No entry found for user {} in {}", username, subid_file))
}

fn get_current_username() -> Result<String, String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .map_err(|_| "Cannot determine current username".to_string())
}

impl OCISpec {
    fn get_uid_mappings(uid: u32) -> Vec<IDMapping> {
        let username = match get_current_username() {
            Ok(u) => u,
            Err(_) => {
                // Fallback to single mapping if we can't get username
                return vec![IDMapping {
                    container_id: 0,
                    host_id: uid,
                    size: 1,
                }];
            }
        };

        match get_subid_range(&username, "/etc/subuid") {
            Ok((start, count)) => {
                vec![
                    // Map container root (0) to host user
                    IDMapping {
                        container_id: 0,
                        host_id: uid,
                        size: 1,
                    },
                    // Map container users 1+ to subordinate UID range
                    IDMapping {
                        container_id: 1,
                        host_id: start,
                        size: count,
                    },
                ]
            }
            Err(_) => {
                // Fallback to single mapping if subuid not configured
                vec![IDMapping {
                    container_id: 0,
                    host_id: uid,
                    size: 1,
                }]
            }
        }
    }

    fn get_gid_mappings(gid: u32) -> Vec<IDMapping> {
        let username = match get_current_username() {
            Ok(u) => u,
            Err(_) => {
                // Fallback to single mapping if we can't get username
                return vec![IDMapping {
                    container_id: 0,
                    host_id: gid,
                    size: 1,
                }];
            }
        };

        match get_subid_range(&username, "/etc/subgid") {
            Ok((start, count)) => {
                vec![
                    // Map container root group (0) to host user group
                    IDMapping {
                        container_id: 0,
                        host_id: gid,
                        size: 1,
                    },
                    // Map container groups 1+ to subordinate GID range
                    IDMapping {
                        container_id: 1,
                        host_id: start,
                        size: count,
                    },
                ]
            }
            Err(_) => {
                // Fallback to single mapping if subgid not configured
                vec![IDMapping {
                    container_id: 0,
                    host_id: gid,
                    size: 1,
                }]
            }
        }
    }

    pub fn new_rootless(
        container_id: &str,
        rootfs: PathBuf,
        command: Vec<String>,
        env: Vec<String>,
        working_dir: String,
        terminal: bool,
    ) -> Self {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();

        OCISpec {
            oci_version: "1.2.1".to_string(),
            process: Process {
                terminal,
                user: User { uid: 0, gid: 0 },
                args: command,
                env,
                cwd: working_dir,
                capabilities: Some(Capabilities {
                    bounding: vec![
                        "CAP_AUDIT_WRITE".to_string(),
                        "CAP_KILL".to_string(),
                        "CAP_NET_BIND_SERVICE".to_string(),
                    ],
                    effective: vec![
                        "CAP_AUDIT_WRITE".to_string(),
                        "CAP_KILL".to_string(),
                        "CAP_NET_BIND_SERVICE".to_string(),
                    ],
                    permitted: vec![
                        "CAP_AUDIT_WRITE".to_string(),
                        "CAP_KILL".to_string(),
                        "CAP_NET_BIND_SERVICE".to_string(),
                    ],
                }),
                rlimits: vec![Rlimit {
                    typ: "RLIMIT_NOFILE".to_string(),
                    hard: 1024,
                    soft: 1024,
                }],
                no_new_privileges: true,
            },
            root: Root {
                path: rootfs.to_string_lossy().to_string(),
                readonly: false,
            },
            hostname: format!("carrier-{}", &container_id[..container_id.len().min(8)]),
            mounts: vec![
                Mount {
                    destination: "/proc".to_string(),
                    typ: "proc".to_string(),
                    source: "proc".to_string(),
                    options: None,
                },
                Mount {
                    destination: "/dev".to_string(),
                    typ: "tmpfs".to_string(),
                    source: "tmpfs".to_string(),
                    options: Some(vec![
                        "nosuid".to_string(),
                        "strictatime".to_string(),
                        "mode=755".to_string(),
                        "size=65536k".to_string(),
                    ]),
                },
                Mount {
                    destination: "/dev/pts".to_string(),
                    typ: "devpts".to_string(),
                    source: "devpts".to_string(),
                    options: Some(vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "newinstance".to_string(),
                        "ptmxmode=0666".to_string(),
                        "mode=0620".to_string(),
                    ]),
                },
                Mount {
                    destination: "/dev/shm".to_string(),
                    typ: "tmpfs".to_string(),
                    source: "shm".to_string(),
                    options: Some(vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                        "mode=1777".to_string(),
                        "size=65536k".to_string(),
                    ]),
                },
                Mount {
                    destination: "/dev/mqueue".to_string(),
                    typ: "mqueue".to_string(),
                    source: "mqueue".to_string(),
                    options: Some(vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                    ]),
                },
                Mount {
                    destination: "/sys".to_string(),
                    typ: "none".to_string(),
                    source: "/sys".to_string(),
                    options: Some(vec![
                        "rbind".to_string(),
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                        "ro".to_string(),
                    ]),
                },
                Mount {
                    destination: "/sys/fs/cgroup".to_string(),
                    typ: "cgroup".to_string(),
                    source: "cgroup".to_string(),
                    options: Some(vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                        "relatime".to_string(),
                        "ro".to_string(),
                    ]),
                },
            ],
            linux: Linux {
                uid_mappings: Self::get_uid_mappings(uid),
                gid_mappings: Self::get_gid_mappings(gid),
                namespaces: vec![
                    Namespace {
                        typ: "pid".to_string(),
                    },
                    Namespace {
                        typ: "ipc".to_string(),
                    },
                    Namespace {
                        typ: "uts".to_string(),
                    },
                    Namespace {
                        typ: "mount".to_string(),
                    },
                    Namespace {
                        typ: "cgroup".to_string(),
                    },
                    Namespace {
                        typ: "user".to_string(),
                    },
                ],
                masked_paths: vec![
                    "/proc/acpi".to_string(),
                    "/proc/asound".to_string(),
                    "/proc/kcore".to_string(),
                    "/proc/keys".to_string(),
                    "/proc/latency_stats".to_string(),
                    "/proc/timer_list".to_string(),
                    "/proc/timer_stats".to_string(),
                    "/proc/sched_debug".to_string(),
                    "/sys/firmware".to_string(),
                    "/proc/scsi".to_string(),
                ],
                readonly_paths: vec![
                    "/proc/bus".to_string(),
                    "/proc/fs".to_string(),
                    "/proc/irq".to_string(),
                    "/proc/sys".to_string(),
                    "/proc/sysrq-trigger".to_string(),
                ],
                resources: None,
            },
        }
    }

    pub fn add_network_namespace(&mut self) {
        if !self.linux.namespaces.iter().any(|ns| ns.typ == "network") {
            self.linux.namespaces.push(Namespace {
                typ: "network".to_string(),
            });
        }
    }

    pub fn to_json(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn write_to_file(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }
}