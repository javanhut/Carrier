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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<Seccomp>,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Seccomp {
    #[serde(rename = "defaultAction")]
    pub default_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architectures: Option<Vec<String>>,
    pub syscalls: Vec<SeccompSyscall>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SeccompSyscall {
    pub names: Vec<String>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<SeccompArg>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "errnoRet")]
    pub errno_ret: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SeccompArg {
    pub index: u32,
    pub value: u64,
    pub op: String,
}

fn get_default_seccomp() -> Seccomp {
    let blocked_syscalls = vec![
        "acct", "add_key", "bpf", "clock_adjtime", "clock_settime", "clone3",
        "delete_module", "finit_module", "get_kernel_syms", "get_mempolicy",
        "init_module", "kcmp", "kexec_file_load", "kexec_load", "keyctl",
        "lookup_dcookie", "mbind", "move_pages", "name_to_handle_at",
        "nfsservctl", "open_by_handle_at", "perf_event_open", "personality",
        "pivot_root", "process_vm_readv", "process_vm_writev", "ptrace",
        "query_module", "quotactl", "reboot", "request_key", "set_mempolicy",
        "setns", "settimeofday", "stime", "swapon", "swapoff", "sysfs",
        "_sysctl", "unshare", "uselib", "userfaultfd",
        "ustat", "vm86", "vm86old",
    ];

    Seccomp {
        default_action: "SCMP_ACT_ALLOW".to_string(),
        architectures: Some(vec![
            "SCMP_ARCH_X86_64".to_string(),
            "SCMP_ARCH_X86".to_string(),
            "SCMP_ARCH_X32".to_string(),
            "SCMP_ARCH_AARCH64".to_string(),
            "SCMP_ARCH_ARM".to_string(),
        ]),
        syscalls: vec![
            SeccompSyscall {
                names: blocked_syscalls.iter().map(|s| s.to_string()).collect(),
                action: "SCMP_ACT_ERRNO".to_string(),
                args: None,
                errno_ret: Some(1),
            },
        ],
    }
}

fn get_default_seccomp_old_allowlist() -> Seccomp {
    let allowed_syscalls = vec![
        "_llseek", "_newselect", "accept", "accept4", "access", "adjtimex", "alarm",
        "arch_prctl", "bind", "brk", "capget", "capset", "chdir", "chmod", "chown",
        "chown32", "chroot", "clock_adjtime", "clock_adjtime64", "clock_getres",
        "clock_getres_time64", "clock_gettime", "clock_gettime64", "clock_nanosleep",
        "clock_nanosleep_time64", "clone", "clone3", "close", "close_range", "connect",
        "copy_file_range", "creat", "dup", "dup2", "dup3", "epoll_create", "epoll_create1",
        "epoll_ctl", "epoll_pwait", "epoll_pwait2", "epoll_wait", "eventfd", "eventfd2",
        "execve", "execveat", "exit", "exit_group", "faccessat", "faccessat2", "fadvise64",
        "fadvise64_64", "fallocate", "fanotify_init", "fanotify_mark", "fchdir", "fchmod",
        "fchmodat", "fchmodat2", "fchown", "fchown32", "fchownat", "fcntl", "fcntl64",
        "fdatasync", "fgetxattr", "flistxattr", "flock", "fork", "fremovexattr", "fsconfig",
        "fsetxattr", "fsmount", "fsopen", "fspick", "fstat", "fstat64", "fstatat64",
        "fstatfs", "fstatfs64", "fsync", "ftruncate", "ftruncate64", "futex", "futex_time64",
        "get_mempolicy", "get_robust_list", "get_thread_area", "getcpu", "getcwd", "getdents",
        "getdents64", "getegid", "getegid32", "geteuid", "geteuid32", "getgid", "getgid32",
        "getgroups", "getgroups32", "getitimer", "getpeername", "getpgid", "getpgrp",
        "getpid", "getppid", "getpriority", "getrandom", "getresgid", "getresgid32",
        "getresuid", "getresuid32", "getrlimit", "getrusage", "getsid", "getsockname",
        "getsockopt", "gettid", "gettimeofday", "getuid", "getuid32", "getxattr",
        "inotify_add_watch", "inotify_init", "inotify_init1", "inotify_rm_watch",
        "io_cancel", "io_destroy", "io_getevents", "io_setup", "io_submit", "ioctl",
        "ioprio_get", "ioprio_set", "ipc", "keyctl", "kill", "lchown", "lchown32",
        "lgetxattr", "link", "linkat", "listen", "listxattr", "llistxattr", "lremovexattr",
        "lseek", "lsetxattr", "lstat", "lstat64", "madvise", "mbind", "membarrier",
        "memfd_create", "mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock",
        "mlock2", "mlockall", "mmap", "mmap2", "mount", "mprotect", "mq_getsetattr",
        "mq_notify", "mq_open", "mq_timedreceive", "mq_timedreceive_time64", "mq_timedsend",
        "mq_timedsend_time64", "mq_unlink", "mremap", "msgctl", "msgget", "msgrcv",
        "msgsnd", "msync", "munlock", "munlockall", "munmap", "nanosleep", "newfstatat",
        "open", "openat", "openat2", "pause", "pipe", "pipe2", "pivot_root", "poll",
        "ppoll", "ppoll_time64", "prctl", "pread64", "preadv", "preadv2", "prlimit64",
        "pselect6", "pselect6_time64", "ptrace", "pwrite64", "pwritev", "pwritev2",
        "read", "readahead", "readlink", "readlinkat", "readv", "recv", "recvfrom",
        "recvmmsg", "recvmmsg_time64", "recvmsg", "remap_file_pages", "removexattr",
        "rename", "renameat", "renameat2", "restart_syscall", "rmdir", "rseq",
        "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigqueueinfo",
        "rt_sigreturn", "rt_sigsuspend", "rt_sigtimedwait", "rt_sigtimedwait_time64",
        "rt_tgsigqueueinfo", "sched_get_priority_max", "sched_get_priority_min",
        "sched_getaffinity", "sched_getattr", "sched_getparam", "sched_getscheduler",
        "sched_rr_get_interval", "sched_rr_get_interval_time64", "sched_setaffinity",
        "sched_setattr", "sched_setparam", "sched_setscheduler", "sched_yield",
        "seccomp", "select", "semctl", "semget", "semop", "semtimedop", "semtimedop_time64",
        "send", "sendfile", "sendfile64", "sendmmsg", "sendmsg", "sendto", "set_mempolicy",
        "set_robust_list", "set_thread_area", "set_tid_address", "setfsgid", "setfsgid32",
        "setfsuid", "setfsuid32", "setgid", "setgid32", "setgroups", "setgroups32",
        "setitimer", "setns", "setpgid", "setpriority", "setregid", "setregid32",
        "setresgid", "setresgid32", "setresuid", "setresuid32", "setreuid", "setreuid32",
        "setrlimit", "setsid", "setsockopt", "settimeofday", "setuid", "setuid32",
        "setxattr", "shmat", "shmctl", "shmdt", "shmget", "shutdown", "sigaltstack",
        "signal", "signalfd", "signalfd4", "sigprocmask", "sigreturn", "socket",
        "socketcall", "socketpair", "splice", "stat", "stat64", "statfs", "statfs64",
        "statx", "symlink", "symlinkat", "sync", "sync_file_range", "syncfs", "sysinfo",
        "syslog", "tee", "tgkill", "time", "timer_create", "timer_delete",
        "timer_getoverrun", "timer_gettime", "timer_gettime64", "timer_settime",
        "timer_settime64", "timerfd_create", "timerfd_gettime", "timerfd_gettime64",
        "timerfd_settime", "timerfd_settime64", "times", "tkill", "truncate", "truncate64",
        "ugetrlimit", "umask", "umount", "umount2", "uname", "unlink", "unlinkat",
        "unshare", "utime", "utimensat", "utimensat_time64", "utimes", "vfork", "wait4",
        "waitid", "waitpid", "write", "writev",
    ];

    Seccomp {
        default_action: "SCMP_ACT_ERRNO".to_string(),
        architectures: Some(vec![
            "SCMP_ARCH_X86_64".to_string(),
            "SCMP_ARCH_X86".to_string(),
            "SCMP_ARCH_X32".to_string(),
            "SCMP_ARCH_AARCH64".to_string(),
            "SCMP_ARCH_ARM".to_string(),
        ]),
        syscalls: vec![
            SeccompSyscall {
                names: allowed_syscalls.iter().map(|s| s.to_string()).collect(),
                action: "SCMP_ACT_ALLOW".to_string(),
                args: None,
                errno_ret: None,
            },
        ],
    }
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
                seccomp: Some(get_default_seccomp()),
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