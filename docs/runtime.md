# Carrier Runtime Architecture

## Overview

Carrier uses **runc** as its OCI-compliant container runtime for managing container execution and permissions. The runtime is designed specifically for rootless operation with comprehensive security features and automatic dependency management.

## Key Features

### 1. **Rootless by Design**
- Full user namespace support with automatic UID/GID mapping
- No root privileges required for container execution
- Uses `newuidmap`/`newgidmap` for secure ID mapping
- Supports subordinate UID/GID ranges from `/etc/subuid` and `/etc/subgid`

### 2. **Comprehensive Security**
- **Namespace Isolation**: PID, Network, IPC, UTS, Mount, User, and Cgroup namespaces
- **Capability Dropping**: Removes dangerous capabilities by default
- **Seccomp Filtering**: System call filtering (when available)
- **No-New-Privileges**: Prevents privilege escalation
- **Read-only Root Filesystem**: Optional immutable system directories

### 3. **Resource Management**
- **Cgroups v2**: Modern resource control and accounting
- **Memory Limits**: Configurable memory and swap limits
- **CPU Quotas**: CPU time allocation and weights
- **PID Limits**: Maximum process count restrictions
- **IO Throttling**: Disk I/O bandwidth control

### 4. **Networking**
- **Slirp4netns Integration**: Usermode networking without root
- **Port Forwarding**: Host-to-container port mapping
- **DNS Configuration**: Automatic `/etc/resolv.conf` setup
- **Network Isolation**: Full network namespace separation

### 5. **Performance Optimizations**
- **Direct Syscalls**: Uses nix crate for minimal overhead
- **No Daemon**: Direct process spawning without intermediate layers
- **Lazy Initialization**: Components initialized only when needed
- **Efficient Overlays**: Optimized overlay filesystem setup

## Architecture

### Component Structure

```
src/runtime/
├── namespaces.rs    # Namespace isolation and management
├── cgroups.rs       # Cgroups v2 resource control
├── security.rs      # Security policies and capabilities
├── process.rs       # Process lifecycle management
├── network.rs       # Container networking
└── container.rs     # Main container runtime
```

### Process Model

The runtime uses a **two-process architecture**:

1. **Parent Process** (Outside Container)
   - Sets up namespaces
   - Configures cgroups
   - Manages networking
   - Monitors container

2. **Child Process** (Inside Container)
   - Enters all namespaces
   - Applies security policies
   - Executes container entrypoint
   - Becomes PID 1 in container

## Security Layers

### 1. Namespace Isolation
- **PID Namespace**: Process isolation, container has its own PID 1
- **Mount Namespace**: Filesystem isolation with pivot_root
- **Network Namespace**: Complete network stack isolation
- **IPC Namespace**: Inter-process communication isolation
- **UTS Namespace**: Hostname and domain name isolation
- **User Namespace**: UID/GID mapping for rootless operation
- **Cgroup Namespace**: Cgroup hierarchy isolation

### 2. Capability Management
Default dropped capabilities:
- `CAP_SYS_ADMIN` - System administration
- `CAP_SYS_MODULE` - Kernel module loading
- `CAP_SYS_RAWIO` - Raw I/O operations
- `CAP_SYS_PTRACE` - Process tracing
- `CAP_NET_ADMIN` - Network administration
- `CAP_MKNOD` - Special file creation

### 3. Seccomp Filtering
- System call filtering when available
- Default secure profile
- Custom profile support

### 4. Resource Limits
Configurable via Cgroups v2:
- Memory usage limits
- CPU time quotas
- Process count limits
- I/O bandwidth throttling

## Configuration

### Container Configuration Structure

```rust
ContainerConfig {
    id: String,                    // Unique container ID
    name: Option<String>,          // Optional container name
    image: String,                 // Image reference
    rootfs: PathBuf,              // Root filesystem path
    command: Vec<String>,         // Command to execute
    env: Vec<(String, String)>,   // Environment variables
    working_dir: String,          // Working directory
    hostname: Option<String>,     // Container hostname
    user: Option<String>,         // User to run as
    readonly_rootfs: bool,        // Make rootfs read-only
    network_config: NetworkConfig,
    cgroup_config: CgroupConfig,
    security_config: SecurityConfig,
}
```

### Network Configuration

```rust
NetworkConfig {
    enable_network: bool,         // Enable networking
    network_mode: NetworkMode,    // None, Host, Slirp4netns
    port_mappings: Vec<PortMapping>, // Port forwards
    dns_servers: Vec<String>,     // DNS servers
    hostname: String,             // Network hostname
}
```

### Resource Limits (Cgroups)

```rust
CgroupConfig {
    memory_limit: Option<u64>,      // Bytes (None = unlimited)
    memory_swap_limit: Option<u64>, // Bytes (None = unlimited)
    cpu_quota: Option<u64>,         // Microseconds (None = unlimited)
    cpu_period: Option<u64>,        // Microseconds (None = unlimited)
    cpu_weight: Option<u32>,        // 1-10000 (None = default weight)
    pids_limit: Option<u64>,        // Max processes (None = unlimited)
    io_weight: Option<u32>,         // 1-10000 (None = default weight)
}
```

**Default Configuration**: By default, all resource limits are set to `None` (unlimited). This prevents memory allocation issues with fork operations in user namespaces. Resource limits can be configured when needed but are disabled by default for maximum compatibility.

## Usage

### Container Execution Modes

#### Interactive Mode (Default)
When you run `carrier run <image>`:
- Container runs in foreground
- Inherits terminal stdin/stdout/stderr
- Suitable for shells and interactive programs
- Process waits for container to exit
- Automatically detected for bash/sh commands

#### Detached Mode
When you run `carrier run -d <image>`:
- Container runs in background
- I/O redirected to null (future: logs)
- Returns immediately with container ID
- Container continues after terminal closes
- Use `carrier sh` to interact later

#### Command Execution in Running Containers
When you run `carrier sh <container-id> [command]`:
- Uses `nsenter` to join container namespaces
- Executes command in container context
- Supports interactive and non-interactive modes
- Default command is `/bin/sh` if not specified
- Requires container to be in "running" state

### Running a Container

When you run `carrier run <image>`, the runtime:

1. **Prepares Filesystem**
   - Creates overlay filesystem with layers
   - Sets up container-specific upper/work directories

2. **Spawns Process**
   - Forks child process for container
   - Parent stays outside for monitoring (or detaches if `-d`)

3. **Configures Isolation**
   - Child enters new namespaces
   - Sets up user namespace mappings
   - Applies cgroup limits

4. **Establishes Security**
   - Drops capabilities
   - Sets no-new-privileges flag
   - Applies seccomp filters (if available)

5. **Sets Up Environment**
   - Pivot root to container filesystem
   - Mount essential filesystems (/proc, /sys, /dev)
   - Configure networking with slirp4netns

6. **Executes Command**
   - Changes to working directory
   - Sets environment variables
   - Executes container entrypoint
   - Saves PID for management

### Container Lifecycle Management

```bash
# Start container (interactive)
carrier run alpine

# Start container (detached)
carrier run -d nginx

# List running containers
carrier ls -c

# Execute command in running container
carrier sh abc123 echo "Hello"

# Open shell in running container  
carrier sh abc123

# Stop container gracefully
carrier stop abc123

# Force stop container
carrier stop --force abc123

# Remove stopped container
carrier rm abc123

# Remove all stopped containers
carrier rm -c
```

## Runtime Components

### runc Integration
Carrier uses **runc** for container lifecycle management:
- **Container Creation**: OCI-compliant container initialization via `runc create`
- **Container Execution**: Process execution with `runc exec`
- **State Management**: Container state tracking via `runc state`
- **Security**: Full namespace isolation and capability management
- **Permissions**: User namespace mapping for rootless operation

### Storage Driver Integration
The runtime works seamlessly with multiple storage drivers:
- **FUSE-OverlayFS**: Default choice with automatic installation
- **Native Overlay**: Fallback for kernel-supported overlay
- **VFS**: Final fallback ensuring compatibility everywhere

## Advantages Over Traditional Setups

### vs Docker
- **Fully Rootless**: No root daemon required
- **No Daemon**: Direct execution without background service
- **Lighter Weight**: Minimal resource overhead
- **Better Security**: Rootless by default with strong isolation
- **Automatic Setup**: Dependencies installed and configured automatically

## Requirements

### System Requirements
- Linux kernel 4.18+ (5.14+ recommended)
- User namespaces enabled
- Cgroups v2 mounted at `/sys/fs/cgroup`
- `runc` installed (automatically checked)
- `newuidmap` and `newgidmap` installed (uidmap package)
- `slirp4netns` for networking
- `fuse-overlayfs` (automatically installed if possible)
- `fuse3` packages (automatically installed if possible)

### Kernel Configuration
Required kernel features:
- `CONFIG_USER_NS=y` - User namespaces
- `CONFIG_PID_NS=y` - PID namespaces
- `CONFIG_NET_NS=y` - Network namespaces
- `CONFIG_CGROUPS=y` - Control groups
- `CONFIG_CGROUP_PIDS=y` - PID controller
- `CONFIG_MEMCG=y` - Memory controller

## Limitations

Current limitations of the runtime:
1. Simplified seccomp implementation (full libseccomp integration pending)
2. Basic networking (advanced features like bridge networking require root)
3. No live migration support
4. No checkpoint/restore functionality

## Future Enhancements

Planned improvements:
- Full libseccomp integration for advanced syscall filtering
- OCI runtime specification compliance
- Bridge networking support (with appropriate permissions)
- GPU device passthrough
- Enhanced statistics and monitoring
- Container checkpoint/restore (CRIU integration)
- Rootless overlay mounts with native kernel support

## Troubleshooting

### Common Issues

**"User namespaces not available"**
- Check `/proc/sys/user/max_user_namespaces` > 0
- Ensure kernel has `CONFIG_USER_NS=y`

**"slirp4netns not found"**
- Install slirp4netns: `sudo apt install slirp4netns` or `sudo dnf install slirp4netns`

**"Cannot create cgroup"**
- Ensure cgroups v2 is mounted: `mount | grep cgroup2`
- Check user has cgroup delegation via systemd

**"Operation not permitted" errors**
- Verify subuid/subgid configuration for your user
- Ensure newuidmap/newgidmap have proper setuid permissions

**"fork: cannot allocate memory"**
- This typically occurs when memory cgroup limits are too restrictive
- Default configuration now uses unlimited memory (no cgroups limits)
- If you've set custom memory limits, increase them or remove them
- Check system overcommit setting: `cat /proc/sys/vm/overcommit_memory`

## Technical Details

### Container Lifecycle

1. **Creation**: Container configuration validated, ID generated
2. **Start**: Process forked, namespaces created, resources allocated
3. **Running**: Container executing with monitoring
4. **Stop**: Graceful termination with SIGTERM, then SIGKILL
5. **Cleanup**: Resources released, cgroups removed, network cleaned up

### Signal Handling

- **SIGTERM**: Graceful shutdown request
- **SIGKILL**: Force termination
- **SIGCHLD**: Child process status change

### File Descriptors

The runtime carefully manages file descriptors to prevent leaks:
- Uses `O_CLOEXEC` where possible
- Explicitly closes unnecessary FDs after fork
- Minimal FD usage in container process