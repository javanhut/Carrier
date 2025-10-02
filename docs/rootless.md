# Rootless Container Execution

Carrier supports running containers without root privileges, similar to Podman's rootless mode. This allows regular users to create and manage containers securely without needing sudo or root access.

## How It Works

Carrier implements rootless containers using:

1. **User Namespaces**: Maps the container's root user (UID 0) to the current user on the host
2. **unshare Command**: Creates new namespaces with `--user` and `--map-root-user` flags
3. **Subuid/Subgid Mappings**: Utilizes `/etc/subuid` and `/etc/subgid` for additional UID/GID ranges

## Prerequisites

### 1. Kernel Support
Ensure your kernel supports user namespaces:
```bash
cat /proc/sys/kernel/unprivileged_userns_clone
```
Should return `1`. If not, enable it with:
```bash
sudo sysctl kernel.unprivileged_userns_clone=1
```

### 2. Subuid/Subgid Configuration
Check if your user has subuid/subgid allocations:
```bash
grep $USER /etc/subuid /etc/subgid
```

If not configured, add them (as root):
```bash
echo "$USER:100000:65536" | sudo tee -a /etc/subuid
echo "$USER:100000:65536" | sudo tee -a /etc/subgid
```

### 3. newuidmap/newgidmap Setup (Required for Multi-User Support)
For proper UID/GID mapping that allows containers to use multiple users (like `_apt`, `nobody`, etc.), the `newuidmap` and `newgidmap` binaries must have setuid permissions:

```bash
# Check current permissions
ls -l /usr/bin/newuidmap /usr/bin/newgidmap

# If they don't show 'rws' (setuid), fix them:
sudo chmod u+s /usr/bin/newuidmap /usr/bin/newgidmap

# Verify they're now setuid:
ls -l /usr/bin/newuidmap /usr/bin/newgidmap
# Should show: -rwsr-xr-x
```

**Why is this needed?**
- Without setuid on these binaries, containers can only map a single UID (container root = host user)
- With setuid, runc can map multiple UIDs using your subuid/subgid ranges
- This allows package managers (apt, yum, dnf) and other tools to switch to unprivileged users
- This is a **one-time system configuration**, not a security risk (these binaries are specifically designed to be setuid)

**What happens without it:**
- Container appears to work, but programs trying to switch users (like `apt`) will fail with:
  ```
  E: setgroups 65534 failed - setgroups (1: Operation not permitted)
  E: seteuid 42 failed - seteuid (22: Invalid argument)
  ```

## Running Rootless Containers

### Create and Run
```bash
# Run a container as a regular user (no sudo needed)
carrier run alpine:latest

# Run with a custom command
carrier run alpine:latest echo "Hello from rootless!"

# Run in detached mode
carrier run -d --name my-app nginx:latest

# Run with elevated privileges (may require sudo)
sudo carrier run --elevated ubuntu:latest
```

### Elevated Mode

The `--elevated` flag allows running containers without user namespace restrictions, which is needed for operations like:
- Package management (apt, yum, apk)
- System administration tasks
- Installing software that requires setuid/setgid

**Note:** Elevated mode requires either:
- Running carrier as root (`sudo carrier run --elevated ...`)
- Having appropriate capabilities set on the carrier binary

Example with apt:
```bash
# Start an elevated Ubuntu container
sudo carrier run -d --elevated --name ubuntu-dev ubuntu:latest sleep infinity

# Update packages
sudo carrier sh ubuntu-dev apt update
sudo carrier sh ubuntu-dev apt install -y git vim
```

### Execute Commands
```bash
# Execute commands in running containers
carrier sh container-id whoami  # Returns: root (mapped to your user)

# Open an interactive shell
carrier sh container-id sh

# Force PTY allocation for full terminal support
carrier terminal container-id bash
```

## Key Differences from Root Mode

| Feature | Root Mode | Rootless Mode |
|---------|-----------|---------------|
| **Container Creation** | Uses all namespaces including user | Uses `unshare --user --map-root-user` |
| **Exec Method** | Uses `nsenter` (requires CAP_SYS_ADMIN) | Uses `unshare` with chroot |
| **UID in Container** | Real root (UID 0) | Mapped root (your UID on host) |
| **Storage Location** | `/var/lib/carrier` | `~/.local/share/carrier` |
| **Network** | Full network capabilities | Limited (uses slirp4netns) |

## Storage Drivers

Rootless mode automatically selects the best available storage driver:

1. **OverlayFS (FUSE)**: Preferred when fuse-overlayfs is installed
2. **VFS (Copy)**: Fallback option that copies all layers (slower but always works)

The driver selection is automatic based on what's available and working on your system.

## Limitations

### Network
- Cannot bind to privileged ports (< 1024) without additional configuration
- Uses slirp4netns for network isolation (may have performance impact)

### Devices
- Cannot create device nodes
- Limited access to host devices

### Performance
- VFS storage driver is slower than native overlayfs
- Some operations may have overhead due to user namespace mapping

## Troubleshooting

### Permission Denied Errors
If you encounter "Operation not permitted" errors:

1. Verify user namespace support:
   ```bash
   unshare --user --map-root-user whoami
   ```
   Should return `root`

2. Check subuid/subgid configuration (see Prerequisites)

3. Ensure the storage directory is writable:
   ```bash
   ls -la ~/.local/share/carrier/
   ```

### Storage Driver Issues
If overlay mounting fails:

1. Install fuse-overlayfs:
   ```bash
   # Debian/Ubuntu
   sudo apt-get install fuse-overlayfs

   # Fedora/RHEL
   sudo dnf install fuse-overlayfs

   # Arch
   sudo pacman -S fuse-overlayfs
   ```

2. Force VFS driver if needed:
   ```bash
   carrier --storage-driver vfs run alpine:latest
   ```

### Container Not Starting
Check container logs:
```bash
carrier logs container-name
```

Verify the container process:
```bash
ps aux | grep container-name
```

## Security Considerations

Rootless containers provide better security isolation:

- Container root is not real root on the host
- Compromised container cannot escalate to host root privileges
- Each user's containers are isolated from other users
- No need for sudo or setuid binaries

## Comparison with Podman

Carrier's rootless implementation is inspired by Podman but uses a simpler approach:

| Aspect | Carrier | Podman |
|--------|---------|--------|
| **Runtime** | Direct namespace management | OCI runtime (crun/runc) |
| **User Mapping** | unshare --map-root-user | newuidmap/newgidmap |
| **Exec Method** | unshare + chroot | Runtime exec API |
| **Configuration** | Minimal | Full OCI spec |

## Best Practices

1. **Always run rootless when possible** - Better security isolation
2. **Configure subuid/subgid properly** - Allows full UID range mapping
3. **Use fuse-overlayfs when available** - Better performance than VFS
4. **Monitor resource usage** - User namespaces may have different limits
5. **Test thoroughly** - Some applications may behave differently in user namespaces

## Example Workflows

### Web Application
```bash
# Pull and run a web app
carrier pull node:alpine
carrier run -d --name my-app -p 8080:3000 node:alpine

# Check logs
carrier logs my-app

# Execute commands
carrier sh my-app npm list
```

### Development Environment
```bash
# Run development container
carrier run -it --name dev-env ubuntu:latest bash

# Install tools (as "root" in container)
carrier sh dev-env apt-get update
carrier sh dev-env apt-get install -y vim git

# Stop when done
carrier stop dev-env
```

### Database Container
```bash
# Run PostgreSQL (will use high ports)
carrier run -d --name postgres \
  -e POSTGRES_PASSWORD=secret \
  -p 5432:5432 \
  postgres:alpine

# Connect to database
carrier sh postgres psql -U postgres
```

## Further Reading

- [User Namespaces Documentation](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [unshare(1) Manual](https://man7.org/linux/man-pages/man1/unshare.1.html)
- [Rootless Containers Overview](https://rootlesscontaine.rs/)