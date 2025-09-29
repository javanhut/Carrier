# Container Networking

Carrier provides automatic network configuration for containers, allowing them to access external networks and DNS resolution without manual configuration.

## Overview

Carrier automatically sets up networking for containers using usermode networking helpers:
- **pasta** (preferred) - Modern, high-performance usermode networking
- **slirp4netns** (fallback) - Traditional usermode networking solution

Network setup is automatic and transparent - containers get network access by default unless explicitly disabled.

## Features

- **Automatic Network Setup**: Networking is configured automatically when containers start
- **DNS Resolution**: Containers get proper DNS configuration from the host or use Google DNS (8.8.8.8, 8.8.4.4)
- **Port Mapping**: Support for exposing container ports to the host (coming soon)
- **Rootless Operation**: Full networking support without requiring root privileges
- **Automatic Cleanup**: Network resources are cleaned up when containers stop

## Network Modes

### Rootless Containers (Default)
- Uses a separate network namespace
- Automatic setup with pasta or slirp4netns
- Full network isolation from host
- DNS resolution configured automatically

### Elevated Containers (--elevated)
- Uses host network namespace
- Direct access to host network interfaces
- No additional network setup required
- Same network access as host system

## How It Works

1. **Container Start**: When a container starts, Carrier:
   - Creates a network namespace (for rootless containers)
   - Sets up `/etc/resolv.conf` for DNS
   - Starts pasta or slirp4netns to provide network connectivity
   - Configures network interfaces inside the container

2. **Terminal/Shell Access**: When using `carrier terminal` or `carrier shell`:
   - Checks if network is already configured
   - If not, automatically sets up networking
   - Ensures DNS resolution works properly

3. **Container Stop**: When a container stops, Carrier:
   - Terminates the network helper process
   - Cleans up network namespace
   - Removes temporary network files

## Troubleshooting

### No Network Connectivity

If a container has no network access:

1. **Check Network Helpers**:
   ```bash
   # Check if pasta or slirp4netns is installed
   which pasta slirp4netns
   ```

2. **Install Network Helpers**:
   ```bash
   # For Arch Linux
   sudo pacman -S passt slirp4netns

   # For Ubuntu/Debian
   sudo apt install pasta slirp4netns

   # For Fedora
   sudo dnf install passt slirp4netns
   ```

3. **Verify Container Network**:
   ```bash
   # Check network inside container
   carrier terminal <container> ping 8.8.8.8
   carrier terminal <container> nslookup google.com
   ```

### DNS Resolution Issues

If DNS doesn't work in containers:

1. **Check Host DNS**:
   ```bash
   cat /etc/resolv.conf
   ```

2. **Check Container DNS**:
   ```bash
   carrier terminal <container> cat /etc/resolv.conf
   ```

The container should have valid nameservers. If not, Carrier will use Google DNS as fallback.

### Network Helper Processes

To see running network helpers:
```bash
ps aux | grep -E "(pasta|slirp4netns)" | grep -v grep
```

## Advanced Configuration

### Disable Networking

To run a container without network:
```bash
# Future feature - not yet implemented
carrier run --no-network <image>
```

### Custom DNS Servers

DNS servers are automatically configured from the host system. To use custom DNS servers, modify `/etc/resolv.conf` on the host before starting containers.

### Port Mapping

Port mapping support is planned for future releases:
```bash
# Future feature - not yet implemented
carrier run -p 8080:80 nginx
```

## Technical Details

### Network Stack

Carrier uses usermode networking which provides:
- NAT-based connectivity
- Automatic DHCP-like configuration
- DNS proxy functionality
- TCP/UDP support

### File Locations

- Container DNS config: `<rootfs>/etc/resolv.conf`
- Container hosts file: `<rootfs>/etc/hosts`
- Network PID tracking: `.carrier/containers/<id>/network.pid`

### Process Management

Network helpers run as separate processes:
- Started after container process creation
- Attached to container's network namespace
- Terminated when container stops
- Automatic cleanup on abnormal termination