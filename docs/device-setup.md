# Device Setup in Carrier Containers

## Overview
This document explains how Carrier sets up device nodes in containers, particularly for elevated (privileged) containers that need to run package management tools like `apt`.

## Problem Statement
When running containers with the `--elevated` flag, commands like `apt update` would fail with errors related to `/dev/null` permissions:
```
/usr/bin/apt-key: 95: cannot create /dev/null: Permission denied
```

This occurred because the container's `/dev` filesystem was not properly initialized with the necessary device nodes.

## Solution
Carrier now properly sets up the `/dev` filesystem for elevated containers by:

### 1. Creating a tmpfs mount for /dev
```bash
mount -t tmpfs -o mode=755,size=65536k tmpfs /dev
```

### 2. Creating essential device nodes
- `/dev/null` (character device, major 1, minor 3)
- `/dev/zero` (character device, major 1, minor 5)
- `/dev/random` (character device, major 1, minor 8)
- `/dev/urandom` (character device, major 1, minor 9)
- `/dev/tty` (character device, major 5, minor 0)
- `/dev/console` (character device, major 5, minor 1)

### 3. Setting up pseudo-terminals
```bash
mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts /dev/pts
ln -sf /dev/pts/ptmx /dev/ptmx
```

### 4. Creating file descriptor symlinks
- `/dev/fd` → `/proc/self/fd`
- `/dev/stdin` → `/proc/self/fd/0`
- `/dev/stdout` → `/proc/self/fd/1`
- `/dev/stderr` → `/proc/self/fd/2`

## Implementation Details

### Elevated Container Creation
When a container is created with the `--elevated` flag, Carrier:
1. Uses `sudo unshare` to create new namespaces (mount, pid)
2. Sets up the `/dev` filesystem before chrooting
3. Copies `/etc/resolv.conf` for DNS resolution
4. Exports necessary environment variables
5. Performs chroot and executes the container command

### Container Terminal Access
When accessing an elevated container via `carrier terminal`:
1. Checks if `/dev/null` exists and is a character device
2. If not properly set up, runs the device setup script
3. Enters the container namespace and executes the requested command

## Usage Examples

### Create an elevated container
```bash
sudo carrier run -d --elevated --name mycontainer ubuntu
```

### Run apt update in the container
```bash
sudo carrier terminal mycontainer apt update
```

### Install packages
```bash
sudo carrier terminal mycontainer apt install -y git vim
```

## Rootless vs Elevated Containers

### Rootless Containers (default)
- Use user namespaces for isolation
- Limited device access
- Cannot run privileged operations
- Suitable for most applications

### Elevated Containers (--elevated flag)
- Run with sudo privileges
- Full device access
- Can perform system operations
- Required for package management
- Use host networking by default

## Security Considerations
Elevated containers have more privileges and should only be used when necessary. For most use cases, rootless containers provide sufficient functionality with better security isolation.

## Troubleshooting

### Permission Denied on /dev/null
If you encounter this error, ensure:
1. The container was created with `--elevated` flag
2. You're running carrier commands with `sudo`
3. The carrier binary has proper permissions

### apt-key warnings about GPG
This is expected in containers without gpg installed. You can either:
1. Install gpg: `carrier terminal <container> apt install -y gnupg`
2. Use `--allow-unauthenticated` flag for apt (not recommended for production)

## Recent Improvements

### Automatic Device Setup for Rootless Containers
As of the latest version, Carrier now automatically sets up `/dev` for rootless containers as well:
- Device nodes are created automatically when running containers
- The `terminal` command verifies and fixes device setup before executing commands
- Both elevated and rootless containers now have proper `/dev` initialization

### Enhanced APT Support
- Automatic detection of missing GPG tools
- Configuration of APT to work without GPG verification when tools are unavailable
- Proper `/dev/null` setup ensures APT commands work correctly

## Technical References
- Linux device nodes: `man 4 null`, `man 4 zero`, `man 4 random`
- Namespace documentation: `man 7 namespaces`
- devpts filesystem: `man 5 devpts`