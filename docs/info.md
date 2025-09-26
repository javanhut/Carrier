# Info/Inspect Command

The `info` (or `inspect`) command displays detailed information about a container or image.

## Usage

```bash
carrier info <CONTAINER|IMAGE>
carrier inspect <CONTAINER|IMAGE>  # Alias
```

## Arguments

- `<CONTAINER|IMAGE>` - Container ID/name or Image ID/name (supports partial matching)

## Description

Provides comprehensive information about containers or images.

### For Containers:
Displays information including:
- Full and short container ID
- Container name
- Image reference
- Current status with visual indicator
- Creation time and uptime
- Exit code (if exited)
- Command being executed
- Root filesystem location
- Process ID (if running)
- Memory usage (if running)
- Environment variables (first 5)
- Available commands based on container state

### For Images:
Displays information including:
- Repository name and tag
- Image ID (short and full)
- Creation date
- Total size and layer count
- Architecture and OS
- Available commands for running the image

## Output Format

The command displays information in a formatted table with:
- 🟢 Green indicator for running containers
- 🔴 Red indicator for stopped/exited containers
- ⚫ Black indicator for unknown status

## Examples

### Get info on a running container
```bash
carrier info abc123def456
```

### Using partial container ID
```bash
carrier info abc1
```

### Get info on an image
```bash
carrier info nginx:latest
```

### Get info by image ID
```bash
carrier info 621a1d661664
```

### Sample Output
```
╔═══════════════════════════════════════════════════════════════════╗
║ CONTAINER INFORMATION                                            ║
╠═══════════════════════════════════════════════════════════════════╣
║ ID:        abc123def456                                           ║
║ Short ID:  abc123def456                                           ║
║ Name:      car_abc123                                             ║
║ Image:     nginx:latest                                           ║
║ Status:    🟢 running                                              ║
║ Created:   2025-09-26T20:00:00 (5 minutes ago)                   ║
║ Uptime:    5 minutes, 23 seconds                                  ║
║ Command:   nginx -g daemon off;                                   ║
║ Rootfs:    ...containers/abc123def456/merged                      ║
║ PID:       12345                                                  ║
║ Memory:    VSZ: 123 MB, RSS: 45 MB                               ║
╠═══════════════════════════════════════════════════════════════════╣
║ AVAILABLE COMMANDS                                               ║
╠═══════════════════════════════════════════════════════════════════╣
║ • carrier sh abc123def456                                          ║
║ • carrier stop abc123def456                                        ║
║ • carrier logs abc123def456 (if implemented)                      ║
╚═══════════════════════════════════════════════════════════════════╝
```

## Information Displayed

### Basic Information
- **ID**: Full container identifier
- **Short ID**: First 12 characters of container ID
- **Name**: Container name (auto-generated or user-specified)
- **Image**: Image reference used to create container
- **Status**: Current container state

### Timing Information
- **Created**: Container creation timestamp with relative time
- **Uptime**: How long the container has been running (if running)
- **Stopped**: When the container was stopped (if stopped)

### Runtime Information
- **Command**: Command being executed in the container
- **Rootfs**: Container's root filesystem path
- **PID**: Process ID of the container (if running)
- **Memory**: Virtual and Resident Set Size (if available)
- **Exit Code**: Container exit code (if exited)

### Environment
- Shows first 5 environment variables
- Indicates total count if more than 5

### Available Commands
- Context-sensitive commands based on container state
- Shows relevant management commands for the container

## Use Cases

1. **Debugging**: Check why a container exited
2. **Monitoring**: View container uptime and resource usage
3. **Management**: Quick access to container details
4. **Troubleshooting**: Verify container configuration

## Status Indicators

- **running** / **Up**: Container is currently running
- **exited**: Container has stopped
- **created**: Container created but never started
- **unknown**: Status cannot be determined

## Related Commands

- `carrier ls -c` - List all containers with brief info
- `carrier sh` - Execute commands in running container
- `carrier stop` - Stop a running container
- `carrier rm` - Remove a stopped container