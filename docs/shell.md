# Shell/Exec Command

The `shell` (or `sh`/`exec`) command allows you to execute commands in running containers.

## Usage

```bash
carrier shell <CONTAINER> [COMMAND...]
carrier sh <CONTAINER> [COMMAND...]     # Alias
carrier exec <CONTAINER> [COMMAND...]   # Alias
```

## Arguments

- `<CONTAINER>` - Container ID or name (supports partial matching)
- `[COMMAND...]` - Optional command to execute (defaults to /bin/sh)

## Description

This command uses `nsenter` to enter the namespaces of a running container and execute commands within its environment. It provides access to:
- Mount namespace (container filesystem)
- UTS namespace (hostname)
- IPC namespace (inter-process communication)
- Network namespace (container network)
- PID namespace (process isolation)

## Examples

### Start an interactive shell
```bash
# Open a shell in a running container
carrier sh abc123def456

# Using partial container ID
carrier sh abc1
```

### Execute a specific command
```bash
# Run a single command
carrier sh abc123 echo "Hello from container"

# Run multiple commands
carrier sh abc123 ls -la /

# Check processes
carrier sh abc123 ps aux

# View environment variables
carrier sh abc123 env
```

### Interactive commands
```bash
# Start bash if available
carrier sh abc123 /bin/bash

# Start python interpreter
carrier sh abc123 python3

# Edit a file
carrier sh abc123 vi /etc/hosts
```

## Requirements

- Container must be running
- `nsenter` command must be installed (part of util-linux package)
- May require elevated privileges depending on system configuration

## Error Handling

The command will fail if:
- Container is not found
- Container is not running (status must be "running")
- nsenter is not installed
- Insufficient permissions to access container namespaces
- Command doesn't exist in container

## Exit Codes

- 0: Command executed successfully
- Non-zero: Command failed or exited with error

## Related Commands

- `carrier run --detach` - Run container in background
- `carrier stop` - Stop a running container
- `carrier ls -c` - List containers to see running ones