# Stop Command

The `stop` command is used to stop running containers in Carrier.

## Usage

```bash
carrier stop [OPTIONS] <CONTAINER>
```

## Arguments

- `<CONTAINER>` - Container ID or name to stop. Supports partial container ID matching (minimum 1 character).

## Options

- `-f, --force` - Force stop (kill) the container immediately without graceful shutdown
- `-t, --timeout <SECONDS>` - Timeout in seconds before forcing stop (default: 10)

## Description

The stop command sends termination signals to running containers:

1. **Graceful Shutdown (default)**: Sends SIGTERM to the container process, allowing it to clean up and exit gracefully
2. **Forced Shutdown**: If the container doesn't stop within the timeout period, or if `--force` is used, sends SIGKILL to immediately terminate the process

## Examples

### Stop a container gracefully
```bash
carrier stop abc123def456
```

### Stop with partial container ID
```bash
carrier stop abc1
```

### Force stop a container immediately
```bash
carrier stop --force abc123def456
```

### Stop with custom timeout
```bash
carrier stop --timeout 30 abc123def456
```

## Container State

After stopping:
- Container status changes to "exited"
- Container filesystem is unmounted
- Process ID file is removed
- Container metadata is updated with stop time and exit code

## Exit Codes

- Exit code 0: Container stopped gracefully
- Exit code 137: Container was forcefully killed (SIGKILL)

## Related Commands

- `carrier list` - List running and stopped containers
- `carrier remove` - Remove stopped containers
- `carrier run` - Run a new container