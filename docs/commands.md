# Carrier Commands

## Overview
Carrier provides comprehensive container management with commands for pulling images, running containers (interactive or detached), executing commands in running containers, and managing container lifecycle. All commands support pulling images from various container registries including Docker Hub, Quay.io, GitHub Container Registry, and more.

Carrier is optimized for performance with sub-100ms container startup times. See [performance.md](performance.md) for detailed benchmarks and optimization tips.

## Quick Start
```bash
# Run a container interactively
carrier run alpine

# Run in background (detached)
carrier run -d nginx

# Run with custom name
carrier run --name my-app alpine

# Execute commands in running container
carrier sh <container-id>

# Stop and remove containers
carrier stop <container-id>
carrier rm -c  # Remove all stopped containers

# Force specific storage driver (global flag, before subcommand)
carrier --storage-driver overlay-fuse run alpine
carrier --storage-driver vfs run debian
```

## Commands

### pull
Pull an image from a container registry without running it.

**Usage:**
```bash
carrier pull <image>
```

**Examples:**
```bash
# Pull latest alpine image
carrier pull alpine

# Pull specific version
carrier pull alpine:3.18

# Pull from specific registry
carrier pull quay.io/prometheus/prometheus:latest
```

**Features:**
- Automatic registry detection and authentication
- Progress bars for layer downloads
- Support for multi-architecture manifest lists
- Automatic platform selection (defaults to linux/amd64)
- Layer caching and deduplication
- Rootless storage in user home directory

### run
Run a container from a local or remote image.

**Usage:**
```bash
carrier [GLOBAL-OPTIONS] run [OPTIONS] <image|image-id> [COMMAND...]
```

**Global Options:**
- `--storage-driver <DRIVER>`: Force storage driver: overlay-fuse, overlay-native, or vfs

**Run Options:**
- `-d, --detach`: Run container in detached mode (background)
- `--name <NAME>`: Assign a custom name to the container
- `--elevated`: Run with elevated privileges (no user namespace, may require sudo)
- `--platform <PLATFORM>`: Target platform (e.g., linux/amd64, linux/arm64)
- `--verbose`: Show verbose output (download progress, layer extraction, container setup details)
- `-v, --volume <HOST:CONTAINER[:ro]>`: Bind mount a volume from host to container (can be used multiple times)
- `-p, --publish <HOST_PORT:CONTAINER_PORT>`: Publish a container port to the host (can be used multiple times)
- `-e, --env <KEY=VALUE>`: Set environment variable (can be used multiple times)

**Examples:**
```bash
# Run latest alpine image interactively
carrier run alpine

# Run by image ID (local image)
carrier run 621a1d661664

# Run specific version
carrier run nginx:1.24

# Run from specific registry
carrier run ghcr.io/my-org/my-app:latest

# Run in detached mode (background)
carrier run -d nginx
carrier run --detach redis:latest

# Run with custom name
carrier run --name my-web-server nginx

# Run with volume mount
carrier run -v /host/data:/container/data alpine
carrier run -v ./config:/etc/app:ro nginx  # Read-only mount
carrier run -v /logs:/var/log -v /data:/data alpine  # Multiple volumes

# Run with port mapping
carrier run -p 8080:80 nginx  # Map host port 8080 to container port 80
carrier run -p 3000:3000 -p 5432:5432 myapp  # Multiple port mappings

# Run with environment variables
carrier run -e DEBUG=1 alpine
carrier run -e DB_HOST=localhost -e DB_PORT=5432 myapp

# Combine options for a complete setup
carrier run -d \
  --name my-webapp \
  -p 8080:80 \
  -p 443:443 \
  -v ./html:/usr/share/nginx/html:ro \
  -v ./nginx.conf:/etc/nginx/nginx.conf:ro \
  -e NGINX_HOST=example.com \
  nginx:latest

# Run with elevated privileges (requires sudo)
sudo carrier run --elevated ubuntu
sudo carrier run -d --elevated --name ubuntu-dev ubuntu sleep infinity
carrier run --name dev-db -d postgres:latest

# Force specific storage driver (global flag)
carrier --storage-driver overlay-fuse run alpine
carrier --storage-driver vfs run debian
carrier --storage-driver overlay-native run ubuntu:22.04

# Run with custom command
carrier run alpine echo "Hello World"

# Run with verbose output (shows download progress, layer extraction)
carrier run --verbose alpine cat /etc/os-release

# Quiet run - only shows command output (default behavior)
carrier run alpine cat /etc/os-release
```

**Features:**
- Checks for local images first (by name or ID)
- Automatically pulls the image if not already downloaded
- Supports running by image ID for local images
- Creates overlay filesystem with copy-on-write
- Sets up container environment with unique ID or custom name
- Custom container naming with `--name` option
- Supports both native overlay and fuse-overlayfs for rootless operation
- Detached mode for background execution
- Interactive mode for shells (bash, sh)
- Volume mounts for sharing data between host and container
- Port mapping for exposing container services
- Environment variable injection for runtime configuration

**Detached Mode:**
When running with `-d` or `--detach`:
- Container runs in the background
- Returns immediately with container ID
- Output is captured to log files for later viewing
- Container continues running after terminal closes
- Use `carrier logs` to view captured output
- Use `carrier stop` to stop the container
- Use `carrier sh` to execute commands in the container

### list
List downloaded images and containers with a clean, box-style output format with dynamic width adjustment.

**Usage:**
```bash
carrier list [OPTIONS]
carrier ls [OPTIONS]      # Alias
carrier ps [OPTIONS]      # Alias
```

**Options:**
- `-a, --all`: Show all containers (default shows only running)
- `-i, --images`: Show only images
- `-c, --containers`: Show only containers

**Examples:**
```bash
# Show all images and running containers
carrier ls

# Show all containers including stopped ones
carrier ls -a

# Show only images (short flag)
carrier ls -i

# Show only containers (short flag)
carrier ls -c

# Show all containers
carrier ls -c -a
```

**Output Format:**

The output uses Unicode box-drawing characters to create clean, visually separated tables. Column widths are dynamically calculated based on content, with automatic truncation (indicated by "...") when content exceeds maximum column width.

Images table includes:
- **REPOSITORY**: Image repository name (max 40 chars)
- **TAG**: Image tag (max 12 chars)
- **IMAGE ID**: Shortened digest identifier (max 12 chars)
- **CREATED**: Relative time since pulled (e.g., "2 hours ago")
- **SIZE**: Image size when available

Containers table includes:
- **ID**: Container identifier (max 12 chars)
- **IMAGE**: Full image name (max 35 chars)
- **COMMAND**: Container command (max 20 chars)
- **CREATED**: Relative time since creation
- **STATUS**: Current status (Created, Up, Exited)
- **NAMES**: Container name or auto-generated (car_XXXXXX)

Example output:
```
╔═══════════════════════════════════════════════════════════════════════════════╗
║ IMAGES                                                                        ║
╠═══════════════════════════════╤════════╤══════════════╤════════════════╤══════╣
║ REPOSITORY                    │ TAG    │ IMAGE ID     │ CREATED        │ SIZE ║
╠═══════════════════════════════╪════════╪══════════════╪════════════════╪══════╣
║ prometheus/prometheus         │ v2.... │ e1fbd49323c6 │ 1 minutes ago  │ N/A  ║
║ hello-world                   │ latest │ 9c7a54a9a43c │ 2 hours ago    │ N/A  ║
╚═══════════════════════════════╧════════╧══════════════╧════════════════╧══════╝

╔═══════════════════════════════════════════════════════════════════════════════╗
║ CONTAINERS                                                                    ║
╠═════════════╤═════════════════════════╤═══════════╤════════════╤════════════╣
║ ID          │ IMAGE                   │ COMMAND   │ CREATED    │ STATUS     │ NAMES      ║
╠═════════════╪═════════════════════════╪═══════════╪════════════╪════════════╪════════════╣
║ abc123def456 │ hello-world:latest      │ -         │ 5 mins ago │ Exited (0) │ car_abc123 ║
╚═════════════╧═════════════════════════╧═══════════╧════════════╧════════════╧════════════╝
```

When no items are found, appropriate messages are displayed:
- "No images found" when no images exist
- "No containers found" when using -a and no containers exist  
- "No running containers (use -a to show all)" when no running containers

### info / inspect
Display detailed information about a container.

**Usage:**
```bash
carrier info <container>
carrier inspect <container>  # Alias
```

**Examples:**
```bash
# Get detailed container information
carrier info abc123def456

# Using partial ID
carrier info abc1
```

**Features:**
- Complete container metadata display
- Runtime status with visual indicators
- Process and resource information
- Environment variables preview
- Context-sensitive command suggestions
- Uptime and timing information

### shell / sh / exec
Execute commands in running containers.

**Usage:**
```bash
carrier shell <container> [COMMAND...]
carrier sh <container> [COMMAND...]     # Alias
carrier exec <container> [COMMAND...]   # Alias
```

**Examples:**
```bash
# Open interactive shell in container
carrier sh abc123def456
carrier sh abc1  # Partial ID

# Execute specific command
carrier sh abc123 echo "Hello"
carrier sh abc123 ls -la /
carrier sh abc123 ps aux

# Run bash if available
carrier sh abc123 /bin/bash
```

**Features:**
- Enters all container namespaces using nsenter
- Supports interactive and non-interactive commands
- Default command is /bin/sh if none specified
- Requires container to be running
- Supports partial container ID matching

**Requirements:**
- Container must be in "running" state
- nsenter command must be installed
- May require elevated privileges

### stop
Stop running containers by sending termination signals.

**Usage:**
```bash
carrier stop [OPTIONS] <container-id>
```

**Options:**
- `-f, --force`: Force stop (kill) the container immediately without graceful shutdown
- `-t, --timeout <SECONDS>`: Timeout in seconds before forcing stop (default: 10)

**Examples:**
```bash
# Stop a container gracefully
carrier stop abc123def456

# Stop with partial container ID
carrier stop abc1

# Force stop a container immediately
carrier stop --force abc123def456

# Stop with custom timeout
carrier stop --timeout 30 abc123def456
```

**Behavior:**
- Sends SIGTERM for graceful shutdown (default)
- Waits for the specified timeout period for the container to exit
- Sends SIGKILL if container doesn't stop within timeout or if forced
- Updates container metadata with exit status
- Unmounts overlay filesystem after stop
- Supports partial container ID matching (with minimum 1 character)

### remove / rm
Remove images, containers, or all stopped containers from local storage.

**Usage:**
```bash
carrier remove [OPTIONS] [image|container-id]
carrier rm [OPTIONS] [image|container-id]  # Alias
```

**Options:**
- `-f, --force`: Force removal even if container is running or image is in use
- `-c, --all-containers`: Remove all stopped containers

**Examples:**
```bash
# Remove an image
carrier remove nginx:latest

# Remove a container by ID
carrier remove abc123def456

# Remove all stopped containers
carrier rm -c
carrier rm --all-containers

# Force remove all containers (including running ones)
carrier rm -c --force

# Force remove an image even if containers exist
carrier remove --force nginx:latest

# Force remove a running container
carrier remove --force abc123def456
```

**Behavior:**
- For individual containers: Unmounts overlay filesystem and removes all container data
- For images: Removes metadata, extracted layers, and cached blobs
- For `--all-containers`: Removes all non-running containers and their metadata
- Prevents accidental removal of in-use resources unless forced
- Cleans up both extracted layers and compressed blobs to free disk space
- Provides summary of containers removed, skipped, and failed

### auth
Authenticate with a container registry to enable higher API rate limits and access to private repositories.

**Usage:**
```bash
carrier auth <username> <registry>
```

**Arguments:**
- `<username>` - Your username for the registry
- `<registry>` - Registry hostname (e.g., docker.io, quay.io, ghcr.io)

**Examples:**
```bash
# Authenticate with Docker Hub
carrier auth myusername docker.io

# Authenticate with GitHub Container Registry
carrier auth myusername ghcr.io

# Authenticate with Quay.io
carrier auth myusername quay.io

# Authenticate with Google Container Registry  
carrier auth myusername gcr.io
```

**Supported Registries:**
- `docker.io` - Docker Hub
- `quay.io` - Red Hat Quay
- `ghcr.io` - GitHub Container Registry
- `gcr.io` - Google Container Registry
- `public.ecr.aws` - Amazon ECR Public

**Features:**
- **Secure Password Entry**: Password is entered securely without echo
- **Credential Validation**: Tests credentials before storing
- **Automatic Token Management**: Uses stored credentials for enhanced API limits
- **Fallback Support**: Falls back to anonymous access if credentials fail

**Behavior:**
- Prompts for password securely (no echo to terminal)
- Tests credentials by attempting to authenticate with the registry
- Stores credentials locally in `~/.local/share/carrier/auth.json`
- Automatically uses stored credentials for all registry operations
- Provides higher API rate limits for authenticated requests
- Enables access to private repositories (when supported)

**Security:**
- Credentials are stored in JSON format in user's home directory
- Only readable by the user (standard file permissions)
- Passwords are stored in plaintext locally (similar to Docker CLI)
- Uses HTTPS for all authentication requests

### logs
Show logs from a container. Works for containers run in detached mode (`-d`) or any container that has produced output written to `container.log`.

**Usage:**
```bash
carrier logs [OPTIONS] <container-id>
```

**Options:**
- `-f, --follow`: Stream logs and wait for new lines.
- `--tail <N>`: Show only the last N lines before streaming or exiting.
- `--timestamps`: Display RFC3339 timestamps for each line. If the line lacks a timestamp, a current-time stamp is added for display.
- `--since <TIME|DURATION>`: Only show logs since the given time. Accepts RFC3339 (e.g., `2024-09-26T12:30:00Z`) or durations like `10m`, `2h`, `1d`. For lines without timestamps, a best-effort filter is applied using the log file's modification time.
- `--search <TERM>`: Case-insensitive substring filtering.
- `--fuzzy`: Use subsequence fuzzy matching with `--search` (e.g., `hwd` matches `hello world`).
- `--regex <PATTERN>`: Case-insensitive regex filtering; overrides `--search/--fuzzy` when provided.

**Examples:**
```bash
# Show logs from a detached container
carrier logs abc123def456

# Using partial container ID
carrier logs abc1

# Follow and show last 100 lines with timestamps
carrier logs -f --tail 100 --timestamps abc1

# Show logs since 15 minutes ago, filter by 'error'
carrier logs --since 15m --search error abc1

# Fuzzy search 'hwd' (matches 'hello world')
carrier logs --search hwd --fuzzy abc1

# Regex matching (case-insensitive)
carrier logs --regex "^\s*ERROR" abc1
```

**Features:**
- Captures both stdout and stderr for detached containers.
- Partial ID matching is supported.
- Clear messages when no logs are available.
- Logs persist until the container is removed.

**Behavior:**
- Detached containers write timestamped lines to `container.log`.
- Interactive containers write directly to the terminal, so `container.log` may be empty or missing.
- If no log file exists or the container is not found, an appropriate message is displayed.

### shell
Execute a command inside a running container. Defaults to `/bin/sh` when no command is given.

**Usage:**
```bash
carrier shell <container-id> [COMMAND...]
```

**Aliases:** `sh`, `exec`, `execute`

**Notes:**
- Shell attempts to allocate a PTY automatically when running common shells (sh/bash) for a better interactive experience.
- Forcing a PTY for any command is supported via the `terminal` command below.

### terminal
Open a PTY terminal inside a running container. Always forces a TTY regardless of the command.

**Usage:**
```bash
carrier terminal <container-id> [COMMAND...]
```

**Aliases:** `term`, `t`

**Examples:**
```bash
# Open an interactive shell with full TTY support
carrier terminal abc123

# Run a TTY session for an arbitrary program
carrier terminal abc123 python3 -i

# Use a short alias
carrier t abc123 bash
```

**Features:**
- **Full TTY Support**: Always allocates a pseudo-terminal (PTY) with proper raw mode
- **Arrow Key Navigation**: Supports arrow keys for command history and line editing
- **Window Resizing**: Automatically handles terminal window resize events
- **Proper Exit Handling**: Clean exit with `exit` command or Ctrl+D without hanging
- **Raw Mode**: Terminal is set to raw mode for immediate character processing
- **Signal Handling**: Proper handling of terminal signals and cleanup

**Behavior:**
- Automatically enables raw mode for proper input handling including arrow keys
- Gracefully restores terminal settings on exit
- Handles Ctrl+C, Ctrl+D, and exit commands properly
- Suitable for interactive programs that expect a terminal (editors, REPLs, shells)
- Non-blocking I/O prevents hanging when processes exit

**Permission Requirements:**
- **Rootless Mode** (default for non-root users):
  - No elevated privileges required
  - Uses `unshare` with user namespaces to exec into containers
  - Container root is mapped to your user on the host
  - See [Rootless Documentation](./rootless.md) for details
- **Root Mode** (when running as root):
  - Uses `nsenter` to join container namespaces
  - Will attempt sudo fallback if permission denied
  - Full system capabilities available

### build
Build a container image (not yet implemented).

**Usage:**
```bash
carrier build <image> <url>
```

### doctor
Check system dependencies and provide installation guidance.

**Usage:**
```bash
carrier doctor [OPTIONS]
carrier check [OPTIONS]  # Alias
```

**Options:**
- `--fix`: Attempt to automatically fix missing dependencies individually
- `--all`: Install all dependencies in a single batch command
- `--dry-run`: Show what would be installed without making changes
- `-y, --yes`: Skip confirmation prompts (use with --fix or --all)
- `-v, --verbose`: Show detailed output during installation
- `--json`: Output results in JSON format for scripting

**Examples:**
```bash
# Check all dependencies
carrier doctor

# Attempt to fix missing dependencies (with prompts)
carrier doctor --fix

# Fix missing dependencies without prompts
carrier doctor --fix -y

# Preview what would be installed
carrier doctor --dry-run

# Install all dependencies at once
carrier doctor --all

# Install all dependencies without prompts
carrier doctor --all -y

# Verbose output with dry-run
carrier doctor --fix --dry-run --verbose

# Output as JSON for CI/scripting
carrier doctor --json
```

**Installation Features:**
- Checks sudo availability before attempting installation
- Waits for package manager if locked by another process
- Updates package cache before installing
- Retries failed installations with exponential backoff
- Verifies each installation succeeded
- Sets required SUID bits on binaries automatically
- Configures subordinate UID/GID ranges

**What It Checks:**

Essential dependencies:
- `runc` - OCI container runtime
- `fuse-overlayfs` - FUSE-based overlay filesystem
- `/dev/fuse` - FUSE device availability
- `fusermount3` - FUSE mount utility with SUID bit
- User namespaces - Kernel support enabled

Recommended dependencies:
- `pasta` - High-performance userspace networking
- `slirp4netns` - Fallback networking
- `nsenter` - For shell/exec operations
- `newuidmap`/`newgidmap` - UID/GID mapping
- `/etc/subuid` and `/etc/subgid` - Subordinate ID ranges

**Platform Support:**
- Detects Linux distributions (Ubuntu, Debian, Fedora, Arch, etc.)
- Suggests correct package manager commands
- macOS support with graceful degradation (Lima recommended)

**Output Format:**
```
[OK] runc (version 1.1.12)
[WARN] pasta - not found
       Alternative: slirp4netns is available
       To install: sudo apt-get install -y passt
[MISSING] fuse-overlayfs
       To install: sudo apt-get install -y fuse-overlayfs
```

**JSON Output:**
```json
{
  "platform": {
    "os": "linux",
    "distro": "ubuntu",
    "version": "22.04"
  },
  "checks": [
    {"name": "runc", "status": "ok", "details": "1.1.12"}
  ],
  "summary": {"passed": 8, "warnings": 2, "errors": 0}
}
```

## Image Format

Images can be specified in various formats:
- `image` - Uses latest tag from Docker Hub
- `image:tag` - Specific tag from Docker Hub
- `registry/image` - Latest tag from specific registry
- `registry/image:tag` - Specific tag from specific registry

## Supported Registries

The following registries are currently supported:
- Docker Hub (docker.io) - default
- Quay.io
- GitHub Container Registry (ghcr.io)
- Google Container Registry (gcr.io)
- Amazon ECR Public (public.ecr.aws)
- Oracle Container Registry
- Red Hat Registry

## Storage Layout

Carrier uses XDG standards for storage in `~/.local/share/carrier/`:

```
~/.local/share/carrier/
├── storage/
│   ├── overlay/              # Extracted image layers
│   ├── overlay-containers/   # Container runtime data
│   ├── overlay-images/       # Image metadata
│   └── overlay-layers/       # Layer metadata
├── cache/
│   └── blobs/               # Compressed layer cache
└── run/                     # Runtime state
```

## Technical Details

### Manifest Handling
Carrier supports both:
- Docker Image Manifest V2
- Docker Manifest Lists (for multi-architecture images)

When encountering a manifest list, Carrier automatically selects the linux/amd64 platform or falls back to the first available platform.

### Authentication
Authentication tokens are automatically obtained for each registry using their specific token endpoints. No manual login is required for public images.

### Layer Management
- **Caching**: Layers are cached by digest to avoid re-downloading
- **Deduplication**: Same layers across images are stored only once
- **Extraction**: Layers are extracted without root privileges
- **Overlay**: Uses overlay filesystems for efficient container creation

### Progress Tracking
All downloads show progress bars with:
- Current/total bytes downloaded
- Download speed
- Estimated time remaining
- Visual progress indicator

### Rootless Operation
Carrier is designed to run without root privileges:
- Uses fuse-overlayfs when kernel overlay isn't available
- Stores all data in user's home directory
- Extracts layers with user ownership
- Skips privileged operations like device node creation
