# Carrier Commands

## Overview
Carrier provides several commands for managing container images and running containers. All commands support pulling images from various container registries including Docker Hub, Quay.io, GitHub Container Registry, and more.

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
Pull an image and run it as a container.

**Usage:**
```bash
carrier run <image>
```

**Examples:**
```bash
# Run latest alpine image
carrier run alpine

# Run specific version
carrier run nginx:1.24

# Run from specific registry
carrier run ghcr.io/my-org/my-app:latest
```

**Features:**
- Automatically pulls the image if not already downloaded
- Creates overlay filesystem with copy-on-write
- Sets up container environment with unique ID
- Supports both native overlay and fuse-overlayfs for rootless operation

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
Authenticate with a container registry (not yet implemented).

**Usage:**
```bash
carrier auth <username> <registry>
```

### logs
Show container logs (not yet implemented).

**Usage:**
```bash
carrier logs <container-id>
```

### build
Build a container image (not yet implemented).

**Usage:**
```bash
carrier build <image> <url>
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