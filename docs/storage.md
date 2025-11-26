# Storage Architecture

## Overview
Carrier uses a layered storage system similar to Docker and Podman, optimized for rootless container operations. The storage system manages container images, layers, and runtime filesystems using overlay filesystems.

## Storage Layout

The storage system follows XDG standards and creates the following directory structure:

```
~/.local/share/carrier/
├── storage/
│   ├── overlay/              # Extracted image layers
│   ├── overlay-containers/   # Container metadata and runtime data
│   ├── overlay-images/       # Image metadata
│   ├── overlay-layers/       # Layer metadata
│   └── tmp/                  # Temporary files
├── cache/
│   └── blobs/               # Downloaded but not extracted blobs
└── run/                     # Runtime state
```

## Key Components

### StorageLayout
Manages the directory structure and provides paths for different storage components:
- **Image layers**: Extracted tar archives organized by digest
- **Container storage**: Per-container directories with upper/work/merged dirs
- **Blob cache**: Downloaded compressed layers before extraction
- **Metadata storage**: JSON files with image and container metadata

### ContainerStorage
Handles the creation and management of container filesystems using overlay:
- Automatically attempts to install and use fuse-overlayfs (fuse3) for optimal performance
- Falls back through multiple storage drivers: fuse-overlayfs -> native overlay -> VFS
- Creates layered filesystems with read-only base layers and writable upper layer
- Supports both privileged and rootless operation modes
- Automatic dependency installation and configuration when possible

### Layer Management
- **Rootless extraction**: Tar archives are extracted without preserving ownership
- **Deduplication**: Layers are cached and reused across containers
- **Progressive download**: Only downloads layers that aren't already cached

## Usage in Commands

### Pull Command
1. Initializes storage layout
2. Downloads manifest and saves metadata
3. Downloads missing layers to blob cache
4. Extracts layers to storage/overlay directory
5. Stores image metadata for later use

### Run Command
1. Uses cached layers from pull operation
2. Creates container-specific overlay filesystem
3. Sets up upper (writable) and work directories
4. Mounts overlay filesystem at merged directory
5. Stores container metadata

## Storage Drivers

Carrier supports multiple storage drivers with automatic fallback:

### 1. FUSE-OverlayFS (Default)
- **Priority**: First choice for rootless containers
- **Requirements**: fuse3, fuse-overlayfs packages
- **Auto-installation**: Carrier attempts to install automatically if missing
- **Performance**: Good performance with full overlay features
- **Compatibility**: Works on all kernels with FUSE support

### 2. Native Overlay
- **Priority**: Second choice, fallback from fuse-overlayfs
- **Requirements**: Kernel 5.11+ with unprivileged overlay support
- **Performance**: Best performance (kernel native)
- **Compatibility**: Limited to newer kernels and specific configurations

### 3. VFS (Virtual File System)
- **Priority**: Last resort fallback
- **Requirements**: None (always available)
- **Performance**: Slower, copies entire filesystem
- **Compatibility**: Works everywhere

### Storage Driver Selection

The driver selection follows this cascade:
1. If `--storage-driver` flag is specified, use that driver first
2. Otherwise, try fuse-overlayfs (attempt auto-install if missing)
3. If fuse-overlayfs fails, try native overlay
4. If native overlay fails, fall back to VFS

### Automatic Dependency Management

Carrier automatically manages storage driver dependencies:
- Detects missing fuse-overlayfs and attempts installation
- Tries to install fuse3 packages via system package manager (apt, dnf, pacman, zypper)
- Attempts to set proper permissions on fusermount3 (setuid bit)
- Loads FUSE kernel module if not loaded
- Provides clear feedback when automatic installation fails
- Gracefully falls back to alternative drivers

## Rootless Operation

The storage system is designed for rootless operation:
- Files are extracted with current user ownership
- Prefers fuse-overlayfs for best compatibility
- Automatically handles driver selection and fallback
- Skips device files that require root privileges
- All storage is within user's home directory
- Runtime directory uses persistent storage to avoid tmpfs limitations

## Caching Strategy

### Layer Caching
- Layers are identified by digest (sha256)
- Once extracted, layers are reused for all containers
- Blob cache stores compressed layers
- Extracted layers stored in overlay directory

### Deduplication
- Same layers across different images are stored only once
- Digest-based identification ensures integrity
- Reduces disk usage for images with common base layers

## Performance Optimizations

1. **Parallel downloads**: Multiple layers downloaded concurrently
2. **Skip cached layers**: Already downloaded layers are not re-fetched
3. **Progressive extraction**: Layers extracted as downloaded
4. **Overlay filesystem**: Efficient copy-on-write for containers

## Troubleshooting

### Storage Driver Issues

**"fuse-overlayfs not found"**
- Carrier will attempt automatic installation
- If automatic installation fails, manually install: `sudo apt install fuse-overlayfs fuse3`
- System will automatically fall back to VFS if fuse is unavailable

**"fusermount3 is not setuid"**
- Carrier will attempt to set the setuid bit automatically
- If automatic fix fails, manually run: `sudo chmod u+s /usr/bin/fusermount3`

**"/dev/fuse not present"**
- Carrier will attempt to load the FUSE module automatically
- If automatic loading fails, manually run: `sudo modprobe fuse`

**"VFS storage driver is slow"**
- VFS copies the entire filesystem, which is slower than overlay methods
- Install fuse-overlayfs for better performance: `sudo apt install fuse-overlayfs fuse3`
- Ensure your kernel supports either FUSE or native overlay

### Manual Storage Driver Selection

You can force a specific storage driver using the global `--storage-driver` flag (must be placed before the subcommand):
```bash
# Force fuse-overlayfs
carrier --storage-driver overlay-fuse run alpine

# Force native overlay
carrier --storage-driver overlay-native run ubuntu

# Force VFS (slowest but most compatible)
carrier --storage-driver vfs run debian
```

**Note**: The `--storage-driver` flag is a global option and must be specified **before** the subcommand (e.g., `run`, `pull`).

## Future Enhancements

- Garbage collection for unused layers
- Storage quota management
- Network-based storage backends
- Compression optimization
- Multi-architecture image support
- Enhanced VFS performance with hard links