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
- Automatically detects if native overlay or fuse-overlayfs should be used
- Creates layered filesystems with read-only base layers and writable upper layer
- Supports both privileged and rootless operation modes

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

## Rootless Operation

The storage system is designed for rootless operation:
- Files are extracted with current user ownership
- Uses fuse-overlayfs when kernel doesn't support rootless overlay
- Skips device files that require root privileges
- All storage is within user's home directory

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

## Future Enhancements

- Garbage collection for unused layers
- Storage quota management
- Network-based storage backends
- Compression optimization
- Multi-architecture image support