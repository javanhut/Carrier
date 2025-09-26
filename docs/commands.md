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
- Extracts container filesystem layers
- Sets up container environment
- Creates unique container ID for each run

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

## Storage

Downloaded images and layers are stored in:
- `./carrier_storage/` - Image layers and configs
- `./containers/` - Extracted container filesystems

## Technical Details

### Manifest Handling
Carrier supports both:
- Docker Image Manifest V2
- Docker Manifest Lists (for multi-architecture images)

When encountering a manifest list, Carrier automatically selects the linux/amd64 platform or falls back to the first available platform.

### Authentication
Authentication tokens are automatically obtained for each registry using their specific token endpoints. No manual login is required for public images.

### Progress Tracking
All downloads show progress bars with:
- Current/total bytes downloaded
- Download speed
- Estimated time remaining
- Visual progress indicator