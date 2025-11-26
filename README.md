# Carrier
A lightweight, secure, rootless container runtime and management tool written in Rust.

## Performance First

Carrier is optimized for speed with **sub-100ms container startup times**, making it one of the fastest container runtimes available:

- **~50-150ms** container run time (vs 270ms Podman, 312ms Docker)
- **10-20x faster** than VFS-based approaches
- Automatic storage driver selection for optimal performance

See [Performance Guide](docs/performance.md) for benchmarks and optimization tips.

## Rootless Containers - No sudo required!

Carrier supports fully rootless container execution, similar to Podman. Regular users can create and manage containers without needing root privileges or sudo access. This provides better security isolation and makes containers accessible to all users.

See [Rootless Documentation](docs/rootless.md) for setup and usage details.

## Features

### Core Capabilities
- **High Performance** - Sub-100ms container startup with intelligent storage driver selection
- **Rootless by Design** - Run containers without root privileges using user namespaces
- **Multi-Registry Support** - Pull from Docker Hub, Quay.io, GHCR, GCR, ECR, and more
- **Container Lifecycle Management** - Run, stop, remove, and execute commands
- **Multiple Execution Modes** - Interactive, detached, and exec into running containers
- **Bulk Operations** - Clean up all stopped containers with one command
- **Clean Output** - Formatted tables for listing images and containers

### Technical Features
- **Smart Storage Drivers** - Automatic selection between fuse-overlayfs, native overlay, and VFS
- **Overlay Filesystem** - Efficient layer management with overlay/fuse-overlayfs
- **Namespace Isolation** - Full Linux namespace support (PID, Network, Mount, UTS, IPC, User)
- **Cgroups v2** - Resource limits and accounting
- **Security** - Capability dropping, seccomp filters, no-new-privileges
- **Device Management** - Proper /dev mounting with automatic fallback from devtmpfs to tmpfs, ensuring correct device node permissions

## Quick Start

```bash
# Build
cargo build --release

# Run your first container
./target/release/carrier run alpine

# Run in background
./target/release/carrier run -d nginx

# Execute command in running container
./target/release/carrier sh <container-id>

# Stop and cleanup
./target/release/carrier stop <container-id>
./target/release/carrier rm -c  # Remove all stopped containers
```

## Installation

### Quick Install (Recommended)
```bash
# Using curl
curl -LsSf https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh

# Using wget
wget -qO- https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh

# Or download and run manually
curl -LO https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh
chmod +x setup.sh
./setup.sh install
```

The installer will:
- Check and install Rust if needed
- Install system dependencies
- Build Carrier from source
- Install the binary to `/usr/local/bin`

To uninstall:
```bash
curl -LsSf https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh -s -- uninstall
# Or if you have the script locally
./setup.sh uninstall
```

### From Source (Manual)
```bash
git clone https://github.com/javanhut/Carrier
cd Carrier
cargo build --release
sudo cp target/release/carrier /usr/local/bin/
```

### Requirements
- Linux kernel 4.18+ (5.14+ recommended)
- Rust 1.70+
- Optional: `nsenter` for shell/exec functionality
- Optional: `fuse-overlayfs` for rootless overlay support

## Usage Examples

### Container Management
```bash
# Pull and run an image
carrier run ubuntu

# Run with detached mode
carrier run -d redis

# Run with specific platform (useful on multi-arch hosts)
carrier run --platform linux/arm64 alpine uname -m

# Execute commands in running container
carrier sh <container-id> redis-cli ping

# Interactive shell
carrier sh <container-id>

# Force a PTY terminal (full TTY support with arrow keys)
carrier terminal <container-id>
# or with alias
carrier t <container-id> bash

# Stop container
carrier stop <container-id>

# Remove container
carrier rm <container-id>
```

### Image Management
```bash
# Pull images
carrier pull nginx:latest
carrier pull quay.io/prometheus/prometheus

# Pull for a specific platform
carrier pull --platform linux/arm64 alpine

# List images
carrier ls -i

# Remove images
carrier rm nginx:latest
carrier rm e1fbd49323c6  # By ID
```

### Bulk Operations
```bash
# List all containers
carrier ls -c -a

# Remove all stopped containers
carrier rm -c

# Force remove all containers
carrier rm -c --force
```

## Supported Registries

- Docker Hub (docker.io)
- Quay.io
- GitHub Container Registry (ghcr.io)
- Google Container Registry (gcr.io)
- Amazon ECR Public (public.ecr.aws)
- Oracle Container Registry
- Red Hat Registry

## Architecture

Carrier implements a complete container runtime with:
- **Storage Layer** - Image and layer management
- **Runtime Layer** - Process isolation and execution
- **Network Layer** - Container networking with slirp4netns
- **Security Layer** - Capabilities, seccomp, and namespace isolation

See [docs/runtime.md](docs/runtime.md) for detailed architecture information.

## Documentation

- [Getting Started](docs/getting-started.md) - Quick start guide
- [Commands Reference](docs/commands.md) - Detailed command documentation
- [Runtime Architecture](docs/runtime.md) - Technical runtime details
- [Storage](docs/storage.md) - Storage layout and management
- [Shell/Exec](docs/shell.md) - Executing commands in containers
- [Stop](docs/stop.md) - Stopping containers

## Development

### Building without Warnings
```bash
# Set environment variable
RUSTFLAGS=-Awarnings cargo build

# Or use the wrapper script
./carrier.sh ls
```

### Project Structure
```
carrier/
├── src/
│   ├── cli/          # CLI parsing and commands
│   ├── commands/     # Command implementations
│   ├── runtime/      # Container runtime
│   └── storage/      # Storage and filesystem management
├── docs/             # Documentation
└── Cargo.toml        # Project configuration
```

## Comparison

### vs Docker
-  No daemon required
-  Rootless by default
-  Lighter resource usage
-  Direct execution model

### vs Podman
-  Simpler architecture
-  Faster container startup
-  Integrated runtime
-  Robust device node handling with proper permission management

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

[Your License Here]

## Acknowledgments

Built with:
- [Rust](https://rust-lang.org) - System programming language
- [Nix](https://github.com/nix-rust/nix) - Unix system calls
- [Tokio](https://tokio.rs) - Async runtime
- [Clap](https://github.com/clap-rs/clap) - CLI parsing
