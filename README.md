# Carrier
A lightweight, secure, rootless container runtime and management tool written in Rust.

## Features

### Core Capabilities
- **Rootless by Design** - Run containers without root privileges
- **Multi-Registry Support** - Pull from Docker Hub, Quay.io, GHCR, GCR, ECR, and more
- **Container Lifecycle Management** - Run, stop, remove, and execute commands
- **Multiple Execution Modes** - Interactive, detached, and exec into running containers
- **Bulk Operations** - Clean up all stopped containers with one command
- **Clean Output** - Formatted tables for listing images and containers

### Technical Features
- **Custom Runtime** - Built-in container runtime, no dependency on runc/crun
- **Overlay Filesystem** - Efficient layer management with overlay/fuse-overlayfs
- **Namespace Isolation** - Full Linux namespace support (PID, Network, Mount, UTS, IPC, User)
- **Cgroups v2** - Resource limits and accounting
- **Security** - Capability dropping, seccomp filters, no-new-privileges

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

### From Source
```bash
git clone https://github.com/yourusername/carrier
cd carrier
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

# Force a PTY terminal (full TTY support)
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
- x No external runtime dependency (runc/crun)
-  Simpler architecture
-  Faster container startup
-  Integrated runtime

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
