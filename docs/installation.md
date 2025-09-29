# Carrier Installation Guide

## Quick Installation

The easiest way to install Carrier is using our installation script:

```bash
curl -LsSf https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh
```

This script will automatically:
1. Check for required dependencies
2. Install Rust if not present
3. Clone and build Carrier from source
4. Install the binary to `/usr/local/bin`

## Installation Methods

### 1. Automated Script Installation

#### Using curl:
```bash
curl -LsSf https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh
```

#### Using wget:
```bash
wget -qO- https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh
```

#### Download and run manually:
```bash
# Download the script
curl -LO https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh
# or
wget https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh

# Make it executable
chmod +x setup.sh

# Run installation
./setup.sh install
```

### 2. Manual Installation from Source

If you prefer to install manually:

```bash
# Clone the repository
git clone https://github.com/javanhut/Carrier
cd Carrier

# Build with cargo
cargo build --release

# Install to system directory (requires sudo)
sudo cp target/release/carrier /usr/local/bin/

# Or install to user directory (no sudo required)
mkdir -p ~/.local/bin
cp target/release/carrier ~/.local/bin/
# Add ~/.local/bin to your PATH if not already there
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

### 3. Development Installation

For development, you can use cargo to install directly:

```bash
git clone https://github.com/javanhut/carrier
cd carrier
cargo install --path .
```

This installs Carrier to `~/.cargo/bin/`, which should already be in your PATH if Rust is installed.

## System Requirements

### Minimum Requirements
- **Linux kernel**: 4.18 or later
- **Rust**: 1.70.0 or later
- **Architecture**: x86_64 or aarch64
- **Memory**: 512MB RAM minimum
- **Disk**: 100MB for Carrier + space for container images

### Recommended Requirements
- **Linux kernel**: 5.14 or later (better cgroup v2 support)
- **Memory**: 2GB RAM or more
- **Disk**: 10GB+ for comfortable container usage

### Required Dependencies

The installation script will check for and help install these:

#### Build Dependencies
- `git` - For cloning the repository
- `gcc` or `clang` - C compiler for building native dependencies
- `pkg-config` - For finding system libraries
- `make` - Build automation tool

#### Runtime Dependencies (Optional)
- `nsenter` - For shell/exec functionality
- `fuse-overlayfs` - For rootless overlay filesystem
- `slirp4netns` - For rootless networking

### Distribution-Specific Installation

#### Ubuntu/Debian
```bash
# Install build dependencies
sudo apt-get update
sudo apt-get install -y git build-essential pkg-config

# Install optional runtime dependencies
sudo apt-get install -y nsenter fuse-overlayfs slirp4netns
```

#### Fedora/RHEL/CentOS
```bash
# Install build dependencies
sudo dnf install -y git gcc pkg-config

# Install optional runtime dependencies
sudo dnf install -y util-linux fuse-overlayfs slirp4netns
```

#### Arch Linux
```bash
# Install build dependencies
sudo pacman -S git base-devel pkg-config

# Install optional runtime dependencies
sudo pacman -S util-linux fuse-overlayfs slirp4netns
```

#### Alpine Linux
```bash
# Install build dependencies
apk add git build-base pkgconfig

# Install optional runtime dependencies
apk add util-linux fuse-overlayfs slirp4netns
```

## Installing Rust

If Rust is not installed, the setup script will install it automatically. To install manually:

```bash
# Official Rust installer
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Follow the prompts and then reload your environment
source $HOME/.cargo/env
```

## Verification

After installation, verify Carrier is working:

```bash
# Check version
carrier --version

# Check help
carrier --help

# Test with a simple container
carrier run alpine echo "Hello from Carrier!"
```

## Uninstallation

### Using the Setup Script
```bash
# If installed with the setup script
curl -LsSf https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh -s -- uninstall

# Or with local script
./setup.sh uninstall
```

### Manual Uninstallation
```bash
# Remove the binary
sudo rm /usr/local/bin/carrier

# Optional: Remove configuration and data
rm -rf ~/.carrier
rm -rf ~/.config/carrier
```

## Troubleshooting

### Permission Denied
If you get permission errors when installing to `/usr/local/bin`:
```bash
# Use sudo
sudo ./setup.sh install

# Or install to user directory instead
PREFIX=$HOME/.local ./setup.sh install
```

### Rust Not Found
If Rust installation fails or isn't detected:
```bash
# Ensure cargo is in PATH
source $HOME/.cargo/env

# Or add to your shell profile
echo 'source $HOME/.cargo/env' >> ~/.bashrc
```

### Build Failures
If the build fails:
```bash
# Ensure all dependencies are installed
cargo --version  # Should be 1.70.0+
gcc --version    # Should be present
pkg-config --version  # Should be present

# Clean and rebuild
cargo clean
cargo build --release
```

### Network Issues
If you can't download the script:
```bash
# Use a different method (wget instead of curl)
wget https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh

# Or clone the repository directly
git clone https://github.com/javanhut/Carrier
```

## Post-Installation Setup

### Rootless Setup
For rootless container support, ensure your user has subordinate UIDs/GIDs:
```bash
# Check if configured
grep $USER /etc/subuid /etc/subgid

# If not configured, add them (requires root)
sudo usermod --add-subuids 100000-165536 $USER
sudo usermod --add-subgids 100000-165536 $USER
```

### PATH Configuration
If `carrier` is not found after installation:
```bash
# Add to PATH (if installed to /usr/local/bin)
export PATH="/usr/local/bin:$PATH"

# Make permanent
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc

# Or for user installation
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

## Getting Help

If you encounter issues:
1. Check the [troubleshooting section](#troubleshooting) above
2. Review the [system requirements](#system-requirements)
3. Check existing [GitHub issues](https://github.com/javanhut/Carrier/issues)
4. Open a new issue with:
   - Your OS and version
   - Installation method used
   - Complete error output
   - Steps to reproduce
