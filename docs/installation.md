# Carrier Installation Guide

## Quick Installation

The easiest way to install Carrier is using our installation script:

```bash
curl -LsSf https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh
```

This script will automatically:
1. Download pre-built binary (or build from source if unavailable)
2. Verify SHA256 checksum for security
3. Install the binary to `/usr/local/bin`
4. Install shell completions (bash, zsh, fish)
5. Install runtime dependencies (runc, fuse-overlayfs, etc.)

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

### Setup Script Commands

The installation script supports multiple commands:

```bash
./setup.sh [COMMAND] [OPTIONS]

Commands:
  install       Install Carrier (default)
  uninstall     Remove Carrier from system
  update        Update to latest version
  deps          Install runtime dependencies only
  completions   Install shell completions only
```

### Setup Script Options

```bash
Options:
  --binary          Force binary download (skip source build)
  --source          Force source build (skip binary download)
  --prefix PATH     Install to custom directory (default: /usr/local)
  --no-deps         Skip runtime dependency installation
  --no-completions  Skip shell completion installation
  -y, --yes         Skip confirmation prompts
  -v, --verbose     Show detailed output
  -h, --help        Show help message
```

### Installation Examples

```bash
# Quick install with all defaults
curl -LsSf https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh

# Install to custom directory
./setup.sh install --prefix ~/.local

# Install without runtime dependencies
./setup.sh install --no-deps

# Force source build (useful if binaries not available)
./setup.sh install --source

# Non-interactive installation (skip prompts)
./setup.sh install -y

# Update to latest version
./setup.sh update

# Install only runtime dependencies
./setup.sh deps

# Install shell completions
./setup.sh completions

# Uninstall
./setup.sh uninstall
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

# Check system dependencies
carrier doctor

# Test with a simple container
carrier run alpine echo "Hello from Carrier!"
```

## Dependency Checking with `carrier doctor`

Carrier includes a built-in dependency checker that verifies all required and recommended dependencies are properly installed and configured.

### Basic Usage

```bash
# Check all dependencies
carrier doctor

# Attempt to automatically fix missing dependencies
carrier doctor --fix

# Output results in JSON format (for scripting)
carrier doctor --json

# Show what would be installed without making changes (dry run)
carrier doctor --dry-run

# Install all dependencies at once
carrier doctor --all

# Install all dependencies without prompts
carrier doctor --all -y

# Install missing dependencies with verbose output
carrier doctor --fix --verbose

# Preview what will be installed with verbose output
carrier doctor --fix --dry-run --verbose
```

### What It Checks

The `carrier doctor` command verifies:

**Essential Dependencies:**
- `runc` - OCI container runtime
- `fuse-overlayfs` - FUSE-based overlay filesystem
- `/dev/fuse` - FUSE device
- `fusermount3` - FUSE mount utility (with SUID bit)
- User namespaces enabled

**Recommended Dependencies:**
- `pasta` - High-performance userspace networking
- `slirp4netns` - Userspace networking (fallback)
- `nsenter` - For shell/exec into containers
- `newuidmap`/`newgidmap` - UID/GID mapping tools
- `/etc/subuid` and `/etc/subgid` - Subordinate ID configuration

### Example Output

```
Carrier Dependency Check
========================

Platform: Linux (Ubuntu)
Kernel: 6.5.0-44-generic
Package Manager: apt

[OK] runc (runc version 1.1.12)
[OK] fuse-overlayfs (fuse-overlayfs 1.13)
[WARN] pasta - not found
       Alternative: slirp4netns is available
       To install: sudo apt-get install -y passt
[OK] slirp4netns (slirp4netns version 1.2.0)
[OK] nsenter (nsenter from util-linux 2.39.3)
[WARN] newuidmap - missing SUID bit
       Fix: sudo chmod u+s /usr/bin/newuidmap
[OK] /dev/fuse
[OK] fusermount3
[OK] user_namespaces
[OK] /etc/subuid (65536 UIDs)
[OK] /etc/subgid (65536 GIDs)

------------------------
Summary: 9 passed, 2 warnings, 0 errors

Run 'carrier doctor --fix' to attempt automatic fixes.
```

### Auto-Fix Mode

When running with `--fix`, Carrier will:
1. Check sudo availability before attempting installation
2. Wait for package manager if locked by another process
3. Update package cache before installing
4. Prompt before installing each missing package (skip with `-y`)
5. Use your system's package manager (apt, dnf, pacman, etc.)
6. Retry failed installations with exponential backoff
7. Verify each installation succeeded
8. Set required SUID bits on binaries
9. Load kernel modules if needed
10. Configure subordinate UID/GID ranges

```bash
# Fix all issues with prompts
carrier doctor --fix

# Fix all issues without prompts
carrier doctor --fix -y

# See what would be fixed without making changes
carrier doctor --fix --dry-run
```

### Batch Installation

Use `--all` to install all dependencies in a single command:

```bash
# Install all dependencies with prompts
carrier doctor --all

# Install all dependencies without prompts
carrier doctor --all -y

# Preview the batch install command
carrier doctor --all --dry-run
```

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--fix` | | Install missing dependencies individually |
| `--all` | | Install all dependencies in one batch |
| `--dry-run` | | Show what would be done without making changes |
| `--yes` | `-y` | Skip confirmation prompts |
| `--verbose` | `-v` | Show detailed output during installation |
| `--json` | | Output results in JSON format |

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
