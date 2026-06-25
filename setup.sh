#!/bin/bash

# Carrier Installation Script
# Usage:
#   curl -LsSf https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh
#   wget -qO- https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh
#   ./setup.sh [COMMAND] [OPTIONS]
#
# Commands:
#   install     Install Carrier (default)
#   uninstall   Remove Carrier from system
#   update      Update to latest version
#   deps        Install runtime dependencies only
#   completions Install shell completions only
#
# Options:
#   --binary        Force binary download (skip source build)
#   --source        Force source build (skip binary download)
#   --prefix PATH   Install to custom directory (default: /usr/local)
#   --no-deps       Skip runtime dependency installation
#   --no-completions Skip shell completion installation
#   -y, --yes       Skip confirmation prompts
#   -v, --verbose   Show detailed output
#   -h, --help      Show help message

set -e

# Configuration
REPO_OWNER="javanhut"
REPO_NAME="Carrier"
BINARY_NAME="carrier"
GITHUB_API="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}"
GITHUB_RELEASES="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
DEFAULT_PREFIX="/usr/local"
BUILD_DIR="/tmp/carrier-build-$$"
REQUIRED_RUST_VERSION="1.70.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Global options
INSTALL_MODE="auto"  # auto, binary, source
PREFIX="$DEFAULT_PREFIX"
INSTALL_DEPS=true
INSTALL_COMPLETIONS=true
YES=false
VERBOSE=false

# ============================================================================
# Helper Functions
# ============================================================================

print_error() {
    echo -e "${RED}error${NC}: $1" >&2
}

print_success() {
    echo -e "${GREEN}ok${NC}: $1"
}

print_info() {
    echo -e "${CYAN}info${NC}: $1"
}

print_warning() {
    echo -e "${YELLOW}warning${NC}: $1"
}

print_step() {
    echo -e "\n${BOLD}==> $1${NC}"
}

print_verbose() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${CYAN}  -> $1${NC}"
    fi
}

die() {
    print_error "$1"
    cleanup
    exit 1
}

# Spinner for long-running operations
spin() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

run_with_spinner() {
    local msg="$1"
    shift
    printf "%s" "$msg"

    if [ "$VERBOSE" = true ]; then
        echo
        "$@"
        local status=$?
    else
        "$@" > /tmp/carrier-install-$$.log 2>&1 &
        local pid=$!
        spin $pid
        wait $pid
        local status=$?
        if [ $status -ne 0 ]; then
            echo
            cat /tmp/carrier-install-$$.log
        fi
        rm -f /tmp/carrier-install-$$.log
    fi

    if [ $status -eq 0 ]; then
        echo -e " ${GREEN}done${NC}"
    else
        echo -e " ${RED}failed${NC}"
    fi
    return $status
}

confirm() {
    if [ "$YES" = true ]; then
        return 0
    fi

    if [ ! -t 0 ]; then
        return 0  # Non-interactive, assume yes
    fi

    local prompt="$1 [y/N] "
    read -p "$prompt" -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

version_ge() {
    [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

check_root() {
    [ "$EUID" -eq 0 ]
}

need_sudo() {
    if check_root; then
        "$@"
    else
        sudo "$@"
    fi
}

# ============================================================================
# Platform Detection
# ============================================================================

detect_os() {
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    echo "$os"
}

detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *) echo "$arch" ;;
    esac
}

detect_platform() {
    local os arch
    os=$(detect_os)
    arch=$(detect_arch)
    echo "${os}-${arch}"
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif command_exists lsb_release; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

detect_package_manager() {
    local distro
    distro=$(detect_distro)

    case "$distro" in
        ubuntu|debian|linuxmint|pop) echo "apt" ;;
        fedora|rhel|centos|rocky|alma) echo "dnf" ;;
        arch|manjaro|endeavouros) echo "pacman" ;;
        opensuse*|suse) echo "zypper" ;;
        alpine) echo "apk" ;;
        void) echo "xbps" ;;
        gentoo) echo "emerge" ;;
        *)
            if command_exists apt-get; then echo "apt"
            elif command_exists dnf; then echo "dnf"
            elif command_exists yum; then echo "yum"
            elif command_exists pacman; then echo "pacman"
            elif command_exists zypper; then echo "zypper"
            elif command_exists apk; then echo "apk"
            elif command_exists brew; then echo "brew"
            else echo "unknown"
            fi
            ;;
    esac
}

# ============================================================================
# Version and Download Functions
# ============================================================================

get_latest_version() {
    local version
    if command_exists curl; then
        version=$(curl -sL "${GITHUB_API}/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')
    elif command_exists wget; then
        version=$(wget -qO- "${GITHUB_API}/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')
    fi
    echo "$version"
}

get_current_version() {
    if command_exists carrier; then
        carrier --version 2>/dev/null | awk '{print $2}'
    fi
}

get_download_url() {
    local version=$1
    local platform=$2
    echo "${GITHUB_RELEASES}/download/v${version}/carrier-${version}-${platform}.tar.gz"
}

get_checksum_url() {
    local version=$1
    echo "${GITHUB_RELEASES}/download/v${version}/carrier-${version}-checksums.txt"
}

download_file() {
    local url=$1
    local output=$2

    if command_exists curl; then
        curl -fsSL "$url" -o "$output"
    elif command_exists wget; then
        wget -q "$url" -O "$output"
    else
        die "Neither curl nor wget found. Please install one of them."
    fi
}

verify_checksum() {
    local file=$1
    local expected=$2

    local actual
    if command_exists sha256sum; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command_exists shasum; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        print_warning "Cannot verify checksum: sha256sum/shasum not found"
        return 0
    fi

    [ "$actual" = "$expected" ]
}

# ============================================================================
# Binary Installation
# ============================================================================

try_binary_install() {
    local prefix=$1
    local platform version download_url checksum_url archive_file checksum_file expected_checksum

    platform=$(detect_platform)
    print_verbose "Detected platform: $platform"

    # Only Linux is supported for pre-built binaries
    if [[ "$platform" != linux-* ]]; then
        print_verbose "Pre-built binaries only available for Linux"
        return 1
    fi

    print_step "Downloading pre-built binary"

    version=$(get_latest_version)
    if [ -z "$version" ]; then
        print_warning "Could not determine latest version"
        return 1
    fi
    print_info "Latest version: $version"

    download_url=$(get_download_url "$version" "$platform")
    checksum_url=$(get_checksum_url "$version")

    print_verbose "Download URL: $download_url"

    # Create temp directory
    local temp_dir
    temp_dir=$(mktemp -d)
    archive_file="$temp_dir/carrier.tar.gz"
    checksum_file="$temp_dir/checksums.txt"

    # Download archive
    if ! run_with_spinner "  Downloading carrier-${version}-${platform}.tar.gz..." download_file "$download_url" "$archive_file"; then
        rm -rf "$temp_dir"
        return 1
    fi

    # Download and verify checksum
    if download_file "$checksum_url" "$checksum_file" 2>/dev/null; then
        expected_checksum=$(grep "carrier-${version}-${platform}.tar.gz" "$checksum_file" | awk '{print $1}')
        if [ -n "$expected_checksum" ]; then
            printf "  Verifying checksum..."
            if verify_checksum "$archive_file" "$expected_checksum"; then
                echo -e " ${GREEN}ok${NC}"
            else
                echo -e " ${RED}failed${NC}"
                print_error "Checksum verification failed"
                rm -rf "$temp_dir"
                return 1
            fi
        fi
    else
        print_warning "Could not download checksums, skipping verification"
    fi

    # Extract archive
    printf "  Extracting archive..."
    if tar xzf "$archive_file" -C "$temp_dir"; then
        echo -e " ${GREEN}done${NC}"
    else
        echo -e " ${RED}failed${NC}"
        rm -rf "$temp_dir"
        return 1
    fi

    # Install binary
    local bin_dir="$prefix/bin"
    printf "  Installing to %s..." "$bin_dir"

    if [ ! -d "$bin_dir" ]; then
        need_sudo mkdir -p "$bin_dir"
    fi

    if need_sudo cp "$temp_dir/carrier" "$bin_dir/" && need_sudo chmod 755 "$bin_dir/carrier"; then
        echo -e " ${GREEN}done${NC}"
    else
        echo -e " ${RED}failed${NC}"
        rm -rf "$temp_dir"
        return 1
    fi

    # Copy completions if present
    if [ -d "$temp_dir/completions" ]; then
        DOWNLOADED_COMPLETIONS="$temp_dir/completions"
    fi

    rm -rf "$temp_dir"
    return 0
}

# ============================================================================
# Source Installation
# ============================================================================

check_rust() {
    if command_exists rustc && command_exists cargo; then
        local rust_version
        rust_version=$(rustc --version | cut -d' ' -f2)
        if version_ge "$rust_version" "$REQUIRED_RUST_VERSION"; then
            print_verbose "Rust $rust_version is installed"
            return 0
        else
            print_warning "Rust $rust_version is installed but version $REQUIRED_RUST_VERSION or higher is required"
            return 1
        fi
    else
        print_verbose "Rust is not installed"
        return 1
    fi
}

install_rust() {
    print_step "Installing Rust"

    if ! confirm "Rust is required to build from source. Install it now?"; then
        die "Rust installation cancelled"
    fi

    if command_exists curl; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    elif command_exists wget; then
        wget -qO- https://sh.rustup.rs | sh -s -- -y
    else
        die "Neither curl nor wget found"
    fi

    # Source cargo env
    if [ -f "$HOME/.cargo/env" ]; then
        . "$HOME/.cargo/env"
    else
        export PATH="$HOME/.cargo/bin:$PATH"
    fi

    if command_exists rustc && command_exists cargo; then
        print_success "Rust installed successfully"
    else
        die "Rust installation failed"
    fi
}

check_build_dependencies() {
    local missing=()

    if ! command_exists git; then
        missing+=("git")
    fi

    if ! command_exists cc && ! command_exists gcc && ! command_exists clang; then
        missing+=("gcc or clang")
    fi

    if ! command_exists pkg-config; then
        missing+=("pkg-config")
    fi

    if [ ${#missing[@]} -ne 0 ]; then
        print_warning "Missing build dependencies: ${missing[*]}"

        local pm
        pm=$(detect_package_manager)
        case "$pm" in
            apt) print_info "Install with: sudo apt-get install -y git build-essential pkg-config" ;;
            dnf) print_info "Install with: sudo dnf install -y git gcc pkg-config" ;;
            pacman) print_info "Install with: sudo pacman -S git base-devel pkg-config" ;;
            *) print_info "Please install: ${missing[*]}" ;;
        esac

        if confirm "Install build dependencies automatically?"; then
            install_build_dependencies "$pm"
        else
            return 1
        fi
    fi
    return 0
}

install_build_dependencies() {
    local pm=$1

    case "$pm" in
        apt)
            need_sudo apt-get update
            need_sudo apt-get install -y git build-essential pkg-config
            ;;
        dnf)
            need_sudo dnf install -y git gcc pkg-config
            ;;
        yum)
            need_sudo yum install -y git gcc pkg-config
            ;;
        pacman)
            need_sudo pacman -Sy --noconfirm git base-devel pkg-config
            ;;
        zypper)
            need_sudo zypper install -y git gcc pkg-config
            ;;
        apk)
            need_sudo apk add git build-base pkgconfig
            ;;
        *)
            die "Automatic installation not supported for $pm"
            ;;
    esac
}

install_from_source() {
    local prefix=$1

    print_step "Building from source"

    # Check build dependencies
    if ! check_build_dependencies; then
        die "Missing build dependencies"
    fi

    # Check Rust
    if ! check_rust; then
        install_rust
    fi

    # Create build directory
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Clone repository
    if ! run_with_spinner "  Cloning repository..." git clone --depth 1 "https://github.com/${REPO_OWNER}/${REPO_NAME}.git" carrier; then
        die "Failed to clone repository"
    fi

    cd carrier

    # Build
    if ! run_with_spinner "  Building (this may take a few minutes)..." cargo build --release; then
        die "Build failed"
    fi

    if [ ! -f "target/release/$BINARY_NAME" ]; then
        die "Binary not found after build"
    fi

    # Install binary
    local bin_dir="$prefix/bin"
    printf "  Installing to %s..." "$bin_dir"

    if [ ! -d "$bin_dir" ]; then
        need_sudo mkdir -p "$bin_dir"
    fi

    if need_sudo cp "target/release/$BINARY_NAME" "$bin_dir/" && need_sudo chmod 755 "$bin_dir/$BINARY_NAME"; then
        echo -e " ${GREEN}done${NC}"
    else
        die "Failed to install binary"
    fi

    print_success "Built and installed successfully"
}

# ============================================================================
# Runtime Dependencies
# ============================================================================

install_runtime_dependencies() {
    print_step "Installing runtime dependencies"

    local pm
    pm=$(detect_package_manager)
    print_verbose "Package manager: $pm"

    local packages
    case "$pm" in
        apt)
            packages="runc fuse-overlayfs fuse3 slirp4netns uidmap util-linux"
            # Try to install passt if available
            if apt-cache show passt >/dev/null 2>&1; then
                packages="$packages passt"
            fi
            ;;
        dnf|yum)
            packages="runc fuse-overlayfs fuse3 slirp4netns shadow-utils util-linux"
            if dnf info passt >/dev/null 2>&1; then
                packages="$packages passt"
            fi
            ;;
        pacman)
            packages="runc fuse-overlayfs fuse3 slirp4netns shadow util-linux"
            # passt may be in AUR
            ;;
        zypper)
            packages="runc fuse-overlayfs fuse3 slirp4netns shadow util-linux"
            ;;
        apk)
            packages="runc fuse-overlayfs fuse3 slirp4netns shadow util-linux"
            ;;
        *)
            print_warning "Cannot install runtime dependencies automatically for $pm"
            print_info "Please install manually: runc, fuse-overlayfs, slirp4netns, uidmap"
            return 0
            ;;
    esac

    print_info "Installing: $packages"

    if ! confirm "Install runtime dependencies?"; then
        print_info "Skipping runtime dependencies"
        return 0
    fi

    case "$pm" in
        apt)
            need_sudo apt-get update
            # shellcheck disable=SC2086
            need_sudo apt-get install -y $packages
            ;;
        dnf)
            # shellcheck disable=SC2086
            need_sudo dnf install -y $packages
            ;;
        yum)
            # shellcheck disable=SC2086
            need_sudo yum install -y $packages
            ;;
        pacman)
            # shellcheck disable=SC2086
            need_sudo pacman -Sy --noconfirm $packages
            ;;
        zypper)
            # shellcheck disable=SC2086
            need_sudo zypper install -y $packages
            ;;
        apk)
            # shellcheck disable=SC2086
            need_sudo apk add $packages
            ;;
    esac

    # Post-install configuration
    post_install_configuration

    print_success "Runtime dependencies installed"
}

post_install_configuration() {
    print_verbose "Running post-install configuration"

    # Load fuse module
    need_sudo modprobe fuse 2>/dev/null || true

    # Set SUID bits
    local suid_binaries="/usr/bin/fusermount3 /usr/bin/fusermount /bin/fusermount3 /bin/fusermount /usr/bin/newuidmap /usr/bin/newgidmap"
    for bin in $suid_binaries; do
        if [ -f "$bin" ]; then
            local mode
            mode=$(stat -c %a "$bin" 2>/dev/null || stat -f %p "$bin" 2>/dev/null)
            if [ -n "$mode" ] && [ $((mode & 4000)) -eq 0 ]; then
                print_verbose "Setting SUID bit on $bin"
                need_sudo chmod u+s "$bin" 2>/dev/null || true
            fi
        fi
    done

    # Setup subuid/subgid if needed
    local username
    username=${USER:-$(whoami)}

    if [ "$username" != "root" ]; then
        if [ -f /etc/subuid ] && ! grep -q "^${username}:" /etc/subuid 2>/dev/null; then
            print_verbose "Configuring /etc/subuid for $username"
            need_sudo usermod --add-subuids 100000-165535 "$username" 2>/dev/null || \
                echo "${username}:100000:65536" | need_sudo tee -a /etc/subuid >/dev/null
        fi

        if [ -f /etc/subgid ] && ! grep -q "^${username}:" /etc/subgid 2>/dev/null; then
            print_verbose "Configuring /etc/subgid for $username"
            need_sudo usermod --add-subgids 100000-165535 "$username" 2>/dev/null || \
                echo "${username}:100000:65536" | need_sudo tee -a /etc/subgid >/dev/null
        fi
    fi
}

# ============================================================================
# Shell Completions
# ============================================================================

install_shell_completions() {
    print_step "Installing shell completions"

    local carrier_bin="$PREFIX/bin/carrier"
    if [ ! -x "$carrier_bin" ]; then
        carrier_bin=$(command -v carrier 2>/dev/null)
    fi

    if [ -z "$carrier_bin" ] || [ ! -x "$carrier_bin" ]; then
        print_warning "Cannot find carrier binary, skipping completions"
        return 0
    fi

    # Install bash completions
    if command_exists bash; then
        local bash_comp_dir
        if [ -d /etc/bash_completion.d ] && check_root; then
            bash_comp_dir="/etc/bash_completion.d"
        elif [ -d "$HOME/.local/share/bash-completion/completions" ]; then
            bash_comp_dir="$HOME/.local/share/bash-completion/completions"
        else
            mkdir -p "$HOME/.local/share/bash-completion/completions"
            bash_comp_dir="$HOME/.local/share/bash-completion/completions"
        fi

        if "$carrier_bin" completions bash > "$bash_comp_dir/carrier" 2>/dev/null; then
            print_verbose "Bash completions installed to $bash_comp_dir/carrier"
        fi
    fi

    # Install zsh completions
    if command_exists zsh; then
        local zsh_comp_dir
        if [ -d /usr/share/zsh/site-functions ] && check_root; then
            zsh_comp_dir="/usr/share/zsh/site-functions"
        elif [ -d "$HOME/.zsh/completions" ]; then
            zsh_comp_dir="$HOME/.zsh/completions"
        else
            mkdir -p "$HOME/.zsh/completions"
            zsh_comp_dir="$HOME/.zsh/completions"
        fi

        if "$carrier_bin" completions zsh > "$zsh_comp_dir/_carrier" 2>/dev/null; then
            print_verbose "Zsh completions installed to $zsh_comp_dir/_carrier"
        fi
    fi

    # Install fish completions
    if command_exists fish; then
        local fish_comp_dir
        if [ -d /usr/share/fish/vendor_completions.d ] && check_root; then
            fish_comp_dir="/usr/share/fish/vendor_completions.d"
        elif [ -d "$HOME/.config/fish/completions" ]; then
            fish_comp_dir="$HOME/.config/fish/completions"
        else
            mkdir -p "$HOME/.config/fish/completions"
            fish_comp_dir="$HOME/.config/fish/completions"
        fi

        if "$carrier_bin" completions fish > "$fish_comp_dir/carrier.fish" 2>/dev/null; then
            print_verbose "Fish completions installed to $fish_comp_dir/carrier.fish"
        fi
    fi

    print_success "Shell completions installed"
}

# ============================================================================
# Update Command
# ============================================================================

update_carrier() {
    print_step "Checking for updates"

    local current_version latest_version
    current_version=$(get_current_version)
    latest_version=$(get_latest_version)

    if [ -z "$latest_version" ]; then
        die "Could not determine latest version"
    fi

    if [ -z "$current_version" ]; then
        print_info "Carrier is not currently installed"
        if confirm "Install Carrier now?"; then
            do_install
        fi
        return
    fi

    print_info "Current version: $current_version"
    print_info "Latest version:  $latest_version"

    if [ "$current_version" = "$latest_version" ]; then
        print_success "Already up to date"
        return 0
    fi

    if ! confirm "Update to version $latest_version?"; then
        print_info "Update cancelled"
        return 0
    fi

    # Try binary update first
    if [ "$INSTALL_MODE" != "source" ]; then
        if try_binary_install "$PREFIX"; then
            print_success "Updated to version $latest_version"
            return 0
        elif [ "$INSTALL_MODE" = "binary" ]; then
            die "Binary download failed"
        fi
    fi

    # Fall back to source
    install_from_source "$PREFIX"
    print_success "Updated to version $latest_version"
}

# ============================================================================
# Uninstall Command
# ============================================================================

uninstall_carrier() {
    print_step "Uninstalling Carrier"

    local bin_path="$PREFIX/bin/$BINARY_NAME"

    if [ ! -f "$bin_path" ]; then
        # Try to find it
        bin_path=$(command -v carrier 2>/dev/null)
        if [ -z "$bin_path" ]; then
            print_warning "Carrier is not installed"
            return 0
        fi
    fi

    if ! confirm "Remove $bin_path?"; then
        print_info "Uninstall cancelled"
        return 0
    fi

    if need_sudo rm -f "$bin_path"; then
        print_success "Removed $bin_path"
    else
        die "Failed to remove $bin_path"
    fi

    # Remove completions
    rm -f /etc/bash_completion.d/carrier 2>/dev/null || true
    rm -f "$HOME/.local/share/bash-completion/completions/carrier" 2>/dev/null || true
    rm -f /usr/share/zsh/site-functions/_carrier 2>/dev/null || true
    rm -f "$HOME/.zsh/completions/_carrier" 2>/dev/null || true
    rm -f /usr/share/fish/vendor_completions.d/carrier.fish 2>/dev/null || true
    rm -f "$HOME/.config/fish/completions/carrier.fish" 2>/dev/null || true

    # Ask about config directories
    if [ -d "$HOME/.local/share/carrier" ] || [ -d "$HOME/.config/carrier" ]; then
        print_info "Configuration directories found:"
        [ -d "$HOME/.local/share/carrier" ] && print_info "  $HOME/.local/share/carrier"
        [ -d "$HOME/.config/carrier" ] && print_info "  $HOME/.config/carrier"

        if confirm "Remove configuration directories?"; then
            rm -rf "$HOME/.local/share/carrier" "$HOME/.config/carrier"
            print_success "Configuration directories removed"
        fi
    fi

    print_success "Carrier uninstalled"
}

# ============================================================================
# Main Commands
# ============================================================================

do_install() {
    local binary_installed=false

    # Check for existing installation
    if command_exists carrier; then
        local current
        current=$(get_current_version)
        print_warning "Carrier $current is already installed"
        if ! confirm "Reinstall?"; then
            print_info "Installation cancelled"
            return 0
        fi
    fi

    # Try binary install first (unless --source)
    if [ "$INSTALL_MODE" != "source" ]; then
        if try_binary_install "$PREFIX"; then
            binary_installed=true
        elif [ "$INSTALL_MODE" = "binary" ]; then
            die "Binary download failed and --binary was specified"
        else
            print_info "Pre-built binary not available, building from source..."
        fi
    fi

    # Fall back to source build
    if [ "$binary_installed" = false ]; then
        install_from_source "$PREFIX"
    fi

    # Install completions
    if [ "$INSTALL_COMPLETIONS" = true ]; then
        install_shell_completions
    fi

    # Install runtime dependencies
    if [ "$INSTALL_DEPS" = true ]; then
        install_runtime_dependencies
    fi

    # Verify installation
    print_step "Verifying installation"

    local bin_path="$PREFIX/bin/$BINARY_NAME"
    if [ -x "$bin_path" ]; then
        print_success "Carrier installed to $bin_path"

        # Check PATH
        if ! echo "$PATH" | grep -q "$PREFIX/bin"; then
            print_warning "$PREFIX/bin is not in your PATH"
            print_info "Add it with: export PATH=\"$PREFIX/bin:\$PATH\""
        fi

        # Show version
        local version
        version=$("$bin_path" --version 2>/dev/null | awk '{print $2}')
        print_info "Version: $version"

        echo
        print_success "Installation complete!"
        print_info "Run 'carrier --help' to get started"
        print_info "Run 'carrier doctor' to verify dependencies"
    else
        die "Installation verification failed"
    fi
}

cleanup() {
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
}

trap cleanup EXIT

show_help() {
    cat << 'EOF'
Carrier Installation Script

Usage: setup.sh [COMMAND] [OPTIONS]

Commands:
  install       Install Carrier (default)
  uninstall     Remove Carrier from system
  update        Update to latest version
  deps          Install runtime dependencies only
  completions   Install shell completions only

Options:
  --binary          Force binary download (skip source build)
  --source          Force source build (skip binary download)
  --prefix PATH     Install to custom directory (default: /usr/local)
  --no-deps         Skip runtime dependency installation
  --no-completions  Skip shell completion installation
  -y, --yes         Skip confirmation prompts
  -v, --verbose     Show detailed output
  -h, --help        Show this help message

Examples:
  # Quick install (downloads binary, installs deps)
  curl -LsSf https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh

  # Install to custom directory
  ./setup.sh install --prefix ~/.local

  # Install without runtime dependencies
  ./setup.sh install --no-deps

  # Update to latest version
  ./setup.sh update

  # Force source build
  ./setup.sh install --source

  # Uninstall
  ./setup.sh uninstall
EOF
}

print_banner() {
    echo -e "${BOLD}${CYAN}"
    cat << 'EOF'
   ____                _
  / ___|__ _ _ __ _ __(_) ___ _ __
 | |   / _` | '__| '__| |/ _ \ '__|
 | |__| (_| | |  | |  | |  __/ |
  \____\__,_|_|  |_|  |_|\___|_|

EOF
    echo -e "${NC}"
    echo "Carrier Installation Script"
    echo "============================"
    echo
}

main() {
    local command="install"

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            install|uninstall|update|deps|completions)
                command="$1"
                shift
                ;;
            --binary)
                INSTALL_MODE="binary"
                shift
                ;;
            --source)
                INSTALL_MODE="source"
                shift
                ;;
            --prefix)
                PREFIX="$2"
                shift 2
                ;;
            --prefix=*)
                PREFIX="${1#*=}"
                shift
                ;;
            --no-deps)
                INSTALL_DEPS=false
                shift
                ;;
            --no-completions)
                INSTALL_COMPLETIONS=false
                shift
                ;;
            -y|--yes)
                YES=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    print_banner

    case "$command" in
        install)
            print_info "Starting installation"
            do_install
            ;;
        uninstall)
            uninstall_carrier
            ;;
        update)
            update_carrier
            ;;
        deps)
            install_runtime_dependencies
            ;;
        completions)
            install_shell_completions
            ;;
        *)
            print_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
