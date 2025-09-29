#!/bin/bash

# Carrier Installation Script
# Usage:
#   curl -LsSf https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh
#   wget -qO- https://raw.githubusercontent.com/javanhut/carrier/main/setup.sh | sh
#   ./setup.sh [install|uninstall]

set -e

# Configuration
REPO_URL="https://github.com/javanhut/Carrier"
REPO_NAME="carrier"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="carrier"
BUILD_DIR="/tmp/carrier-build-$$"
REQUIRED_RUST_VERSION="1.70.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Helper functions
print_error() {
    echo -e "${RED}error${NC}: $1" >&2
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_info() {
    echo -e "${CYAN}info${NC}: $1"
}

print_warning() {
    echo -e "${YELLOW}warning${NC}: $1"
}

print_step() {
    echo -e "${BOLD}==> $1${NC}"
}

# Check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

# Check command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Version comparison
version_ge() {
    [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        VER=$(lsb_release -sr)
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi

    echo "$OS"
}

# Check and install Rust
check_rust() {
    print_step "Checking Rust installation"

    if command_exists rustc && command_exists cargo; then
        RUST_VERSION=$(rustc --version | cut -d' ' -f2)
        if version_ge "$RUST_VERSION" "$REQUIRED_RUST_VERSION"; then
            print_success "Rust $RUST_VERSION is installed"
            return 0
        else
            print_warning "Rust $RUST_VERSION is installed but version $REQUIRED_RUST_VERSION or higher is required"
            return 1
        fi
    else
        print_warning "Rust is not installed"
        return 1
    fi
}

install_rust() {
    print_step "Installing Rust"

    if [ -t 0 ]; then
        # Interactive installation
        print_info "This will install Rust using rustup"
        read -p "Do you want to continue? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_error "Rust installation cancelled"
            exit 1
        fi
    fi

    # Download and install rustup
    if command_exists curl; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    elif command_exists wget; then
        wget -qO- https://sh.rustup.rs | sh -s -- -y
    else
        print_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    # Source cargo env
    if [ -f "$HOME/.cargo/env" ]; then
        . "$HOME/.cargo/env"
    else
        export PATH="$HOME/.cargo/bin:$PATH"
    fi

    # Verify installation
    if command_exists rustc && command_exists cargo; then
        print_success "Rust installed successfully"
    else
        print_error "Rust installation failed"
        exit 1
    fi
}

# Check system dependencies
check_dependencies() {
    print_step "Checking system dependencies"

    local missing_deps=()

    # Check for git
    if ! command_exists git; then
        missing_deps+=("git")
    fi

    # Check for essential build tools
    if ! command_exists cc && ! command_exists gcc && ! command_exists clang; then
        missing_deps+=("build-essential or gcc or clang")
    fi

    # Check for pkg-config
    if ! command_exists pkg-config; then
        missing_deps+=("pkg-config")
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"

        local os=$(detect_os)
        case "$os" in
            ubuntu|debian)
                print_info "Install with: sudo apt-get update && sudo apt-get install -y git build-essential pkg-config"
                ;;
            fedora|rhel|centos)
                print_info "Install with: sudo dnf install -y git gcc pkg-config"
                ;;
            arch|manjaro)
                print_info "Install with: sudo pacman -Sy git base-devel pkg-config"
                ;;
            *)
                print_info "Please install: ${missing_deps[*]}"
                ;;
        esac

        if [ -t 0 ]; then
            read -p "Do you want to try to install dependencies automatically? [y/N] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                install_dependencies "$os"
            else
                exit 1
            fi
        else
            exit 1
        fi
    else
        print_success "All dependencies are installed"
    fi
}

install_dependencies() {
    local os=$1

    if ! check_root; then
        print_error "Root privileges required to install dependencies"
        exit 1
    fi

    case "$os" in
        ubuntu|debian)
            apt-get update && apt-get install -y git build-essential pkg-config
            ;;
        fedora|rhel|centos)
            dnf install -y git gcc pkg-config
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm git base-devel pkg-config
            ;;
        *)
            print_error "Automatic installation not supported for $os"
            exit 1
            ;;
    esac
}

# Download and build Carrier
build_carrier() {
    print_step "Downloading Carrier source code"

    # Create temporary build directory
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Clone repository
    if ! git clone "$REPO_URL" "$REPO_NAME"; then
        print_error "Failed to clone repository from $REPO_URL"
        print_info "Please check that the repository URL is correct"
        cleanup
        exit 1
    fi

    cd "$REPO_NAME"

    print_step "Building Carrier (this may take a few minutes)"

    # Build with cargo
    if ! cargo build --release; then
        print_error "Build failed"
        cleanup
        exit 1
    fi

    if [ ! -f "target/release/$BINARY_NAME" ]; then
        print_error "Binary not found after build"
        cleanup
        exit 1
    fi

    print_success "Carrier built successfully"
}

# Install Carrier
install_carrier() {
    print_step "Installing Carrier to $INSTALL_DIR"

    if ! check_root; then
        print_warning "Root privileges required to install to $INSTALL_DIR"
        print_info "You may be prompted for your password"

        # Try with sudo
        if command_exists sudo; then
            sudo cp "$BUILD_DIR/$REPO_NAME/target/release/$BINARY_NAME" "$INSTALL_DIR/"
            sudo chmod 755 "$INSTALL_DIR/$BINARY_NAME"
        else
            print_error "sudo not available. Please run as root or install to a user directory"
            cleanup
            exit 1
        fi
    else
        cp "$BUILD_DIR/$REPO_NAME/target/release/$BINARY_NAME" "$INSTALL_DIR/"
        chmod 755 "$INSTALL_DIR/$BINARY_NAME"
    fi

    # Verify installation
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        print_success "Carrier installed successfully to $INSTALL_DIR/$BINARY_NAME"

        # Check if install dir is in PATH
        if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
            print_warning "$INSTALL_DIR is not in your PATH"
            print_info "Add it to your PATH by running:"
            print_info "  export PATH=\"$INSTALL_DIR:\$PATH\""
        fi

        # Test the binary
        if command_exists "$BINARY_NAME"; then
            print_info "Version: $($BINARY_NAME --version 2>/dev/null || echo 'unknown')"
        fi
    else
        print_error "Installation verification failed"
        cleanup
        exit 1
    fi
}

# Uninstall Carrier
uninstall_carrier() {
    print_step "Uninstalling Carrier"

    if [ ! -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        print_warning "Carrier is not installed at $INSTALL_DIR/$BINARY_NAME"
        return 0
    fi

    if ! check_root; then
        print_warning "Root privileges required to uninstall from $INSTALL_DIR"
        if command_exists sudo; then
            sudo rm -f "$INSTALL_DIR/$BINARY_NAME"
        else
            print_error "sudo not available. Please run as root"
            exit 1
        fi
    else
        rm -f "$INSTALL_DIR/$BINARY_NAME"
    fi

    if [ ! -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        print_success "Carrier uninstalled successfully"

        # Check for config/data directories
        if [ -d "$HOME/.carrier" ] || [ -d "$HOME/.config/carrier" ]; then
            print_info "Configuration directories found:"
            [ -d "$HOME/.carrier" ] && print_info "  $HOME/.carrier"
            [ -d "$HOME/.config/carrier" ] && print_info "  $HOME/.config/carrier"

            if [ -t 0 ]; then
                read -p "Do you want to remove configuration directories? [y/N] " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    rm -rf "$HOME/.carrier" "$HOME/.config/carrier"
                    print_success "Configuration directories removed"
                fi
            fi
        fi
    else
        print_error "Failed to uninstall Carrier"
        exit 1
    fi
}

# Cleanup function
cleanup() {
    if [ -d "$BUILD_DIR" ]; then
        print_info "Cleaning up build directory"
        rm -rf "$BUILD_DIR"
    fi
}

# Trap cleanup on exit
trap cleanup EXIT

# Main installation flow
main() {
    echo -e "${BOLD}${CYAN}Carrier Installation Script${NC}"
    echo "=============================="
    echo

    # Parse command line arguments
    case "${1:-install}" in
        install)
            print_info "Starting installation process"

            # Check dependencies
            check_dependencies

            # Check and install Rust if needed
            if ! check_rust; then
                install_rust
            fi

            # Build and install Carrier
            build_carrier
            install_carrier

            echo
            print_success "Installation complete!"
            print_info "Run 'carrier --help' to get started"
            ;;

        uninstall)
            print_info "Starting uninstallation process"
            uninstall_carrier
            ;;

        *)
            print_error "Unknown command: $1"
            print_info "Usage: $0 [install|uninstall]"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
