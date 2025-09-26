# Getting Started with Carrier

## Installation

### Building from Source
```bash
# Clone the repository
git clone https://github.com/yourusername/carrier
cd carrier

# Build in release mode
cargo build --release

# Binary will be at ./target/release/carrier
```

### Create Alias for Easy Use
```bash
# Add to ~/.bashrc or ~/.zshrc
alias carrier='./target/release/carrier'

# Or create a symlink
sudo ln -s $(pwd)/target/release/carrier /usr/local/bin/carrier
```

## Basic Usage

### 1. Pull and Run Your First Container

```bash
# Pull and run interactively
carrier run alpine

# You'll get a shell inside the container
/ # echo "Hello from container!"
/ # exit
```

### 2. Run a Web Server in Background

```bash
# Run nginx in detached mode
carrier run -d nginx

# List running containers
carrier ls -c

# Check it's running
carrier sh <container-id> ps aux
```

### 3. Execute Commands in Running Containers

```bash
# Get a shell in the running nginx container
carrier sh <container-id>

# Or run a specific command
carrier sh <container-id> nginx -v
carrier sh <container-id> cat /etc/nginx/nginx.conf
```

### 4. Stop and Clean Up

```bash
# Stop a running container
carrier stop <container-id>

# Remove a stopped container
carrier rm <container-id>

# Remove all stopped containers at once
carrier rm -c
```

## Common Workflows

### Development Workflow

```bash
# Run a development environment
carrier run -d ubuntu

# Install tools in the container
carrier sh <container-id> apt update
carrier sh <container-id> apt install -y python3

# Run your code
carrier sh <container-id> python3 -c "print('Hello World')"

# Stop when done
carrier stop <container-id>
```

### Service Testing

```bash
# Run a database
carrier run -d postgres

# Check logs (if implemented)
carrier logs <container-id>

# Connect and test
carrier sh <container-id> psql -U postgres

# Clean up
carrier stop <container-id>
carrier rm <container-id>
```

### Quick Experiments

```bash
# Test something quickly
carrier run alpine apk add curl
carrier sh <container-id> curl https://example.com

# Try different distributions
carrier run ubuntu cat /etc/os-release
carrier run fedora dnf --version
carrier run debian apt --version
```

## Container Management

### Listing Containers and Images

```bash
# Show everything
carrier ls

# Show only images
carrier ls -i

# Show only running containers
carrier ls -c

# Show all containers (including stopped)
carrier ls -c -a
```

### Removing Resources

```bash
# Remove specific image
carrier rm nginx:latest

# Remove by image ID
carrier rm e1fbd49323c6

# Remove all stopped containers
carrier rm -c

# Force remove (even if running)
carrier rm --force <container-id>
```

## Tips and Tricks

### 1. Use Partial IDs
```bash
# Instead of full ID
carrier stop 2gjn6dcbfuwg

# You can use partial ID
carrier stop 2gj
```

### 2. Run Without Warnings
```bash
# Use environment variable
RUSTFLAGS=-Awarnings cargo run --bin carrier -- ls

# Or use the release binary
./target/release/carrier ls
```

### 3. Quick Shell Access
```bash
# Default command is /bin/sh
carrier sh <container-id>

# Is equivalent to
carrier sh <container-id> /bin/sh
```

### 4. Check Container Status
```bash
# See which containers are running
carrier ls -c

# See all containers with their status
carrier ls -c -a
```

## Supported Registries

Carrier can pull from multiple registries:

```bash
# Docker Hub (default)
carrier run alpine
carrier run nginx:latest

# Quay.io
carrier run quay.io/prometheus/prometheus

# GitHub Container Registry
carrier run ghcr.io/owner/image:tag

# Google Container Registry
carrier run gcr.io/project/image:tag

# Amazon ECR Public
carrier run public.ecr.aws/nginx/nginx:latest
```

## Troubleshooting

### Container Won't Start
- Check if image was pulled: `carrier ls -i`
- Try running interactively to see errors: `carrier run <image>`

### Permission Denied
- For shell/exec: Ensure `nsenter` is installed
- Some operations may need elevated privileges

### Container Still Running
- Check running containers: `carrier ls -c`
- Force stop if needed: `carrier stop --force <id>`

### Can't Remove Image
- Check if containers are using it: `carrier ls -c -a`
- Force remove: `carrier rm --force <image>`

## Next Steps

- Read the [Commands Documentation](commands.md) for detailed command reference
- Learn about the [Runtime Architecture](runtime.md)
- Understand [Storage Layout](storage.md)
- Explore [Shell/Exec Features](shell.md)