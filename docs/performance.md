# Carrier Performance Guide

## Overview

Carrier has been optimized for fast container startup times, achieving sub-100ms container runs for simple workloads. This document covers performance characteristics, optimizations, and troubleshooting.

## Performance Benchmarks

### Container Run Time

Tested with `alpine:latest` running `echo "test"`:

| Metric | Time (avg) | Range |
|--------|-----------|-------|
| Container run | ~47ms | 42-66ms |
| With cold cache | ~150ms | 144-239ms |

Comparison with other runtimes (from benchmarks):
- **Carrier**: 150ms (avg)
- **Podman**: 274ms (avg)
- **Docker**: 312ms (avg)

## Storage Drivers

Carrier supports three storage drivers with different performance characteristics:

### 1. OverlayFS (FUSE) - Default & Recommended

**Performance**: Fastest (no file copying)
**Requirements**: `fuse-overlayfs` package installed

```bash
carrier run --storage-driver overlay-fuse alpine:latest
```

**Pros**:
- No data copying
- Fast startup
- Space efficient
- Works rootless

**Cons**:
- Requires fuse-overlayfs package
- Slightly higher runtime overhead than native overlay

### 2. OverlayFS (Native)

**Performance**: Fastest (when available)
**Requirements**: Kernel 5.11+ with unprivileged overlay support

```bash
carrier run --storage-driver overlay-native alpine:latest
```

**Pros**:
- Zero overhead
- Maximum performance
- No extra packages

**Cons**:
- Requires modern kernel
- May not work on all systems
- Needs specific kernel configuration

### 3. VFS (Copy-on-Write Fallback)

**Performance**: Slowest (copies entire filesystem)
**Requirements**: None

```bash
carrier run --storage-driver vfs alpine:latest
```

**Pros**:
- Works everywhere
- No external dependencies
- Maximum compatibility

**Cons**:
- Copies entire rootfs on every run
- High disk I/O
- Slower startup (500ms-2s for typical images)
- Higher disk space usage

## Automatic Driver Selection

Carrier automatically selects the best available storage driver:

1. **OverlayFS (FUSE)** - Preferred default (requires fuse-overlayfs)
2. **OverlayFS (Native)** - If kernel supports it
3. **VFS** - Last resort fallback

### Checking Active Driver

View the active storage driver in container info:

```bash
carrier info <container-id>
```

Look for the `Storage:` field showing `overlay(fuse)`, `overlay(native)`, or `vfs`.

## Performance Optimizations

### 1. Layer Caching

Carrier caches image layers in `~/.local/share/carrier/storage/`:
- Layers are extracted once and reused
- Blob downloads are cached
- Manifests are stored locally

### 2. Overlay Reuse

For already-mounted overlays, Carrier skips remounting, significantly improving repeated container starts.

### 3. Essential File Setup

Only creates directories and files that don't exist, avoiding redundant I/O:
- `/etc/resolv.conf` (if missing)
- `/etc/hosts` (if missing)  
- Essential directories (`/tmp`, `/var`, etc.)

### 4. Optimized VFS Mode

When VFS fallback is required:
- Uses `cp -a` command for bulk copying (faster than individual file operations)
- Falls back to recursive copy only if `cp` fails
- Skips special directories (`/dev`, `/proc`, `/sys`)

## Troubleshooting Slow Performance

### Issue: Carrier is falling back to VFS mode

**Symptoms**:
```
overlay mount failed; using vfs fallback
Falling back to vfs (copy) backend
```

**Solutions**:

1. Install fuse-overlayfs:
   ```bash
   # Ubuntu/Debian
   sudo apt install fuse-overlayfs
   
   # Fedora
   sudo dnf install fuse-overlayfs
   
   # Arch
   sudo pacman -S fuse-overlayfs
   ```

2. Verify `/dev/fuse` exists:
   ```bash
   ls -la /dev/fuse
   ```
   
   If missing:
   ```bash
   sudo modprobe fuse
   ```

3. Check fusermount3 permissions:
   ```bash
   ls -la /usr/bin/fusermount3
   ```
   
   Should show setuid bit: `-rwsr-xr-x`
   
   If not:
   ```bash
   sudo chmod u+s /usr/bin/fusermount3
   ```

### Issue: Native overlay fails with EPERM

**Symptoms**:
```
native overlay mount failed: EPERM: Operation not permitted
```

**Cause**: Kernel doesn't support unprivileged overlayfs

**Solution**: Use fuse-overlayfs (default) or force VFS:
```bash
carrier run --storage-driver overlay-fuse alpine:latest
```

### Issue: Slow image pulls

**Cause**: Network latency or registry throttling

**Solutions**:
1. Use image caching - pull once, run many times
2. Consider using a local registry mirror
3. Check registry authentication (authenticated pulls may be faster)

## Best Practices

1. **Pull images ahead of time** for fastest run times:
   ```bash
   carrier pull alpine:latest
   carrier run alpine:latest
   ```

2. **Reuse containers** instead of creating new ones:
   ```bash
   carrier run -d --name myapp alpine:latest
   carrier sh myapp
   ```

3. **Use smaller base images**:
   - `alpine:latest` (~7MB)
   - `busybox:latest` (~2MB)
   - `scratch` for static binaries

4. **Clean up stopped containers** to free disk space:
   ```bash
   carrier rm --all-containers
   ```

5. **Monitor storage usage**:
   ```bash
   du -sh ~/.local/share/carrier/storage/
   ```

## System Requirements

### Minimum
- Linux kernel 4.18+
- 512MB RAM
- 1GB free disk space

### Recommended for Best Performance
- Linux kernel 5.11+
- 2GB RAM
- SSD storage
- fuse-overlayfs installed

## Performance Tips

1. **Use SSD storage** - Carrier benefits greatly from fast I/O
2. **Enable kernel optimizations** - Ensure user namespaces are enabled
3. **Regular cleanup** - Remove old containers and unused images
4. **Batch operations** - Pull multiple images at once when possible

## Monitoring Performance

### Measure container startup time
```bash
time carrier run alpine:latest echo "test"
```

### Check active mounts
```bash
mount | grep carrier
```

### View storage driver in use
```bash
carrier info <container-id> | grep Storage
```

## Known Limitations

1. **VFS mode disk usage** - Each container creates a full copy of the rootfs
2. **FUSE overhead** - Slight runtime performance penalty vs native overlay
3. **Layer extraction** - First run after pull is slower (one-time cost)

## Future Optimizations

Planned improvements:
- Parallel layer extraction during pull
- Shared base layer deduplication
- Memory-backed temporary storage option
- Layer compression/decompression optimization