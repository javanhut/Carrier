#!/usr/bin/env bash
# Build the guest initramfs: the agent (PID 1) + static runc + a baked Alpine OCI
# bundle, so the VM can actually `runc run` a container with no virtiofs / no
# guest network. Cross-compiles the agent with rust-lld (no external toolchain).
# The baked bundle is a proof artifact — host-prepared bundles over virtiofs
# replace it for dynamic images.
#
#   rustup target add aarch64-unknown-linux-musl   # one-time
#   vmagent/build.sh
set -euo pipefail
cd "$(dirname "$0")"

TARGET=aarch64-unknown-linux-musl
ALPINE=https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/alpine-minirootfs-3.24.1-aarch64.tar.gz
RUNC=https://github.com/opencontainers/runc/releases/download/v1.5.0/runc.arm64
VMDIR="$HOME/.local/share/carrier/vm"

RUSTFLAGS="-C linker=rust-lld" cargo build --release --target "$TARGET"

rm -rf build/root && mkdir -p build/root/bin build/root/bundle/rootfs
cp "target/$TARGET/release/vmagent" build/root/init && chmod +x build/root/init

# cache downloads so re-runs are fast
[ -f build/runc.arm64 ] || curl -fsSL -o build/runc.arm64 "$RUNC"
[ -f build/alpine.tar.gz ] || curl -fsSL -o build/alpine.tar.gz "$ALPINE"
cp build/runc.arm64 build/root/bin/runc && chmod +x build/root/bin/runc
tar xzf build/alpine.tar.gz -C build/root/bundle/rootfs 2>/dev/null

# Minimal OCI spec: run a shell that proves the container is real.
cat > build/root/bundle/config.json <<'JSON'
{
  "ociVersion": "1.0.2",
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "args": ["/bin/sh", "-c", "echo HELLO_FROM_CONTAINER; uname -a; cat /etc/alpine-release; id"],
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
      "effective": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
      "permitted": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"]
    },
    "noNewPrivileges": true
  },
  "root": { "path": "rootfs", "readonly": false },
  "hostname": "carrier",
  "mounts": [
    { "destination": "/proc", "type": "proc", "source": "proc" },
    { "destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] },
    { "destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"] }
  ],
  "linux": {
    "namespaces": [
      { "type": "pid" }, { "type": "ipc" }, { "type": "uts" }, { "type": "mount" }
    ]
  }
}
JSON

( cd build/root && find . | cpio -o -H newc 2>/dev/null ) | gzip > "$VMDIR/initramfs.cpio.gz"
echo "installed guest initramfs ($(du -h "$VMDIR/initramfs.cpio.gz" | cut -f1)) -> $VMDIR/initramfs.cpio.gz"
