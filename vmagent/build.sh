#!/usr/bin/env bash
# Cross-compile the guest agent to a static aarch64 Linux binary and pack it as
# an initramfs (the agent IS /init), installed next to the kernel in
# ~/.local/share/carrier/vm. No external toolchain — Rust's rust-lld links musl.
#
#   rustup target add aarch64-unknown-linux-musl   # one-time
#   vmagent/build.sh
set -euo pipefail
cd "$(dirname "$0")"

TARGET=aarch64-unknown-linux-musl
RUSTFLAGS="-C linker=rust-lld" cargo build --release --target "$TARGET"

VMDIR="$HOME/.local/share/carrier/vm"
mkdir -p "$VMDIR" build/root
cp "target/$TARGET/release/vmagent" build/root/init
chmod +x build/root/init
# newc cpio with `init` at the root, gzipped — what VZ feeds as the initrd.
( cd build/root && find . | cpio -o -H newc 2>/dev/null ) | gzip > "$VMDIR/initramfs.cpio.gz"
echo "installed agent initramfs -> $VMDIR/initramfs.cpio.gz"
