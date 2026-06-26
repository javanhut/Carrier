#!/usr/bin/env bash
# Build the embeddable guest artifacts for one architecture into
# vmagent/artifacts/<rust-arch>/ : a runc-capable Kata kernel + an agent
# initramfs (PID-1 agent + static runc). build.rs embeds these into the carrier
# binary so a fresh install runs containers with no download / no toolchain.
# The container rootfs is NOT baked — prepare_bundle pulls it per `carrier run`.
#
# Cross-compiles the agent with rust-lld (no external toolchain).
#   vmagent/build.sh [aarch64|x86_64]      # default: host arch
set -euo pipefail
cd "$(dirname "$0")"

case "${1:-$(uname -m)}" in
  arm64|aarch64) RUST_ARCH=aarch64; OCI=arm64 ;;
  x86_64|amd64)  RUST_ARCH=x86_64;  OCI=amd64 ;;
  *) echo "unsupported arch: ${1:-$(uname -m)}" >&2; exit 1 ;;
esac
TARGET="$RUST_ARCH-unknown-linux-musl"
KATA_VER=3.32.0
KATA_KERNEL=./opt/kata/share/kata-containers/vmlinux-6.18.35-197
RUNC="https://github.com/opencontainers/runc/releases/download/v1.5.0/runc.$OCI"
OUT="artifacts/$RUST_ARCH"

rustup target add "$TARGET" >/dev/null 2>&1 || true
RUSTFLAGS="-C linker=rust-lld" cargo build --release --target "$TARGET"

rm -rf "build/$RUST_ARCH" && mkdir -p "build/$RUST_ARCH/root/bin" "$OUT"
cp "target/$TARGET/release/vmagent" "build/$RUST_ARCH/root/init" && chmod +x "build/$RUST_ARCH/root/init"
[ -f "build/runc.$OCI" ] || curl -fsSL -o "build/runc.$OCI" "$RUNC"
cp "build/runc.$OCI" "build/$RUST_ARCH/root/bin/runc" && chmod +x "build/$RUST_ARCH/root/bin/runc"
( cd "build/$RUST_ARCH/root" && find . | cpio -o -H newc 2>/dev/null ) | gzip > "$OUT/initramfs.cpio.gz"

# Kata kernel for this arch: stream the ~600MB bundle, keep only the ~18MB kernel.
if [ ! -f "$OUT/Image" ]; then
  echo "fetching Kata $OCI kernel (~600MB stream, keeps 18MB)..."
  curl -fL "https://github.com/kata-containers/kata-containers/releases/download/$KATA_VER/kata-static-$KATA_VER-$OCI.tar.zst" \
    | tar --zstd -xO -f - "$KATA_KERNEL" > "$OUT/Image"
fi
echo "staged $OUT: Image ($(du -h "$OUT/Image" | cut -f1)) + initramfs ($(du -h "$OUT/initramfs.cpio.gz" | cut -f1))"
