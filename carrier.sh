#!/bin/bash
# Build, (re)sign on macOS, then run. `cargo run` would launch an UNSIGNED binary
# — and the bundled VM needs the com.apple.security.virtualization entitlement,
# which a rebuild wipes. codesign is cheap, so just do it every run.
set -e
cd "$(dirname "$0")"
RUSTFLAGS=-Awarnings cargo build --quiet --bin carrier
BIN="target/debug/carrier"
[ "$(uname)" = "Darwin" ] && bash macos/sign.sh "$BIN" >/dev/null
exec "$BIN" "$@"
