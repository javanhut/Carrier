#!/usr/bin/env bash
# Codesign the carrier binary with the Virtualization entitlement so it can
# boot the bundled Linux VM. Required on macOS — VZVirtualMachine throws without
# it. Ad-hoc signing (the default here) works for local dev; pass a Developer ID
# as $IDENTITY to distribute to other machines.
#
#   ./macos/sign.sh [path-to-binary]   # default: target/release/carrier
#   IDENTITY="Developer ID Application: You (TEAMID)" ./macos/sign.sh
set -euo pipefail

BIN="${1:-target/release/carrier}"
ENTITLEMENTS="$(cd "$(dirname "$0")" && pwd)/Carrier.entitlements"
IDENTITY="${IDENTITY:--}" # "-" = ad-hoc

[ -f "$BIN" ] || { echo "binary not found: $BIN (build it first: cargo build --release)" >&2; exit 1; }

codesign --force --sign "$IDENTITY" --entitlements "$ENTITLEMENTS" --options runtime "$BIN"
echo "signed $BIN with com.apple.security.virtualization (identity: $IDENTITY)"
codesign --display --entitlements - "$BIN" 2>&1 | grep -A2 virtualization || true
