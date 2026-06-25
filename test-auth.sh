#!/bin/bash

# Simple script to test Carrier authentication system

set -e

CARRIER="./target/release/carrier"
[ ! -x "$CARRIER" ] && CARRIER="carrier"

echo "Testing Carrier Authentication System"
echo "===================================="
echo ""

# Test 1: Check if auth commands exist
echo "1. Testing authentication command availability:"
if $CARRIER auth-verify >/dev/null 2>&1; then
    echo "   ✓ Authentication commands are available"
else
    echo "   ✗ Authentication commands not found"
    exit 1
fi

# Test 2: Check current auth status
echo ""
echo "2. Current authentication status:"
$CARRIER auth-verify

# Test 3: Test authenticated vs anonymous pull performance
echo ""
echo "3. Testing pull performance comparison:"

TEST_IMAGE="docker.io/library/hello-world:latest"

# Clean image first
$CARRIER rm $TEST_IMAGE &>/dev/null || true

echo "   Testing anonymous pull..."
start=$(date +%s%N)
if $CARRIER pull $TEST_IMAGE >/dev/null 2>&1; then
    end=$(date +%s%N)
    anon_time=$(( (end - start) / 1000000 ))
    echo "   Anonymous pull: ${anon_time}ms"
else
    echo "   Anonymous pull failed"
    anon_time=0
fi

# If user has credentials, test authenticated pull
if [ -f ~/.local/share/carrier/auth.json ]; then
    echo "   Found stored credentials, testing authenticated pull..."
    
    # Clean image
    $CARRIER rm $TEST_IMAGE &>/dev/null || true
    
    start=$(date +%s%N)
    if $CARRIER pull $TEST_IMAGE >/dev/null 2>&1; then
        end=$(date +%s%N)
        auth_time=$(( (end - start) / 1000000 ))
        echo "   Authenticated pull: ${auth_time}ms"
        
        if [ $anon_time -gt 0 ] && [ $auth_time -gt 0 ]; then
            if [ $auth_time -lt $anon_time ]; then
                improvement=$(( (anon_time * 100) / auth_time ))
                echo "   🎉 Authenticated pull is $(( improvement / 100 )).$(printf "%02d" $(( improvement % 100 )))x faster!"
            else
                echo "   Note: Times are similar (network conditions may vary)"
            fi
        fi
    else
        echo "   Authenticated pull failed"
    fi
else
    echo "   No stored credentials found."
    echo "   To test authenticated performance:"
    echo "     1. Create an account on docker.io (Docker Hub)"
    echo "     2. Run: $CARRIER auth <username> docker.io"
    echo "     3. Re-run this test script"
fi

echo ""
echo "4. How to set up authentication:"
echo "   ────────────────────────────────"
echo "   # For Docker Hub (most important - higher rate limits)"
echo "   $CARRIER auth <your-username> docker.io"
echo ""
echo "   # For GitHub Container Registry"  
echo "   $CARRIER auth <your-username> ghcr.io"
echo ""
echo "   # For other registries"
echo "   $CARRIER auth <your-username> quay.io"
echo "   $CARRIER auth <your-username> gcr.io"
echo ""
echo "   Then verify with:"
echo "   $CARRIER auth-verify"

echo ""
echo "Authentication test complete!"