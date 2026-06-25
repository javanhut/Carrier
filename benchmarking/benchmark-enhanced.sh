#!/bin/bash

# Enhanced Carrier vs Podman vs Docker Benchmark with Authentication Testing
# This script tests authentication functionality and performance benchmarks

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

# Configuration
TEST_IMAGE="docker.io/library/hello-world:latest"  # Use smaller image to reduce rate limit issues
ITERATIONS=${1:-3}
PULL_ITERS=${PULL_ITERS:-2}  # Reduce pull iterations to avoid rate limits

# Setup - adjust path based on execution location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARRIER="$PROJECT_ROOT/target/release/carrier"
[ ! -x "$CARRIER" ] && CARRIER="carrier"

# Check if we need sudo for Docker
DOCKER_CMD="docker"
if ! docker ps >/dev/null 2>&1; then
    if sudo docker ps >/dev/null 2>&1; then
        DOCKER_CMD="sudo docker"
        echo -e "${YELLOW}Note: Using sudo for Docker commands${NC}"
    fi
fi

echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}     Enhanced Carrier Benchmark with Authentication Testing${NC}"
echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Check tools availability
echo "Checking available tools:"
echo "─────────────────────────"

check_tool() {
    local cmd="$1"
    local name="$2"
    if $cmd --version >/dev/null 2>&1; then
        local version=$($cmd --version 2>&1 | head -1)
        echo -e "${GREEN}✓${NC} $name: $version"
        return 0
    else
        echo -e "${RED}✗${NC} $name: Not available"
        return 1
    fi
}

if check_tool "podman" "Podman"; then
    HAVE_PODMAN=true
else
    HAVE_PODMAN=false
fi

if check_tool "$DOCKER_CMD" "Docker"; then
    HAVE_DOCKER=true
else
    HAVE_DOCKER=false
fi

if check_tool "$CARRIER" "Carrier"; then
    HAVE_CARRIER=true
else
    HAVE_CARRIER=false
fi

if [ "$HAVE_CARRIER" != "true" ]; then
    echo -e "\n${RED}Carrier not available! This benchmark requires Carrier.${NC}"
    exit 1
fi

echo ""

# Test 1: Authentication System Test
echo -e "${BOLD}TEST 1: Authentication System Verification${NC}"
echo "════════════════════════════════════════════════════════════"

echo -e "\nTesting authentication command availability:"
if $CARRIER auth-verify >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Authentication commands available"
    
    echo -e "\nChecking stored credentials:"
    $CARRIER auth-verify 2>/dev/null || echo "No stored credentials found"
    
    echo ""
    echo -e "${CYAN}To test authentication with higher rate limits:${NC}"
    echo "  1. Create accounts on container registries"
    echo "  2. Run: carrier auth <username> docker.io"
    echo "  3. Run: carrier auth <username> ghcr.io"
    echo "  4. Re-run this benchmark to see improved performance"
    
else
    echo -e "${RED}✗${NC} Authentication commands not available"
fi

# Test 2: Quick functionality test
echo ""
echo -e "${BOLD}TEST 2: Basic Functionality Test${NC}"
echo "════════════════════════════════════════════════════════════"

test_basic_functionality() {
    local tool="$1"
    local name="$2"
    
    echo -n "Testing $name basic functionality: "
    
    # Test pull (with better error handling)
    local pull_result
    if [ "$name" = "Podman" ]; then
        echo -e "${YELLOW}(checking if image exists first)${NC}"
        echo -n "  $name pull test: "
        # Check if image already exists
        if eval "$tool images $TEST_IMAGE >/dev/null 2>&1"; then
            echo -e "${GREEN}✓ Image already exists${NC}"
            pull_result=0
        else
            pull_result=$(eval "$tool pull $TEST_IMAGE >/dev/null 2>&1; echo $?")
        fi
    else
        pull_result=$(eval "$tool pull $TEST_IMAGE >/dev/null 2>&1; echo $?")
    fi
    
    if [ "$pull_result" -ne 0 ]; then
        echo -e "${YELLOW}⚠ Pull failed (likely rate limited), skipping run test${NC}"
        
        # Still test list functionality
        if eval "$tool ps -a >/dev/null 2>&1" || eval "$tool ls -a >/dev/null 2>&1"; then
            echo -e "  $name list: ${GREEN}✓ List works${NC}"
            return 0
        else
            echo -e "${RED}✗ List also failed${NC}"
            return 1
        fi
    fi
    
    # Test list
    if ! eval "$tool ps -a >/dev/null 2>&1" && ! eval "$tool ls -a >/dev/null 2>&1"; then
        echo -e "${RED}✗ List failed${NC}"
        return 1
    fi
    
    # Test run (quick) - handle different syntaxes
    if [ "$name" = "Carrier" ]; then
        # Carrier doesn't support --rm, create and remove manually
        local test_name="test-func-$$"
        if eval "$tool run --name $test_name $TEST_IMAGE echo test >/dev/null 2>&1"; then
            eval "$tool rm -f $test_name >/dev/null 2>&1" || true
        else
            echo -e "${RED}✗ Run failed${NC}"
            return 1
        fi
    else
        # Docker and Podman support --rm
        if ! eval "$tool run --rm $TEST_IMAGE echo test >/dev/null 2>&1"; then
            echo -e "${RED}✗ Run failed${NC}"
            return 1
        fi
    fi
    
    echo -e "${GREEN}✓ All basic functions work${NC}"
    return 0
}

if [ "$HAVE_CARRIER" = "true" ]; then
    test_basic_functionality "$CARRIER" "Carrier"
fi

if [ "$HAVE_PODMAN" = "true" ]; then
    test_basic_functionality "podman" "Podman"
fi

if [ "$HAVE_DOCKER" = "true" ]; then
    test_basic_functionality "$DOCKER_CMD" "Docker"
fi

# Arrays for results
declare -a podman_pull_times
declare -a docker_pull_times
declare -a carrier_pull_times
declare -a podman_list_times
declare -a docker_list_times
declare -a carrier_list_times
declare -a podman_run_times
declare -a docker_run_times
declare -a carrier_run_times

# Timing function with better error handling
measure_time() {
    local start=$(date +%s%N)
    local output
    local exit_code
    
    # Capture both output and exit code
    output=$("$@" 2>&1)
    exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        local end=$(date +%s%N)
        echo $(( (end - start) / 1000000 ))
    else
        echo -e "\n${RED}Command failed: $*${NC}" >&2
        echo -e "${RED}Output: $output${NC}" >&2
        echo -1
    fi
    return 0
}

# Clean up function with better error handling
cleanup() {
    echo "Cleaning up test resources..."
    
    # Remove containers
    if [ "$HAVE_PODMAN" = "true" ]; then
        podman ps -aq --filter "name=bench-" 2>/dev/null | xargs -r podman rm -f &>/dev/null || true
        podman rmi $TEST_IMAGE &>/dev/null || true
    fi
    
    if [ "$HAVE_DOCKER" = "true" ]; then
        $DOCKER_CMD ps -aq --filter "name=bench-" 2>/dev/null | xargs -r $DOCKER_CMD rm -f &>/dev/null || true
        $DOCKER_CMD rmi $TEST_IMAGE &>/dev/null || true
    fi
    
    if [ "$HAVE_CARRIER" = "true" ]; then
        # Use proper carrier removal
        $CARRIER ls -a 2>/dev/null | grep "bench-" | awk '{print $1}' | xargs -r -I {} $CARRIER rm -f {} &>/dev/null || true
        $CARRIER rm $TEST_IMAGE &>/dev/null || true
    fi
}

# Initial cleanup
cleanup

echo ""
echo -e "${BOLD}TEST 3: Performance Benchmarks${NC}"
echo "════════════════════════════════════════════════════════════"
echo -e "Image: ${BOLD}$TEST_IMAGE${NC}"
echo -e "Iterations: ${BOLD}$ITERATIONS${NC}"
echo ""

# Pre-pull images for performance tests to avoid rate limiting during benchmarks
echo "Pre-pulling image for performance tests..."
echo "──────────────────────────────────────────"

pre_pull_success=()

if [ "$HAVE_CARRIER" = "true" ]; then
    echo -n "Pre-pulling with Carrier: "
    if $CARRIER pull $TEST_IMAGE >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        pre_pull_success+=("carrier")
    else
        echo -e "${RED}✗ (will skip Carrier performance tests)${NC}"
    fi
fi

if [ "$HAVE_DOCKER" = "true" ]; then
    echo -n "Pre-pulling with Docker: "
    if $DOCKER_CMD pull $TEST_IMAGE >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        pre_pull_success+=("docker")
    else
        echo -e "${RED}✗ (will skip Docker performance tests)${NC}"
    fi
fi

if [ "$HAVE_PODMAN" = "true" ]; then
    echo -n "Pre-pulling with Podman: "
    if podman pull $TEST_IMAGE >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        pre_pull_success+=("podman")
    else
        echo -e "${RED}✗ (will skip Podman performance tests - try: podman login docker.io)${NC}"
    fi
fi

if [ ${#pre_pull_success[@]} -eq 0 ]; then
    echo ""
    echo -e "${RED}No tools could pull the test image. Likely rate limited.${NC}"
    echo -e "${YELLOW}Try again later or set up authentication:${NC}"
    echo "  carrier auth <username> docker.io"
    echo "  podman login docker.io" 
    echo "  (Docker should work with sudo access)"
    exit 1
fi

echo ""

# Test 3a: Pull Performance
echo -e "${BOLD}Pull Performance Test:${NC}"
echo "─────────────────────────"

for i in $(seq 1 $PULL_ITERS); do
    echo -e "\n${CYAN}Pull Iteration $i/$PULL_ITERS:${NC}"
    
    # Clean images before each test
    cleanup
    sleep 2  # Wait between cleanup and test to avoid conflicts
    
    # Test Carrier first (has auth)
    if [[ " ${pre_pull_success[@]} " =~ " carrier " ]]; then
        echo -n "  Carrier: "
        ms=$(measure_time $CARRIER pull $TEST_IMAGE)
        if [ $ms -gt 0 ]; then
            carrier_pull_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
        sleep 2
    fi
    
    # Clean for next test
    $CARRIER rm $TEST_IMAGE &>/dev/null || true
    
    # Test Docker
    if [[ " ${pre_pull_success[@]} " =~ " docker " ]]; then
        echo -n "  Docker:  "
        ms=$(measure_time $DOCKER_CMD pull $TEST_IMAGE)
        if [ $ms -gt 0 ]; then
            docker_pull_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
        sleep 2
    fi
    
    # Clean for next test
    $DOCKER_CMD rmi $TEST_IMAGE &>/dev/null || true
    
    # Test Podman
    if [[ " ${pre_pull_success[@]} " =~ " podman " ]]; then
        echo -n "  Podman:  "
        ms=$(measure_time podman pull $TEST_IMAGE)
        if [ $ms -gt 0 ]; then
            podman_pull_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
        sleep 2
    fi
    
    # Clean for next test
    podman rmi $TEST_IMAGE &>/dev/null || true
    
    # Shorter delay between iterations since we're testing with pre-pulled images
    if [ $i -lt $PULL_ITERS ]; then
        echo "  Waiting 3 seconds before next iteration..."
        sleep 3
    fi
done

# Test 3b: List Performance
echo ""
echo -e "${BOLD}List Performance Test:${NC}"
echo "─────────────────────────"

# Images already pre-pulled for successful tools

for i in $(seq 1 $ITERATIONS); do
    echo -e "\n${CYAN}List Iteration $i/$ITERATIONS:${NC}"
    
    if [[ " ${pre_pull_success[@]} " =~ " carrier " ]]; then
        echo -n "  Carrier: "
        ms=$(measure_time $CARRIER ls)
        if [ $ms -gt 0 ]; then
            carrier_list_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
    
    if [[ " ${pre_pull_success[@]} " =~ " podman " ]]; then
        echo -n "  Podman:  "
        ms=$(measure_time podman ps -a)
        if [ $ms -gt 0 ]; then
            podman_list_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
    
    if [[ " ${pre_pull_success[@]} " =~ " docker " ]]; then
        echo -n "  Docker:  "
        ms=$(measure_time $DOCKER_CMD ps -a)
        if [ $ms -gt 0 ]; then
            docker_list_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
done

# Test 3c: Run Performance
echo ""
echo -e "${BOLD}Run Performance Test:${NC}"
echo "─────────────────────────"

for i in $(seq 1 $ITERATIONS); do
    echo -e "\n${CYAN}Run Iteration $i/$ITERATIONS:${NC}"
    
    if [[ " ${pre_pull_success[@]} " =~ " carrier " ]]; then
        echo -n "  Carrier: "
        ms=$(measure_time $CARRIER run --name bench-carrier-$i $TEST_IMAGE echo test)
        if [ $ms -gt 0 ]; then
            carrier_run_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
            # Clean up the container
            $CARRIER rm -f bench-carrier-$i &>/dev/null || true
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
    
    if [[ " ${pre_pull_success[@]} " =~ " podman " ]]; then
        echo -n "  Podman:  "
        ms=$(measure_time podman run --rm $TEST_IMAGE echo test)
        if [ $ms -gt 0 ]; then
            podman_run_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
    
    if [[ " ${pre_pull_success[@]} " =~ " docker " ]]; then
        echo -n "  Docker:  "
        ms=$(measure_time $DOCKER_CMD run --rm $TEST_IMAGE echo test)
        if [ $ms -gt 0 ]; then
            docker_run_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
done

# Calculate statistics
calc_stats() {
    local arr=("$@")
    local sum=0
    local count=0
    local min=999999
    local max=0
    
    for val in "${arr[@]}"; do
        if [ $val -gt 0 ]; then
            sum=$((sum + val))
            count=$((count + 1))
            [ $val -lt $min ] && min=$val
            [ $val -gt $max ] && max=$val
        fi
    done
    
    if [ $count -eq 0 ]; then
        echo "0 0 0 0"
    else
        local avg=$((sum / count))
        echo "$avg $min $max $count"
    fi
}

echo ""
echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}                        RESULTS SUMMARY${NC}"
echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"

# Detailed Results
echo ""
echo -e "${BOLD}Detailed Performance Results:${NC}"
echo "══════════════════════════════════"

print_results() {
    local title="$1"
    local -n carr_times=$2
    local -n pod_times=$3
    local -n dock_times=$4
    
    echo ""
    echo -e "${BOLD}$title:${NC}"
    echo "────────────────────────────"
    
    if [ ${#carr_times[@]} -gt 0 ]; then
        read avg min max count <<< $(calc_stats "${carr_times[@]}")
        echo "  Carrier: avg=${avg}ms, min=${min}ms, max=${max}ms, samples=${count}"
    fi
    
    if [ ${#pod_times[@]} -gt 0 ]; then
        read avg min max count <<< $(calc_stats "${pod_times[@]}")
        echo "  Podman:  avg=${avg}ms, min=${min}ms, max=${max}ms, samples=${count}"
    fi
    
    if [ ${#dock_times[@]} -gt 0 ]; then
        read avg min max count <<< $(calc_stats "${dock_times[@]}")
        echo "  Docker:  avg=${avg}ms, min=${min}ms, max=${max}ms, samples=${count}"
    fi
}

print_results "Image Pull Performance" carrier_pull_times podman_pull_times docker_pull_times
print_results "Container List Performance" carrier_list_times podman_list_times docker_list_times
print_results "Container Run Performance" carrier_run_times podman_run_times docker_run_times

# Winner Analysis
echo ""
echo -e "${BOLD}Performance Winners:${NC}"
echo "──────────────────────"

find_winner() {
    local title="$1"
    local carr_avg="$2"
    local pod_avg="$3" 
    local dock_avg="$4"
    
    local min_time=999999
    local winner=""
    
    [ $carr_avg -gt 0 ] && [ $carr_avg -lt $min_time ] && { min_time=$carr_avg; winner="Carrier"; }
    [ $pod_avg -gt 0 ] && [ $pod_avg -lt $min_time ] && { min_time=$pod_avg; winner="Podman"; }
    [ $dock_avg -gt 0 ] && [ $dock_avg -lt $min_time ] && { min_time=$dock_avg; winner="Docker"; }
    
    if [ -n "$winner" ]; then
        echo -e "  $title: ${GREEN}$winner${NC} (${min_time}ms)"
    else
        echo -e "  $title: ${RED}No valid results${NC}"
    fi
}

if [ ${#carrier_pull_times[@]} -gt 0 ] || [ ${#podman_pull_times[@]} -gt 0 ] || [ ${#docker_pull_times[@]} -gt 0 ]; then
    carr_pull_avg=$(calc_stats "${carrier_pull_times[@]}" | cut -d' ' -f1)
    pod_pull_avg=$(calc_stats "${podman_pull_times[@]}" | cut -d' ' -f1)
    dock_pull_avg=$(calc_stats "${docker_pull_times[@]}" | cut -d' ' -f1)
    find_winner "Pull" $carr_pull_avg $pod_pull_avg $dock_pull_avg
fi

if [ ${#carrier_list_times[@]} -gt 0 ] || [ ${#podman_list_times[@]} -gt 0 ] || [ ${#docker_list_times[@]} -gt 0 ]; then
    carr_list_avg=$(calc_stats "${carrier_list_times[@]}" | cut -d' ' -f1)
    pod_list_avg=$(calc_stats "${podman_list_times[@]}" | cut -d' ' -f1)
    dock_list_avg=$(calc_stats "${docker_list_times[@]}" | cut -d' ' -f1)
    find_winner "List" $carr_list_avg $pod_list_avg $dock_list_avg
fi

if [ ${#carrier_run_times[@]} -gt 0 ] || [ ${#podman_run_times[@]} -gt 0 ] || [ ${#docker_run_times[@]} -gt 0 ]; then
    carr_run_avg=$(calc_stats "${carrier_run_times[@]}" | cut -d' ' -f1)
    pod_run_avg=$(calc_stats "${podman_run_times[@]}" | cut -d' ' -f1)
    dock_run_avg=$(calc_stats "${docker_run_times[@]}" | cut -d' ' -f1)
    find_winner "Run" $carr_run_avg $pod_run_avg $dock_run_avg
fi

# Cleanup
echo ""
cleanup

echo ""
echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}                    Benchmark Complete!${NC}"
echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"

# Save detailed results
RESULTS_FILE="benchmark_results_$(date +%Y%m%d_%H%M%S).json"
{
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"configuration\": {"
    echo "    \"image\": \"$TEST_IMAGE\","
    echo "    \"iterations\": $ITERATIONS,"
    echo "    \"pull_iterations\": $PULL_ITERS"
    echo "  },"
    echo "  \"results\": {"
    echo "    \"pull_times\": {"
    echo "      \"carrier\": [$(IFS=,; echo "${carrier_pull_times[*]}")],"
    echo "      \"podman\": [$(IFS=,; echo "${podman_pull_times[*]}")],"
    echo "      \"docker\": [$(IFS=,; echo "${docker_pull_times[*]}")]"
    echo "    },"
    echo "    \"list_times\": {"
    echo "      \"carrier\": [$(IFS=,; echo "${carrier_list_times[*]}")],"
    echo "      \"podman\": [$(IFS=,; echo "${podman_list_times[*]}")],"
    echo "      \"docker\": [$(IFS=,; echo "${docker_list_times[*]}")]"
    echo "    },"
    echo "    \"run_times\": {"
    echo "      \"carrier\": [$(IFS=,; echo "${carrier_run_times[*]}")],"
    echo "      \"podman\": [$(IFS=,; echo "${podman_run_times[*]}")],"
    echo "      \"docker\": [$(IFS=,; echo "${docker_run_times[*]}")]"
    echo "    }"
    echo "  }"
    echo "}"
} > "$RESULTS_FILE"

echo ""
echo -e "${GREEN}Detailed results saved to: $RESULTS_FILE${NC}"

# Authentication recommendations
echo ""
echo -e "${BOLD}${MAGENTA}Authentication Recommendations:${NC}"
echo "════════════════════════════════════"
echo "To improve performance and avoid rate limits:"
echo "1. Authenticate with registries using:"
echo "   carrier auth <username> docker.io"
echo "   carrier auth <username> ghcr.io"
echo "2. Verify credentials with:"
echo "   carrier auth-verify"
echo "3. Re-run benchmarks to see improved performance"
echo ""
echo "Note: Authenticated users get much higher API rate limits!"