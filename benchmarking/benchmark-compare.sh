#!/bin/bash

# Comprehensive benchmark comparing Carrier vs Podman vs Docker
# Handles Docker permission issues gracefully

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Configuration
TEST_IMAGE="docker.io/library/alpine:latest"
ITERATIONS=${1:-5}
# Limit pull iterations to avoid registry rate limits (override with $PULL_ITERS)
if [ -z "$PULL_ITERS" ]; then
    if [ "$ITERATIONS" -gt 5 ] 2>/dev/null; then
        PULL_ITERS=5
    else
        PULL_ITERS=$ITERATIONS
    fi
fi

# Pull retry settings (override with env vars)
RETRY_PULLS=${RETRY_PULLS:-3}
RETRY_BACKOFF_BASE=${RETRY_BACKOFF_BASE:-1}

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
echo -e "${BOLD}${BLUE}     Carrier vs Podman vs Docker Performance Benchmark${NC}"
echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Check tools
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

if [ "$HAVE_DOCKER" != "true" ] && [ "$HAVE_PODMAN" != "true" ] && [ "$HAVE_CARRIER" != "true" ]; then
    echo -e "\n${RED}No container runtimes available! Exiting.${NC}"
    exit 1
fi

echo ""
echo "Test Configuration:"
echo -e "  Image: ${BOLD}$TEST_IMAGE${NC}"
echo -e "  Iterations: ${BOLD}$ITERATIONS${NC}"
echo -e "  Pull Iters: ${BOLD}$PULL_ITERS${NC}  (set PULL_ITERS to change)"
echo ""

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

# Timing function
measure_time() {
    local start=$(date +%s%N)
    if "$@" >/dev/null 2>&1; then
        local end=$(date +%s%N)
        echo $(( (end - start) / 1000000 ))
    else
        # On failure, emit -1 but do not fail the script
        echo -1
    fi
    return 0
}

# Retry wrapper specifically for pull commands to handle transient errors/rate-limits
retry_time() {
    local tries=0
    local delay=$RETRY_BACKOFF_BASE
    while [ $tries -lt $RETRY_PULLS ]; do
        ms=$(measure_time "$@")
        if [ "$ms" -gt 0 ] 2>/dev/null; then
            echo "$ms"
            return 0
        fi
        tries=$((tries + 1))
        sleep $delay
        delay=$((delay * 2))
    done
    echo -1
    return 0
}

# Clean up function
cleanup() {
    # Remove test containers
    if [ "$HAVE_PODMAN" = "true" ]; then
        podman ps -aq --filter "name=bench-" 2>/dev/null | xargs -r podman rm -f &>/dev/null || true
    fi
    if [ "$HAVE_DOCKER" = "true" ]; then
        $DOCKER_CMD ps -aq --filter "name=bench-" 2>/dev/null | xargs -r $DOCKER_CMD rm -f &>/dev/null || true
    fi
    if [ "$HAVE_CARRIER" = "true" ]; then
        # Parse pretty table output to extract only our benchmark containers and remove them
        # Prefer removing by name (last column), fallback to ID if needed
        $CARRIER ls -a 2>/dev/null \
          | awk -F '│' '/bench-/{name=$NF; gsub(/^[[:space:]║]+|[[:space:]║]+$/, "", name); print name}' \
          | xargs -r -I {} $CARRIER rm -f {} &>/dev/null || true
        # As a fallback, try by ID (first column)
        $CARRIER ls -a 2>/dev/null \
          | awk -F '│' '/bench-/{id=$1; gsub(/^[^[:alnum:]]+|[[:space:]]+$/, "", id); print id}' \
          | xargs -r -I {} $CARRIER rm -f {} &>/dev/null || true
    fi
    
    # Remove images (best-effort)
    if [ "$HAVE_PODMAN" = "true" ]; then podman rmi $TEST_IMAGE &>/dev/null || true; fi
    if [ "$HAVE_DOCKER" = "true" ]; then $DOCKER_CMD rmi $TEST_IMAGE &>/dev/null || true; fi
    if [ "$HAVE_CARRIER" = "true" ]; then $CARRIER rmi $TEST_IMAGE --force &>/dev/null || true; fi
}

# Initial cleanup
echo "Cleaning up any existing resources..."
cleanup

echo ""
echo -e "${BOLD}TEST 1: Image Pull Performance${NC}"
echo "════════════════════════════════════"
if [ "$ITERATIONS" -gt "$PULL_ITERS" ] 2>/dev/null; then
    echo -e "${YELLOW}Note:${NC} Limiting pull test to $PULL_ITERS iterations to avoid registry rate limits. Override with \$PULL_ITERS."
fi

for i in $(seq 1 $PULL_ITERS); do
    echo -e "\n${CYAN}Iteration $i/$ITERATIONS:${NC}"
    
    # Clean images before each test
    podman rmi $TEST_IMAGE &>/dev/null || true
    $DOCKER_CMD rmi $TEST_IMAGE &>/dev/null || true
    $CARRIER rmi $TEST_IMAGE --force &>/dev/null || true
    
    # Test Podman
    if [ "$HAVE_PODMAN" = "true" ]; then
        echo -n "  Podman:  "
        ms=$(retry_time podman pull $TEST_IMAGE)
        if [ $ms -gt 0 ]; then
            podman_pull_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
    
    # Clean for Docker
    podman rmi $TEST_IMAGE &>/dev/null || true
    
    # Test Docker
    if [ "$HAVE_DOCKER" = "true" ]; then
        echo -n "  Docker:  "
        ms=$(retry_time $DOCKER_CMD pull $TEST_IMAGE)
        if [ $ms -gt 0 ]; then
            docker_pull_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
    
    # Clean for Carrier
    $DOCKER_CMD rmi $TEST_IMAGE &>/dev/null || true
    podman rmi $TEST_IMAGE &>/dev/null || true
    
    # Test Carrier
    if [ "$HAVE_CARRIER" = "true" ]; then
        echo -n "  Carrier: "
        ms=$(retry_time $CARRIER pull $TEST_IMAGE)
        if [ $ms -gt 0 ]; then
            carrier_pull_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
done

echo ""
echo -e "${BOLD}TEST 2: Container List Performance${NC}"
echo "════════════════════════════════════"

# Create test containers
NUM_CONTAINERS=20
echo "Creating $NUM_CONTAINERS test containers..."

if [ "$HAVE_PODMAN" = "true" ]; then
    for i in $(seq 1 $NUM_CONTAINERS); do
        podman create --name bench-podman-$i $TEST_IMAGE true &>/dev/null
    done
fi

if [ "$HAVE_DOCKER" = "true" ]; then
    for i in $(seq 1 $NUM_CONTAINERS); do
        $DOCKER_CMD create --name bench-docker-$i $TEST_IMAGE true &>/dev/null
    done
fi

# Create Carrier test containers (exited) for fair listing
if [ "$HAVE_CARRIER" = "true" ]; then
    for i in $(seq 1 $NUM_CONTAINERS); do
        # Run a no-op so container exits immediately but remains listed with -a
        $CARRIER run --name bench-carrier-$i $TEST_IMAGE true &>/dev/null || true
    done
fi

echo ""
for i in $(seq 1 $ITERATIONS); do
    echo -e "${CYAN}Iteration $i/$ITERATIONS:${NC}"
    
    if [ "$HAVE_PODMAN" = "true" ]; then
        echo -n "  Podman:  "
        ms=$(measure_time podman ps -a)
        if [ $ms -gt 0 ]; then
            podman_list_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
    
    if [ "$HAVE_DOCKER" = "true" ]; then
        echo -n "  Docker:  "
        ms=$(measure_time $DOCKER_CMD ps -a)
        if [ $ms -gt 0 ]; then
            docker_list_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
    
    if [ "$HAVE_CARRIER" = "true" ]; then
        echo -n "  Carrier: "
        ms=$(measure_time $CARRIER ls -a)
        if [ $ms -gt 0 ]; then
            carrier_list_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
done

echo ""
echo -e "${BOLD}TEST 3: Container Run Performance${NC}"
echo "════════════════════════════════════"

for i in $(seq 1 $ITERATIONS); do
    echo -e "\n${CYAN}Iteration $i/$ITERATIONS:${NC}"
    
    if [ "$HAVE_PODMAN" = "true" ]; then
        echo -n "  Podman:  "
        ms=$(measure_time podman run --rm $TEST_IMAGE echo test)
        if [ $ms -gt 0 ]; then
            podman_run_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
    
    if [ "$HAVE_DOCKER" = "true" ]; then
        echo -n "  Docker:  "
        ms=$(measure_time $DOCKER_CMD run --rm $TEST_IMAGE echo test)
        if [ $ms -gt 0 ]; then
            docker_run_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
    
    if [ "$HAVE_CARRIER" = "true" ]; then
        echo -n "  Carrier: "
        cname="bench-run-$i"
        ms=$(measure_time $CARRIER run --name $cname $TEST_IMAGE echo test)
        if [ $ms -gt 0 ]; then
            carrier_run_times+=($ms)
            echo -e "${GREEN}${ms}ms${NC}"
            $CARRIER rm -f $cname &>/dev/null || true
        else
            echo -e "${RED}Failed${NC}"
        fi
    fi
done

# Calculate averages
calc_avg() {
    local arr=("$@")
    local sum=0
    local count=0
    
    for val in "${arr[@]}"; do
        if [ $val -gt 0 ]; then
            sum=$((sum + val))
            count=$((count + 1))
        fi
    done
    
    if [ $count -eq 0 ]; then
        echo 0
    else
        echo $((sum / count))
    fi
}

echo ""
echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}                        RESULTS SUMMARY${NC}"
echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"

# Pull Performance Summary
echo ""
echo -e "${BOLD}Image Pull Performance (Average):${NC}"
echo "─────────────────────────────────"

podman_pull_avg=$(calc_avg "${podman_pull_times[@]}")
docker_pull_avg=$(calc_avg "${docker_pull_times[@]}")
carrier_pull_avg=$(calc_avg "${carrier_pull_times[@]}")

[ $podman_pull_avg -gt 0 ] && echo "  Podman:  ${podman_pull_avg}ms"
[ $docker_pull_avg -gt 0 ] && echo "  Docker:  ${docker_pull_avg}ms"
[ $carrier_pull_avg -gt 0 ] && echo "  Carrier: ${carrier_pull_avg}ms"

# Find fastest
min_pull=999999
winner=""
if [ $podman_pull_avg -gt 0 ] && [ $podman_pull_avg -lt $min_pull ]; then
    min_pull=$podman_pull_avg
    winner="Podman"
fi
if [ $docker_pull_avg -gt 0 ] && [ $docker_pull_avg -lt $min_pull ]; then
    min_pull=$docker_pull_avg
    winner="Docker"
fi
if [ $carrier_pull_avg -gt 0 ] && [ $carrier_pull_avg -lt $min_pull ]; then
    min_pull=$carrier_pull_avg
    winner="Carrier"
fi
[ -n "$winner" ] && echo -e "  ${GREEN}Winner: $winner${NC}"

# List Performance Summary
echo ""
echo -e "${BOLD}Container List Performance (Average, $NUM_CONTAINERS containers):${NC}"
echo "─────────────────────────────────"

podman_list_avg=$(calc_avg "${podman_list_times[@]}")
docker_list_avg=$(calc_avg "${docker_list_times[@]}")
carrier_list_avg=$(calc_avg "${carrier_list_times[@]}")

[ $podman_list_avg -gt 0 ] && echo "  Podman:  ${podman_list_avg}ms"
[ $docker_list_avg -gt 0 ] && echo "  Docker:  ${docker_list_avg}ms"
[ $carrier_list_avg -gt 0 ] && echo "  Carrier: ${carrier_list_avg}ms"

# Find fastest
min_list=999999
winner=""
if [ $podman_list_avg -gt 0 ] && [ $podman_list_avg -lt $min_list ]; then
    min_list=$podman_list_avg
    winner="Podman"
fi
if [ $docker_list_avg -gt 0 ] && [ $docker_list_avg -lt $min_list ]; then
    min_list=$docker_list_avg
    winner="Docker"
fi
if [ $carrier_list_avg -gt 0 ] && [ $carrier_list_avg -lt $min_list ]; then
    min_list=$carrier_list_avg
    winner="Carrier"
fi
[ -n "$winner" ] && echo -e "  ${GREEN}Winner: $winner${NC}"

# Run Performance Summary
echo ""
echo -e "${BOLD}Container Run Performance (Average):${NC}"
echo "─────────────────────────────────"

podman_run_avg=$(calc_avg "${podman_run_times[@]}")
docker_run_avg=$(calc_avg "${docker_run_times[@]}")
carrier_run_avg=$(calc_avg "${carrier_run_times[@]}")

[ $podman_run_avg -gt 0 ] && echo "  Podman:  ${podman_run_avg}ms"
[ $docker_run_avg -gt 0 ] && echo "  Docker:  ${docker_run_avg}ms"
[ $carrier_run_avg -gt 0 ] && echo "  Carrier: ${carrier_run_avg}ms"

# Find fastest
min_run=999999
winner=""
if [ $podman_run_avg -gt 0 ] && [ $podman_run_avg -lt $min_run ]; then
    min_run=$podman_run_avg
    winner="Podman"
fi
if [ $docker_run_avg -gt 0 ] && [ $docker_run_avg -lt $min_run ]; then
    min_run=$docker_run_avg
    winner="Docker"
fi
if [ $carrier_run_avg -gt 0 ] && [ $carrier_run_avg -lt $min_run ]; then
    min_run=$carrier_run_avg
    winner="Carrier"
fi
[ -n "$winner" ] && echo -e "  ${GREEN}Winner: $winner${NC}"

# Performance comparison
echo ""
echo -e "${BOLD}Performance Comparisons:${NC}"
echo "─────────────────────────────────"

# Compare Carrier to others
if [ $carrier_pull_avg -gt 0 ]; then
    echo "Pull Performance:"
    if [ $podman_pull_avg -gt 0 ]; then
        ratio=$(( (podman_pull_avg * 100) / carrier_pull_avg ))
        echo "  Carrier vs Podman: $(( ratio / 100 )).$(printf "%02d" $(( ratio % 100 )))x faster"
    fi
    if [ $docker_pull_avg -gt 0 ]; then
        ratio=$(( (docker_pull_avg * 100) / carrier_pull_avg ))
        echo "  Carrier vs Docker: $(( ratio / 100 )).$(printf "%02d" $(( ratio % 100 )))x faster"
    fi
fi

if [ $carrier_list_avg -gt 0 ]; then
    echo ""
    echo "List Performance:"
    if [ $podman_list_avg -gt 0 ]; then
        ratio=$(( (podman_list_avg * 100) / carrier_list_avg ))
        echo "  Carrier vs Podman: $(( ratio / 100 )).$(printf "%02d" $(( ratio % 100 )))x faster"
    fi
    if [ $docker_list_avg -gt 0 ]; then
        ratio=$(( (docker_list_avg * 100) / carrier_list_avg ))
        echo "  Carrier vs Docker: $(( ratio / 100 )).$(printf "%02d" $(( ratio % 100 )))x faster"
    fi
fi

# Cleanup
echo ""
echo "Cleaning up test resources..."
cleanup

echo ""
echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}                    Benchmark Complete!${NC}"
echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"

# Save results
RESULTS_FILE="benchmarking/benchmark_results_$(date +%Y%m%d_%H%M%S).txt"
{
    echo "Benchmark Results - $(date)"
    echo "=========================="
    echo ""
    echo "Configuration:"
    echo "  Image: $TEST_IMAGE"
    echo "  Iterations: $ITERATIONS"
    echo ""
    echo "Raw Pull Times (ms):"
    echo "  Podman: ${podman_pull_times[@]}"
    echo "  Docker: ${docker_pull_times[@]}"
    echo "  Carrier: ${carrier_pull_times[@]}"
    echo ""
    echo "Raw List Times (ms):"
    echo "  Podman: ${podman_list_times[@]}"
    echo "  Docker: ${docker_list_times[@]}"
    echo "  Carrier: ${carrier_list_times[@]}"
    echo ""
    echo "Raw Run Times (ms):"
    echo "  Podman: ${podman_run_times[@]}"
    echo "  Docker: ${docker_run_times[@]}"
    echo "  Carrier: ${carrier_run_times[@]}"
} > "$RESULTS_FILE"

echo ""
echo -e "${GREEN}Results saved to: $RESULTS_FILE${NC}"

# Note about Docker permissions
if [ "$DOCKER_CMD" != "docker" ]; then
    echo ""
    echo -e "${YELLOW}Note: Docker was run with sudo. For non-sudo access, add your user to the docker group:${NC}"
    echo -e "${YELLOW}  sudo usermod -aG docker $USER${NC}"
    echo -e "${YELLOW}  Then log out and back in.${NC}"
fi
