# Carrier Benchmarking Suite

This directory contains performance benchmarking scripts that compare Carrier against other container runtimes (Docker and Podman).

## Available Benchmarks

### 1. benchmark-compare.sh
A comprehensive benchmark that compares Carrier, Podman, and Docker across multiple operations.

#### What it tests:
- **Image Pull Performance**: Times how long it takes to pull images from registries
- **Container Startup Time**: Measures time from run command to container ready state
- **Container Stop Time**: Measures graceful shutdown performance
- **Container Removal Time**: Times cleanup operations
- **Execution Overhead**: Benchmarks command execution in running containers
- **Resource Usage**: Memory consumption during operations

#### Features:
- Automatic tool detection (skips unavailable runtimes)
- Retry logic for network operations (handles rate limits)
- Statistical analysis (mean, standard deviation, min/max)
- Colored output for easy reading
- Handles Docker permission issues gracefully

### 2. benchmark-enhanced.sh
An enhanced benchmark suite with additional authentication and registry testing.

#### What it tests:
All tests from benchmark-compare.sh plus:
- **Authentication Testing**: Tests login/logout functionality
- **Multi-Registry Support**: Tests pulling from different registries (Docker Hub, Quay.io, GHCR)
- **Private Registry Access**: Validates authenticated image pulls
- **Platform-Specific Pulls**: Tests multi-arch image support
- **Network Performance**: Registry-specific timing

#### Features:
- Registry authentication validation
- Cross-registry performance comparison
- Platform architecture testing
- Enhanced error handling and reporting

## Running the Benchmarks

### From the project root:
```bash
# Basic comparison benchmark
sudo ./benchmarking/benchmark-compare.sh [iterations]

# Enhanced benchmark with auth testing
sudo ./benchmarking/benchmark-enhanced.sh [iterations]
```

### From the benchmarking directory:
```bash
cd benchmarking/
sudo ./benchmark-compare.sh [iterations]
sudo ./benchmark-enhanced.sh [iterations]
```

### Parameters:
- `iterations`: Number of test iterations (default: 5 for compare, 3 for enhanced)

### Environment Variables:
- `PULL_ITERS`: Override number of pull test iterations (useful to avoid rate limits)
- `RETRY_PULLS`: Number of retry attempts for pull operations (default: 3)
- `RETRY_BACKOFF_BASE`: Base seconds for exponential backoff (default: 1)

## Example Output

```
================================================================
           Carrier vs Podman vs Docker Benchmark
================================================================

Testing with: alpine:latest
Iterations: 5

----------------------------------------------------------------
                    IMAGE PULL PERFORMANCE
----------------------------------------------------------------
Carrier:    2.34s ± 0.12s (min: 2.21s, max: 2.48s)
Podman:     3.45s ± 0.23s (min: 3.22s, max: 3.68s)
Docker:     2.89s ± 0.15s (min: 2.74s, max: 3.04s)
```

## Requirements

- **Carrier**: Built binary at `./target/release/carrier`
- **Docker** (optional): Docker daemon running or sudo access
- **Podman** (optional): Podman installed
- **Network**: Internet access for pulling images
- **Permissions**: Root/sudo for some operations

## Notes

1. **Rate Limits**: The scripts include logic to handle Docker Hub rate limits by:
   - Using smaller test images (hello-world, alpine)
   - Limiting pull iterations
   - Implementing retry with exponential backoff

2. **Fair Comparison**:
   - All tools test with the same images
   - Warm-up runs ensure caches are primed
   - Multiple iterations provide statistical significance

3. **Error Handling**:
   - Scripts continue if a tool is not available
   - Network errors trigger retries
   - Results clearly indicate which tools were tested

## Interpreting Results

- **Lower times are better** for all metrics
- **Standard deviation** shows consistency (lower is more predictable)
- **Min/Max range** shows best/worst case scenarios
- **Failed operations** are excluded from statistics

## Troubleshooting

### Docker Permission Denied
The scripts automatically detect and use `sudo` for Docker if needed.

### Registry Rate Limits
Reduce iterations or wait between runs:
```bash
PULL_ITERS=1 ./benchmarking/benchmark-compare.sh 10
```

### Missing Tools
Scripts will skip unavailable tools and show:
```
✗ Docker: Not found or not accessible
```

### Build Carrier First
Ensure Carrier is built before running:
```bash
cargo build --release
./benchmarking/benchmark-compare.sh
```