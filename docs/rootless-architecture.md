# Rootless Container Architecture

## Overview
This document outlines the architecture for rootless containers based on Podman's proven approach, which uses Linux user namespaces and specialized user-space networking tools to run unprivileged containers securely.

## User Namespaces: Foundation of Rootless Containers

### UID/GID Mapping
- **Mechanism**: Remap user and group IDs inside containers to non-privileged ranges on the host
- **Root mapping**: Container's root (UID 0) maps to unprivileged user on host
- **Subordinate IDs**: Use `/etc/subuid` and `/etc/subgid` for ID range allocation
- **Security benefit**: Escaped processes retain only unprivileged host user permissions

### Implementation Requirements
1. Parse `/etc/subuid` and `/etc/subgid` for available ID ranges
2. Configure user namespace mapping with `newuidmap` and `newgidmap`
3. Handle file ownership mapping (host root appears as `nobody` UID 65534)

### Namespace Isolation Options
- **Default mode**: All containers share same user namespace per user
- **Auto mode** (`--userns=auto`): Unique namespace per container for enhanced isolation

## User-Space Networking for Rootless

### slirp4netns (Legacy)
- **Function**: Emulates full TCP/IP stack in user space
- **Pros**: Complete network isolation
- **Cons**: Performance overhead due to full stack emulation

### pasta (Modern Default)
- **Function**: Direct TCP coordination without full stack emulation
- **Benefits**:
  - No NAT by default (copies host IP addresses)
  - Fast local connections via Layer-4 socket bypass
  - Better performance than slirp4netns
- **Implementation**: Integrate as default networking backend

## Storage Optimizations

### Metadata-Only Copy-Up
- **Requirement**: Linux kernel 4.19+
- **Benefit**: Avoids expensive `chown` operations during namespace creation
- **Implementation**: Use overlay filesystem features for efficient UID/GID remapping

## Security Considerations

### nsenter TOCTOU Vulnerability
- **Risk**: Time-of-check to time-of-use vulnerability when joining namespaces
- **Scenario**: Process could join recycled namespace if original exits
- **Mitigation**: Verify PID and namespace consistency before entering

### Best Practices
1. Always validate container PID before namespace operations
2. Use atomic operations for namespace joining
3. Implement proper cleanup of stale namespaces
4. Restrict subordinate UID/GID ranges appropriately

## Implementation Roadmap

### Phase 1: User Namespace Enhancement
- [ ] Parse and validate `/etc/subuid` and `/etc/subgid`
- [ ] Implement proper UID/GID mapping with newuidmap/newgidmap
- [ ] Add `--userns=auto` flag for unique namespaces

### Phase 2: Networking Integration
- [ ] Detect and use pasta if available
- [ ] Fallback to slirp4netns
- [ ] Configure proper network namespace setup

### Phase 3: Storage Optimization
- [ ] Detect kernel version for copy-up support
- [ ] Implement metadata-only remapping
- [ ] Optimize container creation performance

### Phase 4: Security Hardening
- [ ] Fix nsenter TOCTOU vulnerabilities
- [ ] Add namespace validation checks
- [ ] Implement secure cleanup procedures

## Testing Requirements
- Test with various UID/GID mappings
- Verify network performance with pasta vs slirp4netns
- Validate security boundaries with escape testing
- Benchmark storage operations with/without optimizations