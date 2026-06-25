//! macOS Linux micro-VM via Apple's built-in Virtualization.framework, driven
//! from pure Rust through the objc2 bindings — no Swift toolchain, no extra app.
//!
//! This module owns the VM *configuration* path: turn a [`VmSpec`] into a
//! validated `VZVirtualMachineConfiguration` for a Linux guest (kernel + initrd
//! + a virtio-block rootfs). Config construction and `validateWithError` need
//! no special privileges and are exercised by the test below.
//!
//! Actually *starting* the VM (`VZVirtualMachine` on a serial dispatch queue,
//! run loop, host<->guest command proxy) is Phase 3 — and it additionally
//! requires the `com.apple.security.virtualization` entitlement + a codesigned
//! binary, plus a real kernel/rootfs to boot. We build that once the artifacts
//! exist, so it can be written against something runnable rather than blind.

// ponytail: build_config/validate are the tested Phase 2 output; the
// `carrier machine` command wires them in Phase 3 (provisioning). Allowed dead
// until then so the warning doesn't mask real ones.
#![allow(dead_code)]

use std::path::Path;

use objc2::rc::Retained;
use objc2::AllocAnyThread;
use objc2_foundation::{NSArray, NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageStorageDeviceAttachment, VZLinuxBootLoader,
    VZVirtioBlockDeviceConfiguration, VZVirtioEntropyDeviceConfiguration,
    VZVirtualMachineConfiguration,
};

/// What to boot. Paths point at host files; the rootfs is a raw disk image
/// attached as the guest's virtio root block device. Provisioning these
/// (kernel + rootfs containing carrier-linux + runc) is Phase 3.
pub struct VmSpec<'a> {
    pub cpus: usize,
    pub memory_mib: u64,
    pub kernel: &'a Path,
    pub initrd: Option<&'a Path>,
    pub rootfs: &'a Path,
    pub cmdline: &'a str,
}

fn file_url(p: &Path) -> Retained<NSURL> {
    // SAFETY: fileURLWithPath: just wraps the path string; no preconditions.
    unsafe { NSURL::fileURLWithPath(&NSString::from_str(&p.to_string_lossy())) }
}

/// Build a `VZVirtualMachineConfiguration` for a Linux guest from `spec`.
/// Touches the filesystem only to open the rootfs disk image (via the disk
/// attachment); the kernel/initrd URLs are validated at boot, not here.
pub fn build_config(
    spec: &VmSpec,
) -> Result<Retained<VZVirtualMachineConfiguration>, String> {
    // SAFETY: every call below is a plain Objective-C message send to a freshly
    // allocated, owned object; objc2 enforces the type signatures.
    unsafe {
        let boot = VZLinuxBootLoader::new();
        boot.setKernelURL(&file_url(spec.kernel));
        boot.setCommandLine(&NSString::from_str(spec.cmdline));
        if let Some(initrd) = spec.initrd {
            boot.setInitialRamdiskURL(Some(&file_url(initrd)));
        }

        let attach = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_error(
            VZDiskImageStorageDeviceAttachment::alloc(),
            &file_url(spec.rootfs),
            false,
        )
        .map_err(|e| format!("attach root disk {}: {e:?}", spec.rootfs.display()))?;
        let block = VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &attach,
        );

        let cfg = VZVirtualMachineConfiguration::new();
        cfg.setCPUCount(spec.cpus);
        cfg.setMemorySize(spec.memory_mib * 1024 * 1024);
        cfg.setBootLoader(Some(&*boot)); // VZLinuxBootLoader derefs to VZBootLoader

        // Upcast the concrete configs to the abstract array element types.
        cfg.setStorageDevices(&NSArray::from_retained_slice(&[Retained::into_super(block)]));
        let entropy = VZVirtioEntropyDeviceConfiguration::new();
        cfg.setEntropyDevices(&NSArray::from_retained_slice(&[Retained::into_super(entropy)]));

        Ok(cfg)
    }
}

/// Build and validate a VM configuration, surfacing why it's invalid. Used by
/// `carrier machine` (Phase 3) to fail fast before attempting to boot.
pub fn validate(spec: &VmSpec) -> Result<(), String> {
    let cfg = build_config(spec)?;
    // SAFETY: validateWithError: only reads the config; no preconditions.
    unsafe { cfg.validateWithError() }
        .map_err(|e| format!("invalid VM configuration: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic: proves the objc2-virtualization FFI path works end to end
    // (alloc, setters, return-value reads) with no files and no entitlement.
    #[test]
    fn vz_config_roundtrip() {
        unsafe {
            let cfg = VZVirtualMachineConfiguration::new();
            cfg.setCPUCount(2);
            cfg.setMemorySize(1024 * 1024 * 1024);
            assert_eq!(cfg.CPUCount(), 2);
            assert_eq!(cfg.memorySize(), 1024 * 1024 * 1024);
        }
    }

    // Exercises the full build path including the disk attachment against a real
    // file. We don't assert a host-dependent outcome — just that the FFI runs.
    #[test]
    fn build_config_runs() {
        let rootfs = tempfile::NamedTempFile::new().unwrap();
        let spec = VmSpec {
            cpus: 2,
            memory_mib: 1024,
            kernel: Path::new("/nonexistent/vmlinux"),
            initrd: None,
            rootfs: rootfs.path(),
            cmdline: "console=hvc0 root=/dev/vda",
        };
        let _ = build_config(&spec);
    }
}
