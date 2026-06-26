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

use std::os::fd::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::AllocAnyThread;
use objc2_foundation::{NSArray, NSError, NSFileHandle, NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageStorageDeviceAttachment, VZFileHandleSerialPortAttachment,
    VZLinuxBootLoader, VZVirtioBlockDeviceConfiguration,
    VZVirtioConsoleDeviceSerialPortConfiguration, VZVirtioEntropyDeviceConfiguration,
    VZVirtioSocketConnection, VZVirtioSocketDevice, VZVirtioSocketDeviceConfiguration,
    VZVirtualMachine, VZVirtualMachineConfiguration,
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

// ---------------------------------------------------------------------------
// Provisioning layout
//
// VM artifacts live under the same root as the runc state (~/.local/share/
// carrier), so everything Carrier owns is in one place. `init` downloads the
// kernel + rootfs here; `boot` reads them. Actual fetch URLs + rootfs strategy
// (virtio-block vs virtiofs) are being finalized — see Phase 3 research.
// ---------------------------------------------------------------------------

/// `~/.local/share/carrier/vm` — home for the bundled VM artifacts.
pub fn vm_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".local/share/carrier/vm")
}

pub fn kernel_path() -> PathBuf {
    vm_dir().join("Image") // uncompressed arm64 kernel (VZ won't boot gzip)
}
pub fn initrd_path() -> PathBuf {
    vm_dir().join("initramfs.cpio.gz") // userland runs from RAM; no host mkfs
}

/// Provisioned == the artifacts needed to boot are present.
pub fn is_provisioned() -> bool {
    kernel_path().exists() && initrd_path().exists()
}

// Day-1 guest: PUI PUI Linux — a tiny arm64 kernel + initramfs purpose-built for
// Virtualization.framework testing. Swap for a Kata/own kernel when runc needs
// more (cgroups v2, overlayfs, full namespaces).
const GUEST_URL: &str =
    "https://github.com/Code-Hex/puipui-linux/releases/download/v1.0.3/puipui_linux_v1.0.3_aarch64.tar.gz";

/// Download + unpack the guest kernel + initramfs into `vm_dir()`. The tarball
/// holds `Image.gz` + `initramfs.cpio.gz`; VZ needs the kernel *uncompressed*,
/// so we gunzip it. Initramfs stays gzipped (the kernel decompresses it).
fn provision() -> Result<(), String> {
    std::fs::create_dir_all(vm_dir()).map_err(|e| format!("mkdir {}: {e}", vm_dir().display()))?;

    eprintln!("downloading guest (PUI PUI Linux v1.0.3, ~5MB)...");
    let body = reqwest::blocking::get(GUEST_URL)
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.bytes())
        .map_err(|e| format!("download {GUEST_URL}: {e}"))?;

    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&body[..]));
    let (mut got_kernel, mut got_initrd) = (false, false);
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .path()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_owned()))
            .unwrap_or_default();
        match name.to_str() {
            Some("Image.gz") => {
                let mut out = std::fs::File::create(kernel_path()).map_err(|e| e.to_string())?;
                std::io::copy(&mut flate2::read::GzDecoder::new(&mut entry), &mut out)
                    .map_err(|e| format!("decompress kernel: {e}"))?;
                got_kernel = true;
            }
            Some("initramfs.cpio.gz") => {
                let mut out = std::fs::File::create(initrd_path()).map_err(|e| e.to_string())?;
                std::io::copy(&mut entry, &mut out).map_err(|e| e.to_string())?;
                got_initrd = true;
            }
            _ => {}
        }
    }
    if !got_kernel || !got_initrd {
        return Err("guest tarball missing Image.gz or initramfs.cpio.gz".into());
    }
    Ok(())
}

/// Boot the provisioned guest and open a vsock channel to `port` inside it,
/// returning the connected socket fd. objc2 objects aren't `Send`, so the VM is
/// built and operated on a serial dispatch queue; we leak the VM and pass its
/// pointer (a Send `usize`) between queue stages. The guest serial console is
/// wired to our stdin/stdout so the boot is visible. The VM keeps running on the
/// queue, so the caller must keep the process alive. Needs the virtualization
/// entitlement (macos/sign.sh) — VZVirtualMachine throws without it.
fn boot_and_connect(port: u32) -> Result<RawFd, String> {
    if !is_provisioned() {
        return Err("not provisioned — run `carrier machine init` first".into());
    }
    let kernel = kernel_path();
    let initrd = initrd_path();
    let queue = DispatchQueue::new("dev.carrier.vm", None); // None attr => serial

    // Stage 1: build + start the VM; report its leaked pointer once started.
    let q1 = queue.clone();
    let (start_tx, start_rx) = std::sync::mpsc::channel::<Result<usize, String>>();
    queue.exec_async(move || {
        // SAFETY: every VZ object is created and used on this serial queue.
        let build: Result<(), String> = (|| unsafe {
            let boot = VZLinuxBootLoader::new();
            boot.setKernelURL(&file_url(&kernel));
            boot.setInitialRamdiskURL(Some(&file_url(&initrd)));
            boot.setCommandLine(&NSString::from_str("console=hvc0"));

            // Guest serial console <-> our stdin/stdout.
            let attach =
                VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                    VZFileHandleSerialPortAttachment::alloc(),
                    Some(&NSFileHandle::fileHandleWithStandardInput()),
                    Some(&NSFileHandle::fileHandleWithStandardOutput()),
                );
            let serial = VZVirtioConsoleDeviceSerialPortConfiguration::new();
            serial.setAttachment(Some(&*attach));

            let cfg = VZVirtualMachineConfiguration::new();
            cfg.setCPUCount(2);
            cfg.setMemorySize(512 * 1024 * 1024);
            cfg.setBootLoader(Some(&*boot));
            cfg.setSerialPorts(&NSArray::from_retained_slice(&[Retained::into_super(serial)]));
            cfg.setEntropyDevices(&NSArray::from_retained_slice(&[Retained::into_super(
                VZVirtioEntropyDeviceConfiguration::new(),
            )]));
            // vsock: the host<->guest transport for the command proxy.
            cfg.setSocketDevices(&NSArray::from_retained_slice(&[Retained::into_super(
                VZVirtioSocketDeviceConfiguration::new(),
            )]));
            cfg.validateWithError()
                .map_err(|e| format!("invalid VM config: {e:?}"))?;

            let vm = VZVirtualMachine::initWithConfiguration_queue(
                VZVirtualMachine::alloc(),
                &cfg,
                &q1,
            );
            let ptr = Retained::into_raw(vm) as usize; // leak: VM lives for the process
            let vm_ref = &*(ptr as *const VZVirtualMachine);
            let tx = start_tx.clone();
            let handler = RcBlock::new(move |err: *mut NSError| {
                let _ = tx.send(if err.is_null() {
                    Ok(ptr)
                } else {
                    Err(format!("VM start failed: {:?}", &*err))
                });
            });
            vm_ref.startWithCompletionHandler(&handler);
            Ok(())
        })();
        if let Err(e) = build {
            let _ = start_tx.send(Err(e));
        }
    });

    let vm_ptr = start_rx
        .recv()
        .map_err(|_| "vm start: channel closed".to_string())??;

    // ponytail: fixed wait for the guest's vsock listener to come up; swap for
    // a connect-retry loop if this proves flaky on slower machines.
    std::thread::sleep(std::time::Duration::from_secs(4));

    // Stage 2: connect to the guest vsock `port`, hand back the socket fd.
    let (fd_tx, fd_rx) = std::sync::mpsc::channel::<Result<RawFd, String>>();
    queue.exec_async(move || unsafe {
        let vm = &*(vm_ptr as *const VZVirtualMachine);
        let dev = match vm.socketDevices().firstObject() {
            Some(d) => d,
            None => {
                let _ = fd_tx.send(Err("guest has no vsock device".into()));
                return;
            }
        };
        let dev = match dev.downcast::<VZVirtioSocketDevice>() {
            Ok(d) => d,
            Err(_) => {
                let _ = fd_tx.send(Err("unexpected vsock device type".into()));
                return;
            }
        };
        let tx = fd_tx.clone();
        let handler =
            RcBlock::new(move |conn: *mut VZVirtioSocketConnection, err: *mut NSError| {
                if !err.is_null() {
                    let _ = tx.send(Err(format!("vsock connect to port {port} failed: {:?}", &*err)));
                    return;
                }
                // dup so the fd outlives the connection object.
                let fd = libc::dup((*conn).fileDescriptor());
                let _ = tx.send(if fd >= 0 {
                    Ok(fd)
                } else {
                    Err("dup vsock fd failed".into())
                });
            });
        dev.connectToPort_completionHandler(port, &handler);
    });

    fd_rx
        .recv()
        .map_err(|_| "vsock connect: channel closed".to_string())?
}

/// Handle `carrier machine <action>`. `status` is fully live; `init`/`start`/
/// `stop` land once the provisioning artifacts + boot path are wired (Phase 3).
pub fn machine(action: crate::cli::MachineCmd) {
    use crate::cli::MachineCmd;
    match action {
        MachineCmd::Status => {
            println!("vm dir:      {}", vm_dir().display());
            println!(
                "provisioned: {}",
                if is_provisioned() {
                    "yes"
                } else {
                    "no — run `carrier machine init`"
                }
            );
        }
        // Run off the tokio runtime: provision() uses blocking reqwest, which
        // panics inside an async context.
        MachineCmd::Init => match std::thread::spawn(provision).join() {
            Ok(Ok(())) => println!("guest provisioned at {}", vm_dir().display()),
            Ok(Err(e)) => {
                eprintln!("carrier: provisioning failed: {e}");
                std::process::exit(1);
            }
            Err(_) => {
                eprintln!("carrier: provisioning thread panicked");
                std::process::exit(1);
            }
        },
        MachineCmd::Start => match boot_and_connect(1024) {
            Ok(fd) => {
                use std::io::{Read, Write};
                // ponytail: UnixStream is just a SOCK_STREAM wrapper — fine over a
                // vsock fd; read()/write() don't care about the address family.
                let mut ch = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
                let _ = ch.set_read_timeout(Some(std::time::Duration::from_secs(20)));
                let _ = ch.write_all(b"run\n"); // ask the agent to runc-run the baked bundle
                // Agent writes its reply then closes, so read to EOF.
                let mut reply = Vec::new();
                let _ = ch.read_to_end(&mut reply);
                eprintln!(
                    "[carrier] guest agent replied:\n{}",
                    String::from_utf8_lossy(&reply).trim_end()
                );
                eprintln!("[carrier] Ctrl-C to stop.");
                // Keep `ch` (and the VM, on its queue) alive by parking.
                loop {
                    std::thread::park();
                }
            }
            Err(e) => {
                eprintln!("carrier: {e}");
                std::process::exit(1);
            }
        },
        // ponytail: foreground start forgets the VM handle, so there's nothing to
        // signal yet. Graceful stop arrives with the daemon/proxy (Phase 4).
        MachineCmd::Stop => {
            eprintln!("carrier: stop the foreground `machine start` with Ctrl-C (daemon stop is Phase 4).");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_paths_are_under_vm_dir() {
        let dir = vm_dir();
        assert!(dir.ends_with("carrier/vm"));
        assert!(kernel_path().starts_with(&dir));
        assert!(initrd_path().starts_with(&dir));
    }


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
