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

use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::path::{Path, PathBuf};

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::AllocAnyThread;
use objc2::rc::Retained;
use objc2_foundation::{NSArray, NSError, NSFileHandle, NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageStorageDeviceAttachment, VZFileHandleSerialPortAttachment, VZLinuxBootLoader,
    VZNATNetworkDeviceAttachment, VZSharedDirectory, VZSingleDirectoryShare,
    VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceSerialPortConfiguration,
    VZVirtioEntropyDeviceConfiguration, VZVirtioFileSystemDeviceConfiguration,
    VZVirtioNetworkDeviceConfiguration, VZVirtioSocketConnection, VZVirtioSocketDevice,
    VZVirtioSocketDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
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
    NSURL::fileURLWithPath(&NSString::from_str(&p.to_string_lossy()))
}

/// Build a `VZVirtualMachineConfiguration` for a Linux guest from `spec`.
/// Touches the filesystem only to open the rootfs disk image (via the disk
/// attachment); the kernel/initrd URLs are validated at boot, not here.
pub fn build_config(spec: &VmSpec) -> Result<Retained<VZVirtualMachineConfiguration>, String> {
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
        cfg.setStorageDevices(&NSArray::from_retained_slice(&[Retained::into_super(
            block,
        )]));
        let entropy = VZVirtioEntropyDeviceConfiguration::new();
        cfg.setEntropyDevices(&NSArray::from_retained_slice(&[Retained::into_super(
            entropy,
        )]));

        Ok(cfg)
    }
}

/// Build and validate a VM configuration, surfacing why it's invalid. Used by
/// `carrier machine` (Phase 3) to fail fast before attempting to boot.
pub fn validate(spec: &VmSpec) -> Result<(), String> {
    let cfg = build_config(spec)?;
    // SAFETY: validateWithError: only reads the config; no preconditions.
    unsafe { cfg.validateWithError() }.map_err(|e| format!("invalid VM configuration: {e:?}"))
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

/// OCI/Kata/runc architecture name ("arm64"/"amd64") for this binary. macOS VZ
/// runs a *same-arch* Linux guest, so the host binary's arch is the guest arch.
fn guest_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        _ => "arm64", // aarch64
    }
}

// Kata Containers kernel: raw arm64, with the cgroups/namespaces/vsock/virtiofs
// runc needs (PUI PUI's minimal kernel lacks cgroups). Pinned to a release.
// ponytail: 664MB bundle streamed to extract one 18MB kernel — wasteful, but the
// only public source. Upgrade path: host the extracted vmlinux and fetch that.
const KATA_VER: &str = "3.32.0";
const KATA_KERNEL: &str = "./opt/kata/share/kata-containers/vmlinux-6.18.35-197";

/// Write the compiled-in guest (kernel + agent initramfs) to vm_dir if missing.
/// When the artifacts are embedded (carrier_embedded), the VM self-installs on
/// first run — no download, no toolchain. Otherwise a no-op; provision()
/// downloads.
fn ensure_guest() {
    #[cfg(carrier_embedded)]
    {
        const KERNEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/Image"));
        const INITRD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/initramfs.cpio.gz"));
        let _ = std::fs::create_dir_all(vm_dir());
        // Refresh when the embedded guest changes (new carrier build) so an
        // upgrade doesn't keep booting a stale on-disk guest. Length tag is a
        // cheap content marker.
        let ver = vm_dir().join("guest.version");
        let tag = format!("{}-{}", KERNEL.len(), INITRD.len());
        if std::fs::read_to_string(&ver).unwrap_or_default() != tag {
            let _ = std::fs::write(kernel_path(), KERNEL);
            let _ = std::fs::write(initrd_path(), INITRD);
            let _ = std::fs::write(&ver, &tag);
        }
    }
}

/// Fetch the runc-capable guest kernel into `vm_dir()`. The agent initramfs is a
/// build artifact (`vmagent/build.sh`), reported if missing.
fn provision() -> Result<(), String> {
    std::fs::create_dir_all(vm_dir()).map_err(|e| format!("mkdir {}: {e}", vm_dir().display()))?;

    ensure_guest(); // instant if the guest is embedded in the binary
    if is_provisioned() {
        eprintln!("guest ready (embedded).");
        return Ok(());
    }

    if kernel_path().exists() {
        eprintln!("kernel already present.");
    } else {
        eprintln!("downloading container kernel (Kata {KATA_VER}, ~664MB one-time, keeps 18MB)...");
        let url = format!(
            "https://github.com/kata-containers/kata-containers/releases/download/{KATA_VER}/kata-static-{KATA_VER}-{arch}.tar.zst",
            arch = guest_arch()
        );
        // Stream the bundle, write only the kernel member (tar -O). Needs curl +
        // a zstd-capable tar — both ship with macOS.
        let pipe = format!(
            "curl -fL '{url}' | tar --zstd -xO -f - '{KATA_KERNEL}' > '{}'",
            kernel_path().display()
        );
        let ok = std::process::Command::new("sh")
            .arg("-c")
            .arg(&pipe)
            .status()
            .map_err(|e| format!("spawn download: {e}"))?
            .success();
        // tar -O can write a partial file on failure; verify a real kernel landed.
        let size = std::fs::metadata(kernel_path())
            .map(|m| m.len())
            .unwrap_or(0);
        if !ok || size < 1_000_000 {
            let _ = std::fs::remove_file(kernel_path());
            return Err("kernel download/extract failed (need curl + zstd-capable tar)".into());
        }
    }

    if !initrd_path().exists() {
        return Err(format!(
            "kernel ready. Build the guest agent initramfs to finish: run `vmagent/build.sh` \
             (one-time first: `rustup target add aarch64-unknown-linux-musl`)."
        ));
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
fn boot_and_connect(port: u32, console: bool) -> Result<RawFd, String> {
    if !is_provisioned() {
        return Err("not provisioned — run `carrier machine init` first".into());
    }
    let kernel = kernel_path();
    let initrd = initrd_path();
    let bundle = vm_dir().join("bundle"); // host-prepared OCI bundle, shared via virtiofs
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

            let cfg = VZVirtualMachineConfiguration::new();
            cfg.setCPUCount(2);
            cfg.setMemorySize(512 * 1024 * 1024);
            cfg.setBootLoader(Some(&*boot));
            // Serial console: always present so the kernel's `console=hvc0` has a
            // device (dropping it disturbs boot). Write to our stdout only for
            // machine start; `carrier run` sends it to the null device — clean
            // terminal, container output comes over vsock. Never read host stdin:
            // it hijacks and closes the terminal.
            // VZ wants real fds (the null-device handle throws). Read from
            // /dev/null (never host stdin — it hijacks the terminal). Write to our
            // stdout for `machine start`, or to console.log for `carrier run`
            // (clean terminal; container output comes over vsock). closeOnDealloc
            // owns the fd (into_raw_fd hands it over, no double close).
            let null_in = std::fs::File::open("/dev/null")
                .map_err(|e| e.to_string())?
                .into_raw_fd();
            let reader = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                NSFileHandle::alloc(),
                null_in,
                true,
            );
            let writer = if console {
                NSFileHandle::fileHandleWithStandardOutput()
            } else {
                let log = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(vm_dir().join("console.log"))
                    .map_err(|e| e.to_string())?
                    .into_raw_fd();
                NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                    NSFileHandle::alloc(),
                    log,
                    true,
                )
            };
            let attach =
                VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                    VZFileHandleSerialPortAttachment::alloc(),
                    Some(&reader),
                    Some(&writer),
                );
            let serial = VZVirtioConsoleDeviceSerialPortConfiguration::new();
            serial.setAttachment(Some(&*attach));
            cfg.setSerialPorts(&NSArray::from_retained_slice(&[Retained::into_super(
                serial,
            )]));
            cfg.setEntropyDevices(&NSArray::from_retained_slice(&[Retained::into_super(
                VZVirtioEntropyDeviceConfiguration::new(),
            )]));
            // vsock: the host<->guest transport for the command proxy.
            cfg.setSocketDevices(&NSArray::from_retained_slice(&[Retained::into_super(
                VZVirtioSocketDeviceConfiguration::new(),
            )]));
            // virtiofs: share the host-prepared OCI bundle into the guest (tag
            // "carrierbundle"), read-write so runc can create mountpoints and the
            // container can write to its rootfs. prepare_bundle recreates the
            // bundle each run, so host-side mutation is ephemeral.
            let shared = VZSharedDirectory::initWithURL_readOnly(
                VZSharedDirectory::alloc(),
                &file_url(&bundle),
                false,
            );
            let share =
                VZSingleDirectoryShare::initWithDirectory(VZSingleDirectoryShare::alloc(), &shared);
            let fsdev = VZVirtioFileSystemDeviceConfiguration::initWithTag(
                VZVirtioFileSystemDeviceConfiguration::alloc(),
                &NSString::from_str("carrierbundle"),
            );
            fsdev.setShare(Some(&*share));
            cfg.setDirectorySharingDevices(&NSArray::from_retained_slice(&[Retained::into_super(
                fsdev,
            )]));
            // NAT networking so the guest (and the container, which shares its
            // netns) can reach the internet (apt/curl/etc.).
            let net = VZVirtioNetworkDeviceConfiguration::new();
            net.setAttachment(Some(&*VZNATNetworkDeviceAttachment::new()));
            cfg.setNetworkDevices(&NSArray::from_retained_slice(&[Retained::into_super(net)]));
            cfg.validateWithError()
                .map_err(|e| format!("invalid VM config: {e:?}"))?;

            let vm =
                VZVirtualMachine::initWithConfiguration_queue(VZVirtualMachine::alloc(), &cfg, &q1);
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
        let handler = RcBlock::new(
            move |conn: *mut VZVirtioSocketConnection, err: *mut NSError| {
                if !err.is_null() {
                    let _ = tx.send(Err(format!(
                        "vsock connect to port {port} failed: {:?}",
                        &*err
                    )));
                    return;
                }
                // dup so the fd outlives the connection object.
                let fd = libc::dup((*conn).fileDescriptor());
                let _ = tx.send(if fd >= 0 {
                    Ok(fd)
                } else {
                    Err("dup vsock fd failed".into())
                });
            },
        );
        dev.connectToPort_completionHandler(port, &handler);
    });

    fd_rx
        .recv()
        .map_err(|_| "vsock connect: channel closed".to_string())?
}

/// `carrier run <image> [cmd]` on macOS: build the OCI bundle on the host (which
/// already pulls/extracts images cross-platform), share it into the guest over
/// virtiofs, boot, run it via the agent, and print the output.
pub async fn run_in_vm(
    image: String,
    mut command: Vec<String>,
    interactive: bool,
    tty: bool,
    detach: bool,
    name: Option<String>,
) {
    ensure_guest(); // self-install the embedded guest on first run
    if !is_provisioned() {
        eprintln!("carrier: VM not provisioned — run `carrier machine init` first");
        std::process::exit(1);
    }
    if detach
        && (command.is_empty()
            || (command.len() == 1
                && matches!(command[0].as_str(), "sh" | "bash" | "/bin/sh" | "/bin/bash")))
    {
        command = vec!["sleep".into(), "infinity".into()];
    }
    if let Err(e) = prepare_bundle(&image, &command, tty).await {
        eprintln!("carrier: {e}");
        std::process::exit(1);
    }
    if detach {
        start_detached(&image, &command, name);
    }
    let fd = match boot_and_connect(1024, false) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("carrier: {e}");
            std::process::exit(1);
        }
    };
    if interactive || tty {
        use std::io::IsTerminal;
        if tty && std::io::stdout().is_terminal() {
            // Embedded terminal pane (ratatui + vt100). Never returns.
            super::vm_tui::session(fd, &image);
        }
        interactive_session(fd, tty); // pumps stdin<->container, never returns
    }
    {
        use std::io::{Read, Write};
        {
            let mut ch = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
            let _ = ch.set_read_timeout(Some(std::time::Duration::from_secs(30)));
            let _ = ch.write_all(b"run\n");
            let mut out = Vec::new();
            let _ = ch.read_to_end(&mut out);
            // Agent replies "EXIT <code>\n<raw container output>".
            let text = String::from_utf8_lossy(&out);
            let (code, body) = match text.strip_prefix("EXIT ") {
                Some(rest) => {
                    let (c, b) = rest.split_once('\n').unwrap_or((rest, ""));
                    (c.trim().parse().unwrap_or(1), b.to_string())
                }
                None => (1, text.to_string()),
            };
            print!("{body}");
            let _ = std::io::stdout().flush();
            // The VM is leaked + running; exiting the process tears it down.
            std::process::exit(code);
        }
    }
}

fn container_dir(id: &str) -> Result<PathBuf, String> {
    let layout = crate::storage::StorageLayout::new().map_err(|e| e.to_string())?;
    Ok(layout.container_path(id))
}

pub fn control_socket(id: &str) -> Result<PathBuf, String> {
    // In run/, not the container dir: the deep overlay-containers path exceeds
    // SUN_LEN (~104 bytes) and unix-socket bind fails.
    let layout = crate::storage::StorageLayout::new().map_err(|e| e.to_string())?;
    Ok(layout.base.join("run").join(format!("{id}.sock")))
}

fn start_detached(image: &str, command: &[String], name: Option<String>) -> ! {
    use std::process::{Command, Stdio};
    let id = crate::storage::generate_container_id();
    let dir = container_dir(&id).unwrap_or_else(|e| fatal(&e));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| fatal(&e.to_string()));
    let metadata = serde_json::json!({
        "id": id,
        "name": name.unwrap_or_else(|| format!("car_{}", &id[..6])),
        "image": image,
        "created": chrono::Utc::now().to_rfc3339(),
        "rootfs": vm_dir().join("bundle/rootfs"),
        "command": command,
        "status": "starting",
        "backend": "macos-vm"
    });
    crate::storage::atomic_write(&dir.join("metadata.json"), metadata.to_string().as_bytes())
        .unwrap_or_else(|e| fatal(&e.to_string()));
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("container.log"))
        .unwrap_or_else(|e| fatal(&e.to_string()));
    let log_err = log.try_clone().unwrap_or_else(|e| fatal(&e.to_string()));
    Command::new(std::env::current_exe().unwrap_or_else(|e| fatal(&e.to_string())))
        .args(["__vm-daemon", &id])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .unwrap_or_else(|e| fatal(&format!("start VM supervisor: {e}")));
    let socket = control_socket(&id).unwrap_or_else(|e| fatal(&e));
    for _ in 0..200 {
        if socket.exists() {
            println!("{id}");
            std::process::exit(0);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    fatal("VM supervisor did not become ready; see the container log")
}

fn fatal(message: &str) -> ! {
    eprintln!("carrier: {message}");
    std::process::exit(1)
}

fn read_frame(stream: &mut std::os::unix::net::UnixStream) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut size = [0u8; 8];
    stream.read_exact(&mut size).map_err(|e| e.to_string())?;
    let len = u64::from_be_bytes(size);
    // ponytail: 64MiB cap — a text reply here means the guest agent is stale
    // (predates framing) and would otherwise parse as an exabyte allocation.
    if len > 64 << 20 {
        return Err(format!(
            "guest sent an unframed reply (stale agent initramfs? re-run vmagent/build.sh): {:?}",
            String::from_utf8_lossy(&size)
        ));
    }
    let mut data = vec![0; len as usize];
    stream.read_exact(&mut data).map_err(|e| e.to_string())?;
    Ok(data)
}

/// Hidden background process that owns the VZ VM and proxies local requests to
/// the long-lived guest-agent connection.
pub fn daemon(container: String) {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    let fd = boot_and_connect(1024, false).unwrap_or_else(|e| fatal(&e));
    let mut guest = unsafe { UnixStream::from_raw_fd(fd) };
    guest
        .write_all(b"supervise\n")
        .unwrap_or_else(|e| fatal(&e.to_string()));
    guest
        .write_all(b"detach\n")
        .unwrap_or_else(|e| fatal(&e.to_string()));
    let reply = read_frame(&mut guest).unwrap_or_else(|e| fatal(&e));
    if !reply.starts_with(b"EXIT 0\n") {
        fatal(&String::from_utf8_lossy(&reply));
    }
    set_vm_status(&container, "running");
    let socket = control_socket(&container).unwrap_or_else(|e| fatal(&e));
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).unwrap_or_else(|e| fatal(&e.to_string()));
    for client in listener.incoming() {
        let Ok(mut client) = client else { continue };
        let mut request = String::new();
        if client.read_to_string(&mut request).is_err() {
            continue;
        }
        if guest.write_all(request.trim_end().as_bytes()).is_err()
            || guest.write_all(b"\n").is_err()
        {
            break;
        }
        let response = match read_frame(&mut guest) {
            Ok(r) => r,
            Err(_) => break,
        };
        let _ = client.write_all(&response);
        if request.trim() == "stop" {
            set_vm_status(&container, "exited");
            break;
        }
    }
    let _ = std::fs::remove_file(socket);
    set_vm_status(&container, "exited");
}

fn set_vm_status(id: &str, status: &str) {
    let Ok(dir) = container_dir(id) else { return };
    let path = dir.join("metadata.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(mut metadata) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    metadata["status"] = serde_json::json!(status);
    let _ = crate::storage::atomic_write(&path, metadata.to_string().as_bytes());
}

fn find_vm_container(query: &str) -> Result<(String, PathBuf), String> {
    let layout = crate::storage::StorageLayout::new().map_err(|e| e.to_string())?;
    let root = layout.base.join("storage/overlay-containers");
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let id = entry.file_name().to_string_lossy().into_owned();
        let metadata =
            std::fs::read_to_string(entry.path().join("metadata.json")).unwrap_or_default();
        let name_matches = serde_json::from_str::<serde_json::Value>(&metadata)
            .ok()
            .and_then(|m| m["name"].as_str().map(|n| n == query))
            .unwrap_or(false);
        if id.starts_with(query) || name_matches {
            matches.push((id, entry.path()));
        }
    }
    match matches.len() {
        0 => Err(format!("container {query} not found")),
        1 => Ok(matches.remove(0)),
        _ => Err(format!("container identifier {query} is ambiguous")),
    }
}

pub fn control(container: &str, request: &str) -> Result<Vec<u8>, String> {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    let (id, _) = find_vm_container(container)?;
    let mut stream = UnixStream::connect(control_socket(&id)?)
        .map_err(|e| format!("container is not running: {e}"))?;
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    if !response.starts_with(b"EXIT 0\n") {
        return Err(String::from_utf8_lossy(&response).trim().to_string());
    }
    Ok(response[7..].to_vec())
}

pub fn exec(container: &str, mut command: Vec<String>) -> Result<(), String> {
    use std::io::Write;
    if command.is_empty() {
        command.push("/bin/sh".into());
    }
    let encoded = command
        .iter()
        .map(|arg| hex::encode(arg.as_bytes()))
        .collect::<Vec<_>>()
        .join(" ");
    let output = control(container, &format!("exec {encoded}"))?;
    std::io::stdout()
        .write_all(&output)
        .map_err(|e| e.to_string())
}

/// Interactive session: forward host stdin to the container and stream its
/// output back over the same vsock channel. Never returns — exits when the
/// container closes the channel.
///
/// `tty`: with -t the guest runs the container on a real PTY, so we put the host
/// terminal in raw mode (the guest PTY does echo/line-editing/prompts). Without
/// -t (plain -i) it's cooked line mode — the host terminal echoes and full lines
/// go to the shell.
fn interactive_session(fd: RawFd, tty: bool) -> ! {
    use std::io::{Read, Write};
    let mut ch = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    let _ = ch.write_all(if tty { b"run-t\n" } else { b"run-i\n" });
    if tty {
        // The agent expects a "cols rows" size line after run-t; zeros = skip.
        let mut ws = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) };
        let _ = ch.write_all(format!("{} {}\n", ws.ws_col, ws.ws_row).as_bytes());
    }

    let orig = if tty { set_raw_mode() } else { None };
    // Host stdin -> container, in a thread (read blocks).
    if let Ok(mut ch_in) = ch.try_clone() {
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut std::io::stdin(), &mut ch_in);
            let _ = ch_in.shutdown(std::net::Shutdown::Write); // EOF to the guest
        });
    }
    // Container -> host stdout, until the channel closes (container exit).
    let mut out = std::io::stdout();
    let mut buf = [0u8; 4096];
    loop {
        match ch.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let _ = out.write_all(&buf[..n]);
                let _ = out.flush();
            }
        }
    }
    restore_raw_mode(orig);
    std::process::exit(0);
}

/// Put stdin in raw mode (only if it's a TTY) so keystrokes pass straight to the
/// container's PTY. Returns the original termios to restore.
fn set_raw_mode() -> Option<libc::termios> {
    unsafe {
        if libc::isatty(0) == 0 {
            return None;
        }
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut t) != 0 {
            return None;
        }
        let orig = t;
        libc::cfmakeraw(&mut t);
        libc::tcsetattr(0, libc::TCSANOW, &t);
        Some(orig)
    }
}

fn restore_raw_mode(orig: Option<libc::termios>) {
    if let Some(t) = orig {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &t);
        }
    }
}

/// Pull `image` (reusing carrier's cross-platform pull), merge its layers into a
/// rootfs, and write an OCI config running `command` — all under vm_dir/bundle,
/// which boot_and_connect shares into the guest via virtiofs.
async fn prepare_bundle(image: &str, command: &[String], tty: bool) -> Result<(), String> {
    use crate::cli::RegistryImage;
    use crate::storage::{StorageLayout, apply_layer_rootless, atomic_write};

    // 1. Pull into the shared blob cache (guest matches the host arch).
    crate::commands::pull_image(image.to_string(), Some(format!("linux/{}", guest_arch()))).await;

    // 2. Read the manifest's ordered layer digests.
    let parsed = RegistryImage::parse(image)?;
    let layout = StorageLayout::new().map_err(|e| e.to_string())?;
    let meta = layout.image_metadata_path(&parsed.image, &parsed.tag);
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&meta)
            .map_err(|e| format!("read manifest {}: {e}", meta.display()))?,
    )
    .map_err(|e| format!("parse manifest: {e}"))?;
    let layers = manifest["layers"]
        .as_array()
        .ok_or("manifest has no layers")?;

    // 3. Merge layers into a staging rootfs, applying OCI whiteouts. Publish the
    // complete tree only after every layer succeeds.
    let rootfs = vm_dir().join("bundle/rootfs");
    let staging = vm_dir().join(format!("bundle/.rootfs-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    for layer in layers {
        let Some(digest) = layer["digest"].as_str() else {
            let _ = std::fs::remove_dir_all(&staging);
            return Err("layer missing digest".into());
        };
        if let Err(error) = apply_layer_rootless(&layout.blob_cache_path(digest), &staging) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(format!("apply {digest}: {error}"));
        }
    }
    // 4. Take the image's default entrypoint/cmd/env/cwd from its config blob, so
    // `carrier run <image>` (no command) runs the image as built. A user command
    // replaces Cmd (Docker semantics: Entrypoint is kept).
    let icfg = manifest["config"]["digest"]
        .as_str()
        .and_then(|d| std::fs::read_to_string(layout.blob_cache_path(d)).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .map(|j| j["config"].clone())
        .unwrap_or(serde_json::Value::Null);
    let strs = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let entrypoint = strs(&icfg["Entrypoint"]);
    let args: Vec<String> = if command.is_empty() {
        [entrypoint, strs(&icfg["Cmd"])].concat()
    } else {
        [entrypoint, command.to_vec()].concat()
    };
    if args.is_empty() {
        let _ = std::fs::remove_dir_all(&staging);
        return Err("image has no default command — pass one: `carrier run <image> <cmd>`".into());
    }
    let mut env = strs(&icfg["Env"]);
    if env.is_empty() {
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    }
    if !env.iter().any(|e| e.starts_with("TERM=")) {
        env.push("TERM=xterm".into()); // so clear/ncurses work under the PTY
    }
    let cwd = icfg["WorkingDir"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("/");
    let config = bundle_config(&args, &env, cwd, tty);

    // Commit rootfs and config together with rollback to the previous rootfs if
    // publishing either artifact fails.
    let previous = vm_dir().join("bundle/.rootfs-previous");
    let _ = std::fs::remove_dir_all(&previous);
    if rootfs.exists() {
        std::fs::rename(&rootfs, &previous).map_err(|e| e.to_string())?;
    }
    if let Err(error) = std::fs::rename(&staging, &rootfs) {
        if previous.exists() {
            let _ = std::fs::rename(&previous, &rootfs);
        }
        return Err(error.to_string());
    }
    if let Err(error) = atomic_write(&vm_dir().join("bundle/config.json"), config.as_bytes()) {
        let _ = std::fs::remove_dir_all(&rootfs);
        if previous.exists() {
            let _ = std::fs::rename(&previous, &rootfs);
        }
        return Err(error.to_string());
    }
    let _ = std::fs::remove_dir_all(previous);
    Ok(())
}

/// Docker's default container capabilities.
const DEFAULT_CAPS: [&str; 14] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
];

/// Minimal OCI runtime spec. `terminal` true makes runc allocate a PTY (for -it).
fn bundle_config(args: &[String], env: &[String], cwd: &str, terminal: bool) -> String {
    serde_json::json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": terminal,
            "user": { "uid": 0, "gid": 0 },
            "args": args,
            "env": env,
            "cwd": cwd,
            // Docker's default capability set — apt's http method drops to the
            // _apt user, so it needs CAP_SETUID/SETGID etc.
            "capabilities": {
                "bounding": DEFAULT_CAPS,
                "effective": DEFAULT_CAPS,
                "permitted": DEFAULT_CAPS
            },
            "noNewPrivileges": true
        },
        "root": { "path": "rootfs", "readonly": false },
        "hostname": "carrier",
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc" },
            { "destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] },
            // devpts: required for terminal:true so runc can open /dev/pts/ptmx.
            { "destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"] },
            { "destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"] },
            // DNS: the container shares the guest netns; bind the guest's resolver.
            { "destination": "/etc/resolv.conf", "type": "bind", "source": "/etc/resolv.conf", "options": ["bind", "ro"] }
        ],
        "linux": { "namespaces": [ {"type":"pid"}, {"type":"ipc"}, {"type":"uts"}, {"type":"mount"} ] }
    })
    .to_string()
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
        MachineCmd::Start => match boot_and_connect(1024, true) {
            Ok(fd) => {
                use std::io::{Read, Write};
                // ponytail: UnixStream is just a SOCK_STREAM wrapper — fine over a
                // vsock fd; read()/write() don't care about the address family.
                let mut ch = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
                let _ = ch.set_read_timeout(Some(std::time::Duration::from_secs(20)));
                let _ = ch.write_all(b"run\n"); // ask the agent to runc-run the bundle
                // Agent writes "EXIT <code>\n<raw output>" then closes.
                let mut reply = Vec::new();
                let _ = ch.read_to_end(&mut reply);
                let text = String::from_utf8_lossy(&reply);
                let (code, body) = match text.strip_prefix("EXIT ") {
                    Some(rest) => {
                        let (c, b) = rest.split_once('\n').unwrap_or((rest, ""));
                        (c.trim().parse().unwrap_or(1), b.to_string())
                    }
                    None => (1, text.to_string()),
                };
                print!("{body}");
                let _ = std::io::stdout().flush();
                std::process::exit(code);
            }
            Err(e) => {
                eprintln!("carrier: {e}");
                std::process::exit(1);
            }
        },
        // ponytail: foreground start forgets the VM handle, so there's nothing to
        // signal yet. Graceful stop arrives with the daemon/proxy (Phase 4).
        MachineCmd::Stop => {
            eprintln!(
                "carrier: stop the foreground `machine start` with Ctrl-C (daemon stop is Phase 4)."
            );
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
