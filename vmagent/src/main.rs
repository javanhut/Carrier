//! Carrier guest agent — PID 1 inside the bundled Linux VM.
//!
//! Boots as init, mounts what runc needs, then serves a dead-simple line
//! protocol over AF_VSOCK so the macOS host can drive the guest without
//! sshd/keys/network. Protocol: send a line; "run" launches the baked OCI
//! bundle via runc and returns its output; anything else returns uname + echo.
//!
//! ponytail: raw libc for AF_VSOCK + mounts — a vsock/nix dep for ~30 lines of
//! syscalls isn't worth it. Single connection at a time; fork per conn if the
//! host ever needs concurrent commands. The baked bundle is a proof artifact —
//! host-prepared bundles over virtiofs replace it for dynamic images.

use std::ffi::CString;
use std::io::{Read, Write};
use std::mem;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::ptr;

const AGENT_PORT: u32 = 1024;

fn main() -> ! {
    // PID 1: mount the filesystems runc needs. Best-effort; runc errors surface
    // to the host if any are missing in this kernel.
    mount(c"proc", "/proc", c"proc");
    mount(c"sysfs", "/sys", c"sysfs");
    mount(c"cgroup2", "/sys/fs/cgroup", c"cgroup2");
    mount(c"devtmpfs", "/dev", c"devtmpfs");
    // virtiofs: the host shares the OCI bundle in under tag "carrierbundle".
    mount(c"carrierbundle", "/bundle", c"virtiofs");
    unsafe { libc::mkdir(c"/run".as_ptr(), 0o755) };
    eprintln!("carrier-agent: up, listening on vsock port {AGENT_PORT}");

    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "vsock socket() failed");
    let mut addr: libc::sockaddr_vm = unsafe { mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_port = AGENT_PORT;
    addr.svm_cid = libc::VMADDR_CID_ANY;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    assert!(rc == 0, "vsock bind() failed");
    assert!(unsafe { libc::listen(fd, 4) } == 0, "vsock listen() failed");

    loop {
        let c = unsafe { libc::accept(fd, ptr::null_mut(), ptr::null_mut()) };
        if c < 0 {
            continue;
        }
        let mut conn = unsafe { UnixStream::from_raw_fd(c) };
        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]).trim().to_string();
        let _ = conn.write_all(handle(&req).as_bytes());
        // conn drops -> closes the connection.
    }
}

fn mount(src: &std::ffi::CStr, target: &str, fstype: &std::ffi::CStr) {
    let t = CString::new(target).unwrap();
    let rc = unsafe {
        libc::mkdir(t.as_ptr(), 0o755);
        libc::mount(src.as_ptr(), t.as_ptr(), fstype.as_ptr(), 0, ptr::null())
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        eprintln!("carrier-agent: mount {} ({}) failed: {e}", target, fstype.to_string_lossy());
    }
}

fn handle(req: &str) -> String {
    if req == "run" {
        return run_container();
    }
    let mut u: libc::utsname = unsafe { mem::zeroed() };
    let uname = if unsafe { libc::uname(&mut u) } == 0 {
        let cstr = |a: &[libc::c_char]| {
            let b: Vec<u8> = a.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
            String::from_utf8_lossy(&b).into_owned()
        };
        format!("{} {} {}", cstr(&u.sysname), cstr(&u.release), cstr(&u.machine))
    } else {
        "uname failed".into()
    };
    format!("carrier-agent ok\nuname: {uname}\nyou said: {req}\n")
}

fn run_container() -> String {
    // --no-pivot: the rootfs sits on the initramfs ramdisk, where pivot_root is
    // unsupported; runc falls back to MS_MOVE + chroot.
    match Command::new("/bin/runc")
        .args(["--root", "/run/runc", "run", "--no-pivot", "--bundle", "/bundle", "carrier-test"])
        .output()
    {
        Ok(o) => format!(
            "runc exit={}\n--- stdout ---\n{}--- stderr ---\n{}",
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr),
        ),
        Err(e) => format!("failed to exec runc: {e}"),
    }
}
