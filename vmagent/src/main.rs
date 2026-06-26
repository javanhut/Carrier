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
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::ptr;

const AGENT_PORT: u32 = 1024;

fn main() -> ! {
    // PID 1: mount the filesystems runc needs. Best-effort; runc errors surface
    // to the host if any are missing in this kernel.
    mount(c"proc", "/proc", c"proc");
    mount(c"sysfs", "/sys", c"sysfs");
    mount(c"cgroup2", "/sys/fs/cgroup", c"cgroup2");
    mount(c"devtmpfs", "/dev", c"devtmpfs");
    mount(c"devpts", "/dev/pts", c"devpts"); // openpty needs /dev/pts
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
        // Read just the command line (byte-by-byte) so we don't swallow the
        // interactive stdin that follows on the same connection.
        let cmd = read_line(&mut conn);
        match cmd.trim() {
            "run-t" => run_container_tty(conn),
            "run-i" => run_container_interactive(conn),
            other => {
                let _ = conn.write_all(handle(other).as_bytes());
            }
        }
        // conn drops -> closes the connection.
    }
}

fn read_line(conn: &mut UnixStream) -> String {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while let Ok(1) = conn.read(&mut b) {
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
    }
    String::from_utf8_lossy(&line).into_owned()
}

/// TTY run: allocate a PTY, run the container on the slave (so it sees a real
/// terminal — prompt, echo, colors), and bridge the master to the vsock
/// connection. Gives `carrier run -it` a proper interactive terminal.
fn run_container_tty(conn: UnixStream) {
    let vsock: RawFd = conn.into_raw_fd();
    let (mut master, mut slave): (RawFd, RawFd) = (-1, -1);
    let rc = unsafe {
        libc::openpty(&mut master, &mut slave, ptr::null_mut(), ptr::null(), ptr::null())
    };
    if rc != 0 {
        unsafe { libc::close(vsock) };
        return;
    }
    let mk = || unsafe { Stdio::from_raw_fd(libc::dup(slave)) };
    let child = Command::new("/bin/runc")
        .args(["--root", "/run/runc", "run", "--no-pivot", "--bundle", "/bundle", "carrier-test"])
        .stdin(mk())
        .stdout(mk())
        .stderr(mk())
        .spawn();
    unsafe { libc::close(slave) };
    let mut child = match child {
        Ok(c) => c,
        Err(_) => {
            unsafe {
                libc::close(master);
                libc::close(vsock);
            }
            return;
        }
    };
    // Bridge: host->pty in a thread, pty->host on this thread (ends at pty EOF =
    // container exit). Each direction owns dup'd fds it closes when done.
    let (v_read, m_write) = unsafe { (libc::dup(vsock), libc::dup(master)) };
    let t = std::thread::spawn(move || pipe_fd(v_read, m_write));
    pipe_fd(master, vsock);
    let _ = child.wait();
    let _ = t.join();
    unsafe {
        libc::close(master);
        libc::close(vsock);
    }
}

/// Copy from one fd to another until EOF/error, then close both.
fn pipe_fd(from: RawFd, to: RawFd) {
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(from, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n <= 0 {
            break;
        }
        let mut off = 0isize;
        while off < n {
            let w = unsafe {
                libc::write(to, buf.as_ptr().offset(off) as *const _, (n - off) as usize)
            };
            if w <= 0 {
                break;
            }
            off += w;
        }
    }
    unsafe {
        libc::close(from);
        libc::close(to);
    }
}

/// Interactive run: wire the vsock connection straight to the container's
/// stdin/stdout/stderr so the host's terminal drives it. Closing the fd at the
/// end signals EOF to the host.
fn run_container_interactive(conn: UnixStream) {
    let fd: RawFd = conn.into_raw_fd();
    let mk = || unsafe { Stdio::from_raw_fd(libc::dup(fd)) };
    let _ = Command::new("/bin/runc")
        .args(["--root", "/run/runc", "run", "--no-pivot", "--bundle", "/bundle", "carrier-test"])
        .stdin(mk())
        .stdout(mk())
        .stderr(mk())
        .status();
    unsafe { libc::close(fd) };
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
        // First line is the exit marker the host strips; the rest is raw
        // container output (stdout then stderr).
        Ok(o) => format!(
            "EXIT {}\n{}{}",
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr),
        ),
        Err(e) => format!("EXIT 127\nfailed to exec runc: {e}\n"),
    }
}
