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
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::OnceLock;

const AGENT_PORT: u32 = 1024;

// Bundle dir runc uses — an overlay (writable) over the virtiofs rootfs, or
// "/bundle" if overlay isn't available. Set once at startup.
static BUNDLE: OnceLock<&'static str> = OnceLock::new();
fn bundle_dir() -> &'static str {
    BUNDLE.get().copied().unwrap_or("/bundle")
}

/// Make the container rootfs writable: overlay the read-only virtiofs image with
/// a RAM upper layer (the initramfs root is writable RAM), so package installs
/// (dpkg writes) work. Falls back to the virtiofs bundle if overlay fails.
fn setup_rootfs() -> &'static str {
    unsafe {
        for d in [
            c"/run/ovl", c"/run/ovl/upper", c"/run/ovl/work",
            c"/run/cbundle", c"/run/cbundle/rootfs",
        ] {
            libc::mkdir(d.as_ptr(), 0o755);
        }
        let opts = c"lowerdir=/bundle/rootfs,upperdir=/run/ovl/upper,workdir=/run/ovl/work";
        let rc = libc::mount(
            c"overlay".as_ptr(),
            c"/run/cbundle/rootfs".as_ptr(),
            c"overlay".as_ptr(),
            0,
            opts.as_ptr() as *const _,
        );
        if rc != 0 {
            eprintln!(
                "carrier-agent: overlay rootfs failed ({}); writes won't persist",
                std::io::Error::last_os_error()
            );
            return "/bundle";
        }
    }
    let _ = std::fs::copy("/bundle/config.json", "/run/cbundle/config.json");
    "/run/cbundle"
}

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
    let _ = BUNDLE.set(setup_rootfs());
    setup_network();
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

/// TTY run: runc (with OCI terminal:true) allocates the PTY, sets it as the
/// container's controlling terminal, and passes its master back over a console
/// socket. We receive that master fd and bridge it to the vsock connection, so
/// `carrier run -it` gets a real interactive terminal (prompt, echo, colors).
fn run_container_tty(conn: UnixStream) {
    let vsock: RawFd = conn.into_raw_fd();
    let sock = "/run/console.sock";
    let _ = std::fs::remove_file(sock);
    let listener = match UnixListener::bind(sock) {
        Ok(l) => l,
        Err(_) => {
            unsafe { libc::close(vsock) };
            return;
        }
    };
    // Detached: runc returns after setup, having sent the PTY master to `sock`.
    let ok = Command::new("/bin/runc")
        .args([
            "--root", "/run/runc", "run", "-d", "--console-socket", sock,
            "--no-pivot", "--bundle", bundle_dir(), "carrier-test",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        unsafe { libc::close(vsock) };
        return;
    }
    let master = match listener.accept() {
        Ok((c, _)) => recv_fd(c.as_raw_fd()),
        Err(_) => -1,
    };
    if master < 0 {
        unsafe { libc::close(vsock) };
        return;
    }
    // Bridge: share the fds (full-duplex, no dup). Host->PTY in a thread; PTY->
    // host on this thread, which ends when the container exits (master EOF). Then
    // shutdown the vsock so the host sees EOF and the thread's read unblocks —
    // dup'ing instead would keep the connection half-open and hang on exit.
    let t = std::thread::spawn(move || copy_loop(vsock, master));
    copy_loop(master, vsock);
    unsafe { libc::shutdown(vsock, libc::SHUT_RDWR) };
    let _ = t.join();
    unsafe {
        libc::close(master);
        libc::close(vsock);
    }
    let _ = Command::new("/bin/runc")
        .args(["--root", "/run/runc", "delete", "-f", "carrier-test"])
        .status();
}

/// Receive a single fd over a unix socket via SCM_RIGHTS (the console-socket
/// protocol runc uses to hand back the PTY master).
fn recv_fd(sock: RawFd) -> RawFd {
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut _,
        iov_len: 1,
    };
    let mut cmsg = [0u8; 32];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg.len() as _;
    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n <= 0 {
        return -1;
    }
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        if c.is_null() {
            return -1;
        }
        *(libc::CMSG_DATA(c) as *const RawFd)
    }
}

/// Copy from one fd to another until EOF/error. Does not close (the caller owns
/// the fds and tears them down after the bridge ends).
fn copy_loop(from: RawFd, to: RawFd) {
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
}

/// Interactive run: wire the vsock connection straight to the container's
/// stdin/stdout/stderr so the host's terminal drives it. Closing the fd at the
/// end signals EOF to the host.
fn run_container_interactive(conn: UnixStream) {
    let fd: RawFd = conn.into_raw_fd();
    let mk = || unsafe { Stdio::from_raw_fd(libc::dup(fd)) };
    let _ = Command::new("/bin/runc")
        .args(["--root", "/run/runc", "run", "--no-pivot", "--bundle", bundle_dir(), "carrier-test"])
        .stdin(mk())
        .stdout(mk())
        .stderr(mk())
        .status();
    unsafe { libc::close(fd) };
}

/// Bring up eth0 and DHCP it via busybox udhcpc (NAT from VZ). The container
/// shares this netns, so it gets connectivity; /etc/resolv.conf (written by the
/// udhcpc script, bind-mounted into the container) gives it DNS.
fn setup_network() {
    use std::fs;
    let _ = fs::create_dir_all("/etc");
    let _ = fs::write("/etc/resolv.conf", b""); // ensure it exists for the bind mount
    let _ = Command::new("/bin/busybox")
        .args(["ip", "link", "set", "eth0", "up"])
        .status();
    let _ = Command::new("/bin/busybox")
        .args(["udhcpc", "-i", "eth0", "-s", "/udhcpc.sh", "-q", "-n", "-t", "8"])
        .status();
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
        .args(["--root", "/run/runc", "run", "--no-pivot", "--bundle", bundle_dir(), "carrier-test"])
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
