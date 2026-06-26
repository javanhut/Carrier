//! Carrier guest agent — PID 1 inside the bundled Linux VM.
//!
//! Boots as init, mounts the basics, then serves a dead-simple line protocol
//! over AF_VSOCK so the macOS host can drive the guest without sshd/keys/network.
//! Today it answers a request with `uname` (proof we're really in the Linux
//! guest) and echoes the request. `runc`-based container exec lands on top of
//! this same channel once a runc-capable rootfs + bundle sharing exist.
//!
//! ponytail: raw libc for AF_VSOCK — a vsock crate would be one more dep for
//! ~20 lines of socket setup. Single-connection-at-a-time loop; fork per conn
//! if the host ever needs concurrent commands.

use std::io::{Read, Write};
use std::mem;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::ptr;

const AGENT_PORT: u32 = 1024;

fn main() -> ! {
    // PID 1: best-effort mounts (harmless if they fail on a minimal initramfs).
    unsafe {
        libc::mkdir(c"/proc".as_ptr(), 0o755);
        libc::mount(c"proc".as_ptr(), c"/proc".as_ptr(), c"proc".as_ptr(), 0, ptr::null());
    }
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
        let req = String::from_utf8_lossy(&buf[..n]);
        let _ = conn.write_all(handle(req.trim()).as_bytes());
        // conn drops -> closes the connection.
    }
}

fn handle(req: &str) -> String {
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
