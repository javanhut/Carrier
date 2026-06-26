//! The container runtime layer.
//!
//! On Linux the runc path runs directly on the host (namespaces, cgroups,
//! overlayfs). macOS has no Linux kernel, so runtime commands can't run on the
//! host — they route through a bundled Linux micro-VM driven by Apple's
//! Virtualization.framework. That VM driver lands in Phase 2 (`backend::vm`).
//!
//! Until then this module is the seam: it tells macOS users plainly that
//! runtime commands need the VM, instead of letting them hit a cryptic
//! "runc not found" failure deep in the stack. Cross-platform commands
//! (pull/list/auth/remove/doctor/completions) pass straight through.

use crate::cli::Commands;

// macOS: the bundled Linux micro-VM driver (Virtualization.framework, pure Rust).
#[cfg(target_os = "macos")]
pub mod vm;

/// Does this subcommand need a real Linux container runtime (runc, namespaces,
/// overlayfs)? Those can't run on the macOS host; on macOS they route through
/// the VM backend.
pub fn needs_linux_runtime(cmd: &Commands) -> bool {
    // Run is handled via the VM on macOS (see backend::run_in_vm), so it's not
    // gated. The rest still hit the runc path that doesn't exist on macOS yet.
    matches!(
        cmd,
        Commands::Stop { .. }
            | Commands::Shell { .. }
            | Commands::Terminal { .. }
            | Commands::Info { .. }
            | Commands::Logs { .. }
    )
}

/// macOS: run a container via the bundled VM (host builds the bundle, guest runs
/// it). On Linux this is never called — `carrier run` uses the native runc path.
#[cfg(target_os = "macos")]
pub async fn run_in_vm(image: String, command: Vec<String>, interactive: bool, tty: bool) {
    vm::run_in_vm(image, command, interactive, tty).await;
}

/// Handle `carrier machine <action>`. macOS drives the bundled VM; on Linux
/// there is no VM (containers run natively), so it's a no-op with a clear note.
pub fn machine(action: crate::cli::MachineCmd) {
    #[cfg(target_os = "macos")]
    {
        vm::machine(action);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = action;
        eprintln!(
            "carrier machine is macOS-only — on Linux, containers run natively \
             (no VM needed)."
        );
        std::process::exit(1);
    }
}

/// Gate the runtime commands per platform. Linux: no-op (the runc path handles
/// it). macOS: until the VM backend is provisioned, exit with a clear,
/// actionable message rather than a confusing low-level error.
pub fn guard(cmd: &Commands) {
    if !needs_linux_runtime(cmd) {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        eprintln!(
            "carrier: `stop`/`sh`/`terminal`/`logs`/`info` operate on a running \
             container, which the macOS VM backend doesn't keep yet — each \
             `carrier run` is ephemeral.\n\
             For a shell, run interactively: `carrier run -i <image> /bin/bash`."
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_vs_crossplatform_classification() {
        // Runtime commands need the Linux backend (VM on macOS).
        assert!(needs_linux_runtime(&Commands::Stop {
            container: "x".into(),
            force: false,
            timeout: 10,
        }));
        assert!(needs_linux_runtime(&Commands::Info {
            container: "x".into(),
        }));
        // Cross-platform commands do not.
        assert!(!needs_linux_runtime(&Commands::Pull {
            image: "alpine".into(),
            platform: None,
        }));
        assert!(!needs_linux_runtime(&Commands::List {
            all: false,
            images: false,
            containers: false,
        }));
    }
}
