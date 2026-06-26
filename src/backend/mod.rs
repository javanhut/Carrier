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
    matches!(
        cmd,
        Commands::Run { .. }
            | Commands::Stop { .. }
            | Commands::Shell { .. }
            | Commands::Terminal { .. }
            | Commands::Info { .. }
            | Commands::Logs { .. }
    )
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
    // ponytail: macOS arm only — the VM driver replaces this exit in Phase 2.
    #[cfg(target_os = "macos")]
    {
        eprintln!(
            "carrier: this command needs a Linux container runtime, which macOS \
             cannot run natively.\n\
             The bundled Linux VM backend is not provisioned yet \
             (`carrier machine init`, coming in a later build).\n\
             Available now on macOS: pull, list, auth, remove, doctor, completions."
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
