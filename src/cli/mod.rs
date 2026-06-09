mod cli;

pub use cli::{Cli, Commands};
// RegistryImage is consumed by the Linux-only container implementation.
#[cfg(target_os = "linux")]
pub use cli::RegistryImage;
