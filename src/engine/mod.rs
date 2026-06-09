//! Container engine abstraction.
//!
//! This is the seam that lets Carrier run containers through different backends
//! while keeping the CLI (`main.rs`) platform-agnostic:
//!
//! * [`linux::LinuxNativeEngine`] — runs containers natively on Linux using the
//!   existing runc/overlay implementation in [`crate::commands`].
//! * [`mac::MacVmEngine`] — placeholder for the upcoming macOS backend, which
//!   will forward calls to a Linux guest agent running inside a managed VM.
//!
//! All command surfaces in the CLI map to a method on [`ContainerEngine`]. To add
//! a new backend, implement the trait and wire it into [`default_engine`].

use async_trait::async_trait;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(not(target_os = "linux"))]
pub mod mac;

/// Unified result type for engine operations.
pub type EngineResult = Result<(), Box<dyn std::error::Error>>;

/// Everything needed to start a container. Mirrors the `run` CLI flags. The
/// image reference is kept as a raw string and parsed by the backend so parsing
/// behavior stays identical to the pre-refactor code path.
// Fields are consumed by the Linux engine; the macOS stub ignores them, so allow
// dead_code only off-Linux to keep real dead-code detection active on Linux.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct RunSpec {
    pub image: String,
    pub detach: bool,
    pub name: Option<String>,
    pub elevated: bool,
    pub volumes: Vec<String>,
    pub ports: Vec<String>,
    pub env: Vec<String>,
    pub platform: Option<String>,
    pub storage_driver: Option<String>,
    pub verbose: bool,
    /// Optional command overriding the image default. Empty = use image default.
    pub command: Vec<String>,
}

/// Options controlling log retrieval/formatting. Mirrors the `logs` CLI flags.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct LogOptions {
    pub follow: bool,
    pub tail: Option<usize>,
    pub timestamps: bool,
    pub since: Option<String>,
    pub search: Option<String>,
    pub fuzzy: bool,
    pub regex: Option<String>,
}

/// Filters for listing images/containers. Mirrors the `list`/`ps` CLI flags.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct ListFilter {
    pub all: bool,
    pub images_only: bool,
    pub containers_only: bool,
}

/// The platform-agnostic container engine interface. Each method corresponds to
/// a Carrier subcommand. Implementations are responsible for their own user-facing
/// output; methods return `Err` only for failures the CLI should surface and
/// translate into a non-zero exit code.
#[async_trait]
pub trait ContainerEngine {
    async fn pull(&self, image: String, platform: Option<String>) -> EngineResult;
    async fn run(&self, spec: RunSpec) -> EngineResult;
    async fn exec(&self, container: String, command: Vec<String>, tty: bool) -> EngineResult;
    async fn stop(&self, container: String, force: bool, timeout: u64) -> EngineResult;
    async fn remove(
        &self,
        item: Option<String>,
        force: bool,
        all_stopped: bool,
        interactive: bool,
    ) -> EngineResult;
    async fn list(&self, filter: ListFilter) -> EngineResult;
    async fn logs(&self, container: String, opts: LogOptions) -> EngineResult;
    async fn info(&self, container: String) -> EngineResult;
    async fn authenticate(&self, username: String, registry: String) -> EngineResult;
    async fn verify_auth(&self) -> EngineResult;
}

/// Construct the appropriate engine for the current platform.
pub fn default_engine() -> Box<dyn ContainerEngine> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxNativeEngine::new())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(mac::MacVmEngine::new())
    }
}
