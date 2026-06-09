//! macOS container engine (placeholder).
//!
//! macOS cannot run Linux containers natively — it has no namespaces, cgroups, or
//! overlayfs. The planned backend boots a lightweight Linux VM (Apple
//! Virtualization.framework) and forwards engine calls to a `carrier` guest agent
//! running inside it. Until that lands, every operation returns a clear error so
//! the crate builds and runs on macOS without pretending to support containers.

use async_trait::async_trait;

use super::{ContainerEngine, EngineResult, ListFilter, LogOptions, RunSpec};

pub struct MacVmEngine;

impl MacVmEngine {
    pub fn new() -> Self {
        Self
    }
}

fn unsupported(op: &str) -> EngineResult {
    Err(format!(
        "'{op}' is not yet supported on macOS. Native container execution requires a Linux \
         VM backend, which is planned but not yet implemented. Run Carrier on Linux for now."
    )
    .into())
}

#[async_trait]
impl ContainerEngine for MacVmEngine {
    async fn pull(&self, _image: String, _platform: Option<String>) -> EngineResult {
        unsupported("pull")
    }

    async fn run(&self, _spec: RunSpec) -> EngineResult {
        unsupported("run")
    }

    async fn exec(&self, _container: String, _command: Vec<String>, _tty: bool) -> EngineResult {
        unsupported("exec")
    }

    async fn stop(&self, _container: String, _force: bool, _timeout: u64) -> EngineResult {
        unsupported("stop")
    }

    async fn remove(
        &self,
        _item: Option<String>,
        _force: bool,
        _all_stopped: bool,
        _interactive: bool,
    ) -> EngineResult {
        unsupported("remove")
    }

    async fn list(&self, _filter: ListFilter) -> EngineResult {
        unsupported("list")
    }

    async fn logs(&self, _container: String, _opts: LogOptions) -> EngineResult {
        unsupported("logs")
    }

    async fn info(&self, _container: String) -> EngineResult {
        unsupported("info")
    }

    async fn authenticate(&self, _username: String, _registry: String) -> EngineResult {
        unsupported("auth")
    }

    async fn verify_auth(&self) -> EngineResult {
        unsupported("auth-verify")
    }
}
