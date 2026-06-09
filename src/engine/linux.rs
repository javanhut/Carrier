//! Native Linux container engine.
//!
//! Thin adapter over the existing implementation in [`crate::commands`]. This
//! module deliberately contains no container logic of its own — it only maps the
//! platform-agnostic [`ContainerEngine`] surface onto the current functions so
//! behavior is byte-for-byte identical to the pre-refactor CLI. The underlying
//! implementation can be decomposed into submodules later without touching the
//! engine boundary.

use async_trait::async_trait;

use super::{ContainerEngine, EngineResult, ListFilter, LogOptions, RunSpec};
use crate::commands;

pub struct LinuxNativeEngine;

impl LinuxNativeEngine {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ContainerEngine for LinuxNativeEngine {
    async fn pull(&self, image: String, platform: Option<String>) -> EngineResult {
        commands::pull_image(image, platform).await;
        Ok(())
    }

    async fn run(&self, spec: RunSpec) -> EngineResult {
        if spec.command.is_empty() {
            commands::run_image(
                spec.image,
                spec.detach,
                spec.name,
                spec.elevated,
                spec.volumes,
                spec.ports,
                spec.env,
                spec.platform,
                spec.storage_driver,
                spec.verbose,
            )
            .await;
        } else {
            commands::run_image_with_command(
                spec.image,
                spec.detach,
                spec.name,
                spec.elevated,
                spec.command,
                spec.volumes,
                spec.ports,
                spec.env,
                spec.platform,
                spec.storage_driver,
                spec.verbose,
            )
            .await;
        }
        Ok(())
    }

    async fn exec(&self, container: String, command: Vec<String>, tty: bool) -> EngineResult {
        commands::exec_in_container(container, command, tty).await
    }

    async fn stop(&self, container: String, force: bool, timeout: u64) -> EngineResult {
        commands::stop_container(container, force, timeout).await
    }

    async fn remove(
        &self,
        item: Option<String>,
        force: bool,
        all_stopped: bool,
        interactive: bool,
    ) -> EngineResult {
        if all_stopped {
            commands::remove_all_stopped_containers(force).await;
        } else if let Some(img) = item {
            commands::remove_item(img, force, interactive).await;
        } else {
            return Err(
                "Either specify an image/container ID or use --all-containers".into(),
            );
        }
        Ok(())
    }

    async fn list(&self, filter: ListFilter) -> EngineResult {
        commands::list_items(filter.all, filter.images_only, filter.containers_only).await;
        Ok(())
    }

    async fn logs(&self, container: String, opts: LogOptions) -> EngineResult {
        commands::show_container_logs(
            container,
            opts.follow,
            opts.tail,
            opts.timestamps,
            opts.since,
            opts.search,
            opts.fuzzy,
            opts.regex,
        )
        .await
    }

    async fn info(&self, container: String) -> EngineResult {
        commands::show_container_info(container).await
    }

    async fn authenticate(&self, username: String, registry: String) -> EngineResult {
        commands::authenticate_registry(username, registry).await
    }

    async fn verify_auth(&self) -> EngineResult {
        commands::verify_authentication().await
    }
}
