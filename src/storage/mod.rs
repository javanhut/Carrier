// The storage layer manages image layers and the overlay container filesystem.
// It relies on Linux-only kernel facilities (mount(2), mknod(2),
// overlayfs/fuse-overlayfs) and is only compiled on Linux; the macOS engine will
// reach storage through the Linux guest agent instead.
#[cfg(target_os = "linux")]
mod layer;
#[cfg(target_os = "linux")]
mod layout;
#[cfg(target_os = "linux")]
mod overlay;

#[cfg(target_os = "linux")]
pub use layer::extract_layer_rootless;
#[cfg(target_os = "linux")]
pub use layout::StorageLayout;
#[cfg(target_os = "linux")]
pub use overlay::{preflight_rootless_checks, ContainerStorage, StorageDriver};

// Helper function for generating container IDs
#[cfg(target_os = "linux")]
pub fn generate_container_id() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();

    (0..12)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}
