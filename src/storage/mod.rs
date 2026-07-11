mod layer;
mod layout;
mod overlay;

pub use layer::{apply_layer_rootless, extract_layer_rootless};
pub use layout::{StorageLayout, atomic_write};
pub use overlay::{ContainerStorage, StorageDriver, preflight_rootless_checks};

// Helper function for generating container IDs
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
