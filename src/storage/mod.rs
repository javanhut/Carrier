mod layer;
mod layout;
mod overlay;

pub use layer::extract_layer_rootless;
pub use layout::StorageLayout;
pub use overlay::{ContainerStorage, preflight_rootless_checks, StorageDriver};

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
