use std::fs;
use std::path::PathBuf;

pub struct StorageLayout {
    pub base: PathBuf,
}

impl StorageLayout {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let base = dirs::data_dir()
            .ok_or("Cannot determine data directory")?
            .join("carrier");

        Ok(Self { base })
    }

    pub fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create directory structure like Podman
        let dirs = vec![
            "storage/overlay",
            "storage/overlay-containers",
            "storage/overlay-images",
            "storage/overlay-layers",
            "storage/tmp",
            "cache/blobs",
            "run",
        ];

        for dir in dirs {
            fs::create_dir_all(self.base.join(dir))?;
        }

        // Create config directory too
        if let Some(config_dir) = dirs::config_dir() {
            fs::create_dir_all(config_dir.join("carrier"))?;
        }

        Ok(())
    }

    pub fn image_layer_path(&self, digest: &str) -> PathBuf {
        let clean_digest = digest.replace(":", "_");
        self.base.join("storage/overlay").join(&clean_digest)
    }

    pub fn container_path(&self, container_id: &str) -> PathBuf {
        self.base
            .join("storage/overlay-containers")
            .join(container_id)
    }

    pub fn blob_cache_path(&self, digest: &str) -> PathBuf {
        let clean_digest = digest.replace(":", "_");
        self.base
            .join("cache/blobs")
            .join(format!("{}.tar.gz", &clean_digest))
    }

    pub fn image_metadata_path(&self, image: &str, tag: &str) -> PathBuf {
        let clean_name = image.replace("/", "_");
        self.base
            .join("storage/overlay-images")
            .join(format!("{}_{}.json", clean_name, tag))
    }

    pub fn blob_exists(&self, digest: &str) -> bool {
        self.blob_cache_path(digest).exists()
    }

    // Check if a layer is already extracted
    pub fn layer_exists(&self, digest: &str) -> bool {
        self.image_layer_path(digest).exists()
    }
}

// Helper functions for working with the layout
impl StorageLayout {
    pub fn save_blob(
        &self,
        digest: &str,
        data: &[u8],
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let blob_path = self.blob_cache_path(digest);
        if let Some(parent) = blob_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&blob_path, data)?;
        Ok(blob_path)
    }
}
