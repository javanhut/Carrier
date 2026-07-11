use std::fs::{self, OpenOptions};
use std::io::Write;
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
        atomic_write(&blob_path, data)?;
        Ok(blob_path)
    }
}

/// Write a file in the destination directory and publish it with an atomic
/// rename. Readers therefore see either the old complete file or the new one,
/// never a partially-written cache entry.
pub fn atomic_write(path: &std::path::Path, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path.parent().ok_or("destination has no parent directory")?;
    fs::create_dir_all(parent)?;

    let mut attempt = 0_u32;
    let tmp_path = loop {
        let candidate = parent.join(format!(
            ".{}.tmp-{}-{}",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("carrier"),
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                if let Err(error) = (|| -> std::io::Result<()> {
                    file.write_all(data)?;
                    file.sync_all()
                })() {
                    let _ = fs::remove_file(&candidate);
                    return Err(error.into());
                }
                break candidate;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt = attempt.checked_add(1).ok_or("too many temporary files")?;
            }
            Err(error) => return Err(error.into()),
        }
    };

    if let Err(error) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::atomic_write;

    #[test]
    fn atomic_write_replaces_complete_file_and_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        std::fs::write(&path, b"old").unwrap();

        atomic_write(&path, b"new contents").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new contents");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec!["blob"]);
    }
}
