use flate2::read::GzDecoder;
use std::fs;
use std::path::Path;
use tar::Archive;

pub fn extract_layer_rootless(
    tar_gz_path: &Path,
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let tar_gz = fs::File::open(tar_gz_path)?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);

    // Configure for rootless extraction
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);
    archive.set_unpack_xattrs(false);

    // Extract without trying to preserve ownership
    archive.unpack(output_dir)?;

    Ok(())
}
