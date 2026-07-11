use flate2::read::GzDecoder;
use std::fs;
use std::path::{Component, Path};
use tar::Archive;

fn open_archive(path: &Path) -> Result<Archive<GzDecoder<fs::File>>, Box<dyn std::error::Error>> {
    let file = fs::File::open(path)?;
    let mut archive = Archive::new(GzDecoder::new(file));
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);
    archive.set_unpack_xattrs(false);
    Ok(archive)
}

fn validate_entry(
    entry: &mut tar::Entry<'_, GzDecoder<fs::File>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = entry.path()?;
    if path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(format!("layer entry escapes destination: {}", path.display()).into());
    }
    let kind = entry.header().entry_type();
    if kind.is_block_special() || kind.is_character_special() || kind.is_fifo() {
        return Err(format!("unsafe special file in layer: {}", path.display()).into());
    }
    if let Some(target) = entry.link_name()? {
        if target.is_absolute()
            || target
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(format!(
                "unsafe link target in layer: {} -> {}",
                path.display(),
                target.display()
            )
            .into());
        }
    }
    Ok(())
}

fn whiteout_target(path: &Path) -> Option<(bool, std::path::PathBuf)> {
    let name = path.file_name()?.to_str()?;
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    if name == ".wh..wh..opq" {
        Some((true, parent.to_path_buf()))
    } else {
        name.strip_prefix(".wh.")
            .filter(|target| !target.is_empty())
            .map(|target| (false, parent.join(target)))
    }
}

fn remove_path(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path)
        }
        Ok(_) => fs::remove_file(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Apply an OCI layer on top of an existing root filesystem. Whiteout markers
/// remove lower-layer paths and are never materialized in the result.
pub fn apply_layer_rootless(
    tar_gz_path: &Path,
    rootfs: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(rootfs)?;

    // Whiteouts must be processed before additions, independent of tar order.
    let mut first_pass = open_archive(tar_gz_path)?;
    for entry in first_pass.entries()? {
        let mut entry = entry?;
        validate_entry(&mut entry)?;
        let path = entry.path()?.into_owned();
        if let Some((opaque, target)) = whiteout_target(&path) {
            let target = rootfs.join(target);
            if opaque {
                if let Ok(children) = fs::read_dir(&target) {
                    for child in children {
                        remove_path(&child?.path())?;
                    }
                }
            } else {
                remove_path(&target)?;
            }
        }
    }

    let mut second_pass = open_archive(tar_gz_path)?;
    for entry in second_pass.entries()? {
        let mut entry = entry?;
        validate_entry(&mut entry)?;
        if whiteout_target(&entry.path()?).is_some() {
            continue;
        }
        if !entry.unpack_in(rootfs)? {
            return Err(format!(
                "layer entry escapes destination: {}",
                entry.path()?.display()
            )
            .into());
        }
    }
    Ok(())
}

fn extract_archive_rootless(
    tar_gz_path: &Path,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut archive = open_archive(tar_gz_path)?;
    for entry in archive.entries()? {
        let mut entry = entry?;
        validate_entry(&mut entry)?;
        if !entry.unpack_in(output)? {
            return Err(format!(
                "layer entry escapes destination: {}",
                entry.path()?.display()
            )
            .into());
        }
    }
    Ok(())
}

pub fn extract_layer_rootless(
    tar_gz_path: &Path,
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = output_dir
        .parent()
        .ok_or("layer output has no parent directory")?;
    fs::create_dir_all(parent)?;

    // Extract beside the final directory and publish only after every entry has
    // succeeded. A failed extraction can never look like a cached layer.
    let temp_dir = parent.join(format!(
        ".{}.extracting-{}-{}",
        output_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("layer"),
        std::process::id(),
        rand::random::<u64>()
    ));
    fs::create_dir(&temp_dir)?;

    let extraction = extract_archive_rootless(tar_gz_path, &temp_dir);

    if let Err(error) = extraction {
        let _ = fs::remove_dir_all(&temp_dir);
        return Err(error);
    }

    if output_dir.exists() {
        fs::remove_dir_all(output_dir)?;
    }
    if let Err(error) = fs::rename(&temp_dir, output_dir) {
        let _ = fs::remove_dir_all(&temp_dir);
        return Err(error.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{apply_layer_rootless, extract_layer_rootless};
    use flate2::{Compression, write::GzEncoder};
    use std::path::Path;
    use tar::{Builder, EntryType, Header};

    fn archive_with_files(path: &Path, files: &[(&str, &[u8])]) {
        let encoder = GzEncoder::new(std::fs::File::create(path).unwrap(), Compression::default());
        let mut archive = Builder::new(encoder);
        for (name, contents) in files {
            let mut header = Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, name, *contents).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn extracts_regular_files_transactionally() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("layer.tar.gz");
        let encoder = GzEncoder::new(
            std::fs::File::create(&archive_path).unwrap(),
            Compression::default(),
        );
        let mut archive = Builder::new(encoder);
        let mut header = Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "hello.txt", &b"hello"[..])
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();

        let output = dir.path().join("layer");
        extract_layer_rootless(&archive_path, &output).unwrap();

        assert_eq!(std::fs::read(output.join("hello.txt")).unwrap(), b"hello");
    }

    #[test]
    fn rejects_special_files_without_publishing_layer() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("layer.tar.gz");
        let encoder = GzEncoder::new(
            std::fs::File::create(&archive_path).unwrap(),
            Compression::default(),
        );
        let mut archive = Builder::new(encoder);
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Fifo);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "unsafe-fifo", std::io::empty())
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();

        let output = dir.path().join("layer");
        let error = extract_layer_rootless(&archive_path, &output).unwrap_err();

        assert!(error.to_string().contains("unsafe special file"));
        assert!(!output.exists());
    }

    #[test]
    fn applies_whiteouts_and_opaque_directories_before_new_entries() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.tar.gz");
        archive_with_files(
            &base,
            &[
                ("remove-me", b"old"),
                ("etc/old", b"old"),
                ("etc/also-old", b"old"),
            ],
        );
        let upper = dir.path().join("upper.tar.gz");
        // Put the opaque marker after the addition to verify tar ordering does
        // not cause the new file to be deleted.
        archive_with_files(
            &upper,
            &[
                ("etc/new", b"new"),
                (".wh.remove-me", b""),
                ("etc/.wh..wh..opq", b""),
            ],
        );

        let rootfs = dir.path().join("rootfs");
        apply_layer_rootless(&base, &rootfs).unwrap();
        apply_layer_rootless(&upper, &rootfs).unwrap();

        assert!(!rootfs.join("remove-me").exists());
        assert!(!rootfs.join("etc/old").exists());
        assert!(!rootfs.join("etc/also-old").exists());
        assert_eq!(std::fs::read(rootfs.join("etc/new")).unwrap(), b"new");
        assert!(!rootfs.join(".wh.remove-me").exists());
        assert!(!rootfs.join("etc/.wh..wh..opq").exists());
    }
}
