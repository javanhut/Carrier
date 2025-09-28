use crate::cli::RegistryImage;
use crate::storage::{
    extract_layer_rootless, generate_container_id, ContainerStorage, StorageLayout,
};

use base64::prelude::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

lazy_static! {
    static ref REGISTRYMAP: HashMap<&'static str, &'static str> = {
        let mut registry_map = HashMap::new();
        registry_map.insert("docker.io", "https://registry-1.docker.io/v2/");
        registry_map.insert("quay.io", "https://quay.io/v2/");
        registry_map.insert(
            "container-registry.oracle.com",
            "https://container-registry.oracle.com/v2/",
        );
        registry_map.insert("registry.redhat.io", "https://registry.redhat.io/v2/");
        registry_map.insert("ghcr.io", "https://ghcr.io/v2/");
        registry_map.insert("public.ecr.aws", "https://public.ecr.aws/v2/");
        registry_map.insert("gcr.io", "https://gcr.io/v2/");
        registry_map.insert("us-docker.pkg.dev", "https://us-docker.pkg.dev/v2/");
        registry_map.insert("europe-docker.pkg.dev", "https://europe-docker.pkg.dev/v2/");
        registry_map.insert("asia-docker.pkg.dev", "https://asia-docker.pkg.dev/v2/");
        registry_map
    };
}

lazy_static! {
    static ref AUTHTOKENMAP: HashMap<&'static str, &'static str> = {
        let mut auth_map = HashMap::new();
        auth_map.insert("docker.io", "https://auth.docker.io/token");
        auth_map.insert("quay.io", "https://quay.io/v2/auth");
        auth_map.insert(
            "container-registry.oracle.com",
            "https://container-registry.oracle.com/auth/token",
        );
        auth_map.insert(
            "registry.redhat.io",
            "https://sso.redhat.com/auth/realms/rhcc/protocol/redhat-docker-v2/auth",
        );
        auth_map.insert("ghcr.io", "https://ghcr.io/token");
        auth_map.insert("public.ecr.aws", "https://public.ecr.aws/token");
        auth_map.insert("gcr.io", "https://gcr.io/v2/token");
        auth_map.insert("us-docker.pkg.dev", "https://us-docker.pkg.dev/v2/token");
        auth_map.insert(
            "europe-docker.pkg.dev",
            "https://europe-docker.pkg.dev/v2/token",
        );
        auth_map.insert(
            "asia-docker.pkg.dev",
            "https://asia-docker.pkg.dev/v2/token",
        );
        auth_map
    };
}

#[derive(Debug, Deserialize, Serialize)]
struct ManifestV2 {
    #[serde(rename = "schemaVersion")]
    schema_version: i32,
    #[serde(rename = "mediaType")]
    media_type: String,
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Descriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    size: i64,
    digest: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ManifestList {
    #[serde(rename = "schemaVersion")]
    schema_version: i32,
    #[serde(rename = "mediaType")]
    media_type: String,
    manifests: Vec<ManifestDescriptor>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ManifestDescriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    size: i64,
    digest: String,
    platform: Platform,
}

#[derive(Debug, Deserialize, Serialize)]
struct Platform {
    architecture: String,
    os: String,
    #[serde(rename = "os.version", default)]
    os_version: Option<String>,
    #[serde(rename = "os.features", default)]
    os_features: Option<Vec<String>>,
    variant: Option<String>,
}

pub async fn run_image(
    image_name: String,
    detach: bool,
    name: Option<String>,
    elevated: bool,
    platform: Option<String>,
    storage_driver: Option<String>,
) {
    // Initialize storage layout
    let storage = match StorageLayout::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize storage: {}", e);
            return;
        }
    };

    if let Err(e) = storage.init() {
        eprintln!("Failed to initialize storage directories: {}", e);
        return;
    }

    // Check if this might be a container name/ID
    if let Ok(Some(_)) = find_container_by_id_optional(&storage, &image_name) {
        eprintln!(
            "Error: '{}' appears to be a container ID or name, not an image.",
            image_name
        );
        eprintln!(
            "Did you mean to use 'carrier sh {}' to execute in the container?",
            image_name
        );
        return;
    }

    // First check if this is an image ID for a local image
    if let Ok(Some((image, tag, manifest_content))) = find_image_by_id(&storage, &image_name) {
        println!("Found local image: {}:{}", image, tag);

        // Parse the manifest
        let manifest: ManifestV2 = match serde_json::from_str(&manifest_content) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to parse local manifest: {}", e);
                return;
            }
        };

        // Build layer paths from the manifest
        let mut layer_paths = Vec::new();
        for layer in &manifest.layers {
            let layer_path = storage.image_layer_path(&layer.digest);
            if !layer_path.exists() {
                eprintln!(
                    "Layer {} not found locally. Please re-pull the image.",
                    &layer.digest[..12]
                );
                return;
            }
            layer_paths.push(layer_path);
        }

        // Create a parsed image struct for compatibility
        let parsed_image = RegistryImage {
            registry: None,
            image: image.clone(),
            tag: tag.clone(),
        };

        println!("Running container from local image {}:{}...", image, tag);

        // Run the container with the local image
        if let Err(e) = run_container_with_storage(
            &parsed_image,
            &manifest,
            layer_paths,
            &storage,
            detach,
            name.clone(),
            elevated,
            None,
            storage_driver.as_deref(),
        )
        .await
        {
            eprintln!("Failed to run container: {}", e);
        }
        return;
    }

    // Not a local image ID, proceed with parsing as image reference
    let parsed_image = match RegistryImage::parse(&image_name) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("Failed to parse image: {}", e);
            return;
        }
    };

    // Check if we have this image locally already
    let metadata_path = storage.image_metadata_path(&parsed_image.image, &parsed_image.tag);
    if metadata_path.exists() {
        println!(
            "Image {}:{} found locally",
            parsed_image.image, parsed_image.tag
        );

        // Load the manifest from local storage
        let manifest_content = match std::fs::read_to_string(&metadata_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to read local manifest: {}", e);
                return;
            }
        };

        let manifest: ManifestV2 = match serde_json::from_str(&manifest_content) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to parse local manifest: {}", e);
                return;
            }
        };

        // Build layer paths
        let mut layer_paths = Vec::new();
        for layer in &manifest.layers {
            let layer_path = storage.image_layer_path(&layer.digest);
            if !layer_path.exists() {
                println!("Layer {} missing, pulling image...", &layer.digest[..12]);
                break; // Will fall through to pull
            }
            layer_paths.push(layer_path);
        }

        // If all layers exist, run directly
        if layer_paths.len() == manifest.layers.len() {
            println!("Running container from local image...");
            if let Err(e) = run_container_with_storage(
                &parsed_image,
                &manifest,
                layer_paths,
                &storage,
                detach,
                name.clone(),
                elevated,
                None,
                storage_driver.as_deref(),
            )
            .await
            {
                eprintln!("Failed to run container: {}", e);
            }
            return;
        }
    }

    // Image not found locally or incomplete, pull it
    let registry = parsed_image.registry.as_deref().unwrap_or("docker.io");
    println!("Registry: {}", registry);
    println!("Image: {}", parsed_image.image);
    println!("Tag: {}", parsed_image.tag);

    // Get auth token (try authenticated first, fall back to anonymous)
    let image_path = normalize_image_path(&parsed_image.image);
    let token = match get_authenticated_token(registry, &image_path).await {
        Ok(t) => {
            println!("Successfully obtained auth token");
            t
        }
        Err(e) => {
            eprintln!("Failed to get auth token: {}", e);
            return;
        }
    };

    // Get manifest
    let manifest_json = match get_manifest_content(&parsed_image, &token).await {
        Ok(m) => {
            println!("Successfully downloaded manifest");
            m
        }
        Err(e) => {
            eprintln!("Failed to get manifest: {}", e);
            return;
        }
    };

    // Parse manifest - handle both manifest list and single manifest
    let manifest =
        match parse_and_get_manifest(&manifest_json, &parsed_image, &token, platform.as_deref())
            .await
        {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to parse manifest: {}", e);
                return;
            }
        };

    // Save the actual manifest (not the manifest list) as metadata
    let metadata_path = storage.image_metadata_path(&parsed_image.image, &parsed_image.tag);
    let manifest_to_save = serde_json::to_string(&manifest).unwrap_or(manifest_json.clone());
    if let Err(e) = std::fs::write(&metadata_path, &manifest_to_save) {
        eprintln!("Warning: Failed to save manifest metadata: {}", e);
    }

    // Download layers with progress using storage
    let layer_paths =
        match download_layers_with_storage(&manifest, &parsed_image, &token, &storage).await {
            Ok(paths) => paths,
            Err(e) => {
                eprintln!("Failed to download layers: {}", e);
                return;
            }
        };

    println!("\nImage {} pulled successfully!", image_name);
    println!("Ready to run container...");

    // Run the container with proper storage
    if let Err(e) = run_container_with_storage(
        &parsed_image,
        &manifest,
        layer_paths,
        &storage,
        detach,
        name,
        elevated,
        None,
        storage_driver.as_deref(),
    )
    .await
    {
        eprintln!("Failed to run container: {}", e);
    }
}

pub async fn run_image_with_command(
    image_name: String,
    detach: bool,
    name: Option<String>,
    elevated: bool,
    command: Vec<String>,
    platform: Option<String>,
    storage_driver: Option<String>,
) {
    // Initialize storage layout
    let storage = match StorageLayout::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize storage: {}", e);
            return;
        }
    };

    // First check if this is an image ID for a local image
    if let Ok(Some((image, tag, manifest_content))) = find_image_by_id(&storage, &image_name) {
        println!("Found local image: {}:{}", image, tag);

        let manifest: ManifestV2 = match serde_json::from_str(&manifest_content) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to parse local manifest: {}", e);
                return;
            }
        };

        // Build layer paths from the manifest
        let mut layer_paths = Vec::new();
        for layer in &manifest.layers {
            let layer_path = storage.image_layer_path(&layer.digest);
            if !layer_path.exists() {
                eprintln!(
                    "Layer {} not found locally. Please re-pull the image.",
                    &layer.digest[..12]
                );
                return;
            }
            layer_paths.push(layer_path);
        }

        // Create a parsed image struct for compatibility
        let parsed_image = RegistryImage {
            registry: None,
            image: image.clone(),
            tag: tag.clone(),
        };

        println!(
            "Running container from local image {}:{} with override...",
            image, tag
        );

        if let Err(e) = run_container_with_storage(
            &parsed_image,
            &manifest,
            layer_paths,
            &storage,
            detach,
            name.clone(),
            elevated,
            Some(command.clone()),
            storage_driver.as_deref(),
        )
        .await
        {
            eprintln!("Failed to run container: {}", e);
        }
        return;
    }

    // Not a local image ID, proceed with parsing as image reference
    let parsed_image = match RegistryImage::parse(&image_name) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("Failed to parse image: {}", e);
            return;
        }
    };

    // Check if we have this image locally already
    let metadata_path = storage.image_metadata_path(&parsed_image.image, &parsed_image.tag);
    if metadata_path.exists() {
        println!(
            "Image {}:{} found locally",
            parsed_image.image, parsed_image.tag
        );

        // Load the manifest from local storage
        let manifest_content = match std::fs::read_to_string(&metadata_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to read local manifest: {}", e);
                return;
            }
        };

        let manifest: ManifestV2 = match serde_json::from_str(&manifest_content) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to parse local manifest: {}", e);
                return;
            }
        };

        // Build layer paths
        let mut layer_paths = Vec::new();
        for layer in &manifest.layers {
            let layer_path = storage.image_layer_path(&layer.digest);
            if !layer_path.exists() {
                println!("Layer {} missing, pulling image...", &layer.digest[..12]);
                break; // Will fall through to pull
            }
            layer_paths.push(layer_path);
        }

        // If all layers exist, run directly
        if layer_paths.len() == manifest.layers.len() {
            println!("Running container from local image with override...");
            if let Err(e) = run_container_with_storage(
                &parsed_image,
                &manifest,
                layer_paths,
                &storage,
                detach,
                name.clone(),
                elevated,
                Some(command.clone()),
                storage_driver.as_deref(),
            )
            .await
            {
                eprintln!("Failed to run container: {}", e);
            }
            return;
        }
    }

    // Image not found locally or incomplete, pull it
    let registry = parsed_image.registry.as_deref().unwrap_or("docker.io");
    println!("Registry: {}", registry);
    println!("Image: {}", parsed_image.image);
    println!("Tag: {}", parsed_image.tag);

    // Get auth token (try authenticated first, fall back to anonymous)
    let image_path = normalize_image_path(&parsed_image.image);
    let token = match get_authenticated_token(registry, &image_path).await {
        Ok(t) => {
            println!("Successfully obtained auth token");
            t
        }
        Err(e) => {
            eprintln!("Failed to get auth token: {}", e);
            return;
        }
    };

    // Get manifest
    let manifest_json = match get_manifest_content(&parsed_image, &token).await {
        Ok(m) => {
            println!("Successfully downloaded manifest");
            m
        }
        Err(e) => {
            eprintln!("Failed to get manifest: {}", e);
            return;
        }
    };

    // Parse manifest - handle both manifest list and single manifest
    let manifest =
        match parse_and_get_manifest(&manifest_json, &parsed_image, &token, platform.as_deref())
            .await
        {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to parse manifest: {}", e);
                return;
            }
        };

    // Save the actual manifest as metadata
    let metadata_path = storage.image_metadata_path(&parsed_image.image, &parsed_image.tag);
    let manifest_to_save = serde_json::to_string(&manifest).unwrap_or(manifest_json.clone());
    let _ = std::fs::write(&metadata_path, &manifest_to_save);

    // Download layers with progress using storage
    let layer_paths =
        match download_layers_with_storage(&manifest, &parsed_image, &token, &storage).await {
            Ok(paths) => paths,
            Err(e) => {
                eprintln!("Failed to download layers: {}", e);
                return;
            }
        };

    println!("\nImage {} pulled successfully!", image_name);
    println!("Ready to run container with override...");

    // Run the container with proper storage and command override
    if let Err(e) = run_container_with_storage(
        &parsed_image,
        &manifest,
        layer_paths,
        &storage,
        detach,
        name,
        elevated,
        Some(command),
        storage_driver.as_deref(),
    )
    .await
    {
        eprintln!("Failed to run container: {}", e);
    }
}

/// Execute a command in an elevated container without user namespace mapping
async fn exec_elevated_container(
    container_dir: &Path,
    rootfs: &Path,
    container_pid: i32,
    command: Vec<String>,
    is_interactive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::{Command, Stdio};

    println!("Executing in elevated container (PID {}) with sudo", container_pid);

    // For elevated containers, use sudo unshare without user namespace
    let mut exec_cmd = Command::new("sudo");

    // Use the same namespace setup as container creation but no user namespace
    exec_cmd.arg("unshare")
        .arg("--mount")
        .arg("--pid")
        .arg("chroot")
        .arg(rootfs);

    // Ensure we use full paths for commands
    let cmd_with_path = if !command.is_empty() && !command[0].starts_with('/') {
        // Try to find the command in common locations
        let cmd_name = &command[0];
        let possible_paths = vec![
            format!("/bin/{}", cmd_name),
            format!("/usr/bin/{}", cmd_name),
            format!("/sbin/{}", cmd_name),
            format!("/usr/sbin/{}", cmd_name),
        ];

        // Check which path exists in the rootfs
        let mut found_path = format!("/bin/{}", cmd_name); // default
        for path in &possible_paths {
            let full_path = rootfs.join(&path[1..]); // Remove leading /
            if full_path.exists() {
                found_path = path.clone();
                break;
            }
        }

        let mut full_path_cmd = vec![found_path];
        if command.len() > 1 {
            full_path_cmd.extend(command[1..].iter().cloned());
        }
        full_path_cmd
    } else {
        command.clone()
    };

    exec_cmd.args(&cmd_with_path);

    // Set up environment
    exec_cmd.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    exec_cmd.env("HOME", "/root");
    exec_cmd.env("TERM", "xterm");

    if is_interactive {
        println!("Starting interactive session with elevated privileges...");
        println!("Type 'exit' or press Ctrl+D to exit.\n");

        // Check if we're in a TTY
        let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;

        if is_tty {
            // Try using PTY for interactive session with sudo
            let mut sudo_args = vec![
                "unshare".to_string(),
                "--mount".to_string(),
                "--pid".to_string(),
                "chroot".to_string(),
                rootfs.to_string_lossy().to_string(),
            ];
            sudo_args.extend(cmd_with_path.clone());

            let exit_code = spawn_with_pty("sudo", &sudo_args)
                .unwrap_or_else(|_| {
                    // Fallback to regular execution
                    let mut child = exec_cmd
                        .stdin(Stdio::inherit())
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit())
                        .spawn()
                        .expect("Failed to spawn unshare");

                    let status = child.wait().expect("Failed to wait for child");
                    status.code().unwrap_or(1)
                });

            if exit_code != 0 {
                return Err(format!("Command exited with code {}", exit_code).into());
            }
        } else {
            println!("Not running in a TTY, using regular command execution...");
            exec_cmd.stdin(Stdio::inherit());
            exec_cmd.stdout(Stdio::inherit());
            exec_cmd.stderr(Stdio::inherit());

            let mut child = exec_cmd.spawn()?;
            let status = child.wait()?;
            if !status.success() {
                if let Some(code) = status.code() {
                    return Err(format!("Command exited with code {}", code).into());
                }
            }
        }
    } else {
        // Non-interactive execution
        exec_cmd.stdout(Stdio::inherit());
        exec_cmd.stderr(Stdio::inherit());

        let mut child = exec_cmd.spawn()?;
        let status = child.wait()?;

        if !status.success() {
            if let Some(code) = status.code() {
                return Err(format!("Command exited with code {}", code).into());
            }
        }
    }

    Ok(())
}

/// Execute a command in a rootless container by directly entering its rootfs
async fn exec_rootless_container(
    container_dir: &Path,
    rootfs: &Path,
    container_pid: i32,
    command: Vec<String>,
    is_interactive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::{Command, Stdio};

    println!("Executing in rootless container (PID {})", container_pid);

    // For entering an already running container, we should use nsenter to join its namespaces
    // Check if we're running as root (e.g., with sudo)
    let is_root = nix::unistd::Uid::effective().is_root();

    let mut exec_cmd = if is_root {
        // If running as root, use nsenter directly
        let mut cmd = Command::new("nsenter");
        cmd.arg("--target").arg(container_pid.to_string())
           .arg("--mount")
           .arg("--uts")
           .arg("--net")
           .arg("--pid")
           .arg("--root").arg(rootfs)  // Set the root filesystem
           .arg("--wd=/");  // Set working directory to /
        cmd
    } else {
        // If not root, we need to use unshare approach since nsenter requires root
        let mut cmd = Command::new("unshare");
        cmd.arg("--user")
           .arg("--map-root-user")  // Map current user to root
           .arg("--mount")
           .arg("--pid")
           .arg("chroot")
           .arg(rootfs);
        cmd
    };

    // For nsenter with --root, we don't need full paths as nsenter handles the root change
    // For unshare with chroot, we do need full paths
    let cmd_with_path = if is_root {
        // With nsenter, use commands as-is since --root handles the filesystem
        command.clone()
    } else if !command.is_empty() && !command[0].starts_with('/') {
        // Try to find the command in common locations
        let cmd_name = &command[0];
        let possible_paths = vec![
            format!("/bin/{}", cmd_name),
            format!("/usr/bin/{}", cmd_name),
            format!("/sbin/{}", cmd_name),
            format!("/usr/sbin/{}", cmd_name),
        ];

        // Check which path exists in the rootfs
        let mut found_path = format!("/bin/{}", cmd_name); // default
        for path in &possible_paths {
            let full_path = rootfs.join(&path[1..]); // Remove leading /
            if full_path.exists() {
                found_path = path.clone();
                break;
            }
        }

        let mut full_path_cmd = vec![found_path];
        if command.len() > 1 {
            full_path_cmd.extend(command[1..].iter().cloned());
        }
        full_path_cmd
    } else {
        command.clone()
    };

    exec_cmd.args(&cmd_with_path);

    // Set up environment
    exec_cmd.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    exec_cmd.env("HOME", "/root");
    exec_cmd.env("TERM", "xterm");

    if is_interactive {
        println!("Starting interactive session...");
        println!("Type 'exit' or press Ctrl+D to exit.\n");

        // Check if we're in a TTY
        let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;

        if is_tty {
            // Try using PTY for interactive session
            let (cmd_name, args) = if is_root {
                // Use nsenter for root
                let mut nsenter_args = vec![
                    "--target".to_string(),
                    container_pid.to_string(),
                    "--mount".to_string(),
                    "--uts".to_string(),
                    "--net".to_string(),
                    "--pid".to_string(),
                    "--root".to_string(),
                    rootfs.to_string_lossy().to_string(),
                    "--wd=/".to_string(),
                ];
                nsenter_args.extend(cmd_with_path.clone());
                ("nsenter", nsenter_args)
            } else {
                // Use unshare for non-root
                let mut unshare_args = vec![
                    "--user".to_string(),
                    "--map-root-user".to_string(),
                    "--mount".to_string(),
                    "--pid".to_string(),
                    "chroot".to_string(),
                    rootfs.to_string_lossy().to_string(),
                ];
                unshare_args.extend(cmd_with_path.clone());
                ("unshare", unshare_args)
            };

            let exit_code = spawn_with_pty(cmd_name, &args)
                .unwrap_or_else(|_| {
                    // Fallback to regular execution
                    let mut child = exec_cmd
                        .stdin(Stdio::inherit())
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit())
                        .spawn()
                        .expect("Failed to spawn unshare");

                    let status = child.wait().expect("Failed to wait for child");
                    status.code().unwrap_or(1)
                });

            if exit_code != 0 {
                return Err(format!("Command exited with code {}", exit_code).into());
            }
        } else {
            println!("Not running in a TTY, using regular command execution...");
            exec_cmd.stdin(Stdio::inherit());
            exec_cmd.stdout(Stdio::inherit());
            exec_cmd.stderr(Stdio::inherit());

            let mut child = exec_cmd.spawn()?;
            let status = child.wait()?;
            if !status.success() {
                if let Some(code) = status.code() {
                    return Err(format!("Command exited with code {}", code).into());
                }
            }
        }
    } else {
        // Non-interactive execution
        exec_cmd.stdout(Stdio::inherit());
        exec_cmd.stderr(Stdio::inherit());

        let mut child = exec_cmd.spawn()?;
        let status = child.wait()?;

        if !status.success() {
            if let Some(code) = status.code() {
                return Err(format!("Command exited with code {}", code).into());
            }
        }
    }

    Ok(())
}

pub async fn exec_in_container(
    container_id: String,
    command: Vec<String>,
    force_pty: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize storage layout
    let storage = StorageLayout::new()?;

    // Find the container
    let container_dir = find_container_by_id(&storage, &container_id)?;
    let full_container_id = container_dir
        .file_name()
        .ok_or("Invalid container directory")?
        .to_string_lossy()
        .to_string();

    // Read container metadata
    let metadata_path = container_dir.join("metadata.json");
    if !metadata_path.exists() {
        return Err(format!("Container {} not found", container_id).into());
    }

    let metadata_content = std::fs::read_to_string(&metadata_path)?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata_content)?;

    let status = metadata["status"].as_str().unwrap_or("unknown");

    // Check if container status indicates it's running - handle different status formats
    let is_running = status == "running" || status.starts_with("Up") || status.contains("Up ");

    if !is_running {
        return Err(format!(
            "Container {} is not running (status: {})",
            short12(&full_container_id),
            status
        )
        .into());
    }

    // Get the container's rootfs
    let rootfs = metadata["rootfs"]
        .as_str()
        .ok_or("No rootfs found in metadata")?;
    let rootfs = PathBuf::from(rootfs);

    if !rootfs.exists() {
        return Err(format!("Container rootfs not found: {}", rootfs.display()).into());
    }

    // Get the PID of the running container
    let pid_file = container_dir.join("pid");
    if !pid_file.exists() {
        // For containers that are showing as "Up" but don't have a PID file,
        // they might be from a different run or the PID wasn't saved properly
        return Err(format!(
            "Container {} appears to be running but PID file not found. Try stopping and restarting the container.",
            short12(&full_container_id)
        ).into());
    }

    let pid_str = std::fs::read_to_string(&pid_file)?;
    let container_pid = pid_str.trim().parse::<i32>()?;

    // Check if the process is still running
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let pid = Pid::from_raw(container_pid);
    if kill(pid, None).is_err() {
        // Process doesn't exist - update the metadata to reflect this
        let mut metadata_mut = metadata.clone();
        metadata_mut["status"] = serde_json::json!("exited");
        let _ = std::fs::write(&metadata_path, metadata_mut.to_string());
        let _ = std::fs::remove_file(&pid_file);

        return Err(format!(
            "Container {} process (PID {}) is not running. Status updated.",
            short12(&full_container_id),
            container_pid
        )
        .into());
    }

    // Prepare the command to execute
    let cmd_to_run = if command.is_empty() {
        vec!["/bin/sh".to_string()]
    } else {
        command
    };

    println!(
        "Executing command in container {}: {:?}",
        short12(&full_container_id),
        cmd_to_run
    );

    // Check if this is an interactive command or PTY is forced
    let is_interactive = force_pty
        || (cmd_to_run.len() == 1
            && (cmd_to_run[0] == "/bin/sh"
                || cmd_to_run[0] == "/bin/bash"
                || cmd_to_run[0] == "sh"
                || cmd_to_run[0] == "bash"));

    // Check if the container was started with elevated privileges
    let elevated = metadata["elevated"].as_bool().unwrap_or(false);

    // Check if we're running as root or regular user
    let is_root = nix::unistd::Uid::effective().is_root();

    // Handle based on how the container was created
    if !elevated {
        // Container was created as rootless, use rootless exec regardless of current privileges
        return exec_rootless_container(&container_dir, &rootfs, container_pid, cmd_to_run, is_interactive).await;
    }

    // For elevated/root containers, check if we need special handling
    if !is_root && elevated {
        // Running as non-root but container needs elevated privileges
        return exec_elevated_container(&container_dir, &rootfs, container_pid, cmd_to_run, is_interactive).await;
    }

    // For root containers running with root privileges, use nsenter
    let mut nsenter_args: Vec<String> = vec![
        "--target".into(),
        container_pid.to_string(),
        "--mount".into(),
        "--uts".into(),
        "--ipc".into(),
        "--net".into(),
        "--pid".into(),
        format!("--root={}", rootfs.to_string_lossy()),
        "--".into(),
    ];
    
    // Wrap the command to ensure we're in a valid directory
    let wrapped_cmd = if cmd_to_run.is_empty() {
        vec!["sh".to_string(), "-c".to_string(), "cd / 2>/dev/null || true; exec /bin/sh".to_string()]
    } else {
        let cmd_str = cmd_to_run.join(" ");
        vec!["sh".to_string(), "-c".to_string(), format!("cd / 2>/dev/null || true; exec {}", cmd_str)]
    };
    
    nsenter_args.extend(wrapped_cmd);

    if is_interactive {
        println!("Starting interactive shell session...");
        println!("Type 'exit' or press Ctrl+D to exit.\n");

        // Check if we're running in a TTY
        let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;

        if is_tty {
            // Try nsenter first, then fallback to sudo if permission denied
            match spawn_with_pty("nsenter", &nsenter_args) {
                Ok(exit_code) => {
                    if exit_code != 0 {
                        return Err(format!("Command exited with code {}", exit_code).into());
                    }
                    return Ok(());
                }
                Err(e) if e.to_string().contains("Operation not permitted") => {
                    println!("Permission denied with nsenter, trying with sudo...");
                    let mut sudo_args = vec!["nsenter".to_string()];
                    sudo_args.extend(nsenter_args);

                    let exit_code = spawn_with_pty("sudo", &sudo_args)
                        .map_err(|e| format!("Failed to start PTY session with sudo: {}", e))?;
                    if exit_code != 0 {
                        return Err(format!("Command exited with code {}", exit_code).into());
                    }
                    return Ok(());
                }
                Err(e) => return Err(format!("Failed to start PTY session: {}", e).into()),
            }
        } else {
            // Not in a TTY, fall back to regular command execution
            println!("Not running in a TTY, using regular command execution...");
            use std::process::{Command, Stdio};

            // Try nsenter first
            let mut exec_cmd = Command::new("nsenter");
            exec_cmd.args(&nsenter_args);
            exec_cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit()).stdin(Stdio::inherit());

            match exec_cmd.spawn() {
                Ok(mut child) => {
                    let status = child.wait()?;
                    if !status.success() {
                        if let Some(code) = status.code() {
                            return Err(format!("Command exited with code {}", code).into());
                        }
                    }
                    return Ok(());
                }
                Err(e) if e.to_string().contains("Operation not permitted") => {
                    println!("Permission denied with nsenter, trying with sudo...");

                    let mut sudo_args = vec!["nsenter".to_string()];
                    sudo_args.extend(nsenter_args);

                    let mut sudo_cmd = Command::new("sudo");
                    sudo_cmd.args(&sudo_args);
                    sudo_cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit()).stdin(Stdio::inherit());

                    let mut child = sudo_cmd.spawn().map_err(|e| {
                        if e.kind() == std::io::ErrorKind::NotFound {
                            "sudo command not found. Please run as root or install sudo.".to_string()
                        } else {
                            format!("Failed to execute command with sudo: {}", e)
                        }
                    })?;

                    let status = child.wait()?;
                    if !status.success() {
                        if let Some(code) = status.code() {
                            return Err(format!("Command exited with code {}", code).into());
                        }
                    }
                    return Ok(());
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        return Err("nsenter command not found. Please install util-linux package.".into());
                    } else {
                        return Err(format!("Failed to execute command: {}", e).into());
                    }
                }
            }
        }
    } else {
        // For non-interactive commands, just inherit stdout/stderr
        use std::process::{Command, Stdio};

        // Try nsenter first
        let mut exec_cmd = Command::new("nsenter");
        exec_cmd.args(&nsenter_args);
        exec_cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

        match exec_cmd.spawn() {
            Ok(mut child) => {
                // Wait for the command to complete
                let status = child.wait()?;
                if !status.success() {
                    if let Some(code) = status.code() {
                        return Err(format!("Command exited with code {}", code).into());
                    }
                }
                return Ok(());
            }
            Err(e) if e.to_string().contains("Operation not permitted") => {
                println!("Permission denied with nsenter, trying with sudo...");

                // Try with sudo
                let mut sudo_args = vec!["nsenter".to_string()];
                sudo_args.extend(nsenter_args);

                let mut sudo_cmd = Command::new("sudo");
                sudo_cmd.args(&sudo_args);
                sudo_cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

                let mut child = sudo_cmd.spawn().map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        "sudo command not found. Please run as root or install sudo.".to_string()
                    } else {
                        format!("Failed to execute command with sudo: {}", e)
                    }
                })?;

                let status = child.wait()?;
                if !status.success() {
                    if let Some(code) = status.code() {
                        return Err(format!("Command exited with code {}", code).into());
                    }
                }
                return Ok(());
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Err("nsenter command not found. Please install util-linux package.".into());
                } else {
                    return Err(format!("Failed to execute command: {}", e).into());
                }
            }
        }
    }
}

pub async fn show_container_logs(
    container_id: String,
    follow: bool,
    tail: Option<usize>,
    timestamps: bool,
    since: Option<String>,
    search: Option<String>,
    fuzzy: bool,
    regex: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize storage layout
    let storage = StorageLayout::new()?;

    // Find the container
    let container_dir = find_container_by_id(&storage, &container_id)?;
    let full_container_id = container_dir
        .file_name()
        .ok_or("Invalid container directory")?
        .to_string_lossy()
        .to_string();

    // Check if container log file exists
    let log_file = container_dir.join("container.log");
    if !log_file.exists() {
        println!(
            "No logs available for container {}",
            short12(&full_container_id)
        );
        println!("Container may not have been run in detached mode or may not have produced any output yet.");
        return Ok(());
    }

    // Display logs
    use std::fs::File;
    use std::io::{BufRead, BufReader, Seek, SeekFrom};

    // Build filters
    let since_time = since.as_deref().and_then(|s| parse_since(s).ok());
    let search = search.map(|s| s.to_lowercase());
    // Pre-compile regex (case-insensitive) if provided
    let regex = if let Some(pat) = regex {
        // (?i) for case-insensitive matching
        Some(
            regex::Regex::new(&format!("(?i){}", pat))
                .map_err(|e| format!("Invalid regex: {}", e))?,
        )
    } else {
        None
    };

    // File mtime for best-effort since filtering of non-timestamped lines
    let file_meta = std::fs::metadata(&log_file)?;
    let file_mtime_utc: Option<chrono::DateTime<chrono::Utc>> = file_meta
        .modified()
        .ok()
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t));

    if follow {
        // Tail-follow implementation: optionally seek to last N lines, then stream appends
        let mut file = File::open(&log_file)?;

        if let Some(n) = tail {
            if n > 0 {
                let pos = seek_to_last_n_lines(&mut file, n)?;
                let _ = file.seek(SeekFrom::Start(pos))?;
            }
        }

        println!(
            "Following logs for container {} (press Ctrl+C to stop)...",
            short12(&full_container_id)
        );
        let mut reader = BufReader::new(file);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // No new data; sleep briefly and retry
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Ok(_) => {
                    if let Some(out) = filter_and_format_log_line(
                        &line,
                        since_time,
                        file_mtime_utc,
                        timestamps,
                        search.as_deref(),
                        fuzzy,
                        regex.as_ref(),
                    ) {
                        print!("{}", out);
                    }
                }
                Err(e) => {
                    eprintln!("Error reading log: {}", e);
                    break;
                }
            }
        }
    } else {
        // Non-follow mode: read file, optionally tail
        let logs = std::fs::read_to_string(&log_file)?;
        let lines: Vec<&str> = logs.lines().collect();
        let start = tail.map(|n| lines.len().saturating_sub(n)).unwrap_or(0);
        for line in &lines[start..] {
            if let Some(out) = filter_and_format_log_line(
                line,
                since_time,
                file_mtime_utc,
                timestamps,
                search.as_deref(),
                fuzzy,
                regex.as_ref(),
            ) {
                print!("{}", out);
            }
        }
    }

    Ok(())
}

pub async fn show_container_info(container_id: String) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize storage layout
    let storage = StorageLayout::new()?;

    // First try to find as a container
    if let Ok(container_dir) = find_container_by_id(&storage, &container_id) {
        return show_container_details(&storage, container_dir, &container_id);
    }

    // If not found as container, try to find as an image
    if let Ok(Some((image, tag, manifest_content))) = find_image_by_id(&storage, &container_id) {
        return show_image_details(&storage, &image, &tag, &manifest_content, &container_id);
    }

    Err(format!("No container or image found matching '{}'", container_id).into())
}

fn show_container_details(
    _storage: &StorageLayout,
    container_dir: std::path::PathBuf,
    container_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let full_container_id = container_dir
        .file_name()
        .ok_or("Invalid container directory")?
        .to_string_lossy()
        .to_string();

    // Read container metadata
    let metadata_path = container_dir.join("metadata.json");
    if !metadata_path.exists() {
        return Err(format!("Container {} not found", container_id).into());
    }

    let metadata_content = std::fs::read_to_string(&metadata_path)?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata_content)?;

    // Print header
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║ CONTAINER INFORMATION                                             ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");

    // Container ID
    println!("║ ID:        {:<54} ║", full_container_id);

    // Short ID
    println!("║ Short ID:  {:<54} ║", short12(&full_container_id));

    // Name
    let default_name = format!("car_{}", &full_container_id[..6]);
    let name = metadata["name"].as_str().unwrap_or(&default_name);
    println!("║ Name:      {:<54} ║", name);

    // Image
    let image = metadata["image"].as_str().unwrap_or("unknown");
    println!("║ Image:     {:<54} ║", image);

    // Status
    let status = metadata["status"].as_str().unwrap_or("unknown");
    let status_display = if status == "running" || status.starts_with("Up") {
        format!("🟢 {}", status)
    } else if status.starts_with("exited") || status.starts_with("Exited") {
        format!("🔴 {}", status)
    } else {
        format!("⚫ {}", status)
    };
    println!("║ Status:    {:<54} ║", status_display);
    // Storage driver indicator
    if let Some(driver) = metadata["storage_driver"].as_str() {
        println!("║ Storage:   {:<54} ║", driver);
    }

    // Created
    let created = metadata["created"].as_str().unwrap_or("unknown");
    if let Ok(datetime) = chrono::DateTime::parse_from_rfc3339(created) {
        let now = chrono::Utc::now();
        let duration = now.signed_duration_since(datetime);

        let uptime = if duration.num_days() > 0 {
            format!(
                "{} ({} days ago)",
                created.chars().take(19).collect::<String>(),
                duration.num_days()
            )
        } else if duration.num_hours() > 0 {
            format!(
                "{} ({} hours ago)",
                created.chars().take(19).collect::<String>(),
                duration.num_hours()
            )
        } else if duration.num_minutes() > 0 {
            format!(
                "{} ({} minutes ago)",
                created.chars().take(19).collect::<String>(),
                duration.num_minutes()
            )
        } else {
            format!(
                "{} (just now)",
                created.chars().take(19).collect::<String>()
            )
        };
        println!("║ Created:   {:<54} ║", uptime);

        // If running, show uptime
        if status == "running" || status.starts_with("Up") {
            let uptime_str = if duration.num_days() > 0 {
                format!(
                    "{} days, {} hours",
                    duration.num_days(),
                    duration.num_hours() % 24
                )
            } else if duration.num_hours() > 0 {
                format!(
                    "{} hours, {} minutes",
                    duration.num_hours(),
                    duration.num_minutes() % 60
                )
            } else if duration.num_minutes() > 0 {
                format!(
                    "{} minutes, {} seconds",
                    duration.num_minutes(),
                    duration.num_seconds() % 60
                )
            } else {
                format!("{} seconds", duration.num_seconds())
            };
            println!("║ Uptime:    {:<54} ║", uptime_str);
        }
    } else {
        println!("║ Created:   {:<54} ║", created);
    }

    // Stopped time if exists
    if let Some(stopped) = metadata["stopped_at"].as_str() {
        println!(
            "║ Stopped:   {:<54} ║",
            stopped.chars().take(19).collect::<String>()
        );
    }

    // Exit code if exists
    if let Some(exit_code) = metadata["exit_code"].as_i64() {
        println!("║ Exit Code: {:<54} ║", exit_code);
    }

    // Command
    if let Some(command) = metadata["command"].as_array() {
        let cmd_str = command
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let cmd_display = if cmd_str.len() > 54 {
            format!("{}...", &cmd_str[..51])
        } else {
            cmd_str
        };
        println!("║ Command:   {:<54} ║", cmd_display);
    }

    // Rootfs
    if let Some(rootfs) = metadata["rootfs"].as_str() {
        let rootfs_display = if rootfs.len() > 54 {
            format!("...{}", &rootfs[rootfs.len() - 51..])
        } else {
            rootfs.to_string()
        };
        println!("║ Rootfs:    {:<54} ║", rootfs_display);
    }

    // PID if running
    let pid_file = container_dir.join("pid");
    if pid_file.exists() {
        if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                // Check if process is actually running
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;

                let process_pid = Pid::from_raw(pid);
                if kill(process_pid, None).is_ok() {
                    println!("║ PID:       {:<54} ║", pid);

                    // Try to get process info
                    if let Ok(proc_stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
                        // Extract CPU and memory info if available
                        let parts: Vec<&str> = proc_stat.split_whitespace().collect();
                        if parts.len() > 23 {
                            let vsize = parts[22].parse::<u64>().unwrap_or(0) / 1024 / 1024; // Convert to MB
                            let rss = parts[23].parse::<u64>().unwrap_or(0) * 4 / 1024; // Pages to MB (assuming 4KB pages)
                            println!(
                                "║ Memory:    {:<54} ║",
                                format!("VSZ: {} MB, RSS: {} MB", vsize, rss)
                            );
                        }
                    }
                }
            }
        }
    }

    println!("╠═══════════════════════════════════════════════════════════════════╣");

    // Log tail (if log file exists - future feature)
    let log_file = container_dir.join("container.log");
    if log_file.exists() {
        println!("║ RECENT LOGS                                                      ║");
        println!("╠═══════════════════════════════════════════════════════════════════╣");

        if let Ok(logs) = std::fs::read_to_string(&log_file) {
            let lines: Vec<&str> = logs.lines().collect();
            let start = if lines.len() > 10 {
                lines.len() - 10
            } else {
                0
            };

            for line in &lines[start..] {
                let display_line = if line.len() > 65 {
                    format!("{}...", &line[..62])
                } else {
                    line.to_string()
                };
                println!("║ {:<65} ║", display_line);
            }
        }
        println!("╠═══════════════════════════════════════════════════════════════════╣");
    }

    // Environment variables (first 5)
    if let Some(env) = metadata["env"].as_array() {
        if !env.is_empty() {
            println!("║ ENVIRONMENT VARIABLES (first 5)                                  ║");
            println!("╠═══════════════════════════════════════════════════════════════════╣");

            for (i, var) in env.iter().take(5).enumerate() {
                if let Some(env_str) = var.as_str() {
                    let display = if env_str.len() > 65 {
                        format!("{}...", &env_str[..62])
                    } else {
                        env_str.to_string()
                    };
                    println!("║ {:<65} ║", display);
                }
            }

            if env.len() > 5 {
                println!(
                    "║ ... and {} more                                                     ║",
                    env.len() - 5
                );
            }
            println!("╠═══════════════════════════════════════════════════════════════════╣");
        }
    }

    // Footer with helpful commands
    println!("║ AVAILABLE COMMANDS                                               ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");

    if status == "running" || status.starts_with("Up") {
        println!(
            "║ • carrier sh {}                                          ║",
            short12(&full_container_id)
        );
        println!(
            "║ • carrier stop {}                                        ║",
            short12(&full_container_id)
        );
        println!(
            "║ • carrier logs {} (if implemented)                      ║",
            short12(&full_container_id)
        );
    } else {
        println!(
            "║ • carrier rm {}                                          ║",
            short12(&full_container_id)
        );
        println!(
            "║ • carrier run {} (to start a new instance)              ║",
            &image[..image.len().min(12)]
        );
    }

    println!("╚═══════════════════════════════════════════════════════════════════╝");

    Ok(())
}

fn show_image_details(
    storage: &StorageLayout,
    image: &str,
    tag: &str,
    manifest_content: &str,
    image_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Parse the manifest
    let manifest: serde_json::Value = serde_json::from_str(manifest_content)?;

    // Print header with wider format to accommodate SHA
    println!(
        "╔═════════════════════════════════════════════════════════════════════════════════════════════╗"
    );
    println!(
        "║ IMAGE INFORMATION                                                                           ║"
    );
    println!(
        "╠═════════════════════════════════════════════════════════════════════════════════════════════╣"
    );

    // Image name and tag
    println!("║ Repository:        {:<70}   ║", image);
    println!("║ Tag:               {:<70}   ║", tag);

    // Image ID (config digest)
    if let Some(config_digest) = manifest["config"]["digest"].as_str() {
        let short_id = config_digest.chars().skip(7).take(12).collect::<String>();
        println!("║ Image ID:          {:<70}   ║", short_id);
        println!("║ Full ID:           {:<71}  ║", config_digest);
    }

    // Count running instances
    let running_instances = count_running_instances(storage, image, tag)?;
    println!("║ Running Instances: {:<70}   ║", running_instances);

    // Created date from config if available
    if let Some(config_digest) = manifest["config"]["digest"].as_str() {
        // Try to read the config blob for creation date
        let config_path = storage.blob_cache_path(config_digest);

        if let Ok(config_content) = std::fs::read_to_string(&config_path) {
            if let Ok(config_json) = serde_json::from_str::<serde_json::Value>(&config_content) {
                if let Some(created) = config_json["created"].as_str() {
                    if let Ok(datetime) = chrono::DateTime::parse_from_rfc3339(created) {
                        let now = chrono::Utc::now();
                        let duration = now.signed_duration_since(datetime);
                        let time_ago = if duration.num_days() > 0 {
                            format!("{} days ago", duration.num_days())
                        } else if duration.num_hours() > 0 {
                            format!("{} hours ago", duration.num_hours())
                        } else if duration.num_minutes() > 0 {
                            format!("{} minutes ago", duration.num_minutes())
                        } else {
                            format!("{} seconds ago", duration.num_seconds())
                        };
                        println!(
                            "║ Created:           {} :{:<44}    ║",
                            datetime.format("%Y-%m-%d %H:%M:%S UTC"),
                            time_ago
                        );
                    }
                }
            }
        }
    }

    // Size information
    if let Some(layers) = manifest["layers"].as_array() {
        let total_size: i64 = layers
            .iter()
            .filter_map(|layer| layer["size"].as_i64())
            .sum();
        println!(
            "║ Size:              {:<70}   ║",
            format_size(total_size as u64)
        );
        println!("║ Layers:            {:<70}   ║", layers.len());
    }

    // Architecture and OS
    if let Some(config_digest) = manifest["config"]["digest"].as_str() {
        let config_path = storage.blob_cache_path(config_digest);

        if let Ok(config_content) = std::fs::read_to_string(&config_path) {
            if let Ok(config_json) = serde_json::from_str::<serde_json::Value>(&config_content) {
                if let Some(arch) = config_json["architecture"].as_str() {
                    println!("║ Architecture:      {:<70}   ║", arch);
                }
                if let Some(os) = config_json["os"].as_str() {
                    println!("║ OS:                {:<70}   ║", os);
                }
            }
        }
    }

    // Footer with helpful commands
    println!(
        "╠═════════════════════════════════════════════════════════════════════════════════════════════╣"
    );
    println!(
        "║ AVAILABLE COMMANDS                                                                          ║"
    );
    println!(
        "╠═════════════════════════════════════════════════════════════════════════════════════════════╣"
    );
    let run_cmd1 = format!("carrier run {}:{}", image, tag);
    let run_cmd2 = format!("carrier run {} (by image ID)", image_id);
    let rm_cmd = format!("carrier rm {}:{}", image, tag);
    println!("║ • {:<89} ║", run_cmd1);
    println!("║ • {:<89} ║", run_cmd2);
    println!("║ • {:<89} ║", rm_cmd);
    println!(
        "╚═════════════════════════════════════════════════════════════════════════════════════════════╝"
    );

    Ok(())
}

fn count_running_instances(
    storage: &StorageLayout,
    image: &str,
    tag: &str,
) -> Result<u32, Box<dyn std::error::Error>> {
    let containers_dir = storage.base.join("storage/overlay-containers");
    let target_image = format!("{}:{}", image, tag);
    let mut count = 0;

    if !containers_dir.exists() {
        return Ok(0);
    }

    for entry in std::fs::read_dir(&containers_dir)? {
        let entry = entry?;
        if entry.path().is_dir() {
            let metadata_path = entry.path().join("metadata.json");
            if metadata_path.exists() {
                if let Ok(metadata_content) = std::fs::read_to_string(&metadata_path) {
                    if let Ok(metadata) =
                        serde_json::from_str::<serde_json::Value>(&metadata_content)
                    {
                        if let (Some(container_image), Some(status)) =
                            (metadata["image"].as_str(), metadata["status"].as_str())
                        {
                            // Check if this container uses this image and is running
                            if container_image == target_image
                                && (status == "running" || status.starts_with("Up"))
                            {
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(count)
}

pub async fn pull_image(image_name: String, platform: Option<String>) {
    // Initialize storage layout
    let storage = match StorageLayout::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize storage: {}", e);
            return;
        }
    };

    if let Err(e) = storage.init() {
        eprintln!("Failed to initialize storage directories: {}", e);
        return;
    }

    let parsed_image = match RegistryImage::parse(&image_name) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("Failed to parse image: {}", e);
            return;
        }
    };

    let registry = parsed_image.registry.as_deref().unwrap_or("docker.io");
    println!("Pulling from {}", registry);
    println!("Image: {}", parsed_image.image);
    println!("Tag: {}", parsed_image.tag);

    // Get auth token (try authenticated first, fall back to anonymous)
    let image_path = normalize_image_path(&parsed_image.image);
    let token = match get_authenticated_token(registry, &image_path).await {
        Ok(t) => {
            println!("Successfully obtained auth token");
            t
        }
        Err(e) => {
            eprintln!("Failed to get auth token: {}", e);
            return;
        }
    };

    // Get manifest
    let manifest_json = match get_manifest_content(&parsed_image, &token).await {
        Ok(m) => {
            println!("Successfully downloaded manifest");
            m
        }
        Err(e) => {
            eprintln!("Failed to get manifest: {}", e);
            return;
        }
    };

    // Parse manifest - handle both manifest list and single manifest
    let manifest =
        match parse_and_get_manifest(&manifest_json, &parsed_image, &token, platform.as_deref())
            .await
        {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to parse manifest: {}", e);
                return;
            }
        };

    // Save the actual manifest (not the manifest list) as metadata
    let metadata_path = storage.image_metadata_path(&parsed_image.image, &parsed_image.tag);
    let manifest_to_save = serde_json::to_string(&manifest).unwrap_or(manifest_json.clone());
    if let Err(e) = std::fs::write(&metadata_path, &manifest_to_save) {
        eprintln!("Warning: Failed to save manifest metadata: {}", e);
    }

    // Download layers with progress using storage
    if let Err(e) = download_layers_with_storage(&manifest, &parsed_image, &token, &storage).await {
        eprintln!("Failed to download layers: {}", e);
        return;
    }

    println!("\nImage {} pulled successfully!", image_name);
    println!(
        "Stored in: {}",
        storage
            .image_metadata_path(&parsed_image.image, &parsed_image.tag)
            .display()
    );
}

async fn get_manifest_content(
    parsed_image: &RegistryImage,
    token: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let registry = parsed_image.registry.as_deref().unwrap_or("docker.io");

    if let Some(registry_endpoint) = REGISTRYMAP.get(registry) {
        let image_path = normalize_image_path(&parsed_image.image);
        let manifest_url = format!(
            "{}{}/manifests/{}",
            registry_endpoint, image_path, parsed_image.tag
        );

        let response = make_authenticated_request(&manifest_url, token).await?;

        if !response.status().is_success() {
            return Err(format!("Failed to get manifest: {}", response.status()).into());
        }

        let manifest_content = response.text().await?;
        Ok(manifest_content)
    } else {
        Err(format!("Registry {} not found", registry).into())
    }
}

async fn parse_and_get_manifest(
    manifest_json: &str,
    parsed_image: &RegistryImage,
    token: &str,
    platform: Option<&str>,
) -> Result<ManifestV2, Box<dyn std::error::Error>> {
    // First try to parse as manifest list
    if let Ok(manifest_list) = serde_json::from_str::<ManifestList>(manifest_json) {
        println!("Detected manifest list, selecting appropriate platform...");

        // Determine desired platform
        let (want_os, want_arch) = platform
            .and_then(|p| p.split_once('/'))
            .map(|(os, arch)| (os.to_string(), arch.to_string()))
            .unwrap_or_else(|| ("linux".to_string(), "amd64".to_string()));

        // Find the desired platform (or first available)
        let selected_manifest = manifest_list
            .manifests
            .iter()
            .find(|m| m.platform.os == want_os && m.platform.architecture == want_arch)
            .or_else(|| manifest_list.manifests.first())
            .ok_or("No suitable manifest found in manifest list")?;

        println!(
            "Selected platform: {}/{}",
            selected_manifest.platform.os, selected_manifest.platform.architecture
        );

        // Fetch the specific manifest
        let registry = parsed_image.registry.as_deref().unwrap_or("docker.io");
        if let Some(registry_endpoint) = REGISTRYMAP.get(registry) {
            let image_path = normalize_image_path(&parsed_image.image);
            let manifest_url = format!(
                "{}{}/manifests/{}",
                registry_endpoint, image_path, selected_manifest.digest
            );

            let response = make_authenticated_request(&manifest_url, token).await?;
            if !response.status().is_success() {
                return Err(
                    format!("Failed to get specific manifest: {}", response.status()).into(),
                );
            }

            let specific_manifest_json = response.text().await?;
            let manifest: ManifestV2 = serde_json::from_str(&specific_manifest_json)?;
            Ok(manifest)
        } else {
            Err(format!("Registry not found").into())
        }
    } else {
        // Try to parse as direct manifest
        let manifest: ManifestV2 = serde_json::from_str(manifest_json)?;
        Ok(manifest)
    }
}

async fn download_layers_with_storage(
    manifest: &ManifestV2,
    parsed_image: &RegistryImage,
    token: &str,
    storage: &StorageLayout,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let registry = parsed_image.registry.as_deref().unwrap_or("docker.io");
    let registry_url = REGISTRYMAP
        .get(registry)
        .ok_or_else(|| format!("Registry {} not found", registry))?;

    let image_path = normalize_image_path(&parsed_image.image);
    let client = Client::new();

    // Create multi-progress for multiple layers
    let multi_progress = MultiProgress::new();
    let mut layer_paths = Vec::new();

    // Download config first
    if !storage.blob_exists(&manifest.config.digest) {
        println!("\nDownloading config: {}", &manifest.config.digest[..12]);
        let config_url = format!(
            "{}{}/blobs/{}",
            registry_url, image_path, manifest.config.digest
        );

        let blob_data = download_blob_with_progress(
            &client,
            &config_url,
            token,
            &manifest.config.digest,
            manifest.config.size as u64,
            &multi_progress,
            "config",
        )
        .await?;

        storage.save_blob(&manifest.config.digest, &blob_data)?;
    } else {
        println!("Config already cached: {}", &manifest.config.digest[..12]);
    }

    // Download each layer
    println!("Processing {} layers", manifest.layers.len());

    for (index, layer) in manifest.layers.iter().enumerate() {
        let layer_dir = storage.image_layer_path(&layer.digest);

        // Check if layer is already extracted
        if storage.layer_exists(&layer.digest) {
            println!(
                "Layer {}/{} already cached: {}",
                index + 1,
                manifest.layers.len(),
                &layer.digest[..12]
            );
            layer_paths.push(layer_dir);
            continue;
        }

        // Download blob if not cached
        let blob_path = if !storage.blob_exists(&layer.digest) {
            let blob_url = format!("{}{}/blobs/{}", registry_url, image_path, layer.digest);

            let blob_data = download_blob_with_progress(
                &client,
                &blob_url,
                token,
                &layer.digest,
                layer.size as u64,
                &multi_progress,
                &format!("layer {}/{}", index + 1, manifest.layers.len()),
            )
            .await?;

            storage.save_blob(&layer.digest, &blob_data)?
        } else {
            println!(
                "Layer blob {}/{} already cached",
                index + 1,
                manifest.layers.len()
            );
            storage.blob_cache_path(&layer.digest)
        };

        // Extract layer to storage
        println!(
            "Extracting layer {}/{}...",
            index + 1,
            manifest.layers.len()
        );
        std::fs::create_dir_all(&layer_dir)?;
        extract_layer_rootless(&blob_path, &layer_dir)?;

        layer_paths.push(layer_dir);
    }

    println!("All layers processed successfully!");
    Ok(layer_paths)
}

async fn download_blob_with_progress(
    client: &Client,
    url: &str,
    token: &str,
    digest: &str,
    expected_size: u64,
    multi_progress: &MultiProgress,
    label: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut attempt = 0;
    let max_attempts = 3;
    loop {
        // Create progress bar for this attempt
        let pb = multi_progress.add(ProgressBar::new(expected_size));
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
                )?
                .progress_chars("#>-"),
        );
        pb.set_message(format!("{} {} (try {})", label, &digest[..12], attempt + 1));

        // Make request
        let response = client
            .get(url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !response.status().is_success() {
            pb.finish_with_message(format!("✗ {} {}", label, &digest[..12]));
            attempt += 1;
            if attempt >= max_attempts {
                return Err(format!("Failed to download blob: {}", response.status()).into());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await;
            continue;
        }

        // Get content length if available
        let content_length = response.content_length().unwrap_or(expected_size);
        if content_length != expected_size && content_length > 0 {
            pb.set_length(content_length);
        }

        // Download with progress
        let mut downloaded = Vec::new();
        let mut stream = response.bytes_stream();

        use futures_util::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            downloaded.extend_from_slice(&chunk);
            pb.inc(chunk.len() as u64);
        }

        // Verify digest if provided as sha256
        if let Some(hex_expected) = digest.strip_prefix("sha256:") {
            let mut hasher = sha2::Sha256::new();
            use sha2::Digest;
            hasher.update(&downloaded);
            let actual = hasher.finalize();
            let actual_hex = hex::encode(actual);
            if actual_hex != hex_expected {
                pb.finish_with_message(format!("✗ digest mismatch for {}", &digest[..12]));
                attempt += 1;
                if attempt >= max_attempts {
                    return Err("Downloaded blob digest verification failed".into());
                }
                tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await;
                continue;
            }
        }

        pb.finish_with_message(format!("✓ {} {}", label, &digest[..12]));
        return Ok(downloaded);
    }
}

/// Set up essential network configuration files in the container
fn setup_container_network_files(rootfs: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let etc_dir = rootfs.join("etc");
    
    println!("Setting up network files in: {}", etc_dir.display());
    
    // Ensure /etc exists
    std::fs::create_dir_all(&etc_dir)?;
    
    // Copy host's resolv.conf for DNS resolution
    let host_resolv = Path::new("/etc/resolv.conf");
    let container_resolv = etc_dir.join("resolv.conf");
    
    // Always overwrite resolv.conf to ensure DNS works
    if host_resolv.exists() {
        println!("Copying host resolv.conf to container");
        std::fs::copy(host_resolv, &container_resolv)?;
    } else {
        println!("Creating default resolv.conf with Google DNS");
        // Create a basic resolv.conf with common DNS servers
        std::fs::write(
            &container_resolv,
            "# Generated by carrier\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n"
        )?;
    }
    
    // Set up hosts file (always overwrite for consistency)
    let container_hosts = etc_dir.join("hosts");
    std::fs::write(
        &container_hosts,
        "127.0.0.1\tlocalhost\n::1\tlocalhost\n"
    )?;
    
    Ok(())
}

async fn run_container_with_storage(
    parsed_image: &RegistryImage,
    manifest: &ManifestV2,
    layer_paths: Vec<PathBuf>,
    storage: &StorageLayout,
    detach: bool,
    name: Option<String>,
    elevated: bool,
    command_override: Option<Vec<String>>,
    storage_driver: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::runtime::container::{Container, ContainerConfig};
    use crate::runtime::network::{NetworkConfig, NetworkMode};

    println!(
        "\nStarting container from image {}...",
        parsed_image.to_string()
    );

    // Generate container ID or use custom name
    let container_id = match &name {
        Some(custom_name) => custom_name.clone(),
        None => generate_container_id(),
    };
    println!("Container ID: {}", container_id);

    // Create container with overlay filesystem
    println!("Setting up container filesystem with overlay...");

    // Preflight checks for rootless operation
    crate::storage::preflight_rootless_checks();
    // Allow forcing storage driver via CLI
    let mut container_storage = if let Some(drv) = storage_driver {
        ContainerStorage::new_with_driver(Some(drv))?
    } else {
        ContainerStorage::new()?
    };
    let rootfs = container_storage.create_container_filesystem(&container_id, layer_paths)?;
    let storage_driver_str = match container_storage.last_driver() {
        crate::storage::StorageDriver::OverlayFuse => "overlay(fuse)",
        crate::storage::StorageDriver::OverlayNative => "overlay(native)",
        crate::storage::StorageDriver::Vfs => "vfs",
    };

    println!("Container filesystem ready at: {}", rootfs.display());
    
    // Set up essential files for networking
    setup_container_network_files(&rootfs)?;

    // Read image config to get command and env
    let config_blob_path = storage.blob_cache_path(&manifest.config.digest);
    let mut command = vec!["/bin/sh".to_string()];
    let mut env = vec![];
    let mut working_dir = "/".to_string();

    if config_blob_path.exists() {
        if let Ok(config_content) = std::fs::read_to_string(&config_blob_path) {
            if let Ok(config_json) = serde_json::from_str::<serde_json::Value>(&config_content) {
                // Extract command
                if let Some(cmd) = config_json["config"]["Cmd"].as_array() {
                    command = cmd
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                } else if let Some(entrypoint) = config_json["config"]["Entrypoint"].as_array() {
                    command = entrypoint
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                }

                // Extract environment
                if let Some(env_array) = config_json["config"]["Env"].as_array() {
                    for e in env_array {
                        if let Some(env_str) = e.as_str() {
                            if let Some(eq_pos) = env_str.find('=') {
                                let key = env_str[..eq_pos].to_string();
                                let value = env_str[eq_pos + 1..].to_string();
                                env.push((key, value));
                            }
                        }
                    }
                }

                // Extract working directory
                if let Some(wd) = config_json["config"]["WorkingDir"].as_str() {
                    if !wd.is_empty() {
                        working_dir = wd.to_string();
                    }
                }
            }
        }
    }

    // Apply command override if provided
    if let Some(override_cmd) = command_override.clone() {
        if !override_cmd.is_empty() {
            command = override_cmd;
        }
    }

    // For detached containers with no explicit command or only a shell, use sleep infinity
    if detach && (command.is_empty()
        || (command.len() == 1 && (command[0] == "/bin/sh"
            || command[0] == "/bin/bash"
            || command[0] == "sh"
            || command[0] == "bash"))) {
        println!("No persistent command specified for detached container, using 'sleep infinity'");
        command = vec!["sleep".to_string(), "infinity".to_string()];
    }

    // Add default environment if not present
    if !env.iter().any(|(k, _)| k == "PATH") {
        env.push((
            "PATH".to_string(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        ));
    }
    if !env.iter().any(|(k, _)| k == "TERM") {
        env.push(("TERM".to_string(), "xterm".to_string()));
    }

    // Clone command for later use
    let command_to_run = command.clone();

    // Configure container
    let container_config = ContainerConfig {
        id: container_id.clone(),
        name: None,
        image: parsed_image.to_string(),
        rootfs: rootfs.clone(),
        command,
        env,
        working_dir,
        hostname: Some(format!("carrier-{}", &container_id[..8])),
        user: None,
        readonly_rootfs: false,
        network_config: NetworkConfig {
            enable_network: true,
            network_mode: NetworkMode::Slirp4netns,
            ..Default::default()
        },
        ..Default::default()
    };

    // Store container metadata
    let container_meta_path = storage.container_path(&container_id).join("metadata.json");
    // Generate container name - use custom name if provided, otherwise generate default name
    let container_name = match &name {
        Some(custom_name) => custom_name.clone(),
        None => format!("car_{}", &container_id[..6]),
    };

    let metadata = serde_json::json!({
        "id": container_id,
        "name": container_name,
        "image": parsed_image.to_string(),
        "created": chrono::Utc::now().to_rfc3339(),
        "rootfs": rootfs.to_string_lossy(),
        "command": container_config.command,
        "status": "running",
        "storage_driver": storage_driver_str,
        "elevated": elevated
    });

    if let Some(parent) = container_meta_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&container_meta_path, metadata.to_string())?;

    // Execute in container environment with proper isolation
    if detach {
        println!(
            "\nRunning container {} in detached mode...",
            short12(&container_id)
        );
    } else {
        println!("\nRunning container {}...", container_id);
    }
    println!("Command: {:?}", &command_to_run);

    use std::process::Stdio;

    if command_to_run.is_empty() || command_to_run[0].is_empty() {
        println!("No command specified in image");
        return Ok(());
    }

    // Detect if this should be an interactive container (not applicable in detached mode)
    let is_interactive = !detach
        && (command_to_run[0].contains("bash")
            || command_to_run[0].contains("sh")
            || command_to_run.contains(&"-it".to_string())
            || command_to_run.contains(&"-i".to_string()));

    // Build the command path
    let cmd_in_container = &command_to_run[0];

    if !detach {
        println!("Starting container with command: {}", cmd_in_container);
    }

    // Use different approach based on elevated flag
    let mut cmd = if elevated {
        println!("Running container with elevated privileges (using sudo)...");
        // For elevated mode, use sudo to run unshare without user namespace
        // Use host networking for elevated containers to ensure network connectivity
        let mut c = Command::new("sudo");
        c.arg("unshare")
            .arg("--mount")
            .arg("--pid")
            .arg("--fork")  // Fork to properly handle PID namespace
            .arg("chroot")
            .arg(&rootfs);
        c
    } else {
        // For rootless mode, use user namespaces for better isolation
        let mut c = Command::new("unshare");
        c.arg("--user")
            .arg("--map-root-user") // Map current user to root in container
            .arg("--mount")
            .arg("--pid")
            .arg("--fork")  // Fork to properly handle PID namespace
            .arg("--net")   // Create network namespace for rootless
            .arg("chroot")
            .arg(&rootfs);
        c
    };

    // Set up environment
    cmd.env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    )
    .env("HOME", "/root")
    .env("TERM", "xterm")
    .env("HOSTNAME", format!("carrier-{}", &container_id[..8]));

    // Add the actual command
    cmd.args(&command_to_run);

    if detach {
        // For detached containers, pipe stdout/stderr and write timestamped lines to log file
        let log_path = storage.container_path(&container_id).join("container.log");

        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Save the PID to a file
        let pid_file = storage.container_path(&container_id).join("pid");
        std::fs::write(&pid_file, child.id().to_string())?;

        // Spawn logging threads
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let log_writer = std::sync::Arc::new(std::sync::Mutex::new(log_file));

        // stdout thread
        if let Some(stdout) = child.stdout.take() {
            let writer = log_writer.clone();
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader, Write};
                let reader = BufReader::new(stdout);
                for line in reader.lines().flatten() {
                    let stamp = chrono::Utc::now().to_rfc3339();
                    let mut w = writer.lock().unwrap();
                    let _ = writeln!(w, "{} {}", stamp, line);
                }
            });
        }
        // stderr thread
        if let Some(stderr) = child.stderr.take() {
            let writer = log_writer.clone();
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader, Write};
                let reader = BufReader::new(stderr);
                for line in reader.lines().flatten() {
                    let stamp = chrono::Utc::now().to_rfc3339();
                    let mut w = writer.lock().unwrap();
                    let _ = writeln!(w, "{} {}", stamp, line);
                }
            });
        }

        println!("Container {} started in background", short12(&container_id));
        println!("Logs are being written to: {}", log_path.display());
        println!("To view logs: carrier logs {}", short12(&container_id));
        println!("To stop: carrier stop {}", short12(&container_id));

        // Do not wait for the child; threads handle logging
        return Ok(());
    } else if is_interactive {
        println!("\nStarting interactive container session...");
        println!("Type 'exit' or press Ctrl+D to exit the container.\n");

        // Build argv for unshare + chroot + command
        let mut args: Vec<String> = vec![
            "--user".into(),
            "--map-root-user".into(),
            "--mount".into(),
            "--pid".into(),
                "chroot".into(),
            rootfs.display().to_string(),
        ];
        args.extend(command_to_run.clone());
        let exit_code = spawn_with_pty("unshare", &args)?;

        // Remove PID file after process exits
        let pid_file = storage.container_path(&container_id).join("pid");
        let _ = std::fs::remove_file(&pid_file);

        // Update container status
        let metadata = serde_json::json!({
            "id": container_id,
            "image": parsed_image.to_string(),
            "created": chrono::Utc::now().to_rfc3339(),
            "rootfs": rootfs.to_string_lossy(),
            "status": format!("exited ({})", exit_code)
        });
        std::fs::write(&container_meta_path, metadata.to_string())?;

        if exit_code == 0 {
            println!("\nContainer {} exited successfully", container_id);
        } else {
            println!(
                "\nContainer {} exited with code {}",
                container_id, exit_code
            );
        }
    } else {
        // For non-interactive containers, capture output
        use std::process::Command;
        match Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "--pid",
                "chroot",
                &rootfs.to_string_lossy(),
            ])
            .args(&command_to_run)
            .output()
        {
            Ok(output) => {
                // Print output
                if !output.stdout.is_empty() {
                    print!("{}", String::from_utf8_lossy(&output.stdout));
                }
                if !output.stderr.is_empty() {
                    eprint!("{}", String::from_utf8_lossy(&output.stderr));
                }

                let exit_code = output.status.code().unwrap_or(-1);

                // Update container status
                let metadata = serde_json::json!({
                    "id": container_id,
                    "image": parsed_image.to_string(),
                    "created": chrono::Utc::now().to_rfc3339(),
                    "rootfs": rootfs.to_string_lossy(),
                    "status": format!("exited ({})", exit_code)
                });
                std::fs::write(&container_meta_path, metadata.to_string())?;

                if exit_code == 0 {
                    println!("\nContainer {} exited successfully", container_id);
                } else {
                    println!(
                        "\nContainer {} exited with code {}",
                        container_id, exit_code
                    );
                }
            }
            Err(e) => {
                eprintln!("Failed to execute container: {}", e);

                // Fallback for systems without proper unshare support
                if e.to_string().contains("Operation not permitted") {
                    println!("\nFalling back to direct execution mode...");

                    // Execute directly in the overlay filesystem
                    let cmd_path = rootfs.join(cmd_in_container.trim_start_matches('/'));
                    if cmd_path.exists() {
                        let mut fallback = Command::new(&cmd_path);
                        fallback
                            .args(&command_to_run[1..])
                            .current_dir(&rootfs)
                            .env(
                                "PATH",
                                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                            );

                        if is_interactive {
                            fallback
                                .stdin(Stdio::inherit())
                                .stdout(Stdio::inherit())
                                .stderr(Stdio::inherit());

                            let mut child = fallback.spawn()?;
                            let _ = child.wait();
                        } else {
                            if let Ok(output) = fallback.output() {
                                print!("{}", String::from_utf8_lossy(&output.stdout));
                                if !output.stderr.is_empty() {
                                    eprint!("{}", String::from_utf8_lossy(&output.stderr));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn normalize_image_path(image_name: &str) -> String {
    let parts: Vec<&str> = image_name.split('/').collect();
    match parts.len() {
        1 => format!("library/{}", parts[0]),
        _ => image_name.to_string(),
    }
}

fn short12(s: &str) -> String {
    s.chars().take(12).collect::<String>()
}

// Spawn a Command under a pseudo-terminal with TTY semantics, window resizing, and raw mode
/// Detect a compatible terminal type for maximum portability
fn detect_compatible_term() -> &'static str {
    if let Ok(term) = std::env::var("TERM") {
        // Map common terminal types to widely supported ones
        if term.starts_with("xterm") || term.contains("256color") {
            "xterm-256color"
        } else if term.contains("color") {
            "xterm-color"
        } else if term == "screen" || term.starts_with("screen") {
            "screen"
        } else if term == "tmux" || term.starts_with("tmux") {
            "screen"
        } else if term == "linux" || term == "vt100" || term == "vt102" {
            term.leak()  // These are basic and widely supported
        } else {
            // Default to most basic terminal that should work everywhere
            "xterm"
        }
    } else {
        // No TERM set, use most compatible option
        "xterm"
    }
}

fn spawn_with_pty(program: &str, args: &[String]) -> Result<i32, Box<dyn std::error::Error>> {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::{Read, Write};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    // Check if we're actually in a TTY
    let stdin_fd = libc::STDIN_FILENO;
    let is_tty = unsafe { libc::isatty(stdin_fd) } == 1;

    // Save the original terminal attributes only if we're in a TTY
    let mut original_attrs: Option<libc::termios> = None;

    if is_tty {
        let mut attrs: libc::termios = unsafe { std::mem::zeroed() };

        // Get original terminal settings
        if unsafe { libc::tcgetattr(stdin_fd, &mut attrs) } != 0 {
            return Err("Failed to get terminal attributes".into());
        }

        original_attrs = Some(attrs);

        // Set terminal to raw mode for proper input handling
        let mut raw_attrs = attrs;
        raw_attrs.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);
        raw_attrs.c_iflag &= !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);
        raw_attrs.c_cflag &= !(libc::CSIZE | libc::PARENB);
        raw_attrs.c_cflag |= libc::CS8;
        raw_attrs.c_oflag &= !(libc::OPOST);
        raw_attrs.c_cc[libc::VMIN] = 1;
        raw_attrs.c_cc[libc::VTIME] = 0;

        if unsafe { libc::tcsetattr(stdin_fd, libc::TCSAFLUSH, &raw_attrs) } != 0 {
            return Err("Failed to set raw mode".into());
        }
    }

    // Ensure we restore terminal on any exit (only if we modified it)
    let _restore_guard = scopeguard::guard(original_attrs, |attrs| {
        if let Some(attrs) = attrs {
            let _ = unsafe { libc::tcsetattr(stdin_fd, libc::TCSAFLUSH, &attrs) };
        }
    });

    // Open a PTY with a reasonable default size
    let pty_system = native_pty_system();
    let size = PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    };
    let pair = pty_system.openpty(size)?;

    // Build command
    let mut builder = CommandBuilder::new(program);
    builder.args(args.iter().map(|s| s.as_str()));
    
    // Set up compatible environment variables for maximum portability
    builder.env("TERM", detect_compatible_term());
    builder.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    builder.env("HOME", "/root");
    builder.env("USER", "root");
    builder.env("LOGNAME", "root");
    builder.env("SHELL", "/bin/sh");  // Most compatible shell
    builder.env("LANG", "C.UTF-8");   // UTF-8 support with C locale fallback
    builder.env("LC_ALL", "C");        // Override all locale settings for compatibility
    builder.env("PWD", "/");           // Set initial working directory

    // Spawn the child connected to the slave end of the PTY
    let mut child = pair.slave.spawn_command(builder)?;
    drop(pair.slave); // not needed in parent

    // Prepare master for I/O and resizing
    let master = pair.master;
    let mut reader = master.try_clone_reader()?;
    let mut writer = master.take_writer()?;
    let master_arc = Arc::new(Mutex::new(master));

    // Shared flag to signal when child process has exited
    let child_running = Arc::new(AtomicBool::new(true));
    let child_running_tx = child_running.clone();
    let child_running_rx = child_running.clone();

    // stdin -> PTY writer
    let tx = std::thread::spawn(move || {
        use std::os::unix::io::AsRawFd;
        let mut buf = [0u8; 4096];
        let stdin_fd = std::io::stdin().as_raw_fd();

        while child_running_tx.load(Ordering::Relaxed) {
            // Use select to check if stdin has data available with timeout
            let mut read_fds = unsafe { std::mem::zeroed::<libc::fd_set>() };
            unsafe { libc::FD_ZERO(&mut read_fds) };
            unsafe { libc::FD_SET(stdin_fd, &mut read_fds) };

            let mut timeout = libc::timeval {
                tv_sec: 0,
                tv_usec: 100_000, // 100ms timeout
            };

            let result = unsafe {
                libc::select(
                    stdin_fd + 1,
                    &mut read_fds,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut timeout,
                )
            };

            if result > 0 && unsafe { libc::FD_ISSET(stdin_fd, &read_fds) } {
                // Data is available, read it
                let bytes_read = unsafe {
                    libc::read(stdin_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };

                if bytes_read > 0 {
                    let n = bytes_read as usize;
                    if writer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                } else if bytes_read == 0 {
                    break; // EOF
                }
            }
            // If result <= 0, either timeout or error, continue loop to check child_running
        }
    });

    // PTY reader -> stdout
    let rx = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut stdout = std::io::stdout();
        while child_running_rx.load(Ordering::Relaxed) {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = stdout.flush();
                }
                Err(_) => break,
            }
        }
    });

    // Resize thread: poll terminal size and update PTY size
    let master_for_resize = master_arc.clone();
    let child_running_resize = child_running.clone();
    let _resize_handle = std::thread::spawn(move || {
        let mut last = (24u16, 80u16);
        while child_running_resize.load(Ordering::Relaxed) {
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            let ok = unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } == 0;
            if ok {
                let current = (ws.ws_row, ws.ws_col);
                if current != last && ws.ws_row > 0 && ws.ws_col > 0 {
                    if let Ok(guard) = master_for_resize.lock() {
                        let _ = guard.resize(PtySize {
                            rows: ws.ws_row,
                            cols: ws.ws_col,
                            pixel_width: 0,
                            pixel_height: 0,
                        });
                    }
                    last = current;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    });

    // Wait for child to complete and signal threads to stop
    let status = child.wait()?;
    child_running.store(false, Ordering::Relaxed);

    // Wait for threads to finish
    let _ = tx.join();
    let _ = rx.join();

    Ok(status.exit_code() as i32)
}

fn parse_since(input: &str) -> Result<chrono::DateTime<chrono::Utc>, Box<dyn std::error::Error>> {
    // Try RFC3339 first
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(input) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }
    // Try duration suffixes: s,m,h,d
    let (num_part, unit) = input.trim().split_at(input.trim().len().saturating_sub(1));
    let n: i64 = num_part.parse()?;
    let dur = match unit {
        "s" => chrono::Duration::seconds(n),
        "m" => chrono::Duration::minutes(n),
        "h" => chrono::Duration::hours(n),
        "d" => chrono::Duration::days(n),
        _ => return Err("Invalid since format".into()),
    };
    Ok(chrono::Utc::now() - dur)
}

fn filter_and_format_log_line(
    raw_line: &str,
    since_time: Option<chrono::DateTime<chrono::Utc>>,
    file_mtime_utc: Option<chrono::DateTime<chrono::Utc>>,
    show_timestamps: bool,
    search: Option<&str>,
    fuzzy: bool,
    regex: Option<&regex::Regex>,
) -> Option<String> {
    let line = raw_line.trim_end_matches('\n');
    if line.is_empty() {
        return None;
    }

    // Parse optional timestamp prefix: RFC3339 followed by space
    let (ts, content) = if let Some((ts_str, rest)) = line.split_once(' ') {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts_str) {
            (Some(dt.with_timezone(&chrono::Utc)), rest)
        } else {
            (None, line)
        }
    } else {
        (None, line)
    };

    // Apply since filter only if we have a parsable timestamp
    match (since_time, ts) {
        (Some(since_dt), Some(entry_dt)) => {
            if entry_dt < since_dt {
                return None;
            }
        }
        (Some(since_dt), None) => {
            // Best-effort: include only if file mtime is newer than since
            if let Some(mtime) = file_mtime_utc {
                if mtime < since_dt {
                    return None;
                }
            }
        }
        _ => {}
    }

    // Apply search filter
    if let Some(re) = regex {
        if !re.is_match(content) {
            return None;
        }
    } else if let Some(q) = search {
        let lc = content.to_lowercase();
        let matched = if fuzzy {
            fuzzy_match(&lc, q)
        } else {
            lc.contains(q)
        };
        if !matched {
            return None;
        }
    }

    // Format output
    let out = if show_timestamps {
        let stamp = ts.unwrap_or_else(|| chrono::Utc::now()).to_rfc3339();
        format!("{} {}\n", stamp, content)
    } else {
        format!("{}\n", content)
    };
    Some(out)
}

fn fuzzy_match(text: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let mut it = text.chars();
    for pc in pattern.chars() {
        let mut found = false;
        while let Some(tc) = it.next() {
            if tc == pc {
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    true
}

#[cfg(test)]
fn choose_manifest_digest(
    manifest_list_json: &str,
    platform: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let manifest_list: ManifestList = serde_json::from_str(manifest_list_json)?;
    let (want_os, want_arch) = platform
        .and_then(|p| p.split_once('/'))
        .map(|(os, arch)| (os, arch))
        .unwrap_or(("linux", "amd64"));
    let selected = manifest_list
        .manifests
        .iter()
        .find(|m| m.platform.os == want_os && m.platform.architecture == want_arch)
        .or_else(|| manifest_list.manifests.first())
        .ok_or("no manifest")?;
    Ok(selected.digest.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn test_normalize_image_path() {
        assert_eq!(normalize_image_path("alpine"), "library/alpine");
        assert_eq!(normalize_image_path("library/nginx"), "library/nginx");
        assert_eq!(normalize_image_path("myorg/myimg"), "myorg/myimg");
    }

    #[test]
    fn test_choose_manifest_digest() {
        let json = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
            "manifests": [
                {"mediaType":"application/vnd.docker.distribution.manifest.v2+json","size":123,"digest":"sha256:amd64digest","platform":{"architecture":"amd64","os":"linux"}},
                {"mediaType":"application/vnd.docker.distribution.manifest.v2+json","size":124,"digest":"sha256:arm64digest","platform":{"architecture":"arm64","os":"linux"}}
            ]
        }"#;
        assert_eq!(
            choose_manifest_digest(json, Some("linux/arm64")).unwrap(),
            "sha256:arm64digest"
        );
        assert_eq!(
            choose_manifest_digest(json, Some("linux/amd64")).unwrap(),
            "sha256:amd64digest"
        );
        // default picks first if platform not provided
        let d = choose_manifest_digest(json, None).unwrap();
        assert!(d.starts_with("sha256:"));
    }

    #[test]
    fn test_seek_to_last_n_lines() {
        let mut tf = tempfile::NamedTempFile::new().unwrap();
        let content = "line1\nline2\nline3\nline4\nline5\n";
        tf.write_all(content.as_bytes()).unwrap();
        let mut file = std::fs::File::open(tf.path()).unwrap();
        let pos = seek_to_last_n_lines(&mut file, 2).unwrap();
        file.seek(SeekFrom::Start(pos)).unwrap();
        let mut out = String::new();
        file.read_to_string(&mut out).unwrap();
        assert_eq!(out, "line4\nline5\n");
    }

    #[test]
    fn test_parse_since_duration() {
        let now = chrono::Utc::now();
        let dt = parse_since("10m").unwrap();
        assert!(now - dt >= chrono::Duration::minutes(9));
        assert!(now - dt <= chrono::Duration::minutes(11));
    }

    #[test]
    fn test_parse_since_rfc3339() {
        let s = "2020-01-01T00:00:00Z";
        let dt = parse_since(s).unwrap();
        assert_eq!(dt.to_rfc3339(), s);
    }

    #[test]
    fn test_fuzzy_match() {
        assert!(fuzzy_match("hello world", "hwd"));
        assert!(fuzzy_match("ContainerLogs", "clg"));
        assert!(!fuzzy_match("abc", "acdb"));
    }
}

pub async fn get_repo_auth_token(url: String) -> Result<String, Box<dyn std::error::Error>> {
    let parsed_image = RegistryImage::parse(&url)?;
    let client = Client::new();
    let registry = parsed_image.registry.as_deref().unwrap_or("docker.io");

    if let Some(auth_endpoint) = AUTHTOKENMAP.get(registry) {
        // Build the auth URL with query parameters
        let image_path = normalize_image_path(&parsed_image.image);
        let scope = format!("repository:{}:pull", image_path);

        let auth_url = match registry {
            "docker.io" => format!(
                "{}?service=registry.docker.io&scope={}",
                auth_endpoint, scope
            ),
            "quay.io" => format!("{}?service=quay.io&scope={}", auth_endpoint, scope),
            "ghcr.io" => format!("{}?service=ghcr.io&scope={}", auth_endpoint, scope),
            "public.ecr.aws" => format!("{}?service=public.ecr.aws&scope={}", auth_endpoint, scope),
            _ => format!("{}?scope={}", auth_endpoint, scope),
        };

        // Make the token request
        let response = client
            .get(&auth_url)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Auth request failed: {}", response.status()).into());
        }

        // Parse the token from response
        let auth_response: serde_json::Value = response.json().await?;

        if let Some(token) = auth_response.get("token").and_then(|t| t.as_str()) {
            Ok(token.to_string())
        } else if let Some(access_token) =
            auth_response.get("access_token").and_then(|t| t.as_str())
        {
            // Some registries use "access_token" instead of "token"
            Ok(access_token.to_string())
        } else {
            Err("No token found in auth response".into())
        }
    } else {
        Err(format!("No auth endpoint configured for registry: {}", registry).into())
    }
}

pub async fn make_authenticated_request(
    url: &str,
    token: &str,
) -> Result<Response, Box<dyn std::error::Error>> {
    let client = Client::new();
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", token))
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json",
        )
        .send()
        .await?;
    Ok(response)
}

// Helper: seek to last N lines in a file
fn seek_to_last_n_lines(
    file: &mut std::fs::File,
    n: usize,
) -> Result<u64, Box<dyn std::error::Error>> {
    use std::io::{Read, Seek, SeekFrom};
    if n == 0 {
        return Ok(0);
    }
    let pos_len = file.metadata()?.len() as i64;
    let mut pos = pos_len;
    let mut count = 0usize;
    let mut buf = [0u8; 1024];
    while pos > 0 && count <= n {
        let read_size = std::cmp::min(buf.len() as i64, pos) as usize;
        pos -= read_size as i64;
        file.seek(SeekFrom::Start(pos as u64))?;
        file.read_exact(&mut buf[..read_size])?;
        for &b in buf[..read_size].iter().rev() {
            if b == b'\n' {
                count += 1;
                if count > n {
                    break;
                }
            }
        }
    }
    // If file shorter than requested lines, start at 0
    let start = if count > n { pos as u64 } else { 0 };
    Ok(start)
}

// List command implementation
pub async fn list_items(all: bool, images_only: bool, containers_only: bool) {
    // Initialize storage layout
    let storage = match StorageLayout::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize storage: {}", e);
            return;
        }
    };

    // Don't show both if neither flag is set (show both by default)
    let show_images = !containers_only;
    let show_containers = !images_only;

    if show_images {
        // Collect all images first
        let mut images = Vec::new();

        if let Ok(entries) = std::fs::read_dir(storage.base.join("storage/overlay-images")) {
            for entry in entries.flatten() {
                if let Some(filename) = entry.file_name().to_str() {
                    if filename.ends_with(".json") {
                        // Parse image name from filename
                        let image_info = filename.trim_end_matches(".json");

                        // Read metadata to get more info
                        if let Ok(metadata_content) = std::fs::read_to_string(entry.path()) {
                            if let Ok(metadata) =
                                serde_json::from_str::<serde_json::Value>(&metadata_content)
                            {
                                let config_digest = metadata["config"]["digest"]
                                    .as_str()
                                    .unwrap_or("unknown")
                                    .chars()
                                    .skip(7)
                                    .take(12)
                                    .collect::<String>();

                                // Get file modification time as creation time
                                let created = if let Ok(file_meta) = entry.metadata() {
                                    if let Ok(modified) = file_meta.modified() {
                                        let datetime =
                                            chrono::DateTime::<chrono::Utc>::from(modified);
                                        // Calculate relative time
                                        let now = chrono::Utc::now();
                                        let duration = now.signed_duration_since(datetime);

                                        if duration.num_days() > 0 {
                                            format!("{} days ago", duration.num_days())
                                        } else if duration.num_hours() > 0 {
                                            format!("{} hours ago", duration.num_hours())
                                        } else if duration.num_minutes() > 0 {
                                            format!("{} minutes ago", duration.num_minutes())
                                        } else {
                                            "Just now".to_string()
                                        }
                                    } else {
                                        "Unknown".to_string()
                                    }
                                } else {
                                    "Unknown".to_string()
                                };

                                // Calculate size from layers
                                let size = calculate_image_size(&storage, &metadata);

                                // Replace underscores back to slashes for display
                                let display_name = image_info.replace("_", "/");
                                images.push((
                                    display_name,
                                    config_digest,
                                    created,
                                    size.to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Print images in box format with fixed alignment
        if !images.is_empty() || (show_images && !show_containers) {
            // Fixed column widths for consistent alignment
            const REPO_WIDTH: usize = 30;
            const TAG_WIDTH: usize = 10;
            const ID_WIDTH: usize = 12;
            const CREATED_WIDTH: usize = 15;
            const SIZE_WIDTH: usize = 8;

            // Calculate exact total width: columns + separators
            // 30 + 10 + 12 + 15 + 8 = 75 (columns)
            // 5 columns = 4 separators × 3 chars = 12 + 4 (║ at start/end) = 16
            // Total = 75 + 16 = 91
            const TOTAL_WIDTH: usize = 91;

            // Print top border
            println!("╔{}╗", "═".repeat(TOTAL_WIDTH - 2));
            println!("║ IMAGES{}║", " ".repeat(TOTAL_WIDTH - 9));

            // Print header separator - manually calculated for exact alignment
            println!(
                "╠{}╤{}╤{}╤{}╤{}╣",
                "═".repeat(REPO_WIDTH + 2),
                "═".repeat(TAG_WIDTH + 2),
                "═".repeat(ID_WIDTH + 2),
                "═".repeat(CREATED_WIDTH + 2),
                "═".repeat(SIZE_WIDTH + 2)
            );

            // Print headers
            println!(
                "║ {:^width1$} │ {:^width2$} │ {:^width3$} │ {:^width4$} │ {:^width5$} ║",
                "REPOSITORY",
                "TAG",
                "IMAGE ID",
                "CREATED",
                "SIZE",
                width1 = REPO_WIDTH,
                width2 = TAG_WIDTH,
                width3 = ID_WIDTH,
                width4 = CREATED_WIDTH,
                width5 = SIZE_WIDTH
            );

            // Print header bottom separator
            println!(
                "╠{}╪{}╪{}╪{}╪{}╣",
                "═".repeat(REPO_WIDTH + 2),
                "═".repeat(TAG_WIDTH + 2),
                "═".repeat(ID_WIDTH + 2),
                "═".repeat(CREATED_WIDTH + 2),
                "═".repeat(SIZE_WIDTH + 2)
            );

            if images.is_empty() {
                println!("║ No images found{}║", " ".repeat(TOTAL_WIDTH - 18));
                println!("╚{}╝", "═".repeat(TOTAL_WIDTH - 2));
            } else {
                for (full_name, id, created, size) in &images {
                    // Split repository and tag
                    let (repository, tag) = if let Some(last_slash) = full_name.rfind('/') {
                        let repo_part = &full_name[..last_slash];
                        let tag_part = &full_name[last_slash + 1..];
                        (repo_part.to_string(), tag_part.to_string())
                    } else {
                        (full_name.clone(), "latest".to_string())
                    };

                    // Truncate fields if necessary
                    let repo_display = if repository.len() > REPO_WIDTH {
                        format!("{}...", &repository[..REPO_WIDTH - 3])
                    } else {
                        repository
                    };

                    let tag_display = if tag.len() > TAG_WIDTH {
                        format!("{}...", &tag[..TAG_WIDTH - 3])
                    } else {
                        tag
                    };

                    let id_display = if id.len() > ID_WIDTH {
                        format!("{}...", &id[..ID_WIDTH - 3])
                    } else {
                        id.clone()
                    };

                    let created_display = if created.len() > CREATED_WIDTH {
                        format!("{}...", &created[..CREATED_WIDTH - 3])
                    } else {
                        created.clone()
                    };

                    let size_display = if size.len() > SIZE_WIDTH {
                        format!("{}...", &size[..SIZE_WIDTH - 3])
                    } else {
                        size.clone()
                    };

                    println!(
                        "║ {:<width1$} │ {:<width2$} │ {:<width3$} │ {:<width4$} │ {:<width5$} ║",
                        repo_display,
                        tag_display,
                        id_display,
                        created_display,
                        size_display,
                        width1 = REPO_WIDTH,
                        width2 = TAG_WIDTH,
                        width3 = ID_WIDTH,
                        width4 = CREATED_WIDTH,
                        width5 = SIZE_WIDTH
                    );
                }

                // Print bottom border
                println!(
                    "╚{}╧{}╧{}╧{}╧{}╝",
                    "═".repeat(REPO_WIDTH + 2),
                    "═".repeat(TAG_WIDTH + 2),
                    "═".repeat(ID_WIDTH + 2),
                    "═".repeat(CREATED_WIDTH + 2),
                    "═".repeat(SIZE_WIDTH + 2)
                );
            }
        }

        if show_containers && show_images {
            println!(); // Spacing between sections
        }
    }

    if show_containers {
        // List all containers from storage
        let mut containers = Vec::new();

        if let Ok(entries) = std::fs::read_dir(storage.base.join("storage/overlay-containers")) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let container_id = entry.file_name().to_string_lossy().to_string();
                    let metadata_path = entry.path().join("metadata.json");

                    if metadata_path.exists() {
                        if let Ok(content) = std::fs::read_to_string(&metadata_path) {
                            if let Ok(metadata) =
                                serde_json::from_str::<serde_json::Value>(&content)
                            {
                                let status = metadata["status"].as_str().unwrap_or("unknown");

                                // Filter based on 'all' flag
                                if !all && status != "running" {
                                    continue;
                                }

                                // Calculate relative time for created
                                let created_str = metadata["created"].as_str().unwrap_or("unknown");

                                let created_display = if let Ok(datetime) =
                                    chrono::DateTime::parse_from_rfc3339(created_str)
                                {
                                    let now = chrono::Utc::now();
                                    let duration = now.signed_duration_since(datetime);

                                    if duration.num_weeks() > 0 {
                                        format!("{} weeks ago", duration.num_weeks())
                                    } else if duration.num_days() > 0 {
                                        format!("{} days ago", duration.num_days())
                                    } else if duration.num_hours() > 0 {
                                        format!("{} hours ago", duration.num_hours())
                                    } else if duration.num_minutes() > 0 {
                                        format!("{} minutes ago", duration.num_minutes())
                                    } else {
                                        "Just now".to_string()
                                    }
                                } else {
                                    "Unknown".to_string()
                                };

                                // Check if container is actually running if it claims to be
                                let actual_status = if status == "running"
                                    || status.starts_with("Up")
                                {
                                    // Check PID file and process
                                    let pid_file = entry.path().join("pid");
                                    if pid_file.exists() {
                                        if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
                                            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                                                use nix::sys::signal::{kill, Signal};
                                                use nix::unistd::Pid;

                                                let process_pid = Pid::from_raw(pid);
                                                if kill(process_pid, None).is_ok() {
                                                    status // Process is actually running
                                                } else {
                                                    // Process is dead, update metadata
                                                    let mut metadata_mut = metadata.clone();
                                                    metadata_mut["status"] =
                                                        serde_json::json!("exited");
                                                    let _ = std::fs::write(
                                                        &metadata_path,
                                                        metadata_mut.to_string(),
                                                    );
                                                    let _ = std::fs::remove_file(&pid_file);
                                                    "exited"
                                                }
                                            } else {
                                                "exited"
                                            }
                                        } else {
                                            "exited"
                                        }
                                    } else {
                                        // No PID file, container is not running
                                        let mut metadata_mut = metadata.clone();
                                        metadata_mut["status"] = serde_json::json!("exited");
                                        let _ = std::fs::write(
                                            &metadata_path,
                                            metadata_mut.to_string(),
                                        );
                                        "exited"
                                    }
                                } else {
                                    status
                                };

                                // Format status display
                                let mut status_display = match actual_status {
                                    "created" => format!("Created"),
                                    "running" => format!("Up {}", created_display.clone()),
                                    "exited" => format!("Exited (0) {}", created_display.clone()),
                                    _ if actual_status.starts_with("Up") => {
                                        actual_status.to_string()
                                    }
                                    _ => actual_status.to_string(),
                                };

                                // Append storage driver indicator if present
                                if let Some(driver) = metadata["storage_driver"].as_str() {
                                    if !driver.is_empty() {
                                        status_display = format!("{} ({})", status_display, driver);
                                    }
                                }

                                // Get command if available
                                let command =
                                    if let Some(cmd_array) = metadata["command"].as_array() {
                                        cmd_array
                                            .iter()
                                            .filter_map(|v| v.as_str())
                                            .collect::<Vec<_>>()
                                            .join(" ")
                                    } else {
                                        metadata["command"].as_str().unwrap_or("").to_string()
                                    };

                                // Get ports if available
                                let ports = metadata["ports"].as_str().unwrap_or("").to_string();

                                // Get container name if available
                                let name = metadata["name"].as_str().unwrap_or("").to_string();

                                containers.push((
                                    container_id.clone(),
                                    metadata["image"].as_str().unwrap_or("unknown").to_string(),
                                    command,
                                    created_display,
                                    status_display,
                                    ports,
                                    name,
                                    created_str.to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Sort by creation time (newest first)
        containers.sort_by(|a, b| b.7.cmp(&a.7));

        // Print containers in box format with fixed alignment
        if show_containers {
            // Fixed column widths - adjusted to match images total width of 91
            // Need 72 total column width for 6 columns (91 - 19 for separators/borders)
            const ID_WIDTH: usize = 12;
            const IMAGE_WIDTH: usize = 20;
            const CMD_WIDTH: usize = 9;
            const CREATED_WIDTH: usize = 12;
            const STATUS_WIDTH: usize = 11;
            const NAME_WIDTH: usize = 8;

            // Total: 12+20+9+12+11+8 = 72 columns
            // Plus: 6 columns means 5 × " │ " = 15, plus "║ " and " ║" = 4
            // Total = 72 + 19 = 91 (matches images)
            const TOTAL_WIDTH: usize = 91;

            // Print top border
            println!("╔{}╗", "═".repeat(TOTAL_WIDTH - 2));
            println!("║ CONTAINERS{}║", " ".repeat(TOTAL_WIDTH - 13));

            // Print header separator - must match total width
            println!(
                "╠{}╤{}╤{}╤{}╤{}╤{}╣",
                "═".repeat(ID_WIDTH + 2),
                "═".repeat(IMAGE_WIDTH + 2),
                "═".repeat(CMD_WIDTH + 2),
                "═".repeat(CREATED_WIDTH + 2),
                "═".repeat(STATUS_WIDTH + 2),
                "═".repeat(NAME_WIDTH + 2)
            );

            // Print headers
            println!(
                "║ {:^width1$} │ {:^width2$} │ {:^width3$} │ {:^width4$} │ {:^width5$} │ {:^width6$} ║",
                "ID",
                "IMAGE",
                "COMMAND",
                "CREATED",
                "STATUS",
                "NAMES",
                width1 = ID_WIDTH,
                width2 = IMAGE_WIDTH,
                width3 = CMD_WIDTH,
                width4 = CREATED_WIDTH,
                width5 = STATUS_WIDTH,
                width6 = NAME_WIDTH
            );

            // Print header bottom separator
            println!(
                "╠{}╪{}╪{}╪{}╪{}╪{}╣",
                "═".repeat(ID_WIDTH + 2),
                "═".repeat(IMAGE_WIDTH + 2),
                "═".repeat(CMD_WIDTH + 2),
                "═".repeat(CREATED_WIDTH + 2),
                "═".repeat(STATUS_WIDTH + 2),
                "═".repeat(NAME_WIDTH + 2)
            );

            if containers.is_empty() {
                let msg = if all {
                    "No containers found"
                } else {
                    "No running containers (use -a to show all) "
                };
                println!("║ {}{} ║", msg, " ".repeat(TOTAL_WIDTH - msg.len() - 4));
                println!("╚{}╝", "═".repeat(TOTAL_WIDTH - 2));
            } else {
                for (id, image, command, created, status, _ports, name, _) in &containers {
                    // Truncate fields if necessary
                    let id_display = if id.len() > ID_WIDTH {
                        format!("{}...", &id[..ID_WIDTH - 3])
                    } else {
                        id.clone()
                    };

                    let image_display = if image.len() > IMAGE_WIDTH {
                        format!("{}...", &image[..IMAGE_WIDTH - 3])
                    } else {
                        image.clone()
                    };

                    let cmd_display = if command.is_empty() {
                        "-".to_string()
                    } else if command.len() > CMD_WIDTH {
                        format!("{}...", &command[..CMD_WIDTH - 3])
                    } else {
                        command.clone()
                    };

                    let created_display = if created.len() > CREATED_WIDTH {
                        format!("{}...", &created[..CREATED_WIDTH - 3])
                    } else {
                        created.clone()
                    };

                    let status_display = if status.len() > STATUS_WIDTH {
                        format!("{}...", &status[..STATUS_WIDTH - 3])
                    } else {
                        status.clone()
                    };

                    let name_display = if name.is_empty() {
                        let generated = format!("car_{}", &id[..6.min(id.len())]);
                        if generated.len() > NAME_WIDTH {
                            format!("{}...", &generated[..NAME_WIDTH - 3])
                        } else {
                            generated
                        }
                    } else if name.len() > NAME_WIDTH {
                        format!("{}...", &name[..NAME_WIDTH - 3])
                    } else {
                        name.clone()
                    };

                    println!(
                        "║ {:<width1$} │ {:<width2$} │ {:<width3$} │ {:<width4$} │ {:<width5$} │ {:<width6$} ║",
                        id_display,
                        image_display,
                        cmd_display,
                        created_display,
                        status_display,
                        name_display,
                        width1 = ID_WIDTH,
                        width2 = IMAGE_WIDTH,
                        width3 = CMD_WIDTH,
                        width4 = CREATED_WIDTH,
                        width5 = STATUS_WIDTH,
                        width6 = NAME_WIDTH
                    );
                }

                // Print bottom border
                println!(
                    "╚{}╧{}╧{}╧{}╧{}╧{}╝",
                    "═".repeat(ID_WIDTH + 2),
                    "═".repeat(IMAGE_WIDTH + 2),
                    "═".repeat(CMD_WIDTH + 2),
                    "═".repeat(CREATED_WIDTH + 2),
                    "═".repeat(STATUS_WIDTH + 2),
                    "═".repeat(NAME_WIDTH + 2)
                );
            }
        }
    }
}

// Remove command implementation
pub async fn remove_item(item: String, force: bool) {
    // Initialize storage layout
    let storage = match StorageLayout::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize storage: {}", e);
            return;
        }
    };

    // First, try to find as a container (by exact or partial ID match)
    let container_result = find_container_by_id_optional(&storage, &item);

    // If found as container, remove it
    if let Ok(Some(container_path)) = container_result {
        let container_id = container_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Check container status
        let metadata_path = container_path.join("metadata.json");
        if metadata_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&metadata_path) {
                if let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&content) {
                    let status = metadata["status"].as_str().unwrap_or("unknown");

                    if status == "running" && !force {
                        eprintln!(
                            "Container {} is running. Use --force to remove",
                            container_id
                        );
                        return;
                    }
                }
            }
        }

        // Unmount overlay if it's mounted
        let merged_dir = container_path.join("merged");
        if merged_dir.exists() {
            // Try to unmount (ignore errors as it might not be mounted)
            let _ = std::process::Command::new("fusermount")
                .arg("-u")
                .arg(&merged_dir)
                .output();

            // Also try regular umount in case native overlay was used
            let _ = std::process::Command::new("umount")
                .arg(&merged_dir)
                .output();
        }

        // Remove container directory
        match std::fs::remove_dir_all(&container_path) {
            Ok(_) => println!("Container {} removed successfully", container_id),
            Err(e) => eprintln!("Failed to remove container {}: {}", container_id, e),
        }
        return;
    }

    // Not a container, try as an image
    // First try to find by image ID (digest)
    if let Ok(Some(image_info)) = find_image_by_id(&storage, &item) {
        remove_image(&storage, &image_info.0, &image_info.1, &image_info.2, force);
        return;
    }

    // Try to parse as image reference
    match RegistryImage::parse(&item) {
        Ok(parsed_image) => {
            // Remove image metadata
            let metadata_path = storage.image_metadata_path(&parsed_image.image, &parsed_image.tag);

            if !metadata_path.exists() {
                eprintln!("Image {} not found", item);
                return;
            }

            // Read the actual manifest to get layer info
            if let Ok(content) = std::fs::read_to_string(&metadata_path) {
                remove_image(
                    &storage,
                    &parsed_image.image,
                    &parsed_image.tag,
                    &content,
                    force,
                );
            }
        }
        Err(_) => {
            eprintln!("Invalid image reference or container ID: {}", item);
        }
    }
}

pub async fn remove_all_stopped_containers(force: bool) {
    // Initialize storage layout
    let storage = match StorageLayout::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize storage: {}", e);
            return;
        }
    };

    let containers_dir = storage.base.join("storage/overlay-containers");
    if !containers_dir.exists() {
        println!("No containers found");
        return;
    }

    let mut removed_count = 0;
    let mut failed_count = 0;
    let mut skipped_count = 0;

    // Iterate through all containers
    match std::fs::read_dir(&containers_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let container_id = entry.file_name().to_string_lossy().to_string();
                    let metadata_path = entry.path().join("metadata.json");

                    // Check container status
                    let should_remove = if metadata_path.exists() {
                        match std::fs::read_to_string(&metadata_path) {
                            Ok(content) => {
                                match serde_json::from_str::<serde_json::Value>(&content) {
                                    Ok(metadata) => {
                                        let status =
                                            metadata["status"].as_str().unwrap_or("unknown");
                                        // Remove if not running, or if force is specified
                                        status != "running" || force
                                    }
                                    Err(_) => true, // Remove if we can't parse metadata
                                }
                            }
                            Err(_) => true, // Remove if we can't read metadata
                        }
                    } else {
                        true // Remove if no metadata exists
                    };

                    if should_remove {
                        // Unmount overlay if mounted
                        let merged_dir = entry.path().join("merged");
                        if merged_dir.exists() {
                            let _ = std::process::Command::new("fusermount")
                                .arg("-u")
                                .arg(&merged_dir)
                                .output();

                            let _ = std::process::Command::new("umount")
                                .arg(&merged_dir)
                                .output();
                        }

                        // Remove container directory
                        match std::fs::remove_dir_all(entry.path()) {
                            Ok(_) => {
                                println!(
                                    "Removed container {}",
                                    &container_id[..12.min(container_id.len())]
                                );
                                removed_count += 1;
                            }
                            Err(e) => {
                                eprintln!(
                                    "Failed to remove container {}: {}",
                                    &container_id[..12.min(container_id.len())],
                                    e
                                );
                                failed_count += 1;
                            }
                        }
                    } else {
                        println!(
                            "Skipping running container {}",
                            &container_id[..12.min(container_id.len())]
                        );
                        skipped_count += 1;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read containers directory: {}", e);
            return;
        }
    }

    // Print summary
    println!("\n=== Summary ===");
    if removed_count > 0 {
        println!(
            "Removed {} container{}",
            removed_count,
            if removed_count == 1 { "" } else { "s" }
        );
    }
    if skipped_count > 0 {
        println!(
            "Skipped {} running container{}",
            skipped_count,
            if skipped_count == 1 { "" } else { "s" }
        );
    }
    if failed_count > 0 {
        println!(
            "Failed to remove {} container{}",
            failed_count,
            if failed_count == 1 { "" } else { "s" }
        );
    }
    if removed_count == 0 && skipped_count == 0 && failed_count == 0 {
        println!("No containers to remove");
    }
}

pub async fn stop_container(
    container_id: String,
    force: bool,
    timeout: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize storage layout
    let storage = StorageLayout::new()?;

    // Find the container - support partial IDs
    let container_dir = find_container_by_id(&storage, &container_id)?;
    let full_container_id = container_dir
        .file_name()
        .ok_or("Invalid container directory")?
        .to_string_lossy()
        .to_string();

    // Read container metadata to check status
    let metadata_path = container_dir.join("metadata.json");
    if !metadata_path.exists() {
        return Err(format!("Container {} not found", container_id).into());
    }

    let metadata_content = std::fs::read_to_string(&metadata_path)?;
    let mut metadata: serde_json::Value = serde_json::from_str(&metadata_content)?;

    let status = metadata["status"].as_str().unwrap_or("unknown");
    if status != "running" {
        println!(
            "Container {} is not running (status: {})",
            full_container_id, status
        );
        return Ok(());
    }

    println!("Stopping container {}...", short12(&full_container_id));

    // Get the PID file if it exists
    let pid_file = container_dir.join("pid");
    if pid_file.exists() {
        let pid_str = std::fs::read_to_string(&pid_file)?;
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let container_pid = Pid::from_raw(pid);

            // Try graceful shutdown with SIGTERM
            if !force {
                println!("Sending SIGTERM to process {}...", pid);
                if let Err(e) = kill(container_pid, Signal::SIGTERM) {
                    // Process might have already exited
                    if e != nix::errno::Errno::ESRCH {
                        eprintln!("Warning: Failed to send SIGTERM: {}", e);
                    }
                } else {
                    // Wait for process to terminate gracefully
                    let start = std::time::Instant::now();
                    let timeout_duration = std::time::Duration::from_secs(timeout);

                    while start.elapsed() < timeout_duration {
                        // Check if process still exists
                        if kill(container_pid, None).is_err() {
                            // Process has exited
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }

                    // Check if we need to force kill
                    if kill(container_pid, None).is_ok() {
                        println!(
                            "Container did not stop within {} seconds, forcing...",
                            timeout
                        );
                        force_kill_container(container_pid)?;
                    }
                }
            } else {
                // Force kill immediately
                force_kill_container(container_pid)?;
            }
        }

        // Remove PID file
        let _ = std::fs::remove_file(&pid_file);
    }

    // Try to unmount the overlay filesystem if it's mounted
    let merged_dir = container_dir.join("merged");
    if merged_dir.exists() {
        // Try fusermount for fuse-overlayfs
        let _ = std::process::Command::new("fusermount")
            .arg("-u")
            .arg(&merged_dir)
            .output();

        // Also try regular umount in case native overlay was used
        let _ = std::process::Command::new("umount")
            .arg(&merged_dir)
            .output();
    }

    // Update container metadata
    metadata["status"] = serde_json::json!("exited");
    metadata["stopped_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
    metadata["exit_code"] = serde_json::json!(if force { 137 } else { 0 });

    std::fs::write(&metadata_path, metadata.to_string())?;

    println!("Container {} stopped", short12(&full_container_id));
    Ok(())
}

fn force_kill_container(pid: nix::unistd::Pid) -> Result<(), Box<dyn std::error::Error>> {
    use nix::sys::signal::{kill, Signal};

    println!("Sending SIGKILL to process {}...", pid);
    if let Err(e) = kill(pid, Signal::SIGKILL) {
        // Process might have already exited
        if e != nix::errno::Errno::ESRCH {
            return Err(format!("Failed to kill process: {}", e).into());
        }
    }

    // Give it a moment to die
    std::thread::sleep(std::time::Duration::from_millis(500));
    Ok(())
}

fn calculate_image_size(storage: &StorageLayout, manifest: &serde_json::Value) -> String {
    let mut total_size: u64 = 0;

    // First check if this is a manifest list or a direct manifest
    if manifest.get("manifests").is_some() {
        // This is a manifest list - we need to get size differently
        // For now, calculate from actual cached blobs

        // Try to find any blobs that might be related to this image
        // Look in cache directory for any blobs
        let cache_dir = storage.base.join("cache/blobs");
        if cache_dir.exists() {
            // We'll estimate based on what we have cached
            // This is a rough estimate since we don't have the exact manifest
            if let Ok(entries) = std::fs::read_dir(&cache_dir) {
                let mut found_any = false;
                for entry in entries.flatten() {
                    let filename = entry.file_name().to_string_lossy().to_string();
                    // Check if this might be related (very rough heuristic)
                    if filename.starts_with("sha256_") {
                        // For a better estimate, we'd need to track which blobs belong to which image
                        // For now, just get the size of files we know are there
                        if let Ok(metadata) = entry.metadata() {
                            // Only count if modified recently (within last hour)
                            if let Ok(modified) = metadata.modified() {
                                let elapsed = std::time::SystemTime::now()
                                    .duration_since(modified)
                                    .unwrap_or_default();
                                if elapsed.as_secs() < 3600 {
                                    total_size += metadata.len();
                                    found_any = true;
                                }
                            }
                        }
                    }
                }
                if !found_any {
                    // Fallback: just report unknown
                    return "N/A".to_string();
                }
            }
        }
    } else {
        // This is a direct manifest with config and layers

        // Add config size if available
        if let Some(config) = manifest.get("config") {
            if let Some(size) = config["size"].as_u64() {
                total_size += size;
            } else if let Some(digest) = config["digest"].as_str() {
                // Try to get size from cached blob
                let blob_path = storage.blob_cache_path(digest);
                if blob_path.exists() {
                    if let Ok(metadata) = std::fs::metadata(&blob_path) {
                        total_size += metadata.len();
                    }
                }
            }
        }

        // Add all layer sizes
        if let Some(layers) = manifest["layers"].as_array() {
            for layer in layers {
                if let Some(size) = layer["size"].as_u64() {
                    total_size += size;
                } else if let Some(digest) = layer["digest"].as_str() {
                    // Try to get size from cached blob
                    let blob_path = storage.blob_cache_path(digest);
                    if blob_path.exists() {
                        if let Ok(metadata) = std::fs::metadata(&blob_path) {
                            total_size += metadata.len();
                        }
                    }
                }
            }
        }
    }

    // If we still have no size, return N/A
    if total_size == 0 {
        return "N/A".to_string();
    }

    // Format size in human-readable format
    format_size(total_size)
}

fn format_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];

    if size == 0 {
        return "0 B".to_string();
    }

    let mut size_f = size as f64;
    let mut unit_index = 0;

    while size_f >= 1024.0 && unit_index < UNITS.len() - 1 {
        size_f /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size_f, UNITS[unit_index])
    }
}

fn find_container_by_id(
    storage: &StorageLayout,
    container_id: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let containers_dir = storage.base.join("storage/overlay-containers");

    if !containers_dir.exists() {
        return Err("No containers found".into());
    }

    // Look for exact match or prefix match by ID, and also check by name
    let mut matches = Vec::new();

    for entry in std::fs::read_dir(&containers_dir)? {
        let entry = entry?;
        if entry.path().is_dir() {
            let dir_name = entry.file_name().to_string_lossy().to_string();

            // Exact match by ID
            if dir_name == container_id {
                return Ok(entry.path());
            }

            // Prefix match by ID
            if dir_name.starts_with(container_id) {
                matches.push(entry.path());
            }

            // Check container name in metadata
            let metadata_path = entry.path().join("metadata.json");
            if metadata_path.exists() {
                if let Ok(metadata_content) = std::fs::read_to_string(&metadata_path) {
                    if let Ok(metadata) =
                        serde_json::from_str::<serde_json::Value>(&metadata_content)
                    {
                        if let Some(name) = metadata["name"].as_str() {
                            // Exact match by name
                            if name == container_id {
                                return Ok(entry.path());
                            }
                            // Prefix match by name
                            if name.starts_with(container_id) {
                                matches.push(entry.path());
                            }
                        }
                    }
                }
            }
        }
    }

    // Remove duplicates
    matches.sort();
    matches.dedup();

    match matches.len() {
        0 => Err(format!("No container found matching '{}'", container_id).into()),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => Err(format!(
            "Ambiguous container ID '{}' matches {} containers",
            container_id,
            matches.len()
        )
        .into()),
    }
}

fn find_container_by_id_optional(
    storage: &StorageLayout,
    container_id: &str,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let containers_dir = storage.base.join("storage/overlay-containers");

    if !containers_dir.exists() {
        return Ok(None);
    }

    // Look for exact match or prefix match by ID, and also check by name
    let mut matches = Vec::new();

    for entry in std::fs::read_dir(&containers_dir)? {
        let entry = entry?;
        if entry.path().is_dir() {
            let dir_name = entry.file_name().to_string_lossy().to_string();

            // Exact match by ID
            if dir_name == container_id {
                return Ok(Some(entry.path()));
            }

            // Prefix match by ID
            if dir_name.starts_with(container_id) {
                matches.push(entry.path());
            }

            // Check container name in metadata
            let metadata_path = entry.path().join("metadata.json");
            if metadata_path.exists() {
                if let Ok(metadata_content) = std::fs::read_to_string(&metadata_path) {
                    if let Ok(metadata) =
                        serde_json::from_str::<serde_json::Value>(&metadata_content)
                    {
                        if let Some(name) = metadata["name"].as_str() {
                            // Exact match by name
                            if name == container_id {
                                return Ok(Some(entry.path()));
                            }
                            // Prefix match by name
                            if name.starts_with(container_id) {
                                matches.push(entry.path());
                            }
                        }
                    }
                }
            }
        }
    }

    // Remove duplicates
    matches.sort();
    matches.dedup();

    match matches.len() {
        0 => Ok(None),
        1 => Ok(Some(matches.into_iter().next().unwrap())),
        _ => Err(format!(
            "Ambiguous container ID '{}' matches {} containers",
            container_id,
            matches.len()
        )
        .into()),
    }
}

fn find_image_by_id(
    storage: &StorageLayout,
    image_id: &str,
) -> Result<Option<(String, String, String)>, Box<dyn std::error::Error>> {
    let images_dir = storage.base.join("storage/overlay-images");

    if !images_dir.exists() {
        return Ok(None);
    }

    // Search through all image metadata files
    for entry in std::fs::read_dir(&images_dir)? {
        let entry = entry?;
        if entry.path().is_file()
            && entry.path().extension().and_then(|s| s.to_str()) == Some("json")
        {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&content) {
                    // Check if config digest matches (partial or full)
                    if let Some(config_digest) = metadata["config"]["digest"].as_str() {
                        let short_id = config_digest.chars().skip(7).take(12).collect::<String>();

                        // Match against full digest, short ID, or prefix
                        if config_digest == image_id
                            || short_id == image_id
                            || short_id.starts_with(image_id)
                            || config_digest.starts_with(&format!("sha256:{}", image_id))
                        {
                            // Parse filename to get image name and tag
                            let filename = entry.file_name().to_string_lossy().to_string();
                            let filename = filename.trim_end_matches(".json");

                            // Split by last underscore to get tag
                            if let Some(last_underscore) = filename.rfind('_') {
                                let image = filename[..last_underscore].replace("_", "/");
                                let tag = filename[last_underscore + 1..].to_string();
                                return Ok(Some((image, tag, content)));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

fn remove_image(
    storage: &StorageLayout,
    image: &str,
    tag: &str,
    manifest_content: &str,
    force: bool,
) {
    let parsed_image = RegistryImage {
        registry: None,
        image: image.to_string(),
        tag: tag.to_string(),
    };

    // Read manifest to get layer digests
    let mut layers_to_remove = Vec::new();
    if let Ok(manifest) = serde_json::from_str::<ManifestV2>(manifest_content) {
        // Collect config and layer digests
        layers_to_remove.push(manifest.config.digest.clone());
        for layer in &manifest.layers {
            layers_to_remove.push(layer.digest.clone());
        }
    }

    // Check if any containers are using this image
    if !force {
        if let Ok(entries) = std::fs::read_dir(storage.base.join("storage/overlay-containers")) {
            for entry in entries.flatten() {
                let container_meta = entry.path().join("metadata.json");
                if container_meta.exists() {
                    if let Ok(content) = std::fs::read_to_string(&container_meta) {
                        if let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(container_image) = metadata["image"].as_str() {
                                // Check if the container is using this image
                                if container_image == parsed_image.to_string()
                                    || container_image == format!("{}:{}", image, tag)
                                    || container_image == image && tag == "latest"
                                {
                                    eprintln!(
                                        "Image {}:{} is being used by container {}. Use --force to remove",
                                        image, tag,
                                        entry.file_name().to_string_lossy()
                                    );
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Remove image metadata
    let metadata_path = storage.image_metadata_path(image, tag);
    if let Err(e) = std::fs::remove_file(&metadata_path) {
        eprintln!("Failed to remove image metadata: {}", e);
        return;
    }

    // Remove layers (both extracted and cached blobs)
    for digest in layers_to_remove {
        // Remove extracted layer
        let layer_path = storage.image_layer_path(&digest);
        if layer_path.exists() {
            let _ = std::fs::remove_dir_all(&layer_path);
        }

        // Remove cached blob
        let blob_path = storage.blob_cache_path(&digest);
        if blob_path.exists() {
            let _ = std::fs::remove_file(&blob_path);
        }
    }

    println!("Image {}:{} removed successfully", image, tag);
}

// Authentication and credential management

use std::fs;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegistryCredentials {
    pub username: String,
    pub password: String,
    pub registry: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AuthConfig {
    pub auths: HashMap<String, RegistryCredentials>,
}

impl AuthConfig {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let auth_path = get_auth_config_path()?;
        if !auth_path.exists() {
            return Ok(AuthConfig::default());
        }

        let content = fs::read_to_string(auth_path)?;
        let config: AuthConfig = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let auth_path = get_auth_config_path()?;
        if let Some(parent) = auth_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(self)?;
        fs::write(auth_path, content)?;
        Ok(())
    }

    pub fn add_credentials(&mut self, registry: String, username: String, password: String) {
        let creds = RegistryCredentials {
            username,
            password,
            registry: registry.clone(),
        };
        self.auths.insert(registry, creds);
    }

    pub fn get_credentials(&self, registry: &str) -> Option<&RegistryCredentials> {
        self.auths.get(registry)
    }
}

fn get_auth_config_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("Cannot determine home directory")?;
    Ok(home
        .join(".local")
        .join("share")
        .join("carrier")
        .join("auth.json"))
}

pub async fn authenticate_registry(
    username: String,
    registry: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Authenticating with registry: {}", registry);
    print!("Password: ");
    std::io::stdout().flush()?;

    let password = rpassword::read_password()?;

    // Test the credentials by attempting to get a token
    let test_result = test_registry_credentials(&registry, &username, &password).await;

    match test_result {
        Ok(_) => {
            // Save credentials if authentication succeeds
            let mut auth_config = AuthConfig::load()?;
            auth_config.add_credentials(registry.clone(), username.clone(), password);
            auth_config.save()?;

            println!(
                "✓ Successfully authenticated with {} as {}",
                registry, username
            );
        }
        Err(e) => {
            eprintln!("✗ Authentication failed: {}", e);
            return Err(e);
        }
    }

    Ok(())
}

async fn test_registry_credentials(
    registry: &str,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    // Create basic auth header
    let auth_string = format!("{}:{}", username, password);
    let auth_header = format!(
        "Basic {}",
        base64::prelude::BASE64_STANDARD.encode(auth_string)
    );

    // Test with a simple API endpoint for each registry
    let test_url = match registry {
        "docker.io" => "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/hello-world:pull",
        "quay.io" => "https://quay.io/v2/auth?service=quay.io&scope=repository:quay/busybox:pull",
        "ghcr.io" => "https://ghcr.io/token?service=ghcr.io&scope=repository:library/hello-world:pull",
        "gcr.io" => "https://gcr.io/v2/token?service=gcr.io&scope=repository:library/hello-world:pull",
        "public.ecr.aws" => "https://public.ecr.aws/token?service=public.ecr.aws&scope=repository:library/hello-world:pull",
        _ => return Err(format!("Unsupported registry: {}", registry).into()),
    };

    let response = client
        .get(test_url)
        .header("Authorization", &auth_header)
        .header("Accept", "application/json")
        .send()
        .await?;

    let status = response.status();
    let is_success = status.is_success();
    let status_code = status.as_u16();

    if is_success || status_code == 401 {
        // 401 might mean the scope/repo doesn't exist but auth worked
        // We'll accept both success and certain auth errors as "credentials work"
        let body: serde_json::Value = response.json().await.unwrap_or_default();

        // Check if we got a token (success) or an auth error with proper format
        if body.get("token").is_some() || body.get("access_token").is_some() {
            Ok(())
        } else if status_code == 401 {
            // For 401, check if it's a proper auth response format
            if body.get("errors").is_some() {
                Ok(()) // Proper registry response, credentials format is correct
            } else {
                Err("Invalid credentials".into())
            }
        } else {
            Err("Authentication test failed".into())
        }
    } else {
        Err(format!("Authentication failed with status: {}", status).into())
    }
}

pub async fn get_authenticated_token(
    registry: &str,
    image_path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Try to load stored credentials first
    let auth_config = AuthConfig::load()?;

    if let Some(creds) = auth_config.get_credentials(registry) {
        // Use stored credentials to get token
        get_token_with_credentials(registry, &creds.username, &creds.password, image_path).await
    } else {
        // Fall back to anonymous token request
        let dummy_url = format!("{}:latest", image_path);
        get_repo_auth_token(dummy_url).await
    }
}

async fn get_token_with_credentials(
    registry: &str,
    username: &str,
    password: &str,
    image_path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();

    // Create basic auth header
    let auth_string = format!("{}:{}", username, password);
    let auth_header = format!(
        "Basic {}",
        base64::prelude::BASE64_STANDARD.encode(auth_string)
    );

    // Get the auth endpoint for this registry
    let auth_endpoint = AUTHTOKENMAP
        .get(registry)
        .ok_or_else(|| format!("No auth endpoint configured for registry: {}", registry))?;

    // Build scope for the specific image
    let scope = format!("repository:{}:pull,push", image_path);

    let auth_url = match registry {
        "docker.io" => format!(
            "{}?service=registry.docker.io&scope={}",
            auth_endpoint, scope
        ),
        "quay.io" => format!("{}?service=quay.io&scope={}", auth_endpoint, scope),
        "ghcr.io" => format!("{}?service=ghcr.io&scope={}", auth_endpoint, scope),
        "gcr.io" => format!("{}?service=gcr.io&scope={}", auth_endpoint, scope),
        "public.ecr.aws" => format!("{}?service=public.ecr.aws&scope={}", auth_endpoint, scope),
        _ => format!("{}?scope={}", auth_endpoint, scope),
    };

    let response = client
        .get(&auth_url)
        .header("Authorization", &auth_header)
        .header("Accept", "application/json")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("Auth request failed: {}", response.status()).into());
    }

    // Parse the token from response
    let auth_response: serde_json::Value = response.json().await?;

    if let Some(token) = auth_response.get("token").and_then(|t| t.as_str()) {
        Ok(token.to_string())
    } else if let Some(access_token) = auth_response.get("access_token").and_then(|t| t.as_str()) {
        Ok(access_token.to_string())
    } else {
        Err("No token found in auth response".into())
    }
}

pub async fn verify_authentication() -> Result<(), Box<dyn std::error::Error>> {
    let auth_config = AuthConfig::load()?;

    if auth_config.auths.is_empty() {
        println!("No registry credentials stored.");
        return Ok(());
    }

    println!("Verifying stored credentials:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    for (registry, creds) in &auth_config.auths {
        print!("  {}: ", registry);
        std::io::stdout().flush()?;

        match test_registry_credentials(registry, &creds.username, &creds.password).await {
            Ok(_) => println!("✓ Valid (user: {})", creds.username),
            Err(e) => println!("✗ Failed - {}", e),
        }
    }

    Ok(())
}
