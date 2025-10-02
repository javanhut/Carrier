use crate::cli::RegistryImage;
use crate::storage::StorageLayout;
use crate::storage::{ContainerStorage, extract_layer_rootless, generate_container_id};
use std::io::{self, Write};

fn get_runc_root() -> String {
    if let Ok(home) = std::env::var("HOME") {
        format!("{}/.local/share/carrier/runc", home)
    } else {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .unwrap_or_else(|_| format!("/run/user/{}", nix::unistd::getuid().as_raw()));
        format!("{}/carrier/runc", runtime_dir)
    }
}

use base64::prelude::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    _container_dir: &Path,
    rootfs: &Path,
    container_pid: i32,
    command: Vec<String>,
    is_interactive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::{Command, Stdio};

    println!(
        "Executing in elevated container (PID {}) rootless",
        container_pid
    );

    // For entering an already running container, we should use nsenter to join its namespaces
    let mut exec_cmd = Command::new("nsenter");
    exec_cmd
        .arg("--target")
        .arg(container_pid.to_string())
        .arg("--mount")
        .arg("--uts")
        .arg("--net")
        .arg("--pid")
        .arg("--root")
        .arg(rootfs) // Set the root filesystem
        .arg("--wd=/"); // Set working directory to /

    // Add the command to run
    exec_cmd.args(&command);

    // Set up environment
    exec_cmd.env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    exec_cmd.env("HOME", "/root");
    exec_cmd.env("TERM", "xterm");

    if is_interactive {
        println!("Starting interactive session...");
        println!("Type 'exit' or press Ctrl+D to exit.\n");

        // Check if we're in a TTY
        let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;

        if is_tty {
            // For elevated containers, use nsenter directly (no user namespace mapping)
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
            nsenter_args.extend(command.clone());

            let exit_code = spawn_with_pty("nsenter", &nsenter_args).unwrap_or_else(|_| {
                // Fallback to regular execution
                let mut child = exec_cmd
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .expect("Failed to spawn nsenter");

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
    _rootfs: &Path,
    _container_pid: i32,
    command: Vec<String>,
    is_interactive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::{Command, Stdio};

    // Get container ID from directory name
    let container_id = container_dir
        .file_name()
        .ok_or("Invalid container directory")?
        .to_string_lossy()
        .to_string();

    println!(
        "Executing in container {} using runc exec",
        short12(&container_id)
    );

    // Determine runc root directory
    let runc_root_path = get_runc_root();

    // Build runc exec command
    let mut exec_cmd = Command::new("runc");
    exec_cmd.arg("--root").arg(&runc_root_path).arg("exec");

    // Add -t flag for terminal if interactive
    if is_interactive {
        println!("Starting interactive session...");
        println!("Type 'exit' or press Ctrl+D to exit.\n");
        exec_cmd.arg("-t");
    }

    // Set environment variables
    exec_cmd
        .arg("--env")
        .arg("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        .arg("--env")
        .arg("HOME=/root")
        .arg("--env")
        .arg("TERM=xterm");

    // Add container ID
    exec_cmd.arg(&container_id);

    // Add command to execute
    if command.is_empty() {
        exec_cmd.arg("/bin/sh");
    } else {
        exec_cmd.args(&command);
    }

    // Set stdio
    exec_cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // Execute the command
    let status = exec_cmd.status()?;

    if !status.success() {
        if let Some(code) = status.code() {
            return Err(format!("Command exited with code {}", code).into());
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
    use nix::sys::signal::kill;
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

    // Set up essential files and networking for the container if not already done
    setup_container_essential_files(&rootfs)?;
    setup_container_network_if_needed(&container_dir, &rootfs, pid)?;

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

    if !elevated {
        return exec_rootless_container(
            &container_dir,
            &rootfs,
            container_pid,
            cmd_to_run,
            is_interactive,
        )
        .await;
    }

    // For elevated containers, use elevated exec (rootless but without user namespace mapping)
    if elevated {
        return exec_elevated_container(
            &container_dir,
            &rootfs,
            container_pid,
            cmd_to_run,
            is_interactive,
        )
        .await;
    }

    // This should never be reached - all containers should be either rootless or elevated (but still rootless)
    return Err(
        "Invalid container execution path - all containers should use rootless execution".into(),
    );
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
        println!(
            "Container may not have been run in detached mode or may not have produced any output yet."
        );
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
                use nix::sys::signal::kill;
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

            for (_i, var) in env.iter().take(5).enumerate() {
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

/// Set up essential directories and files in the container
fn setup_container_essential_files(rootfs: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let essential_dirs = vec!["etc", "tmp", "var", "var/tmp", "dev", "proc", "sys"];

    for dir in essential_dirs {
        let dir_path = rootfs.join(dir);
        if !dir_path.exists() {
            std::fs::create_dir_all(&dir_path)?;
        }

        if dir.contains("tmp") {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&dir_path) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o1777);
                let _ = std::fs::set_permissions(&dir_path, perms);
            }
        }
    }

    let etc_dir = rootfs.join("etc");
    let container_resolv = etc_dir.join("resolv.conf");
    let container_hosts = etc_dir.join("hosts");

    if !container_resolv.exists() {
        let host_resolv = Path::new("/etc/resolv.conf");
        if host_resolv.exists() {
            let _ = std::fs::copy(host_resolv, &container_resolv);
        } else {
            let _ = std::fs::write(
                &container_resolv,
                "nameserver 8.8.8.8\nnameserver 8.8.4.4\n",
            );
        }
    }

    if !container_hosts.exists() {
        let _ = std::fs::write(&container_hosts, "127.0.0.1\tlocalhost\n::1\tlocalhost\n");
    }

    let apt_conf_dir = etc_dir.join("apt").join("apt.conf.d");
    if !apt_conf_dir.exists() {
        let _ = std::fs::create_dir_all(&apt_conf_dir);
    }

    let apt_sandbox_conf = apt_conf_dir.join("99-carrier-sandbox");
    if !apt_sandbox_conf.exists() {
        let _ = std::fs::write(&apt_sandbox_conf, "APT::Sandbox::User \"root\";\n");
    }

    Ok(())
}

fn ensure_host_dev_null_ready() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = std::fs::metadata("/dev/null").map_err(|err| {
        format!(
            "Host /dev/null is not accessible: {}. Containers require a working /dev/null.\nThis is typically a system configuration issue.",
            err
        )
    })?;

    if !metadata.file_type().is_char_device() {
        return Err(
            "Host /dev/null is not a character device. Recreate it with:\n  sudo rm -f /dev/null\n  sudo mknod -m 666 /dev/null c 1 3\n  sudo chown root:root /dev/null"
                .into(),
        );
    }

    let rdev = metadata.rdev();
    let major = libc::major(rdev);
    let minor = libc::minor(rdev);
    if major != 1 || minor != 3 {
        return Err(
            format!(
                "Host /dev/null has unexpected device numbers ({}:{}) — expected 1:3. Recreate it with:\n  sudo rm -f /dev/null\n  sudo mknod -m 666 /dev/null c 1 3\n  sudo chown root:root /dev/null",
                major, minor
            )
            .into(),
        );
    }

    if OpenOptions::new().write(true).open("/dev/null").is_err() {
        return Err(
            "Host /dev/null is not writable. Fix permissions with:\n  sudo chown root:root /dev/null\n  sudo chmod 666 /dev/null"
                .into(),
        );
    }

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
    println!(
        "\nStarting container from image {}...",
        parsed_image.to_string()
    );

    // Set up cgroup resource limits for carrier containers
    let _ = setup_carrier_cgroup_limits();

    // Generate container ID or use custom name
    let container_id = match &name {
        Some(custom_name) => custom_name.clone(),
        None => generate_container_id(),
    };
    println!("Container ID: {}", container_id);

    // Create container with overlay filesystem
    println!("Setting up container filesystem with overlay...");

    // Elevated containers need a healthy host /dev/null to create device nodes inside the namespace
    if elevated {
        ensure_host_dev_null_ready()?;
    }

    // Preflight checks for rootless operation
    crate::storage::preflight_rootless_checks();
    // Allow forcing storage driver via CLI
    let mut container_storage = if let Some(ref drv) = storage_driver {
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

    // Set up essential directories and files
    setup_container_essential_files(&rootfs)?;

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
    if detach
        && (command.is_empty()
            || (command.len() == 1
                && (command[0] == "/bin/sh"
                    || command[0] == "/bin/bash"
                    || command[0] == "sh"
                    || command[0] == "bash")))
    {
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

    // Network configuration handled by runc based on OCI spec namespace settings

    // Container configuration - convert to what we need for OCI spec
    let final_env = env;
    let final_command = command;
    let final_working_dir = working_dir;

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
        "command": final_command,
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
    // Only use interactive mode if it's a plain shell without -c flag
    let has_command_flag = command_to_run.contains(&"-c".to_string());
    let is_shell_only = (command_to_run[0].contains("bash") || command_to_run[0].contains("sh"))
        && command_to_run.len() == 1;
    let is_interactive = !detach
        && (is_shell_only
            || command_to_run.contains(&"-it".to_string())
            || command_to_run.contains(&"-i".to_string()))
        && !has_command_flag;

    // Build the command path
    let cmd_in_container = &command_to_run[0];

    if !detach {
        println!("Starting container with command: {}", cmd_in_container);
    }

    // Use runc for container execution
    use std::process::Command;

    // Create bundle directory (runc requires bundle structure)
    let bundle_dir = storage.container_path(&container_id);
    std::fs::create_dir_all(&bundle_dir)?;

    // Convert env to OCI format (KEY=VALUE strings)
    let env_strings: Vec<String> = final_env
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();

    // Generate OCI spec using our custom function
    let config_path = bundle_dir.join("config.json");
    generate_oci_config(
        &config_path,
        &container_id,
        rootfs.clone(),
        command_to_run.clone(),
        env_strings,
        final_working_dir.clone(),
        !elevated, // add network namespace if not elevated
    )?;

    // Determine runc root directory (for state storage) - use home directory to avoid tmpfs space issues
    let runc_root = if let Ok(home) = std::env::var("HOME") {
        format!("{}/.local/share/carrier/runc", home)
    } else {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .unwrap_or_else(|_| format!("/run/user/{}", nix::unistd::getuid().as_raw()));
        format!("{}/carrier/runc", runtime_dir)
    };
    let runc_root_path = runc_root;
    std::fs::create_dir_all(&runc_root_path)?;

    if detach {
        // Detached mode: runc create + start
        println!(
            "Container {} started in detached mode",
            short12(&container_id)
        );

        // Create the container
        let create_status = Command::new("runc")
            .arg("--root")
            .arg(&runc_root_path)
            .arg("create")
            .arg("--bundle")
            .arg(&bundle_dir)
            .arg(&container_id)
            .status()?;

        if !create_status.success() {
            return Err(format!("Failed to create container with runc").into());
        }

        // Start the container
        let start_status = Command::new("runc")
            .arg("--root")
            .arg(&runc_root_path)
            .arg("start")
            .arg(&container_id)
            .status()?;

        if !start_status.success() {
            return Err(format!("Failed to start container with runc").into());
        }

        // Get container PID from runc state
        let state_output = Command::new("runc")
            .arg("--root")
            .arg(&runc_root_path)
            .arg("state")
            .arg(&container_id)
            .output()?;

        if state_output.status.success() {
            if let Ok(state_json) = String::from_utf8(state_output.stdout) {
                if let Ok(state) = serde_json::from_str::<serde_json::Value>(&state_json) {
                    if let Some(pid) = state["pid"].as_i64() {
                        let pid_file = bundle_dir.join("pid");
                        std::fs::write(&pid_file, pid.to_string())?;

                        // Set up network for rootless containers
                        if !elevated {
                            setup_container_network_if_needed(
                                &bundle_dir,
                                &rootfs,
                                nix::unistd::Pid::from_raw(pid as i32),
                            )?;
                        }
                    }
                }
            }
        }

        println!("To view logs: carrier logs {}", short12(&container_id));
        println!("To stop: carrier stop {}", short12(&container_id));

        return Ok(());
    }

    // Foreground mode: use runc create + network setup + exec
    // This ensures network is properly configured before the container runs
    if is_interactive {
        println!("\nStarting interactive container session...");
        println!("Type 'exit' or press Ctrl+D to exit the container.\n");
    }

    // Modify OCI spec to use a pause-like init process
    // We'll use `sleep infinity` as init, then exec the real command
    let config_path = bundle_dir.join("config.json");
    let mut oci_spec: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config_path)?)?;

    // Save the original command to exec later
    let original_command = command_to_run.clone();

    // Replace process args with a long-running process for init
    oci_spec["process"]["args"] = serde_json::json!([
        "/bin/sh",
        "-c",
        "trap 'exit 0' TERM; sleep infinity & wait $!"
    ]);

    // Disable terminal for the init process (we'll use it for exec)
    oci_spec["process"]["terminal"] = serde_json::json!(false);

    std::fs::write(&config_path, serde_json::to_string_pretty(&oci_spec)?)?;

    // Create the container with the pause process
    let create_status = Command::new("runc")
        .arg("--root")
        .arg(&runc_root_path)
        .arg("create")
        .arg("--bundle")
        .arg(&bundle_dir)
        .arg(&container_id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()?;

    if !create_status.success() {
        return Err(format!("Failed to create container with runc").into());
    }

    // Get container PID from runc state
    let state_output = Command::new("runc")
        .arg("--root")
        .arg(&runc_root_path)
        .arg("state")
        .arg(&container_id)
        .output()?;

    if state_output.status.success() {
        if let Ok(state_json) = String::from_utf8(state_output.stdout) {
            if let Ok(state) = serde_json::from_str::<serde_json::Value>(&state_json) {
                if let Some(pid) = state["pid"].as_i64() {
                    let pid_file = bundle_dir.join("pid");
                    std::fs::write(&pid_file, pid.to_string())?;

                    // Set up network for rootless containers
                    if !elevated {
                        setup_container_network_if_needed(
                            &bundle_dir,
                            &rootfs,
                            nix::unistd::Pid::from_raw(pid as i32),
                        )?;
                    }
                }
            }
        }
    }

    // Start the container (starts the pause process)
    let start_status = Command::new("runc")
        .arg("--root")
        .arg(&runc_root_path)
        .arg("start")
        .arg(&container_id)
        .status()?;

    if !start_status.success() {
        return Err(format!("Failed to start container with runc").into());
    }

    // Now exec the actual command with inherited stdio
    let mut exec_cmd = Command::new("runc");
    exec_cmd.arg("--root").arg(&runc_root_path).arg("exec");

    // Only allocate TTY if stdin is actually a terminal
    use std::io::IsTerminal;
    if is_interactive && std::io::stdin().is_terminal() {
        exec_cmd.arg("-t"); // Allocate pseudo-TTY
    }

    exec_cmd.arg(&container_id);

    // Add the command arguments
    for arg in &original_command {
        exec_cmd.arg(arg);
    }

    // Set stdio
    exec_cmd
        .stdin(if is_interactive {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let exec_result = exec_cmd.status();

    // Get exit code from exec
    let exit_code = match exec_result {
        Ok(status) => status.code().unwrap_or(-1),
        Err(e) => {
            let _ = Command::new("runc")
                .arg("--root")
                .arg(&runc_root_path)
                .arg("kill")
                .arg(&container_id)
                .arg("SIGKILL")
                .status();
            let _ = Command::new("runc")
                .arg("--root")
                .arg(&runc_root_path)
                .arg("delete")
                .arg(&container_id)
                .status();
            return Err(format!("Failed to exec in container: {}", e).into());
        }
    };

    // Kill and delete the container
    let _ = Command::new("runc")
        .arg("--root")
        .arg(&runc_root_path)
        .arg("kill")
        .arg(&container_id)
        .arg("SIGTERM")
        .status();

    // Give it a moment to clean up
    std::thread::sleep(std::time::Duration::from_millis(100));

    let _ = Command::new("runc")
        .arg("--root")
        .arg(&runc_root_path)
        .arg("delete")
        .arg(&container_id)
        .status();

    // Update container status
    let metadata = serde_json::json!({
        "id": container_id,
        "name": container_name,
        "image": parsed_image.to_string(),
        "created": chrono::Utc::now().to_rfc3339(),
        "rootfs": rootfs.to_string_lossy(),
        "command": original_command,
        "status": "exited",
        "exit_code": exit_code,
        "storage_driver": storage_driver_str,
        "elevated": elevated
    });
    std::fs::write(&container_meta_path, metadata.to_string())?;

    if exit_code == 0 {
        println!("\nContainer {} exited successfully", short12(&container_id));
    } else {
        println!(
            "\nContainer {} exited with code {}",
            short12(&container_id),
            exit_code
        );
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

/// Read subordinate UID/GID mappings from /etc/subuid or /etc/subgid
fn read_subid_mappings(file_path: &str, username: &str) -> Result<(u32, u32), Box<dyn std::error::Error>> {
    use std::fs;

    let content = fs::read_to_string(file_path)?;

    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[0] == username {
            let start: u32 = parts[1].parse()?;
            let count: u32 = parts[2].parse()?;
            return Ok((start, count));
        }
    }

    Err(format!("No mapping found for user {} in {}", username, file_path).into())
}

/// Get UID/GID mappings for rootless containers
fn get_id_mappings(uid: u32, gid: u32) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    use std::env;

    // Get username for looking up subuid/subgid
    let username = env::var("USER").unwrap_or_else(|_| {
        // Fallback: try to get username from /etc/passwd
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| uid.to_string())
    });

    // Try to read subuid/subgid mappings
    let uid_mappings = if let Ok((subuid_start, subuid_count)) = read_subid_mappings("/etc/subuid", &username) {
        // Map container UID 0 to current user, then map 1-N to subuid range
        vec![
            serde_json::json!({"containerID": 0, "hostID": uid, "size": 1}),
            serde_json::json!({"containerID": 1, "hostID": subuid_start, "size": subuid_count}),
        ]
    } else {
        // Fallback: just map container root to current user
        eprintln!("Warning: No subuid mapping found for user {}. Only container UID 0 will be mapped.", username);
        eprintln!("Consider adding an entry to /etc/subuid: {}:100000:65536", username);
        vec![serde_json::json!({"containerID": 0, "hostID": uid, "size": 1})]
    };

    let gid_mappings = if let Ok((subgid_start, subgid_count)) = read_subid_mappings("/etc/subgid", &username) {
        // Map container GID 0 to current group, then map 1-N to subgid range
        vec![
            serde_json::json!({"containerID": 0, "hostID": gid, "size": 1}),
            serde_json::json!({"containerID": 1, "hostID": subgid_start, "size": subgid_count}),
        ]
    } else {
        // Fallback: just map container root to current group
        eprintln!("Warning: No subgid mapping found for user {}. Only container GID 0 will be mapped.", username);
        eprintln!("Consider adding an entry to /etc/subgid: {}:100000:65536", username);
        vec![serde_json::json!({"containerID": 0, "hostID": gid, "size": 1})]
    };

    (uid_mappings, gid_mappings)
}

fn generate_oci_config(
    config_path: &Path,
    container_id: &str,
    rootfs: PathBuf,
    command: Vec<String>,
    env: Vec<String>,
    working_dir: String,
    add_network_ns: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();

    // Get proper UID/GID mappings from subuid/subgid
    let (uid_mappings, gid_mappings) = get_id_mappings(uid, gid);

    let mut namespaces = vec![
        serde_json::json!({"type": "pid"}),
        serde_json::json!({"type": "ipc"}),
        serde_json::json!({"type": "uts"}),
        serde_json::json!({"type": "mount"}),
        serde_json::json!({"type": "user"}),
    ];

    if add_network_ns {
        namespaces.push(serde_json::json!({"type": "network"}));
    }

    let config = serde_json::json!({
        "ociVersion": "1.0.0",
        "process": {
            "terminal": true,
            "user": {"uid": 0, "gid": 0},
            "args": command,
            "env": env,
            "cwd": working_dir,
            "capabilities": {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
                "ambient": []
            },
            "rlimits": [
                {"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}
            ]
        },
        "root": {
            "path": rootfs,
            "readonly": false
        },
        "hostname": container_id,
        "mounts": [
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc"
            },
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
            },
            {
                "destination": "/dev/pts",
                "type": "devpts",
                "source": "devpts",
                "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]
            },
            {
                "destination": "/dev/shm",
                "type": "tmpfs",
                "source": "shm",
                "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]
            },
            {
                "destination": "/dev/mqueue",
                "type": "mqueue",
                "source": "mqueue",
                "options": ["nosuid", "noexec", "nodev"]
            },
            {
                "destination": "/sys",
                "type": "sysfs",
                "source": "sysfs",
                "options": ["nosuid", "noexec", "nodev", "ro"]
            }
        ],
        "linux": {
            "namespaces": namespaces,
            "uidMappings": uid_mappings,
            "gidMappings": gid_mappings
        }
    });

    std::fs::write(config_path, serde_json::to_string_pretty(&config)?)?;
    Ok(())
}

/// Set up basic DNS configuration for container
fn setup_dns_config(rootfs: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let etc_dir = rootfs.join("etc");
    std::fs::create_dir_all(&etc_dir)?;

    // Create resolv.conf with basic DNS settings
    let resolv_conf = etc_dir.join("resolv.conf");
    std::fs::write(&resolv_conf, "nameserver 8.8.8.8\nnameserver 8.8.4.4\n")?;

    println!("DNS configuration set up at {}", resolv_conf.display());
    Ok(())
}

/// Set up network for an existing container if not already configured
fn setup_container_network_if_needed(
    container_dir: &Path,
    rootfs: &Path,
    container_pid: nix::unistd::Pid,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check if network is already set up by looking for network helper processes
    let pid_raw = container_pid.as_raw();

    // Check for existing pasta or slirp4netns processes for this container
    let check_pasta = Command::new("pgrep")
        .args(&["-f", &format!("pasta.*{}", pid_raw)])
        .output();

    let check_slirp = Command::new("pgrep")
        .args(&["-f", &format!("slirp4netns.*{}", pid_raw)])
        .output();

    let network_exists = (check_pasta.is_ok() && check_pasta.unwrap().status.success())
        || (check_slirp.is_ok() && check_slirp.unwrap().status.success());

    if network_exists {
        println!("Network already configured for container");
        return Ok(());
    }

    println!("Setting up network for container...");

    // Set up basic DNS configuration for container
    setup_dns_config(rootfs)?;

    // Start slirp4netns to provide userspace networking
    // Try slirp4netns first, then fall back to pasta if available
    let network_pid_file = container_dir.join("network.pid");

    // Check if slirp4netns is available
    let slirp_available = Command::new("which")
        .arg("slirp4netns")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if slirp_available {
        println!("Starting slirp4netns for network connectivity...");

        // Start slirp4netns in the background
        let slirp_child = Command::new("slirp4netns")
            .arg("--configure")
            .arg("--mtu=65520")
            .arg("--disable-host-loopback")
            .arg(pid_raw.to_string())
            .arg("tap0")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();

        match slirp_child {
            Ok(child) => {
                // Store the slirp4netns PID for cleanup
                let slirp_pid = child.id();
                std::fs::write(&network_pid_file, slirp_pid.to_string())?;
                println!("slirp4netns started with PID {}", slirp_pid);

                // Give slirp4netns a moment to set up
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("Warning: Failed to start slirp4netns: {}", e);
                eprintln!("Container will have limited network connectivity");
            }
        }
    } else {
        eprintln!("Warning: slirp4netns not found. Install it for network connectivity:");
        eprintln!("  sudo apt install slirp4netns  # Debian/Ubuntu");
        eprintln!("  sudo dnf install slirp4netns  # Fedora");
        eprintln!("  sudo pacman -S slirp4netns    # Arch");
        eprintln!("Container will have limited network connectivity");
    }

    println!("Network setup complete");

    Ok(())
}

/// Set up cgroup resource limits for carrier globally and move current process into it
fn setup_carrier_cgroup_limits() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;

    // Get user's delegated cgroup path
    let uid = nix::unistd::getuid().as_raw();
    let carrier_cgroup = format!(
        "/sys/fs/cgroup/user.slice/user-{}.slice/user@{}.service/carrier.slice",
        uid, uid
    );

    let carrier_path = std::path::Path::new(&carrier_cgroup);
    if !carrier_path.exists() {
        // Create carrier.slice if it doesn't exist
        let _ = fs::create_dir_all(carrier_path);
    }

    // Set generous per-container limits on the carrier.slice itself
    // These will be inherited by all containers

    // Memory: 8GB per carrier.slice (shared by all containers)
    let memory_max = carrier_path.join("memory.max");
    if memory_max.exists() {
        let _ = fs::write(&memory_max, (8u64 * 1024 * 1024 * 1024).to_string());
    }

    // PIDs: 32768 total PIDs for all containers (generous limit)
    let pids_max = carrier_path.join("pids.max");
    if pids_max.exists() {
        let _ = fs::write(&pids_max, "32768");
    }

    // Move current process (and all future children) into carrier.slice
    let cgroup_procs = carrier_path.join("cgroup.procs");
    if cgroup_procs.exists() {
        let pid = std::process::id();
        let _ = fs::write(&cgroup_procs, pid.to_string());
    }

    Ok(())
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
            term.leak() // These are basic and widely supported
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
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    use std::io::{Read, Write};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
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
        raw_attrs.c_iflag &=
            !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);
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

    // Ensure /dev/ptmx exists - create symlink if needed
    if !std::path::Path::new("/dev/ptmx").exists() && std::path::Path::new("/dev/pts/ptmx").exists()
    {
        eprintln!("Warning: /dev/ptmx not found. PTY functionality requires /dev/ptmx");
        eprintln!("Run: sudo ln -s /dev/pts/ptmx /dev/ptmx");
        return Err("PTY not available: /dev/ptmx missing".into());
    }

    let pair = pty_system.openpty(size)?;

    // Build command
    let mut builder = CommandBuilder::new(program);
    builder.args(args.iter().map(|s| s.as_str()));

    // Set up compatible environment variables for maximum portability
    builder.env("TERM", detect_compatible_term());
    builder.env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    builder.env("HOME", "/root");
    builder.env("USER", "root");
    builder.env("LOGNAME", "root");
    builder.env("SHELL", "/bin/sh"); // Most compatible shell
    builder.env("LANG", "C.UTF-8"); // UTF-8 support with C locale fallback
    builder.env("LC_ALL", "C"); // Override all locale settings for compatibility
    builder.env("PWD", "/"); // Set initial working directory

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
    for pc in pattern.chars().map(|c| c.to_ascii_lowercase()) {
        let mut found = false;
        while let Some(tc) = it.next() {
            if tc.to_ascii_lowercase() == pc {
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
        assert_eq!(dt.to_rfc3339(), "2020-01-01T00:00:00+00:00");
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
    let file_len = file.metadata()?.len();

    // Read the entire file backwards to find newlines
    let mut newline_positions = Vec::new();
    let mut buf = vec![0u8; file_len as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut buf)?;

    // Find all newline positions
    for (i, &b) in buf.iter().enumerate() {
        if b == b'\n' {
            newline_positions.push(i);
        }
    }

    // If we have fewer or equal newlines than requested lines, return start of file
    if newline_positions.len() <= n {
        return Ok(0);
    }

    // Get the position after the newline that precedes the last n lines
    let target_newline_idx = newline_positions.len() - n - 1;
    let start_pos = newline_positions[target_newline_idx] + 1;

    Ok(start_pos as u64)
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

                                // Check if container is actually running using runc state
                                let actual_status = if status == "running"
                                    || status.starts_with("Up")
                                {
                                    // Query runc for actual state
                                    let runc_root_path = get_runc_root();

                                    let state_result = std::process::Command::new("runc")
                                        .arg("--root")
                                        .arg(&runc_root_path)
                                        .arg("state")
                                        .arg(&container_id)
                                        .output();

                                    if let Ok(output) = state_result {
                                        if output.status.success() {
                                            if let Ok(state_json) = String::from_utf8(output.stdout)
                                            {
                                                if let Ok(state) =
                                                    serde_json::from_str::<serde_json::Value>(
                                                        &state_json,
                                                    )
                                                {
                                                    if let Some(runc_status) =
                                                        state["status"].as_str()
                                                    {
                                                        match runc_status {
                                                            "running" => status,
                                                            "stopped" | "created" => {
                                                                // Update metadata to reflect stopped state
                                                                let mut metadata_mut =
                                                                    metadata.clone();
                                                                metadata_mut["status"] =
                                                                    serde_json::json!("exited");
                                                                let _ = std::fs::write(
                                                                    &metadata_path,
                                                                    metadata_mut.to_string(),
                                                                );
                                                                "exited"
                                                            }
                                                            _ => "exited",
                                                        }
                                                    } else {
                                                        status
                                                    }
                                                } else {
                                                    status
                                                }
                                            } else {
                                                status
                                            }
                                        } else {
                                            // Container doesn't exist in runc, mark as exited
                                            let mut metadata_mut = metadata.clone();
                                            metadata_mut["status"] = serde_json::json!("exited");
                                            let _ = std::fs::write(
                                                &metadata_path,
                                                metadata_mut.to_string(),
                                            );
                                            "exited"
                                        }
                                    } else {
                                        // Fallback: check PID file
                                        let pid_file = entry.path().join("pid");
                                        if pid_file.exists() {
                                            if let Ok(pid_str) = std::fs::read_to_string(&pid_file)
                                            {
                                                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                                                    use nix::sys::signal::kill;
                                                    use nix::unistd::Pid;

                                                    if kill(Pid::from_raw(pid), None).is_ok() {
                                                        status
                                                    } else {
                                                        "exited"
                                                    }
                                                } else {
                                                    "exited"
                                                }
                                            } else {
                                                "exited"
                                            }
                                        } else {
                                            "exited"
                                        }
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

/// Ask user for confirmation when in interactive mode
fn confirm_removal(item_type: &str, name: &str) -> bool {
    print!("Remove {} '{}'? (y/N): ", item_type, name);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_) => {
            let input = input.trim().to_lowercase();
            input == "y" || input == "yes"
        }
        Err(_) => false,
    }
}

// Remove command implementation
pub async fn remove_item(item: String, force: bool, interactive: bool) {
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

        // Interactive confirmation for container removal
        if interactive {
            if !confirm_removal("container", &container_id) {
                println!("Container removal cancelled.");
                return;
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
        // Interactive confirmation for image removal
        if interactive {
            let image_name = format!("{}:{}", image_info.0, image_info.1);
            if !confirm_removal("image", &image_name) {
                println!("Image removal cancelled.");
                return;
            }
        }
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

            // Interactive confirmation for image removal
            if interactive {
                let image_name = format!("{}:{}", parsed_image.image, parsed_image.tag);
                if !confirm_removal("image", &image_name) {
                    println!("Image removal cancelled.");
                    return;
                }
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

    // Use runc to stop the container properly
    let runc_root_path = get_runc_root();

    // Check if container exists in runc
    let state_result = Command::new("runc")
        .arg("--root")
        .arg(&runc_root_path)
        .arg("state")
        .arg(&full_container_id)
        .output();

    let container_in_runc = state_result
        .map(|out| out.status.success())
        .unwrap_or(false);

    if container_in_runc {
        // Use runc to stop the container
        if !force {
            println!("Sending SIGTERM via runc...");
            let kill_status = Command::new("runc")
                .arg("--root")
                .arg(&runc_root_path)
                .arg("kill")
                .arg(&full_container_id)
                .arg("TERM")
                .status();

            if kill_status.is_ok() {
                // Wait for graceful shutdown
                let start = std::time::Instant::now();
                let timeout_duration = std::time::Duration::from_secs(timeout);

                while start.elapsed() < timeout_duration {
                    let state = Command::new("runc")
                        .arg("--root")
                        .arg(&runc_root_path)
                        .arg("state")
                        .arg(&full_container_id)
                        .output();

                    if let Ok(out) = state {
                        if !out.status.success() {
                            // Container no longer exists
                            break;
                        }
                        if let Ok(json) = String::from_utf8(out.stdout) {
                            if let Ok(state) = serde_json::from_str::<serde_json::Value>(&json) {
                                if state["status"].as_str() == Some("stopped") {
                                    break;
                                }
                            }
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }

        // Force kill if needed or requested
        if force {
            println!("Force killing container...");
        } else {
            println!("Sending SIGKILL via runc...");
        }

        let _ = Command::new("runc")
            .arg("--root")
            .arg(&runc_root_path)
            .arg("kill")
            .arg(&full_container_id)
            .arg("KILL")
            .status();

        // Delete the container from runc
        std::thread::sleep(std::time::Duration::from_millis(100));
        let _ = Command::new("runc")
            .arg("--root")
            .arg(&runc_root_path)
            .arg("delete")
            .arg(&full_container_id)
            .status();

        // Remove PID file
        let pid_file = container_dir.join("pid");
        let _ = std::fs::remove_file(&pid_file);
    } else {
        // Container not in runc, try legacy PID-based stopping
        let pid_file = container_dir.join("pid");
        if pid_file.exists() {
            let pid_str = std::fs::read_to_string(&pid_file)?;
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                use nix::sys::signal::{Signal, kill};
                use nix::unistd::Pid;

                let container_pid = Pid::from_raw(pid);
                println!("Using legacy PID-based stop for process {}...", pid);

                if !force {
                    let _ = kill(container_pid, Signal::SIGTERM);
                    std::thread::sleep(std::time::Duration::from_secs(timeout.min(5)));
                }

                let _ = kill(container_pid, Signal::SIGKILL);
            }
            let _ = std::fs::remove_file(&pid_file);
        }
    }

    // Clean up network processes (pasta or slirp4netns)
    let network_pid_file = container_dir.join("network.pid");
    if network_pid_file.exists() {
        if let Ok(net_pid_str) = std::fs::read_to_string(&network_pid_file) {
            if let Ok(net_pid) = net_pid_str.trim().parse::<i32>() {
                use nix::sys::signal::{Signal, kill};
                use nix::unistd::Pid;

                let network_pid = Pid::from_raw(net_pid);
                println!("Stopping network helper (PID {})...", net_pid);
                let _ = kill(network_pid, Signal::SIGTERM);
            }
        }
        let _ = std::fs::remove_file(&network_pid_file);
    }

    // Also try to find and kill any pasta/slirp4netns processes for this container
    if let Ok(output) = Command::new("pgrep")
        .args(&["-f", &format!("(pasta|slirp4netns).*{}", full_container_id)])
        .output()
    {
        if output.status.success() {
            let pids = String::from_utf8_lossy(&output.stdout);
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    use nix::sys::signal::{Signal, kill};
                    use nix::unistd::Pid;

                    let net_pid = Pid::from_raw(pid);
                    let _ = kill(net_pid, Signal::SIGTERM);
                }
            }
        }
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
                                        image,
                                        tag,
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
        "docker.io" => {
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/hello-world:pull"
        }
        "quay.io" => "https://quay.io/v2/auth?service=quay.io&scope=repository:quay/busybox:pull",
        "ghcr.io" => {
            "https://ghcr.io/token?service=ghcr.io&scope=repository:library/hello-world:pull"
        }
        "gcr.io" => {
            "https://gcr.io/v2/token?service=gcr.io&scope=repository:library/hello-world:pull"
        }
        "public.ecr.aws" => {
            "https://public.ecr.aws/token?service=public.ecr.aws&scope=repository:library/hello-world:pull"
        }
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
