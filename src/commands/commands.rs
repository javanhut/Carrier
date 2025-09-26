use crate::cli::RegistryImage;
use crate::storage::{
    ContainerStorage, StorageLayout, extract_layer_rootless, generate_container_id,
};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

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

pub async fn run_image(image_name: String) {
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
    println!("Registry: {}", registry);
    println!("Image: {}", parsed_image.image);
    println!("Tag: {}", parsed_image.tag);

    // Get auth token
    let token = match get_repo_auth_token(image_name.clone()).await {
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
    let manifest = match parse_and_get_manifest(&manifest_json, &parsed_image, &token).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to parse manifest: {}", e);
            return;
        }
    };

    // Save manifest metadata
    let metadata_path = storage.image_metadata_path(&parsed_image.image, &parsed_image.tag);
    if let Err(e) = std::fs::write(&metadata_path, &manifest_json) {
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
    if let Err(e) =
        run_container_with_storage(&parsed_image, &manifest, layer_paths, &storage).await
    {
        eprintln!("Failed to run container: {}", e);
    }
}

pub async fn pull_image(image_name: String) {
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

    // Get auth token
    let token = match get_repo_auth_token(image_name.clone()).await {
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
    let manifest = match parse_and_get_manifest(&manifest_json, &parsed_image, &token).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to parse manifest: {}", e);
            return;
        }
    };

    // Save manifest metadata
    let metadata_path = storage.image_metadata_path(&parsed_image.image, &parsed_image.tag);
    if let Err(e) = std::fs::write(&metadata_path, &manifest_json) {
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
) -> Result<ManifestV2, Box<dyn std::error::Error>> {
    // First try to parse as manifest list
    if let Ok(manifest_list) = serde_json::from_str::<ManifestList>(manifest_json) {
        println!("Detected manifest list, selecting appropriate platform...");

        // Find the linux/amd64 manifest (or first available)
        let selected_manifest = manifest_list
            .manifests
            .iter()
            .find(|m| m.platform.os == "linux" && m.platform.architecture == "amd64")
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
    // Create progress bar
    let pb = multi_progress.add(ProgressBar::new(expected_size));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("#>-"),
    );
    pb.set_message(format!("{} {}", label, &digest[..12]));

    // Make request
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("Failed to download blob: {}", response.status()).into());
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

    pb.finish_with_message(format!("✓ {} {}", label, &digest[..12]));

    Ok(downloaded)
}

async fn run_container_with_storage(
    parsed_image: &RegistryImage,
    manifest: &ManifestV2,
    layer_paths: Vec<PathBuf>,
    storage: &StorageLayout,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::runtime::container::{Container, ContainerConfig};
    use crate::runtime::network::{NetworkConfig, NetworkMode};

    println!(
        "\nStarting container from image {}...",
        parsed_image.to_string()
    );

    // Generate container ID
    let container_id = generate_container_id();
    println!("Container ID: {}", container_id);

    // Create container with overlay filesystem
    println!("Setting up container filesystem with overlay...");

    let container_storage = ContainerStorage::new()?;
    let rootfs = container_storage.create_container_filesystem(&container_id, layer_paths)?;

    println!("Container filesystem ready at: {}", rootfs.display());

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
    let metadata = serde_json::json!({
        "id": container_id,
        "image": parsed_image.to_string(),
        "created": chrono::Utc::now().to_rfc3339(),
        "rootfs": rootfs.to_string_lossy(),
        "command": container_config.command,
        "status": "running"
    });

    if let Some(parent) = container_meta_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&container_meta_path, metadata.to_string())?;

    // Execute in container environment with proper isolation
    println!("\nRunning container {}...", container_id);
    println!("Command: {:?}", &command_to_run);

    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    if command_to_run.is_empty() || command_to_run[0].is_empty() {
        println!("No command specified in image");
        return Ok(());
    }

    // Detect if this should be an interactive container
    let is_interactive = command_to_run[0].contains("bash")
        || command_to_run[0].contains("sh")
        || command_to_run.contains(&"-it".to_string())
        || command_to_run.contains(&"-i".to_string());

    // Build the command path
    let cmd_in_container = &command_to_run[0];

    println!("Starting container with command: {}", cmd_in_container);

    // Use unshare with user namespaces for better isolation
    let mut cmd = Command::new("unshare");

    // Add namespace flags
    cmd.arg("--user")
        .arg("--map-root-user") // Map current user to root in container
        .arg("--mount")
        .arg("--pid")
        .arg("--fork");

    // Add chroot to the container filesystem
    cmd.arg("chroot").arg(&rootfs);

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

    if is_interactive {
        println!("\nStarting interactive container session...");
        println!("Type 'exit' or press Ctrl+D to exit the container.\n");

        // For interactive containers, use spawn and inherit stdio
        let mut child = cmd
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        // Save the PID to a file
        let pid_file = storage.container_path(&container_id).join("pid");
        std::fs::write(&pid_file, child.id().to_string())?;

        // Wait for the process to complete
        let status = child.wait()?;
        let exit_code = status.code().unwrap_or(0);
        
        // Remove PID file after process exits
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
        match cmd.output() {
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
            "application/vnd.docker.distribution.manifest.v2+json",
        )
        .send()
        .await?;
    Ok(response)
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

                                // Get size if available
                                let size = "N/A"; // Placeholder for now

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

                                // Format status display
                                let status_display = match status {
                                    "created" => format!("Created"),
                                    "running" => format!("Up {}", created_display.clone()),
                                    "exited" => format!("Exited (0) {}", created_display.clone()),
                                    _ => status.to_string(),
                                };

                                // Get command if available
                                let command =
                                    metadata["command"].as_str().unwrap_or("").to_string();

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
                    "No running containers (use -a to show all)"
                };
                println!("║ {}{}║", msg, " ".repeat(TOTAL_WIDTH - msg.len() - 4));
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
                        eprintln!("Container {} is running. Use --force to remove", container_id);
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
            let metadata_path =
                storage.image_metadata_path(&parsed_image.image, &parsed_image.tag);

            if !metadata_path.exists() {
                eprintln!("Image {} not found", item);
                return;
            }
            
            // Read the actual manifest to get layer info
            if let Ok(content) = std::fs::read_to_string(&metadata_path) {
                remove_image(&storage, &parsed_image.image, &parsed_image.tag, &content, force);
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
                                        let status = metadata["status"].as_str().unwrap_or("unknown");
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
                                println!("Removed container {}", &container_id[..12.min(container_id.len())]);
                                removed_count += 1;
                            }
                            Err(e) => {
                                eprintln!("Failed to remove container {}: {}", &container_id[..12.min(container_id.len())], e);
                                failed_count += 1;
                            }
                        }
                    } else {
                        println!("Skipping running container {}", &container_id[..12.min(container_id.len())]);
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
        println!("Removed {} container{}", removed_count, if removed_count == 1 { "" } else { "s" });
    }
    if skipped_count > 0 {
        println!("Skipped {} running container{}", skipped_count, if skipped_count == 1 { "" } else { "s" });
    }
    if failed_count > 0 {
        println!("Failed to remove {} container{}", failed_count, if failed_count == 1 { "" } else { "s" });
    }
    if removed_count == 0 && skipped_count == 0 && failed_count == 0 {
        println!("No containers to remove");
    }
}

pub async fn stop_container(container_id: String, force: bool, timeout: u64) -> Result<(), Box<dyn std::error::Error>> {
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
        println!("Container {} is not running (status: {})", full_container_id, status);
        return Ok(());
    }
    
    println!("Stopping container {}...", &full_container_id[..12]);
    
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
                        println!("Container did not stop within {} seconds, forcing...", timeout);
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
    
    println!("Container {} stopped", &full_container_id[..12]);
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

fn find_container_by_id(storage: &StorageLayout, container_id: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let containers_dir = storage.base.join("storage/overlay-containers");
    
    if !containers_dir.exists() {
        return Err("No containers found".into());
    }
    
    // Look for exact match or prefix match
    let mut matches = Vec::new();
    
    for entry in std::fs::read_dir(&containers_dir)? {
        let entry = entry?;
        if entry.path().is_dir() {
            let dir_name = entry.file_name().to_string_lossy().to_string();
            
            // Exact match
            if dir_name == container_id {
                return Ok(entry.path());
            }
            
            // Prefix match
            if dir_name.starts_with(container_id) {
                matches.push(entry.path());
            }
        }
    }
    
    match matches.len() {
        0 => Err(format!("No container found matching '{}'", container_id).into()),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => Err(format!("Ambiguous container ID '{}' matches {} containers", container_id, matches.len()).into()),
    }
}

fn find_container_by_id_optional(storage: &StorageLayout, container_id: &str) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let containers_dir = storage.base.join("storage/overlay-containers");
    
    if !containers_dir.exists() {
        return Ok(None);
    }
    
    // Look for exact match or prefix match
    let mut matches = Vec::new();
    
    for entry in std::fs::read_dir(&containers_dir)? {
        let entry = entry?;
        if entry.path().is_dir() {
            let dir_name = entry.file_name().to_string_lossy().to_string();
            
            // Exact match
            if dir_name == container_id {
                return Ok(Some(entry.path()));
            }
            
            // Prefix match
            if dir_name.starts_with(container_id) {
                matches.push(entry.path());
            }
        }
    }
    
    match matches.len() {
        0 => Ok(None),
        1 => Ok(Some(matches.into_iter().next().unwrap())),
        _ => Err(format!("Ambiguous container ID '{}' matches {} containers", container_id, matches.len()).into()),
    }
}

fn find_image_by_id(storage: &StorageLayout, image_id: &str) -> Result<Option<(String, String, String)>, Box<dyn std::error::Error>> {
    let images_dir = storage.base.join("storage/overlay-images");
    
    if !images_dir.exists() {
        return Ok(None);
    }
    
    // Search through all image metadata files
    for entry in std::fs::read_dir(&images_dir)? {
        let entry = entry?;
        if entry.path().is_file() && entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&content) {
                    // Check if config digest matches (partial or full)
                    if let Some(config_digest) = metadata["config"]["digest"].as_str() {
                        let short_id = config_digest.chars().skip(7).take(12).collect::<String>();
                        
                        // Match against full digest, short ID, or prefix
                        if config_digest == image_id || 
                           short_id == image_id || 
                           short_id.starts_with(image_id) ||
                           config_digest.starts_with(&format!("sha256:{}", image_id)) {
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

fn remove_image(storage: &StorageLayout, image: &str, tag: &str, manifest_content: &str, force: bool) {
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
        if let Ok(entries) =
            std::fs::read_dir(storage.base.join("storage/overlay-containers"))
        {
            for entry in entries.flatten() {
                let container_meta = entry.path().join("metadata.json");
                if container_meta.exists() {
                    if let Ok(content) = std::fs::read_to_string(&container_meta) {
                        if let Ok(metadata) =
                            serde_json::from_str::<serde_json::Value>(&content)
                        {
                            if let Some(container_image) = metadata["image"].as_str() {
                                // Check if the container is using this image
                                if container_image == parsed_image.to_string() ||
                                   container_image == format!("{}:{}", image, tag) ||
                                   container_image == image && tag == "latest" {
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
