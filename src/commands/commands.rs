use crate::cli::RegistryImage;
use crate::storage::{
    extract_layer_rootless, generate_container_id, ContainerStorage, StorageLayout,
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

pub async fn run_image(image_name: String, detach: bool, name: Option<String>) {
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
    command: Vec<String>,
) {
    // For now, just call run_image since command override isn't fully implemented
    // TODO: Pass the command to override the image's default command
    run_image(image_name, detach, name).await;
}

pub async fn exec_in_container(
    container_id: String,
    command: Vec<String>,
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
            &full_container_id[..12],
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
            &full_container_id[..12]
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
            &full_container_id[..12],
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
        &full_container_id[..12],
        cmd_to_run
    );

    // Use nsenter to enter the container's namespaces
    use std::process::{Command, Stdio};

    let mut exec_cmd = Command::new("nsenter");

    // Enter all namespaces of the target process
    exec_cmd
        .arg("-t")
        .arg(container_pid.to_string())
        .arg("-m") // Mount namespace
        .arg("-u") // UTS namespace
        .arg("-i") // IPC namespace
        .arg("-n") // Network namespace
        .arg("-p"); // PID namespace

    // Add the command to execute
    exec_cmd.args(&cmd_to_run);

    // Check if this is an interactive command
    let is_interactive = cmd_to_run.len() == 1
        && (cmd_to_run[0] == "/bin/sh"
            || cmd_to_run[0] == "/bin/bash"
            || cmd_to_run[0] == "sh"
            || cmd_to_run[0] == "bash");

    if is_interactive {
        println!("Starting interactive shell session...");
        println!("Type 'exit' or press Ctrl+D to exit.\n");

        exec_cmd
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    } else {
        // For non-interactive commands, just inherit stdout/stderr
        exec_cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    }

    // Execute the command
    let mut child = exec_cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            "nsenter command not found. Please install util-linux package.".to_string()
        } else if e.to_string().contains("Operation not permitted") {
            format!(
                "Permission denied. You may need to run this command with elevated privileges: {}",
                e
            )
        } else {
            format!("Failed to execute command: {}", e)
        }
    })?;

    // Wait for the command to complete
    let status = child.wait()?;

    if !status.success() {
        if let Some(code) = status.code() {
            return Err(format!("Command exited with code {}", code).into());
        }
    }

    Ok(())
}

pub async fn show_container_logs(container_id: String) -> Result<(), Box<dyn std::error::Error>> {
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
        println!("No logs available for container {}", &full_container_id[..12]);
        println!("Container may not have been run in detached mode or may not have produced any output yet.");
        return Ok(());
    }
    
    // Read and display the logs
    let logs = std::fs::read_to_string(&log_file)?;
    if logs.trim().is_empty() {
        println!("Log file exists but is empty for container {}", &full_container_id[..12]);
        return Ok(());
    }
    
    // Display logs with timestamps if available
    println!("Logs for container {}:", &full_container_id[..12]);
    println!("{}", "─".repeat(60));
    
    for line in logs.lines() {
        if !line.trim().is_empty() {
            println!("{}", line);
        }
    }
    
    println!("{}", "─".repeat(60));
    println!("End of logs for container {}", &full_container_id[..12]);
    
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
    println!("║ Short ID:  {:<54} ║", &full_container_id[..12]);

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
            &full_container_id[..12]
        );
        println!(
            "║ • carrier stop {}                                        ║",
            &full_container_id[..12]
        );
        println!(
            "║ • carrier logs {} (if implemented)                      ║",
            &full_container_id[..12]
        );
    } else {
        println!(
            "║ • carrier rm {}                                          ║",
            &full_container_id[..12]
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
    detach: bool,
    name: Option<String>,
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
        "status": "running"
    });

    if let Some(parent) = container_meta_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&container_meta_path, metadata.to_string())?;

    // Execute in container environment with proper isolation
    if detach {
        println!(
            "\nRunning container {} in detached mode...",
            &container_id[..12]
        );
    } else {
        println!("\nRunning container {}...", container_id);
    }
    println!("Command: {:?}", &command_to_run);

    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

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

    if detach {
        // For detached containers, redirect stdout/stderr to log file
        let log_file = storage.container_path(&container_id).join("container.log");
        let log_file_stdout = std::fs::File::create(&log_file)?;
        let log_file_stderr = log_file_stdout.try_clone()?;
        
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file_stdout))
            .stderr(Stdio::from(log_file_stderr))
            .spawn()?;

        // Save the PID to a file
        let pid_file = storage.container_path(&container_id).join("pid");
        std::fs::write(&pid_file, child.id().to_string())?;

        println!("Container {} started in background", &container_id[..12]);
        println!("Logs are being written to: {}", log_file.display());
        println!("To view logs: carrier logs {}", &container_id[..12]);
        println!("To stop: carrier stop {}", &container_id[..12]);

        // Don't wait for the process - let it run in background
        return Ok(());
    } else if is_interactive {
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
                                let status_display = match actual_status {
                                    "created" => format!("Created"),
                                    "running" => format!("Up {}", created_display.clone()),
                                    "exited" => format!("Exited (0) {}", created_display.clone()),
                                    _ if actual_status.starts_with("Up") => {
                                        actual_status.to_string()
                                    }
                                    _ => actual_status.to_string(),
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
