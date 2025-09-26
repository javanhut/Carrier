use crate::cli::RegistryImage;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

    // Download layers with progress
    if let Err(e) = download_layers_with_progress(&manifest, &parsed_image, &token).await {
        eprintln!("Failed to download layers: {}", e);
        return;
    }

    println!("\nImage {} pulled successfully!", image_name);
    println!("Ready to run container...");
    
    // Run the container
    if let Err(e) = run_container(&parsed_image, &manifest).await {
        eprintln!("Failed to run container: {}", e);
    }
}

pub async fn pull_image(image_name: String) {
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

    // Download layers with progress
    if let Err(e) = download_layers_with_progress(&manifest, &parsed_image, &token).await {
        eprintln!("Failed to download layers: {}", e);
        return;
    }

    println!("\nImage {} pulled successfully!", image_name);
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
        
        println!("Selected platform: {}/{}", 
            selected_manifest.platform.os, 
            selected_manifest.platform.architecture);
        
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
                return Err(format!("Failed to get specific manifest: {}", response.status()).into());
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

async fn download_layers_with_progress(
    manifest: &ManifestV2,
    parsed_image: &RegistryImage,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let registry = parsed_image.registry.as_deref().unwrap_or("docker.io");
    let registry_url = REGISTRYMAP
        .get(registry)
        .ok_or_else(|| format!("Registry {} not found", registry))?;
    
    let image_path = normalize_image_path(&parsed_image.image);
    let client = Client::new();

    // Create multi-progress for multiple layers
    let multi_progress = MultiProgress::new();

    // Download config first
    println!("\nDownloading config: {}", &manifest.config.digest[..12]);
    let config_url = format!(
        "{}{}/blobs/{}",
        registry_url, image_path, manifest.config.digest
    );

    download_blob_with_progress(
        &client,
        &config_url,
        token,
        &manifest.config.digest,
        manifest.config.size as u64,
        &multi_progress,
        "config",
    )
    .await?;

    // Download each layer
    println!("Downloading {} layers", manifest.layers.len());

    for (index, layer) in manifest.layers.iter().enumerate() {
        let blob_url = format!(
            "{}{}/blobs/{}",
            registry_url, image_path, layer.digest
        );

        download_blob_with_progress(
            &client,
            &blob_url,
            token,
            &layer.digest,
            layer.size as u64,
            &multi_progress,
            &format!("layer {}/{}", index + 1, manifest.layers.len()),
        )
        .await?;
    }

    println!("Download complete!");
    Ok(())
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
    let content_length = response
        .content_length()
        .unwrap_or(expected_size);
    
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

    // Create storage directory if it doesn't exist
    std::fs::create_dir_all("./carrier_storage")?;
    
    // Save to file
    let filename = format!("./carrier_storage/{}_{}.tar.gz", label.replace(" ", "_").replace("/", "_"), &digest[7..19]);
    std::fs::write(&filename, &downloaded)?;

    Ok(downloaded)
}

async fn run_container(
    parsed_image: &RegistryImage,
    manifest: &ManifestV2,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nStarting container from image {}...", parsed_image.to_string());
    
    // Extract and setup container filesystem
    println!("Setting up container filesystem...");
    
    // Create container directory
    let container_id = format!("carrier_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs());
    let container_path = format!("./containers/{}", container_id);
    std::fs::create_dir_all(&container_path)?;
    
    // Extract layers in order
    for (index, layer) in manifest.layers.iter().enumerate() {
        println!("Extracting layer {}/{}", index + 1, manifest.layers.len());
        let layer_file = format!("./carrier_storage/layer_{}_{}.tar.gz", 
            format!("{}/{}", index + 1, manifest.layers.len()).replace("/", "_"), 
            &layer.digest[7..19]);
        
        if std::path::Path::new(&layer_file).exists() {
            extract_layer(&layer_file, &container_path)?;
        }
    }
    
    println!("Container filesystem ready");
    println!("Container ID: {}", container_id);
    
    Ok(())
}

fn extract_layer(
    layer_path: &str,
    output_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use flate2::read::GzDecoder;
    use std::fs::File;
    use tar::Archive;

    let file = File::open(layer_path)?;
    let tar = GzDecoder::new(file);
    let mut archive = Archive::new(tar);

    archive.unpack(output_dir)?;

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