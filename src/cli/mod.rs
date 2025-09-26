use clap::{Parser, Subcommand, error::Result};

#[derive(Parser)]
#[command(name = "carrier", version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(short, long, default_value = "carrier_config.toml")]
    config: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Logs { image: String },

    Pull { image: String },

    Run { image: String },

    Build { image: String, url: String },
    Auth { username: String, registry: String },
    Remove { image: String },
}

#[derive(Debug, PartialEq, Clone)]
pub struct RegistryImage {
    pub registry: Option<String>,
    pub image: String,
    pub tag: String,
}

impl RegistryImage {
    pub fn parse(image_ref: &str) -> Result<Self, String> {
        if image_ref.is_empty() {
            return Err("Image reference cannot be empty".to_string());
        }

        // Split registry from image path
        let (registry, image_and_tag) = if let Some(slash_idx) = image_ref.find('/') {
            let potential_registry = &image_ref[..slash_idx];

            // Check if it's actually a registry (contains . or : or is localhost)
            if potential_registry.contains('.')
                || potential_registry.contains(':')
                || potential_registry == "localhost"
            {
                (
                    Some(potential_registry.to_string()),
                    &image_ref[slash_idx + 1..],
                )
            } else {
                // It's part of the image name (like "library/nginx")
                (None, image_ref)
            }
        } else {
            (None, image_ref)
        };

        // Split image and tag
        let (image, tag) = if let Some((img, t)) = image_and_tag.split_once(':') {
            (img.to_string(), t.to_string())
        } else {
            (image_and_tag.to_string(), "latest".to_string())
        };

        // Validate image name
        if image.is_empty() {
            return Err("Image name cannot be empty".to_string());
        }

        Ok(RegistryImage {
            registry,
            image,
            tag,
        })
    }

    /// Reconstruct the full image reference
    pub fn to_string(&self) -> String {
        match &self.registry {
            Some(reg) => format!("{}/{}:{}", reg, self.image, self.tag),
            None => format!("{}:{}", self.image, self.tag),
        }
    }


}