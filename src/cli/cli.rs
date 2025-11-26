use clap::{error::Result, Parser, Subcommand};
pub use clap_complete::Shell;

#[derive(Parser)]
#[command(name = "carrier", version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(short, long, default_value = "carrier_config.toml")]
    config: String,

    /// Force storage driver: auto, overlay-fuse, overlay-native, or vfs
    #[arg(long = "storage-driver")]
    pub storage_driver: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Show container logs
    Logs {
        /// Container ID or name
        image: String,
        /// Follow log output
        #[arg(short = 'f', long = "follow")]
        follow: bool,
        /// Number of lines to show from the end of the logs
        #[arg(long = "tail")]
        tail: Option<usize>,
        /// Show timestamps with each log line
        #[arg(long = "timestamps")]
        timestamps: bool,
        /// Only show logs since the given time (RFC3339) or duration like 10m, 2h, 1d
        #[arg(long = "since")]
        since: Option<String>,
        /// Case-insensitive search term; combined with --fuzzy for fuzzy matching
        #[arg(long = "search")]
        search: Option<String>,
        /// Enable fuzzy matching for --search (subsequence match)
        #[arg(long = "fuzzy")]
        fuzzy: bool,
        /// Use a regex pattern to filter lines (case-insensitive). Overrides --search/--fuzzy if set.
        #[arg(long = "regex")]
        regex: Option<String>,
    },

    // Pull command moved below with platform option
    /// Run a container from an image
    Run {
        image: String,

        /// Run container in detached mode (background)
        #[arg(short = 'd', long = "detach")]
        detach: bool,

        /// Custom name for the container
        #[arg(long = "name")]
        name: Option<String>,

        /// Run container with elevated privileges (allows operations like apt update)
        #[arg(long = "elevated")]
        elevated: bool,

        /// Bind mount a volume (host_path:container_path[:ro])
        #[arg(short = 'v', long = "volume", action = clap::ArgAction::Append)]
        volumes: Vec<String>,

        /// Publish a container's port to the host (host_port:container_port)
        #[arg(short = 'p', long = "publish", action = clap::ArgAction::Append)]
        ports: Vec<String>,

        /// Set environment variables (KEY=VALUE)
        #[arg(short = 'e', long = "env", action = clap::ArgAction::Append)]
        env: Vec<String>,

        /// Target platform (e.g., linux/amd64, linux/arm64)
        #[arg(long = "platform")]
        platform: Option<String>,

        /// Show verbose output (download progress, layer extraction, etc.)
        #[arg(long = "verbose")]
        verbose: bool,

        /// Optional command to override the image default
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Build a container image
    Build { image: String, url: String },

    /// Authenticate with a registry
    Auth { username: String, registry: String },

    /// Verify stored authentication credentials
    AuthVerify,

    /// Remove an image or container
    #[command(alias = "rm", aliases = ["rmi"])]
    Remove {
        /// Image or container ID to remove (optional if using --all-containers)
        image: Option<String>,

        /// Force removal even if container is running
        #[arg(short, long)]
        force: bool,

        /// Remove all stopped containers
        #[arg(short = 'c', long = "all-containers")]
        all_containers: bool,

        /// Interactive mode - prompt before removing
        #[arg(short, long)]
        interactive: bool,
    },

    /// List images and containers
    #[command(aliases= ["ls", "ps"])]
    List {
        /// Show all containers (default shows only running)
        #[arg(short, long)]
        all: bool,

        /// Show only images
        #[arg(short = 'i', long)]
        images: bool,

        /// Show only containers
        #[arg(short = 'c', long)]
        containers: bool,
    },

    /// Stop a running container
    Stop {
        /// Container ID or name to stop
        container: String,

        /// Force stop (kill) if graceful stop fails
        #[arg(short, long)]
        force: bool,

        /// Timeout in seconds before forcing stop
        #[arg(short = 't', long, default_value = "10")]
        timeout: u64,
    },

    /// Execute a command in a running container
    #[command(alias = "sh", aliases = ["exec","execute"])]
    Shell {
        /// Container ID or name
        container: String,

        /// Command to execute in the container
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Open a PTY terminal inside a running container (forces TTY)
    #[command(aliases = ["term", "t"])]
    Terminal {
        /// Container ID or name
        container: String,

        /// Command to execute (defaults to /bin/sh)
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Show detailed information about a container
    #[command(alias = "inspect")]
    Info {
        /// Container ID or name
        container: String,
    },

    /// Pull an image with optional platform selection
    #[command(alias="p", aliases=["download", "get"])]
    Pull {
        image: String,
        /// Target platform (e.g., linux/amd64)
        #[arg(long = "platform")]
        platform: Option<String>,
    },

    /// Check system dependencies and provide installation guidance
    #[command(alias = "check")]
    Doctor {
        /// Attempt to fix missing dependencies automatically
        #[arg(long)]
        fix: bool,

        /// Output results in JSON format
        #[arg(long)]
        json: bool,

        /// Install all dependencies at once
        #[arg(long)]
        all: bool,

        /// Show what would be installed without making changes
        #[arg(long, alias = "dry-run")]
        dry_run: bool,

        /// Skip confirmation prompts (use with --fix or --all)
        #[arg(short = 'y', long)]
        yes: bool,

        /// Show verbose output during installation
        #[arg(short, long)]
        verbose: bool,
    },

    /// Generate shell completions for the specified shell
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, powershell, elvish)
        #[arg(value_enum)]
        shell: Shell,
    },
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

#[cfg(test)]
mod tests {
    use super::RegistryImage;

    #[test]
    fn parse_simple_image() {
        let img = RegistryImage::parse("alpine").unwrap();
        assert_eq!(img.registry, None);
        assert_eq!(img.image, "alpine");
        assert_eq!(img.tag, "latest");
    }

    #[test]
    fn parse_with_tag() {
        let img = RegistryImage::parse("nginx:1.25").unwrap();
        assert_eq!(img.image, "nginx");
        assert_eq!(img.tag, "1.25");
    }

    #[test]
    fn parse_with_registry() {
        let img = RegistryImage::parse("docker.io/library/ubuntu:22.04").unwrap();
        assert_eq!(img.registry.as_deref(), Some("docker.io"));
        assert_eq!(img.image, "library/ubuntu");
        assert_eq!(img.tag, "22.04");
    }

    #[test]
    fn parse_localhost_registry() {
        let img = RegistryImage::parse("localhost:5000/my/app:dev").unwrap();
        assert_eq!(img.registry.as_deref(), Some("localhost:5000"));
        assert_eq!(img.image, "my/app");
        assert_eq!(img.tag, "dev");
    }
}
