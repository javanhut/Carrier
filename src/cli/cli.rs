use clap::{Parser, Subcommand, ValueEnum, error::Result};
pub use clap_complete::Shell;

#[derive(Parser)]
#[command(name = "carrier", version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Force storage driver: auto, overlay-fuse, overlay-native, or vfs
    #[arg(long = "storage-driver")]
    pub storage_driver: Option<StorageDriverChoice>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum StorageDriverChoice {
    Auto,
    OverlayFuse,
    OverlayNative,
    Vfs,
}

impl StorageDriverChoice {
    pub fn forced_name(self) -> Option<&'static str> {
        match self {
            Self::Auto => None,
            Self::OverlayFuse => Some("overlay-fuse"),
            Self::OverlayNative => Some("overlay-native"),
            Self::Vfs => Some("vfs"),
        }
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Internal macOS VM supervisor entry point.
    #[command(name = "__vm-daemon", hide = true)]
    VmDaemon { container: String },

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

        /// Keep STDIN open — forward your input to the container (interactive)
        #[arg(short = 'i', long = "interactive")]
        interactive: bool,

        /// Allocate a TTY (implies interactive; raw terminal)
        #[arg(short = 't', long = "tty")]
        tty: bool,

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

    /// Manage the bundled Linux VM backend (macOS only)
    Machine {
        #[command(subcommand)]
        action: MachineCmd,
    },
}

/// Lifecycle of the macOS Linux micro-VM that runs containers.
#[derive(Subcommand, Clone)]
pub enum MachineCmd {
    /// Download the VM artifacts (kernel + rootfs) into ~/.local/share/carrier/vm
    Init,
    /// Boot the VM
    Start,
    /// Stop the VM
    Stop,
    /// Show provisioning / run status
    Status,
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
        if image_ref.contains(char::is_whitespace) {
            return Err("Image reference cannot contain whitespace".to_string());
        }
        if image_ref.contains('@') {
            return Err("Digest image references are not supported yet; use a tag".to_string());
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
        let last_slash = image_and_tag.rfind('/');
        let last_colon = image_and_tag.rfind(':');
        let (image, tag) =
            if last_colon.is_some_and(|colon| last_slash.is_none_or(|slash| colon > slash)) {
                let colon = last_colon.unwrap();
                let (img, tagged) = image_and_tag.split_at(colon);
                let t = &tagged[1..];
                (img.to_string(), t.to_string())
            } else {
                (image_and_tag.to_string(), "latest".to_string())
            };

        // Validate image name
        if image.is_empty() {
            return Err("Image name cannot be empty".to_string());
        }
        if tag.is_empty() || tag.len() > 128 {
            return Err("Image tag must contain between 1 and 128 characters".to_string());
        }
        if !tag.chars().enumerate().all(|(index, ch)| {
            ch.is_ascii_alphanumeric() || ch == '_' || ((ch == '-' || ch == '.') && index > 0)
        }) {
            return Err("Image tag contains invalid characters".to_string());
        }
        if image.split('/').any(|part| {
            part.is_empty()
                || part.starts_with(['.', '-'])
                || part.ends_with(['.', '-'])
                || !part.chars().all(|ch| {
                    ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-')
                })
        }) {
            return Err("Image name contains an invalid repository component".to_string());
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
    use super::{Cli, RegistryImage, StorageDriverChoice};
    use clap::Parser;

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

    #[test]
    fn rejects_malformed_image_references() {
        for reference in [
            "UPPER/image",
            "image:",
            "image:-bad",
            "owner//image",
            "image@sha256:abc",
            "bad image",
        ] {
            assert!(
                RegistryImage::parse(reference).is_err(),
                "accepted {reference}"
            );
        }
    }

    #[test]
    fn clap_validates_storage_driver() {
        let cli = Cli::try_parse_from(["carrier", "--storage-driver", "vfs", "list"]).unwrap();
        assert!(matches!(cli.storage_driver, Some(StorageDriverChoice::Vfs)));
        assert!(Cli::try_parse_from(["carrier", "--storage-driver", "typo", "list"]).is_err());
    }
}
