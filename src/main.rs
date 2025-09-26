use clap::Parser;

mod cli;
mod commands;

use cli::{Cli, Commands};
use commands::{run_image, pull_image};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { image } => {
            run_image(image).await;
        }
        Commands::Logs { image } => {
            println!("Printing logs from {image}");
        }
        Commands::Pull { image } => {
            pull_image(image).await;
        }
        Commands::Auth { username, registry } => {
            println!("Login into {registry} using {username}");
        }
        Commands::Remove { image } => {
            println!("Removing image: {image}");
        }
        Commands::Build { image, url } => {
            println!("Building image: {image} to {url}");
        }
    }
}
