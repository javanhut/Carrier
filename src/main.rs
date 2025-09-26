use clap::Parser;

mod cli;
mod commands;
mod runtime;
mod storage;

use cli::{Cli, Commands};
use commands::{list_items, pull_image, remove_item, remove_all_stopped_containers, run_image, stop_container};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { image, command } => {
            if command.is_empty() {
                run_image(image).await;
            } else {
                // For now, just use run_image since we'll handle command override internally
                // In the future, we can pass the command through
                run_image(image).await;
            }
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
        Commands::Remove { image, force, all_containers } => {
            if all_containers {
                remove_all_stopped_containers(force).await;
            } else if let Some(img) = image {
                remove_item(img, force).await;
            } else {
                eprintln!("Error: Either specify an image/container ID or use --all-containers");
                std::process::exit(1);
            }
        }
        Commands::Build { image, url } => {
            println!("Building image: {image} to {url}");
        }
        Commands::List {
            all,
            images,
            containers,
        } => {
            list_items(all, images, containers).await;
        }
        Commands::Stop {
            container,
            force,
            timeout,
        } => {
            if let Err(e) = stop_container(container, force, timeout).await {
                eprintln!("Failed to stop container: {}", e);
                std::process::exit(1);
            }
        }
    }
}
