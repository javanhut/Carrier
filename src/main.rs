use clap::Parser;

mod cli;
mod commands;
mod runtime;
mod storage;

use cli::{Cli, Commands};
use commands::{exec_in_container, list_items, pull_image, remove_item, remove_all_stopped_containers, run_image, run_image_with_command, show_container_info, show_container_logs, stop_container};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { image, detach, name, command, platform } => {
            if command.is_empty() {
                run_image(image, detach, name, platform, cli.storage_driver.clone()).await;
            } else {
                // For now, just use run_image since we'll handle command override internally
                // In the future, we can pass the command through
                run_image_with_command(image, detach, name, command, platform, cli.storage_driver.clone()).await;
            }
        }
        Commands::Logs { image, follow, tail, timestamps, since, search, fuzzy, regex } => {
            if let Err(e) = show_container_logs(image, follow, tail, timestamps, since, search, fuzzy, regex).await {
                eprintln!("Failed to show logs: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Pull { image, platform } => {
            pull_image(image, platform).await;
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
        Commands::Shell { container, command } => {
            if let Err(e) = exec_in_container(container, command, false).await {
                eprintln!("Failed to execute command: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Terminal { container, command } => {
            if let Err(e) = exec_in_container(container, command, true).await {
                eprintln!("Failed to open terminal: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Info { container } => {
            if let Err(e) = show_container_info(container).await {
                eprintln!("Failed to get container info: {}", e);
                std::process::exit(1);
            }
        }
    }
}
