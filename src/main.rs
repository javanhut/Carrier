use clap::{CommandFactory, Parser};

mod cli;
mod commands;
mod deps;
mod storage;

use cli::{Cli, Commands};
use commands::{
    authenticate_registry, exec_in_container, list_items, pull_image,
    remove_all_stopped_containers, remove_item, run_image, run_image_with_command,
    show_container_info, show_container_logs, stop_container, verify_authentication,
};
use deps::run_doctor;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            image,
            detach,
            name,
            elevated,
            volumes,
            ports,
            env,
            platform,
            command,
        } => {
            if command.is_empty() {
                run_image(
                    image,
                    detach,
                    name,
                    elevated,
                    volumes,
                    ports,
                    env,
                    platform,
                    cli.storage_driver.clone(),
                )
                .await;
            } else {
                run_image_with_command(
                    image,
                    detach,
                    name,
                    elevated,
                    command,
                    volumes,
                    ports,
                    env,
                    platform,
                    cli.storage_driver.clone(),
                )
                .await;
            }
        }
        Commands::Logs {
            image,
            follow,
            tail,
            timestamps,
            since,
            search,
            fuzzy,
            regex,
        } => {
            if let Err(e) =
                show_container_logs(image, follow, tail, timestamps, since, search, fuzzy, regex)
                    .await
            {
                eprintln!("Failed to show logs: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Pull { image, platform } => {
            pull_image(image, platform).await;
        }
        Commands::Auth { username, registry } => {
            if let Err(e) = authenticate_registry(username, registry).await {
                eprintln!("Failed to authenticate: {}", e);
                std::process::exit(1);
            }
        }
        Commands::AuthVerify => {
            if let Err(e) = verify_authentication().await {
                eprintln!("Failed to verify authentication: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Remove {
            image,
            force,
            all_containers,
            interactive,
        } => {
            if all_containers {
                remove_all_stopped_containers(force).await;
            } else if let Some(img) = image {
                remove_item(img, force, interactive).await;
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
        Commands::Doctor { fix, json, all, dry_run, yes, verbose } => {
            use deps::installer::{install_all, install_missing, print_install_summary, InstallOptions};
            use deps::platform::detect_platform;

            let platform = detect_platform();
            let options = InstallOptions {
                dry_run,
                yes,
                max_retries: 3,
                verbose,
            };

            if dry_run && !fix && !all {
                // Just show what would be installed
                print_install_summary(&platform);
            } else if all {
                // Install all dependencies at once
                if let Err(e) = install_all(&platform, &options) {
                    eprintln!("Installation failed: {}", e);
                    std::process::exit(1);
                }
            } else if fix {
                // Install only missing dependencies
                match install_missing(&platform, &options) {
                    Ok((installed, failed)) => {
                        if failed > 0 {
                            std::process::exit(1);
                        }
                        if installed == 0 && !dry_run {
                            println!("All dependencies are already installed.");
                        }
                    }
                    Err(e) => {
                        eprintln!("Installation failed: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                // Just run the doctor check
                run_doctor(false, json).await;
            }
        }
        Commands::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "carrier",
                &mut std::io::stdout(),
            );
        }
    }
}
