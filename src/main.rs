use clap::{CommandFactory, Parser};

mod cli;
// The native container implementation is Linux-only; on other platforms the
// engine layer substitutes a stub backend (see `engine::default_engine`).
#[cfg(target_os = "linux")]
mod commands;
mod deps;
mod engine;
mod storage;

use cli::{Cli, Commands};
use deps::run_doctor;
use engine::{default_engine, ListFilter, LogOptions, RunSpec};

/// Print an error and exit non-zero. Used for engine operations whose failure
/// should surface to the shell.
fn fail(context: &str, e: Box<dyn std::error::Error>) -> ! {
    eprintln!("{}: {}", context, e);
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let engine = default_engine();

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
            verbose,
            command,
        } => {
            let spec = RunSpec {
                image,
                detach,
                name,
                elevated,
                volumes,
                ports,
                env,
                platform,
                storage_driver: cli.storage_driver.clone(),
                verbose,
                command,
            };
            if let Err(e) = engine.run(spec).await {
                fail("Failed to run container", e);
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
            let opts = LogOptions {
                follow,
                tail,
                timestamps,
                since,
                search,
                fuzzy,
                regex,
            };
            if let Err(e) = engine.logs(image, opts).await {
                fail("Failed to show logs", e);
            }
        }
        Commands::Pull { image, platform } => {
            if let Err(e) = engine.pull(image, platform).await {
                fail("Failed to pull image", e);
            }
        }
        Commands::Auth { username, registry } => {
            if let Err(e) = engine.authenticate(username, registry).await {
                fail("Failed to authenticate", e);
            }
        }
        Commands::AuthVerify => {
            if let Err(e) = engine.verify_auth().await {
                fail("Failed to verify authentication", e);
            }
        }
        Commands::Remove {
            image,
            force,
            all_containers,
            interactive,
        } => {
            if let Err(e) = engine.remove(image, force, all_containers, interactive).await {
                fail("Error", e);
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
            let filter = ListFilter {
                all,
                images_only: images,
                containers_only: containers,
            };
            if let Err(e) = engine.list(filter).await {
                fail("Failed to list items", e);
            }
        }
        Commands::Stop {
            container,
            force,
            timeout,
        } => {
            if let Err(e) = engine.stop(container, force, timeout).await {
                fail("Failed to stop container", e);
            }
        }
        Commands::Shell { container, command } => {
            if let Err(e) = engine.exec(container, command, false).await {
                fail("Failed to execute command", e);
            }
        }
        Commands::Terminal { container, command } => {
            if let Err(e) = engine.exec(container, command, true).await {
                fail("Failed to open terminal", e);
            }
        }
        Commands::Info { container } => {
            if let Err(e) = engine.info(container).await {
                fail("Failed to get container info", e);
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
