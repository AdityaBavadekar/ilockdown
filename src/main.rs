use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use nix::unistd::Uid;
use std::{
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};
use tokio::runtime::Runtime;

use crate::watchdog::start_process_watchdog;
use crate::{
    lock::InstanceLock,
    lockdown::{lockdown_daemon, release_lockdown},
    proxy::run_proxy,
};
mod audio;
mod browser;
mod config;
mod firewall;
mod focus;
mod init;
mod lock;
mod lockdown;
mod logger;
mod proxy;
mod watchdog;

#[derive(Parser)]
#[command(name = "iicpc-lockdown")]
#[command(
    about = "Secure Proctoring Environment for Linux",
    author,
    version,
    about = "Secure Lockdown Tool for Linux"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Args)]
struct ScanArgs {
    /// Kill flagged processes if found
    #[arg(short = 'k', long = "kill")]
    kill: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Creates necessary directories, performs preflight checks
    Init,

    /// Starts the lockdown daemon
    Start,

    /// Checks if the lockdown is currently active
    Status,

    /// Releases the lockdown, restoring normal system operation
    Unlock,

    /// A background heartbeat process that prevents the system from sleeping
    KeepAlive,

    /// Performs a one-time forensic scan for blacklisted processes (see help for options)
    Scan(ScanArgs),

    // Launches a locked-down browser instance
    BrowserTest,

    // Runs a proxy server for testing purposes
    ProxyTest,

    // Logs blacklisted applications and kills them
    RestrictAppsTest,

    // Focus monitoring test
    FocusMonitor,

    // Audio test
    AudioTest,
}

const DEFAULT_PREFERED_BROWSER: Option<&str> = None;

fn require_root() {
    if !Uid::effective().is_root() {
        eprintln!("[!] This tool requires root privileges.");
        eprintln!("Run using 'sudo':");
        eprintln!("   sudo iicpc-lockdown");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    logger::init();
    log::info!("iicpc-lockdown v{}", env!("CARGO_PKG_VERSION"));

    //TODO: verify self

    require_root();

    init::run()?;

    match cli.command {
        Commands::Init => {
            println!("Initialization complete.");
            focus::init_monitor();
        }
        Commands::Status => {
            if !lock::check_lockdown_active() {
                println!("Lockdown is not active.");
                return Ok(());
            }
            println!("Lockdown is currently active.");
        }
        Commands::Start => {
            let _lock = InstanceLock::acquire()?;
            lockdown_daemon(DEFAULT_PREFERED_BROWSER)?;
        }
        Commands::Unlock => {
            let _lock = InstanceLock::acquire()?;
            release_lockdown()?;
            println!("Lockdown has been lifted.");
        }
        Commands::Scan(args) => {
            watchdog::scan_only(args.kill)?;
            println!("Process scan complete.");
        }
        Commands::FocusMonitor => {
            log::info!("Focus monitoring test running...");
            // focus::start_focus_monitor().await;
            let allowed_pids: Option<Vec<u32>> = Some(vec![std::process::id()]);
            focus::main(&allowed_pids);
        }
        Commands::BrowserTest => {
            let instance = browser::launch_locked_browser(DEFAULT_PREFERED_BROWSER)?;
            // keep the main thread alive
            browser::supervise_browser(instance)?;
        }
        Commands::RestrictAppsTest => {
            log::info!("RestrictApps test running...");
            start_process_watchdog(0);
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
        Commands::AudioTest => {
            log::info!("Audio test starting...");
            audio::start_lockdown();
            let running = Arc::new(AtomicBool::new(true));
            let r = running.clone();
            ctrlc::set_handler(move || {
                r.store(false, Ordering::SeqCst);
            })
            .unwrap();

            while running.load(Ordering::SeqCst) {
                log::info!("Audio lockdown tick...");
                audio::lockdown_tick();
                thread::sleep(Duration::from_millis(1000));
            }

            audio::end_lockdown();
            log::info!("Audio test ended.");
        }
        Commands::ProxyTest => {
            let rt = Runtime::new().context("Failed to create tokio runtime")?;
            std::thread::spawn(move || {
                if let Err(e) = rt.block_on(run_proxy()) {
                    log::error!("Proxy exited with error: {}", e);
                }
            });
            loop {
                log::info!("Proxy test server running...");
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
        Commands::KeepAlive => {
            let _lock = InstanceLock::acquire()?;
            while {
                std::thread::sleep(std::time::Duration::from_secs(60));
                true
            } {}
        }
    };

    Ok(())
}
