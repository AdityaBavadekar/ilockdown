use anyhow::Context;
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use nix::unistd::Uid;
use tokio::runtime::Runtime;

use crate::watchdog::start_process_watchdog;
use crate::{
    firewall::{apply_lockdown, lockdown_daemon, release_lockdown},
    lock::InstanceLock,
    proxy::run_proxy,
};
mod browser;
mod firewall;
mod focus;
mod init;
mod lock;
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
}

// make sure the program is run as root
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
            lockdown_daemon(&_lock)?;
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
            focus::start_focus_monitor().await;
        }
        Commands::BrowserTest => {
            browser::launch_locked_browser()?;
            // keep the main thread alive while the browser is running
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
        Commands::RestrictAppsTest => {
            log::info!("RestrictApps test running...");
            start_process_watchdog(0);
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
        Commands::ProxyTest => {
            // create async runtime for proxy
            let rt = Runtime::new().context("Failed to create tokio runtime")?;

            // spawn proxy in background thread
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
