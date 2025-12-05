use crate::proxy::run_proxy;
use crate::{audio, browser, firewall, lock, watchdog};
use anyhow::{Context, Result, anyhow};
use colored::*;
use std::fs;
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tokio::runtime::Runtime;

fn wait_for_proxy() {
    for _ in 0..50 {
        if TcpStream::connect("127.0.0.1:8080").is_ok() {
            log::info!("Proxy is ready");
            return;
        }
        log::info!("Waiting for proxy to start...");
        thread::sleep(Duration::from_millis(100));
    }

    panic!("Proxy did not start");
}

pub fn setup_cgroup(browser_pid: u32) -> Result<()> {
    let cg = "/sys/fs/cgroup/iicpc";
    fs::create_dir_all(cg)?;
    fs::write(
        "/sys/fs/cgroup/cgroup.subtree_control",
        "+cpu +memory +pids",
    )?;
    fs::write(format!("{cg}/cgroup.procs"), browser_pid.to_string())?;
    fs::write(format!("{cg}/memory.high"), "3G")?;
    fs::write(format!("{cg}/memory.swap.max"), "0")?;
    fs::write(format!("{cg}/pids.max"), "2048")?;

    Ok(())
}

pub fn restore_cgroup() -> Result<()> {
    let cg = "/sys/fs/cgroup/iicpc";

    if !Path::new(cg).exists() {
        return Ok(());
    }

    // Reset limits first (best practice)
    let _ = fs::write(format!("{cg}/memory.high"), "max");
    let _ = fs::write(format!("{cg}/memory.swap.max"), "max");
    let _ = fs::write(format!("{cg}/pids.max"), "max");

    // Remove the cgroup folder
    fs::remove_dir(cg)?;

    Ok(())
}

pub fn release_lockdown() -> Result<()> {
    log::info!("Releasing lockdown...");

    log::info!("Restoring cgroup...");
    if let Err(e) = restore_cgroup() {
        log::error!("Failed to restore cgroup: {}", e);
    }
    firewall::release_lockdown()?;
    audio::end_lockdown();
    log::info!("Lockdown released successfully.");
    Ok(())
}

pub fn lockdown_daemon(prefered_browser: Option<&str>) -> Result<()> {
    println!("\n\n");
    println!(
        "{}",
        "════════════════════════════════════════════════════════════"
            .bright_yellow()
            .bold()
    );
    println!("{}", "LOCKDOWN INITIALIZING...".bright_yellow().bold());
    println!(
        "{}",
        "════════════════════════════════════════════════════════════"
            .bright_yellow()
            .bold()
    );
    println!("\n");

    let running = Arc::new(AtomicBool::new(true));
    let flag = running.clone();
    ctrlc::set_handler(move || {
        flag.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");

    // validate lock_instance is held
    if !lock::check_lockdown_active() {
        return Err(anyhow::anyhow!(
            "lock_instance is not active, cannot proceed with lockdown daemon"
        ));
    }

    log::info!("Lock instance verified, proceeding with lockdown daemon");
    log::info!("Starting lockdown daemon...");

    // pre-flight checks
    log::info!("Performing pre-flight checks...");
    log::info!("[PASS] pre-flight checks passed");

    // apply network lockdown
    if let Err(e) = firewall::apply_network_lockdown() {
        log::error!("Network lockdown failed: {}, releasing lockdown...", e);
        eprintln!("{}", format!("Network lockdown failed: {}", e).red().bold());
        let _ = release_lockdown();
        log::error!("Lockdown daemon aborted due to network lockdown failure");
        return Err(anyhow!("Network lockdown failed: {}", e));
    }

    // apply hosts blocklist
    if let Err(e) = firewall::apply_hosts_blocklist() {
        log::error!(
            "Failed to apply hosts blocklist: {}, releasing lockdown...",
            e
        );
        eprintln!(
            "{}",
            format!("Failed to apply hosts blocklist: {}", e)
                .red()
                .bold()
        );
        let _ = release_lockdown();
        log::error!("Lockdown daemon aborted due to hosts blocklist failure");
        return Err(anyhow!("Failed to apply hosts blocklist: {}", e));
    }

    firewall::verify_connectivity(true)?;

    log::info!("Starting proxy server for browser...");
    // create async runtime for proxy
    let rt = Runtime::new().context("Failed to create tokio runtime")?;

    // spawn proxy in background thread
    std::thread::spawn(move || {
        if let Err(e) = rt.block_on(run_proxy()) {
            log::error!("Proxy exited with error: {}", e);
        }
    });
    log::info!("Proxy server started, waiting for readiness...");

    wait_for_proxy();

    let browser_proc = browser::launch_locked_browser(prefered_browser)
        .context("Failed to launch locked browser session")?;
    log::info!("Locked browser launched with PID {}", browser_proc.id());
    let browser_pid: u32 = browser_proc.id();

    setup_cgroup(browser_proc.id()).context("Failed to setup cgroup for browser")?;
    let r2_clone = running.clone();
    let _supervisor = thread::spawn(move || {
        if let Err(e) = browser::supervise_browser(browser_proc) {
            log::error!("Browser closed: {}", e);
            r2_clone.store(false, Ordering::SeqCst);
        }
    });

    log::info!("Starting process watchdog...");
    watchdog::start_process_watchdog(browser_pid);

    let r2 = running.clone();
    thread::spawn(move || {
        while r2.load(Ordering::SeqCst) {
            firewall::watchdog_network();
            thread::sleep(Duration::from_secs(5));
        }
    });
    log::info!("Lockdown applied successfully, current status: ACTIVE");
    println!("\n\n");
    println!(
        "{}",
        "════════════════════════════════════════════════════════════"
            .bright_green()
            .bold()
    );
    println!("{}", "LOCKDOWN MODE ACTIVE".bright_green().bold());
    println!(
        "{}",
        "════════════════════════════════════════════════════════════"
            .bright_green()
            .bold()
    );
    println!();
    println!("{}", "SYSTEM RESTRICTIONS ARE NOW ENFORCED".yellow().bold());
    println!(
        "{}",
        "All user activity is locked to the secure browser session.".yellow()
    );
    println!();
    println!("{}", "To STOP the lockdown safely:".bright_white().bold());
    println!(
        "{}",
        "→ PRESS  Ctrl + C  IN THIS TERMINAL".bright_red().bold()
    );
    println!();
    println!(
        "{}",
        "════════════════════════════════════════════════════════════"
            .bright_green()
            .bold()
    );

    println!("\n");

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    log::info!("Lockdown daemon shutting down...");
    println!("Lockdown daemon shutting down...");

    log::info!("Lockdown daemon exiting — cleaning up...");
    release_lockdown()?;

    println!("\n");
    println!(
        "{}",
        "════════════════════════════════════════════════════════════"
            .bright_yellow()
            .bold()
    );
    println!("{}", "LOCKDOWN HAS BEEN LIFTED".bright_yellow().bold());
    println!(
        "{}",
        "════════════════════════════════════════════════════════════"
            .bright_yellow()
            .bold()
    );
    println!("\n");

    Ok(())
}
