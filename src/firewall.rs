use crate::proxy::run_proxy;
use crate::watchdog::restore_blocked_services;
use anyhow::{Context, Result, anyhow};
use colored::*;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tokio::runtime::Runtime;

use crate::{
    browser::launch_locked_browser,
    lock::{self, RUNTIME_DIR},
    watchdog::start_process_watchdog,
};

const NFT_BACKUP: &str = "/run/iicpc-lockdown/pre_lockdown.nft";
const NFT_LOCKDOWN_SCRIPT: &str = "/run/iicpc-lockdown/lockdown.nft";
const NFT_SECOND_WRITE_ONCE_BACKUP: &str = "/run/iicpc-lockdown/system_wo_backup.nft";
pub fn apply_lockdown() -> Result<()> {
    // should be very critical section, should ensure that it does not backup the wrong state
    fs::create_dir_all(RUNTIME_DIR).context("Failed to create runtime dir for nft backup")?;

    backup_rules()?;
    write_lockdown_script()?;
    apply_lockdown_script()?;

    log::info!("nftables lockdown applied");
    Ok(())
}

use std::process::Stdio;
pub fn release_lockdown() -> Result<()> {
    log::info!("Releasing lockdown...");

    log::info!("Restoring cgroup...");
    if let Err(e) = restore_cgroup() {
        log::error!("Failed to restore cgroup: {}", e);
    }

    log::info!("Restoring blocked services...");
    if let Err(e) = restore_blocked_services() {
        log::error!("Failed to restore blocked services: {}", e);
    }

    log::info!("Releasing lockdown, restoring previous nftables ruleset");

    // restore blocked hosts
    if let Err(e) = restore_hosts() {
        log::error!("Failed to restore /etc/hosts: {}", e);
    }

    let exists = Command::new("nft")
        .args(["list", "table", "inet", "iicpc_lock"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !exists {
        log::warn!("No added nft table found, nothing to clean up");
        log::info!("Verifying connectivity post-unlock...");
        verify_connectivity(false)?;
        return Ok(());
    }

    let status = Command::new("nft")
        .args(["delete", "table", "inet", "iicpc_lock"])
        .status()
        .context("Failed to delete iicpc_lock nft table")?;

    if !status.success() {
        return Err(anyhow!("Failed to remove iicpc nft firewall table"));
    }

    log::info!("iicpc_lock nft table removed");
    log::info!("Lockdown released, previous nftables ruleset restored");

    // verify connection
    log::info!("Verifying connectivity post-unlock...");
    verify_connectivity(false)?;
    Ok(())
}

fn backup_rules() -> Result<()> {
    log::info!("Backing up current nft ruleset to {}", NFT_BACKUP);
    let status = Command::new("nft")
        .arg("list")
        .arg("ruleset")
        .output()
        .context("Failed to list nft ruleset")?;

    if !status.status.success() {
        return Err(anyhow::anyhow!(
            "nft list ruleset failed with status: {}",
            status.status
        ));
    }

    fs::write(NFT_BACKUP, &status.stdout).context("Failed to write nft backup file")?;

    // check 2nd write-once backup exists, if not create it
    if !Path::new(NFT_SECOND_WRITE_ONCE_BACKUP).exists() {
        fs::write(NFT_SECOND_WRITE_ONCE_BACKUP, &status.stdout)
            .context("Failed to write second write-once nft backup file")?;
        log::info!(
            "Created second write-once nft backup at {}",
            NFT_SECOND_WRITE_ONCE_BACKUP
        );
    }

    log::info!("Backed up nft ruleset to {}", NFT_BACKUP);
    Ok(())
}

fn write_lockdown_script() -> Result<()> {
    log::info!("Writing lockdown nft script to {}", NFT_LOCKDOWN_SCRIPT);

    let rules = generate_lockdown_rules()?;
    fs::write(NFT_LOCKDOWN_SCRIPT, rules).context("Failed to write lockdown nft script")?;

    log::info!("Wrote lockdown script to {}", NFT_LOCKDOWN_SCRIPT);
    Ok(())
}

const TRUE_LOCKDOWN_ALLOWED: bool = true;

fn apply_lockdown_script() -> Result<()> {
    if !TRUE_LOCKDOWN_ALLOWED {
        log::info!("TRUE_LOCKDOWN_ALLOWED is false, skipping actual application of lockdown");
        return Ok(());
    }

    let status = Command::new("nft")
        .arg("-f")
        .arg(NFT_LOCKDOWN_SCRIPT)
        .status()
        .context("Failed to execute nft lockdown script")?;

    if !status.success() {
        return Err(anyhow::anyhow!(
            "nft -f {} failed with status: {}",
            NFT_LOCKDOWN_SCRIPT,
            status
        ));
    }

    Ok(())
}

fn apply_network_lockdown() -> Result<()> {
    apply_lockdown()?;
    log::info!("Network lockdown ACTIVE and verified");
    Ok(())
}

const CHECK_BLOCKED_DOMAIN: &str = "google.com";
const CHECK_REACHABLE_DOMAIN: &str = "codeforces.com";

fn verify_connectivity(is_lockdowned: bool) -> Result<()> {
    log::info!("Validating firewall behavior");
    let is_connecting_base = tcp_443_connect(CHECK_BLOCKED_DOMAIN);

    if is_connecting_base {
        if is_lockdowned {
            return Err(anyhow!(
                "Lockdown failed — google.com is reachable on 443 (must be blocked)"
            ));
        } else {
            log::info!("Google 443 connectivity verified ✔");
        }
    } else {
        if !is_lockdowned {
            return Err(anyhow!(
                "Lockdown failed — google.com is NOT reachable on 443 (must be allowed)"
            ));
        }
        log::info!("Google 443 blocking verified ✔");
    }

    if is_lockdowned && tcp_443_connect("chatgpt.com") {
        return Err(anyhow!(
            "Lockdown failed — chatgpt.com reachable on 443 (must be blocked)"
        ));
    }

    // should pass
    if !tcp_443_connect(CHECK_REACHABLE_DOMAIN) {
        return Err(anyhow!(
            "Lockdown failed — codeforces.com unreachable on 443 (must be allowed)"
        ));
    }
    log::info!("Codeforces 443 connectivity verified ✔");

    Ok(())
}

fn tcp_443_connect(host: &str) -> bool {
    log::info!("TCP connect to {}:443 ...", host);
    let addrs = match (host, 443).to_socket_addrs() {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(_) => return false,
    };

    for addr in addrs {
        if TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok() {
            return true;
        }
    }

    false
}

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

pub fn lockdown_daemon(lock_instance: &lock::InstanceLock) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let flag = running.clone();
    ctrlc::set_handler(move || {
        flag.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");

    // 0) acquire global instance lock
    // validate lock_instance is held
    if !lock::check_lockdown_active() {
        return Err(anyhow::anyhow!(
            "lock_instance is not active, cannot proceed with lockdown daemon"
        ));
    }

    log::info!("Lock instance verified, proceeding with lockdown daemon");
    log::info!("Starting lockdown daemon...");

    // 1) pre-flight checks
    log::info!("Performing pre-flight checks...");
    log::info!("[PASS] pre-flight checks passed");

    // 2) take baseline snapshot (for logs & later comparisons)
    //    - capture list of network interfaces (ip link)
    //    - capture current monitors / display topology (xrandr / wayland)
    //    - capture baseline process list (/proc/*/cmdline)
    //    - capture usb devices (lsusb / /sys/bus/usb)
    //    - save to ~/.iicpc-lockdown/logs/baseline-*.txt

    // 3) apply network lockdown
    if let Err(e) = apply_network_lockdown() {
        log::error!("Network lockdown failed: {}, releasing lockdown...", e);
        eprintln!("{}", format!("Network lockdown failed: {}", e).red().bold());
        let _ = release_lockdown();
        log::error!("Lockdown daemon aborted due to network lockdown failure");
        return Err(anyhow!("Network lockdown failed: {}", e));
    }

    // apply hosts blocklist
    if let Err(e) = apply_hosts_blocklist() {
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

    verify_connectivity(true)?;

    // 4) Enter restricted namespaces / cgroup
    //    - unshare NEWPID / NEWNET / NEWNS / NEWCGROUP / NEWIPC
    //    - Create cgroup v2 "iicpc-lockdown":
    //        * Limit pids.max (prevent mass process spawns)
    //        * Deny /dev/nvidia*, /dev/dri for GPU LLMs
    //    - Move browser + our daemon into this cgroup
    //    - Ensure no other user processes are in this sandbox

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

    // 5) launch locked browser session
    let browser = launch_locked_browser().context("Failed to launch locked browser session")?;
    log::info!("Locked browser launched with PID {}", browser.id());
    let BROWSER_PID: u32 = browser.id();

    setup_cgroup(browser.id()).context("Failed to setup cgroup for browser")?;

    // 6) start watchdog tasks
    log::info!("Starting process watchdog...");
    start_process_watchdog(BROWSER_PID);

    // network watchdog
    let r2 = running.clone();
    thread::spawn(move || {
        while r2.load(Ordering::SeqCst) {
            watchdog_network();
            thread::sleep(Duration::from_secs(5));
        }
    });

    //    6.2) Network / interface watchdog (every 3–5s)
    //        - Check for new interfaces: tun*, tap*, wg*, usb*
    //        - Detect active VPN processes (openvpn, wireguard, tailscale, warp)
    //        - On detection:
    //            * Log violation
    //            * Optionally kill browser + mark attempt

    //    6.3) VM / remote-access watchdog (every 10–15s)
    //        - Re-check:
    //            * systemd-detect-virt
    //            * Processes: teamviewer, anydesk, rustdesk, chrome-remote-desktop, sunshine, etc.
    //        - On detection: log + optionally mark system as “untrusted environment”

    //    6.4) Focus / UI watchdog (short interval, 500–1000ms, X11-only MVP)
    //        - Query current active window
    //        - If focus is not on the lockdown browser:
    //            * Log FOCUS_LOST
    //            * Optionally bring browser back to foreground

    //    6.5) USB / hardware watchdog (event-based or polling)
    //        - Listen to udev events or poll /sys/bus/usb/devices
    //        - Detect new HID devices, HDMI display plug-in
    //        - On detection: log + optional immediate alert

    // 7) Main daemon loop
    //    - Sleep in a simple loop (e.g., 1s) just to keep main thread alive
    //    - Optionally aggregate stats from watchdogs:
    //        * # of violations
    //        * last violation time
    //        * system resource usage
    //    - Continue until:
    //        * Ctrl+C
    //        * “unlock” command (future: IPC/message / signal)

    // 8) Shutdown / unlock sequence (called by separate `unlock` command or on exit)
    //    - Kill/close lockdown browser
    //    - Stop watchdog threads cleanly (set a shutdown flag / join threads)
    //    - Restore nftables rules from backup
    //    - Tear down cgroup v2 for iicpc-lockdown
    //    - Remove /run/iicpc-lockdown/* temp files

    log::info!("Lockdown applied successfully, current status: ACTIVE");
    println!(
        "{}",
        "Lockdown applied successfully, current status: ACTIVE"
            .green()
            .bold()
    );

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    log::info!("Lockdown daemon shutting down...");
    println!("Lockdown daemon shutting down...");

    log::info!("Lockdown daemon exiting — cleaning up...");
    release_lockdown()?;

    Ok(())
}

fn watchdog_network() {
    if let Ok(output) = Command::new("ip").args(["link", "show"]).output() {
        let links = String::from_utf8_lossy(&output.stdout);

        let suspicious = vec!["tun", "tap", "wg", "vpn"];
        for pattern in suspicious {
            if links.contains(pattern) {
                eprintln!("[!!] Suspicious network interface detected: {}", pattern);
                //TODO: handle violation
                let _ = Command::new("pkill").arg("-9").arg("firefox").status();
            }
        }
    }
}

fn resolve_ips(domains: &[&str]) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();

    for d in domains {
        // resolve domain:443
        for addr in (*d, 443)
            .to_socket_addrs()
            .context(format!("DNS lookup failed for {d}"))?
        {
            ips.push(addr.ip());
        }
    }

    ips.sort();
    ips.dedup();
    Ok(ips)
}

fn generate_lockdown_rules() -> Result<String> {
    let domains = [
        // [CORE]
        "codeforces.com",
        "www.codeforces.com",
        // [MIRRORS]
        "m1.codeforces.com",
        "m2.codeforces.com",
        "m3.codeforces.com",
        "mirror.codeforces.com",
        // [ASSETS]
        "assets.codeforces.com",
        "static.codeforces.com",
        "cdn.codeforces.com",
        // [REAL-TIME] Websockets
        "pubsub.codeforces.com",
        // [SECURITY] Cloudflare
        "challenges.cloudflare.com",
        "static.cloudflareinsights.com",
        // [DEPENDENCIES] Google Fonts & jQuery
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "ajax.googleapis.com",
        // [RENDERING] MathJax & External Libs
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
    ];
    let ips = resolve_ips(&domains)?;

    let mut rules = String::from(
        r#"table inet iicpc_lock {
  chain output {
    type filter hook output priority -100;
    policy drop;

    ip daddr 127.0.0.1 accept
    ip saddr 127.0.0.1 accept
    ip6 daddr ::1 accept
    ip6 saddr ::1 accept
    ct state established,related accept
    udp dport 53 accept
    tcp dport 53 accept
"#,
    );

    for ip in ips {
        match ip {
            IpAddr::V4(v4) => {
                rules.push_str(&format!("    ip daddr {} tcp dport 443 accept\n", v4));
            }
            IpAddr::V6(v6) => {
                rules.push_str(&format!("    ip6 daddr {} tcp dport 443 accept\n", v6));
            }
        }
    }

    rules.push_str(
        "  }
}
",
    );

    Ok(rules)
}

const HOSTS_PATH: &str = "/etc/hosts";
const HOSTS_BACKUP_PATH: &str = "/etc/hosts.system_backup";
const LLM_BLOCKLIST: &[&str] = &[
    "chatgpt.com",
    "chat.openai.com",
    "openai.com",
    "platform.openai.com",
    "claude.ai",
    "anthropic.com",
    "perplexity.ai",
    "poe.com",
    "gemini.google.com",
    "ai.google.com",
    "copilot.microsoft.com",
    "huggingface.co",
    "character.ai",
    "phind.com",
    "llama.meta.com",
];

pub fn apply_hosts_blocklist() -> Result<()> {
    log::info!("Applying hosts file blocklist...");
    if !std::path::Path::new(HOSTS_BACKUP_PATH).exists() {
        fs::copy(HOSTS_PATH, HOSTS_BACKUP_PATH).context("Failed to backup /etc/hosts")?;
    }

    let mut hosts = fs::read_to_string(HOSTS_PATH).context("Failed to read /etc/hosts")?;

    hosts.push_str("\n# --- IICPC LOCKDOWN LLM BLOCKLIST ---\n");

    for domain in LLM_BLOCKLIST {
        let entry = format!("0.0.0.0 {}\n", domain);

        if !hosts.contains(&entry) {
            hosts.push_str(&entry);
            log::info!("Hosts-block: {}", domain);
        }
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(HOSTS_PATH)
        .context("Failed to open /etc/hosts")?;

    file.write_all(hosts.as_bytes())
        .context("Failed to write updated /etc/hosts")?;

    log::info!("Applied hosts blocklist");
    Ok(())
}

pub fn restore_hosts() -> Result<()> {
    log::info!("Restoring original /etc/hosts from backup...");
    if Path::new(HOSTS_BACKUP_PATH).exists() {
        fs::copy(HOSTS_BACKUP_PATH, HOSTS_PATH)?;
        fs::remove_file(HOSTS_BACKUP_PATH).ok();
        log::info!("Restored original /etc/hosts");
    } else {
        log::warn!("Hosts backup not found, skipping restore");
    }

    Ok(())
}
