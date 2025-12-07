use anyhow::{Context, Result};
use chrono::Local;
use colored::*;
use libc::{SIGKILL, kill};
use nix::unistd::Uid;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::{fs, process::Command, thread};
use uuid::Uuid;

use crate::config::{
    BLACKLIST, BLOCK_CODE_EDITORS, BLOCK_INTERPRETERS_AND_COMPILERS, CODE_EDITORS,
    INTERPRETERS_AND_COMPILERS, SCAN_INTERVAL, TEST_MODE,
};
use crate::focus;

#[derive(Serialize)]
struct ScanFinding {
    pub pid: u32,
    pub rule: String,
    pub cmdline: String,
}

#[derive(Serialize)]
struct ScanReport {
    pub timestamp: String,
    pub hostname: String,
    pub kernel: String,
    pub scan_duration_secs: u64,
    pub username: String,
    pub contest_id: Option<String>,
    pub session_id: String,
    pub cli_version: String,
    pub findings: Vec<ScanFinding>,
}

pub fn start_process_watchdog(browser_pid: u32) {
    let allowed_pids: Option<Vec<u32>> = Some(vec![browser_pid, std::process::id()]);

    thread::spawn(move || {
        log::info!("Process watchdog started");
        focus::main(&allowed_pids);
    });
}

pub fn scan_only(kill_on_detect: bool) -> Result<()> {
    log::info!("Running watchdog scan-only mode");
    let mut found = false;
    let mut flag_count = 0;
    let mut results = Vec::new();
    iter_processes(Some(&mut |proc_info: &ProcInfo| {
        found = true;
        flag_count += 1;
        log::info!(
            "Flagged process => PID {} CMD: {}",
            proc_info.pid,
            proc_info.clean_cmdline
        );
        println!(
            "Flagged process => PID {} CMD: {}",
            proc_info.pid, proc_info.clean_cmdline
        );
        results.push(ScanFinding {
            pid: proc_info.pid,
            rule: proc_info.binary.clone(),
            cmdline: proc_info.clean_cmdline.clone(),
        });

        if kill_on_detect && !TEST_MODE {
            if let Some(service) = get_service_for_pid(proc_info.pid) {
                log::warn!(
                    "Process PID {} is managed by systemd service: {}",
                    proc_info.pid,
                    service
                );
                let _ = disable_and_record_service(&service);
                log::warn!("Disabled systemd service: {}", service);
            }
            handle_violation(
                proc_info.pid,
                &proc_info.binary,
                &proc_info.clean_cmdline,
                0,
            )
            .unwrap_or_else(|e| {
                log::error!("Error handling violation for PID {}: {}", proc_info.pid, e)
            });
        }
    }))?;

    if !found {
        println!("No blacklisted processes running");
        log::info!("No blacklisted processes running");
    } else {
        println!("Total flagged processes: {}", flag_count);
        log::info!("Total flagged processes: {}", flag_count);
    }
    build_report(results)?;

    Ok(())
}

#[derive(Debug)]
struct ProcInfo {
    pid: u32,
    binary: String,
    args: Vec<String>,
    clean_cmdline: String,
}

fn iter_processes(mut on_match: Option<&mut dyn FnMut(&ProcInfo)>) -> Result<Vec<ProcInfo>> {
    // log::info!("Itertion");
    let mut list = Vec::new();

    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };

        let pid_str = entry.file_name().to_string_lossy().into_owned();
        if !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let Ok(cmdline) = fs::read_to_string(cmdline_path) else {
            continue;
        };

        if cmdline.is_empty() {
            continue;
        }

        let parts: Vec<String> = cmdline
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase())
            .collect();

        if parts.is_empty() {
            continue;
        }

        let binary = Path::new(&parts[0])
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        // let realpath = get_real_exe_path(pid);
        let proc_info = ProcInfo {
            pid,
            binary,
            args: parts[1..].to_vec(),
            clean_cmdline: parts.join(" "),
        };

        if let Some(_rule) = match_blacklist(&proc_info) {
            if let Some(callback) = on_match.as_mut() {
                callback(&proc_info);
            }
            list.push(proc_info);
        }
    }

    Ok(list)
}

fn kill_tree(root_pid: u32) -> std::io::Result<()> {
    let pgid = -(root_pid as i32);

    let res = unsafe { kill(pgid as i32, SIGKILL) };

    if res == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub fn get_service_for_pid(pid: u32) -> Option<String> {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let data = std::fs::read_to_string(cgroup_path).ok()?;

    for line in data.lines() {
        // take the last path component
        if let Some(last) = line.split('/').last() {
            if last.ends_with(".service") {
                return Some(last.to_string());
            }
        }
    }

    None
}

fn match_blacklist(proc: &ProcInfo) -> Option<String> {
    for rule in BLACKLIST {
        let rule = rule.to_lowercase();
        if proc.binary == rule {
            return Some(rule);
        }
        if proc
            .args
            .iter()
            .any(|arg| arg == &rule || arg.ends_with(&format!("/{}", rule)))
        {
            return Some(rule);
        }

        // optional fallback
        // if proc.clean_cmdline.contains(&rule) {
        //     return Some(rule);
        // }
    }

    if BLOCK_CODE_EDITORS {
        for editor in CODE_EDITORS {
            let editor = editor.to_lowercase();
            if proc.binary == editor {
                return Some(editor);
            }
            if proc
                .args
                .iter()
                .any(|arg| arg == &editor || arg.ends_with(&format!("/{}", editor)))
            {
                return Some(editor);
            }
        }
    }

    if BLOCK_INTERPRETERS_AND_COMPILERS {
        for interp in INTERPRETERS_AND_COMPILERS {
            let interp = interp.to_lowercase();
            if proc.binary == interp {
                return Some(interp);
            }
            if proc
                .args
                .iter()
                .any(|arg| arg == &interp || arg.ends_with(&format!("/{}", interp)))
            {
                return Some(interp);
            }
        }
    }

    None
}

const BLOCKED_SERVICES_FILE: &str = "/var/lib/iicpc/blocked_services.json";

pub fn disable_and_record_service(service: &str) -> Result<()> {
    const ALLOWED_SERVICES: &[&str] = &[
        "systemd-journald.service",
        "systemd-logind.service",
        "dbus.service",
        "sshd.service",
        "networking.service",
        "NetworkManager.service",
        "cron.service",
        "rsyslog.service",
        "firefox",
        "chromium",
        "google-chrome",
        "brave-browser",
        "microsoft-edge",
    ];

    if ALLOWED_SERVICES.contains(&service) {
        log::info!("Service {} is in allowed list, skipping disable.", service);
        return Ok(());
    }

    log::info!("Blocking service: {}", service);

    // stop service
    std::process::Command::new("systemctl")
        .args(["stop", service])
        .status()?;

    // mask service
    std::process::Command::new("systemctl")
        .args(["mask", service])
        .status()?;

    // load or create journal
    let mut journal = if Path::new(BLOCKED_SERVICES_FILE).exists() {
        let raw = fs::read_to_string(BLOCKED_SERVICES_FILE)?;
        serde_json::from_str::<BlockedServices>(&raw)?
    } else {
        BlockedServices {
            timestamp: chrono::Local::now().to_rfc3339(),
            services: Vec::new(),
        }
    };

    // avoid duplicates
    if !journal.services.contains(&service.to_string()) {
        journal.services.push(service.to_string());
    }

    // save journal
    fs::create_dir_all("/var/lib/iicpc")?;
    fs::write(
        BLOCKED_SERVICES_FILE,
        serde_json::to_string_pretty(&journal)?,
    )?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct BlockedServices {
    timestamp: String,
    services: Vec<String>,
}

pub fn restore_blocked_services() -> Result<()> {
    use std::{fs, path::Path};

    if !Path::new(BLOCKED_SERVICES_FILE).exists() {
        log::info!("No blocked services to restore");
        return Ok(());
    }

    let raw = fs::read_to_string(BLOCKED_SERVICES_FILE)?;
    let journal: BlockedServices = serde_json::from_str(&raw)?;

    for svc in &journal.services {
        log::info!("Restoring {}", svc);

        // unmask
        std::process::Command::new("systemctl")
            .args(["unmask", svc])
            .status()?;

        // re-enable
        std::process::Command::new("systemctl")
            .args(["enable", svc])
            .status()?;

        // restart
        std::process::Command::new("systemctl")
            .args(["start", svc])
            .status()?;
    }

    fs::remove_file(BLOCKED_SERVICES_FILE)?;

    Ok(())
}

fn handle_violation(pid: u32, binary: &str, cmdline: &str, browser_pid: u32) -> Result<()> {
    log::warn!("[FORBIDDEN] => [PID={}] CMD: {}", pid, cmdline);
    println!(
        "{} => CMD: {}",
        "[FORBIDDEN]".red().bold(),
        binary.red().bold()
    );

    if !TEST_MODE {
        // check is not self or browser
        let self_pid = std::process::id();
        if pid == self_pid || pid == browser_pid {
            return Ok(());
        }

        log::warn!("Terminating offending process (PID {})", pid);
        kill_process(pid);

        // log::warn!("Terminating exam browser (PID {})", browser_pid);
        // kill_process(browser_pid);

        show_violation_screen();

        // exit daemon
        // log::warn!("Exiting lockdown daemon due to cheating detection.");
        // std::process::exit(1);
    }

    let _ = kill_tree(pid);

    Ok(())
}

fn show_violation_screen() {}

fn kill_process(pid: u32) {
    let result = Command::new("kill").arg("-9").arg(pid.to_string()).status();

    match result {
        Ok(s) if s.success() => {
            log::info!("Killed PID {}", pid);
        }
        _ => {
            log::error!("Failed to kill PID {}", pid);
        }
    }
}

fn write_report(report: &ScanReport) -> Result<()> {
    let ts = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let filename = format!("/tmp/IICPC_SCAN_REPORT_{}.json", ts);
    let json = serde_json::to_string_pretty(report)?;
    let mut f = File::create(&filename).context("Failed to create report file")?;

    f.write_all(json.as_bytes())?;

    println!("\nScan report saved to:");
    println!("   {}", filename);

    Ok(())
}

fn build_report(findings: Vec<ScanFinding>) -> Result<()> {
    use sysinfo::System;
    let timestamp = chrono::Local::now().to_rfc3339();
    let hostname = hostname::get()?.to_string_lossy().to_string();
    let kernel = System::kernel_version().unwrap_or("unknown".into());
    let uid = Uid::current();
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| format!("uid:{}", uid.as_raw()));
    let session_id = Uuid::new_v4().to_string();
    let cli_version = env!("CARGO_PKG_VERSION").to_string();

    let report = ScanReport {
        timestamp,
        hostname,
        kernel,
        scan_duration_secs: SCAN_INTERVAL.as_secs(),
        username,
        contest_id: None,
        session_id,
        cli_version,
        findings,
    };

    write_report(&report)?;
    Ok(())
}
