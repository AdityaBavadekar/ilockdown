use crate::config::PROC_BASELINE_FILE;
use anyhow::Result;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::config::{BLACKLIST, CODE_EDITORS, INTERPRETERS_AND_COMPILERS};
use crate::watchdog;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct Process {
    pid: u32,
    name: String,
    cmdline: String,
    ppid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Baseline {
    processes: HashMap<String, ProcessPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProcessPattern {
    name: String,
    allow_children: bool,
    #[serde(default)]
    cmdline_patterns: Vec<String>,
}

const SYSTEM_CRITICAL: &[&str] = &[
    "systemd", "dbus", "kwin", "plasma", "Xwayland", "Xorg", "sddm", "gdm", "lightdm", "ssh",
    "login", "init",
];

const SAFE_CHILD_TYPES: &[&str] = &["bash", "sh", "zsh", "fish", "kitten"];

fn get_user_info() -> (String, String) {
    let user = env::var("SUDO_USER")
        .or_else(|_| env::var("USER"))
        .unwrap_or_else(|_| "root".to_string());

    let uid = env::var("SUDO_UID").unwrap_or_else(|_| {
        Command::new("id")
            .arg("-u")
            .arg(&user)
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "1000".to_string())
    });

    (user, uid)
}

fn get_user_processes(uid: &str) -> Vec<Process> {
    let mut processes = Vec::new();

    let output = Command::new("ps")
        .arg("-u")
        .arg(uid)
        .arg("-o")
        .arg("pid,ppid,comm,args")
        .arg("--no-headers")
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            for line in stdout.lines() {
                let parts: Vec<&str> = line.trim().split_whitespace().collect();
                if parts.len() >= 3 {
                    if let (Ok(pid), Ok(ppid)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>())
                    {
                        let name = parts[2].to_string();
                        let cmdline = parts[3..].join(" ");

                        if !cmdline.starts_with('[') {
                            processes.push(Process {
                                pid,
                                name,
                                cmdline,
                                ppid,
                            });
                        }
                    }
                }
            }
        }
    }

    processes
}

fn get_user_processes_2(_uid: &str) -> Vec<Process> {
    let mut processes = Vec::new();

    let output = Command::new("ps")
        .args(["-eo", "pid,ppid,comm,args", "--no-headers"])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.trim().split_whitespace().collect();
                if parts.len() >= 3 {
                    if let (Ok(pid), Ok(ppid)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>())
                    {
                        processes.push(Process {
                            pid,
                            ppid,
                            name: parts[2].to_string(),
                            cmdline: parts[3..].join(" "),
                        });
                    }
                }
            }
        }
    }

    processes
}

fn is_child_of(
    pid: u32,
    parent_pid: u32,
    tree: &HashMap<u32, Vec<u32>>,
    processes: &HashMap<u32, &Process>,
) -> bool {
    if let Some(process) = processes.get(&pid) {
        if process.ppid == parent_pid {
            return true;
        }
        if process.ppid != 0 {
            return is_child_of(process.ppid, parent_pid, tree, processes);
        }
    }
    false
}

fn capture_baseline() -> Baseline {
    info!("Capturing baseline of current processes...",);

    let (_, uid) = get_user_info();
    let processes = get_user_processes(&uid);

    let mut patterns = HashMap::new();

    for process in &processes {
        // skip if already exists
        if patterns.contains_key(&process.name) {
            continue;
        }

        let name = process.name.as_str();

        let is_forced_non_baseline = CODE_EDITORS.contains(&name)
            || INTERPRETERS_AND_COMPILERS.contains(&name)
            || BLACKLIST.contains(&name);
        if is_forced_non_baseline {
            info!("Skipping process in baseline: {}", name);
            continue;
        }

        // determine if this type of process should allow children
        let allow_children = is_parent_process(&process.name, &process.cmdline);

        let pattern = ProcessPattern {
            name: process.name.clone(),
            allow_children,
            cmdline_patterns: vec![],
        };

        patterns.insert(process.name.clone(), pattern);
        info!(
            "Baseline: {} (allow_children: {})",
            process.name, allow_children
        );
    }

    Baseline {
        processes: patterns,
    }
}

fn is_parent_process(name: &str, cmdline: &str) -> bool {
    // applications that spawn child processes
    let parent_apps = [
        "firefox",
        "chrome",
        "chromium",
        "brave",
        "kitty",
        "alacritty",
        "konsole",
        "gnome-terminal",
        "code",
        "vscode",
        "electron",
        "python",
        "node",
        "java",
    ];

    for app in &parent_apps {
        if name.contains(app) {
            return true;
        }
    }

    // check if cmdline indicates it's a parent process
    !cmdline.contains("-contentproc") && !cmdline.contains("--type=")
}

fn save_baseline(baseline: &Baseline) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(baseline)?;
    fs::write(PROC_BASELINE_FILE, json)?;
    info!("Baseline saved to {}", PROC_BASELINE_FILE);
    Ok(())
}

fn load_baseline() -> Result<Baseline, Box<dyn std::error::Error>> {
    let json = fs::read_to_string(PROC_BASELINE_FILE)?;
    let baseline: Baseline = serde_json::from_str(&json)?;
    Ok(baseline)
}

fn is_system_critical(process: &Process) -> bool {
    for crit in SYSTEM_CRITICAL {
        if process.name.contains(crit) || process.cmdline.contains(crit) {
            return true;
        }
    }
    false
}

fn is_allowed(
    process: &Process,
    baseline: &Baseline,
    tree: &HashMap<u32, Vec<u32>>,
    process_map: &HashMap<u32, &Process>,
) -> (bool, String) {
    // allow critical system processes
    if is_system_critical(process) {
        return (true, "SYSTEM".to_string());
    }

    // check if process name is in baseline
    if baseline.processes.contains_key(&process.name) {
        return (true, "BASELINE".to_string());
    }

    // check if it's a safe child type
    for safe_child in SAFE_CHILD_TYPES {
        if process.name == *safe_child {
            // only allow shells if they're children of allowed processes
            if let Some(parent) = process_map.get(&process.ppid) {
                if baseline.processes.contains_key(&parent.name) || is_system_critical(parent) {
                    return (true, "SAFE_CHILD".to_string());
                }
            }
        }
    }

    // check if it's a child of an allowed paren
    for (name, pattern) in &baseline.processes {
        if !pattern.allow_children {
            continue;
        }

        // skip systemd - don't allow all children of systemd
        if name == "systemd" {
            continue;
        }

        // find parent process with this name
        for (pid, p) in process_map {
            if p.name == *name && is_child_of(process.pid, *pid, tree, process_map) {
                return (true, format!("CHILD_OF_{}", name));
            }
        }
    }

    (false, "NOT_IN_BASELINE".to_string())
}

const COMMAND_KILL_DISABLED: bool = false;

fn kill_process(pid: u32, name: &str) -> bool {
    info!("[TERMINATING]: {} (PID: {})", name, pid);

    if COMMAND_KILL_DISABLED {
        return false;
    }

    let result = Command::new("kill").arg("-9").arg(pid.to_string()).output();

    if let Ok(output) = result {
        if output.status.success() {
            return true;
        }
    }

    thread::sleep(Duration::from_millis(200));

    let result = Command::new("kill").arg("-9").arg(pid.to_string()).output();

    if let Ok(output) = result {
        output.status.success()
    } else {
        false
    }
}

pub fn init_monitor() {
    info!("INIT MODE - Capturing baseline",);
    let baseline = capture_baseline();

    match save_baseline(&baseline) {
        Ok(_) => {
            info!("Baseline saved successfully!");
            info!("Captured {} unique processes", baseline.processes.len());
            info!("Run without 'init' to start monitoring");
            return;
        }
        Err(e) => {
            info!("ERROR: Failed to save baseline: {}", e);
            std::process::exit(1);
        }
    }
}

fn is_descendant_of_any(pid: u32, roots: &[u32], tree: &HashMap<u32, Vec<u32>>) -> bool {
    let mut stack = roots.to_vec();
    let mut visited = std::collections::HashSet::new();

    while let Some(cur) = stack.pop() {
        if cur == pid {
            return true;
        }

        if !visited.insert(cur) {
            continue;
        }

        if let Some(children) = tree.get(&cur) {
            stack.extend(children.iter().copied());
        }
    }

    false
}

fn get_executable_path(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/exe", pid);
    if let Ok(exe_path) = fs::read_link(path) {
        return Some(exe_path.to_string_lossy().to_string());
    }
    None
}

pub fn kill_all_matching(names: &[&str]) {
    let (_, uid) = get_user_info();
    let processes = get_user_processes(&uid);

    let self_pid = std::process::id();
    for process in processes {
        if process.pid == self_pid {
            continue; // don't suicide
        }

        let executable_path = get_executable_path(process.pid);
        let is_match = names.iter().any(|name| {
            process.name.contains(name)
                || process.cmdline.contains(name)
                || executable_path.as_deref().is_some_and(|p| p.contains(name))
        });

        if is_match {
            info!(
                "[KILLING]: {} (PID: {}) (bin: {})",
                process.name,
                process.pid,
                executable_path.unwrap_or_default()
            );
            kill_process(process.pid, &process.name);
        }
    }
}

fn collect_descendants(root: u32, tree: &HashMap<u32, Vec<u32>>, out: &mut HashSet<u32>) {
    if !out.insert(root) {
        return;
    }

    if let Some(children) = tree.get(&root) {
        for &child in children {
            collect_descendants(child, tree, out);
        }
    }
}

fn build_process_tree(processes: &[Process]) -> HashMap<u32, Vec<u32>> {
    let mut map = HashMap::new();

    for p in processes {
        map.entry(p.ppid).or_insert_with(Vec::new).push(p.pid);
    }

    map
}

const ALLOWED_BINARIES: &[&str] = &[
    "/usr/bin/obs", // TODO: only for when recording demo
    "/home/adi/Downloads/icpc_obs_linux/obshash",
    "/usr/bin/obs-ffmpeg-mux",
];

pub fn main(allowed_pids: &Option<Vec<u32>>) {
    info!("Starting process lockdown monitor",);

    let (user, uid) = get_user_info();
    info!("Monitoring user: {} (UID: {})", user, uid);

    // Load baseline
    let baseline = match load_baseline() {
        Ok(b) => {
            info!("Loaded baseline with {} processes", b.processes.len());
            b
        }
        Err(e) => {
            info!("ERROR: Could not load baseline: {}", e);
            info!("Run with 'init' first: sudo ./program init",);
            std::process::exit(1);
        }
    };

    info!("Starting enforcement...");

    let mut known_processes: HashMap<u32, Process> = HashMap::new();
    let target_browser_pid = allowed_pids
        .as_ref()
        .and_then(|pids| pids.first().copied())
        .unwrap_or(0);

    info!("Firefox started at PID {}", target_browser_pid);

    let mut seen_root = false;
    let root_pid = target_browser_pid;
    return loop {
        let current_processes = get_user_processes(&uid);
        // let tree = get_process_tree(&current_processes);
        let process_map: HashMap<u32, &Process> =
            current_processes.iter().map(|p| (p.pid, p)).collect();
        let mut current_pids = HashSet::new();

        let processes = get_user_processes_2(&uid);
        let exists = processes.iter().any(|p| p.pid == root_pid);
        // mark observed
        if exists {
            seen_root = true;
        }

        if seen_root && !exists {
            log::warn!(
                "Watched process {} exited after being observed – stopping watcher",
                root_pid
            );
            break;
        }

        let tree = build_process_tree(&processes);
        let mut all = HashSet::new();
        collect_descendants(root_pid, &tree, &mut all);

        for process in &current_processes {
            current_pids.insert(process.pid);

            if process.pid == std::process::id() {
                continue;
            }

            // skip allowed browser tree
            if let Some(allowed_list) = &allowed_pids {
                if is_descendant_of_any(process.pid, allowed_list, &tree) {
                    known_processes.insert(process.pid, process.clone());
                    continue;
                }
            }

            if !known_processes.contains_key(&process.pid) {
                let (allowed, reason) = is_allowed(process, &baseline, &tree, &process_map);

                let executable_path = get_executable_path(process.pid);
                let exe_str = executable_path.as_deref().unwrap_or("");
                if let Some(path) = &executable_path {
                    if ALLOWED_BINARIES.iter().any(|b| path == b) {
                        known_processes.insert(process.pid, process.clone());
                        log::info!(
                            "[ALLOWED:BINARY_WHITELIST] {} (PID: {}) (bin: {})",
                            process.name,
                            process.pid,
                            exe_str
                        );
                        continue;
                    }
                }

                if !allowed {
                    if let Some(allowed_list) = &allowed_pids {
                        if is_descendant_of_any(process.pid, allowed_list, &tree) {
                            info!(
                                "[ALLOWED:WHITELIST_TREE] {} (PID: {})",
                                process.name, process.pid
                            );
                            known_processes.insert(process.pid, process.clone());
                            continue;
                        }
                    }

                    // kill services like docker, tor, etc.
                    if let Some(service) = watchdog::get_service_for_pid(process.pid) {
                        log::warn!(
                            "Process PID {} is managed by systemd service: {}",
                            process.pid,
                            service
                        );
                        let _ = watchdog::disable_and_record_service(&service);
                        log::warn!("Disabled systemd service: {}", service);
                    }

                    info!(
                        "[BLOCKED:{}] {} (PID: {}) - {} (bin: {})",
                        reason, process.name, process.pid, process.cmdline, exe_str
                    );
                    kill_process(process.pid, &process.name);
                }

                known_processes.insert(process.pid, process.clone());
            }
        }

        known_processes.retain(|pid, _| current_pids.contains(pid));
        thread::sleep(Duration::from_millis(500));
    };
}
