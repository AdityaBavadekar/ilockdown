use anyhow::{Result, anyhow};
use std::io::{self, Write};
use std::process;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::time;

static EXPECTED_WINDOW: OnceLock<Mutex<ExpectedWindow>> = OnceLock::new();

#[derive(Default)]
struct ExpectedWindow {
    id: u64,
    title: String,
}

#[derive(Debug)]
struct WindowInfo {
    id: String,
    desktop: i32,
    hostname: String,
    title: String,
}

pub fn set_expected_window(wid: u64, title: String) {
    let state = EXPECTED_WINDOW.get_or_init(|| Mutex::new(ExpectedWindow::default()));
    let mut guard = state.lock().unwrap();

    guard.id = wid;
    guard.title = title;
}

fn set_terminal_title(title: &str) {
    print!("\x1b]0;{}\x07", title);
    io::stdout().flush().unwrap();
}

pub async fn start_focus_monitor() {
    log::info!("Starting focus monitor...");

    loop {
        time::sleep(Duration::from_millis(1000)).await;

        match active_window_title() {
            Ok(current_title) => {
                let expected = EXPECTED_WINDOW
                    .get_or_init(|| Mutex::new(ExpectedWindow::default()))
                    .lock()
                    .unwrap();

                log::info!(
                    "Focus check: expected title '{}', current title '{}'",
                    expected.title,
                    current_title
                );

                // Only check if we have an expected title set
                if !expected.title.is_empty() && expected.title != current_title {
                    log::error!(
                        "FOCUS CHEAT: Expected window '{}', but got '{}'",
                        expected.title,
                        current_title
                    );
                    trigger_cheating_shutdown("Another window gained focus");
                }
            }
            Err(e) => log::warn!("Window detection failed: {:?}", e),
        }
    }
}

fn active_window_title() -> Result<String> {
    // Try wmctrl first (works on X11 and Wayland with XWayland)
    if let Ok(title) = try_wmctrl() {
        return Ok(title);
    }

    // Try xdotool (X11 / XWayland)
    if let Ok(title) = try_xdotool() {
        return Ok(title);
    }

    // Try GNOME Wayland
    if let Ok(title) = try_gnome_wayland() {
        return Ok(title);
    }

    // Try KDE Plasma Wayland
    if let Ok(title) = try_kde_wayland() {
        return Ok(title);
    }

    // Try Hyprland
    if let Ok(title) = try_hyprland() {
        return Ok(title);
    }

    // Try Sway
    if let Ok(title) = try_sway() {
        return Ok(title);
    }

    Err(anyhow!("No working window detection method found"))
}

// New function to list all windows from all desktops
pub fn list_all_windows() -> Result<Vec<WindowInfo>> {
    let output = Command::new("wmctrl").args(["-l"]).output()?;

    if !output.status.success() {
        return Err(anyhow!("wmctrl -l failed"));
    }

    let wmctrl_str = String::from_utf8_lossy(&output.stdout);
    let mut windows = Vec::new();

    // Parse each line
    // Format: 0x03c00006  0  hostname  Window Title Here
    //         ^win_id     ^desktop ^hostname ^title...
    for line in wmctrl_str.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() >= 4 {
            let window = WindowInfo {
                id: parts[0].to_string(),
                desktop: parts[1].parse().unwrap_or(-1),
                hostname: parts[2].to_string(),
                title: parts[3..].join(" "),
            };
            windows.push(window);
        }
    }

    Ok(windows)
}

// New function to get desktop names
pub fn get_desktop_names() -> Result<Vec<String>> {
    let output = Command::new("wmctrl").args(["-d"]).output()?;

    if !output.status.success() {
        return Err(anyhow!("wmctrl -d failed"));
    }

    let wmctrl_str = String::from_utf8_lossy(&output.stdout);
    let mut desktops = Vec::new();

    // Parse desktop info
    // Format: 0  * DG: 1920x1200  VP: 0,0  WA: 0,24 1920x1176  Desktop 1
    for line in wmctrl_str.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 9 {
            // Desktop name is everything after WA field
            let desktop_name = parts[8..].join(" ");
            desktops.push(desktop_name);
        }
    }

    Ok(desktops)
}

// New function to print all windows grouped by desktop
pub fn print_all_windows() -> Result<()> {
    log::info!("=== All Windows Across All Desktops ===");

    let desktops = get_desktop_names()?;
    let windows = list_all_windows()?;

    // Group windows by desktop
    for (desktop_num, desktop_name) in desktops.iter().enumerate() {
        let desktop_windows: Vec<&WindowInfo> = windows
            .iter()
            .filter(|w| w.desktop == desktop_num as i32)
            .collect();

        log::info!(
            "Desktop {}: {} ({} windows)",
            desktop_num,
            desktop_name,
            desktop_windows.len()
        );

        for window in desktop_windows {
            log::info!("  [{}] {}", window.id, window.title);
        }
    }

    // Show windows on all desktops (desktop = -1)
    let all_desktop_windows: Vec<&WindowInfo> =
        windows.iter().filter(|w| w.desktop == -1).collect();

    if !all_desktop_windows.is_empty() {
        log::info!("Windows on All Desktops:");
        for window in all_desktop_windows {
            log::info!("  [{}] {}", window.id, window.title);
        }
    }

    log::info!("Total windows: {}", windows.len());

    Ok(())
}

fn try_wmctrl() -> Result<String> {
    // Get active window ID first
    let xprop_out = Command::new("xprop")
        .args(["-root", "_NET_ACTIVE_WINDOW"])
        .output()?;

    if !xprop_out.status.success() {
        return Err(anyhow!("xprop failed"));
    }

    let xprop_str = String::from_utf8_lossy(&xprop_out.stdout);
    // Parse format: _NET_ACTIVE_WINDOW(WINDOW): window id # 0x3c00006
    let active_id = xprop_str
        .split_whitespace()
        .last()
        .ok_or_else(|| anyhow!("no window id in xprop output"))?;

    // Get all windows from wmctrl
    let wmctrl_out = Command::new("wmctrl").args(["-l"]).output()?;

    if !wmctrl_out.status.success() {
        return Err(anyhow!("wmctrl failed"));
    }

    let wmctrl_str = String::from_utf8_lossy(&wmctrl_out.stdout);

    // Find the active window in wmctrl output
    // Format: 0x03c00006  0  hostname  Window Title Here
    //         ^win_id     ^desktop ^hostname ^title...
    for line in wmctrl_str.lines() {
        if line.starts_with(active_id) {
            // Split by whitespace and skip first 3 fields (win_id, desktop, hostname)
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                // Join everything from index 3 onwards as the title
                let title = parts[3..].join(" ");
                if !title.is_empty() {
                    return Ok(title);
                }
            }
        }
    }

    Err(anyhow!("active window not found in wmctrl output"))
}

fn try_xdotool() -> Result<String> {
    if std::env::var("DISPLAY").is_err() {
        return Err(anyhow!("DISPLAY not set"));
    }

    let out = Command::new("xdotool").arg("getactivewindow").output()?;

    if !out.status.success() {
        return Err(anyhow!("xdotool getactivewindow failed"));
    }

    let wid = std::str::from_utf8(&out.stdout)?.trim();
    if wid.is_empty() || wid == "0" {
        return Err(anyhow!("no active window"));
    }

    let title_out = Command::new("xdotool")
        .args(["getwindowname", wid])
        .output()?;

    if !title_out.status.success() {
        return Err(anyhow!("xdotool getwindowname failed"));
    }

    let title = String::from_utf8_lossy(&title_out.stdout)
        .trim()
        .to_string();

    if title.is_empty() {
        return Err(anyhow!("empty window title"));
    }

    Ok(title)
}

fn try_gnome_wayland() -> Result<String> {
    if std::env::var("WAYLAND_DISPLAY").is_err() {
        return Err(anyhow!("not on Wayland"));
    }

    let output = Command::new("busctl")
        .args([
            "--user",
            "call",
            "org.gnome.Shell",
            "/org/gnome/Shell",
            "org.gnome.Shell",
            "Eval",
            "s",
            "global.get_window_actors?.().find(a => a.meta_window?.has_focus?.())?.meta_window.get_title?.() || ''",
        ])
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("busctl failed"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(line) = stdout.lines().nth(1) {
        let title = line.trim().trim_matches('"');
        if !title.is_empty() && title != "null" {
            return Ok(title.to_string());
        }
    }

    Err(anyhow!("no GNOME window title found"))
}

fn try_kde_wayland() -> Result<String> {
    if std::env::var("WAYLAND_DISPLAY").is_err() {
        return Err(anyhow!("not on Wayland"));
    }

    // First check if KWin is available
    let check = Command::new("qdbus")
        .args(["org.kde.KWin", "/KWin"])
        .output()?;

    if !check.status.success() {
        return Err(anyhow!("KWin not available"));
    }

    // Try to get active window caption (title)
    // KDE exposes window info through various methods, try them in order

    // Method 1: Try getting window list and find active one
    let methods = [
        "org.kde.KWin.activeWindowCaption",
        "org.kde.KWin.activeWindowTitle",
    ];

    for method in &methods {
        if let Ok(output) = Command::new("qdbus")
            .args(["org.kde.KWin", "/KWin", method])
            .output()
        {
            if output.status.success() {
                let title = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !title.is_empty() && !title.contains("Error") {
                    return Ok(title);
                }
            }
        }
    }

    Err(anyhow!("no KDE window title method worked"))
}

fn try_hyprland() -> Result<String> {
    if std::env::var("HYPRLAND_INSTANCE_SIGNATURE").is_err() {
        return Err(anyhow!("not on Hyprland"));
    }

    let output = Command::new("hyprctl")
        .args(["activewindow", "-j"])
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("hyprctl failed"));
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let title = json["title"]
        .as_str()
        .ok_or_else(|| anyhow!("no title in hyprctl output"))?
        .to_string();

    if title.is_empty() {
        return Err(anyhow!("empty title"));
    }

    Ok(title)
}

fn try_sway() -> Result<String> {
    let output = Command::new("swaymsg").args(["-t", "get_tree"]).output()?;

    if !output.status.success() {
        return Err(anyhow!("swaymsg failed"));
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    // Recursively search for focused window
    fn find_focused(node: &serde_json::Value) -> Option<String> {
        if node["focused"].as_bool() == Some(true) {
            if let Some(name) = node["name"].as_str() {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }

        if let Some(nodes) = node["nodes"].as_array() {
            for child in nodes {
                if let Some(title) = find_focused(child) {
                    return Some(title);
                }
            }
        }

        if let Some(floating) = node["floating_nodes"].as_array() {
            for child in floating {
                if let Some(title) = find_focused(child) {
                    return Some(title);
                }
            }
        }

        None
    }

    find_focused(&json).ok_or_else(|| anyhow!("no focused window in sway tree"))
}

fn trigger_cheating_shutdown(reason: &str) {
    let _ = Command::new("notify-send")
        .args(["--urgency=critical", "CHEATING DETECTED", reason])
        .spawn();

    // Full red screen (X11 only)
    let _ = Command::new("xsetroot")
        .arg("-solid")
        .arg("#ff0000")
        .spawn();

    log::error!("TERMINATING SESSION: {reason}");
    process::exit(1);
}

