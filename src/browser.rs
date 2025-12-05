use anyhow::{Context, Result, anyhow};
use colored::*;
use nix::unistd::{Gid, Uid, User};
use std::fs::{create_dir_all, set_permissions};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};

use crate::config::{BROWSER_TARGETS_BASE_NAMES, BROWSER_TO_PATH, BROWSERS};
use crate::config::{CF_URL, PROXY_HOST, PROXY_PORT};
use crate::{focus};

pub fn launch_locked_browser(prefered_browser: Option<&str>) -> Result<Child> {
    let binary = BROWSER_TO_PATH
        .get(prefered_browser.unwrap_or_default())
        .cloned()
        .unwrap_or_default();

    log::info!("Killing existing browser instances...");
    focus::kill_all_matching(BROWSER_TARGETS_BASE_NAMES);

    if !binary.is_empty() && Path::new(binary).exists() {
        log::info!("Launching preferred kiosk browser: {}", binary);

        let child = if binary.ends_with("firefox") {
            launch_firefox(binary)?
        } else {
            launch_chromium(binary)?
        };
        log::info!("Browser started with PID {}", child.id());
        return Ok(child);
    }

    for bin in BROWSERS {
        if Path::new(bin).exists() {
            log::info!("Launching kiosk browser: {}", bin);

            let child = if bin.ends_with("firefox") {
                launch_firefox(bin)?
            } else {
                launch_chromium(bin)?
            };

            log::info!("Browser started with PID {}", child.id());
            return Ok(child);
        }
    }

    Err(anyhow!("No supported browser found"))
}

pub fn supervise_browser(mut child: Child) -> Result<()> {
    match child.wait() {
        Ok(status) => {
            log::warn!("Browser exited with status: {}", status);
        }
        Err(e) => {
            log::error!("Failed to wait for browser: {e}");
        }
    }
    log::info!("Browser process ended!");
    println!("Browser process ended!");
    log::info!("Browser process ended — initiating lockdown release");

    println!("\n\n\n");
    println!(
        "{}",
        "══════════════════════════════════════════════════════════"
            .bright_red()
            .bold()
    );

    println!(
        "{}",
        "!!!  LOCKDOWN SESSION TERMINATED  !!!".bright_red().bold()
    );

    println!(
        "{}",
        "══════════════════════════════════════════════════════════"
            .bright_red()
            .bold()
    );

    println!();

    println!("{}", format!("Browser process exited ").yellow().bold());

    println!();
    println!(
        "{}",
        "SYSTEM IS RELEASING LOCKDOWN NOW".bright_yellow().bold()
    );

    println!(
        "{}",
        "PLEASE DO NOT USE YOUR COMPUTER UNTIL CLEANUP IS COMPLETE"
            .bright_green()
            .bold()
    );

    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════"
            .bright_red()
            .bold()
    );

    println!("\n");

    Err(anyhow!("Browser process ended"))
}

fn resolve_desktop_user() -> Result<User> {
    // sudo invocation user
    if let Ok(name) = std::env::var("SUDO_USER") {
        if name != "root" {
            if let Some(user) = User::from_name(&name)? {
                return Ok(user);
            }
        }
    }

    // fallback: login shell user
    if let Ok(name) = std::env::var("USER") {
        if name != "root" {
            if let Some(user) = User::from_name(&name)? {
                return Ok(user);
            }
        }
    }

    // uid 1000 heuristic
    if let Some(user) = User::from_uid(nix::unistd::Uid::from_raw(1000))? {
        return Ok(user);
    }

    Err(anyhow::anyhow!("No non-root user could be resolved"))
}

fn launch_chromium(path: &str) -> Result<Child> {
    let proxy_arg = format!("--proxy-server=http://{}:{}", PROXY_HOST, PROXY_PORT);

    let cur_uid = Uid::current();
    let cur_gid = Gid::current();

    let user = resolve_desktop_user().context("Failed to resolve desktop user for Chromium")?;

    log::info!(
        "Launching Chromium as user '{}' (uid={}, gid={}) from uid={} gid={}",
        user.name,
        user.uid.as_raw(),
        user.gid.as_raw(),
        cur_uid.as_raw(),
        cur_gid.as_raw()
    );

    //create home just for this browser instance
    let base_home = format!("/tmp/chrome-home-{}", user.uid.as_raw());
    let profile_dir = format!("{}/profile", base_home);
    let crashpad_dir = format!("{}/.config/google-chrome/Crashpad", base_home);

    for dir in [
        format!("{}/.local", base_home),
        format!("{}/.cache", base_home),
        format!("{}/.pki", base_home),
        format!("{}/.config/google-chrome", base_home),
        crashpad_dir.clone(),
        profile_dir.clone(),
    ] {
        create_dir_all(&dir)?;
        nix::unistd::chown(
            Path::new(&dir),
            Some(Uid::from_raw(user.uid.as_raw())),
            Some(Gid::from_raw(user.gid.as_raw())),
        )?;
        set_permissions(&dir, PermissionsExt::from_mode(0o700))?;
    }

    let mut cmd = Command::new(path);

    // switch uid/gid only for the child
    if cur_uid.is_root() {
        cmd.uid(user.uid.as_raw()).gid(user.gid.as_raw());
    } else {
        log::warn!(
            "Not running as root (uid={}), will NOT change uid/gid for Chromium",
            cur_uid.as_raw()
        );
    }

    cmd.env("HOME", &base_home)
        // .env("CHROME_CRASHPAD_DISABLED", "1")
        .env("XDG_CONFIG_HOME", "/tmp/.chromium") // https://github.com/hardkoded/puppeteer-sharp/issues/2633
        .env("XDG_CACHE_HOME", "/tmp/.chromium")
        .args([
            // "--kiosk",
            "--no-first-run",
            "--disable-extensions",
            "--disable-dev-tools",
            "--disable-translate",
            "--disable-save-password-bubble",
            "--disable-infobars",
            "--no-default-browser-check",
            "--disable-sync",
            "--disable-gpu",
            "--disable-features=TranslateUI",
            // "--disable-crash-reporter",
            // "--disable-features=Crashpad",
            "--disable-breakpad",
            "--crashpad-handler",
            &format!("--database={}", crashpad_dir),
            "--user-data-dir",
            &profile_dir,
            &proxy_arg,
            "--app",
            CF_URL,
        ])
        .spawn()
        .context("Failed to start Chromium")
}

fn launch_firefox(path: &str) -> Result<Child> {
    let user = resolve_desktop_user().context("Failed to resolve desktop user for Firefox")?;

    log::info!(
        "Launching Firefox as '{}' (uid={}, gid={})",
        user.name,
        user.uid.as_raw(),
        user.gid.as_raw()
    );

    let mut cmd = Command::new("sudo");

    cmd.args([
        "-u",
        &user.name,
        "--preserve-env=DISPLAY,XAUTHORITY,DBUS_SESSION_BUS_ADDRESS",
        path,
        "--private-window",
        CF_URL,
    ]);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to launch Firefox via sudo")
}
