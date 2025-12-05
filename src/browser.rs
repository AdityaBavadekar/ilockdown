use anyhow::{Context, Result, anyhow};
use nix::unistd::{Gid, Group, Uid, User, setgid, setuid};
use std::fs::{create_dir_all, set_permissions, write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};

const CF_URL: &str = "https://codeforces.com";
const PROXY_HOST: &str = "127.0.0.1";
const PROXY_PORT: u16 = 8080;

const BROWSERS: &[&str] = &[
    "/usr/bin/brave",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/microsoft-edge",
    "/usr/bin/firefox",
];

pub fn launch_locked_browser() -> Result<Child> {
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

fn resolve_desktop_user() -> Result<User> {
    // 1. Strong source: sudo invocation user
    if let Ok(name) = std::env::var("SUDO_USER") {
        if name != "root" {
            if let Some(user) = User::from_name(&name)? {
                return Ok(user);
            }
        }
    }

    // 2. Fallback: login shell user
    if let Ok(name) = std::env::var("USER") {
        if name != "root" {
            if let Some(user) = User::from_name(&name)? {
                return Ok(user);
            }
        }
    }

    // 3. Safety net: UID 1000 heuristic
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

    //  create clean home just for this browser instance
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
        .env("CHROME_CRASHPAD_DISABLED", "1")
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
            "--disable-crash-reporter",
            "--disable-features=Crashpad",
            // "--user-data-dir",
            // &profile_dir,
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

    // Always spawn Firefox via sudo -u to preserve DISPLAY + XAUTHORITY
    let mut cmd = Command::new("sudo");

    cmd.args([
        "-u",
        &user.name, // <—— critical
        "--preserve-env=DISPLAY,XAUTHORITY,DBUS_SESSION_BUS_ADDRESS",
        path,
        "--private-window",
        CF_URL,
    ]);
    cmd.spawn().context("Failed to launch Firefox via sudo")
}

fn launch_firefox2(path: &str) -> Result<Child> {
    let profile_path = "/tmp/iicpc-firefox-profile";

    create_dir_all(profile_path)?;

    let prefs = format!(
        r#"
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.startup.homepage", "{}");
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "{}");
user_pref("network.proxy.http_port", {});
user_pref("network.proxy.ssl", "{}");
user_pref("network.proxy.ssl_port", {});
"#,
        CF_URL, PROXY_HOST, PROXY_PORT, PROXY_HOST, PROXY_PORT
    );

    write(format!("{}/user.js", profile_path), prefs)?;

    let uid = Uid::current();
    let gid = Gid::current();

    Command::new(path)
        .uid(uid.as_raw())
        .gid(gid.as_raw())
        .args([
            "--profile",
            profile_path,
            "--no-remote",
            "--kiosk",
            "--private-window",
            CF_URL,
        ])
        .spawn()
        .context("Failed to launch Firefox")
}

