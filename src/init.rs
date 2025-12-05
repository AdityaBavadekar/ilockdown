use anyhow::{Result, anyhow};
use std::fs;
use sysinfo::System;

use crate::config::{LOG_DIR, RUNTIME_DIR};
use crate::logger;

pub fn run() -> Result<()> {
    log::info!("initializing...");
    log::info!("saving logs to {}", logger::active_log_file().display());
    log::info!("performing preflight checks...");
    preflight_checks()?;

    log::info!("creating necessary directories...");
    fs::create_dir_all(LOG_DIR)?;
    fs::create_dir_all(RUNTIME_DIR)?;
    Ok(())
}

fn preflight_checks() -> Result<()> {
    let os = System::name().unwrap_or("Unknown".into());
    let ver = System::os_version().unwrap_or("unk".into());

    let kernel_ver =
        System::kernel_version().ok_or_else(|| anyhow!("Failed to read kernel version"))?;

    log::info!("Detected OS: {} (version {})", os, ver);
    log::info!("Kernel version: {}", kernel_ver);
    log::info!(
        "Session: {}",
        std::env::var("XDG_SESSION_TYPE").unwrap_or("unknown".into())
    );

    ensure_kernel_support(&kernel_ver)?;
    ensure_nft_sni_support()?;

    Ok(())
}

fn ensure_kernel_support(kernel: &str) -> Result<()> {
    let bits: Vec<&str> = kernel.split('.').collect();

    if bits.len() < 2 {
        return Err(anyhow!("Invalid kernel version format: {}", kernel));
    }

    let major: u32 = bits[0]
        .parse()
        .map_err(|_| anyhow!("Invalid kernel major version"))?;
    let minor: u32 = bits[1]
        .parse()
        .map_err(|_| anyhow!("Invalid kernel minor version"))?;

    if major < 5 || (major == 5 && minor < 10) {
        Err(anyhow!("Kernel {} too old — require >= 5.10", kernel))
    } else {
        log::info!("Kernel version {} is supported", kernel);
        Ok(())
    }
}

fn ensure_nft_sni_support() -> Result<()> {
    let output = std::process::Command::new("nft")
        .arg("--version")
        .output()?;

    let version_str = String::from_utf8_lossy(&output.stdout);
    if version_str.contains("v1.") || version_str.contains("v0.9.") {
        let v = version_str
            .split(' ')
            .nth(1)
            .and_then(|s| s.strip_prefix('v'))
            .unwrap_or("0");
        if v < "0.9.8" {
            return Err(anyhow!("nftables too old — need ≥ 0.9.8 for TLS SNI"));
        }
    }
    log::info!("nftables version supports TLS SNI matching");
    Ok(())
}
