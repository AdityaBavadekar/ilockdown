pub fn start() -> Result<()> {
    if std::path::Path::new(LOCKFILE).exists() {
        anyhow::bail!(
            "Lockdown already active!\n\
             Run 'iicpc-lockdown unlock' to exit first."
        );
    }

    log::info!("Starting secure lockdown mode...");

    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("PANIC during lockdown: {}", panic_info);
        let _ = emergency_restore();
    }));

    Ok(())
}

const LOCKFILE: &str = "/run/iicpc-lockdown/active.lock";
