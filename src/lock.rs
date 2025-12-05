use anyhow::{Context, Result};
use nix::fcntl::{FlockArg, flock};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use crate::config::{LOCK_FILE, RUNTIME_DIR};

pub struct InstanceLock {
    _file: std::fs::File,
    path: PathBuf,
}

impl InstanceLock {
    pub fn acquire() -> Result<Self> {
        create_dir_all(RUNTIME_DIR).context(format!(
            "Failed to create runtime directory ({})",
            RUNTIME_DIR
        ))?;

        let path = PathBuf::from(LOCK_FILE);

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)
            .context("Failed to open lock file")?;

        flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock)
            .context("Another iicpc-lockdown instance is already running")?;

        let pid = std::process::id();
        file.set_len(0)?;
        writeln!(&file, "{}", pid)?;
        file.flush()?;

        log::info!("Acquired lock: {} (pid={})", path.display(), pid);

        Ok(Self { _file: file, path })
    }
}

pub fn check_lockdown_active() -> bool {
    let file = match OpenOptions::new().read(true).write(true).open(LOCK_FILE) {
        Ok(f) => f,
        Err(_) => return false,
    };

    flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock).is_err()
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        log::info!("Releasing lock {}", self.path.display());
        let _ = std::fs::remove_file(&self.path);
    }
}
