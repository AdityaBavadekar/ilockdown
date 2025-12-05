use chrono::Local;
use colored::*;
use env_logger::Builder;
use log::{LevelFilter, Record};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

static FILE_LOCK: Mutex<()> = Mutex::new(());

pub fn init() {
    let log_dir = log_directory();
    create_dir_all(&log_dir).expect("Failed to create log dir");

    let file_path = log_dir.join(today_file());

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
        .expect("Failed to open log file");

    let file = Mutex::new(log_file);

    Builder::new()
        .filter_level(LevelFilter::Info)
        .format(move |buf, record: &Record| {
            let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
            let pid = std::process::id();
            let level = record.level();

            let level_color = match level {
                log::Level::Error => level.to_string().red(),
                log::Level::Warn => level.to_string().yellow(),
                log::Level::Info => level.to_string().green(),
                log::Level::Debug => level.to_string().blue(),
                log::Level::Trace => level.to_string().white(),
            };

            let line = format!("[{:<5}][{}][pid={}]: {}\n", level, ts, pid, record.args());

            writeln!(
                buf,
                "[{:<5}][{}][pid={}]: {}",
                level_color,
                ts,
                pid,
                record.args()
            )?;

            {
                let _g = FILE_LOCK.lock().unwrap();
                let mut f = file.lock().unwrap();
                f.write_all(line.as_bytes()).unwrap();
            }

            Ok(())
        })
        .init();
}

pub fn active_log_file() -> PathBuf {
    log_directory().join(today_file())
}

fn log_directory() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".iicpc-lockdown/logs")
    } else {
        PathBuf::from("/tmp/iicpc-lockdown/logs")
    }
}

fn today_file() -> String {
    format!("log-{}.txt", Local::now().format("%Y-%m-%d"))
}
