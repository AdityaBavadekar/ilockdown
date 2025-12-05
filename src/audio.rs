use std::fs;
use std::path::Path;
use std::process::Command;

// TODO: does not work in root

const STATE_FILE: &str = "/tmp/lockdown_audio_state";

#[derive(Clone, Copy)]
struct AudioState {
    sink_muted: bool,
    mic_muted: bool,
}

fn run_shell(cmd: &str) {
    let _ = Command::new("bash").arg("-lc").arg(cmd).status();
}

fn wpctl_get(target: &str) -> Option<bool> {
    let out = Command::new("bash")
        .arg("-lc")
        .arg(format!("wpctl get-volume {target}"))
        .output()
        .ok()?;

    let s = String::from_utf8(out.stdout).ok()?;
    Some(s.contains("MUTED"))
}

fn wpctl_set(target: &str, mute: bool) {
    run_shell(&format!(
        "wpctl set-mute {target} {}",
        if mute { 1 } else { 0 }
    ));
}

fn amixer_set_output(mute: bool) {
    run_shell(if mute {
        "amixer set Master mute"
    } else {
        "amixer set Master unmute"
    });
}

fn amixer_set_mic(mute: bool) {
    run_shell(if mute {
        "amixer set Capture nocap"
    } else {
        "amixer set Capture cap"
    });
}

fn has_wpctl() -> bool {
    Command::new("bash")
        .arg("-lc")
        .arg("command -v wpctl >/dev/null 2>&1")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn get_state() -> AudioState {
    if has_wpctl() {
        AudioState {
            sink_muted: wpctl_get("@DEFAULT_AUDIO_SINK@").unwrap_or(false),
            mic_muted: wpctl_get("@DEFAULT_AUDIO_SOURCE@").unwrap_or(false),
        }
    } else {
        AudioState {
            sink_muted: false,
            mic_muted: false,
        }
    }
}

fn set_state(s: AudioState) {
    if has_wpctl() {
        wpctl_set("@DEFAULT_AUDIO_SINK@", s.sink_muted);
        wpctl_set("@DEFAULT_AUDIO_SOURCE@", s.mic_muted);
    } else {
        amixer_set_output(s.sink_muted);
        amixer_set_mic(s.mic_muted);
    }
}

fn save_state(s: AudioState) {
    let _ = fs::write(
        STATE_FILE,
        format!("{} {}", s.sink_muted as u8, s.mic_muted as u8),
    );
}

fn load_state() -> Option<AudioState> {
    let data = fs::read_to_string(STATE_FILE).ok()?;
    let mut p = data.split_whitespace();
    let sink = p.next()?.parse::<u8>().ok()? != 0;
    let mic = p.next()?.parse::<u8>().ok()? != 0;
    Some(AudioState {
        sink_muted: sink,
        mic_muted: mic,
    })
}

pub fn mute_all() {
    if has_wpctl() {
        wpctl_set("@DEFAULT_AUDIO_SINK@", true);
        wpctl_set("@DEFAULT_AUDIO_SOURCE@", true);
    } else {
        amixer_set_output(true);
        amixer_set_mic(true);
    }
}

pub fn start_lockdown() {
    if !Path::new(STATE_FILE).exists() {
        save_state(get_state());
    }
    mute_all();
}

pub fn lockdown_tick() {
    mute_all();
}

pub fn end_lockdown() {
    if let Some(s) = load_state() {
        set_state(s);
        let _ = fs::remove_file(STATE_FILE);
    }
}
