#!/bin/bash
set -e

if [ "$(id -u)" -eq 0 ]; then
    echo "[ERROR] Do not run installer as root"
    exit 1
fi


log() {
    echo -e "\033[1;32m[INSTALLER]\033[0m $1"
}

log "Starting installation process..."

log "Checking for Rust toolchain..."
if ! command -v cargo &> /dev/null; then
    log "Rust not found. Do you want to install it? (y/n)"
    read -r response
    if [ "$response" != "y" ] || [ "$response" != "Y" ]; then
        log "Rust not installed. Exiting..."
        exit 1
    fi
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    log "Rust is already installed."
fi

log "Building and installing iicpc-lockdown from source..."
cargo install --path .

log "Verifying installation..."
if command -v iicpc-lockdown &> /dev/null; then
    BINARY_PATH=$(which iicpc-lockdown)
    log "Installation verified successfully."
    log "The binary is available at: $BINARY_PATH"

    SRC="$(command -v iicpc-lockdown)"
    DST="/usr/local/bin/iicpc-lockdown"

    if [ "$SRC" != "$DST" ]; then
        log "Copying binary to system path (You will see a prompt for sudo password)"
        sudo install -Dm755 "$SRC" "$DST"
    else
        log "Binary already installed at system path; skipping copy."
    fi
    
    log "Checking binary version..."
    if iicpc-lockdown --version; then
        log "Binary is executable and running."
    else
        log "Binary failed to run."
        exit 1
    fi

    log "You can run it using the command: iicpc-lockdown"
else
    log "Installation failed. Binary not found in PATH."
    exit 1
fi
