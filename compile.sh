#!/usr/bin/env bash
set -euo pipefail

# IronWire — compile.sh
# Installs Rust (if missing) and builds the project in release mode.

if ! command -v cargo &>/dev/null; then
    echo "[*] Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

echo "[*] Building IronWire in release mode..."
cargo build --release

echo "[+] Done. Binary at: target/release/ironwire"
