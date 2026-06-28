#!/usr/bin/env bash
set -euo pipefail

# IronWire — rust-install.sh
# Installs Rust toolchain via rustup if cargo is not found.

if command -v cargo &>/dev/null; then
    echo "[+] Rust already installed ($(cargo --version))"
    exit 0
fi

echo "[*] Installing Rust via rustup..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

echo "[+] Rust installed: $(cargo --version)"
