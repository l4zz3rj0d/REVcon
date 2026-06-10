#!/usr/bin/env bash

# REVcon Installer Script
# Author: Lazzer

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN}             REVcon Installation Script              ${NC}"
echo -e "${GREEN}=====================================================${NC}"

# Helper function to check command existence
check_cmd() {
    if command -v "$1" >/dev/null 2>&1; then
        echo -e "[+] $1 is installed."
        return 0
    else
        echo -e "${YELLOW}[!] $1 is NOT installed.${NC}"
        return 1
    fi
}

echo -e "\n[*] Checking system dependencies..."
MISSING_DEPS=0

check_cmd file || MISSING_DEPS=$((MISSING_DEPS+1))
check_cmd readelf || MISSING_DEPS=$((MISSING_DEPS+1))
check_cmd nm || MISSING_DEPS=$((MISSING_DEPS+1))
check_cmd strings || MISSING_DEPS=$((MISSING_DEPS+1))
check_cmd checksec || MISSING_DEPS=$((MISSING_DEPS+1))

if [ $MISSING_DEPS -gt 0 ]; then
    echo -e "\n${YELLOW}[!] Some system tools are missing. Attempting to install them...${NC}"
    if [ -f /etc/debian_version ]; then
        echo -e "[*] Debian/Ubuntu detected. Installing via apt..."
        # If checksec package isn't directly available or to be safe, install binutils and file
        # checksec is usually in 'checksec' package in newer debian/ubuntu
        sudo apt-get update && sudo apt-get install -y binutils file checksec || {
            echo -e "${RED}[-] Failed to install system dependencies via apt.${NC}"
            echo -e "${YELLOW}[*] Please install binutils, file, and checksec manually.${NC}"
        }
    else
        echo -e "${YELLOW}[*] Non-Debian system. Please install missing tools (binutils, file, checksec) manually.${NC}"
    fi
else
    echo -e "\n[+] All system dependencies satisfied."
fi

echo -e "\n[*] Installing REVcon Python package in a virtual environment..."
# Check if python3 is installed
if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[-] python3 is required but not installed. Exiting.${NC}"
    exit 1
fi

# Ensure python3-venv is available
if ! python3 -m venv --help >/dev/null 2>&1; then
    echo -e "${RED}[-] python3-venv is required but not installed. Exiting.${NC}"
    echo -e "${YELLOW}[*] On Debian/Ubuntu, run: sudo apt install python3-venv${NC}"
    exit 1
fi

# Determine venv and bin locations
if [ "$EUID" -ne 0 ]; then
    VENV_DIR="$HOME/.local/share/revcon/venv"
    BIN_DIR="$HOME/.local/bin"
else
    VENV_DIR="/opt/revcon/venv"
    BIN_DIR="/usr/local/bin"
fi

echo -e "[*] Creating virtual environment at ${VENV_DIR}..."
mkdir -p "$(dirname "$VENV_DIR")"
python3 -m venv "$VENV_DIR"

echo -e "[*] Installing REVcon inside the virtual environment..."
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install .

echo -e "[*] Creating symlink in ${BIN_DIR}/revcon..."
mkdir -p "$BIN_DIR"
ln -sf "$VENV_DIR/bin/revcon" "$BIN_DIR/revcon"

echo -e "\n[*] Verifying installation..."
# Add local bin to path just in case for verification if installed in user space
export PATH="$BIN_DIR:$PATH"

if command -v revcon >/dev/null 2>&1; then
    echo -e "${GREEN}[+] REVcon installed successfully!${NC}"
    echo -e "[+] You can now run it from anywhere using the 'revcon' command."
else
    echo -e "${RED}[-] Verification failed. 'revcon' command not found in PATH.${NC}"
    echo -e "${YELLOW}[*] Make sure ${BIN_DIR} is in your PATH. (e.g. export PATH=\$PATH:${BIN_DIR})${NC}"
fi
