#!/bin/bash
set -e

# AckAgent PAM Linux Installer

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect architecture for PAM module path
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        PAM_DIR="/lib/x86_64-linux-gnu/security"
        PAM_DIR_ALT="/lib64/security"
        ;;
    aarch64)
        PAM_DIR="/lib/aarch64-linux-gnu/security"
        PAM_DIR_ALT="/lib64/security"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Default installation directories
if [ "$(id -u)" -eq 0 ]; then
    # Running as root - install system-wide
    BIN_DIR="/usr/local/bin"
    CONFIG_DIR="/etc/ackagent"
    VAR_DIR="/var/lib/ackagent"
else
    echo "Error: This installer must be run as root to install the PAM module."
    echo "Please run: sudo ./install.sh"
    exit 1
fi

echo "AckAgent PAM Installer"
echo "======================"
echo ""
echo "Installing to:"
echo "  CLI: ${BIN_DIR}/ackagent-pam"
echo "  PAM Module: ${PAM_DIR}/pam_ackagent.so (or ${PAM_DIR_ALT}/pam_ackagent.so)"
echo "  Config: ${CONFIG_DIR}/"
echo ""

# Create directories
mkdir -p "${BIN_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${VAR_DIR}"
chmod 755 "${VAR_DIR}"

# Install CLI
cp "${SCRIPT_DIR}/ackagent-pam" "${BIN_DIR}/ackagent-pam"
chmod 755 "${BIN_DIR}/ackagent-pam"

# Install PAM module - try distribution-specific path first
if [ -d "$(dirname "${PAM_DIR}")" ]; then
    mkdir -p "${PAM_DIR}"
    cp "${SCRIPT_DIR}/pam_ackagent.so" "${PAM_DIR}/pam_ackagent.so"
    chmod 755 "${PAM_DIR}/pam_ackagent.so"
    echo "PAM module installed to: ${PAM_DIR}/pam_ackagent.so"
elif [ -d "$(dirname "${PAM_DIR_ALT}")" ]; then
    mkdir -p "${PAM_DIR_ALT}"
    cp "${SCRIPT_DIR}/pam_ackagent.so" "${PAM_DIR_ALT}/pam_ackagent.so"
    chmod 755 "${PAM_DIR_ALT}/pam_ackagent.so"
    echo "PAM module installed to: ${PAM_DIR_ALT}/pam_ackagent.so"
else
    echo "Warning: Could not determine PAM module directory."
    echo "PAM module not installed automatically."
    echo "Please copy pam_ackagent.so to your PAM security directory manually."
fi

# Install example configuration
if [ -f "${SCRIPT_DIR}/pam.conf.example" ]; then
    cp "${SCRIPT_DIR}/pam.conf.example" "${CONFIG_DIR}/pam.conf.example"
    echo "Example config installed to: ${CONFIG_DIR}/pam.conf.example"
fi

# Update shared library cache
if command -v ldconfig >/dev/null 2>&1; then
    ldconfig
fi

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo ""
echo "1. Configure the PAM module:"
echo "   sudo cp ${CONFIG_DIR}/pam.conf.example ${CONFIG_DIR}/pam.conf"
echo "   sudo nano ${CONFIG_DIR}/pam.conf"
echo ""
echo "2. Enable PAM authentication for your service."
echo "   For SSH, add to /etc/pam.d/sshd:"
echo "   auth sufficient pam_ackagent.so"
echo ""
echo "3. Test authentication:"
echo "   ackagent-pam test <username>"
echo ""
echo "See README.txt for more details."
