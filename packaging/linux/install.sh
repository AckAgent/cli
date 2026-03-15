#!/bin/bash
set -e

# AckAgent Linux Installer

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default installation directories
if [ "$(id -u)" -eq 0 ]; then
    # Running as root - install system-wide
    BIN_DIR="/usr/local/bin"
    LIB_DIR="/usr/local/lib"
else
    # Running as user - install to home directory
    BIN_DIR="${HOME}/.local/bin"
    LIB_DIR="${HOME}/.local/lib"
fi

echo "AckAgent Installer"
echo "=================="
echo ""
echo "Installing to:"
echo "  Binary: ${BIN_DIR}/ackagent"
echo "  Binary: ${BIN_DIR}/age-plugin-ackagent"
echo "  Library: ${LIB_DIR}/libackagent-sk.so"
echo ""

# Create directories
mkdir -p "${BIN_DIR}"
mkdir -p "${LIB_DIR}"

# Install files
cp "${SCRIPT_DIR}/ackagent" "${BIN_DIR}/ackagent"
chmod 755 "${BIN_DIR}/ackagent"

cp "${SCRIPT_DIR}/age-plugin-ackagent" "${BIN_DIR}/age-plugin-ackagent"
chmod 755 "${BIN_DIR}/age-plugin-ackagent"

cp "${SCRIPT_DIR}/libackagent-sk.so" "${LIB_DIR}/libackagent-sk.so"
chmod 755 "${LIB_DIR}/libackagent-sk.so"

echo "Installation complete!"
echo ""

# Check if bin directory is in PATH
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo "NOTE: ${BIN_DIR} is not in your PATH."
    echo "Add this to your shell profile (~/.bashrc or ~/.zshrc):"
    echo ""
    echo "  export PATH=\"${BIN_DIR}:\$PATH\""
    echo ""
fi

echo "Next steps:"
echo ""
echo "1. Login to AckAgent:"
echo "   ackagent login"
echo ""
echo "2. For SSH SecurityKeyProvider, add to ~/.ssh/config:"
echo "   SecurityKeyProvider ${LIB_DIR}/libackagent-sk.so"
echo ""
echo "   Or set environment variable:"
echo "   export SSH_SK_PROVIDER=${LIB_DIR}/libackagent-sk.so"
echo ""
echo "3. For GPG signing, configure git:"
echo "   git config --global gpg.program \"ackagent gpg\""
echo ""
echo "4. For age encryption/decryption:"
echo "   ackagent age keygen"
echo "   age -r \$(ackagent age recipient) -o secret.age file.txt"
echo "   age -d -i <(ackagent age identity) secret.age"
echo ""
echo "See README.txt for more details."
