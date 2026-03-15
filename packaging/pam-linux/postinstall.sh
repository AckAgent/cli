#!/bin/sh
# Post-install script for ackagent-pam

set -e

# Create configuration directory
mkdir -p /etc/ackagent
mkdir -p /var/lib/ackagent
chmod 755 /var/lib/ackagent

# Update shared library cache
if command -v ldconfig >/dev/null 2>&1; then
    ldconfig
fi

exit 0
