#!/bin/sh
# Post-install script for ackagent

# Update shared library cache
if command -v ldconfig >/dev/null 2>&1; then
    ldconfig
fi

exit 0
