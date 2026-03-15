AckAgent PAM Module for Linux
=============================

The AckAgent PAM module enables push-based authentication for Linux systems.
When a user attempts to authenticate, a push notification is sent to their
registered iOS device for biometric approval.

Contents
--------
- ackagent-pam        CLI tool for configuration and testing
- pam_ackagent.so     PAM authentication module
- pam.conf.example    Configuration template
- ackagent.example    PAM service configuration example
- install.sh          Installation script
- README.txt          This file

Installation
------------
Run the install script as root:

    sudo ./install.sh

This installs:
- /usr/local/bin/ackagent-pam
- /lib/x86_64-linux-gnu/security/pam_ackagent.so (or /lib64/security/ on RHEL)
- /etc/ackagent/pam.conf.example

Configuration
-------------
1. Copy and edit the configuration file:

    sudo cp /etc/ackagent/pam.conf.example /etc/ackagent/pam.conf
    sudo nano /etc/ackagent/pam.conf

2. Configure the organization settings in pam.conf.

PAM Integration
---------------
To enable AckAgent authentication for a service, add to its PAM configuration.

For SSH (/etc/pam.d/sshd):

    # Add before @include common-auth or other auth lines
    auth sufficient pam_ackagent.so

For sudo (/etc/pam.d/sudo):

    # Add at the top of the file
    auth sufficient pam_ackagent.so

Authentication Modes
--------------------
The PAM module supports several authentication modes:

- push: Push notification only (default)
- challenge: Challenge-response only
- fallback: Try push, fall back to password on timeout/failure

Testing
-------
Test authentication without modifying PAM configuration:

    ackagent-pam test <username>

This simulates the authentication flow and shows what would happen.

Troubleshooting
---------------
1. Check the PAM module is installed:
    ls -la /lib/*/security/pam_ackagent.so

2. Verify configuration:
    ackagent-pam config

3. Test connectivity:
    ackagent-pam test --verbose <username>

4. Check system logs:
    journalctl -t pam_ackagent
    tail -f /var/log/auth.log

Security Considerations
-----------------------
- The PAM module runs as root during authentication
- Configuration file permissions should be 600 or 640
- Private keys should be stored with 600 permissions
- Consider enabling attestation verification for high-security environments

Requirements
------------
- Linux x86_64 or arm64
- PAM (libpam) installed
- Network connectivity to AckAgent services
- Users must have AckAgent iOS app with enrolled keys

More Information
----------------
https://github.com/ackagent/ackagent
