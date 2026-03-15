AckAgent CLI for Linux
======================

AckAgent routes signing and authorization requests to your iOS device for
biometric approval. Private keys never leave the iOS Secure Enclave.

Contents
--------
- ackagent              CLI tool for login, GPG signing, and Claude Code hooks
- age-plugin-ackagent   age encryption plugin for iOS key decryption
- libackagent-sk.so     SSH SecurityKeyProvider shared library
- install.sh            Installation script
- README.txt            This file

Installation
------------
Run the install script:

    ./install.sh

This installs to ~/.local/bin and ~/.local/lib by default.
Run with sudo for system-wide installation to /usr/local.

Quick Start
-----------
1. Login to AckAgent (requires iOS app):

    ackagent login

2. Verify your enrolled keys:

    ackagent login --keys

SSH Setup
---------
Add to ~/.ssh/config:

    SecurityKeyProvider ~/.local/lib/libackagent-sk.so

Or set environment variable:

    export SSH_SK_PROVIDER=~/.local/lib/libackagent-sk.so

GPG Signing
-----------
Configure git to use AckAgent for signing:

    git config --global gpg.program "ackagent gpg"
    git config --global commit.gpgsign true

Claude Code Hook
----------------
Configure in ~/.claude/settings.json:

    {
      "hooks": {
        "PermissionRequest": [{
          "hooks": [{
            "type": "command",
            "command": "~/.local/bin/ackagent hook claude",
            "timeout": 120
          }]
        }]
      }
    }

Or run the auto-configuration:

    ackagent hook claude --configure

age Encryption
--------------
Generate an age key on your iOS device:

    ackagent age keygen

Get your recipient address for sharing:

    ackagent age recipient

Encrypt files (standard age command):

    age -r age1ackagent1... -o secret.age secret.txt

Decrypt files (requires iOS approval):

    age -d -i <(ackagent age identity) secret.age

Requirements
------------
- Linux x86_64 or arm64
- For SSH: OpenSSH 8.2+ with SecurityKeyProvider support
- For credential storage: pass, kwallet, or secretservice (D-Bus)

More Information
----------------
https://github.com/ackagent/ackagent
