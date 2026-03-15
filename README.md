# AckAgent CLI

Command-line tool for SSH, GPG, age, and PAM signing via AckAgent. Routes signing requests to your phone for biometric approval with hardware-backed cryptographic keys.

## Install

```bash
brew install ackagent/tap/ackagent
```

## Quick Start

```bash
# Log in to your AckAgent account
ackagent login

# List your signing keys
ackagent keys list

# Use with SSH (add to ~/.ssh/config)
#   SecurityKeyProvider /opt/homebrew/lib/libackagent-sk.dylib

# Use with GPG
ackagent gpg setup

# Use with age
age -d -i age-plugin-ackagent encrypted.age
```

## Build from Source

```bash
# Download BBS+ FFI static library (required for CGo)
make download-bbs-ffi

# Build all binaries
CGO_ENABLED=1 go build ./...

# Run tests
CGO_ENABLED=1 go test ./...
```

## Components

| Binary | Description |
|--------|-------------|
| `ackagent` | Main CLI |
| `age-plugin-ackagent` | age encryption plugin |
| `libackagent-sk.dylib` | SSH SecurityKeyProvider (software keys) |
| `libackagent-pkcs11.dylib` | SSH PKCS#11 provider (hardware keys) |
| `ackagent-pam` | PAM module for sudo/login |
| `ackagent-audit` | Audit log verification |

## Related Repos

- [ackagent/bbs-ffi](https://github.com/AckAgent/bbs-ffi) — BBS+ static library (CGo dependency)
- [ackagent/api](https://github.com/AckAgent/api) — API types (Go module)
- [ackagent/homebrew-tap](https://github.com/AckAgent/homebrew-tap) — Homebrew formulae

## License

Proprietary - All rights reserved
