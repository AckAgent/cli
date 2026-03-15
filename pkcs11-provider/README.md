# AckAgent PKCS#11 Provider

A PKCS#11 shared library that enables any PKCS#11-compatible application (OpenSSL, Firefox, etc.) to use AckAgent for hardware-backed P-256 ECDSA signing and ECDH key derivation via iOS Secure Enclave.

## Features

- **P-256 ECDSA Signing**: `CKM_ECDSA` and `CKM_ECDSA_SHA256` mechanisms
- **ECDH Key Derivation**: `CKM_ECDH1_DERIVE` for shared secret derivation
- **Hardware-backed**: Keys never leave the iOS Secure Enclave
- **Out-of-band Approval**: All operations require biometric approval on iOS

## Prerequisites

1. **AckAgent CLI**: Must be installed and configured
2. **Logged in**: Run `ackagent login` to authenticate with your iOS device
3. **Enrolled Keys**: At least one P-256 key must be enrolled via `ackagent login`

## Installation

### Build from Source

```bash
cd cli/pkcs11-provider
make darwin          # Build for macOS
make darwin-universal # Build universal binary (x86_64 + ARM64)
make linux           # Build for Linux
```

### Install

```bash
# Install to user directory (recommended)
make install-user    # Installs to ~/.ackagent/lib/

# Install system-wide (requires sudo)
sudo make install    # Installs to /usr/local/lib/
```

## Usage

### Testing with pkcs11-tool

```bash
# List slots (should show "AckAgent" token)
pkcs11-tool --module ./libackagent-pkcs11.dylib --list-slots

# List mechanisms
pkcs11-tool --module ./libackagent-pkcs11.dylib --list-mechanisms

# List keys (requires ackagent login first)
pkcs11-tool --module ./libackagent-pkcs11.dylib --list-objects --type privkey

# Sign a file with ECDSA-SHA256 (will prompt on iOS)
echo "test data" > /tmp/testfile.txt
pkcs11-tool --module ./libackagent-pkcs11.dylib \
    --sign --mechanism ECDSA-SHA256 \
    --input-file /tmp/testfile.txt \
    --output-file /tmp/signature.bin
```

### OpenSSL 3.x Integration

First, install OpenSSL 3.x with pkcs11-provider:

```bash
brew install openssl@3 pkcs11-provider
```

Create an OpenSSL config file (`~/.openssl-pkcs11.cnf`):

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
pkcs11 = pkcs11_sect
default = default_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = /opt/homebrew/lib/ossl-modules/pkcs11.dylib
pkcs11-module-path = ~/.ackagent/lib/libackagent-pkcs11.dylib
activate = 1
```

Sign a file with OpenSSL:

```bash
OPENSSL_CONF=~/.openssl-pkcs11.cnf openssl dgst -sha256 \
    -sign "pkcs11:token=AckAgent;object=<key-label>" \
    -out signature.bin file.txt
```

### Firefox Integration

1. Open Firefox Preferences
2. Go to Privacy & Security → Certificates → Security Devices
3. Click "Load" and browse to `libackagent-pkcs11.dylib`
4. Name it "AckAgent" and click OK
5. Use the enrolled keys for client certificate authentication

## Supported PKCS#11 Functions

| Category | Functions |
|----------|-----------|
| General | `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList` |
| Slot/Token | `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo` |
| Session | `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`, `C_Login`, `C_Logout` |
| Objects | `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal`, `C_GetAttributeValue` |
| Signing | `C_SignInit`, `C_Sign`, `C_SignUpdate`, `C_SignFinal` |
| Key Derivation | `C_DeriveKey` |

All other PKCS#11 functions return `CKR_FUNCTION_NOT_SUPPORTED`.

## Supported Mechanisms

| Mechanism | Description |
|-----------|-------------|
| `CKM_ECDSA` | Raw ECDSA signing (input: 32-byte pre-hashed data) |
| `CKM_ECDSA_SHA256` | ECDSA with SHA-256 (input: raw data, hashed internally) |
| `CKM_ECDH1_DERIVE` | ECDH key derivation (returns 32-byte shared secret) |

## Debugging

Enable debug logging by setting the environment variable:

```bash
export ACKAGENT_LOG_LEVEL=debug
pkcs11-tool --module ./libackagent-pkcs11.dylib --list-slots
```

Debug output is written to stderr.

## Troubleshooting

### "Not logged in" error

Run `ackagent login` to authenticate with your iOS device:

```bash
ackagent login
```

### No keys found

Ensure you have enrolled at least one key:

```bash
ackagent keys
```

If no keys are listed, the enrollment may have failed. Try logging in again.

### iOS approval timeout

The default timeout for iOS approval is 120 seconds. If you don't approve on iOS within this time, the operation will fail. Watch for the push notification on your iOS device.

### "Token not present" error

This usually means the configuration is not found or the user is not logged in. Check:

1. `ackagent login --config` to see current configuration
2. Ensure the profile has valid authentication

## Limitations

- **No key generation/import**: Keys must be enrolled via iOS app or `ackagent login`
- **P-256 only**: Matches iOS Secure Enclave capabilities (no RSA, Ed25519)
- **No direct encryption**: Use ECDH derivation for hybrid encryption schemes
- **Blocking operations**: Operations wait up to 120s for iOS approval
- **PIN ignored**: Authentication handled by prior `ackagent login` + iOS biometrics

## Architecture

```
Application (OpenSSL) → libackagent-pkcs11.dylib → Relay → iOS Secure Enclave
```

The PKCS#11 module:
1. Receives signing/derivation requests from applications
2. Collects metadata (application name, process chain, hostname)
3. Encrypts the request for all enrolled iOS devices
4. Sends to the AckAgent relay service
5. Polls for response (iOS devices receive push notifications)
6. Decrypts and returns the result (signature or shared secret)
