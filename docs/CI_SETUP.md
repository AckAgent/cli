# CI Setup

## Required Secrets

### `GOPRIVATE_TOKEN`

GitHub Personal Access Token with `read:packages` scope for accessing private Go modules (`github.com/ackagent/api`, `github.com/ackagent/core`).

### `HOMEBREW_TAP_TOKEN`

GitHub PAT with `repo` scope on the `ackagent/homebrew-tap` repository. Used by the release workflow to update the Homebrew formula after a new CLI release.

### Apple Notarization (macOS binary signing)

For notarized macOS releases, configure:

- `APPLE_DEVELOPER_ID`: Developer ID certificate identity
- `APPLE_KEYCHAIN_PROFILE`: Notarytool keychain profile name
- `APPLE_TEAM_ID`: Apple Developer Team ID

These are used during the release workflow to codesign and notarize the macOS binary.

## BBS+ FFI Dependency

The CLI depends on `libbbs_ffi.a` from the `ackagent/bbs-ffi` repo. In CI, this is downloaded automatically via `make download-bbs-ffi`. The download target fetches the prebuilt static library from the latest bbs-ffi GitHub Release.

To override the version: `make download-bbs-ffi BBS_FFI_VERSION=v0.2.0`
