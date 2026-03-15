// Package config manages desktop client configuration including
// pairing state, encryption keys, and enrolled signing keys.
package config

import (
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/shared/log"
)

var cfgLog = log.New("config")

// configDirOverride allows overriding the config directory for testing
var configDirOverride string

// SetConfigDir overrides the config directory (for testing)
func SetConfigDir(dir string) {
	configDirOverride = dir
}

// ResetConfigDir clears the config directory override
func ResetConfigDir() {
	configDirOverride = ""
}

const (
	// ConfigVersion is the current config file format version
	// Version 2: profiles stored inline in config.json
	// Version 3: profiles stored in separate files under profiles/
	// Version 4: org-scoped keys and org management
	// Version 5: standardized hex-encoded public key formats
	ConfigVersion = 5

	// AppID is the application identifier used for config paths
	AppID = "com.ackagent.ackagent"

	// DefaultProfileName is the name used for the default profile
	DefaultProfileName = "default"

	// maxBackups is the number of timestamped config backups to retain
	maxBackups = 5
)

var (
	ErrKeyNotFound        = errors.New("key not found")
	ErrKeyringRequired    = errors.New("keyring unavailable: secure credential storage is required")
	ErrProfileNotFound    = errors.New("profile not found")
	ErrProfileExists      = errors.New("profile already exists")
	ErrNoActiveProfile    = errors.New("no active profile")
	ErrCannotDeleteLast   = errors.New("cannot delete last profile")
	ErrInvalidProfileName = errors.New("invalid profile name: must be alphanumeric with hyphens or underscores")
	ErrOrgNotFound        = errors.New("organization not found")
	ErrOrgRequired        = errors.New("multiple organizations found, --org flag required")
	ErrNoOrgs             = errors.New("no organizations configured")
)

// Config represents the desktop client configuration (v3 with file-based profiles)
type Config struct {
	Version       int                       `json:"version"`
	DeviceID      string                    `json:"device_id"`
	DeviceName    string                    `json:"device_name"`
	ActiveProfile string                    `json:"active_profile"`
	Profiles      map[string]*ProfileConfig `json:"-"` // Loaded from profiles/*.json, not stored in config.json

	// workingProfile overrides ActiveProfile when set (via --profile flag or env var)
	workingProfile string

	// workingOrg overrides DefaultOrgID when set (via --org flag or ACKAGENT_ORG env var)
	workingOrg string

	// BLE transport runtime settings (not persisted, set via CLI flags)
	BLEEnabled bool   // Enable BLE local transport
	BLEDevice  string // BLE device name or address filter
}

// OrgConfig holds per-organization configuration including org-scoped signing keys.
type OrgConfig struct {
	OrgID      string        `json:"org_id"`
	EmojiIndex int64         `json:"emoji_index"`
	LocalName  string        `json:"local_name,omitempty"`
	Keys       []KeyMetadata `json:"keys,omitempty"`
}

// EmojiWords returns the human-readable word form of the org's emoji index.
func (o *OrgConfig) EmojiWords() string {
	words, _ := crypto.EmojiFromIndex(int(o.EmojiIndex))
	return words
}

// Emojis returns the emoji string for the org's emoji index.
func (o *OrgConfig) Emojis() string {
	_, emojis := crypto.EmojiFromIndex(int(o.EmojiIndex))
	return emojis
}

// DisplayName returns the best human-readable name for this org:
// local name if set, otherwise emoji words.
func (o *OrgConfig) DisplayName() string {
	if o.LocalName != "" {
		return o.LocalName
	}
	return o.EmojiWords()
}

// ProfileConfig contains per-profile configuration
type ProfileConfig struct {
	RelayURL        string        `json:"relay_url"`
	IssuerURL       string        `json:"issuer_url,omitempty"`        // OIDC issuer URL for token refresh
	BlobURL         string        `json:"blob_url,omitempty"`          // Blob service URL for encrypted key metadata
	IssuerPublicKey   []byte        `json:"issuer_public_key,omitempty"`    // 96-byte BLS12-381 G2 issuer public key for BBS+ anonymous attestation verification
	IssuerPublicKeyID string        `json:"issuer_public_key_id,omitempty"` // Key ID of the cached issuer public key
	UserAccount     *UserAccount  `json:"user_account,omitempty"`
	Keys            []KeyMetadata `json:"keys,omitempty"`
	Orgs            []OrgConfig   `json:"orgs,omitempty"`           // Organizations for this profile
	DefaultOrgID    string        `json:"default_org_id,omitempty"` // Default org ID for key operations
	HookSettings    *HookSettings `json:"hook_settings,omitempty"`
}

// IsLoggedIn returns true if this profile is logged into a user account with verified SAS
func (p *ProfileConfig) IsLoggedIn() bool {
	return p.UserAccount != nil && p.UserAccount.SASVerified && len(p.UserAccount.Devices) > 0
}

// UserAccount represents a logged-in user account with multiple approver devices
type UserAccount struct {
	UserID          string       `json:"user_id"`
	RequesterID     string       `json:"requester_id,omitempty"`      // Requester ID for signing requests
	TokenRef        string       `json:"access_token_ref,omitempty"`  // Keyring reference for access token
	RefreshTokenRef string       `json:"refresh_token_ref,omitempty"` // Keyring reference for refresh token
	ExpiresAt       time.Time    `json:"expires_at"`
	LoggedInAt      time.Time    `json:"logged_in_at"`
	SASVerified     bool         `json:"sas_verified"`
	Devices         []UserDevice `json:"devices"`
	// Our identity key pair for this account
	IdentityPrivateKeyRef string `json:"identity_private_key_ref,omitempty"` // Keyring reference
	IdentityPublicKey     []byte `json:"identity_public_key"`
}

// UserDevice represents a device in the user's account
type UserDevice struct {
	ApproverId           string `json:"approverId"`    // Approver UUID from backend registration
	AuthPublicKey        []byte `json:"authPublicKey"` // P-256 33 bytes compressed (0x02/0x03 || X) for auth
	DeviceName           string `json:"device_name"`
	PublicKey            []byte `json:"public_key"`                       // P-256 33 bytes compressed (0x02/0x03 || X) for ECDH
	AttestationPublicKey []byte `json:"attestation_public_key,omitempty"` // P-256 33 bytes compressed (0x02/0x03 || X) for attestation verification
	IsPrimary            bool   `json:"is_primary"`
}

// HookSettings contains configuration for ackagent hook
type HookSettings struct {
	// FilteredTools are tools that require approval (default: Bash, Write, Edit, MultiEdit)
	FilteredTools []string `json:"filtered_tools,omitempty"`

	// AlwaysAllowRules are learned permissions that bypass approval
	AlwaysAllowRules []AlwaysAllowRule `json:"always_allow_rules,omitempty"`

	// TimeoutSeconds is the timeout for waiting for iOS approval (default: 120)
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// AlwaysAllowRule represents a learned permission that bypasses approval
type AlwaysAllowRule struct {
	ID        string    `json:"id"`
	Tool      string    `json:"tool"`
	Pattern   string    `json:"pattern,omitempty"` // Regex pattern for tool input
	CreatedAt time.Time `json:"created_at"`
}

// KeyPurpose represents the intended use of a signing key
type KeyPurpose string

const (
	KeyPurposeSSH KeyPurpose = "ssh" // SSH authentication/signing
	KeyPurposeGPG KeyPurpose = "gpg" // GPG signing (git commits)
	KeyPurposeAge KeyPurpose = "age" // Age encryption/decryption
)

// KeyStorageType indicates where/how a key is stored on iOS
type KeyStorageType string

const (
	StorageTypeSecureEnclave  KeyStorageType = "secureEnclave"  // Hardware-backed, device-only
	StorageTypeICloudKeychain KeyStorageType = "icloudKeychain" // Software key with iCloud Keychain sync
	StorageTypeSoftwareLocal  KeyStorageType = "softwareLocal"  // Software key, device-only
)

// Key algorithm constants
const (
	AlgorithmP256    = "ecdsa"   // ECDSA P-256 (default for SSH/GPG)
	AlgorithmEd25519 = "ed25519" // EdDSA Ed25519 (software-only)
	AlgorithmX25519  = "X25519"  // X25519 (for Age encryption)
)

// KeyMetadataAttestation proves a key was created on attested device hardware
type KeyMetadataAttestation struct {
	PublicKey            []byte `json:"publicKey"`                      // The attested public key
	Assertion            []byte `json:"assertion"`                      // App Attest assertion or software signature
	AttestationType      string `json:"attestationType"`                // "ios_secure_enclave", "android_tee", "android_strongbox", "software"
	AttestationObject    []byte `json:"attestationObject,omitempty"`    // CBOR attestation (for hardware)
	Challenge            []byte `json:"challenge"`                      // SHA256(id || publicKey || createdAt || deviceAuthPublicKey)
	AttestationTimestamp int64  `json:"attestationTimestamp"`           // Unix timestamp in milliseconds
	AttestationPublicKey []byte `json:"attestationPublicKey,omitempty"` // Attestation key's public key (33 bytes compressed)
}

// KeyMetadata represents an enrolled signing key
type KeyMetadata struct {
	IOSKeyID     string         `json:"ios_key_id"`             // UUID of key on iOS
	Label        string         `json:"label"`                  // User-provided label
	PublicKey    []byte         `json:"public_key"`             // 33 bytes compressed (0x02/0x03 || X) for P-256, or 32 bytes for X25519/Ed25519
	Algorithm    string         `json:"algorithm"`              // e.g., "ecdsa-sha2-nistp256" or "X25519"
	Purpose      KeyPurpose     `json:"purpose,omitempty"`      // ssh, gpg, or age
	StorageType  KeyStorageType `json:"storage_type,omitempty"` // secureEnclave, icloudKeychain, softwareLocal
	DeviceName   string         `json:"device_name,omitempty"`  // Device name where key is stored
	CreatedAt    time.Time      `json:"created_at"`
	AgeRecipient string         `json:"age_recipient,omitempty"` // Age recipient string (age1ackagent1...)

	// GPG encryption subkey fields (for OpenPGP subkey binding)
	// These are only populated for GPG keys that have a separate ECDH encryption subkey
	EncryptionPublicKey   []byte `json:"encryption_public_key,omitempty"`  // 33 bytes compressed (0x02/0x03 || X) for P-256
	EncryptionFingerprint string `json:"encryption_fingerprint,omitempty"` // 40-char hex fingerprint of ECDH subkey
	KeyCreationTimestamp  int64  `json:"key_creation_timestamp,omitempty"` // Unix timestamp for consistent fingerprint computation

	// GPG signature packets (created at key generation time for offline export)
	// These are complete OpenPGP signature packets (tag 2) ready for export
	UserIDSignature []byte `json:"user_id_signature,omitempty"` // Self-certification (type 0x13) on User ID
	SubkeySignature []byte `json:"subkey_signature,omitempty"`  // Subkey binding (type 0x18) for encryption subkey

	// Key attestation (proves key was created on attested hardware)
	Attestation *KeyMetadataAttestation `json:"attestation,omitempty"`

	// ApproverId is the UUID of the approver device where this key is stored.
	ApproverId string `json:"approverId,omitempty"`
}

// IsHardwareBacked returns true if the key is stored in Secure Enclave
func (k *KeyMetadata) IsHardwareBacked() bool {
	return k.StorageType == StorageTypeSecureEnclave
}

// IsSyncable returns true if the key syncs via iCloud Keychain
func (k *KeyMetadata) IsSyncable() bool {
	return k.StorageType == StorageTypeICloudKeychain
}

// IsEd25519 returns true if the key uses Ed25519 algorithm
func (k *KeyMetadata) IsEd25519() bool {
	return k.Algorithm == AlgorithmEd25519
}

// IsP256 returns true if the key uses P-256 ECDSA algorithm
func (k *KeyMetadata) IsP256() bool {
	return k.Algorithm == AlgorithmP256 || k.Algorithm == ""
}

// IsX25519 returns true if the key uses X25519 algorithm (Age)
func (k *KeyMetadata) IsX25519() bool {
	return k.Algorithm == AlgorithmX25519
}

// PublicKeySize returns the expected public key size based on algorithm
func (k *KeyMetadata) PublicKeySize() int {
	if k.IsEd25519() || k.IsX25519() {
		return 32
	}
	return 33 // P-256 compressed
}

// Hex returns the hex-encoded public key string.
func (k *KeyMetadata) Hex() string {
	return hex.EncodeToString(k.PublicKey)
}

// HasEncryptionSubkey returns true if the key has a separate ECDH encryption subkey
func (k *KeyMetadata) HasEncryptionSubkey() bool {
	return len(k.EncryptionPublicKey) > 0 && k.EncryptionFingerprint != ""
}

// EffectiveEncryptionPublicKey returns the public key to use for ECDH encryption.
// Returns the encryption subkey if available, otherwise falls back to the primary key.
func (k *KeyMetadata) EffectiveEncryptionPublicKey() []byte {
	if k.HasEncryptionSubkey() {
		return k.EncryptionPublicKey
	}
	return k.PublicKey
}

// EffectiveEncryptionFingerprint returns the GPG fingerprint to use for PKESK key ID.
// Returns the encryption subkey fingerprint if available, otherwise falls back to the primary public key hex.
// Note: For GPG keys, the GPG V4 fingerprint should be computed on demand from the public key.
func (k *KeyMetadata) EffectiveEncryptionFingerprint() string {
	if k.HasEncryptionSubkey() {
		return k.EncryptionFingerprint
	}
	return k.Hex()
}

// profileNameRegex validates profile names: alphanumeric, hyphens, underscores
var profileNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// ValidateProfileName checks if a profile name is valid
func ValidateProfileName(name string) error {
	if name == "" || !profileNameRegex.MatchString(name) {
		return ErrInvalidProfileName
	}
	return nil
}
