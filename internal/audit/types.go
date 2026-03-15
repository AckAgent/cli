package audit

import (
	"crypto/ed25519"
	"time"
)

// These types use snake_case JSON tags to match the audit chain export format.
// They intentionally differ from the generated auditchain package types which use camelCase.

// ChainExport represents an exported audit chain dataset.
type ChainExport struct {
	OrgID               string                  `json:"org_id"`
	ExportedAt          time.Time               `json:"exported_at"`
	FromTime            time.Time               `json:"from_time"`
	ToTime              time.Time               `json:"to_time"`
	DeviceEntries       []*DeviceChainEntry     `json:"device_entries"`
	RequestEntries      []*RequestChainEntry    `json:"request_entries"`
	MerkleTrees         []*MerkleTree           `json:"merkle_trees"`
	TransparencyEntries []*TransparencyLogEntry `json:"transparency_entries,omitempty"`
}

// DeviceChainEntry represents an entry in a device's audit chain.
type DeviceChainEntry struct {
	EntryID                string    `json:"entry_id"`
	OrgID                  string    `json:"org_id"`
	DeviceID               string    `json:"device_id"`
	Sequence               int64     `json:"sequence"`
	Timestamp              time.Time `json:"timestamp"`
	EntryHash              []byte    `json:"entry_hash"`
	PrevHash               []byte    `json:"prev_hash,omitempty"`
	EntryType              string    `json:"entry_type"`
	RequestHash            []byte    `json:"request_hash,omitempty"`
	ChallengeHash          []byte    `json:"challenge_hash,omitempty"`
	ChallengeContext       string    `json:"challenge_context,omitempty"`
	EncryptedPayloadHash   []byte    `json:"encrypted_payload_hash"`
	PlaintextHash          []byte    `json:"plaintext_hash"`
	DeviceSignature        []byte    `json:"device_signature"`
	DevicePublicKey        []byte    `json:"device_public_key,omitempty"`
	DeviceAuthPublicKeyHex string    `json:"device_auth_public_key_hex,omitempty"`
	AttestationData        []byte    `json:"attestation_data,omitempty"`
	AttestationType        string    `json:"attestation_type,omitempty"`
}

// RequestChainEntry represents an entry in the request chain.
type RequestChainEntry struct {
	EntryID                string           `json:"entry_id"`
	OrgID                  string           `json:"org_id"`
	Sequence               int64            `json:"sequence"`
	Timestamp              time.Time        `json:"timestamp"`
	EntryHash              []byte           `json:"entry_hash"`
	PrevHash               []byte           `json:"prev_hash,omitempty"`
	EntryType              string           `json:"entry_type"`
	RequestID              string           `json:"request_id,omitempty"`
	RequesterID            string           `json:"requester_id,omitempty"`
	RequesterContext       RequesterContext `json:"requester_context"`
	SigningPublicKey       string           `json:"signing_public_key,omitempty"`
	EncryptedPayloadHash   []byte           `json:"encrypted_payload_hash,omitempty"`
	PlaintextHash          []byte           `json:"plaintext_hash,omitempty"`
	ExpiresAt              *time.Time       `json:"expires_at,omitempty"`
	RequestEntryHash       []byte           `json:"request_entry_hash,omitempty"`
	Outcome                string           `json:"outcome,omitempty"`
	WinningDeviceID        string           `json:"winning_device_id,omitempty"`
	WinningDeviceEntryHash []byte           `json:"winning_device_entry_hash,omitempty"`
}

// RequesterContext contains sanitized HTTP context.
type RequesterContext struct {
	ClientIP  string `json:"client_ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Origin    string `json:"origin,omitempty"`
}

// MerkleTree represents a periodic rollup of all chains.
type MerkleTree struct {
	TreeID                  string           `json:"tree_id"`
	OrgID                   string           `json:"org_id"`
	Sequence                int64            `json:"sequence"`
	Timestamp               time.Time        `json:"timestamp"`
	PrevRoot                []byte           `json:"prev_root,omitempty"`
	RequestChainTipHash     []byte           `json:"request_chain_tip_hash"`
	RequestChainTipSequence int64            `json:"request_chain_tip_sequence"`
	DeviceChainTips         []DeviceChainTip `json:"device_chain_tips"`
	MerkleRoot              []byte           `json:"merkle_root"`
	CoordinatorSignature    []byte           `json:"coordinator_signature"`
	CoordinatorKeyID        string           `json:"coordinator_key_id"`
	TransparencyLogSequence *int64           `json:"transparency_log_sequence,omitempty"`
	PublishedAt             *time.Time       `json:"published_at,omitempty"`
}

// DeviceChainTip represents a device chain's tip in a Merkle tree.
type DeviceChainTip struct {
	DeviceID  string `json:"device_id"`
	Hash      []byte `json:"hash"`
	Sequence  int64  `json:"sequence"`
	Timestamp string `json:"timestamp,omitempty"`
}

// TransparencyLogEntry represents an entry in the transparency log.
type TransparencyLogEntry struct {
	Sequence      int64     `json:"sequence"`
	EntryID       string    `json:"entry_id"`
	Timestamp     time.Time `json:"timestamp"`
	OrgID         string    `json:"org_id"`
	TreeSequence  int64     `json:"tree_sequence"`
	MerkleRoot    []byte    `json:"merkle_root"`
	EntryHash     []byte    `json:"entry_hash"`
	PrevEntryHash []byte    `json:"prev_entry_hash,omitempty"`
	LogSignature  []byte    `json:"log_signature"`
	LogKeyID      string    `json:"log_key_id"`
}

// VerificationResult contains the results of chain verification.
type VerificationResult struct {
	Valid        bool                `json:"valid"`
	EntriesCount int64               `json:"entries_count"`
	Errors       []VerificationError `json:"errors,omitempty"`
	Warnings     []string            `json:"warnings,omitempty"`
}

// VerificationError represents a verification failure.
type VerificationError struct {
	EntryID     string `json:"entry_id,omitempty"`
	Sequence    int64  `json:"sequence,omitempty"`
	ErrorType   string `json:"error_type"`
	Description string `json:"description"`
}

// Verifier provides methods for verifying audit chain integrity.
type Verifier struct {
	// CoordinatorKeys maps key IDs to public keys for signature verification
	CoordinatorKeys map[string]ed25519.PublicKey
}

// NewVerifier creates a new verifier.
func NewVerifier() *Verifier {
	return &Verifier{
		CoordinatorKeys: make(map[string]ed25519.PublicKey),
	}
}
