package commands

import (
	"testing"
	"time"

	"github.com/ackagent/cli/internal/gpg/cli"
	"github.com/ackagent/cli/internal/gpg/openpgp"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/stretchr/testify/assert"
)

func TestExportKey_FindsKeyByLocalUser(t *testing.T) {
	key1 := makeGPGTestKey("Work Key <work@example.com>", []byte("gpg-pubkey-1"))
	key2 := makeGPGTestKey("Personal Key <me@example.com>", []byte("gpg-pubkey-2"))
	key2FP := GPGFingerprint(&key2)

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key1, key2},
			},
		},
	}

	// Find by computed GPG fingerprint
	key := FindKey(cfg, key2FP, config.KeyPurposeGPG)
	assert.NotNil(t, key)
	assert.Equal(t, "Personal Key <me@example.com>", key.Label)
}

func TestExportKey_KeyCreationTimestamp(t *testing.T) {
	// When KeyCreationTimestamp is set, it should be used for export
	key := config.KeyMetadata{
		KeyCreationTimestamp: 1700000000,
		CreatedAt:            time.Now(),
	}

	var keyCreationTime time.Time
	if key.KeyCreationTimestamp > 0 {
		keyCreationTime = time.Unix(key.KeyCreationTimestamp, 0)
	} else {
		keyCreationTime = key.CreatedAt
	}

	assert.Equal(t, int64(1700000000), keyCreationTime.Unix())
}

func TestExportKey_FallbackToCreatedAt(t *testing.T) {
	// When KeyCreationTimestamp is 0, CreatedAt should be used
	createdAt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	key := config.KeyMetadata{
		KeyCreationTimestamp: 0,
		CreatedAt:            createdAt,
	}

	var keyCreationTime time.Time
	if key.KeyCreationTimestamp > 0 {
		keyCreationTime = time.Unix(key.KeyCreationTimestamp, 0)
	} else {
		keyCreationTime = key.CreatedAt
	}

	assert.Equal(t, createdAt, keyCreationTime)
}

func TestExportKey_HasEncryptionSubkey(t *testing.T) {
	// Key with encryption subkey should include it in export
	epk := make([]byte, 65)
	epk[0] = 0x04
	key := config.KeyMetadata{
		EncryptionPublicKey:   epk,
		EncryptionFingerprint: "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333",
	}

	assert.True(t, key.HasEncryptionSubkey(), "key with encryption data should have subkey")
}

func TestExportKey_NoEncryptionSubkey(t *testing.T) {
	// Key without encryption subkey
	key := config.KeyMetadata{
		PublicKey: make([]byte, 65),
	}

	assert.False(t, key.HasEncryptionSubkey(), "key without encryption data should not have subkey")
}

func TestExportKey_Ed25519Detected(t *testing.T) {
	ecdsaKey := config.KeyMetadata{Algorithm: config.AlgorithmP256}
	ed25519Key := config.KeyMetadata{Algorithm: config.AlgorithmEd25519}

	assert.False(t, ecdsaKey.IsEd25519())
	assert.True(t, ed25519Key.IsEd25519())
}

func TestExportKey_Ed25519_FixesEdDSASignatureMPIs(t *testing.T) {
	// Regression: Ed25519 export should re-encode single-MPI EdDSA signatures
	// into two-MPI format before appending to packet stream

	// Build a minimal EdDSA signature packet with a single 64-byte MPI
	// (mimics Android's Ed25519SignatureBuilder output)
	combined := make([]byte, 64)
	for i := range combined {
		combined[i] = byte(i + 1)
	}
	badSig := buildBadEdDSASigPacket(combined)

	key := config.KeyMetadata{
		PublicKey:            make([]byte, 32),
		Algorithm:            config.AlgorithmEd25519,
		Purpose:              config.KeyPurposeGPG,
		KeyCreationTimestamp: 1700000000,
		UserIDSignature:      badSig,
		Label:                "Test Ed25519 <test@example.com>",
	}

	assert.True(t, key.IsEd25519())
	assert.True(t, len(key.UserIDSignature) > 0)

	// Verify the fix function produces valid two-MPI output
	fixed := openpgp.FixEdDSASignatureMPIs(key.UserIDSignature)
	assert.NotEqual(t, badSig, fixed, "fixed packet should differ from original")

	// Parse and verify two MPIs exist
	reader := openpgp.NewPacketReader(fixed)
	parsed, err := reader.Next()
	assert.NoError(t, err)

	// Navigate to MPI area in the body
	body := parsed.Body
	offset := 4 // version + sigType + pubAlgo + hashAlgo
	hashedLen := int(body[offset])<<8 | int(body[offset+1])
	offset += 2 + hashedLen
	unhashedLen := int(body[offset])<<8 | int(body[offset+1])
	offset += 2 + unhashedLen
	offset += 2 // hash left 2

	r, rConsumed, err := openpgp.DecodeMPI(body, offset)
	assert.NoError(t, err)
	assert.Len(t, r, 32, "R should be 32 bytes")

	s, _, err := openpgp.DecodeMPI(body, offset+rConsumed)
	assert.NoError(t, err)
	assert.Len(t, s, 32, "S should be 32 bytes")
}

// buildBadEdDSASigPacket builds an EdDSA signature packet with a single combined
// 64-byte MPI (mimicking Android's encoding bug).
func buildBadEdDSASigPacket(combined []byte) []byte {
	pw := openpgp.NewPacketWriter()
	pw.WriteByte(4)    // V4
	pw.WriteByte(0x13) // positive certification
	pw.WriteByte(22)   // EdDSA
	pw.WriteByte(8)    // SHA-256
	pw.WriteUint16(0)  // no hashed subpackets
	pw.WriteUint16(0)  // no unhashed subpackets
	pw.WriteByte(0xAB) // hash left 2
	pw.WriteByte(0xCD)
	pw.Write(openpgp.EncodeMPIFromBytes(combined)) // single 64-byte MPI
	return openpgp.BuildPacket(2, pw.Bytes())      // tag 2 = signature
}

func TestExportKey_ArgsHandling(t *testing.T) {
	args := &cli.Args{
		LocalUser: "AAAA1111",
		Armor:     true,
		Verbose:   false,
	}

	assert.Equal(t, "AAAA1111", args.LocalUser)
	assert.True(t, args.Armor)
	assert.False(t, args.Verbose)
}
