package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVectors represents the structure of crypto_test_vectors.json
type TestVectors struct {
	SASVectors []SASVector `json:"sas_vectors"`
}

// SASVector represents a single SAS test vector
type SASVector struct {
	Description         string           `json:"description"`
	RequesterPubKeyHex  string           `json:"requester_public_key_hex"`
	DeviceKeys          []DeviceKeyInput `json:"device_keys"`
	ExpectedWords       []string         `json:"expected_words"`
	ExpectedEmojis      []string         `json:"expected_emojis"`
	ExpectedWordString  string           `json:"expected_word_string"`
	ExpectedEmojiString string           `json:"expected_emoji_string"`
}

// DeviceKeyInput represents a device key in test vectors
type DeviceKeyInput struct {
	DeviceID     string `json:"device_id"`
	PublicKeyHex string `json:"public_key_hex"`
}

// getTestVectorsPath returns the path to the test vectors file
func getTestVectorsPath() string {
	_, filename, _, _ := runtime.Caller(0)
	// Navigate from crypto/ to data/
	return filepath.Join(filepath.Dir(filename), "..", "data", "crypto_test_vectors.json")
}

// loadTestVectors loads the test vectors from the JSON file
func loadTestVectors(t *testing.T) TestVectors {
	t.Helper()

	path := getTestVectorsPath()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read test vectors file at %s", path)

	var vectors TestVectors
	err = json.Unmarshal(data, &vectors)
	require.NoError(t, err, "failed to parse test vectors JSON")

	return vectors
}

// TestComputeSASAgainstVectors validates the CLI SAS implementation against shared test vectors
func TestComputeSASAgainstVectors(t *testing.T) {
	vectors := loadTestVectors(t)
	require.NotEmpty(t, vectors.SASVectors, "no SAS test vectors found")

	for _, v := range vectors.SASVectors {
		t.Run(v.Description, func(t *testing.T) {
			// Decode requester public key
			requesterPubKey, err := hex.DecodeString(v.RequesterPubKeyHex)
			require.NoError(t, err, "failed to decode requester public key")

			// Build device keys slice
			deviceKeys := make([]SASDeviceKey, len(v.DeviceKeys))
			for i, dk := range v.DeviceKeys {
				pubKey, err := hex.DecodeString(dk.PublicKeyHex)
				require.NoError(t, err, "failed to decode device public key")

				deviceKeys[i] = SASDeviceKey{
					ApproverId:             dk.DeviceID,
					EncryptionPublicKeyHex: dk.PublicKeyHex,
					PublicKey:              pubKey,
				}
			}

			// Compute SAS
			result := ComputeSAS(requesterPubKey, deviceKeys)

			// Verify all fields
			assert.Equal(t, v.ExpectedWords, result.Words, "words mismatch")
			assert.Equal(t, v.ExpectedEmojis, result.Emojis, "emojis mismatch")
			assert.Equal(t, v.ExpectedWordString, result.WordString, "word string mismatch")
			assert.Equal(t, v.ExpectedEmojiString, result.EmojiString, "emoji string mismatch")
		})
	}
}

// TestSASDeviceSorting verifies that device keys are sorted correctly
func TestSASDeviceSorting(t *testing.T) {
	vectors := loadTestVectors(t)
	var twoDeviceVector *SASVector
	for i := range vectors.SASVectors {
		if len(vectors.SASVectors[i].DeviceKeys) == 2 {
			twoDeviceVector = &vectors.SASVectors[i]
			break
		}
	}
	require.NotNil(t, twoDeviceVector, "two-device test vector not found")

	requesterPubKey, _ := hex.DecodeString(twoDeviceVector.RequesterPubKeyHex)

	// Build device keys
	deviceKeys := make([]SASDeviceKey, len(twoDeviceVector.DeviceKeys))
	for i, dk := range twoDeviceVector.DeviceKeys {
		pubKey, _ := hex.DecodeString(dk.PublicKeyHex)
		deviceKeys[i] = SASDeviceKey{
			ApproverId:             dk.DeviceID,
			EncryptionPublicKeyHex: dk.PublicKeyHex,
			PublicKey:              pubKey,
		}
	}

	// Compute SAS - should produce same result regardless of input order
	result1 := ComputeSAS(requesterPubKey, deviceKeys)
	assert.Equal(t, twoDeviceVector.ExpectedWords, result1.Words,
		"SAS should match expected regardless of input order")

	// Now try with reversed input order
	reversedKeys := []SASDeviceKey{deviceKeys[1], deviceKeys[0]}
	result2 := ComputeSAS(requesterPubKey, reversedKeys)
	assert.Equal(t, result1.Words, result2.Words,
		"SAS should be identical regardless of device key input order")
}

// TestSASSortingDivergence verifies that SAS sorts by key hex, not device UUID.
// This catches the bug where UUID-based sorting produces different results than key-hex-based sorting.
func TestSASSortingDivergence(t *testing.T) {
	vectors := loadTestVectors(t)

	// Find the sorting-divergence vector
	var divergenceVector *SASVector
	for i := range vectors.SASVectors {
		if vectors.SASVectors[i].Description == "Sorting divergence - UUID sort differs from key hex sort" {
			divergenceVector = &vectors.SASVectors[i]
			break
		}
	}
	require.NotNil(t, divergenceVector, "sorting-divergence test vector not found")
	require.GreaterOrEqual(t, len(divergenceVector.DeviceKeys), 2, "sorting-divergence vector must have at least 2 devices")

	requesterPubKey, err := hex.DecodeString(divergenceVector.RequesterPubKeyHex)
	require.NoError(t, err)

	deviceKeys := make([]SASDeviceKey, len(divergenceVector.DeviceKeys))
	for i, dk := range divergenceVector.DeviceKeys {
		pubKey, err := hex.DecodeString(dk.PublicKeyHex)
		require.NoError(t, err)
		deviceKeys[i] = SASDeviceKey{
			ApproverId:             dk.DeviceID,
			EncryptionPublicKeyHex: dk.PublicKeyHex,
			PublicKey:              pubKey,
		}
	}

	result := ComputeSAS(requesterPubKey, deviceKeys)
	assert.Equal(t, divergenceVector.ExpectedWords, result.Words,
		"SAS must match expected value (key-hex sort order, not UUID sort order)")
	assert.Equal(t, divergenceVector.ExpectedWordString, result.WordString)
}

// TestSASDictionaryLength verifies dictionaries have exactly 256 entries
func TestSASDictionaryLength(t *testing.T) {
	assert.Len(t, SASWords, 256, "SASWords dictionary must have exactly 256 entries")
	assert.Len(t, SASEmojis, 256, "SASEmojis dictionary must have exactly 256 entries")
}

// TestSASEmptyDeviceKeys verifies behavior with no devices
func TestSASEmptyDeviceKeys(t *testing.T) {
	requesterPubKey := make([]byte, 32)
	deviceKeys := []SASDeviceKey{}

	// Should not panic
	result := ComputeSAS(requesterPubKey, deviceKeys)

	// Should return 5 words/emojis (40 bits of entropy)
	assert.Len(t, result.Words, 5)
	assert.Len(t, result.Emojis, 5)
	assert.NotEmpty(t, result.WordString)
	assert.NotEmpty(t, result.EmojiString)
}
