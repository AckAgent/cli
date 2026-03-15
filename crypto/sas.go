// Package crypto provides SAS (Short Authentication String) generation
// for login verification. Must match backend and iOS implementations exactly.
package crypto

import (
	"crypto/sha256"
	"sort"
	"strings"
)

// SAS dictionaries are defined in sas_dict_gen.go (generated from data/sas_dictionary.json)

// SASDeviceKey represents a device's key for SAS computation
type SASDeviceKey struct {
	ApproverId             string // Approver device UUID
	EncryptionPublicKeyHex string // Lowercase hex-encoded encryption public key (sort key)
	PublicKey              []byte // P-256 33 bytes (compressed: 0x02/0x03 || X)
}

// SASResult contains the computed SAS values
type SASResult struct {
	Words       []string
	Emojis      []string
	WordString  string
	EmojiString string
}

// ComputeSAS computes the Short Authentication String from public keys
//
// Algorithm:
// 1. Sort device keys by encryption public key hex (for determinism)
// 2. Concatenate: requester_pub || device_1_pub || device_2_pub || ...
// 3. SHA-256 hash the concatenation
// 4. Take first 5 bytes as indices into word/emoji dictionaries (40 bits of entropy)
func ComputeSAS(requesterPubKey []byte, deviceKeys []SASDeviceKey) SASResult {
	// Sort device keys by encryption public key hex for deterministic ordering
	sorted := make([]SASDeviceKey, len(deviceKeys))
	copy(sorted, deviceKeys)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].EncryptionPublicKeyHex < sorted[j].EncryptionPublicKeyHex
	})

	// Concatenate all public keys
	var data []byte
	data = append(data, requesterPubKey...)
	for _, dk := range sorted {
		data = append(data, dk.PublicKey...)
	}

	// SHA-256 hash
	hash := sha256.Sum256(data)

	// Extract 5 bytes for indices (40 bits of entropy)
	var words []string
	var emojis []string

	for i := 0; i < 5; i++ {
		idx := int(hash[i])
		words = append(words, SASWords[idx])
		emojis = append(emojis, SASEmojis[idx])
	}

	return SASResult{
		Words:       words,
		Emojis:      emojis,
		WordString:  strings.Join(words, "-"),
		EmojiString: strings.Join(emojis, " "),
	}
}
