package audit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// VerifyExport verifies all chains in an exported dataset.
func (v *Verifier) VerifyExport(export *ChainExport) *VerificationResult {
	result := &VerificationResult{
		Valid:        true,
		EntriesCount: 0,
	}

	deviceChains := groupDeviceEntriesByDevice(export.DeviceEntries)
	for deviceID, entries := range deviceChains {
		r := v.VerifyDeviceChain(entries)
		result.EntriesCount += r.EntriesCount
		if !r.Valid {
			result.Valid = false
			for _, err := range r.Errors {
				err.Description = fmt.Sprintf("device %s: %s", deviceID, err.Description)
				result.Errors = append(result.Errors, err)
			}
		}
		result.Warnings = append(result.Warnings, r.Warnings...)
	}

	r := v.VerifyRequestChain(export.RequestEntries)
	result.EntriesCount += r.EntriesCount
	if !r.Valid {
		result.Valid = false
		result.Errors = append(result.Errors, r.Errors...)
	}
	result.Warnings = append(result.Warnings, r.Warnings...)

	for _, tree := range export.MerkleTrees {
		if err := v.VerifyMerkleTree(tree); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, VerificationError{
				EntryID:     tree.TreeID,
				Sequence:    tree.Sequence,
				ErrorType:   "merkle_tree_invalid",
				Description: err.Error(),
			})
		}
	}

	if len(export.TransparencyEntries) > 0 {
		r := v.VerifyTransparencyLog(export.TransparencyEntries)
		if !r.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, r.Errors...)
		}
		result.Warnings = append(result.Warnings, r.Warnings...)
	}

	return result
}

// VerifyDeviceChain verifies the integrity of a device chain.
func (v *Verifier) VerifyDeviceChain(entries []*DeviceChainEntry) *VerificationResult {
	result := &VerificationResult{
		Valid:        true,
		EntriesCount: int64(len(entries)),
	}

	if len(entries) == 0 {
		return result
	}

	sortDeviceEntries(entries)

	var prevEntry *DeviceChainEntry
	for _, entry := range entries {
		computed := computeDeviceEntryHash(entry)
		if !bytes.Equal(entry.EntryHash, computed) {
			result.Valid = false
			result.Errors = append(result.Errors, VerificationError{
				EntryID:     entry.EntryID,
				Sequence:    entry.Sequence,
				ErrorType:   "hash_mismatch",
				Description: fmt.Sprintf("hash mismatch: stored=%s computed=%s", hex.EncodeToString(entry.EntryHash), hex.EncodeToString(computed)),
			})
		}

		if prevEntry != nil {
			if entry.Sequence != prevEntry.Sequence+1 {
				result.Valid = false
				result.Errors = append(result.Errors, VerificationError{
					EntryID:     entry.EntryID,
					Sequence:    entry.Sequence,
					ErrorType:   "sequence_gap",
					Description: fmt.Sprintf("sequence gap: expected %d, got %d", prevEntry.Sequence+1, entry.Sequence),
				})
			}
			if !bytes.Equal(entry.PrevHash, prevEntry.EntryHash) {
				result.Valid = false
				result.Errors = append(result.Errors, VerificationError{
					EntryID:     entry.EntryID,
					Sequence:    entry.Sequence,
					ErrorType:   "prev_hash_mismatch",
					Description: "prev_hash does not match previous entry's hash",
				})
			}
		} else {
			if len(entry.PrevHash) > 0 {
				result.Warnings = append(result.Warnings, fmt.Sprintf("entry %s: genesis entry has non-empty prev_hash", entry.EntryID))
			}
		}

		if len(entry.DevicePublicKey) > 0 && len(entry.DeviceSignature) > 0 {
			if err := verifyDeviceSignature(entry); err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, VerificationError{
					EntryID:     entry.EntryID,
					Sequence:    entry.Sequence,
					ErrorType:   "signature_invalid",
					Description: err.Error(),
				})
			}
		}

		prevEntry = entry
	}

	return result
}

// VerifyRequestChain verifies the integrity of a request chain.
func (v *Verifier) VerifyRequestChain(entries []*RequestChainEntry) *VerificationResult {
	result := &VerificationResult{
		Valid:        true,
		EntriesCount: int64(len(entries)),
	}

	if len(entries) == 0 {
		return result
	}

	sortRequestEntries(entries)

	var prevEntry *RequestChainEntry
	for _, entry := range entries {
		computed := computeRequestEntryHash(entry)
		if !bytes.Equal(entry.EntryHash, computed) {
			result.Valid = false
			result.Errors = append(result.Errors, VerificationError{
				EntryID:     entry.EntryID,
				Sequence:    entry.Sequence,
				ErrorType:   "hash_mismatch",
				Description: fmt.Sprintf("hash mismatch: stored=%s computed=%s", hex.EncodeToString(entry.EntryHash), hex.EncodeToString(computed)),
			})
		}

		if prevEntry != nil {
			if entry.Sequence != prevEntry.Sequence+1 {
				result.Valid = false
				result.Errors = append(result.Errors, VerificationError{
					EntryID:     entry.EntryID,
					Sequence:    entry.Sequence,
					ErrorType:   "sequence_gap",
					Description: fmt.Sprintf("sequence gap: expected %d, got %d", prevEntry.Sequence+1, entry.Sequence),
				})
			}
			if !bytes.Equal(entry.PrevHash, prevEntry.EntryHash) {
				result.Valid = false
				result.Errors = append(result.Errors, VerificationError{
					EntryID:     entry.EntryID,
					Sequence:    entry.Sequence,
					ErrorType:   "prev_hash_mismatch",
					Description: "prev_hash does not match previous entry's hash",
				})
			}
		}

		prevEntry = entry
	}

	return result
}

// VerifyMerkleTree verifies a Merkle tree's integrity.
func (v *Verifier) VerifyMerkleTree(tree *MerkleTree) error {
	computed := computeMerkleRoot(tree.RequestChainTipHash, tree.DeviceChainTips)
	if !bytes.Equal(tree.MerkleRoot, computed) {
		return fmt.Errorf("merkle root mismatch: stored=%s computed=%s",
			hex.EncodeToString(tree.MerkleRoot),
			hex.EncodeToString(computed))
	}

	if key, ok := v.CoordinatorKeys[tree.CoordinatorKeyID]; ok {
		signingData := computeTreeSigningData(tree)
		if !ed25519.Verify(key, signingData, tree.CoordinatorSignature) {
			return fmt.Errorf("coordinator signature invalid")
		}
	}

	return nil
}

// VerifyTransparencyLog verifies the integrity of transparency log entries.
func (v *Verifier) VerifyTransparencyLog(entries []*TransparencyLogEntry) *VerificationResult {
	result := &VerificationResult{
		Valid:        true,
		EntriesCount: int64(len(entries)),
	}

	if len(entries) == 0 {
		return result
	}

	sortTransparencyEntries(entries)

	var prevEntry *TransparencyLogEntry
	for _, entry := range entries {
		computed := computeTransparencyEntryHash(entry)
		if !bytes.Equal(entry.EntryHash, computed) {
			result.Valid = false
			result.Errors = append(result.Errors, VerificationError{
				EntryID:     entry.EntryID,
				Sequence:    entry.Sequence,
				ErrorType:   "hash_mismatch",
				Description: fmt.Sprintf("hash mismatch: stored=%s computed=%s", hex.EncodeToString(entry.EntryHash), hex.EncodeToString(computed)),
			})
		}

		if prevEntry != nil {
			if entry.Sequence != prevEntry.Sequence+1 {
				result.Valid = false
				result.Errors = append(result.Errors, VerificationError{
					EntryID:     entry.EntryID,
					Sequence:    entry.Sequence,
					ErrorType:   "sequence_gap",
					Description: fmt.Sprintf("sequence gap: expected %d, got %d", prevEntry.Sequence+1, entry.Sequence),
				})
			}
			if !bytes.Equal(entry.PrevEntryHash, prevEntry.EntryHash) {
				result.Valid = false
				result.Errors = append(result.Errors, VerificationError{
					EntryID:     entry.EntryID,
					Sequence:    entry.Sequence,
					ErrorType:   "prev_hash_mismatch",
					Description: "prev_entry_hash does not match previous entry's hash",
				})
			}
		}

		prevEntry = entry
	}

	return result
}
