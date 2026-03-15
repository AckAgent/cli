package audit

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

func groupDeviceEntriesByDevice(entries []*DeviceChainEntry) map[string][]*DeviceChainEntry {
	groups := make(map[string][]*DeviceChainEntry)
	for _, entry := range entries {
		groups[entry.DeviceID] = append(groups[entry.DeviceID], entry)
	}
	return groups
}

func sortDeviceEntries(entries []*DeviceChainEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Sequence < entries[j].Sequence })
}

func sortRequestEntries(entries []*RequestChainEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Sequence < entries[j].Sequence })
}

func sortTransparencyEntries(entries []*TransparencyLogEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Sequence < entries[j].Sequence })
}

func computeDeviceEntryHash(e *DeviceChainEntry) []byte {
	h := sha256.New()
	h.Write([]byte(e.EntryID))
	h.Write([]byte(e.OrgID))
	h.Write([]byte(e.DeviceID))
	h.Write(int64Bytes(e.Sequence))
	h.Write(timeBytes(e.Timestamp))
	h.Write(e.PrevHash)
	h.Write([]byte(e.EntryType))
	h.Write(e.RequestHash)
	h.Write(e.ChallengeHash)
	h.Write([]byte(e.ChallengeContext))
	h.Write(e.EncryptedPayloadHash)
	h.Write(e.PlaintextHash)
	h.Write(e.DeviceSignature)
	h.Write(e.DevicePublicKey)
	h.Write([]byte(e.DeviceAuthPublicKeyHex))
	h.Write(e.AttestationData)
	h.Write([]byte(e.AttestationType))
	return h.Sum(nil)
}

func computeDeviceSigningData(e *DeviceChainEntry) []byte {
	h := sha256.New()
	h.Write([]byte(e.EntryID))
	h.Write([]byte(e.OrgID))
	h.Write([]byte(e.DeviceID))
	h.Write(int64Bytes(e.Sequence))
	h.Write(timeBytes(e.Timestamp))
	h.Write(e.PrevHash)
	h.Write([]byte(e.EntryType))
	h.Write(e.RequestHash)
	h.Write(e.ChallengeHash)
	h.Write([]byte(e.ChallengeContext))
	h.Write(e.EncryptedPayloadHash)
	h.Write(e.PlaintextHash)
	return h.Sum(nil)
}

func computeRequestEntryHash(e *RequestChainEntry) []byte {
	h := sha256.New()
	h.Write([]byte(e.EntryID))
	h.Write([]byte(e.OrgID))
	h.Write(int64Bytes(e.Sequence))
	h.Write(timeBytes(e.Timestamp))
	h.Write(e.PrevHash)
	h.Write([]byte(e.EntryType))
	h.Write([]byte(e.RequestID))
	h.Write([]byte(e.RequesterID))
	if ctx, err := json.Marshal(e.RequesterContext); err == nil {
		h.Write(ctx)
	}
	h.Write([]byte(e.SigningPublicKey))
	h.Write(e.EncryptedPayloadHash)
	h.Write(e.PlaintextHash)
	if e.ExpiresAt != nil {
		h.Write(timeBytes(*e.ExpiresAt))
	}
	h.Write(e.RequestEntryHash)
	h.Write([]byte(e.Outcome))
	h.Write([]byte(e.WinningDeviceID))
	h.Write(e.WinningDeviceEntryHash)
	return h.Sum(nil)
}

func computeTransparencyEntryHash(e *TransparencyLogEntry) []byte {
	h := sha256.New()
	h.Write(int64Bytes(e.Sequence))
	h.Write([]byte(e.EntryID))
	h.Write(timeBytes(e.Timestamp))
	h.Write([]byte(e.OrgID))
	h.Write(int64Bytes(e.TreeSequence))
	h.Write(e.MerkleRoot)
	h.Write(e.PrevEntryHash)
	return h.Sum(nil)
}

func computeMerkleRoot(requestTipHash []byte, deviceTips []DeviceChainTip) []byte {
	var leaves [][]byte

	if len(requestTipHash) > 0 {
		leaves = append(leaves, requestTipHash)
	} else {
		leaves = append(leaves, make([]byte, 32))
	}

	for _, tip := range deviceTips {
		leaves = append(leaves, tip.Hash)
	}

	return computeMerkleRootFromLeaves(leaves)
}

func computeMerkleRootFromLeaves(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return make([]byte, 32)
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	for len(leaves)&(len(leaves)-1) != 0 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}

	for len(leaves) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(leaves); i += 2 {
			h := sha256.New()
			h.Write(leaves[i])
			h.Write(leaves[i+1])
			nextLevel = append(nextLevel, h.Sum(nil))
		}
		leaves = nextLevel
	}

	return leaves[0]
}

func computeTreeSigningData(tree *MerkleTree) []byte {
	h := sha256.New()
	h.Write([]byte(tree.TreeID))
	h.Write([]byte(tree.OrgID))
	h.Write(int64Bytes(tree.Sequence))
	h.Write(timeBytes(tree.Timestamp))
	h.Write(tree.PrevRoot)
	h.Write(tree.RequestChainTipHash)
	h.Write(tree.MerkleRoot)
	return h.Sum(nil)
}

func verifyDeviceSignature(entry *DeviceChainEntry) error {
	pubKey, err := x509.ParsePKIXPublicKey(entry.DevicePublicKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an ECDSA public key")
	}

	signingData := computeDeviceSigningData(entry)

	if !ecdsa.VerifyASN1(ecdsaKey, signingData, entry.DeviceSignature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func int64Bytes(n int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(n))
	return b
}

func timeBytes(t time.Time) []byte {
	return int64Bytes(t.UnixNano())
}
