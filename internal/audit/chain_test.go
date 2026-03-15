package audit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"math"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// makeDeviceEntry creates a DeviceChainEntry with its EntryHash correctly computed.
func makeDeviceEntry(seq int64, prevHash []byte) *DeviceChainEntry {
	e := &DeviceChainEntry{
		EntryID:              "dev-entry-" + string(rune('a'+seq)),
		OrgID:                "org-1",
		DeviceID:             "device-1",
		Sequence:             seq,
		Timestamp:            time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(seq) * time.Hour),
		PrevHash:             prevHash,
		EntryType:            "approval",
		EncryptedPayloadHash: []byte("encrypted"),
		PlaintextHash:        []byte("plaintext"),
	}
	e.EntryHash = computeDeviceEntryHash(e)
	return e
}

// makeDeviceChain builds a valid hash-linked device chain of length n (starting at sequence 0).
func makeDeviceChain(n int) []*DeviceChainEntry {
	chain := make([]*DeviceChainEntry, 0, n)
	var prevHash []byte
	for i := 0; i < n; i++ {
		e := makeDeviceEntry(int64(i), prevHash)
		chain = append(chain, e)
		prevHash = e.EntryHash
	}
	return chain
}

// makeSignedDeviceEntry creates a DeviceChainEntry with a real ECDSA P-256 signature.
func makeSignedDeviceEntry(t *testing.T, key *ecdsa.PrivateKey, seq int64, prevHash []byte) *DeviceChainEntry {
	t.Helper()
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	e := &DeviceChainEntry{
		EntryID:              "signed-entry",
		OrgID:                "org-1",
		DeviceID:             "device-1",
		Sequence:             seq,
		Timestamp:            time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
		PrevHash:             prevHash,
		EntryType:            "approval",
		EncryptedPayloadHash: []byte("enc-payload"),
		PlaintextHash:        []byte("plain-payload"),
		DevicePublicKey:      pubKeyBytes,
	}
	// Sign before computing entry hash (entry hash includes the signature + public key)
	signingData := computeDeviceSigningData(e)
	sig, err := ecdsa.SignASN1(rand.Reader, key, signingData)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	e.DeviceSignature = sig
	e.EntryHash = computeDeviceEntryHash(e)
	return e
}

// makeRequestEntry creates a RequestChainEntry with its EntryHash correctly computed.
func makeRequestEntry(seq int64, prevHash []byte) *RequestChainEntry {
	e := &RequestChainEntry{
		EntryID:   "req-entry-" + string(rune('a'+seq)),
		OrgID:     "org-1",
		Sequence:  seq,
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(seq) * time.Hour),
		PrevHash:  prevHash,
		EntryType: "request",
		RequestID: "req-123",
		RequesterContext: RequesterContext{
			ClientIP:  "10.0.0.1",
			UserAgent: "test-agent",
		},
	}
	e.EntryHash = computeRequestEntryHash(e)
	return e
}

// makeRequestChain builds a valid hash-linked request chain of length n.
func makeRequestChain(n int) []*RequestChainEntry {
	chain := make([]*RequestChainEntry, 0, n)
	var prevHash []byte
	for i := 0; i < n; i++ {
		e := makeRequestEntry(int64(i), prevHash)
		chain = append(chain, e)
		prevHash = e.EntryHash
	}
	return chain
}

// makeTransparencyEntry creates a TransparencyLogEntry with its EntryHash correctly computed.
func makeTransparencyEntry(seq int64, prevHash []byte) *TransparencyLogEntry {
	e := &TransparencyLogEntry{
		Sequence:      seq,
		EntryID:       "tl-entry-" + string(rune('a'+seq)),
		Timestamp:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(seq) * time.Hour),
		OrgID:         "org-1",
		TreeSequence:  seq,
		MerkleRoot:    []byte("merkle-root-placeholder"),
		PrevEntryHash: prevHash,
	}
	e.EntryHash = computeTransparencyEntryHash(e)
	return e
}

// makeTransparencyChain builds a valid hash-linked transparency chain of length n.
func makeTransparencyChain(n int) []*TransparencyLogEntry {
	chain := make([]*TransparencyLogEntry, 0, n)
	var prevHash []byte
	for i := 0; i < n; i++ {
		e := makeTransparencyEntry(int64(i), prevHash)
		chain = append(chain, e)
		prevHash = e.EntryHash
	}
	return chain
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

func TestInt64Bytes(t *testing.T) {
	tests := []struct {
		name string
		val  int64
	}{
		{"zero", 0},
		{"positive", 42},
		{"negative", -1},
		{"max_int64", math.MaxInt64},
		{"min_int64", math.MinInt64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := int64Bytes(tt.val)
			if len(b) != 8 {
				t.Fatalf("expected 8 bytes, got %d", len(b))
			}
			got := int64(binary.BigEndian.Uint64(b))
			if got != tt.val {
				t.Errorf("int64Bytes(%d) round-trip = %d", tt.val, got)
			}
		})
	}
}

func TestTimeBytes(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 30, 45, 123456789, time.UTC)
	b := timeBytes(ts)
	if len(b) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(b))
	}
	got := int64(binary.BigEndian.Uint64(b))
	if got != ts.UnixNano() {
		t.Errorf("timeBytes produced %d, want %d", got, ts.UnixNano())
	}

	// Zero time
	zeroTime := time.Time{}
	zero := timeBytes(zeroTime)
	zeroVal := int64(binary.BigEndian.Uint64(zero))
	wantZero := zeroTime.UnixNano()
	if zeroVal != wantZero {
		t.Errorf("timeBytes(zero) produced %d, want %d", zeroVal, wantZero)
	}
}

// ---------------------------------------------------------------------------
// Hash functions — determinism & field sensitivity
// ---------------------------------------------------------------------------

func TestComputeDeviceEntryHash_Determinism(t *testing.T) {
	e := makeDeviceEntry(1, []byte("prev"))
	// Reset EntryHash so we can recompute
	h1 := computeDeviceEntryHash(e)
	h2 := computeDeviceEntryHash(e)
	if !bytes.Equal(h1, h2) {
		t.Error("computeDeviceEntryHash is not deterministic")
	}
}

func TestComputeDeviceEntryHash_FieldSensitivity(t *testing.T) {
	base := makeDeviceEntry(1, []byte("prev"))
	baseHash := computeDeviceEntryHash(base)

	// Changing any field must produce a different hash
	fields := []struct {
		name   string
		mutate func(e *DeviceChainEntry)
	}{
		{"EntryID", func(e *DeviceChainEntry) { e.EntryID = "different" }},
		{"OrgID", func(e *DeviceChainEntry) { e.OrgID = "different" }},
		{"DeviceID", func(e *DeviceChainEntry) { e.DeviceID = "different" }},
		{"Sequence", func(e *DeviceChainEntry) { e.Sequence = 999 }},
		{"Timestamp", func(e *DeviceChainEntry) { e.Timestamp = time.Now() }},
		{"PrevHash", func(e *DeviceChainEntry) { e.PrevHash = []byte("other") }},
		{"EntryType", func(e *DeviceChainEntry) { e.EntryType = "rejection" }},
		{"EncryptedPayloadHash", func(e *DeviceChainEntry) { e.EncryptedPayloadHash = []byte("changed") }},
		{"PlaintextHash", func(e *DeviceChainEntry) { e.PlaintextHash = []byte("changed") }},
		{"ChallengeContext", func(e *DeviceChainEntry) { e.ChallengeContext = "ctx" }},
	}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			clone := *base
			f.mutate(&clone)
			mutatedHash := computeDeviceEntryHash(&clone)
			if bytes.Equal(mutatedHash, baseHash) {
				t.Errorf("changing %s did not change the hash", f.name)
			}
		})
	}
}

func TestComputeRequestEntryHash_Determinism(t *testing.T) {
	e := makeRequestEntry(1, []byte("prev"))
	h1 := computeRequestEntryHash(e)
	h2 := computeRequestEntryHash(e)
	if !bytes.Equal(h1, h2) {
		t.Error("computeRequestEntryHash is not deterministic")
	}
}

func TestComputeRequestEntryHash_FieldSensitivity(t *testing.T) {
	base := makeRequestEntry(1, []byte("prev"))
	baseHash := computeRequestEntryHash(base)

	fields := []struct {
		name   string
		mutate func(e *RequestChainEntry)
	}{
		{"EntryID", func(e *RequestChainEntry) { e.EntryID = "different" }},
		{"OrgID", func(e *RequestChainEntry) { e.OrgID = "different" }},
		{"Sequence", func(e *RequestChainEntry) { e.Sequence = 999 }},
		{"Timestamp", func(e *RequestChainEntry) { e.Timestamp = time.Now() }},
		{"PrevHash", func(e *RequestChainEntry) { e.PrevHash = []byte("other") }},
		{"EntryType", func(e *RequestChainEntry) { e.EntryType = "different" }},
		{"RequestID", func(e *RequestChainEntry) { e.RequestID = "different" }},
		{"RequesterID", func(e *RequestChainEntry) { e.RequesterID = "different" }},
		{"Outcome", func(e *RequestChainEntry) { e.Outcome = "approved" }},
		{"WinningDeviceID", func(e *RequestChainEntry) { e.WinningDeviceID = "dev-99" }},
	}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			clone := *base
			f.mutate(&clone)
			mutatedHash := computeRequestEntryHash(&clone)
			if bytes.Equal(mutatedHash, baseHash) {
				t.Errorf("changing %s did not change the hash", f.name)
			}
		})
	}
}

func TestComputeTransparencyEntryHash_Determinism(t *testing.T) {
	e := makeTransparencyEntry(1, []byte("prev"))
	h1 := computeTransparencyEntryHash(e)
	h2 := computeTransparencyEntryHash(e)
	if !bytes.Equal(h1, h2) {
		t.Error("computeTransparencyEntryHash is not deterministic")
	}
}

func TestComputeTransparencyEntryHash_FieldSensitivity(t *testing.T) {
	base := makeTransparencyEntry(1, []byte("prev"))
	baseHash := computeTransparencyEntryHash(base)

	fields := []struct {
		name   string
		mutate func(e *TransparencyLogEntry)
	}{
		{"Sequence", func(e *TransparencyLogEntry) { e.Sequence = 999 }},
		{"EntryID", func(e *TransparencyLogEntry) { e.EntryID = "different" }},
		{"Timestamp", func(e *TransparencyLogEntry) { e.Timestamp = time.Now() }},
		{"OrgID", func(e *TransparencyLogEntry) { e.OrgID = "different" }},
		{"TreeSequence", func(e *TransparencyLogEntry) { e.TreeSequence = 999 }},
		{"MerkleRoot", func(e *TransparencyLogEntry) { e.MerkleRoot = []byte("different") }},
		{"PrevEntryHash", func(e *TransparencyLogEntry) { e.PrevEntryHash = []byte("different") }},
	}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			clone := *base
			f.mutate(&clone)
			mutatedHash := computeTransparencyEntryHash(&clone)
			if bytes.Equal(mutatedHash, baseHash) {
				t.Errorf("changing %s did not change the hash", f.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Signing data
// ---------------------------------------------------------------------------

func TestComputeDeviceSigningData_ExcludesFields(t *testing.T) {
	// computeDeviceSigningData must NOT include DeviceSignature, DevicePublicKey,
	// DeviceAuthPublicKeyHex, AttestationData, or AttestationType.
	base := &DeviceChainEntry{
		EntryID:              "e1",
		OrgID:                "org-1",
		DeviceID:             "d1",
		Sequence:             1,
		Timestamp:            time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		EntryType:            "approval",
		EncryptedPayloadHash: []byte("enc"),
		PlaintextHash:        []byte("plain"),
	}
	baseData := computeDeviceSigningData(base)

	// Changing excluded fields should NOT change signing data
	excluded := []struct {
		name   string
		mutate func(e *DeviceChainEntry)
	}{
		{"DeviceSignature", func(e *DeviceChainEntry) { e.DeviceSignature = []byte("sig") }},
		{"DevicePublicKey", func(e *DeviceChainEntry) { e.DevicePublicKey = []byte("key") }},
		{"DeviceAuthPublicKeyHex", func(e *DeviceChainEntry) { e.DeviceAuthPublicKeyHex = "aabbccdd" }},
		{"AttestationData", func(e *DeviceChainEntry) { e.AttestationData = []byte("attest") }},
		{"AttestationType", func(e *DeviceChainEntry) { e.AttestationType = "ios_secure_enclave" }},
	}
	for _, f := range excluded {
		t.Run(f.name+"_excluded", func(t *testing.T) {
			clone := *base
			f.mutate(&clone)
			mutatedData := computeDeviceSigningData(&clone)
			if !bytes.Equal(mutatedData, baseData) {
				t.Errorf("changing excluded field %s changed signing data", f.name)
			}
		})
	}

	// Changing included fields should change signing data
	included := []struct {
		name   string
		mutate func(e *DeviceChainEntry)
	}{
		{"EntryID", func(e *DeviceChainEntry) { e.EntryID = "other" }},
		{"Sequence", func(e *DeviceChainEntry) { e.Sequence = 99 }},
		{"EntryType", func(e *DeviceChainEntry) { e.EntryType = "other" }},
		{"PlaintextHash", func(e *DeviceChainEntry) { e.PlaintextHash = []byte("other") }},
	}
	for _, f := range included {
		t.Run(f.name+"_included", func(t *testing.T) {
			clone := *base
			f.mutate(&clone)
			mutatedData := computeDeviceSigningData(&clone)
			if bytes.Equal(mutatedData, baseData) {
				t.Errorf("changing included field %s did not change signing data", f.name)
			}
		})
	}
}

func TestComputeTreeSigningData(t *testing.T) {
	tree := &MerkleTree{
		TreeID:              "tree-1",
		OrgID:               "org-1",
		Sequence:            5,
		Timestamp:           time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
		PrevRoot:            []byte("prev-root"),
		RequestChainTipHash: []byte("req-tip"),
		MerkleRoot:          []byte("root"),
	}

	d1 := computeTreeSigningData(tree)
	d2 := computeTreeSigningData(tree)
	if !bytes.Equal(d1, d2) {
		t.Error("computeTreeSigningData is not deterministic")
	}

	// Changing fields must change signing data
	fields := []struct {
		name   string
		mutate func(tr *MerkleTree)
	}{
		{"TreeID", func(tr *MerkleTree) { tr.TreeID = "different" }},
		{"OrgID", func(tr *MerkleTree) { tr.OrgID = "different" }},
		{"Sequence", func(tr *MerkleTree) { tr.Sequence = 999 }},
		{"Timestamp", func(tr *MerkleTree) { tr.Timestamp = time.Now() }},
		{"PrevRoot", func(tr *MerkleTree) { tr.PrevRoot = []byte("different") }},
		{"RequestChainTipHash", func(tr *MerkleTree) { tr.RequestChainTipHash = []byte("different") }},
		{"MerkleRoot", func(tr *MerkleTree) { tr.MerkleRoot = []byte("different") }},
	}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			clone := *tree
			f.mutate(&clone)
			mutated := computeTreeSigningData(&clone)
			if bytes.Equal(mutated, d1) {
				t.Errorf("changing %s did not change tree signing data", f.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Merkle tree computation
// ---------------------------------------------------------------------------

func TestComputeMerkleRootFromLeaves(t *testing.T) {
	t.Run("zero_leaves", func(t *testing.T) {
		root := computeMerkleRootFromLeaves(nil)
		if len(root) != 32 {
			t.Fatalf("expected 32 zero bytes, got %d", len(root))
		}
		if !bytes.Equal(root, make([]byte, 32)) {
			t.Error("zero leaves should return 32 zero bytes")
		}
	})

	t.Run("one_leaf", func(t *testing.T) {
		leaf := sha256Bytes([]byte("leaf"))
		root := computeMerkleRootFromLeaves([][]byte{leaf})
		if !bytes.Equal(root, leaf) {
			t.Error("single leaf should be returned as root")
		}
	})

	t.Run("two_leaves", func(t *testing.T) {
		a := sha256Bytes([]byte("a"))
		b := sha256Bytes([]byte("b"))
		root := computeMerkleRootFromLeaves([][]byte{a, b})

		// Manual: H(a || b)
		h := sha256.New()
		h.Write(a)
		h.Write(b)
		expected := h.Sum(nil)
		if !bytes.Equal(root, expected) {
			t.Error("two leaves: root mismatch")
		}
	})

	t.Run("three_leaves_padding", func(t *testing.T) {
		a := sha256Bytes([]byte("a"))
		b := sha256Bytes([]byte("b"))
		c := sha256Bytes([]byte("c"))
		root := computeMerkleRootFromLeaves([][]byte{a, b, c})

		// 3 leaves → pad to 4: [a, b, c, c]
		// Level 1: H(a||b), H(c||c)
		// Level 2: H(H(a||b) || H(c||c))
		hab := hashPair(a, b)
		hcc := hashPair(c, c)
		expected := hashPair(hab, hcc)
		if !bytes.Equal(root, expected) {
			t.Error("three leaves: root mismatch")
		}
	})

	t.Run("four_leaves", func(t *testing.T) {
		leaves := make([][]byte, 4)
		for i := range leaves {
			leaves[i] = sha256Bytes([]byte{byte(i)})
		}
		root := computeMerkleRootFromLeaves(leaves)

		h01 := hashPair(leaves[0], leaves[1])
		h23 := hashPair(leaves[2], leaves[3])
		expected := hashPair(h01, h23)
		if !bytes.Equal(root, expected) {
			t.Error("four leaves: root mismatch")
		}
	})

	t.Run("five_leaves_padding", func(t *testing.T) {
		leaves := make([][]byte, 5)
		for i := range leaves {
			leaves[i] = sha256Bytes([]byte{byte(i)})
		}
		root := computeMerkleRootFromLeaves(leaves)
		// 5 → pad to 8: [0,1,2,3,4,4,4,4]
		padded := make([][]byte, 8)
		copy(padded, leaves)
		for i := 5; i < 8; i++ {
			padded[i] = leaves[4]
		}
		h01 := hashPair(padded[0], padded[1])
		h23 := hashPair(padded[2], padded[3])
		h45 := hashPair(padded[4], padded[5])
		h67 := hashPair(padded[6], padded[7])
		h0123 := hashPair(h01, h23)
		h4567 := hashPair(h45, h67)
		expected := hashPair(h0123, h4567)
		if !bytes.Equal(root, expected) {
			t.Error("five leaves: root mismatch")
		}
	})

	t.Run("eight_leaves", func(t *testing.T) {
		leaves := make([][]byte, 8)
		for i := range leaves {
			leaves[i] = sha256Bytes([]byte{byte(i)})
		}
		root := computeMerkleRootFromLeaves(leaves)
		// Already power of 2, no padding needed
		h01 := hashPair(leaves[0], leaves[1])
		h23 := hashPair(leaves[2], leaves[3])
		h45 := hashPair(leaves[4], leaves[5])
		h67 := hashPair(leaves[6], leaves[7])
		h0123 := hashPair(h01, h23)
		h4567 := hashPair(h45, h67)
		expected := hashPair(h0123, h4567)
		if !bytes.Equal(root, expected) {
			t.Error("eight leaves: root mismatch")
		}
	})

	t.Run("ordering_matters", func(t *testing.T) {
		a := sha256Bytes([]byte("a"))
		b := sha256Bytes([]byte("b"))
		root1 := computeMerkleRootFromLeaves([][]byte{a, b})
		root2 := computeMerkleRootFromLeaves([][]byte{b, a})
		if bytes.Equal(root1, root2) {
			t.Error("leaf ordering should affect the merkle root")
		}
	})
}

func TestComputeMerkleRoot(t *testing.T) {
	t.Run("with_request_tip_and_device_tips", func(t *testing.T) {
		reqTip := sha256Bytes([]byte("request-tip"))
		tips := []DeviceChainTip{
			{DeviceID: "d1", Hash: sha256Bytes([]byte("d1-hash")), Sequence: 1},
			{DeviceID: "d2", Hash: sha256Bytes([]byte("d2-hash")), Sequence: 2},
		}
		root := computeMerkleRoot(reqTip, tips)

		// Manual: leaves = [reqTip, d1Hash, d2Hash] → pad to 4
		leaves := [][]byte{reqTip, tips[0].Hash, tips[1].Hash}
		expected := computeMerkleRootFromLeaves(leaves)
		if !bytes.Equal(root, expected) {
			t.Error("computeMerkleRoot with tips mismatch")
		}
	})

	t.Run("nil_request_tip_uses_zero_hash", func(t *testing.T) {
		tips := []DeviceChainTip{
			{DeviceID: "d1", Hash: sha256Bytes([]byte("d1")), Sequence: 1},
		}
		root := computeMerkleRoot(nil, tips)
		leaves := [][]byte{make([]byte, 32), tips[0].Hash}
		expected := computeMerkleRootFromLeaves(leaves)
		if !bytes.Equal(root, expected) {
			t.Error("nil request tip should use zero hash")
		}
	})

	t.Run("no_device_tips", func(t *testing.T) {
		reqTip := sha256Bytes([]byte("req"))
		root := computeMerkleRoot(reqTip, nil)
		// Single leaf = reqTip
		if !bytes.Equal(root, reqTip) {
			t.Error("no device tips: root should equal request tip hash")
		}
	})
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

func TestVerifyDeviceSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	t.Run("valid_signature", func(t *testing.T) {
		entry := makeSignedDeviceEntry(t, key, 0, nil)
		if err := verifyDeviceSignature(entry); err != nil {
			t.Fatalf("expected valid signature, got: %v", err)
		}
	})

	t.Run("invalid_public_key", func(t *testing.T) {
		entry := makeSignedDeviceEntry(t, key, 0, nil)
		entry.DevicePublicKey = []byte("not-a-valid-key")
		if err := verifyDeviceSignature(entry); err == nil {
			t.Fatal("expected error for invalid public key")
		}
	})

	t.Run("wrong_signature", func(t *testing.T) {
		entry := makeSignedDeviceEntry(t, key, 0, nil)
		entry.DeviceSignature = []byte("wrong-signature")
		if err := verifyDeviceSignature(entry); err == nil {
			t.Fatal("expected error for wrong signature")
		}
	})

	t.Run("tampered_data", func(t *testing.T) {
		entry := makeSignedDeviceEntry(t, key, 0, nil)
		entry.PlaintextHash = []byte("tampered")
		// Signature was over original data, so verification should fail
		if err := verifyDeviceSignature(entry); err == nil {
			t.Fatal("expected error for tampered data")
		}
	})

	t.Run("wrong_key", func(t *testing.T) {
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate other key: %v", err)
		}
		entry := makeSignedDeviceEntry(t, key, 0, nil)
		// Replace public key with a different key's public key
		otherPub, err := x509.MarshalPKIXPublicKey(&otherKey.PublicKey)
		if err != nil {
			t.Fatalf("marshal other key: %v", err)
		}
		entry.DevicePublicKey = otherPub
		if err := verifyDeviceSignature(entry); err == nil {
			t.Fatal("expected error for wrong key")
		}
	})
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func TestGroupDeviceEntriesByDevice(t *testing.T) {
	entries := []*DeviceChainEntry{
		{DeviceID: "d1", Sequence: 0},
		{DeviceID: "d2", Sequence: 0},
		{DeviceID: "d1", Sequence: 1},
		{DeviceID: "d3", Sequence: 0},
		{DeviceID: "d2", Sequence: 1},
	}
	groups := groupDeviceEntriesByDevice(entries)

	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}
	if len(groups["d1"]) != 2 {
		t.Errorf("d1: expected 2 entries, got %d", len(groups["d1"]))
	}
	if len(groups["d2"]) != 2 {
		t.Errorf("d2: expected 2 entries, got %d", len(groups["d2"]))
	}
	if len(groups["d3"]) != 1 {
		t.Errorf("d3: expected 1 entry, got %d", len(groups["d3"]))
	}
}

func TestSortDeviceEntries(t *testing.T) {
	entries := []*DeviceChainEntry{
		{Sequence: 3},
		{Sequence: 1},
		{Sequence: 2},
		{Sequence: 0},
	}
	sortDeviceEntries(entries)
	for i, e := range entries {
		if e.Sequence != int64(i) {
			t.Errorf("index %d: expected sequence %d, got %d", i, i, e.Sequence)
		}
	}
}

func TestSortRequestEntries(t *testing.T) {
	entries := []*RequestChainEntry{
		{Sequence: 2},
		{Sequence: 0},
		{Sequence: 1},
	}
	sortRequestEntries(entries)
	for i, e := range entries {
		if e.Sequence != int64(i) {
			t.Errorf("index %d: expected sequence %d, got %d", i, i, e.Sequence)
		}
	}
}

func TestSortTransparencyEntries(t *testing.T) {
	entries := []*TransparencyLogEntry{
		{Sequence: 5},
		{Sequence: 1},
		{Sequence: 3},
	}
	sortTransparencyEntries(entries)
	prev := int64(-1)
	for _, e := range entries {
		if e.Sequence <= prev {
			t.Errorf("not sorted: sequence %d after %d", e.Sequence, prev)
		}
		prev = e.Sequence
	}
}

// ---------------------------------------------------------------------------
// VerifyDeviceChain
// ---------------------------------------------------------------------------

func TestVerifyDeviceChain(t *testing.T) {
	v := NewVerifier()

	t.Run("empty_chain", func(t *testing.T) {
		r := v.VerifyDeviceChain(nil)
		if !r.Valid {
			t.Error("empty chain should be valid")
		}
		if r.EntriesCount != 0 {
			t.Errorf("expected 0 entries, got %d", r.EntriesCount)
		}
	})

	t.Run("valid_single_entry", func(t *testing.T) {
		chain := makeDeviceChain(1)
		r := v.VerifyDeviceChain(chain)
		if !r.Valid {
			t.Errorf("expected valid, got errors: %v", r.Errors)
		}
		if r.EntriesCount != 1 {
			t.Errorf("expected 1 entry, got %d", r.EntriesCount)
		}
	})

	t.Run("valid_three_entry_chain", func(t *testing.T) {
		chain := makeDeviceChain(3)
		r := v.VerifyDeviceChain(chain)
		if !r.Valid {
			t.Errorf("expected valid, got errors: %v", r.Errors)
		}
		if r.EntriesCount != 3 {
			t.Errorf("expected 3 entries, got %d", r.EntriesCount)
		}
	})

	t.Run("hash_mismatch", func(t *testing.T) {
		chain := makeDeviceChain(3)
		chain[1].EntryHash = []byte("wrong-hash")
		r := v.VerifyDeviceChain(chain)
		if r.Valid {
			t.Error("expected invalid for hash mismatch")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "hash_mismatch" {
				found = true
			}
		}
		if !found {
			t.Error("expected hash_mismatch error type")
		}
	})

	t.Run("sequence_gap", func(t *testing.T) {
		chain := makeDeviceChain(3)
		chain[2].Sequence = 5 // Gap: 0, 1, 5
		r := v.VerifyDeviceChain(chain)
		if r.Valid {
			t.Error("expected invalid for sequence gap")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "sequence_gap" {
				found = true
			}
		}
		if !found {
			t.Error("expected sequence_gap error type")
		}
	})

	t.Run("prev_hash_mismatch", func(t *testing.T) {
		chain := makeDeviceChain(3)
		chain[2].PrevHash = []byte("wrong-prev-hash")
		// Recompute entry hash so hash_mismatch doesn't fire
		chain[2].EntryHash = computeDeviceEntryHash(chain[2])
		r := v.VerifyDeviceChain(chain)
		if r.Valid {
			t.Error("expected invalid for prev_hash mismatch")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "prev_hash_mismatch" {
				found = true
			}
		}
		if !found {
			t.Error("expected prev_hash_mismatch error type")
		}
	})

	t.Run("genesis_entry_with_prev_hash_warning", func(t *testing.T) {
		chain := makeDeviceChain(1)
		chain[0].PrevHash = []byte("unexpected")
		chain[0].EntryHash = computeDeviceEntryHash(chain[0])
		r := v.VerifyDeviceChain(chain)
		if !r.Valid {
			t.Error("genesis with prev_hash should still be valid (warning only)")
		}
		if len(r.Warnings) == 0 {
			t.Error("expected warning for genesis entry with prev_hash")
		}
	})

	t.Run("signature_verification_integration", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		entry := makeSignedDeviceEntry(t, key, 0, nil)
		r := v.VerifyDeviceChain([]*DeviceChainEntry{entry})
		if !r.Valid {
			t.Errorf("expected valid signed chain, got errors: %v", r.Errors)
		}
	})

	t.Run("invalid_signature_detected", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		entry := makeSignedDeviceEntry(t, key, 0, nil)
		// Corrupt signature
		entry.DeviceSignature[0] ^= 0xFF
		// Recompute entry hash so hash check passes
		entry.EntryHash = computeDeviceEntryHash(entry)
		r := v.VerifyDeviceChain([]*DeviceChainEntry{entry})
		if r.Valid {
			t.Error("expected invalid for corrupted signature")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "signature_invalid" {
				found = true
			}
		}
		if !found {
			t.Error("expected signature_invalid error type")
		}
	})

	t.Run("unsorted_input_is_sorted", func(t *testing.T) {
		chain := makeDeviceChain(3)
		// Reverse order
		reversed := []*DeviceChainEntry{chain[2], chain[0], chain[1]}
		r := v.VerifyDeviceChain(reversed)
		if !r.Valid {
			t.Errorf("out-of-order chain should pass after sorting, got errors: %v", r.Errors)
		}
	})
}

// ---------------------------------------------------------------------------
// VerifyRequestChain
// ---------------------------------------------------------------------------

func TestVerifyRequestChain(t *testing.T) {
	v := NewVerifier()

	t.Run("empty_chain", func(t *testing.T) {
		r := v.VerifyRequestChain(nil)
		if !r.Valid {
			t.Error("empty chain should be valid")
		}
	})

	t.Run("valid_three_entry_chain", func(t *testing.T) {
		chain := makeRequestChain(3)
		r := v.VerifyRequestChain(chain)
		if !r.Valid {
			t.Errorf("expected valid, got errors: %v", r.Errors)
		}
		if r.EntriesCount != 3 {
			t.Errorf("expected 3 entries, got %d", r.EntriesCount)
		}
	})

	t.Run("hash_mismatch", func(t *testing.T) {
		chain := makeRequestChain(3)
		chain[1].EntryHash = []byte("wrong")
		r := v.VerifyRequestChain(chain)
		if r.Valid {
			t.Error("expected invalid for hash mismatch")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "hash_mismatch" {
				found = true
			}
		}
		if !found {
			t.Error("expected hash_mismatch error type")
		}
	})

	t.Run("sequence_gap", func(t *testing.T) {
		chain := makeRequestChain(3)
		chain[2].Sequence = 10
		r := v.VerifyRequestChain(chain)
		if r.Valid {
			t.Error("expected invalid for sequence gap")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "sequence_gap" {
				found = true
			}
		}
		if !found {
			t.Error("expected sequence_gap error type")
		}
	})

	t.Run("prev_hash_mismatch", func(t *testing.T) {
		chain := makeRequestChain(3)
		chain[2].PrevHash = []byte("bad-prev")
		chain[2].EntryHash = computeRequestEntryHash(chain[2])
		r := v.VerifyRequestChain(chain)
		if r.Valid {
			t.Error("expected invalid for prev_hash mismatch")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "prev_hash_mismatch" {
				found = true
			}
		}
		if !found {
			t.Error("expected prev_hash_mismatch error type")
		}
	})

	t.Run("unsorted_input_is_sorted", func(t *testing.T) {
		chain := makeRequestChain(3)
		reversed := []*RequestChainEntry{chain[2], chain[0], chain[1]}
		r := v.VerifyRequestChain(reversed)
		if !r.Valid {
			t.Errorf("unsorted chain should pass after sorting, got errors: %v", r.Errors)
		}
	})
}

// ---------------------------------------------------------------------------
// VerifyTransparencyLog
// ---------------------------------------------------------------------------

func TestVerifyTransparencyLog(t *testing.T) {
	v := NewVerifier()

	t.Run("empty_log", func(t *testing.T) {
		r := v.VerifyTransparencyLog(nil)
		if !r.Valid {
			t.Error("empty log should be valid")
		}
	})

	t.Run("valid_three_entry_log", func(t *testing.T) {
		chain := makeTransparencyChain(3)
		r := v.VerifyTransparencyLog(chain)
		if !r.Valid {
			t.Errorf("expected valid, got errors: %v", r.Errors)
		}
		if r.EntriesCount != 3 {
			t.Errorf("expected 3 entries, got %d", r.EntriesCount)
		}
	})

	t.Run("hash_mismatch", func(t *testing.T) {
		chain := makeTransparencyChain(3)
		chain[1].EntryHash = []byte("wrong")
		r := v.VerifyTransparencyLog(chain)
		if r.Valid {
			t.Error("expected invalid for hash mismatch")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "hash_mismatch" {
				found = true
			}
		}
		if !found {
			t.Error("expected hash_mismatch error type")
		}
	})

	t.Run("sequence_gap", func(t *testing.T) {
		chain := makeTransparencyChain(3)
		chain[2].Sequence = 10
		r := v.VerifyTransparencyLog(chain)
		if r.Valid {
			t.Error("expected invalid for sequence gap")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "sequence_gap" {
				found = true
			}
		}
		if !found {
			t.Error("expected sequence_gap error type")
		}
	})

	t.Run("prev_hash_mismatch", func(t *testing.T) {
		chain := makeTransparencyChain(3)
		chain[2].PrevEntryHash = []byte("bad-prev")
		chain[2].EntryHash = computeTransparencyEntryHash(chain[2])
		r := v.VerifyTransparencyLog(chain)
		if r.Valid {
			t.Error("expected invalid for prev_hash mismatch")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "prev_hash_mismatch" {
				found = true
			}
		}
		if !found {
			t.Error("expected prev_hash_mismatch error type")
		}
	})

	t.Run("unsorted_input_is_sorted", func(t *testing.T) {
		chain := makeTransparencyChain(3)
		reversed := []*TransparencyLogEntry{chain[2], chain[0], chain[1]}
		r := v.VerifyTransparencyLog(reversed)
		if !r.Valid {
			t.Errorf("unsorted log should pass after sorting, got errors: %v", r.Errors)
		}
	})
}

// ---------------------------------------------------------------------------
// VerifyMerkleTree
// ---------------------------------------------------------------------------

func TestVerifyMerkleTree(t *testing.T) {
	t.Run("valid_tree", func(t *testing.T) {
		v := NewVerifier()
		reqTip := sha256Bytes([]byte("req-tip"))
		tips := []DeviceChainTip{
			{DeviceID: "d1", Hash: sha256Bytes([]byte("d1")), Sequence: 1},
		}
		root := computeMerkleRoot(reqTip, tips)
		tree := &MerkleTree{
			TreeID:              "tree-1",
			OrgID:               "org-1",
			Sequence:            1,
			Timestamp:           time.Now(),
			RequestChainTipHash: reqTip,
			DeviceChainTips:     tips,
			MerkleRoot:          root,
			CoordinatorKeyID:    "key-1",
		}
		if err := v.VerifyMerkleTree(tree); err != nil {
			t.Fatalf("expected valid tree, got: %v", err)
		}
	})

	t.Run("root_mismatch", func(t *testing.T) {
		v := NewVerifier()
		reqTip := sha256Bytes([]byte("req-tip"))
		tree := &MerkleTree{
			TreeID:              "tree-1",
			OrgID:               "org-1",
			Sequence:            1,
			Timestamp:           time.Now(),
			RequestChainTipHash: reqTip,
			MerkleRoot:          []byte("wrong-root"),
			CoordinatorKeyID:    "key-1",
		}
		if err := v.VerifyMerkleTree(tree); err == nil {
			t.Fatal("expected error for root mismatch")
		}
	})

	t.Run("valid_coordinator_ed25519_signature", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate ed25519 key: %v", err)
		}
		v := NewVerifier()
		v.CoordinatorKeys["coord-key"] = pub

		reqTip := sha256Bytes([]byte("req"))
		tips := []DeviceChainTip{
			{DeviceID: "d1", Hash: sha256Bytes([]byte("d1")), Sequence: 1},
		}
		root := computeMerkleRoot(reqTip, tips)
		tree := &MerkleTree{
			TreeID:              "tree-1",
			OrgID:               "org-1",
			Sequence:            1,
			Timestamp:           time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
			RequestChainTipHash: reqTip,
			DeviceChainTips:     tips,
			MerkleRoot:          root,
			CoordinatorKeyID:    "coord-key",
		}
		signingData := computeTreeSigningData(tree)
		tree.CoordinatorSignature = ed25519.Sign(priv, signingData)

		if err := v.VerifyMerkleTree(tree); err != nil {
			t.Fatalf("expected valid signed tree, got: %v", err)
		}
	})

	t.Run("invalid_coordinator_signature", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate ed25519 key: %v", err)
		}
		v := NewVerifier()
		v.CoordinatorKeys["coord-key"] = pub

		reqTip := sha256Bytes([]byte("req"))
		root := computeMerkleRoot(reqTip, nil)
		tree := &MerkleTree{
			TreeID:               "tree-1",
			OrgID:                "org-1",
			Sequence:             1,
			Timestamp:            time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
			RequestChainTipHash:  reqTip,
			MerkleRoot:           root,
			CoordinatorKeyID:     "coord-key",
			CoordinatorSignature: []byte("invalid-signature-that-is-at-least-64-bytes-long-for-ed25519-format-xxx"),
		}
		if err := v.VerifyMerkleTree(tree); err == nil {
			t.Fatal("expected error for invalid coordinator signature")
		}
	})

	t.Run("unknown_coordinator_key_skips_verification", func(t *testing.T) {
		v := NewVerifier()
		reqTip := sha256Bytes([]byte("req"))
		root := computeMerkleRoot(reqTip, nil)
		tree := &MerkleTree{
			TreeID:               "tree-1",
			OrgID:                "org-1",
			Sequence:             1,
			Timestamp:            time.Now(),
			RequestChainTipHash:  reqTip,
			MerkleRoot:           root,
			CoordinatorKeyID:     "unknown-key",
			CoordinatorSignature: []byte("some-signature"),
		}
		// Should pass because the key is not in CoordinatorKeys
		if err := v.VerifyMerkleTree(tree); err != nil {
			t.Fatalf("unknown key should skip sig verification, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// VerifyExport (integration)
// ---------------------------------------------------------------------------

func TestVerifyExport(t *testing.T) {
	t.Run("valid_export", func(t *testing.T) {
		v := NewVerifier()
		deviceChain := makeDeviceChain(3)
		requestChain := makeRequestChain(2)

		reqTip := requestChain[len(requestChain)-1].EntryHash
		devTip := deviceChain[len(deviceChain)-1].EntryHash
		tips := []DeviceChainTip{
			{DeviceID: "device-1", Hash: devTip, Sequence: 2},
		}
		root := computeMerkleRoot(reqTip, tips)

		export := &ChainExport{
			OrgID:          "org-1",
			DeviceEntries:  deviceChain,
			RequestEntries: requestChain,
			MerkleTrees: []*MerkleTree{
				{
					TreeID:              "tree-1",
					OrgID:               "org-1",
					Sequence:            1,
					Timestamp:           time.Now(),
					RequestChainTipHash: reqTip,
					DeviceChainTips:     tips,
					MerkleRoot:          root,
					CoordinatorKeyID:    "key-1",
				},
			},
		}
		r := v.VerifyExport(export)
		if !r.Valid {
			t.Errorf("expected valid export, got errors: %v", r.Errors)
		}
		if r.EntriesCount != 5 {
			t.Errorf("expected 5 entries (3 device + 2 request), got %d", r.EntriesCount)
		}
	})

	t.Run("device_chain_error_propagates", func(t *testing.T) {
		v := NewVerifier()
		deviceChain := makeDeviceChain(2)
		deviceChain[1].EntryHash = []byte("corrupted")

		export := &ChainExport{
			OrgID:         "org-1",
			DeviceEntries: deviceChain,
		}
		r := v.VerifyExport(export)
		if r.Valid {
			t.Error("expected invalid due to device chain error")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "hash_mismatch" {
				found = true
			}
		}
		if !found {
			t.Error("expected hash_mismatch error from device chain")
		}
	})

	t.Run("request_chain_error_propagates", func(t *testing.T) {
		v := NewVerifier()
		requestChain := makeRequestChain(2)
		requestChain[1].EntryHash = []byte("corrupted")

		export := &ChainExport{
			OrgID:          "org-1",
			RequestEntries: requestChain,
		}
		r := v.VerifyExport(export)
		if r.Valid {
			t.Error("expected invalid due to request chain error")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "hash_mismatch" {
				found = true
			}
		}
		if !found {
			t.Error("expected hash_mismatch error from request chain")
		}
	})

	t.Run("merkle_tree_error_propagates", func(t *testing.T) {
		v := NewVerifier()
		export := &ChainExport{
			OrgID: "org-1",
			MerkleTrees: []*MerkleTree{
				{
					TreeID:              "tree-1",
					OrgID:               "org-1",
					Sequence:            1,
					Timestamp:           time.Now(),
					RequestChainTipHash: sha256Bytes([]byte("tip")),
					MerkleRoot:          []byte("wrong"),
					CoordinatorKeyID:    "key-1",
				},
			},
		}
		r := v.VerifyExport(export)
		if r.Valid {
			t.Error("expected invalid due to merkle tree error")
		}
		found := false
		for _, e := range r.Errors {
			if e.ErrorType == "merkle_tree_invalid" {
				found = true
			}
		}
		if !found {
			t.Error("expected merkle_tree_invalid error")
		}
	})

	t.Run("transparency_log_error_propagates", func(t *testing.T) {
		v := NewVerifier()
		tlChain := makeTransparencyChain(2)
		tlChain[1].EntryHash = []byte("corrupted")

		export := &ChainExport{
			OrgID:               "org-1",
			TransparencyEntries: tlChain,
		}
		r := v.VerifyExport(export)
		if r.Valid {
			t.Error("expected invalid due to transparency log error")
		}
	})

	t.Run("empty_transparency_entries_skipped", func(t *testing.T) {
		v := NewVerifier()
		export := &ChainExport{
			OrgID:               "org-1",
			TransparencyEntries: nil,
		}
		r := v.VerifyExport(export)
		if !r.Valid {
			t.Error("empty export should be valid")
		}
	})

	t.Run("multiple_device_chains", func(t *testing.T) {
		v := NewVerifier()
		// Two devices, each with 2 entries
		d1 := makeDeviceChain(2)
		d2chain := make([]*DeviceChainEntry, 2)
		var prevHash []byte
		for i := 0; i < 2; i++ {
			e := &DeviceChainEntry{
				EntryID:              "d2-entry-" + string(rune('a'+i)),
				OrgID:                "org-1",
				DeviceID:             "device-2",
				Sequence:             int64(i),
				Timestamp:            time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Hour),
				PrevHash:             prevHash,
				EntryType:            "approval",
				EncryptedPayloadHash: []byte("enc"),
				PlaintextHash:        []byte("plain"),
			}
			e.EntryHash = computeDeviceEntryHash(e)
			d2chain[i] = e
			prevHash = e.EntryHash
		}

		allEntries := append(d1, d2chain...)
		export := &ChainExport{
			OrgID:         "org-1",
			DeviceEntries: allEntries,
		}
		r := v.VerifyExport(export)
		if !r.Valid {
			t.Errorf("expected valid with two device chains, got errors: %v", r.Errors)
		}
		if r.EntriesCount != 4 {
			t.Errorf("expected 4 entries, got %d", r.EntriesCount)
		}
	})
}

// ---------------------------------------------------------------------------
// NewVerifier
// ---------------------------------------------------------------------------

func TestNewVerifier(t *testing.T) {
	v := NewVerifier()
	if v == nil {
		t.Fatal("NewVerifier returned nil")
	}
	if v.CoordinatorKeys == nil {
		t.Fatal("CoordinatorKeys map should be initialized")
	}
	if len(v.CoordinatorKeys) != 0 {
		t.Errorf("CoordinatorKeys should be empty, got %d", len(v.CoordinatorKeys))
	}
}

// ---------------------------------------------------------------------------
// Utility functions for tests
// ---------------------------------------------------------------------------

func sha256Bytes(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func hashPair(a, b []byte) []byte {
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	return h.Sum(nil)
}
