package approval

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"testing"

	protocol "github.com/ackagent/api/go/protocol"
)

func TestParseP256CompressedPublicKey(t *testing.T) {
	// Generate a real P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create compressed public key (33 bytes: 0x02/0x03 || X)
	compressedKey := elliptic.MarshalCompressed(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)

	// Test parsing
	parsedKey, err := parseP256CompressedPublicKey(compressedKey)
	if err != nil {
		t.Fatalf("parseP256CompressedPublicKey() error = %v", err)
	}

	// Verify parsed key matches original
	if parsedKey.X.Cmp(privateKey.PublicKey.X) != 0 {
		t.Error("Parsed X coordinate doesn't match")
	}
	if parsedKey.Y.Cmp(privateKey.PublicKey.Y) != 0 {
		t.Error("Parsed Y coordinate doesn't match")
	}
	if parsedKey.Curve != elliptic.P256() {
		t.Error("Parsed curve is not P-256")
	}
}

func TestParseP256CompressedPublicKey_InvalidLength(t *testing.T) {
	tests := []struct {
		name    string
		rawKey  []byte
		wantErr bool
	}{
		{
			name:    "too short",
			rawKey:  make([]byte, 32),
			wantErr: true,
		},
		{
			name:    "too long",
			rawKey:  make([]byte, 65),
			wantErr: true,
		},
		{
			name:    "empty",
			rawKey:  []byte{},
			wantErr: true,
		},
		{
			name:    "old 64-byte raw format rejected",
			rawKey:  make([]byte, 64),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseP256CompressedPublicKey(tt.rawKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseP256CompressedPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifySignature_RawFormat(t *testing.T) {
	// Generate key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create test hash
	testData := []byte("test data to sign")
	hash := sha256.Sum256(testData)

	// Sign with raw format (r || s)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Create raw signature (32 bytes each, padded)
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	// Verify
	err = verifySignature(hash[:], signature, &privateKey.PublicKey)
	if err != nil {
		t.Errorf("verifySignature() error = %v, want nil", err)
	}
}

func TestVerifySignature_ASN1Format(t *testing.T) {
	// Generate key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create test hash
	testData := []byte("test data to sign in ASN.1")
	hash := sha256.Sum256(testData)

	// Sign with ASN.1 DER format
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify
	err = verifySignature(hash[:], signature, &privateKey.PublicKey)
	if err != nil {
		t.Errorf("verifySignature() error = %v, want nil", err)
	}
}

func TestVerifySignature_InvalidSignature(t *testing.T) {
	// Generate key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create test hash
	testData := []byte("test data")
	hash := sha256.Sum256(testData)

	tests := []struct {
		name      string
		signature []byte
		wantErr   error
	}{
		{
			name:      "wrong raw signature",
			signature: make([]byte, 64), // All zeros
			wantErr:   ErrInvalidSignature,
		},
		{
			name:      "random bytes as ASN.1",
			signature: []byte{0x30, 0x44, 0x00, 0x00}, // Invalid ASN.1
			wantErr:   ErrInvalidSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifySignature(hash[:], tt.signature, &privateKey.PublicKey)
			if err != tt.wantErr {
				t.Errorf("verifySignature() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	// Generate two different key pairs
	privateKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Sign with key1
	testData := []byte("test data")
	hash := sha256.Sum256(testData)

	r, s, _ := ecdsa.Sign(rand.Reader, privateKey1, hash[:])
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	// Verify with key2 should fail
	err := verifySignature(hash[:], signature, &privateKey2.PublicKey)
	if err != ErrInvalidSignature {
		t.Errorf("verifySignature() with wrong key error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestVerifySignature_WrongHash(t *testing.T) {
	// Generate key pair
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Sign one message
	testData := []byte("original data")
	hash := sha256.Sum256(testData)

	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	// Verify with different hash should fail
	differentData := []byte("different data")
	differentHash := sha256.Sum256(differentData)

	err := verifySignature(differentHash[:], signature, &privateKey.PublicKey)
	if err != ErrInvalidSignature {
		t.Errorf("verifySignature() with wrong hash error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestGenerateRuleID(t *testing.T) {
	id1 := generateRuleID()
	id2 := generateRuleID()

	// Should be 16 hex chars (8 bytes)
	if len(id1) != 16 {
		t.Errorf("generateRuleID() length = %d, want 16", len(id1))
	}

	// Should be unique
	if id1 == id2 {
		t.Error("generateRuleID() should generate unique IDs")
	}

	// Should be valid hex
	for _, c := range id1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("generateRuleID() contains invalid hex char: %c", c)
		}
	}
}

func TestApprovalResponse_Decisions(t *testing.T) {
	tests := []struct {
		name     string
		decision protocol.ClaudeApprovalResponseDecision
		isAllow  bool
		isDeny   bool
	}{
		{"allow", protocol.Allow, true, false},
		{"allow_always", protocol.AllowAlways, true, false},
		{"deny", protocol.Deny, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := ApprovalResponse{Decision: tt.decision}
			decision := getDecision(&resp)
			isAllow := decision == "allow" || decision == "allow_always"
			isDeny := decision == "deny"

			if isAllow != tt.isAllow {
				t.Errorf("isAllow = %v, want %v", isAllow, tt.isAllow)
			}
			if isDeny != tt.isDeny {
				t.Errorf("isDeny = %v, want %v", isDeny, tt.isDeny)
			}
		})
	}
}

// BenchmarkVerifySignature benchmarks signature verification
func BenchmarkVerifySignature(b *testing.B) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testData := []byte("benchmark test data")
	hash := sha256.Sum256(testData)

	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	signature := make([]byte, 64)
	copy(signature[32-len(r.Bytes()):32], r.Bytes())
	copy(signature[64-len(s.Bytes()):64], s.Bytes())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verifySignature(hash[:], signature, &privateKey.PublicKey)
	}
}

// BenchmarkSerializeContextPreimage benchmarks context preimage serialization
func BenchmarkSerializeContextPreimage(b *testing.B) {
	ctx := &ApprovalContext{
		SessionID: "benchmark-session",
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "ls -la /tmp"},
		Timestamp: 1703001234567,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SerializeContextPreimage(ctx)
	}
}

// Regression: signature verification must work against SHA256(preimage), not
// against the preimage bytes directly.
func TestVerifySignature_AgainstSHA256OfPreimage(t *testing.T) {
	// Generate key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Build a context preimage (raw JSON bytes)
	ctx := &ApprovalContext{
		SessionID: "session-regression",
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "rm -rf /"},
		Timestamp: 1703001234567,
	}
	preimage, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("Failed to marshal context: %v", err)
	}

	// Approver computes SHA-256 of the preimage and signs the digest
	digest := sha256.Sum256(preimage)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	signature := createRawSignature(r, s)

	// Verification should succeed against SHA256(preimage)
	if err := verifySignature(digest[:], signature, &privateKey.PublicKey); err != nil {
		t.Errorf("verification against SHA256(preimage) failed: %v", err)
	}

	// Verification against raw preimage bytes directly should fail (regression guard)
	if err := verifySignature(preimage, signature, &privateKey.PublicKey); err == nil {
		t.Error("verification against raw preimage bytes should fail, but succeeded")
	}
}

// Helper to create raw P-256 signature for testing
func createRawSignature(r, s *big.Int) []byte {
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig
}
