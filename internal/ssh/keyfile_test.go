package ssh

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestVectors matches the ssh_vectors structure in data/crypto_test_vectors.json
type TestVectors struct {
	SSHVectors SSHVectors `json:"ssh_vectors"`
}

type SSHVectors struct {
	KeyMaterial     KeyMaterial     `json:"key_material"`
	PublicKeyFormat PublicKeyFormat `json:"public_key_format"`
	KeyHandle       KeyHandleVec    `json:"key_handle"`
}

type KeyMaterial struct {
	PublicKeyXHex string `json:"public_key_x_hex"`
	PublicKeyYHex string `json:"public_key_y_hex"`
}

type PublicKeyFormat struct {
	KeyType           string `json:"key_type"`
	Application       string `json:"application"`
	BlobHex           string `json:"blob_hex"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	AuthorizedKeys    string `json:"authorized_keys_line"`
}

type KeyHandleVec struct {
	MagicHex          string         `json:"magic_hex"`
	JSONPayload       map[string]any `json:"json_payload"`
	CompleteHandleHex string         `json:"complete_handle_hex"`
}

func loadTestVectors(t *testing.T) *TestVectors {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get caller info")
	}

	// Navigate from internal/ssh/ to data/
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	path := filepath.Join(root, "data", "crypto_test_vectors.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test vectors: %v", err)
	}

	var vectors TestVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse test vectors: %v", err)
	}

	return &vectors
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}
	return b
}

// compressedKeyFromXY builds a 33-byte compressed P-256 public key from raw X, Y coordinates.
func compressedKeyFromXY(t *testing.T, xHex, yHex string) []byte {
	t.Helper()
	x := new(big.Int).SetBytes(mustDecodeHex(t, xHex))
	y := new(big.Int).SetBytes(mustDecodeHex(t, yHex))
	return elliptic.MarshalCompressed(elliptic.P256(), x, y)
}

func TestBuildPublicKeyBlob(t *testing.T) {
	vectors := loadTestVectors(t)
	km := vectors.SSHVectors.KeyMaterial
	pkf := vectors.SSHVectors.PublicKeyFormat

	// Build compressed public key from X and Y
	publicKey := compressedKeyFromXY(t, km.PublicKeyXHex, km.PublicKeyYHex)

	blob := BuildPublicKeyBlob(publicKey, pkf.Application)
	blobHex := hex.EncodeToString(blob)

	if blobHex != pkf.BlobHex {
		t.Errorf("blob mismatch:\ngot:  %s\nwant: %s", blobHex, pkf.BlobHex)
	}
}

func TestComputeSSHFingerprint(t *testing.T) {
	vectors := loadTestVectors(t)
	km := vectors.SSHVectors.KeyMaterial
	pkf := vectors.SSHVectors.PublicKeyFormat

	// Build compressed public key from X and Y
	publicKey := compressedKeyFromXY(t, km.PublicKeyXHex, km.PublicKeyYHex)

	fingerprint := ComputeSSHFingerprint(publicKey, pkf.Application)

	if fingerprint != pkf.FingerprintSHA256 {
		t.Errorf("fingerprint mismatch:\ngot:  %s\nwant: %s", fingerprint, pkf.FingerprintSHA256)
	}
}

func TestBuildKeyHandle(t *testing.T) {
	vectors := loadTestVectors(t)
	kh := vectors.SSHVectors.KeyHandle

	// Extract test values from JSON payload
	iosKeyID := kh.JSONPayload["k"].(string)
	userID := kh.JSONPayload["d"].(string)
	application := kh.JSONPayload["a"].(string)

	// Build key handle
	handle := BuildKeyHandle(iosKeyID, userID, application)

	// Verify magic bytes (first 4 bytes)
	if len(handle) < 8 {
		t.Fatal("key handle too short")
	}

	magicBytes := handle[0:4]
	expectedMagic := mustDecodeHex(t, kh.MagicHex)
	// Note: magic is stored in little-endian, so "APPR" (0x41505052) appears as bytes [0x52, 0x50, 0x50, 0x41]
	if !bytes.Equal(magicBytes, []byte{0x52, 0x50, 0x50, 0x41}) {
		t.Errorf("magic bytes mismatch:\ngot:  %x\nwant: %x (little-endian APPR)", magicBytes, expectedMagic)
	}

	// Parse the JSON payload from our generated handle
	jsonStart := 8
	var generatedPayload map[string]any
	if err := json.Unmarshal(handle[jsonStart:], &generatedPayload); err != nil {
		t.Fatalf("failed to parse generated key handle JSON: %v", err)
	}

	// Verify key fields match
	if generatedPayload["k"] != kh.JSONPayload["k"] {
		t.Errorf("ios_key_id mismatch: got %v, want %v", generatedPayload["k"], kh.JSONPayload["k"])
	}
	if generatedPayload["d"] != kh.JSONPayload["d"] {
		t.Errorf("user_id mismatch: got %v, want %v", generatedPayload["d"], kh.JSONPayload["d"])
	}
	if generatedPayload["a"] != kh.JSONPayload["a"] {
		t.Errorf("application mismatch: got %v, want %v", generatedPayload["a"], kh.JSONPayload["a"])
	}
	if generatedPayload["v"] != float64(1) {
		t.Errorf("version mismatch: got %v, want 1", generatedPayload["v"])
	}
}

func TestWritePublicKeyFile(t *testing.T) {
	vectors := loadTestVectors(t)
	km := vectors.SSHVectors.KeyMaterial
	pkf := vectors.SSHVectors.PublicKeyFormat

	// Build compressed public key from X and Y
	publicKey := compressedKeyFromXY(t, km.PublicKeyXHex, km.PublicKeyYHex)

	// Create temp file
	tmpDir := t.TempDir()
	pubPath := filepath.Join(tmpDir, "test.pub")

	if err := WritePublicKeyFile(pubPath, publicKey, pkf.Application, "test-key"); err != nil {
		t.Fatalf("failed to write public key: %v", err)
	}

	// Read and verify
	content, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("failed to read public key: %v", err)
	}

	// Check format
	line := strings.TrimSpace(string(content))
	if line != pkf.AuthorizedKeys {
		t.Errorf("authorized_keys line mismatch:\ngot:  %s\nwant: %s", line, pkf.AuthorizedKeys)
	}
}

func TestWritePrivateKeyFile(t *testing.T) {
	vectors := loadTestVectors(t)
	km := vectors.SSHVectors.KeyMaterial
	pkf := vectors.SSHVectors.PublicKeyFormat

	// Build compressed public key from X and Y
	publicKey := compressedKeyFromXY(t, km.PublicKeyXHex, km.PublicKeyYHex)

	// Build key handle
	keyHandle := BuildKeyHandle("test-ios-key-id", "test-user-id", pkf.Application)

	// Create temp file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test")

	if err := WritePrivateKeyFile(keyPath, publicKey, keyHandle, pkf.Application, "test-key"); err != nil {
		t.Fatalf("failed to write private key: %v", err)
	}

	// Read and verify
	content, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read private key: %v", err)
	}

	// Check format
	s := string(content)
	if !strings.HasPrefix(s, "-----BEGIN OPENSSH PRIVATE KEY-----\n") {
		t.Error("private key missing header")
	}
	if !strings.HasSuffix(s, "-----END OPENSSH PRIVATE KEY-----\n") {
		t.Error("private key missing footer")
	}

	// Verify base64 content is valid
	lines := strings.Split(s, "\n")
	var base64Lines []string
	for _, line := range lines {
		if strings.HasPrefix(line, "-----") || line == "" {
			continue
		}
		base64Lines = append(base64Lines, line)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.Join(base64Lines, ""))
	if err != nil {
		t.Fatalf("failed to decode private key base64: %v", err)
	}

	// Verify magic bytes
	if !bytes.HasPrefix(decoded, []byte("openssh-key-v1\x00")) {
		t.Error("private key missing openssh-key-v1 magic")
	}
}

func TestBuildPublicKeyBlobEd25519(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 10)
	}
	app := "ssh:"

	blob := BuildPublicKeyBlobEd25519(pubKey, app)

	// Verify key type prefix
	keyTypeLen := int(blob[0])<<24 | int(blob[1])<<16 | int(blob[2])<<8 | int(blob[3])
	keyType := string(blob[4 : 4+keyTypeLen])
	if keyType != SSHKeyTypeEd25519 {
		t.Errorf("key type mismatch: got %s, want %s", keyType, SSHKeyTypeEd25519)
	}

	// Verify blob is non-empty and has expected structure
	if len(blob) == 0 {
		t.Fatal("blob is empty")
	}
}

func TestComputeSSHFingerprintEd25519(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 20)
	}

	fp := ComputeSSHFingerprintEd25519(pubKey, "ssh:")

	// Should start with SHA256:
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fingerprint should start with SHA256:, got %s", fp)
	}

	// Deterministic: same input → same output
	fp2 := ComputeSSHFingerprintEd25519(pubKey, "ssh:")
	if fp != fp2 {
		t.Errorf("fingerprint should be deterministic: %s != %s", fp, fp2)
	}

	// Different keys → different fingerprints
	pubKey2 := make([]byte, 32)
	fp3 := ComputeSSHFingerprintEd25519(pubKey2, "ssh:")
	if fp == fp3 {
		t.Error("different keys should have different fingerprints")
	}
}

func TestWritePublicKeyFileEd25519(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}

	tmpDir := t.TempDir()
	pubPath := filepath.Join(tmpDir, "test_ed25519.pub")

	if err := WritePublicKeyFileEd25519(pubPath, pubKey, "ssh:", "test-ed25519-key"); err != nil {
		t.Fatalf("failed to write Ed25519 public key: %v", err)
	}

	content, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	line := strings.TrimSpace(string(content))
	if !strings.HasPrefix(line, SSHKeyTypeEd25519) {
		t.Errorf("expected Ed25519 key type prefix, got: %s", line[:40])
	}
	if !strings.HasSuffix(line, "test-ed25519-key") {
		t.Errorf("expected comment at end, got: %s", line)
	}
}

func TestWritePrivateKeyFileEd25519(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	keyHandle := BuildKeyHandle("test-key", "test-user", "ssh:")

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_ed25519")

	if err := WritePrivateKeyFileEd25519(keyPath, pubKey, keyHandle, "ssh:", "test-ed25519"); err != nil {
		t.Fatalf("failed to write Ed25519 private key: %v", err)
	}

	content, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	s := string(content)
	if !strings.HasPrefix(s, "-----BEGIN OPENSSH PRIVATE KEY-----\n") {
		t.Error("missing header")
	}
	if !strings.HasSuffix(s, "-----END OPENSSH PRIVATE KEY-----\n") {
		t.Error("missing footer")
	}

	// Verify base64 content is valid
	lines := strings.Split(s, "\n")
	var base64Lines []string
	for _, line := range lines {
		if strings.HasPrefix(line, "-----") || line == "" {
			continue
		}
		base64Lines = append(base64Lines, line)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.Join(base64Lines, ""))
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}

	if !bytes.HasPrefix(decoded, []byte("openssh-key-v1\x00")) {
		t.Error("missing openssh-key-v1 magic")
	}

	// Verify permissions
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions: got %o, want 0600", info.Mode().Perm())
	}
}

func TestBuildPrivateKeyContentEd25519(t *testing.T) {
	pubKey := make([]byte, 32)
	keyHandle := []byte(`{"v":1,"k":"key-id","d":"user-id","a":"ssh:","t":1700000000}`)

	content, err := BuildPrivateKeyContentEd25519(pubKey, keyHandle, "ssh:", "ed25519-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(content, "-----BEGIN OPENSSH PRIVATE KEY-----\n") {
		t.Error("missing PEM header")
	}
	if !strings.HasSuffix(content, "-----END OPENSSH PRIVATE KEY-----\n") {
		t.Error("missing PEM footer")
	}
}

func TestWriteKeyFiles_ECDSA(t *testing.T) {
	vectors := loadTestVectors(t)
	km := vectors.SSHVectors.KeyMaterial

	publicKey := compressedKeyFromXY(t, km.PublicKeyXHex, km.PublicKeyYHex)
	keyHandle := BuildKeyHandle("test-key", "test-user", "ssh:")

	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, "id_ecdsa")
	pubPath := filepath.Join(tmpDir, "id_ecdsa.pub")

	err := WriteKeyFiles(privPath, pubPath, publicKey, keyHandle, "ssh:", "test-comment", false)
	if err != nil {
		t.Fatalf("WriteKeyFiles failed: %v", err)
	}

	// Verify private key
	privContent, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("failed to read private key: %v", err)
	}
	if !strings.HasPrefix(string(privContent), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Error("private key missing header")
	}

	// Verify public key
	pubContent, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("failed to read public key: %v", err)
	}
	if !strings.HasPrefix(string(pubContent), SSHKeyTypeECDSA) {
		t.Error("public key missing type prefix")
	}
}

func TestWriteKeyFiles_Ed25519(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	keyHandle := BuildKeyHandle("test-key", "test-user", "ssh:")

	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, "id_ed25519")
	pubPath := filepath.Join(tmpDir, "id_ed25519.pub")

	err := WriteKeyFiles(privPath, pubPath, pubKey, keyHandle, "ssh:", "test-comment", true)
	if err != nil {
		t.Fatalf("WriteKeyFiles (Ed25519) failed: %v", err)
	}

	// Verify both files exist
	if _, err := os.Stat(privPath); err != nil {
		t.Fatalf("private key not created: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("public key not created: %v", err)
	}
}

func TestWriteKeyFiles_CleanupOnPublicKeyFailure(t *testing.T) {
	vectors := loadTestVectors(t)
	km := vectors.SSHVectors.KeyMaterial
	publicKey := compressedKeyFromXY(t, km.PublicKeyXHex, km.PublicKeyYHex)
	keyHandle := BuildKeyHandle("test-key", "test-user", "ssh:")

	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, "id_ecdsa")
	pubPath := filepath.Join(tmpDir, "nonexistent-dir", "id_ecdsa.pub") // invalid path

	err := WriteKeyFiles(privPath, pubPath, publicKey, keyHandle, "ssh:", "test", false)
	if err == nil {
		t.Fatal("expected error for invalid public key path")
	}

	// Private key should be cleaned up
	if _, statErr := os.Stat(privPath); statErr == nil {
		t.Error("private key should have been removed on public key write failure")
	}
}

func TestDecompressForSSH_Fallback(t *testing.T) {
	// Already uncompressed (65 bytes, 0x04 prefix)
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	result := decompressForSSH(uncompressed)
	if !bytes.Equal(result, uncompressed) {
		t.Error("uncompressed key should be returned as-is")
	}

	// Invalid length
	invalid := []byte{0x01, 0x02, 0x03}
	result = decompressForSSH(invalid)
	if !bytes.Equal(result, invalid) {
		t.Error("invalid key should be returned as-is")
	}
}

func TestWrapBase64(t *testing.T) {
	// Short string (fits in one line)
	short := "ABCDEF"
	wrapped := wrapBase64(short, 70)
	if wrapped != "ABCDEF\n" {
		t.Errorf("unexpected wrap for short string: %q", wrapped)
	}

	// Long string requiring wrapping
	long := strings.Repeat("A", 150)
	wrapped = wrapBase64(long, 70)
	lines := strings.Split(strings.TrimSuffix(wrapped, "\n"), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines for 150 chars at 70 per line, got %d", len(lines))
	}
	if len(lines[0]) != 70 {
		t.Errorf("first line length: got %d, want 70", len(lines[0]))
	}
	if len(lines[1]) != 70 {
		t.Errorf("second line length: got %d, want 70", len(lines[1]))
	}
	if len(lines[2]) != 10 {
		t.Errorf("third line length: got %d, want 10", len(lines[2]))
	}
}

func TestWritePrivateKeyFilePermissions(t *testing.T) {
	vectors := loadTestVectors(t)
	km := vectors.SSHVectors.KeyMaterial

	// Build compressed public key from X and Y
	publicKey := compressedKeyFromXY(t, km.PublicKeyXHex, km.PublicKeyYHex)

	keyHandle := BuildKeyHandle("test-key", "test-user", "ssh:")

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test")

	if err := WritePrivateKeyFile(keyPath, publicKey, keyHandle, "ssh:", "test"); err != nil {
		t.Fatalf("failed to write private key: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("failed to stat private key: %v", err)
	}

	// Check permissions are 0600 (rw-------)
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("private key permissions: got %o, want 0600", perm)
	}
}
