package ssh

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/sysinfo"
	"github.com/ackagent/cli/internal/shared/util"
)

func TestBuildEnrollPayload(t *testing.T) {
	processInfo := sysinfo.ProcessInfo{
		Command:  "test-cmd",
		Hostname: "test-host",
		LocalIP:  "10.0.0.1",
		Username: "testuser",
	}

	t.Run("default algorithm normalizes to P256", func(t *testing.T) {
		data, err := buildEnrollPayload("my-key", "", processInfo)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var p protocol.EnrollPayload
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if p.Algorithm == nil || *p.Algorithm != config.AlgorithmP256 {
			t.Errorf("expected algorithm %s, got %v", config.AlgorithmP256, p.Algorithm)
		}
	})

	t.Run("explicit ecdsa algorithm", func(t *testing.T) {
		data, err := buildEnrollPayload("my-key", config.AlgorithmP256, processInfo)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var p protocol.EnrollPayload
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if p.Algorithm == nil || *p.Algorithm != config.AlgorithmP256 {
			t.Errorf("expected algorithm %s, got %v", config.AlgorithmP256, p.Algorithm)
		}
	})

	t.Run("explicit ed25519 algorithm", func(t *testing.T) {
		data, err := buildEnrollPayload("my-key", config.AlgorithmEd25519, processInfo)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var p protocol.EnrollPayload
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if p.Algorithm == nil || *p.Algorithm != config.AlgorithmEd25519 {
			t.Errorf("expected algorithm %s, got %v", config.AlgorithmEd25519, p.Algorithm)
		}
	})

	t.Run("unsupported algorithm returns error", func(t *testing.T) {
		_, err := buildEnrollPayload("my-key", "rsa-4096", processInfo)
		if err == nil {
			t.Fatal("expected error for unsupported algorithm")
		}
		if !strings.Contains(err.Error(), "unsupported algorithm") {
			t.Errorf("expected error containing 'unsupported algorithm', got: %v", err)
		}
	})

	t.Run("payload JSON structure", func(t *testing.T) {
		label := "test-label"
		data, err := buildEnrollPayload(label, config.AlgorithmP256, processInfo)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var p protocol.EnrollPayload
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if p.Type != protocol.Enroll {
			t.Errorf("expected type %q, got %q", protocol.Enroll, p.Type)
		}
		if p.Purpose != protocol.Ssh {
			t.Errorf("expected purpose %q, got %q", protocol.Ssh, p.Purpose)
		}
		if p.Label == nil || *p.Label != label {
			t.Errorf("expected label %q, got %v", label, p.Label)
		}
	})

	t.Run("display schema fields", func(t *testing.T) {
		data, err := buildEnrollPayload("my-key", config.AlgorithmP256, processInfo)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var p protocol.EnrollPayload
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if p.Display == nil {
			t.Fatal("expected display schema to be set")
		}
		if p.Display.Title != "Enroll SSH Key?" {
			t.Errorf("expected title %q, got %q", "Enroll SSH Key?", p.Display.Title)
		}
		if len(p.Display.Fields) != 2 {
			t.Fatalf("expected 2 fields, got %d", len(p.Display.Fields))
		}
		if p.Display.Fields[0].Label != "Algorithm" {
			t.Errorf("expected first field label %q, got %q", "Algorithm", p.Display.Fields[0].Label)
		}
		if p.Display.Fields[1].Label != "Label" {
			t.Errorf("expected second field label %q, got %q", "Label", p.Display.Fields[1].Label)
		}
		if p.Display.Fields[1].Value != "my-key" {
			t.Errorf("expected label field value %q, got %q", "my-key", p.Display.Fields[1].Value)
		}
	})

	t.Run("ECDSA display shows ECDSA P-256 and Ed25519 shows Ed25519", func(t *testing.T) {
		// ECDSA
		data, err := buildEnrollPayload("k", config.AlgorithmP256, processInfo)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var p protocol.EnrollPayload
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if p.Display.Fields[0].Value != "ECDSA P-256" {
			t.Errorf("expected algorithm display %q, got %q", "ECDSA P-256", p.Display.Fields[0].Value)
		}

		// Ed25519
		data, err = buildEnrollPayload("k", config.AlgorithmEd25519, processInfo)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var p2 protocol.EnrollPayload
		if err := json.Unmarshal(data, &p2); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if p2.Display.Fields[0].Value != "Ed25519" {
			t.Errorf("expected algorithm display %q, got %q", "Ed25519", p2.Display.Fields[0].Value)
		}
	})
}

func TestParseEnrollResponse(t *testing.T) {
	// Valid 33-byte compressed P-256 public key (0x03 || X, deterministic for reproducible tests)
	p256Key := make([]byte, 33)
	p256Key[0] = 0x03
	for i := 1; i < 33; i++ {
		p256Key[i] = byte(i - 1)
	}
	p256KeyHex := hex.EncodeToString(p256Key)

	// Valid 32-byte Ed25519 public key
	ed25519Key := make([]byte, 32)
	for i := range ed25519Key {
		ed25519Key[i] = byte(i + 100)
	}
	ed25519KeyHex := hex.EncodeToString(ed25519Key)

	t.Run("approved P-256 response", func(t *testing.T) {
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: &p256KeyHex,
		}
		data, _ := json.Marshal(resp)

		meta, err := parseEnrollResponse(data, config.AlgorithmP256, "test-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.Algorithm != config.AlgorithmP256 {
			t.Errorf("expected algorithm %s, got %s", config.AlgorithmP256, meta.Algorithm)
		}
		if meta.Hex() == "" {
			t.Error("expected non-empty Hex()")
		}
		if meta.Label != "test-key" {
			t.Errorf("expected label %q, got %q", "test-key", meta.Label)
		}
		if meta.Purpose != config.KeyPurposeSSH {
			t.Errorf("expected purpose %q, got %q", config.KeyPurposeSSH, meta.Purpose)
		}
		if len(meta.PublicKey) != 33 {
			t.Errorf("expected 33-byte public key, got %d", len(meta.PublicKey))
		}
	})

	t.Run("approved Ed25519 response", func(t *testing.T) {
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: &ed25519KeyHex,
			Algorithm:    util.Ptr(config.AlgorithmEd25519),
		}
		data, _ := json.Marshal(resp)

		meta, err := parseEnrollResponse(data, config.AlgorithmEd25519, "ed-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.Algorithm != config.AlgorithmEd25519 {
			t.Errorf("expected algorithm %s, got %s", config.AlgorithmEd25519, meta.Algorithm)
		}
		if meta.Hex() == "" {
			t.Error("expected non-empty Hex()")
		}
		if len(meta.PublicKey) != 32 {
			t.Errorf("expected 32-byte public key, got %d", len(meta.PublicKey))
		}
	})

	t.Run("error code in response", func(t *testing.T) {
		errCode := protocol.AckAgentCommonSigningErrorCode(1)
		errMsg := "key generation failed"
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			ErrorCode:    &errCode,
			ErrorMessage: &errMsg,
		}
		data, _ := json.Marshal(resp)

		_, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "enrollment failed: key generation failed") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("error code with nil message", func(t *testing.T) {
		errCode := protocol.AckAgentCommonSigningErrorCode(2)
		resp := protocol.EnrollResponse{
			Status:    protocol.EnrollResponseStatusApproved,
			ErrorCode: &errCode,
		}
		data, _ := json.Marshal(resp)

		_, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "enrollment failed: ") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("rejected status", func(t *testing.T) {
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusRejected,
			PublicKeyHex: &p256KeyHex,
		}
		data, _ := json.Marshal(resp)

		_, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "enrollment rejected") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("missing public key", func(t *testing.T) {
		resp := protocol.EnrollResponse{
			Status: protocol.EnrollResponseStatusApproved,
		}
		data, _ := json.Marshal(resp)

		_, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "response missing public key") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid P-256 key length 63 bytes", func(t *testing.T) {
		shortKey := make([]byte, 63)
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: util.Ptr(hex.EncodeToString(shortKey)),
		}
		data, _ := json.Marshal(resp)

		_, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "invalid P-256 public key length") {
			t.Errorf("unexpected error: %v", err)
		}
		if !strings.Contains(err.Error(), "got 63") {
			t.Errorf("expected error to mention length 63: %v", err)
		}
	})

	t.Run("invalid P-256 key length 66 bytes", func(t *testing.T) {
		longKey := make([]byte, 66)
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: util.Ptr(hex.EncodeToString(longKey)),
		}
		data, _ := json.Marshal(resp)

		_, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "invalid P-256 public key length") {
			t.Errorf("unexpected error: %v", err)
		}
		if !strings.Contains(err.Error(), "got 66") {
			t.Errorf("expected error to mention length 66: %v", err)
		}
	})

	t.Run("invalid Ed25519 key length 31 bytes", func(t *testing.T) {
		shortKey := make([]byte, 31)
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: util.Ptr(hex.EncodeToString(shortKey)),
		}
		data, _ := json.Marshal(resp)

		_, err := parseEnrollResponse(data, config.AlgorithmEd25519, "k")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "invalid Ed25519 public key length") {
			t.Errorf("unexpected error: %v", err)
		}
		if !strings.Contains(err.Error(), "got 31") {
			t.Errorf("expected error to mention length 31: %v", err)
		}
	})

	t.Run("invalid Ed25519 key length 33 bytes", func(t *testing.T) {
		longKey := make([]byte, 33)
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: util.Ptr(hex.EncodeToString(longKey)),
		}
		data, _ := json.Marshal(resp)

		_, err := parseEnrollResponse(data, config.AlgorithmEd25519, "k")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "invalid Ed25519 public key length") {
			t.Errorf("unexpected error: %v", err)
		}
		if !strings.Contains(err.Error(), "got 33") {
			t.Errorf("expected error to mention length 33: %v", err)
		}
	})

	t.Run("algorithm override from response", func(t *testing.T) {
		// Request ecdsa but response says ed25519
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: &ed25519KeyHex,
			Algorithm:    util.Ptr(config.AlgorithmEd25519),
		}
		data, _ := json.Marshal(resp)

		meta, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.Algorithm != config.AlgorithmEd25519 {
			t.Errorf("expected algorithm %s (from response), got %s", config.AlgorithmEd25519, meta.Algorithm)
		}
	})

	t.Run("algorithm from response used when present", func(t *testing.T) {
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: &p256KeyHex,
			Algorithm:    util.Ptr(config.AlgorithmP256),
		}
		data, _ := json.Marshal(resp)

		meta, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.Algorithm != config.AlgorithmP256 {
			t.Errorf("expected algorithm %s, got %s", config.AlgorithmP256, meta.Algorithm)
		}
	})

	t.Run("algorithm from request used when response has no algorithm", func(t *testing.T) {
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: &p256KeyHex,
		}
		data, _ := json.Marshal(resp)

		meta, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.Algorithm != config.AlgorithmP256 {
			t.Errorf("expected algorithm %s, got %s", config.AlgorithmP256, meta.Algorithm)
		}
	})

	t.Run("unsupported algorithm in response", func(t *testing.T) {
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: &p256KeyHex,
			Algorithm:    util.Ptr("rsa-4096"),
		}
		data, _ := json.Marshal(resp)

		_, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "unsupported algorithm in response") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("iOS key ID mapping", func(t *testing.T) {
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: &p256KeyHex,
			IosKeyId:     util.Ptr("ios-key-uuid-123"),
		}
		data, _ := json.Marshal(resp)

		meta, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.IOSKeyID != "ios-key-uuid-123" {
			t.Errorf("expected iOS key ID %q, got %q", "ios-key-uuid-123", meta.IOSKeyID)
		}
	})

	t.Run("no iOS key ID results in empty string", func(t *testing.T) {
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: &p256KeyHex,
		}
		data, _ := json.Marshal(resp)

		meta, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.IOSKeyID != "" {
			t.Errorf("expected empty iOS key ID, got %q", meta.IOSKeyID)
		}
	})

	t.Run("attestation mapping with all fields", func(t *testing.T) {
		attObj := []byte("attestation-object-data")
		attPubKeyHex := hex.EncodeToString([]byte("attestation-pub-key-data"))
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: &p256KeyHex,
			Attestation: &protocol.AckAgentCommonKeyMetadataAttestation{
				PublicKeyHex:            hex.EncodeToString([]byte("attested-pub-key")),
				Assertion:               []byte("assertion-data"),
				AttestationType:         "ios_secure_enclave",
				Challenge:               []byte("challenge-data"),
				AttestationTimestamp:    1700000000000,
				AttestationObject:       &attObj,
				AttestationPublicKeyHex: &attPubKeyHex,
			},
		}
		data, _ := json.Marshal(resp)

		meta, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.Attestation == nil {
			t.Fatal("expected attestation to be set")
		}
		if string(meta.Attestation.PublicKey) != "attested-pub-key" {
			t.Errorf("unexpected attestation public key: %s", meta.Attestation.PublicKey)
		}
		if string(meta.Attestation.Assertion) != "assertion-data" {
			t.Errorf("unexpected attestation assertion: %s", meta.Attestation.Assertion)
		}
		if meta.Attestation.AttestationType != "ios_secure_enclave" {
			t.Errorf("unexpected attestation type: %s", meta.Attestation.AttestationType)
		}
		if string(meta.Attestation.Challenge) != "challenge-data" {
			t.Errorf("unexpected attestation challenge: %s", meta.Attestation.Challenge)
		}
		if meta.Attestation.AttestationTimestamp != 1700000000000 {
			t.Errorf("unexpected attestation timestamp: %d", meta.Attestation.AttestationTimestamp)
		}
		if string(meta.Attestation.AttestationObject) != "attestation-object-data" {
			t.Errorf("unexpected attestation object: %s", meta.Attestation.AttestationObject)
		}
		if string(meta.Attestation.AttestationPublicKey) != "attestation-pub-key-data" {
			t.Errorf("unexpected attestation public key: %s", meta.Attestation.AttestationPublicKey)
		}
	})

	t.Run("attestation with nil optional fields", func(t *testing.T) {
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: &p256KeyHex,
			Attestation: &protocol.AckAgentCommonKeyMetadataAttestation{
				PublicKeyHex:         hex.EncodeToString([]byte("pub")),
				Assertion:            []byte("assert"),
				AttestationType:      "software",
				Challenge:            []byte("chal"),
				AttestationTimestamp: 1234567890,
			},
		}
		data, _ := json.Marshal(resp)

		meta, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.Attestation == nil {
			t.Fatal("expected attestation to be set")
		}
		if meta.Attestation.AttestationObject != nil {
			t.Errorf("expected nil attestation object, got %v", meta.Attestation.AttestationObject)
		}
		if meta.Attestation.AttestationPublicKey != nil {
			t.Errorf("expected nil attestation public key, got %v", meta.Attestation.AttestationPublicKey)
		}
	})

	t.Run("no attestation results in nil", func(t *testing.T) {
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: &p256KeyHex,
		}
		data, _ := json.Marshal(resp)

		meta, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.Attestation != nil {
			t.Errorf("expected nil attestation, got %+v", meta.Attestation)
		}
	})

	t.Run("invalid JSON returns parse error", func(t *testing.T) {
		_, err := parseEnrollResponse([]byte("{invalid"), config.AlgorithmP256, "k")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "failed to parse enrollment response") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Hex is hex encoded", func(t *testing.T) {
		resp := protocol.EnrollResponse{
			Status:       protocol.EnrollResponseStatusApproved,
			PublicKeyHex: &p256KeyHex,
		}
		data, _ := json.Marshal(resp)

		meta, err := parseEnrollResponse(data, config.AlgorithmP256, "k")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.Hex() == "" {
			t.Error("expected non-empty Hex()")
		}
		// Should be 66 hex chars for 33-byte compressed P-256 key (0x02/0x03 || X)
		if len(meta.Hex()) != 66 {
			t.Errorf("expected Hex() length 66, got %d", len(meta.Hex()))
		}
	})
}
