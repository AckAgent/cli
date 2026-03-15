package openpgp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestVectors matches the structure in data/crypto_test_vectors.json
type TestVectors struct {
	GPGVectors         GPGVectors         `json:"gpg_vectors"`
	FingerprintVectors FingerprintVectors `json:"fingerprint_vectors"`
}

// FingerprintVectors contains cross-platform fingerprint test vectors.
type FingerprintVectors struct {
	Ed25519        FingerprintKeyVector  `json:"ed25519"`
	Curve25519ECDH FingerprintKeyVector  `json:"curve25519_ecdh"`
	P256           FingerprintP256Vector `json:"p256"`
}

type FingerprintKeyVector struct {
	PublicKeyHex      string `json:"public_key_hex"`
	CreationTimestamp int64  `json:"creation_timestamp"`
	FingerprintHex    string `json:"fingerprint_hex"`
	KeyIDHex          string `json:"key_id_hex"`
}

type FingerprintP256Vector struct {
	PublicKeyUncompressedHex string `json:"public_key_uncompressed_hex"`
	PublicKeyCompressedHex   string `json:"public_key_compressed_hex"`
	CreationTimestamp        int64  `json:"creation_timestamp"`
	FingerprintHex           string `json:"fingerprint_hex"`
	KeyIDHex                 string `json:"key_id_hex"`
}

type GPGVectors struct {
	Description      string             `json:"description"`
	KeyMaterial      GPGKeyMaterial     `json:"key_material"`
	PublicKeyPacket  GPGPublicKeyPacket `json:"public_key_packet"`
	SignatureCases   []GPGSignatureCase `json:"signature_cases"`
	ComponentVectors ComponentVectors   `json:"component_vectors"`
}

type GPGKeyMaterial struct {
	PrivateKeyDHex        string `json:"private_key_d_hex"`
	PublicKeyXHex         string `json:"public_key_x_hex"`
	PublicKeyYHex         string `json:"public_key_y_hex"`
	PublicKeyUncompressed string `json:"public_key_uncompressed_hex"`
	CreationTimestamp     int64  `json:"creation_timestamp"`
	FingerprintHex        string `json:"fingerprint_hex"`
	KeyIDHex              string `json:"key_id_hex"`
}

type GPGPublicKeyPacket struct {
	PacketBodyHex    string `json:"packet_body_hex"`
	PacketHex        string `json:"packet_hex"`
	UserID           string `json:"user_id"`
	UserIDPacketHex  string `json:"user_id_packet_hex"`
	FullPublicKeyHex string `json:"full_public_key_hex"`
	Armored          string `json:"armored"`
}

type GPGSignatureCase struct {
	Description        string             `json:"description"`
	MessageHex         string             `json:"message_hex"`
	MessageText        string             `json:"message_text"`
	SignatureTimestamp int64              `json:"signature_timestamp"`
	Layers             GPGSignatureLayers `json:"layers"`
}

type GPGSignatureLayers struct {
	SignatureHeaderHex     string `json:"signature_header_hex"`
	HashedSubpacketsHex    string `json:"hashed_subpackets_hex"`
	UnhashedSubpacketsHex  string `json:"unhashed_subpackets_hex"`
	TrailerHex             string `json:"trailer_hex"`
	HashInputHex           string `json:"hash_input_hex"`
	DigestHex              string `json:"digest_hex"`
	SignatureRHex          string `json:"signature_r_hex"`
	SignatureSHex          string `json:"signature_s_hex"`
	MPIRHex                string `json:"mpi_r_hex"`
	MPISHex                string `json:"mpi_s_hex"`
	SignaturePacketBodyHex string `json:"signature_packet_body_hex"`
	SignaturePacketHex     string `json:"signature_packet_hex"`
	CRC24Hex               string `json:"crc24_hex"`
	Armored                string `json:"armored"`
}

type ComponentVectors struct {
	MPI        []MPIVector       `json:"mpi"`
	CRC24      []CRC24Vector     `json:"crc24"`
	Subpackets []SubpacketVector `json:"subpackets"`
}

type MPIVector struct {
	Description string `json:"description"`
	InputHex    string `json:"input_hex"`
	OutputHex   string `json:"output_hex"`
}

type CRC24Vector struct {
	Description string `json:"description"`
	InputHex    string `json:"input_hex"`
	CRC24Hex    string `json:"crc24_hex"`
}

type SubpacketVector struct {
	Description string `json:"description"`
	Type        string `json:"type"`
	ValueHex    string `json:"value_hex"`
	EncodedHex  string `json:"encoded_hex"`
}

func loadVectors(t *testing.T) *TestVectors {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get caller info")
	}

	// Navigate from internal/gpg/openpgp/ to data/
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
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

// TestGPGVectorsFingerprint validates fingerprint computation against test vectors
func TestGPGVectorsFingerprint(t *testing.T) {
	vectors := loadVectors(t)
	km := vectors.GPGVectors.KeyMaterial

	pubKey := mustDecodeHex(t, km.PublicKeyUncompressed)
	creationTime := time.Unix(km.CreationTimestamp, 0)

	fp := V4Fingerprint(pubKey, creationTime)
	fpHex := hex.EncodeToString(fp)

	if fpHex != km.FingerprintHex {
		t.Errorf("fingerprint mismatch:\ngot:  %s\nwant: %s", fpHex, km.FingerprintHex)
	}
}

// TestGPGVectorsKeyID validates key ID extraction against test vectors
func TestGPGVectorsKeyID(t *testing.T) {
	vectors := loadVectors(t)
	km := vectors.GPGVectors.KeyMaterial

	fp := mustDecodeHex(t, km.FingerprintHex)
	keyID := KeyIDFromFingerprint(fp)
	keyIDHex := FormatKeyID(keyID)

	// FormatKeyID returns uppercase, test vectors are lowercase
	if keyIDHex != km.KeyIDHex && hex.EncodeToString([]byte{
		byte(keyID >> 56), byte(keyID >> 48), byte(keyID >> 40), byte(keyID >> 32),
		byte(keyID >> 24), byte(keyID >> 16), byte(keyID >> 8), byte(keyID),
	}) != km.KeyIDHex {
		t.Errorf("key ID mismatch:\ngot:  %s\nwant: %s", keyIDHex, km.KeyIDHex)
	}
}

// TestGPGVectorsPublicKeyPacket validates public key packet construction
func TestGPGVectorsPublicKeyPacket(t *testing.T) {
	vectors := loadVectors(t)
	km := vectors.GPGVectors.KeyMaterial
	pkp := vectors.GPGVectors.PublicKeyPacket

	pubKey := mustDecodeHex(t, km.PublicKeyUncompressed)
	creationTime := time.Unix(km.CreationTimestamp, 0)

	packet := BuildPublicKeyPacket(pubKey, creationTime)
	packetHex := hex.EncodeToString(packet)

	if packetHex != pkp.PacketHex {
		t.Errorf("public key packet mismatch:\ngot:  %s\nwant: %s", packetHex, pkp.PacketHex)
	}
}

// TestGPGVectorsUserIDPacket validates user ID packet construction
func TestGPGVectorsUserIDPacket(t *testing.T) {
	vectors := loadVectors(t)
	pkp := vectors.GPGVectors.PublicKeyPacket

	packet := BuildUserIDPacket(pkp.UserID)
	packetHex := hex.EncodeToString(packet)

	if packetHex != pkp.UserIDPacketHex {
		t.Errorf("user ID packet mismatch:\ngot:  %s\nwant: %s", packetHex, pkp.UserIDPacketHex)
	}
}

// TestGPGVectorsHashInput validates hash input construction for signatures
func TestGPGVectorsHashInput(t *testing.T) {
	vectors := loadVectors(t)
	km := vectors.GPGVectors.KeyMaterial

	for _, tc := range vectors.GPGVectors.SignatureCases {
		t.Run(tc.Description, func(t *testing.T) {
			message := mustDecodeHex(t, tc.MessageHex)
			fp := mustDecodeHex(t, km.FingerprintHex)
			keyID := KeyIDFromFingerprint(fp)
			sigTime := time.Unix(tc.SignatureTimestamp, 0)

			sb := NewSignatureBuilder().
				SetSignatureType(SigTypeBinary).
				SetCreationTime(sigTime).
				SetIssuerKeyID(keyID).
				SetIssuerFingerprint(fp)

			digest, header := sb.BuildHashInput(message)

			// Verify header
			headerHex := hex.EncodeToString(header)
			if headerHex != tc.Layers.SignatureHeaderHex {
				t.Errorf("header mismatch:\ngot:  %s\nwant: %s", headerHex, tc.Layers.SignatureHeaderHex)
			}

			// Verify digest
			digestHex := hex.EncodeToString(digest)
			if digestHex != tc.Layers.DigestHex {
				t.Errorf("digest mismatch:\ngot:  %s\nwant: %s", digestHex, tc.Layers.DigestHex)
			}
		})
	}
}

// TestGPGVectorsSignaturePacket validates complete signature packet construction
func TestGPGVectorsSignaturePacket(t *testing.T) {
	vectors := loadVectors(t)
	km := vectors.GPGVectors.KeyMaterial

	for _, tc := range vectors.GPGVectors.SignatureCases {
		t.Run(tc.Description, func(t *testing.T) {
			message := mustDecodeHex(t, tc.MessageHex)
			fp := mustDecodeHex(t, km.FingerprintHex)
			keyID := KeyIDFromFingerprint(fp)
			sigTime := time.Unix(tc.SignatureTimestamp, 0)

			sb := NewSignatureBuilder().
				SetSignatureType(SigTypeBinary).
				SetCreationTime(sigTime).
				SetIssuerKeyID(keyID).
				SetIssuerFingerprint(fp)

			digest, header := sb.BuildHashInput(message)

			// Use the signature from test vectors
			sigR := mustDecodeHex(t, tc.Layers.SignatureRHex)
			sigS := mustDecodeHex(t, tc.Layers.SignatureSHex)
			rawSig := append(sigR, sigS...)

			sigPacket, err := sb.FinalizeSignature(header, digest, rawSig)
			if err != nil {
				t.Fatalf("FinalizeSignature failed: %v", err)
			}

			sigPacketHex := hex.EncodeToString(sigPacket)
			if sigPacketHex != tc.Layers.SignaturePacketHex {
				t.Errorf("signature packet mismatch:\ngot:  %s\nwant: %s", sigPacketHex, tc.Layers.SignaturePacketHex)
			}
		})
	}
}

// TestGPGVectorsCRC24 validates CRC24 computation against test vectors
func TestGPGVectorsCRC24(t *testing.T) {
	vectors := loadVectors(t)

	for _, tc := range vectors.GPGVectors.ComponentVectors.CRC24 {
		t.Run(tc.Description, func(t *testing.T) {
			input := mustDecodeHex(t, tc.InputHex)
			crc := CRC24(input)
			crcHex := hex.EncodeToString([]byte{byte(crc >> 16), byte(crc >> 8), byte(crc)})

			if crcHex != tc.CRC24Hex {
				t.Errorf("CRC24 mismatch:\ngot:  %s\nwant: %s", crcHex, tc.CRC24Hex)
			}
		})
	}
}

// TestGPGVectorsMPI validates MPI encoding against test vectors
func TestGPGVectorsMPI(t *testing.T) {
	vectors := loadVectors(t)

	for _, tc := range vectors.GPGVectors.ComponentVectors.MPI {
		t.Run(tc.Description, func(t *testing.T) {
			input := mustDecodeHex(t, tc.InputHex)
			output := EncodeMPIFromBytes(input)
			outputHex := hex.EncodeToString(output)

			if outputHex != tc.OutputHex {
				t.Errorf("MPI encoding mismatch:\ngot:  %s\nwant: %s", outputHex, tc.OutputHex)
			}
		})
	}
}

// TestGPGVectorsArmor validates ASCII armor output against test vectors
func TestGPGVectorsArmor(t *testing.T) {
	vectors := loadVectors(t)

	for _, tc := range vectors.GPGVectors.SignatureCases {
		t.Run(tc.Description, func(t *testing.T) {
			sigPacket := mustDecodeHex(t, tc.Layers.SignaturePacketHex)
			armored := ArmorSig(sigPacket)

			if armored != tc.Layers.Armored {
				t.Errorf("armor mismatch:\ngot:\n%s\nwant:\n%s", armored, tc.Layers.Armored)
			}
		})
	}
}

// TestGPGVectorsSubpackets validates subpacket encoding against test vectors
func TestGPGVectorsSubpackets(t *testing.T) {
	vectors := loadVectors(t)

	for _, tc := range vectors.GPGVectors.ComponentVectors.Subpackets {
		t.Run(tc.Description, func(t *testing.T) {
			switch tc.Type {
			case "creation_time":
				// Parse timestamp from hex (4 bytes big-endian)
				valueBytes := mustDecodeHex(t, tc.ValueHex)
				ts := int64(valueBytes[0])<<24 | int64(valueBytes[1])<<16 | int64(valueBytes[2])<<8 | int64(valueBytes[3])

				sb := NewSubpacketBuilder()
				sb.AddCreationTime(time.Unix(ts, 0))
				encoded := sb.Bytes()
				encodedHex := hex.EncodeToString(encoded)

				if encodedHex != tc.EncodedHex {
					t.Errorf("subpacket encoding mismatch:\ngot:  %s\nwant: %s", encodedHex, tc.EncodedHex)
				}
			}
		})
	}
}

// TestGPGVectorsDigestComputation validates that we compute the correct digest
func TestGPGVectorsDigestComputation(t *testing.T) {
	vectors := loadVectors(t)

	for _, tc := range vectors.GPGVectors.SignatureCases {
		t.Run(tc.Description, func(t *testing.T) {
			// Manually compute digest from hash input
			hashInput := mustDecodeHex(t, tc.Layers.HashInputHex)
			expectedDigest := mustDecodeHex(t, tc.Layers.DigestHex)

			h := sha256.New()
			h.Write(hashInput)
			computed := h.Sum(nil)

			if hex.EncodeToString(computed) != hex.EncodeToString(expectedDigest) {
				t.Errorf("digest computation mismatch:\ngot:  %s\nwant: %s",
					hex.EncodeToString(computed), hex.EncodeToString(expectedDigest))
			}
		})
	}
}

// TestCrossPlatformFingerprintEd25519 validates Ed25519 fingerprint matches the cross-platform test vector.
func TestCrossPlatformFingerprintEd25519(t *testing.T) {
	vectors := loadVectors(t)
	v := vectors.FingerprintVectors.Ed25519

	pubKey := mustDecodeHex(t, v.PublicKeyHex)
	creationTime := time.Unix(v.CreationTimestamp, 0)

	fp := V4FingerprintEd25519(pubKey, creationTime)
	fpHex := hex.EncodeToString(fp)

	if fpHex != v.FingerprintHex {
		t.Errorf("Ed25519 fingerprint mismatch:\ngot:  %s\nwant: %s", fpHex, v.FingerprintHex)
	}

	// Also verify key ID
	keyID := KeyIDFromFingerprint(fp)
	keyIDHex := hex.EncodeToString([]byte{
		byte(keyID >> 56), byte(keyID >> 48), byte(keyID >> 40), byte(keyID >> 32),
		byte(keyID >> 24), byte(keyID >> 16), byte(keyID >> 8), byte(keyID),
	})
	if keyIDHex != v.KeyIDHex {
		t.Errorf("Ed25519 key ID mismatch:\ngot:  %s\nwant: %s", keyIDHex, v.KeyIDHex)
	}
}

// TestCrossPlatformFingerprintCurve25519ECDH validates Curve25519 ECDH subkey fingerprint matches the cross-platform test vector.
func TestCrossPlatformFingerprintCurve25519ECDH(t *testing.T) {
	vectors := loadVectors(t)
	v := vectors.FingerprintVectors.Curve25519ECDH

	pubKey := mustDecodeHex(t, v.PublicKeyHex)
	creationTime := time.Unix(v.CreationTimestamp, 0)

	fp := V4FingerprintCurve25519ECDH(pubKey, creationTime)
	fpHex := hex.EncodeToString(fp)

	if fpHex != v.FingerprintHex {
		t.Errorf("Curve25519 ECDH fingerprint mismatch:\ngot:  %s\nwant: %s", fpHex, v.FingerprintHex)
	}

	// Also verify key ID
	keyID := KeyIDFromFingerprint(fp)
	keyIDHex := hex.EncodeToString([]byte{
		byte(keyID >> 56), byte(keyID >> 48), byte(keyID >> 40), byte(keyID >> 32),
		byte(keyID >> 24), byte(keyID >> 16), byte(keyID >> 8), byte(keyID),
	})
	if keyIDHex != v.KeyIDHex {
		t.Errorf("Curve25519 ECDH key ID mismatch:\ngot:  %s\nwant: %s", keyIDHex, v.KeyIDHex)
	}
}

// TestCrossPlatformFingerprintP256 validates P-256 fingerprint matches the cross-platform test vector.
// Tests both compressed and uncompressed input produce the same fingerprint.
func TestCrossPlatformFingerprintP256(t *testing.T) {
	vectors := loadVectors(t)
	v := vectors.FingerprintVectors.P256

	// Test with uncompressed key
	uncompressed := mustDecodeHex(t, v.PublicKeyUncompressedHex)
	creationTime := time.Unix(v.CreationTimestamp, 0)

	fp := V4Fingerprint(uncompressed, creationTime)
	fpHex := hex.EncodeToString(fp)

	if fpHex != v.FingerprintHex {
		t.Errorf("P-256 fingerprint (uncompressed) mismatch:\ngot:  %s\nwant: %s", fpHex, v.FingerprintHex)
	}

	// Test with compressed key (should produce same fingerprint after decompression)
	compressed := mustDecodeHex(t, v.PublicKeyCompressedHex)
	fpCompressed := V4Fingerprint(compressed, creationTime)
	fpCompressedHex := hex.EncodeToString(fpCompressed)

	if fpCompressedHex != v.FingerprintHex {
		t.Errorf("P-256 fingerprint (compressed) mismatch:\ngot:  %s\nwant: %s", fpCompressedHex, v.FingerprintHex)
	}

	// Verify key ID
	keyID := KeyIDFromFingerprint(fp)
	keyIDHex := hex.EncodeToString([]byte{
		byte(keyID >> 56), byte(keyID >> 48), byte(keyID >> 40), byte(keyID >> 32),
		byte(keyID >> 24), byte(keyID >> 16), byte(keyID >> 8), byte(keyID),
	})
	if keyIDHex != v.KeyIDHex {
		t.Errorf("P-256 key ID mismatch:\ngot:  %s\nwant: %s", keyIDHex, v.KeyIDHex)
	}
}
