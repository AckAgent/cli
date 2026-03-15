// gentestvectors generates deterministic test vectors for GPG and SSH operations.
// These vectors are used for cross-platform testing (Go, Swift, Kotlin).
//
// Usage:
//
//	go run ./cmd/gentestvectors > gpg_ssh_vectors.json
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"
)

// TestVectors contains all test vectors for GPG and SSH operations
type TestVectors struct {
	GPGVectors GPGVectors `json:"gpg_vectors"`
	SSHVectors SSHVectors `json:"ssh_vectors"`
}

// GPGVectors contains OpenPGP signature test vectors
type GPGVectors struct {
	Description      string              `json:"description"`
	KeyMaterial      GPGKeyMaterial      `json:"key_material"`
	PublicKeyPacket  GPGPublicKeyPacket  `json:"public_key_packet"`
	SignatureCases   []GPGSignatureCase  `json:"signature_cases"`
	ComponentVectors GPGComponentVectors `json:"component_vectors"`
}

type GPGKeyMaterial struct {
	Description           string `json:"description"`
	PrivateKeyDHex        string `json:"private_key_d_hex"`
	PublicKeyXHex         string `json:"public_key_x_hex"`
	PublicKeyYHex         string `json:"public_key_y_hex"`
	PublicKeyUncompressed string `json:"public_key_uncompressed_hex"`
	CreationTimestamp     int64  `json:"creation_timestamp"`
	FingerprintHex        string `json:"fingerprint_hex"`
	KeyIDHex              string `json:"key_id_hex"`
}

type GPGPublicKeyPacket struct {
	Description      string `json:"description"`
	PacketBodyHex    string `json:"packet_body_hex"`
	PacketHex        string `json:"packet_hex"`
	UserID           string `json:"user_id"`
	UserIDPacketHex  string `json:"user_id_packet_hex"`
	SelfSigPacketHex string `json:"self_sig_packet_hex"`
	FullPublicKeyHex string `json:"full_public_key_hex"`
	Armored          string `json:"armored"`
}

type GPGSignatureCase struct {
	Description       string             `json:"description"`
	MessageHex        string             `json:"message_hex"`
	MessageText       string             `json:"message_text,omitempty"`
	SignatureTimestamp int64              `json:"signature_timestamp"`
	Layers            GPGSignatureLayers `json:"layers"`
}

type GPGSignatureLayers struct {
	SignatureHeaderHex    string `json:"signature_header_hex"`
	HashedSubpacketsHex   string `json:"hashed_subpackets_hex"`
	UnhashedSubpacketsHex string `json:"unhashed_subpackets_hex"`
	TrailerHex            string `json:"trailer_hex"`
	HashInputHex          string `json:"hash_input_hex"`
	DigestHex             string `json:"digest_hex"`
	SignatureRHex         string `json:"signature_r_hex"`
	SignatureSHex         string `json:"signature_s_hex"`
	MPIRHex               string `json:"mpi_r_hex"`
	MPISHex               string `json:"mpi_s_hex"`
	SignaturePacketBodyHex string `json:"signature_packet_body_hex"`
	SignaturePacketHex     string `json:"signature_packet_hex"`
	CRC24Hex               string `json:"crc24_hex"`
	Armored                string `json:"armored"`
}

type GPGComponentVectors struct {
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

// SSHVectors contains SSH key and signature test vectors
type SSHVectors struct {
	Description     string             `json:"description"`
	KeyMaterial     SSHKeyMaterial     `json:"key_material"`
	PublicKeyFormat SSHPublicKeyFormat `json:"public_key_format"`
	KeyHandle       SSHKeyHandle       `json:"key_handle"`
	SignatureCases  []SSHSignatureCase `json:"signature_cases"`
}

type SSHKeyMaterial struct {
	Description    string `json:"description"`
	PrivateKeyDHex string `json:"private_key_d_hex"`
	PublicKeyXHex  string `json:"public_key_x_hex"`
	PublicKeyYHex  string `json:"public_key_y_hex"`
}

type SSHPublicKeyFormat struct {
	KeyType            string `json:"key_type"`
	CurveName          string `json:"curve_name"`
	Application        string `json:"application"`
	BlobHex            string `json:"blob_hex"`
	FingerprintSHA256  string `json:"fingerprint_sha256"`
	AuthorizedKeysLine string `json:"authorized_keys_line"`
}

type SSHKeyHandle struct {
	MagicHex          string                 `json:"magic_hex"`
	JSONPayload       map[string]interface{} `json:"json_payload"`
	CompleteHandleHex string                 `json:"complete_handle_hex"`
}

type SSHSignatureCase struct {
	Description     string `json:"description"`
	DataToSignHex   string `json:"data_to_sign_hex"`
	SignatureRHex   string `json:"signature_r_hex"`
	SignatureSHex   string `json:"signature_s_hex"`
	RawSignatureHex string `json:"raw_signature_hex"`
}

func main() {
	vectors := generateVectors()

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(vectors); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode vectors: %v\n", err)
		os.Exit(1)
	}
}

func generateVectors() TestVectors {
	privateKeyD := mustDecodeHex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")

	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(privateKeyD)

	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(privateKeyD),
	}

	keyCreationTime := time.Unix(1700000000, 0)
	sigTimestamp := time.Unix(1700000100, 0)

	return TestVectors{
		GPGVectors: generateGPGVectors(privateKey, keyCreationTime, sigTimestamp),
		SSHVectors: generateSSHVectors(privateKey),
	}
}
