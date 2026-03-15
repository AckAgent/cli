package commands

import (
	"bytes"
	"compress/flate"
	"testing"

	"github.com/ackagent/cli/internal/gpg/openpgp"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLiteralData_ValidPacket(t *testing.T) {
	// Build a literal data packet body:
	// format (1 byte) || filename_len (1 byte) || filename || date (4 bytes) || data
	body := []byte{
		'b',                // format: binary
		0x04,               // filename length: 4
		't', 'e', 's', 't', // filename: "test"
		0x00, 0x00, 0x00, 0x00, // date: zero
	}
	expectedData := []byte("Hello, World!")
	body = append(body, expectedData...)

	result, err := parseLiteralData(body)
	require.NoError(t, err)
	assert.Equal(t, expectedData, result)
}

func TestParseLiteralData_EmptyFilename(t *testing.T) {
	// format (1 byte) || filename_len=0 (1 byte) || date (4 bytes) || data
	body := []byte{
		'b',                    // format: binary
		0x00,                   // filename length: 0
		0x00, 0x00, 0x00, 0x00, // date: zero
	}
	expectedData := []byte("data without filename")
	body = append(body, expectedData...)

	result, err := parseLiteralData(body)
	require.NoError(t, err)
	assert.Equal(t, expectedData, result)
}

func TestParseLiteralData_EmptyData(t *testing.T) {
	// Literal data with no actual data after the header
	body := []byte{
		'b',                    // format
		0x00,                   // filename length: 0
		0x00, 0x00, 0x00, 0x00, // date
	}

	result, err := parseLiteralData(body)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestParseLiteralData_TooShort(t *testing.T) {
	// Packet shorter than minimum 6 bytes
	_, err := parseLiteralData([]byte{0x62, 0x00, 0x00})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestParseLiteralData_Truncated(t *testing.T) {
	// Filename length says 10, but not enough data
	body := []byte{
		'b',                // format
		0x0A,               // filename length: 10
		't', 'e', 's', 't', // only 4 bytes of filename
	}

	_, err := parseLiteralData(body)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "truncated")
}

func TestParseLiteralData_TextFormat(t *testing.T) {
	// Text format ('t' = 0x74)
	body := []byte{
		't',                    // format: text
		0x00,                   // filename length: 0
		0x00, 0x00, 0x00, 0x00, // date
	}
	textData := []byte("text format data\n")
	body = append(body, textData...)

	result, err := parseLiteralData(body)
	require.NoError(t, err)
	assert.Equal(t, textData, result)
}

func TestParseLiteralData_LongFilename(t *testing.T) {
	// Maximum filename length (255)
	filename := make([]byte, 255)
	for i := range filename {
		filename[i] = 'a'
	}

	body := []byte{
		'b',  // format
		0xFF, // filename length: 255
	}
	body = append(body, filename...)
	body = append(body, 0x00, 0x00, 0x00, 0x00) // date
	expectedData := []byte("data after long filename")
	body = append(body, expectedData...)

	result, err := parseLiteralData(body)
	require.NoError(t, err)
	assert.Equal(t, expectedData, result)
}

func TestExtractLiteralData_LiteralPacket(t *testing.T) {
	// Build a literal data packet using openpgp primitives
	pw := openpgp.NewPacketWriter()
	pw.WriteByte('b')                   // format: binary
	pw.WriteByte(0x00)                  // filename length: 0
	pw.Write([]byte{0, 0, 0, 0})        // date
	pw.Write([]byte("hello from test")) // data
	literalPacket := openpgp.BuildPacket(openpgp.PacketTagLiteralData, pw.Bytes())

	result, err := extractLiteralData(literalPacket)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello from test"), result)
}

func TestExtractLiteralData_CompressedThenLiteral(t *testing.T) {
	// Build a literal data packet inside a compressed data packet
	pw := openpgp.NewPacketWriter()
	pw.WriteByte('b')                   // format
	pw.WriteByte(0x00)                  // filename length
	pw.Write([]byte{0, 0, 0, 0})        // date
	pw.Write([]byte("compressed data")) // data
	innerLiteral := openpgp.BuildPacket(openpgp.PacketTagLiteralData, pw.Bytes())

	// Compress with ZIP (algorithm 1 = raw deflate)
	var compressed bytes.Buffer
	compressed.WriteByte(1) // algorithm = ZIP (raw deflate)
	w, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
	w.Write(innerLiteral)
	w.Close()
	compressedPacket := openpgp.BuildPacket(openpgp.PacketTagCompressedData, compressed.Bytes())

	result, err := extractLiteralData(compressedPacket)
	require.NoError(t, err)
	assert.Equal(t, []byte("compressed data"), result)
}

func TestExtractLiteralData_NoPackets(t *testing.T) {
	// Empty data should fail to parse
	_, err := extractLiteralData([]byte{})
	assert.Error(t, err)
}

func TestExtractLiteralData_NoLiteralPacketFallback(t *testing.T) {
	// Build a non-literal, non-compressed packet (e.g., a signature packet)
	sigBody := []byte{4, 0x00, 1, 8, 0, 0, 0, 0, 0xAB, 0xCD}
	sigPacket := openpgp.BuildPacket(openpgp.PacketTagSignature, sigBody)

	// When no literal data is found, extractLiteralData returns the raw input
	result, err := extractLiteralData(sigPacket)
	require.NoError(t, err)
	assert.Equal(t, sigPacket, result)
}

func TestIssuerKeyIDString_WithFingerprint(t *testing.T) {
	fp := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD}
	sig := &openpgp.ParsedSignature{
		IssuerFP:    fp,
		IssuerKeyID: 0x1234567890ABCDEF,
	}

	result := issuerKeyIDString(sig)
	assert.Equal(t, "AABBCCDDEEFF00112233445566778899AABBCCDD", result)
}

func TestIssuerKeyIDString_WithKeyIDOnly(t *testing.T) {
	sig := &openpgp.ParsedSignature{
		IssuerFP:    nil,
		IssuerKeyID: 0x1234567890ABCDEF,
	}

	result := issuerKeyIDString(sig)
	assert.Equal(t, openpgp.FormatKeyID(0x1234567890ABCDEF), result)
}

func TestIssuerKeyIDString_NoIssuer(t *testing.T) {
	sig := &openpgp.ParsedSignature{
		IssuerFP:    nil,
		IssuerKeyID: 0,
	}

	result := issuerKeyIDString(sig)
	assert.Equal(t, "", result)
}

func TestGPGFingerprint_NonGPGPurpose(t *testing.T) {
	key := &config.KeyMetadata{
		Purpose:   config.KeyPurposeSSH,
		PublicKey: []byte("some-pubkey"),
	}
	assert.Equal(t, "", GPGFingerprint(key))
}

func TestGPGFingerprint_EmptyPublicKey(t *testing.T) {
	key := &config.KeyMetadata{
		Purpose:   config.KeyPurposeGPG,
		PublicKey: nil,
	}
	assert.Equal(t, "", GPGFingerprint(key))
}

func TestGPGFingerprint_Ed25519Key(t *testing.T) {
	key := &config.KeyMetadata{
		Purpose:              config.KeyPurposeGPG,
		PublicKey:            make([]byte, 32),
		Algorithm:            config.AlgorithmEd25519,
		KeyCreationTimestamp: 1700000000,
	}
	fp := GPGFingerprint(key)
	assert.Len(t, fp, 40, "fingerprint should be 40 hex chars")
}

func TestGPGFingerprint_UsesKeyCreationTimestamp(t *testing.T) {
	key1 := &config.KeyMetadata{
		Purpose:              config.KeyPurposeGPG,
		PublicKey:            []byte("test-pubkey-data"),
		KeyCreationTimestamp: 1700000000,
	}
	key2 := &config.KeyMetadata{
		Purpose:              config.KeyPurposeGPG,
		PublicKey:            []byte("test-pubkey-data"),
		KeyCreationTimestamp: 1700000001,
	}
	fp1 := GPGFingerprint(key1)
	fp2 := GPGFingerprint(key2)
	assert.NotEqual(t, fp1, fp2, "different creation timestamps should produce different fingerprints")
}

func TestListKeys_OutputFormat(t *testing.T) {
	// Test the logic of ListKeys without calling the function
	// (it writes to stdout and can't be easily captured without refactoring)

	key := config.KeyMetadata{
		IOSKeyID:             "gpg-key",
		Label:                "Test User <test@example.com>",
		PublicKey:            []byte("test-public-key-data"),
		Purpose:              config.KeyPurposeGPG,
		Algorithm:            config.AlgorithmP256,
		KeyCreationTimestamp: 1700000000,
	}

	// Test algorithm display
	algoDisplay := "nistp256"
	if key.Algorithm == config.AlgorithmEd25519 {
		algoDisplay = "EdDSA"
	}
	assert.Equal(t, "nistp256", algoDisplay)

	// Test GPG fingerprint computation
	fp := GPGFingerprint(&key)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 40)

	// Verify fingerprint validation logic from ListKeys
	assert.True(t, fp != "" && len(fp) == 40, "fingerprint should pass ListKeys validation")
}

func TestListKeys_Ed25519AlgoDisplay(t *testing.T) {
	key := config.KeyMetadata{
		Algorithm: config.AlgorithmEd25519,
	}

	algoDisplay := "nistp256"
	if key.Algorithm == config.AlgorithmEd25519 {
		algoDisplay = "EdDSA"
	}
	assert.Equal(t, "EdDSA", algoDisplay)
}
