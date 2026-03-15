package openpgp

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"testing"
)

func TestParseCompressed(t *testing.T) {
	tests := []struct {
		name        string
		body        []byte
		wantAlgo    byte
		wantDataLen int
		wantErr     bool
	}{
		{
			name:        "uncompressed",
			body:        []byte{0x00, 0x01, 0x02, 0x03},
			wantAlgo:    CompressionUncompressed,
			wantDataLen: 3,
		},
		{
			name:        "zip algorithm marker",
			body:        []byte{0x01, 0xAB, 0xCD},
			wantAlgo:    CompressionZIP,
			wantDataLen: 2,
		},
		{
			name:        "zlib algorithm marker",
			body:        []byte{0x02, 0xDE, 0xAD, 0xBE, 0xEF},
			wantAlgo:    CompressionZLIB,
			wantDataLen: 4,
		},
		{
			name:        "bzip2 algorithm marker",
			body:        []byte{0x03, 0x42, 0x5A},
			wantAlgo:    CompressionBZIP2,
			wantDataLen: 2,
		},
		{
			name:    "empty body",
			body:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt, err := ParseCompressed(tt.body)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pkt.Algorithm != tt.wantAlgo {
				t.Errorf("Algorithm = %d, want %d", pkt.Algorithm, tt.wantAlgo)
			}
			if len(pkt.CompressedData) != tt.wantDataLen {
				t.Errorf("CompressedData length = %d, want %d", len(pkt.CompressedData), tt.wantDataLen)
			}
		})
	}
}

func TestDecompressUncompressed(t *testing.T) {
	data := []byte("hello world")
	pkt := &CompressedDataPacket{
		Algorithm:      CompressionUncompressed,
		CompressedData: data,
	}

	result, err := pkt.Decompress()
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Errorf("Decompress = %q, want %q", result, data)
	}
}

func TestDecompressZIP(t *testing.T) {
	// Create DEFLATE-compressed data
	original := []byte("test data for compression testing")
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("failed to create flate writer: %v", err)
	}
	if _, err := w.Write(original); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	pkt := &CompressedDataPacket{
		Algorithm:      CompressionZIP,
		CompressedData: buf.Bytes(),
	}

	result, err := pkt.Decompress()
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}
	if !bytes.Equal(result, original) {
		t.Errorf("Decompress = %q, want %q", result, original)
	}
}

func TestDecompressZLIB(t *testing.T) {
	// Create ZLIB-compressed data
	original := []byte("test data for zlib compression testing")
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(original); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	pkt := &CompressedDataPacket{
		Algorithm:      CompressionZLIB,
		CompressedData: buf.Bytes(),
	}

	result, err := pkt.Decompress()
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}
	if !bytes.Equal(result, original) {
		t.Errorf("Decompress = %q, want %q", result, original)
	}
}

// Note: Go's compress/bzip2 package only provides a reader (no writer),
// so we test with pre-compressed data from a known source.
func TestDecompressBZIP2(t *testing.T) {
	// BZIP2 compressed "hello" - generated with: echo -n "hello" | bzip2 | xxd -i
	compressedData := []byte{
		0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26,
		0x53, 0x59, 0x19, 0x31, 0x65, 0x3d, 0x00, 0x00,
		0x00, 0x81, 0x00, 0x02, 0x44, 0xa0, 0x00, 0x21,
		0x9a, 0x68, 0x33, 0x4d, 0x07, 0x33, 0x8b, 0xb9,
		0x22, 0x9c, 0x28, 0x48, 0x0c, 0x98, 0xb2, 0x9e,
		0x80,
	}

	pkt := &CompressedDataPacket{
		Algorithm:      CompressionBZIP2,
		CompressedData: compressedData,
	}

	result, err := pkt.Decompress()
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}
	if string(result) != "hello" {
		t.Errorf("Decompress = %q, want %q", result, "hello")
	}
}

func TestDecompressUnsupportedAlgorithm(t *testing.T) {
	pkt := &CompressedDataPacket{
		Algorithm:      99, // Unknown algorithm
		CompressedData: []byte{0x01, 0x02, 0x03},
	}

	_, err := pkt.Decompress()
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestDecompressInvalidData(t *testing.T) {
	tests := []struct {
		name string
		pkt  *CompressedDataPacket
	}{
		{
			name: "invalid ZIP data",
			pkt: &CompressedDataPacket{
				Algorithm:      CompressionZIP,
				CompressedData: []byte{0xFF, 0xFF, 0xFF},
			},
		},
		{
			name: "invalid ZLIB data",
			pkt: &CompressedDataPacket{
				Algorithm:      CompressionZLIB,
				CompressedData: []byte{0xFF, 0xFF, 0xFF},
			},
		},
		{
			name: "invalid BZIP2 data",
			pkt: &CompressedDataPacket{
				Algorithm:      CompressionBZIP2,
				CompressedData: []byte{0xFF, 0xFF, 0xFF},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.pkt.Decompress()
			if err == nil {
				t.Error("expected error for invalid compressed data")
			}
		})
	}
}

func TestAlgorithmName(t *testing.T) {
	tests := []struct {
		algo byte
		want string
	}{
		{CompressionUncompressed, "Uncompressed"},
		{CompressionZIP, "ZIP"},
		{CompressionZLIB, "ZLIB"},
		{CompressionBZIP2, "BZIP2"},
		{99, "Unknown(99)"},
	}

	for _, tt := range tests {
		pkt := &CompressedDataPacket{Algorithm: tt.algo}
		if got := pkt.AlgorithmName(); got != tt.want {
			t.Errorf("AlgorithmName() for %d = %q, want %q", tt.algo, got, tt.want)
		}
	}
}

// TestDecompressWithNestedPackets tests decompressing data that contains
// nested OpenPGP packets (the real-world use case).
func TestDecompressWithNestedPackets(t *testing.T) {
	// Create a simple literal data packet
	// Format: format (1 byte) || filename_len (1 byte) || filename || date (4 bytes) || data
	literalContent := []byte("test message content")
	literalBody := make([]byte, 0, 6+len(literalContent))
	literalBody = append(literalBody, 'b')        // format: binary
	literalBody = append(literalBody, 0x00)       // filename length: 0
	literalBody = append(literalBody, 0, 0, 0, 0) // date: 0
	literalBody = append(literalBody, literalContent...)

	// Wrap in a packet (tag 11 = literal data)
	literalPacket := BuildPacket(PacketTagLiteralData, literalBody)

	// Compress with ZLIB
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(literalPacket); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	pkt := &CompressedDataPacket{
		Algorithm:      CompressionZLIB,
		CompressedData: buf.Bytes(),
	}

	// Decompress
	decompressed, err := pkt.Decompress()
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}

	// Parse the decompressed data as OpenPGP packets
	packets, err := ParseAllPackets(decompressed)
	if err != nil {
		t.Fatalf("ParseAllPackets failed: %v", err)
	}

	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	if packets[0].Tag != PacketTagLiteralData {
		t.Errorf("expected literal data packet (tag %d), got tag %d", PacketTagLiteralData, packets[0].Tag)
	}
}
