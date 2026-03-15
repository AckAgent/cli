package openpgp

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
)

// Compression algorithms (RFC 4880 §9.3)
const (
	CompressionUncompressed = 0 // No compression
	CompressionZIP          = 1 // ZIP (RFC 1951 raw DEFLATE)
	CompressionZLIB         = 2 // ZLIB (RFC 1950)
	CompressionBZIP2        = 3 // BZIP2
)

// CompressedDataPacket represents an OpenPGP compressed data packet (tag 8).
// RFC 4880 section 5.6
type CompressedDataPacket struct {
	Algorithm      byte   // Compression algorithm
	CompressedData []byte // The compressed data (contains nested packets)
}

// ParseCompressed parses a compressed data packet body.
// Format: algorithm (1 byte) || compressed_data
func ParseCompressed(body []byte) (*CompressedDataPacket, error) {
	if len(body) < 1 {
		return nil, errors.New("compressed data packet too short")
	}

	return &CompressedDataPacket{
		Algorithm:      body[0],
		CompressedData: body[1:],
	}, nil
}

// Decompress decompresses the packet data and returns the raw bytes.
// The returned data contains nested OpenPGP packets (typically literal data).
func (c *CompressedDataPacket) Decompress() ([]byte, error) {
	switch c.Algorithm {
	case CompressionUncompressed:
		// No compression - return data as-is
		return c.CompressedData, nil

	case CompressionZIP:
		// ZIP uses raw DEFLATE (RFC 1951) without zlib header/trailer
		return decompressFlate(c.CompressedData)

	case CompressionZLIB:
		// ZLIB (RFC 1950) includes header and checksum
		return decompressZlib(c.CompressedData)

	case CompressionBZIP2:
		// BZIP2 compression
		return decompressBzip2(c.CompressedData)

	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %d", c.Algorithm)
	}
}

// AlgorithmName returns a human-readable name for the compression algorithm.
func (c *CompressedDataPacket) AlgorithmName() string {
	switch c.Algorithm {
	case CompressionUncompressed:
		return "Uncompressed"
	case CompressionZIP:
		return "ZIP"
	case CompressionZLIB:
		return "ZLIB"
	case CompressionBZIP2:
		return "BZIP2"
	default:
		return fmt.Sprintf("Unknown(%d)", c.Algorithm)
	}
}

// decompressFlate decompresses raw DEFLATE data (RFC 1951).
func decompressFlate(data []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	defer reader.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return nil, fmt.Errorf("DEFLATE decompression failed: %w", err)
	}

	return buf.Bytes(), nil
}

// decompressZlib decompresses ZLIB data (RFC 1950).
func decompressZlib(data []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer reader.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return nil, fmt.Errorf("ZLIB decompression failed: %w", err)
	}

	return buf.Bytes(), nil
}

// decompressBzip2 decompresses BZIP2 data.
func decompressBzip2(data []byte) ([]byte, error) {
	reader := bzip2.NewReader(bytes.NewReader(data))

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return nil, fmt.Errorf("BZIP2 decompression failed: %w", err)
	}

	return buf.Bytes(), nil
}
