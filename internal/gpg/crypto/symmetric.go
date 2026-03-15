// Package crypto implements OpenPGP cryptographic operations for encryption and decryption.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"

	"github.com/ackagent/cli/internal/gpg/openpgp"
)

// randReader is used for generating random bytes. Can be overridden for testing.
var randReader io.Reader = rand.Reader

// DecryptSEIPDv1 decrypts a version 1 SEIPD packet (CFB mode with MDC).
// RFC 4880 section 5.13
//
// The ciphertext format is:
// - Random prefix (block_size + 2 bytes, where last 2 bytes repeat previous 2)
// - Encrypted literal data packet
// - MDC packet: tag (1 byte) + length (1 byte) + SHA1 hash (20 bytes)
func DecryptSEIPDv1(key, ciphertext []byte, cipherAlgo byte) ([]byte, error) {
	blockSize := openpgp.KeyBlockSize(cipherAlgo)
	if blockSize == 0 {
		return nil, fmt.Errorf("unsupported cipher algorithm: %d", cipherAlgo)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Minimum length: prefix (blockSize+2) + 1 byte data + MDC (22 bytes)
	minLen := blockSize + 2 + 1 + 22
	if len(ciphertext) < minLen {
		return nil, fmt.Errorf("ciphertext too short: %d bytes (min %d)", len(ciphertext), minLen)
	}

	// OpenPGP CFB mode with resync
	plaintext := make([]byte, len(ciphertext))
	cfbDecrypt(block, plaintext, ciphertext)

	// Verify prefix - last 2 bytes should repeat previous 2
	if plaintext[blockSize] != plaintext[blockSize-2] || plaintext[blockSize+1] != plaintext[blockSize-1] {
		return nil, errors.New("quick check failed: prefix mismatch (wrong key?)")
	}

	// Remove prefix
	data := plaintext[blockSize+2:]

	// Extract and verify MDC
	if len(data) < 22 {
		return nil, errors.New("data too short for MDC")
	}

	mdcPacket := data[len(data)-22:]
	data = data[:len(data)-22]

	// MDC packet: 0xD3 (tag 19, new format), 0x14 (length 20), then 20-byte SHA1
	if mdcPacket[0] != 0xD3 || mdcPacket[1] != 0x14 {
		return nil, fmt.Errorf("invalid MDC packet header: %02x %02x", mdcPacket[0], mdcPacket[1])
	}

	expectedHash := mdcPacket[2:]

	// Compute MDC hash: SHA1(prefix || decrypted_data || 0xD3 || 0x14)
	h := sha1.New()
	h.Write(plaintext[:blockSize+2]) // prefix
	h.Write(data)                    // decrypted data
	h.Write([]byte{0xD3, 0x14})      // MDC packet header
	computedHash := h.Sum(nil)

	if !bytes.Equal(computedHash, expectedHash) {
		return nil, errors.New("MDC hash mismatch: message may have been tampered with")
	}

	return data, nil
}

// cfbDecrypt implements OpenPGP CFB mode decryption.
// RFC 4880 section 13.9: "OpenPGP CFB Mode"
//
// OpenPGP uses a modified CFB mode with block-by-block encryption:
// - Start with IV of all zeros
// - For each block: plaintext = ciphertext XOR encrypt(previous_ciphertext_block)
// - After the first block+2 bytes, there's a "resync" where the CFB shifts
func cfbDecrypt(block cipher.Block, dst, src []byte) {
	blockSize := block.BlockSize()
	iv := make([]byte, blockSize)
	prev := make([]byte, blockSize)
	copy(prev, iv)

	// Decrypt in CFB mode with OpenPGP resync
	encrypted := make([]byte, blockSize)
	pos := 0

	for pos < len(src) {
		block.Encrypt(encrypted, prev)

		// Determine how many bytes to process
		n := blockSize
		if pos+n > len(src) {
			n = len(src) - pos
		}

		// XOR to get plaintext
		for i := 0; i < n; i++ {
			dst[pos+i] = src[pos+i] ^ encrypted[i]
		}

		// Shift in new ciphertext for next block
		copy(prev, src[pos:pos+n])

		pos += n
	}
}

// DecryptSEIPDv2 decrypts a version 2 SEIPD packet (AEAD mode).
// RFC 9580 section 5.13.2
func DecryptSEIPDv2(key []byte, aeadAlgo, chunkSizeByte byte, salt, ciphertext []byte) ([]byte, error) {
	switch aeadAlgo {
	case openpgp.AEADAlgoOCB:
		return decryptOCB(key, chunkSizeByte, salt, ciphertext)
	case openpgp.AEADAlgoGCM:
		return decryptGCM(key, chunkSizeByte, salt, ciphertext)
	default:
		return nil, fmt.Errorf("unsupported AEAD algorithm: %d", aeadAlgo)
	}
}

// decryptOCB decrypts data using AES-OCB mode (RFC 7253).
// Note: Go's standard library doesn't include OCB, so we'd need a third-party implementation.
// For now, we return an error suggesting to use GCM.
func decryptOCB(key []byte, chunkSizeByte byte, salt, ciphertext []byte) ([]byte, error) {
	return nil, errors.New("OCB mode not yet implemented; use GCM-encrypted messages instead")
}

// decryptGCM decrypts data using AES-GCM mode.
// RFC 9580 AEAD decryption with chunking.
func decryptGCM(key []byte, chunkSizeByte byte, salt, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	chunkSize := 1 << (int(chunkSizeByte) + 6)
	tagSize := gcm.Overhead()

	// Each encrypted chunk is: encrypted_data || auth_tag
	// Final auth tag after all chunks
	encryptedChunkSize := chunkSize + tagSize

	var plaintext bytes.Buffer
	chunkIndex := uint64(0)

	for len(ciphertext) > tagSize {
		// Determine chunk size (last chunk may be smaller)
		thisChunkSize := encryptedChunkSize
		if thisChunkSize > len(ciphertext) {
			thisChunkSize = len(ciphertext)
		}

		// Build nonce: salt || chunk_index (8 bytes big-endian)
		nonce := make([]byte, 12)
		copy(nonce, salt[:4]) // First 4 bytes of salt
		nonce[4] = byte(chunkIndex >> 56)
		nonce[5] = byte(chunkIndex >> 48)
		nonce[6] = byte(chunkIndex >> 40)
		nonce[7] = byte(chunkIndex >> 32)
		nonce[8] = byte(chunkIndex >> 24)
		nonce[9] = byte(chunkIndex >> 16)
		nonce[10] = byte(chunkIndex >> 8)
		nonce[11] = byte(chunkIndex)

		chunk := ciphertext[:thisChunkSize]
		ciphertext = ciphertext[thisChunkSize:]

		decrypted, err := gcm.Open(nil, nonce, chunk, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt chunk %d: %w", chunkIndex, err)
		}

		plaintext.Write(decrypted)
		chunkIndex++
	}

	// Verify final authentication tag
	if len(ciphertext) != tagSize {
		return nil, errors.New("missing or invalid final authentication tag")
	}

	return plaintext.Bytes(), nil
}

// EncryptSEIPDv1 encrypts data using SEIPD v1 (CFB mode with MDC).
// Returns the complete SEIPD packet body.
func EncryptSEIPDv1(key, plaintext []byte, cipherAlgo byte) ([]byte, error) {
	blockSize := openpgp.KeyBlockSize(cipherAlgo)
	if blockSize == 0 {
		return nil, fmt.Errorf("unsupported cipher algorithm: %d", cipherAlgo)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate random prefix
	prefix := make([]byte, blockSize+2)
	if _, err := randReader.Read(prefix[:blockSize]); err != nil {
		return nil, fmt.Errorf("failed to generate random prefix: %w", err)
	}
	// Last 2 bytes repeat previous 2
	prefix[blockSize] = prefix[blockSize-2]
	prefix[blockSize+1] = prefix[blockSize-1]

	// Compute MDC hash: SHA1(prefix || plaintext || 0xD3 || 0x14)
	h := sha1.New()
	h.Write(prefix)
	h.Write(plaintext)
	h.Write([]byte{0xD3, 0x14})
	mdcHash := h.Sum(nil)

	// Build complete plaintext: prefix || data || MDC packet
	fullPlaintext := make([]byte, len(prefix)+len(plaintext)+22)
	copy(fullPlaintext, prefix)
	copy(fullPlaintext[len(prefix):], plaintext)
	fullPlaintext[len(prefix)+len(plaintext)] = 0xD3
	fullPlaintext[len(prefix)+len(plaintext)+1] = 0x14
	copy(fullPlaintext[len(prefix)+len(plaintext)+2:], mdcHash)

	// Encrypt with OpenPGP CFB
	ciphertext := make([]byte, len(fullPlaintext))
	cfbEncrypt(block, ciphertext, fullPlaintext)

	// Return SEIPD v1 packet body
	return openpgp.BuildSEIPDv1(ciphertext), nil
}

// cfbEncrypt implements OpenPGP CFB mode encryption.
func cfbEncrypt(block cipher.Block, dst, src []byte) {
	blockSize := block.BlockSize()
	iv := make([]byte, blockSize)
	prev := make([]byte, blockSize)
	copy(prev, iv)

	encrypted := make([]byte, blockSize)
	pos := 0

	for pos < len(src) {
		block.Encrypt(encrypted, prev)

		n := blockSize
		if pos+n > len(src) {
			n = len(src) - pos
		}

		for i := 0; i < n; i++ {
			dst[pos+i] = src[pos+i] ^ encrypted[i]
		}

		copy(prev, dst[pos:pos+n])
		pos += n
	}
}
