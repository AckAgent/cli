package commands

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ackagent/cli/internal/gpg/cli"
	gpgcrypto "github.com/ackagent/cli/internal/gpg/crypto"
	"github.com/ackagent/cli/internal/gpg/openpgp"
	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/config"
)

// Decrypt decrypts an OpenPGP-encrypted message.
// iOS handles session key unwrapping via ECDH, CLI handles bulk decryption.
func Decrypt(cfg *config.Config, args *cli.Args) {
	if !cfg.IsLoggedIn() {
		fmt.Fprintf(os.Stderr, "ackagent gpg: not logged in\n")
		fmt.Fprintf(os.Stderr, "Run 'ackagent login' to login first.\n")
		os.Exit(1)
	}

	// Read input data (encrypted message)
	var data []byte
	var err error
	if args.InputFile != "" && args.InputFile != "-" {
		data, err = os.ReadFile(args.InputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: %v\n", err)
			os.Exit(1)
		}
	} else {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: %v\n", err)
			os.Exit(1)
		}
	}

	// Dearmor if ASCII-armored
	binaryData, armorType, err := openpgp.Dearmor(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: failed to dearmor: %v\n", err)
		os.Exit(1)
	}

	if armorType != "" && armorType != openpgp.ArmorMessage {
		fmt.Fprintf(os.Stderr, "ackagent gpg: expected PGP MESSAGE, got %s\n", armorType)
		os.Exit(1)
	}

	// Parse the encrypted message
	msg, err := openpgp.ParseEncryptedMessage(binaryData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: failed to parse message: %v\n", err)
		os.Exit(1)
	}

	// Collect fingerprints from enrolled GPG keys
	// We check both primary fingerprints and encryption subkey fingerprints
	keys := cfg.KeysForPurpose(config.KeyPurposeGPG)
	if len(keys) == 0 {
		fmt.Fprintf(os.Stderr, "ackagent gpg: no keys enrolled\n")
		fmt.Fprintf(os.Stderr, "Enroll a key using the AckAgent iOS app first.\n")
		os.Exit(1)
	}

	// Build list of all fingerprints to try (primary + encryption subkeys)
	// Maps fingerprint hex to key index for reverse lookup
	type fpEntry struct {
		fingerprint []byte
		keyIndex    int
		isSubkey    bool
	}
	var fingerprintEntries []fpEntry

	for i, key := range keys {
		// Add primary fingerprint (computed from public key and creation timestamp)
		gpgFP := GPGFingerprint(&key)
		fp := openpgp.ParseFingerprint(gpgFP)
		if fp != nil {
			fingerprintEntries = append(fingerprintEntries, fpEntry{fp, i, false})
		}
		// Add encryption subkey fingerprint if present
		if key.HasEncryptionSubkey() {
			encFp := openpgp.ParseFingerprint(key.EncryptionFingerprint)
			if encFp != nil {
				fingerprintEntries = append(fingerprintEntries, fpEntry{encFp, i, true})
			}
		}
	}

	// Extract just fingerprints for matching
	var fingerprints [][]byte
	for _, entry := range fingerprintEntries {
		fingerprints = append(fingerprints, entry.fingerprint)
	}

	// Find matching PKESK packet
	matchingPKESK, matchedFingerprint := msg.FindMatchingPKESK(fingerprints)
	if matchingPKESK == nil {
		// List the key IDs we tried
		fmt.Fprintf(os.Stderr, "ackagent gpg: no matching key found for this message\n")
		fmt.Fprintf(os.Stderr, "Message was encrypted for key ID(s):\n")
		for _, pkesk := range msg.PKESKPackets {
			if pkesk.IsWildcardKeyID() {
				fmt.Fprintf(os.Stderr, "  - [anonymous recipient]\n")
			} else {
				fmt.Fprintf(os.Stderr, "  - %s\n", pkesk.KeyIDString())
			}
		}
		fmt.Fprintf(os.Stderr, "Your enrolled keys:\n")
		for _, key := range keys {
			fp := strings.ToUpper(GPGFingerprint(&key))
			if len(fp) >= 16 {
				keyIDSuffix := fp[len(fp)-16:]
				if key.HasEncryptionSubkey() {
					encFp := strings.ToUpper(key.EncryptionFingerprint)
					if len(encFp) >= 16 {
						fmt.Fprintf(os.Stderr, "  - %s (enc subkey: %s) (%s)\n", keyIDSuffix, encFp[len(encFp)-16:], key.Label)
					}
				} else {
					fmt.Fprintf(os.Stderr, "  - %s (%s)\n", keyIDSuffix, key.Label)
				}
			}
		}
		os.Exit(1)
	}

	// Find the config key that matches the fingerprint
	var matchedKey *config.KeyMetadata
	var matchedIsSubkey bool
	for _, entry := range fingerprintEntries {
		if bytes.Equal(entry.fingerprint, matchedFingerprint) {
			matchedKey = &keys[entry.keyIndex]
			matchedIsSubkey = entry.isSubkey
			break
		}
	}

	if matchedKey == nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: internal error: matched fingerprint but no key found\n")
		os.Exit(1)
	}

	// Prepare PKESK data for iOS
	pkeskData := &protocol.PkeskData{
		Version:        int32(matchingPKESK.Version),
		KeyId:          matchingPKESK.KeyID,
		Algorithm:      int32(matchingPKESK.Algorithm),
		EphemeralPoint: matchingPKESK.EphemeralPoint,
		WrappedKey:     matchingPKESK.WrappedKey,
	}

	// Build decrypt context for iOS UI
	decryptCtx := &GPGDecryptContext{
		MessageSize: len(binaryData),
		IsAnonymous: matchingPKESK.IsWildcardKeyID(),
		EncryptedTo: matchedKey.Label,
	}

	// Send request to iOS for session key unwrapping
	if args.Verbose {
		fmt.Fprintf(os.Stderr, "ackagent gpg: requesting session key from iOS...\n")
		if matchedIsSubkey {
			fmt.Fprintf(os.Stderr, "  Matched encryption subkey: %s\n", matchedKey.EncryptionFingerprint)
		} else {
			fmt.Fprintf(os.Stderr, "  Matched primary key: %s\n", GPGFingerprint(matchedKey))
		}
	}

	response, err := RequestGPGDecrypt(cfg, matchedKey, pkeskData, decryptCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: decryption failed: %v\n", err)
		os.Exit(1)
	}

	// Now decrypt the SEIPD packet locally using the session key
	sessionKey := response.GetSessionKey()
	symAlgo := response.GetAlgorithm()

	if args.Verbose {
		fmt.Fprintf(os.Stderr, "ackagent gpg: received session key, decrypting locally...\n")
	}

	var plaintext []byte
	seipd := msg.SEIPDPacket

	switch seipd.Version {
	case openpgp.SEIPDVersion1:
		// Version 1: The cipher algorithm is encoded in the session key from iOS
		// But for v1 SEIPD, we need to know the cipher algorithm.
		// The session key format is: algo (1 byte) || key || checksum (2 bytes)
		// However, iOS returns just the session key after unwrapping.
		// We'll assume AES-256 for now (most common) or use the algorithm from response
		cipherAlgo := symAlgo
		if cipherAlgo == 0 {
			// Default to AES-256 if not specified
			cipherAlgo = openpgp.SymAlgoAES256
		}

		plaintext, err = gpgcrypto.DecryptSEIPDv1(sessionKey, seipd.Ciphertext, cipherAlgo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: decryption failed: %v\n", err)
			os.Exit(1)
		}

	case openpgp.SEIPDVersion2:
		// Version 2: AEAD mode with cipher/AEAD info in the packet
		plaintext, err = gpgcrypto.DecryptSEIPDv2(
			sessionKey,
			seipd.AEADAlgo,
			seipd.ChunkSizeByte,
			seipd.Salt,
			seipd.Ciphertext,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: decryption failed: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "ackagent gpg: unsupported SEIPD version: %d\n", seipd.Version)
		os.Exit(1)
	}

	// The plaintext should contain a literal data packet
	literalData, err := extractLiteralData(plaintext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: %v\n", err)
		os.Exit(1)
	}

	// Write output
	var output io.Writer = os.Stdout
	if args.OutputFile != "" && args.OutputFile != "-" {
		f, err := os.Create(args.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		output = f
	}

	_, err = output.Write(literalData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: failed to write output: %v\n", err)
		os.Exit(1)
	}
}

// extractLiteralData extracts the actual data from a literal data packet.
// The decrypted SEIPD contains one or more OpenPGP packets, typically
// a literal data packet (tag 11) optionally preceded by a compressed data packet.
func extractLiteralData(data []byte) ([]byte, error) {
	packets, err := openpgp.ParseAllPackets(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted packets: %w", err)
	}

	if len(packets) == 0 {
		return nil, fmt.Errorf("no packets found in decrypted data")
	}

	// Look for literal data packet
	for _, pkt := range packets {
		switch pkt.Tag {
		case openpgp.PacketTagLiteralData:
			return parseLiteralData(pkt.Body)
		case openpgp.PacketTagCompressedData:
			// Decompress and recursively extract literal data from the result
			compressed, err := openpgp.ParseCompressed(pkt.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to parse compressed data: %w", err)
			}
			decompressed, err := compressed.Decompress()
			if err != nil {
				return nil, fmt.Errorf("decompression failed (%s): %w", compressed.AlgorithmName(), err)
			}
			// Recursively extract literal data from decompressed content
			return extractLiteralData(decompressed)
		}
	}

	// If no literal data packet found, return the raw data
	// (some implementations might not use literal data packets)
	return data, nil
}

// parseLiteralData parses a literal data packet body.
// RFC 4880 section 5.9
// Format: format (1 byte) || filename_len (1 byte) || filename || date (4 bytes) || data
func parseLiteralData(body []byte) ([]byte, error) {
	if len(body) < 6 {
		return nil, fmt.Errorf("literal data packet too short")
	}

	// Skip format byte
	pos := 1

	// Skip filename
	filenameLen := int(body[pos])
	pos++
	if len(body) < pos+filenameLen+4 {
		return nil, fmt.Errorf("literal data packet truncated")
	}
	pos += filenameLen

	// Skip date (4 bytes)
	pos += 4

	// Rest is the actual data
	return body[pos:], nil
}
