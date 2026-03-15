package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ackagent/cli/internal/gpg/openpgp"
)

func generateGPGVectors(privateKey *ecdsa.PrivateKey, keyCreationTime, sigTimestamp time.Time) GPGVectors {
	pubKeyX := padTo32(privateKey.X.Bytes())
	pubKeyY := padTo32(privateKey.Y.Bytes())
	pubKeyBytes := append(pubKeyX, pubKeyY...)

	fingerprint := openpgp.V4Fingerprint(pubKeyBytes, keyCreationTime)
	keyID := openpgp.KeyIDFromFingerprint(fingerprint)

	pubKeyPacketBody := buildECDSAPublicKeyBody(pubKeyBytes, keyCreationTime)
	pubKeyPacket := openpgp.BuildPublicKeyPacket(pubKeyBytes, keyCreationTime)

	userID := "AckAgent Test Key <test@ackagent.com>"
	userIDPacket := openpgp.BuildUserIDPacket(userID)

	selfSigPacket := buildSelfSignature(privateKey, pubKeyPacket, userIDPacket, keyCreationTime, fingerprint, keyID)

	fullPubKeyBlock := make([]byte, 0, len(pubKeyPacket)+len(userIDPacket)+len(selfSigPacket))
	fullPubKeyBlock = append(fullPubKeyBlock, pubKeyPacket...)
	fullPubKeyBlock = append(fullPubKeyBlock, userIDPacket...)
	fullPubKeyBlock = append(fullPubKeyBlock, selfSigPacket...)

	message := []byte("Hello, AckAgent!")
	messageHex := hex.EncodeToString(message)

	sb := openpgp.NewSignatureBuilder().
		SetSignatureType(openpgp.SigTypeBinary).
		SetCreationTime(sigTimestamp).
		SetIssuerKeyID(keyID).
		SetIssuerFingerprint(fingerprint)

	digest, header := sb.BuildHashInput(message)

	hashedSubpackets := buildHashedSubpackets(sigTimestamp, fingerprint)
	unhashedSubpackets := buildUnhashedSubpackets(keyID)

	headerLen := len(header) + len(hashedSubpackets)
	trailer := []byte{
		0x04,
		0xFF,
		byte(headerLen >> 24),
		byte(headerLen >> 16),
		byte(headerLen >> 8),
		byte(headerLen),
	}

	hashInput := make([]byte, 0, len(message)+len(header)+len(hashedSubpackets)+len(trailer))
	hashInput = append(hashInput, message...)
	hashInput = append(hashInput, header...)
	hashInput = append(hashInput, hashedSubpackets...)
	hashInput = append(hashInput, trailer...)

	r, s := signDeterministic(privateKey, digest)

	rBytes := padTo32(r.Bytes())
	sBytes := padTo32(s.Bytes())
	rawSig := append(rBytes, sBytes...)

	sigPacket, _ := sb.FinalizeSignature(header, digest, rawSig)

	sigPacketBody := buildSignaturePacketBody(header, hashedSubpackets, unhashedSubpackets, digest, rBytes, sBytes)

	crc := openpgp.CRC24(sigPacket)
	crc24Hex := fmt.Sprintf("%06x", crc)

	armored := openpgp.ArmorSig(sigPacket)

	return GPGVectors{
		Description: "OpenPGP V4 ECDSA P-256 signature test vectors (RFC 4880, RFC 6637)",
		KeyMaterial: GPGKeyMaterial{
			Description:           "P-256 ECDSA key pair (deterministic for testing only)",
			PrivateKeyDHex:        hex.EncodeToString(privateKey.D.Bytes()),
			PublicKeyXHex:         hex.EncodeToString(pubKeyX),
			PublicKeyYHex:         hex.EncodeToString(pubKeyY),
			PublicKeyUncompressed: hex.EncodeToString(pubKeyBytes),
			CreationTimestamp:     keyCreationTime.Unix(),
			FingerprintHex:        hex.EncodeToString(fingerprint),
			KeyIDHex:              fmt.Sprintf("%016x", keyID),
		},
		PublicKeyPacket: GPGPublicKeyPacket{
			Description:      "Complete public key block for gpg --import (pubkey + userid + self-sig)",
			PacketBodyHex:    hex.EncodeToString(pubKeyPacketBody),
			PacketHex:        hex.EncodeToString(pubKeyPacket),
			UserID:           userID,
			UserIDPacketHex:  hex.EncodeToString(userIDPacket),
			SelfSigPacketHex: hex.EncodeToString(selfSigPacket),
			FullPublicKeyHex: hex.EncodeToString(fullPubKeyBlock),
			Armored:          openpgp.Armor(openpgp.ArmorPublicKey, fullPubKeyBlock),
		},
		SignatureCases: []GPGSignatureCase{
			{
				Description:       "Simple binary message signing",
				MessageHex:        messageHex,
				MessageText:       string(message),
				SignatureTimestamp: sigTimestamp.Unix(),
				Layers: GPGSignatureLayers{
					SignatureHeaderHex:     hex.EncodeToString(header),
					HashedSubpacketsHex:    hex.EncodeToString(hashedSubpackets),
					UnhashedSubpacketsHex:  hex.EncodeToString(unhashedSubpackets),
					TrailerHex:             hex.EncodeToString(trailer),
					HashInputHex:           hex.EncodeToString(hashInput),
					DigestHex:              hex.EncodeToString(digest),
					SignatureRHex:          hex.EncodeToString(rBytes),
					SignatureSHex:          hex.EncodeToString(sBytes),
					MPIRHex:                hex.EncodeToString(openpgp.EncodeMPIFromBytes(rBytes)),
					MPISHex:                hex.EncodeToString(openpgp.EncodeMPIFromBytes(sBytes)),
					SignaturePacketBodyHex: hex.EncodeToString(sigPacketBody),
					SignaturePacketHex:     hex.EncodeToString(sigPacket),
					CRC24Hex:               crc24Hex,
					Armored:                armored,
				},
			},
		},
		ComponentVectors: generateComponentVectors(),
	}
}

func generateComponentVectors() GPGComponentVectors {
	return GPGComponentVectors{
		MPI: []MPIVector{
			{
				Description: "Single byte (0x01)",
				InputHex:    "01",
				OutputHex:   hex.EncodeToString(openpgp.EncodeMPIFromBytes([]byte{0x01})),
			},
			{
				Description: "256 (0x0100)",
				InputHex:    "0100",
				OutputHex:   hex.EncodeToString(openpgp.EncodeMPIFromBytes([]byte{0x01, 0x00})),
			},
			{
				Description: "Leading zeros stripped (0x00007f)",
				InputHex:    "00007f",
				OutputHex:   hex.EncodeToString(openpgp.EncodeMPIFromBytes([]byte{0x00, 0x00, 0x7f})),
			},
			{
				Description: "32 bytes of 0xff",
				InputHex:    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				OutputHex:   hex.EncodeToString(openpgp.EncodeMPIFromBytes(mustDecodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))),
			},
		},
		CRC24: []CRC24Vector{
			{
				Description: "Empty input",
				InputHex:    "",
				CRC24Hex:    fmt.Sprintf("%06x", openpgp.CRC24([]byte{})),
			},
			{
				Description: "Hello, World!",
				InputHex:    hex.EncodeToString([]byte("Hello, World!")),
				CRC24Hex:    fmt.Sprintf("%06x", openpgp.CRC24([]byte("Hello, World!"))),
			},
			{
				Description: "Test data",
				InputHex:    hex.EncodeToString([]byte("test")),
				CRC24Hex:    fmt.Sprintf("%06x", openpgp.CRC24([]byte("test"))),
			},
		},
		Subpackets: []SubpacketVector{
			{
				Description: "Creation time (1700000000)",
				Type:        "creation_time",
				ValueHex:    "6553f100",
				EncodedHex:  hex.EncodeToString(buildCreationTimeSubpacket(time.Unix(1700000000, 0))),
			},
		},
	}
}

func buildECDSAPublicKeyBody(publicKey []byte, creationTime time.Time) []byte {
	result := make([]byte, 0, 128)

	result = append(result, 4)

	ts := uint32(creationTime.Unix())
	result = append(result, byte(ts>>24), byte(ts>>16), byte(ts>>8), byte(ts))

	result = append(result, 19)

	oid := []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	result = append(result, byte(len(oid)))
	result = append(result, oid...)

	point := append([]byte{0x04}, publicKey...)
	result = append(result, openpgp.EncodeMPIFromBytes(point)...)

	return result
}

func buildHashedSubpackets(sigTime time.Time, fingerprint []byte) []byte {
	sb := openpgp.NewSubpacketBuilder()
	sb.AddCreationTime(sigTime)
	sb.AddIssuerFingerprint(fingerprint)
	return sb.Bytes()
}

func buildUnhashedSubpackets(keyID uint64) []byte {
	sb := openpgp.NewSubpacketBuilder()
	sb.AddIssuer(keyID)
	return sb.Bytes()
}

func buildSignaturePacketBody(header, hashedSub, unhashedSub, digest, r, s []byte) []byte {
	result := make([]byte, 0, 256)
	result = append(result, header...)
	result = append(result, hashedSub...)

	result = append(result, byte(len(unhashedSub)>>8), byte(len(unhashedSub)))
	result = append(result, unhashedSub...)

	result = append(result, digest[0], digest[1])

	result = append(result, openpgp.EncodeMPIFromBytes(r)...)
	result = append(result, openpgp.EncodeMPIFromBytes(s)...)

	return result
}

func buildCreationTimeSubpacket(t time.Time) []byte {
	ts := uint32(t.Unix())
	return []byte{
		5,
		2,
		byte(ts >> 24),
		byte(ts >> 16),
		byte(ts >> 8),
		byte(ts),
	}
}

func buildSelfSignature(privateKey *ecdsa.PrivateKey, pubKeyPacket, userIDPacket []byte, creationTime time.Time, fingerprint []byte, keyID uint64) []byte {
	sigType := byte(0x13)

	hashedSub := openpgp.NewSubpacketBuilder()
	hashedSub.AddCreationTime(creationTime)
	hashedSub.AddIssuerFingerprint(fingerprint)
	hashedSubData := hashedSub.Bytes()

	unhashedSub := openpgp.NewSubpacketBuilder()
	unhashedSub.AddIssuer(keyID)
	unhashedSubData := unhashedSub.Bytes()

	header := []byte{
		0x04,
		sigType,
		0x13,
		0x08,
		byte(len(hashedSubData) >> 8),
		byte(len(hashedSubData)),
	}

	headerLen := len(header) + len(hashedSubData)
	trailer := []byte{
		0x04,
		0xFF,
		byte(headerLen >> 24),
		byte(headerLen >> 16),
		byte(headerLen >> 8),
		byte(headerLen),
	}

	h := sha256.New()

	pubKeyBody := pubKeyPacket[2:]
	h.Write([]byte{0x99})
	h.Write([]byte{byte(len(pubKeyBody) >> 8), byte(len(pubKeyBody))})
	h.Write(pubKeyBody)

	userIDBody := userIDPacket[2:]
	h.Write([]byte{0xB4})
	h.Write([]byte{0, 0, byte(len(userIDBody) >> 8), byte(len(userIDBody))})
	h.Write(userIDBody)

	h.Write(header)
	h.Write(hashedSubData)
	h.Write(trailer)

	digest := h.Sum(nil)

	r, s := signDeterministic(privateKey, digest)
	rBytes := padTo32(r.Bytes())
	sBytes := padTo32(s.Bytes())

	sigBody := make([]byte, 0, 256)
	sigBody = append(sigBody, header...)
	sigBody = append(sigBody, hashedSubData...)
	sigBody = append(sigBody, byte(len(unhashedSubData)>>8), byte(len(unhashedSubData)))
	sigBody = append(sigBody, unhashedSubData...)
	sigBody = append(sigBody, digest[0], digest[1])
	sigBody = append(sigBody, openpgp.EncodeMPIFromBytes(rBytes)...)
	sigBody = append(sigBody, openpgp.EncodeMPIFromBytes(sBytes)...)

	return openpgp.BuildPacket(openpgp.PacketTagSignature, sigBody)
}
