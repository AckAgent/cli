// Package openpgp implements OpenPGP packet parsing and construction
// according to RFC 4880 and RFC 6637 (for ECDSA/ECDH).
package openpgp

// Packet tags
const (
	PacketTagPKESK          = 1  // Public Key Encrypted Session Key
	PacketTagSignature      = 2  // Signature Packet
	PacketTagPublicKey      = 6  // Public Key Packet
	PacketTagCompressedData = 8  // Compressed Data Packet
	PacketTagLiteralData    = 11 // Literal Data Packet
	PacketTagUserID         = 13 // User ID Packet
	PacketTagSEIPD          = 18 // Sym. Encrypted Integrity Protected Data
	PacketTagAEAD           = 20 // AEAD Encrypted Data (LibrePGP)
)

// Signature versions
const (
	SigVersion4 = 4
)

// Signature types
const (
	SigTypeBinary                = 0x00 // Binary document signature
	SigTypePositiveCertification = 0x13 // Positive certification of User ID (self-signature)
	SigTypeSubkeyBinding         = 0x18 // Subkey binding signature
)

// Public key algorithms
const (
	PubKeyAlgoECDH  = 18
	PubKeyAlgoECDSA = 19
	PubKeyAlgoEdDSA = 22 // RFC 4880bis EdDSA
)

// Hash algorithms
const (
	HashAlgoSHA256 = 8
)

// Symmetric algorithms
const (
	SymAlgoAES128 = 7
	SymAlgoAES192 = 8
	SymAlgoAES256 = 9
)

// AEAD algorithms
const (
	AEADAlgoEAX = 1
	AEADAlgoOCB = 2
	AEADAlgoGCM = 3
)

// Subpacket types
const (
	SubpacketSignatureCreationTime = 2
	SubpacketKeyFlags              = 27
	SubpacketIssuer                = 16
	SubpacketIssuerFingerprint     = 33
)

// PKESK packet version
const (
	PKESKVersion3 = 3
)

// SEIPD packet versions
const (
	SEIPDVersion1 = 1
	SEIPDVersion2 = 2
)

// NIST P-256 OID: 1.2.840.10045.3.1.7
var OIDP256 = []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}

// Ed25519 OID: 1.3.6.1.4.1.11591.15.1
var OIDEd25519 = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}

// Curve25519 OID: 1.3.6.1.4.1.3029.1.5.1 (for ECDH)
var OIDCurve25519 = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}

// KeyBlockSize returns the block size for a symmetric algorithm.
func KeyBlockSize(algo byte) int {
	switch algo {
	case SymAlgoAES128, SymAlgoAES192, SymAlgoAES256:
		return 16 // AES block size is always 16 bytes
	default:
		return 0
	}
}

// KeySize returns the key size in bytes for a symmetric algorithm.
func KeySize(algo byte) int {
	switch algo {
	case SymAlgoAES128:
		return 16
	case SymAlgoAES192:
		return 24
	case SymAlgoAES256:
		return 32
	default:
		return 0
	}
}
