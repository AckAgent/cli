package crypto

import (
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/gpg/openpgp"
)

// ECDHCurve identifies which ECDH curve to use.
type ECDHCurve int

const (
	ECDHCurveP256       ECDHCurve = iota // NIST P-256
	ECDHCurveCurve25519                  // Curve25519 (X25519)
)

// ECDHParams holds parameters for ECDH key agreement.
type ECDHParams struct {
	HashAlgo  byte      // Hash algorithm for KDF (8 = SHA256)
	SymAlgo   byte      // Symmetric algorithm for key wrap (9 = AES256)
	PublicKey []byte    // Recipient's public key (33 bytes compressed P-256 or 32 bytes Curve25519)
	Curve     ECDHCurve // Which curve to use
}

// WrapSessionKey performs ECDH key agreement and AES key wrap for encryption.
// Returns the ephemeral public point and the wrapped session key.
//
// RFC 6637 Section 8:
// 1. Generate ephemeral key pair
// 2. Perform ECDH to get shared secret
// 3. Derive KEK using KDF: SHA256(03 || 01 || shared_secret || params)
// 4. AES key wrap the session key with the KEK
func WrapSessionKey(params *ECDHParams, sessionKey []byte, fingerprint []byte) (ephemeralPoint, wrappedKey []byte, err error) {
	switch params.Curve {
	case ECDHCurveCurve25519:
		return wrapSessionKeyCurve25519(params, sessionKey, fingerprint)
	default:
		return wrapSessionKeyP256(params, sessionKey, fingerprint)
	}
}

// wrapSessionKeyP256 performs P-256 ECDH key wrap.
func wrapSessionKeyP256(params *ECDHParams, sessionKey []byte, fingerprint []byte) (ephemeralPoint, wrappedKey []byte, err error) {
	if len(params.PublicKey) != crypto.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid public key length: %d (expected %d compressed)", len(params.PublicKey), crypto.PublicKeySize)
	}

	// Decompress the public key for ECDH (crypto/ecdh requires uncompressed format)
	uncompressedKey, err := crypto.DecompressPublicKey(params.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decompress public key: %w", err)
	}

	// Parse recipient's public key
	curve := ecdh.P256()
	recipientPub, err := curve.NewPublicKey(uncompressedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid recipient public key: %w", err)
	}

	// Generate ephemeral key pair
	ephemeralPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Perform ECDH
	sharedSecret, err := ephemeralPriv.ECDH(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive KEK using RFC 6637 KDF
	kek, err := deriveKEK(sharedSecret, params.HashAlgo, params.SymAlgo, fingerprint, openpgp.OIDP256)
	if err != nil {
		return nil, nil, fmt.Errorf("KDF failed: %w", err)
	}

	// AES key wrap
	wrapped, err := aesKeyWrap(kek, sessionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("key wrap failed: %w", err)
	}

	return ephemeralPriv.PublicKey().Bytes(), wrapped, nil
}

// wrapSessionKeyCurve25519 performs Curve25519 (X25519) ECDH key wrap.
// The recipient's public key is 32 bytes in native (little-endian) format.
// The ephemeral point is returned as 0x40 || reversed(ephemeralPub) for OpenPGP.
func wrapSessionKeyCurve25519(params *ECDHParams, sessionKey []byte, fingerprint []byte) (ephemeralPoint, wrappedKey []byte, err error) {
	if len(params.PublicKey) != 32 {
		return nil, nil, fmt.Errorf("invalid Curve25519 public key length: %d (expected 32)", len(params.PublicKey))
	}

	// Parse recipient's public key (already in native little-endian format)
	recipientPub, err := ecdh.X25519().NewPublicKey(params.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid recipient X25519 public key: %w", err)
	}

	// Generate ephemeral X25519 key pair
	ephemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral X25519 key: %w", err)
	}

	// Perform ECDH
	sharedSecret, err := ephemeralPriv.ECDH(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("X25519 ECDH failed: %w", err)
	}

	// OpenPGP Curve25519 shared secret needs to be reversed (big-endian)
	reversedSecret := reverseBytes(sharedSecret)

	// Derive KEK using RFC 6637 KDF with Curve25519 OID
	kek, err := deriveKEK(reversedSecret, params.HashAlgo, params.SymAlgo, fingerprint, openpgp.OIDCurve25519)
	if err != nil {
		return nil, nil, fmt.Errorf("KDF failed: %w", err)
	}

	// AES key wrap
	wrapped, err := aesKeyWrap(kek, sessionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("key wrap failed: %w", err)
	}

	// Build ephemeral point for OpenPGP: 0x40 || reversed(publicKey)
	ephPubBytes := ephemeralPriv.PublicKey().Bytes() // native little-endian
	ephemeralForOpenPGP := make([]byte, 1+len(ephPubBytes))
	ephemeralForOpenPGP[0] = 0x40
	copy(ephemeralForOpenPGP[1:], reverseBytes(ephPubBytes))

	return ephemeralForOpenPGP, wrapped, nil
}

// UnwrapSessionKey performs ECDH key agreement and AES key unwrap for decryption.
// This would be called on iOS with access to the private key.
// The CLI only calls this for testing; in production, iOS does the unwrapping.
func UnwrapSessionKey(params *ECDHParams, ephemeralPoint, wrappedKey []byte, privateKey *ecdh.PrivateKey, fingerprint []byte) ([]byte, error) {
	switch params.Curve {
	case ECDHCurveCurve25519:
		return unwrapSessionKeyCurve25519(params, ephemeralPoint, wrappedKey, privateKey, fingerprint)
	default:
		return unwrapSessionKeyP256(params, ephemeralPoint, wrappedKey, privateKey, fingerprint)
	}
}

// unwrapSessionKeyP256 performs P-256 ECDH key unwrap.
func unwrapSessionKeyP256(params *ECDHParams, ephemeralPoint, wrappedKey []byte, privateKey *ecdh.PrivateKey, fingerprint []byte) ([]byte, error) {
	// Parse ephemeral public key
	curve := ecdh.P256()
	ephemeralPub, err := curve.NewPublicKey(ephemeralPoint)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// Perform ECDH
	sharedSecret, err := privateKey.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive KEK using RFC 6637 KDF
	kek, err := deriveKEK(sharedSecret, params.HashAlgo, params.SymAlgo, fingerprint, openpgp.OIDP256)
	if err != nil {
		return nil, fmt.Errorf("KDF failed: %w", err)
	}

	// AES key unwrap
	sessionKey, err := aesKeyUnwrap(kek, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("key unwrap failed: %w", err)
	}

	return sessionKey, nil
}

// unwrapSessionKeyCurve25519 performs X25519 ECDH key unwrap.
// The ephemeral point is 0x40 || reversed(publicKey) from OpenPGP.
func unwrapSessionKeyCurve25519(params *ECDHParams, ephemeralPoint, wrappedKey []byte, privateKey *ecdh.PrivateKey, fingerprint []byte) ([]byte, error) {
	if len(ephemeralPoint) != 33 || ephemeralPoint[0] != 0x40 {
		return nil, fmt.Errorf("invalid Curve25519 ephemeral point: expected 33 bytes with 0x40 prefix, got %d bytes", len(ephemeralPoint))
	}

	// Strip 0x40 prefix and reverse to get native little-endian
	nativeEphemeral := reverseBytes(ephemeralPoint[1:])

	ephemeralPub, err := ecdh.X25519().NewPublicKey(nativeEphemeral)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral X25519 public key: %w", err)
	}

	// Perform ECDH
	sharedSecret, err := privateKey.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("X25519 ECDH failed: %w", err)
	}

	// Reverse shared secret for OpenPGP KDF
	reversedSecret := reverseBytes(sharedSecret)

	// Derive KEK using RFC 6637 KDF with Curve25519 OID
	kek, err := deriveKEK(reversedSecret, params.HashAlgo, params.SymAlgo, fingerprint, openpgp.OIDCurve25519)
	if err != nil {
		return nil, fmt.Errorf("KDF failed: %w", err)
	}

	// AES key unwrap
	sessionKey, err := aesKeyUnwrap(kek, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("key unwrap failed: %w", err)
	}

	return sessionKey, nil
}

// reverseBytes returns a new slice with bytes in reverse order.
func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i, v := range b {
		result[len(b)-1-i] = v
	}
	return result
}

// deriveKEK derives a Key Encryption Key using RFC 6637 KDF.
// RFC 6637 Section 8:
//
//	Param = OID_len || OID || public_key_algo_ID ||
//	        03 || 01 || KDF_hash_ID || KEK_algo_ID ||
//	        "Anonymous Sender    " || recipient_fingerprint
//	MB = Hash(00 || 00 || 00 || 01 || ZZ || Param)
//	KEK = MB[0..n]
func deriveKEK(sharedSecret []byte, hashAlgo, symAlgo byte, fingerprint, oid []byte) ([]byte, error) {
	if hashAlgo != openpgp.HashAlgoSHA256 {
		return nil, fmt.Errorf("unsupported hash algorithm: %d", hashAlgo)
	}

	// Build Param per RFC 6637 Section 8
	// Param = OID_len || OID || public_key_algo || 03 01 hash sym || "Anonymous Sender    " || fingerprint
	param := make([]byte, 0, 1+len(oid)+1+4+20+len(fingerprint))
	param = append(param, byte(len(oid)))         // OID length
	param = append(param, oid...)                 // Curve OID
	param = append(param, openpgp.PubKeyAlgoECDH) // Public key algorithm (18)
	param = append(param, 0x03, 0x01, hashAlgo, symAlgo)
	param = append(param, []byte("Anonymous Sender    ")...) // 20-byte UTF-8 string
	param = append(param, fingerprint...)

	// MB = SHA256(00 00 00 01 || ZZ || Param)
	h := sha256.New()
	h.Write([]byte{0x00, 0x00, 0x00, 0x01}) // Counter (per NIST SP 800-56A)
	h.Write(sharedSecret)
	h.Write(param)

	kek := h.Sum(nil)

	// Truncate to key size for symmetric algorithm
	keySize := openpgp.KeySize(symAlgo)
	if keySize == 0 {
		return nil, fmt.Errorf("unsupported symmetric algorithm: %d", symAlgo)
	}
	if len(kek) < keySize {
		return nil, errors.New("derived key too short")
	}

	return kek[:keySize], nil
}

// aesKeyWrap implements RFC 3394 AES Key Wrap.
func aesKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 {
		return nil, errors.New("plaintext must be multiple of 8 bytes")
	}

	n := len(plaintext) / 8
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	// Initialize: A = IV, R[1..n] = plaintext
	a := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:(i+1)*8])
	}

	// Wrap: 6 rounds
	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[i])
			block.Encrypt(buf, buf)

			t := uint64(n*j + i + 1)
			for k := 0; k < 8; k++ {
				buf[7-k] ^= byte(t >> (8 * k))
			}

			copy(a, buf[:8])
			copy(r[i], buf[8:])
		}
	}

	// Output: A || R[1] || ... || R[n]
	ciphertext := make([]byte, 8+len(plaintext))
	copy(ciphertext[:8], a)
	for i := 0; i < n; i++ {
		copy(ciphertext[8+i*8:], r[i])
	}

	return ciphertext, nil
}

// aesKeyUnwrap implements RFC 3394 AES Key Unwrap.
func aesKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, errors.New("invalid ciphertext length")
	}

	n := (len(ciphertext) - 8) / 8
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	// Initialize: A = C[0], R[1..n] = C[1..n]
	a := make([]byte, 8)
	copy(a, ciphertext[:8])
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[8+i*8:8+(i+1)*8])
	}

	// Unwrap: 6 rounds in reverse
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			for k := 0; k < 8; k++ {
				a[7-k] ^= byte(t >> (8 * k))
			}

			copy(buf[:8], a)
			copy(buf[8:], r[i])
			block.Decrypt(buf, buf)

			copy(a, buf[:8])
			copy(r[i], buf[8:])
		}
	}

	// Verify IV
	expectedIV := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	for i := 0; i < 8; i++ {
		if a[i] != expectedIV[i] {
			return nil, errors.New("key unwrap failed: IV mismatch")
		}
	}

	// Output: R[1] || ... || R[n]
	plaintext := make([]byte, n*8)
	for i := 0; i < n; i++ {
		copy(plaintext[i*8:], r[i])
	}

	return plaintext, nil
}

// GenerateSessionKey generates a random session key for symmetric encryption.
func GenerateSessionKey(symAlgo byte) ([]byte, error) {
	keySize := openpgp.KeySize(symAlgo)
	if keySize == 0 {
		return nil, fmt.Errorf("unsupported symmetric algorithm: %d", symAlgo)
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	return key, nil
}

// BuildSessionKeyWithChecksum prepends algorithm byte and appends checksum for PKESK.
// RFC 4880: The session key is preceded by a one-octet algorithm identifier
// and followed by a two-octet checksum (sum of all session key octets, mod 65536).
// RFC 6637: For ECDH, the result is then padded with PKCS5 to a multiple of 8 bytes.
func BuildSessionKeyWithChecksum(symAlgo byte, sessionKey []byte) []byte {
	// Build: algo || session_key || checksum
	baseLen := 1 + len(sessionKey) + 2
	result := make([]byte, baseLen)
	result[0] = symAlgo
	copy(result[1:], sessionKey)

	// Compute checksum
	var checksum uint16
	for _, b := range sessionKey {
		checksum += uint16(b)
	}
	result[baseLen-2] = byte(checksum >> 8)
	result[baseLen-1] = byte(checksum)

	// RFC 6637: Apply PKCS5 padding to make length a multiple of 8
	padLen := 8 - (baseLen % 8)
	if padLen == 0 {
		padLen = 8 // Always add at least one block of padding
	}
	padded := make([]byte, baseLen+padLen)
	copy(padded, result)
	for i := 0; i < padLen; i++ {
		padded[baseLen+i] = byte(padLen)
	}

	return padded
}

// ParseSessionKeyWithChecksum extracts algorithm and session key from PKESK payload.
// Returns the algorithm byte and the session key (without checksum).
// RFC 6637: The data includes PKCS5 padding that must be removed first.
func ParseSessionKeyWithChecksum(data []byte) (byte, []byte, error) {
	if len(data) < 4 {
		return 0, nil, errors.New("session key data too short")
	}

	// RFC 6637: Remove PKCS5 padding first
	padLen := int(data[len(data)-1])
	if padLen < 1 || padLen > 8 {
		return 0, nil, fmt.Errorf("invalid PKCS5 padding: %d", padLen)
	}
	if padLen > len(data) {
		return 0, nil, errors.New("PKCS5 padding larger than data")
	}
	// Verify padding bytes
	for i := 0; i < padLen; i++ {
		if data[len(data)-1-i] != byte(padLen) {
			return 0, nil, errors.New("invalid PKCS5 padding bytes")
		}
	}
	// Remove padding
	data = data[:len(data)-padLen]

	if len(data) < 4 {
		return 0, nil, errors.New("session key data too short after removing padding")
	}

	algo := data[0]
	sessionKey := data[1 : len(data)-2]
	checksumBytes := data[len(data)-2:]

	// Verify checksum
	var checksum uint16
	for _, b := range sessionKey {
		checksum += uint16(b)
	}

	expectedChecksum := uint16(checksumBytes[0])<<8 | uint16(checksumBytes[1])
	if checksum != expectedChecksum {
		return 0, nil, errors.New("session key checksum mismatch")
	}

	return algo, sessionKey, nil
}
