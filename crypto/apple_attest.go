// Package crypto provides cryptographic operations for the CLI.
// This file contains Apple App Attest attestation verification for key enrollment during device sync.
package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// =============================================================================
// Apple App Attestation Root CA
// =============================================================================

// Apple App Attestation Root CA
// Downloaded from: https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
const appleAppAttestRootCA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`

var (
	// Parsed Apple Root CA
	appleRootCertPool *x509.CertPool
	appleRootCert     *x509.Certificate

	// AAGUIDs
	productionAAGUID = append([]byte("appattest"), make([]byte, 7)...)
	sandboxAAGUID    = []byte("appattestsandbox")
)

var (
	ErrInvalidAttestation = errors.New("invalid attestation")
	ErrUntrustedRoot      = errors.New("certificate not rooted in Apple")
	ErrAAGUIDMismatch     = errors.New("AAGUID environment mismatch")
	ErrKeyBindingInvalid  = errors.New("key binding verification failed")
)

func init() {
	appleRootCertPool = x509.NewCertPool()
	if !appleRootCertPool.AppendCertsFromPEM([]byte(appleAppAttestRootCA)) {
		panic("failed to parse Apple App Attestation Root CA")
	}

	block, _ := pem.Decode([]byte(appleAppAttestRootCA))
	if block == nil {
		panic("failed to decode Apple App Attestation Root CA PEM")
	}

	var err error
	appleRootCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("failed to parse Apple App Attestation Root CA: %v", err))
	}
}

// AttestationEnvironment represents the expected environment.
type AttestationEnvironment string

const (
	EnvProduction  AttestationEnvironment = "production"
	EnvSandbox     AttestationEnvironment = "sandbox"
	EnvDevelopment AttestationEnvironment = "development"
)

// AttestationVerifier verifies Apple App Attest attestations for key enrollment.
type AttestationVerifier struct {
	environment AttestationEnvironment
}

// NewAttestationVerifier creates a new verifier for the given environment.
func NewAttestationVerifier(env AttestationEnvironment) *AttestationVerifier {
	return &AttestationVerifier{environment: env}
}

// AttestationResult contains the result of key attestation verification.
type AttestationResult struct {
	Valid           bool
	ChainValid      bool
	AAGUIDValid     bool
	KeyBindingValid bool
	Environment     AttestationEnvironment
	VerifiedAt      time.Time
	Errors          []string
}

// attestationObject is the CBOR structure from Apple.
type attestationObject struct {
	AuthData []byte `cbor:"authData"`
	Fmt      string `cbor:"fmt"`
	AttStmt  struct {
		X5c     [][]byte `cbor:"x5c"`
		Receipt []byte   `cbor:"receipt"`
	} `cbor:"attStmt"`
}

// Verify verifies key attestation data from the backend during device sync.
func (v *AttestationVerifier) Verify(
	signingPublicKey []byte,
	attestationType string,
	attestationObj []byte,
	keyBindingAssertion []byte,
	keyBindingChallenge []byte,
) (*AttestationResult, error) {
	result := &AttestationResult{
		Environment: v.environment,
		VerifiedAt:  time.Now(),
	}

	if attestationType != "ios_secure_enclave" {
		// Software fallback - no attestation to verify
		result.Valid = true
		return result, nil
	}

	if len(attestationObj) == 0 {
		result.Errors = append(result.Errors, "missing attestation object")
		return result, ErrInvalidAttestation
	}

	// Verify certificate chain
	chainErr := v.verifyCertificateChain(attestationObj)
	if chainErr != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("chain: %v", chainErr))
	} else {
		result.ChainValid = true
	}

	// Verify AAGUID
	aaguidErr := v.verifyAAGUID(attestationObj)
	if aaguidErr != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("aaguid: %v", aaguidErr))
	} else {
		result.AAGUIDValid = true
	}

	// Verify key binding if we have assertion data
	if len(keyBindingAssertion) > 0 && len(keyBindingChallenge) > 0 {
		bindingErr := v.verifyKeyBinding(signingPublicKey, keyBindingAssertion, keyBindingChallenge, attestationObj)
		if bindingErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("key binding: %v", bindingErr))
		} else {
			result.KeyBindingValid = true
		}
	}

	result.Valid = result.ChainValid && result.AAGUIDValid && result.KeyBindingValid
	if !result.Valid && len(result.Errors) == 0 {
		result.Errors = append(result.Errors, "verification failed")
	}

	return result, nil
}

// verifyCertificateChain verifies the x5c chain against Apple's root CA.
func (v *AttestationVerifier) verifyCertificateChain(attestationObj []byte) error {
	var attObj attestationObject
	if err := cbor.Unmarshal(attestationObj, &attObj); err != nil {
		return fmt.Errorf("failed to parse attestation: %w", err)
	}

	x5c := attObj.AttStmt.X5c
	if len(x5c) == 0 {
		return fmt.Errorf("missing certificate chain")
	}

	// Parse leaf certificate
	leafCert, err := x509.ParseCertificate(x5c[0])
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Build intermediate pool
	intermediates := x509.NewCertPool()
	for i := 1; i < len(x5c); i++ {
		cert, err := x509.ParseCertificate(x5c[i])
		if err != nil {
			return fmt.Errorf("failed to parse intermediate certificate: %w", err)
		}
		intermediates.AddCert(cert)
	}

	// Attestation is a point-in-time proof - validate against issuance time.
	opts := x509.VerifyOptions{
		Roots:         appleRootCertPool,
		Intermediates: intermediates,
		CurrentTime:   leafCert.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := leafCert.Verify(opts); err != nil {
		return fmt.Errorf("%w: %v", ErrUntrustedRoot, err)
	}

	return nil
}

// verifyAAGUID checks that the AAGUID matches the expected environment.
func (v *AttestationVerifier) verifyAAGUID(attestationObj []byte) error {
	var attObj attestationObject
	if err := cbor.Unmarshal(attestationObj, &attObj); err != nil {
		return fmt.Errorf("failed to parse attestation: %w", err)
	}

	authData := attObj.AuthData
	if len(authData) < 53 {
		return fmt.Errorf("authData too short")
	}

	// AAGUID is at bytes 37-52
	aaguid := authData[37:53]

	isSandbox := bytes.Equal(aaguid, sandboxAAGUID)
	isProduction := bytes.Equal(aaguid, productionAAGUID)

	switch v.environment {
	case EnvProduction:
		if !isProduction {
			return fmt.Errorf("%w: expected production, got sandbox", ErrAAGUIDMismatch)
		}
	case EnvDevelopment, EnvSandbox:
		if !isSandbox {
			return fmt.Errorf("%w: expected sandbox, got production", ErrAAGUIDMismatch)
		}
	}

	return nil
}

// verifyKeyBinding verifies that the assertion binds the signing key.
func (v *AttestationVerifier) verifyKeyBinding(
	signingPublicKey []byte,
	assertion []byte,
	challenge []byte,
	attestationObj []byte,
) error {
	if len(signingPublicKey) != PublicKeySize {
		return fmt.Errorf("signing public key must be %d bytes (compressed P-256)", PublicKeySize)
	}

	// Parse attestation to get the attested public key
	var attObj attestationObject
	if err := cbor.Unmarshal(attestationObj, &attObj); err != nil {
		return fmt.Errorf("failed to parse attestation: %w", err)
	}

	// Get public key from leaf certificate
	x5c := attObj.AttStmt.X5c
	if len(x5c) == 0 {
		return fmt.Errorf("missing certificate chain")
	}

	leafCert, err := x509.ParseCertificate(x5c[0])
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	ecdsaKey, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("leaf certificate does not contain ECDSA key")
	}

	// Parse the assertion
	var assertionObj AppAttestAssertion
	if err := cbor.Unmarshal(assertion, &assertionObj); err != nil {
		return fmt.Errorf("failed to parse assertion: %w", err)
	}

	// Compute client data hash
	clientData := make([]byte, 0, len(signingPublicKey)+len(challenge))
	clientData = append(clientData, signingPublicKey...)
	clientData = append(clientData, challenge...)
	clientDataHash := sha256.Sum256(clientData)

	// The assertion signature is over: authenticatorData || clientDataHash
	signedData := make([]byte, 0, len(assertionObj.AuthenticatorData)+32)
	signedData = append(signedData, assertionObj.AuthenticatorData...)
	signedData = append(signedData, clientDataHash[:]...)
	signedDataHash := sha256.Sum256(signedData)

	// Verify the signature
	if !verifyDERSignature(ecdsaKey, signedDataHash[:], assertionObj.Signature) {
		return ErrKeyBindingInvalid
	}

	return nil
}

// VerifySoftwareKeyBinding verifies a software key binding (for simulator/fallback).
func (v *AttestationVerifier) VerifySoftwareKeyBinding(
	signingPublicKey []byte,
	assertion []byte,
	challenge []byte,
) error {
	if len(signingPublicKey) != PublicKeySize {
		return fmt.Errorf("signing public key must be %d bytes (compressed P-256)", PublicKeySize)
	}

	if len(assertion) != 64 {
		return fmt.Errorf("software assertion must be 64 bytes")
	}

	// Decompress the public key
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), signingPublicKey)
	if x == nil {
		return fmt.Errorf("failed to decompress P-256 public key")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Compute hash of client data (over compressed key)
	clientData := make([]byte, 0, len(signingPublicKey)+len(challenge))
	clientData = append(clientData, signingPublicKey...)
	clientData = append(clientData, challenge...)
	hash := sha256.Sum256(clientData)

	// Parse raw signature (r || s, 64 bytes)
	r := new(big.Int).SetBytes(assertion[:32])
	s := new(big.Int).SetBytes(assertion[32:])

	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return ErrKeyBindingInvalid
	}

	return nil
}

// =============================================================================
// ECDSA signature helpers (used by key attestation verification)
// =============================================================================

// verifyDERSignature verifies a DER-encoded ECDSA signature.
// Uses constant-time error handling to prevent timing side-channels.
func verifyDERSignature(pubKey *ecdsa.PublicKey, hash []byte, sig []byte) bool {
	r, s, err := ParseDERSignature(sig)
	parseOK := err == nil
	if !parseOK {
		r = big.NewInt(1)
		s = big.NewInt(1)
	}
	verifyOK := ecdsa.Verify(pubKey, hash, r, s)
	return parseOK && verifyOK
}
