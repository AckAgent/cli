// Package crypto provides cryptographic operations for the CLI.
// This file contains Android Key Attestation verification and unified attestation data
// verification for device sync (dispatching to iOS or Android platform-specific checks).
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// =============================================================================
// Google Hardware Attestation Root CA Certificates
// =============================================================================

// Google Hardware Attestation Root CA certificates.
// These are used to verify Android Key Attestation certificate chains.
// Downloaded from: https://developer.android.com/privacy-and-security/security-key-attestation

// googleHardwareAttestationRoot is the primary Google Hardware Attestation Root CA.
const googleHardwareAttestationRoot = `-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAz
NzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnu
XKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83U
h6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cno
L/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2ok
QBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vA
D32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAI
mMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz+Jucth+IqoW
Fua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91
oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09o
jm6xNIrw2OocrDKsudk/okr/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUB
ZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCH
ex0SdDrx+tWUDqG8At2JHA==
-----END CERTIFICATE-----`

// googleHardwareAttestationRootEC is the EC-based root (for newer devices).
const googleHardwareAttestationRootEC = `-----BEGIN CERTIFICATE-----
MIIBYRCB96ADAgECAgkA1IFnLa5qnGgwCgYIKoZIzj0EAwIwGzEZMBcGA1UEFRMQ
ZjkyMDA5ZTg1M2I2YjA0NTAeFw0xOTExMjIyMDM3NThaFw0zNDExMTgyMDM3NTha
MBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATbpY2YYGL3G6w/WKzX6/v7Y1hMF/A6P+Yb6GWf5/vDQNLPhYfFe+jB
cHuoNHv+WfR9TBrxzA0i2OQLHD66yuf/oyMwITAfBgNVHSMEGDAWgBQpmE1hD17L
4k4a15SfU+mw8y/GATAKBggqhkjOPQQDAgNJADBGAiEA0qb3F6ET4+WN6l4LMICN
qlBIFz4z3f+6aW0H2ZQXEL8CIQCjZPNLBKo+HBOmcPVBnfoG8U3yDuY/z1/m3DsY
wS0LZA==
-----END CERTIFICATE-----`

var (
	// Parsed Google Root CAs
	googleRootCertPool *x509.CertPool
)

func init() {
	googleRootCertPool = x509.NewCertPool()

	roots := []string{
		googleHardwareAttestationRoot,
		googleHardwareAttestationRootEC,
	}

	parsedCount := 0
	for _, rootPEM := range roots {
		if googleRootCertPool.AppendCertsFromPEM([]byte(rootPEM)) {
			parsedCount++
		} else {
			block, _ := pem.Decode([]byte(rootPEM))
			if block != nil {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					googleRootCertPool.AddCert(cert)
					parsedCount++
				}
			}
		}
	}

	if parsedCount == 0 {
		panic("failed to parse any Google Hardware Attestation Root CA certificates")
	}
}

// =============================================================================
// Unified Attestation Data Verification (for device sync)
// =============================================================================

// AttestationData contains everything needed for client-side device attestation verification
// during device sync. This is the identified-mode attestation from the auth service.
type AttestationData struct {
	DeviceType           string                  `json:"deviceType"`              // "ios" or "android"
	AttestationType      AttestationSecurityType `json:"attestationType"`         // unified type
	AttestationPublicKey []byte                  `json:"attestationPublicKeyHex"` // from certificate (33 bytes compressed: 0x02/0x03 || X)
	Timestamp            int64                   `json:"timestamp"`               // Unix timestamp in milliseconds
	CertificateChain     [][]byte                `json:"certificateChain"`        // DER-encoded certificates
	Mode                 string                  `json:"mode"`                    // "identified"
	ResponseAssertion    []byte                  `json:"responseAssertion"`       // attestation key assertion over response hash
	AuthPublicKeyHex     string                  `json:"authPublicKeyHex"`        // Hex-encoded auth public key
	EncryptionPublicKey  []byte                  `json:"encryptionPublicKeyHex"`  // P-256 ECDH public key
}

// AttestationVerificationResult contains the result of device attestation verification.
type AttestationVerificationResult struct {
	Valid            bool
	IsHardwareBacked bool
	AttestationType  AttestationSecurityType
	ChainValid       bool
	Errors           []string
	VerifiedAt       time.Time
}

var (
	ErrInvalidAttestationType    = errors.New("invalid attestation type")
	ErrAndroidChainInvalid       = errors.New("Android certificate chain invalid")
	ErrAndroidUntrustedRoot      = errors.New("Android certificate not rooted in Google")
	ErrAttestationPublicKeyMatch = errors.New("attestation public key mismatch")
)

// VerifyAttestationData verifies device attestation data during device sync.
// This is the main entry point for identified-mode device attestation verification.
func VerifyAttestationData(data *AttestationData, env AttestationEnvironment) (*AttestationVerificationResult, error) {
	result := &AttestationVerificationResult{
		AttestationType:  data.AttestationType,
		IsHardwareBacked: data.AttestationType.IsHardwareBacked(),
		VerifiedAt:       time.Now(),
	}

	// Software attestation - minimal verification (no cert chain to verify)
	if data.AttestationType == AttestationSoftware {
		result.Valid = true
		return result, nil
	}

	// Hardware-backed attestation - full verification
	switch data.DeviceType {
	case "ios":
		return verifyIOSAttestationData(data, env, result)
	case "android":
		return verifyAndroidAttestationData(data, result)
	default:
		result.Errors = append(result.Errors, fmt.Sprintf("unknown device type: %s", data.DeviceType))
		return result, ErrInvalidAttestationType
	}
}

// verifyIOSAttestationData verifies iOS App Attest attestation.
func verifyIOSAttestationData(data *AttestationData, _ AttestationEnvironment, result *AttestationVerificationResult) (*AttestationVerificationResult, error) {
	if len(data.CertificateChain) > 0 {
		chainErr := verifyDERCertificateChain(data.CertificateChain, appleRootCertPool)
		if chainErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("chain: %v", chainErr))
		} else {
			result.ChainValid = true
		}
	}

	result.Valid = result.ChainValid
	return result, nil
}

// verifyAndroidAttestationData verifies Android Key Attestation.
func verifyAndroidAttestationData(data *AttestationData, result *AttestationVerificationResult) (*AttestationVerificationResult, error) {
	if len(data.CertificateChain) == 0 {
		result.Errors = append(result.Errors, "missing Android certificate chain")
		return result, ErrAndroidChainInvalid
	}

	certs := make([]*x509.Certificate, len(data.CertificateChain))
	for i, der := range data.CertificateChain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to parse certificate %d: %v", i, err))
			return result, ErrAndroidChainInvalid
		}
		certs[i] = cert
	}

	leafCert := certs[0]

	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}

	opts := x509.VerifyOptions{
		Roots:         googleRootCertPool,
		Intermediates: intermediates,
		CurrentTime:   leafCert.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := leafCert.Verify(opts); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("chain verification failed: %v", err))
	} else {
		result.ChainValid = true
	}

	if len(data.AttestationPublicKey) == PublicKeySize {
		// Decompress the stored compressed key to compare with certificate
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), data.AttestationPublicKey)
		if x != nil {
			ecdsaKey, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
			if ok {
				if ecdsaKey.X.Cmp(x) != 0 || ecdsaKey.Y.Cmp(y) != 0 {
					result.Errors = append(result.Errors, "attestation public key does not match certificate")
				}
			}
		}
	}

	result.Valid = result.ChainValid
	return result, nil
}

// verifyDERCertificateChain verifies a DER-encoded certificate chain against a root pool.
func verifyDERCertificateChain(certChain [][]byte, rootPool *x509.CertPool) error {
	if len(certChain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	leafCert, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	intermediates := x509.NewCertPool()
	for i := 1; i < len(certChain); i++ {
		cert, err := x509.ParseCertificate(certChain[i])
		if err != nil {
			return fmt.Errorf("failed to parse intermediate certificate: %w", err)
		}
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediates,
		CurrentTime:   leafCert.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := leafCert.Verify(opts); err != nil {
		return fmt.Errorf("%w: %v", ErrUntrustedRoot, err)
	}

	return nil
}
