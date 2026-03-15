package crypto

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// AppAttestAssertion is the CBOR-decoded assertion from Apple App Attest.
type AppAttestAssertion struct {
	Signature         []byte `cbor:"signature"`
	AuthenticatorData []byte `cbor:"authenticatorData"`
}

type ecdsaSignature struct {
	R, S *big.Int
}

// ParseDERSignature parses a DER-encoded ECDSA signature using Go's encoding/asn1 package.
func ParseDERSignature(der []byte) (*big.Int, *big.Int, error) {
	var sig ecdsaSignature
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DER signature: %v", err)
	}
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("trailing data after DER signature: %d bytes", len(rest))
	}
	if sig.R == nil || sig.S == nil {
		return nil, nil, errors.New("DER signature missing R or S component")
	}
	return sig.R, sig.S, nil
}
