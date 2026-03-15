package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type bbsVectorMessage struct {
	Index    int    `json:"index"`
	ValueHex string `json:"valueHex"`
}

type bbsPseudonymVector struct {
	IssuerPublicKeyHex         string             `json:"issuerPublicKeyHex"`
	ProofHex                   string             `json:"proofHex"`
	PseudonymHex               string             `json:"pseudonymHex"`
	HeaderHex                  string             `json:"headerHex"`
	PresentationHeaderHex      string             `json:"presentationHeaderHex"`
	ScopeHex                   string             `json:"scopeHex"`
	TotalSignerMessages        int                `json:"totalSignerMessages"`
	DisclosedMessages          []bbsVectorMessage `json:"disclosedMessages"`
	DisclosedCommittedMessages []bbsVectorMessage `json:"disclosedCommittedMessages"`
	DisclosedCommitmentIndices []int              `json:"disclosedCommitmentIndices"`
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}
	return decoded
}

func loadBbsPseudonymVector(t *testing.T, fixtureFile string) bbsPseudonymVector {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	repoRoot := filepath.Join(filepath.Dir(thisFile), "..")
	fixturePath := filepath.Join(
		repoRoot,
		"data",
		"fixtures",
		fixtureFile,
	)

	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	var vector bbsPseudonymVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("failed to unmarshal fixture: %v", err)
	}

	return vector
}

func TestBbsVerifyProofWithPseudonymVectors(t *testing.T) {
	fixtures := []struct {
		name string
		file string
	}{
		{name: "web-sdk-vector", file: "bbs-pseudonym-vector.json"},
		{name: "android-vector", file: "android-bbs-pseudonym-vector.json"},
	}

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			vector := loadBbsPseudonymVector(t, fixture.file)

			issuerPublicKey := decodeHex(t, vector.IssuerPublicKeyHex)
			proof := decodeHex(t, vector.ProofHex)
			pseudonym := decodeHex(t, vector.PseudonymHex)
			header := decodeHex(t, vector.HeaderHex)
			presentationHeader := decodeHex(t, vector.PresentationHeaderHex)
			scope := decodeHex(t, vector.ScopeHex)

			disclosedMessages := make([][]byte, 0, len(vector.DisclosedMessages))
			disclosedIndices := make([]int, 0, len(vector.DisclosedMessages))
			for _, message := range vector.DisclosedMessages {
				disclosedIndices = append(disclosedIndices, message.Index)
				disclosedMessages = append(disclosedMessages, decodeHex(t, message.ValueHex))
			}

			t.Run("valid vector verifies", func(t *testing.T) {
				err := bbsVerifyProofWithPseudonym(
					issuerPublicKey,
					proof,
					pseudonym,
					header,
					presentationHeader,
					scope,
					vector.TotalSignerMessages,
					disclosedMessages,
					disclosedIndices,
				)
				if err != nil {
					t.Fatalf("expected valid vector to verify: %v", err)
				}
			})

			t.Run("wrong scope fails", func(t *testing.T) {
				badScope := append([]byte(nil), scope...)
				badScope[0] ^= 0xff

				err := bbsVerifyProofWithPseudonym(
					issuerPublicKey,
					proof,
					pseudonym,
					header,
					presentationHeader,
					badScope,
					vector.TotalSignerMessages,
					disclosedMessages,
					disclosedIndices,
				)
				if err == nil {
					t.Fatal("expected wrong scope verification to fail")
				}
			})

			t.Run("tampered pseudonym fails", func(t *testing.T) {
				badPseudonym := append([]byte(nil), pseudonym...)
				badPseudonym[5] ^= 0xff

				err := bbsVerifyProofWithPseudonym(
					issuerPublicKey,
					proof,
					badPseudonym,
					header,
					presentationHeader,
					scope,
					vector.TotalSignerMessages,
					disclosedMessages,
					disclosedIndices,
				)
				if err == nil {
					t.Fatal("expected tampered pseudonym verification to fail")
				}
			})

			t.Run("tampered proof fails", func(t *testing.T) {
				badProof := append([]byte(nil), proof...)
				badProof[0] ^= 0xff
				badProof[10] ^= 0xff

				err := bbsVerifyProofWithPseudonym(
					issuerPublicKey,
					badProof,
					pseudonym,
					header,
					presentationHeader,
					scope,
					vector.TotalSignerMessages,
					disclosedMessages,
					disclosedIndices,
				)
				if err == nil {
					t.Fatal("expected tampered proof verification to fail")
				}
			})
		})
	}
}
