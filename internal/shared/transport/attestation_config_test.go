package transport

import (
	"os"
	"testing"
)

func TestAllowSkipAttestationDefaultsFalse(t *testing.T) {
	if AllowSkipAttestation != "false" {
		t.Errorf("AllowSkipAttestation should default to \"false\", got %q", AllowSkipAttestation)
	}
}

func TestSkipAttestationRequestedReturnsFalseWhenBuildDisallows(t *testing.T) {
	// Even with the env var set, the function must return false
	// when AllowSkipAttestation is "false" (the default for production builds).
	original := AllowSkipAttestation
	AllowSkipAttestation = "false"
	t.Cleanup(func() { AllowSkipAttestation = original })

	t.Setenv("SKIP_VERIFY_ATTESTATION", "true")

	if SkipAttestationRequested() {
		t.Error("SkipAttestationRequested() should return false when AllowSkipAttestation is \"false\"")
	}
}

func TestSkipAttestationRequestedReturnsFalseWhenEnvUnset(t *testing.T) {
	// Even with a dev build, the function must return false
	// when the env var is not set.
	original := AllowSkipAttestation
	AllowSkipAttestation = "true"
	t.Cleanup(func() { AllowSkipAttestation = original })

	os.Unsetenv("SKIP_VERIFY_ATTESTATION")

	if SkipAttestationRequested() {
		t.Error("SkipAttestationRequested() should return false when SKIP_VERIFY_ATTESTATION is not set")
	}
}

func TestSkipAttestationRequestedReturnsFalseWhenEnvWrongValue(t *testing.T) {
	// The old code accepted "1"; the new code requires "true".
	// Verify that "1" is no longer accepted.
	original := AllowSkipAttestation
	AllowSkipAttestation = "true"
	t.Cleanup(func() { AllowSkipAttestation = original })

	t.Setenv("SKIP_VERIFY_ATTESTATION", "1")

	if SkipAttestationRequested() {
		t.Error("SkipAttestationRequested() should return false when SKIP_VERIFY_ATTESTATION is \"1\" (must be \"true\")")
	}
}

func TestSkipAttestationRequestedReturnsTrueWhenBothConditionsMet(t *testing.T) {
	original := AllowSkipAttestation
	AllowSkipAttestation = "true"
	t.Cleanup(func() { AllowSkipAttestation = original })

	t.Setenv("SKIP_VERIFY_ATTESTATION", "true")

	if !SkipAttestationRequested() {
		t.Error("SkipAttestationRequested() should return true when AllowSkipAttestation is \"true\" and SKIP_VERIFY_ATTESTATION is \"true\"")
	}
}
