package main

import (
	"strings"
	"testing"
)

// TestCkrToString verifies return value to string conversion.
func TestCkrToString(t *testing.T) {
	tests := []struct {
		rv   uint64
		want string
	}{
		{ckrOK, "CKR_OK"},
		{ckrCancel, "CKR_CANCEL"},
		{ckrHostMemory, "CKR_HOST_MEMORY"},
		{ckrSlotIDInvalid, "CKR_SLOT_ID_INVALID"},
		{ckrGeneralError, "CKR_GENERAL_ERROR"},
		{ckrFunctionFailed, "CKR_FUNCTION_FAILED"},
		{ckrArgumentsBad, "CKR_ARGUMENTS_BAD"},
		{ckrMechanismInvalid, "CKR_MECHANISM_INVALID"},
		{ckrMechanismParamInvalid, "CKR_MECHANISM_PARAM_INVALID"},
		{ckrObjectHandleInvalid, "CKR_OBJECT_HANDLE_INVALID"},
		{ckrOperationActive, "CKR_OPERATION_ACTIVE"},
		{ckrOperationNotInitialized, "CKR_OPERATION_NOT_INITIALIZED"},
		{ckrSessionClosed, "CKR_SESSION_CLOSED"},
		{ckrSessionHandleInvalid, "CKR_SESSION_HANDLE_INVALID"},
		{ckrTokenNotPresent, "CKR_TOKEN_NOT_PRESENT"},
		{ckrUserNotLoggedIn, "CKR_USER_NOT_LOGGED_IN"},
		{ckrUserAlreadyLoggedIn, "CKR_USER_ALREADY_LOGGED_IN"},
		{ckrKeyHandleInvalid, "CKR_KEY_HANDLE_INVALID"},
		{ckrKeyTypeInconsistent, "CKR_KEY_TYPE_INCONSISTENT"},
		{ckrBufferTooSmall, "CKR_BUFFER_TOO_SMALL"},
		{ckrCryptokiNotInitialized, "CKR_CRYPTOKI_NOT_INITIALIZED"},
		{ckrCryptokiAlreadyInitialized, "CKR_CRYPTOKI_ALREADY_INITIALIZED"},
		{ckrFunctionNotSupported, "CKR_FUNCTION_NOT_SUPPORTED"},
		{0xBEEFDEAD, "CKR_0x"},
	}

	for _, tt := range tests {
		got := bridgeCkrToString(tt.rv)
		if !strings.HasPrefix(got, tt.want) {
			t.Errorf("ckrToString(0x%x) = %q, want prefix %q", tt.rv, got, tt.want)
		}
	}
}

// TestCkmToString verifies mechanism type to string conversion.
func TestCkmToString(t *testing.T) {
	tests := []struct {
		mech uint64
		want string
	}{
		{ckmECDSA, "CKM_ECDSA"},
		{ckmECDSASHA256, "CKM_ECDSA_SHA256"},
		{ckmECDH1Derive, "CKM_ECDH1_DERIVE"},
		{ckmECDH1CofactorDerive, "CKM_ECDH1_COFACTOR_DERIVE"},
		{0xDEAD, "CKM_0x"},
	}

	for _, tt := range tests {
		got := bridgeCkmToString(tt.mech)
		if !strings.HasPrefix(got, tt.want) {
			t.Errorf("ckmToString(0x%x) = %q, want prefix %q", tt.mech, got, tt.want)
		}
	}
}

// TestCkaToString verifies attribute type to string conversion.
func TestCkaToString(t *testing.T) {
	tests := []struct {
		attr uint64
		want string
	}{
		{ckaClass, "CKA_CLASS"},
		{ckaToken, "CKA_TOKEN"},
		{ckaPrivate, "CKA_PRIVATE"},
		{ckaLabel, "CKA_LABEL"},
		{ckaID, "CKA_ID"},
		{ckaKeyType, "CKA_KEY_TYPE"},
		{ckaSign, "CKA_SIGN"},
		{ckaDerive, "CKA_DERIVE"},
		{ckaECParams, "CKA_EC_PARAMS"},
		{ckaECPoint, "CKA_EC_POINT"},
		{ckaSensitive, "CKA_SENSITIVE"},
		{ckaExtractable, "CKA_EXTRACTABLE"},
		{ckaNeverExtractable, "CKA_NEVER_EXTRACTABLE"},
		{ckaAlwaysSensitive, "CKA_ALWAYS_SENSITIVE"},
		{ckaLocal, "CKA_LOCAL"},
		{ckaModifiable, "CKA_MODIFIABLE"},
		{ckaValue, "CKA_VALUE"},
		{ckaValueLen, "CKA_VALUE_LEN"},
		{ckaAlwaysAuthenticate, "CKA_ALWAYS_AUTHENTICATE"},
		{0xFFFF, "CKA_0x"},
	}

	for _, tt := range tests {
		got := bridgeCkaToString(tt.attr)
		if !strings.HasPrefix(got, tt.want) {
			t.Errorf("ckaToString(0x%x) = %q, want prefix %q", tt.attr, got, tt.want)
		}
	}
}

// TestCkoToString verifies object class to string conversion.
func TestCkoToString(t *testing.T) {
	tests := []struct {
		class uint64
		want  string
	}{
		{ckoData, "CKO_DATA"},
		{ckoCertificate, "CKO_CERTIFICATE"},
		{ckoPublicKey, "CKO_PUBLIC_KEY"},
		{ckoPrivateKey, "CKO_PRIVATE_KEY"},
		{ckoSecretKey, "CKO_SECRET_KEY"},
		{0xFFFF, "CKO_0x"},
	}

	for _, tt := range tests {
		got := bridgeCkoToString(tt.class)
		if !strings.HasPrefix(got, tt.want) {
			t.Errorf("ckoToString(0x%x) = %q, want prefix %q", tt.class, got, tt.want)
		}
	}
}

// TestCkkToString verifies key type to string conversion.
func TestCkkToString(t *testing.T) {
	tests := []struct {
		keyType uint64
		want    string
	}{
		{ckkRSA, "CKK_RSA"},
		{ckkDSA, "CKK_DSA"},
		{ckkDH, "CKK_DH"},
		{ckkEC, "CKK_EC"},
		{ckkGenericSecret, "CKK_GENERIC_SECRET"},
		{ckkAES, "CKK_AES"},
		{0xFFFF, "CKK_0x"},
	}

	for _, tt := range tests {
		got := bridgeCkkToString(tt.keyType)
		if !strings.HasPrefix(got, tt.want) {
			t.Errorf("ckkToString(0x%x) = %q, want prefix %q", tt.keyType, got, tt.want)
		}
	}
}

// TestKdfToString verifies KDF type to string conversion.
func TestKdfToString(t *testing.T) {
	tests := []struct {
		kdf  uint64
		want string
	}{
		{ckdNull, "NULL (raw ECDH)"},
		{ckdSHA1KDF, "SHA1-KDF"},
		{ckdSHA256KDF, "SHA256-KDF"},
		{0xFFFF, "CKD_0x"},
	}

	for _, tt := range tests {
		got := bridgeKdfToString(tt.kdf)
		if !strings.HasPrefix(got, tt.want) {
			t.Errorf("kdfToString(0x%x) = %q, want prefix %q", tt.kdf, got, tt.want)
		}
	}
}

// TestFormatHex verifies hex formatting helper.
func TestFormatHex(t *testing.T) {
	tests := []struct {
		data   []byte
		maxLen int
		want   string
	}{
		{nil, 0, "(empty)"},
		{[]byte{}, 0, "(empty)"},
		{[]byte{0xaa, 0xbb}, 0, "aabb"},
		{[]byte{0xaa, 0xbb, 0xcc}, 2, "aabb..."},
	}

	for _, tt := range tests {
		got := formatHex(tt.data, tt.maxLen)
		if !strings.HasPrefix(got, tt.want) {
			t.Errorf("formatHex(%x, %d) = %q, want prefix %q", tt.data, tt.maxLen, got, tt.want)
		}
	}
}

// TestTruncateString verifies string truncation.
func TestTruncateString(t *testing.T) {
	tests := []struct {
		s      string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 8, "hello..."},
		{"", 5, ""},
	}

	for _, tt := range tests {
		got := truncateString(tt.s, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tt.s, tt.maxLen, got, tt.want)
		}
	}
}

// TestCleanLabel verifies label cleaning (trailing space removal).
func TestCleanLabel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello   ", "hello"},
		{"hello", "hello"},
		{"   ", ""},
		{"", ""},
		{"hello world", "hello world"},
	}

	for _, tt := range tests {
		got := cleanLabel(tt.input)
		if got != tt.want {
			t.Errorf("cleanLabel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestBoolToCK verifies Go bool to CK_BBOOL conversion.
func TestBoolToCK(t *testing.T) {
	if bridgeBoolToCK(true) != ckTrue {
		t.Error("boolToCK(true) != CK_TRUE")
	}
	if bridgeBoolToCK(false) != ckFalse {
		t.Error("boolToCK(false) != CK_FALSE")
	}
}

// TestCkToBool verifies CK_BBOOL to Go bool conversion.
func TestCkToBool(t *testing.T) {
	if !bridgeCkToBool(ckTrue) {
		t.Error("ckToBool(CK_TRUE) != true")
	}
	if bridgeCkToBool(ckFalse) {
		t.Error("ckToBool(CK_FALSE) != false")
	}
}
