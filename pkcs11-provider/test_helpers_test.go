package main

import (
	"github.com/ackagent/cli/internal/shared/config"
)

// This file provides Go-level constants and helpers for tests that cannot use
// import "C" due to the //export directives in the main source files.
// All CK constants are Go equivalents of the C #define values from types.go.

// CK return values (matching PKCS#11 spec values)
const (
	ckrOK                          = 0x00000000
	ckrCancel                      = 0x00000001
	ckrHostMemory                  = 0x00000002
	ckrSlotIDInvalid               = 0x00000003
	ckrGeneralError                = 0x00000005
	ckrFunctionFailed              = 0x00000006
	ckrArgumentsBad                = 0x00000007
	ckrAttributeSensitive          = 0x00000011
	ckrAttributeTypeInvalid        = 0x00000012
	ckrDataInvalid                 = 0x00000020
	ckrDataLenRange                = 0x00000021
	ckrDeviceError                 = 0x00000030
	ckrKeyHandleInvalid            = 0x00000060
	ckrKeyTypeInconsistent         = 0x00000063
	ckrMechanismInvalid            = 0x00000070
	ckrMechanismParamInvalid       = 0x00000071
	ckrFunctionNotSupported        = 0x00000054
	ckrObjectHandleInvalid         = 0x00000082
	ckrOperationActive             = 0x00000090
	ckrOperationNotInitialized     = 0x00000091
	ckrSessionClosed               = 0x000000B0
	ckrSessionHandleInvalid        = 0x000000B3
	ckrSessionParallelNotSupported = 0x000000B4
	ckrTokenNotPresent             = 0x000000E0
	ckrUserAlreadyLoggedIn         = 0x00000100
	ckrUserNotLoggedIn             = 0x00000101
	ckrUserPINNotInitialized       = 0x00000102
	ckrBufferTooSmall              = 0x00000150
	ckrCryptokiNotInitialized      = 0x00000190
	ckrCryptokiAlreadyInitialized  = 0x00000191
)

// Mechanism types
const (
	ckmECDSA               = 0x00001041
	ckmECDSASHA256         = 0x00001044
	ckmECDH1Derive         = 0x00001050
	ckmECDH1CofactorDerive = 0x00001051
)

// KDF types
const (
	ckdNull      = 0x00000001
	ckdSHA1KDF   = 0x00000002
	ckdSHA256KDF = 0x00000006
)

// Object classes
const (
	ckoData        = 0x00000000
	ckoCertificate = 0x00000001
	ckoPublicKey   = 0x00000002
	ckoPrivateKey  = 0x00000003
	ckoSecretKey   = 0x00000004
)

// Key types
const (
	ckkRSA           = 0x00000000
	ckkDSA           = 0x00000001
	ckkDH            = 0x00000002
	ckkEC            = 0x00000003
	ckkGenericSecret = 0x00000010
	ckkAES           = 0x0000001F
)

// Attribute types
const (
	ckaClass              = 0x00000000
	ckaToken              = 0x00000001
	ckaPrivate            = 0x00000002
	ckaLabel              = 0x00000003
	ckaValue              = 0x00000011
	ckaKeyType            = 0x00000100
	ckaID                 = 0x00000102
	ckaSensitive          = 0x00000103
	ckaSign               = 0x00000108
	ckaDerive             = 0x0000010C
	ckaECParams           = 0x00000180
	ckaECPoint            = 0x00000181
	ckaExtractable        = 0x00000162
	ckaLocal              = 0x00000163
	ckaNeverExtractable   = 0x00000164
	ckaAlwaysSensitive    = 0x00000165
	ckaModifiable         = 0x00000170
	ckaValueLen           = 0x00000161
	ckaAlwaysAuthenticate = 0x00000202
)

// Session flags
const (
	ckfRWSession     = 0x00000002
	ckfSerialSession = 0x00000004
)

// Session states
const (
	cksROPublicSession = 0
	cksROUserFunctions = 1
	cksRWPublicSession = 2
	cksRWUserFunctions = 3
)

// Token flags
const (
	ckfTokenPresent       = 0x00000001
	ckfWriteProtected     = 0x00000002
	ckfHWSlot             = 0x00000004
	ckfUserPINInitialized = 0x00000008
	ckfTokenInitialized   = 0x00000400
)

// Mechanism info flags
const (
	ckfSignFlag     = 0x00000800
	ckfVerify       = 0x00002000
	ckfDeriveFlag   = 0x00080000
	ckfECFP         = 0x00100000
	ckfECNamedCurve = 0x00800000
)

// Boolean
const (
	ckTrue  = 1
	ckFalse = 0
)

// ckUnavailableInformation is the equivalent of (~0UL) -- all bits set.
const ckUnavailableInformation = ^uint64(0)

// rvName returns a human-readable name for a CK_RV value (as uint64).
func rvName(rv uint64) string {
	switch rv {
	case ckrOK:
		return "CKR_OK"
	case ckrArgumentsBad:
		return "CKR_ARGUMENTS_BAD"
	case ckrSlotIDInvalid:
		return "CKR_SLOT_ID_INVALID"
	case ckrMechanismInvalid:
		return "CKR_MECHANISM_INVALID"
	case ckrMechanismParamInvalid:
		return "CKR_MECHANISM_PARAM_INVALID"
	case ckrKeyHandleInvalid:
		return "CKR_KEY_HANDLE_INVALID"
	case ckrObjectHandleInvalid:
		return "CKR_OBJECT_HANDLE_INVALID"
	case ckrOperationActive:
		return "CKR_OPERATION_ACTIVE"
	case ckrOperationNotInitialized:
		return "CKR_OPERATION_NOT_INITIALIZED"
	case ckrSessionHandleInvalid:
		return "CKR_SESSION_HANDLE_INVALID"
	case ckrBufferTooSmall:
		return "CKR_BUFFER_TOO_SMALL"
	case ckrCryptokiNotInitialized:
		return "CKR_CRYPTOKI_NOT_INITIALIZED"
	case ckrCryptokiAlreadyInitialized:
		return "CKR_CRYPTOKI_ALREADY_INITIALIZED"
	case ckrUserAlreadyLoggedIn:
		return "CKR_USER_ALREADY_LOGGED_IN"
	case ckrUserNotLoggedIn:
		return "CKR_USER_NOT_LOGGED_IN"
	case ckrUserPINNotInitialized:
		return "CKR_USER_PIN_NOT_INITIALIZED"
	case ckrAttributeSensitive:
		return "CKR_ATTRIBUTE_SENSITIVE"
	case ckrAttributeTypeInvalid:
		return "CKR_ATTRIBUTE_TYPE_INVALID"
	case ckrDataLenRange:
		return "CKR_DATA_LEN_RANGE"
	case ckrFunctionFailed:
		return "CKR_FUNCTION_FAILED"
	case ckrTokenNotPresent:
		return "CKR_TOKEN_NOT_PRESENT"
	case ckrDeviceError:
		return "CKR_DEVICE_ERROR"
	case ckrFunctionNotSupported:
		return "CKR_FUNCTION_NOT_SUPPORTED"
	default:
		return "CKR_UNKNOWN"
	}
}

// newTestConfig creates a minimal config for testing.
// If loggedIn is true, it sets up enough state for IsLoggedIn() to return true.
func newTestConfig(loggedIn bool) *config.Config {
	tmpDir := "/tmp/pkcs11-test-config"
	config.SetConfigDir(tmpDir)
	cfg := config.NewDefault()
	if loggedIn {
		p, _ := cfg.GetActiveProfile()
		p.UserAccount = &config.UserAccount{
			UserID:      "test-user",
			RequesterID: "test-requester",
			SASVerified: true,
			Devices: []config.UserDevice{
				{ApproverId: "test-approver-1", AuthPublicKey: []byte{0xaa, 0xbb, 0xcc, 0xdd}, PublicKey: []byte("pubkey")},
			},
		}
	}
	return cfg
}

// testRegisterSession is a convenience wrapper for test code that calls
// bridgeRegisterTestSession with a default logged-in config.
func testRegisterSession(flags uint64, keys []*keyObject) uint64 {
	return bridgeRegisterTestSession(flags, keys, newTestConfig(true))
}
