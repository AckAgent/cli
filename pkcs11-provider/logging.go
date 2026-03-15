package main

/*
#include <stdint.h>

// Import types from types.go
typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;

// Return values
#define CKR_OK                              0x00000000
#define CKR_CANCEL                          0x00000001
#define CKR_HOST_MEMORY                     0x00000002
#define CKR_SLOT_ID_INVALID                 0x00000003
#define CKR_GENERAL_ERROR                   0x00000005
#define CKR_FUNCTION_FAILED                 0x00000006
#define CKR_ARGUMENTS_BAD                   0x00000007
#define CKR_MECHANISM_INVALID               0x00000070
#define CKR_MECHANISM_PARAM_INVALID         0x00000071
#define CKR_OBJECT_HANDLE_INVALID           0x00000082
#define CKR_OPERATION_ACTIVE                0x00000090
#define CKR_OPERATION_NOT_INITIALIZED       0x00000091
#define CKR_SESSION_CLOSED                  0x000000B0
#define CKR_SESSION_HANDLE_INVALID          0x000000B3
#define CKR_TOKEN_NOT_PRESENT               0x000000E0
#define CKR_USER_NOT_LOGGED_IN              0x00000101
#define CKR_USER_ALREADY_LOGGED_IN          0x00000100
#define CKR_KEY_HANDLE_INVALID              0x00000060
#define CKR_KEY_TYPE_INCONSISTENT           0x00000063
#define CKR_BUFFER_TOO_SMALL                0x00000150
#define CKR_CRYPTOKI_NOT_INITIALIZED        0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED    0x00000191
#define CKR_FUNCTION_NOT_SUPPORTED          0x00000054

// Mechanisms
#define CKM_ECDSA                           0x00001041
#define CKM_ECDSA_SHA256                    0x00001044
#define CKM_ECDH1_DERIVE                    0x00001050
#define CKM_ECDH1_COFACTOR_DERIVE           0x00001051

// Attributes
#define CKA_CLASS                           0x00000000
#define CKA_TOKEN                           0x00000001
#define CKA_PRIVATE                         0x00000002
#define CKA_LABEL                           0x00000003
#define CKA_ID                              0x00000102
#define CKA_KEY_TYPE                        0x00000100
#define CKA_SIGN                            0x00000108
#define CKA_DERIVE                          0x0000010C
#define CKA_EC_PARAMS                       0x00000180
#define CKA_EC_POINT                        0x00000181
#define CKA_SENSITIVE                       0x00000103
#define CKA_EXTRACTABLE                     0x00000162
#define CKA_NEVER_EXTRACTABLE               0x00000164
#define CKA_ALWAYS_SENSITIVE                0x00000165
#define CKA_LOCAL                           0x00000163
#define CKA_MODIFIABLE                      0x00000170
#define CKA_VALUE                           0x00000011
#define CKA_VALUE_LEN                       0x00000161
#define CKA_ALWAYS_AUTHENTICATE             0x00000202

// Object classes
#define CKO_DATA                            0x00000000
#define CKO_CERTIFICATE                     0x00000001
#define CKO_PUBLIC_KEY                      0x00000002
#define CKO_PRIVATE_KEY                     0x00000003
#define CKO_SECRET_KEY                      0x00000004

// Key types
#define CKK_RSA                             0x00000000
#define CKK_DSA                             0x00000001
#define CKK_DH                              0x00000002
#define CKK_EC                              0x00000003
#define CKK_GENERIC_SECRET                  0x00000010
#define CKK_AES                             0x0000001F
*/
import "C"

import (
	"fmt"
	"strings"

	"github.com/ackagent/cli/internal/shared/log"
)

var pkcs11Log = log.New("pkcs11")

func init() {
	log.InitFromEnv()
}

// logDebug logs debug messages when enabled by log level.
func logDebug(format string, args ...interface{}) {
	pkcs11Log.Debug(format, args...)
}

// logInfo logs info messages when enabled by log level.
func logInfo(format string, args ...interface{}) {
	pkcs11Log.Info(format, args...)
}

// logError logs error messages (always).
func logError(format string, args ...interface{}) {
	pkcs11Log.Error(format, args...)
}

// logWarn logs warning messages when enabled by log level.
func logWarn(format string, args ...interface{}) {
	pkcs11Log.Warn(format, args...)
}

// formatHex formats a byte slice as a hex string with optional max length
func formatHex(data []byte, maxLen int) string {
	if len(data) == 0 {
		return "(empty)"
	}
	if maxLen > 0 && len(data) > maxLen {
		return fmt.Sprintf("%x... (%d bytes)", data[:maxLen], len(data))
	}
	return fmt.Sprintf("%x", data)
}

// ckrToString converts a PKCS#11 return value to a string for logging
func ckrToString(rv C.CK_RV) string {
	switch rv {
	case C.CKR_OK:
		return "CKR_OK"
	case C.CKR_CANCEL:
		return "CKR_CANCEL"
	case C.CKR_HOST_MEMORY:
		return "CKR_HOST_MEMORY"
	case C.CKR_SLOT_ID_INVALID:
		return "CKR_SLOT_ID_INVALID"
	case C.CKR_GENERAL_ERROR:
		return "CKR_GENERAL_ERROR"
	case C.CKR_FUNCTION_FAILED:
		return "CKR_FUNCTION_FAILED"
	case C.CKR_ARGUMENTS_BAD:
		return "CKR_ARGUMENTS_BAD"
	case C.CKR_MECHANISM_INVALID:
		return "CKR_MECHANISM_INVALID"
	case C.CKR_MECHANISM_PARAM_INVALID:
		return "CKR_MECHANISM_PARAM_INVALID"
	case C.CKR_OBJECT_HANDLE_INVALID:
		return "CKR_OBJECT_HANDLE_INVALID"
	case C.CKR_OPERATION_ACTIVE:
		return "CKR_OPERATION_ACTIVE"
	case C.CKR_OPERATION_NOT_INITIALIZED:
		return "CKR_OPERATION_NOT_INITIALIZED"
	case C.CKR_SESSION_CLOSED:
		return "CKR_SESSION_CLOSED"
	case C.CKR_SESSION_HANDLE_INVALID:
		return "CKR_SESSION_HANDLE_INVALID"
	case C.CKR_TOKEN_NOT_PRESENT:
		return "CKR_TOKEN_NOT_PRESENT"
	case C.CKR_USER_NOT_LOGGED_IN:
		return "CKR_USER_NOT_LOGGED_IN"
	case C.CKR_USER_ALREADY_LOGGED_IN:
		return "CKR_USER_ALREADY_LOGGED_IN"
	case C.CKR_KEY_HANDLE_INVALID:
		return "CKR_KEY_HANDLE_INVALID"
	case C.CKR_KEY_TYPE_INCONSISTENT:
		return "CKR_KEY_TYPE_INCONSISTENT"
	case C.CKR_BUFFER_TOO_SMALL:
		return "CKR_BUFFER_TOO_SMALL"
	case C.CKR_CRYPTOKI_NOT_INITIALIZED:
		return "CKR_CRYPTOKI_NOT_INITIALIZED"
	case C.CKR_CRYPTOKI_ALREADY_INITIALIZED:
		return "CKR_CRYPTOKI_ALREADY_INITIALIZED"
	case C.CKR_FUNCTION_NOT_SUPPORTED:
		return "CKR_FUNCTION_NOT_SUPPORTED"
	default:
		return fmt.Sprintf("CKR_0x%08X", uint32(rv))
	}
}

// ckmToString converts a mechanism type to a string for logging
func ckmToString(mechanism C.CK_MECHANISM_TYPE) string {
	switch mechanism {
	case C.CKM_ECDSA:
		return "CKM_ECDSA"
	case C.CKM_ECDSA_SHA256:
		return "CKM_ECDSA_SHA256"
	case C.CKM_ECDH1_DERIVE:
		return "CKM_ECDH1_DERIVE"
	case C.CKM_ECDH1_COFACTOR_DERIVE:
		return "CKM_ECDH1_COFACTOR_DERIVE"
	default:
		return fmt.Sprintf("CKM_0x%08X", uint32(mechanism))
	}
}

// ckaToString converts an attribute type to a string for logging
func ckaToString(attr C.CK_ATTRIBUTE_TYPE) string {
	switch attr {
	case C.CKA_CLASS:
		return "CKA_CLASS"
	case C.CKA_TOKEN:
		return "CKA_TOKEN"
	case C.CKA_PRIVATE:
		return "CKA_PRIVATE"
	case C.CKA_LABEL:
		return "CKA_LABEL"
	case C.CKA_ID:
		return "CKA_ID"
	case C.CKA_KEY_TYPE:
		return "CKA_KEY_TYPE"
	case C.CKA_SIGN:
		return "CKA_SIGN"
	case C.CKA_DERIVE:
		return "CKA_DERIVE"
	case C.CKA_EC_PARAMS:
		return "CKA_EC_PARAMS"
	case C.CKA_EC_POINT:
		return "CKA_EC_POINT"
	case C.CKA_SENSITIVE:
		return "CKA_SENSITIVE"
	case C.CKA_EXTRACTABLE:
		return "CKA_EXTRACTABLE"
	case C.CKA_NEVER_EXTRACTABLE:
		return "CKA_NEVER_EXTRACTABLE"
	case C.CKA_ALWAYS_SENSITIVE:
		return "CKA_ALWAYS_SENSITIVE"
	case C.CKA_LOCAL:
		return "CKA_LOCAL"
	case C.CKA_MODIFIABLE:
		return "CKA_MODIFIABLE"
	case C.CKA_VALUE:
		return "CKA_VALUE"
	case C.CKA_VALUE_LEN:
		return "CKA_VALUE_LEN"
	case C.CKA_ALWAYS_AUTHENTICATE:
		return "CKA_ALWAYS_AUTHENTICATE"
	default:
		return fmt.Sprintf("CKA_0x%08X", uint32(attr))
	}
}

// ckoToString converts an object class to a string for logging
func ckoToString(class C.CK_OBJECT_CLASS) string {
	switch class {
	case C.CKO_DATA:
		return "CKO_DATA"
	case C.CKO_CERTIFICATE:
		return "CKO_CERTIFICATE"
	case C.CKO_PUBLIC_KEY:
		return "CKO_PUBLIC_KEY"
	case C.CKO_PRIVATE_KEY:
		return "CKO_PRIVATE_KEY"
	case C.CKO_SECRET_KEY:
		return "CKO_SECRET_KEY"
	default:
		return fmt.Sprintf("CKO_0x%08X", uint32(class))
	}
}

// ckkToString converts a key type to a string for logging
func ckkToString(keyType C.CK_KEY_TYPE) string {
	switch keyType {
	case C.CKK_RSA:
		return "CKK_RSA"
	case C.CKK_DSA:
		return "CKK_DSA"
	case C.CKK_DH:
		return "CKK_DH"
	case C.CKK_EC:
		return "CKK_EC"
	case C.CKK_GENERIC_SECRET:
		return "CKK_GENERIC_SECRET"
	case C.CKK_AES:
		return "CKK_AES"
	default:
		return fmt.Sprintf("CKK_0x%08X", uint32(keyType))
	}
}

// truncateString truncates a string to a maximum length with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// cleanLabel removes trailing spaces from a PKCS#11 label
func cleanLabel(label string) string {
	return strings.TrimRight(label, " ")
}
