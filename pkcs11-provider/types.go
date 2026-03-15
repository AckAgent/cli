// Package main provides a PKCS#11 shared library for AckAgent.
// It enables any PKCS#11-compatible application to use hardware-backed
// P-256 ECDSA signing via iOS Secure Enclave.
package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// PKCS#11 base types
typedef uint8_t CK_BYTE;
typedef uint8_t CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef long CK_LONG;
typedef CK_BYTE* CK_BYTE_PTR;
typedef CK_ULONG* CK_ULONG_PTR;
typedef void* CK_VOID_PTR;
typedef void** CK_VOID_PTR_PTR;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_SLOT_ID* CK_SLOT_ID_PTR;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_SESSION_HANDLE* CK_SESSION_HANDLE_PTR;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE* CK_OBJECT_HANDLE_PTR;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_MECHANISM_TYPE* CK_MECHANISM_TYPE_PTR;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_STATE;
typedef CK_ULONG CK_NOTIFICATION;
typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE session, CK_NOTIFICATION event, CK_VOID_PTR pApplication);

// Boolean constants
#define CK_TRUE 1
#define CK_FALSE 0

// Invalid handle
#define CK_INVALID_HANDLE 0

// Return values (CKR_*)
#define CKR_OK                              0x00000000
#define CKR_CANCEL                          0x00000001
#define CKR_HOST_MEMORY                     0x00000002
#define CKR_SLOT_ID_INVALID                 0x00000003
#define CKR_GENERAL_ERROR                   0x00000005
#define CKR_FUNCTION_FAILED                 0x00000006
#define CKR_ARGUMENTS_BAD                   0x00000007
#define CKR_ATTRIBUTE_READ_ONLY             0x00000010
#define CKR_ATTRIBUTE_SENSITIVE             0x00000011
#define CKR_ATTRIBUTE_TYPE_INVALID          0x00000012
#define CKR_ATTRIBUTE_VALUE_INVALID         0x00000013
#define CKR_DATA_INVALID                    0x00000020
#define CKR_DATA_LEN_RANGE                  0x00000021
#define CKR_DEVICE_ERROR                    0x00000030
#define CKR_DEVICE_MEMORY                   0x00000031
#define CKR_DEVICE_REMOVED                  0x00000032
#define CKR_ENCRYPTED_DATA_INVALID          0x00000040
#define CKR_ENCRYPTED_DATA_LEN_RANGE        0x00000041
#define CKR_KEY_HANDLE_INVALID              0x00000060
#define CKR_KEY_SIZE_RANGE                  0x00000062
#define CKR_KEY_TYPE_INCONSISTENT           0x00000063
#define CKR_KEY_NOT_NEEDED                  0x00000064
#define CKR_KEY_CHANGED                     0x00000065
#define CKR_KEY_NEEDED                      0x00000066
#define CKR_KEY_INDIGESTIBLE                0x00000067
#define CKR_KEY_FUNCTION_NOT_PERMITTED      0x00000068
#define CKR_KEY_NOT_WRAPPABLE               0x00000069
#define CKR_KEY_UNEXTRACTABLE               0x0000006A
#define CKR_MECHANISM_INVALID               0x00000070
#define CKR_MECHANISM_PARAM_INVALID         0x00000071
#define CKR_OBJECT_HANDLE_INVALID           0x00000082
#define CKR_OPERATION_ACTIVE                0x00000090
#define CKR_OPERATION_NOT_INITIALIZED       0x00000091
#define CKR_PIN_INCORRECT                   0x000000A0
#define CKR_PIN_INVALID                     0x000000A1
#define CKR_PIN_LEN_RANGE                   0x000000A2
#define CKR_SESSION_CLOSED                  0x000000B0
#define CKR_SESSION_COUNT                   0x000000B1
#define CKR_SESSION_HANDLE_INVALID          0x000000B3
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED  0x000000B4
#define CKR_SESSION_READ_ONLY               0x000000B5
#define CKR_SESSION_EXISTS                  0x000000B6
#define CKR_SESSION_READ_ONLY_EXISTS        0x000000B7
#define CKR_SESSION_READ_WRITE_SO_EXISTS    0x000000B8
#define CKR_SIGNATURE_INVALID               0x000000C0
#define CKR_SIGNATURE_LEN_RANGE             0x000000C1
#define CKR_TEMPLATE_INCOMPLETE             0x000000D0
#define CKR_TEMPLATE_INCONSISTENT           0x000000D1
#define CKR_TOKEN_NOT_PRESENT               0x000000E0
#define CKR_TOKEN_NOT_RECOGNIZED            0x000000E1
#define CKR_TOKEN_WRITE_PROTECTED           0x000000E2
#define CKR_USER_ALREADY_LOGGED_IN          0x00000100
#define CKR_USER_NOT_LOGGED_IN              0x00000101
#define CKR_USER_PIN_NOT_INITIALIZED        0x00000102
#define CKR_USER_TYPE_INVALID               0x00000103
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN  0x00000104
#define CKR_USER_TOO_MANY_TYPES             0x00000105
#define CKR_BUFFER_TOO_SMALL                0x00000150
#define CKR_CRYPTOKI_NOT_INITIALIZED        0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED    0x00000191
#define CKR_FUNCTION_NOT_SUPPORTED          0x00000054

// Mechanism types (CKM_*)
#define CKM_ECDSA                           0x00001041
#define CKM_ECDSA_SHA256                    0x00001044
#define CKM_ECDH1_DERIVE                    0x00001050
#define CKM_ECDH1_COFACTOR_DERIVE           0x00001051

// Key derivation functions (CKD_*)
#define CKD_NULL                            0x00000001
#define CKD_SHA1_KDF                        0x00000002
#define CKD_SHA256_KDF                      0x00000006

// Object classes (CKO_*)
#define CKO_DATA                            0x00000000
#define CKO_CERTIFICATE                     0x00000001
#define CKO_PUBLIC_KEY                      0x00000002
#define CKO_PRIVATE_KEY                     0x00000003
#define CKO_SECRET_KEY                      0x00000004

// Key types (CKK_*)
#define CKK_RSA                             0x00000000
#define CKK_DSA                             0x00000001
#define CKK_DH                              0x00000002
#define CKK_EC                              0x00000003
#define CKK_GENERIC_SECRET                  0x00000010
#define CKK_AES                             0x0000001F

// Attribute types (CKA_*)
#define CKA_CLASS                           0x00000000
#define CKA_TOKEN                           0x00000001
#define CKA_PRIVATE                         0x00000002
#define CKA_LABEL                           0x00000003
#define CKA_APPLICATION                     0x00000010
#define CKA_VALUE                           0x00000011
#define CKA_OBJECT_ID                       0x00000012
#define CKA_CERTIFICATE_TYPE                0x00000080
#define CKA_ISSUER                          0x00000081
#define CKA_SERIAL_NUMBER                   0x00000082
#define CKA_AC_ISSUER                       0x00000083
#define CKA_OWNER                           0x00000084
#define CKA_ATTR_TYPES                      0x00000085
#define CKA_TRUSTED                         0x00000086
#define CKA_KEY_TYPE                        0x00000100
#define CKA_SUBJECT                         0x00000101
#define CKA_ID                              0x00000102
#define CKA_SENSITIVE                       0x00000103
#define CKA_ENCRYPT                         0x00000104
#define CKA_DECRYPT                         0x00000105
#define CKA_WRAP                            0x00000106
#define CKA_UNWRAP                          0x00000107
#define CKA_SIGN                            0x00000108
#define CKA_SIGN_RECOVER                    0x00000109
#define CKA_VERIFY                          0x0000010A
#define CKA_VERIFY_RECOVER                  0x0000010B
#define CKA_DERIVE                          0x0000010C
#define CKA_START_DATE                      0x00000110
#define CKA_END_DATE                        0x00000111
#define CKA_MODULUS                         0x00000120
#define CKA_MODULUS_BITS                    0x00000121
#define CKA_PUBLIC_EXPONENT                 0x00000122
#define CKA_PRIVATE_EXPONENT                0x00000123
#define CKA_PRIME_1                         0x00000124
#define CKA_PRIME_2                         0x00000125
#define CKA_EXPONENT_1                      0x00000126
#define CKA_EXPONENT_2                      0x00000127
#define CKA_COEFFICIENT                     0x00000128
#define CKA_PRIME                           0x00000130
#define CKA_SUBPRIME                        0x00000131
#define CKA_BASE                            0x00000132
#define CKA_PRIME_BITS                      0x00000133
#define CKA_SUBPRIME_BITS                   0x00000134
#define CKA_VALUE_BITS                      0x00000160
#define CKA_VALUE_LEN                       0x00000161
#define CKA_EXTRACTABLE                     0x00000162
#define CKA_LOCAL                           0x00000163
#define CKA_NEVER_EXTRACTABLE               0x00000164
#define CKA_ALWAYS_SENSITIVE                0x00000165
#define CKA_KEY_GEN_MECHANISM               0x00000166
#define CKA_MODIFIABLE                      0x00000170
#define CKA_EC_PARAMS                       0x00000180
#define CKA_EC_POINT                        0x00000181
#define CKA_ALWAYS_AUTHENTICATE             0x00000202

// User types
#define CKU_SO                              0
#define CKU_USER                            1
#define CKU_CONTEXT_SPECIFIC                2

// Session states
#define CKS_RO_PUBLIC_SESSION               0
#define CKS_RO_USER_FUNCTIONS               1
#define CKS_RW_PUBLIC_SESSION               2
#define CKS_RW_USER_FUNCTIONS               3
#define CKS_RW_SO_FUNCTIONS                 4

// Session flags
#define CKF_RW_SESSION                      0x00000002
#define CKF_SERIAL_SESSION                  0x00000004

// Token flags
#define CKF_RNG                             0x00000001
#define CKF_WRITE_PROTECTED                 0x00000002
#define CKF_LOGIN_REQUIRED                  0x00000004
#define CKF_USER_PIN_INITIALIZED            0x00000008
#define CKF_TOKEN_INITIALIZED               0x00000400
#define CKF_HW_SLOT                         0x00000004

// Slot flags
#define CKF_TOKEN_PRESENT                   0x00000001
#define CKF_REMOVABLE_DEVICE                0x00000002

// Mechanism flags
#define CKF_SIGN                            0x00000800
#define CKF_VERIFY                          0x00002000
#define CKF_DERIVE                          0x00080000
#define CKF_EC_F_P                          0x00100000
#define CKF_EC_NAMEDCURVE                   0x00800000

// PKCS#11 structures
typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_BYTE manufacturerID[32];
    CK_FLAGS flags;
    CK_BYTE libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;
typedef CK_INFO* CK_INFO_PTR;

typedef struct CK_SLOT_INFO {
    CK_BYTE slotDescription[64];
    CK_BYTE manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
} CK_SLOT_INFO;
typedef CK_SLOT_INFO* CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO {
    CK_BYTE label[32];
    CK_BYTE manufacturerID[32];
    CK_BYTE model[16];
    CK_BYTE serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_BYTE utcTime[16];
} CK_TOKEN_INFO;
typedef CK_TOKEN_INFO* CK_TOKEN_INFO_PTR;

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;
    CK_STATE state;
    CK_FLAGS flags;
    CK_ULONG ulDeviceError;
} CK_SESSION_INFO;
typedef CK_SESSION_INFO* CK_SESSION_INFO_PTR;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM* CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
} CK_MECHANISM_INFO;
typedef CK_MECHANISM_INFO* CK_MECHANISM_INFO_PTR;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE* CK_ATTRIBUTE_PTR;

// ECDH1 derive params
typedef struct CK_ECDH1_DERIVE_PARAMS {
    CK_ULONG kdf;              // Key derivation function (CKD_NULL, CKD_SHA256_KDF, etc.)
    CK_ULONG ulSharedDataLen;  // Optional shared data length
    CK_BYTE_PTR pSharedData;   // Optional shared data
    CK_ULONG ulPublicDataLen;  // Public key length (65 bytes for uncompressed P-256)
    CK_BYTE_PTR pPublicData;   // Their public key (0x04 || X || Y)
} CK_ECDH1_DERIVE_PARAMS;
typedef CK_ECDH1_DERIVE_PARAMS* CK_ECDH1_DERIVE_PARAMS_PTR;

// Function list structure
struct CK_FUNCTION_LIST;
typedef struct CK_FUNCTION_LIST* CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR* CK_FUNCTION_LIST_PTR_PTR;

// Helper functions for memory management
static void* pkcs11_malloc(size_t size) {
    return calloc(1, size);
}

static void pkcs11_free(void* ptr) {
    free(ptr);
}

static void pkcs11_memcpy(void* dst, const void* src, size_t n) {
    memcpy(dst, src, n);
}

static void pkcs11_memset(void* ptr, int c, size_t n) {
    memset(ptr, c, n);
}

// Helper to pad a string with spaces to a fixed length
static void padString(CK_BYTE* dst, const char* src, size_t len) {
    size_t srcLen = strlen(src);
    if (srcLen > len) srcLen = len;
    memset(dst, ' ', len);
    memcpy(dst, src, srcLen);
}
*/
import "C"

// Constants for internal use
const (
	// Module information
	manufacturerID     = "AckAgent"
	libraryDescription = "AckAgent PKCS#11"

	// Version
	cryptokiMajor = 2
	cryptokiMinor = 40
	libraryMajor  = 1
	libraryMinor  = 0

	// Slot
	slotID          = 0
	slotDescription = "AckAgent iOS Secure Enclave"
	tokenLabel      = "AckAgent"
	tokenModel      = "Secure Enclave"

	// Key sizes for P-256
	p256KeySize      = 256
	p256SignatureLen = 64 // r||s format (32 bytes each)
	p256PublicKeyLen = 65 // PKCS#11 uncompressed format: 0x04 || X (32 bytes) || Y (32 bytes)
	p256PrivateSize  = 32

	// P-256 OID: 1.2.840.10045.3.1.7 (secp256r1/prime256v1)
	// DER encoded: 06 08 2A 86 48 CE 3D 03 01 07
	p256OIDLen = 10
)

// p256OID is the DER-encoded OID for P-256 (secp256r1)
var p256OID = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}

// Convert Go bool to C CK_BBOOL
func boolToCK(b bool) C.CK_BBOOL {
	if b {
		return C.CK_TRUE
	}
	return C.CK_FALSE
}

// Convert C CK_BBOOL to Go bool
func ckToBool(b C.CK_BBOOL) bool {
	return b != C.CK_FALSE
}
