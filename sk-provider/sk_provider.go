package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// SSH SK API version - must match OpenSSH's expected version
#define SSH_SK_VERSION_MAJOR        0x000a0000
#define SSH_SK_VERSION_MAJOR_MASK   0xffff0000

// Algorithms
#define SSH_SK_ECDSA                0x00
#define SSH_SK_ED25519              0x01

// Flags
#define SSH_SK_USER_PRESENCE_REQD       0x01
#define SSH_SK_USER_VERIFICATION_REQD   0x04
#define SSH_SK_FORCE_OPERATION          0x10
#define SSH_SK_RESIDENT_KEY             0x20

// Error codes
#define SSH_SK_ERR_GENERAL              -1
#define SSH_SK_ERR_UNSUPPORTED          -2
#define SSH_SK_ERR_PIN_REQUIRED         -3
#define SSH_SK_ERR_DEVICE_NOT_FOUND     -4
#define SSH_SK_ERR_CREDENTIAL_EXISTS    -5

struct sk_option {
    char *name;
    char *value;
    uint8_t required;
};

struct sk_enroll_response {
    uint8_t flags;
    uint8_t *public_key;
    size_t public_key_len;
    uint8_t *key_handle;
    size_t key_handle_len;
    uint8_t *signature;
    size_t signature_len;
    uint8_t *attestation_cert;
    size_t attestation_cert_len;
    uint8_t *authdata;
    size_t authdata_len;
};

struct sk_sign_response {
    uint8_t flags;
    uint32_t counter;
    uint8_t *sig_r;
    size_t sig_r_len;
    uint8_t *sig_s;
    size_t sig_s_len;
};

struct sk_resident_key {
    uint32_t alg;
    size_t slot;
    char *application;
    struct sk_enroll_response key;
    uint8_t flags;
    uint8_t *user_id;
    size_t user_id_len;
};

// Helper to allocate and copy bytes
static uint8_t* copy_bytes(const uint8_t *src, size_t len) {
    if (src == NULL || len == 0) return NULL;
    uint8_t *dst = (uint8_t*)malloc(len);
    if (dst != NULL) {
        memcpy(dst, src, len);
    }
    return dst;
}
*/
import "C"

/*
SSH SecurityKey Provider for AckAgent

This implements OpenSSH's sk-api.h interface to provide hardware-backed
SSH keys via iOS. See:
- PROTOCOL.u2f: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
- sk-api.h: https://github.com/openssh/openssh-portable/blob/master/sk-api.h

Supported Algorithms
--------------------
- SSH_SK_ECDSA (0x00): P-256 ECDSA, supports Secure Enclave
- SSH_SK_ED25519 (0x01): Ed25519, software-only (iCloud Keychain or local)

Key Handle Format
-----------------
The key handle is an opaque blob from OpenSSH's perspective. We use:

    [4-byte magic][4-byte length LE][JSON payload]

Magic: 0x41505052 ("APPR" in little-endian)
Length: uint32 little-endian, length of JSON payload

JSON payload (KeyHandleData):

	{
	  "v": 1,           // Format version
	  "k": "<uuid>",    // iOS key UUID
	  "d": "<user-id>", // User ID for multi-device lookup
	  "a": "ssh:",      // SSH application string
	  "t": 1705312800   // Unix timestamp of key creation
	}

The iOS Key ID ("k") is used to:
1. Look up which profile contains this key (for relay URL, credentials)
2. Identify the key to iOS for signing operations

Public Key Format
-----------------
P-256 ECDSA: Config stores 33 bytes compressed (0x02/0x03 || X).
             We decompress to SEC1 uncompressed (65 bytes: 0x04 || X || Y) for OpenSSH.
Ed25519:     Config stores 32 bytes (the public key directly, no prefix).

Signature Format
----------------
P-256 ECDSA: iOS returns 64 bytes (r || s, each 32 bytes).
Ed25519:     iOS returns 64 bytes (the complete Ed25519 signature).
*/

import (
	"unsafe"
)

// Debug logging is defined in sysinfo.go

//export sk_api_version
func sk_api_version() C.uint32_t {
	logDebug("sk_api_version called")
	return C.SSH_SK_VERSION_MAJOR
}

//export sk_enroll
func sk_enroll(
	alg C.uint32_t,
	challenge *C.uint8_t,
	challenge_len C.size_t,
	application *C.char,
	flags C.uint8_t,
	pin *C.char,
	options **C.struct_sk_option,
	enroll_response **C.struct_sk_enroll_response,
) C.int {
	logDebug("sk_enroll called: alg=%d, flags=0x%02x", alg, flags)

	app := "ssh:"
	if application != nil {
		app = C.GoString(application)
	}

	var challengeBytes []byte
	if challenge != nil && challenge_len > 0 {
		challengeBytes = C.GoBytes(unsafe.Pointer(challenge), C.int(challenge_len))
	}

	result, errCode := executeEnroll(uint32(alg), challengeBytes, app, uint8(flags))
	if errCode != 0 {
		return C.int(errCode)
	}

	cResp := (*C.struct_sk_enroll_response)(C.calloc(1, C.sizeof_struct_sk_enroll_response))
	cResp.flags = C.uint8_t(flags)

	cResp.public_key_len = C.size_t(len(result.publicKey))
	if len(result.publicKey) > 0 {
		cResp.public_key = C.copy_bytes((*C.uint8_t)(unsafe.Pointer(&result.publicKey[0])), cResp.public_key_len)
	}

	cResp.key_handle_len = C.size_t(len(result.keyHandle))
	if len(result.keyHandle) > 0 {
		cResp.key_handle = C.copy_bytes((*C.uint8_t)(unsafe.Pointer(&result.keyHandle[0])), cResp.key_handle_len)
	}

	if len(result.signature) > 0 {
		cResp.signature_len = C.size_t(len(result.signature))
		cResp.signature = C.copy_bytes((*C.uint8_t)(unsafe.Pointer(&result.signature[0])), cResp.signature_len)
	}
	if len(result.attestationCert) > 0 {
		cResp.attestation_cert_len = C.size_t(len(result.attestationCert))
		cResp.attestation_cert = C.copy_bytes((*C.uint8_t)(unsafe.Pointer(&result.attestationCert[0])), cResp.attestation_cert_len)
	}

	*enroll_response = cResp
	logDebug("enrollment successful")
	return 0
}

//export sk_sign
func sk_sign(
	alg C.uint32_t,
	data *C.uint8_t,
	data_len C.size_t,
	application *C.char,
	key_handle *C.uint8_t,
	key_handle_len C.size_t,
	flags C.uint8_t,
	pin *C.char,
	options **C.struct_sk_option,
	sign_response **C.struct_sk_sign_response,
) C.int {
	logDebug("sk_sign called: alg=%d, flags=0x%02x", alg, flags)

	dataBytes := C.GoBytes(unsafe.Pointer(data), C.int(data_len))
	keyHandleBytes := C.GoBytes(unsafe.Pointer(key_handle), C.int(key_handle_len))

	app := "ssh:"
	if application != nil {
		app = C.GoString(application)
	}

	result, errCode := executeSign(uint32(alg), dataBytes, app, keyHandleBytes, uint8(flags))
	if errCode != 0 {
		return C.int(errCode)
	}

	cResp := (*C.struct_sk_sign_response)(C.calloc(1, C.sizeof_struct_sk_sign_response))
	cResp.flags = C.uint8_t(flags)
	cResp.counter = C.uint32_t(result.counter)

	if alg == C.SSH_SK_ED25519 {
		cResp.sig_r_len = C.size_t(len(result.signature))
		cResp.sig_r = C.copy_bytes((*C.uint8_t)(unsafe.Pointer(&result.signature[0])), cResp.sig_r_len)
		cResp.sig_s_len = 0
		cResp.sig_s = nil
	} else {
		sigR := result.signature[:32]
		sigS := result.signature[32:]
		cResp.sig_r_len = C.size_t(len(sigR))
		cResp.sig_r = C.copy_bytes((*C.uint8_t)(unsafe.Pointer(&sigR[0])), cResp.sig_r_len)
		cResp.sig_s_len = C.size_t(len(sigS))
		cResp.sig_s = C.copy_bytes((*C.uint8_t)(unsafe.Pointer(&sigS[0])), cResp.sig_s_len)
	}

	*sign_response = cResp
	logDebug("signing successful")
	return 0
}

//export sk_load_resident_keys
func sk_load_resident_keys(
	pin *C.char,
	options **C.struct_sk_option,
	rks ***C.struct_sk_resident_key,
	nrks *C.size_t,
) C.int {
	logDebug("sk_load_resident_keys called")
	// Resident keys are stored on iOS, not locally
	// Return empty list
	*nrks = 0
	return 0
}

func main() {
	// Required for c-shared build mode
}
