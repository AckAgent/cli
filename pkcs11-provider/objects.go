package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t CK_BYTE;
typedef uint8_t CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE* CK_OBJECT_HANDLE_PTR;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef void* CK_VOID_PTR;

#define CK_TRUE 1
#define CK_FALSE 0

// Return values
#define CKR_OK                              0x00000000
#define CKR_ARGUMENTS_BAD                   0x00000007
#define CKR_ATTRIBUTE_SENSITIVE             0x00000011
#define CKR_ATTRIBUTE_TYPE_INVALID          0x00000012
#define CKR_OBJECT_HANDLE_INVALID           0x00000082
#define CKR_OPERATION_ACTIVE                0x00000090
#define CKR_OPERATION_NOT_INITIALIZED       0x00000091
#define CKR_SESSION_HANDLE_INVALID          0x000000B3
#define CKR_BUFFER_TOO_SMALL                0x00000150
#define CKR_CRYPTOKI_NOT_INITIALIZED        0x00000190

// Object classes
#define CKO_PUBLIC_KEY                      0x00000002
#define CKO_PRIVATE_KEY                     0x00000003
#define CKO_SECRET_KEY                      0x00000004

// Key types
#define CKK_EC                              0x00000003
#define CKK_GENERIC_SECRET                  0x00000010

// Attributes
#define CKA_CLASS                           0x00000000
#define CKA_TOKEN                           0x00000001
#define CKA_PRIVATE                         0x00000002
#define CKA_LABEL                           0x00000003
#define CKA_ID                              0x00000102
#define CKA_KEY_TYPE                        0x00000100
#define CKA_SENSITIVE                       0x00000103
#define CKA_SIGN                            0x00000108
#define CKA_DERIVE                          0x0000010C
#define CKA_EC_PARAMS                       0x00000180
#define CKA_EC_POINT                        0x00000181
#define CKA_EXTRACTABLE                     0x00000162
#define CKA_NEVER_EXTRACTABLE               0x00000164
#define CKA_ALWAYS_SENSITIVE                0x00000165
#define CKA_LOCAL                           0x00000163
#define CKA_MODIFIABLE                      0x00000170
#define CKA_VALUE                           0x00000011
#define CKA_VALUE_LEN                       0x00000161
#define CKA_ALWAYS_AUTHENTICATE             0x00000202

// Attribute structure
typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE* CK_ATTRIBUTE_PTR;
*/
import "C"

import (
	"unsafe"
)

// findObjectsInit initializes an object search
func findObjectsInit(sessionHandle C.CK_SESSION_HANDLE, template C.CK_ATTRIBUTE_PTR, count C.CK_ULONG) C.CK_RV {
	sess, rv := sessions.getSession(sessionHandle)
	if rv != C.CKR_OK {
		return rv
	}

	if sess.findActive {
		return C.CKR_OPERATION_ACTIVE
	}

	// Parse template to filter keys
	var wantClass C.CK_OBJECT_CLASS = 0xFFFFFFFF // "any"
	var wantKeyType C.CK_KEY_TYPE = 0xFFFFFFFF   // "any"
	var wantLabel string
	var wantID []byte

	if count > 0 && template != nil {
		attrs := unsafe.Slice(template, count)
		for _, attr := range attrs {
			switch attr._type {
			case C.CKA_CLASS:
				if attr.pValue != nil && attr.ulValueLen == C.CK_ULONG(unsafe.Sizeof(C.CK_OBJECT_CLASS(0))) {
					wantClass = *(*C.CK_OBJECT_CLASS)(attr.pValue)
				}
			case C.CKA_KEY_TYPE:
				if attr.pValue != nil && attr.ulValueLen == C.CK_ULONG(unsafe.Sizeof(C.CK_KEY_TYPE(0))) {
					wantKeyType = *(*C.CK_KEY_TYPE)(attr.pValue)
				}
			case C.CKA_LABEL:
				if attr.pValue != nil && attr.ulValueLen > 0 {
					wantLabel = C.GoStringN((*C.char)(attr.pValue), C.int(attr.ulValueLen))
				}
			case C.CKA_ID:
				if attr.pValue != nil && attr.ulValueLen > 0 {
					wantID = C.GoBytes(unsafe.Pointer(attr.pValue), C.int(attr.ulValueLen))
				}
			}
		}
	}

	logDebug("FindObjectsInit: class=%s keyType=%s label=%q id=%x",
		ckoToString(wantClass), ckkToString(wantKeyType), wantLabel, wantID)

	// Find matching keys
	var results []C.CK_OBJECT_HANDLE
	for _, key := range sess.keys {
		// Filter by class (we only have private keys)
		if wantClass != 0xFFFFFFFF && wantClass != C.CKO_PRIVATE_KEY {
			continue
		}

		// Filter by key type (we only have EC keys)
		if wantKeyType != 0xFFFFFFFF && wantKeyType != C.CKK_EC {
			continue
		}

		// Filter by label
		if wantLabel != "" && key.metadata.Label != wantLabel {
			continue
		}

		// Filter by ID (public key hex)
		if len(wantID) > 0 && !bytesEqual(key.publicKeyHexBytes, wantID) {
			continue
		}

		results = append(results, key.handle)
	}

	sess.findActive = true
	sess.findResults = results
	sess.findIndex = 0

	logDebug("FindObjectsInit: found %d objects", len(results))
	return C.CKR_OK
}

// findObjects returns objects matching the search criteria
func findObjects(sessionHandle C.CK_SESSION_HANDLE, objects C.CK_OBJECT_HANDLE_PTR, maxCount C.CK_ULONG, count *C.CK_ULONG) C.CK_RV {
	sess, rv := sessions.getSession(sessionHandle)
	if rv != C.CKR_OK {
		return rv
	}

	if !sess.findActive {
		return C.CKR_OPERATION_NOT_INITIALIZED
	}

	if objects == nil || count == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Return up to maxCount objects
	objSlice := unsafe.Slice(objects, maxCount)
	returned := C.CK_ULONG(0)

	for returned < maxCount && sess.findIndex < len(sess.findResults) {
		objSlice[returned] = sess.findResults[sess.findIndex]
		sess.findIndex++
		returned++
	}

	*count = returned
	logDebug("FindObjects: returned %d objects", returned)
	return C.CKR_OK
}

// findObjectsFinal ends the object search
func findObjectsFinal(sessionHandle C.CK_SESSION_HANDLE) C.CK_RV {
	sess, rv := sessions.getSession(sessionHandle)
	if rv != C.CKR_OK {
		return rv
	}

	if !sess.findActive {
		return C.CKR_OPERATION_NOT_INITIALIZED
	}

	sess.findActive = false
	sess.findResults = nil
	sess.findIndex = 0

	logDebug("FindObjectsFinal")
	return C.CKR_OK
}

// getAttributeValue returns attributes of an object
func getAttributeValue(sessionHandle C.CK_SESSION_HANDLE, objectHandle C.CK_OBJECT_HANDLE, template C.CK_ATTRIBUTE_PTR, count C.CK_ULONG) C.CK_RV {
	sess, rv := sessions.getSession(sessionHandle)
	if rv != C.CKR_OK {
		return rv
	}

	key := sess.getKey(objectHandle)
	if key == nil {
		return C.CKR_OBJECT_HANDLE_INVALID
	}

	if count == 0 || template == nil {
		return C.CKR_OK
	}

	attrs := unsafe.Slice(template, count)
	allOK := C.CKR_OK

	for i := range attrs {
		attr := &attrs[i]
		var value []byte
		var valueLen C.CK_ULONG
		sensitive := false

		switch attr._type {
		case C.CKA_CLASS:
			class := C.CK_OBJECT_CLASS(C.CKO_PRIVATE_KEY)
			value = (*[8]byte)(unsafe.Pointer(&class))[:unsafe.Sizeof(class)]
			valueLen = C.CK_ULONG(unsafe.Sizeof(class))

		case C.CKA_KEY_TYPE:
			keyType := C.CK_KEY_TYPE(C.CKK_EC)
			value = (*[8]byte)(unsafe.Pointer(&keyType))[:unsafe.Sizeof(keyType)]
			valueLen = C.CK_ULONG(unsafe.Sizeof(keyType))

		case C.CKA_TOKEN:
			b := C.CK_BBOOL(C.CK_TRUE)
			value = (*[1]byte)(unsafe.Pointer(&b))[:1]
			valueLen = 1

		case C.CKA_PRIVATE:
			b := C.CK_BBOOL(C.CK_TRUE)
			value = (*[1]byte)(unsafe.Pointer(&b))[:1]
			valueLen = 1

		case C.CKA_SENSITIVE:
			b := C.CK_BBOOL(C.CK_TRUE)
			value = (*[1]byte)(unsafe.Pointer(&b))[:1]
			valueLen = 1

		case C.CKA_EXTRACTABLE:
			b := C.CK_BBOOL(C.CK_FALSE)
			value = (*[1]byte)(unsafe.Pointer(&b))[:1]
			valueLen = 1

		case C.CKA_NEVER_EXTRACTABLE:
			b := C.CK_BBOOL(C.CK_TRUE)
			value = (*[1]byte)(unsafe.Pointer(&b))[:1]
			valueLen = 1

		case C.CKA_ALWAYS_SENSITIVE:
			b := C.CK_BBOOL(C.CK_TRUE)
			value = (*[1]byte)(unsafe.Pointer(&b))[:1]
			valueLen = 1

		case C.CKA_LOCAL:
			b := C.CK_BBOOL(C.CK_TRUE)
			value = (*[1]byte)(unsafe.Pointer(&b))[:1]
			valueLen = 1

		case C.CKA_MODIFIABLE:
			b := C.CK_BBOOL(C.CK_FALSE)
			value = (*[1]byte)(unsafe.Pointer(&b))[:1]
			valueLen = 1

		case C.CKA_SIGN:
			b := C.CK_BBOOL(C.CK_TRUE)
			value = (*[1]byte)(unsafe.Pointer(&b))[:1]
			valueLen = 1

		case C.CKA_DERIVE:
			b := C.CK_BBOOL(C.CK_TRUE)
			value = (*[1]byte)(unsafe.Pointer(&b))[:1]
			valueLen = 1

		case C.CKA_ALWAYS_AUTHENTICATE:
			b := C.CK_BBOOL(C.CK_FALSE)
			value = (*[1]byte)(unsafe.Pointer(&b))[:1]
			valueLen = 1

		case C.CKA_LABEL:
			label := key.metadata.Label
			value = []byte(label)
			valueLen = C.CK_ULONG(len(label))

		case C.CKA_ID:
			value = key.publicKeyHexBytes
			valueLen = C.CK_ULONG(len(key.publicKeyHexBytes))

		case C.CKA_EC_PARAMS:
			// Return P-256 OID
			value = p256OID
			valueLen = C.CK_ULONG(len(p256OID))

		case C.CKA_EC_POINT:
			// Return SEC1 uncompressed public key wrapped in OCTET STRING
			// Format: 04 41 04 <X> <Y>
			// (DER OCTET STRING tag 04, length 65 (0x41), then 04 || X || Y)
			wrapped := make([]byte, 2+len(key.publicKey))
			wrapped[0] = 0x04 // OCTET STRING tag
			wrapped[1] = byte(len(key.publicKey))
			copy(wrapped[2:], key.publicKey)
			value = wrapped
			valueLen = C.CK_ULONG(len(wrapped))

		case C.CKA_VALUE:
			// Private key value - always sensitive
			sensitive = true
			attr.ulValueLen = C.CK_ULONG(0xFFFFFFFF)
			allOK = C.CKR_ATTRIBUTE_SENSITIVE
			continue

		default:
			// Unknown attribute
			attr.ulValueLen = C.CK_ULONG(0xFFFFFFFF)
			if allOK == C.CKR_OK {
				allOK = C.CKR_ATTRIBUTE_TYPE_INVALID
			}
			continue
		}

		// Handle sensitive attributes
		if sensitive {
			attr.ulValueLen = C.CK_ULONG(0xFFFFFFFF)
			allOK = C.CKR_ATTRIBUTE_SENSITIVE
			continue
		}

		// If pValue is NULL, just return the size
		if attr.pValue == nil {
			attr.ulValueLen = valueLen
			continue
		}

		// Check buffer size
		if attr.ulValueLen < valueLen {
			attr.ulValueLen = valueLen
			if allOK == C.CKR_OK {
				allOK = C.CKR_BUFFER_TOO_SMALL
			}
			continue
		}

		// Copy value
		if len(value) > 0 {
			C.memcpy(unsafe.Pointer(attr.pValue), unsafe.Pointer(&value[0]), C.size_t(valueLen))
		}
		attr.ulValueLen = valueLen
	}

	return C.CK_RV(allOK)
}

// bytesEqual compares two byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
