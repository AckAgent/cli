package main

// test_bridge.go provides Go-typed wrapper functions for internal PKCS#11 functions.
// This file is needed because _test.go files cannot use import "C" when the package
// contains //export directives. This regular .go file CAN access C types, and test
// files call these wrappers using only pure Go types.
//
// These bridge functions are only used by tests and have zero impact on the
// production shared library since they are not exported.

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
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_STATE;
typedef CK_BYTE* CK_BYTE_PTR;
typedef CK_ULONG* CK_ULONG_PTR;
typedef void* CK_VOID_PTR;

#define CK_TRUE 1
#define CK_FALSE 0

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

typedef struct CK_ECDH1_DERIVE_PARAMS {
    CK_ULONG kdf;
    CK_ULONG ulSharedDataLen;
    CK_BYTE_PTR pSharedData;
    CK_ULONG ulPublicDataLen;
    CK_BYTE_PTR pPublicData;
} CK_ECDH1_DERIVE_PARAMS;
*/
import "C"

import (
	"unsafe"

	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/sysinfo"
)

// ---- Global state helpers ----

// bridgeResetGlobalState resets the global session manager to a clean state.
func bridgeResetGlobalState() {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	sessions.sessions = make(map[C.CK_SESSION_HANDLE]*session)
	sessions.nextHandle = 1
	sessions.initialized = false
}

// bridgeRegisterTestSession creates and registers a test session with the given
// flags, keys, and config, returning the session handle as uint64.
// The cfg parameter must be a valid *config.Config (use newTestConfig in test code).
func bridgeRegisterTestSession(flags uint64, keys []*keyObject, cfg *config.Config) uint64 {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()

	handle := sessions.nextHandle
	sessions.nextHandle++

	sess := &session{
		handle: handle,
		slotID: 0,
		flags:  C.CK_FLAGS(flags),
		state:  sessionPublic,
		cfg:    cfg,
		keys:   keys,
	}
	sessions.sessions[handle] = sess
	return uint64(handle)
}

// bridgeGetSession returns the session for the given handle, or nil if not found.
func bridgeGetSession(handle uint64) *session {
	sessions.mu.RLock()
	defer sessions.mu.RUnlock()
	return sessions.sessions[C.CK_SESSION_HANDLE(handle)]
}

// ---- Initialize / Finalize ----

// bridgeInitialize wraps sessions.initialize().
func bridgeInitialize() uint64 {
	return uint64(sessions.initialize())
}

// bridgeFinalize wraps sessions.finalize().
func bridgeFinalize() uint64 {
	return uint64(sessions.finalize())
}

// bridgeIsInitialized wraps sessions.isInitialized().
func bridgeIsInitialized() bool {
	return sessions.isInitialized()
}

// ---- Session operations ----

// bridgeOpenSession wraps sessions.openSession().
func bridgeOpenSession(slotID, flags uint64) (uint64, uint64) {
	h, rv := sessions.openSession(C.CK_SLOT_ID(slotID), C.CK_FLAGS(flags))
	return uint64(h), uint64(rv)
}

// bridgeCloseSession wraps sessions.closeSession().
func bridgeCloseSession(handle uint64) uint64 {
	return uint64(sessions.closeSession(C.CK_SESSION_HANDLE(handle)))
}

// bridgeCloseAllSessions wraps sessions.closeAllSessions().
func bridgeCloseAllSessions(slotID uint64) uint64 {
	return uint64(sessions.closeAllSessions(C.CK_SLOT_ID(slotID)))
}

// bridgeGetSessionRV wraps sessions.getSession(), returning (session, rv).
func bridgeGetSessionRV(handle uint64) (*session, uint64) {
	s, rv := sessions.getSession(C.CK_SESSION_HANDLE(handle))
	return s, uint64(rv)
}

// ---- Session methods ----

// bridgeLogin wraps sess.login().
func bridgeLogin(sess *session) uint64 {
	return uint64(sess.login())
}

// bridgeLogout wraps sess.logout().
func bridgeLogout(sess *session) uint64 {
	return uint64(sess.logout())
}

// bridgeGetCKState wraps sess.getCKState().
func bridgeGetCKState(sess *session) uint64 {
	return uint64(sess.getCKState())
}

// bridgeGetKey wraps sess.getKey().
func bridgeGetKey(sess *session, handle uint64) *keyObject {
	return sess.getKey(C.CK_OBJECT_HANDLE(handle))
}

// ---- Info functions ----

// bridgeGetInfoResult holds the result of go_C_GetInfo.
type bridgeGetInfoResult struct {
	CryptokiMajor uint8
	CryptokiMinor uint8
	LibraryMajor  uint8
	LibraryMinor  uint8
	Flags         uint64
}

// bridgeGetInfo wraps go_C_GetInfo.
func bridgeGetInfo() (uint64, *bridgeGetInfoResult) {
	var info C.CK_INFO
	rv := go_C_GetInfo(&info)
	return uint64(rv), &bridgeGetInfoResult{
		CryptokiMajor: uint8(info.cryptokiVersion.major),
		CryptokiMinor: uint8(info.cryptokiVersion.minor),
		LibraryMajor:  uint8(info.libraryVersion.major),
		LibraryMinor:  uint8(info.libraryVersion.minor),
		Flags:         uint64(info.flags),
	}
}

// bridgeGetInfoNil wraps go_C_GetInfo with nil.
func bridgeGetInfoNil() uint64 {
	return uint64(go_C_GetInfo(nil))
}

// ---- Slot functions ----

// bridgeGetSlotListCount queries the slot count.
func bridgeGetSlotListCount() (uint64, uint64) {
	var count C.CK_ULONG
	rv := go_C_GetSlotList(1, nil, &count)
	return uint64(rv), uint64(count)
}

// bridgeGetSlotListNilCount calls go_C_GetSlotList with nil pulCount.
func bridgeGetSlotListNilCount() uint64 {
	return uint64(go_C_GetSlotList(1, nil, nil))
}

// bridgeGetSlotListBufferTooSmall calls go_C_GetSlotList with count=0.
func bridgeGetSlotListBufferTooSmall() (uint64, uint64) {
	var slotList C.CK_SLOT_ID
	var count C.CK_ULONG = 0
	rv := go_C_GetSlotList(1, &slotList, &count)
	return uint64(rv), uint64(count)
}

// bridgeGetSlotListSuccess calls go_C_GetSlotList with sufficient buffer.
func bridgeGetSlotListSuccess() (uint64, uint64, uint64) {
	var slotList C.CK_SLOT_ID
	var count C.CK_ULONG = 1
	rv := go_C_GetSlotList(1, &slotList, &count)
	return uint64(rv), uint64(slotList), uint64(count)
}

// bridgeGetSlotInfo wraps go_C_GetSlotInfo.
func bridgeGetSlotInfo(slotID uint64) (uint64, uint64) {
	var info C.CK_SLOT_INFO
	rv := go_C_GetSlotInfo(C.CK_SLOT_ID(slotID), &info)
	return uint64(rv), uint64(info.flags)
}

// bridgeGetSlotInfoNil wraps go_C_GetSlotInfo with nil pInfo.
func bridgeGetSlotInfoNil(slotID uint64) uint64 {
	return uint64(go_C_GetSlotInfo(C.CK_SLOT_ID(slotID), nil))
}

// bridgeTokenInfoResult holds the result of go_C_GetTokenInfo.
type bridgeTokenInfoResult struct {
	Flags     uint64
	MaxPinLen uint64
	MinPinLen uint64
}

// bridgeGetTokenInfo wraps go_C_GetTokenInfo.
func bridgeGetTokenInfo(slotID uint64) (uint64, *bridgeTokenInfoResult) {
	var info C.CK_TOKEN_INFO
	rv := go_C_GetTokenInfo(C.CK_SLOT_ID(slotID), &info)
	return uint64(rv), &bridgeTokenInfoResult{
		Flags:     uint64(info.flags),
		MaxPinLen: uint64(info.ulMaxPinLen),
		MinPinLen: uint64(info.ulMinPinLen),
	}
}

// bridgeGetTokenInfoNil wraps go_C_GetTokenInfo with nil pInfo.
func bridgeGetTokenInfoNil(slotID uint64) uint64 {
	return uint64(go_C_GetTokenInfo(C.CK_SLOT_ID(slotID), nil))
}

// ---- Mechanism functions ----

// bridgeGetMechanismListCount queries the mechanism count.
func bridgeGetMechanismListCount(slotID uint64) (uint64, uint64) {
	var count C.CK_ULONG
	rv := go_C_GetMechanismList(C.CK_SLOT_ID(slotID), nil, &count)
	return uint64(rv), uint64(count)
}

// bridgeGetMechanismListNilCount calls with nil pulCount.
func bridgeGetMechanismListNilCount(slotID uint64) uint64 {
	return uint64(go_C_GetMechanismList(C.CK_SLOT_ID(slotID), nil, nil))
}

// bridgeGetMechanismListBufferTooSmall calls with too-small buffer.
func bridgeGetMechanismListBufferTooSmall(slotID uint64) (uint64, uint64) {
	var mechList [1]C.CK_MECHANISM_TYPE
	var count C.CK_ULONG = 1
	rv := go_C_GetMechanismList(C.CK_SLOT_ID(slotID), &mechList[0], &count)
	return uint64(rv), uint64(count)
}

// bridgeGetMechanismListSuccess retrieves the full mechanism list.
func bridgeGetMechanismListSuccess(slotID uint64) (uint64, []uint64) {
	var mechList [10]C.CK_MECHANISM_TYPE
	var count C.CK_ULONG = 10
	rv := go_C_GetMechanismList(C.CK_SLOT_ID(slotID), &mechList[0], &count)
	result := make([]uint64, int(count))
	for i := 0; i < int(count); i++ {
		result[i] = uint64(mechList[i])
	}
	return uint64(rv), result
}

// bridgeMechInfoResult holds mechanism info fields.
type bridgeMechInfoResult struct {
	MinKeySize uint64
	MaxKeySize uint64
	Flags      uint64
}

// bridgeGetMechanismInfo wraps go_C_GetMechanismInfo.
func bridgeGetMechanismInfo(slotID, mechType uint64) (uint64, *bridgeMechInfoResult) {
	var info C.CK_MECHANISM_INFO
	rv := go_C_GetMechanismInfo(C.CK_SLOT_ID(slotID), C.CK_MECHANISM_TYPE(mechType), &info)
	return uint64(rv), &bridgeMechInfoResult{
		MinKeySize: uint64(info.ulMinKeySize),
		MaxKeySize: uint64(info.ulMaxKeySize),
		Flags:      uint64(info.flags),
	}
}

// bridgeGetMechanismInfoNil wraps go_C_GetMechanismInfo with nil pInfo.
func bridgeGetMechanismInfoNil(slotID, mechType uint64) uint64 {
	return uint64(go_C_GetMechanismInfo(C.CK_SLOT_ID(slotID), C.CK_MECHANISM_TYPE(mechType), nil))
}

// ---- Find objects ----

// bridgeFindObjectsInit wraps findObjectsInit with no template.
func bridgeFindObjectsInit(sessionHandle uint64) uint64 {
	return uint64(findObjectsInit(C.CK_SESSION_HANDLE(sessionHandle), nil, 0))
}

// bridgeFindObjectsInitByClass wraps findObjectsInit with a class filter.
func bridgeFindObjectsInitByClass(sessionHandle, class uint64) uint64 {
	classVal := C.CK_OBJECT_CLASS(class)
	tmpl := C.CK_ATTRIBUTE{
		_type:      C.CK_ATTRIBUTE_TYPE(C.CK_ULONG(0x00000000)), // CKA_CLASS
		pValue:     C.CK_VOID_PTR(unsafe.Pointer(&classVal)),
		ulValueLen: C.CK_ULONG(unsafe.Sizeof(classVal)),
	}
	return uint64(findObjectsInit(C.CK_SESSION_HANDLE(sessionHandle), &tmpl, 1))
}

// bridgeFindObjectsInitByKeyType wraps findObjectsInit with a key type filter.
func bridgeFindObjectsInitByKeyType(sessionHandle, keyType uint64) uint64 {
	keyTypeVal := C.CK_KEY_TYPE(keyType)
	tmpl := C.CK_ATTRIBUTE{
		_type:      C.CK_ATTRIBUTE_TYPE(C.CK_ULONG(0x00000100)), // CKA_KEY_TYPE
		pValue:     C.CK_VOID_PTR(unsafe.Pointer(&keyTypeVal)),
		ulValueLen: C.CK_ULONG(unsafe.Sizeof(keyTypeVal)),
	}
	return uint64(findObjectsInit(C.CK_SESSION_HANDLE(sessionHandle), &tmpl, 1))
}

// bridgeFindObjectsInitByID wraps findObjectsInit with an ID filter.
func bridgeFindObjectsInitByID(sessionHandle uint64, id []byte) uint64 {
	tmpl := C.CK_ATTRIBUTE{
		_type:      C.CK_ATTRIBUTE_TYPE(C.CK_ULONG(0x00000102)), // CKA_ID
		pValue:     C.CK_VOID_PTR(unsafe.Pointer(&id[0])),
		ulValueLen: C.CK_ULONG(len(id)),
	}
	return uint64(findObjectsInit(C.CK_SESSION_HANDLE(sessionHandle), &tmpl, 1))
}

// bridgeFindObjects wraps findObjects, returning (rv, handles).
func bridgeFindObjects(sessionHandle uint64, maxCount int) (uint64, []uint64) {
	objects := make([]C.CK_OBJECT_HANDLE, maxCount)
	var count C.CK_ULONG
	rv := findObjects(C.CK_SESSION_HANDLE(sessionHandle), &objects[0], C.CK_ULONG(maxCount), &count)
	result := make([]uint64, int(count))
	for i := 0; i < int(count); i++ {
		result[i] = uint64(objects[i])
	}
	return uint64(rv), result
}

// bridgeFindObjectsNilArgs wraps findObjects with nil arguments.
func bridgeFindObjectsNilArgs(sessionHandle uint64) uint64 {
	return uint64(findObjects(C.CK_SESSION_HANDLE(sessionHandle), nil, 10, nil))
}

// bridgeFindObjectsFinal wraps findObjectsFinal.
func bridgeFindObjectsFinal(sessionHandle uint64) uint64 {
	return uint64(findObjectsFinal(C.CK_SESSION_HANDLE(sessionHandle)))
}

// ---- Get attribute value ----

// bridgeGetAttrClass retrieves CKA_CLASS for an object.
func bridgeGetAttrClass(sessionHandle, objectHandle uint64) (uint64, uint64) {
	var class C.CK_OBJECT_CLASS
	var attr C.CK_ATTRIBUTE
	attr._type = C.CK_ATTRIBUTE_TYPE(0x00000000) // CKA_CLASS
	attr.pValue = C.CK_VOID_PTR(unsafe.Pointer(&class))
	attr.ulValueLen = C.CK_ULONG(unsafe.Sizeof(class))

	rv := getAttributeValue(C.CK_SESSION_HANDLE(sessionHandle), C.CK_OBJECT_HANDLE(objectHandle), &attr, 1)
	return uint64(rv), uint64(class)
}

// bridgeGetAttrKeyType retrieves CKA_KEY_TYPE for an object.
func bridgeGetAttrKeyType(sessionHandle, objectHandle uint64) (uint64, uint64) {
	var keyType C.CK_KEY_TYPE
	var attr C.CK_ATTRIBUTE
	attr._type = C.CK_ATTRIBUTE_TYPE(0x00000100) // CKA_KEY_TYPE
	attr.pValue = C.CK_VOID_PTR(unsafe.Pointer(&keyType))
	attr.ulValueLen = C.CK_ULONG(unsafe.Sizeof(keyType))

	rv := getAttributeValue(C.CK_SESSION_HANDLE(sessionHandle), C.CK_OBJECT_HANDLE(objectHandle), &attr, 1)
	return uint64(rv), uint64(keyType)
}

// bridgeGetAttrBool retrieves a boolean attribute for an object.
func bridgeGetAttrBool(sessionHandle, objectHandle, attrType uint64) (uint64, bool) {
	var b C.CK_BBOOL
	var attr C.CK_ATTRIBUTE
	attr._type = C.CK_ATTRIBUTE_TYPE(attrType)
	attr.pValue = C.CK_VOID_PTR(unsafe.Pointer(&b))
	attr.ulValueLen = 1

	rv := getAttributeValue(C.CK_SESSION_HANDLE(sessionHandle), C.CK_OBJECT_HANDLE(objectHandle), &attr, 1)
	return uint64(rv), ckToBool(b)
}

// bridgeGetAttrBytes retrieves a byte-array attribute for an object.
func bridgeGetAttrBytes(sessionHandle, objectHandle, attrType uint64, bufSize int) (uint64, []byte, uint64) {
	buf := make([]byte, bufSize)
	var attr C.CK_ATTRIBUTE
	attr._type = C.CK_ATTRIBUTE_TYPE(attrType)
	attr.pValue = C.CK_VOID_PTR(unsafe.Pointer(&buf[0]))
	attr.ulValueLen = C.CK_ULONG(bufSize)

	rv := getAttributeValue(C.CK_SESSION_HANDLE(sessionHandle), C.CK_OBJECT_HANDLE(objectHandle), &attr, 1)
	return uint64(rv), buf[:attr.ulValueLen], uint64(attr.ulValueLen)
}

// bridgeGetAttrSizeQuery queries the size of an attribute without copying data.
func bridgeGetAttrSizeQuery(sessionHandle, objectHandle, attrType uint64) (uint64, uint64) {
	var attr C.CK_ATTRIBUTE
	attr._type = C.CK_ATTRIBUTE_TYPE(attrType)
	attr.pValue = nil
	attr.ulValueLen = 0

	rv := getAttributeValue(C.CK_SESSION_HANDLE(sessionHandle), C.CK_OBJECT_HANDLE(objectHandle), &attr, 1)
	return uint64(rv), uint64(attr.ulValueLen)
}

// bridgeGetAttrBufferTooSmall calls getAttributeValue with a too-small buffer.
func bridgeGetAttrBufferTooSmall(sessionHandle, objectHandle, attrType uint64) uint64 {
	buf := make([]byte, 1)
	var attr C.CK_ATTRIBUTE
	attr._type = C.CK_ATTRIBUTE_TYPE(attrType)
	attr.pValue = C.CK_VOID_PTR(unsafe.Pointer(&buf[0]))
	attr.ulValueLen = 1

	return uint64(getAttributeValue(C.CK_SESSION_HANDLE(sessionHandle), C.CK_OBJECT_HANDLE(objectHandle), &attr, 1))
}

// bridgeGetAttrInvalidObject calls getAttributeValue with a bad object handle.
func bridgeGetAttrInvalidObject(sessionHandle, objectHandle uint64) uint64 {
	var attr C.CK_ATTRIBUTE
	attr._type = C.CK_ATTRIBUTE_TYPE(0x00000000) // CKA_CLASS
	return uint64(getAttributeValue(C.CK_SESSION_HANDLE(sessionHandle), C.CK_OBJECT_HANDLE(objectHandle), &attr, 1))
}

// bridgeGetAttrEmpty calls getAttributeValue with an empty template.
func bridgeGetAttrEmpty(sessionHandle, objectHandle uint64) uint64 {
	return uint64(getAttributeValue(C.CK_SESSION_HANDLE(sessionHandle), C.CK_OBJECT_HANDLE(objectHandle), nil, 0))
}

// bridgeGetAttrUnknownType calls getAttributeValue with an unknown attribute type.
func bridgeGetAttrUnknownType(sessionHandle, objectHandle uint64) uint64 {
	var attr C.CK_ATTRIBUTE
	attr._type = 0xDEADBEEF
	attr.pValue = nil
	attr.ulValueLen = 0

	return uint64(getAttributeValue(C.CK_SESSION_HANDLE(sessionHandle), C.CK_OBJECT_HANDLE(objectHandle), &attr, 1))
}

// ---- Sign operations ----

// bridgeSignInit wraps signInit with a mechanism type.
func bridgeSignInit(sessionHandle, mechType, keyHandle uint64) uint64 {
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(mechType)
	return uint64(signInit(C.CK_SESSION_HANDLE(sessionHandle), &mech, C.CK_OBJECT_HANDLE(keyHandle)))
}

// bridgeSignInitNilMech wraps signInit with nil mechanism.
func bridgeSignInitNilMech(sessionHandle, keyHandle uint64) uint64 {
	return uint64(signInit(C.CK_SESSION_HANDLE(sessionHandle), nil, C.CK_OBJECT_HANDLE(keyHandle)))
}

// bridgeSignSizeQuery queries the required signature length.
func bridgeSignSizeQuery(sessionHandle uint64) (uint64, uint64) {
	var sigLen C.CK_ULONG
	rv := sign(C.CK_SESSION_HANDLE(sessionHandle), nil, 0, nil, &sigLen)
	return uint64(rv), uint64(sigLen)
}

// bridgeSignNotInitialized calls sign without signInit.
func bridgeSignNotInitialized(sessionHandle uint64) uint64 {
	var sigLen C.CK_ULONG
	return uint64(sign(C.CK_SESSION_HANDLE(sessionHandle), nil, 0, nil, &sigLen))
}

// bridgeSignNilSignatureLen calls sign with nil signatureLen.
func bridgeSignNilSignatureLen(sessionHandle uint64) uint64 {
	return uint64(sign(C.CK_SESSION_HANDLE(sessionHandle), nil, 0, nil, nil))
}

// bridgeSignBufferTooSmall calls sign with a too-small output buffer.
func bridgeSignBufferTooSmall(sessionHandle uint64) (uint64, uint64) {
	var sig [1]C.CK_BYTE
	var sigLen C.CK_ULONG = 1
	rv := sign(C.CK_SESSION_HANDLE(sessionHandle), nil, 0, &sig[0], &sigLen)
	return uint64(rv), uint64(sigLen)
}

// bridgeSignBadDataLen calls sign with wrong-size pre-hashed data for CKM_ECDSA.
func bridgeSignBadDataLen(sessionHandle uint64, data []byte) uint64 {
	var sig [64]C.CK_BYTE
	var sigLen C.CK_ULONG = 64
	return uint64(sign(C.CK_SESSION_HANDLE(sessionHandle),
		(*C.CK_BYTE)(unsafe.Pointer(&data[0])), C.CK_ULONG(len(data)),
		&sig[0], &sigLen))
}

// bridgeSignInvalidSession calls sign with an invalid session handle.
func bridgeSignInvalidSession() uint64 {
	var sigLen C.CK_ULONG
	return uint64(sign(999, nil, 0, nil, &sigLen))
}

// bridgeSignUpdate wraps signUpdate.
func bridgeSignUpdate(sessionHandle uint64, data []byte) uint64 {
	if len(data) == 0 {
		return uint64(signUpdate(C.CK_SESSION_HANDLE(sessionHandle), nil, 0))
	}
	return uint64(signUpdate(C.CK_SESSION_HANDLE(sessionHandle),
		(*C.CK_BYTE)(unsafe.Pointer(&data[0])), C.CK_ULONG(len(data))))
}

// bridgeSignUpdateInvalidSession calls signUpdate with an invalid session.
func bridgeSignUpdateInvalidSession() uint64 {
	return uint64(signUpdate(999, nil, 0))
}

// ---- Derive operations ----

// bridgeDeriveKeyInvalidSession calls deriveKey with an invalid session.
func bridgeDeriveKeyInvalidSession() uint64 {
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(0x00001050) // CKM_ECDH1_DERIVE
	var derivedHandle C.CK_OBJECT_HANDLE
	return uint64(deriveKey(999, &mech, 1, nil, 0, &derivedHandle))
}

// bridgeDeriveKeyNilMechanism calls deriveKey with nil mechanism.
func bridgeDeriveKeyNilMechanism(sessionHandle uint64) uint64 {
	var derivedHandle C.CK_OBJECT_HANDLE
	return uint64(deriveKey(C.CK_SESSION_HANDLE(sessionHandle), nil, 1, nil, 0, &derivedHandle))
}

// bridgeDeriveKeyNilDerivedHandle calls deriveKey with nil derivedKeyHandle.
func bridgeDeriveKeyNilDerivedHandle(sessionHandle uint64) uint64 {
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(0x00001050) // CKM_ECDH1_DERIVE
	return uint64(deriveKey(C.CK_SESSION_HANDLE(sessionHandle), &mech, 1, nil, 0, nil))
}

// bridgeDeriveKeyInvalidMechanism calls deriveKey with a non-ECDH mechanism.
func bridgeDeriveKeyInvalidMechanism(sessionHandle uint64, mechType uint64) uint64 {
	var derivedHandle C.CK_OBJECT_HANDLE
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(mechType)
	return uint64(deriveKey(C.CK_SESSION_HANDLE(sessionHandle), &mech, 1, nil, 0, &derivedHandle))
}

// bridgeDeriveKeyNilParameter calls deriveKey with nil mechanism parameter.
func bridgeDeriveKeyNilParameter(sessionHandle uint64) uint64 {
	var derivedHandle C.CK_OBJECT_HANDLE
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(0x00001050) // CKM_ECDH1_DERIVE
	mech.pParameter = nil
	return uint64(deriveKey(C.CK_SESSION_HANDLE(sessionHandle), &mech, 1, nil, 0, &derivedHandle))
}

// bridgeDeriveKeyUnsupportedKDF calls deriveKey with a non-NULL KDF.
func bridgeDeriveKeyUnsupportedKDF(sessionHandle uint64, publicKey []byte, kdf uint64) uint64 {
	var derivedHandle C.CK_OBJECT_HANDLE
	params := C.CK_ECDH1_DERIVE_PARAMS{
		kdf:             C.CK_ULONG(kdf),
		ulPublicDataLen: C.CK_ULONG(len(publicKey)),
		pPublicData:     (*C.CK_BYTE)(unsafe.Pointer(&publicKey[0])),
	}
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(0x00001050) // CKM_ECDH1_DERIVE
	mech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(&params))
	mech.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(params))
	return uint64(deriveKey(C.CK_SESSION_HANDLE(sessionHandle), &mech, 1, nil, 0, &derivedHandle))
}

// bridgeDeriveKeyNilPublicData calls deriveKey with nil public data.
func bridgeDeriveKeyNilPublicData(sessionHandle uint64) uint64 {
	var derivedHandle C.CK_OBJECT_HANDLE
	params := C.CK_ECDH1_DERIVE_PARAMS{
		kdf:             C.CK_ULONG(0x00000001), // CKD_NULL
		ulPublicDataLen: 0,
		pPublicData:     nil,
	}
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(0x00001050) // CKM_ECDH1_DERIVE
	mech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(&params))
	mech.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(params))
	return uint64(deriveKey(C.CK_SESSION_HANDLE(sessionHandle), &mech, 1, nil, 0, &derivedHandle))
}

// bridgeDeriveKeyInvalidPublicKey calls deriveKey with an invalid public key.
func bridgeDeriveKeyInvalidPublicKey(sessionHandle uint64, publicKey []byte) uint64 {
	var derivedHandle C.CK_OBJECT_HANDLE
	params := C.CK_ECDH1_DERIVE_PARAMS{
		kdf:             C.CK_ULONG(0x00000001), // CKD_NULL
		ulPublicDataLen: C.CK_ULONG(len(publicKey)),
		pPublicData:     (*C.CK_BYTE)(unsafe.Pointer(&publicKey[0])),
	}
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(0x00001050) // CKM_ECDH1_DERIVE
	mech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(&params))
	mech.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(params))
	return uint64(deriveKey(C.CK_SESSION_HANDLE(sessionHandle), &mech, 1, nil, 0, &derivedHandle))
}

// bridgeDeriveKeyInvalidBaseKey calls deriveKey with an invalid base key handle.
func bridgeDeriveKeyInvalidBaseKey(sessionHandle uint64, publicKey []byte, baseKeyHandle uint64) uint64 {
	var derivedHandle C.CK_OBJECT_HANDLE
	params := C.CK_ECDH1_DERIVE_PARAMS{
		kdf:             C.CK_ULONG(0x00000001), // CKD_NULL
		ulPublicDataLen: C.CK_ULONG(len(publicKey)),
		pPublicData:     (*C.CK_BYTE)(unsafe.Pointer(&publicKey[0])),
	}
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(0x00001050) // CKM_ECDH1_DERIVE
	mech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(&params))
	mech.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(params))
	return uint64(deriveKey(C.CK_SESSION_HANDLE(sessionHandle), &mech, C.CK_OBJECT_HANDLE(baseKeyHandle), nil, 0, &derivedHandle))
}

// ---- Logging helpers ----

// bridgeCkrToString wraps ckrToString.
func bridgeCkrToString(rv uint64) string {
	return ckrToString(C.CK_RV(rv))
}

// bridgeCkmToString wraps ckmToString.
func bridgeCkmToString(mech uint64) string {
	return ckmToString(C.CK_MECHANISM_TYPE(mech))
}

// bridgeCkaToString wraps ckaToString.
func bridgeCkaToString(attr uint64) string {
	return ckaToString(C.CK_ATTRIBUTE_TYPE(attr))
}

// bridgeCkoToString wraps ckoToString.
func bridgeCkoToString(class uint64) string {
	return ckoToString(C.CK_OBJECT_CLASS(class))
}

// bridgeCkkToString wraps ckkToString.
func bridgeCkkToString(keyType uint64) string {
	return ckkToString(C.CK_KEY_TYPE(keyType))
}

// bridgeKdfToString wraps kdfToString.
func bridgeKdfToString(kdf uint64) string {
	return kdfToString(C.CK_ULONG(kdf))
}

// bridgeBoolToCK wraps boolToCK and returns the result as uint64.
func bridgeBoolToCK(b bool) uint64 {
	return uint64(boolToCK(b))
}

// bridgeCkToBool wraps ckToBool.
func bridgeCkToBool(v uint64) bool {
	return ckToBool(C.CK_BBOOL(v))
}

// ---- Session context helpers (for signCtx/deriveCtx inspection) ----

// bridgeSetSignCtx sets a signing context on the session directly.
func bridgeSetSignCtx(sess *session, mechType, keyHandle uint64) {
	sess.signCtx = &signContext{
		mechanism: C.CK_MECHANISM_TYPE(mechType),
		keyHandle: C.CK_OBJECT_HANDLE(keyHandle),
	}
}

// bridgeSetDeriveCtx sets a derive context on the session directly.
func bridgeSetDeriveCtx(sess *session, mechType, baseKeyHandle uint64) {
	sess.deriveCtx = &deriveContext{
		mechanism:     C.CK_MECHANISM_TYPE(mechType),
		baseKeyHandle: C.CK_OBJECT_HANDLE(baseKeyHandle),
	}
}

// bridgeSetFindActive sets the find-active state on the session.
func bridgeSetFindActive(sess *session, active bool, handles []uint64) {
	sess.findActive = active
	if handles != nil {
		sess.findResults = make([]C.CK_OBJECT_HANDLE, len(handles))
		for i, h := range handles {
			sess.findResults[i] = C.CK_OBJECT_HANDLE(h)
		}
	} else {
		sess.findResults = nil
	}
}

// bridgeGetSignCtxMechanism returns the sign context mechanism type, or 0 if nil.
func bridgeGetSignCtxMechanism(sess *session) uint64 {
	if sess.signCtx == nil {
		return 0
	}
	return uint64(sess.signCtx.mechanism)
}

// bridgeGetSignCtxKeyHandle returns the sign context key handle, or 0 if nil.
func bridgeGetSignCtxKeyHandle(sess *session) uint64 {
	if sess.signCtx == nil {
		return 0
	}
	return uint64(sess.signCtx.keyHandle)
}

// bridgeGetSignCtxData returns the accumulated sign context data, or nil if no context.
func bridgeGetSignCtxData(sess *session) []byte {
	if sess.signCtx == nil {
		return nil
	}
	return sess.signCtx.data
}

// bridgeIsSignCtxNil returns true if signCtx is nil.
func bridgeIsSignCtxNil(sess *session) bool {
	return sess.signCtx == nil
}

// bridgeIsDeriveCtxNil returns true if deriveCtx is nil.
func bridgeIsDeriveCtxNil(sess *session) bool {
	return sess.deriveCtx == nil
}

// bridgeSetSessionFlags sets the flags on a session directly.
func bridgeSetSessionFlags(sess *session, flags uint64) {
	sess.flags = C.CK_FLAGS(flags)
}

// bridgeGetApplicationName wraps getApplicationName for testing.
func bridgeGetApplicationName(processChain []sysinfo.ProcessEntry) string {
	return getApplicationName(processChain)
}

// bridgeParseFingerprint wraps parseFingerprint for testing.
func bridgeParseFingerprint(fp string) []byte {
	return parseFingerprint(fp)
}

// bridgeParseHexByte wraps parseHexByte for testing.
func bridgeParseHexByte(s string) (byte, int) {
	var b byte
	n, _ := parseHexByte(s, &b)
	return b, n
}

// bridgeOpenSession wraps sessions.openSession for testing.
func bridgeOpenSessionDirect(slotID, flags uint64) (uint64, uint64) {
	handle, rv := sessions.openSession(C.CK_SLOT_ID(slotID), C.CK_FLAGS(flags))
	return uint64(handle), uint64(rv)
}

// bridgeCollectSigningDisplay wraps collectSigningDisplay for testing.
func bridgeCollectSigningDisplay(key *config.KeyMetadata, mechanism string, dataLen int) (title string, fieldCount int) {
	display, sourceInfo := collectSigningDisplay(key, mechanism, dataLen)
	_ = sourceInfo
	return display.Title, len(display.Fields)
}

// bridgeCollectDeriveDisplay wraps collectDeriveDisplay for testing.
func bridgeCollectDeriveDisplay(key *config.KeyMetadata, mechanism string, kdf string) (title string, fieldCount int) {
	display, sourceInfo := collectDeriveDisplay(key, mechanism, kdf)
	_ = sourceInfo
	return display.Title, len(display.Fields)
}
