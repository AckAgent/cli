// Package main provides a PKCS#11 shared library for AckAgent.
// Build with: CGO_ENABLED=1 go build -buildmode=c-shared -o libackagent-pkcs11.dylib .
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
typedef CK_RV (*CK_CREATEMUTEX)(CK_VOID_PTR_PTR ppMutex);
typedef CK_RV (*CK_DESTROYMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV (*CK_LOCKMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV (*CK_UNLOCKMUTEX)(CK_VOID_PTR pMutex);

#define CK_TRUE 1
#define CK_FALSE 0
#define CK_INVALID_HANDLE 0
#define CK_UNAVAILABLE_INFORMATION (~0UL)

// Return values
#define CKR_OK                              0x00000000
#define CKR_CANCEL                          0x00000001
#define CKR_HOST_MEMORY                     0x00000002
#define CKR_SLOT_ID_INVALID                 0x00000003
#define CKR_GENERAL_ERROR                   0x00000005
#define CKR_FUNCTION_FAILED                 0x00000006
#define CKR_ARGUMENTS_BAD                   0x00000007
#define CKR_ATTRIBUTE_SENSITIVE             0x00000011
#define CKR_ATTRIBUTE_TYPE_INVALID          0x00000012
#define CKR_DATA_INVALID                    0x00000020
#define CKR_DATA_LEN_RANGE                  0x00000021
#define CKR_DEVICE_ERROR                    0x00000030
#define CKR_KEY_HANDLE_INVALID              0x00000060
#define CKR_KEY_TYPE_INCONSISTENT           0x00000063
#define CKR_MECHANISM_INVALID               0x00000070
#define CKR_MECHANISM_PARAM_INVALID         0x00000071
#define CKR_OBJECT_HANDLE_INVALID           0x00000082
#define CKR_OPERATION_ACTIVE                0x00000090
#define CKR_OPERATION_NOT_INITIALIZED       0x00000091
#define CKR_SESSION_CLOSED                  0x000000B0
#define CKR_SESSION_HANDLE_INVALID          0x000000B3
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED  0x000000B4
#define CKR_TOKEN_NOT_PRESENT               0x000000E0
#define CKR_USER_ALREADY_LOGGED_IN          0x00000100
#define CKR_USER_NOT_LOGGED_IN              0x00000101
#define CKR_USER_PIN_NOT_INITIALIZED        0x00000102
#define CKR_BUFFER_TOO_SMALL                0x00000150
#define CKR_CRYPTOKI_NOT_INITIALIZED        0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED    0x00000191
#define CKR_FUNCTION_NOT_SUPPORTED          0x00000054

// Mechanisms
#define CKM_ECDSA                           0x00001041
#define CKM_ECDSA_SHA256                    0x00001044
#define CKM_ECDH1_DERIVE                    0x00001050

// Mechanism flags
#define CKF_SIGN                            0x00000800
#define CKF_VERIFY                          0x00002000
#define CKF_DERIVE                          0x00080000
#define CKF_EC_F_P                          0x00100000
#define CKF_EC_NAMEDCURVE                   0x00800000

// Token flags
#define CKF_RNG                             0x00000001
#define CKF_WRITE_PROTECTED                 0x00000002
#define CKF_LOGIN_REQUIRED                  0x00000004
#define CKF_USER_PIN_INITIALIZED            0x00000008
#define CKF_TOKEN_INITIALIZED               0x00000400

// Slot flags
#define CKF_TOKEN_PRESENT                   0x00000001
#define CKF_REMOVABLE_DEVICE                0x00000002
#define CKF_HW_SLOT                         0x00000004

// Session flags
#define CKF_RW_SESSION                      0x00000002
#define CKF_SERIAL_SESSION                  0x00000004

// Session states
#define CKS_RO_PUBLIC_SESSION               0
#define CKS_RO_USER_FUNCTIONS               1
#define CKS_RW_PUBLIC_SESSION               2
#define CKS_RW_USER_FUNCTIONS               3

// Structures
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

typedef struct CK_C_INITIALIZE_ARGS {
    CK_CREATEMUTEX CreateMutex;
    CK_DESTROYMUTEX DestroyMutex;
    CK_LOCKMUTEX LockMutex;
    CK_UNLOCKMUTEX UnlockMutex;
    CK_FLAGS flags;
    CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;
typedef CK_C_INITIALIZE_ARGS* CK_C_INITIALIZE_ARGS_PTR;

// Forward declare function list type
struct CK_FUNCTION_LIST;
typedef struct CK_FUNCTION_LIST* CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR* CK_FUNCTION_LIST_PTR_PTR;

// Function pointer types
typedef CK_RV (*CK_C_Initialize)(CK_VOID_PTR pInitArgs);
typedef CK_RV (*CK_C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV (*CK_C_GetInfo)(CK_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV (*CK_C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
typedef CK_RV (*CK_C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
typedef CK_RV (*CK_C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV (*CK_C_InitToken)(CK_SLOT_ID slotID, CK_BYTE_PTR pPin, CK_ULONG ulPinLen, CK_BYTE_PTR pLabel);
typedef CK_RV (*CK_C_InitPIN)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*CK_C_SetPIN)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOldPin, CK_ULONG ulOldLen, CK_BYTE_PTR pNewPin, CK_ULONG ulNewLen);
typedef CK_RV (*CK_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV (*CK_C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CloseAllSessions)(CK_SLOT_ID slotID);
typedef CK_RV (*CK_C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV (*CK_C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV (*CK_C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_BYTE_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*CK_C_Logout)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
typedef CK_RV (*CK_C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV (*CK_C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
typedef CK_RV (*CK_C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
typedef CK_RV (*CK_C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*CK_C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*CK_C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*CK_C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
typedef CK_RV (*CK_C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
typedef CK_RV (*CK_C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_RV (*CK_C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
typedef CK_RV (*CK_C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
typedef CK_RV (*CK_C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*CK_C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*CK_C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (*CK_C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (*CK_C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_RV (*CK_C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
typedef CK_RV (*CK_C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
typedef CK_RV (*CK_C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
typedef CK_RV (*CK_C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);
typedef CK_RV (*CK_C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CancelFunction)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);

// Function list structure
struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_C_Initialize C_Initialize;
    CK_C_Finalize C_Finalize;
    CK_C_GetInfo C_GetInfo;
    CK_C_GetFunctionList C_GetFunctionList;
    CK_C_GetSlotList C_GetSlotList;
    CK_C_GetSlotInfo C_GetSlotInfo;
    CK_C_GetTokenInfo C_GetTokenInfo;
    CK_C_GetMechanismList C_GetMechanismList;
    CK_C_GetMechanismInfo C_GetMechanismInfo;
    CK_C_InitToken C_InitToken;
    CK_C_InitPIN C_InitPIN;
    CK_C_SetPIN C_SetPIN;
    CK_C_OpenSession C_OpenSession;
    CK_C_CloseSession C_CloseSession;
    CK_C_CloseAllSessions C_CloseAllSessions;
    CK_C_GetSessionInfo C_GetSessionInfo;
    CK_C_GetOperationState C_GetOperationState;
    CK_C_SetOperationState C_SetOperationState;
    CK_C_Login C_Login;
    CK_C_Logout C_Logout;
    CK_C_CreateObject C_CreateObject;
    CK_C_CopyObject C_CopyObject;
    CK_C_DestroyObject C_DestroyObject;
    CK_C_GetObjectSize C_GetObjectSize;
    CK_C_GetAttributeValue C_GetAttributeValue;
    CK_C_SetAttributeValue C_SetAttributeValue;
    CK_C_FindObjectsInit C_FindObjectsInit;
    CK_C_FindObjects C_FindObjects;
    CK_C_FindObjectsFinal C_FindObjectsFinal;
    CK_C_EncryptInit C_EncryptInit;
    CK_C_Encrypt C_Encrypt;
    CK_C_EncryptUpdate C_EncryptUpdate;
    CK_C_EncryptFinal C_EncryptFinal;
    CK_C_DecryptInit C_DecryptInit;
    CK_C_Decrypt C_Decrypt;
    CK_C_DecryptUpdate C_DecryptUpdate;
    CK_C_DecryptFinal C_DecryptFinal;
    CK_C_DigestInit C_DigestInit;
    CK_C_Digest C_Digest;
    CK_C_DigestUpdate C_DigestUpdate;
    CK_C_DigestKey C_DigestKey;
    CK_C_DigestFinal C_DigestFinal;
    CK_C_SignInit C_SignInit;
    CK_C_Sign C_Sign;
    CK_C_SignUpdate C_SignUpdate;
    CK_C_SignFinal C_SignFinal;
    CK_C_SignRecoverInit C_SignRecoverInit;
    CK_C_SignRecover C_SignRecover;
    CK_C_VerifyInit C_VerifyInit;
    CK_C_Verify C_Verify;
    CK_C_VerifyUpdate C_VerifyUpdate;
    CK_C_VerifyFinal C_VerifyFinal;
    CK_C_VerifyRecoverInit C_VerifyRecoverInit;
    CK_C_VerifyRecover C_VerifyRecover;
    CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
    CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
    CK_C_SignEncryptUpdate C_SignEncryptUpdate;
    CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
    CK_C_GenerateKey C_GenerateKey;
    CK_C_GenerateKeyPair C_GenerateKeyPair;
    CK_C_WrapKey C_WrapKey;
    CK_C_UnwrapKey C_UnwrapKey;
    CK_C_DeriveKey C_DeriveKey;
    CK_C_SeedRandom C_SeedRandom;
    CK_C_GenerateRandom C_GenerateRandom;
    CK_C_GetFunctionStatus C_GetFunctionStatus;
    CK_C_CancelFunction C_CancelFunction;
    CK_C_WaitForSlotEvent C_WaitForSlotEvent;
};

// Helper to pad a string with spaces
static void padString(CK_BYTE* dst, const char* src, size_t len) {
    size_t srcLen = strlen(src);
    if (srcLen > len) srcLen = len;
    memset(dst, ' ', len);
    memcpy(dst, src, srcLen);
}

// Forward declarations for Go functions
extern CK_RV go_C_Initialize(CK_VOID_PTR pInitArgs);
extern CK_RV go_C_Finalize(CK_VOID_PTR pReserved);
extern CK_RV go_C_GetInfo(CK_INFO_PTR pInfo);
extern CK_RV go_C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
extern CK_RV go_C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
extern CK_RV go_C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
extern CK_RV go_C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
extern CK_RV go_C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
extern CK_RV go_C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
extern CK_RV go_C_CloseSession(CK_SESSION_HANDLE hSession);
extern CK_RV go_C_CloseAllSessions(CK_SLOT_ID slotID);
extern CK_RV go_C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
extern CK_RV go_C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_BYTE_PTR pPin, CK_ULONG ulPinLen);
extern CK_RV go_C_Logout(CK_SESSION_HANDLE hSession);
extern CK_RV go_C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
extern CK_RV go_C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
extern CK_RV go_C_FindObjectsFinal(CK_SESSION_HANDLE hSession);
extern CK_RV go_C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
extern CK_RV go_C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV go_C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
extern CK_RV go_C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
extern CK_RV go_C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
extern CK_RV go_C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);

// Stub for unsupported functions
static CK_RV not_supported() {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// Global function list
static struct CK_FUNCTION_LIST function_list = {
    .version = { 2, 40 },
    .C_Initialize = go_C_Initialize,
    .C_Finalize = go_C_Finalize,
    .C_GetInfo = go_C_GetInfo,
    .C_GetFunctionList = NULL, // Set in init
    .C_GetSlotList = go_C_GetSlotList,
    .C_GetSlotInfo = go_C_GetSlotInfo,
    .C_GetTokenInfo = go_C_GetTokenInfo,
    .C_GetMechanismList = go_C_GetMechanismList,
    .C_GetMechanismInfo = go_C_GetMechanismInfo,
    .C_InitToken = (CK_C_InitToken)not_supported,
    .C_InitPIN = (CK_C_InitPIN)not_supported,
    .C_SetPIN = (CK_C_SetPIN)not_supported,
    .C_OpenSession = go_C_OpenSession,
    .C_CloseSession = go_C_CloseSession,
    .C_CloseAllSessions = go_C_CloseAllSessions,
    .C_GetSessionInfo = go_C_GetSessionInfo,
    .C_GetOperationState = (CK_C_GetOperationState)not_supported,
    .C_SetOperationState = (CK_C_SetOperationState)not_supported,
    .C_Login = go_C_Login,
    .C_Logout = go_C_Logout,
    .C_CreateObject = (CK_C_CreateObject)not_supported,
    .C_CopyObject = (CK_C_CopyObject)not_supported,
    .C_DestroyObject = (CK_C_DestroyObject)not_supported,
    .C_GetObjectSize = (CK_C_GetObjectSize)not_supported,
    .C_GetAttributeValue = go_C_GetAttributeValue,
    .C_SetAttributeValue = (CK_C_SetAttributeValue)not_supported,
    .C_FindObjectsInit = go_C_FindObjectsInit,
    .C_FindObjects = go_C_FindObjects,
    .C_FindObjectsFinal = go_C_FindObjectsFinal,
    .C_EncryptInit = (CK_C_EncryptInit)not_supported,
    .C_Encrypt = (CK_C_Encrypt)not_supported,
    .C_EncryptUpdate = (CK_C_EncryptUpdate)not_supported,
    .C_EncryptFinal = (CK_C_EncryptFinal)not_supported,
    .C_DecryptInit = (CK_C_DecryptInit)not_supported,
    .C_Decrypt = (CK_C_Decrypt)not_supported,
    .C_DecryptUpdate = (CK_C_DecryptUpdate)not_supported,
    .C_DecryptFinal = (CK_C_DecryptFinal)not_supported,
    .C_DigestInit = (CK_C_DigestInit)not_supported,
    .C_Digest = (CK_C_Digest)not_supported,
    .C_DigestUpdate = (CK_C_DigestUpdate)not_supported,
    .C_DigestKey = (CK_C_DigestKey)not_supported,
    .C_DigestFinal = (CK_C_DigestFinal)not_supported,
    .C_SignInit = go_C_SignInit,
    .C_Sign = go_C_Sign,
    .C_SignUpdate = go_C_SignUpdate,
    .C_SignFinal = go_C_SignFinal,
    .C_SignRecoverInit = (CK_C_SignRecoverInit)not_supported,
    .C_SignRecover = (CK_C_SignRecover)not_supported,
    .C_VerifyInit = (CK_C_VerifyInit)not_supported,
    .C_Verify = (CK_C_Verify)not_supported,
    .C_VerifyUpdate = (CK_C_VerifyUpdate)not_supported,
    .C_VerifyFinal = (CK_C_VerifyFinal)not_supported,
    .C_VerifyRecoverInit = (CK_C_VerifyRecoverInit)not_supported,
    .C_VerifyRecover = (CK_C_VerifyRecover)not_supported,
    .C_DigestEncryptUpdate = (CK_C_DigestEncryptUpdate)not_supported,
    .C_DecryptDigestUpdate = (CK_C_DecryptDigestUpdate)not_supported,
    .C_SignEncryptUpdate = (CK_C_SignEncryptUpdate)not_supported,
    .C_DecryptVerifyUpdate = (CK_C_DecryptVerifyUpdate)not_supported,
    .C_GenerateKey = (CK_C_GenerateKey)not_supported,
    .C_GenerateKeyPair = (CK_C_GenerateKeyPair)not_supported,
    .C_WrapKey = (CK_C_WrapKey)not_supported,
    .C_UnwrapKey = (CK_C_UnwrapKey)not_supported,
    .C_DeriveKey = go_C_DeriveKey,
    .C_SeedRandom = (CK_C_SeedRandom)not_supported,
    .C_GenerateRandom = (CK_C_GenerateRandom)not_supported,
    .C_GetFunctionStatus = (CK_C_GetFunctionStatus)not_supported,
    .C_CancelFunction = (CK_C_CancelFunction)not_supported,
    .C_WaitForSlotEvent = (CK_C_WaitForSlotEvent)not_supported,
};

// C_GetFunctionList wrapper that returns the function list
static CK_RV c_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    if (ppFunctionList == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    // Set up the self-reference
    function_list.C_GetFunctionList = c_GetFunctionList;
    *ppFunctionList = &function_list;
    return CKR_OK;
}
*/
import "C"

import "unsafe"

// Required for building as a shared library
func main() {}

//export C_GetFunctionList
func C_GetFunctionList(ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR) C.CK_RV {
	logDebug("C_GetFunctionList called")
	return C.c_GetFunctionList(ppFunctionList)
}

//export go_C_Initialize
func go_C_Initialize(pInitArgs C.CK_VOID_PTR) C.CK_RV {
	logDebug("C_Initialize called")
	return sessions.initialize()
}

//export go_C_Finalize
func go_C_Finalize(pReserved C.CK_VOID_PTR) C.CK_RV {
	logDebug("C_Finalize called")
	return sessions.finalize()
}

//export go_C_GetInfo
func go_C_GetInfo(pInfo C.CK_INFO_PTR) C.CK_RV {
	logDebug("C_GetInfo called")
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	pInfo.cryptokiVersion.major = cryptokiMajor
	pInfo.cryptokiVersion.minor = cryptokiMinor
	C.padString(&pInfo.manufacturerID[0], C.CString(manufacturerID), 32)
	pInfo.flags = 0
	C.padString(&pInfo.libraryDescription[0], C.CString(libraryDescription), 32)
	pInfo.libraryVersion.major = libraryMajor
	pInfo.libraryVersion.minor = libraryMinor

	return C.CKR_OK
}

//export go_C_GetSlotList
func go_C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	logDebug("C_GetSlotList called")
	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// We have exactly one slot
	if pSlotList == nil {
		*pulCount = 1
		return C.CKR_OK
	}

	if *pulCount < 1 {
		*pulCount = 1
		return C.CKR_BUFFER_TOO_SMALL
	}

	*pSlotList = slotID
	*pulCount = 1
	return C.CKR_OK
}

//export go_C_GetSlotInfo
func go_C_GetSlotInfo(sID C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) C.CK_RV {
	logDebug("C_GetSlotInfo called for slot %d", sID)
	if sID != slotID {
		return C.CKR_SLOT_ID_INVALID
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	C.padString(&pInfo.slotDescription[0], C.CString(slotDescription), 64)
	C.padString(&pInfo.manufacturerID[0], C.CString(manufacturerID), 32)
	pInfo.flags = C.CKF_TOKEN_PRESENT | C.CKF_HW_SLOT
	pInfo.hardwareVersion.major = 1
	pInfo.hardwareVersion.minor = 0
	pInfo.firmwareVersion.major = 1
	pInfo.firmwareVersion.minor = 0

	return C.CKR_OK
}

//export go_C_GetTokenInfo
func go_C_GetTokenInfo(sID C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) C.CK_RV {
	logDebug("C_GetTokenInfo called for slot %d", sID)
	if sID != slotID {
		return C.CKR_SLOT_ID_INVALID
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	C.padString(&pInfo.label[0], C.CString(tokenLabel), 32)
	C.padString(&pInfo.manufacturerID[0], C.CString(manufacturerID), 32)
	C.padString(&pInfo.model[0], C.CString(tokenModel), 16)
	C.padString(&pInfo.serialNumber[0], C.CString("000000"), 16)

	pInfo.flags = C.CKF_TOKEN_INITIALIZED | C.CKF_USER_PIN_INITIALIZED | C.CKF_WRITE_PROTECTED
	pInfo.ulMaxSessionCount = C.CK_UNAVAILABLE_INFORMATION
	pInfo.ulSessionCount = C.CK_UNAVAILABLE_INFORMATION
	pInfo.ulMaxRwSessionCount = C.CK_UNAVAILABLE_INFORMATION
	pInfo.ulRwSessionCount = C.CK_UNAVAILABLE_INFORMATION
	pInfo.ulMaxPinLen = 0
	pInfo.ulMinPinLen = 0
	pInfo.ulTotalPublicMemory = C.CK_UNAVAILABLE_INFORMATION
	pInfo.ulFreePublicMemory = C.CK_UNAVAILABLE_INFORMATION
	pInfo.ulTotalPrivateMemory = C.CK_UNAVAILABLE_INFORMATION
	pInfo.ulFreePrivateMemory = C.CK_UNAVAILABLE_INFORMATION
	pInfo.hardwareVersion.major = 1
	pInfo.hardwareVersion.minor = 0
	pInfo.firmwareVersion.major = 1
	pInfo.firmwareVersion.minor = 0
	C.padString(&pInfo.utcTime[0], C.CString(""), 16)

	return C.CKR_OK
}

//export go_C_GetMechanismList
func go_C_GetMechanismList(sID C.CK_SLOT_ID, pMechanismList C.CK_MECHANISM_TYPE_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	logDebug("C_GetMechanismList called for slot %d", sID)
	if sID != slotID {
		return C.CKR_SLOT_ID_INVALID
	}
	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// We support 3 mechanisms: ECDSA, ECDSA_SHA256, ECDH1_DERIVE
	mechanisms := []C.CK_MECHANISM_TYPE{C.CKM_ECDSA, C.CKM_ECDSA_SHA256, C.CKM_ECDH1_DERIVE}

	if pMechanismList == nil {
		*pulCount = C.CK_ULONG(len(mechanisms))
		return C.CKR_OK
	}

	if *pulCount < C.CK_ULONG(len(mechanisms)) {
		*pulCount = C.CK_ULONG(len(mechanisms))
		return C.CKR_BUFFER_TOO_SMALL
	}

	mechSlice := unsafe.Slice(pMechanismList, len(mechanisms))
	for i, m := range mechanisms {
		mechSlice[i] = m
	}
	*pulCount = C.CK_ULONG(len(mechanisms))

	return C.CKR_OK
}

//export go_C_GetMechanismInfo
func go_C_GetMechanismInfo(sID C.CK_SLOT_ID, mechType C.CK_MECHANISM_TYPE, pInfo C.CK_MECHANISM_INFO_PTR) C.CK_RV {
	logDebug("C_GetMechanismInfo called for slot %d, mechanism %s", sID, ckmToString(mechType))
	if sID != slotID {
		return C.CKR_SLOT_ID_INVALID
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	switch mechType {
	case C.CKM_ECDSA, C.CKM_ECDSA_SHA256:
		pInfo.ulMinKeySize = 256
		pInfo.ulMaxKeySize = 256
		pInfo.flags = C.CKF_SIGN | C.CKF_EC_F_P | C.CKF_EC_NAMEDCURVE
	case C.CKM_ECDH1_DERIVE:
		pInfo.ulMinKeySize = 256
		pInfo.ulMaxKeySize = 256
		pInfo.flags = C.CKF_DERIVE | C.CKF_EC_F_P | C.CKF_EC_NAMEDCURVE
	default:
		return C.CKR_MECHANISM_INVALID
	}

	return C.CKR_OK
}

//export go_C_OpenSession
func go_C_OpenSession(sID C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, notify C.CK_NOTIFY, phSession C.CK_SESSION_HANDLE_PTR) C.CK_RV {
	logDebug("C_OpenSession called for slot %d", sID)
	if phSession == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	handle, rv := sessions.openSession(sID, flags)
	if rv != C.CKR_OK {
		return rv
	}

	*phSession = handle
	return C.CKR_OK
}

//export go_C_CloseSession
func go_C_CloseSession(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	logDebug("C_CloseSession called for session %d", hSession)
	return sessions.closeSession(hSession)
}

//export go_C_CloseAllSessions
func go_C_CloseAllSessions(sID C.CK_SLOT_ID) C.CK_RV {
	logDebug("C_CloseAllSessions called for slot %d", sID)
	return sessions.closeAllSessions(sID)
}

//export go_C_GetSessionInfo
func go_C_GetSessionInfo(hSession C.CK_SESSION_HANDLE, pInfo C.CK_SESSION_INFO_PTR) C.CK_RV {
	logDebug("C_GetSessionInfo called for session %d", hSession)
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	sess, rv := sessions.getSession(hSession)
	if rv != C.CKR_OK {
		return rv
	}

	pInfo.slotID = sess.slotID
	pInfo.state = sess.getCKState()
	pInfo.flags = sess.flags
	pInfo.ulDeviceError = 0

	return C.CKR_OK
}

//export go_C_Login
func go_C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_BYTE_PTR, ulPinLen C.CK_ULONG) C.CK_RV {
	logDebug("C_Login called for session %d", hSession)
	sess, rv := sessions.getSession(hSession)
	if rv != C.CKR_OK {
		return rv
	}

	// PIN is ignored - authentication happens via prior ackagent login
	return sess.login()
}

//export go_C_Logout
func go_C_Logout(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	logDebug("C_Logout called for session %d", hSession)
	sess, rv := sessions.getSession(hSession)
	if rv != C.CKR_OK {
		return rv
	}

	return sess.logout()
}

//export go_C_FindObjectsInit
func go_C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	logDebug("C_FindObjectsInit called for session %d", hSession)
	return findObjectsInit(hSession, pTemplate, ulCount)
}

//export go_C_FindObjects
func go_C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG, pulObjectCount C.CK_ULONG_PTR) C.CK_RV {
	logDebug("C_FindObjects called for session %d", hSession)
	return findObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount)
}

//export go_C_FindObjectsFinal
func go_C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	logDebug("C_FindObjectsFinal called for session %d", hSession)
	return findObjectsFinal(hSession)
}

//export go_C_GetAttributeValue
func go_C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	logDebug("C_GetAttributeValue called for session %d, object %d", hSession, hObject)
	return getAttributeValue(hSession, hObject, pTemplate, ulCount)
}

//export go_C_SignInit
func go_C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	logDebug("C_SignInit called for session %d, key %d", hSession, hKey)
	return signInit(hSession, pMechanism, hKey)
}

//export go_C_Sign
func go_C_Sign(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	logDebug("C_Sign called for session %d", hSession)
	return sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
}

//export go_C_SignUpdate
func go_C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) C.CK_RV {
	logDebug("C_SignUpdate called for session %d", hSession)
	return signUpdate(hSession, pPart, ulPartLen)
}

//export go_C_SignFinal
func go_C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	logDebug("C_SignFinal called for session %d", hSession)
	return signFinal(hSession, pSignature, pulSignatureLen)
}

//export go_C_DeriveKey
func go_C_DeriveKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hBaseKey C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	logDebug("C_DeriveKey called for session %d, base key %d", hSession, hBaseKey)
	return deriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey)
}
