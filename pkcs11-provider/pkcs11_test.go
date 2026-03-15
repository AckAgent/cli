package main

import (
	"testing"
)

// TestInitializeFinalize tests the session manager initialize/finalize lifecycle.
func TestInitializeFinalize(t *testing.T) {
	bridgeResetGlobalState()

	// First initialize should succeed
	rv := bridgeInitialize()
	if rv != ckrOK {
		t.Fatalf("initialize() = %s, want CKR_OK", rvName(rv))
	}

	if !bridgeIsInitialized() {
		t.Fatal("isInitialized() = false after initialize")
	}

	// Double initialize should return CKR_CRYPTOKI_ALREADY_INITIALIZED
	rv = bridgeInitialize()
	if rv != ckrCryptokiAlreadyInitialized {
		t.Fatalf("double initialize() = %s, want CKR_CRYPTOKI_ALREADY_INITIALIZED", rvName(rv))
	}

	// Finalize should succeed
	rv = bridgeFinalize()
	if rv != ckrOK {
		t.Fatalf("finalize() = %s, want CKR_OK", rvName(rv))
	}

	if bridgeIsInitialized() {
		t.Fatal("isInitialized() = true after finalize")
	}

	// Double finalize should return CKR_CRYPTOKI_NOT_INITIALIZED
	rv = bridgeFinalize()
	if rv != ckrCryptokiNotInitialized {
		t.Fatalf("double finalize() = %s, want CKR_CRYPTOKI_NOT_INITIALIZED", rvName(rv))
	}
}

// TestInitializeAfterFinalize verifies that re-initialization works after finalize.
func TestInitializeAfterFinalize(t *testing.T) {
	bridgeResetGlobalState()

	rv := bridgeInitialize()
	if rv != ckrOK {
		t.Fatalf("first initialize() = %s, want CKR_OK", rvName(rv))
	}

	rv = bridgeFinalize()
	if rv != ckrOK {
		t.Fatalf("finalize() = %s, want CKR_OK", rvName(rv))
	}

	rv = bridgeInitialize()
	if rv != ckrOK {
		t.Fatalf("re-initialize() = %s, want CKR_OK", rvName(rv))
	}

	bridgeFinalize()
}

// TestGetInfoNilPointer verifies CKR_ARGUMENTS_BAD for nil pInfo pointer.
func TestGetInfoNilPointer(t *testing.T) {
	rv := bridgeGetInfoNil()
	if rv != ckrArgumentsBad {
		t.Fatalf("go_C_GetInfo(nil) = %s, want CKR_ARGUMENTS_BAD", rvName(rv))
	}
}

// TestGetInfoValues verifies the returned info structure fields.
func TestGetInfoValues(t *testing.T) {
	rv, info := bridgeGetInfo()
	if rv != ckrOK {
		t.Fatalf("go_C_GetInfo() = %s, want CKR_OK", rvName(rv))
	}

	if info.CryptokiMajor != cryptokiMajor {
		t.Errorf("cryptokiVersion.major = %d, want %d", info.CryptokiMajor, cryptokiMajor)
	}
	if info.CryptokiMinor != cryptokiMinor {
		t.Errorf("cryptokiVersion.minor = %d, want %d", info.CryptokiMinor, cryptokiMinor)
	}
	if info.LibraryMajor != libraryMajor {
		t.Errorf("libraryVersion.major = %d, want %d", info.LibraryMajor, libraryMajor)
	}
	if info.LibraryMinor != libraryMinor {
		t.Errorf("libraryVersion.minor = %d, want %d", info.LibraryMinor, libraryMinor)
	}
	if info.Flags != 0 {
		t.Errorf("flags = %d, want 0", info.Flags)
	}
}

// TestGetSlotListNilCount verifies CKR_ARGUMENTS_BAD when pulCount is nil.
func TestGetSlotListNilCount(t *testing.T) {
	rv := bridgeGetSlotListNilCount()
	if rv != ckrArgumentsBad {
		t.Fatalf("go_C_GetSlotList(nil count) = %s, want CKR_ARGUMENTS_BAD", rvName(rv))
	}
}

// TestGetSlotListCountOnly verifies slot count query (pSlotList = nil).
func TestGetSlotListCountOnly(t *testing.T) {
	rv, count := bridgeGetSlotListCount()
	if rv != ckrOK {
		t.Fatalf("go_C_GetSlotList(count only) = %s, want CKR_OK", rvName(rv))
	}
	if count != 1 {
		t.Fatalf("slot count = %d, want 1", count)
	}
}

// TestGetSlotListBufferTooSmall verifies CKR_BUFFER_TOO_SMALL when buffer is too small.
func TestGetSlotListBufferTooSmall(t *testing.T) {
	rv, count := bridgeGetSlotListBufferTooSmall()
	if rv != ckrBufferTooSmall {
		t.Fatalf("go_C_GetSlotList(small buffer) = %s, want CKR_BUFFER_TOO_SMALL", rvName(rv))
	}
	if count != 1 {
		t.Fatalf("count after buffer too small = %d, want 1", count)
	}
}

// TestGetSlotListSuccess verifies successful slot list retrieval.
func TestGetSlotListSuccess(t *testing.T) {
	rv, slotList, count := bridgeGetSlotListSuccess()
	if rv != ckrOK {
		t.Fatalf("go_C_GetSlotList() = %s, want CKR_OK", rvName(rv))
	}
	if slotList != 0 {
		t.Fatalf("slotList[0] = %d, want 0", slotList)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
}

// TestGetSlotInfoInvalidSlot verifies CKR_SLOT_ID_INVALID for bad slot ID.
func TestGetSlotInfoInvalidSlot(t *testing.T) {
	rv, _ := bridgeGetSlotInfo(99)
	if rv != ckrSlotIDInvalid {
		t.Fatalf("go_C_GetSlotInfo(99) = %s, want CKR_SLOT_ID_INVALID", rvName(rv))
	}
}

// TestGetSlotInfoNilPointer verifies CKR_ARGUMENTS_BAD for nil pInfo.
func TestGetSlotInfoNilPointer(t *testing.T) {
	rv := bridgeGetSlotInfoNil(0)
	if rv != ckrArgumentsBad {
		t.Fatalf("go_C_GetSlotInfo(nil) = %s, want CKR_ARGUMENTS_BAD", rvName(rv))
	}
}

// TestGetSlotInfoSuccess verifies successful slot info retrieval.
func TestGetSlotInfoSuccess(t *testing.T) {
	rv, flags := bridgeGetSlotInfo(0)
	if rv != ckrOK {
		t.Fatalf("go_C_GetSlotInfo(0) = %s, want CKR_OK", rvName(rv))
	}

	expectedFlags := uint64(ckfTokenPresent | ckfHWSlot)
	if flags != expectedFlags {
		t.Errorf("flags = 0x%x, want 0x%x", flags, expectedFlags)
	}
}

// TestGetTokenInfoInvalidSlot verifies CKR_SLOT_ID_INVALID for bad slot.
func TestGetTokenInfoInvalidSlot(t *testing.T) {
	rv, _ := bridgeGetTokenInfo(99)
	if rv != ckrSlotIDInvalid {
		t.Fatalf("go_C_GetTokenInfo(99) = %s, want CKR_SLOT_ID_INVALID", rvName(rv))
	}
}

// TestGetTokenInfoNilPointer verifies CKR_ARGUMENTS_BAD for nil pInfo.
func TestGetTokenInfoNilPointer(t *testing.T) {
	rv := bridgeGetTokenInfoNil(0)
	if rv != ckrArgumentsBad {
		t.Fatalf("go_C_GetTokenInfo(nil) = %s, want CKR_ARGUMENTS_BAD", rvName(rv))
	}
}

// TestGetTokenInfoSuccess verifies token info fields.
func TestGetTokenInfoSuccess(t *testing.T) {
	rv, info := bridgeGetTokenInfo(0)
	if rv != ckrOK {
		t.Fatalf("go_C_GetTokenInfo(0) = %s, want CKR_OK", rvName(rv))
	}

	expectedFlags := uint64(ckfTokenInitialized | ckfUserPINInitialized | ckfWriteProtected)
	if info.Flags != expectedFlags {
		t.Errorf("flags = 0x%x, want 0x%x", info.Flags, expectedFlags)
	}
	if info.MaxPinLen != 0 || info.MinPinLen != 0 {
		t.Errorf("PIN len: max=%d min=%d, want 0 and 0", info.MaxPinLen, info.MinPinLen)
	}
}

// TestGetMechanismListInvalidSlot verifies CKR_SLOT_ID_INVALID for bad slot.
func TestGetMechanismListInvalidSlot(t *testing.T) {
	rv, _ := bridgeGetMechanismListCount(99)
	if rv != ckrSlotIDInvalid {
		t.Fatalf("go_C_GetMechanismList(99) = %s, want CKR_SLOT_ID_INVALID", rvName(rv))
	}
}

// TestGetMechanismListNilCount verifies CKR_ARGUMENTS_BAD for nil pulCount.
func TestGetMechanismListNilCount(t *testing.T) {
	rv := bridgeGetMechanismListNilCount(0)
	if rv != ckrArgumentsBad {
		t.Fatalf("go_C_GetMechanismList(nil count) = %s, want CKR_ARGUMENTS_BAD", rvName(rv))
	}
}

// TestGetMechanismListCountOnly verifies mechanism count query.
func TestGetMechanismListCountOnly(t *testing.T) {
	rv, count := bridgeGetMechanismListCount(0)
	if rv != ckrOK {
		t.Fatalf("go_C_GetMechanismList(count only) = %s, want CKR_OK", rvName(rv))
	}
	if count != 3 {
		t.Fatalf("mechanism count = %d, want 3", count)
	}
}

// TestGetMechanismListBufferTooSmall verifies CKR_BUFFER_TOO_SMALL.
func TestGetMechanismListBufferTooSmall(t *testing.T) {
	rv, count := bridgeGetMechanismListBufferTooSmall(0)
	if rv != ckrBufferTooSmall {
		t.Fatalf("go_C_GetMechanismList(small buffer) = %s, want CKR_BUFFER_TOO_SMALL", rvName(rv))
	}
	if count != 3 {
		t.Fatalf("count after buffer too small = %d, want 3", count)
	}
}

// TestGetMechanismListSuccess verifies the mechanism list contents.
func TestGetMechanismListSuccess(t *testing.T) {
	rv, mechs := bridgeGetMechanismListSuccess(0)
	if rv != ckrOK {
		t.Fatalf("go_C_GetMechanismList() = %s, want CKR_OK", rvName(rv))
	}
	if len(mechs) != 3 {
		t.Fatalf("count = %d, want 3", len(mechs))
	}

	// Verify mechanisms are present
	wantMechs := map[uint64]bool{
		ckmECDSA:       false,
		ckmECDSASHA256: false,
		ckmECDH1Derive: false,
	}
	for _, m := range mechs {
		if _, ok := wantMechs[m]; ok {
			wantMechs[m] = true
		}
	}
	for m, found := range wantMechs {
		if !found {
			t.Errorf("mechanism 0x%x not found in list", m)
		}
	}
}

// TestGetMechanismInfoECDSA verifies mechanism info for CKM_ECDSA.
func TestGetMechanismInfoECDSA(t *testing.T) {
	rv, info := bridgeGetMechanismInfo(0, ckmECDSA)
	if rv != ckrOK {
		t.Fatalf("go_C_GetMechanismInfo(ECDSA) = %s, want CKR_OK", rvName(rv))
	}
	if info.MinKeySize != 256 || info.MaxKeySize != 256 {
		t.Errorf("key size: min=%d max=%d, want 256 and 256", info.MinKeySize, info.MaxKeySize)
	}
	if info.Flags&ckfSignFlag == 0 {
		t.Error("CKF_SIGN flag not set for CKM_ECDSA")
	}
	if info.Flags&ckfECFP == 0 {
		t.Error("CKF_EC_F_P flag not set for CKM_ECDSA")
	}
}

// TestGetMechanismInfoECDSASHA256 verifies mechanism info for CKM_ECDSA_SHA256.
func TestGetMechanismInfoECDSASHA256(t *testing.T) {
	rv, info := bridgeGetMechanismInfo(0, ckmECDSASHA256)
	if rv != ckrOK {
		t.Fatalf("go_C_GetMechanismInfo(ECDSA_SHA256) = %s, want CKR_OK", rvName(rv))
	}
	if info.Flags&ckfSignFlag == 0 {
		t.Error("CKF_SIGN flag not set for CKM_ECDSA_SHA256")
	}
}

// TestGetMechanismInfoECDH1Derive verifies mechanism info for CKM_ECDH1_DERIVE.
func TestGetMechanismInfoECDH1Derive(t *testing.T) {
	rv, info := bridgeGetMechanismInfo(0, ckmECDH1Derive)
	if rv != ckrOK {
		t.Fatalf("go_C_GetMechanismInfo(ECDH1_DERIVE) = %s, want CKR_OK", rvName(rv))
	}
	if info.Flags&ckfDeriveFlag == 0 {
		t.Error("CKF_DERIVE flag not set for CKM_ECDH1_DERIVE")
	}
}

// TestGetMechanismInfoInvalidMechanism verifies CKR_MECHANISM_INVALID.
func TestGetMechanismInfoInvalidMechanism(t *testing.T) {
	rv, _ := bridgeGetMechanismInfo(0, 0xDEADBEEF)
	if rv != ckrMechanismInvalid {
		t.Fatalf("go_C_GetMechanismInfo(invalid) = %s, want CKR_MECHANISM_INVALID", rvName(rv))
	}
}

// TestGetMechanismInfoInvalidSlot verifies CKR_SLOT_ID_INVALID.
func TestGetMechanismInfoInvalidSlot(t *testing.T) {
	rv, _ := bridgeGetMechanismInfo(99, ckmECDSA)
	if rv != ckrSlotIDInvalid {
		t.Fatalf("go_C_GetMechanismInfo(bad slot) = %s, want CKR_SLOT_ID_INVALID", rvName(rv))
	}
}

// TestGetMechanismInfoNilPointer verifies CKR_ARGUMENTS_BAD for nil pInfo.
func TestGetMechanismInfoNilPointer(t *testing.T) {
	rv := bridgeGetMechanismInfoNil(0, ckmECDSA)
	if rv != ckrArgumentsBad {
		t.Fatalf("go_C_GetMechanismInfo(nil) = %s, want CKR_ARGUMENTS_BAD", rvName(rv))
	}
}
