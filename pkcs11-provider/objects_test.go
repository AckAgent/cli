package main

import (
	"testing"

	"github.com/ackagent/cli/internal/shared/config"
)

// createTestKeys creates a set of test key objects for use in object tests.
func createTestKeys() []*keyObject {
	publicKey := make([]byte, 65)
	publicKey[0] = 0x04
	for i := 1; i < 65; i++ {
		publicKey[i] = byte(i)
	}

	return []*keyObject{
		{
			handle: 1, metadata: &config.KeyMetadata{Label: "SSH Key", PublicKey: []byte{0xaa, 0xbb}, IOSKeyID: "key-1", Algorithm: "ecdsa-sha2-nistp256"},
			publicKey: publicKey, publicKeyHexBytes: []byte{0xaa, 0xbb},
		},
		{
			handle: 2, metadata: &config.KeyMetadata{Label: "GPG Key", PublicKey: []byte{0xcc, 0xdd}, IOSKeyID: "key-2", Algorithm: "ecdsa-sha2-nistp256"},
			publicKey: publicKey, publicKeyHexBytes: []byte{0xcc, 0xdd},
		},
		{
			handle: 3, metadata: &config.KeyMetadata{Label: "Age Key", PublicKey: []byte{0xee, 0xff}, IOSKeyID: "key-3", Algorithm: "ecdsa-sha2-nistp256"},
			publicKey: publicKey, publicKeyHexBytes: []byte{0xee, 0xff},
		},
	}
}

// TestFindObjectsInitInvalidSession verifies session validation.
func TestFindObjectsInitInvalidSession(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	rv := bridgeFindObjectsInit(999)
	if rv != ckrSessionHandleInvalid {
		t.Fatalf("findObjectsInit(invalid session) = %s, want CKR_SESSION_HANDLE_INVALID", rvName(rv))
	}
}

// TestFindObjectsEmptySearch verifies finding all objects with no filter.
func TestFindObjectsEmptySearch(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	keys := createTestKeys()
	handle := testRegisterSession(ckfSerialSession, keys)

	rv := bridgeFindObjectsInit(handle)
	if rv != ckrOK {
		t.Fatalf("findObjectsInit() = %s, want CKR_OK", rvName(rv))
	}

	rv, objects := bridgeFindObjects(handle, 10)
	if rv != ckrOK {
		t.Fatalf("findObjects() = %s, want CKR_OK", rvName(rv))
	}
	if len(objects) != 3 {
		t.Errorf("findObjects count = %d, want 3", len(objects))
	}

	rv = bridgeFindObjectsFinal(handle)
	if rv != ckrOK {
		t.Fatalf("findObjectsFinal() = %s, want CKR_OK", rvName(rv))
	}
}

// TestFindObjectsByClass tests filtering by object class.
func TestFindObjectsByClass(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	keys := createTestKeys()
	handle := testRegisterSession(ckfSerialSession, keys)

	// Search for private keys (should find all)
	rv := bridgeFindObjectsInitByClass(handle, ckoPrivateKey)
	if rv != ckrOK {
		t.Fatalf("findObjectsInit(private key) = %s, want CKR_OK", rvName(rv))
	}

	rv, objects := bridgeFindObjects(handle, 10)
	if rv != ckrOK {
		t.Fatalf("findObjects(private key) = %s, want CKR_OK", rvName(rv))
	}
	if len(objects) != 3 {
		t.Errorf("findObjects(private key) count = %d, want 3", len(objects))
	}
	bridgeFindObjectsFinal(handle)

	// Search for public keys (should find none)
	rv = bridgeFindObjectsInitByClass(handle, ckoPublicKey)
	if rv != ckrOK {
		t.Fatalf("findObjectsInit(public key) = %s, want CKR_OK", rvName(rv))
	}

	rv, objects = bridgeFindObjects(handle, 10)
	if rv != ckrOK {
		t.Fatalf("findObjects(public key) = %s, want CKR_OK", rvName(rv))
	}
	if len(objects) != 0 {
		t.Errorf("findObjects(public key) count = %d, want 0", len(objects))
	}
	bridgeFindObjectsFinal(handle)
}

// TestFindObjectsByKeyType tests filtering by key type.
func TestFindObjectsByKeyType(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	keys := createTestKeys()
	handle := testRegisterSession(ckfSerialSession, keys)

	// Search for EC keys (should find all)
	rv := bridgeFindObjectsInitByKeyType(handle, ckkEC)
	if rv != ckrOK {
		t.Fatalf("findObjectsInit(EC) = %s, want CKR_OK", rvName(rv))
	}

	rv, objects := bridgeFindObjects(handle, 10)
	if rv != ckrOK {
		t.Fatalf("findObjects(EC) = %s, want CKR_OK", rvName(rv))
	}
	if len(objects) != 3 {
		t.Errorf("findObjects(EC) count = %d, want 3", len(objects))
	}
	bridgeFindObjectsFinal(handle)

	// Search for RSA keys (should find none)
	rv = bridgeFindObjectsInitByKeyType(handle, ckkRSA)
	if rv != ckrOK {
		t.Fatalf("findObjectsInit(RSA) = %s, want CKR_OK", rvName(rv))
	}

	rv, objects = bridgeFindObjects(handle, 10)
	if rv != ckrOK {
		t.Fatalf("findObjects(RSA) = %s, want CKR_OK", rvName(rv))
	}
	if len(objects) != 0 {
		t.Errorf("findObjects(RSA) count = %d, want 0", len(objects))
	}
	bridgeFindObjectsFinal(handle)
}

// TestFindObjectsByID tests filtering by ID (fingerprint).
func TestFindObjectsByID(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	keys := createTestKeys()
	handle := testRegisterSession(ckfSerialSession, keys)

	id := []byte{0xee, 0xff}
	rv := bridgeFindObjectsInitByID(handle, id)
	if rv != ckrOK {
		t.Fatalf("findObjectsInit(ID) = %s, want CKR_OK", rvName(rv))
	}

	rv, objects := bridgeFindObjects(handle, 10)
	if rv != ckrOK {
		t.Fatalf("findObjects(ID) = %s, want CKR_OK", rvName(rv))
	}
	if len(objects) != 1 {
		t.Errorf("findObjects(ID=eeff) count = %d, want 1", len(objects))
	}
	if len(objects) > 0 && objects[0] != 3 {
		t.Errorf("findObjects(ID=eeff) handle = %d, want 3", objects[0])
	}
	bridgeFindObjectsFinal(handle)
}

// TestFindObjectsNoMatch verifies empty results when nothing matches.
func TestFindObjectsNoMatch(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	keys := createTestKeys()
	handle := testRegisterSession(ckfSerialSession, keys)

	id := []byte{0xde, 0xad} // No key has this fingerprint
	rv := bridgeFindObjectsInitByID(handle, id)
	if rv != ckrOK {
		t.Fatalf("findObjectsInit(no match) = %s, want CKR_OK", rvName(rv))
	}

	rv, objects := bridgeFindObjects(handle, 10)
	if rv != ckrOK {
		t.Fatalf("findObjects(no match) = %s, want CKR_OK", rvName(rv))
	}
	if len(objects) != 0 {
		t.Errorf("findObjects(no match) count = %d, want 0", len(objects))
	}
	bridgeFindObjectsFinal(handle)
}

// TestFindObjectsDoubleInit verifies CKR_OPERATION_ACTIVE for double init.
func TestFindObjectsDoubleInit(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeys())

	rv := bridgeFindObjectsInit(handle)
	if rv != ckrOK {
		t.Fatalf("first findObjectsInit() = %s, want CKR_OK", rvName(rv))
	}

	rv = bridgeFindObjectsInit(handle)
	if rv != ckrOperationActive {
		t.Fatalf("second findObjectsInit() = %s, want CKR_OPERATION_ACTIVE", rvName(rv))
	}
	bridgeFindObjectsFinal(handle)
}

// TestFindObjectsNotInitialized verifies CKR_OPERATION_NOT_INITIALIZED.
func TestFindObjectsNotInitialized(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, nil)

	rv, _ := bridgeFindObjects(handle, 10)
	if rv != ckrOperationNotInitialized {
		t.Fatalf("findObjects(not init) = %s, want CKR_OPERATION_NOT_INITIALIZED", rvName(rv))
	}
}

// TestFindObjectsFinalNotInitialized verifies CKR_OPERATION_NOT_INITIALIZED for final without init.
func TestFindObjectsFinalNotInitialized(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, nil)

	rv := bridgeFindObjectsFinal(handle)
	if rv != ckrOperationNotInitialized {
		t.Fatalf("findObjectsFinal(not init) = %s, want CKR_OPERATION_NOT_INITIALIZED", rvName(rv))
	}
}

// TestFindObjectsNilArguments verifies CKR_ARGUMENTS_BAD for nil output pointers.
func TestFindObjectsNilArguments(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeys())
	bridgeFindObjectsInit(handle)
	defer bridgeFindObjectsFinal(handle)

	rv := bridgeFindObjectsNilArgs(handle)
	if rv != ckrArgumentsBad {
		t.Fatalf("findObjects(nil args) = %s, want CKR_ARGUMENTS_BAD", rvName(rv))
	}
}

// TestFindObjectsPagination tests returning objects in batches.
func TestFindObjectsPagination(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	keys := createTestKeys()
	handle := testRegisterSession(ckfSerialSession, keys)

	rv := bridgeFindObjectsInit(handle)
	if rv != ckrOK {
		t.Fatalf("findObjectsInit() = %s, want CKR_OK", rvName(rv))
	}

	rv, objects := bridgeFindObjects(handle, 2)
	if rv != ckrOK {
		t.Fatalf("first findObjects() = %s, want CKR_OK", rvName(rv))
	}
	if len(objects) != 2 {
		t.Errorf("first batch count = %d, want 2", len(objects))
	}

	rv, objects = bridgeFindObjects(handle, 2)
	if rv != ckrOK {
		t.Fatalf("second findObjects() = %s, want CKR_OK", rvName(rv))
	}
	if len(objects) != 1 {
		t.Errorf("second batch count = %d, want 1", len(objects))
	}

	rv, objects = bridgeFindObjects(handle, 2)
	if rv != ckrOK {
		t.Fatalf("third findObjects() = %s, want CKR_OK", rvName(rv))
	}
	if len(objects) != 0 {
		t.Errorf("third batch count = %d, want 0", len(objects))
	}
	bridgeFindObjectsFinal(handle)
}

// TestGetAttributeValueInvalidObject verifies CKR_OBJECT_HANDLE_INVALID.
func TestGetAttributeValueInvalidObject(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeys())

	rv := bridgeGetAttrInvalidObject(handle, 999)
	if rv != ckrObjectHandleInvalid {
		t.Fatalf("getAttributeValue(invalid object) = %s, want CKR_OBJECT_HANDLE_INVALID", rvName(rv))
	}
}

// TestGetAttributeValueEmptyTemplate verifies CKR_OK for empty template.
func TestGetAttributeValueEmptyTemplate(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeys())

	rv := bridgeGetAttrEmpty(handle, 1)
	if rv != ckrOK {
		t.Fatalf("getAttributeValue(empty) = %s, want CKR_OK", rvName(rv))
	}
}

// TestGetAttributeValueSizeQuery tests getting attribute size without copying data.
func TestGetAttributeValueSizeQuery(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeys())

	rv, size := bridgeGetAttrSizeQuery(handle, 1, ckaLabel)
	if rv != ckrOK {
		t.Fatalf("getAttributeValue(size query) = %s, want CKR_OK", rvName(rv))
	}

	expectedLen := uint64(len("SSH Key"))
	if size != expectedLen {
		t.Errorf("label size = %d, want %d", size, expectedLen)
	}
}

// TestGetAttributeValueClass tests retrieving CKA_CLASS attribute.
func TestGetAttributeValueClass(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeys())

	rv, class := bridgeGetAttrClass(handle, 1)
	if rv != ckrOK {
		t.Fatalf("getAttributeValue(CLASS) = %s, want CKR_OK", rvName(rv))
	}
	if class != ckoPrivateKey {
		t.Errorf("class = 0x%x, want CKO_PRIVATE_KEY(0x%x)", class, ckoPrivateKey)
	}
}

// TestGetAttributeValueKeyType tests retrieving CKA_KEY_TYPE attribute.
func TestGetAttributeValueKeyType(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeys())

	rv, keyType := bridgeGetAttrKeyType(handle, 1)
	if rv != ckrOK {
		t.Fatalf("getAttributeValue(KEY_TYPE) = %s, want CKR_OK", rvName(rv))
	}
	if keyType != ckkEC {
		t.Errorf("keyType = 0x%x, want CKK_EC(0x%x)", keyType, ckkEC)
	}
}

// TestGetAttributeValueBooleanAttributes tests various boolean attributes.
func TestGetAttributeValueBooleanAttributes(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeys())

	tests := []struct {
		attrType uint64
		name     string
		wantTrue bool
	}{
		{ckaToken, "CKA_TOKEN", true},
		{ckaPrivate, "CKA_PRIVATE", true},
		{ckaSensitive, "CKA_SENSITIVE", true},
		{ckaSign, "CKA_SIGN", true},
		{ckaDerive, "CKA_DERIVE", true},
		{ckaLocal, "CKA_LOCAL", true},
		{ckaNeverExtractable, "CKA_NEVER_EXTRACTABLE", true},
		{ckaAlwaysSensitive, "CKA_ALWAYS_SENSITIVE", true},
		{ckaExtractable, "CKA_EXTRACTABLE", false},
		{ckaModifiable, "CKA_MODIFIABLE", false},
		{ckaAlwaysAuthenticate, "CKA_ALWAYS_AUTHENTICATE", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rv, got := bridgeGetAttrBool(handle, 1, tt.attrType)
			if rv != ckrOK {
				t.Fatalf("getAttributeValue(%s) = %s, want CKR_OK", tt.name, rvName(rv))
			}
			if got != tt.wantTrue {
				t.Errorf("%s = %v, want %v", tt.name, got, tt.wantTrue)
			}
		})
	}
}

// TestGetAttributeValueECParams tests retrieving EC params (P-256 OID).
func TestGetAttributeValueECParams(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeys())

	rv, got, _ := bridgeGetAttrBytes(handle, 1, ckaECParams, 256)
	if rv != ckrOK {
		t.Fatalf("getAttributeValue(EC_PARAMS) = %s, want CKR_OK", rvName(rv))
	}

	if !bytesEqual(got, p256OID) {
		t.Errorf("EC_PARAMS = %x, want %x", got, p256OID)
	}
}

// TestGetAttributeValueECPoint tests retrieving EC point (public key).
func TestGetAttributeValueECPoint(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	keys := createTestKeys()
	handle := testRegisterSession(ckfSerialSession, keys)

	rv, got, _ := bridgeGetAttrBytes(handle, 1, ckaECPoint, 256)
	if rv != ckrOK {
		t.Fatalf("getAttributeValue(EC_POINT) = %s, want CKR_OK", rvName(rv))
	}

	if len(got) != 67 {
		t.Fatalf("EC_POINT length = %d, want 67", len(got))
	}
	if got[0] != 0x04 {
		t.Errorf("EC_POINT[0] = 0x%02x, want 0x04 (OCTET STRING tag)", got[0])
	}
	if got[1] != 0x41 {
		t.Errorf("EC_POINT[1] = 0x%02x, want 0x41 (length 65)", got[1])
	}
	if got[2] != 0x04 {
		t.Errorf("EC_POINT[2] = 0x%02x, want 0x04 (uncompressed point prefix)", got[2])
	}
}

// TestGetAttributeValueSensitive tests that CKA_VALUE returns CKR_ATTRIBUTE_SENSITIVE.
func TestGetAttributeValueSensitive(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeys())

	rv, _ := bridgeGetAttrSizeQuery(handle, 1, ckaValue)
	if rv != ckrAttributeSensitive {
		t.Fatalf("getAttributeValue(VALUE) = %s, want CKR_ATTRIBUTE_SENSITIVE", rvName(rv))
	}
}

// TestGetAttributeValueUnknownType tests that unknown attributes return CKR_ATTRIBUTE_TYPE_INVALID.
func TestGetAttributeValueUnknownType(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeys())

	rv := bridgeGetAttrUnknownType(handle, 1)
	if rv != ckrAttributeTypeInvalid {
		t.Fatalf("getAttributeValue(unknown) = %s, want CKR_ATTRIBUTE_TYPE_INVALID", rvName(rv))
	}
}

// TestGetAttributeValueBufferTooSmall tests CKR_BUFFER_TOO_SMALL when buffer is too small.
func TestGetAttributeValueBufferTooSmall(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeys())

	rv := bridgeGetAttrBufferTooSmall(handle, 1, ckaLabel)
	if rv != ckrBufferTooSmall {
		t.Fatalf("getAttributeValue(small buffer) = %s, want CKR_BUFFER_TOO_SMALL", rvName(rv))
	}
}

// TestBytesEqual tests the bytesEqual helper function.
func TestBytesEqual(t *testing.T) {
	tests := []struct {
		a, b []byte
		want bool
	}{
		{nil, nil, true},
		{[]byte{}, []byte{}, true},
		{[]byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{[]byte{1, 2, 3}, []byte{1, 2, 4}, false},
		{[]byte{1, 2}, []byte{1, 2, 3}, false},
		{nil, []byte{1}, false},
	}

	for _, tt := range tests {
		got := bytesEqual(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("bytesEqual(%x, %x) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
