// Package crypto provides cryptographic operations for the CLI.
//
// bbsverify.go provides BBS+ proof verification via the Rust bbs-ffi static library.
// This is the CLI-side counterpart to the backend's credential-issuer BBS signer,
// used to verify anonymous attestation proofs from approver devices.
//
// Build requirements:
//   - CGO_ENABLED=1
//   - libbbs_ffi.a must be built first (cd bbs-ffi && make static-lib)

package crypto

/*
#cgo CFLAGS: -I${SRCDIR}/../deps/bbs-ffi/include
#cgo LDFLAGS: ${SRCDIR}/../deps/bbs-ffi/lib/libbbs_ffi.a -lm -ldl -lpthread
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation

#include "bbs_ffi.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// bbsVerifyProofWithPseudonym verifies a BBS+ selective disclosure proof with pseudonym
// via the Rust FFI. This is used to verify anonymous attestation proofs.
//
// Parameters:
//   - issuerPublicKey: 96-byte BLS12-381 G2 issuer public key
//   - proof: serialized BBS+ proof bytes
//   - pseudonym: 48-byte scope-bound pseudonym (compressed G1 point)
//   - header: application-specific header bytes
//   - presentationHeader: presentation-specific binding bytes
//   - scope: scope for pseudonym verification (e.g., request ID)
//   - totalSignerMessages: total count of issuer-signed messages in the credential
//   - disclosedMessages: revealed message byte arrays
//   - disclosedIndices: indices of disclosed messages in the credential vector
//
// Returns nil if the proof is valid, or an error describing the failure.
func bbsVerifyProofWithPseudonym(
	issuerPublicKey, proof, pseudonym, header, presentationHeader, scope []byte,
	totalSignerMessages int,
	disclosedMessages [][]byte,
	disclosedIndices []int,
) error {
	if len(issuerPublicKey) == 0 {
		return fmt.Errorf("issuer public key is required")
	}
	if len(proof) == 0 {
		return fmt.Errorf("proof is required")
	}
	if len(pseudonym) == 0 {
		return fmt.Errorf("pseudonym is required")
	}
	if len(scope) == 0 {
		return fmt.Errorf("scope is required")
	}

	// Pin all Go memory that will be passed to C.
	var pinner runtime.Pinner
	defer pinner.Unpin()

	pinner.Pin(&issuerPublicKey[0])
	pinner.Pin(&proof[0])
	pinner.Pin(&pseudonym[0])
	pinner.Pin(&scope[0])

	// Header and presentationHeader may be empty; only pin if non-empty.
	var headerPtr *C.uint8_t
	headerLen := C.size_t(0)
	if len(header) > 0 {
		pinner.Pin(&header[0])
		headerPtr = (*C.uint8_t)(unsafe.Pointer(&header[0]))
		headerLen = C.size_t(len(header))
	}

	var phPtr *C.uint8_t
	phLen := C.size_t(0)
	if len(presentationHeader) > 0 {
		pinner.Pin(&presentationHeader[0])
		phPtr = (*C.uint8_t)(unsafe.Pointer(&presentationHeader[0]))
		phLen = C.size_t(len(presentationHeader))
	}

	// Prepare disclosed messages array.
	cMsgs := make([]C.BbsMessage, len(disclosedMessages))
	for i, msg := range disclosedMessages {
		if len(msg) > 0 {
			pinner.Pin(&msg[0])
			cMsgs[i] = C.BbsMessage{
				data: (*C.uint8_t)(unsafe.Pointer(&msg[0])),
				len:  C.size_t(len(msg)),
			}
		} else {
			cMsgs[i] = C.BbsMessage{
				data: nil,
				len:  0,
			}
		}
	}

	var msgsPtr *C.BbsMessage
	if len(cMsgs) > 0 {
		pinner.Pin(&cMsgs[0])
		msgsPtr = &cMsgs[0]
	}

	// Convert disclosedIndices from []int to []C.uint32_t.
	cIndices := make([]C.uint32_t, len(disclosedIndices))
	for i, idx := range disclosedIndices {
		cIndices[i] = C.uint32_t(idx)
	}

	var indicesPtr *C.uint32_t
	if len(cIndices) > 0 {
		pinner.Pin(&cIndices[0])
		indicesPtr = &cIndices[0]
	}

	var valid C.int32_t
	result := C.bbs_ffi_proof_verify_with_nym(
		(*C.uint8_t)(unsafe.Pointer(&issuerPublicKey[0])), C.size_t(len(issuerPublicKey)),
		(*C.uint8_t)(unsafe.Pointer(&proof[0])), C.size_t(len(proof)),
		(*C.uint8_t)(unsafe.Pointer(&pseudonym[0])), C.size_t(len(pseudonym)),
		headerPtr, headerLen,
		phPtr, phLen,
		(*C.uint8_t)(unsafe.Pointer(&scope[0])), C.size_t(len(scope)),
		C.uint32_t(totalSignerMessages),
		msgsPtr, C.size_t(len(cMsgs)),
		nil, 0, // No disclosed committed messages
		indicesPtr, C.size_t(len(cIndices)),
		nil, 0, // No disclosed commitment indices
		&valid,
	)
	if result != C.BBS_FFI_OK {
		return fmt.Errorf("BBS+ proof verify with pseudonym FFI call failed: error code %d", result)
	}

	if valid != 1 {
		return fmt.Errorf("BBS+ proof with pseudonym verification failed")
	}

	return nil
}
