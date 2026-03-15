//go:build linux || darwin

// PAM module for AckAgent push-based authentication.
//
// This is compiled as a shared library (pam_ackagent.so) that implements
// the PAM authentication interface. When a user authenticates via SSH,
// sudo, or other PAM-enabled services, this module sends a push notification
// to their enrolled iOS device for approval.
//
// Build:
//
//	CGO_ENABLED=1 go build -buildmode=c-shared -o pam_ackagent.so ./cmd/pam-module
//
// Install:
//
//	Linux: sudo cp pam_ackagent.so /lib/security/pam_ackagent.so
//	macOS: sudo cp pam_ackagent.so /usr/local/lib/pam/pam_ackagent.so
//
// Configure PAM (e.g., /etc/pam.d/sshd or /etc/pam.d/sudo):
//
//	auth required pam_ackagent.so
package main

/*
#cgo linux CFLAGS: -I/usr/include
#cgo darwin CFLAGS: -I/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include -Wno-nullability-completeness
#cgo LDFLAGS: -lpam

#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>

// On Linux, pam_get_user is declared in pam_modules.h which we cannot
// include (it declares pam_sm_* with const argv, conflicting with CGO exports).
// Provide our own declaration so the compiler doesn't warn.
#ifndef __APPLE__
extern int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt);
#endif

// PAM return codes
#define GO_PAM_SUCCESS          0
#define GO_PAM_AUTH_ERR         7
#define GO_PAM_USER_UNKNOWN     10
#define GO_PAM_AUTHINFO_UNAVAIL 9

// Helper to get username from PAM handle
static int get_pam_user(pam_handle_t *pamh, const char **user) {
    return pam_get_user(pamh, user, NULL);
}

// Helper to get PAM item as string
static int get_pam_item_string(pam_handle_t *pamh, int item_type, const char **value) {
    return pam_get_item(pamh, item_type, (const void **)value);
}
*/
import "C"

import (
	"log"
	"unsafe"

	"github.com/ackagent/cli/internal/pam"
)

// PAM return codes
const (
	pamSuccess         = C.GO_PAM_SUCCESS
	pamAuthErr         = C.GO_PAM_AUTH_ERR
	pamUserUnknown     = C.GO_PAM_USER_UNKNOWN
	pamAuthInfoUnavail = C.GO_PAM_AUTHINFO_UNAVAIL
)

// pam_sm_authenticate is the PAM authentication entry point.
// Exported via //export so CGO generates the C symbol.
//
//export pam_sm_authenticate
func pam_sm_authenticate(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	// Get username
	var cUser *C.char
	if ret := C.get_pam_user(pamh, &cUser); ret != pamSuccess {
		log.Printf("pam_ackagent: failed to get username: %d", ret)
		return pamUserUnknown
	}
	username := C.GoString(cUser)

	// Get service name
	var cService *C.char
	if ret := C.get_pam_item_string(pamh, C.PAM_SERVICE, &cService); ret != pamSuccess {
		cService = C.CString("unknown")
		defer C.free(unsafe.Pointer(cService))
	}
	service := C.GoString(cService)

	log.Printf("pam_ackagent: authenticating user=%s service=%s", username, service)

	// Load configuration
	config, err := pam.LoadDefaultConfig()
	if err != nil {
		log.Printf("pam_ackagent: failed to load config: %v", err)
		return pamAuthInfoUnavail
	}

	// Gather PAM environment
	pamEnv := gatherPamEnv(pamh)

	// Build authentication context
	ctx := pam.GatherContext(username, service, pamEnv)

	// Authenticate based on configured mode
	switch config.Auth.Mode {
	case pam.AuthModePush:
		return authenticatePush(config, ctx)

	case pam.AuthModeChallenge:
		log.Printf("pam_ackagent: challenge mode not yet implemented")
		return pamAuthInfoUnavail

	case pam.AuthModeFallback:
		// Try push first
		result := authenticatePush(config, ctx)
		if result == pamSuccess {
			return pamSuccess
		}
		if result == pamAuthInfoUnavail {
			log.Printf("pam_ackagent: push auth unavailable, challenge mode not implemented")
			return pamAuthInfoUnavail
		}
		return result

	default:
		log.Printf("pam_ackagent: unknown auth mode: %s", config.Auth.Mode)
		return pamAuthErr
	}
}

//export pam_sm_setcred
func pam_sm_setcred(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	return pamSuccess
}

//export pam_sm_acct_mgmt
func pam_sm_acct_mgmt(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	return pamSuccess
}

//export pam_sm_open_session
func pam_sm_open_session(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	return pamSuccess
}

//export pam_sm_close_session
func pam_sm_close_session(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	return pamSuccess
}

//export pam_sm_chauthtok
func pam_sm_chauthtok(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	return pamSuccess
}

// gatherPamEnv collects PAM environment variables.
func gatherPamEnv(pamh *C.pam_handle_t) *pam.PAMEnv {
	env := &pam.PAMEnv{}

	// Get remote host
	var cRHost *C.char
	if ret := C.get_pam_item_string(pamh, C.PAM_RHOST, &cRHost); ret == pamSuccess && cRHost != nil {
		env.RemoteHost = C.GoString(cRHost)
	}

	// Get TTY
	var cTTY *C.char
	if ret := C.get_pam_item_string(pamh, C.PAM_TTY, &cTTY); ret == pamSuccess && cTTY != nil {
		env.TTY = C.GoString(cTTY)
	}

	return env
}

// authenticatePush performs push-based authentication.
func authenticatePush(config *pam.Config, ctx *pam.AuthContext) C.int {
	authenticator, err := pam.NewPushAuthenticator(config)
	if err != nil {
		log.Printf("pam_ackagent: failed to create push authenticator: %v", err)
		return pamAuthInfoUnavail
	}

	result, err := authenticator.Authenticate(ctx)
	if err != nil {
		log.Printf("pam_ackagent: push authentication error: %v", err)
		return pamAuthInfoUnavail
	}

	if result.Approved {
		log.Printf("pam_ackagent: authentication approved by device %s", result.ApproverId)
		return pamSuccess
	}

	log.Printf("pam_ackagent: authentication rejected or timed out")
	return pamAuthErr
}

func main() {}
