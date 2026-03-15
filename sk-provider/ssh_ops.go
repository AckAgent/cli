package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ackagent/cli/crypto"
	relayapi "github.com/ackagent/api/go/relay"
	"github.com/ackagent/cli/internal/shared/client"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/multidevice"
	"github.com/ackagent/cli/internal/shared/transport"
	"github.com/ackagent/cli/internal/shared/util"
	protocol "github.com/ackagent/api/go/protocol"
	"github.com/google/uuid"
)

const (
	sshAlgECDSA   = 0
	sshAlgEd25519 = 1

	sshErrGeneral        = -1
	sshErrUnsupported    = -2
	sshErrDeviceNotFound = -4
)

type enrollResult struct {
	publicKey       []byte
	keyHandle       []byte
	signature       []byte
	attestationCert []byte
}

type signResult struct {
	signature []byte
	counter   uint32
}

func executeEnroll(alg uint32, challengeBytes []byte, app string, flags uint8) (*enrollResult, int) {
	if alg != sshAlgECDSA && alg != sshAlgEd25519 {
		logError("unsupported algorithm: %d", alg)
		return nil, sshErrUnsupported
	}

	cfg, err := config.Load()
	if err != nil {
		logError("failed to load config: %v", err)
		return nil, sshErrGeneral
	}
	if !cfg.IsLoggedIn() {
		logError("not logged in - run 'ackagent login' first")
		return nil, sshErrDeviceNotFound
	}

	ephemeral, err := crypto.GenerateKeyPair()
	if err != nil {
		logError("failed to generate ephemeral key: %v", err)
		return nil, sshErrGeneral
	}

	requestID := uuid.New()
	requestIDBytes, err := requestID.MarshalBinary()
	if err != nil {
		logError("failed to encode request ID: %v", err)
		return nil, sshErrGeneral
	}

	processInfo := getProcessInfo()

	algDisplayName := "ECDSA P-256"
	if alg == sshAlgEd25519 {
		algDisplayName = "Ed25519"
	}
	fields := []protocol.DisplayField{
		{Label: "Algorithm", Value: algDisplayName},
		{Label: "Application", Value: app, Monospace: util.Ptr(true)},
	}

	icon := "key.fill"
	historyTitle := "SSH Key Enrolled"
	subtitle := "SSH key enrollment"
	req := EnrollRequest{
		RequestID:   requestID.String(),
		Type:        protocol.Enroll,
		Purpose:     protocol.Ssh,
		Algorithm:   int(alg),
		Challenge:   challengeBytes,
		Application: app,
		Flags:       flags,
		Timestamp:   time.Now().Unix(),
		Display: &protocol.GenericDisplaySchema{
			Title:        "Enroll SSH Key?",
			HistoryTitle: &historyTitle,
			Subtitle:     &subtitle,
			Icon:         &icon,
			Fields:       fields,
		},
		SourceInfo: processInfo.ToSourceInfo(),
	}

	plaintext, err := json.Marshal(req)
	if err != nil {
		logError("failed to marshal enroll request: %v", err)
		return nil, sshErrGeneral
	}

	encrypted, err := multidevice.EncryptForDevices(cfg, plaintext, requestID)
	if err != nil {
		logError("encryption failed: %v", err)
		return nil, sshErrGeneral
	}

	ctx := context.Background()
	accessToken, err := cfg.GetValidAccessToken(ctx)
	if err != nil {
		logError("authentication required: please run 'ackagent login' first (%v)", err)
		return nil, sshErrGeneral
	}

	relayClient, err := client.NewClient(cfg.RelayURL(), cfg.DeviceID)
	if err != nil {
		logError("failed to create API client: %v", err)
		return nil, sshErrGeneral
	}
	relayClient.SetAccessToken(accessToken)

	enrollExpiresIn := int32(300)
	enrollReq := &relayapi.CreateSigningRequest{
		Id:                       requestID.String(),
		RequesterId:              cfg.UserAccount().RequesterID,
		RequesterEphemeralKeyHex: hex.EncodeToString(ephemeral.PublicKey[:]),
		EncryptedPayload:         encrypted.EncryptedPayload,
		PayloadNonce:             encrypted.PayloadNonce,
		WrappedKeys:              &encrypted.WrappedKeys,
		ExpiresIn:                &enrollExpiresIn,
		Timestamp:                time.Now().UnixMilli(),
	}

	logDebug("sending enrollment request to backend")
	_, err = relayClient.CreateSigningRequest(ctx, enrollReq)
	if err != nil {
		logError("failed to send request: %v", err)
		return nil, sshErrGeneral
	}

	logDebug("waiting for iOS response...")
	status, err := relayClient.PollForResponse(ctx, requestID.String(), config.DefaultSSHTimeout, client.DefaultPollConfig())
	if err != nil {
		logError("failed to get response: %v", err)
		return nil, sshErrGeneral
	}

	if len(status.GetEphemeralPublic()) != crypto.PublicKeySize {
		logError("missing signer ephemeral public key in response")
		return nil, sshErrGeneral
	}

	responseKey, err := crypto.DeriveResponseKey(
		ephemeral.PrivateKey[:],
		status.GetEphemeralPublic(),
		requestIDBytes,
	)
	if err != nil {
		logError("failed to derive response key: %v", err)
		return nil, sshErrGeneral
	}

	decrypted, err := crypto.Decrypt(responseKey, status.GetResponseNonce(), status.GetEncryptedResponse(), requestIDBytes)
	if err != nil {
		logError("failed to decrypt response: %v", err)
		return nil, sshErrGeneral
	}

	var enrollResp protocol.EnrollResponse
	if err := json.Unmarshal(decrypted, &enrollResp); err != nil {
		logError("failed to parse response: %v", err)
		return nil, sshErrGeneral
	}

	if enrollResp.Status != protocol.EnrollResponseStatusApproved {
		logError("enrollment rejected")
		return nil, sshErrGeneral
	}
	if enrollResp.IosKeyId == nil {
		logError("missing iOS key ID in response")
		return nil, sshErrGeneral
	}
	if enrollResp.PublicKeyHex == nil {
		logError("missing public key in response")
		return nil, sshErrGeneral
	}

	iosKeyID := *enrollResp.IosKeyId
	publicKey, err := hex.DecodeString(*enrollResp.PublicKeyHex)
	if err != nil {
		logError("invalid hex public key: %v", err)
		return nil, sshErrGeneral
	}

	keyHandle := buildKeyHandle(iosKeyID, cfg.UserAccount().UserID, app)

	algName := config.AlgorithmP256
	if alg == sshAlgEd25519 {
		algName = config.AlgorithmEd25519
	}

	cfg.AddKey(config.KeyMetadata{
		IOSKeyID:  iosKeyID,
		Label:     app,
		PublicKey: publicKey,
		Algorithm: algName,
		Purpose:   config.KeyPurposeSSH,
		CreatedAt: time.Now(),
	})
	cfg.Save()

	sshPublicKey := publicKey
	if alg == sshAlgECDSA && len(publicKey) == int(crypto.PublicKeySize) {
		decompressed, err := crypto.DecompressPublicKey(publicKey)
		if err != nil {
			logError("failed to decompress public key: %v", err)
			return nil, sshErrGeneral
		}
		sshPublicKey = decompressed
	}

	var signature []byte
	if enrollResp.SubkeySignature != nil {
		signature = *enrollResp.SubkeySignature
	}

	var attestationCert []byte
	if enrollResp.Attestation != nil {
		att, err := json.Marshal(enrollResp.Attestation)
		if err == nil {
			attestationCert = att
		}
	}

	return &enrollResult{
		publicKey:       sshPublicKey,
		keyHandle:       keyHandle,
		signature:       signature,
		attestationCert: attestationCert,
	}, 0
}

func executeSign(alg uint32, dataBytes []byte, app string, keyHandleBytes []byte, flags uint8) (*signResult, int) {
	if alg != sshAlgECDSA && alg != sshAlgEd25519 {
		logError("unsupported algorithm: %d", alg)
		return nil, sshErrUnsupported
	}

	keyHandleData, err := parseKeyHandle(keyHandleBytes)
	if err != nil {
		logError("invalid key handle: %v", err)
		return nil, sshErrGeneral
	}

	cfg, err := config.Load()
	if err != nil {
		logError("failed to load config: %v", err)
		return nil, sshErrGeneral
	}

	_, profileName, err := cfg.FindKeyAcrossProfilesAndOrgs(keyHandleData.IOSKeyID)
	if err == nil {
		if err := cfg.SetWorkingProfile(profileName); err != nil {
			logDebug("failed to set profile '%s': %v", profileName, err)
		} else {
			logDebug("using profile '%s' for key %s", profileName, keyHandleData.IOSKeyID)
		}
	} else {
		logDebug("key %s not found in any profile, using active profile", keyHandleData.IOSKeyID)
	}

	logDebug("config loaded: issuer=%s, relay=%s", cfg.IssuerURL(), cfg.RelayURL())
	if !cfg.IsLoggedIn() {
		logError("not logged in")
		return nil, sshErrDeviceNotFound
	}

	ephemeral, err := crypto.GenerateKeyPair()
	if err != nil {
		logError("failed to generate ephemeral key: %v", err)
		return nil, sshErrGeneral
	}

	requestID := uuid.New()
	requestIDBytes, err := requestID.MarshalBinary()
	if err != nil {
		logError("failed to encode request ID: %v", err)
		return nil, sshErrGeneral
	}

	processInfo := getProcessInfo()
	logDebug("ssh command: %s", processInfo.Command)
	logDebug("process chain: %v", processInfo.ProcessChain)

	fields := []protocol.DisplayField{
		{Label: "Application", Value: app, Monospace: util.Ptr(true)},
	}

	icon := "terminal"
	historyTitle := "SSH Signature"
	req := SignRequest{
		RequestID:   requestID.String(),
		Type:        protocol.SshAuth,
		IOSKeyID:    keyHandleData.IOSKeyID,
		RawData:     dataBytes,
		Application: app,
		Flags:       flags,
		Timestamp:   time.Now().Unix(),
		Command:     processInfo.Command,
		Display: &protocol.GenericDisplaySchema{
			Title:        "Authorize SSH?",
			HistoryTitle: &historyTitle,
			Icon:         &icon,
			Fields:       fields,
		},
		SourceInfo: processInfo.ToSourceInfo(),
	}

	plaintext, err := json.Marshal(req)
	if err != nil {
		logError("failed to marshal sign request: %v", err)
		return nil, sshErrGeneral
	}
	logDebug("sign request payload: %s", string(plaintext))

	encrypted, err := multidevice.EncryptForDevices(cfg, plaintext, requestID)
	if err != nil {
		logError("encryption failed: %v", err)
		return nil, sshErrGeneral
	}

	ctx := context.Background()
	accessToken, err := cfg.GetValidAccessToken(ctx)
	if err != nil {
		logError("authentication required: please run 'ackagent login' first (%v)", err)
		return nil, sshErrGeneral
	}

	relayClient, err := client.NewClient(cfg.RelayURL(), cfg.DeviceID)
	if err != nil {
		logError("failed to create API client: %v", err)
		return nil, sshErrGeneral
	}
	relayClient.SetAccessToken(accessToken)

	signExpiresIn := int32(60)
	signReq := &relayapi.CreateSigningRequest{
		Id:                       requestID.String(),
		RequesterId:              cfg.UserAccount().RequesterID,
		RequesterEphemeralKeyHex: hex.EncodeToString(ephemeral.PublicKey[:]),
		EncryptedPayload:         encrypted.EncryptedPayload,
		PayloadNonce:             encrypted.PayloadNonce,
		WrappedKeys:              &encrypted.WrappedKeys,
		ExpiresIn:                &signExpiresIn,
		Timestamp:                time.Now().UnixMilli(),
	}

	logDebug("sending sign request to backend")
	_, err = relayClient.CreateSigningRequest(ctx, signReq)
	if err != nil {
		logError("failed to send request: %v", err)
		return nil, sshErrGeneral
	}

	logDebug("waiting for iOS response...")
	status, err := relayClient.PollForResponse(ctx, requestID.String(), config.DefaultSSHTimeout, client.DefaultPollConfig())
	if err != nil {
		logError("failed to get response: %v", err)
		return nil, sshErrGeneral
	}

	if len(status.GetEphemeralPublic()) != crypto.PublicKeySize {
		logError("missing signer ephemeral public key in response")
		return nil, sshErrGeneral
	}

	responseKey, err := crypto.DeriveResponseKey(
		ephemeral.PrivateKey[:],
		status.GetEphemeralPublic(),
		requestIDBytes,
	)
	if err != nil {
		logError("failed to derive response key: %v", err)
		return nil, sshErrGeneral
	}

	decrypted, err := crypto.Decrypt(responseKey, status.GetResponseNonce(), status.GetEncryptedResponse(), requestIDBytes)
	if err != nil {
		logError("failed to decrypt response: %v", err)
		return nil, sshErrGeneral
	}

	var signResp protocol.SignatureResponse
	if err := json.Unmarshal(decrypted, &signResp); err != nil {
		logError("failed to parse response: %v", err)
		return nil, sshErrGeneral
	}
	if signResp.Status == nil || *signResp.Status != protocol.Approved {
		logError("signing rejected")
		return nil, sshErrGeneral
	}

	var issuerKeys []transport.IssuerKeyInfo
	if profile, profileErr := cfg.GetActiveProfile(); profileErr == nil {
		if len(profile.IssuerPublicKey) > 0 {
			issuerKeys = []transport.IssuerKeyInfo{{
				ID:        profile.IssuerPublicKeyID,
				PublicKey: profile.IssuerPublicKey,
			}}
		}
	}
	if err := transport.VerifyAttestationFromJSON(decrypted, requestID.String(), issuerKeys, transport.SkipAttestationRequested()); err != nil {
		logError("anonymous attestation verification failed: %v", err)
		return nil, sshErrGeneral
	}

	if signResp.Signature == nil {
		logError("missing signature in response")
		return nil, sshErrGeneral
	}
	signature := *signResp.Signature
	if len(signature) != 64 {
		logError("invalid signature length: %d", len(signature))
		return nil, sshErrGeneral
	}

	var counter uint32
	if signResp.Counter != nil {
		counter = uint32(*signResp.Counter)
	}

	return &signResult{signature: signature, counter: counter}, 0
}
