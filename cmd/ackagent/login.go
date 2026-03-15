package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ackagent/cli/crypto"
	authapi "github.com/ackagent/api/go/auth"
	"github.com/ackagent/cli/internal/shared/attestation"
	"github.com/ackagent/cli/internal/shared/client"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/display"
	"github.com/ackagent/cli/internal/shared/log"
	"github.com/ackagent/cli/internal/shared/sync"
	"github.com/ackagent/cli/internal/shared/sysinfo"
	"github.com/ackagent/cli/internal/ptr"
)

var (
	loginLocaldev                   bool
	loginSandbox                    bool
	loginRelayURL                   string
	loginIssuerURL                  string
	loginDeviceName                 string
	loginShowConfig                 bool
	loginListKeys                   bool
	loginLogout                     bool
	loginForce                      bool
	loginAcceptSoftwareApproverKeys bool
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with AckAgent via QR code",
	Run:   runLogin,
}

func init() {
	f := loginCmd.Flags()
	f.BoolVar(&loginLocaldev, "localdev", false, "Use local development environment (localhost)")
	f.BoolVar(&loginSandbox, "sandbox", false, "Use sandbox environment")
	f.StringVar(&loginRelayURL, "relay", "", "Override relay server URL")
	f.StringVar(&loginIssuerURL, "issuer", "", "Override OIDC issuer URL")
	f.StringVar(&loginDeviceName, "device-name", "", "Device name for this CLI (defaults to hostname)")
	f.BoolVar(&loginShowConfig, "config", false, "Show current configuration")
	f.BoolVar(&loginListKeys, "keys", false, "List enrolled keys")
	f.BoolVar(&loginLogout, "logout", false, "Logout from user account")
	f.BoolVarP(&loginForce, "force", "f", false, "Force re-login on existing profile")
	f.BoolVar(&loginAcceptSoftwareApproverKeys, "accept-software-approver-keys", false, "Accept devices with software-only attestation (less secure)")
}

func runLogin(cmd *cobra.Command, args []string) {
	profileOverride := profile

	// Validate mutually exclusive flags
	if loginLocaldev && loginSandbox {
		die("--localdev and --sandbox are mutually exclusive")
	}

	// Resolve environment defaults (production is default)
	env := config.Production
	if loginLocaldev {
		env = config.LocalDev
	} else if loginSandbox {
		env = config.Sandbox
	}

	// Apply overrides if provided
	relayURL := loginRelayURL
	issuerURL := loginIssuerURL
	if relayURL == "" {
		relayURL = env.RelayURL
	}
	if issuerURL == "" {
		issuerURL = env.IssuerURL
	}
	blobURL := env.BlobURL

	if loginShowConfig {
		showConfiguration(profileOverride)
		return
	}

	if loginLogout {
		doLogout(profileOverride)
		return
	}

	if loginListKeys {
		if err := showEnrolledKeys(profileOverride); err != nil {
			die("%v", err)
		}
		return
	}

	login(relayURL, issuerURL, blobURL, loginDeviceName, profileOverride, loginForce)
}

func showConfiguration(profileOverride string) {
	cfg := loadConfigWithProfile(profileOverride)

	fmt.Println("Configuration:")
	fmt.Printf("  Config file: %s\n", config.ConfigPath())
	fmt.Printf("  Profiles dir: %s\n", config.ProfilesDir())
	fmt.Printf("  Device ID: %s\n", cfg.DeviceID)
	fmt.Printf("  Device Name: %s\n", cfg.DeviceName)
	fmt.Printf("  Active Profile: %s\n", cfg.ActiveProfile)
	effectiveProfile := cfg.EffectiveProfile()
	if effectiveProfile != cfg.ActiveProfile {
		fmt.Printf("  Using Profile: %s (via --profile or ACKAGENT_PROFILE)\n", effectiveProfile)
	}
	fmt.Printf("  Relay URL: %s\n", cfg.RelayURL())
	p, _ := cfg.GetActiveProfile()
	if p != nil && p.BlobURL != "" {
		fmt.Printf("  Blob URL: %s\n", p.BlobURL)
	}

	if cfg.IsLoggedIn() {
		userAccount := cfg.UserAccount()
		fmt.Println("\nUser Account:")
		fmt.Printf("  User ID: %s\n", userAccount.UserID)
		fmt.Printf("  Logged In: %s\n", userAccount.LoggedInAt.Format(time.RFC3339))
		fmt.Printf("  SAS Verified: %v\n", userAccount.SASVerified)
		fmt.Printf("  Devices: %d\n", len(userAccount.Devices))
		for i, dev := range userAccount.Devices {
			fmt.Printf("    %d. %s\n", i+1, dev.DeviceName)
		}
	} else {
		fmt.Println("\nStatus: Not logged in")
	}

	keys := cfg.Keys()
	fmt.Printf("\nEnrolled Keys: %d\n", len(keys))
	for i, key := range keys {
		fmt.Printf("  %d. %s (%s)\n", i+1, key.Label, truncateFingerprint(key.Hex()))
	}
}

func doLogout(profileOverride string) {
	cfg := loadConfigWithProfile(profileOverride)

	if !cfg.IsLoggedIn() {
		fmt.Println("Not currently logged in.")
		return
	}

	fmt.Print("This will remove your login and all enrolled keys. Continue? (y/N): ")

	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer != "y" && answer != "yes" {
		fmt.Println("Cancelled.")
		return
	}

	cfg.ClearUserAccount()
	if err := cfg.Save(); err != nil {
		die("Error saving config: %v", err)
	}

	fmt.Println("Logged out successfully.")
}

func showEnrolledKeys(profileOverride string) error {
	cfg := loadConfigWithProfile(profileOverride)
	if !cfg.IsLoggedIn() {
		return fmt.Errorf("not logged in: run 'ackagent login' first")
	}
	display.PrintEnrolledKeys(os.Stdout, cfg.Keys())
	return nil
}

func login(relayURL, issuerURL, blobURL, deviceNameFlag, profileOverride string, force bool) {
	var cfg *config.Config
	var targetProfile string

	if profileOverride != "" {
		// Load config without applying profile override (since it might not exist)
		var err error
		cfg, err = config.Load()
		if err != nil {
			die("Error loading config: %v", err)
		}

		// Check if the specified profile exists, create if not
		if _, err := cfg.GetProfile(profileOverride); err != nil {
			// Profile doesn't exist, create it
			if err := cfg.CreateProfile(profileOverride, relayURL, issuerURL); err != nil {
				die("Error creating profile: %v", err)
			}
		}
		targetProfile = profileOverride

		// Set working profile now that it exists
		if err := cfg.SetWorkingProfile(profileOverride); err != nil {
			die("Error: %v", err)
		}
	} else {
		// No profile override, use loadConfigOrDie which uses active profile
		cfg = loadConfigOrDie()
		targetProfile = cfg.EffectiveProfile()
	}

	// Get the target profile for login
	p, err := cfg.GetProfile(targetProfile)
	if err != nil {
		die("Error: %v", err)
	}

	// Check if profile already has login credentials (require --force to overwrite)
	if p.IsLoggedIn() {
		if !force {
			die("Profile '%s' is already logged in. Use --force to re-login or --logout to remove.", targetProfile)
		}
		fmt.Printf("Re-logging in to profile '%s' (currently has %d device(s))...\n", targetProfile, len(p.UserAccount.Devices))
	}

	// Update URLs in the target profile
	p.RelayURL = relayURL
	p.IssuerURL = issuerURL
	p.BlobURL = blobURL

	// Determine device name
	deviceName := deviceNameFlag
	if deviceName == "" {
		deviceName = cfg.DeviceName
	}

	// Generate our X25519 identity key pair
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		die("Failed to generate key pair: %v", err)
	}

	authClient, err := client.NewClient(issuerURL, cfg.DeviceID)
	if err != nil {
		die("Failed to create API client: %v", err)
	}

	loginWithQRCode(cfg, authClient, issuerURL, deviceName, keyPair, targetProfile)
}

// loginWithQRCode performs QR-code based login.
// The CLI displays a QR code that the user scans with their iOS device to authenticate.
func loginWithQRCode(cfg *config.Config, authClient *client.Client, issuerURL string, deviceName string, keyPair *crypto.KeyPair, targetProfile string) {
	fmt.Println("QR Code Login")
	fmt.Println("=============")
	fmt.Println()
	fmt.Printf("Device: %s\n", deviceName)
	fmt.Println()

	ctx := context.Background()

	// 1. Create requester session (no username required)
	fmt.Println("Creating login session...")
	createReq := &client.CreateRequesterSessionRequest{
		RequesterPublicKeyHex: hex.EncodeToString(keyPair.PublicKey[:]),
		// Device name is now passed in QR code URL for iOS display
	}

	createResp, err := authClient.CreateRequesterSession(ctx, createReq)
	if err != nil {
		die("Failed to create login session: %v", err)
	}

	// 2. Generate QR code with session ID, public key, device name, and username
	// Device name and username are passed in URL for iOS to display during SAS verification
	// Uses HTTPS URL format for Universal Links / App Links support
	username := sysinfo.GetCurrentUsername()
	qrData := fmt.Sprintf("%s/link/login?sid=%s&pk=%s&dn=%s&un=%s",
		issuerURL,
		createResp.SessionId,
		base64.RawURLEncoding.EncodeToString(keyPair.PublicKey[:]),
		url.QueryEscape(deviceName),
		url.QueryEscape(username))

	// 3. Display QR code
	fmt.Println()
	fmt.Println("Scan this QR code with any camera app:")
	fmt.Println()
	displayQRCode(qrData)
	fmt.Println()
	fmt.Printf("Or paste this URL in the app: %s\n", qrData)
	fmt.Printf("Session expires at: %s\n", createResp.ExpiresAt.Local().Format("15:04:05"))
	fmt.Println()

	// 4. Poll for session to be claimed and verified
	fmt.Println("Waiting for QR code scan...")

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer pollCancel()

	pollCfg := client.DefaultPollConfig()

	// First, wait for the session to be claimed (approver keys will appear)
	var sasDisplayed bool
	var verified bool
	var status *authapi.GetRequesterSessionStatusResponse

	for !verified {
		status, err = authClient.GetRequesterSessionStatus(pollCtx, createResp.SessionId)
		if err != nil {
			if err == client.ErrExpired {
				die("Login session expired. Please try again.")
			}
			die("Failed to check status: %v", err)
		}

		// If session is claimed (has approver keys) but not yet verified, compute and display SAS locally
		if status.ApproverKeys != nil && len(*status.ApproverKeys) > 0 && !sasDisplayed {
			keys := *status.ApproverKeys
			// Build approver keys for SAS computation
			approverKeys := make([]crypto.SASDeviceKey, len(keys))
			for i, ak := range keys {
				encPubKey, _ := hex.DecodeString(ptr.DerefString(ak.EncryptionPublicKeyHex))
				approverKeys[i] = crypto.SASDeviceKey{
					ApproverId:             ptr.DerefString(ak.ApproverId),
					EncryptionPublicKeyHex: ptr.DerefString(ak.EncryptionPublicKeyHex),
					PublicKey:              encPubKey,
				}
			}

			// Compute SAS locally using our private key and approver public keys
			sasResult := crypto.ComputeSAS(keyPair.PublicKey[:], approverKeys)

			fmt.Println()
			fmt.Println("Device connected! Verify these symbols match your iOS device:")
			fmt.Println()
			fmt.Printf("  Emoji: %s\n", sasResult.EmojiString)
			fmt.Printf("  Words: %s\n", sasResult.WordString)
			fmt.Println()
			fmt.Println("Waiting for approval on iOS device...")
			sasDisplayed = true
		}

		// Check final status
		statusStr := ""
		if status.Status != nil {
			statusStr = string(*status.Status)
		}
		switch statusStr {
		case "verified":
			verified = true
		case "rejected":
			die("Login was rejected by device.")
		case "expired":
			die("Login session expired. Please try again.")
		case "pending", "claimed":
			// Continue polling (claimed = device scanned, waiting for approval)
		default:
			die("Unexpected status: %s", statusStr)
		}

		if !verified {
			select {
			case <-pollCtx.Done():
				die("Login timed out. Please try again.")
			case <-time.After(pollCfg.InitialInterval):
			}
		}
	}

	// 5. Get OIDC tokens
	fmt.Println()
	fmt.Println("Login approved! Fetching tokens...")

	tokens, err := authClient.GetSessionTokens(ctx, createResp.SessionId, createResp.TokenClaimSecret)
	if err != nil {
		die("Failed to get tokens: %v", err)
	}

	// 6. Fetch devices list (now that we have tokens)
	devices, err := authClient.ListUserDevices(ctx, tokens.UserId, tokens.AccessToken)
	if err != nil {
		die("Failed to list devices: %v", err)
	}

	if len(devices) == 0 {
		die("No devices found in your account. Please register a device via the iOS app first.")
	}

	fmt.Printf("Found %d device(s) in your account.\n", len(devices))

	// 7. Store tokens and devices
	configDevices := make([]config.UserDevice, 0, len(devices))
	for _, dev := range devices {
		encPubKey, _ := hex.DecodeString(ptr.DerefString(dev.EncryptionPublicKeyHex))
		var attestPubKey []byte
		if dev.Attestation != nil && dev.Attestation.AttestationPublicKeyHex != nil {
			attestPubKey, _ = hex.DecodeString(*dev.Attestation.AttestationPublicKeyHex)
		}
		log.Debug("Device from API: approverId=%s, name=%s, publicKey len=%d, attestationPublicKey len=%d",
			ptr.DerefString(dev.ApproverId), ptr.DerefString(dev.DeviceName), len(encPubKey), len(attestPubKey))
		authPublicKey, _ := hex.DecodeString(ptr.DerefString(dev.AuthPublicKeyHex))
		configDevices = append(configDevices, config.UserDevice{
			ApproverId:           ptr.DerefString(dev.ApproverId),
			AuthPublicKey:        authPublicKey,
			DeviceName:           ptr.DerefString(dev.DeviceName),
			PublicKey:            encPubKey,
			AttestationPublicKey: attestPubKey,
		})
	}

	// Calculate token expiration
	expiresAt := time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)

	// Convert refresh token pointer to string
	refreshToken := ""
	if tokens.RefreshToken != nil {
		refreshToken = *tokens.RefreshToken
	}

	if err := cfg.SetUserAccount(targetProfile, tokens.UserId, ptr.DerefString(status.RequesterId), tokens.AccessToken, refreshToken, expiresAt, configDevices, keyPair.PrivateKey[:], keyPair.PublicKey[:]); err != nil {
		die("Failed to store credentials: %v", err)
	}
	cfg.VerifySASForProfile(targetProfile)

	issuerPublicKey, err := attestation.EnsureIssuerPublicKeyForProfile(
		ctx,
		cfg,
		targetProfile,
		tokens.AccessToken,
	)
	if err != nil {
		die("Failed to fetch credential issuer public key: %v", err)
	}
	log.Debug("Fetched credential issuer public key (%d bytes)", len(issuerPublicKey))

	// Update device name if provided
	if deviceName != cfg.DeviceName {
		cfg.DeviceName = deviceName
	}

	// 8. Sync signing keys from devices
	syncedKeys := syncSigningKeys(cfg, authClient, tokens.UserId, tokens.AccessToken)

	if err := cfg.Save(); err != nil {
		die("Failed to save configuration: %v", err)
	}

	printLoginSuccess(len(devices), syncedKeys)
}

// syncSigningKeys fetches signing keys from the backend and stores them in config.
func syncSigningKeys(cfg *config.Config, c *client.Client, userID, accessToken string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check for environment variable override
	acceptSoftware := loginAcceptSoftwareApproverKeys
	if os.Getenv("ACKAGENT_ACCEPT_SOFTWARE_APPROVER_KEYS") == "1" ||
		os.Getenv("ACKAGENT_ACCEPT_SOFTWARE_APPROVER_KEYS") == "true" {
		acceptSoftware = true
	}

	// Determine attestation environment
	attestationEnv := crypto.EnvProduction
	if loginLocaldev || loginSandbox {
		attestationEnv = crypto.EnvDevelopment
	}

	result, err := sync.SyncKeys(ctx, cfg, c, userID, accessToken, sync.SyncOptions{
		VerifyAttestation:          true,
		AttestationEnv:             attestationEnv,
		AcceptSoftwareApproverKeys: acceptSoftware,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to sync signing keys: %v\n", err)
		return 0
	}

	// Report attestation status for each synced device
	for _, device := range result.Devices {
		if device.IsAttested {
			// Show hardware attestation type
			attestLabel := "hardware"
			if device.AttestationType != "" {
				attestLabel = string(device.AttestationType)
			}
			fmt.Printf("  ✓ %s (%s)\n", device.DeviceName, attestLabel)
		} else if device.VerificationErr != nil {
			fmt.Printf("  ✗ %s (verification failed: %v)\n", device.DeviceName, device.VerificationErr)
		} else {
			fmt.Printf("  ○ %s (software fallback)\n", device.DeviceName)
		}
	}

	return result.DeviceCount()
}
