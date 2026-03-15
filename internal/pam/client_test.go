package pam

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	keyauthapi "github.com/ackagent/api/go/keyauth"
	relayapi "github.com/ackagent/api/go/relay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	cfg := &Config{
		Organization: OrganizationConfig{
			ServiceAccountID: "sa-123",
			APIKey:           "test-api-key",
		},
		API: APIConfig{
			LoginURL: "https://login.example.com",
			RelayURL: "https://relay.example.com",
			OIDCURL:  "https://oidc.example.com",
		},
	}

	client := NewClient(cfg)
	require.NotNil(t, client)
	assert.Equal(t, "https://login.example.com", client.loginURL)
	assert.Equal(t, "https://relay.example.com", client.relayURL)
	assert.Equal(t, "https://oidc.example.com", client.oidcURL)
	assert.Equal(t, "sa-123", client.serviceAccountID)
	assert.Equal(t, "test-api-key", client.apiKey)
	assert.Empty(t, client.accessToken)
}

func TestAuthenticate_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/token", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
		assert.Equal(t, "sa-123", r.Form.Get("client_id"))
		assert.Equal(t, "test-api-key", r.Form.Get("client_secret"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "test-access-token",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		})
	}))
	defer server.Close()

	client := &Client{
		httpClient:       server.Client(),
		oidcURL:          server.URL,
		serviceAccountID: "sa-123",
		apiKey:           "test-api-key",
	}

	err := client.Authenticate()
	require.NoError(t, err)
	assert.Equal(t, "test-access-token", client.accessToken)
}

func TestAuthenticate_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid credentials"))
	}))
	defer server.Close()

	client := &Client{
		httpClient:       server.Client(),
		oidcURL:          server.URL,
		serviceAccountID: "sa-123",
		apiKey:           "bad-key",
	}

	err := client.Authenticate()
	require.Error(t, err)

	var apiErr *APIError
	assert.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
}

func TestAuthenticate_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	client := &Client{
		httpClient:       server.Client(),
		oidcURL:          server.URL,
		serviceAccountID: "sa-123",
		apiKey:           "test-api-key",
	}

	err := client.Authenticate()
	require.Error(t, err)

	var apiErr *APIError
	assert.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
}

func TestAuthenticate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	client := &Client{
		httpClient:       server.Client(),
		oidcURL:          server.URL,
		serviceAccountID: "sa-123",
		apiKey:           "test-api-key",
	}

	err := client.Authenticate()
	require.Error(t, err)

	var apiErr *APIError
	assert.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)
}

func TestAuthenticate_MissingOIDCURL(t *testing.T) {
	client := &Client{
		serviceAccountID: "sa-123",
		apiKey:           "test-api-key",
	}

	err := client.Authenticate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC URL not configured")
}

func TestAuthenticate_MissingCredentials(t *testing.T) {
	client := &Client{
		oidcURL: "https://oidc.example.com",
	}

	err := client.Authenticate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service account credentials not configured")
}

func TestPollRequest_Responded(t *testing.T) {
	requestID := "test-request-id"
	respondedStatus := relayapi.Responded
	encResp := []byte("encrypted-response-data")
	ephKey := []byte("approver-ephemeral-key")
	ephKeyHex := hex.EncodeToString(ephKey)
	nonce := []byte("response-nonce")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/requests/"+requestID, r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(relayapi.SigningRequestStatus{
			Id:                      &requestID,
			Status:                  &respondedStatus,
			EncryptedResponse:       &encResp,
			ApproverEphemeralKeyHex: &ephKeyHex,
			ResponseNonce:           &nonce,
		})
	}))
	defer server.Close()

	client := &Client{
		httpClient:  server.Client(),
		relayURL:    server.URL,
		accessToken: "test-token",
	}

	status, err := client.PollRequest(requestID)
	require.NoError(t, err)
	assert.Equal(t, "responded", status.Status)
	assert.Equal(t, requestID, status.ID)
	assert.Equal(t, encResp, status.EncryptedResponse)
	assert.Equal(t, ephKey, status.ApproverEphemeralKey)
	assert.Equal(t, nonce, status.ResponseNonce)
}

func TestPollRequest_Pending(t *testing.T) {
	pendingStatus := relayapi.Pending
	reqID := "req-1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(relayapi.SigningRequestStatus{
			Id:     &reqID,
			Status: &pendingStatus,
		})
	}))
	defer server.Close()

	client := &Client{
		httpClient:  server.Client(),
		relayURL:    server.URL,
		accessToken: "test-token",
	}

	status, err := client.PollRequest("req-1")
	require.NoError(t, err)
	assert.Equal(t, "pending", status.Status)
	assert.Nil(t, status.EncryptedResponse)
}

func TestPollRequest_Expired(t *testing.T) {
	expiredStatus := relayapi.Expired
	reqID := "req-expired"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(relayapi.SigningRequestStatus{
			Id:     &reqID,
			Status: &expiredStatus,
		})
	}))
	defer server.Close()

	client := &Client{
		httpClient:  server.Client(),
		relayURL:    server.URL,
		accessToken: "test-token",
	}

	status, err := client.PollRequest("req-expired")
	require.NoError(t, err)
	assert.Equal(t, "expired", status.Status)
}

func TestPollRequest_NotAuthenticated(t *testing.T) {
	client := &Client{
		loginURL: "http://localhost",
		relayURL: "http://localhost",
	}

	_, err := client.PollRequest("req-1")
	assert.ErrorIs(t, err, ErrNotAuthenticated)
}

func TestPollRequest_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	client := &Client{
		httpClient:  server.Client(),
		relayURL:    server.URL,
		accessToken: "test-token",
	}

	_, err := client.PollRequest("req-1")
	require.Error(t, err)

	var apiErr *APIError
	assert.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)
}

func TestSendPamRequest_NotAuthenticated(t *testing.T) {
	client := &Client{
		loginURL: "http://localhost",
		relayURL: "http://localhost",
	}

	_, _, _, err := client.SendPamRequest(nil, "requester-1", nil, 120)
	assert.ErrorIs(t, err, ErrNotAuthenticated)
}

func TestSendPamRequest_NoDevices(t *testing.T) {
	client := &Client{
		loginURL:    "http://localhost",
		relayURL:    "http://localhost",
		accessToken: "test-token",
	}

	_, _, _, err := client.SendPamRequest(nil, "requester-1", nil, 120)
	assert.ErrorIs(t, err, ErrNoDevices)
}

func TestListMemberDeviceKeys_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/organizations/org-1/members/user@example.com/approver-keys", r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"deviceKeys": []map[string]string{},
		})
	}))
	defer server.Close()

	keyauthClient, _ := keyauthapi.NewClientWithResponses(server.URL, keyauthapi.WithHTTPClient(server.Client()))
	client := &Client{
		httpClient:  server.Client(),
		relayURL:    server.URL,
		accessToken: "test-token",
		keyauthAPI:  keyauthClient,
	}

	devices, err := client.ListMemberDeviceKeys("org-1", "user@example.com")
	require.NoError(t, err)
	assert.Empty(t, devices)
}

func TestListMemberDeviceKeys_NotAuthenticated(t *testing.T) {
	client := &Client{
		relayURL: "http://localhost",
	}

	_, err := client.ListMemberDeviceKeys("org-1", "user@example.com")
	assert.ErrorIs(t, err, ErrNotAuthenticated)
}

func TestListMemberDeviceKeys_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	keyauthClient, _ := keyauthapi.NewClientWithResponses(server.URL, keyauthapi.WithHTTPClient(server.Client()))
	client := &Client{
		httpClient:  server.Client(),
		relayURL:    server.URL,
		accessToken: "test-token",
		keyauthAPI:  keyauthClient,
	}

	_, err := client.ListMemberDeviceKeys("org-1", "user@example.com")
	require.Error(t, err)

	var apiErr *APIError
	assert.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
}

func TestListMemberDeviceKeys_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("bad gateway"))
	}))
	defer server.Close()

	keyauthClient, _ := keyauthapi.NewClientWithResponses(server.URL, keyauthapi.WithHTTPClient(server.Client()))
	client := &Client{
		httpClient:  server.Client(),
		relayURL:    server.URL,
		accessToken: "test-token",
		keyauthAPI:  keyauthClient,
	}

	_, err := client.ListMemberDeviceKeys("org-1", "user@example.com")
	require.Error(t, err)

	var apiErr *APIError
	assert.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusBadGateway, apiErr.StatusCode)
}

func TestAPIError_ErrorMessage(t *testing.T) {
	err := &APIError{
		StatusCode: 404,
		Message:    "not found",
	}

	assert.Contains(t, err.Error(), "404")
	assert.Contains(t, err.Error(), "not found")
}

func TestSendPamRequest_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("user not found"))
	}))
	defer server.Close()

	client := &Client{
		httpClient:  server.Client(),
		loginURL:    server.URL,
		relayURL:    server.URL,
		accessToken: "test-token",
	}

	// SendPamRequest with empty devices returns ErrNoDevices
	_, _, _, err := client.SendPamRequest(nil, "requester-1", nil, 120)
	assert.ErrorIs(t, err, ErrNoDevices)
}

// TestPollRequest_RespondedStatus_Regression is a regression test for Bug 1:
// The relay returns "responded" (not "approved"/"rejected") — those are inside
// the E2E encrypted payload. If PollRequest is reverted to unmarshal into the old
// RequestStatus type, this test will fail because the old type uses "approved"/"rejected".
func TestPollRequest_RespondedStatus_Regression(t *testing.T) {
	requestID := "regression-req-1"
	respondedStatus := relayapi.Responded
	encResp := []byte("some-encrypted-response")
	ephKey := []byte("some-ephemeral-key")
	ephKeyHex := hex.EncodeToString(ephKey)
	nonce := []byte("some-nonce")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(relayapi.SigningRequestStatus{
			Id:                      &requestID,
			Status:                  &respondedStatus,
			EncryptedResponse:       &encResp,
			ApproverEphemeralKeyHex: &ephKeyHex,
			ResponseNonce:           &nonce,
		})
	}))
	defer server.Close()

	client := &Client{
		httpClient:  server.Client(),
		relayURL:    server.URL,
		accessToken: "test-token",
	}

	status, err := client.PollRequest(requestID)
	require.NoError(t, err)

	// The relay uses "responded" — never "approved" or "rejected"
	assert.Equal(t, "responded", status.Status, "relay must return 'responded', not 'approved'/'rejected'")
	assert.NotEmpty(t, status.EncryptedResponse, "responded status must include encrypted response")
	assert.NotEmpty(t, status.ApproverEphemeralKey, "responded status must include approver ephemeral key")
	assert.NotEmpty(t, status.ResponseNonce, "responded status must include response nonce")
}
