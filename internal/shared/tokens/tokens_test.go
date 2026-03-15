package tokens

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserAgentTransport_SetsHeader(t *testing.T) {
	// Create a test server to verify headers
	var receivedUA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &userAgentTransport{base: http.DefaultTransport}
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if receivedUA == "" {
		t.Error("User-Agent header was not set")
	}
	if !hasPrefix(receivedUA, "ackagent-cli/") {
		t.Errorf("User-Agent = %q, want prefix ackagent-cli/", receivedUA)
	}
}

func TestUserAgentTransport_DoesNotMutateOriginalRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &userAgentTransport{base: http.DefaultTransport}
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest("GET", server.URL, nil)
	originalUA := req.Header.Get("User-Agent")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	// Original request should not be mutated
	if req.Header.Get("User-Agent") != originalUA {
		t.Error("original request was mutated")
	}
}

func TestTokenResponse_Fields(t *testing.T) {
	resp := TokenResponse{
		AccessToken:  "at",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "rt",
		IDToken:      "idt",
		Scope:        "openid",
	}

	if resp.AccessToken != "at" {
		t.Errorf("AccessToken = %q", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d", resp.ExpiresIn)
	}
	if resp.RefreshToken != "rt" {
		t.Errorf("RefreshToken = %q", resp.RefreshToken)
	}
}

func TestDefaultClientID(t *testing.T) {
	if DefaultClientID != "ackagent-cli" {
		t.Errorf("DefaultClientID = %q, want ackagent-cli", DefaultClientID)
	}
}

func TestHttpClient_HasTimeout(t *testing.T) {
	if httpClient.Timeout <= 0 {
		t.Error("httpClient should have a positive timeout")
	}
}

func TestHttpClient_HasTransport(t *testing.T) {
	if httpClient.Transport == nil {
		t.Error("httpClient should have a transport configured")
	}
	_, ok := httpClient.Transport.(*userAgentTransport)
	if !ok {
		t.Errorf("httpClient.Transport is %T, want *userAgentTransport", httpClient.Transport)
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
