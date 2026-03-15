// Package tokens provides OIDC token management including refresh token handling.
package tokens

import (
	"context"
	"net/http"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"

	"github.com/ackagent/cli/internal/shared/version"
)

// userAgentTransport wraps an http.RoundTripper to add User-Agent header.
type userAgentTransport struct {
	base http.RoundTripper
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", "ackagent-cli/"+version.Version)
	return t.base.RoundTrip(req)
}

// httpClient is a configured HTTP client with proper timeouts and User-Agent.
var httpClient = &http.Client{
	Timeout:   30 * time.Second,
	Transport: &userAgentTransport{base: http.DefaultTransport},
}

// TokenResponse represents the OAuth2 token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// DefaultClientID is the default OAuth client ID for the CLI.
const DefaultClientID = "ackagent-cli"

// RefreshAccessToken uses a refresh token to get a new access token.
// It fetches the token endpoint from OIDC discovery.
func RefreshAccessToken(ctx context.Context, issuerURL, refreshToken, clientID string) (*TokenResponse, error) {
	if clientID == "" {
		clientID = DefaultClientID
	}

	// Discover OIDC endpoints (zitadel/oidc handles caching internally)
	discovery, err := client.Discover(ctx, issuerURL, httpClient)
	if err != nil {
		return nil, err
	}

	// Build OAuth2 config for token refresh
	oauth2Config := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			TokenURL: discovery.TokenEndpoint,
		},
	}

	// Create a token source that will refresh the token
	oldToken := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	// Get new token using refresh token
	tokenSource := oauth2Config.TokenSource(ctx, oldToken)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}

	// Calculate expires_in from expiry time
	expiresIn := 0
	if !newToken.Expiry.IsZero() {
		expiresIn = int(time.Until(newToken.Expiry).Seconds())
	}

	// Extract ID token if present
	var idToken string
	if v := newToken.Extra("id_token"); v != nil {
		idToken, _ = v.(string)
	}

	return &TokenResponse{
		AccessToken:  newToken.AccessToken,
		TokenType:    newToken.TokenType,
		ExpiresIn:    expiresIn,
		RefreshToken: newToken.RefreshToken,
		IDToken:      idToken,
	}, nil
}

// GetOIDCDiscovery fetches the OIDC discovery document for an issuer.
func GetOIDCDiscovery(ctx context.Context, issuerURL string) (*oidc.DiscoveryConfiguration, error) {
	return client.Discover(ctx, issuerURL, httpClient)
}
