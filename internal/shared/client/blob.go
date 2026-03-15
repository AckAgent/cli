// Package client provides HTTP communication with the backend services.
package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	blobapi "github.com/ackagent/api/go/blob"
)

// BlobClient handles communication with the blob service using the generated OpenAPI client.
type BlobClient struct {
	api   *blobapi.ClientWithResponses
	OrgID string // Organization ID for org-scoped blob access (set after login)
}

// NewBlobClient creates a new blob service client using the generated OpenAPI client.
func NewBlobClient(baseURL string) (*BlobClient, error) {
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	c := &BlobClient{}

	// Common headers for all requests.
	headerEditor := func(_ context.Context, req *http.Request) error {
		req.Header.Set("User-Agent", userAgent())
		return nil
	}

	apiClient, err := blobapi.NewClientWithResponses(baseURL,
		blobapi.WithHTTPClient(httpClient),
		blobapi.WithRequestEditorFn(blobapi.RequestEditorFn(headerEditor)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob API client: %w", err)
	}
	c.api = apiClient

	return c, nil
}

// WrappedKey is an alias for the generated blob.WrappedKey type.
type WrappedKey = blobapi.WrappedKey

// BlobResult contains the blob data and version (ETag) for optimistic locking.
type BlobResult struct {
	blobapi.BlobResponse
	ETag string // e.g., "v1" - used for If-Match header on updates
}

// ErrVersionConflict is returned when an update fails due to version mismatch.
var ErrVersionConflict = fmt.Errorf("version conflict - please refetch and retry")

// authEditor returns a request editor that sets the Authorization header.
func authEditor(accessToken string) blobapi.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+accessToken)
		return nil
	}
}

// extractETag extracts and unquotes the ETag header from an HTTP response.
func extractETag(resp *http.Response) string {
	etag := resp.Header.Get("ETag")
	if len(etag) >= 2 && etag[0] == '"' && etag[len(etag)-1] == '"' {
		etag = etag[1 : len(etag)-1]
	}
	return etag
}

// GetBlob fetches the encrypted blob for the authenticated user via the generated API client.
// Returns the blob data and the current version (ETag) for subsequent updates.
func (c *BlobClient) GetBlob(ctx context.Context, accessToken string) (*BlobResult, error) {
	httpLog.Debug("GET blob")

	resp, err := c.api.BlobGetWithResponse(ctx, c.OrgID, authEditor(accessToken))
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET blob status=%d", resp.StatusCode())

	switch resp.StatusCode() {
	case http.StatusOK:
		if resp.JSON200 == nil {
			return nil, fmt.Errorf("unexpected nil response body")
		}
		return &BlobResult{
			BlobResponse: *resp.JSON200,
			ETag:         extractETag(resp.HTTPResponse),
		}, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("authentication required: please run 'ackagent login' first")
	default:
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode(), string(resp.Body))
	}
}

// GetBlobHistory lists previous versions of the blob via the generated API client.
func (c *BlobClient) GetBlobHistory(ctx context.Context, accessToken string, limit int) (*blobapi.HistoryListResponse, error) {
	httpLog.Debug("GET blob/history")

	params := &blobapi.BlobHistoryListParams{}
	if limit > 0 {
		l := int32(limit)
		params.Limit = &l
	}

	resp, err := c.api.BlobHistoryListWithResponse(ctx, c.OrgID, params, authEditor(accessToken))
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET blob/history status=%d", resp.StatusCode())

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode(), string(resp.Body))
	}

	if resp.JSON200 == nil {
		return nil, fmt.Errorf("unexpected nil response body")
	}

	return resp.JSON200, nil
}

// GetBlobHistoryVersion gets a specific version from history via the generated API client.
func (c *BlobClient) GetBlobHistoryVersion(ctx context.Context, accessToken string, version int) (*blobapi.HistoryDetailResponse, error) {
	httpLog.Debug("GET blob/history/%d", version)

	resp, err := c.api.BlobHistoryVersionGetWithResponse(ctx, c.OrgID, int32(version), authEditor(accessToken))
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET blob/history/%d status=%d", version, resp.StatusCode())

	switch resp.StatusCode() {
	case http.StatusOK:
		if resp.JSON200 == nil {
			return nil, fmt.Errorf("unexpected nil response body")
		}
		return resp.JSON200, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode(), string(resp.Body))
	}
}
