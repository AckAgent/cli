package transport

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/ackagent/cli/internal/shared/log"
)

var tlog = log.New("transport")

var (
	// ErrNoTransports is returned when no transports are registered.
	ErrNoTransports = errors.New("no transports registered")

	// ErrAllTransportsFailed is returned when all transports fail.
	ErrAllTransportsFailed = errors.New("all transports failed")
)

// Manager manages multiple transports and routes requests through them.
// It tries transports in priority order and falls back to the next one on failure.
type Manager struct {
	mu         sync.RWMutex
	transports []Transport
	sorted     bool
}

// NewManager creates a new transport manager.
func NewManager() *Manager {
	return &Manager{
		transports: make([]Transport, 0),
	}
}

// Register adds a transport to the manager.
// Transports are tried in priority order (lower priority number = tried first).
func (m *Manager) Register(t Transport) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transports = append(m.transports, t)
	m.sorted = false
}

// ensureSorted sorts transports by priority (must hold lock).
func (m *Manager) ensureSorted() {
	if m.sorted {
		return
	}
	sort.Slice(m.transports, func(i, j int) bool {
		return m.transports[i].Priority() < m.transports[j].Priority()
	})
	m.sorted = true
}

// Send sends a request using the first available transport.
// It tries transports in priority order and falls back to the next one on failure.
func (m *Manager) Send(ctx context.Context, req *Request, timeout time.Duration) (*Response, error) {
	m.mu.RLock()
	if len(m.transports) == 0 {
		m.mu.RUnlock()
		return nil, ErrNoTransports
	}
	m.ensureSorted()
	transports := make([]Transport, len(m.transports))
	copy(transports, m.transports)
	m.mu.RUnlock()

	var lastErr error
	for _, t := range transports {
		// Check if transport is available
		available, err := t.IsAvailable(ctx)
		if err != nil {
			tlog.Debug("transport %s availability check failed: %v", t.Name(), err)
			continue
		}
		if !available {
			tlog.Debug("transport %s not available", t.Name())
			continue
		}

		tlog.Debug("trying transport %s (priority %d)", t.Name(), t.Priority())

		// Try to send via this transport
		resp, err := t.Send(ctx, req, timeout)
		if err == nil {
			tlog.Debug("transport %s succeeded", t.Name())
			return resp, nil
		}

		// Log the error and try next transport
		lastErr = &TransportError{Transport: t.Name(), Err: err}
		tlog.Debug("transport %s failed: %v, trying next", t.Name(), err)

		// Check context cancellation
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrAllTransportsFailed
}
