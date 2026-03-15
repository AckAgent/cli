package client

import (
	"context"
	"errors"
	"time"
)

// PollConfig configures polling behavior
type PollConfig struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
}

// DefaultPollConfig returns the default polling configuration
func DefaultPollConfig() PollConfig {
	return PollConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
	}
}

// poll is a generic helper for polling with exponential backoff.
// fetcher: gets current status, returns (result, err)
// checker: given result, returns (done, resultErr) where done=true means stop polling
func poll[T any](ctx context.Context, timeout time.Duration, cfg PollConfig,
	fetcher func(context.Context) (T, error),
	checker func(T) (done bool, err error),
) (T, error) {
	var zero T
	deadline := time.Now().Add(timeout)
	interval := cfg.InitialInterval
	attempt := 0

	httpLog.Debug("polling started timeout=%v", timeout)

	for time.Now().Before(deadline) {
		attempt++
		result, err := fetcher(ctx)
		if err != nil {
			// Fatal errors - stop polling immediately
			if errors.Is(err, ErrExpired) || errors.Is(err, ErrNotFound) || errors.Is(err, context.Canceled) {
				httpLog.Debug("polling stopped: %v", err)
				return zero, err
			}
			// Transient errors - continue polling with backoff
			httpLog.Debug("polling attempt=%d error=%v, retrying in %v", attempt, err, interval)
			time.Sleep(interval)
			interval = time.Duration(float64(interval) * cfg.Multiplier)
			if interval > cfg.MaxInterval {
				interval = cfg.MaxInterval
			}
			continue
		}

		done, resultErr := checker(result)
		if done {
			httpLog.Debug("polling completed attempt=%d", attempt)
			return result, resultErr
		}

		httpLog.Debug("polling attempt=%d pending, next in %v", attempt, interval)

		// Wait before next poll
		select {
		case <-ctx.Done():
			httpLog.Debug("polling cancelled")
			return zero, ctx.Err()
		case <-time.After(interval):
		}

		// Exponential backoff
		interval = time.Duration(float64(interval) * cfg.Multiplier)
		if interval > cfg.MaxInterval {
			interval = cfg.MaxInterval
		}
	}

	httpLog.Warn("polling timeout after %d attempts", attempt)
	return zero, ErrTimeout
}
