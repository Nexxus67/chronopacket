// Package timing contains replay clock abstractions.
package timing

import (
	"context"
	"time"
)

// Sleeper waits for a duration or until the context is cancelled.
type Sleeper interface {
	Sleep(context.Context, time.Duration) error
}

// RealSleeper uses timers backed by the system clock.
type RealSleeper struct{}

// Sleep waits for d, returning the context error if cancellation occurs first.
func (RealSleeper) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
