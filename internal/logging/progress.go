// Package logging contains CLI-facing progress reporters.
package logging

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/chronopacket/chronopacket/internal/replay"
)

// ProgressReporter prints compact, live replay progress.
type ProgressReporter struct {
	output io.Writer
	speed  float64
	mu     sync.Mutex
}

// NewProgressReporter creates a reporter writing to output.
func NewProgressReporter(output io.Writer, speed float64) *ProgressReporter {
	return &ProgressReporter{output: output, speed: speed}
}

// Report prints packets sent, elapsed time, speed, and throughput.
func (r *ProgressReporter) Report(p replay.Progress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seconds := p.Elapsed.Seconds()
	rate := float64(p.Packets)
	if seconds > 0 {
		rate /= seconds
	}
	fmt.Fprintf(r.output, "\rpackets sent: %d | elapsed: %s | replay speed: %.0fx | packets/sec: %.1f", p.Packets, p.Elapsed.Round(time.Millisecond), r.speed, rate)
}

// Finish moves the terminal to the next line after a replay.
func (r *ProgressReporter) Finish() { r.mu.Lock(); defer r.mu.Unlock(); fmt.Fprintln(r.output) }
