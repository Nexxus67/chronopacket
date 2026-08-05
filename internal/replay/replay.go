// Package replay coordinates deterministic packet replay.
package replay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/chronopacket/chronopacket/internal/reader"
	"github.com/chronopacket/chronopacket/internal/timing"
)

// PacketReader is the input boundary used by Engine.
type PacketReader interface {
	Read() (reader.Packet, error)
	Close() error
}

// PacketSender is the output boundary used by Engine.
type PacketSender interface {
	Send([]byte) error
	Close() error
}

// Progress contains cumulative replay measurements.
type Progress struct {
	Packets uint64
	Bytes   uint64
	Elapsed time.Duration
}

// Reporter receives progress after each successfully sent packet.
type Reporter interface{ Report(Progress) }

// Engine replays packets while preserving capture timing at a speed multiplier.
type Engine struct {
	reader   PacketReader
	sender   PacketSender
	sleeper  timing.Sleeper
	speed    float64
	reporter Reporter
	clock    func() time.Time
}

// Options configures an Engine.
type Options struct {
	Reader   PacketReader
	Sender   PacketSender
	Sleeper  timing.Sleeper
	Speed    float64
	Reporter Reporter
	Clock    func() time.Time
}

// New constructs a replay engine after validating its dependencies.
func New(opts Options) (*Engine, error) {
	if opts.Reader == nil {
		return nil, errors.New("replay reader is required")
	}
	if opts.Sender == nil {
		return nil, errors.New("replay sender is required")
	}
	if opts.Sleeper == nil {
		opts.Sleeper = timing.RealSleeper{}
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Speed <= 0 {
		return nil, fmt.Errorf("replay speed must be positive (got %v)", opts.Speed)
	}
	return &Engine{reader: opts.Reader, sender: opts.Sender, sleeper: opts.Sleeper, speed: opts.Speed, reporter: opts.Reporter, clock: opts.Clock}, nil
}

// Run replays all packets until completion or context cancellation.
func (e *Engine) Run(ctx context.Context) (Progress, error) {
	started := e.clock()
	var stats Progress
	var previous time.Time
	for {
		packet, err := e.reader.Read()
		if errors.Is(err, io.EOF) {
			stats.Elapsed = e.clock().Sub(started)
			return stats, nil
		}
		if err != nil {
			return stats, err
		}
		if !previous.IsZero() {
			delay := packet.Timestamp.Sub(previous)
			if delay > 0 {
				if err := e.sleeper.Sleep(ctx, time.Duration(float64(delay)/e.speed)); err != nil {
					return stats, fmt.Errorf("wait between packets: %w", err)
				}
			}
		}
		if err := e.sender.Send(packet.Data); err != nil {
			return stats, err
		}
		previous = packet.Timestamp
		stats.Packets++
		stats.Bytes += uint64(len(packet.Data))
		stats.Elapsed = e.clock().Sub(started)
		if e.reporter != nil {
			e.reporter.Report(stats)
		}
	}
}
