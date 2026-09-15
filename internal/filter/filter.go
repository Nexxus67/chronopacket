// Package filter selects which captured packets take part in a replay.
package filter

import (
	"fmt"

	"github.com/chronopacket/chronopacket/internal/reader"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// snapLength is the capture length assumed when compiling filter programs.
const snapLength = 65535

// Matcher decides whether a packet participates in a replay.
type Matcher interface {
	Matches(reader.Packet) bool
	String() string
}

// MatchAll accepts every packet and is used when no filter is configured.
type MatchAll struct{}

// Matches always reports true.
func (MatchAll) Matches(reader.Packet) bool { return true }

// String describes the match-everything behavior.
func (MatchAll) String() string { return "" }

// BPF matches packets against a compiled libpcap filter expression.
type BPF struct {
	expression string
	program    *pcap.BPF
}

// NewBPF compiles expression for linkType, reporting invalid syntax as an error.
func NewBPF(linkType layers.LinkType, expression string) (*BPF, error) {
	program, err := pcap.NewBPF(linkType, snapLength, expression)
	if err != nil {
		return nil, fmt.Errorf("compile filter %q: %w", expression, err)
	}
	return &BPF{expression: expression, program: program}, nil
}

// Matches reports whether packet satisfies the compiled expression.
func (f *BPF) Matches(packet reader.Packet) bool {
	info := gopacket.CaptureInfo{
		Timestamp:     packet.Timestamp,
		CaptureLength: len(packet.Data),
		Length:        len(packet.Data),
	}
	return f.program.Matches(info, packet.Data)
}

// String returns the original filter expression.
func (f *BPF) String() string { return f.expression }

// New returns a matcher for expression, or MatchAll when expression is empty.
func New(linkType layers.LinkType, expression string) (Matcher, error) {
	if expression == "" {
		return MatchAll{}, nil
	}
	return NewBPF(linkType, expression)
}

// Reader yields only the packets of an underlying reader that match a filter.
// Skipped packets keep their original timestamps out of the replay, so the
// engine still observes true capture intervals between the packets it sends.
type Reader struct {
	source  reader.Reader
	matcher Matcher
}

// NewReader wraps source so that only packets accepted by matcher are returned.
func NewReader(source reader.Reader, matcher Matcher) *Reader {
	return &Reader{source: source, matcher: matcher}
}

// Read returns the next matching packet, or the underlying error such as io.EOF.
func (r *Reader) Read() (reader.Packet, error) {
	for {
		packet, err := r.source.Read()
		if err != nil {
			return reader.Packet{}, err
		}
		if r.matcher.Matches(packet) {
			return packet, nil
		}
	}
}

// Close releases the underlying reader.
func (r *Reader) Close() error { return r.source.Close() }
