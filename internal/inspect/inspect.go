// Package inspect renders captured packets without transmitting them.
package inspect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/chronopacket/chronopacket/internal/filter"
	"github.com/chronopacket/chronopacket/internal/reader"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Summary contains the totals reported after an inspection.
type Summary struct {
	Inspected uint64
	Matched   uint64
	Bytes     uint64
	Duration  time.Duration
	Filter    string
}

// Options configures an inspection run.
type Options struct {
	Reader   reader.Reader
	Matcher  filter.Matcher
	LinkType layers.LinkType
	Output   io.Writer
}

// Run reads the whole capture, prints one line per matching packet, and returns
// the totals. It never sends packets and never waits for capture timestamps.
func Run(ctx context.Context, opts Options) (Summary, error) {
	if opts.Reader == nil {
		return Summary{}, errors.New("inspect reader is required")
	}
	if opts.Matcher == nil {
		opts.Matcher = filter.MatchAll{}
	}
	summary := Summary{Filter: opts.Matcher.String()}
	var first, last time.Time
	for {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		packet, err := opts.Reader.Read()
		if errors.Is(err, io.EOF) {
			summary.Duration = last.Sub(first)
			return summary, nil
		}
		if err != nil {
			return summary, err
		}
		summary.Inspected++
		if first.IsZero() {
			first = packet.Timestamp
		}
		last = packet.Timestamp
		if !opts.Matcher.Matches(packet) {
			continue
		}
		summary.Matched++
		summary.Bytes += uint64(len(packet.Data))
		if opts.Output != nil {
			fmt.Fprintln(opts.Output, Describe(summary.Matched, packet.Timestamp.Sub(first), packet, opts.LinkType))
		}
	}
}

// Describe formats one packet as a compact, human-readable line. Packets whose
// layers cannot be decoded degrade to placeholders instead of failing.
func Describe(number uint64, offset time.Duration, packet reader.Packet, linkType layers.LinkType) string {
	decoded := gopacket.NewPacket(packet.Data, linkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	protocol := "?"
	source, destination := "?", "?"
	if network := decoded.NetworkLayer(); network != nil {
		flow := network.NetworkFlow()
		source, destination = address(flow.Src()), address(flow.Dst())
		protocol = network.LayerType().String()
	}
	switch layer := decoded.TransportLayer().(type) {
	case *layers.TCP:
		protocol = "TCP"
		source = net.JoinHostPort(source, strconv.Itoa(int(layer.SrcPort)))
		destination = net.JoinHostPort(destination, strconv.Itoa(int(layer.DstPort)))
	case *layers.UDP:
		protocol = "UDP"
		source = net.JoinHostPort(source, strconv.Itoa(int(layer.SrcPort)))
		destination = net.JoinHostPort(destination, strconv.Itoa(int(layer.DstPort)))
	default:
		if transport := decoded.TransportLayer(); transport != nil {
			protocol = transport.LayerType().String()
		}
	}
	return fmt.Sprintf("#%-5d +%.3fs  %-5s %-24s -> %-24s %d bytes", number, offset.Seconds(), protocol, source, destination, len(packet.Data))
}

// address renders an endpoint, falling back to a placeholder when it is empty.
func address(endpoint gopacket.Endpoint) string {
	text := endpoint.String()
	if text == "" {
		return "?"
	}
	return text
}

// WriteSummary prints the closing inspection totals.
func WriteSummary(output io.Writer, summary Summary) {
	fmt.Fprintf(output, "inspected: %d packets\n", summary.Inspected)
	if summary.Filter == "" {
		fmt.Fprintf(output, "matched:   %d packets (no filter, all packets matched)\n", summary.Matched)
	} else {
		fmt.Fprintf(output, "matched:   %d packets\n", summary.Matched)
	}
	fmt.Fprintf(output, "bytes:     %d\n", summary.Bytes)
	fmt.Fprintf(output, "duration:  %s\n", summary.Duration.Round(time.Millisecond))
	if summary.Filter != "" {
		fmt.Fprintf(output, "filter:    %s\n", summary.Filter)
	}
}
