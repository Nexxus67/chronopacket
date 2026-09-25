// Package inspect renders captured packets without transmitting them.
package inspect

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/chronopacket/chronopacket/internal/filter"
	"github.com/chronopacket/chronopacket/internal/output"
	"github.com/chronopacket/chronopacket/internal/reader"
	"github.com/chronopacket/chronopacket/internal/rewrite"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Options configures an inspection run.
type Options struct {
	Reader   reader.Reader
	Matcher  filter.Matcher
	Rewriter rewrite.Rewriter
	LinkType layers.LinkType
	Writer   output.Writer
}

// Run reads the whole capture, emits one record per matching packet, and returns
// the totals. It never sends packets and never waits for capture timestamps.
// Rewriting is applied after matching, so records show the addresses a replay
// with the same flags would actually put on the wire.
func Run(ctx context.Context, opts Options) (output.Summary, error) {
	if opts.Reader == nil {
		return output.Summary{}, errors.New("inspect reader is required")
	}
	if opts.Matcher == nil {
		opts.Matcher = filter.MatchAll{}
	}
	if opts.Rewriter == nil {
		opts.Rewriter = rewrite.NoOp{}
	}
	summary := output.Summary{Filter: opts.Matcher.String(), Rewrite: opts.Rewriter.String()}
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
		rewritten, err := opts.Rewriter.Rewrite(&packet)
		if err != nil {
			return summary, err
		}
		summary.Packets++
		summary.Bytes += uint64(len(packet.Data))
		if opts.Writer == nil {
			continue
		}
		record := Describe(summary.Packets, packet.Timestamp.Sub(first), packet, opts.LinkType)
		record.Rewritten = rewritten
		if err := opts.Writer.WriteRecord(record); err != nil {
			return summary, err
		}
	}
}

// Describe decodes one packet into a renderable record. Packets whose layers
// cannot be decoded degrade to placeholders instead of failing.
func Describe(number uint64, offset time.Duration, packet reader.Packet, linkType layers.LinkType) output.Record {
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
	return output.Record{
		Number:      number,
		Offset:      offset,
		Protocol:    protocol,
		Source:      source,
		Destination: destination,
		Bytes:       len(packet.Data),
	}
}

// address renders an endpoint, falling back to a placeholder when it is empty.
func address(endpoint gopacket.Endpoint) string {
	text := endpoint.String()
	if text == "" {
		return "?"
	}
	return text
}
