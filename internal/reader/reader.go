// Package reader provides sequential packet sources.
package reader

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Packet is a captured packet and its original capture timestamp.
type Packet struct {
	Data      []byte
	Timestamp time.Time
}

// Reader reads packets in capture order.
type Reader interface {
	Read() (Packet, error)
	Close() error
}

// PcapReader reads packets from an offline libpcap capture.
type PcapReader struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
}

// NewPcapReader opens path for sequential reading.
func NewPcapReader(path string) (*PcapReader, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap %q: %w", path, err)
	}
	return &PcapReader{handle: handle, source: gopacket.NewPacketSource(handle, handle.LinkType())}, nil
}

// Read returns the next packet, or io.EOF when the capture is exhausted.
func (r *PcapReader) Read() (Packet, error) {
	p, err := r.source.NextPacket()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return Packet{}, io.EOF
		}
		return Packet{}, fmt.Errorf("read pcap: %w", err)
	}
	data := append([]byte(nil), p.Data()...)
	return Packet{Data: data, Timestamp: p.Metadata().Timestamp}, nil
}

// Close releases the underlying libpcap handle.
func (r *PcapReader) Close() error { r.handle.Close(); return nil }
