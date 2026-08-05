// Package sender provides packet transmission adapters.
package sender

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

// Sender transmits raw packet bytes.
type Sender interface {
	Send([]byte) error
	Close() error
}

// InterfaceSender transmits packets through a network interface using libpcap.
type InterfaceSender struct{ handle *pcap.Handle }

// NewInterfaceSender validates iface and opens it for packet transmission.
func NewInterfaceSender(iface string) (*InterfaceSender, error) {
	if _, err := net.InterfaceByName(iface); err != nil {
		return nil, fmt.Errorf("validate interface %q: %w", iface, err)
	}
	handle, err := pcap.OpenLive(iface, 65535, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open interface %q: %w", iface, err)
	}
	return &InterfaceSender{handle: handle}, nil
}

// Send writes one raw packet to the interface.
func (s *InterfaceSender) Send(data []byte) error {
	if err := s.handle.WritePacketData(data); err != nil {
		return fmt.Errorf("send packet: %w", err)
	}
	return nil
}

// Close releases the underlying libpcap handle.
func (s *InterfaceSender) Close() error { s.handle.Close(); return nil }
