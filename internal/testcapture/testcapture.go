// Package testcapture builds small deterministic pcap fixtures for tests.
package testcapture

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Spec describes one synthetic packet to write into a fixture capture.
type Spec struct {
	Offset      time.Duration
	Protocol    layers.IPProtocol
	SourceIP    string
	DestIP      string
	SourcePort  int
	DestPort    int
	PayloadSize int
}

// Base is the capture timestamp of a fixture's first packet.
var Base = time.Unix(1700000000, 0).UTC()

// Write creates a temporary Ethernet pcap file containing specs and returns its path.
func Write(t *testing.T, specs ...Spec) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capture.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	defer file.Close()
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write fixture header: %v", err)
	}
	for _, spec := range specs {
		data := build(t, spec)
		info := gopacket.CaptureInfo{
			Timestamp:     Base.Add(spec.Offset),
			CaptureLength: len(data),
			Length:        len(data),
		}
		if err := writer.WritePacket(info, data); err != nil {
			t.Fatalf("write fixture packet: %v", err)
		}
	}
	return path
}

// build serializes one Ethernet/IPv4/TCP-or-UDP packet.
func build(t *testing.T, spec Spec) []byte {
	t.Helper()
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: spec.Protocol,
		SrcIP:    net.ParseIP(spec.SourceIP).To4(),
		DstIP:    net.ParseIP(spec.DestIP).To4(),
	}
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buffer := gopacket.NewSerializeBuffer()
	payload := gopacket.Payload(make([]byte, spec.PayloadSize))
	var err error
	switch spec.Protocol {
	case layers.IPProtocolTCP:
		tcp := &layers.TCP{SrcPort: layers.TCPPort(spec.SourcePort), DstPort: layers.TCPPort(spec.DestPort), SYN: true, Window: 1024}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatalf("tcp checksum layer: %v", err)
		}
		err = gopacket.SerializeLayers(buffer, options, ethernet, ip, tcp, payload)
	case layers.IPProtocolUDP:
		udp := &layers.UDP{SrcPort: layers.UDPPort(spec.SourcePort), DstPort: layers.UDPPort(spec.DestPort)}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatalf("udp checksum layer: %v", err)
		}
		err = gopacket.SerializeLayers(buffer, options, ethernet, ip, udp, payload)
	default:
		err = gopacket.SerializeLayers(buffer, options, ethernet, ip, payload)
	}
	if err != nil {
		t.Fatalf("serialize fixture packet: %v", err)
	}
	return buffer.Bytes()
}
