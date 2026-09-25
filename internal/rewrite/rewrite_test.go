package rewrite

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/chronopacket/chronopacket/internal/reader"
	"github.com/chronopacket/chronopacket/internal/testcapture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// capture builds a two-packet Ethernet/IPv4 fixture: one TCP, one UDP.
func capture(t *testing.T) string {
	t.Helper()
	return testcapture.Write(t,
		testcapture.Spec{Offset: 0, Protocol: layers.IPProtocolTCP, SourceIP: "192.168.1.10", DestIP: "93.184.216.34", SourcePort: 51532, DestPort: 443, PayloadSize: 20},
		testcapture.Spec{Offset: 5 * time.Second, Protocol: layers.IPProtocolUDP, SourceIP: "192.168.1.10", DestIP: "8.8.8.8", SourcePort: 53001, DestPort: 53, PayloadSize: 29},
	)
}

// rules builds rules or fails the test.
func rules(t *testing.T, ipPairs, macPairs []string) *Rules {
	t.Helper()
	parsed, err := ParseRules(ipPairs, macPairs)
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}
	return parsed
}

// readAll drains a reader into a slice.
func readAll(t *testing.T, source reader.Reader) []reader.Packet {
	t.Helper()
	var packets []reader.Packet
	for {
		packet, err := source.Read()
		if err == io.EOF {
			return packets
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		packets = append(packets, packet)
	}
}

func TestRewriteSubstitutesAddressesAndFixesChecksums(t *testing.T) {
	source, err := reader.NewPcapReader(capture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	rewriter, err := New(source.LinkType(), rules(t,
		[]string{"192.168.1.10=10.99.0.1", "8.8.8.8=10.99.0.53"},
		[]string{"02:00:00:00:00:01=aa:bb:cc:dd:ee:ff"},
	))
	if err != nil {
		t.Fatal(err)
	}
	packets := readAll(t, NewReader(source, rewriter))
	if len(packets) != 2 {
		t.Fatalf("packets = %d, want 2", len(packets))
	}

	tcp := decode(t, packets[0])
	ip := tcp.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if got := ip.SrcIP.String(); got != "10.99.0.1" {
		t.Errorf("tcp src IP = %s, want 10.99.0.1", got)
	}
	// 93.184.216.34 has no rule, so it must survive untouched.
	if got := ip.DstIP.String(); got != "93.184.216.34" {
		t.Errorf("tcp dst IP = %s, want it unmapped", got)
	}
	ethernet := tcp.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if got := ethernet.SrcMAC.String(); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("src MAC = %s, want aa:bb:cc:dd:ee:ff", got)
	}
	if got := ethernet.DstMAC.String(); got != "02:00:00:00:00:02" {
		t.Errorf("dst MAC = %s, want it unmapped", got)
	}

	udp := decode(t, packets[1])
	udpIP := udp.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if udpIP.SrcIP.String() != "10.99.0.1" || udpIP.DstIP.String() != "10.99.0.53" {
		t.Errorf("udp addresses = %s -> %s", udpIP.SrcIP, udpIP.DstIP)
	}

	// A v4-to-v4 substitution must not change the frame length.
	original := readAll(t, mustOpen(t, capture(t)))
	for index := range packets {
		if len(packets[index].Data) != len(original[index].Data) {
			t.Errorf("packet %d length changed: %d != %d", index, len(packets[index].Data), len(original[index].Data))
		}
	}

	// Checksums must match the new addresses, not the captured ones.
	assertChecksumsValid(t, packets[0])
	assertChecksumsValid(t, packets[1])
}

// assertChecksumsValid re-serializes a packet's decoded layers with checksum
// computation on; correct stored checksums are reproduced byte for byte.
func assertChecksumsValid(t *testing.T, packet reader.Packet) {
	t.Helper()
	decoded := decode(t, packet)
	var network gopacket.NetworkLayer
	if ip, ok := decoded.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		network = ip
	}
	recomputed, err := rebuild(packet.Data, decoded, network)
	if err != nil {
		t.Fatalf("re-serialize: %v", err)
	}
	if !bytes.Equal(recomputed, packet.Data) {
		t.Errorf("stored checksums do not match recomputed ones\n got: % x\nwant: % x", packet.Data, recomputed)
	}
}

// decode parses a rewritten packet as Ethernet, failing on any decode error.
func decode(t *testing.T, packet reader.Packet) gopacket.Packet {
	t.Helper()
	decoded := gopacket.NewPacket(packet.Data, layers.LinkTypeEthernet, gopacket.Default)
	if err := decoded.ErrorLayer(); err != nil {
		t.Fatalf("decode rewritten packet: %v", err.Error())
	}
	return decoded
}

// mustOpen opens a capture or fails the test.
func mustOpen(t *testing.T, path string) reader.Reader {
	t.Helper()
	source, err := reader.NewPcapReader(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	return source
}

func TestRewriteLeavesUnmatchedPacketsByteIdentical(t *testing.T) {
	rewriter, err := New(layers.LinkTypeEthernet, rules(t, []string{"10.0.0.1=10.0.0.2"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	// An undecodable two-byte frame matches nothing and must pass through.
	packet := reader.Packet{Data: []byte{0xff, 0xfe}}
	changed, err := rewriter.Rewrite(&packet)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("undecodable packet reported as rewritten")
	}
	if !bytes.Equal(packet.Data, []byte{0xff, 0xfe}) {
		t.Errorf("packet mutated: % x", packet.Data)
	}

	// A well-formed packet whose addresses match no rule is also untouched.
	original := readAll(t, mustOpen(t, capture(t)))
	subject := reader.Packet{Data: append([]byte(nil), original[0].Data...)}
	changed, err = rewriter.Rewrite(&subject)
	if err != nil {
		t.Fatal(err)
	}
	if changed || !bytes.Equal(subject.Data, original[0].Data) {
		t.Errorf("unmatched packet was rewritten (changed=%v)", changed)
	}
}

func TestNewIsANoOpWithoutRules(t *testing.T) {
	rewriter, err := New(layers.LinkTypeEthernet, rules(t, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rewriter.(NoOp); !ok {
		t.Fatalf("rewriter = %T, want NoOp", rewriter)
	}
	if rewriter.String() != "" {
		t.Errorf("NoOp description = %q, want empty", rewriter.String())
	}
}

func TestMapMACNeedsAnEthernetCapture(t *testing.T) {
	_, err := New(layers.LinkTypeRaw, rules(t, nil, []string{"02:00:00:00:00:01=aa:bb:cc:dd:ee:ff"}))
	if err == nil {
		t.Fatal("expected --map-mac against a non-Ethernet capture to fail")
	}
	if !strings.Contains(err.Error(), "map-mac") {
		t.Errorf("error = %v, want it to name the flag", err)
	}
	// IP-only rules remain valid on the same link type.
	if _, err := New(layers.LinkTypeRaw, rules(t, []string{"10.0.0.1=10.0.0.2"}, nil)); err != nil {
		t.Errorf("IP rewriting on a raw capture: %v", err)
	}
}

func TestParseRulesRejectsBadValues(t *testing.T) {
	for name, test := range map[string]struct{ ip, mac []string }{
		"no separator":       {ip: []string{"10.0.0.1"}},
		"empty target":       {ip: []string{"10.0.0.1="}},
		"empty source":       {ip: []string{"=10.0.0.1"}},
		"not an IP":          {ip: []string{"not-an-ip=10.0.0.1"}},
		"bad target IP":      {ip: []string{"10.0.0.1=nope"}},
		"family mismatch":    {ip: []string{"10.0.0.1=fe80::1"}},
		"duplicate IP":       {ip: []string{"10.0.0.1=10.0.0.2", "10.0.0.1=10.0.0.3"}},
		"not a MAC":          {mac: []string{"nope=aa:bb:cc:dd:ee:ff"}},
		"bad target MAC":     {mac: []string{"aa:bb:cc:dd:ee:ff=nope"}},
		"duplicate MAC":      {mac: []string{"aa:bb:cc:dd:ee:ff=02:00:00:00:00:01", "aa:bb:cc:dd:ee:ff=02:00:00:00:00:02"}},
		"malformed MAC pair": {mac: []string{"aa:bb:cc:dd:ee:ff"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRules(test.ip, test.mac); err == nil {
				t.Fatalf("expected an error for %+v", test)
			}
		})
	}
}

func TestParseRulesNormalizesAndDescribes(t *testing.T) {
	parsed := rules(t, []string{"FE80::0001=fe80::2"}, []string{"AA-BB-CC-DD-EE-FF=02:00:00:00:00:01"})
	if parsed.Empty() {
		t.Fatal("rules should not be empty")
	}
	if !parsed.HasMAC() {
		t.Fatal("rules should report a MAC substitution")
	}
	// An uppercase, uncompressed source form must be keyed by its canonical spelling.
	if _, ok := parsed.ip["fe80::1"]; !ok {
		t.Fatalf("ip keys = %v, want a canonical fe80::1 key", parsed.ip)
	}
	if _, ok := parsed.mac["aa:bb:cc:dd:ee:ff"]; !ok {
		t.Fatalf("mac keys = %v, want a canonical key", parsed.mac)
	}
	want := "ip fe80::1=fe80::2, mac aa:bb:cc:dd:ee:ff=02:00:00:00:00:01"
	if parsed.String() != want {
		t.Errorf("description = %q, want %q", parsed.String(), want)
	}
}

func TestIPv4TargetsAreStoredAsFourBytes(t *testing.T) {
	parsed := rules(t, []string{"10.0.0.1=10.0.0.2"}, nil)
	target := parsed.ip["10.0.0.1"]
	if len(target) != net.IPv4len {
		t.Fatalf("target length = %d, want %d so header sizes stay fixed", len(target), net.IPv4len)
	}
}

// TestRewritePreservesApplicationPayloads guards the reason rebuild stops at the
// transport header: gopacket decodes UDP port 53 as DNS, and re-serializing that
// layer would canonicalize the message and change its length.
func TestRewritePreservesApplicationPayloads(t *testing.T) {
	original := readAll(t, mustOpen(t, capture(t)))
	rewriter, err := New(layers.LinkTypeEthernet, rules(t, []string{"8.8.8.8=10.99.0.53"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	// Packet 1 is the UDP/53 packet, whose 29-byte payload decodes as DNS.
	subject := reader.Packet{Data: append([]byte(nil), original[1].Data...)}
	changed, err := rewriter.Rewrite(&subject)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("packet should have been rewritten")
	}
	const headers = 14 + 20 + 8 // Ethernet + IPv4 + UDP
	if !bytes.Equal(subject.Data[headers:], original[1].Data[headers:]) {
		t.Errorf("payload changed\n got: % x\nwant: % x", subject.Data[headers:], original[1].Data[headers:])
	}
}

// TestRewritePreservesLinkLayerTrailers covers a frame carrying bytes beyond the
// IPv4 total length: the trailer must survive and stay out of the TCP checksum.
func TestRewritePreservesLinkLayerTrailers(t *testing.T) {
	original := readAll(t, mustOpen(t, capture(t)))
	trailer := []byte{0xde, 0xad, 0xbe, 0xef}
	padded := reader.Packet{Data: append(append([]byte(nil), original[0].Data...), trailer...)}
	rewriter, err := New(layers.LinkTypeEthernet, rules(t, []string{"192.168.1.10=10.99.0.1"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rewriter.Rewrite(&padded); err != nil {
		t.Fatal(err)
	}
	if len(padded.Data) != len(original[0].Data)+len(trailer) {
		t.Fatalf("length = %d, want %d", len(padded.Data), len(original[0].Data)+len(trailer))
	}
	if !bytes.Equal(padded.Data[len(padded.Data)-len(trailer):], trailer) {
		t.Errorf("trailer lost: % x", padded.Data)
	}
	// The TCP checksum must cover only the IPv4 packet, not the trailer, so it
	// must equal the checksum of the same packet rewritten without one.
	unpadded := reader.Packet{Data: append([]byte(nil), original[0].Data...)}
	if _, err := rewriter.Rewrite(&unpadded); err != nil {
		t.Fatal(err)
	}
	withTrailer := decode(t, reader.Packet{Data: padded.Data[:len(original[0].Data)]}).Layer(layers.LayerTypeTCP).(*layers.TCP)
	without := decode(t, unpadded).Layer(layers.LayerTypeTCP).(*layers.TCP)
	if withTrailer.Checksum != without.Checksum {
		t.Errorf("checksum = %#x with a trailer, %#x without", withTrailer.Checksum, without.Checksum)
	}
}
