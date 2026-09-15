package filter

import (
	"io"
	"testing"
	"time"

	"github.com/chronopacket/chronopacket/internal/reader"
	"github.com/chronopacket/chronopacket/internal/testcapture"
	"github.com/google/gopacket/layers"
)

// fixture returns the standard four-packet capture used across filter tests.
func fixture(t *testing.T) string {
	t.Helper()
	return testcapture.Write(t,
		testcapture.Spec{Offset: 0, Protocol: layers.IPProtocolTCP, SourceIP: "192.168.1.10", DestIP: "93.184.216.34", SourcePort: 51532, DestPort: 443, PayloadSize: 20},
		testcapture.Spec{Offset: time.Second, Protocol: layers.IPProtocolTCP, SourceIP: "93.184.216.34", DestIP: "192.168.1.10", SourcePort: 443, DestPort: 51532, PayloadSize: 12},
		testcapture.Spec{Offset: 5 * time.Second, Protocol: layers.IPProtocolUDP, SourceIP: "192.168.1.10", DestIP: "8.8.8.8", SourcePort: 53001, DestPort: 53, PayloadSize: 29},
		testcapture.Spec{Offset: 6 * time.Second, Protocol: layers.IPProtocolTCP, SourceIP: "10.0.0.5", DestIP: "10.0.0.6", SourcePort: 1234, DestPort: 80, PayloadSize: 8},
	)
}

// readAll collects every packet a reader returns.
func readAll(t *testing.T, source interface {
	Read() (reader.Packet, error)
}) []reader.Packet {
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

func TestMatcherSelectsExpectedPackets(t *testing.T) {
	path := fixture(t)
	cases := []struct {
		name       string
		expression string
		want       int
	}{
		{"no filter accepts all", "", 4},
		{"tcp", "tcp", 3},
		{"udp", "udp", 1},
		{"tcp port", "tcp port 443", 2},
		{"udp and port", "udp and port 53", 1},
		{"host", "host 8.8.8.8", 1},
		{"port only", "port 80", 1},
		{"no match", "tcp port 9999", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source, err := reader.NewPcapReader(path)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			matcher, err := New(source.LinkType(), tc.expression)
			if err != nil {
				t.Fatal(err)
			}
			var matched int
			for _, packet := range readAll(t, source) {
				if matcher.Matches(packet) {
					matched++
				}
			}
			if matched != tc.want {
				t.Fatalf("matched = %d, want %d", matched, tc.want)
			}
		})
	}
}

func TestNewRejectsInvalidExpression(t *testing.T) {
	if _, err := New(layers.LinkTypeEthernet, "tcp port not-a-port"); err == nil {
		t.Fatal("expected an error for an invalid BPF expression")
	}
}

func TestNewWithoutExpressionMatchesEverything(t *testing.T) {
	matcher, err := New(layers.LinkTypeEthernet, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := matcher.(MatchAll); !ok {
		t.Fatalf("matcher = %T, want MatchAll", matcher)
	}
	if !matcher.Matches(reader.Packet{}) || matcher.String() != "" {
		t.Fatal("MatchAll must accept every packet and report an empty expression")
	}
}

func TestReaderSkipsNonMatchingPacketsAndKeepsTimestamps(t *testing.T) {
	source, err := reader.NewPcapReader(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	matcher, err := New(source.LinkType(), "udp or port 80")
	if err != nil {
		t.Fatal(err)
	}
	packets := readAll(t, NewReader(source, matcher))
	if len(packets) != 2 {
		t.Fatalf("packets = %d, want 2", len(packets))
	}
	if got := packets[0].Timestamp.Sub(testcapture.Base); got != 5*time.Second {
		t.Fatalf("first matching offset = %v, want 5s", got)
	}
	if got := packets[1].Timestamp.Sub(packets[0].Timestamp); got != time.Second {
		t.Fatalf("interval between matches = %v, want 1s", got)
	}
}
