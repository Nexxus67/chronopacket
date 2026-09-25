package inspect

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/chronopacket/chronopacket/internal/filter"
	"github.com/chronopacket/chronopacket/internal/output"
	"github.com/chronopacket/chronopacket/internal/reader"
	"github.com/chronopacket/chronopacket/internal/testcapture"
	"github.com/google/gopacket/layers"
)

// staticReader replays a fixed slice of packets without touching libpcap.
type staticReader struct {
	packets []reader.Packet
	index   int
	closed  bool
}

func (r *staticReader) Read() (reader.Packet, error) {
	if r.index == len(r.packets) {
		return reader.Packet{}, io.EOF
	}
	p := r.packets[r.index]
	r.index++
	return p, nil
}
func (r *staticReader) Close() error { r.closed = true; return nil }

// textWriter renders records into buffer using the default terminal format.
func textWriter(t *testing.T, buffer io.Writer) output.Writer {
	t.Helper()
	writer, err := output.NewWriter(buffer, io.Discard, output.FormatText)
	if err != nil {
		t.Fatal(err)
	}
	return writer
}

func fixture(t *testing.T) string {
	t.Helper()
	return testcapture.Write(t,
		testcapture.Spec{Offset: 0, Protocol: layers.IPProtocolTCP, SourceIP: "192.168.1.10", DestIP: "93.184.216.34", SourcePort: 51532, DestPort: 443, PayloadSize: 20},
		testcapture.Spec{Offset: 42 * time.Millisecond, Protocol: layers.IPProtocolTCP, SourceIP: "93.184.216.34", DestIP: "192.168.1.10", SourcePort: 443, DestPort: 51532, PayloadSize: 12},
		testcapture.Spec{Offset: 5 * time.Second, Protocol: layers.IPProtocolUDP, SourceIP: "192.168.1.10", DestIP: "8.8.8.8", SourcePort: 53001, DestPort: 53, PayloadSize: 29},
	)
}

func TestRunDescribesEveryPacketWithoutAFilter(t *testing.T) {
	source, err := reader.NewPcapReader(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var output bytes.Buffer
	summary, err := Run(context.Background(), Options{Reader: source, LinkType: source.LinkType(), Writer: textWriter(t, &output)})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Inspected != 3 || summary.Packets != 3 {
		t.Fatalf("inspected=%d matched=%d, want 3/3", summary.Inspected, summary.Packets)
	}
	if summary.Duration != 5*time.Second {
		t.Fatalf("duration = %v, want 5s", summary.Duration)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3:\n%s", len(lines), output.String())
	}
	for _, want := range []string{"#1", "+0.000s", "TCP", "192.168.1.10:51532", "93.184.216.34:443"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("first line %q missing %q", lines[0], want)
		}
	}
	if !strings.Contains(lines[1], "+0.042s") {
		t.Errorf("second line %q missing relative timestamp", lines[1])
	}
	for _, want := range []string{"UDP", "192.168.1.10:53001", "8.8.8.8:53", "+5.000s"} {
		if !strings.Contains(lines[2], want) {
			t.Errorf("third line %q missing %q", lines[2], want)
		}
	}
}

func TestRunCountsFilteredPacketsSeparately(t *testing.T) {
	source, err := reader.NewPcapReader(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	matcher, err := filter.New(source.LinkType(), "tcp port 443")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	summary, err := Run(context.Background(), Options{Reader: source, Matcher: matcher, LinkType: source.LinkType(), Writer: textWriter(t, &output)})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Inspected != 3 || summary.Packets != 2 {
		t.Fatalf("inspected=%d matched=%d, want 3/2", summary.Inspected, summary.Packets)
	}
	if summary.Filter != "tcp port 443" {
		t.Fatalf("filter = %q", summary.Filter)
	}
	if strings.Contains(output.String(), "UDP") {
		t.Fatalf("filtered packet was printed:\n%s", output.String())
	}
	var rendered bytes.Buffer
	if err := textWriter(t, &rendered).WriteSummary(summary); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"inspected: 3 packets", "matched:   2 packets", "filter:    tcp port 443", "bytes:"} {
		if !strings.Contains(rendered.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, rendered.String())
		}
	}
}

func TestRunDoesNotWaitForCaptureTimestamps(t *testing.T) {
	base := time.Unix(1700000000, 0)
	source := &staticReader{packets: []reader.Packet{
		{Data: []byte{0x01, 0x02}, Timestamp: base},
		{Data: []byte{0x03}, Timestamp: base.Add(time.Hour)},
	}}
	started := time.Now()
	summary, err := Run(context.Background(), Options{Reader: source, LinkType: layers.LinkTypeEthernet, Writer: textWriter(t, io.Discard)})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("inspection took %v; it must not honor capture timing", elapsed)
	}
	if summary.Packets != 2 || summary.Bytes != 3 || summary.Duration != time.Hour {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestDescribeDegradesOnUndecodablePackets(t *testing.T) {
	record := Describe(7, 250*time.Millisecond, reader.Packet{Data: []byte{0xff, 0xfe}}, layers.LinkTypeEthernet)
	if record.Number != 7 || record.Offset != 250*time.Millisecond || record.Bytes != 2 {
		t.Fatalf("unexpected record: %+v", record)
	}
	if record.Protocol != "?" || record.Source != "?" || record.Destination != "?" {
		t.Fatalf("undecodable packet should use placeholders: %+v", record)
	}
}

func TestRunRequiresAReader(t *testing.T) {
	if _, err := Run(context.Background(), Options{}); err == nil {
		t.Fatal("expected an error when no reader is configured")
	}
}
