package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/chronopacket/chronopacket/internal/testcapture"
	"github.com/google/gopacket/layers"
)

func fixture(t *testing.T) string {
	t.Helper()
	return testcapture.Write(t,
		testcapture.Spec{Offset: 0, Protocol: layers.IPProtocolTCP, SourceIP: "192.168.1.10", DestIP: "93.184.216.34", SourcePort: 51532, DestPort: 443, PayloadSize: 20},
		testcapture.Spec{Offset: 30 * time.Second, Protocol: layers.IPProtocolUDP, SourceIP: "192.168.1.10", DestIP: "8.8.8.8", SourcePort: 53001, DestPort: 53, PayloadSize: 29},
	)
}

// TestDryRunNeedsNoInterfaceAndNeverSends covers the whole dry-run contract: the
// run succeeds without --iface (so no sender is ever opened, which would require
// root) and returns immediately instead of honoring the 30s capture span.
func TestDryRunNeedsNoInterfaceAndNeverSends(t *testing.T) {
	var output, errOutput bytes.Buffer
	started := time.Now()
	if err := run([]string{"--pcap", fixture(t), "--dry-run"}, &output, &errOutput); err != nil {
		t.Fatalf("dry run: %v (stderr: %s)", err, errOutput.String())
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("dry run took %v; it must not sleep for capture timing", elapsed)
	}
	text := output.String()
	for _, want := range []string{"#1", "TCP", "UDP", "inspected: 2 packets", "duration:  30s"} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "filter:") {
		t.Errorf("no filter was given, so no filter line is expected:\n%s", text)
	}
}

func TestDryRunAppliesFilter(t *testing.T) {
	var output, errOutput bytes.Buffer
	if err := run([]string{"--pcap", fixture(t), "--filter", "tcp port 443", "--dry-run"}, &output, &errOutput); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	text := output.String()
	if !strings.Contains(text, "matched:   1 packets") || !strings.Contains(text, "filter:    tcp port 443") {
		t.Fatalf("unexpected summary:\n%s", text)
	}
	if strings.Contains(text, "UDP") {
		t.Fatalf("filtered packet was printed:\n%s", text)
	}
}

func TestInvalidFilterFailsBeforeReplay(t *testing.T) {
	var output, errOutput bytes.Buffer
	// --iface is deliberately bogus: a valid run would fail on the interface, so
	// the filter error proves compilation happens before any sender is opened.
	err := run([]string{"--pcap", fixture(t), "--iface", "definitely-not-an-interface", "--filter", "tcp port bogus"}, &output, &errOutput)
	if err == nil {
		t.Fatal("expected an error for an invalid BPF expression")
	}
	if !strings.Contains(err.Error(), "tcp port bogus") {
		t.Fatalf("error = %v, want it to name the invalid filter", err)
	}
	if output.Len() != 0 {
		t.Fatalf("no traffic output expected, got:\n%s", output.String())
	}
}

func TestInterfaceStillRequiredForReplay(t *testing.T) {
	var output, errOutput bytes.Buffer
	if err := run([]string{"--pcap", fixture(t)}, &output, &errOutput); err == nil {
		t.Fatal("expected replay without --iface to fail")
	}
}

func TestMissingPCAPFails(t *testing.T) {
	var output, errOutput bytes.Buffer
	if err := run([]string{"--dry-run"}, &output, &errOutput); err == nil {
		t.Fatal("expected missing --pcap to fail")
	}
}
