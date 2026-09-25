package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
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

func TestDryRunShowsRewrittenAddresses(t *testing.T) {
	var output, errOutput bytes.Buffer
	args := []string{"--pcap", fixture(t), "--dry-run", "--map-ip", "192.168.1.10=10.99.0.1"}
	if err := run(args, &output, &errOutput); err != nil {
		t.Fatalf("dry run: %v (stderr: %s)", err, errOutput.String())
	}
	text := output.String()
	packets, summary, _ := strings.Cut(text, "inspected:")
	if !strings.Contains(packets, "10.99.0.1") {
		t.Errorf("rewritten address missing:\n%s", text)
	}
	// The summary echoes the rule, so only the packet lines may be checked here.
	if strings.Contains(packets, "192.168.1.10") {
		t.Errorf("original address still printed:\n%s", text)
	}
	if !strings.Contains(summary, "rewrite:   ip 192.168.1.10=10.99.0.1") {
		t.Errorf("summary missing the rewrite line:\n%s", text)
	}
}

// TestFilterMatchesCaptureAddressesNotRewrittenOnes pins the stage order: the
// filter sees the capture as recorded, so an expression written against the
// original addresses still selects the packets the user then relocates.
func TestFilterMatchesCaptureAddressesNotRewrittenOnes(t *testing.T) {
	var output, errOutput bytes.Buffer
	args := []string{"--pcap", fixture(t), "--dry-run", "--filter", "host 192.168.1.10", "--map-ip", "192.168.1.10=10.99.0.1"}
	if err := run(args, &output, &errOutput); err != nil {
		t.Fatalf("dry run: %v (stderr: %s)", err, errOutput.String())
	}
	text := output.String()
	if !strings.Contains(text, "matched:   2 packets") {
		t.Errorf("filter should still match both packets:\n%s", text)
	}
	if !strings.Contains(text, "10.99.0.1") {
		t.Errorf("matched packets should be printed rewritten:\n%s", text)
	}
}

func TestDryRunEmitsNewlineDelimitedJSON(t *testing.T) {
	var output, errOutput bytes.Buffer
	if err := run([]string{"--pcap", fixture(t), "--dry-run", "--format", "json"}, &output, &errOutput); err != nil {
		t.Fatalf("dry run: %v (stderr: %s)", err, errOutput.String())
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want two packets and a summary:\n%s", len(lines), output.String())
	}
	for index, line := range lines {
		var object map[string]any
		if err := json.Unmarshal([]byte(line), &object); err != nil {
			t.Fatalf("line %d is not JSON: %v", index+1, err)
		}
		want := "packet"
		if index == len(lines)-1 {
			want = "summary"
		}
		if object["type"] != want {
			t.Errorf("line %d type = %v, want %v", index+1, object["type"], want)
		}
	}
}

func TestDryRunEmitsCSVOnStdoutAndTheSummaryOnStderr(t *testing.T) {
	var output, errOutput bytes.Buffer
	if err := run([]string{"--pcap", fixture(t), "--dry-run", "--format", "csv"}, &output, &errOutput); err != nil {
		t.Fatalf("dry run: %v (stderr: %s)", err, errOutput.String())
	}
	rows, err := csv.NewReader(&output).ReadAll()
	if err != nil {
		t.Fatalf("stdout is not valid CSV: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want a header plus two packets:\n%v", len(rows), rows)
	}
	if rows[0][0] != "number" {
		t.Errorf("first row = %v, want a header", rows[0])
	}
	if !strings.Contains(errOutput.String(), "inspected: 2 packets") {
		t.Errorf("summary missing from stderr:\n%s", errOutput.String())
	}
}

func TestInvalidRewriteFailsBeforeReplay(t *testing.T) {
	var output, errOutput bytes.Buffer
	// As with the filter test, --iface is bogus: a rewrite error proves the flag
	// is parsed before any sender is opened.
	err := run([]string{"--pcap", fixture(t), "--iface", "definitely-not-an-interface", "--map-ip", "192.168.1.10"}, &output, &errOutput)
	if err == nil {
		t.Fatal("expected an error for a malformed --map-ip value")
	}
	if !strings.Contains(err.Error(), "192.168.1.10") {
		t.Fatalf("error = %v, want it to name the invalid value", err)
	}
	if output.Len() != 0 {
		t.Fatalf("no output expected, got:\n%s", output.String())
	}
}

func TestUnknownFormatFails(t *testing.T) {
	var output, errOutput bytes.Buffer
	err := run([]string{"--pcap", fixture(t), "--dry-run", "--format", "yaml"}, &output, &errOutput)
	if err == nil {
		t.Fatal("expected an error for an unsupported --format")
	}
	if !strings.Contains(err.Error(), "yaml") {
		t.Fatalf("error = %v, want it to name the format", err)
	}
}
