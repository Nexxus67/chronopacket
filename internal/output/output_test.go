package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// sample is one representative record.
var sample = Record{Number: 1, Offset: 42 * time.Millisecond, Protocol: "TCP", Source: "192.168.1.10:51532", Destination: "93.184.216.34:443", Bytes: 74}

// dryRun is the summary of an inspection with a filter and a rewrite.
var dryRun = Summary{Inspected: 481, Packets: 37, Bytes: 12492, Duration: 27464 * time.Millisecond, Filter: "tcp port 443", Rewrite: "ip 192.168.1.10=10.99.0.1"}

func TestParseFormat(t *testing.T) {
	for _, name := range []string{"text", "json", "csv"} {
		if _, err := ParseFormat(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, name := range []string{"", "TEXT", "yaml"} {
		if _, err := ParseFormat(name); err == nil {
			t.Errorf("%q: expected an error", name)
		}
	}
	if FormatText.Structured() {
		t.Error("text must not be treated as structured")
	}
	if !FormatJSON.Structured() || !FormatCSV.Structured() {
		t.Error("json and csv must be treated as structured")
	}
}

// TestTextMatchesTheTerminalLayout pins the v0.2 output byte for byte, because
// existing users and the README's examples depend on these exact columns.
func TestTextMatchesTheTerminalLayout(t *testing.T) {
	var buffer bytes.Buffer
	writer, err := NewWriter(&buffer, io.Discard, FormatText)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteRecord(sample); err != nil {
		t.Fatal(err)
	}
	want := "#1     +0.042s  TCP   192.168.1.10:51532       -> 93.184.216.34:443        74 bytes\n"
	if buffer.String() != want {
		t.Fatalf("record line:\n got %q\nwant %q", buffer.String(), want)
	}
	buffer.Reset()
	if err := writer.WriteSummary(dryRun); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"inspected: 481 packets\n",
		"matched:   37 packets\n",
		"bytes:     12492\n",
		"duration:  27.464s\n",
		"filter:    tcp port 443\n",
		"rewrite:   ip 192.168.1.10=10.99.0.1\n",
	} {
		if !strings.Contains(buffer.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, buffer.String())
		}
	}
}

func TestTextSummaryNotesTheAbsenceOfAFilter(t *testing.T) {
	var buffer bytes.Buffer
	writer, _ := NewWriter(&buffer, io.Discard, FormatText)
	summary := dryRun
	summary.Filter = ""
	summary.Rewrite = ""
	if err := writer.WriteSummary(summary); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buffer.String(), "no filter, all packets matched") {
		t.Errorf("unexpected summary:\n%s", buffer.String())
	}
	for _, unwanted := range []string{"filter:", "rewrite:"} {
		if strings.Contains(buffer.String(), unwanted) {
			t.Errorf("summary should omit %q:\n%s", unwanted, buffer.String())
		}
	}
}

func TestTextSummaryReportsAReplayDifferently(t *testing.T) {
	var buffer bytes.Buffer
	writer, _ := NewWriter(&buffer, io.Discard, FormatText)
	if err := writer.WriteSummary(Summary{Packets: 37, Bytes: 12492, Duration: time.Second, Replay: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buffer.String(), "completed: 37 packets") {
		t.Errorf("unexpected replay summary:\n%s", buffer.String())
	}
	if strings.Contains(buffer.String(), "inspected:") {
		t.Errorf("a replay has nothing to report as inspected:\n%s", buffer.String())
	}
}

func TestJSONEmitsOneObjectPerLineEndingWithTheSummary(t *testing.T) {
	var buffer bytes.Buffer
	writer, err := NewWriter(&buffer, io.Discard, FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteRecord(sample); err != nil {
		t.Fatal(err)
	}
	second := sample
	second.Number = 2
	second.Rewritten = true
	if err := writer.WriteRecord(second); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteSummary(dryRun); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3:\n%s", len(lines), buffer.String())
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("first line: %v", err)
	}
	if first["type"] != "packet" || first["protocol"] != "TCP" || first["bytes"] != float64(74) {
		t.Errorf("unexpected packet object: %v", first)
	}
	if first["offset_seconds"] != 0.042 {
		t.Errorf("offset_seconds = %v, want 0.042", first["offset_seconds"])
	}
	if first["rewritten"] != false {
		t.Errorf("rewritten = %v, want false", first["rewritten"])
	}
	var rewritten map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &rewritten); err != nil {
		t.Fatalf("second line: %v", err)
	}
	if rewritten["rewritten"] != true {
		t.Errorf("rewritten = %v, want true", rewritten["rewritten"])
	}
	var summary map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &summary); err != nil {
		t.Fatalf("summary line: %v", err)
	}
	if summary["type"] != "summary" || summary["packets"] != float64(37) || summary["inspected"] != float64(481) {
		t.Errorf("unexpected summary object: %v", summary)
	}
	if summary["filter"] != "tcp port 443" || summary["rewrite"] != "ip 192.168.1.10=10.99.0.1" {
		t.Errorf("summary lost the filter or rewrite: %v", summary)
	}
}

func TestJSONSummaryOmitsInspectedForAReplay(t *testing.T) {
	var buffer bytes.Buffer
	writer, _ := NewWriter(&buffer, io.Discard, FormatJSON)
	if err := writer.WriteSummary(Summary{Packets: 3, Bytes: 9, Replay: true}); err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if _, present := summary["inspected"]; present {
		t.Errorf("replay summary should omit inspected: %v", summary)
	}
}

// TestCSVKeepsStdoutParseableAndPutsTheSummaryOnStderr covers the contract that
// makes `--format csv` pipeable: stdout is one table, nothing else.
func TestCSVKeepsStdoutParseableAndPutsTheSummaryOnStderr(t *testing.T) {
	var records, summaryOut bytes.Buffer
	writer, err := NewWriter(&records, &summaryOut, FormatCSV)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteRecord(sample); err != nil {
		t.Fatal(err)
	}
	second := sample
	second.Number = 2
	second.Rewritten = true
	if err := writer.WriteRecord(second); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteSummary(dryRun); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&records).ReadAll()
	if err != nil {
		t.Fatalf("stdout is not valid CSV: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want a header plus two records:\n%v", len(rows), rows)
	}
	if strings.Join(rows[0], ",") != strings.Join(CSVHeader, ",") {
		t.Errorf("header = %v, want %v", rows[0], CSVHeader)
	}
	want := []string{"1", "0.042", "TCP", "192.168.1.10:51532", "93.184.216.34:443", "74", "false"}
	if strings.Join(rows[1], ",") != strings.Join(want, ",") {
		t.Errorf("row = %v, want %v", rows[1], want)
	}
	if rows[2][6] != "true" {
		t.Errorf("second row rewritten = %q, want true", rows[2][6])
	}
	if !strings.Contains(summaryOut.String(), "inspected: 481 packets") {
		t.Errorf("summary missing from the secondary stream:\n%s", summaryOut.String())
	}
}

func TestCSVWritesNoHeaderWhenThereAreNoRecords(t *testing.T) {
	var records, summaryOut bytes.Buffer
	writer, _ := NewWriter(&records, &summaryOut, FormatCSV)
	if err := writer.WriteSummary(Summary{}); err != nil {
		t.Fatal(err)
	}
	if records.Len() != 0 {
		t.Errorf("expected empty stdout, got %q", records.String())
	}
}

func TestNewWriterRejectsAnUnknownFormat(t *testing.T) {
	if _, err := NewWriter(io.Discard, io.Discard, Format("yaml")); err == nil {
		t.Fatal("expected an error for an unsupported format")
	}
}
