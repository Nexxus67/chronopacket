// Package output renders packet records and run summaries in a selectable format.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

// Format names one rendering of records and summaries.
type Format string

// The supported output formats.
const (
	// FormatText is the default human-readable column layout.
	FormatText Format = "text"
	// FormatJSON emits newline-delimited JSON objects.
	FormatJSON Format = "json"
	// FormatCSV emits a header row followed by one row per packet.
	FormatCSV Format = "csv"
)

// ParseFormat validates a user-supplied format name.
func ParseFormat(name string) (Format, error) {
	switch Format(name) {
	case FormatText, FormatJSON, FormatCSV:
		return Format(name), nil
	default:
		return "", fmt.Errorf("format must be one of text, json, or csv (got %q)", name)
	}
}

// Structured reports whether f is machine-readable, in which case live progress
// must not be interleaved with records on the same stream.
func (f Format) Structured() bool { return f == FormatJSON || f == FormatCSV }

// Record describes one packet that took part in a run.
type Record struct {
	Number      uint64
	Offset      time.Duration
	Protocol    string
	Source      string
	Destination string
	Bytes       int
	Rewritten   bool
}

// Summary contains the totals reported after a run.
type Summary struct {
	// Packets is the number of packets matched by a dry run, or sent by a replay.
	Packets uint64
	// Inspected is the number of packets read, and is meaningful only for a dry run.
	Inspected uint64
	Bytes     uint64
	Duration  time.Duration
	Filter    string
	Rewrite   string
	// Replay distinguishes a transmitting run from a dry-run inspection.
	Replay bool
}

// Writer renders records and a closing summary.
type Writer interface {
	WriteRecord(Record) error
	WriteSummary(Summary) error
	Close() error
}

// NewWriter builds a writer for f. Records go to out; a structured format that
// cannot carry the summary in band writes it to errOutput instead.
func NewWriter(out, errOutput io.Writer, f Format) (Writer, error) {
	switch f {
	case FormatText:
		return &textWriter{out: out}, nil
	case FormatJSON:
		return &jsonWriter{encoder: json.NewEncoder(out)}, nil
	case FormatCSV:
		return &csvWriter{records: csv.NewWriter(out), summary: errOutput}, nil
	default:
		return nil, fmt.Errorf("unsupported output format %q", f)
	}
}

// textWriter reproduces the compact terminal layout.
type textWriter struct{ out io.Writer }

// WriteRecord prints one aligned packet line.
func (w *textWriter) WriteRecord(r Record) error {
	_, err := fmt.Fprintf(w.out, "#%-5d +%.3fs  %-5s %-24s -> %-24s %d bytes\n",
		r.Number, r.Offset.Seconds(), r.Protocol, r.Source, r.Destination, r.Bytes)
	return err
}

// WriteSummary prints the closing totals, one label per line.
func (w *textWriter) WriteSummary(s Summary) error {
	if s.Replay {
		fmt.Fprintf(w.out, "completed: %d packets\n", s.Packets)
	} else {
		fmt.Fprintf(w.out, "inspected: %d packets\n", s.Inspected)
		if s.Filter == "" {
			fmt.Fprintf(w.out, "matched:   %d packets (no filter, all packets matched)\n", s.Packets)
		} else {
			fmt.Fprintf(w.out, "matched:   %d packets\n", s.Packets)
		}
	}
	fmt.Fprintf(w.out, "bytes:     %d\n", s.Bytes)
	fmt.Fprintf(w.out, "duration:  %s\n", s.Duration.Round(time.Millisecond))
	if s.Filter != "" {
		fmt.Fprintf(w.out, "filter:    %s\n", s.Filter)
	}
	if s.Rewrite != "" {
		fmt.Fprintf(w.out, "rewrite:   %s\n", s.Rewrite)
	}
	return nil
}

// Close has nothing to flush for text output.
func (w *textWriter) Close() error { return nil }

// jsonWriter emits one self-describing object per line.
type jsonWriter struct{ encoder *json.Encoder }

// packetLine is the wire shape of a record in JSON output.
type packetLine struct {
	Type          string  `json:"type"`
	Number        uint64  `json:"number"`
	OffsetSeconds float64 `json:"offset_seconds"`
	Protocol      string  `json:"protocol"`
	Source        string  `json:"source"`
	Destination   string  `json:"destination"`
	Bytes         int     `json:"bytes"`
	Rewritten     bool    `json:"rewritten"`
}

// summaryLine is the wire shape of a summary in JSON output.
type summaryLine struct {
	Type            string  `json:"type"`
	Packets         uint64  `json:"packets"`
	Inspected       uint64  `json:"inspected,omitempty"`
	Bytes           uint64  `json:"bytes"`
	DurationSeconds float64 `json:"duration_seconds"`
	Filter          string  `json:"filter,omitempty"`
	Rewrite         string  `json:"rewrite,omitempty"`
}

// WriteRecord encodes one packet object.
func (w *jsonWriter) WriteRecord(r Record) error {
	return w.encoder.Encode(packetLine{
		Type:          "packet",
		Number:        r.Number,
		OffsetSeconds: r.Offset.Seconds(),
		Protocol:      r.Protocol,
		Source:        r.Source,
		Destination:   r.Destination,
		Bytes:         r.Bytes,
		Rewritten:     r.Rewritten,
	})
}

// WriteSummary encodes the closing summary object.
func (w *jsonWriter) WriteSummary(s Summary) error {
	return w.encoder.Encode(summaryLine{
		Type:            "summary",
		Packets:         s.Packets,
		Inspected:       s.Inspected,
		Bytes:           s.Bytes,
		DurationSeconds: s.Duration.Seconds(),
		Filter:          s.Filter,
		Rewrite:         s.Rewrite,
	})
}

// Close has nothing to flush: each object is written as it is encoded.
func (w *jsonWriter) Close() error { return nil }

// csvWriter emits a single table on stdout and the summary on stderr, so that
// stdout stays parseable as one CSV document.
type csvWriter struct {
	records *csv.Writer
	summary io.Writer
	header  bool
}

// CSVHeader is the column order of CSV output.
var CSVHeader = []string{"number", "offset_seconds", "protocol", "source", "destination", "bytes", "rewritten"}

// WriteRecord writes the header row once, then one row per packet.
func (w *csvWriter) WriteRecord(r Record) error {
	if !w.header {
		if err := w.records.Write(CSVHeader); err != nil {
			return err
		}
		w.header = true
	}
	return w.records.Write([]string{
		strconv.FormatUint(r.Number, 10),
		strconv.FormatFloat(r.Offset.Seconds(), 'f', 3, 64),
		r.Protocol,
		r.Source,
		r.Destination,
		strconv.Itoa(r.Bytes),
		strconv.FormatBool(r.Rewritten),
	})
}

// WriteSummary renders the totals as text on the secondary stream.
func (w *csvWriter) WriteSummary(s Summary) error {
	w.records.Flush()
	if err := w.records.Error(); err != nil {
		return err
	}
	if w.summary == nil {
		return nil
	}
	return (&textWriter{out: w.summary}).WriteSummary(s)
}

// Close flushes buffered rows.
func (w *csvWriter) Close() error {
	w.records.Flush()
	return w.records.Error()
}
