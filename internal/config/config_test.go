package config

import (
	"testing"

	"github.com/chronopacket/chronopacket/internal/output"
)

func TestConfigValidate(t *testing.T) {
	valid := Config{PCAPPath: "capture.pcap", Interface: "eth0", Speed: 2}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, speed := range []float64{0, 3, 0.5} {
		cfg := valid
		cfg.Speed = speed
		if err := cfg.Validate(); err == nil {
			t.Errorf("speed %v: expected validation error", speed)
		}
	}
}

func TestDryRunDoesNotRequireInterface(t *testing.T) {
	cfg := Config{PCAPPath: "capture.pcap", Speed: 1, DryRun: true}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("dry run without an interface: %v", err)
	}
	cfg.DryRun = false
	if err := cfg.Validate(); err == nil {
		t.Fatal("replay without an interface must fail")
	}
}

func TestFilterIsOptional(t *testing.T) {
	cfg := Config{PCAPPath: "capture.pcap", Interface: "eth0", Speed: 1}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty filter must be accepted: %v", err)
	}
	cfg.Filter = "tcp port 443"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("filter expression must be accepted: %v", err)
	}
}

func TestFormatDefaultsToTextAndRejectsUnknownNames(t *testing.T) {
	cfg := Config{PCAPPath: "capture.pcap", Interface: "eth0", Speed: 1}
	format, err := cfg.OutputFormat()
	if err != nil {
		t.Fatal(err)
	}
	if format != output.FormatText {
		t.Errorf("default format = %q, want text", format)
	}
	for _, name := range []string{"text", "json", "csv"} {
		cfg.Format = name
		if err := cfg.Validate(); err != nil {
			t.Errorf("format %q: %v", name, err)
		}
	}
	cfg.Format = "yaml"
	if err := cfg.Validate(); err == nil {
		t.Error("expected an unsupported format to fail validation")
	}
}

func TestRewriteFlagsAreOptional(t *testing.T) {
	cfg := Config{PCAPPath: "capture.pcap", Interface: "eth0", Speed: 1,
		MapIP: []string{"10.0.0.1=10.0.0.2"}, MapMAC: []string{"aa:bb:cc:dd:ee:ff=02:00:00:00:00:01"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("rewrite flags must be accepted: %v", err)
	}
}
