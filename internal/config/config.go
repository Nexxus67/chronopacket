// Package config contains validated runtime configuration for ChronoPacket.
package config

import (
	"fmt"

	"github.com/chronopacket/chronopacket/internal/output"
)

// Config contains the options required for one replay.
type Config struct {
	PCAPPath  string
	Interface string
	Speed     float64
	Filter    string
	DryRun    bool
	MapIP     []string
	MapMAC    []string
	Format    string
}

// Validate checks that the replay configuration is complete and supported.
func (c Config) Validate() error {
	if c.PCAPPath == "" {
		return fmt.Errorf("pcap path is required")
	}
	if c.Interface == "" && !c.DryRun {
		return fmt.Errorf("network interface is required")
	}
	if c.Speed != 1 && c.Speed != 2 && c.Speed != 5 && c.Speed != 10 {
		return fmt.Errorf("speed must be one of 1, 2, 5, or 10 (got %v)", c.Speed)
	}
	if _, err := c.OutputFormat(); err != nil {
		return err
	}
	return nil
}

// OutputFormat resolves the configured format, defaulting to text when unset.
func (c Config) OutputFormat() (output.Format, error) {
	if c.Format == "" {
		return output.FormatText, nil
	}
	return output.ParseFormat(c.Format)
}
