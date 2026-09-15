// Package config contains validated runtime configuration for ChronoPacket.
package config

import "fmt"

// Config contains the options required for one replay.
type Config struct {
	PCAPPath  string
	Interface string
	Speed     float64
	Filter    string
	DryRun    bool
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
	return nil
}
