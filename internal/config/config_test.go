package config

import "testing"

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
