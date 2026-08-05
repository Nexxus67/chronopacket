// Command chronopacket replays libpcap captures through a network interface.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/chronopacket/chronopacket/internal/config"
	"github.com/chronopacket/chronopacket/internal/logging"
	"github.com/chronopacket/chronopacket/internal/reader"
	"github.com/chronopacket/chronopacket/internal/replay"
	"github.com/chronopacket/chronopacket/internal/sender"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "chronopacket: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, output, errOutput io.Writer) error {
	flags := flag.NewFlagSet("chronopacket", flag.ContinueOnError)
	flags.SetOutput(errOutput)
	pcapPath := flags.String("pcap", "", "path to a libpcap capture")
	iface := flags.String("iface", "", "network interface to transmit through")
	speed := flags.Float64("speed", 1, "replay speed multiplier: 1, 2, 5, or 10")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg := config.Config{PCAPPath: *pcapPath, Interface: *iface, Speed: *speed}
	if err := cfg.Validate(); err != nil {
		return err
	}

	input, err := reader.NewPcapReader(cfg.PCAPPath)
	if err != nil {
		return err
	}
	defer input.Close()
	outputSender, err := sender.NewInterfaceSender(cfg.Interface)
	if err != nil {
		return err
	}
	defer outputSender.Close()
	reporter := logging.NewProgressReporter(output, cfg.Speed)
	engine, err := replay.New(replay.Options{Reader: input, Sender: outputSender, Speed: cfg.Speed, Reporter: reporter})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stats, err := engine.Run(ctx)
	reporter.Finish()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return errors.New("replay interrupted")
		}
		return err
	}
	fmt.Fprintf(output, "completed: %d packets, %d bytes\n", stats.Packets, stats.Bytes)
	return nil
}
