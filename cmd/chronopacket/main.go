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
	"strings"
	"syscall"

	"github.com/chronopacket/chronopacket/internal/config"
	"github.com/chronopacket/chronopacket/internal/filter"
	"github.com/chronopacket/chronopacket/internal/inspect"
	"github.com/chronopacket/chronopacket/internal/logging"
	"github.com/chronopacket/chronopacket/internal/output"
	"github.com/chronopacket/chronopacket/internal/reader"
	"github.com/chronopacket/chronopacket/internal/replay"
	"github.com/chronopacket/chronopacket/internal/rewrite"
	"github.com/chronopacket/chronopacket/internal/sender"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "chronopacket: %v\n", err)
		os.Exit(1)
	}
}

// repeatedFlag collects every occurrence of a flag, in the order given.
type repeatedFlag []string

// String renders the collected values for flag usage output.
func (f *repeatedFlag) String() string { return strings.Join(*f, ",") }

// Set appends one occurrence.
func (f *repeatedFlag) Set(value string) error { *f = append(*f, value); return nil }

func run(args []string, out, errOutput io.Writer) error {
	flags := flag.NewFlagSet("chronopacket", flag.ContinueOnError)
	flags.SetOutput(errOutput)
	pcapPath := flags.String("pcap", "", "path to a libpcap capture")
	iface := flags.String("iface", "", "network interface to transmit through")
	speed := flags.Float64("speed", 1, "replay speed multiplier: 1, 2, 5, or 10")
	filterExpr := flags.String("filter", "", "optional libpcap/BPF expression selecting packets to replay")
	dryRun := flags.Bool("dry-run", false, "inspect matching packets without transmitting anything")
	format := flags.String("format", string(output.FormatText), "output format: text, json, or csv")
	var mapIP, mapMAC repeatedFlag
	flags.Var(&mapIP, "map-ip", "rewrite an IP address as old=new; repeatable")
	flags.Var(&mapMAC, "map-mac", "rewrite a hardware address as old=new; repeatable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg := config.Config{
		PCAPPath:  *pcapPath,
		Interface: *iface,
		Speed:     *speed,
		Filter:    *filterExpr,
		DryRun:    *dryRun,
		MapIP:     mapIP,
		MapMAC:    mapMAC,
		Format:    *format,
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	outputFormat, err := cfg.OutputFormat()
	if err != nil {
		return err
	}
	rules, err := rewrite.ParseRules(cfg.MapIP, cfg.MapMAC)
	if err != nil {
		return err
	}

	input, err := reader.NewPcapReader(cfg.PCAPPath)
	if err != nil {
		return err
	}
	defer input.Close()
	matcher, err := filter.New(input.LinkType(), cfg.Filter)
	if err != nil {
		return err
	}
	rewriter, err := rewrite.New(input.LinkType(), rules)
	if err != nil {
		return err
	}
	records, err := output.NewWriter(out, errOutput, outputFormat)
	if err != nil {
		return err
	}
	defer records.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.DryRun {
		summary, err := inspect.Run(ctx, inspect.Options{Reader: input, Matcher: matcher, Rewriter: rewriter, LinkType: input.LinkType(), Writer: records})
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return errors.New("inspection interrupted")
			}
			return err
		}
		return records.WriteSummary(summary)
	}

	outputSender, err := sender.NewInterfaceSender(cfg.Interface)
	if err != nil {
		return err
	}
	defer outputSender.Close()
	// A live progress line would corrupt a structured stream sharing stdout.
	var reporter *logging.ProgressReporter
	if !outputFormat.Structured() {
		reporter = logging.NewProgressReporter(out, cfg.Speed)
	}
	source := rewrite.NewReader(filter.NewReader(input, matcher), rewriter)
	engine, err := replay.New(replay.Options{Reader: source, Sender: outputSender, Speed: cfg.Speed, Reporter: reporterOrNil(reporter)})
	if err != nil {
		return err
	}
	stats, err := engine.Run(ctx)
	if reporter != nil {
		reporter.Finish()
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return errors.New("replay interrupted")
		}
		return err
	}
	return records.WriteSummary(output.Summary{
		Packets:  stats.Packets,
		Replay:   true,
		Bytes:    stats.Bytes,
		Duration: stats.Elapsed,
		Filter:   matcher.String(),
		Rewrite:  rewriter.String(),
	})
}

// reporterOrNil avoids handing the engine a non-nil interface wrapping a nil
// reporter, which would panic on the first report.
func reporterOrNil(reporter *logging.ProgressReporter) replay.Reporter {
	if reporter == nil {
		return nil
	}
	return reporter
}
