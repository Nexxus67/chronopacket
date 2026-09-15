# Architecture

ChronoPacket is organized around a small composition root in `cmd/chronopacket` and focused internal packages:

```text
CLI/configuration
       |
       +--> reader.PcapReader --> filter.Reader --> replay.Engine --> sender.InterfaceSender
       |                              |                   |
       |                        filter.Matcher            +--> timing.Sleeper
       |                              |
       |                              +--> inspect.Run (dry run; no sender, no sleeping)
       |
       +--> logging.ProgressReporter
```

## Responsibilities

- `internal/config` validates user-facing replay options.
- `internal/reader` turns libpcap records into timestamped packet values.
- `internal/sender` validates a device and writes raw packet bytes through libpcap.
- `internal/filter` compiles libpcap/BPF expressions into a `Matcher` and wraps a reader so only matching packets reach the next stage.
- `internal/inspect` decodes and prints matching packets for dry runs, and reports inspection totals.
- `internal/timing` owns cancellable real-time waiting.
- `internal/replay` coordinates ordering, scaled inter-packet delays, cancellation, and statistics.
- `internal/logging` formats progress for the terminal.
- `internal/testcapture` builds small synthetic pcap fixtures for deterministic tests.
- `cmd/chronopacket` parses flags, wires concrete implementations, handles signals, and maps failures to a useful CLI error.

The engine does not know about libpcap, command-line flags, or terminal output. Its reader and sender interfaces make behavior easy to test with small fakes and provide stable seams for future features.

## Filtering and dry run

Filtering is a reader-side stage, not an engine concern. `filter.New` returns `MatchAll` for an empty expression and a compiled `BPF` otherwise; compilation happens in the composition root right after the capture is opened, so an invalid expression fails before a sender is opened or a packet is sent. `filter.Reader` wraps any `reader.Reader` and returns only matching packets, which leaves the engine unchanged: it still waits for the difference between the timestamps of consecutive packets it receives, so intervals spanning filtered-out packets are preserved.

Dry run is a separate top-level path in `cmd/chronopacket`. It uses the matcher directly rather than through `filter.Reader`, because the summary distinguishes inspected from matched packets. It constructs no sender and no sleeper, which structurally guarantees that no traffic is transmitted and that capture timestamps are not honored.

## Extension points

Future rewriting should follow the filtering precedent: a composable packet-processing stage between the reader and the sender. New input/output transports can implement the existing boundaries. Metrics and APIs should subscribe to replay statistics or wrap the reporter boundary rather than add global state to the engine.

## Timing model

The first packet is sent immediately. Each later packet waits for the positive difference between its capture timestamp and the previous packet timestamp, divided by the configured speed. Non-increasing timestamps do not introduce a delay. Context cancellation interrupts an active wait and prevents further sends. When a filter is configured, only matching packets reach the engine, so the delay before a packet spans any filtered-out packets that preceded it. Dry-run inspection is outside this model entirely: it never sleeps.
