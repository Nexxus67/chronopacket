# Architecture

ChronoPacket is organized around a small composition root in `cmd/chronopacket` and focused internal packages:

```text
CLI/configuration
       |
       +--> reader.PcapReader --> filter.Reader --> rewrite.Reader --> replay.Engine --> sender.InterfaceSender
       |                              |                   |                 |
       |                        filter.Matcher     rewrite.Rewriter         +--> timing.Sleeper
       |                              |                   |
       |                              +-------------------+--> inspect.Run (dry run; no sender, no sleeping)
       |                                                            |
       +--> logging.ProgressReporter                                +--> output.Writer (text | json | csv)
```

## Responsibilities

- `internal/config` validates user-facing replay options.
- `internal/reader` turns libpcap records into timestamped packet values.
- `internal/sender` validates a device and writes raw packet bytes through libpcap.
- `internal/filter` compiles libpcap/BPF expressions into a `Matcher` and wraps a reader so only matching packets reach the next stage.
- `internal/rewrite` parses `old=new` address substitutions into a `Rules` set, and wraps a reader so that matching addresses are replaced and affected checksums recomputed.
- `internal/inspect` decodes matching packets for dry runs into renderable records, and reports inspection totals.
- `internal/output` owns every rendering of a record or summary: the terminal layout, newline-delimited JSON, and CSV.
- `internal/timing` owns cancellable real-time waiting.
- `internal/replay` coordinates ordering, scaled inter-packet delays, cancellation, and statistics.
- `internal/logging` formats progress for the terminal.
- `internal/testcapture` builds small synthetic pcap fixtures for deterministic tests.
- `cmd/chronopacket` parses flags, wires concrete implementations, handles signals, and maps failures to a useful CLI error.

The engine does not know about libpcap, command-line flags, or terminal output. Its reader and sender interfaces make behavior easy to test with small fakes and provide stable seams for future features.

## Filtering and dry run

Filtering is a reader-side stage, not an engine concern. `filter.New` returns `MatchAll` for an empty expression and a compiled `BPF` otherwise; compilation happens in the composition root right after the capture is opened, so an invalid expression fails before a sender is opened or a packet is sent. `filter.Reader` wraps any `reader.Reader` and returns only matching packets, which leaves the engine unchanged: it still waits for the difference between the timestamps of consecutive packets it receives, so intervals spanning filtered-out packets are preserved.

Dry run is a separate top-level path in `cmd/chronopacket`. It uses the matcher directly rather than through `filter.Reader`, because the summary distinguishes inspected from matched packets. It constructs no sender and no sleeper, which structurally guarantees that no traffic is transmitted and that capture timestamps are not honored.

## Rewriting

Rewriting follows the filtering precedent: a composable packet-processing stage between the reader and the sender, invisible to the engine. `rewrite.ParseRules` validates every flag value in the composition root, and `rewrite.New` returns `NoOp` when nothing is configured, so an unconfigured run costs one interface call per packet and nothing more.

**Stage order is filter, then rewrite.** `filter.BPF` evaluates a compiled libpcap program against the packet bytes, so a filter placed after rewriting would be tested against substituted addresses — an expression like `host 192.168.1.10` would stop matching the very packets the user asked to relocate. Putting the filter first means expressions are always written against the capture as recorded.

Rewriting decodes a packet, substitutes addresses in the Ethernet, IPv4, and IPv6 layers, and re-serializes with `FixLengths` and `ComputeChecksums` so the IPv4 header checksum and the TCP and UDP pseudo-header checksums match the new addresses. Re-serialization deliberately stops at the transport header: gopacket decodes UDP port 53 as DNS, and re-encoding that layer would canonicalize the message and change its length, so everything past the transport header is copied verbatim. Any link-layer trailer beyond the network layer's declared length is appended after serialization, which keeps it out of the transport checksum. Substitutions may not cross between IPv4 and IPv6, so header sizes are fixed. A packet that matches no rule, or that cannot be decoded or rebuilt, passes through byte for byte; a malformed capture never aborts a run.

Dry run shares the same rewriter and applies it after matching, so inspection prints the addresses a replay with the same flags would transmit.

## Output

`output.Record` and `output.Summary` are what a run produces; `output.Writer` is the only thing that knows how they look. `inspect.Describe` decodes a packet into a `Record` and formats nothing, which is what made a second and third format cheap to add. Structured formats report themselves through `Format.Structured`, and the composition root suppresses the live progress reporter for them, because a carriage-returned progress line and a JSON or CSV stream cannot share stdout. CSV goes further and sends its summary to stderr, so stdout remains one parseable table.

## Extension points

New packet-processing stages belong between the reader and the sender, as filtering and rewriting are. New input/output transports can implement the existing boundaries. New renderings implement `output.Writer`. Metrics and APIs should subscribe to replay statistics or wrap the reporter boundary rather than add global state to the engine.

## Timing model

The first packet is sent immediately. Each later packet waits for the positive difference between its capture timestamp and the previous packet timestamp, divided by the configured speed. Non-increasing timestamps do not introduce a delay. Context cancellation interrupts an active wait and prevents further sends. When a filter is configured, only matching packets reach the engine, so the delay before a packet spans any filtered-out packets that preceded it. Dry-run inspection is outside this model entirely: it never sleeps. Rewriting does not touch timestamps, so it has no effect on pacing.
