# Architecture

ChronoPacket is organized around a small composition root in `cmd/chronopacket` and focused internal packages:

```text
CLI/configuration
       |
       +--> reader.PcapReader ----> replay.Engine ----> sender.InterfaceSender
       |                                  |
       +--> logging.ProgressReporter      +--> timing.Sleeper
```

## Responsibilities

- `internal/config` validates user-facing replay options.
- `internal/reader` turns libpcap records into timestamped packet values.
- `internal/sender` validates a device and writes raw packet bytes through libpcap.
- `internal/timing` owns cancellable real-time waiting.
- `internal/replay` coordinates ordering, scaled inter-packet delays, cancellation, and statistics.
- `internal/logging` formats progress for the terminal.
- `cmd/chronopacket` parses flags, wires concrete implementations, handles signals, and maps failures to a useful CLI error.

The engine does not know about libpcap, command-line flags, or terminal output. Its reader and sender interfaces make behavior easy to test with small fakes and provide stable seams for future features.

## Extension points

Future filtering or rewriting should be modeled as composable packet-processing stages between the reader and sender. New input/output transports can implement the existing boundaries. Metrics and APIs should subscribe to replay statistics or wrap the reporter boundary rather than add global state to the engine.

## Timing model

The first packet is sent immediately. Each later packet waits for the positive difference between its capture timestamp and the previous packet timestamp, divided by the configured speed. Non-increasing timestamps do not introduce a delay. Context cancellation interrupts an active wait and prevents further sends.
