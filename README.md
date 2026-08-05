# ChronoPacket

ChronoPacket is an open-source packet replay engine for deterministic network traffic reproduction. It is intended for security testing, IDS/IPS validation, malware-traffic simulation in controlled environments, networking labs, and performance benchmarking.

## v0.1 scope

The first release reads packets from a libpcap (`.pcap`) capture and transmits them sequentially through a selected interface while preserving capture timing. Replay speed can be `1x`, `2x`, `5x`, or `10x`. The CLI reports packets sent, elapsed time, replay speed, and packets per second.

Packet replay can inject traffic onto a real interface. Use it only on networks and systems you own or are explicitly authorized to test.

## Requirements

- Go 1.25 or newer
- libpcap development libraries and headers
- Permission to open the capture and transmit on the selected interface (often root or a suitable capability)

On macOS, libpcap is provided by the operating system. On Debian/Ubuntu, install `libpcap-dev`.

## Build and test

```sh
make test
make build
```

The binary is written to `bin/chronopacket`.

## Usage

```sh
sudo ./bin/chronopacket \
  --pcap capture.pcap \
  --iface eth0 \
  --speed 2
```

The selected interface is validated before replay begins. Press Ctrl-C to stop safely. Capture timestamps are used for inter-packet delays; packets with non-increasing timestamps are sent without an additional delay.

## Architecture

The command assembles four small boundaries: a pcap reader, a packet sender, a timing sleeper, and a progress reporter. The replay engine depends on interfaces for those boundaries, which keeps protocol-independent orchestration testable and leaves room for future adapters. See [architecture.md](architecture.md) for responsibilities and extension points.

## Roadmap

- v0.2: packet filtering and dry-run inspection
- v0.3: configurable IP/MAC rewriting and richer output formats
- v0.4: REST control API and Prometheus metrics
- v0.5: distributed replay workers and scenario management

YAML configuration, a TUI, and Docker packaging are intentionally outside v0.1.
