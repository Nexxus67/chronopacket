# ChronoPacket

ChronoPacket is an open-source packet replay engine for deterministic network traffic reproduction. It is intended for security testing, IDS/IPS validation, malware-traffic simulation in controlled environments, networking labs, and performance benchmarking.

## Scope

v0.1 reads packets from a libpcap (`.pcap`/`.pcapng`) capture and transmits them sequentially through a selected interface while preserving capture timing. Replay speed can be `1x`, `2x`, `5x`, or `10x`. The CLI reports packets sent, elapsed time, replay speed, and packets per second.

v0.2 adds optional BPF packet filtering (`--filter`) and a non-transmitting inspection mode (`--dry-run`).

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

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `--pcap` | _(required)_ | Path to a libpcap capture. |
| `--iface` | _(required unless `--dry-run`)_ | Interface to transmit through. |
| `--speed` | `1` | Replay speed multiplier: `1`, `2`, `5`, or `10`. |
| `--filter` | _(none)_ | Optional libpcap/BPF expression selecting packets. |
| `--dry-run` | `false` | Inspect matching packets; never transmit. |

### Filtering

`--filter` takes a standard libpcap/BPF expression, the same syntax `tcpdump` accepts. There is no ChronoPacket-specific filter language. Non-matching packets are dropped before the sender ever sees them, and the original capture intervals between the packets that *are* replayed are preserved: if a matching packet is five seconds after the previous match, it is sent five seconds later at `1x`, one second later at `5x`. An invalid expression is reported and the process exits before any traffic is transmitted. Without `--filter`, behavior is identical to v0.1.

```sh
sudo ./bin/chronopacket \
  --pcap capture.pcapng \
  --iface eth0 \
  --filter "udp port 53" \
  --speed 2
```

Other examples: `"tcp port 443"`, `"host 192.168.1.10"`, `"udp and port 53"`.

### Dry run

`--dry-run` reads the capture, applies the optional filter, and prints one line per matching packet followed by a summary. It never opens an interface and never transmits, so `--iface` is not required and no elevated privileges are needed. Inspection runs at full speed and ignores capture timestamps for pacing. Packets whose layers cannot be decoded are printed with placeholders rather than aborting the run.

```sh
./bin/chronopacket --pcap capture.pcapng --dry-run

./bin/chronopacket \
  --pcap capture.pcapng \
  --filter "tcp port 443" \
  --dry-run
```

```text
#1     +0.000s  TCP   192.168.1.10:51532       -> 93.184.216.34:443        74 bytes
#2     +0.042s  TCP   93.184.216.34:443        -> 192.168.1.10:51532       66 bytes
#3     +0.153s  UDP   192.168.1.10:53001       -> 8.8.8.8:53               71 bytes
inspected: 481 packets
matched:   37 packets
bytes:     12492
duration:  27.464s
filter:    tcp port 443
```

Timestamps are relative to the first packet in the capture, and `duration` is the capture's own span. Without a filter the summary notes that every packet matched and omits the `filter` line.

## Architecture

The command assembles a pcap reader, an optional BPF filter stage between reader and sender, a packet sender, a timing sleeper, and a progress reporter. The replay engine depends on interfaces for those boundaries, which keeps protocol-independent orchestration testable and leaves room for future adapters. See [architecture.md](architecture.md) for responsibilities and extension points.

## Roadmap

- v0.2: packet filtering and dry-run inspection (implemented)
- v0.3: configurable IP/MAC rewriting and richer output formats
- v0.4: REST control API and Prometheus metrics
- v0.5: distributed replay workers and scenario management

IP/MAC rewriting, YAML configuration, a TUI, and Docker packaging remain outside v0.2.
