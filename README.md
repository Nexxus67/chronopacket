# ChronoPacket

ChronoPacket is an open-source packet replay engine for deterministic network traffic reproduction. It is intended for security testing, IDS/IPS validation, malware-traffic simulation in controlled environments, networking labs, and performance benchmarking.

## Scope

v0.1 reads packets from a libpcap (`.pcap`/`.pcapng`) capture and transmits them sequentially through a selected interface while preserving capture timing. Replay speed can be `1x`, `2x`, `5x`, or `10x`. The CLI reports packets sent, elapsed time, replay speed, and packets per second.

v0.2 adds optional BPF packet filtering (`--filter`) and a non-transmitting inspection mode (`--dry-run`).

v0.3 adds configurable IP and MAC rewriting (`--map-ip`, `--map-mac`) and selectable output formats (`--format text|json|csv`).

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
| `--map-ip` | _(none)_ | Rewrite an IP address as `old=new`. Repeatable. |
| `--map-mac` | _(none)_ | Rewrite a hardware address as `old=new`. Repeatable. Ethernet captures only. |
| `--format` | `text` | Output format: `text`, `json`, or `csv`. |

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

### Rewriting

`--map-ip` and `--map-mac` relocate a capture onto a different network. Each takes an `old=new` pair and may be repeated, so the two endpoints of a conversation can be moved independently:

```sh
sudo ./bin/chronopacket \
  --pcap capture.pcapng \
  --iface eth0 \
  --map-ip 192.168.1.10=10.0.0.5 \
  --map-ip 8.8.8.8=10.0.0.53 \
  --map-mac 02:00:00:00:00:01=aa:bb:cc:dd:ee:ff
```

Only addresses that appear on the left-hand side of a rule are touched; everything else is left exactly as captured. Source and destination fields are both considered, so one rule relocates a host in both directions of a conversation. IPv4 and IPv6 are supported, but a rule may not cross between them — the substituted address must be the same family, which keeps every header the size it was.

Rewriting fixes the IPv4 header checksum and the TCP and UDP checksums, which otherwise would no longer match the new addresses and would be dropped by the receiver. Only link, network, and transport headers are re-serialized; application payloads are carried over byte for byte, and any link-layer trailer is preserved outside the transport checksum. Packets that match no rule, and packets whose headers cannot be decoded, pass through untouched.

A malformed value is reported before the capture is read and before any interface is opened. `--map-mac` requires an Ethernet capture.

Filtering happens before rewriting, so a `--filter` expression is written against the addresses as recorded:

```sh
./bin/chronopacket --pcap capture.pcapng --dry-run \
  --filter "host 192.168.1.10" --map-ip 192.168.1.10=10.0.0.5
```

Combining `--map-ip` with `--dry-run` is the simplest way to check a rewrite: the printed addresses are the ones a real replay would put on the wire, with no root and no traffic.

### Output formats

`--format` selects how per-packet records and the closing summary are rendered.

- `text` (default) is the aligned terminal layout shown above.
- `json` emits newline-delimited JSON: one `{"type":"packet",...}` object per packet, then a final `{"type":"summary",...}` object.
- `csv` emits a header row followed by one row per packet. The summary goes to stderr instead, so stdout stays a single valid CSV table.

```sh
./bin/chronopacket --pcap capture.pcapng --dry-run --format json | jq -c 'select(.type=="packet")'

./bin/chronopacket --pcap capture.pcapng --dry-run --format csv > packets.csv
```

Each record carries a `rewritten` field reporting whether any rule applied to that packet, and the summary repeats the configured filter and rewrite rules. Because the live progress line would corrupt a structured stream sharing stdout, `--format json` and `--format csv` suppress it during a replay and report only the summary.

## Architecture

The command assembles a pcap reader, optional filter and rewrite stages between reader and sender, a packet sender, a timing sleeper, an output writer, and a progress reporter. The replay engine depends on interfaces for those boundaries, which keeps protocol-independent orchestration testable and leaves room for future adapters. See [architecture.md](architecture.md) for responsibilities and extension points.

## Roadmap

- v0.2: packet filtering and dry-run inspection (implemented)
- v0.3: configurable IP/MAC rewriting and richer output formats (implemented)
- v0.4: REST control API and Prometheus metrics
- v0.5: distributed replay workers and scenario management

Port rewriting, writing rewritten packets to a capture file, YAML configuration, a TUI, and Docker packaging remain outside v0.3.
