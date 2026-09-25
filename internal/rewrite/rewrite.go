// Package rewrite substitutes addresses in packets between reading and sending.
package rewrite

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/chronopacket/chronopacket/internal/reader"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Rewriter substitutes addresses in a packet, reporting whether it changed.
type Rewriter interface {
	Rewrite(*reader.Packet) (bool, error)
	String() string
}

// NoOp leaves every packet untouched and is used when no rules are configured.
type NoOp struct{}

// Rewrite reports no change.
func (NoOp) Rewrite(*reader.Packet) (bool, error) { return false, nil }

// String describes the absence of rewriting.
func (NoOp) String() string { return "" }

// Rules holds parsed address substitutions. Keys are canonical address strings.
type Rules struct {
	ip           map[string]net.IP
	mac          map[string]net.HardwareAddr
	descriptions []string
}

// Empty reports whether there is nothing to rewrite.
func (r *Rules) Empty() bool { return r == nil || (len(r.ip) == 0 && len(r.mac) == 0) }

// HasMAC reports whether any link-layer substitution was configured.
func (r *Rules) HasMAC() bool { return r != nil && len(r.mac) > 0 }

// String lists the substitutions in the order they were given.
func (r *Rules) String() string {
	if r == nil {
		return ""
	}
	return strings.Join(r.descriptions, ", ")
}

// ParseRules turns repeated "old=new" flag values into compiled rules. Every
// value is validated here so that a typo fails before any interface is opened.
func ParseRules(ipPairs, macPairs []string) (*Rules, error) {
	rules := &Rules{ip: map[string]net.IP{}, mac: map[string]net.HardwareAddr{}}
	for _, pair := range ipPairs {
		from, to, err := split("map-ip", pair)
		if err != nil {
			return nil, err
		}
		source, err := parseIP("map-ip", pair, from)
		if err != nil {
			return nil, err
		}
		target, err := parseIP("map-ip", pair, to)
		if err != nil {
			return nil, err
		}
		if (source.To4() == nil) != (target.To4() == nil) {
			return nil, fmt.Errorf("invalid --map-ip %q: cannot map between IPv4 and IPv6", pair)
		}
		if _, exists := rules.ip[source.String()]; exists {
			return nil, fmt.Errorf("invalid --map-ip %q: %s is already mapped", pair, source)
		}
		rules.ip[source.String()] = target
		rules.descriptions = append(rules.descriptions, fmt.Sprintf("ip %s=%s", source, target))
	}
	for _, pair := range macPairs {
		from, to, err := split("map-mac", pair)
		if err != nil {
			return nil, err
		}
		source, err := parseMAC(pair, from)
		if err != nil {
			return nil, err
		}
		target, err := parseMAC(pair, to)
		if err != nil {
			return nil, err
		}
		if _, exists := rules.mac[source.String()]; exists {
			return nil, fmt.Errorf("invalid --map-mac %q: %s is already mapped", pair, source)
		}
		rules.mac[source.String()] = target
		rules.descriptions = append(rules.descriptions, fmt.Sprintf("mac %s=%s", source, target))
	}
	return rules, nil
}

// split separates an "old=new" flag value.
func split(flagName, pair string) (string, string, error) {
	from, to, found := strings.Cut(pair, "=")
	if !found || from == "" || to == "" {
		return "", "", fmt.Errorf("invalid --%s %q: expected the form old=new", flagName, pair)
	}
	return strings.TrimSpace(from), strings.TrimSpace(to), nil
}

// parseIP parses one side of an IP substitution, normalizing IPv4 to 4 bytes so
// that serialized header lengths never change.
func parseIP(flagName, pair, text string) (net.IP, error) {
	address := net.ParseIP(text)
	if address == nil {
		return nil, fmt.Errorf("invalid --%s %q: %q is not an IP address", flagName, pair, text)
	}
	if v4 := address.To4(); v4 != nil {
		return v4, nil
	}
	return address, nil
}

// parseMAC parses one side of a hardware address substitution.
func parseMAC(pair, text string) (net.HardwareAddr, error) {
	address, err := net.ParseMAC(text)
	if err != nil {
		return nil, fmt.Errorf("invalid --map-mac %q: %q is not a hardware address", pair, text)
	}
	return address, nil
}

// New returns a rewriter for rules, or NoOp when there is nothing to do.
func New(linkType layers.LinkType, rules *Rules) (Rewriter, error) {
	if rules.Empty() {
		return NoOp{}, nil
	}
	if rules.HasMAC() && linkType != layers.LinkTypeEthernet {
		return nil, fmt.Errorf("--map-mac needs an Ethernet capture, but this one is %s", linkType)
	}
	return &addressRewriter{rules: rules, linkType: linkType}, nil
}

// addressRewriter decodes a packet, substitutes addresses, and re-serializes it
// so that header and transport checksums match the new addresses.
type addressRewriter struct {
	rules    *Rules
	linkType layers.LinkType
}

// serializeOptions recomputes lengths and checksums after a substitution.
var serializeOptions = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

// Rewrite applies the rules in place. Packets that match no rule, and packets
// whose layers cannot be decoded or re-serialized, are left byte-for-byte
// untouched rather than failing the run.
func (r *addressRewriter) Rewrite(packet *reader.Packet) (bool, error) {
	decoded := gopacket.NewPacket(packet.Data, r.linkType, gopacket.Default)
	if decoded.ErrorLayer() != nil {
		return false, nil
	}
	changed := false
	var network gopacket.NetworkLayer
	for _, layer := range decoded.Layers() {
		switch typed := layer.(type) {
		case *layers.Ethernet:
			if replacement, ok := r.rules.mac[typed.SrcMAC.String()]; ok {
				typed.SrcMAC = replacement
				changed = true
			}
			if replacement, ok := r.rules.mac[typed.DstMAC.String()]; ok {
				typed.DstMAC = replacement
				changed = true
			}
		case *layers.IPv4:
			network = typed
			if replacement, ok := r.rules.ip[typed.SrcIP.String()]; ok {
				typed.SrcIP = replacement
				changed = true
			}
			if replacement, ok := r.rules.ip[typed.DstIP.String()]; ok {
				typed.DstIP = replacement
				changed = true
			}
		case *layers.IPv6:
			network = typed
			if replacement, ok := r.rules.ip[typed.SrcIP.String()]; ok {
				typed.SrcIP = replacement
				changed = true
			}
			if replacement, ok := r.rules.ip[typed.DstIP.String()]; ok {
				typed.DstIP = replacement
				changed = true
			}
		}
	}
	if !changed {
		return false, nil
	}
	data, err := rebuild(packet.Data, decoded, network)
	if err != nil {
		return false, nil
	}
	packet.Data = data
	return true, nil
}

// String lists the configured substitutions.
func (r *addressRewriter) String() string { return r.rules.String() }

// rebuild reassembles data from the mutated headers of decoded.
//
// Only the link, network, and transport headers are re-serialized; everything
// beyond them is carried over verbatim. Re-encoding application layers would
// rewrite bytes ChronoPacket has no business touching — gopacket decodes UDP
// port 53 as DNS, for instance, and re-serializing that canonicalizes the
// message and changes its length. Any trailer past the network layer's declared
// length, such as Ethernet padding, is appended after serialization so that it
// stays out of the transport checksum.
func rebuild(data []byte, decoded gopacket.Packet, network gopacket.NetworkLayer) ([]byte, error) {
	last := lastHeader(decoded)
	if last == nil {
		return nil, errors.New("packet has no header to rebuild")
	}
	var stack []gopacket.SerializableLayer
	offset, networkStart, headerEnd := 0, -1, -1
	for _, layer := range decoded.Layers() {
		if network != nil && layer == network {
			networkStart = offset
		}
		serializable, ok := layer.(gopacket.SerializableLayer)
		if !ok {
			return nil, fmt.Errorf("layer %s cannot be re-serialized", layer.LayerType())
		}
		if network != nil {
			switch typed := serializable.(type) {
			case *layers.TCP:
				if err := typed.SetNetworkLayerForChecksum(network); err != nil {
					return nil, err
				}
			case *layers.UDP:
				if err := typed.SetNetworkLayerForChecksum(network); err != nil {
					return nil, err
				}
			}
		}
		stack = append(stack, serializable)
		offset += len(layer.LayerContents())
		if layer == last {
			headerEnd = offset
			break
		}
	}
	if headerEnd < 0 || headerEnd > len(data) {
		return nil, errors.New("packet headers are not contiguous")
	}
	payloadEnd := declaredEnd(network, networkStart, len(data))
	if payloadEnd < headerEnd || payloadEnd > len(data) {
		payloadEnd = len(data)
	}
	if payloadEnd > headerEnd {
		stack = append(stack, gopacket.Payload(data[headerEnd:payloadEnd]))
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, serializeOptions, stack...); err != nil {
		return nil, err
	}
	rebuilt := append([]byte(nil), buffer.Bytes()...)
	return append(rebuilt, data[payloadEnd:]...), nil
}

// lastHeader reports the deepest header rebuild re-serializes: the transport
// layer when there is one, otherwise the network or link layer.
func lastHeader(decoded gopacket.Packet) gopacket.Layer {
	if transport := decoded.TransportLayer(); transport != nil {
		return transport
	}
	if network := decoded.NetworkLayer(); network != nil {
		return network
	}
	if link := decoded.LinkLayer(); link != nil {
		return link
	}
	return nil
}

// declaredEnd reports where the network layer says its packet ends, so that any
// link-layer trailer after it can be preserved separately.
func declaredEnd(network gopacket.NetworkLayer, start, total int) int {
	if network == nil || start < 0 {
		return total
	}
	switch typed := network.(type) {
	case *layers.IPv4:
		if typed.Length > 0 {
			return start + int(typed.Length)
		}
	case *layers.IPv6:
		if typed.Length > 0 {
			return start + ipv6HeaderLength + int(typed.Length)
		}
	}
	return total
}

// ipv6HeaderLength is the fixed size of an IPv6 header, which IPv6.Length excludes.
const ipv6HeaderLength = 40

// Reader applies a rewriter to every packet of an underlying reader. It sits
// after any filter stage, so filter expressions still match capture addresses.
type Reader struct {
	source   reader.Reader
	rewriter Rewriter
}

// NewReader wraps source so that each packet is rewritten before it is returned.
func NewReader(source reader.Reader, rewriter Rewriter) *Reader {
	return &Reader{source: source, rewriter: rewriter}
}

// Read returns the next packet with substitutions applied.
func (r *Reader) Read() (reader.Packet, error) {
	packet, err := r.source.Read()
	if err != nil {
		return reader.Packet{}, err
	}
	if _, err := r.rewriter.Rewrite(&packet); err != nil {
		return reader.Packet{}, err
	}
	return packet, nil
}

// Close releases the underlying reader.
func (r *Reader) Close() error { return r.source.Close() }
