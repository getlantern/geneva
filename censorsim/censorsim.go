// Package censorsim provides in-process simulations of the censors from the canonical Geneva
// project (its censors/ directory), for use as an end-to-end test harness.
//
// Each censor models an on-path middlebox that watches a TCP/IPv4 packet stream and, when it
// sees a forbidden keyword (canonical Geneva defaults to "ultrasurf") in a payload it considers
// part of a tracked connection, "censors" the flow — dropping packets or injecting RSTs. None of
// them parse TLS or SNI: the keyword is a raw substring of the TCP payload. The keyword ends up
// inside a TLS ClientHello's SNI only because the traffic generator puts it there, so a strategy
// that splits or mangles the ClientHello (or desynchronizes the censor's connection tracking)
// hides it from the substring search.
//
// The censors form a difficulty ladder, from Censor1 (synchronize on the first SYN, then drop) up
// to Censor11 (multiple connections, checksum validation, SYN/ACK resynchronization — the most
// GFW-like). To test a strategy, apply it with the geneva engine, then Replay the resulting
// packets (plus a synthetic handshake) through a censor and assert Triggered() is false:
//
//	s, _ := geneva.NewStrategy("[TCP:flags:PA]-fragment{tcp:8:True}-| \\/")
//	mutated, _ := s.Apply(clientHello, strategy.DirectionOutbound)
//	c := censorsim.New("1", censorsim.Config{Forbidden: censorsim.DefaultForbidden()})
//	censorsim.Replay(c, append(handshake, mutated...))
//	// c.Triggered() == false  =>  the strategy evaded Censor1
//
// The simulations are faithful to the Python originals, including their quirks (exact TCP-flag
// matching, direction-keyed TCBs, and the sequence-number bookkeeping that desynchronization
// strategies exploit). Only IPv4/TCP is modeled, matching both geneva and geneva-server.
package censorsim

import (
	"bytes"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Action is what a censor decides to do with a packet it has just processed.
type Action int

const (
	// Accept forwards the packet unchanged.
	Accept Action = iota
	// Drop discards the packet.
	Drop
)

// Verdict is a censor's decision for a single processed packet.
type Verdict struct {
	// Action is what happens to the processed packet.
	Action Action
	// Injected holds any packets the censor emits in response (e.g. RSTs). These are real,
	// serialized IPv4/TCP packets so a test can assert on their flags, seq, and ack.
	Injected []gopacket.Packet
	// Reason is a short human-readable explanation, set when the censor triggered.
	Reason string
}

// Censor models a simulated on-path censor. Feed it the ordered packet stream (handshake
// included, since TCB-synchronizing censors track it); it keeps its TCB and flagged-IP state
// internally.
type Censor interface {
	// Process consumes one packet observed on the wire and returns the verdict.
	Process(pkt gopacket.Packet) Verdict
	// Triggered reports whether the censor has ever fired on this stream (dropped a payload,
	// flagged an IP, or injected a RST). For a strategy under test, false means it evaded.
	Triggered() bool
	// Name returns the censor's identifier (e.g. "1", "8b", "dummy").
	Name() string
}

// Config configures a censor.
type Config struct {
	// Forbidden is the set of keywords the censor searches for in TCP payloads.
	Forbidden [][]byte
	// CensorIP is the source address the censor spoofs for server-directed RST injection
	// (censors 3, 5, 8b, 10, 11). In the Python original this is the middlebox's own eth0
	// address; here it is a configured value. It may be nil for censors that never inject
	// server-directed RSTs.
	CensorIP net.IP
}

// DefaultForbidden returns the canonical Geneva default forbidden keyword ("ultrasurf").
func DefaultForbidden() [][]byte {
	return [][]byte{[]byte("ultrasurf")}
}

// New constructs a censor by name. Valid names are "dummy", "1".."11", and "8b" (optionally
// prefixed with "censor", e.g. "censor11").
func New(name string, cfg Config) (Censor, error) {
	if c, ok := constructors[normalizeName(name)]; ok {
		return c(cfg), nil
	}

	return nil, fmt.Errorf("unknown censor %q", name)
}

// Replay feeds packets through a censor in order and returns whether it triggered. It is a
// convenience wrapper over repeated Process calls for the common "does this strategy evade?"
// assertion; callers that need the per-packet verdicts should call Process directly.
func Replay(c Censor, packets []gopacket.Packet) bool {
	for _, pkt := range packets {
		c.Process(pkt)
	}

	return c.Triggered()
}

func normalizeName(name string) string {
	if len(name) > 6 && (name[:6] == "censor" || name[:6] == "Censor") {
		return name[6:]
	}

	return name
}

var constructors = map[string]func(Config) Censor{
	"dummy": func(cfg Config) Censor { return &Dummy{base: base{cfg: cfg, name: "dummy"}} },
	"1":     func(cfg Config) Censor { return &Censor1{base: base{cfg: cfg, name: "1"}} },
	"2":     func(cfg Config) Censor { return &Censor2{base: base{cfg: cfg, name: "2"}} },
	"3":     func(cfg Config) Censor { return &Censor3{base: base{cfg: cfg, name: "3"}} },
	"4":     func(cfg Config) Censor { return &Censor4{base: base{cfg: cfg, name: "4"}} },
	"5":     func(cfg Config) Censor { return &Censor5{base: base{cfg: cfg, name: "5"}} },
	"6":     func(cfg Config) Censor { return &Censor6{base: base{cfg: cfg, name: "6"}} },
	"7":     func(cfg Config) Censor { return &Censor7{base: base{cfg: cfg, name: "7"}} },
	"8":     func(cfg Config) Censor { return &Censor8{base: base{cfg: cfg, name: "8"}} },
	"8b":    func(cfg Config) Censor { return &Censor8b{base: base{cfg: cfg, name: "8b"}} },
	"9":     func(cfg Config) Censor { return &Censor9{base: base{cfg: cfg, name: "9"}} },
	"10":    func(cfg Config) Censor { return newCensor10(cfg) },
	"11":    func(cfg Config) Censor { return newCensor11(cfg) },
}

// base carries the state shared by every censor: its config, name, and whether it has fired.
type base struct {
	cfg       Config
	name      string
	triggered bool
}

// Triggered reports whether this censor has ever fired.
func (b *base) Triggered() bool { return b.triggered }

// Name returns this censor's identifier.
func (b *base) Name() string { return b.name }

//
// packet helpers
//

func ipv4Of(pkt gopacket.Packet) *layers.IPv4 {
	ip, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	return ip
}

func tcpOf(pkt gopacket.Packet) *layers.TCP {
	tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	return tcp
}

// payloadOf returns the TCP payload bytes (empty if none).
func payloadOf(tcp *layers.TCP) []byte {
	return tcp.LayerPayload()
}

// TCP flag bits, matching the on-the-wire order.
const (
	flagFIN uint16 = 1 << iota
	flagSYN
	flagRST
	flagPSH
	flagACK
	flagURG
	flagECE
	flagCWR
	flagNS
)

// flagMask returns the set flags of a TCP segment as a bitmask.
func flagMask(tcp *layers.TCP) uint16 {
	var m uint16
	for bit, set := range map[uint16]bool{
		flagFIN: tcp.FIN, flagSYN: tcp.SYN, flagRST: tcp.RST, flagPSH: tcp.PSH,
		flagACK: tcp.ACK, flagURG: tcp.URG, flagECE: tcp.ECE, flagCWR: tcp.CWR, flagNS: tcp.NS,
	} {
		if set {
			m |= bit
		}
	}

	return m
}

// parseFlagCode converts a scapy-style flag code (e.g. "S", "RA", "FA") to a bitmask.
func parseFlagCode(code string) uint16 {
	var m uint16
	for _, c := range code {
		switch c {
		case 'F', 'f':
			m |= flagFIN
		case 'S', 's':
			m |= flagSYN
		case 'R', 'r':
			m |= flagRST
		case 'P', 'p':
			m |= flagPSH
		case 'A', 'a':
			m |= flagACK
		case 'U', 'u':
			m |= flagURG
		case 'E', 'e':
			m |= flagECE
		case 'C', 'c':
			m |= flagCWR
		case 'N', 'n':
			m |= flagNS
		}
	}

	return m
}

// flagsAre reports whether a TCP segment has exactly the flags named by code and no others,
// mirroring canonical Geneva's `sprintf('%TCP.flags%') == code` comparison.
func flagsAre(tcp *layers.TCP, codes ...string) bool {
	got := flagMask(tcp)
	for _, code := range codes {
		if got == parseFlagCode(code) {
			return true
		}
	}

	return false
}

// containsForbidden reports whether payload contains any forbidden keyword.
func containsForbidden(payload []byte, forbidden [][]byte) bool {
	for _, word := range forbidden {
		if len(word) > 0 && bytes.Contains(payload, word) {
			return true
		}
	}

	return false
}

// tcpChecksumValid reports whether a segment's TCP checksum matches what geneva would compute.
// Deliberately corrupted checksums (a common insertion-packet trick) therefore read as invalid,
// which is what lets checksum-validating censors (10, 11) ignore them.
func tcpChecksumValid(pkt gopacket.Packet) bool {
	ip, tcp := ipv4Of(pkt), tcpOf(pkt)
	if ip == nil || tcp == nil || len(tcp.Contents) < 18 {
		return false
	}

	reported := tcp.Checksum
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return false
	}

	// ComputeChecksum sums the raw header, so the checksum field must be zeroed first (exactly
	// as common.UpdateTCPChecksum does); restore it afterward so the packet is left unchanged.
	c16, c17 := tcp.Contents[16], tcp.Contents[17]
	tcp.Contents[16], tcp.Contents[17] = 0, 0
	correct, err := tcp.ComputeChecksum()
	tcp.Contents[16], tcp.Contents[17] = c16, c17
	if err != nil {
		return false
	}

	return reported == correct
}

// buildRST constructs a serialized IPv4/TCP RST packet with a computed checksum.
func buildRST(srcIP, dstIP net.IP, sport, dport uint16, seq, ack uint32) gopacket.Packet {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sport),
		DstPort: layers.TCPPort(dport),
		Seq:     seq,
		Ack:     ack,
		RST:     true,
		Window:  0,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
		// Building a fixed RST from valid inputs cannot fail in practice; if it somehow does,
		// return an empty (nil-layer) packet rather than panicking in a test harness.
		return gopacket.NewPacket(nil, layers.LayerTypeIPv4, gopacket.Default)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

// clientRST builds the RST a censor spoofs toward the client (src/dst swapped from the observed
// packet), matching canonical Geneva's client RST construction.
func clientRST(pkt gopacket.Packet) gopacket.Packet {
	ip, tcp := ipv4Of(pkt), tcpOf(pkt)
	return buildRST(
		ip.DstIP, ip.SrcIP,
		uint16(tcp.DstPort), uint16(tcp.SrcPort),
		tcp.Ack, tcp.Seq+uint32(len(payloadOf(tcp))),
	)
}

// serverRST builds the RST a censor spoofs toward the server (from the censor's own IP), matching
// canonical Geneva's server RST construction.
func serverRST(censorIP net.IP, pkt gopacket.Packet) gopacket.Packet {
	ip, tcp := ipv4Of(pkt), tcpOf(pkt)
	return buildRST(
		censorIP, ip.DstIP,
		uint16(tcp.SrcPort), uint16(tcp.DstPort),
		tcp.Seq, tcp.Ack,
	)
}

// srcIP / dstIP return the packet's addresses as strings for TCB keys.
func srcIP(pkt gopacket.Packet) string { return ipv4Of(pkt).SrcIP.String() }
func dstIP(pkt gopacket.Packet) string { return ipv4Of(pkt).DstIP.String() }
