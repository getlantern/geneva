package censorsim

import (
	"net"

	"github.com/gopacket/gopacket"
)

// synSeqState is the SYN-synchronize + sequence-window tracker shared by the simple RST censors
// (2, 3, 5), identical to Censor1's tracking minus the flagged-IP bookkeeping.
type synSeqState struct {
	tcb uint32
}

// forbidden reports whether pkt is an in-window payload carrying a forbidden keyword, advancing
// the tracked sequence number as canonical Geneva does.
func (s *synSeqState) forbidden(pkt gopacket.Packet, forbidden [][]byte) bool {
	// These censors model IPv4/TCP and build RSTs from the IPv4 header, so ignore any packet
	// that is not IPv4/TCP rather than triggering (and later dereferencing a nil IPv4 layer).
	if ipv4Of(pkt) == nil {
		return false
	}
	tcp := tcpOf(pkt)
	if tcp == nil {
		return false
	}

	if flagsAre(tcp, "S") {
		s.tcb = tcp.Seq + 1
		return false
	}

	if tcp.Seq == s.tcb {
		s.tcb += uint32(len(payloadOf(tcp)))
	} else {
		return false
	}

	return containsForbidden(payloadOf(tcp), forbidden)
}

func repeat(pkt gopacket.Packet, n int, build func(gopacket.Packet) gopacket.Packet) []gopacket.Packet {
	out := make([]gopacket.Packet, 0, n)
	for range n {
		out = append(out, build(pkt))
	}

	return out
}

//
// Censor2: synchronize on the first SYN; on a forbidden keyword, inject 5 RSTs to the client.
//

type Censor2 struct {
	base
	syn synSeqState
}

func (c *Censor2) Process(pkt gopacket.Packet) Verdict {
	if c.syn.forbidden(pkt, c.cfg.Forbidden) {
		c.triggered = true
		return Verdict{
			Action:   Accept,
			Injected: repeat(pkt, 5, clientRST),
			Reason:   "forbidden keyword",
		}
	}

	return Verdict{Action: Accept}
}

//
// Censor3: like Censor2, but injects 5 RSTs to both the client and the server.
//

type Censor3 struct {
	base
	syn synSeqState
}

func (c *Censor3) Process(pkt gopacket.Packet) Verdict {
	if c.syn.forbidden(pkt, c.cfg.Forbidden) {
		c.triggered = true
		injected := repeat(pkt, 5, clientRST)
		injected = append(injected, repeat(pkt, 5, func(p gopacket.Packet) gopacket.Packet {
			return serverRST(c.cfg.CensorIP, p)
		})...)
		return Verdict{Action: Accept, Injected: injected, Reason: "forbidden keyword"}
	}

	return Verdict{Action: Accept}
}

//
// Censor5: like Censor2, but injects 5 RSTs to the server only.
//

type Censor5 struct {
	base
	syn synSeqState
}

func (c *Censor5) Process(pkt gopacket.Packet) Verdict {
	if c.syn.forbidden(pkt, c.cfg.Forbidden) {
		c.triggered = true
		return Verdict{
			Action: Accept,
			Injected: repeat(pkt, 5, func(p gopacket.Packet) gopacket.Packet {
				return serverRST(c.cfg.CensorIP, p)
			}),
			Reason: "forbidden keyword",
		}
	}

	return Verdict{Action: Accept}
}

//
// Multi-connection TCB machinery, shared by censors 8b, 10, and 11.
//

type mtcb struct {
	src, dst string
	sport    uint16
	dport    uint16
	seq      uint32
}

type connKey struct {
	src, dst string
	sport    uint16
	dport    uint16
}

func (t *mtcb) key() connKey {
	return connKey{src: t.src, dst: t.dst, sport: t.sport, dport: t.dport}
}

// matchingTCB returns the TCB whose full directional four-tuple and sequence match the packet.
func matchingTCB(tcbs []*mtcb, pkt gopacket.Packet) *mtcb {
	tcp := tcpOf(pkt)
	for _, t := range tcbs {
		if t.src == srcIP(pkt) && t.dst == dstIP(pkt) &&
			t.sport == uint16(tcp.SrcPort) && t.dport == uint16(tcp.DstPort) &&
			t.seq == tcp.Seq {
			return t
		}
	}

	return nil
}

// partialTCB returns the TCB whose directional four-tuple matches, ignoring the sequence number.
func partialTCB(tcbs []*mtcb, pkt gopacket.Packet) *mtcb {
	tcp := tcpOf(pkt)
	for _, t := range tcbs {
		if t.src == srcIP(pkt) && t.dst == dstIP(pkt) &&
			t.sport == uint16(tcp.SrcPort) && t.dport == uint16(tcp.DstPort) {
			return t
		}
	}

	return nil
}

func removeTCB(tcbs []*mtcb, target *mtcb) []*mtcb {
	for i, t := range tcbs {
		if t == target {
			return append(tcbs[:i], tcbs[i+1:]...)
		}
	}

	return tcbs
}

// flagBothIPs adds the packet's source and destination to the flagged list (deduplicated).
func flagBothIPs(flagged []string, pkt gopacket.Packet) []string {
	for _, ip := range []string{srcIP(pkt), dstIP(pkt)} {
		found := false
		for _, f := range flagged {
			if f == ip {
				found = true
				break
			}
		}
		if !found {
			flagged = append(flagged, ip)
		}
	}

	return flagged
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}

	return false
}

// injectPairedRSTs builds the 5 client + 5 server RSTs that the multi-connection RST censors emit.
func injectPairedRSTs(censorIP net.IP, pkt gopacket.Packet) []gopacket.Packet {
	injected := repeat(pkt, 5, clientRST)
	return append(injected, repeat(pkt, 5, func(p gopacket.Packet) gopacket.Packet {
		return serverRST(censorIP, p)
	})...)
}

//
// Censor8b: tracks multiple connections, tears a TCB down on a matching R/RA (no resync), does not
// validate checksums, and ignores segments with an invalid data offset. On a keyword it flags both
// IPs and injects paired RSTs.
//

type Censor8b struct {
	base
	tcbs       []*mtcb
	flaggedIPs []string
}

func (c *Censor8b) Process(pkt gopacket.Packet) Verdict {
	if c.check(pkt) {
		c.triggered = true
		c.flaggedIPs = flagBothIPs(c.flaggedIPs, pkt)
		return Verdict{Action: Accept, Injected: injectPairedRSTs(c.cfg.CensorIP, pkt), Reason: "forbidden keyword"}
	}

	return Verdict{Action: Accept}
}

func (c *Censor8b) check(pkt gopacket.Packet) bool {
	ip := ipv4Of(pkt)
	if ip == nil {
		return false
	}
	if contains(c.flaggedIPs, ip.SrcIP.String()) {
		return true
	}

	tcp := tcpOf(pkt)
	if tcp == nil {
		return false
	}
	if tcp.DataOffset < 5 {
		return false
	}

	tcb := matchingTCB(c.tcbs, pkt)
	switch {
	case tcb == nil && flagsAre(tcp, "S"):
		var isNew bool
		if partial := partialTCB(c.tcbs, pkt); partial != nil {
			tcb = partial
		} else {
			tcb = &mtcb{src: srcIP(pkt), dst: dstIP(pkt), sport: uint16(tcp.SrcPort), dport: uint16(tcp.DstPort), seq: tcp.Seq}
			isNew = true
		}
		tcb.seq++ // synchronizing on a SYN
		if isNew {
			// Reusing an existing TCB is already tracked; appending again would grow the
			// list with duplicate references without changing lookup behavior.
			c.tcbs = append(c.tcbs, tcb)
		}
		return false
	case tcb != nil && flagsAre(tcp, "R", "RA"):
		c.tcbs = removeTCB(c.tcbs, tcb)
		return false
	}

	if tcb == nil {
		return false
	}

	tcb.seq += uint32(len(payloadOf(tcp)))

	return containsForbidden(payloadOf(tcp), c.cfg.Forbidden)
}

//
// Censor10: tracks multiple connections, validates TCP checksums (ignoring segments whose checksum
// is wrong — which defeats bad-checksum insertion packets), and resynchronizes a TCB on a matching
// R/F. On a keyword it flags both IPs and injects paired RSTs.
//

type Censor10 struct {
	base
	tcbs       []*mtcb
	flaggedIPs []string
	resync     map[connKey]bool
}

func newCensor10(cfg Config) *Censor10 {
	return &Censor10{base: base{cfg: cfg, name: "10"}, resync: map[connKey]bool{}}
}

func (c *Censor10) Process(pkt gopacket.Packet) Verdict {
	if c.check(pkt) {
		c.triggered = true
		c.flaggedIPs = flagBothIPs(c.flaggedIPs, pkt)
		return Verdict{Action: Accept, Injected: injectPairedRSTs(c.cfg.CensorIP, pkt), Reason: "forbidden keyword"}
	}

	return Verdict{Action: Accept}
}

func (c *Censor10) check(pkt gopacket.Packet) bool {
	ip := ipv4Of(pkt)
	if ip == nil {
		return false
	}
	if contains(c.flaggedIPs, ip.SrcIP.String()) {
		return true
	}

	tcp := tcpOf(pkt)
	if tcp == nil {
		return false
	}
	if !tcpChecksumValid(pkt) {
		return false
	}

	tcb := matchingTCB(c.tcbs, pkt)
	switch {
	case (tcb != nil && c.resync[tcb.key()]) || (tcb == nil && flagsAre(tcp, "S")):
		var isNew bool
		if tcb == nil {
			tcb = partialTCB(c.tcbs, pkt)
		}
		if tcb == nil {
			tcb = &mtcb{}
			isNew = true
		}
		tcb.src, tcb.dst = srcIP(pkt), dstIP(pkt)
		tcb.sport, tcb.dport = uint16(tcp.SrcPort), uint16(tcp.DstPort)
		tcb.seq = tcp.Seq
		if flagsAre(tcp, "S") {
			tcb.seq++
		} else {
			tcb.seq += uint32(len(payloadOf(tcp)))
		}
		if isNew {
			c.tcbs = append(c.tcbs, tcb)
		}
		c.resync[tcb.key()] = false
		return false
	case tcb != nil && flagsAre(tcp, "R", "F"):
		c.resync[tcb.key()] = true
	}

	if tcb == nil {
		return false
	}

	tcb.seq += uint32(len(payloadOf(tcp)))

	return containsForbidden(payloadOf(tcp), c.cfg.Forbidden)
}

//
// Censor11: the most GFW-like. Like Censor10, but also ignores invalid data offsets, resynchronizes
// on S and A (defeating pre-handshake desynchronization), and tears/resyncs on R/F/RA/FA.
//

type Censor11 struct {
	base
	tcbs       []*mtcb
	flaggedIPs []string
	resync     map[connKey]bool
}

func newCensor11(cfg Config) *Censor11 {
	return &Censor11{base: base{cfg: cfg, name: "11"}, resync: map[connKey]bool{}}
}

func (c *Censor11) Process(pkt gopacket.Packet) Verdict {
	if c.check(pkt) {
		c.triggered = true
		c.flaggedIPs = flagBothIPs(c.flaggedIPs, pkt)
		return Verdict{Action: Accept, Injected: injectPairedRSTs(c.cfg.CensorIP, pkt), Reason: "forbidden keyword"}
	}

	return Verdict{Action: Accept}
}

func (c *Censor11) check(pkt gopacket.Packet) bool {
	ip := ipv4Of(pkt)
	if ip == nil {
		return false
	}
	if contains(c.flaggedIPs, ip.SrcIP.String()) {
		return true
	}

	tcp := tcpOf(pkt)
	if tcp == nil {
		return false
	}
	if tcp.DataOffset < 5 {
		return false
	}
	if !tcpChecksumValid(pkt) {
		return false
	}

	tcb := matchingTCB(c.tcbs, pkt)
	switch {
	case (tcb != nil && c.resync[tcb.key()]) || (tcb == nil && flagsAre(tcp, "S", "A")):
		var isNew bool
		tcb = partialTCB(c.tcbs, pkt)
		if tcb == nil {
			tcb = &mtcb{}
			isNew = true
		}
		tcb.src, tcb.dst = srcIP(pkt), dstIP(pkt)
		tcb.sport, tcb.dport = uint16(tcp.SrcPort), uint16(tcp.DstPort)
		tcb.seq = tcp.Seq
		if flagsAre(tcp, "S") {
			tcb.seq++
		} else {
			tcb.seq += uint32(len(payloadOf(tcp)))
		}
		if isNew {
			c.tcbs = append(c.tcbs, tcb)
		}
		c.resync[tcb.key()] = false
		return false
	case tcb != nil && flagsAre(tcp, "R", "F", "RA", "FA"):
		c.resync[tcb.key()] = true
	}

	if tcb == nil {
		return false
	}

	tcb.seq += uint32(len(payloadOf(tcp)))

	return containsForbidden(payloadOf(tcp), c.cfg.Forbidden)
}
