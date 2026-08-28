package censorsim

import "github.com/gopacket/gopacket"

// Dummy censors nothing; it exists to validate harness plumbing.
type Dummy struct{ base }

// Process always accepts and never triggers.
func (c *Dummy) Process(pkt gopacket.Packet) Verdict { return Verdict{Action: Accept} }

//
// Censor1: synchronize on the first SYN, track the sequence window, drop everything from a
// source once a forbidden keyword is seen in an in-window payload.
//

type Censor1 struct {
	base
	tcb         uint32
	dropAllFrom string
}

func (c *Censor1) Process(pkt gopacket.Packet) Verdict {
	if c.check(pkt) {
		c.triggered = true
		c.dropAllFrom = srcIP(pkt)
		return Verdict{Action: Drop, Reason: "forbidden keyword"}
	}

	return Verdict{Action: Accept}
}

func (c *Censor1) check(pkt gopacket.Packet) bool {
	ip := ipv4Of(pkt)
	if ip == nil {
		return false
	}
	if c.dropAllFrom != "" && c.dropAllFrom == ip.SrcIP.String() {
		return true
	}

	tcp := tcpOf(pkt)
	if tcp == nil {
		return false
	}

	if flagsAre(tcp, "S") {
		c.tcb = tcp.Seq + 1
		return false
	}

	if tcp.Seq == c.tcb {
		c.tcb += uint32(len(payloadOf(tcp)))
	} else {
		return false
	}

	return containsForbidden(payloadOf(tcp), c.cfg.Forbidden)
}

//
// Censor4: like Censor1, but also resynchronizes the TCB on every bare ACK, defeating strategies
// that desynchronize before the handshake completes.
//

type Censor4 struct {
	base
	tcb         uint32
	dropAllFrom string
}

func (c *Censor4) Process(pkt gopacket.Packet) Verdict {
	if c.check(pkt) {
		c.triggered = true
		c.dropAllFrom = srcIP(pkt)
		return Verdict{Action: Drop, Reason: "forbidden keyword"}
	}

	return Verdict{Action: Accept}
}

func (c *Censor4) check(pkt gopacket.Packet) bool {
	ip := ipv4Of(pkt)
	if ip == nil {
		return false
	}
	if c.dropAllFrom != "" && c.dropAllFrom == ip.SrcIP.String() {
		return true
	}

	tcp := tcpOf(pkt)
	if tcp == nil {
		return false
	}

	if flagsAre(tcp, "S") {
		c.tcb = tcp.Seq + 1
		return false
	}
	if flagsAre(tcp, "A") {
		c.tcb = tcp.Seq
		return false
	}

	if tcp.Seq == c.tcb {
		c.tcb += uint32(len(payloadOf(tcp)))
	} else {
		return false
	}

	return containsForbidden(payloadOf(tcp), c.cfg.Forbidden)
}

//
// Censor6: no sequence tracking. It inspects every payload until any R/RA/F tears the TCB down
// (it does not check that the R/RA/F belongs to the connection).
//

type Censor6 struct {
	base
	tornDown    bool
	dropAllFrom string
}

func (c *Censor6) Process(pkt gopacket.Packet) Verdict {
	if c.check(pkt) {
		c.triggered = true
		c.dropAllFrom = srcIP(pkt)
		return Verdict{Action: Drop, Reason: "forbidden keyword"}
	}

	return Verdict{Action: Accept}
}

func (c *Censor6) check(pkt gopacket.Packet) bool {
	ip := ipv4Of(pkt)
	if ip == nil {
		return false
	}
	if c.dropAllFrom != "" && c.dropAllFrom == ip.SrcIP.String() {
		return true
	}

	tcp := tcpOf(pkt)
	if tcp == nil {
		return false
	}

	if flagsAre(tcp, "R", "RA", "F") {
		c.tornDown = true
		return false
	}
	if c.tornDown {
		return false
	}

	return containsForbidden(payloadOf(tcp), c.cfg.Forbidden)
}

//
// Censor7: tears the TCB down only when a R/RA/F matches the connection's four-tuple (addresses
// and ports, direction-agnostic); it does not check the sequence number.
//

type Censor7 struct {
	base
	dropAllFrom string
	ips         [2]string
	ports       [2]uint16
	established bool
	tornDown    bool
}

func (c *Censor7) Process(pkt gopacket.Packet) Verdict {
	if c.check(pkt) {
		c.triggered = true
		c.dropAllFrom = srcIP(pkt)
		return Verdict{Action: Drop, Reason: "forbidden keyword"}
	}

	return Verdict{Action: Accept}
}

func (c *Censor7) check(pkt gopacket.Packet) bool {
	ip := ipv4Of(pkt)
	if ip == nil {
		return false
	}
	if c.dropAllFrom != "" && c.dropAllFrom == ip.SrcIP.String() {
		return true
	}

	tcp := tcpOf(pkt)
	if tcp == nil {
		return false
	}

	switch {
	case flagsAre(tcp, "R", "RA", "F"):
		if c.established && !c.tornDown && c.tupleMatches(pkt) {
			c.tornDown = true
			return false
		}
	case !c.established && !c.tornDown:
		c.ips = [2]string{srcIP(pkt), dstIP(pkt)}
		c.ports = [2]uint16{uint16(tcp.SrcPort), uint16(tcp.DstPort)}
		c.established = true
	}

	if c.tornDown {
		return false
	}

	return containsForbidden(payloadOf(tcp), c.cfg.Forbidden)
}

func (c *Censor7) tupleMatches(pkt gopacket.Packet) bool {
	tcp := tcpOf(pkt)
	return ipInSet(srcIP(pkt), c.ips) && ipInSet(dstIP(pkt), c.ips) &&
		portInSet(uint16(tcp.SrcPort), c.ports) && portInSet(uint16(tcp.DstPort), c.ports)
}

//
// Censor8: synchronizes on the first SYN, recording the four-tuple and sequence. It tears the TCB
// down on a R/F only when the full tuple *and* sequence match. Once established, it inspects every
// in-connection payload for the keyword.
//

type Censor8 struct {
	base
	dropAllFrom string
	ips         [2]string
	ports       [2]uint16
	seq         uint32
	established bool
	tornDown    bool
}

func (c *Censor8) Process(pkt gopacket.Packet) Verdict {
	if c.check(pkt) {
		c.triggered = true
		c.dropAllFrom = srcIP(pkt)
		return Verdict{Action: Drop, Reason: "forbidden keyword"}
	}

	return Verdict{Action: Accept}
}

func (c *Censor8) check(pkt gopacket.Packet) bool {
	ip := ipv4Of(pkt)
	if ip == nil {
		return false
	}
	if c.dropAllFrom != "" && c.dropAllFrom == ip.SrcIP.String() {
		return true
	}

	tcp := tcpOf(pkt)
	if tcp == nil {
		return false
	}

	switch {
	case flagsAre(tcp, "S") && !c.established && !c.tornDown:
		c.ips = [2]string{srcIP(pkt), dstIP(pkt)}
		c.ports = [2]uint16{uint16(tcp.SrcPort), uint16(tcp.DstPort)}
		c.seq = tcp.Seq + 1
		c.established = true
		return false
	case flagsAre(tcp, "R") || flagsAre(tcp, "F"):
		if c.established && !c.tornDown &&
			ipInSet(srcIP(pkt), c.ips) && ipInSet(dstIP(pkt), c.ips) &&
			portInSet(uint16(tcp.SrcPort), c.ports) && portInSet(uint16(tcp.DstPort), c.ports) &&
			tcp.Seq == c.seq {
			c.tornDown = true
			return false
		}
	}

	if c.tornDown {
		return false
	}
	if c.established && tcp.Seq == c.seq {
		c.seq += uint32(len(payloadOf(tcp)))
	}

	return containsForbidden(payloadOf(tcp), c.cfg.Forbidden)
}

//
// Censor9: a single-connection censor that does not tear the TCB down, but enters a
// resynchronization state on a matching R/F and re-establishes on the next packet — closely
// mimicking GFW resync behavior.
//

type Censor9 struct {
	base
	dropAllFrom string
	src, dst    string
	sport       uint16
	dport       uint16
	seq         uint32
	established bool
	resync      bool
}

func (c *Censor9) Process(pkt gopacket.Packet) Verdict {
	if c.check(pkt) {
		c.triggered = true
		c.dropAllFrom = srcIP(pkt)
		return Verdict{Action: Drop, Reason: "forbidden keyword"}
	}

	return Verdict{Action: Accept}
}

func (c *Censor9) check(pkt gopacket.Packet) bool {
	ip := ipv4Of(pkt)
	if ip == nil {
		return false
	}
	if c.dropAllFrom != "" && c.dropAllFrom == ip.SrcIP.String() {
		return true
	}

	tcp := tcpOf(pkt)
	if tcp == nil {
		return false
	}

	// Establish or resynchronize the TCB.
	if c.resync || (!c.established && flagsAre(tcp, "S")) {
		c.src, c.dst = srcIP(pkt), dstIP(pkt)
		c.sport, c.dport = uint16(tcp.SrcPort), uint16(tcp.DstPort)
		c.seq = tcp.Seq
		if flagsAre(tcp, "S") {
			c.seq++
		} else {
			c.seq += uint32(len(payloadOf(tcp)))
		}
		c.established = true
		c.resync = false
		return containsForbidden(payloadOf(tcp), c.cfg.Forbidden)
	}

	if c.tcbMatches(pkt) && (flagsAre(tcp, "R") || flagsAre(tcp, "F")) {
		c.resync = true
	}

	if !c.tcbMatches(pkt) {
		return false
	}
	if c.established {
		c.seq += uint32(len(payloadOf(tcp)))
	}

	return containsForbidden(payloadOf(tcp), c.cfg.Forbidden)
}

// tcbMatches mirrors canonical Geneva: an unestablished TCB matches everything; once established
// it requires an exact directional four-tuple and sequence match.
func (c *Censor9) tcbMatches(pkt gopacket.Packet) bool {
	if !c.established {
		return true
	}

	tcp := tcpOf(pkt)
	return srcIP(pkt) == c.src && dstIP(pkt) == c.dst &&
		uint16(tcp.SrcPort) == c.sport && uint16(tcp.DstPort) == c.dport &&
		tcp.Seq == c.seq
}

func ipInSet(ip string, set [2]string) bool {
	return ip == set[0] || ip == set[1]
}

func portInSet(port uint16, set [2]uint16) bool {
	return port == set[0] || port == set[1]
}
