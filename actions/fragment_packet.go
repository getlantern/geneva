package actions

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/getlantern/errors"
	"github.com/getlantern/geneva/internal"
	"github.com/getlantern/geneva/internal/scanner"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FragmentAction is a Geneva action that splits a packet into two fragments and applies separate action trees to each.
//
// As an example, if Proto is "IP" and FragSize is 8, this will fragment a 60-byte IP packet into two fragments: the
// first will contain the first eight bytes of the original packet's payload, and the second will contain the remaining
// 52 bytes.  Each fragment will retain the original header (modulo the fields that must be updated to mark it as a
// fragmented packet). If the Proto's header includes a checksum, it will be recomputed.
type FragmentAction struct {
	// Proto is the protocol layer where the packet will be fragmented.
	Proto string
	// FragSize is the offset into the protocol's payload where fragmentation will happen.
	FragSize int
	// InOrder specifies whether to return the fragments in order.
	InOrder bool
	overlap int
	// FirstFragmentAction is the action to apply to the first fragment.
	FirstFragmentAction Action
	// SecondFragmentAction is the action to apply to the second fragment.
	SecondFragmentAction Action
}

// Apply applies this action to the given packet.
func (a *FragmentAction) Apply(packet gopacket.Packet) ([]gopacket.Packet, error) {
	var err error
	var packets, lpackets, rpackets []gopacket.Packet

	switch a.Proto {
	case "IP":
		// Note: the original Geneva code only fragments IPv4, not IPv6.
		packets, err = FragmentIPPacket(packet, a.FragSize)
	case "TCP":
		packets, err = FragmentTCPSegment(packet, a.FragSize)
	default:
		// TODO: should we log this?
		packets, err = duplicate(packet)
	}

	if err != nil {
		return nil, errors.Wrap(err)
	}

	if len(packets) == 2 && !a.InOrder {
		packets = []gopacket.Packet{packets[1], packets[0]}
	}

	if lpackets, err = a.FirstFragmentAction.Apply(packets[0]); err != nil {
		return nil, errors.Wrap(err)
	}

	if rpackets, err = a.SecondFragmentAction.Apply(packets[1]); err != nil {
		return nil, errors.Wrap(err)
	}

	return append(lpackets, rpackets...), nil
}

func FragmentTCPSegment(packet gopacket.Packet, fragSize int) ([]gopacket.Packet, error) {
	// XXX: the original Geneva code does not seem to handle TCP segmentation for IPv6 packets, so we don't either
	// for now.
	if packet.NetworkLayer().LayerType() != layers.LayerTypeIPv4 {
		return duplicate(packet)
	}

	if packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
		return duplicate(packet)
	}

	tcpPayload := packet.TransportLayer().LayerPayload()

	tcpPayloadLen := len(tcpPayload)
	if tcpPayloadLen == 0 {
		return duplicate(packet)
	}

	if fragSize == -1 || fragSize > tcpPayloadLen-1 {
		fragSize = tcpPayloadLen / 2
	}

	// XXX: upstream Geneva supports "overlap bytes"; i.e., taking the first few bytes of the second fragment and
	// tacking them onto the end of the first fragment. It's not mentioned in the original paper. We don't do this
	// right now, but could later.

	headersLen := len(packet.Data()) - tcpPayloadLen

	/*
	 * Strangely, all the manual bit-banging below was easier than dealing with creating packets using gopacket.
	 */

	// create the first fragment.
	f1Len := headersLen + fragSize
	buf := make([]byte, f1Len)
	copy(buf, packet.Data()[:f1Len])

	// fix up the IP header's Total Length field and checksum
	binary.BigEndian.PutUint16(buf[2:], uint16(f1Len))
	ipHdrLen := uint16(buf[0]&0x0f) * 4
	ComputeIPv4Checksum(buf[:ipHdrLen])

	chksum := ComputeTCPChecksum(buf[:ipHdrLen], buf[ipHdrLen:headersLen], buf[headersLen:])
	binary.BigEndian.PutUint16(buf[ipHdrLen+16:], chksum)

	first := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.NoCopy)

	// create the second fragment.
	f2Len := headersLen + tcpPayloadLen - fragSize
	buf = make([]byte, f2Len)
	copy(buf, packet.Data()[:headersLen])
	copy(buf[headersLen:], packet.Data()[headersLen+fragSize:])

	// fix up the IP header's Total Length field and checksum
	binary.BigEndian.PutUint16(buf[2:], uint16(f2Len))
	ComputeIPv4Checksum(buf[:ipHdrLen])

	// fix up the TCP sequence number. Excitingly, Go does integer wrapping, so we don't have to.
	tcp := buf[ipHdrLen:]
	seqNum := binary.BigEndian.Uint32(tcp[4:])
	seqNum += uint32(fragSize)
	binary.BigEndian.PutUint32(tcp[4:], seqNum)

	// fix up the TCP checksum
	chksum = ComputeTCPChecksum(buf[:ipHdrLen], buf[ipHdrLen:headersLen], buf[headersLen:])
	binary.BigEndian.PutUint16(buf[ipHdrLen+16:], chksum)

	second := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.NoCopy)

	return []gopacket.Packet{first, second}, nil
}

// FragmentIPPacket will fragment an IPv4 or IPv6 packet into two packets at the given 8-byte chunk offset.
//
// The first fragment will include up to (fragSize * 8) bytes of the IP packet's payload, and the second fragment will
// include the rest.
func FragmentIPPacket(packet gopacket.Packet, fragSize int) ([]gopacket.Packet, error) {
	if packet.NetworkLayer() == nil || packet.NetworkLayer().LayerType() != layers.LayerTypeIPv4 {
		return duplicate(packet)
	}

	plen := len(packet.NetworkLayer().LayerPayload())
	if plen == 0 {
		return duplicate(packet)
	}

	if fragSize == -1 || (fragSize*8)%8 > plen || plen <= 8 {
		fragSize = plen / 2 / 8
	}

	// corner case: if fragSize is 0, just return the original packet.
	if fragSize == 0 {
		return []gopacket.Packet{packet}, nil
	}

	// from this point on we can assume that the IP payload is _at least_ (fragSize*8) bytes long

	ofs := len(packet.Data()) - len(packet.NetworkLayer().LayerContents()) - len(packet.NetworkLayer().LayerPayload())
	if ofs < 0 {
		// something bad has happened, so let's bail.
		return nil, errors.New("error calculating offset to network layer")
	}

	buf := make([]byte, len(packet.Data()))
	copy(buf, packet.Data())
	ipv4Buf := buf[ofs:]

	hdrLen := uint16((ipv4Buf[0] & 0x0f) * 4)
	payloadLen := binary.BigEndian.Uint16(ipv4Buf[2:]) - hdrLen

	// fix up the fragment size to a multiple of 8 to satisfy fragment offset value
	offset := uint16((fragSize * 8))

	// update the total length of the first fragmented packet
	binary.BigEndian.PutUint16(ipv4Buf[2:], hdrLen+offset)

	// set the More Fragments bit, and make the fragment offset 0
	flagsAndFrags := (binary.BigEndian.Uint16(ipv4Buf[6:]) | 0x20) & 0xe0
	binary.LittleEndian.PutUint16(ipv4Buf[6:], flagsAndFrags)

	ComputeIPv4Checksum(ipv4Buf[:hdrLen])

	// slice off everything past the first fragment's end
	buf = buf[:uint16(ofs)+hdrLen+offset]

	first := gopacket.NewPacket(buf, packet.Layers()[0].LayerType(), gopacket.NoCopy)

	// now start on the second fragment.
	// First copy the old IP header as-is, then copy just the second fragment's payload right after.
	buf = make([]byte, len(packet.Data())-int(offset))
	copy(buf, packet.Data()[:uint16(ofs)+hdrLen])

	ipv4Buf = buf[ofs:]
	copy(ipv4Buf[hdrLen:], packet.Data()[uint16(ofs)+hdrLen+offset:])

	// fix up the length
	binary.BigEndian.PutUint16(ipv4Buf[2:], hdrLen+payloadLen-offset)

	// clear the MF bit and set the fragment offset appropriately
	flagsAndFrags = (binary.BigEndian.Uint16(ipv4Buf[6:]) & 0x40) + uint16(fragSize)
	binary.BigEndian.PutUint16(ipv4Buf[6:], flagsAndFrags)

	ComputeIPv4Checksum(ipv4Buf[:hdrLen])

	second := gopacket.NewPacket(buf, packet.Layers()[0].LayerType(), gopacket.NoCopy)

	return []gopacket.Packet{first, second}, nil
}

// VerifyIPv4Checksum verifies whether an IPv4 header's checksum field is correct.
func VerifyIPv4Checksum(header []byte) bool {
	c := internal.OnesComplementChecksum{}

	for i := 0; i < len(header); i += 2 {
		c.Add(binary.BigEndian.Uint16(header[i:]))
	}

	return c.Finalize() == 0
}

// ComputeIPv4Checksum computes a new checksum for the given IPv4 header and writes it into the header.
func ComputeIPv4Checksum(header []byte) uint16 {
	// zero out the old checksum
	binary.BigEndian.PutUint16(header[10:], 0)

	c := internal.OnesComplementChecksum{}

	for i := 0; i < len(header); i += 2 {
		c.Add(binary.BigEndian.Uint16(header[i:]))
	}
	chksum := c.Finalize()
	binary.BigEndian.PutUint16(header[10:], chksum)
	return chksum
}

func ComputeTCPChecksum(ipHeader, tcpHeader, payload []byte) uint16 {
	c := internal.OnesComplementChecksum{}

	// pseudo-header
	c.Add(binary.BigEndian.Uint16(ipHeader[12:])) // source ip address
	c.Add(binary.BigEndian.Uint16(ipHeader[14:])) // destination ip address
	c.Add(uint16(ipHeader[6]) << 8)               // protocol
	tcpLength := binary.BigEndian.Uint16(ipHeader[2:])
	tcpLength -= uint16((ipHeader[0] & 0xf)) * 4
	c.Add(tcpLength) // "TCP Length" from RFC 793

	// TCP header
	for i := 0; i < len(tcpHeader); i += 2 {
		if i == 16 {
			// don't add existing checksum value
			continue
		}
		c.Add(binary.BigEndian.Uint16(tcpHeader[i:]))
	}

	// TCP payload
	for i := 0; i < len(payload); i += 2 {
		if len(payload)-i == 1 {
			// If there are an odd number of octets in the payload, the last octet must be padded on the
			// right with zeros.
			c.Add(uint16(payload[i]) << 8)
		} else {
			c.Add(binary.BigEndian.Uint16(payload[i:]))
		}
	}
	return c.Finalize()
}

func VerifyTCPChecksum(ipHeader, tcpHeader, payload []byte) bool {
	c := internal.OnesComplementChecksum{}
	c.Add(ComputeTCPChecksum(ipHeader, tcpHeader, payload))
	c.Add(binary.BigEndian.Uint16(tcpHeader[16:]))
	return c.Finalize() == 0
}

// String returns a string representation of this Action.
func (a *FragmentAction) String() string {
	actions := [2]string{"", ""}
	if _, ok := a.FirstFragmentAction.(*SendAction); !ok {
		actions[0] = a.FirstFragmentAction.String()
	}
	if _, ok := a.SecondFragmentAction.(*SendAction); !ok {
		actions[1] = a.SecondFragmentAction.String()
	}

	var actStr string
	if len(actions[0])+len(actions[1]) > 0 {
		actStr = fmt.Sprintf("(%s,%s)", actions[0], actions[1])
	}

	return fmt.Sprintf("fragment{%s:%d:%t}%s",
		a.Proto, a.FragSize, a.InOrder, actStr)
}

// ParseFragmentAction parses a string representation of a "fragment" action.
// If the string is malformed, and error will be returned instead.
func ParseFragmentAction(s *scanner.Scanner) (Action, error) {
	if _, err := s.Expect("fragment{"); err != nil {
		return nil, errors.New("invalid fragment rule at %d: %v", s.Pos(), err)
	}

	str, err := s.Until('}')
	if err != nil {
		return nil, errors.New("invalid fragment rule at %d: %v", s.Pos(), err)
	}
	_, _ = s.Pop()

	fields := strings.Split(str, ":")
	if len(fields) < 3 {
		return nil, errors.New("not enough fields for fragment rule at %d (got %d)", s.Pos(), len(fields))
	}

	action := &FragmentAction{}
	switch strings.ToLower(fields[0]) {
	case "ip":
		action.Proto = "IP"
	case "tcp":
		action.Proto = "TCP"
	case "udp":
		action.Proto = "UDP"
	default:
		return nil, errors.New("invalid fragment rule: %q is not a recognized protocol", fields[0])
	}

	ofs, err := strconv.ParseInt(fields[1], 10, 16)
	if err != nil {
		return nil, errors.New("invalid fragment rule: %q is not a valid offset", fields[1])
	}
	action.FragSize = int(ofs)

	if action.InOrder, err = strconv.ParseBool(fields[2]); err != nil {
		return nil, errors.New("invalid fragment rule: %q is not a valid boolean", fields[2])
	}

	if len(fields) == 4 {
		overlap, err := strconv.ParseInt(fields[3], 10, 16)
		if err != nil {
			return nil, errors.New("invalid fragment rule: %q is not a valid overlap", fields[3])
		}
		action.overlap = int(overlap)
	}

	if _, err = s.Expect("("); err != nil {
		action.FirstFragmentAction = &SendAction{}
		action.SecondFragmentAction = &SendAction{}
		return action, nil
	}

	if action.FirstFragmentAction, err = ParseAction(s); err != nil {
		if c, err2 := s.Peek(); err2 == nil && c == ',' {
			action.FirstFragmentAction = &SendAction{}
		} else {
			return nil, errors.New("error parsing first action of fragment rule: %v", err)
		}
	}

	if _, err = s.Expect(","); err != nil {
		return nil, errors.New("invalid fragment rule: %v", internal.EOFUnexpected(err))
	}

	if action.SecondFragmentAction, err = ParseAction(s); err != nil {
		if c, err2 := s.Peek(); err2 == nil && c == ')' {
			action.SecondFragmentAction = &SendAction{}
		} else {
			return nil, errors.New("error parsing second action of fragment rule: %v", err)
		}
	}

	if _, err := s.Expect(")"); err != nil {
		return nil, errors.New("invalid fragment rule: %v", internal.EOFUnexpected(err))
	}

	return action, nil
}
