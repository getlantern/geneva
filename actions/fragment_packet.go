package actions

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/Crosse/geneva/internal/scanner"
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
	// FirstFragmentAction is the action to apply to the first fragment.
	FirstFragmentAction Action
	// SecondFragmentAction is the action to apply to the second fragment.
	SecondFragmentAction Action
}

// Apply applies this action to the given packet.
func (a *FragmentAction) Apply(packet gopacket.Packet) []gopacket.Packet {
	var packets []gopacket.Packet

	switch a.Proto {
	case "IP":
		// Note: the original Geneva code only fragments IPv4, not IPv6.
		packets = FragmentIPPacket(packet, a.FragSize)
	case "TCP":
		packets = FragmentTCPSegment(packet, a.FragSize)
	default:
		// TODO: should we log this?
		packets = duplicate(packet)
	}

	if len(packets) == 2 && !a.InOrder {
		packets = []gopacket.Packet{packets[1], packets[0]}
	}

	result := a.FirstFragmentAction.Apply(packets[0])
	result = append(result, a.SecondFragmentAction.Apply(packets[1])...)
	return result
}

func FragmentTCPSegment(packet gopacket.Packet, fragSize int) []gopacket.Packet {
	// TODO
	return []gopacket.Packet{packet}
}

// FragmentIPPacket will fragment an IPv4 or IPv6 packet into two packets at the given 8-byte chunk offset.
//
// The first fragment will include up to (fragSize * 8) bytes of the IP packet's payload, and the second fragment will
// include the rest.
func FragmentIPPacket(packet gopacket.Packet, fragSize int) []gopacket.Packet {
	if packet.NetworkLayer() == nil || packet.NetworkLayer().LayerType() != layers.LayerTypeIPv4 {
		return duplicate(packet)
	}

	plen := len(packet.NetworkLayer().LayerPayload())
	if plen == 0 {
		return duplicate(packet)
	}

	if fragSize == -1 || (fragSize*8)%8 > plen || plen <= 8 {
		fragSize = (plen / 2) % 8
	}

	// corner case: if fragSize is 0, just return the original packet.
	if fragSize == 0 {
		return []gopacket.Packet{packet}
	}

	// from this point on we can assume that the IP payload is _at least_ (fragSize*8) bytes long

	buf := make([]byte, len(packet.Data()))
	copy(buf, packet.Data())

	hdrLen := uint16((buf[0] & 0x0f) * 4)
	payloadLen := binary.BigEndian.Uint16(buf[2:]) - hdrLen

	// fix up the fragment size to a multiple of 8 to satisfy fragment offset value
	offset := uint16((fragSize * 8))

	// update the total length of the first fragmented packet
	binary.BigEndian.PutUint16(buf[2:], hdrLen+offset)

	// set the More Fragments bit, and make the fragment offset 0
	flagsAndFrags := (binary.BigEndian.Uint16(buf[6:]) | 0x20) & 0xe0
	binary.LittleEndian.PutUint16(buf[6:], flagsAndFrags)

	ComputeIPv4Checksum(buf[:hdrLen])

	// slice off everything past the first fragment's end
	buf = buf[:hdrLen+offset]

	first := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.NoCopy)

	// now start on the second fragment.
	// First copy the old IP header as-is, then copy just the second fragment's payload right after.
	buf = make([]byte, len(packet.Data())-int(offset))
	copy(buf, packet.Data()[:hdrLen])
	copy(buf[hdrLen:], packet.Data()[hdrLen+(offset):])

	// fix up the length
	binary.BigEndian.PutUint16(buf[2:], hdrLen+payloadLen-offset)

	// clear the MF bit and set the fragment offset appropriately
	flagsAndFrags = (binary.BigEndian.Uint16(buf[6:]) & 0x40) + uint16(fragSize)
	binary.BigEndian.PutUint16(buf[6:], flagsAndFrags)

	ComputeIPv4Checksum(buf[:hdrLen])

	second := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.NoCopy)

	return []gopacket.Packet{first, second}
}

// VerifyIPv4Checksum verifies whether an IPv4 header's checksum field is correct.
func VerifyIPv4Checksum(header []byte) bool {
	chksum := uint32(0)
	for i := 0; i < len(header); i += 2 {
		chksum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for chksum > 0xffff {
		chksum = (chksum & 0xffff) + (chksum >> 16)
	}

	return uint16(^chksum) == 0
}

// ComputeIPv4Checksum computes a new checksum for the given IPv4 header and writes it into the header.
func ComputeIPv4Checksum(header []byte) uint16 {
	// zero out the old checksum
	binary.BigEndian.PutUint16(header[10:], 0)

	chksum := uint32(0)
	for i := 0; i < len(header); i += 2 {
		chksum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for chksum > 0xffff {
		chksum = (chksum & 0xffff) + (chksum >> 16)
	}

	chksum16 := uint16(^chksum)
	binary.BigEndian.PutUint16(header[10:], chksum16)
	return chksum16
}

// String returns a string representation of this Action.
func (a *FragmentAction) String() string {
	return fmt.Sprintf("fragment{%s:%d:%t}}(%s,%s)",
		a.Proto, a.FragSize, a.InOrder,
		a.FirstFragmentAction,
		a.SecondFragmentAction)
}

// ParseFragmentAction parses a string representation of a "fragment" action.
// If the string is malformed, and error will be returned instead.
func ParseFragmentAction(s *scanner.Scanner) (Action, error) {
	if _, err := s.Expect("fragment{"); err != nil {
		return nil, fmt.Errorf("invalid fragment rule: %v", err)
	}

	str, err := s.Until('}')
	if err != nil {
		return nil, fmt.Errorf("invalid fragment rule: %v", err)
	}
	_, _ = s.Pop()

	fields := strings.Split(str, ":")
	if len(fields) != 3 {
		return nil, fmt.Errorf("invalid fragment rule: %v", err)
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
		return nil, fmt.Errorf("invalid fragment rule: \"%s\" is not a recognized protocol", fields[0])
	}

	ofs, err := strconv.ParseUint(fields[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalud fragment rule: \"%s\" is not a valid offset", fields[1])
	}
	action.FragSize = int(ofs)

	if action.InOrder, err = strconv.ParseBool(fields[2]); err != nil {
		return nil, fmt.Errorf("invalid fragment rule: \"%s\" is not a valid boolean", fields[2])
	}

	if _, err := s.Expect("("); err != nil {
		action.FirstFragmentAction = &SendAction{}
		action.SecondFragmentAction = &SendAction{}
		return action, nil
	}

	if action.FirstFragmentAction, err = ParseAction(s); err != nil {
		if c, err2 := s.Peek(); err2 == nil && c == ',' {
			action.FirstFragmentAction = &SendAction{}
		} else {
			return nil, fmt.Errorf("invalid fragment rule: %v", err)
		}
	}

	if _, err = s.Expect(","); err != nil {
		return nil, fmt.Errorf("invalid fragment() rule: %v", err)
	}

	if action.SecondFragmentAction, err = ParseAction(s); err != nil {
		if c, err2 := s.Peek(); err2 == nil && c == ')' {
			action.SecondFragmentAction = &SendAction{}
		} else {
			return nil, fmt.Errorf("invalid fragment rule: %v", err)
		}
	}

	if _, err := s.Expect(")"); err != nil {
		return nil, fmt.Errorf("invalid fragment rule: %v", err)
	}

	return action, nil
}
