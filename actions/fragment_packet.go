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
// As an example, if Proto is "IP" and FragSize is 8, this will fragment a 60-byte IP segment into two fragments: the
// first will contain the first eight bytes of the original segment's payload, and the second will contain the remaining
// 52 bytes.  Each fragment will retain the original header (modulo the fields that must be updated to mark it as a
// fragmented segment). If the Proto's header includes a checksum, it will be recomputed.
type FragmentAction struct {
	// Proto is the protocol layer where the packet will be fragmented.
	Proto string
	// FragSize is the offset into the protocol's payload where fragmentation will happen.
	FragSize uint16
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
		packets = FragmentIPSegment(packet, a.FragSize)
	default:
		/// TODO: log this and return the packet instead of panicking
		packets = fragmentIPv6Segment(packet, a.FragSize)
		panic(fmt.Sprintf("%s is unimplemented", a.Proto))
	}

	if !a.InOrder {
		packets = []gopacket.Packet{packets[1], packets[0]}
	}

	result := a.FirstFragmentAction.Apply(packets[0])
	result = append(result, a.SecondFragmentAction.Apply(packets[1])...)
	return result
}

// FragmentIPSegment will fragment an dIPv4 or IPv6 segment into two segments at the given offset.
//
// The first fragment will include up to fragSize bytes of the IP segment's payload, and the second fragment will
// include the rest.
func FragmentIPSegment(packet gopacket.Packet, fragSize uint16) []gopacket.Packet {
	fragSize -= fragSize % 8

	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		// uh oh, this isn't something we can deal with. Bail!
		/// TODO: log this
		return []gopacket.Packet{packet}
	}

	if ipv4, _ := netLayer.(*layers.IPv4); ipv4 != nil {
		return fragmentIPv4Segment(packet, fragSize)
	} else if ipv6, _ := netLayer.(*layers.IPv6); ipv6 != nil {
		return fragmentIPv6Segment(packet, fragSize)
	}

	// This was neither IPv4 nor IPv6 (somehow?), so just pass it through
	/// TODO: log this
	return []gopacket.Packet{packet}
}

func fragmentIPv4Segment(packet gopacket.Packet, fragSize uint16) []gopacket.Packet {
	// corner case: if offset is 0 (Geneva calls "offset" the "fragsize"), then just return the original
	// packet.
	if fragSize == 0 {
		return []gopacket.Packet{packet}
	}

	// corner case: if the packet has no payload, the canonical Geneva implementation simply duplicates the packet.
	if len(packet.NetworkLayer().LayerPayload()) == 0 {
		return duplicatePacket(packet, DefaultSendAction, DefaultSendAction)
	}

	// fix up the fragment size to a multiple of 8 to satisfy fragment offset value
	fragSize -= fragSize % 8

	// corner case: if the IP payload is smaller than our fragment size, just return the packet.
	if len(packet.NetworkLayer().LayerPayload()) == int(fragSize) {
		return []gopacket.Packet{packet}
	}

	// from this point on we can assume that the IP payload is _at least_ fragSize bytes long

	buf := make([]byte, len(packet.Data()))
	copy(buf, packet.Data())

	hdrLen := uint16((buf[0] & 0x0f) * 4)
	payloadLen := binary.BigEndian.Uint16(buf[2:]) - hdrLen

	// update the total length of the first fragmented segment
	binary.BigEndian.PutUint16(buf[2:], hdrLen+fragSize)

	// set the More Fragments bit, and make the fragment offset 0
	flagsAndFrags := (binary.BigEndian.Uint16(buf[6:]) | 0x20) & 0xe0
	binary.LittleEndian.PutUint16(buf[6:], flagsAndFrags)

	ComputeIPv4Checksum(buf[:hdrLen])

	// slice off everything past the first fragment's end
	buf = buf[:hdrLen+fragSize]

	first := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.NoCopy)

	// now start on the second fragment.
	// First copy the old IP header as-is, then copy just the second fragment's payload right after.
	buf = make([]byte, len(packet.Data())-int(fragSize))
	copy(buf, packet.Data()[:hdrLen])
	copy(buf[hdrLen:], packet.Data()[hdrLen+(fragSize):])

	// fix up the length
	binary.BigEndian.PutUint16(buf[2:], payloadLen-fragSize)

	// clear the MF bit and set the fragment offset appropriately
	flagsAndFrags = (binary.BigEndian.Uint16(buf[6:]) & 0x40) + (fragSize / 8)
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

func fragmentIPv6Segment(packet gopacket.Packet, fragSize uint16) []gopacket.Packet {
	return nil
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
	action.FragSize = uint16(ofs)

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
