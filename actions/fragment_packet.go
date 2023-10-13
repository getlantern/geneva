package actions

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/getlantern/geneva/common"
	"github.com/getlantern/geneva/internal"
	"github.com/getlantern/geneva/internal/scanner"
)

// FragmentAction is a Geneva action that splits a packet into two fragments and applies separate
// action trees to each.
//
// As an example, if Proto is "IP" and FragSize is 8, this will fragment a 60-byte IP packet into
// two fragments: the first will contain the first eight bytes of the original packet's payload, and
// the second will contain the remaining 52 bytes.  Each fragment will retain the original header
// (modulo the fields that must be updated to mark it as a fragmented packet). If the Proto's header
// includes a checksum, it will be recomputed.
type FragmentAction struct {
	// Proto is the protocol layer where the packet will be fragmented.
	proto gopacket.LayerType
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

func (a *FragmentAction) Proto() string {
	switch a.proto {
	case layers.LayerTypeIPv4:
		return "IP"
	case layers.LayerTypeTCP:
		return "TCP"
	case layers.LayerTypeUDP:
		return "UDP"
	default:
		return ""
	}
}

// Apply applies this action to the given packet.
func (a *FragmentAction) Apply(packet gopacket.Packet) ([]gopacket.Packet, error) {
	var (
		err                error
		packets            []gopacket.Packet
		lpackets, rpackets []gopacket.Packet
	)

	switch a.proto {
	case layers.LayerTypeIPv4:
		// Note: the original Geneva code only fragments IPv4, not IPv6.
		packets, err = FragmentIPPacket(packet, a.FragSize)
	case layers.LayerTypeTCP:
		packets, err = fragmentTCPSegment(packet, a.FragSize)
	default:
		// nolint: godox
		// TODO: should we log this?
		packets, err = duplicate(packet)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to fragment: %w", err)
	}

	if len(packets) == 2 && !a.InOrder {
		packets = []gopacket.Packet{packets[1], packets[0]}
	}

	if lpackets, err = a.FirstFragmentAction.Apply(packets[0]); err != nil {
		return nil, fmt.Errorf("failed to apply action to first fragment: %w", err)
	}

	if rpackets, err = a.SecondFragmentAction.Apply(packets[1]); err != nil {
		return nil, fmt.Errorf("failed to apply action to second fragment: %w", err)
	}

	return append(lpackets, rpackets...), nil
}

func fragmentTCPSegment(packet gopacket.Packet, fragSize int) ([]gopacket.Packet, error) {
	// XXX: the original Geneva code does not seem to handle TCP segmentation for IPv6 packets,
	// so we don't either for now.
	if packet.NetworkLayer().LayerType() != layers.LayerTypeIPv4 {
		return duplicate(packet)
	}

	if packet.TransportLayer() == nil ||
		packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
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

	// XXX: upstream Geneva supports "overlap bytes"; i.e., taking the first few bytes of the
	// second fragment and tacking them onto the end of the first fragment. It's not mentioned
	// in the original paper. We don't do this right now, but could later.

	headersLen := len(packet.Data()) - tcpPayloadLen

	// Strangely, all the manual bit-banging below was easier than dealing with creating packets
	// using gopacket.

	ofs := len(
		packet.Data(),
	) - len(
		packet.NetworkLayer().LayerContents(),
	) - len(
		packet.NetworkLayer().LayerPayload(),
	)
	if ofs < 0 {
		// something bad has happened, so let's bail.
		return nil, errors.New("error calculating offset to network layer")
	}

	// create the first fragment.
	f1Len := headersLen + fragSize
	buf := make([]byte, f1Len)
	copy(buf, packet.Data()[:f1Len])

	ipv4Buf := buf[ofs:]

	// fix up the IP header's Total Length field
	binary.BigEndian.PutUint16(ipv4Buf[2:], uint16(f1Len-ofs))
	ipHdrLen := uint16(ipv4Buf[0]&0x0f) * 4

	first := gopacket.NewPacket(buf, packet.Layers()[0].LayerType(), gopacket.NoCopy)
	updateChecksums(first)

	// create the second fragment.
	f2Len := headersLen + tcpPayloadLen - fragSize
	buf = make([]byte, f2Len)
	copy(buf, packet.Data()[:headersLen])
	copy(buf[headersLen:], packet.Data()[headersLen+fragSize:])

	ipv4Buf = buf[ofs:]

	// fix up the IP header's Total Length field
	binary.BigEndian.PutUint16(ipv4Buf[2:], uint16(f2Len-ofs))

	// Fix up the TCP sequence number.
	// Excitingly, Go does integer wrapping, so we don't have to.
	tcp := ipv4Buf[ipHdrLen:]
	seqNum := binary.BigEndian.Uint32(tcp[4:])
	seqNum += uint32(fragSize)
	binary.BigEndian.PutUint32(tcp[4:], seqNum)

	second := gopacket.NewPacket(buf, packet.Layers()[0].LayerType(), gopacket.NoCopy)
	updateChecksums(second)

	return []gopacket.Packet{first, second}, nil
}

// FragmentIPPacket will fragment an IPv4 or IPv6 packet into two packets at the given 8-byte chunk
// offset.
//
// The first fragment will include up to (fragSize * 8) bytes of the IP packet's payload, and the
// second fragment will include the rest.
func FragmentIPPacket(packet gopacket.Packet, fragSize int) ([]gopacket.Packet, error) {
	if packet.NetworkLayer() == nil ||
		packet.NetworkLayer().LayerType() != layers.LayerTypeIPv4 {
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

	// from this point on we can assume that the IP payload is _at least_ (fragSize*8) bytes
	// long

	ofs := len(
		packet.Data(),
	) - len(
		packet.NetworkLayer().LayerContents(),
	) - len(
		packet.NetworkLayer().LayerPayload(),
	)
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

	// slice off everything past the first fragment's end
	buf = buf[:uint16(ofs)+hdrLen+offset]

	first := gopacket.NewPacket(buf, packet.Layers()[0].LayerType(), gopacket.NoCopy)
	if ipv4 := first.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ipv4 != nil {
		common.UpdateIPv4Checksum(ipv4)
	}

	// Now start on the second fragment.
	// First copy the old IP header as-is, then copy just the second fragment's payload right
	// after.
	buf = make([]byte, len(packet.Data())-int(offset))
	copy(buf, packet.Data()[:uint16(ofs)+hdrLen])

	ipv4Buf = buf[ofs:]
	copy(ipv4Buf[hdrLen:], packet.Data()[uint16(ofs)+hdrLen+offset:])

	// fix up the length
	binary.BigEndian.PutUint16(ipv4Buf[2:], hdrLen+payloadLen-offset)

	// clear the MF bit and set the fragment offset appropriately
	flagsAndFrags = (binary.BigEndian.Uint16(ipv4Buf[6:]) & 0x40) + uint16(fragSize)
	binary.BigEndian.PutUint16(ipv4Buf[6:], flagsAndFrags)

	second := gopacket.NewPacket(buf, packet.Layers()[0].LayerType(), gopacket.NoCopy)
	if ipv4 := second.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ipv4 != nil {
		common.UpdateIPv4Checksum(ipv4)
	}

	return []gopacket.Packet{first, second}, nil
}

func updateChecksums(packet gopacket.Packet) {
	if ipv4, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ipv4 != nil {
		common.UpdateIPv4Checksum(ipv4)
	}

	if tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); tcp != nil {
		common.UpdateTCPChecksum(tcp)
	}
}

// VerifyIPv4Checksum verifies whether an IPv4 header's checksum field is correct.
func VerifyIPv4Checksum(header []byte) bool {
	c := internal.OnesComplementChecksum{}

	for i := 0; i < len(header); i += 2 {
		c.Add(binary.BigEndian.Uint16(header[i:]))
	}

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
		a.Proto(), a.FragSize, a.InOrder, actStr)
}

// ParseFragmentAction parses a string representation of a "fragment" action.
//
// If the string is malformed, an error will be returned instead.
func ParseFragmentAction(s *scanner.Scanner) (Action, error) {
	if _, err := s.Expect("fragment{"); err != nil {
		return nil, fmt.Errorf("invalid fragment rule at %d: %w", s.Pos(), err)
	}

	str, err := s.Until('}')
	if err != nil {
		return nil, fmt.Errorf("invalid fragment rule at %d: %w", s.Pos(), err)
	}

	_, _ = s.Pop()

	fields := strings.Split(str, ":")
	if len(fields) < 3 {
		return nil, fmt.Errorf(
			"not enough fields for fragment rule at %d (got %d)",
			s.Pos(),
			len(fields),
		)
	}

	action := &FragmentAction{}

	switch strings.ToLower(fields[0]) {
	case "ip":
		action.proto = layers.LayerTypeIPv4
	case "tcp":
		action.proto = layers.LayerTypeTCP
	case "udp":
		action.proto = layers.LayerTypeUDP
	default:
		return nil, fmt.Errorf(
			"invalid fragment rule: %q is not a recognized protocol",
			fields[0],
		)
	}

	ofs, err := strconv.ParseInt(fields[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid fragment rule: %q is not a valid offset", fields[1])
	}

	action.FragSize = int(ofs)

	if action.InOrder, err = strconv.ParseBool(fields[2]); err != nil {
		return nil, fmt.Errorf(
			"invalid fragment rule: %q is not a valid boolean",
			fields[2],
		)
	}

	if len(fields) == 4 {
		overlap, err := strconv.ParseInt(fields[3], 10, 16)
		if err != nil {
			return nil, fmt.Errorf(
				"invalid fragment rule: %q is not a valid overlap",
				fields[3],
			)
		}

		action.overlap = int(overlap)
	}

	if _, err = s.Expect("("); err != nil {
		action.FirstFragmentAction = &SendAction{}
		action.SecondFragmentAction = &SendAction{}

		return action, nil //nolint:nilerr
	}

	if action.FirstFragmentAction, err = ParseAction(s); err != nil {
		if !errors.Is(err, ErrInvalidAction) {
			return nil, err
		}

		if c, err2 := s.Peek(); err2 == nil && c == ',' {
			action.FirstFragmentAction = &SendAction{}
		} else {
			return nil, fmt.Errorf("error parsing first action of fragment rule: %w", err)
		}
	}

	if _, err = s.Expect(","); err != nil {
		return nil, fmt.Errorf(
			"unexpected token in fragment rule: %w",
			internal.EOFUnexpected(err),
		)
	}

	if action.SecondFragmentAction, err = ParseAction(s); err != nil {
		if c, err2 := s.Peek(); err2 == nil && c == ')' {
			action.SecondFragmentAction = &SendAction{}
		} else {
			return nil, fmt.Errorf("error parsing second action of fragment rule: %v", err)
		}
	}

	if _, err := s.Expect(")"); err != nil {
		return nil, fmt.Errorf(
			"unexpected token in fragment rule: %v",
			internal.EOFUnexpected(err),
		)
	}

	return action, nil
}
