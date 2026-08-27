package actions

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

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
		packets, err = fragmentTCPSegment(packet, a.FragSize, a.overlap)
	default:
		// TODO: should we log this?
		packets, err = duplicate(packet)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to fragment: %w", err)
	}
	if len(packets) != 2 {
		return nil, fmt.Errorf("fragment action produced %d packets; expected 2", len(packets))
	}

	if !a.InOrder {
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

func fragmentTCPSegment(packet gopacket.Packet, fragSize, overlap int) ([]gopacket.Packet, error) {
	// XXX: the original Geneva code does not seem to handle TCP segmentation for IPv6 packets,
	// so we don't either for now.
	if packet.NetworkLayer() == nil || packet.NetworkLayer().LayerType() != layers.LayerTypeIPv4 {
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

	// Note on fragSize semantics: TCP fragments are counted in *bytes*, unlike IP fragments
	// which count 8-byte blocks. Canonical Geneva (upstream tcp_segment) therefore keeps
	// fragSize == 0 intact here and emits a header-only first segment followed by a
	// full-payload second segment at the original sequence number. The IP path treats zero
	// as unsplittable because a zero-block fragment carries no data at all.
	if fragSize == -1 || fragSize > tcpPayloadLen-1 {
		fragSize = tcpPayloadLen / 2
	}

	headersLen := len(packet.Data()) - tcpPayloadLen
	overlap = min(overlap, tcpPayloadLen-fragSize)

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
	f1Len := headersLen + fragSize + overlap
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

	// Canonical Geneva clamps an oversized or unsplittable offset to the payload's midpoint
	// (upstream ip_fragment: fragsize == -1 || fragsize*8 > len(load) || len(load) <= 8).
	if fragSize == -1 || fragSize*8 > plen || plen <= 8 {
		fragSize = plen / 2 / 8
	}

	// A fragment action is branching, so an unsplittable packet becomes two
	// independent copies just like canonical Geneva.
	if fragSize <= 0 {
		return duplicate(packet)
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
	// Use the actual on-the-wire payload size rather than the header's Total Length so that
	// malformed or trailing-padded packets cannot underflow the second fragment's length.
	payloadLen := uint16(plen)

	// fix up the fragment size to a multiple of 8 to satisfy fragment offset value
	offset := uint16((fragSize * 8))

	// update the total length of the first fragmented packet
	binary.BigEndian.PutUint16(ipv4Buf[2:], hdrLen+offset)

	// Set the More Fragments bit and make the fragment offset zero, preserving the evil
	// (0x8000) and Don't Fragment (0x4000) bits. The flags/offset word is big-endian on the
	// wire; the previous little-endian write here corrupted the flag bits whenever the
	// original fragment offset had low bits set.
	flagsAndFrags := binary.BigEndian.Uint16(ipv4Buf[6:])
	flagsAndFrags = (flagsAndFrags | 0x2000) & 0xe000
	binary.BigEndian.PutUint16(ipv4Buf[6:], flagsAndFrags)

	// slice off everything past the first fragment's end
	buf = buf[:uint16(ofs)+hdrLen+offset]

	first := gopacket.NewPacket(buf, packet.Layers()[0].LayerType(), gopacket.NoCopy)
	if ipv4, ok := first.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok && ipv4 != nil {
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

	// Clear the More Fragments bit and the fragment offset, preserving the evil and
	// Don't Fragment bits, then encode the offset for this fragment (in 8-byte units).
	flagsAndFrags = (binary.BigEndian.Uint16(ipv4Buf[6:]) & 0xc000) + uint16(fragSize)
	binary.BigEndian.PutUint16(ipv4Buf[6:], flagsAndFrags)

	second := gopacket.NewPacket(buf, packet.Layers()[0].LayerType(), gopacket.NoCopy)
	if ipv4, _ := second.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ipv4 != nil {
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

	overlap := ""
	if a.overlap > 0 {
		overlap = fmt.Sprintf(":%d", a.overlap)
	}

	return fmt.Sprintf("fragment{%s:%d:%t%s}%s",
		a.Proto(), a.FragSize, a.InOrder, overlap, actStr)
}

// Overlap returns the number of bytes shared by both TCP segments.
func (a *FragmentAction) Overlap() int {
	return a.overlap
}

// NewFragmentAction creates a supported IPv4 or TCP fragment action.
func NewFragmentAction(proto string, fragSize int, inOrder bool, overlap int, first, second Action) (*FragmentAction, error) {
	if fragSize < -1 {
		return nil, fmt.Errorf("invalid fragment size %d", fragSize)
	}
	if overlap < 0 {
		return nil, fmt.Errorf("invalid fragment overlap %d", overlap)
	}
	if first == nil || second == nil {
		return nil, errors.New("fragment actions must have two children")
	}

	action := &FragmentAction{
		FragSize:             fragSize,
		InOrder:              inOrder,
		overlap:              overlap,
		FirstFragmentAction:  first,
		SecondFragmentAction: second,
	}
	switch strings.ToUpper(proto) {
	case "IP":
		action.proto = layers.LayerTypeIPv4
	case "TCP":
		action.proto = layers.LayerTypeTCP
	default:
		return nil, fmt.Errorf("unsupported fragment protocol %q", proto)
	}

	return action, nil
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

	proto := strings.ToUpper(fields[0])
	if proto != "IP" && proto != "TCP" {
		return nil, fmt.Errorf(
			"invalid fragment rule: %q is not a supported protocol",
			fields[0],
		)
	}

	ofs, err := strconv.ParseInt(fields[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid fragment rule: %q is not a valid offset", fields[1])
	}

	fragSize := int(ofs)

	inOrder, err := strconv.ParseBool(fields[2])
	if err != nil {
		return nil, fmt.Errorf(
			"invalid fragment rule: %q is not a valid boolean",
			fields[2],
		)
	}

	overlap := 0
	if len(fields) == 4 {
		parsedOverlap, err := strconv.ParseInt(fields[3], 10, 16)
		if err != nil {
			return nil, fmt.Errorf(
				"invalid fragment rule: %q is not a valid overlap",
				fields[3],
			)
		}

		if parsedOverlap < 0 {
			return nil, fmt.Errorf("invalid fragment rule: overlap must not be negative")
		}

		overlap = int(parsedOverlap)
	} else if len(fields) > 4 {
		return nil, fmt.Errorf("invalid fragment rule: too many fields")
	}

	action, err := NewFragmentAction(proto, fragSize, inOrder, overlap, DefaultSendAction, DefaultSendAction)
	if err != nil {
		return nil, fmt.Errorf("invalid fragment rule: %w", err)
	}

	if _, err = s.Expect("("); err != nil {
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
			return nil, fmt.Errorf("error parsing second action of fragment rule: %w", err)
		}
	}

	if _, err := s.Expect(")"); err != nil {
		return nil, fmt.Errorf(
			"unexpected token in fragment rule: %w",
			internal.EOFUnexpected(err),
		)
	}

	return action, nil
}
