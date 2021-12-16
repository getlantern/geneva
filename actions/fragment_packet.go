package actions

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/Crosse/geneva/internal/lexer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type FragmentAction struct {
	Proto                string
	FragSize             uint16
	InOrder              bool
	FirstFragmentAction  Action
	SecondFragmentAction Action
}

func (a *FragmentAction) Apply(packet gopacket.Packet) []gopacket.Packet {
	/*
	   - IP
	     - check whether the DF bit is set and unset it
	     - change total length field to fragment size
	     - set MF on first fragment, clear on second
	     - set the fragment offset field (0 for first, calculated for second)
	     - recompute header checksum
	*/
	switch a.Proto {
	case "IP":
		return FragmentIPSegment(packet, a.FragSize)
	default:
		/// TODO: log this and return the packet instead of panicking
		panic(fmt.Sprintf("%s is unimplemented", a.Proto))
	}
}

func FragmentIPSegment(packet gopacket.Packet, fragSize uint16) []gopacket.Packet {
	fragSize -= fragSize % 8

	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		// uh oh, this isn't something we can deal with. Bail!
		/// TODO: log this
		return []gopacket.Packet{packet}
	}

	if ipv4, _ := netLayer.(*layers.IPv4); ipv4 != nil {
		return FragmentIPv4Segment(packet, fragSize)
	} else if ipv6, _ := netLayer.(*layers.IPv6); ipv6 != nil {
		return FragmentIPv4Segment(packet, fragSize)
	}

	// This was neither IPv4 nor IPv6 (somehow?), so just pass it through
	/// TODO: log this
	return []gopacket.Packet{packet}
}

func FragmentIPv4Segment(packet gopacket.Packet, fragSize uint16) []gopacket.Packet {
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

	chksum := ComputeIPv4Checksum(buf[:hdrLen])
	binary.BigEndian.PutUint16(buf[10:], chksum)

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

	chksum = ComputeIPv4Checksum(buf[:hdrLen])
	binary.BigEndian.PutUint16(buf[10:], chksum)

	second := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.NoCopy)

	return []gopacket.Packet{first, second}
}

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
	return uint16(^chksum)
}

func FragmentIPv4SegmentOld(packet gopacket.Packet, offset int) []gopacket.Packet {
	offset -= offset % 8
	payload := packet.NetworkLayer().LayerPayload()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// first fragment
	gopacket.SerializeLayers(buf, opts,
		packet.NetworkLayer().(*layers.IPv4),
		gopacket.Payload(payload[:offset]))

	first := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	if layer, ok := first.NetworkLayer().(*layers.IPv4); ok {
		layer.Flags |= layers.IPv4MoreFragments
		layer.FragOffset = 0
	}
	buf = gopacket.NewSerializeBuffer()
	if err := gopacket.SerializePacket(buf, opts, first); err != nil {
		// XXX if this can fail we should probably return the error as well.
		fmt.Printf("wtf: %v\n", err)
		return []gopacket.Packet{}
	}
	first = gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.NoCopy)

	// second fragment
	buf = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, opts,
		packet.NetworkLayer().(*layers.IPv4),
		gopacket.Payload(payload[offset:]))
	second := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Lazy)
	if layer, ok := first.NetworkLayer().(*layers.IPv4); ok {
		layer.Flags &= layers.IPv4MoreFragments
		layer.FragOffset = uint16(offset) / 8
	}
	buf = gopacket.NewSerializeBuffer()
	if err := gopacket.SerializePacket(buf, opts, second); err != nil {
		// XXX if this can fail we should probably return the error as well.
		fmt.Printf("wtf the sequel: %v\n", err)
		return []gopacket.Packet{}
	}
	second = gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.NoCopy)

	return []gopacket.Packet{first, second}
}

func FragmentIPv6Segment(data []byte, offset int) []gopacket.Packet {
	return nil
}

func (a *FragmentAction) String() string {
	return fmt.Sprintf("fragment{%s:%d:%t}}(%s,%s)",
		a.Proto, a.FragSize, a.InOrder,
		a.FirstFragmentAction,
		a.SecondFragmentAction)
}

func ParseFragmentAction(l *lexer.Lexer) (Action, error) {
	if _, err := l.Expect("fragment{"); err != nil {
		return nil, fmt.Errorf("invalid fragment rule: %v", err)
	}

	str, err := l.Until('}')
	if err != nil {
		return nil, fmt.Errorf("invalid fragment rule: %v", err)
	}
	_, _ = l.Pop()

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
		return nil, fmt.Errorf("invalid fragment rule: %s is not a recognized protocol", fields[0])
	}

	ofs, err := strconv.ParseUint(fields[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalud fragment rule: %s is not a valid offset", fields[1])
	}
	action.FragSize = uint16(ofs)

	if action.InOrder, err = strconv.ParseBool(fields[2]); err != nil {
		return nil, fmt.Errorf("invalid fragment fule: %s is not a valid boolean", fields[2])
	}

	if _, err := l.Expect("("); err != nil {
		action.FirstFragmentAction = &SendAction{}
		action.SecondFragmentAction = &SendAction{}
		return action, nil
	}

	if action.FirstFragmentAction, err = ParseAction(l); err != nil {
		if c, err2 := l.Peek(); err2 == nil && c == ',' {
			action.FirstFragmentAction = &SendAction{}
		} else {
			return nil, fmt.Errorf("invalid fragment rule: %v", err)
		}
	}

	if _, err = l.Expect(","); err != nil {
		return nil, fmt.Errorf("invalid fragment() rule: %v", err)
	}

	if action.SecondFragmentAction, err = ParseAction(l); err != nil {
		if c, err2 := l.Peek(); err2 == nil && c == ')' {
			action.SecondFragmentAction = &SendAction{}
		} else {
			return nil, fmt.Errorf("invalid fragment rule: %v", err)
		}
	}

	if _, err := l.Expect(")"); err != nil {
		return nil, fmt.Errorf("invalid fragment rule: %v", err)
	}

	return action, nil
}
