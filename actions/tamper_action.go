package actions

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/getlantern/geneva/common"
	"github.com/getlantern/geneva/internal"
	"github.com/getlantern/geneva/internal/scanner"
)

const (
	// TamperReplace replaces the value of a packet field with the given value.
	TamperReplace = iota
	// TamperCorrupt replaces the value of a packet field with a randomly-generated value.
	TamperCorrupt
)

var (
	ErrInvalidTamperMode = errors.New("invalid tamper mode")
	ErrInvalidTamperRule = errors.New("invalid tamper rule")
	ErrUDPNotSupported   = errors.New("UDP tamper action not currently supported")
)

// TamperMode describes the way that the "tamper" action can manipulate a packet.
type TamperMode int

// String returns a string representation of the tamper mode.
func (tm TamperMode) String() string {
	switch tm {
	case TamperReplace:
		return "replace"
	case TamperCorrupt:
		return "corrupt"
	}

	return ""
}

// TamperAction is a Geneva action that modifies a given field of a packet while always
// trying to keep the packet valid. This is done by updating the checksums and lengths
// unless the tamper rule is specifically for the checksum or length. If proto is TCP
// and the field is an option, the option will be added if it doesn't exist.
//
// There are two modes for tampering:
//
//	"replace" - replace the field with the given value.
//	"corrupt" - replace the field with a randomly-generated value of the same bitsize.
//
// Currently, only TCP and IPv4 is supported. UDP support is planned for the future.
type TamperAction struct {
	// Proto is the protocol layer where the modification will occur.
	Proto string
	// Field is the layer field to modify.
	Field string
	// NewValue is the new value to which the Field should be set. This is only relevant for
	// "replace" mode.
	NewValue string
	// Mode indicates how the modification should happen.
	Mode TamperMode
	// Action is the action to apply to the packet after modification.
	Action Action
}

// String returns a string representation of this Action.
func (a *TamperAction) String() string {
	newValue := ""
	if a.Mode == TamperReplace {
		newValue = fmt.Sprintf(":%s", a.NewValue)
	}

	return fmt.Sprintf("tamper{%s:%s:%s%s}(%s,)",
		a.Proto, a.Field, a.Mode, newValue, a.Action)
}

// ParseTamperAction parses a string representation of a "tamper" action.
//
// If the string is malformed, an error will be returned instead.
//
//nolint:errorlint
func ParseTamperAction(s *scanner.Scanner) (Action, error) {
	if _, err := s.Expect("tamper{"); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrInvalidTamperRule, err)
	}

	str, err := s.Until('}')
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrInvalidTamperRule, err)
	}

	_, _ = s.Pop()

	fields := strings.Split(str, ":")
	if len(fields) < 3 || len(fields) > 4 {
		return nil, fmt.Errorf("%s: invalid field, %w", ErrInvalidTamperRule, err)
	}

	var (
		proto = strings.ToUpper(fields[0])
		field = strings.ToLower(fields[1])

		mode     TamperMode
		newValue string
	)

	switch strings.ToLower(fields[2]) {
	case "replace":
		mode = TamperReplace
		newValue = fields[3]
	case "corrupt":
		mode = TamperCorrupt
	default:
		return nil, fmt.Errorf(
			"%w: %q must be either 'replace' or 'corrupt'",
			ErrInvalidTamperMode,
			fields[2],
		)
	}

	tamperAction := TamperAction{
		Proto:    proto,
		Field:    field,
		Mode:     mode,
		NewValue: newValue,
	}

	if _, err = s.Expect("("); err != nil {
		tamperAction.Action = &SendAction{}
		return newTamperAction(tamperAction)
	}

	if tamperAction.Action, err = ParseAction(s); err != nil {
		if !errors.Is(err, ErrInvalidAction) {
			return nil, err
		}

		if c, err2 := s.Peek(); err2 == nil && c == ')' {
			tamperAction.Action = &SendAction{}
		} else {
			return nil, fmt.Errorf("%s: invalid action, %w", ErrInvalidTamperRule, err)
		}
	}

	if _, err = s.Expect(","); err == nil {
		if !s.FindToken(")", true) {
			return nil, fmt.Errorf("%w: only one action is allowed", ErrInvalidTamperRule)
		}
	}

	if _, err = s.Expect(")"); err != nil {
		return nil, fmt.Errorf("%s: unexpected token: %w", ErrInvalidTamperRule, internal.EOFUnexpected(err))
	}

	return newTamperAction(tamperAction)
}

func newTamperAction(ta TamperAction) (Action, error) {
	switch ta.Proto {
	case "IP":
		return NewIPv4TamperAction(ta)
	case "TCP":
		return NewTCPTamperAction(ta)
	case "UDP":
		return nil, ErrUDPNotSupported
	default:
		return nil, fmt.Errorf("%w: %q is not a recognized protocol", ErrInvalidTamperRule, ta.Proto)
	}
}

//
// TCP Tamper Action
//

// TCPField is a TCP field that can be modified by a TCPTamperAction.
type TCPField uint8

const (
	// supported TCP options. The other options are apparently obsolete and not used.
	TCPOptionEol       = layers.TCPOptionKindEndList
	TCPOptionNop       = layers.TCPOptionKindNop
	TCPOptionMss       = layers.TCPOptionKindMSS
	TCPOptionWscale    = layers.TCPOptionKindWindowScale
	TCPOptionSackok    = layers.TCPOptionKindSACKPermitted
	TCPOptionSack      = layers.TCPOptionKindSACK
	TCPOptionTimestamp = layers.TCPOptionKindTimestamps

	// obsolete TCP options geneva uses and is in the strategies.md document:
	// https://github.com/Kkevsterrr/geneva/blob/master/strategies.md
	TCPOptionAltCkhsum = 14
	TCPOptionMd5Header = 19
	TCPOptionUto       = 28

	// putting fields after options so that we can use the gopacket.TCPOptionKind constants for options.
	// this lets us use the same map for both fields and options and also directly compare
	// tcpTamperAction.field == TCPOption when iterating over tcpPacket.Options.
	TCPFieldSrcPort  = 9
	TCPFieldDstPort  = 10
	TCPFieldSeq      = 11
	TCPFieldAck      = 12
	TCPFieldDataOff  = 13
	TCPFieldFlags    = 15
	TCPFieldWindow   = 16
	TCPFieldUrgent   = 17
	TCPFieldChecksum = 18
	TCPLoad          = 20

	// TCP flag string representations for tamper rules.
	TCPFlagFin = "f"
	TCPFlagSyn = "s"
	TCPFlagRst = "r"
	TCPFlagPsh = "p"
	TCPFlagAck = "a"
	TCPFlagUrg = "u"
	TCPFlagEce = "e"
	TCPFlagCwr = "c"
	TCPFlagNop = "n"
)

var (
	// tcpFields is a map of TCP fields to their corresponding TCPField constants.
	// easier to use a map than a switch statement when parsing tamper rules.
	tcpFields = map[string]TCPField{
		"srcport":           TCPFieldSrcPort,
		"dstport":           TCPFieldDstPort,
		"seq":               TCPFieldSeq,
		"ack":               TCPFieldAck,
		"dataofs":           TCPFieldDataOff,
		"flags":             TCPFieldFlags,
		"window":            TCPFieldWindow,
		"urgptr":            TCPFieldUrgent,
		"chksum":            TCPFieldChecksum,
		"options-eol":       TCPOptionEol,
		"options-nop":       TCPOptionNop,
		"options-mss":       TCPOptionMss,
		"options-wscale":    TCPOptionWscale,
		"options-sackok":    TCPOptionSackok,
		"options-sack":      TCPOptionSack,
		"options-timestamp": TCPOptionTimestamp,
		"options-altchksum": TCPOptionTimestamp,
		"options-md5header": TCPOptionMd5Header,
		"options-uto":       TCPOptionUto,
		"load":              TCPLoad,
	}

	// tcpOptionLengths is a map of TCP options to the length of their data field.
	tcpOptionLengths = map[TCPField]int{
		TCPOptionEol:       1,
		TCPOptionNop:       1,
		TCPOptionMss:       2,
		TCPOptionWscale:    1,
		TCPOptionSackok:    0, // the geneva team has this listed as 0, so at most the data is deleted
		TCPOptionSack:      0, // same as above
		TCPOptionTimestamp: 8,
		TCPOptionAltCkhsum: 3,
		TCPOptionMd5Header: 16,
		TCPOptionUto:       2,
	}
)

// TCPTamperAction is a Geneva action that modifies TCP packets.
type TCPTamperAction struct {
	// TamperAction is the underlying action parsed from the tamper rule.
	TamperAction
	// field is the TCP field to modify.
	field TCPField
	// valueGen is the value generator to use when modifying the field.
	valueGen tamperValueGen
}

// NewTCPTamperAction returns a new TCPTamperAction from the given TamperAction.
func NewTCPTamperAction(ta TamperAction) (*TCPTamperAction, error) {
	field, ok := tcpFields[ta.Field]
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a recognized TCP field", ErrInvalidTamperRule, ta.Field)
	}

	switch ta.Mode {
	case TamperCorrupt:
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		return &TCPTamperAction{
			TamperAction: ta,
			field:        field,
			valueGen:     &tamperCorruptGen{r},
		}, nil
	case TamperReplace:
		gen := &tamperReplaceGen{}

		switch {
		case field == TCPFieldFlags:
			gen.vUint = tcpFlagsToUint32(ta.NewValue)
		case field < TCPFieldSrcPort:
			// if field is an option, we need to convert the value to a byte slice
			var b []byte
			if val, err := strconv.ParseUint(ta.NewValue, 10, 64); err == nil {
				b = make([]byte, 8)
				binary.BigEndian.PutUint64(b, val)
				b = b[8-tcpOptionLengths[field]:]
			} else {
				b = []byte(ta.NewValue)
			}

			gen.vBytes = b
		case field == TCPLoad:
			gen.vBytes = []byte(ta.NewValue)
		default:
			var (
				val uint64
				err error
			)
			if ta.NewValue != "" {
				val, err = strconv.ParseUint(ta.NewValue, 10, 32)
				if err != nil {
					return nil, fmt.Errorf(
						"%w: %q is not a valid value for field %q",
						ErrInvalidTamperRule,
						ta.NewValue,
						ta.Field,
					)
				}
			}

			gen.vUint = uint32(val)
		}

		return &TCPTamperAction{
			TamperAction: ta,
			field:        field,
			valueGen:     gen,
		}, nil
	}

	return nil, fmt.Errorf("%w: %q is not a valid tamper mode for TCP", ErrInvalidTamperRule, ta.Mode)
}

// Apply applies the tamper action to the given packet.
func (a *TCPTamperAction) Apply(packet gopacket.Packet) ([]gopacket.Packet, error) {
	tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcp == nil {
		return nil, errors.New("packet does not have a TCP layer")
	}

	tamperTCP(tcp, a.field, a.valueGen)

	// if tampering with TCP options, we need to update the data offset and checksum
	if strings.HasPrefix(a.Field, "options") {
		updateTCPDataOffAndChksum(tcp)

		if ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ip != nil {
			updateIPv4Length(ip)
		}
	}

	sb := gopacket.NewSerializeBuffer()
	err := gopacket.SerializePacket(sb, gopacket.SerializeOptions{}, packet)
	if err != nil {
		panic(err)
	}
	packet = gopacket.NewPacket(sb.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	return a.Action.Apply(packet)
}

// tamperTCP modifies the given TCP field using the given value generator.
func tamperTCP(tcp *layers.TCP, field TCPField, valueGen tamperValueGen) {
	switch field {
	case TCPFieldSrcPort:
		tcp.SrcPort = layers.TCPPort(valueGen.uint(16))
	case TCPFieldDstPort:
		tcp.DstPort = layers.TCPPort(valueGen.uint(16))
	case TCPFieldSeq:
		tcp.Seq = valueGen.uint(32)
	case TCPFieldAck:
		tcp.Ack = valueGen.uint(32)
	case TCPFieldDataOff:
		tcp.DataOffset = uint8(valueGen.uint(8))
	case TCPFieldWindow:
		tcp.Window = uint16(valueGen.uint(16))
	case TCPFieldUrgent:
		tcp.Urgent = uint16(valueGen.uint(16))
	case TCPFieldChecksum:
		tcp.Checksum = uint16(valueGen.uint(16))
	case TCPFieldFlags:
		setTCPFlags(tcp, uint16(valueGen.uint(16)))
	case TCPLoad:
		tcp.Payload = valueGen.bytes(1480)
	default:
		// find option in TCP header
		var opt *layers.TCPOption

		for i, o := range tcp.Options {
			if field == TCPField(o.OptionType) {
				opt = &tcp.Options[i]
				break
			}
		}

		// create option if it doesn't exist and move options-eol to the end of the list
		if opt == nil {
			tcp.Options = append(tcp.Options, layers.TCPOption{
				OptionType: layers.TCPOptionKind(field),
			})

			ol := len(tcp.Options)
			opt = &tcp.Options[ol-1]
		}

		opt.OptionData = valueGen.bytes(tcpOptionLengths[field])
		if field == TCPOptionEol || field == TCPOptionNop {
			opt.OptionLength = 1
		} else {
			opt.OptionLength = uint8(tcpOptionLengths[field]) + 2
		}
	}
}

// tcpFlagsToUint32 converts a string of TCP flags to a uint32 bitmap.
func tcpFlagsToUint32(flags string) uint32 {
	flags = strings.ToLower(flags)

	var f uint32
	for _, c := range flags { //nolint:wsl
		switch c {
		case 'f': // FIN
			f |= 0x0001
		case 's': // SYN
			f |= 0x0002
		case 'r': // RST
			f |= 0x0004
		case 'p': // PSH
			f |= 0x0008
		case 'a': // ACK
			f |= 0x0010
		case 'u': // URG
			f |= 0x0020
		case 'e': // ECE
			f |= 0x0040
		case 'c': // CWR
			f |= 0x0080
		case 'n': // NS
			f |= 0x0100
		}
	}

	return f
}

// setTCPFlags sets the tcp struct fields using flags bitmap, does not modify the raw packet bytes.
func setTCPFlags(tcp *layers.TCP, flags uint16) {
	tcp.FIN = flags&0x0001 != 0
	tcp.SYN = flags&0x0002 != 0
	tcp.RST = flags&0x0004 != 0
	tcp.PSH = flags&0x0008 != 0
	tcp.ACK = flags&0x0010 != 0
	tcp.URG = flags&0x0020 != 0
	tcp.ECE = flags&0x0040 != 0
	tcp.CWR = flags&0x0080 != 0
	tcp.NS = flags&0x0100 != 0
}

// updateTCPDataOffAndChksum updates the TCP data offset and checksum fields on the TCP struct
// and in the raw packet bytes.
func updateTCPDataOffAndChksum(tcp *layers.TCP) {
	// update data offset
	headerLen := len(tcp.Contents)
	tcp.DataOffset = uint8(headerLen / 4)
	tcp.Contents[12] = tcp.DataOffset << 4

	// update checksum.
	common.UpdateTCPChecksum(tcp)
}

//
// IPv4 Tamper Action
//

// IPv4Field is an IPv4 field that can be modified by an IPv4TamperAction.
type IPv4Field uint8

const (
	// supported IPv4 fields.
	IPv4FieldSrcIP = iota
	IPv4FieldDstIP
	IPv4FieldVersion
	IPv4FieldIHL
	IPv4FieldTOS
	IPv4FieldLength
	IPv4FieldID
	IPv4FieldFlags
	IPv4FieldFragOffset
	IPv4FieldTTL
	IPv4FieldProtocol
	IPv4FieldChecksum
	IPv4Load
)

var ipv4Fields = map[string]IPv4Field{
	"srcip":  IPv4FieldSrcIP,
	"dstip":  IPv4FieldDstIP,
	"verion": IPv4FieldVersion,
	"ihl":    IPv4FieldIHL,
	"tos":    IPv4FieldTOS,
	"len":    IPv4FieldLength,
	"id":     IPv4FieldID,
	//
	// I don't know what the flags will look like in a tamper rule
	// shouldn't be a problem since there isn't any tamper rules for IP flags currently
	// "flags":      IPv4FieldFlags,
	//
	"fragoffset": IPv4FieldFragOffset,
	"ttl":        IPv4FieldTTL,
	"protocol":   IPv4FieldProtocol,
	"checksum":   IPv4FieldChecksum,
	"load":       IPv4Load,
}

// IPv4TamperAction is a Geneva action that modifies IPv4 packets.
type IPv4TamperAction struct {
	// TamperAction is the underlying action parsed from the tamper rule.
	TamperAction
	// field is the IPv4 field to modify.
	field IPv4Field
	// valueGen is the value generator to use when modifying the field.
	valueGen tamperValueGen
}

// NewIPv4TamperAction returns a new IPv4TamperAction from the given TamperAction.
func NewIPv4TamperAction(ta TamperAction) (*IPv4TamperAction, error) {
	field, ok := ipv4Fields[ta.Field]
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a recognized IPv4 field", ErrInvalidTamperRule, ta.Field)
	}

	switch ta.Mode {
	case TamperCorrupt:
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		return &IPv4TamperAction{
			TamperAction: ta,
			field:        field,
			valueGen:     &tamperCorruptGen{r},
		}, nil
	case TamperReplace:
		gen := &tamperReplaceGen{}

		switch field {
		case IPv4FieldSrcIP, IPv4FieldDstIP:
			// parse IP address from NewValue and convert to []byte
			ip := net.ParseIP(ta.NewValue)
			if ip == nil {
				return nil, fmt.Errorf("%w: %q is not a valid IPv4 address", ErrInvalidTamperRule, ta.NewValue)
			}

			if ip.To4() == nil {
				return nil, fmt.Errorf("%w: IPv6 is not supported", ErrInvalidTamperRule)
			}

			gen.vBytes = ip
		case IPv4Load:
			gen.vBytes = []byte(ta.NewValue)
		default:
			// parse uint from NewValue
			val, err := strconv.ParseUint(ta.NewValue, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%w: %q is not a valid value for field %q", ErrInvalidTamperRule, ta.NewValue, ta.Field)
			}

			gen.vUint = uint32(val)
		}

		return &IPv4TamperAction{
			TamperAction: ta,
			field:        field,
			valueGen:     gen,
		}, nil
	}

	return nil, fmt.Errorf("%w: %q is not a valid tamper mode for IPv4", ErrInvalidTamperRule, ta.Mode)
}

// Apply applies the tamper action to the given packet.
func (a *IPv4TamperAction) Apply(packet gopacket.Packet) ([]gopacket.Packet, error) {
	ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip == nil {
		return nil, errors.New("packet does not have a IPv4 layer")
	}

	tamperIPv4(ip, a.field, a.valueGen)
	common.UpdateIPv4Checksum(ip)

	return a.Action.Apply(packet)
}

// tamperIPv4 modifies the given IP field using the given value generator.
func tamperIPv4(ip *layers.IPv4, field IPv4Field, valueGen tamperValueGen) {
	switch field {
	case IPv4FieldSrcIP:
		ip.SrcIP = valueGen.bytes(4)
	case IPv4FieldDstIP:
		ip.DstIP = valueGen.bytes(4)
	case IPv4FieldVersion:
		ip.Version = uint8(valueGen.uint(8))
	case IPv4FieldIHL:
		ip.IHL = uint8(valueGen.uint(8))
	case IPv4FieldTOS:
		ip.TOS = uint8(valueGen.uint(8))
	case IPv4FieldLength:
		ip.Length = uint16(valueGen.uint(16))
	case IPv4FieldFlags:
		// not implemented yet. see comment above.
	case IPv4FieldFragOffset:
		ip.FragOffset = uint16(valueGen.uint(16))
	case IPv4FieldTTL:
		ip.TTL = uint8(valueGen.uint(8))
	case IPv4FieldProtocol:
		ip.Protocol = layers.IPProtocol(valueGen.uint(8))
	case IPv4FieldChecksum:
		ip.Checksum = uint16(valueGen.uint(16))
	case IPv4Load:
		ip.Payload = valueGen.bytes(1480)
	}

	// let gopacket handle converting modified packet into []byte again, it's just easier
	// again copy the bytes back into the packet header
	sb := gopacket.NewSerializeBuffer()
	ip.SerializeTo(sb, gopacket.SerializeOptions{})
	ip.Contents = make([]byte, len(sb.Bytes()))
	copy(ip.Contents, sb.Bytes())
}

// updateIPv4Length updates the IPv4 length.
func updateIPv4Length(ip *layers.IPv4) {
	length := len(ip.Contents) + len(ip.Payload)
	ip.Length = uint16(length)
	binary.BigEndian.PutUint16(ip.Contents[2:4], ip.Length)
}

// tamperValueGen is a value generator for tamper actions.
type tamperValueGen interface {
	uint(bitSize int) uint32
	bytes(n int) []byte
}

// tamperReplaceGen just returns newValue casted to the appropriate type.
// it assumes that newValue is the correct type.
type tamperReplaceGen struct {
	vUint  uint32
	vBytes []byte
}

// uint returns the uint value. bitSize is ignored.
func (g *tamperReplaceGen) uint(_ int) uint32 {
	return g.vUint
}

// bytes returns the byte slice or an empty byte slice if n == 0.
func (g *tamperReplaceGen) bytes(n int) []byte {
	if n == 0 {
		return []byte{}
	}

	return append([]byte{}, g.vBytes...)
}

// tamperCorruptGen generates random values for tamperCorrupt actions.
type tamperCorruptGen struct {
	r *rand.Rand
}

// uint returns a random value of the given bit size as a uint32.
func (g *tamperCorruptGen) uint(bitSize int) uint32 {
	n := g.r.Intn(1<<bitSize - 1)
	return uint32(n)
}

// bytes returns a random byte slice of length n if n <= 20, otherwise it returns a
// a random byte slice of random length up to n.
func (g *tamperCorruptGen) bytes(n int) []byte {
	if n > 20 {
		n = g.r.Intn(n)
	}

	b := make([]byte, n)
	g.r.Read(b)

	return b
}
