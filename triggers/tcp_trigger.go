package triggers

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ErrUnsupportedOption is returned when an unsupported TCP option is specified in a trigger rule.
var ErrUnsupportedOption = errors.New("unsupported option")

// TCPField is the type of a supported TCP field.
type TCPField int

const (
	TCPFieldSourcePort = iota
	TCPFieldDestPort
	TCPFieldSeq
	TCPFieldAck
	TCPFieldDataOffset
	TCPFieldReserved
	TCPFieldFlags
	TCPFieldWindow
	TCPFieldChecksum
	TCPFieldUrgentPointer
	TCPFieldPayload
	TCPFieldOptionEOL
	TCPFieldOptionNOP
	TCPFieldOptionMSS
	TCPFieldOptionWScale
	TCPFieldOptionSackOk
	TCPFieldOptionSack
	TCPFieldOptionTimestamp
	TCPFieldOptionAltChecksum
	TCPFieldOptionAltChecksumOpt
	TCPFieldOptionMD5Header
	TCPFieldOptionUTO
)

// TCPFields returns a list of the fields supported by the TCP trigger.
func TCPFields() map[TCPField]string {
	return map[TCPField]string{
		TCPFieldSourcePort:           "sport",
		TCPFieldDestPort:             "dport",
		TCPFieldSeq:                  "seq",
		TCPFieldAck:                  "ack",
		TCPFieldDataOffset:           "dataofs",
		TCPFieldReserved:             "reserved",
		TCPFieldFlags:                "flags",
		TCPFieldWindow:               "window",
		TCPFieldChecksum:             "chksum",
		TCPFieldUrgentPointer:        "urgptr",
		TCPFieldPayload:              "load",
		TCPFieldOptionEOL:            "options-eol",
		TCPFieldOptionNOP:            "options-nop",
		TCPFieldOptionMSS:            "options-mss",
		TCPFieldOptionWScale:         "options-wscale",
		TCPFieldOptionSackOk:         "options-sackok",
		TCPFieldOptionSack:           "options-sack",
		TCPFieldOptionTimestamp:      "options-timestamp",
		TCPFieldOptionAltChecksum:    "options-altchksum",
		TCPFieldOptionAltChecksumOpt: "options-altchksumopt",
		TCPFieldOptionMD5Header:      "options-md5header",
		TCPFieldOptionUTO:            "options-uto",
	}
}

// ParseTCPField parses a field name and returns an TCPField, or an error if the field is not
// supported.
func ParseTCPField(field string) (TCPField, error) {
	for k, v := range TCPFields() {
		if field == v {
			return k, nil
		}
	}

	return TCPField(-1), fmt.Errorf("unknown TCP field %q", field)
}

// TCPTrigger is a Trigger that matches on the TCP layer.
type TCPTrigger struct {
	field TCPField
	value string
	gas   *triggerGas
}

// String returns a string representation of this trigger.
func (t *TCPTrigger) String() string {
	gas := ""
	if value, ok := t.gas.value(); ok {
		gas = fmt.Sprintf(":%d", value)
	}

	return fmt.Sprintf("[%s:%s:%s%s]", t.Protocol(), t.Field(), t.value, gas)
}

// Protocol is the protocol that this trigger can act upon.
func (t *TCPTrigger) Protocol() string {
	return "TCP"
}

// Field is an TCP-specific field name used by this trigger.
func (t *TCPTrigger) Field() string {
	return TCPFields()[t.field]
}

// Gas denotes how many times this trigger can fire before it stops triggering.
//
// Gas is lossy: an unlimited trigger and a fully configured-but-exhausted one both read as 0
// here. Use GasConfigured when the distinction matters.
func (t *TCPTrigger) Gas() int {
	gas, _ := t.gas.value()
	return gas
}

// GasConfigured returns the trigger's configured gas and whether a gas limit was configured at
// all. Positive gas fires for that many matching packets, zero never fires, and negative gas is
// a bomb that fires indefinitely after suppressing -gas matches. When configured is false the
// trigger has unlimited gas.
func (t *TCPTrigger) GasConfigured() (int, bool) {
	return t.gas.value()
}

func matchField(value string, tcpLayer *layers.TCP) bool {
	wildcard := strings.HasSuffix(value, "*")
	value = strings.TrimSuffix(value, "*")

	var wanted uint16
	for _, c := range value {
		switch c {
		case 'F':
			wanted |= 0x001
		case 'S':
			wanted |= 0x002
		case 'R':
			wanted |= 0x004
		case 'P':
			wanted |= 0x008
		case 'A':
			wanted |= 0x010
		case 'U':
			wanted |= 0x020
		case 'E':
			wanted |= 0x040
		case 'C':
			wanted |= 0x080
		case 'N':
			wanted |= 0x100
		default:
			return false
		}
	}

	var actual uint16
	if tcpLayer.FIN {
		actual |= 0x001
	}
	if tcpLayer.SYN {
		actual |= 0x002
	}
	if tcpLayer.RST {
		actual |= 0x004
	}
	if tcpLayer.PSH {
		actual |= 0x008
	}
	if tcpLayer.ACK {
		actual |= 0x010
	}
	if tcpLayer.URG {
		actual |= 0x020
	}
	if tcpLayer.ECE {
		actual |= 0x040
	}
	if tcpLayer.CWR {
		actual |= 0x080
	}
	if tcpLayer.NS {
		actual |= 0x100
	}

	if wildcard {
		return actual&wanted == wanted
	}

	return actual == wanted
}

// isTCPOptionField reports whether field refers to a TCP header option rather than a
// fixed TCP header field or the payload.
func isTCPOptionField(field TCPField) bool {
	switch field {
	case TCPFieldOptionEOL, TCPFieldOptionNOP, TCPFieldOptionMSS, TCPFieldOptionWScale,
		TCPFieldOptionSackOk, TCPFieldOptionSack, TCPFieldOptionTimestamp,
		TCPFieldOptionAltChecksum, TCPFieldOptionAltChecksumOpt, TCPFieldOptionMD5Header,
		TCPFieldOptionUTO:
		return true
	default:
		return false
	}
}

// matchTCPOption compares a TCP header option's data against value.
func matchTCPOption(field TCPField, value string, tcpLayer *layers.TCP) (bool, error) {
	var optKind layers.TCPOptionKind

	switch field {
	case TCPFieldOptionEOL:
		optKind = layers.TCPOptionKindEndList
	case TCPFieldOptionNOP:
		optKind = layers.TCPOptionKindNop
	case TCPFieldOptionMSS:
		optKind = layers.TCPOptionKindMSS
	case TCPFieldOptionWScale:
		optKind = layers.TCPOptionKindWindowScale
	case TCPFieldOptionSackOk:
		optKind = layers.TCPOptionKindSACKPermitted
	case TCPFieldOptionSack:
		optKind = layers.TCPOptionKindSACK
	case TCPFieldOptionTimestamp:
		optKind = layers.TCPOptionKindTimestamps
	case TCPFieldOptionAltChecksum:
		optKind = layers.TCPOptionKindAltChecksumData
	case TCPFieldOptionAltChecksumOpt:
		optKind = layers.TCPOptionKindAltChecksum
	case TCPFieldOptionMD5Header:
		optKind = 19 // gopacket doesn't know about this one
	case TCPFieldOptionUTO:
		optKind = 28 // "User Time-Out"; also unknown to gopacket
	default:
		return false, ErrUnsupportedOption
	}

	for _, opt := range tcpLayer.Options {
		if opt.OptionType == optKind {
			// An empty value is a presence trigger: it matches any packet carrying the
			// option, regardless of its data.
			if value == "" {
				return true, nil
			}
			return bytes.Equal(opt.OptionData, []byte(value)), nil
		}
	}

	return false, nil
}

// Matches returns whether the trigger matches the packet.
func (t *TCPTrigger) Matches(pkt gopacket.Packet) (bool, error) {
	matched, err := t.matches(pkt)
	if err != nil {
		return false, err
	}

	return t.gas.allow(matched), nil
}

func (t *TCPTrigger) matches(pkt gopacket.Packet) (bool, error) {
	tcpLayer, ok := pkt.TransportLayer().(*layers.TCP)
	if !ok || tcpLayer == nil {
		return false, nil
	}

	switch t.field {
	case TCPFieldFlags:
		return matchField(t.value, tcpLayer), nil
	case TCPFieldPayload:
		return bytes.Equal(tcpLayer.Payload, []byte(t.value)), nil
	}

	if isTCPOptionField(t.field) {
		return matchTCPOption(t.field, t.value, tcpLayer)
	}

	tmp, err := strconv.ParseUint(t.value, 0, 32)
	if err != nil {
		return false, fmt.Errorf("match failed: %w", err)
	}

	v := uint32(tmp)

	switch t.field {
	case TCPFieldSourcePort:
		if v > math.MaxUint16 {
			return false, errors.New("source port must be in the range 0-65535")
		}

		return tcpLayer.SrcPort == layers.TCPPort(v), nil
	case TCPFieldDestPort:
		if v > math.MaxUint16 {
			return false, errors.New("destination port must be in the range 0-65535")
		}

		return tcpLayer.DstPort == layers.TCPPort(v), nil
	case TCPFieldSeq:
		return tcpLayer.Seq == v, nil
	case TCPFieldAck:
		return tcpLayer.Ack == v, nil
	case TCPFieldDataOffset:
		return uint32(tcpLayer.DataOffset) == v, nil
	case TCPFieldReserved:
		return (uint32((pkt.Data()[12]&0xf)>>1) == v), nil
	case TCPFieldWindow:
		return uint32(tcpLayer.Window) == v, nil
	case TCPFieldChecksum:
		return uint32(tcpLayer.Checksum) == v, nil
	case TCPFieldUrgentPointer:
		return uint32(tcpLayer.Urgent) == v, nil
	}

	return false, fmt.Errorf("TCPTrigger.Matches(%s) is unimplemented", t.Field())
}

func (t *TCPTrigger) validate() error {
	if t == nil {
		return fmt.Errorf("TCP trigger is nil")
	}

	// An empty value is meaningful for the payload and for any option: "[tcp:load:]" triggers
	// on packets with no payload, and an empty option value is a presence trigger that fires on
	// any packet carrying that option, regardless of its data (canonical Geneva ships strategies
	// like "[tcp:options-sackok:]" and "[tcp:options-sack:]"). For any other field an empty value
	// would be a permanently dead trigger, so reject it rather than letting it fail later with a
	// confusing parse error (or silently never fire).
	if t.value == "" && t.field != TCPFieldPayload && !isTCPOptionField(t.field) {
		return fmt.Errorf("TCP field %q has an empty trigger value", t.Field())
	}

	switch t.field {
	case TCPFieldFlags:
		flags := strings.TrimSuffix(t.value, "*")
		if flags == "" {
			return fmt.Errorf("TCP flags value is empty")
		}
		for _, flag := range flags {
			if !strings.ContainsRune("FSRPAUECN", flag) {
				return fmt.Errorf("unknown TCP flag %q", flag)
			}
		}
		return nil
	case TCPFieldPayload:
		return nil
	}

	if isTCPOptionField(t.field) {
		return nil
	}

	value, err := strconv.ParseUint(t.value, 0, 32)
	if err != nil {
		return fmt.Errorf("invalid value %q for TCP field %q: %w", t.value, t.Field(), err)
	}
	if (t.field == TCPFieldSourcePort || t.field == TCPFieldDestPort) && value > math.MaxUint16 {
		return fmt.Errorf("value %d for TCP field %q exceeds 65535", value, t.Field())
	}

	return nil
}

// NewTCPTrigger creates a new TCP trigger.
//
// For compatibility with earlier versions of this package, a gas of 0 means the
// trigger has unlimited gas; it will fire for every matching packet. To create
// a trigger with zero gas (one that never fires), parse "[TCP:field:value:0]"
// with ParseTrigger or strategy.ParseStrategy, or call NewTCPTriggerWithGas.
func NewTCPTrigger(field, value string, gas int) (*TCPTrigger, error) {
	if gas == 0 {
		return newTCPTrigger(field, value, nil)
	}

	return newTCPTrigger(field, value, &gas)
}

// NewTCPTriggerWithGas creates a new TCP trigger whose gas is interpreted exactly as given:
// positive gas fires for that many matching packets, zero never fires, and negative gas is a
// bomb that fires indefinitely after suppressing -gas matches.
func NewTCPTriggerWithGas(field, value string, gas int) (*TCPTrigger, error) {
	return newTCPTrigger(field, value, &gas)
}

func newTCPTrigger(field, value string, gas *int) (*TCPTrigger, error) {
	if field == "" {
		return nil, fmt.Errorf("cannot create TCP trigger with empty field")
	}

	f, err := ParseTCPField(field)
	if err != nil {
		return nil, fmt.Errorf("failed to create trigger: %w", err)
	}

	if f == TCPFieldFlags {
		value = strings.ToUpper(value)
	}

	trigger := &TCPTrigger{field: f, value: value, gas: newTriggerGas(gas)}
	if err := trigger.validate(); err != nil {
		return nil, fmt.Errorf("failed to create trigger: %w", err)
	}

	return trigger, nil
}
