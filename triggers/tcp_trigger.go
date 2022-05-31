package triggers

import (
	gerrors "errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/getlantern/errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ErrUnsupportedOption is returned when an unsupported TCP option is specified in a trigger rule.
var ErrUnsupportedOption = gerrors.New("unsupported option")

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

	return TCPField(-1), errors.New("unknown TCP field %q", field)
}

// TCPTrigger is a Trigger that matches on the TCP layer.
type TCPTrigger struct {
	field TCPField
	value string
	gas   int
}

// String returns a string representation of this trigger.
func (t *TCPTrigger) String() string {
	gas := ""
	if t.gas > 0 {
		gas = fmt.Sprintf(":%d", t.gas)
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
func (t *TCPTrigger) Gas() int {
	return t.gas
}

func matchField(value string, tcpLayer *layers.TCP) bool {
	for _, c := range value {
		var match bool

		switch c {
		case 'F':
			match = tcpLayer.FIN
		case 'S':
			match = tcpLayer.SYN
		case 'R':
			match = tcpLayer.RST
		case 'P':
			match = tcpLayer.PSH
		case 'A':
			match = tcpLayer.ACK
		case 'U':
			match = tcpLayer.URG
		case 'E':
			match = tcpLayer.ECE
		case 'C':
			match = tcpLayer.CWR
		case 'N':
			match = tcpLayer.NS
		default:
			match = false
		}

		if !match {
			// bail early if the trigger wants a flag set that isn't
			return false
		}
	}

	return true
}

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
			if len(opt.OptionData) < len(value) {
				return false, nil
			}

			for i, b := range opt.OptionData {
				if b != []byte(value)[i] {
					return false, nil
				}
			}

			return true, nil
		}
	}

	return false, nil
}

// Matches returns whether the trigger matches the packet.
func (t *TCPTrigger) Matches(pkt gopacket.Packet) (bool, error) {
	tcpLayer, ok := pkt.TransportLayer().(*layers.TCP)
	if !ok || tcpLayer == nil {
		return false, nil
	}

	switch t.field {
	case TCPFieldFlags:
		return matchField(t.value, tcpLayer), nil
	case TCPFieldPayload:
		if len(tcpLayer.Payload) < len(t.value) {
			return false, nil
		}

		for i, r := range []byte(t.value) {
			if r != tcpLayer.Payload[i] {
				return false, nil
			}
		}

		return true, nil

	case TCPFieldOptionEOL, TCPFieldOptionNOP, TCPFieldOptionMSS, TCPFieldOptionWScale,
		TCPFieldOptionSackOk, TCPFieldOptionSack, TCPFieldOptionTimestamp,
		TCPFieldOptionAltChecksum, TCPFieldOptionAltChecksumOpt, TCPFieldOptionMD5Header,
		TCPFieldOptionUTO:
		return matchTCPOption(t.field, t.value, tcpLayer)
	}

	tmp, err := strconv.ParseUint(t.value, 0, 32)
	if err != nil {
		return false, errors.Wrap(err)
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

	return false, errors.New("TCPTrigger.Matches(%s) is unimplemented", t.Field())
}

// NewTCPTrigger creates a new TCP trigger.
func NewTCPTrigger(field, value string, gas int) (*TCPTrigger, error) {
	if field == "" {
		return nil, errors.New("cannot create TCP trigger with empty field")
	}

	f, err := ParseTCPField(field)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	if f == TCPFieldFlags {
		value = strings.ToUpper(value)
	}

	return &TCPTrigger{f, value, gas}, nil
}
