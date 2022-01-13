package triggers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/getlantern/errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPField is the type of a supported TCP field.
type TCPField int

// TCPFields returns a list of the fields supported by the TCP trigger.
func TCPFields() []string {
	return []string{
		"sport",
		"dport",
		"seq",
		"ack",
		"dataofs",
		"reserved",
		"flags",
		"window",
		"chksum",
		"urgptr",
		"load",
		"options-eol",
		"options-nop",
		"options-mss",
		"options-wscale",
		"options-sackok",
		"options-sack",
		"options-timestamp",
		"options-altchksum",
		"options-altchksumopt",
		"options-md5header",
		"options-uto",
	}
}

// ParseTCPField parses a field name and returns an TCPField, or an error if the field is not supported.
func ParseTCPField(field string) (TCPField, error) {
	for i, v := range TCPFields() {
		if field == v {
			return TCPField(i), nil
		}
	}
	return TCPField(0), errors.New("unknown TCP field %s", field)
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

// Matches returns whether the trigger matches the packet.
func (t *TCPTrigger) Matches(pkt gopacket.Packet) (bool, error) {
	tcpLayer, ok := pkt.TransportLayer().(*layers.TCP)
	if !ok || tcpLayer == nil {
		return false, nil
	}

	switch t.Field() {
	case "flags":
		for _, flag := range strings.ToUpper(t.value) {
			var match bool

			switch flag {
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
				return false, nil
			}
		}
		return true, nil
	case "load":
		if len(tcpLayer.Payload) < len(t.value) {
			return false, nil
		}

		for i, r := range []byte(t.value) {
			if r != tcpLayer.Payload[i] {
				return false, nil
			}
		}
		return true, nil
	}

	if strings.HasPrefix(t.Field(), "options-") {
		var optKind layers.TCPOptionKind

		switch strings.Split(t.Field(), "-")[1] {
		case "eol":
			optKind = layers.TCPOptionKindEndList
		case "nop":
			optKind = layers.TCPOptionKindNop
		case "mss":
			optKind = layers.TCPOptionKindMSS
		case "wscale":
			optKind = layers.TCPOptionKindWindowScale
		case "sackok":
			optKind = layers.TCPOptionKindSACKPermitted
		case "sack":
			optKind = layers.TCPOptionKindSACK
		case "timestamp":
			optKind = layers.TCPOptionKindTimestamps
		case "altchksum":
			optKind = layers.TCPOptionKindAltChecksumData
		case "altchksumopt":
			optKind = layers.TCPOptionKindAltChecksum
		case "md5header":
			optKind = 19 // gopacket doesn't know about this one
		case "uto":
			optKind = 28 // "User Time-Out"; also unknown to gopacket
		}

		for _, opt := range tcpLayer.Options {
			if opt.OptionType == optKind {
				for i, b := range opt.OptionData {
					if b != []byte(t.value)[i] {
						return false, nil
					}
				}
				return true, nil
			}
		}
		return false, nil
	}

	tmp, err := strconv.ParseUint(t.value, 0, 32)
	if err != nil {
		return false, errors.Wrap(err)
	}

	v := uint32(tmp)

	switch t.Field() {
	case "sport":
		return tcpLayer.SrcPort == layers.TCPPort(v), nil
	case "dport":
		return tcpLayer.DstPort == layers.TCPPort(v), nil
	case "seq":
		return tcpLayer.Seq == v, nil
	case "ack":
		return tcpLayer.Ack == v, nil
	case "dataofs":
		return uint32(tcpLayer.DataOffset) == v, nil
	case "reserved":
		return (uint32((pkt.Data()[12]&0xf)>>1) == v), nil
	case "window":
		return uint32(tcpLayer.Window) == v, nil
	case "chksum":
		return uint32(tcpLayer.Checksum) == v, nil
	case "urgptr":
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

	return &TCPTrigger{f, value, gas}, nil
}
