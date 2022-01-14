package triggers

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/getlantern/errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// IPField is the type of a supported IP field.
type IPField int

const (
	IPFieldVersion = iota
	IPFieldIHL
	IPFieldTOS
	IPFieldLength
	IPFieldIdentification
	IPFieldFlags
	IPFieldFragmentOffset
	IPFieldTTL
	IPFieldProtocol
	IPFieldChecksum
	IPFieldSourceAddress
	IPFieldDestAddress
	IPFieldPayload
)

// IPFields returns a list of the fields supported by the IP trigger.
func IPFields() map[IPField]string {
	return map[IPField]string{
		IPFieldVersion:        "version",
		IPFieldIHL:            "ihl",
		IPFieldTOS:            "tos",
		IPFieldLength:         "len",
		IPFieldIdentification: "id",
		IPFieldFlags:          "flags",
		IPFieldFragmentOffset: "frag",
		IPFieldTTL:            "ttl",
		IPFieldProtocol:       "proto",
		IPFieldChecksum:       "chksum",
		IPFieldSourceAddress:  "src",
		IPFieldDestAddress:    "dst",
		IPFieldPayload:        "load",
	}
}

// ParseIPField parses a field name and returns an IPField, or an error if the field is not supported.
func ParseIPField(field string) (IPField, error) {
	for k, v := range IPFields() {
		if field == v {
			return k, nil
		}
	}

	return IPField(-1), errors.New("unknown IP field %q", field)
}

// IPTrigger is a Trigger that matches on the IP layer.
type IPTrigger struct {
	field IPField
	value string
	gas   int

	ipField layers.IPv4Flag
}

// String returns a string representation of this trigger.
func (t *IPTrigger) String() string {
	gas := ""
	if t.gas > 0 {
		gas = fmt.Sprintf(":%d", t.gas)
	}

	return fmt.Sprintf("[%s:%s:%s%s]", t.Protocol(), t.Field(), t.value, gas)
}

// Protocol is the protocol that this trigger can act upon.
func (t *IPTrigger) Protocol() string {
	return "IP"
}

// Field is an IP-specific field name used by this trigger.
func (t *IPTrigger) Field() string {
	return IPFields()[t.field]
}

// Gas denotes how many times this trigger can fire before it stops triggering.
func (t *IPTrigger) Gas() int {
	return t.gas
}

// Matches returns whether the trigger matches the packet.
func (t *IPTrigger) Matches(pkt gopacket.Packet) (bool, error) {
	ipLayer, ok := pkt.NetworkLayer().(*layers.IPv4)
	if !ok || ipLayer == nil {
		// XXX currently only supports IPv4
		return false, nil
	}

	switch t.field {
	case IPFieldFlags:
		return (ipLayer.Flags == t.ipField), nil
	case IPFieldSourceAddress:
		return ipLayer.SrcIP.Equal(net.ParseIP(t.value)), nil
	case IPFieldDestAddress:
		return ipLayer.DstIP.Equal(net.ParseIP(t.value)), nil
	case IPFieldPayload:
		if len(ipLayer.Payload) < len(t.value) {
			return false, nil
		}

		for i, r := range []byte(t.value) {
			if r != ipLayer.Payload[i] {
				return false, nil
			}
		}

		return true, nil
	}

	// The rest of the triggers work on numbers.
	tmp, err := strconv.ParseUint(t.value, 0, 16)
	if err != nil {
		return false, errors.Wrap(err)
	}

	v := uint16(tmp)

	switch t.field {
	case IPFieldVersion:
		return (uint16(ipLayer.Version) == v), nil
	case IPFieldIHL:
		return (uint16(ipLayer.IHL) == v), nil
	case IPFieldTOS:
		return (uint16(ipLayer.TOS) == v), nil
	case IPFieldLength:
		return (ipLayer.Length == v), nil
	case IPFieldIdentification:
		return (ipLayer.Id == v), nil
	case IPFieldFragmentOffset:
		return (ipLayer.FragOffset == v), nil
	case IPFieldTTL:
		return (uint16(ipLayer.TTL) == v), nil
	case IPFieldProtocol:
		return (uint16(ipLayer.Protocol) == v), nil
	case IPFieldChecksum:
		return (ipLayer.Checksum == v), nil
	default:
		return false, errors.New("IPTrigger.Matches(%s) is unimplemented", t.Field())
	}
}

// NewIPTrigger creates a new IP trigger.
func NewIPTrigger(field, value string, gas int) (*IPTrigger, error) {
	if field == "" {
		return nil, errors.New("cannot create IP trigger with empty field")
	}

	if value == "" {
		// XXX just like with TCP triggers, this is a false statement
		// that needs to be fixed.
		return nil, errors.New("cannot create IP trigger with empty value")
	}

	f, err := ParseIPField(field)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	trigger := &IPTrigger{f, value, gas, 0}

	if f == IPFieldFlags {
		// The original Geneva project heavily relies on Scapy for processing. Due to this, we need to convert
		// from scapy's string representations to gopacket's more structured ones.
		for _, flag := range strings.Split(value, "+") {
			switch strings.ToLower(flag) {
			case "mf":
				trigger.ipField |= layers.IPv4MoreFragments
			case "df":
				trigger.ipField |= layers.IPv4DontFragment
			case "evil":
				trigger.ipField |= layers.IPv4EvilBit
			}
		}
	}

	return trigger, nil
}
