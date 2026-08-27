package triggers

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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

// ParseIPField parses a field name and returns an IPField, or an error if the field is not
// supported.
func ParseIPField(field string) (IPField, error) {
	for k, v := range IPFields() {
		if field == v {
			return k, nil
		}
	}

	return IPField(-1), fmt.Errorf("unknown IP field %q", field)
}

// IPTrigger is a Trigger that matches on the IP layer.
type IPTrigger struct {
	field IPField
	value string
	gas   *triggerGas

	ipField layers.IPv4Flag
}

// String returns a string representation of this trigger.
func (t *IPTrigger) String() string {
	gas := ""
	if value, ok := t.gas.value(); ok {
		gas = fmt.Sprintf(":%d", value)
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
//
// Gas is lossy: an unlimited trigger and a fully configured-but-exhausted one both read as 0
// here. Use GasConfigured when the distinction matters.
func (t *IPTrigger) Gas() int {
	gas, _ := t.gas.value()
	return gas
}

// GasConfigured returns the trigger's configured gas and whether a gas limit was configured at
// all. Positive gas fires for that many matching packets, zero never fires, and negative gas is
// a bomb that fires indefinitely after suppressing -gas matches. When configured is false the
// trigger has unlimited gas.
func (t *IPTrigger) GasConfigured() (int, bool) {
	return t.gas.value()
}

// Matches returns whether the trigger matches the packet.
func (t *IPTrigger) Matches(pkt gopacket.Packet) (bool, error) {
	matched, err := t.matches(pkt)
	if err != nil {
		return false, err
	}

	return t.gas.allow(matched), nil
}

func (t *IPTrigger) matches(pkt gopacket.Packet) (bool, error) {
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
		return bytes.Equal(ipLayer.Payload, []byte(t.value)), nil
	}

	// The rest of the triggers work on numbers.
	tmp, err := strconv.ParseUint(t.value, 0, 16)
	if err != nil {
		return false, fmt.Errorf("failed to parse value while matching: %w", err)
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
		return false, fmt.Errorf("IPTrigger.Matches(%s) is unimplemented", t.Field())
	}
}

func (t *IPTrigger) validate() error {
	if t == nil {
		return fmt.Errorf("IP trigger is nil")
	}

	switch t.field {
	case IPFieldFlags:
		if t.value == "" {
			return fmt.Errorf("IP flags value is empty")
		}
		for _, flag := range strings.Split(t.value, "+") {
			switch strings.ToLower(flag) {
			case "mf", "df", "evil":
			default:
				return fmt.Errorf("unknown IP flag %q", flag)
			}
		}
		return nil
	case IPFieldSourceAddress, IPFieldDestAddress:
		ip := net.ParseIP(t.value)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("%q is not an IPv4 address", t.value)
		}
		return nil
	case IPFieldPayload:
		return nil
	}

	bits := 16
	switch t.field {
	case IPFieldVersion, IPFieldIHL, IPFieldTOS, IPFieldTTL, IPFieldProtocol:
		bits = 8
	}
	if _, err := strconv.ParseUint(t.value, 0, bits); err != nil {
		return fmt.Errorf("invalid value %q for IP field %q: %w", t.value, t.Field(), err)
	}

	return nil
}

// NewIPTrigger creates a new IP trigger.
//
// For compatibility with earlier versions of this package, a gas of 0 means the
// trigger has unlimited gas; it will fire for every matching packet. To create
// a trigger with zero gas (one that never fires), parse "[IP:field:value:0]"
// with ParseTrigger or strategy.ParseStrategy, or call NewIPTriggerWithGas.
func NewIPTrigger(field, value string, gas int) (*IPTrigger, error) {
	if gas == 0 {
		return newIPTrigger(field, value, nil)
	}

	return newIPTrigger(field, value, &gas)
}

// NewIPTriggerWithGas creates a new IP trigger whose gas is interpreted exactly as given:
// positive gas fires for that many matching packets, zero never fires, and negative gas is a
// bomb that fires indefinitely after suppressing -gas matches.
func NewIPTriggerWithGas(field, value string, gas int) (*IPTrigger, error) {
	return newIPTrigger(field, value, &gas)
}

func newIPTrigger(field, value string, gas *int) (*IPTrigger, error) {
	if field == "" {
		return nil, fmt.Errorf("cannot create IP trigger with empty field")
	}

	f, err := ParseIPField(field)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IP field: %w", err)
	}

	trigger := &IPTrigger{field: f, value: value, gas: newTriggerGas(gas)}

	if f == IPFieldFlags {
		// The original Geneva project heavily relies on Scapy for processing. Due to this,
		// we need to convert from scapy's string representations to gopacket's more
		// structured ones.
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

	if err := trigger.validate(); err != nil {
		return nil, fmt.Errorf("failed to create trigger: %w", err)
	}

	return trigger, nil
}
