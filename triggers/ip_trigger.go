package triggers

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers" // gopacket best practice is to import this as well
)

// IPField is the type of a supported IP field.
type IPField int

// IPFields returns a list of the fields supported by the IP trigger.
func IPFields() []string {
	return []string{
		"version",
		"ihl",
		"tos",
		"len",
		"id",
		"flags",
		"frag",
		"ttl",
		"proto",
		"chksum",
		"src",
		"dst",
		"load",
	}
}

// ParseIPField parses a field name and returns an IPField, or an error if the field is not supported.
func ParseIPField(field string) (IPField, error) {
	for i, v := range IPFields() {
		if field == v {
			return IPField(i), nil
		}
	}
	return IPField(0), fmt.Errorf("invalid field name")
}

// IPTrigger is a Trigger that matches on the IP layer.
type IPTrigger struct {
	field IPField
	value string
	gas   int
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
	ipLayer := pkt.NetworkLayer().(*layers.IPv4)
	if ipLayer == nil {
		// XXX currently only supports IPv4
		return false, nil
	}

	switch t.Field() {
	case "flags":
		var val layers.IPv4Flag
		// The original Geneva project heavily relies on Scapy for processing. Due to this, we need to convert
		// from scapy's string representations to gopacket's more structured ones.
		for _, flag := range strings.Split(t.value, "+") {
			switch strings.ToLower(flag) {
			case "mf":
				val |= layers.IPv4MoreFragments
			case "df":
				val |= layers.IPv4DontFragment
			case "evil":
				val |= layers.IPv4EvilBit
			}
		}
		return (ipLayer.Flags == val), nil
	case "src":
		ipAddr := net.ParseIP(t.value)
		return ipLayer.SrcIP.Equal(ipAddr), nil
	case "dst":
		ipAddr := net.ParseIP(t.value)
		return ipLayer.DstIP.Equal(ipAddr), nil
	case "load":
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
		return false, err
	}

	v := uint16(tmp)

	switch t.Field() {
	case "version":
		return (uint16(ipLayer.Version) == v), nil
	case "ihl":
		return (uint16(ipLayer.IHL) == v), nil
	case "tos":
		return (uint16(ipLayer.TOS) == v), nil
	case "len":
		return (uint16(ipLayer.Length) == v), nil
	case "id":
		return (uint16(ipLayer.Id) == v), nil
	case "frag":
		return (uint16(ipLayer.FragOffset) == v), nil
	case "ttl":
		return (uint16(ipLayer.TTL) == v), nil
	case "proto":
		return (uint16(ipLayer.Protocol) == v), nil
	case "chksum":
		return (uint16(ipLayer.Checksum) == v), nil
	default:
		return false, fmt.Errorf("IPTrigger.Matches(%s) is unimplemented", t.Field())
	}
}

// NewIPTrigger creates a new IP trigger.
func NewIPTrigger(field, value string, gas int) (*IPTrigger, error) {
	if value == "" {
		return nil, fmt.Errorf("invalid field value")
	}

	f, err := ParseIPField(field)
	if err != nil {
		return nil, err
	}

	return &IPTrigger{f, value, gas}, nil
}
