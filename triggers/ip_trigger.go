package triggers

import (
	"fmt"

	"github.com/google/gopacket"
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
func (t *IPTrigger) Matches(gopacket.Packet) (bool, error) {
	return false, nil
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
