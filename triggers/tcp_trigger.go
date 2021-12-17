package triggers

import (
	"fmt"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
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
	return TCPField(0), fmt.Errorf("invalid field name")
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
func (t *TCPTrigger) Matches(gopacket.Packet) (bool, error) {
	return false, nil
}

// NewTCPTrigger creates a new TCP trigger.
func NewTCPTrigger(field, value string, gas int) (*TCPTrigger, error) {
	if field == "" {
		return nil, fmt.Errorf("invalid field")
	}

	if value == "" {
		return nil, fmt.Errorf("invalid value")
	}

	if f, err := ParseTCPField(field); err != nil {
		return nil, err
	} else {
		return &TCPTrigger{f, value, gas}, nil
	}
}
