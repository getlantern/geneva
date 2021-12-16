package triggers

import (
	"fmt"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
)

type IPField int

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

func ParseIPField(field string) (IPField, error) {
	for i, v := range IPFields() {
		if field == v {
			return IPField(i), nil
		}
	}
	return IPField(0), fmt.Errorf("invalid field name")
}

type IPTrigger struct {
	field IPField
	value string
	gas   int
}

func (t *IPTrigger) String() string {
	gas := ""
	if t.gas > 0 {
		gas = fmt.Sprintf(":%d", t.gas)
	}
	return fmt.Sprintf("[%s:%s:%s%s]", t.Protocol(), t.Field(), t.value, gas)
}

func (t *IPTrigger) Protocol() string {
	return "IP"
}

func (t *IPTrigger) Field() string {
	return IPFields()[t.field]
}

func (t *IPTrigger) Gas() int {
	return t.gas
}

func (t *IPTrigger) Matches(gopacket.Packet) (bool, error) {
	return false, nil
}

func NewIPTrigger(field, value string, gas int) (*IPTrigger, error) {
	if value == "" {
		return nil, fmt.Errorf("invalid field value")
	}

	if f, err := ParseIPField(field); err != nil {
		return nil, err
	} else {
		return &IPTrigger{f, value, gas}, nil
	}
}
