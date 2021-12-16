package triggers

import (
	"fmt"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
)

type TCPField int

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

func ParseTCPField(field string) (TCPField, error) {
	for i, v := range TCPFields() {
		if field == v {
			return TCPField(i), nil
		}
	}
	return TCPField(0), fmt.Errorf("invalid field name")
}

type TCPTrigger struct {
	field TCPField
	value string
	gas   int
}

func (t *TCPTrigger) String() string {
	gas := ""
	if t.gas > 0 {
		gas = fmt.Sprintf(":%d", t.gas)
	}
	return fmt.Sprintf("[%s:%s:%s%s]", t.Protocol(), t.Field(), t.value, gas)
}

func (t *TCPTrigger) Protocol() string {
	return "TCP"
}

func (t *TCPTrigger) Field() string {
	return TCPFields()[t.field]
}

func (t *TCPTrigger) Gas() int {
	return t.gas
}

func (t *TCPTrigger) Matches(gopacket.Packet) (bool, error) {
	return false, nil
}

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
