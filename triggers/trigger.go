package triggers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Crosse/geneva/internal/scanner"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
)

// Trigger is implemented by any value that describes a Geneva trigger.
type Trigger interface {
	// Protocol is the protocol that a trigger can act upon.
	Protocol() string
	// Field is a protocol-specific field name.
	Field() string
	// Gas denotes how many times this trigger can fire before it stops triggering.
	Gas() int
	// Matches returns whether the trigger matches the packet.
	Matches(gopacket.Packet) (bool, error)
	fmt.Stringer
}

// ParseTrigger parses a string representation of a trigger into the actual Trigger object.
// If the string is malformed, and error will be returned instead.
func ParseTrigger(s *scanner.Scanner) (Trigger, error) {
	if _, err := s.Expect("["); err != nil {
		return nil, err
	}

	str, err := s.Until(']')
	if err != nil {
		return nil, err
	}
	_, _ = s.Pop()

	fields := strings.Split(str, ":")
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid trigger format")
	}

	if fields[0] == "" {
		return nil, fmt.Errorf("invalid protocol")
	}

	gas := 0
	if len(fields) == 4 {
		gas, err = strconv.Atoi(fields[3])
		if err != nil {
			return nil, err
		}
	}

	var trigger Trigger
	switch strings.ToLower(fields[0]) {
	case "ip":
		trigger, err = NewIPTrigger(fields[1], fields[2], gas)
	case "tcp":
		trigger, err = NewTCPTrigger(fields[1], fields[2], gas)
	}

	if err != nil {
		return nil, err
	}

	return trigger, nil
}
