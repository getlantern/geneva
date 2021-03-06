// Package triggers enumerates all of the various triggers that can be used to match packets.
//
// See the top-level documentation for more details.
package triggers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/getlantern/geneva/internal"
	"github.com/getlantern/geneva/internal/scanner"
	"github.com/google/gopacket"

	// gopacket best practice says import this, too.
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
//
// If the string is malformed, an error will be returned instead.
func ParseTrigger(s *scanner.Scanner) (Trigger, error) {
	if _, err := s.Expect("["); err != nil {
		return nil, fmt.Errorf(
			"unexpected token in trigger: %w",
			internal.EOFUnexpected(err),
		)
	}

	str, err := s.Until(']')
	if err != nil {
		return nil, fmt.Errorf(
			"unexpected token in trigger: %w",
			internal.EOFUnexpected(err),
		)
	}

	_, _ = s.Pop()

	fields := strings.Split(str, ":")
	if len(fields) < 3 {
		return nil, fmt.Errorf(
			`trigger "[%s]" must have at least three fields (found %d)`,
			str, len(fields))
	}

	if fields[0] == "" {
		return nil, fmt.Errorf(`trigger "[%s]" does not specify a protocol`, str)
	}

	gas := 0
	if len(fields) == 4 {
		gas, err = strconv.Atoi(fields[3])
		if err != nil {
			return nil, fmt.Errorf("failed to parse value for gas: %w", err)
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
		return nil, fmt.Errorf("failed to create trigger: %w", err)
	}

	return trigger, nil
}
