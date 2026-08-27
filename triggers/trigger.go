// Package triggers enumerates all of the various triggers that can be used to match packets.
//
// See the top-level documentation for more details.
package triggers

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/getlantern/geneva/internal"
	"github.com/getlantern/geneva/internal/scanner"
	"github.com/gopacket/gopacket"

	// gopacket best practice says import this, too.
	_ "github.com/gopacket/gopacket/layers"
)

// ErrInvalidTrigger is returned when a trigger cannot be safely evaluated by
// the IPv4/TCP strategy engine.
var ErrInvalidTrigger = errors.New("invalid trigger")

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
	if len(fields) != 3 && len(fields) != 4 {
		return nil, fmt.Errorf(
			`trigger "[%s]" must have three or four fields (found %d)`,
			str, len(fields))
	}

	if fields[0] == "" {
		return nil, fmt.Errorf(`trigger "[%s]" does not specify a protocol`, str)
	}

	var gas *int
	if len(fields) == 4 {
		parsedGas, parseErr := strconv.Atoi(fields[3])
		err = parseErr
		if err != nil {
			return nil, fmt.Errorf("failed to parse value for gas: %w", err)
		}
		gas = &parsedGas
	}

	var trigger Trigger

	switch strings.ToLower(fields[0]) {
	case "ip":
		trigger, err = newIPTrigger(fields[1], fields[2], gas)
	case "tcp":
		trigger, err = newTCPTrigger(fields[1], fields[2], gas)
	default:
		return nil, fmt.Errorf("unsupported trigger protocol %q", fields[0])
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create trigger: %w", err)
	}

	return trigger, nil
}

// Validate checks that trigger is a supported, fully configured IPv4 or TCP
// trigger. It does not consume trigger gas.
func Validate(trigger Trigger) error {
	if trigger == nil {
		return fmt.Errorf("%w: trigger is nil", ErrInvalidTrigger)
	}

	var err error
	switch typed := trigger.(type) {
	case *IPTrigger:
		err = typed.validate()
	case *TCPTrigger:
		err = typed.validate()
	default:
		return fmt.Errorf("%w: unsupported trigger type %T", ErrInvalidTrigger, trigger)
	}

	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTrigger, err)
	}

	return nil
}
