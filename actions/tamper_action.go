package actions

import (
	"fmt"
	"strings"

	"github.com/getlantern/errors"
	"github.com/getlantern/geneva/internal/scanner"
	"github.com/google/gopacket"
)

// TamperMode describes the way that the "tamper" action can manipulate a packet.
type TamperMode int

func (tm TamperMode) String() string {
	switch tm {
	case TamperReplace:
		return "replace"
	case TamperCorrupt:
		return "corrupt"
	case TamperAdd:
		return "add"
	}

	return ""
}

const (
	// TamperReplace replaces the value of a packet field with the given value.
	TamperReplace = iota
	// TamperCorrupt replaces the value of a packet field with a randomly-generated value.
	TamperCorrupt
	// TamperAdd adds the value to a packet field.
	TamperAdd
)

// TamperAction is a Geneva action that modifies packets (typically values in the packet header).
type TamperAction struct {
	// Proto is the protocol layer where the modification will occur.
	Proto string
	// Field is the layer field to modify.
	Field string
	// NewValue is the new value to which the Field should be set. This is only relevant for
	// "replace" mode.
	NewValue string
	// Mode indicates how the modification should happen.
	Mode TamperMode
	// Action is the action to apply to the packet after modification.
	Action Action
}

// Apply applies this action to the given packet.
func (a *TamperAction) Apply(packet gopacket.Packet) ([]gopacket.Packet, error) {
	return nil, errors.New("tamper action unimplemented")
}

func (a *TamperAction) String() string {
	newValue := ""
	if a.Mode == TamperReplace {
		newValue = fmt.Sprintf(":%s", a.NewValue)
	}

	return fmt.Sprintf("tamper{%s:%s:%s%s}(%s,)",
		a.Proto, a.Field, a.Mode, newValue, a.Action)
}

func ParseTamperAction(s *scanner.Scanner) (Action, error) {
	if _, err := s.Expect("tamper{"); err != nil {
		return nil, errors.New("invalid tamper rule: %v", err)
	}

	str, err := s.Until('}')
	if err != nil {
		return nil, errors.New("invalid tamper rule: %v", err)
	}

	_, _ = s.Pop()

	fields := strings.Split(str, ":")
	if len(fields) < 3 || len(fields) > 4 {
		return nil, errors.New("invalid fields for tamper rule: %s", str)
	}

	action := &TamperAction{}

	switch strings.ToLower(fields[0]) {
	case "ip":
		action.Proto = "IP"
	case "tcp":
		action.Proto = "TCP"
	case "udp":
		action.Proto = "UDP"
	default:
		return nil, errors.New(
			"invalid tamper rule: %q is not a recognized protocol",
			fields[0],
		)
	}

	action.Field = fields[1]

	switch strings.ToLower(fields[2]) {
	case "replace":
		action.Mode = TamperReplace
		action.NewValue = fields[3]
	case "corrupt":
		action.Mode = TamperCorrupt
	default:
		return nil, errors.New(
			"invalid tamper mode: %q must be either 'replace' or 'corrupt'",
			fields[2],
		)
	}

	if _, err := s.Expect("("); err != nil {
		action.Action = &SendAction{}

		return action, nil //nolint:nilerr
	}

	if action.Action, err = ParseAction(s); err != nil {
		if c, err2 := s.Peek(); err2 == nil && c == ')' {
			action.Action = &SendAction{}
		} else {
			return nil, errors.New("invalid action for tamper rule: %v", err)
		}
	}

	if _, err = s.Expect(","); err == nil {
		if !s.FindToken(")", true) {
			return nil, errors.New("tamper rules can only have one action")
		}
	}

	if _, err := s.Expect(")"); err != nil {
		return nil, errors.New("invalid tamper rule: %v", err)
	}

	return action, nil
}
