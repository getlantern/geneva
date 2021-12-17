package actions

import (
	"fmt"

	"github.com/Crosse/geneva/internal/scanner"
	"github.com/google/gopacket"
)

// DuplicateAction is a Geneva action that duplicates a packet and applies separate action trees to each.
type DuplicateAction struct {
	Left  Action
	Right Action
}

func duplicatePacket(packet gopacket.Packet, leftAction, rightAction Action) []gopacket.Packet {
	packets := leftAction.Apply(packet)
	return append(packets, rightAction.Apply(packet)...)
}

// Apply duplicates packet, returning zero or more potentially-modified packets.
//
// The number of returned packets depends on this action's sub-actions.
func (a *DuplicateAction) Apply(packet gopacket.Packet) []gopacket.Packet {
	return duplicatePacket(packet, a.Left, a.Right)
}

// String returns a string representation of this Action.
func (a *DuplicateAction) String() string {
	return fmt.Sprintf("duplicate(%s,%s)", a.Left, a.Right)
}

// ParseDuplicateAction parses a string representation of a "duplicate" action.
// If the string is malformed, and error will be returned instead.
func ParseDuplicateAction(s *scanner.Scanner) (Action, error) {
	var err error

	if _, err = s.Expect("duplicate("); err != nil {
		return nil, fmt.Errorf("invalid duplicate() rule: %v", err)
	}

	action := &DuplicateAction{}
	if action.Left, err = ParseAction(s); err != nil {
		if c, err2 := s.Peek(); err2 == nil && c == ',' {
			action.Left = &SendAction{}
		} else {
			return nil, fmt.Errorf("invalid duplicate() rule: %v", err)
		}
	}

	if _, err = s.Expect(","); err != nil {
		return nil, fmt.Errorf("invalid duplicate() rule: %v", err)
	}

	if action.Right, err = ParseAction(s); err != nil {
		if c, err2 := s.Peek(); err2 == nil && c == ')' {
			action.Right = &SendAction{}
		} else {
			return nil, fmt.Errorf("invalid duplicate() rule: %v", err)
		}
	}

	if _, err = s.Expect(")"); err != nil {
		return nil, fmt.Errorf("invalid duplicate() rule: %v", err)
	}

	return action, nil
}
