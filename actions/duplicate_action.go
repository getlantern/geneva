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

func duplicate(packet gopacket.Packet) []gopacket.Packet {
	buf := make([]byte, 0, len(packet.Data()))
	copy(buf, packet.Data())
	p2 := gopacket.NewPacket(buf, packet.Layers()[0].LayerType(), gopacket.NoCopy)
	return []gopacket.Packet{packet, p2}
}

// Apply duplicates packet, returning zero or more potentially-modified packets.
//
// The number of returned packets depends on this action's sub-actions.
func (a *DuplicateAction) Apply(packet gopacket.Packet) []gopacket.Packet {
	duped := duplicate(packet)
	packets := a.Left.Apply(duped[0])
	return append(packets, a.Right.Apply(duped[1])...)
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
