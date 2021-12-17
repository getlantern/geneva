package actions

import (
	"fmt"

	"github.com/Crosse/geneva/internal/scanner"
	"github.com/google/gopacket"
)

type DuplicateAction struct {
	Left  Action
	Right Action
}

func duplicatePacket(packet gopacket.Packet, leftAction, rightAction Action) []gopacket.Packet {
	packets := leftAction.Apply(packet)
	return append(packets, rightAction.Apply(packet)...)
}

func (a *DuplicateAction) Apply(packet gopacket.Packet) []gopacket.Packet {
	return duplicatePacket(packet, a.Left, a.Right)
}

func (a *DuplicateAction) String() string {
	return fmt.Sprintf("duplicate(%s,%s)", a.Left, a.Right)
}

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
